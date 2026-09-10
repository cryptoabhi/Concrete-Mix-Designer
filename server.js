/**
 * Concrete Mix Designer — backend
 * Pure Node.js (no npm packages required). Provides:
 *   - Account creation / login / logout (session cookie)
 *   - Per-user storage of trial sheets (JSON file "database")
 *   - Static file serving for the front-end (public/)
 *
 * Run:  node server.js
 * Then open http://localhost:3000
 */

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const url = require('url');

const PORT = process.env.PORT || 3000;
const DATA_DIR = path.join(__dirname, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const TRIALS_FILE = path.join(DATA_DIR, 'trials.json');
const PUBLIC_DIR = path.join(__dirname, 'public');

// ---------------------------------------------------------------------------
// Bootstrap data files
// ---------------------------------------------------------------------------
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(USERS_FILE)) fs.writeFileSync(USERS_FILE, '[]');
if (!fs.existsSync(TRIALS_FILE)) fs.writeFileSync(TRIALS_FILE, '[]');

function readJSON(file) {
  return JSON.parse(fs.readFileSync(file, 'utf8') || '[]');
}
function writeJSON(file, data) {
  fs.writeFileSync(file, JSON.stringify(data, null, 2));
}

// ---------------------------------------------------------------------------
// Password hashing (scrypt, built into Node — no bcrypt dependency needed)
// ---------------------------------------------------------------------------
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${hash}`;
}
function verifyPassword(password, stored) {
  const [salt, hash] = String(stored).split(':');
  if (!salt || !hash) return false;
  const check = crypto.scryptSync(password, salt, 64).toString('hex');
  const a = Buffer.from(hash, 'hex');
  const b = Buffer.from(check, 'hex');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

// ---------------------------------------------------------------------------
// Sessions (in-memory cookie sessions — fine for a single-instance prototype)
// ---------------------------------------------------------------------------
const sessions = new Map(); // sid -> { userId, createdAt }

function createSession(userId) {
  const sid = crypto.randomBytes(24).toString('hex');
  sessions.set(sid, { userId, createdAt: Date.now() });
  return sid;
}
function parseCookies(header) {
  const out = {};
  (header || '').split(';').forEach((pair) => {
    const idx = pair.indexOf('=');
    if (idx === -1) return;
    const k = pair.slice(0, idx).trim();
    const v = pair.slice(idx + 1).trim();
    if (k) out[k] = decodeURIComponent(v);
  });
  return out;
}
function getSession(req) {
  const cookies = parseCookies(req.headers.cookie);
  const sid = cookies.sid;
  if (!sid) return null;
  const s = sessions.get(sid);
  return s ? { sid, ...s } : null;
}

// ---------------------------------------------------------------------------
// Request body / response helpers
// ---------------------------------------------------------------------------
function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    let tooLarge = false;
    req.on('data', (chunk) => {
      data += chunk;
      if (data.length > 5 * 1024 * 1024) { // 5MB safety cap
        tooLarge = true;
        req.destroy();
      }
    });
    req.on('end', () => {
      if (tooLarge) return reject(new Error('Payload too large'));
      if (!data) return resolve({});
      try {
        resolve(JSON.parse(data));
      } catch (e) {
        reject(e);
      }
    });
    req.on('error', reject);
  });
}
function sendJSON(res, status, obj, extraHeaders) {
  res.writeHead(status, Object.assign({ 'Content-Type': 'application/json; charset=utf-8' }, extraHeaders));
  res.end(JSON.stringify(obj));
}

// ---------------------------------------------------------------------------
// Static file serving
// ---------------------------------------------------------------------------
const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
};
function serveStatic(req, res, pathname) {
  const safePath = path.normalize(pathname).replace(/^(\.\.[/\\])+/, '');
  const filePath = path.join(PUBLIC_DIR, safePath);
  if (!filePath.startsWith(PUBLIC_DIR)) {
    res.writeHead(403);
    return res.end('Forbidden');
  }
  fs.stat(filePath, (err, stat) => {
    if (err || !stat.isFile()) {
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      return res.end('Not found');
    }
    const ext = path.extname(filePath);
    res.writeHead(200, { 'Content-Type': MIME[ext] || 'application/octet-stream' });
    fs.createReadStream(filePath).pipe(res);
  });
}

// ---------------------------------------------------------------------------
// Data access helpers
// ---------------------------------------------------------------------------
function findUserByEmail(email) {
  const users = readJSON(USERS_FILE);
  return users.find((u) => u.email.toLowerCase() === String(email).toLowerCase());
}
function findUserById(id) {
  const users = readJSON(USERS_FILE);
  return users.find((u) => u.id === id);
}
function trialSummary(t) {
  const d = t.data || {};
  return {
    id: t.id,
    trialRef: t.trialRef,
    project: d.project || '',
    customer: d.customer || '',
    grade: d.grade || '',
    updatedAt: t.updatedAt,
    createdAt: t.createdAt,
  };
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------
const server = http.createServer(async (req, res) => {
  const parsed = url.parse(req.url, true);
  const pathname = decodeURIComponent(parsed.pathname);

  try {
    // ---------------- AUTH ----------------
    if (pathname === '/api/auth/signup' && req.method === 'POST') {
      const body = await readBody(req);
      const name = (body.name || '').trim();
      const email = (body.email || '').trim();
      const password = body.password || '';

      if (!name || !email || !password || password.length < 6) {
        return sendJSON(res, 400, { error: 'Name, a valid email, and a password of at least 6 characters are required.' });
      }
      if (findUserByEmail(email)) {
        return sendJSON(res, 409, { error: 'An account with this email already exists.' });
      }

      const users = readJSON(USERS_FILE);
      const user = {
        id: crypto.randomUUID(),
        name,
        email,
        passwordHash: hashPassword(password),
        createdAt: new Date().toISOString(),
      };
      users.push(user);
      writeJSON(USERS_FILE, users);

      const sid = createSession(user.id);
      return sendJSON(res, 200, { id: user.id, name: user.name, email: user.email }, {
        'Set-Cookie': `sid=${sid}; HttpOnly; Path=/; SameSite=Lax`,
      });
    }

    if (pathname === '/api/auth/login' && req.method === 'POST') {
      const body = await readBody(req);
      const email = (body.email || '').trim();
      const password = body.password || '';
      const user = email && findUserByEmail(email);

      if (!user || !verifyPassword(password, user.passwordHash)) {
        return sendJSON(res, 401, { error: 'Invalid email or password.' });
      }

      const sid = createSession(user.id);
      return sendJSON(res, 200, { id: user.id, name: user.name, email: user.email }, {
        'Set-Cookie': `sid=${sid}; HttpOnly; Path=/; SameSite=Lax`,
      });
    }

    if (pathname === '/api/auth/logout' && req.method === 'POST') {
      const session = getSession(req);
      if (session) sessions.delete(session.sid);
      return sendJSON(res, 200, { ok: true }, {
        'Set-Cookie': 'sid=; HttpOnly; Path=/; Max-Age=0',
      });
    }

    if (pathname === '/api/auth/me' && req.method === 'GET') {
      const session = getSession(req);
      const user = session && findUserById(session.userId);
      if (!user) return sendJSON(res, 401, { error: 'Not signed in.' });
      return sendJSON(res, 200, { id: user.id, name: user.name, email: user.email });
    }

    // ---------------- TRIALS (auth required) ----------------
    if (pathname.startsWith('/api/trials')) {
      const session = getSession(req);
      const user = session && findUserById(session.userId);
      if (!user) return sendJSON(res, 401, { error: 'Not signed in.' });
      const userId = user.id;

      if (pathname === '/api/trials' && req.method === 'GET') {
        const trials = readJSON(TRIALS_FILE)
          .filter((t) => t.userId === userId)
          .sort((a, b) => new Date(b.updatedAt) - new Date(a.updatedAt));
        return sendJSON(res, 200, trials.map(trialSummary));
      }

      if (pathname === '/api/trials' && req.method === 'POST') {
        const body = await readBody(req);
        if (!body.data) return sendJSON(res, 400, { error: 'Missing trial data.' });
        const trials = readJSON(TRIALS_FILE);
        const now = new Date().toISOString();
        const trial = {
          id: crypto.randomUUID(),
          userId,
          trialRef: body.data.trialRef || 'Untitled Trial',
          data: body.data,
          createdAt: now,
          updatedAt: now,
        };
        trials.push(trial);
        writeJSON(TRIALS_FILE, trials);
        return sendJSON(res, 200, { id: trial.id, updatedAt: trial.updatedAt });
      }

      const idMatch = pathname.match(/^\/api\/trials\/([a-zA-Z0-9-]+)$/);
      if (idMatch) {
        const trialId = idMatch[1];
        const trials = readJSON(TRIALS_FILE);
        const idx = trials.findIndex((t) => t.id === trialId && t.userId === userId);

        if (req.method === 'GET') {
          if (idx === -1) return sendJSON(res, 404, { error: 'Trial not found.' });
          return sendJSON(res, 200, trials[idx]);
        }

        if (req.method === 'PUT') {
          if (idx === -1) return sendJSON(res, 404, { error: 'Trial not found.' });
          const body = await readBody(req);
          if (!body.data) return sendJSON(res, 400, { error: 'Missing trial data.' });
          trials[idx].data = body.data;
          trials[idx].trialRef = body.data.trialRef || trials[idx].trialRef;
          trials[idx].updatedAt = new Date().toISOString();
          writeJSON(TRIALS_FILE, trials);
          return sendJSON(res, 200, { id: trials[idx].id, updatedAt: trials[idx].updatedAt });
        }

        if (req.method === 'DELETE') {
          if (idx === -1) return sendJSON(res, 404, { error: 'Trial not found.' });
          trials.splice(idx, 1);
          writeJSON(TRIALS_FILE, trials);
          return sendJSON(res, 200, { ok: true });
        }
      }

      return sendJSON(res, 404, { error: 'Not found.' });
    }

    // ---------------- STATIC FILES ----------------
    if (req.method === 'GET') {
      if (pathname === '/') {
        res.writeHead(302, { Location: '/login.html' });
        return res.end();
      }
      return serveStatic(req, res, pathname);
    }

    sendJSON(res, 404, { error: 'Not found.' });
  } catch (err) {
    console.error(err);
    sendJSON(res, 500, { error: 'Server error.' });
  }
});

server.listen(PORT, () => {
  console.log(`Concrete Mix Designer running at http://localhost:${PORT}`);
});
