/**
 * Concrete Mix Designer — backend with MongoDB Atlas
 */

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const url = require('url');
const { MongoClient } = require('mongodb');

const PORT = process.env.PORT || 3000;
const MONGODB_URI = process.env.MONGODB_URI;
const PUBLIC_DIR = path.join(__dirname, 'public');

let db, usersCol, trialsCol;

// ---------------------------------------------------------------------------
// Password hashing (scrypt)
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
// Sessions
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
// Request / Response helpers
// ---------------------------------------------------------------------------
function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    let tooLarge = false;
    req.on('data', (chunk) => {
      data += chunk;
      if (data.length > 5 * 1024 * 1024) {
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
// Server Handler
// ---------------------------------------------------------------------------
const server = http.createServer(async (req, res) => {
  const parsed = url.parse(req.url, true);
  const pathname = decodeURIComponent(parsed.pathname);

  try {
    // ---------------- AUTH ----------------
    if (pathname === '/api/auth/signup' && req.method === 'POST') {
      const body = await readBody(req);
      const name = (body.name || '').trim();
      const email = (body.email || '').trim().toLowerCase();
      const password = body.password || '';

      if (!name || !email || !password || password.length < 6) {
        return sendJSON(res, 400, { error: 'Name, a valid email, and a password of at least 6 characters are required.' });
      }

      const existing = await usersCol.findOne({ email });
      if (existing) {
        return sendJSON(res, 409, { error: 'An account with this email already exists.' });
      }

      const user = {
        id: crypto.randomUUID(),
        name,
        email,
        passwordHash: hashPassword(password),
        createdAt: new Date().toISOString(),
      };
      await usersCol.insertOne(user);

      const sid = createSession(user.id);
      return sendJSON(res, 200, { id: user.id, name: user.name, email: user.email }, {
        'Set-Cookie': `sid=${sid}; HttpOnly; Path=/; SameSite=Lax; Secure`,
      });
    }

    if (pathname === '/api/auth/login' && req.method === 'POST') {
      const body = await readBody(req);
      const email = (body.email || '').trim().toLowerCase();
      const password = body.password || '';
      const user = email ? await usersCol.findOne({ email }) : null;

      if (!user || !verifyPassword(password, user.passwordHash)) {
        return sendJSON(res, 401, { error: 'Invalid email or password.' });
      }

      const sid = createSession(user.id);
      return sendJSON(res, 200, { id: user.id, name: user.name, email: user.email }, {
        'Set-Cookie': `sid=${sid}; HttpOnly; Path=/; SameSite=Lax; Secure`,
      });
    }

    if (pathname === '/api/auth/logout' && req.method === 'POST') {
      const session = getSession(req);
      if (session) sessions.delete(session.sid);
      return sendJSON(res, 200, { ok: true }, {
        'Set-Cookie': 'sid=; HttpOnly; Path=/; Max-Age=0; Secure',
      });
    }

    if (pathname === '/api/auth/me' && req.method === 'GET') {
      const session = getSession(req);
      const user = session ? await usersCol.findOne({ id: session.userId }) : null;
      if (!user) return sendJSON(res, 401, { error: 'Not signed in.' });
      return sendJSON(res, 200, { id: user.id, name: user.name, email: user.email });
    }

    // ---------------- TRIALS (auth required) ----------------
    if (pathname.startsWith('/api/trials')) {
      const session = getSession(req);
      const user = session ? await usersCol.findOne({ id: session.userId }) : null;
      if (!user) return sendJSON(res, 401, { error: 'Not signed in.' });
      const userId = user.id;

      if (pathname === '/api/trials' && req.method === 'GET') {
        const trials = await trialsCol
          .find({ userId })
          .sort({ updatedAt: -1 })
          .toArray();
        return sendJSON(res, 200, trials.map(trialSummary));
      }

      if (pathname === '/api/trials' && req.method === 'POST') {
        const body = await readBody(req);
        if (!body.data) return sendJSON(res, 400, { error: 'Missing trial data.' });
        const now = new Date().toISOString();
        const trial = {
          id: crypto.randomUUID(),
          userId,
          trialRef: body.data.trialRef || 'Untitled Trial',
          data: body.data,
          createdAt: now,
          updatedAt: now,
        };
        await trialsCol.insertOne(trial);
        return sendJSON(res, 200, { id: trial.id, updatedAt: trial.updatedAt });
      }

      const idMatch = pathname.match(/^\/api\/trials\/([a-zA-Z0-9-]+)$/);
      if (idMatch) {
        const trialId = idMatch[1];

        if (req.method === 'GET') {
          const trial = await trialsCol.findOne({ id: trialId, userId }, { projection: { _id: 0 } });
          if (!trial) return sendJSON(res, 404, { error: 'Trial not found.' });
          return sendJSON(res, 200, trial);
        }

        if (req.method === 'PUT') {
          const body = await readBody(req);
          if (!body.data) return sendJSON(res, 400, { error: 'Missing trial data.' });
          const updatedAt = new Date().toISOString();
          const trialRef = body.data.trialRef || 'Untitled Trial';

          const result = await trialsCol.updateOne(
            { id: trialId, userId },
            { $set: { data: body.data, trialRef, updatedAt } }
          );

          if (result.matchedCount === 0) return sendJSON(res, 404, { error: 'Trial not found.' });
          return sendJSON(res, 200, { id: trialId, updatedAt });
        }

        if (req.method === 'DELETE') {
          const result = await trialsCol.deleteOne({ id: trialId, userId });
          if (result.deletedCount === 0) return sendJSON(res, 404, { error: 'Trial not found.' });
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

// ---------------------------------------------------------------------------
// Database Connection & Server Start
// ---------------------------------------------------------------------------
async function start() {
  try {
    if (!MONGODB_URI) {
      throw new Error('MONGODB_URI environment variable is missing.');
    }
    const client = new MongoClient(MONGODB_URI);
    await client.connect();
    console.log('Connected successfully to MongoDB Atlas');

    db = client.db();
    usersCol = db.collection('users');
    trialsCol = db.collection('trials');

    await usersCol.createIndex({ email: 1 }, { unique: true });

    server.listen(PORT, () => {
      console.log(`Concrete Mix Designer running on port ${PORT}`);
    });
  } catch (err) {
    console.error('Failed to connect to database:', err);
    process.exit(1);
  }
}

start();
