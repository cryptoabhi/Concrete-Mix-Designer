/**
 * Concrete Technology Tools
 * Backend with MongoDB Atlas
 *
 * Features:
 * - User signup/login/logout
 * - Session-based authentication
 * - MongoDB Atlas user and trial storage
 * - User-specific trial management
 * - Formulation Suggester access control
 * - Admin grant/revoke formulation access
 * - Protected formulation tool
 * - Static file serving
 */

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { URL } = require('url');
const { MongoClient } = require('mongodb');

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

const PORT = process.env.PORT || 3000;
const MONGODB_URI = process.env.MONGODB_URI;
const PUBLIC_DIR = path.join(__dirname, 'public');

// Admin email with permanent formulation access
const ADMIN_EMAIL = 'kordeabhishek383@gmail.com';

// MongoDB variables
let db;
let usersCol;
let trialsCol;
let formulationTrialsCol;

// ---------------------------------------------------------------------------
// Password Hashing
// ---------------------------------------------------------------------------

function hashPassword(password) {
    const salt = crypto.randomBytes(16).toString('hex');

    const hash = crypto
        .scryptSync(password, salt, 64)
        .toString('hex');

    return `${salt}:${hash}`;
}

function verifyPassword(password, storedHash) {
    try {
        const parts = String(storedHash || '').split(':');

        if (parts.length !== 2) {
            return false;
        }

        const salt = parts[0];
        const originalHash = Buffer.from(parts[1], 'hex');

        const hash = crypto.scryptSync(
            password,
            salt,
            64
        );

        return (
            hash.length === originalHash.length &&
            crypto.timingSafeEqual(hash, originalHash)
        );
    } catch (err) {
        return false;
    }
}

// ---------------------------------------------------------------------------
// Sessions
// ---------------------------------------------------------------------------

const sessions = new Map();
// sid -> { userId, createdAt }

function createSession(userId) {
    const sid = crypto.randomBytes(32).toString('hex');

    sessions.set(sid, {
        userId,
        createdAt: Date.now()
    });

    return sid;
}

function parseCookies(req) {
    const header = req.headers.cookie || '';
    const cookies = {};

    header.split(';').forEach((part) => {
        const index = part.indexOf('=');

        if (index === -1) {
            return;
        }

        const key = part.slice(0, index).trim();
        const value = part.slice(index + 1).trim();

        if (key) {
            cookies[key] = decodeURIComponent(value);
        }
    });

    return cookies;
}

function getSession(req) {
    const cookies = parseCookies(req);

    if (!cookies.sid) {
        return null;
    }

    const session = sessions.get(cookies.sid);

    if (!session) {
        return null;
    }

    return {
        sid: cookies.sid,
        ...session
    };
}

// ---------------------------------------------------------------------------
// Request Body
// ---------------------------------------------------------------------------

function parseBody(req) {
    return new Promise((resolve, reject) => {
        let body = '';
        let tooLarge = false;

        req.on('data', (chunk) => {
            body += chunk.toString();

            // Maximum request body size: 1 MB
            if (body.length > 1024 * 1024) {
                tooLarge = true;
                req.destroy();
                reject(new Error('Request body too large'));
            }
        });

        req.on('end', () => {
            if (tooLarge) {
                return;
            }

            if (!body) {
                resolve({});
                return;
            }

            try {
                resolve(JSON.parse(body));
            } catch (err) {
                reject(new Error('Invalid JSON'));
            }
        });

        req.on('error', reject);
    });
}

// ---------------------------------------------------------------------------
// Response Helpers
// ---------------------------------------------------------------------------

function sendJSON(res, statusCode, data, extraHeaders = {}) {
    res.writeHead(statusCode, {
        'Content-Type': 'application/json; charset=utf-8',
        ...extraHeaders
    });

    res.end(JSON.stringify(data));
}

function redirect(res, location) {
    res.writeHead(302, {
        Location: location
    });

    res.end();
}

function unauthorized(res, message = 'Unauthorized') {
    sendJSON(res, 401, {
        error: message
    });
}

function forbidden(res, message = 'Access denied') {
    sendJSON(res, 403, {
        error: message
    });
}

// ---------------------------------------------------------------------------
// User Helpers
// ---------------------------------------------------------------------------

async function findUserByEmail(email) {
    const normalizedEmail = String(email || '')
        .trim()
        .toLowerCase();

    if (!normalizedEmail) {
        return null;
    }

    return usersCol.findOne({
        email: normalizedEmail
    });
}

async function findUserById(id) {
    if (!id) {
        return null;
    }

    return usersCol.findOne({
        id
    });
}

async function getCurrentUser(req) {
    const session = getSession(req);

    if (!session) {
        return null;
    }

    return findUserById(session.userId);
}

// ---------------------------------------------------------------------------
// Formulation Access Control
// ---------------------------------------------------------------------------

function isAdmin(user) {
    return (
        !!user &&
        String(user.email || '').toLowerCase() ===
            ADMIN_EMAIL.toLowerCase()
    );
}

function hasFormulationAccess(user) {
    if (!user) {
        return false;
    }

    // Admin always has access
    if (isAdmin(user)) {
        return true;
    }

    // Other users need explicit permission
    return user.formulationAccess === true;
}

// ---------------------------------------------------------------------------
// Static File Server
// ---------------------------------------------------------------------------

const MIME_TYPES = {
    '.html': 'text/html; charset=utf-8',
    '.css': 'text/css; charset=utf-8',
    '.js': 'application/javascript; charset=utf-8',
    '.json': 'application/json; charset=utf-8',

    '.txt': 'text/plain; charset=utf-8',
    '.xml': 'application/xml; charset=utf-8',

    '.png': 'image/png',
    '.jpg': 'image/jpeg',
    '.jpeg': 'image/jpeg',
    '.gif': 'image/gif',
    '.svg': 'image/svg+xml',
    '.ico': 'image/x-icon',
    '.webp': 'image/webp'
};

function serveStatic(req, res, pathname) {
    let decodedPath;

    try {
        decodedPath = decodeURIComponent(pathname);
    } catch (err) {
        forbidden(res, 'Invalid path');
        return;
    }

    // Remove leading slash before joining with PUBLIC_DIR
    const relativePath = decodedPath.replace(/^[/\\]+/, '');

    const filePath = path.resolve(
        PUBLIC_DIR,
        relativePath
    );

    const publicRoot = path.resolve(PUBLIC_DIR);

    // Prevent path traversal
    if (
        filePath !== publicRoot &&
        !filePath.startsWith(publicRoot + path.sep)
    ) {
        forbidden(res, 'Invalid path');
        return;
    }

    fs.stat(filePath, (err, stats) => {
        if (err || !stats.isFile()) {
            sendJSON(res, 404, {
                error: 'File not found'
            });
            return;
        }

        const ext = path.extname(filePath).toLowerCase();

        const contentType =
            MIME_TYPES[ext] ||
            'application/octet-stream';

        res.writeHead(200, {
            'Content-Type': contentType,
            'Cache-Control': 'no-cache'
        });

        fs.createReadStream(filePath).pipe(res);
    });
}

// ---------------------------------------------------------------------------
// Protected Access Restricted Page
// ---------------------------------------------------------------------------

function sendFormulationRestrictedPage(res) {
    res.writeHead(403, {
        'Content-Type': 'text/html; charset=utf-8'
    });

    res.end(`
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Access Restricted</title>

    <style>
        * {
            box-sizing: border-box;
        }

        body {
            margin: 0;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
            background: #f1f5f9;
            font-family: Arial, sans-serif;
            color: #1e293b;
        }

        .box {
            width: 100%;
            max-width: 440px;
            padding: 40px 30px;
            background: #ffffff;
            border-radius: 16px;
            text-align: center;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.10);
        }

        .icon {
            font-size: 48px;
            margin-bottom: 15px;
        }

        h1 {
            margin: 0 0 14px;
            font-size: 26px;
        }

        p {
            color: #64748b;
            line-height: 1.6;
            margin: 8px 0;
        }

        a {
            display: inline-block;
            margin-top: 20px;
            padding: 11px 20px;
            background: #2563eb;
            color: white;
            text-decoration: none;
            border-radius: 8px;
        }

        a:hover {
            background: #1d4ed8;
        }
    </style>
</head>

<body>
    <div class="box">
        <div class="icon">🔒</div>

        <h1>Access Restricted</h1>

        <p>
            You do not currently have access to the
            Formulation Suggester.
        </p>

        <p>
            Please contact Abhishek to request access.
        </p>

        <a href="/select-tool.html">
            Back to Tools
        </a>
    </div>
</body>
</html>
    `);
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

const server = http.createServer(async (req, res) => {
    try {
        const parsedURL = new URL(
            req.url,
            `http://${req.headers.host || 'localhost'}`
        );

        const pathname = parsedURL.pathname;

        // ===================================================================
        // AUTH: SIGNUP
        // ===================================================================

        if (
            req.method === 'POST' &&
            pathname === '/api/auth/signup'
        ) {
            const body = await parseBody(req);

            const name = String(body.name || '').trim();

            const email = String(body.email || '')
                .trim()
                .toLowerCase();

            const password = String(body.password || '');

            if (!name) {
                sendJSON(res, 400, {
                    error: 'Name is required'
                });
                return;
            }

            if (!email || !email.includes('@')) {
                sendJSON(res, 400, {
                    error: 'A valid email is required'
                });
                return;
            }

            if (password.length < 6) {
                sendJSON(res, 400, {
                    error: 'Password must be at least 6 characters'
                });
                return;
            }

            const existingUser = await findUserByEmail(email);

            if (existingUser) {
                sendJSON(res, 409, {
                    error: 'An account with this email already exists'
                });
                return;
            }

            const user = {
                id: crypto.randomUUID(),
                name,
                email,
                passwordHash: hashPassword(password),

                // New users do not receive formulation access
                formulationAccess: false,

                createdAt: new Date().toISOString()
            };

            await usersCol.insertOne(user);

            const sid = createSession(user.id);

            sendJSON(
                res,
                201,
                {
                    id: user.id,
                    name: user.name,
                    email: user.email
                },
                {
                    'Set-Cookie':
                        `sid=${encodeURIComponent(sid)}; HttpOnly; Path=/; SameSite=Lax; Secure`
                }
            );

            return;
        }

        // ===================================================================
        // AUTH: LOGIN
        // ===================================================================

        if (
            req.method === 'POST' &&
            pathname === '/api/auth/login'
        ) {
            const body = await parseBody(req);

            const email = String(body.email || '')
                .trim()
                .toLowerCase();

            const password = String(body.password || '');

            const user = await findUserByEmail(email);

            if (
                !user ||
                !verifyPassword(password, user.passwordHash)
            ) {
                sendJSON(res, 401, {
                    error: 'Invalid email or password'
                });
                return;
            }

            const sid = createSession(user.id);

            sendJSON(
                res,
                200,
                {
                    id: user.id,
                    name: user.name,
                    email: user.email
                },
                {
                    'Set-Cookie':
                        `sid=${encodeURIComponent(sid)}; HttpOnly; Path=/; SameSite=Lax; Secure`
                }
            );

            return;
        }

        // ===================================================================
        // AUTH: LOGOUT
        // ===================================================================

        if (
            req.method === 'POST' &&
            pathname === '/api/auth/logout'
        ) {
            const session = getSession(req);

            if (session) {
                sessions.delete(session.sid);
            }

            sendJSON(
                res,
                200,
                {
                    success: true
                },
                {
                    'Set-Cookie':
                        'sid=; HttpOnly; Path=/; Max-Age=0; SameSite=Lax; Secure'
                }
            );

            return;
        }

        // ===================================================================
        // AUTH: CURRENT USER
        // ===================================================================

        if (
            req.method === 'GET' &&
            pathname === '/api/auth/me'
        ) {
            const user = await getCurrentUser(req);

            if (!user) {
                unauthorized(res, 'Not logged in');
                return;
            }

            sendJSON(res, 200, {
                id: user.id,
                name: user.name,
                email: user.email
            });

            return;
        }

        // ===================================================================
        // FORMULATION: ACCESS CHECK
        // ===================================================================

        if (
            req.method === 'GET' &&
            pathname === '/api/auth/formulation-access'
        ) {
            const user = await getCurrentUser(req);

            if (!user) {
                unauthorized(res, 'Not logged in');
                return;
            }

            sendJSON(res, 200, {
                allowed: hasFormulationAccess(user),
                admin: isAdmin(user),
                name: user.name,
                email: user.email
            });

            return;
        }

        // ===================================================================
        // ADMIN: GRANT / REVOKE FORMULATION ACCESS
        // ===================================================================

        if (
            req.method === 'POST' &&
            pathname === '/api/admin/formulation-access'
        ) {
            const adminUser = await getCurrentUser(req);

            if (!adminUser) {
                unauthorized(res, 'Not logged in');
                return;
            }

            if (!isAdmin(adminUser)) {
                forbidden(res, 'Admin access required');
                return;
            }

            const body = await parseBody(req);

            const targetUserId = String(
                body.userId || ''
            ).trim();

            const targetEmail = String(
                body.email || ''
            ).trim().toLowerCase();

            const allowed = body.allowed === true;

            if (!targetUserId && !targetEmail) {
                sendJSON(res, 400, {
                    error: 'User ID or email is required'
                });
                return;
            }

            let targetUser = null;

            if (targetUserId) {
                targetUser = await findUserById(targetUserId);
            }

            if (!targetUser && targetEmail) {
                targetUser = await findUserByEmail(targetEmail);
            }

            if (!targetUser) {
                sendJSON(res, 404, {
                    error: 'User not found'
                });
                return;
            }

            // Admin access cannot be revoked
            if (isAdmin(targetUser)) {
                await usersCol.updateOne(
                    { id: targetUser.id },
                    {
                        $set: {
                            formulationAccess: true
                        }
                    }
                );

                sendJSON(res, 200, {
                    success: true,
                    message: 'Admin access is permanently enabled',
                    user: {
                        id: targetUser.id,
                        name: targetUser.name,
                        email: targetUser.email,
                        formulationAccess: true
                    }
                });

                return;
            }

            await usersCol.updateOne(
                { id: targetUser.id },
                {
                    $set: {
                        formulationAccess: allowed
                    }
                }
            );

            sendJSON(res, 200, {
                success: true,
                message: allowed
                    ? 'Formulation access granted'
                    : 'Formulation access revoked',
                user: {
                    id: targetUser.id,
                    name: targetUser.name,
                    email: targetUser.email,
                    formulationAccess: allowed
                }
            });

            return;
        }

        // ===================================================================
        // ADMIN: GET ALL USERS
        // ===================================================================

        if (
            req.method === 'GET' &&
            pathname === '/api/admin/users'
        ) {
            const adminUser = await getCurrentUser(req);

            if (!adminUser) {
                unauthorized(res, 'Not logged in');
                return;
            }

            if (!isAdmin(adminUser)) {
                forbidden(res, 'Admin access required');
                return;
            }

            const users = await usersCol
                .find({})
                .sort({ createdAt: -1 })
                .toArray();

            const safeUsers = users.map((user) => ({
                id: user.id,
                name: user.name,
                email: user.email,

                formulationAccess: isAdmin(user)
                    ? true
                    : user.formulationAccess === true,

                isAdmin: isAdmin(user),
                createdAt: user.createdAt
            }));

            sendJSON(res, 200, safeUsers);
            return;
        }

        // ===================================================================
        // TRIALS: AUTHENTICATION REQUIRED
        // ===================================================================

        if (pathname.startsWith('/api/trials')) {
            const user = await getCurrentUser(req);

            if (!user) {
                unauthorized(res, 'Not logged in');
                return;
            }

            // ---------------------------------------------------------------
            // GET ALL USER TRIALS
            // ---------------------------------------------------------------

            if (
                req.method === 'GET' &&
                pathname === '/api/trials'
            ) {
                const trials = await trialsCol
                    .find({ userId: user.id })
                    .sort({ updatedAt: -1 })
                    .toArray();

                sendJSON(res, 200, trials);
                return;
            }

            // ---------------------------------------------------------------
            // CREATE TRIAL
            // ---------------------------------------------------------------

            if (
                req.method === 'POST' &&
                pathname === '/api/trials'
            ) {
                const body = await parseBody(req);

                const now = new Date().toISOString();

                const trial = {
                    id: crypto.randomUUID(),
                    userId: user.id,
                    ...body,
                    createdAt: now,
                    updatedAt: now
                };

                await trialsCol.insertOne(trial);

                sendJSON(res, 201, trial);
                return;
            }

            // ---------------------------------------------------------------
            // GET / UPDATE / DELETE SINGLE TRIAL
            // ---------------------------------------------------------------

            const match = pathname.match(
                /^\/api\/trials\/([^/]+)$/
            );

            if (match) {
                const trialId = match[1];

                const trial = await trialsCol.findOne({
                    id: trialId,
                    userId: user.id
                });

                if (!trial) {
                    sendJSON(res, 404, {
                        error: 'Trial not found'
                    });
                    return;
                }

                // GET SINGLE TRIAL
                if (req.method === 'GET') {
                    sendJSON(res, 200, trial);
                    return;
                }

                // UPDATE TRIAL
                if (req.method === 'PUT') {
                    const body = await parseBody(req);

                    const updatedAt = new Date().toISOString();

                    const updateData = {
                        ...body,
                        updatedAt
                    };

                    // Do not allow changing ownership or ID
                    delete updateData.id;
                    delete updateData.userId;
                    delete updateData.createdAt;

                    await trialsCol.updateOne(
                        {
                            id: trialId,
                            userId: user.id
                        },
                        {
                            $set: updateData
                        }
                    );

                    const updatedTrial = await trialsCol.findOne({
                        id: trialId,
                        userId: user.id
                    });

                    sendJSON(res, 200, updatedTrial);
                    return;
                }

                // DELETE TRIAL
                if (req.method === 'DELETE') {
                    await trialsCol.deleteOne({
                        id: trialId,
                        userId: user.id
                    });

                    sendJSON(res, 200, {
                        success: true
                    });

                    return;
                }
            }

            sendJSON(res, 404, {
                error: 'Trial endpoint not found'
            });

            return;
        }
        // ===================================================================
// FORMULATION TRIALS: AUTHENTICATION REQUIRED
// ===================================================================

if (pathname.startsWith('/api/formulation-trials')) {
    const user = await getCurrentUser(req);

    if (!user) {
        unauthorized(res, 'Not logged in');
        return;
    }

    // ---------------------------------------------------------------
    // GET ALL FORMULATION TRIALS FOR CURRENT USER
    // ---------------------------------------------------------------

    if (
        req.method === 'GET' &&
        pathname === '/api/formulation-trials'
    ) {
        const trials = await formulationTrialsCol
            .find({ userId: user.id })
            .sort({ updatedAt: -1 })
            .toArray();

        sendJSON(res, 200, trials);
        return;
    }

    // ---------------------------------------------------------------
    // CREATE FORMULATION TRIAL
    // ---------------------------------------------------------------

    if (
        req.method === 'POST' &&
        pathname === '/api/formulation-trials'
    ) {
        const body = await parseBody(req);

        const now = new Date().toISOString();

        const trial = {
            id: crypto.randomUUID(),
            userId: user.id,
            ...body,
            createdAt: now,
            updatedAt: now
        };

        // Never allow the browser to control ownership
        trial.userId = user.id;
        trial.id = trial.id;

        await formulationTrialsCol.insertOne(trial);

        sendJSON(res, 201, trial);
        return;
    }

    // ---------------------------------------------------------------
// DELETE ALL FORMULATION TRIALS FOR CURRENT USER
// ---------------------------------------------------------------

if (
    req.method === 'DELETE' &&
    pathname === '/api/formulation-trials'
) {
    const result = await formulationTrialsCol.deleteMany({
        userId: user.id
    });

    sendJSON(res, 200, {
        success: true,
        deletedCount: result.deletedCount
    });

    return;
}


    // ---------------------------------------------------------------
    // GET / UPDATE / DELETE SINGLE FORMULATION TRIAL
    // ---------------------------------------------------------------

    const match = pathname.match(
        /^\/api\/formulation-trials\/([^/]+)$/
    );

    if (match) {
        const trialId = match[1];

        const trial = await formulationTrialsCol.findOne({
            id: trialId,
            userId: user.id
        });

        if (!trial) {
            sendJSON(res, 404, {
                error: 'Formulation trial not found'
            });
            return;
        }

        // -----------------------------------------------------------
        // GET SINGLE TRIAL
        // -----------------------------------------------------------

        if (req.method === 'GET') {
            sendJSON(res, 200, trial);
            return;
        }

        // -----------------------------------------------------------
        // UPDATE TRIAL
        // -----------------------------------------------------------

        if (req.method === 'PUT') {
            const body = await parseBody(req);

            const updatedAt = new Date().toISOString();

            const updateData = {
                ...body,
                updatedAt
            };

            // Never allow ownership or identity changes
            delete updateData.id;
            delete updateData.userId;
            delete updateData.createdAt;

            await formulationTrialsCol.updateOne(
                {
                    id: trialId,
                    userId: user.id
                },
                {
                    $set: updateData
                }
            );

            const updatedTrial =
                await formulationTrialsCol.findOne({
                    id: trialId,
                    userId: user.id
                });

            sendJSON(res, 200, updatedTrial);
            return;
        }

        // -----------------------------------------------------------
        // DELETE TRIAL
        // -----------------------------------------------------------

        if (req.method === 'DELETE') {
            await formulationTrialsCol.deleteOne({
                id: trialId,
                userId: user.id
            });

            sendJSON(res, 200, {
                success: true
            });

            return;
        }
    }

    sendJSON(res, 404, {
        error: 'Formulation trial endpoint not found'
    });

    return;
}

        // ===================================================================
        // STATIC FILES
        // ===================================================================

        if (req.method === 'GET') {
            // Home page
        if (pathname === '/') {
        serveStatic(req, res, '/index.html');
        return;
            }

            // Protect Formulation Suggester
            if (pathname === '/formulation.html') {
                const user = await getCurrentUser(req);

                if (!user) {
                    redirect(res, '/login.html');
                    return;
                }

                if (!hasFormulationAccess(user)) {
                    sendFormulationRestrictedPage(res);
                    return;
                }
            }

            serveStatic(req, res, pathname);
            return;
        }

        // ===================================================================
        // UNKNOWN ROUTE
        // ===================================================================

        sendJSON(res, 404, {
            error: 'Route not found'
        });

    } catch (err) {
        console.error('Server error:', err);

        if (!res.headersSent) {
            sendJSON(res, 500, {
                error: 'Internal server error'
            });
        } else {
            res.end();
        }
    }
});

// ---------------------------------------------------------------------------
// Database Connection & Server Start
// ---------------------------------------------------------------------------

async function start() {
    try {
        if (!MONGODB_URI) {
            throw new Error(
                'MONGODB_URI environment variable is missing.'
            );
        }

        const client = new MongoClient(MONGODB_URI);

        await client.connect();

        console.log('Connected successfully to MongoDB Atlas');

        db = client.db();

        usersCol = db.collection('users');
        trialsCol = db.collection('trials');
        formulationTrialsCol = db.collection('formulationTrials');
        // Unique email index
        await usersCol.createIndex(
            { email: 1 },
            { unique: true }
        );

        // Useful indexes for faster trial queries
        await trialsCol.createIndex({
            userId: 1,
            updatedAt: -1
        });

        // Formulation trial indexes
        await formulationTrialsCol.createIndex({
        userId: 1,
        updatedAt: -1
        });

        server.listen(PORT, () => {
            console.log(
                `Concrete Technology Tools running on port ${PORT}`
            );
        });

    } catch (err) {
        console.error(
            'Failed to connect to database:',
            err
        );

        process.exit(1);
    }
}

start();
