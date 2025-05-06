// api-server/index.js
const express  = require('express');
const jwt      = require('jsonwebtoken');
const cookie   = require('cookie-parser');
const body     = require('body-parser');
const cors     = require('cors');
const path     = require('path');

const SECRET = 'replace-me';
const app    = express();

app.use(cors({ origin: 'http://127.0.0.1:5173', credentials: true }));
app.use(body.json());
app.use(cookie());

/* ---------- NTLM / Kerberos (optional) --------------------------- */
let NodeSSPI;
if (process.platform === 'win32') {
    try { NodeSSPI = require('node-sspi'); } catch {/* noop */ }
}
if (NodeSSPI) {
    app.use((req, res, next) => {
        if (!/^Negotiate|NTLM/i.test(req.headers.authorization || '')) return next();
        new NodeSSPI().authenticate(req, res, err => {
            if (err) return next(err);
            if (req.connection.user) req.identity = req.connection.user; // "CORP\\John"
            next();
        });
    });
}

/* ---------- silent cookie --------------------------------------- */
app.get('/auth/silent', (req, res) => {
    const sid = req.cookies.sid;
    if (!sid) return res.sendStatus(401);
    try {
        const { sub } = jwt.verify(sid, SECRET);
        return res.json({ token: sid, user: sub });
    } catch { return res.sendStatus(401); }
});

/* ---------- interactive login (mock) ---------------------------- */
app.post('/auth/login', (req, res) => {
    const { email, password } = req.body;
    if (email === 'demo@example.com' && password === 'pass') {
        const token = jwt.sign({ sub: 'testUser' }, SECRET, { expiresIn: '1h' });
        res.cookie('sid', token, { httpOnly: true, sameSite: 'lax' });
        return res.json({ token });
    }
    res.sendStatus(401);
});

/* ---------- guard ----------------------------------------------- */
function ensureAuth(req, res, next) {
    if (req.identity) return next();                            // NTLM

    const m = (req.headers.authorization || '').match(/^Bearer (.+)$/);
    if (m) {
        try { req.identity = jwt.verify(m[1], SECRET).sub; return next(); }
        catch {/* fall through */}
    }

    res.status(401)
        .set('WWW-Authenticate', NodeSSPI ? 'Negotiate' : '')
        .json({ interactive: '/static/login.html' });
}

/* ---------- protected user endpoint ----------------------------- */
app.get('/api/user', ensureAuth, (req, res) => {
    res.json({ user: req.identity });          // "CORP\\John" | "testUser"
});

/* ---------- static login page ----------------------------------- */
app.use('/static', express.static(path.join(__dirname, 'static')));

app.listen(3001, () =>
    console.log(`API listening on http://127.0.0.1:3001  (${process.platform})`));
