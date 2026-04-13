const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
const DATA_DIR = path.join(__dirname, 'data');
const NOTES_FILE = path.join(DATA_DIR, 'notes.json');
const FILES_META = path.join(DATA_DIR, 'files_meta.json');
const FILES_DIR = path.join(DATA_DIR, 'files');
const CONFIG_FILE = path.join(DATA_DIR, 'config.json');

// ── INIT DATA DIR ─────────────────────────────────────
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(FILES_DIR)) fs.mkdirSync(FILES_DIR, { recursive: true });
if (!fs.existsSync(NOTES_FILE)) fs.writeFileSync(NOTES_FILE, '[]');
if (!fs.existsSync(FILES_META)) fs.writeFileSync(FILES_META, '[]');

if (!fs.existsSync(CONFIG_FILE)) {
  const serverSecret = crypto.randomBytes(32).toString('hex');
  const defaultHash = hmacHash('admin', serverSecret);
  fs.writeFileSync(CONFIG_FILE, JSON.stringify({ passwordHash: defaultHash, serverSecret }));
}

// Migrate older configs that lack serverSecret
(function migrateConfig() {
  const config = JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8'));
  if (!config.serverSecret) {
    config.serverSecret = crypto.randomBytes(32).toString('hex');
    fs.writeFileSync(CONFIG_FILE, JSON.stringify(config));
  }
})();

// ── SECURITY HEADERS ──────────────────────────────────
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  next();
});

// ── MIDDLEWARE ─────────────────────────────────────────
app.use(express.json({ limit: '50mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// ── HELPERS ───────────────────────────────────────────
function hmacHash(pw, secret) {
  return crypto.createHmac('sha256', secret).update(pw).digest('hex');
}
function plainHash(pw) {
  return crypto.createHash('sha256').update(pw).digest('hex');
}
function safeEqual(a, b) {
  const bufA = Buffer.from(a, 'hex');
  const bufB = Buffer.from(b, 'hex');
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}
function getConfig() { return JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8')); }
function getNotes() { return JSON.parse(fs.readFileSync(NOTES_FILE, 'utf8')); }
function getFilesMeta() { return JSON.parse(fs.readFileSync(FILES_META, 'utf8')); }
function sanitizeExt(name) {
  const ext = path.extname(name);
  return ext.replace(/[^a-zA-Z0-9.]/g, '');
}

// ── RATE LIMITING ─────────────────────────────────────
const loginAttempts = new Map();
function checkRateLimit(ip) {
  const now = Date.now();
  const record = loginAttempts.get(ip);
  if (!record || now > record.resetTime) {
    loginAttempts.set(ip, { count: 1, resetTime: now + 60000 });
    return true;
  }
  if (record.count >= 5) return false;
  record.count++;
  return true;
}
// Cleanup old rate limit entries every 5 min
setInterval(() => {
  const now = Date.now();
  for (const [ip, r] of loginAttempts) {
    if (now > r.resetTime) loginAttempts.delete(ip);
  }
}, 5 * 60 * 1000);

// ── SESSION (token → { created }) ────────────────────
const sessions = new Map();
const SESSION_MAX_AGE = 24 * 60 * 60 * 1000;

function authMiddleware(req, res, next) {
  const token = req.headers['x-auth-token'];
  if (!token || !sessions.has(token)) {
    return res.status(401).json({ error: 'Nicht angemeldet' });
  }
  const session = sessions.get(token);
  if (Date.now() - session.created > SESSION_MAX_AGE) {
    sessions.delete(token);
    return res.status(401).json({ error: 'Sitzung abgelaufen' });
  }
  next();
}

// Cleanup expired sessions every hour
setInterval(() => {
  const now = Date.now();
  for (const [token, s] of sessions) {
    if (now - s.created > SESSION_MAX_AGE) sessions.delete(token);
  }
}, 60 * 60 * 1000);

// ── AUTH ROUTES ───────────────────────────────────────
app.post('/api/login', (req, res) => {
  const ip = req.ip || req.connection.remoteAddress;
  if (!checkRateLimit(ip)) {
    return res.status(429).json({ error: 'Zu viele Versuche. Bitte warte eine Minute.' });
  }

  const { password } = req.body;
  if (!password) return res.status(400).json({ error: 'Kein Passwort' });

  const config = getConfig();
  let match = false;

  // Try HMAC hash first (new method)
  if (config.serverSecret) {
    const hashed = hmacHash(password, config.serverSecret);
    match = safeEqual(hashed, config.passwordHash);
  }

  // Fallback: try plain SHA-256 (old method) and auto-migrate
  if (!match) {
    const oldHash = plainHash(password);
    if (safeEqual(oldHash, config.passwordHash)) {
      match = true;
      // Migrate to HMAC
      if (!config.serverSecret) {
        config.serverSecret = crypto.randomBytes(32).toString('hex');
      }
      config.passwordHash = hmacHash(password, config.serverSecret);
      fs.writeFileSync(CONFIG_FILE, JSON.stringify(config));
    }
  }

  if (!match) {
    return res.status(401).json({ error: 'Falsches Passwort' });
  }

  const token = crypto.randomBytes(32).toString('hex');
  sessions.set(token, { created: Date.now() });
  res.json({ token });
});

app.post('/api/logout', (req, res) => {
  const token = req.headers['x-auth-token'];
  sessions.delete(token);
  res.json({ ok: true });
});

app.post('/api/change-password', authMiddleware, (req, res) => {
  const { currentPassword, newPassword } = req.body;
  const config = getConfig();

  // Verify current password
  let currentMatch = false;
  if (config.serverSecret) {
    currentMatch = safeEqual(hmacHash(currentPassword, config.serverSecret), config.passwordHash);
  }
  if (!currentMatch) {
    currentMatch = safeEqual(plainHash(currentPassword), config.passwordHash);
  }
  if (!currentMatch) {
    return res.status(401).json({ error: 'Aktuelles Passwort falsch' });
  }

  if (!newPassword || newPassword.length < 6) {
    return res.status(400).json({ error: 'Passwort muss mind. 6 Zeichen haben' });
  }

  // New secret + hash
  config.serverSecret = crypto.randomBytes(32).toString('hex');
  config.passwordHash = hmacHash(newPassword, config.serverSecret);
  fs.writeFileSync(CONFIG_FILE, JSON.stringify(config));

  // Invalidate all sessions
  sessions.clear();
  res.json({ ok: true });
});

// ── NOTES ROUTES ──────────────────────────────────────
app.get('/api/notes', authMiddleware, (req, res) => {
  res.json(getNotes());
});

app.post('/api/notes', authMiddleware, (req, res) => {
  const notes = getNotes();
  const note = {
    id: crypto.randomBytes(8).toString('hex'),
    title: req.body.title || '',
    body: req.body.body || '',
    pinned: false,
    color: null,
    trashed: false,
    category: '',
    created: Date.now(),
    updated: Date.now()
  };
  notes.unshift(note);
  fs.writeFileSync(NOTES_FILE, JSON.stringify(notes));
  res.json(note);
});

app.put('/api/notes/:id', authMiddleware, (req, res) => {
  const notes = getNotes();
  const idx = notes.findIndex(n => n.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Nicht gefunden' });

  const allowed = ['title', 'body', 'pinned', 'color', 'trashed', 'category'];
  const updates = {};
  for (const key of allowed) {
    if (req.body[key] !== undefined) updates[key] = req.body[key];
  }
  notes[idx] = { ...notes[idx], ...updates, updated: Date.now() };
  fs.writeFileSync(NOTES_FILE, JSON.stringify(notes));
  res.json(notes[idx]);
});

app.delete('/api/notes/:id', authMiddleware, (req, res) => {
  const notes = getNotes().filter(n => n.id !== req.params.id);
  fs.writeFileSync(NOTES_FILE, JSON.stringify(notes));
  res.json({ ok: true });
});

// ── FILES ROUTES ──────────────────────────────────────
app.get('/api/files', authMiddleware, (req, res) => {
  res.json(getFilesMeta());
});

app.post('/api/files', authMiddleware, (req, res) => {
  const { name, type, size, data } = req.body;
  if (!data || !name) return res.status(400).json({ error: 'Fehlende Daten' });

  const id = crypto.randomBytes(8).toString('hex');
  const ext = sanitizeExt(name);
  const filePath = path.join(FILES_DIR, id + ext);

  // Path traversal check
  const resolved = path.resolve(filePath);
  if (!resolved.startsWith(path.resolve(FILES_DIR))) {
    return res.status(400).json({ error: 'Ungueltiger Dateiname' });
  }

  const base64 = data.replace(/^data:[^;]+;base64,/, '');
  fs.writeFileSync(filePath, Buffer.from(base64, 'base64'));

  const meta = getFilesMeta();
  const entry = { id, name, type, size, ext, added: Date.now() };
  meta.push(entry);
  fs.writeFileSync(FILES_META, JSON.stringify(meta));
  res.json(entry);
});

app.get('/api/files/:id/download', authMiddleware, (req, res) => {
  const meta = getFilesMeta().find(f => f.id === req.params.id);
  if (!meta) return res.status(404).json({ error: 'Nicht gefunden' });
  const filePath = path.resolve(path.join(FILES_DIR, meta.id + meta.ext));
  if (!filePath.startsWith(path.resolve(FILES_DIR))) return res.status(400).json({ error: 'Ungueltig' });
  res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(meta.name)}"`);
  res.setHeader('Content-Type', meta.type || 'application/octet-stream');
  res.sendFile(filePath);
});

app.get('/api/files/:id/preview', authMiddleware, (req, res) => {
  const meta = getFilesMeta().find(f => f.id === req.params.id);
  if (!meta) return res.status(404).json({ error: 'Nicht gefunden' });
  if (!meta.type || !meta.type.startsWith('image/')) {
    return res.status(400).json({ error: 'Keine Bilddatei' });
  }
  const filePath = path.resolve(path.join(FILES_DIR, meta.id + meta.ext));
  if (!filePath.startsWith(path.resolve(FILES_DIR))) return res.status(400).json({ error: 'Ungueltig' });
  res.setHeader('Content-Type', meta.type);
  res.setHeader('Cache-Control', 'private, max-age=3600');
  res.sendFile(filePath);
});

app.delete('/api/files/:id', authMiddleware, (req, res) => {
  const meta = getFilesMeta();
  const entry = meta.find(f => f.id === req.params.id);
  if (!entry) return res.status(404).json({ error: 'Nicht gefunden' });
  const filePath = path.resolve(path.join(FILES_DIR, entry.id + entry.ext));
  if (filePath.startsWith(path.resolve(FILES_DIR)) && fs.existsSync(filePath)) {
    fs.unlinkSync(filePath);
  }
  fs.writeFileSync(FILES_META, JSON.stringify(meta.filter(f => f.id !== req.params.id)));
  res.json({ ok: true });
});

// ── CLEAR ALL ─────────────────────────────────────────
app.delete('/api/all', authMiddleware, (req, res) => {
  fs.writeFileSync(NOTES_FILE, '[]');
  const meta = getFilesMeta();
  meta.forEach(f => {
    const p = path.resolve(path.join(FILES_DIR, f.id + f.ext));
    if (p.startsWith(path.resolve(FILES_DIR)) && fs.existsSync(p)) fs.unlinkSync(p);
  });
  fs.writeFileSync(FILES_META, '[]');
  res.json({ ok: true });
});

// ── START ─────────────────────────────────────────────
app.listen(PORT, () => console.log(`MeinVault laeuft auf Port ${PORT}`));
