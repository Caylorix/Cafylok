const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
const DATA_DIR = path.join(__dirname, 'data');
const NOTES_FILE = path.join(DATA_DIR, 'notes.json');
const FILES_META = path.join(DATA_DIR, 'files_meta.json');
const FILES_DIR  = path.join(DATA_DIR, 'files');
const CONFIG_FILE = path.join(DATA_DIR, 'config.json');

// ── INIT DATA DIR ──────────────────────────────────────
if (!fs.existsSync(DATA_DIR))  fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(FILES_DIR)) fs.mkdirSync(FILES_DIR, { recursive: true });
if (!fs.existsSync(NOTES_FILE))  fs.writeFileSync(NOTES_FILE, '[]');
if (!fs.existsSync(FILES_META))  fs.writeFileSync(FILES_META, '[]');

// Default password "admin" if not set
if (!fs.existsSync(CONFIG_FILE)) {
  const defaultHash = crypto.createHash('sha256').update('admin').digest('hex');
  fs.writeFileSync(CONFIG_FILE, JSON.stringify({ passwordHash: defaultHash }));
}

// ── MIDDLEWARE ─────────────────────────────────────────
app.use(express.json({ limit: '50mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// ── HELPERS ────────────────────────────────────────────
function hash(pw) { return crypto.createHash('sha256').update(pw).digest('hex'); }
function getConfig() { return JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8')); }
function getNotes()  { return JSON.parse(fs.readFileSync(NOTES_FILE, 'utf8')); }
function getFilesMeta() { return JSON.parse(fs.readFileSync(FILES_META, 'utf8')); }

// ── SESSION (simple token in memory) ──────────────────
const sessions = new Set();
function authMiddleware(req, res, next) {
  const token = req.headers['x-auth-token'];
  if (!token || !sessions.has(token)) return res.status(401).json({ error: 'Nicht angemeldet' });
  next();
}

// ── AUTH ROUTES ────────────────────────────────────────
app.post('/api/login', (req, res) => {
  const { password } = req.body;
  const config = getConfig();
  if (!password) return res.status(400).json({ error: 'Kein Passwort' });
  
  const isFirst = !config.passwordHash;
  if (isFirst) {
    config.passwordHash = hash(password);
    fs.writeFileSync(CONFIG_FILE, JSON.stringify(config));
  }
  
  if (hash(password) !== config.passwordHash) {
    return res.status(401).json({ error: 'Falsches Passwort' });
  }
  
  const token = crypto.randomBytes(32).toString('hex');
  sessions.add(token);
  res.json({ token, isFirst });
});

app.post('/api/logout', (req, res) => {
  const token = req.headers['x-auth-token'];
  sessions.delete(token);
  res.json({ ok: true });
});

app.post('/api/change-password', authMiddleware, (req, res) => {
  const { currentPassword, newPassword } = req.body;
  const config = getConfig();
  if (hash(currentPassword) !== config.passwordHash) {
    return res.status(401).json({ error: 'Aktuelles Passwort falsch' });
  }
  if (!newPassword || newPassword.length < 4) {
    return res.status(400).json({ error: 'Passwort zu kurz' });
  }
  config.passwordHash = hash(newPassword);
  fs.writeFileSync(CONFIG_FILE, JSON.stringify(config));
  res.json({ ok: true });
});

// ── NOTES ROUTES ───────────────────────────────────────
app.get('/api/notes', authMiddleware, (req, res) => {
  res.json(getNotes());
});

app.post('/api/notes', authMiddleware, (req, res) => {
  const notes = getNotes();
  const note = {
    id: crypto.randomBytes(8).toString('hex'),
    title: req.body.title || '',
    body: req.body.body || '',
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
  notes[idx] = { ...notes[idx], ...req.body, updated: Date.now() };
  fs.writeFileSync(NOTES_FILE, JSON.stringify(notes));
  res.json(notes[idx]);
});

app.delete('/api/notes/:id', authMiddleware, (req, res) => {
  const notes = getNotes().filter(n => n.id !== req.params.id);
  fs.writeFileSync(NOTES_FILE, JSON.stringify(notes));
  res.json({ ok: true });
});

// ── FILES ROUTES ───────────────────────────────────────
app.get('/api/files', authMiddleware, (req, res) => {
  res.json(getFilesMeta());
});

app.post('/api/files', authMiddleware, (req, res) => {
  const { name, type, size, data } = req.body;
  if (!data || !name) return res.status(400).json({ error: 'Fehlende Daten' });
  
  const id = crypto.randomBytes(8).toString('hex');
  const ext = path.extname(name);
  const filePath = path.join(FILES_DIR, id + ext);
  
  // data is base64 data URL: "data:mime;base64,XXX"
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
  const filePath = path.join(FILES_DIR, meta.id + meta.ext);
  res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(meta.name)}"`);
  res.setHeader('Content-Type', meta.type || 'application/octet-stream');
  res.sendFile(filePath);
});

app.delete('/api/files/:id', authMiddleware, (req, res) => {
  const meta = getFilesMeta();
  const entry = meta.find(f => f.id === req.params.id);
  if (!entry) return res.status(404).json({ error: 'Nicht gefunden' });
  const filePath = path.join(FILES_DIR, entry.id + entry.ext);
  if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
  fs.writeFileSync(FILES_META, JSON.stringify(meta.filter(f => f.id !== req.params.id)));
  res.json({ ok: true });
});

// ── CLEAR ALL ──────────────────────────────────────────
app.delete('/api/all', authMiddleware, (req, res) => {
  fs.writeFileSync(NOTES_FILE, '[]');
  const meta = getFilesMeta();
  meta.forEach(f => {
    const p = path.join(FILES_DIR, f.id + f.ext);
    if (fs.existsSync(p)) fs.unlinkSync(p);
  });
  fs.writeFileSync(FILES_META, '[]');
  res.json({ ok: true });
});

// ── START ──────────────────────────────────────────────
app.listen(PORT, () => console.log(`MeinVault läuft auf Port ${PORT}`));
