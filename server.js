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
const QUESTS_FILE = path.join(DATA_DIR, 'quests.json');
const FINANCE_FILE = path.join(DATA_DIR, 'finance.json');

// ── INIT DATA DIR ─────────────────────────────────────
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(FILES_DIR)) fs.mkdirSync(FILES_DIR, { recursive: true });
if (!fs.existsSync(NOTES_FILE)) fs.writeFileSync(NOTES_FILE, '[]');
if (!fs.existsSync(FILES_META)) fs.writeFileSync(FILES_META, '[]');
if (!fs.existsSync(QUESTS_FILE)) fs.writeFileSync(QUESTS_FILE, JSON.stringify({
  quests: [],
  stats: { totalXp: 0, level: 1, streak: 0, longestStreak: 0, lastCompletionDate: null, completedCount: 0, failedCount: 0 },
  achievements: []
}));
if (!fs.existsSync(FINANCE_FILE)) fs.writeFileSync(FINANCE_FILE, JSON.stringify({
  accounts: [],
  transactions: [],
  budgets: [],
  goals: [],
  categories: {
    income: ['Gehalt', 'Nebenjob', 'Geschenk', 'Zinsen', 'Sonstiges'],
    expense: ['Miete', 'Lebensmittel', 'Transport', 'Freizeit', 'Gesundheit', 'Abos', 'Kleidung', 'Restaurant', 'Haushalt', 'Bildung', 'Sonstiges']
  },
  settings: { currency: 'EUR', startOfMonth: 1 }
}));

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
function getQuestsData() { return JSON.parse(fs.readFileSync(QUESTS_FILE, 'utf8')); }
function saveQuestsData(d) { fs.writeFileSync(QUESTS_FILE, JSON.stringify(d)); }
function getFinanceData() { return JSON.parse(fs.readFileSync(FINANCE_FILE, 'utf8')); }
function saveFinanceData(d) { fs.writeFileSync(FINANCE_FILE, JSON.stringify(d)); }
function levelFromXp(xp) {
  // Each level needs progressively more XP: level n requires 100*n(n-1)/2 + 100 ≈ quadratic curve
  let lvl = 1;
  let need = 100;
  let acc = 0;
  while (xp >= acc + need) {
    acc += need;
    lvl++;
    need = Math.floor(100 * Math.pow(lvl, 1.35));
  }
  return { level: lvl, currentLevelXp: xp - acc, nextLevelXp: need, totalForLevel: acc };
}
function todayKey() {
  const d = new Date();
  return d.getFullYear() + '-' + String(d.getMonth() + 1).padStart(2, '0') + '-' + String(d.getDate()).padStart(2, '0');
}
function daysBetween(a, b) {
  const d1 = new Date(a); d1.setHours(0,0,0,0);
  const d2 = new Date(b); d2.setHours(0,0,0,0);
  return Math.round((d2 - d1) / 86400000);
}
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

// ── QUESTS ROUTES ─────────────────────────────────────
const XP_BY_DIFFICULTY = { trivial: 10, easy: 25, medium: 60, hard: 120, epic: 250 };

const ACHIEVEMENT_DEFS = [
  { id: 'first_quest', name: 'Erster Schritt', desc: 'Schliesse deine erste Quest ab', icon: '🌱', check: s => s.completedCount >= 1 },
  { id: 'ten_quests', name: 'Abenteurer', desc: '10 Quests abgeschlossen', icon: '⚔️', check: s => s.completedCount >= 10 },
  { id: 'fifty_quests', name: 'Veteran', desc: '50 Quests abgeschlossen', icon: '🛡️', check: s => s.completedCount >= 50 },
  { id: 'hundred_quests', name: 'Legende', desc: '100 Quests abgeschlossen', icon: '👑', check: s => s.completedCount >= 100 },
  { id: 'streak_3', name: 'Auf Kurs', desc: '3 Tage Streak', icon: '🔥', check: s => s.longestStreak >= 3 },
  { id: 'streak_7', name: 'Wochen-Krieger', desc: '7 Tage Streak', icon: '🔥', check: s => s.longestStreak >= 7 },
  { id: 'streak_30', name: 'Unerschuetterlich', desc: '30 Tage Streak', icon: '💎', check: s => s.longestStreak >= 30 },
  { id: 'level_5', name: 'Aufsteiger', desc: 'Erreiche Level 5', icon: '⭐', check: s => s.level >= 5 },
  { id: 'level_10', name: 'Meister', desc: 'Erreiche Level 10', icon: '🌟', check: s => s.level >= 10 },
  { id: 'level_25', name: 'Grossmeister', desc: 'Erreiche Level 25', icon: '✨', check: s => s.level >= 25 },
  { id: 'epic_slayer', name: 'Epic Slayer', desc: 'Schliesse eine Epic-Quest ab', icon: '🐉', check: (s, d) => d.quests.some(q => q.status === 'completed' && q.difficulty === 'epic') },
  { id: 'xp_1000', name: 'Tausendsassa', desc: '1000 XP gesammelt', icon: '💫', check: s => s.totalXp >= 1000 },
  { id: 'xp_5000', name: 'XP Sammler', desc: '5000 XP gesammelt', icon: '💠', check: s => s.totalXp >= 5000 }
];

function recalcStats(data) {
  const s = data.stats;
  const lvlInfo = levelFromXp(s.totalXp);
  s.level = lvlInfo.level;
  s.currentLevelXp = lvlInfo.currentLevelXp;
  s.nextLevelXp = lvlInfo.nextLevelXp;
  s.totalForLevel = lvlInfo.totalForLevel;
  // Achievements
  data.achievements = data.achievements || [];
  for (const a of ACHIEVEMENT_DEFS) {
    if (!data.achievements.find(x => x.id === a.id) && a.check(s, data)) {
      data.achievements.push({ id: a.id, unlockedAt: Date.now() });
    }
  }
}

app.get('/api/quests', authMiddleware, (req, res) => {
  const data = getQuestsData();
  recalcStats(data);
  saveQuestsData(data);
  res.json({
    quests: data.quests,
    stats: data.stats,
    achievements: data.achievements,
    achievementDefs: ACHIEVEMENT_DEFS.map(a => ({ id: a.id, name: a.name, desc: a.desc, icon: a.icon }))
  });
});

app.post('/api/quests', authMiddleware, (req, res) => {
  const data = getQuestsData();
  const b = req.body || {};
  const diff = ['trivial','easy','medium','hard','epic'].includes(b.difficulty) ? b.difficulty : 'easy';
  const quest = {
    id: crypto.randomBytes(8).toString('hex'),
    title: String(b.title || '').slice(0, 200),
    description: String(b.description || '').slice(0, 2000),
    category: String(b.category || 'Allgemein').slice(0, 50),
    difficulty: diff,
    xp: b.xp || XP_BY_DIFFICULTY[diff],
    priority: ['low','medium','high'].includes(b.priority) ? b.priority : 'medium',
    deadline: b.deadline || null,
    recurring: ['none','daily','weekly','monthly'].includes(b.recurring) ? b.recurring : 'none',
    subtasks: Array.isArray(b.subtasks) ? b.subtasks.map(s => ({
      id: crypto.randomBytes(4).toString('hex'),
      text: String(s.text || '').slice(0, 200),
      done: !!s.done
    })) : [],
    status: 'active',
    tags: Array.isArray(b.tags) ? b.tags.slice(0, 10).map(t => String(t).slice(0, 30)) : [],
    created: Date.now(),
    updated: Date.now(),
    completedAt: null
  };
  data.quests.unshift(quest);
  recalcStats(data);
  saveQuestsData(data);
  res.json(quest);
});

app.put('/api/quests/:id', authMiddleware, (req, res) => {
  const data = getQuestsData();
  const idx = data.quests.findIndex(q => q.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Nicht gefunden' });
  const allowed = ['title','description','category','difficulty','xp','priority','deadline','recurring','subtasks','tags'];
  const updates = {};
  for (const k of allowed) if (req.body[k] !== undefined) updates[k] = req.body[k];
  if (updates.difficulty && !updates.xp) updates.xp = XP_BY_DIFFICULTY[updates.difficulty] || data.quests[idx].xp;
  data.quests[idx] = { ...data.quests[idx], ...updates, updated: Date.now() };
  saveQuestsData(data);
  res.json(data.quests[idx]);
});

app.post('/api/quests/:id/complete', authMiddleware, (req, res) => {
  const data = getQuestsData();
  const idx = data.quests.findIndex(q => q.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Nicht gefunden' });
  const q = data.quests[idx];
  if (q.status === 'completed') return res.json({ quest: q, stats: data.stats });

  q.status = 'completed';
  q.completedAt = Date.now();
  q.updated = Date.now();

  // Update stats
  const s = data.stats;
  s.totalXp = (s.totalXp || 0) + (q.xp || 0);
  s.completedCount = (s.completedCount || 0) + 1;

  // Streak logic
  const today = todayKey();
  if (s.lastCompletionDate) {
    const diff = daysBetween(s.lastCompletionDate, today);
    if (diff === 0) { /* same day, keep streak */ }
    else if (diff === 1) { s.streak = (s.streak || 0) + 1; }
    else { s.streak = 1; }
  } else {
    s.streak = 1;
  }
  s.lastCompletionDate = today;
  if ((s.streak || 0) > (s.longestStreak || 0)) s.longestStreak = s.streak;

  // If recurring: create a fresh copy
  let nextQuest = null;
  if (q.recurring && q.recurring !== 'none') {
    nextQuest = {
      ...q,
      id: crypto.randomBytes(8).toString('hex'),
      status: 'active',
      completedAt: null,
      subtasks: (q.subtasks || []).map(st => ({ ...st, id: crypto.randomBytes(4).toString('hex'), done: false })),
      created: Date.now(),
      updated: Date.now()
    };
    // Next deadline (optional)
    if (q.deadline) {
      const d = new Date(q.deadline);
      if (q.recurring === 'daily') d.setDate(d.getDate() + 1);
      else if (q.recurring === 'weekly') d.setDate(d.getDate() + 7);
      else if (q.recurring === 'monthly') d.setMonth(d.getMonth() + 1);
      nextQuest.deadline = d.toISOString().slice(0, 10);
    }
    data.quests.unshift(nextQuest);
  }

  recalcStats(data);
  saveQuestsData(data);
  res.json({ quest: q, stats: data.stats, achievements: data.achievements, nextQuest });
});

app.post('/api/quests/:id/uncomplete', authMiddleware, (req, res) => {
  const data = getQuestsData();
  const idx = data.quests.findIndex(q => q.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Nicht gefunden' });
  const q = data.quests[idx];
  if (q.status !== 'completed') return res.json({ quest: q, stats: data.stats });
  q.status = 'active';
  q.completedAt = null;
  q.updated = Date.now();
  const s = data.stats;
  s.totalXp = Math.max(0, (s.totalXp || 0) - (q.xp || 0));
  s.completedCount = Math.max(0, (s.completedCount || 0) - 1);
  recalcStats(data);
  saveQuestsData(data);
  res.json({ quest: q, stats: data.stats });
});

app.delete('/api/quests/:id', authMiddleware, (req, res) => {
  const data = getQuestsData();
  data.quests = data.quests.filter(q => q.id !== req.params.id);
  saveQuestsData(data);
  res.json({ ok: true });
});

// ── FINANCE ROUTES ────────────────────────────────────
app.get('/api/finance', authMiddleware, (req, res) => {
  res.json(getFinanceData());
});

function computeBalance(accountId, transactions) {
  return transactions
    .filter(t => t.accountId === accountId)
    .reduce((sum, t) => sum + (t.type === 'income' ? t.amount : -t.amount), 0);
}

// Accounts
app.post('/api/finance/accounts', authMiddleware, (req, res) => {
  const data = getFinanceData();
  const b = req.body || {};
  const acc = {
    id: crypto.randomBytes(8).toString('hex'),
    name: String(b.name || 'Konto').slice(0, 60),
    type: ['checking','savings','cash','credit','investment'].includes(b.type) ? b.type : 'checking',
    initialBalance: Number(b.initialBalance) || 0,
    color: b.color || '#6c5ce7',
    icon: b.icon || '💳',
    created: Date.now()
  };
  data.accounts.push(acc);
  saveFinanceData(data);
  res.json(acc);
});
app.put('/api/finance/accounts/:id', authMiddleware, (req, res) => {
  const data = getFinanceData();
  const idx = data.accounts.findIndex(a => a.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Nicht gefunden' });
  const allowed = ['name','type','initialBalance','color','icon'];
  const updates = {};
  for (const k of allowed) if (req.body[k] !== undefined) updates[k] = req.body[k];
  data.accounts[idx] = { ...data.accounts[idx], ...updates };
  saveFinanceData(data);
  res.json(data.accounts[idx]);
});
app.delete('/api/finance/accounts/:id', authMiddleware, (req, res) => {
  const data = getFinanceData();
  data.accounts = data.accounts.filter(a => a.id !== req.params.id);
  data.transactions = data.transactions.filter(t => t.accountId !== req.params.id);
  saveFinanceData(data);
  res.json({ ok: true });
});

// Transactions
app.post('/api/finance/transactions', authMiddleware, (req, res) => {
  const data = getFinanceData();
  const b = req.body || {};
  const tx = {
    id: crypto.randomBytes(8).toString('hex'),
    type: b.type === 'income' ? 'income' : 'expense',
    amount: Math.abs(Number(b.amount) || 0),
    category: String(b.category || 'Sonstiges').slice(0, 50),
    accountId: b.accountId || null,
    description: String(b.description || '').slice(0, 200),
    date: b.date || new Date().toISOString().slice(0, 10),
    recurring: ['none','daily','weekly','monthly','yearly'].includes(b.recurring) ? b.recurring : 'none',
    tags: Array.isArray(b.tags) ? b.tags.slice(0, 10).map(t => String(t).slice(0, 30)) : [],
    created: Date.now()
  };
  data.transactions.unshift(tx);
  saveFinanceData(data);
  res.json(tx);
});
app.put('/api/finance/transactions/:id', authMiddleware, (req, res) => {
  const data = getFinanceData();
  const idx = data.transactions.findIndex(t => t.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Nicht gefunden' });
  const allowed = ['type','amount','category','accountId','description','date','recurring','tags'];
  const updates = {};
  for (const k of allowed) if (req.body[k] !== undefined) updates[k] = req.body[k];
  if (updates.amount !== undefined) updates.amount = Math.abs(Number(updates.amount) || 0);
  data.transactions[idx] = { ...data.transactions[idx], ...updates };
  saveFinanceData(data);
  res.json(data.transactions[idx]);
});
app.delete('/api/finance/transactions/:id', authMiddleware, (req, res) => {
  const data = getFinanceData();
  data.transactions = data.transactions.filter(t => t.id !== req.params.id);
  saveFinanceData(data);
  res.json({ ok: true });
});

// Budgets
app.post('/api/finance/budgets', authMiddleware, (req, res) => {
  const data = getFinanceData();
  const b = req.body || {};
  const bud = {
    id: crypto.randomBytes(8).toString('hex'),
    category: String(b.category || 'Sonstiges').slice(0, 50),
    limit: Number(b.limit) || 0,
    period: ['monthly','weekly'].includes(b.period) ? b.period : 'monthly',
    color: b.color || '#6c5ce7',
    created: Date.now()
  };
  data.budgets.push(bud);
  saveFinanceData(data);
  res.json(bud);
});
app.put('/api/finance/budgets/:id', authMiddleware, (req, res) => {
  const data = getFinanceData();
  const idx = data.budgets.findIndex(x => x.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Nicht gefunden' });
  const allowed = ['category','limit','period','color'];
  const updates = {};
  for (const k of allowed) if (req.body[k] !== undefined) updates[k] = req.body[k];
  if (updates.limit !== undefined) updates.limit = Number(updates.limit) || 0;
  data.budgets[idx] = { ...data.budgets[idx], ...updates };
  saveFinanceData(data);
  res.json(data.budgets[idx]);
});
app.delete('/api/finance/budgets/:id', authMiddleware, (req, res) => {
  const data = getFinanceData();
  data.budgets = data.budgets.filter(x => x.id !== req.params.id);
  saveFinanceData(data);
  res.json({ ok: true });
});

// Goals
app.post('/api/finance/goals', authMiddleware, (req, res) => {
  const data = getFinanceData();
  const b = req.body || {};
  const g = {
    id: crypto.randomBytes(8).toString('hex'),
    name: String(b.name || 'Sparziel').slice(0, 80),
    target: Number(b.target) || 0,
    current: Number(b.current) || 0,
    deadline: b.deadline || null,
    icon: b.icon || '🎯',
    color: b.color || '#10b981',
    created: Date.now()
  };
  data.goals.push(g);
  saveFinanceData(data);
  res.json(g);
});
app.put('/api/finance/goals/:id', authMiddleware, (req, res) => {
  const data = getFinanceData();
  const idx = data.goals.findIndex(x => x.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Nicht gefunden' });
  const allowed = ['name','target','current','deadline','icon','color'];
  const updates = {};
  for (const k of allowed) if (req.body[k] !== undefined) updates[k] = req.body[k];
  if (updates.target !== undefined) updates.target = Number(updates.target) || 0;
  if (updates.current !== undefined) updates.current = Number(updates.current) || 0;
  data.goals[idx] = { ...data.goals[idx], ...updates };
  saveFinanceData(data);
  res.json(data.goals[idx]);
});
app.delete('/api/finance/goals/:id', authMiddleware, (req, res) => {
  const data = getFinanceData();
  data.goals = data.goals.filter(x => x.id !== req.params.id);
  saveFinanceData(data);
  res.json({ ok: true });
});

// Settings
app.put('/api/finance/settings', authMiddleware, (req, res) => {
  const data = getFinanceData();
  const b = req.body || {};
  if (b.currency) data.settings.currency = String(b.currency).slice(0, 8);
  if (b.startOfMonth !== undefined) data.settings.startOfMonth = Math.min(28, Math.max(1, Number(b.startOfMonth) || 1));
  saveFinanceData(data);
  res.json(data.settings);
});

// Custom categories
app.put('/api/finance/categories', authMiddleware, (req, res) => {
  const data = getFinanceData();
  const b = req.body || {};
  if (Array.isArray(b.income)) data.categories.income = b.income.slice(0, 40).map(c => String(c).slice(0, 50));
  if (Array.isArray(b.expense)) data.categories.expense = b.expense.slice(0, 40).map(c => String(c).slice(0, 50));
  saveFinanceData(data);
  res.json(data.categories);
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
  fs.writeFileSync(QUESTS_FILE, JSON.stringify({
    quests: [],
    stats: { totalXp: 0, level: 1, streak: 0, longestStreak: 0, lastCompletionDate: null, completedCount: 0, failedCount: 0 },
    achievements: []
  }));
  fs.writeFileSync(FINANCE_FILE, JSON.stringify({
    accounts: [], transactions: [], budgets: [], goals: [],
    categories: {
      income: ['Gehalt', 'Nebenjob', 'Geschenk', 'Zinsen', 'Sonstiges'],
      expense: ['Miete', 'Lebensmittel', 'Transport', 'Freizeit', 'Gesundheit', 'Abos', 'Kleidung', 'Restaurant', 'Haushalt', 'Bildung', 'Sonstiges']
    },
    settings: { currency: 'EUR', startOfMonth: 1 }
  }));
  res.json({ ok: true });
});

// ── START ─────────────────────────────────────────────
app.listen(PORT, () => console.log(`MeinVault laeuft auf Port ${PORT}`));
