const path = require('path');
const fs = require('fs');
const express = require('express');
const cors = require('cors');
const fetch = require('node-fetch');
const crypto = require('crypto');
const sqlite3 = require('sqlite3').verbose();
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3020;
const BASE_URL =
  process.env.DASHSCOPE_BASE_URL || 'https://dashscope.aliyuncs.com/compatible-mode/v1';
const API_KEY = process.env.DASHSCOPE_API_KEY;
const TEXT_MODEL = process.env.TEXT_MODEL || 'qwen-plus';
const VISION_MODEL = process.env.VISION_MODEL || 'qwen-vl-plus';
const PROMPTS_DIR = path.join(__dirname, 'public', 'prompts');
const SCENARIO_PROMPTS = {
  card: 'CARD_SCENARIO.txt',
  moment: 'CARD_SCENARIO.txt'
};
const PROMPT_PATH = path.join(PROMPTS_DIR, SCENARIO_PROMPTS.card);
const DATA_DIR = path.join(__dirname, 'data');
const DB_FILE = path.join(DATA_DIR, 'auth.db');
const AUTH_SECRET = process.env.AUTH_SECRET || 'moments-dev-secret';
const TOKEN_TTL_SECONDS = 7 * 24 * 60 * 60;
const DEFAULT_TEMP_PASSWORD = '123456';
let db;

if (!API_KEY) {
  console.warn('DASHSCOPE_API_KEY is missing. Set it in .env before running the server.');
}

app.use(cors());
app.use(
  express.json({
    limit: '10mb'
  })
);
app.use((err, req, res, next) => {
  if (err instanceof SyntaxError && err.status === 400 && 'body' in err) {
    console.error('JSON parse error:', err.message);
    return res.status(400).json({ error: 'Invalid request body.' });
  }
  next(err);
});
app.use(express.static(path.join(__dirname, 'public')));
app.use('/locales', express.static(path.join(__dirname, 'locales')));

function ensureDataFiles() {
  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
  }
}

function initDb() {
  ensureDataFiles();
  db = new sqlite3.Database(DB_FILE);
  db.serialize(() => {
    db.run(
      `CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        phone TEXT UNIQUE NOT NULL,
        nickname TEXT NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'normal',
        credits INTEGER NOT NULL DEFAULT 5,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      )`
    );
    db.run(
      `CREATE TABLE IF NOT EXISTS activation_codes (
        id TEXT PRIMARY KEY,
        code TEXT UNIQUE NOT NULL,
        batch_id TEXT,
        total_uses INTEGER NOT NULL,
        used_uses INTEGER NOT NULL DEFAULT 0,
        status TEXT NOT NULL DEFAULT 'unused',
        expired_at TEXT,
        created_by TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      )`
    );
    db.run(
      `CREATE TABLE IF NOT EXISTS activation_logs (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        code_id TEXT NOT NULL,
        added_uses INTEGER NOT NULL,
        created_at TEXT NOT NULL
      )`
    );
    db.run(
      `CREATE TABLE IF NOT EXISTS analysis_logs (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        type TEXT NOT NULL,
        created_at TEXT NOT NULL,
        duration_ms INTEGER
      )`
    );
  });
}

function dbGet(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
      if (err) return reject(err);
      resolve(row);
    });
  });
}

function dbRun(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function (err) {
      if (err) return reject(err);
      resolve(this);
    });
  });
}

async function runInTransaction(fn) {
  await dbRun('BEGIN');
  try {
    const result = await fn();
    await dbRun('COMMIT');
    return result;
  } catch (err) {
    try {
      await dbRun('ROLLBACK');
    } catch (rollbackErr) {
      console.error('Transaction rollback failed:', rollbackErr.message);
    }
    throw err;
  }
}

function randomCode(len = 18) {
  return crypto.randomBytes(Math.ceil(len / 2)).toString('hex').slice(0, len);
}

async function ensureColumn(table, column, definition) {
  const cols = await new Promise((resolve, reject) => {
    db.all(`PRAGMA table_info(${table})`, [], (err, rows) => {
      if (err) return reject(err);
      resolve(rows || []);
    });
  });
  const exists = cols.some((c) => c.name === column);
  if (!exists) {
    await dbRun(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`);
  }
}

async function migrateSchema() {
  await ensureColumn('users', 'role', "TEXT NOT NULL DEFAULT 'normal'");
  await ensureColumn('users', 'credits', 'INTEGER NOT NULL DEFAULT 5');
  await ensureColumn('users', 'updated_at', 'TEXT NOT NULL DEFAULT ""');
  await dbRun(`UPDATE users SET role = COALESCE(role, 'normal') WHERE role IS NULL OR role = ''`);
  await dbRun(`UPDATE users SET credits = COALESCE(credits, 5) WHERE credits IS NULL`);
  await dbRun(
    `UPDATE users SET updated_at = CASE WHEN updated_at IS NULL OR updated_at = '' THEN created_at ELSE updated_at END`
  );
}

async function deleteUserCompletely(userId) {
  await runInTransaction(async () => {
    await dbRun('DELETE FROM analysis_logs WHERE user_id = ?', [userId]);
    await dbRun('DELETE FROM activation_logs WHERE user_id = ?', [userId]);
    await dbRun('DELETE FROM users WHERE id = ?', [userId]);
  });
}

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const derived = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${derived}`;
}

function verifyPassword(password, stored) {
  if (!stored || !stored.includes(':')) return false;
  const [salt, hash] = stored.split(':');
  const derived = crypto.scryptSync(password, salt, 64).toString('hex');
  return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(derived, 'hex'));
}

function base64Url(input) {
  return Buffer.from(JSON.stringify(input))
    .toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

function signToken(payload) {
  const header = { alg: 'HS256', typ: 'JWT' };
  const exp = Math.floor(Date.now() / 1000) + TOKEN_TTL_SECONDS;
  const fullPayload = { ...payload, exp };
  const headerPart = base64Url(header);
  const payloadPart = base64Url(fullPayload);
  const data = `${headerPart}.${payloadPart}`;
  const signature = crypto
    .createHmac('sha256', AUTH_SECRET)
    .update(data)
    .digest('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
  return `${data}.${signature}`;
}

function verifyToken(token) {
  if (!token || typeof token !== 'string' || !token.includes('.')) return null;
  const [headerPart, payloadPart, signature] = token.split('.');
  const data = `${headerPart}.${payloadPart}`;
  const expectedSig = crypto
    .createHmac('sha256', AUTH_SECRET)
    .update(data)
    .digest('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
  if (!crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expectedSig))) return null;
  try {
    const payload = JSON.parse(Buffer.from(payloadPart, 'base64').toString('utf8'));
    if (!payload.exp || payload.exp < Math.floor(Date.now() / 1000)) return null;
    return payload;
  } catch (err) {
    return null;
  }
}

function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : '';
  const payload = verifyToken(token);
  if (!payload || !payload.sub) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  req.user = payload;
  next();
}

function requireRole(roles) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Unauthorized' });
    }
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    next();
  };
}

function normalizeContent(content) {
  if (typeof content === 'string') {
    return content;
  }
  if (Array.isArray(content)) {
    return content
      .map((part) => {
        if (typeof part === 'string') return part;
        if (part && typeof part === 'object' && typeof part.text === 'string') return part.text;
        return '';
      })
      .filter(Boolean)
      .join('\n')
      .trim();
  }
  return '';
}

function readPrompt() {
  try {
    if (!fs.existsSync(PROMPT_PATH)) return '';
    return fs.readFileSync(PROMPT_PATH, 'utf8').trim();
  } catch (err) {
    console.error('Read prompt error:', err.message);
    return '';
  }
}

function readScenarioPrompt(scenario) {
  const fileName = SCENARIO_PROMPTS[scenario];
  if (fileName) {
    const scenarioPath = path.join(PROMPTS_DIR, fileName);
    try {
      if (fs.existsSync(scenarioPath)) {
        return fs.readFileSync(scenarioPath, 'utf8').trim();
      }
    } catch (err) {
      console.error(`Read scenario prompt error (${scenario}):`, err.message);
    }
  }
  return readPrompt();
}

async function callDashScopeChat(model, messages) {
  const url = `${BASE_URL}/chat/completions`;
  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${API_KEY}`
    },
    body: JSON.stringify({
      model,
      messages
    })
  });

  const result = await response.json();
  if (!response.ok) {
    const errorMessage = result?.error?.message || 'Unexpected response from DashScope';
    throw new Error(errorMessage);
  }

  const reply = normalizeContent(result?.choices?.[0]?.message?.content);
  if (!reply) {
    throw new Error('No reply content returned from DashScope.');
  }
  return reply;
}

app.post('/auth/register', async (req, res) => {
  const { phone, password, nickname } = req.body || {};
  if (!/^\d{11}$/.test(phone || '')) {
    return res.status(400).json({ error: 'Phone number must be 11 digits.' });
  }
  if (!password || password.length < 6) {
    return res.status(400).json({ error: 'Password must be at least 6 characters.' });
  }
  const safeNickname =
    typeof nickname === 'string' && nickname.trim() ? nickname.trim() : `user-${phone.slice(-4)}`;
  try {
    const existing = await dbGet('SELECT id FROM users WHERE phone = ?', [phone]);
    if (existing) {
      return res.status(400).json({ error: 'Phone number already registered.' });
    }
    const id = crypto.randomUUID ? crypto.randomUUID() : String(Date.now());
    const now = new Date().toISOString();
    const passwordHash = hashPassword(password);
    await dbRun(
      'INSERT INTO users (id, phone, nickname, password_hash, role, credits, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
      [id, phone, safeNickname, passwordHash, 'normal', 5, now, now]
    );
    const token = signToken({ sub: id, phone, nickname: safeNickname, role: 'normal' });
    res.json({ token, user: { id, phone, nickname: safeNickname, role: 'normal', credits: 5 } });
  } catch (err) {
    console.error('Register error:', err.message);
    res.status(500).json({ error: 'Registration failed.' });
  }
});

app.post('/auth/login', async (req, res) => {
  const { phone, password } = req.body || {};
  if (!/^\d{11}$/.test(phone || '')) {
    return res.status(400).json({ error: 'Phone number must be 11 digits.' });
  }
  try {
    const user = await dbGet('SELECT * FROM users WHERE phone = ?', [phone]);
    if (!user || !verifyPassword(password || '', user.password_hash)) {
      return res.status(401).json({ error: 'Invalid phone number or password.' });
    }
    const role = user.role || 'normal';
    const credits = typeof user.credits === 'number' ? user.credits : 0;
    const token = signToken({ sub: user.id, phone: user.phone, nickname: user.nickname, role });
    res.json({
      token,
      user: { id: user.id, phone: user.phone, nickname: user.nickname, role, credits }
    });
  } catch (err) {
    console.error('Login error:', err.message);
    res.status(500).json({ error: 'Login failed.' });
  }
});

app.get('/auth/me', authMiddleware, async (req, res) => {
  try {
    const user = await dbGet('SELECT id, phone, nickname, role, credits FROM users WHERE id = ?', [
      req.user.sub
    ]);
    if (!user) {
      return res.status(401).json({ error: 'Unauthorized' });
    }
    res.json(user);
  } catch (err) {
    console.error('Me error:', err.message);
    res.status(500).json({ error: 'Failed to fetch user info.' });
  }
});

app.post('/auth/init-super-admin', async (req, res) => {
  const { phone, password, nickname } = req.body || {};
  if (!/^\d{11}$/.test(phone || '')) {
    return res.status(400).json({ error: 'Phone number must be 11 digits.' });
  }
  if (!password || password.length < 6) {
    return res.status(400).json({ error: 'Password must be at least 6 characters.' });
  }
  const safeNickname =
    typeof nickname === 'string' && nickname.trim() ? nickname.trim() : `super-${phone.slice(-4)}`;
  try {
    const existing = await dbGet("SELECT id FROM users WHERE role = 'super_admin' LIMIT 1");
    if (existing) {
      return res.status(400).json({ error: 'Super admin already exists.' });
    }
    const id = crypto.randomUUID ? crypto.randomUUID() : String(Date.now());
    const now = new Date().toISOString();
    const passwordHash = hashPassword(password);
    await dbRun(
      'INSERT INTO users (id, phone, nickname, password_hash, role, credits, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
      [id, phone, safeNickname, passwordHash, 'super_admin', 5, now, now]
    );
    const token = signToken({ sub: id, phone, nickname: safeNickname, role: 'super_admin' });
    res.json({ token, user: { id, phone, nickname: safeNickname, role: 'super_admin', credits: 5 } });
  } catch (err) {
    console.error('Init super admin error:', err.message);
    res.status(500).json({ error: 'Failed to initialize super admin.' });
  }
});

app.post('/api/profile/delete', authMiddleware, async (req, res) => {
  try {
    const user = await dbGet('SELECT id, role FROM users WHERE id = ?', [req.user.sub]);
    if (!user) return res.status(401).json({ error: 'Unauthorized' });
    if (user.role === 'super_admin') {
      const count = await dbGet("SELECT COUNT(*) as cnt FROM users WHERE role = 'super_admin'");
      if (count && count.cnt <= 1) {
        return res.status(400).json({ error: 'Cannot delete the last super admin.' });
      }
    }
    await deleteUserCompletely(user.id);
    res.json({ success: true });
  } catch (err) {
    console.error('Delete profile error:', err.message);
    res.status(500).json({ error: 'Account deletion failed.' });
  }
});

app.post('/api/user/updateProfile', authMiddleware, async (req, res) => {
  const { nickname } = req.body || {};
  if (!nickname || typeof nickname !== 'string' || !nickname.trim()) {
    return res.status(400).json({ error: 'Nickname is required.' });
  }
  const safeNickname = nickname.trim();
  try {
    await dbRun('UPDATE users SET nickname = ?, updated_at = ? WHERE id = ?', [
      safeNickname,
      new Date().toISOString(),
      req.user.sub
    ]);
    const user = await dbGet('SELECT id, phone, nickname, role, credits FROM users WHERE id = ?', [
      req.user.sub
    ]);
    res.json({ success: true, user });
  } catch (err) {
    console.error('Update profile error:', err.message);
    res.status(500).json({ error: 'Update failed.' });
  }
});

app.post('/api/user/changePassword', authMiddleware, async (req, res) => {
  const { oldPassword, newPassword } = req.body || {};
  if (!oldPassword || !newPassword) {
    return res.status(400).json({ error: 'Both current and new passwords are required.' });
  }
  if (typeof newPassword !== 'string' || newPassword.length < 6) {
    return res.status(400).json({ error: 'New password must be at least 6 characters.' });
  }
  try {
    const user = await dbGet('SELECT id, password_hash FROM users WHERE id = ?', [req.user.sub]);
    if (!user || !verifyPassword(oldPassword, user.password_hash)) {
      return res.status(400).json({ error: 'Current password is incorrect.' });
    }
    const hashed = hashPassword(newPassword);
    await dbRun('UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?', [
      hashed,
      new Date().toISOString(),
      req.user.sub
    ]);
    res.json({ success: true });
  } catch (err) {
    console.error('Change password error:', err.message);
    res.status(500).json({ error: 'Password update failed.' });
  }
});

app.post('/api/activation/use', authMiddleware, requireRole(['normal', 'admin', 'super_admin']), async (req, res) => {
  const { code } = req.body || {};
  if (!code || typeof code !== 'string') {
    return res.status(400).json({ error: 'Activation code cannot be empty.' });
  }
  const now = new Date().toISOString();
  try {
    const codeRow = await dbGet('SELECT * FROM activation_codes WHERE code = ?', [code.trim()]);
    if (!codeRow) return res.status(404).json({ error: 'Activation code does not exist.' });
    if (codeRow.status !== 'unused')
      return res.status(400).json({ error: 'Activation code already used or expired.' });
    if (codeRow.expired_at && new Date(codeRow.expired_at).getTime() < Date.now()) {
      return res.status(400).json({ error: 'Activation code has expired.' });
    }
    const user = await dbGet('SELECT id, credits FROM users WHERE id = ?', [req.user.sub]);
    if (!user) return res.status(401).json({ error: 'Unauthorized' });

    await runInTransaction(async () => {
      await dbRun(
        'UPDATE activation_codes SET status = ?, used_uses = ?, updated_at = ? WHERE id = ?',
        ['used', codeRow.total_uses, now, codeRow.id]
      );
      await dbRun(
        'UPDATE users SET credits = credits + ?, updated_at = ? WHERE id = ?',
        [codeRow.total_uses, now, user.id]
      );
      await dbRun(
        'INSERT INTO activation_logs (id, user_id, code_id, added_uses, created_at) VALUES (?, ?, ?, ?, ?)',
        [
          crypto.randomUUID ? crypto.randomUUID() : String(Date.now()),
          user.id,
          codeRow.id,
          codeRow.total_uses,
          now
        ]
      );
    });
    const refreshed = await dbGet('SELECT credits FROM users WHERE id = ?', [req.user.sub]);
    res.json({
      credits: refreshed?.credits ?? user.credits + codeRow.total_uses,
      code: { code: codeRow.code, total_uses: codeRow.total_uses, status: 'used' }
    });
  } catch (err) {
    console.error('Use activation error:', err.message);
    res.status(500).json({ error: 'Activation failed.' });
  }
});

app.post(
  '/api/activation/batch-generate',
  authMiddleware,
  requireRole(['admin', 'super_admin']),
  async (req, res) => {
    const { count, uses_per_code, expired_at, batch_id } = req.body || {};
    const total = parseInt(count, 10);
    const uses = parseInt(uses_per_code, 10);
    if (!total || total <= 0 || total > 500) {
      return res.status(400).json({ error: 'Count must be between 1 and 500.' });
    }
    if (!uses || uses <= 0) {
      return res.status(400).json({ error: 'Uses per code must be greater than 0.' });
    }
    const now = new Date().toISOString();
    const codes = [];
    try {
      await runInTransaction(async () => {
        for (let i = 0; i < total; i++) {
          const id = crypto.randomUUID ? crypto.randomUUID() : `${Date.now()}_${i}`;
          const code = randomCode(18);
          await dbRun(
            'INSERT INTO activation_codes (id, code, batch_id, total_uses, used_uses, status, expired_at, created_by, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
            [
              id,
              code,
              batch_id || null,
              uses,
              0,
              'unused',
              expired_at || null,
              req.user.sub,
              now,
              now
            ]
          );
          codes.push({ code, total_uses: uses, expired_at: expired_at || null, batch_id: batch_id || null });
        }
      });
      res.json({ codes });
    } catch (err) {
      console.error('Batch generate error:', err.message);
      res.status(500).json({ error: 'Generation failed.' });
    }
  }
);

app.get(
  '/api/activation/list',
  authMiddleware,
  requireRole(['admin', 'super_admin']),
  async (req, res) => {
    const { status, batch_id, page = 1, page_size = 50 } = req.query;
    const limit = Math.min(parseInt(page_size, 10) || 50, 200);
    const offset = ((parseInt(page, 10) || 1) - 1) * limit;
    const filters = [];
    const params = [];
    if (status) {
      filters.push('status = ?');
      params.push(status);
    }
    if (batch_id) {
      filters.push('batch_id = ?');
      params.push(batch_id);
    }
    const where = filters.length ? `WHERE ${filters.join(' AND ')}` : '';
    try {
      const rows = await new Promise((resolve, reject) => {
        db.all(
          `SELECT * FROM activation_codes ${where} ORDER BY created_at DESC LIMIT ? OFFSET ?`,
          [...params, limit, offset],
          (err, result) => {
            if (err) return reject(err);
            resolve(result || []);
          }
        );
      });
      res.json({ items: rows, page: parseInt(page, 10) || 1, page_size: limit });
    } catch (err) {
      console.error('List activation error:', err.message);
      res.status(500).json({ error: 'Query failed.' });
    }
  }
);

app.get(
  '/api/activation/:id/logs',
  authMiddleware,
  requireRole(['admin', 'super_admin']),
  async (req, res) => {
    try {
      const rows = await new Promise((resolve, reject) => {
        db.all(
          `SELECT al.*, u.phone, u.nickname FROM activation_logs al
           LEFT JOIN users u ON u.id = al.user_id
           WHERE al.code_id = ?
           ORDER BY al.created_at DESC`,
          [req.params.id],
          (err, result) => {
            if (err) return reject(err);
            resolve(result || []);
          }
        );
      });
      res.json({ items: rows });
    } catch (err) {
      console.error('Activation logs error:', err.message);
      res.status(500).json({ error: 'Query failed.' });
    }
  }
);

app.post('/api/chat/text', authMiddleware, async (req, res) => {
  const { text, scenario } = req.body || {};
  if (!text || typeof text !== 'string') {
    return res.status(400).json({ error: 'Text is required.' });
  }

  const start = Date.now();
  try {
    const user = await dbGet('SELECT id, credits FROM users WHERE id = ?', [req.user.sub]);
    if (!user) return res.status(401).json({ error: 'Unauthorized' });
    if (user.credits <= 0) {
      return res
        .status(402)
        .json({
          error: 'Analysis credits exhausted; use an activation code to add more.',
          code: 'INSUFFICIENT_CREDITS'
        });
    }

    const prompt = readScenarioPrompt(scenario);
    const messages = [
      ...(prompt
        ? [
            {
              role: 'system',
              content: [{ type: 'text', text: prompt }]
            }
          ]
        : []),
      {
        role: 'user',
        content: [{ type: 'text', text }]
      }
    ];
    const reply = await callDashScopeChat(TEXT_MODEL, messages);
    const replyText = typeof reply === 'string' ? reply.trim() : '';
    if (!replyText) {
      return res.status(502).json({ error: 'Analysis failed: empty response.' });
    }
    const now = new Date().toISOString();
    await runInTransaction(async () => {
      const updateRes = await dbRun(
        'UPDATE users SET credits = credits - 1, updated_at = ? WHERE id = ? AND credits > 0',
        [now, user.id]
      );
      if (!updateRes || updateRes.changes === 0) {
        throw new Error('INSUFFICIENT_CREDITS');
      }
      await dbRun(
        'INSERT INTO analysis_logs (id, user_id, type, created_at, duration_ms) VALUES (?, ?, ?, ?, ?)',
        [crypto.randomUUID ? crypto.randomUUID() : String(Date.now()), user.id, 'text', now, Date.now() - start]
      );
    });
    const refreshed = await dbGet('SELECT credits FROM users WHERE id = ?', [user.id]);
    res.json({ text: replyText, credits: refreshed?.credits ?? user.credits - 1 });
  } catch (err) {
    if (err.message === 'INSUFFICIENT_CREDITS') {
      return res
        .status(402)
        .json({
          error: 'Analysis credits exhausted; use an activation code to add more.',
          code: 'INSUFFICIENT_CREDITS'
        });
    }
    console.error('Text chat error:', err.message);
    res.status(502).json({ error: err.message });
  }
});

app.post('/api/chat/image', authMiddleware, async (req, res) => {
  const { text, imageBase64, scenario } = req.body || {};
  const userText = typeof text === 'string' ? text : '';
  const hasImage = Boolean(imageBase64 && typeof imageBase64 === 'string');
  if (!userText && !hasImage) {
    return res.status(400).json({ error: 'Provide text or image.' });
  }

  const start = Date.now();
  try {
    const user = await dbGet('SELECT id, credits FROM users WHERE id = ?', [req.user.sub]);
    if (!user) return res.status(401).json({ error: 'Unauthorized' });
    if (user.credits <= 0) {
      return res
        .status(402)
        .json({
          error: 'Analysis credits exhausted; use an activation code to add more.',
          code: 'INSUFFICIENT_CREDITS'
        });
    }

    const prompt = readScenarioPrompt(scenario);
    const imageUrl =
      imageBase64.startsWith('data:') && imageBase64.includes('base64,')
        ? imageBase64
        : `data:image/png;base64,${imageBase64}`;
    const visionMessages = [
      ...(prompt
        ? [
            {
              role: 'system',
              content: [{ type: 'text', text: prompt }]
            }
          ]
        : []),
      {
        role: 'system',
        content: [
          {
            type: 'text',
            text:
              'You analyze images and describe factual details briefly. Focus on card recognition: identify card color (only red/blue/yellow/green), row position (which row), score, and content.'
          }
        ]
      },
      {
        role: 'user',
        content: [
          {
            type: 'text',
            text:
              'Identify card details in the image: color (only red/blue/yellow/green), position (which row), score, and content. Mark unknown for any missing fields.'
          },
          { type: 'image_url', image_url: { url: imageUrl } }
        ]
      }
    ];
    const imageAnalysis = await callDashScopeChat(VISION_MODEL, visionMessages);
    const parsedImageAnalysis = typeof imageAnalysis === 'string' ? imageAnalysis.trim() : '';
    if (!parsedImageAnalysis) {
      return res.status(502).json({ error: 'Image analysis failed: empty response.' });
    }

    const combinedPrompt = [
      'Below is the user text and the image analysis result; provide a combined response:',
      `User text: ${text}`,
      `Image analysis: ${parsedImageAnalysis}`
    ].join('\n');

    const textMessages = [
      ...(prompt
        ? [
            {
              role: 'system',
              content: [{ type: 'text', text: prompt }]
            }
          ]
        : []),
      {
        role: 'system',
        content: [{ type: 'text', text: 'You are a helpful assistant that reasons over text and extracted image details.' }]
      },
      {
        role: 'user',
        content: [{ type: 'text', text: combinedPrompt }]
      }
    ];
    const finalReply = await callDashScopeChat(TEXT_MODEL, textMessages);
    const replyText = typeof finalReply === 'string' ? finalReply.trim() : '';
    if (!replyText) {
      return res.status(502).json({ error: 'Analysis failed: empty response.' });
    }
    const now = new Date().toISOString();
    await runInTransaction(async () => {
      const updateRes = await dbRun(
        'UPDATE users SET credits = credits - 1, updated_at = ? WHERE id = ? AND credits > 0',
        [now, user.id]
      );
      if (!updateRes || updateRes.changes === 0) {
        throw new Error('INSUFFICIENT_CREDITS');
      }
      await dbRun(
        'INSERT INTO analysis_logs (id, user_id, type, created_at, duration_ms) VALUES (?, ?, ?, ?, ?)',
        [
          crypto.randomUUID ? crypto.randomUUID() : String(Date.now()),
          user.id,
          'image',
          now,
          Date.now() - start
        ]
      );
    });
    const refreshed = await dbGet('SELECT credits FROM users WHERE id = ?', [user.id]);
    res.json({
      text: replyText,
      imageAnalysis: parsedImageAnalysis,
      credits: refreshed?.credits ?? user.credits - 1
    });
  } catch (err) {
    console.error('Image chat error:', err.message);
    res.status(502).json({ error: err.message });
  }
});

app.get(
  '/api/admin/stats/overview',
  authMiddleware,
  requireRole(['admin', 'super_admin']),
  async (req, res) => {
    try {
      const totalUsers = await dbGet('SELECT COUNT(*) as cnt FROM users');
      const last7 = await dbGet(
        "SELECT COUNT(*) as cnt FROM analysis_logs WHERE datetime(created_at) >= datetime('now', '-7 days')"
      );
      const last30 = await dbGet(
        "SELECT COUNT(*) as cnt FROM analysis_logs WHERE datetime(created_at) >= datetime('now', '-30 days')"
      );
      const trend = await new Promise((resolve, reject) => {
        db.all(
          `SELECT date(created_at) as day, COUNT(*) as cnt
           FROM analysis_logs
           WHERE datetime(created_at) >= datetime('now', '-30 days')
           GROUP BY day
           ORDER BY day`,
          [],
          (err, rows) => {
            if (err) return reject(err);
            resolve(rows || []);
          }
        );
      });
      res.json({
        total_users: totalUsers?.cnt || 0,
        analyses_last7: last7?.cnt || 0,
        analyses_last30: last30?.cnt || 0,
        trend
      });
    } catch (err) {
      console.error('Stats overview error:', err.message);
      res.status(500).json({ error: 'Statistics query failed.' });
    }
  }
);

app.get(
  '/api/admin/users/:id/stats',
  authMiddleware,
  requireRole(['admin', 'super_admin']),
  async (req, res) => {
    try {
      const user = await dbGet('SELECT id, phone, nickname, role, credits FROM users WHERE id = ?', [
        req.params.id
      ]);
      if (!user) return res.status(404).json({ error: 'User not found.' });
      const total = await dbGet('SELECT COUNT(*) as cnt FROM analysis_logs WHERE user_id = ?', [
        user.id
      ]);
      const recent = await new Promise((resolve, reject) => {
        db.all(
          `SELECT date(created_at) as day, COUNT(*) as cnt
           FROM analysis_logs
           WHERE user_id = ? AND datetime(created_at) >= datetime('now', '-30 days')
           GROUP BY day
           ORDER BY day`,
          [user.id],
          (err, rows) => {
            if (err) return reject(err);
            resolve(rows || []);
          }
        );
      });
      res.json({
        user,
        total_analyses: total?.cnt || 0,
        trend: recent
      });
    } catch (err) {
      console.error('User stats error:', err.message);
      res.status(500).json({ error: 'Query failed.' });
    }
  }
);

app.get(
  '/api/admin/users',
  authMiddleware,
  requireRole(['admin', 'super_admin']),
  async (req, res) => {
    const { q, page = 1, page_size = 50 } = req.query;
    const limit = Math.min(parseInt(page_size, 10) || 50, 200);
    const offset = ((parseInt(page, 10) || 1) - 1) * limit;
    const params = [];
    let where = '';
    if (q) {
      where = 'WHERE phone LIKE ? OR nickname LIKE ?';
      params.push(`%${q}%`, `%${q}%`);
    }
    try {
      const items = await new Promise((resolve, reject) => {
        db.all(
          `SELECT id, phone, nickname, role, credits, created_at FROM users ${where} ORDER BY created_at DESC LIMIT ? OFFSET ?`,
          [...params, limit, offset],
          (err, rows) => {
            if (err) return reject(err);
            resolve(rows || []);
          }
        );
      });
      res.json({ items, page: parseInt(page, 10) || 1, page_size: limit });
    } catch (err) {
      console.error('Admin list users error:', err.message);
      res.status(500).json({ error: 'Query failed.' });
    }
  }
);

app.post(
  '/api/admin/users/:id/set-role',
  authMiddleware,
  requireRole(['super_admin']),
  async (req, res) => {
    const { role } = req.body || {};
    if (!['normal', 'admin'].includes(role)) {
      return res.status(400).json({ error: 'Invalid role.' });
    }
    try {
      const user = await dbGet('SELECT id FROM users WHERE id = ?', [req.params.id]);
      if (!user) return res.status(404).json({ error: 'User not found.' });
      await dbRun('UPDATE users SET role = ?, updated_at = ? WHERE id = ?', [
        role,
        new Date().toISOString(),
        user.id
      ]);
      res.json({ success: true });
    } catch (err) {
      console.error('Set role error:', err.message);
      res.status(500).json({ error: 'Update failed.' });
    }
  }
);

app.post(
  '/api/admin/users/:id/reset-password',
  authMiddleware,
  requireRole(['super_admin']),
  async (req, res) => {
    const newPassword = DEFAULT_TEMP_PASSWORD;
    try {
      const user = await dbGet('SELECT id FROM users WHERE id = ?', [req.params.id]);
      if (!user) return res.status(404).json({ error: 'User not found.' });
      const hashed = hashPassword(newPassword);
      await dbRun('UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?', [
        hashed,
        new Date().toISOString(),
        user.id
      ]);
      console.log(
        `Password reset by ${req.user?.sub || 'unknown'} for user ${user.id} at ${new Date().toISOString()}`
      );
      res.json({ success: true });
    } catch (err) {
      console.error('Reset password error:', err.message);
      res.status(500).json({ error: 'Reset failed.' });
    }
  }
);

app.post('/api/profile/update', authMiddleware, async (req, res) => {
  const { nickname, password } = req.body || {};
  if (!nickname && !password) {
    return res.status(400).json({ error: 'Nothing to update.' });
  }
  if (password && (typeof password !== 'string' || password.length < 6)) {
    return res.status(400).json({ error: 'Password must be at least 6 characters.' });
  }
  const updates = [];
  const params = [];
  if (typeof nickname === 'string' && nickname.trim()) {
    updates.push('nickname = ?');
    params.push(nickname.trim());
  }
  if (password) {
    updates.push('password_hash = ?');
    params.push(hashPassword(password));
  }
  if (!updates.length) {
    return res.status(400).json({ error: 'Nothing to update.' });
  }
  updates.push('updated_at = ?');
  params.push(new Date().toISOString(), req.user.sub);
  try {
    await dbRun(`UPDATE users SET ${updates.join(', ')} WHERE id = ?`, params);
    const user = await dbGet('SELECT id, phone, nickname, role, credits FROM users WHERE id = ?', [
      req.user.sub
    ]);
    res.json({ success: true, user });
  } catch (err) {
    console.error('Profile update error:', err.message);
    res.status(500).json({ error: 'Update failed.' });
  }
});

initDb();
migrateSchema().catch((err) => {
  console.error('Schema migration failed:', err.message);
});

app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  if (res.headersSent) {
    return next(err);
  }
  const status = err.status || 500;
  if (req.path.startsWith('/api/') || req.path.startsWith('/auth/')) {
    return res.status(status).json({ error: err.message || 'Internal server error.' });
  }
  res.status(status).send('Internal Server Error');
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
