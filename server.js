const path = require('path');
const fs = require('fs');
const express = require('express');
const cors = require('cors');
const fetch = require('node-fetch');
const crypto = require('crypto');
const sharp = require('sharp');
const sqlite3 = require('sqlite3').verbose();
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3021;
const BASE_URL =
  process.env.DASHSCOPE_BASE_URL || 'https://dashscope.aliyuncs.com/compatible-mode/v1';
const API_KEY = process.env.DASHSCOPE_API_KEY;
const TEXT_MODEL = process.env.TEXT_MODEL || 'qwen-plus';
const VISION_MODEL = process.env.VISION_MODEL || 'qwen-vl-plus';
const PROMPT_PATH = path.join(__dirname, 'prompt.txt');
const PROMPTS_DIR = path.join(__dirname, 'public', 'prompts');
const SCENARIO_PROMPTS = {
  card: 'CARD_SCENARIO.txt',
  moment: 'MOMENT_SCENARIO.txt'
};
const VISION_SYS_PROMPT_PATH = path.join(PROMPTS_DIR, 'VISION_SYSTEM_PROMPT.txt');
const DEFAULT_VISION_SYSTEM_PROMPT =
  'You are an image fact-extraction assistant. Describe only what is strictly visible in the image: objects, people, actions, text, numbers, colors, and spatial layout. Do not infer emotions, background stories, intentions, or unseen elements. Do not summarize, beautify, generalize, or optimize for social media. Output should be factual, objective, and limited to what the image literally shows.';
const PUBLIC_THUMB_DIR = path.join(__dirname, 'public', 'uploads', 'thumbnails');
const DATA_DIR = path.join(__dirname, 'data');
const DB_FILE = path.join(DATA_DIR, 'auth.db');
const AUTH_SECRET = process.env.AUTH_SECRET || 'moments-dev-secret';
const TOKEN_TTL_SECONDS = 7 * 24 * 60 * 60;
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
app.use(express.static(path.join(__dirname, 'public')));

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
    db.run(
      `CREATE TABLE IF NOT EXISTS analysis_history (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        created_at TEXT NOT NULL,
        image_path TEXT,
        input_text TEXT,
        output_text TEXT,
        duration_ms INTEGER,
        input_tokens INTEGER,
        output_tokens INTEGER,
        total_tokens INTEGER,
        model_name TEXT,
        success INTEGER NOT NULL DEFAULT 1,
        error_message TEXT
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

async function consumeCreditAndLog(userId, type, durationMs) {
  const now = new Date().toISOString();
  await runInTransaction(async () => {
    const updateRes = await dbRun(
      'UPDATE users SET credits = credits - 1, updated_at = ? WHERE id = ? AND credits > 0',
      [now, userId]
    );
    if (!updateRes || updateRes.changes === 0) {
      const err = new Error('INSUFFICIENT_CREDITS');
      err.code = 'INSUFFICIENT_CREDITS';
      throw err;
    }
    await dbRun(
      'INSERT INTO analysis_logs (id, user_id, type, created_at, duration_ms) VALUES (?, ?, ?, ?, ?)',
      [
        crypto.randomUUID ? crypto.randomUUID() : String(Date.now()),
        userId,
        type,
        now,
        durationMs ?? null
      ]
    );
  });
  const refreshed = await dbGet('SELECT credits FROM users WHERE id = ?', [userId]);
  return refreshed?.credits;
}

async function recordHistory({
  userId,
  inputText,
  outputText,
  imagePath,
  durationMs,
  usage,
  modelName,
  success = true,
  errorMessage
}) {
  const now = new Date().toISOString();
  const id = crypto.randomUUID ? crypto.randomUUID() : String(Date.now());
  await dbRun(
    `INSERT INTO analysis_history (
      id, user_id, created_at, image_path, input_text, output_text,
      duration_ms, input_tokens, output_tokens, total_tokens, model_name, success, error_message
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      id,
      userId,
      now,
      imagePath || '',
      inputText || '',
      outputText || '',
      durationMs ?? null,
      usage?.input_tokens ?? null,
      usage?.output_tokens ?? null,
      usage?.total_tokens ?? null,
      modelName || null,
      success ? 1 : 0,
      errorMessage || null
    ]
  );
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
  await ensureColumn('activation_codes', 'created_by', 'TEXT');
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

function readVisionSystemPrompt() {
  try {
    if (fs.existsSync(VISION_SYS_PROMPT_PATH)) {
      return fs.readFileSync(VISION_SYS_PROMPT_PATH, 'utf8').trim();
    }
  } catch (err) {
    console.error('Read vision system prompt error:', err.message);
  }
  return DEFAULT_VISION_SYSTEM_PROMPT;
}

async function saveThumbnailFromBase64(base64, userId) {
  if (!sharp || !base64) return '';
  try {
    const [meta, data] = base64.split(',');
    const buffer = Buffer.from(data || base64, 'base64');
    fs.mkdirSync(PUBLIC_THUMB_DIR, { recursive: true });
    const filename = `${Date.now()}-${userId || 'anon'}.jpg`;
    const filepath = path.join(PUBLIC_THUMB_DIR, filename);
    await sharp(buffer)
      .resize({ width: 800, height: 800, fit: 'inside', withoutEnlargement: true })
      .jpeg({ quality: 70 })
      .toFile(filepath);
    return `/uploads/thumbnails/${filename}`;
  } catch (err) {
    console.error('Save thumbnail failed:', err.message);
    return '';
  }
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
  return {
    reply,
    usage: {
      input_tokens: result?.usage?.input_tokens ?? null,
      output_tokens: result?.usage?.output_tokens ?? null,
      total_tokens: result?.usage?.total_tokens ?? null
    }
  };
}

app.post('/auth/register', async (req, res) => {
  const { phone, password, password_confirm, nickname } = req.body || {};
  if (!/^\d{11}$/.test(phone || '')) {
    return res.status(400).json({ error: 'error.invalidPhone' });
  }
  if (!password || password.length < 6) {
    return res.status(400).json({ error: 'error.passwordTooShort' });
  }
  if (password !== password_confirm) {
    return res.status(400).json({ error: 'error.passwordMismatch' });
  }
  const safeNickname = typeof nickname === 'string' && nickname.trim() ? nickname.trim() : `User${phone.slice(-4)}`;
  try {
    const existing = await dbGet('SELECT id FROM users WHERE phone = ?', [phone]);
    if (existing) {
      return res.status(400).json({ error: 'error.phoneExists' });
    }
    const id = crypto.randomUUID ? crypto.randomUUID() : String(Date.now());
    const now = new Date().toISOString();
    const passwordHash = hashPassword(password);
    await dbRun(
      'INSERT INTO users (id, phone, nickname, password_hash, role, credits, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
      [id, phone, safeNickname, passwordHash, 'normal', 5, now, now]
    );
    const token = signToken({ sub: id, phone, nickname: safeNickname, role: 'normal' });
    res.json({
      token,
      user: { id, phone, nickname: safeNickname, role: 'normal', credits: 5, created_at: now }
    });
  } catch (err) {
    console.error('Register error:', err.message);
    res.status(500).json({ error: 'error.registerFailed' });
  }
});

app.post('/auth/login', async (req, res) => {
  const { phone, password } = req.body || {};
  if (!/^\d{11}$/.test(phone || '')) {
    return res.status(400).json({ error: 'error.invalidPhone' });
  }
  try {
    const user = await dbGet('SELECT * FROM users WHERE phone = ?', [phone]);
    if (!user || !verifyPassword(password || '', user.password_hash)) {
      return res.status(401).json({ error: 'error.badCredentials' });
    }
    const role = user.role || 'normal';
    const credits = typeof user.credits === 'number' ? user.credits : 0;
    const token = signToken({ sub: user.id, phone: user.phone, nickname: user.nickname, role });
    res.json({
      token,
      user: {
        id: user.id,
        phone: user.phone,
        nickname: user.nickname,
        role,
        credits,
        created_at: user.created_at
      }
    });
  } catch (err) {
    console.error('Login error:', err.message);
    res.status(500).json({ error: 'error.loginFailed' });
  }
});

app.get('/auth/me', authMiddleware, async (req, res) => {
  try {
    const user = await dbGet('SELECT id, phone, nickname, role, credits, created_at FROM users WHERE id = ?', [
      req.user.sub
    ]);
    if (!user) {
      return res.status(401).json({ error: 'Unauthorized' });
    }
    res.json(user);
  } catch (err) {
    console.error('Me error:', err.message);
    res.status(500).json({ error: 'error.fetchUserFailed' });
  }
});

app.post('/auth/init-super-admin', async (req, res) => {
  const { phone, password, nickname } = req.body || {};
  if (!/^\d{11}$/.test(phone || '')) {
    return res.status(400).json({ error: 'error.invalidPhone' });
  }
  if (!password || password.length < 6) {
    return res.status(400).json({ error: 'error.passwordTooShort' });
  }
  const safeNickname =
    typeof nickname === 'string' && nickname.trim() ? nickname.trim() : `Super${phone.slice(-4)}`;
  try {
    const existing = await dbGet("SELECT id FROM users WHERE role = 'super_admin' LIMIT 1");
    if (existing) {
      return res.status(400).json({ error: 'error.superAdminExists' });
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
    res.status(500).json({ error: 'error.initSuperAdminFailed' });
  }
});

app.patch('/api/user/profile', authMiddleware, async (req, res) => {
  const { nickname } = req.body || {};
  const safeNickname = typeof nickname === 'string' ? nickname.trim() : '';
  const isValidNickname = safeNickname && safeNickname.length >= 2 && safeNickname.length <= 30;
  if (!isValidNickname) {
    return res.status(400).json({ error: 'error.nicknameInvalid' });
  }
  const now = new Date().toISOString();
  try {
    const user = await dbGet('SELECT id FROM users WHERE id = ?', [req.user.sub]);
    if (!user) return res.status(401).json({ error: 'Unauthorized' });
    await dbRun('UPDATE users SET nickname = ?, updated_at = ? WHERE id = ?', [
      safeNickname,
      now,
      user.id
    ]);
    res.json({ nickname: safeNickname });
  } catch (err) {
    console.error('Update nickname error:', err.message);
    res.status(500).json({ error: 'error.updateProfileFailed' });
  }
});

app.post('/api/user/change-password', authMiddleware, async (req, res) => {
  const { old_password, new_password, new_password_confirm } = req.body || {};
  const meetsLength = new_password && new_password.length >= 6;
  const meetsComplexity = /[A-Za-z]/.test(new_password || '') && /\d/.test(new_password || '');
  if (!meetsLength) {
    return res.status(400).json({ error: 'error.passwordTooShort' });
  }
  if (!meetsComplexity) {
    return res.status(400).json({ error: 'error.passwordComplexity' });
  }
  if (new_password !== new_password_confirm) {
    return res.status(400).json({ error: 'error.passwordMismatch' });
  }
  try {
    const user = await dbGet('SELECT id, password_hash FROM users WHERE id = ?', [req.user.sub]);
    if (!user) return res.status(401).json({ error: 'Unauthorized' });
    if (!verifyPassword(old_password || '', user.password_hash)) {
      return res.status(400).json({ error: 'error.badCredentials' });
    }
    const newHash = hashPassword(new_password);
    const now = new Date().toISOString();
    await dbRun('UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?', [
      newHash,
      now,
      user.id
    ]);
    res.json({ success: true });
  } catch (err) {
    console.error('Update password error:', err.message);
    res.status(500).json({ error: 'error.updateProfileFailed' });
  }
});

app.post('/api/profile/delete', authMiddleware, async (req, res) => {
  try {
    const user = await dbGet('SELECT id, role FROM users WHERE id = ?', [req.user.sub]);
    if (!user) return res.status(401).json({ error: 'Unauthorized' });
    if (user.role === 'super_admin') {
      const count = await dbGet("SELECT COUNT(*) as cnt FROM users WHERE role = 'super_admin'");
      if (count && count.cnt <= 1) {
        return res.status(400).json({ error: 'error.cannotDeleteLastSuper' });
      }
    }
    await deleteUserCompletely(user.id);
    res.json({ success: true });
  } catch (err) {
    console.error('Delete profile error:', err.message);
    res.status(500).json({ error: 'error.logoutFailed' });
  }
});

app.post('/api/activation/use', authMiddleware, requireRole(['normal', 'admin', 'super_admin']), async (req, res) => {
  const { code } = req.body || {};
  if (!code || typeof code !== 'string') {
    return res.status(400).json({ error: 'error.activationCodeRequired' });
  }
  const now = new Date().toISOString();
  try {
    const codeRow = await dbGet('SELECT * FROM activation_codes WHERE code = ?', [code.trim()]);
    if (!codeRow) return res.status(404).json({ error: 'error.activationCodeNotFound' });
    if (codeRow.status !== 'unused') return res.status(400).json({ error: 'error.activationCodeUsed' });
    if (codeRow.expired_at && new Date(codeRow.expired_at).getTime() < Date.now()) {
      return res.status(400).json({ error: 'error.activationCodeExpired' });
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
    res.status(500).json({ error: 'error.activationFailed' });
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
      return res.status(400).json({ error: 'error.generateCountInvalid' });
    }
    if (!uses || uses <= 0) {
      return res.status(400).json({ error: 'error.generateUsesInvalid' });
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
      res.status(500).json({ error: 'error.generateFailed' });
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
    if (req.user.role === 'admin') {
      filters.push('created_by = ?');
      params.push(req.user.sub);
    }
    const where = filters.length ? `WHERE ${filters.join(' AND ')}` : '';
    try {
      const rows = await new Promise((resolve, reject) => {
        db.all(
          `SELECT ac.*, u.phone as creator_phone
           FROM activation_codes ac
           LEFT JOIN users u ON u.id = ac.created_by
           ${where}
           ORDER BY ac.created_at DESC
           LIMIT ? OFFSET ?`,
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
      res.status(500).json({ error: 'error.queryFailed' });
    }
  }
);

app.get(
  '/api/activation/:id/logs',
  authMiddleware,
  requireRole(['admin', 'super_admin']),
  async (req, res) => {
    try {
      const codeRow = await dbGet('SELECT * FROM activation_codes WHERE id = ?', [req.params.id]);
      if (!codeRow) return res.status(404).json({ error: 'error.activationCodeNotFound' });
      if (req.user.role === 'admin' && codeRow.created_by !== req.user.sub) {
        return res.status(403).json({ error: 'Forbidden' });
      }
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
      res.status(500).json({ error: 'error.queryFailed' });
    }
  }
);

app.post('/api/chat/text', authMiddleware, async (req, res) => {
  const { text, userText } = req.body || {};
  if (!text || typeof text !== 'string') {
    return res.status(400).json({ error: 'Text is required.' });
  }
  const plainInput = typeof userText === 'string' ? userText : '';
  const enableDebug = req.user?.role === 'super_admin' && req.headers['x-debug-trace'] === '1';

  const start = Date.now();
  try {
    const user = await dbGet('SELECT id, credits FROM users WHERE id = ?', [req.user.sub]);
    if (!user) return res.status(401).json({ error: 'Unauthorized' });
    if (user.credits <= 0) {
      return res
        .status(402)
        .json({ error: 'error.creditsExhausted', code: 'INSUFFICIENT_CREDITS' });
    }

    const prompt = readScenarioPrompt('card');
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
    const { reply, usage } = await callDashScopeChat(TEXT_MODEL, messages);
    const duration = Date.now() - start;
    const refreshedCredits = await consumeCreditAndLog(user.id, 'text', duration);
    try {
      await recordHistory({
        userId: user.id,
        inputText: plainInput,
        outputText: reply,
        durationMs: duration,
        usage,
        modelName: TEXT_MODEL,
        success: true
      });
    } catch (logErr) {
      console.warn('Record history (text) failed:', logErr.message);
    }
    const responsePayload = { text: reply, credits: refreshedCredits ?? user.credits - 1 };
    if (enableDebug) {
      responsePayload.debug = {
        model: TEXT_MODEL,
        messages
      };
    }
    res.json(responsePayload);
  } catch (err) {
    if (err.code === 'INSUFFICIENT_CREDITS' || err.message === 'INSUFFICIENT_CREDITS') {
      return res
        .status(402)
        .json({ error: 'error.creditsExhausted', code: 'INSUFFICIENT_CREDITS' });
    }
    console.error('Text chat error:', err.message);
    res.status(502).json({ error: err.message });
  }
});

app.post('/api/chat/image', authMiddleware, async (req, res) => {
  const { text, imageBase64, userText } = req.body || {};
  const userInputText = typeof userText === 'string' ? userText : '';
  const userTextCombined = typeof text === 'string' ? text : '';
  const hasImage = Boolean(imageBase64 && typeof imageBase64 === 'string');
  if (!userText && !hasImage) {
    return res.status(400).json({ error: 'Provide text or image.' });
  }
  const enableDebug = req.user?.role === 'super_admin' && req.headers['x-debug-trace'] === '1';

  const start = Date.now();
  try {
    const user = await dbGet('SELECT id, credits FROM users WHERE id = ?', [req.user.sub]);
    if (!user) return res.status(401).json({ error: 'Unauthorized' });
    if (user.credits <= 0) {
      return res
        .status(402)
        .json({ error: 'error.creditsExhausted', code: 'INSUFFICIENT_CREDITS' });
    }

    const prompt = readScenarioPrompt('card');
    const imageUrl =
      imageBase64.startsWith('data:') && imageBase64.includes('base64,')
        ? imageBase64
        : `data:image/png;base64,${imageBase64}`;
    const visionSystemPrompt = readVisionSystemPrompt();
    const visionMessages = [
      {
        role: 'system',
        content: [
          {
            type: 'text',
            text: visionSystemPrompt
          }
        ]
      },
      {
        role: 'user',
        content: [{ type: 'image_url', image_url: { url: imageUrl } }]
      }
    ];
    const imageResult = await callDashScopeChat(VISION_MODEL, visionMessages);
    const imageAnalysis = imageResult.reply;

    const combinedPrompt = [
      'Below are the user text and image analysis:',
      `User text:${userInputText}`,
      `Image analysis:${imageAnalysis}`
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
    const finalResult = await callDashScopeChat(TEXT_MODEL, textMessages);
    const finalReply = finalResult.reply;
    const thumbPath = await saveThumbnailFromBase64(imageBase64, user.id);
    const duration = Date.now() - start;
    const refreshedCredits = await consumeCreditAndLog(user.id, 'image', duration);
    try {
      await recordHistory({
        userId: user.id,
        inputText: userInputText,
        outputText: finalReply,
        imagePath: thumbPath || '',
        durationMs: duration,
        usage: finalResult.usage,
        modelName: TEXT_MODEL,
        success: true
      });
    } catch (logErr) {
      console.warn('Record history (image) failed:', logErr.message);
    }
    const responsePayload = {
      text: finalReply,
      imageAnalysis,
      credits: refreshedCredits ?? user.credits - 1
    };
    if (enableDebug) {
      responsePayload.debug = {
        visionModel: VISION_MODEL,
        visionMessages,
        visionReply: imageAnalysis,
        textModel: TEXT_MODEL,
        textMessages,
        textReply: finalReply
      };
    }
    res.json(responsePayload);
  } catch (err) {
    if (err.code === 'INSUFFICIENT_CREDITS' || err.message === 'INSUFFICIENT_CREDITS') {
      return res
        .status(402)
        .json({ error: 'error.creditsExhausted', code: 'INSUFFICIENT_CREDITS' });
    }
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
    res.status(500).json({ error: 'error.statsFailed' });
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
      if (!user) return res.status(404).json({ error: 'error.userNotFound' });
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
      res.status(500).json({ error: 'error.queryFailed' });
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
      res.status(500).json({ error: 'error.queryFailed' });
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
      return res.status(400).json({ error: 'error.roleInvalid' });
    }
    try {
      const user = await dbGet('SELECT id FROM users WHERE id = ?', [req.params.id]);
      if (!user) return res.status(404).json({ error: 'error.userNotFound' });
      await dbRun('UPDATE users SET role = ?, updated_at = ? WHERE id = ?', [
        role,
        new Date().toISOString(),
        user.id
      ]);
      res.json({ success: true });
    } catch (err) {
      console.error('Set role error:', err.message);
      res.status(500).json({ error: 'error.setRoleFailed' });
    }
  }
);

app.post(
  '/api/admin/users/:id/reset-password',
  authMiddleware,
  requireRole(['super_admin']),
  async (req, res) => {
    try {
      const user = await dbGet('SELECT id FROM users WHERE id = ?', [req.params.id]);
      if (!user) return res.status(404).json({ error: 'error.userNotFound' });
      const newHash = hashPassword('123456');
      await dbRun('UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?', [
        newHash,
        new Date().toISOString(),
        user.id
      ]);
      res.json({ success: true, password: '123456' });
    } catch (err) {
      console.error('Admin reset password error:', err.message);
      res.status(500).json({ error: 'error.resetPasswordFailed' });
    }
  }
);

app.get('/api/history/list', authMiddleware, async (req, res) => {
  const { startDate, endDate, keyword, page = 1, pageSize = 10 } = req.query || {};
  const limit = Math.min(parseInt(pageSize, 10) || 10, 50);
  const offset = ((parseInt(page, 10) || 1) - 1) * limit;
  const params = [req.user.sub];
  let where = 'WHERE user_id = ? AND success = 1';
  if (startDate) {
    where += ' AND datetime(created_at) >= datetime(?)';
    params.push(startDate);
  }
  if (endDate) {
    where += ' AND datetime(created_at) <= datetime(?)';
    params.push(endDate);
  }
  if (keyword) {
    where += ' AND (input_text LIKE ? OR output_text LIKE ?)';
    params.push(`%${keyword}%`, `%${keyword}%`);
  }
  try {
    const rows = await new Promise((resolve, reject) => {
      db.all(
        `SELECT id, created_at, image_path,
                substr(input_text,1,80) AS input_summary, substr(output_text,1,120) AS output_summary,
                duration_ms, input_tokens, output_tokens, total_tokens
         FROM analysis_history
         ${where}
         ORDER BY datetime(created_at) DESC
         LIMIT ? OFFSET ?`,
        [...params, limit, offset],
        (err, result) => {
          if (err) return reject(err);
          resolve(result || []);
        }
      );
    });
    const totalRow = await dbGet(`SELECT COUNT(*) as cnt FROM analysis_history ${where}`, params);
    res.json({
      items: rows,
      page: parseInt(page, 10) || 1,
      pageSize: limit,
      total: totalRow?.cnt || 0
    });
  } catch (err) {
    console.error('History list error:', err.message);
    res.status(500).json({ error: 'error.queryFailed' });
  }
});

app.get('/api/history/detail', authMiddleware, async (req, res) => {
  const { id } = req.query || {};
  if (!id) return res.status(400).json({ error: 'error.queryFailed' });
  try {
    const row = await dbGet('SELECT * FROM analysis_history WHERE id = ? AND user_id = ?', [
      id,
      req.user.sub
    ]);
    if (!row) return res.status(404).json({ error: 'error.userNotFound' });
    res.json(row);
  } catch (err) {
    console.error('History detail error:', err.message);
    res.status(500).json({ error: 'error.queryFailed' });
  }
});

app.delete('/api/history/:id', authMiddleware, async (req, res) => {
  try {
    const result = await dbRun('DELETE FROM analysis_history WHERE id = ? AND user_id = ?', [
      req.params.id,
      req.user.sub
    ]);
    if (!result || result.changes === 0) {
      return res.status(404).json({ error: 'error.userNotFound' });
    }
    res.json({ success: true });
  } catch (err) {
    console.error('History delete error:', err.message);
    res.status(500).json({ error: 'error.deleteHistoryFailed' });
  }
});

initDb();
migrateSchema().catch((err) => {
  console.error('Schema migration failed:', err.message);
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
