const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const sqlite3 = require('sqlite3');
const { open } = require('sqlite');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 3000;
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
fs.mkdirSync(DATA_DIR, { recursive: true });

let db;

// เริ่มต้นเชื่อมต่อและสร้างตารางในฐานข้อมูล SQLite
async function initDb() {
  db = await open({
    filename: path.join(DATA_DIR, 'ecoloop.sqlite'),
    driver: sqlite3.Database
  });

  await db.exec('PRAGMA journal_mode = WAL;');
  await db.exec('PRAGMA foreign_keys = ON;');
  await db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      public_id TEXT NOT NULL,
      role TEXT NOT NULL CHECK(role IN ('student','merchant')),
      password_hash TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      UNIQUE(public_id, role)
    );
    CREATE TABLE IF NOT EXISTS sessions (
      token_hash TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      expires_at INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS sessions_user_idx ON sessions(user_id);
    CREATE TABLE IF NOT EXISTS verification_codes (
      code TEXT PRIMARY KEY,
      student_user_id INTEGER NOT NULL REFERENCES users(id),
      expires_at INTEGER NOT NULL,
      used_at INTEGER,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
    CREATE INDEX IF NOT EXISTS codes_student_idx ON verification_codes(student_user_id);
    CREATE TABLE IF NOT EXISTS transactions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      student_user_id INTEGER NOT NULL REFERENCES users(id),
      merchant_user_id INTEGER NOT NULL REFERENCES users(id),
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
    CREATE INDEX IF NOT EXISTS tx_student_idx ON transactions(student_user_id, id DESC);
    CREATE INDEX IF NOT EXISTS tx_merchant_idx ON transactions(merchant_user_id, id DESC);
  `);
}

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '20kb' }));
app.use('/api/', rateLimit({ windowMs: 60_000, limit: 120, standardHeaders: 'draft-7', legacyHeaders: false }));

const cookieName = 'ecoloop_session';
const hashToken = token => crypto.createHash('sha256').update(token).digest('hex');

async function setSession(res, userId) {
  const token = crypto.randomBytes(32).toString('hex');
  const expires = Date.now() + 7 * 24 * 60 * 60 * 1000;
  await db.run('INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(?,?,?)', hashToken(token), userId, expires);
  res.cookie(cookieName, token, { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'strict', path: '/', maxAge: 7 * 24 * 60 * 60 * 1000 });
}

async function auth(req, res, next) {
  const token = req.cookies?.[cookieName];
  if (!token) return res.status(401).json({ error: 'กรุณาเข้าสู่ระบบก่อน' });
  
  const row = await db.get(`SELECT u.id,u.public_id,u.role,s.expires_at FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=?`, hashToken(token));
  if (!row || row.expires_at < Date.now()) {
    if (token) await db.run('DELETE FROM sessions WHERE token_hash=?', hashToken(token));
    res.clearCookie(cookieName, { path: '/' });
    return res.status(401).json({ error: 'เซสชันหมดอายุ กรุณาเข้าสู่ระบบใหม่' });
  }
  req.user = { dbId: row.id, id: row.public_id, role: row.role };
  next();
}

const requireRole = role => (req, res, next) => req.user.role === role ? next() : res.status(403).json({ error: 'ไม่มีสิทธิ์ใช้งานส่วนนี้' });
function publicUser(u) { return { id: u.id, role: u.role }; }

app.use((req, res, next) => {
  req.cookies = {};
  (req.headers.cookie || '').split(';').forEach(part => { 
    const i = part.indexOf('='); 
    if (i > 0) req.cookies[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim()); 
  });
  next();
});

app.post('/api/register', async (req, res) => {
  const { id, password, role } = req.body || {};
  if (!/^\d{5,20}$/.test(String(id || '')) || typeof password !== 'string' || password.length < 6 || password.length > 128 || !['student', 'merchant'].includes(role)) {
    return res.status(400).json({ error: 'กรอกรหัสตัวเลข 5–20 หลัก และรหัสผ่าน 6–128 ตัวอักษร' });
  }
  try {
    const result = await db.run('INSERT INTO users(public_id,role,password_hash) VALUES(?,?,?)', String(id), role, await bcrypt.hash(password, 12));
    await setSession(res, result.lastID);
    res.json({ user: { id: String(id), role } });
  } catch (e) { 
    if (String(e.message).includes('UNIQUE')) return res.status(409).json({ error: 'รหัสนี้สมัครบัญชีประเภทนี้ไว้แล้ว กรุณาเข้าสู่ระบบ' }); 
    res.status(500).json({ error: 'ไม่สามารถสร้างบัญชีได้' }); 
  }
});

app.post('/api/login', async (req, res) => {
  const { id, password, role } = req.body || {};
  if (!/^\d{5,20}$/.test(String(id || '')) || typeof password !== 'string' || !['student', 'merchant'].includes(role)) {
    return res.status(400).json({ error: 'ข้อมูลเข้าสู่ระบบไม่ถูกต้อง' });
  }
  const row = await db.get('SELECT * FROM users WHERE public_id=? AND role=?', String(id), role);
  if (!row || !(await bcrypt.compare(password, row.password_hash))) {
    return res.status(401).json({ error: 'ไม่พบบัญชีหรือรหัสผ่านไม่ถูกต้อง หากยังไม่มีบัญชีให้กดสมัครบัญชีใหม่' });
  }
  await setSession(res, row.id);
  res.json({ user: { id: row.public_id, role: row.role } });
});

app.get('/api/me', auth, (req, res) => res.json({ user: publicUser(req.user) }));

app.post('/api/logout', async (req, res) => {
  const token = req.cookies?.[cookieName];
  if (token) await db.run('DELETE FROM sessions WHERE token_hash=?', hashToken(token));
  res.clearCookie(cookieName, { path: '/' });
  res.json({ ok: true });
});

app.post('/api/codes', auth, requireRole('student'), async (req, res) => {
  await db.run('UPDATE verification_codes SET used_at=? WHERE student_user_id=? AND used_at IS NULL', Date.now(), req.user.dbId);
  let code; 
  do { 
    code = String(crypto.randomInt(100000, 1000000)); 
  } while (await db.get('SELECT 1 FROM verification_codes WHERE code=?', code));
  
  const expires = Date.now() + 60_000;
  await db.run('INSERT INTO verification_codes(code,student_user_id,expires_at) VALUES(?,?,?)', code, req.user.dbId, expires);
  res.json({ code, expires_at: new Date(expires).toISOString() });
});

app.post('/api/codes/lookup', auth, requireRole('merchant'), async (req, res) => {
  const code = String(req.body?.code || '');
  if (!/^\d{6}$/.test(code)) return res.status(400).json({ error: 'กรุณากรอกรหัส 6 หลัก' });
  const row = await db.get(`SELECT v.*,u.public_id AS student_id FROM verification_codes v JOIN users u ON u.id=v.student_user_id WHERE v.code=?`, code);
  if (!row || row.used_at || row.expires_at <= Date.now()) return res.status(404).json({ error: 'ไม่พบรหัส รหัสหมดอายุ หรือถูกใช้ไปแล้ว' });
  res.json({ student_id: row.student_id });
});

app.post('/api/codes/confirm', auth, requireRole('merchant'), async (req, res) => {
  const code = String(req.body?.code || '');
  if (req.body?.observed !== true) return res.status(400).json({ error: 'กรุณายืนยันว่าเห็นการใช้แก้วส่วนตัวจริง' });
  if (!/^\d{6}$/.test(code)) return res.status(400).json({ error: 'รหัสไม่ถูกต้อง' });
  
  try { 
    const row = await db.get('SELECT * FROM verification_codes WHERE code=?', code);
    if (!row || row.used_at || row.expires_at <= Date.now()) return res.status(409).json({ error: 'รหัสหมดอายุหรือถูกใช้ไปแล้ว' });
    
    const updateResult = await db.run('UPDATE verification_codes SET used_at=? WHERE code=? AND used_at IS NULL AND expires_at>?', Date.now(), code, Date.now());
    if (updateResult.changes === 0) return res.status(409).json({ error: 'รหัสหมดอายุหรือถูกใช้ไปแล้ว' });
    
    await db.run('INSERT INTO transactions(student_user_id,merchant_user_id) VALUES(?,?)', row.student_user_id, req.user.dbId);
    res.json({ ok: true, points_awarded: 100 }); 
  } catch (e) {
    res.status(500).json({ error: 'บันทึกรายการไม่สำเร็จ' });
  }
});

app.get('/api/dashboard', auth, async (req, res) => {
  if (req.user.role === 'student') {
    const tx = await db.all(`SELECT t.id,t.created_at,m.public_id AS merchant_id FROM transactions t JOIN users m ON m.id=t.merchant_user_id WHERE t.student_user_id=? ORDER BY t.id DESC LIMIT 100`, req.user.dbId);
    const active = await db.get('SELECT code,expires_at FROM verification_codes WHERE student_user_id=? AND used_at IS NULL AND expires_at>? ORDER BY expires_at DESC LIMIT 1', req.user.dbId, Date.now());
    const cupsRow = await db.get('SELECT COUNT(*) AS n FROM transactions WHERE student_user_id=?', req.user.dbId);
    const pointsRow = await db.get('SELECT COUNT(*)*100 AS n FROM transactions WHERE student_user_id=?', req.user.dbId);
    
    res.json({
      transactions: tx,
      stats: { cups: cupsRow ? cupsRow.n : 0, points: pointsRow ? pointsRow.n : 0 },
      activeCode: active ? { code: active.code, expires_at: new Date(active.expires_at).toISOString() } : null
    });
  } else {
    const tx = await db.all(`SELECT t.id,t.created_at,s.public_id AS student_id FROM transactions t JOIN users s ON s.id=t.student_user_id WHERE t.merchant_user_id=? ORDER BY t.id DESC LIMIT 100`, req.user.dbId);
    const todayRow = await db.get(`SELECT COUNT(*) AS n FROM transactions WHERE merchant_user_id=? AND date(created_at,'localtime')=date('now','localtime')`, req.user.dbId);
    
    res.json({ transactions: tx, stats: { today: todayRow ? todayRow.n : 0 } });
  }
});

app.use(express.static(path.join(__dirname, 'public')));
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

// เริ่มต้นฐานข้อมูลก่อนสั่งรันเซิร์ฟเวอร์
initDb().then(() => {
  app.listen(PORT, () => console.log(`EcoLoop server running on port ${PORT}`));
}).catch(err => {
  console.error('Failed to initialize database:', err);
});