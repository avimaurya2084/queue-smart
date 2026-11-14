const express = require('express');
const cors = require('cors');
const http = require('http');
const path = require('path');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { Server } = require('socket.io');
const db = require('./db');

const SECRET = process.env.JWT_SECRET || 'queuesmart_secret_key';
const PORT = process.env.PORT || 5001;
const TARGET_WAIT_MIN = 10;
const AGING_MS = 15 * 60000;
const ORDER = `ORDER BY (created_at - priority * ${AGING_MS}) ASC, id ASC`;
let autoMode = false;

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' } });

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

function auth(...roles) {
  return (req, res, next) => {
    const h = req.headers.authorization || '';
    try {
      req.user = jwt.verify(h.replace('Bearer ', ''), SECRET);
    } catch {
      return res.status(401).json({ error: 'Login required' });
    }
    if (roles.length && !roles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Not allowed' });
    }
    next();
  };
}

function avgServiceMin(service) {
  const q = (svc) =>
    db
      .prepare(`SELECT (done_at - called_at) AS d FROM tokens WHERE status='done' AND called_at IS NOT NULL AND done_at IS NOT NULL ${svc ? 'AND service=?' : ''} ORDER BY done_at DESC LIMIT 10`)
      .all(...(svc ? [svc] : []));
  let rows = service ? q(service) : [];
  if (rows.length < 3) rows = q();
  if (!rows.length) return 5;
  const avg = rows.reduce((s, r) => s + r.d, 0) / rows.length / 60000;
  return Math.max(0.5, avg);
}

function openCount() {
  return db.prepare("SELECT COUNT(*) c FROM counters WHERE status='open'").get().c;
}

function snapshot() {
  const avg = avgServiceMin();
  const open = Math.max(1, openCount());
  const cache = {};
  const avgFor = (svc) => (cache[svc] ??= avgServiceMin(svc));
  let cum = 0;
  const waiting = db
    .prepare(`SELECT id, number, service, category, priority, created_at FROM tokens WHERE status='waiting' ${ORDER}`)
    .all()
    .map((t, i) => {
      cum += avgFor(t.service);
      return { ...t, position: i + 1, etaMin: Math.ceil(cum / open) };
    });
  const counters = db
    .prepare("SELECT c.id, c.name, c.status, c.staff_id, u.name AS staff, t.number AS serving FROM counters c LEFT JOIN users u ON u.id = c.staff_id LEFT JOIN tokens t ON t.counter_id = c.id AND t.status = 'serving' ORDER BY c.id")
    .all()
    .map((c) => ({ ...c }));
  return { avgServiceMin: Number(avg.toFixed(1)), openCounters: openCount(), autoMode, waiting, counters };
}

function broadcast() {
  if (autoMode) applyAllocation();
  io.emit('queue:update', snapshot());
}

function sign(u) {
  return jwt.sign({ id: u.id, name: u.name, role: u.role }, SECRET, { expiresIn: '1d' });
}

app.post('/api/auth/register', (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) return res.status(400).json({ error: 'All fields required' });
  if (db.prepare('SELECT id FROM users WHERE email=?').get(email)) {
    return res.status(400).json({ error: 'Email already registered' });
  }
  const id = db
    .prepare('INSERT INTO users (name,email,password,role) VALUES (?,?,?,?)')
    .run(name, email, bcrypt.hashSync(password, 8), 'citizen').lastInsertRowid;
  const user = { id: Number(id), name, role: 'citizen' };
  res.json({ token: sign(user), user });
});

app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body;
  const u = db.prepare('SELECT * FROM users WHERE email=?').get(email || '');
  if (!u || !bcrypt.compareSync(password || '', u.password)) {
    return res.status(401).json({ error: 'Invalid email or password' });
  }
  const user = { id: u.id, name: u.name, role: u.role };
  res.json({ token: sign(user), user });
});

app.get('/api/queue', (req, res) => res.json(snapshot()));

app.post('/api/tokens', auth('citizen'), (req, res) => {
  const { service, category } = req.body;
  if (!service) return res.status(400).json({ error: 'Service required' });
  const cat = ['normal', 'senior', 'disabled'].includes(category) ? category : 'normal';
  const active = db
    .prepare("SELECT id FROM tokens WHERE citizen_id=? AND status IN ('waiting','serving')")
    .get(req.user.id);
  if (active) return res.status(400).json({ error: 'You already have an active token' });
  const priority = cat === 'normal' ? 0 : 1;
  const r = db
    .prepare('INSERT INTO tokens (number,citizen_id,service,category,priority,created_at) VALUES (?,?,?,?,?,?)')
    .run('TMP', req.user.id, service, cat, priority, Date.now());
  const id = Number(r.lastInsertRowid);
  const number = (priority ? 'P' : 'N') + String(id).padStart(3, '0');
  db.prepare('UPDATE tokens SET number=? WHERE id=?').run(number, id);
  broadcast();
  res.json({ id, number });
});

app.get('/api/tokens/my', auth('citizen'), (req, res) => {
  const snap = snapshot();
  const rows = db
    .prepare('SELECT t.id, t.number, t.service, t.category, t.status, t.created_at, c.name AS counter FROM tokens t LEFT JOIN counters c ON c.id = t.counter_id WHERE t.citizen_id=? ORDER BY t.id DESC LIMIT 10')
    .all(req.user.id)
    .map((t) => {
      const w = snap.waiting.find((x) => x.id === t.id);
      return { ...t, position: w ? w.position : null, etaMin: w ? w.etaMin : null };
    });
  res.json(rows);
});

function ownCounter(req, res) {
  const c = db.prepare('SELECT * FROM counters WHERE id=?').get(Number(req.params.id));
  if (!c) {
    res.status(404).json({ error: 'Counter not found' });
    return null;
  }
  if (req.user.role !== 'admin' && c.staff_id !== req.user.id) {
    res.status(403).json({ error: 'Not your counter' });
    return null;
  }
  return c;
}

app.post('/api/counters/:id/call-next', auth('staff', 'admin'), (req, res) => {
  const c = ownCounter(req, res);
  if (!c) return;
  if (c.status !== 'open') return res.status(400).json({ error: 'Counter is closed' });
  if (db.prepare("SELECT id FROM tokens WHERE counter_id=? AND status='serving'").get(c.id)) {
    return res.status(400).json({ error: 'Complete or skip the current token first' });
  }
  const next = db
    .prepare(`SELECT id, number FROM tokens WHERE status='waiting' ${ORDER} LIMIT 1`)
    .get();
  if (!next) return res.status(400).json({ error: 'No one is waiting' });
  db.prepare("UPDATE tokens SET status='serving', counter_id=?, called_at=? WHERE id=?").run(c.id, Date.now(), next.id);
  broadcast();
  res.json({ number: next.number });
});

function finish(status) {
  return (req, res) => {
    const c = ownCounter(req, res);
    if (!c) return;
    const t = db.prepare("SELECT id FROM tokens WHERE counter_id=? AND status='serving'").get(c.id);
    if (!t) return res.status(400).json({ error: 'No token being served' });
    db.prepare('UPDATE tokens SET status=?, done_at=? WHERE id=?').run(status, Date.now(), t.id);
    broadcast();
    res.json({ ok: true });
  };
}
app.post('/api/counters/:id/complete', auth('staff', 'admin'), finish('done'));
app.post('/api/counters/:id/skip', auth('staff', 'admin'), finish('skipped'));

app.post('/api/counters/:id/toggle', auth('admin'), (req, res) => {
  const c = db.prepare('SELECT * FROM counters WHERE id=?').get(Number(req.params.id));
  if (!c) return res.status(404).json({ error: 'Counter not found' });
  if (c.status === 'open' && db.prepare("SELECT id FROM tokens WHERE counter_id=? AND status='serving'").get(c.id)) {
    return res.status(400).json({ error: 'Counter is serving a token' });
  }
  db.prepare('UPDATE counters SET status=? WHERE id=?').run(c.status === 'open' ? 'closed' : 'open', c.id);
  broadcast();
  res.json({ ok: true });
});

function suggestion() {
  const rows = db.prepare("SELECT service FROM tokens WHERE status='waiting'").all();
  const total = db.prepare('SELECT COUNT(*) c FROM counters').get().c;
  const cache = {};
  const workMin = rows.reduce((s, r) => s + (cache[r.service] ??= avgServiceMin(r.service)), 0);
  const recommended = Math.min(total, Math.max(1, Math.ceil(workMin / TARGET_WAIT_MIN)));
  return { waiting: rows.length, avgServiceMin: Number(avgServiceMin().toFixed(1)), workMin: Number(workMin.toFixed(1)), targetWaitMin: TARGET_WAIT_MIN, open: openCount(), recommended, autoMode };
}

function applyAllocation() {
  const { recommended } = suggestion();
  const counters = db.prepare('SELECT id, status FROM counters ORDER BY id').all();
  let open = counters.filter((c) => c.status === 'open').length;
  for (const c of counters) {
    if (open >= recommended) break;
    if (c.status === 'closed') {
      db.prepare("UPDATE counters SET status='open' WHERE id=?").run(c.id);
      open++;
    }
  }
  for (const c of [...counters].reverse()) {
    if (open <= recommended) break;
    const live = db.prepare('SELECT status FROM counters WHERE id=?').get(c.id);
    const busy = db.prepare("SELECT id FROM tokens WHERE counter_id=? AND status='serving'").get(c.id);
    if (live.status === 'open' && !busy) {
      db.prepare("UPDATE counters SET status='closed' WHERE id=?").run(c.id);
      open--;
    }
  }
}

app.get('/api/allocation/suggest', auth('admin'), (req, res) => res.json(suggestion()));

app.post('/api/allocation/apply', auth('admin'), (req, res) => {
  applyAllocation();
  broadcast();
  res.json(suggestion());
});

app.post('/api/allocation/auto', auth('admin'), (req, res) => {
  autoMode = !!req.body.enabled;
  broadcast();
  res.json(suggestion());
});

app.get('/api/stats', auth('admin'), (req, res) => {
  const count = (s) => db.prepare('SELECT COUNT(*) c FROM tokens WHERE status=?').get(s).c;
  res.json({ waiting: count('waiting'), serving: count('serving'), done: count('done'), skipped: count('skipped'), avgServiceMin: Number(avgServiceMin().toFixed(1)) });
});

app.get('/api/analytics', auth('admin'), (req, res) => {
  const rows = db.prepare('SELECT service, category, status, counter_id, created_at, called_at, done_at FROM tokens').all();
  const hourly = Array(24).fill(0);
  const cat = { normal: 0, senior: 0, disabled: 0 };
  const svc = {};
  const ctr = {};
  let waitSum = 0;
  let waitN = 0;
  for (const t of rows) {
    hourly[new Date(t.created_at).getHours()]++;
    cat[t.category] = (cat[t.category] || 0) + 1;
    const s = (svc[t.service] ||= { service: t.service, count: 0, served: 0, svcSum: 0, waitSum: 0, waitN: 0 });
    s.count++;
    if (t.called_at) {
      s.waitSum += t.called_at - t.created_at;
      s.waitN++;
      waitSum += t.called_at - t.created_at;
      waitN++;
    }
    if (t.status === 'done' && t.called_at && t.done_at) {
      s.served++;
      s.svcSum += t.done_at - t.called_at;
      ctr[t.counter_id] = (ctr[t.counter_id] || 0) + 1;
    }
  }
  const max = Math.max(...hourly);
  const m = (ms, n) => (n ? Number((ms / n / 60000).toFixed(1)) : 0);
  res.json({
    total: rows.length,
    hourly,
    busiestHour: max > 0 ? hourly.indexOf(max) : null,
    avgWaitMin: m(waitSum, waitN),
    categories: cat,
    services: Object.values(svc).map((s) => ({ service: s.service, count: s.count, served: s.served, avgServiceMin: m(s.svcSum, s.served), avgWaitMin: m(s.waitSum, s.waitN) })),
    counters: db.prepare('SELECT id, name FROM counters ORDER BY id').all().map((c) => ({ name: c.name, served: ctr[c.id] || 0 })),
  });
});

app.post('/api/simulate', auth('admin'), (req, res) => {
  const n = Math.min(30, Math.max(1, Number(req.body.count) || 10));
  const services = ['Certificates', 'Tax', 'Licence', 'Enquiry'];
  const ins = db.prepare('INSERT INTO tokens (number,citizen_id,service,category,priority,created_at) VALUES (?,?,?,?,?,?)');
  const now = Date.now();
  for (let i = 0; i < n; i++) {
    const r = Math.random();
    const category = r < 0.7 ? 'normal' : r < 0.9 ? 'senior' : 'disabled';
    const priority = category === 'normal' ? 0 : 1;
    const service = services[Math.floor(Math.random() * services.length)];
    const id = Number(ins.run('TMP', 0, service, category, priority, now + i).lastInsertRowid);
    db.prepare('UPDATE tokens SET number=? WHERE id=?').run((priority ? 'P' : 'N') + String(id).padStart(3, '0'), id);
  }
  broadcast();
  res.json({ added: n });
});

app.post('/api/simulate/clear', auth('admin'), (req, res) => {
  db.prepare("DELETE FROM tokens WHERE citizen_id=0 AND status='waiting'").run();
  broadcast();
  res.json({ ok: true });
});

io.on('connection', (socket) => socket.emit('queue:update', snapshot()));

server.listen(PORT, () => console.log(`QueueSmart running on http://localhost:${PORT}`));
