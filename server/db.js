const { DatabaseSync } = require('node:sqlite');
const bcrypt = require('bcryptjs');
const path = require('path');

const db = new DatabaseSync(path.join(__dirname, 'queuesmart.db'));

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT UNIQUE NOT NULL,
  password TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'citizen'
);
CREATE TABLE IF NOT EXISTS counters (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  staff_id INTEGER,
  status TEXT NOT NULL DEFAULT 'open'
);
CREATE TABLE IF NOT EXISTS tokens (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  number TEXT NOT NULL,
  citizen_id INTEGER NOT NULL,
  service TEXT NOT NULL,
  category TEXT NOT NULL,
  priority INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'waiting',
  counter_id INTEGER,
  created_at INTEGER NOT NULL,
  called_at INTEGER,
  done_at INTEGER
);
`);

if (db.prepare('SELECT COUNT(*) c FROM users').get().c === 0) {
  const add = db.prepare('INSERT INTO users (name,email,password,role) VALUES (?,?,?,?)');
  add.run('Admin', 'admin@queue.com', bcrypt.hashSync('admin123', 8), 'admin');
  const s1 = add.run('Staff One', 'staff1@queue.com', bcrypt.hashSync('staff123', 8), 'staff').lastInsertRowid;
  const s2 = add.run('Staff Two', 'staff2@queue.com', bcrypt.hashSync('staff123', 8), 'staff').lastInsertRowid;
  const s3 = add.run('Staff Three', 'staff3@queue.com', bcrypt.hashSync('staff123', 8), 'staff').lastInsertRowid;
  const c = db.prepare('INSERT INTO counters (name,staff_id,status) VALUES (?,?,?)');
  c.run('Counter 1', s1, 'open');
  c.run('Counter 2', s2, 'closed');
  c.run('Counter 3', s3, 'closed');
}

module.exports = db;
