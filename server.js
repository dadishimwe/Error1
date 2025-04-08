const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const session = require('express-session');
const csrf = require('csurf');
const bcrypt = require('bcrypt');
const { body, validationResult } = require('express-validator');
require('dotenv').config();

const app = express();
const db = new sqlite3.Database('./database.db');
const saltRounds = 10;

app.use(express.json());
app.use(express.static('public'));
app.use(session({
  secret: process.env.SESSION_SECRET || 'default-secret-please-change',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production', // HTTPS in production
    httpOnly: true, // Prevents client-side access
    sameSite: 'strict' // Mitigates CSRF
  }
}));
app.use(csrf({ cookie: true }));

// Optimize SQLite for Raspberry Pi
db.serialize(() => {
  db.run('PRAGMA synchronous = OFF;');
  db.run('PRAGMA journal_mode = WAL;');
  db.run('PRAGMA foreign_keys = ON;'); // Enable foreign key enforcement

  // Users table
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE,
      name TEXT,
      password TEXT,
      role TEXT DEFAULT 'staff'
    )`);

  // Expenses table
  db.run(`
    CREATE TABLE IF NOT EXISTS expenses (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      userId INTEGER,
      amount REAL,
      description TEXT,
      date TEXT,
      status TEXT DEFAULT 'Pending',
      adminNote TEXT,
      FOREIGN KEY(userId) REFERENCES users(id)
    )`);

  // Inventory table
  db.run(`
    CREATE TABLE IF NOT EXISTS inventory (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      item_type TEXT,
      item_id TEXT UNIQUE,
      status TEXT,
      location TEXT,
      checked_out_to INTEGER,
      installed_at INTEGER,
      FOREIGN KEY(checked_out_to) REFERENCES users(id),
      FOREIGN KEY(installed_at) REFERENCES clients(id)
    )`);

  // Clients table
  db.run(`
    CREATE TABLE IF NOT EXISTS clients (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT,
      address TEXT,
      contact TEXT,
      notes TEXT
    )`);

  // Issues table
  db.run(`
    CREATE TABLE IF NOT EXISTS issues (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      client_id INTEGER,
      inventory_id INTEGER,
      title TEXT,
      description TEXT,
      status TEXT DEFAULT 'Open',
      created_at TEXT,
      updated_at TEXT,
      created_by INTEGER,
      assigned_to INTEGER,
      FOREIGN KEY(client_id) REFERENCES clients(id),
      FOREIGN KEY(inventory_id) REFERENCES inventory(id),
      FOREIGN KEY(created_by) REFERENCES users(id),
      FOREIGN KEY(assigned_to) REFERENCES users(id)
    )`);

  // Audit logs table
  db.run(`
    CREATE TABLE IF NOT EXISTS audit_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      action TEXT,
      userId INTEGER,
      details TEXT,
      timestamp TEXT,
      FOREIGN KEY(userId) REFERENCES users(id)
    )`);

  // Add indexes for performance
  db.run('CREATE INDEX IF NOT EXISTS idx_expenses_userId ON expenses(userId)');
  db.run('CREATE INDEX IF NOT EXISTS idx_inventory_status ON inventory(status)');
  db.run('CREATE INDEX IF NOT EXISTS idx_issues_client_id ON issues(client_id)');
});

// Middleware to check authentication
function isAuthenticated(req, res, next) {
  if (req.session.user) next();
  else res.status(401).json({ error: 'Unauthorized' });
}

function isAdmin(req, res, next) {
  if (req.session.user && req.session.user.role === 'admin') next();
  else res.status(403).json({ error: 'Forbidden' });
}

// CSRF token route
app.get('/csrf-token', (req, res) => res.json({ token: req.csrfToken() }));

// User routes
app.post('/signup', [
  body('username').trim().isLength({ min: 3 }),
  body('name').trim(),
  body('password').matches(/^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{8,}$/)
], (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
  const { username, name, password } = req.body;
  bcrypt.hash(password, saltRounds, (err, hash) => {
    if (err) return res.status(500).json({ error: 'Error hashing password' });
    db.run(`INSERT INTO users (username, name, password, role) VALUES (?, ?, ?, 'staff')`,
      [username, name, hash], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ id: this.lastID });
      });
  });
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  db.get(`SELECT * FROM users WHERE username = ?`, [username], (err, user) => {
    if (err || !user) return res.status(401).json({ error: 'Invalid credentials' });
    bcrypt.compare(password, user.password, (err, match) => {
      if (err || !match) return res.status(401).json({ error: 'Invalid credentials' });
      req.session.user = user;
      res.json({ role: user.role });
    });
  });
});

app.get('/logout', (req, res) => {
  req.session.destroy();
  res.json({ success: true });
});

// Expense routes
app.get('/expenses', isAuthenticated, (req, res) => {
  const limit = 50;
  const page = req.query.page || 1;
  const offset = (page - 1) * limit;
  db.all(`SELECT e.*, u.name as staffName FROM expenses e JOIN users u ON e.userId = u.id LIMIT ? OFFSET ?`,
    [limit, offset], (err, rows) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json(rows);
    });
});

app.post('/expenses', isAuthenticated, [
  body('amount').isFloat({ min: 0 }),
  body('description').trim().escape(),
  body('date').isISO8601()
], (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
  const { amount, description, date } = req.body;
  db.run(`INSERT INTO expenses (userId, amount, description, date) VALUES (?, ?, ?, ?)`,
    [req.session.user.id, amount, description, date], function(err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ id: this.lastID });
    });
});

app.put('/expenses/:id', isAdmin, (req, res) => {
  const { status, adminNote } = req.body;
  db.run(`UPDATE expenses SET status = ?, adminNote = ? WHERE id = ?`,
    [status, adminNote, req.params.id], function(err) {
      if (err) return res.status(500).json({ error: err.message });
      db.run(`INSERT INTO audit_logs (action, userId, details, timestamp) VALUES (?, ?, ?, ?)`,
        ['reimburse', req.session.user.id, `Reimbursed expense ${req.params.id}`, new Date().toISOString()]);
      res.json({ changes: this.changes });
    });
});

// Inventory routes
app.get('/inventory', isAuthenticated, (req, res) => {
  const limit = 50;
  const page = req.query.page || 1;
  const offset = (page - 1) * limit;
  db.all(`SELECT i.*, u.name as checkedOutTo FROM inventory i LEFT JOIN users u ON i.checked_out_to = u.id LIMIT ? OFFSET ?`,
    [limit, offset], (err, rows) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json(rows);
    });
});

app.post('/inventory', isAdmin, [
  body('item_type').trim().escape(),
  body('item_id').trim().escape(),
  body('status').isIn(['In Stock', 'Checked Out', 'Installed']),
  body('location').trim().escape()
], (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
  const { item_type, item_id, status, location } = req.body;
  db.run(`INSERT INTO inventory (item_type, item_id, status, location) VALUES (?, ?, ?, ?)`,
    [item_type, item_id, status, location], function(err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ id: this.lastID });
    });
});

app.put('/inventory/:id', isAuthenticated, (req, res) => {
  const { status, checked_out_to, installed_at } = req.body;
  db.run(`UPDATE inventory SET status = ?, checked_out_to = ?, installed_at = ? WHERE id = ?`,
    [status, checked_out_to || null, installed_at || null, req.params.id], function(err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ changes: this.changes });
    });
});

// Client routes
app.get('/clients', isAuthenticated, (req, res) => {
  const limit = 50;
  const page = req.query.page || 1;
  const offset = (page - 1) * limit;
  db.all(`SELECT * FROM clients LIMIT ? OFFSET ?`, [limit, offset], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.post('/clients', isAuthenticated, [
  body('name').trim().escape(),
  body('address').trim().escape(),
  body('contact').trim().escape(),
  body('notes').trim().escape()
], (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
  const { name, address, contact, notes } = req.body;
  db.run(`INSERT INTO clients (name, address, contact, notes) VALUES (?, ?, ?, ?)`,
    [name, address, contact, notes], function(err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ id: this.lastID });
    });
});

app.delete('/clients/:id', isAdmin, (req, res) => {
  db.get(`SELECT COUNT(*) AS count FROM issues WHERE client_id = ?`, [req.params.id], (err, row) => {
    if (err) return res.status(500).json({ error: err.message });
    if (row.count > 0) return res.status(400).json({ error: 'Client has active issues' });
    db.get(`SELECT COUNT(*) AS count FROM inventory WHERE installed_at = ?`, [req.params.id], (err, row) => {
      if (err) return res.status(500).json({ error: err.message });
      if (row.count > 0) return res.status(400).json({ error: 'Client has installed inventory' });
      db.run(`DELETE FROM clients WHERE id = ?`, [req.params.id], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ changes: this.changes });
      });
    });
  });
});

// Issue routes
app.get('/issues', isAuthenticated, (req, res) => {
  const limit = 50;
  const page = req.query.page || 1;
  const offset = (page - 1) * limit;
  db.all(`SELECT i.*, c.name as clientName, u.name as assignedTo FROM issues i 
          LEFT JOIN clients c ON i.client_id = c.id 
          LEFT JOIN users u ON i.assigned_to = u.id LIMIT ? OFFSET ?`,
    [limit, offset], (err, rows) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json(rows);
    });
});

app.post('/issues', isAuthenticated, [
  body('client_id').isInt(),
  body('title').trim().escape(),
  body('description').trim().escape(),
  body('assigned_to').isInt().optional()
], (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
  const { client_id, inventory_id, title, description, assigned_to } = req.body;
  const now = new Date().toISOString();
  db.run(`INSERT INTO issues (client_id, inventory_id, title, description, status, created_at, updated_at, created_by, assigned_to) 
          VALUES (?, ?, ?, ?, 'Open', ?, ?, ?, ?)`,
    [client_id, inventory_id || null, title, description, now, now, req.session.user.id, assigned_to || null], function(err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ id: this.lastID });
    });
});

app.put('/issues/:id', isAuthenticated, (req, res) => {
  const { status } = req.body;
  db.run(`UPDATE issues SET status = ? WHERE id = ?`, [status, req.params.id], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ changes: this.changes });
  });
});

app.get('/users', isAuthenticated, (req, res) => {
  db.all(`SELECT id, name FROM users`, (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.listen(3000, () => console.log('Server running on port 3000'));