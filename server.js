const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const crypto = require('crypto');
const path = require('path');

const app = express();
app.use(express.json());
app.use(cors());
app.use(express.static(path.join(__dirname, 'public')));

// SQLite database stored in memory/file
const db = new sqlite3.Database('./secrets.db');

db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS secrets (
      token TEXT PRIMARY KEY,
      compartments TEXT NOT NULL
    )
  `);
});

// Helper for SHA-256
function hashPassword(pw) {
  return crypto.createHash('sha256').update(pw || '').digest('hex');
}

// POST /api/create - Save secret and return a unique token
app.post('/api/create', (req, res) => {
  const { mode, compartments } = req.body;
  if (!compartments || !Array.isArray(compartments) || compartments.length === 0) {
    return res.status(400).json({ error: 'Invalid payload' });
  }

  const token = crypto.randomBytes(16).toString('hex');
  const storedCompartments = compartments.map(c => ({
    text: c.text,
    password: c.password,
    viewsLeft: Number(c.views) || 1,
    expiry: c.expiry ? new Date(c.expiry).getTime() : null,
    copy: Boolean(c.copy)
  }));

  db.run(
    'INSERT INTO secrets (token, compartments) VALUES (?, ?)',
    [token, JSON.stringify(storedCompartments)],
    (err) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      res.json({ token });
    }
  );
});

// POST /api/reveal - Verify password and decrement view count / delete if burned
app.post('/api/reveal', (req, res) => {
  const { token, password } = req.body;
  if (!token) return res.status(400).json({ error: 'Token missing' });

  db.get('SELECT * FROM secrets WHERE token = ?', [token], (err, row) => {
    if (err || !row) return res.status(404).json({ error: 'Secret burned or does not exist.' });

    let compartments = JSON.parse(row.compartments);
    const userHash = hashPassword(password);

    const index = compartments.findIndex(c => c.password === userHash);
    if (index === -1) {
      return res.status(401).json({ error: 'Invalid password.' });
    }

    const matched = compartments[index];
    const now = Date.now();

    if (matched.expiry && now > matched.expiry) {
      deleteCompartment(token, compartments, index);
      return res.status(410).json({ error: 'Message has expired.' });
    }

    matched.viewsLeft -= 1;

    const responsePayload = {
      text: matched.text,
      expiry: matched.expiry,
      copy: matched.copy
    };

    if (matched.viewsLeft <= 0) {
      deleteCompartment(token, compartments, index);
    } else {
      db.run('UPDATE secrets SET compartments = ? WHERE token = ?', [JSON.stringify(compartments), token]);
    }

    res.json(responsePayload);
  });
});

function deleteCompartment(token, compartments, index) {
  compartments.splice(index, 1);
  if (compartments.length === 0) {
    db.run('DELETE FROM secrets WHERE token = ?', [token]);
  } else {
    db.run('UPDATE secrets SET compartments = ? WHERE token = ?', [JSON.stringify(compartments), token]);
  }
}

// Serve message.html for clean subpage URL paths (/message/RANDOM_TOKEN)
app.get('/message/:token', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'message.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
