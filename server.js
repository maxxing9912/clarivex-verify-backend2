// server.js
const express = require('express');
const crypto = require('crypto');
const bodyParser = require('body-parser');
const cors = require('cors');
const path = require('path');

const { Low } = require('lowdb');
const { JSONFile } = require('lowdb/node');

const app = express();
app.use(cors());
app.use(bodyParser.json());

// LowDB setup
const file = path.join(__dirname, 'db.json');
const adapter = new JSONFile(file);
const defaultData = {
  verifycodes: {},    // discordId → code
  verifydata: {},     // discordId → { robloxUsername, code, hashes… }
  ipconfirmed: {}     // discordId → true
};
const db = new Low(adapter, defaultData);
(async () => {
  await db.read();
  await db.write();
})();

// Health check
app.get('/', (req, res) => {
  res.send('Backend is running');
});

// 1) CLICK-LINK endpoint
app.get('/api/confirm', async (req, res) => {
  try {
    const { discordId, code } = req.query;
    if (!discordId || !code) {
      return res.status(400).send('<h1>Missing discordId or code</h1>');
    }

    await db.read();
    const saved = db.data.verifycodes[discordId];
    if (!saved || saved !== code) {
      return res.status(400).send('<h1>Invalid or expired code</h1>');
    }

    db.data.ipconfirmed[discordId] = true;
    await db.write();

    return res.send(`
      <h1>✅ Device confirmed!</h1>
      <p>You can now return to Discord and click “Complete Verification.”</p>
    `);
  } catch (err) {
    console.error('[/api/confirm] Error:', err);
    return res.status(500).send('<h1>Server error</h1>');
  }
});

// 2) FRONTEND POST endpoint
app.post('/api/verify', async (req, res) => {
  try {
    const { discordId, code, fingerprint, ip, robloxUsername } = req.body;
    if (!discordId || !code || !fingerprint || !ip || !robloxUsername) {
      return res.status(400).json({ error: 'Missing required parameters.' });
    }

    await db.read();
    const saved = db.data.verifycodes[discordId];
    if (saved !== code) {
      return res.status(400).json({ error: 'Invalid verification code.' });
    }

    const hash = s => crypto.createHash('sha256').update(s).digest('hex');
    db.data.verifydata[discordId] = {
      robloxUsername,
      code,
      fingerprintHash: hash(fingerprint),
      ipHash: hash(ip),
      timestamp: Date.now()
    };
    db.data.ipconfirmed[discordId] = true;
    delete db.data.verifycodes[discordId];
    await db.write();

    return res.json({ success: true });
  } catch (err) {
    console.error('[/api/verify] Error:', err);
    return res.status(500).json({ error: 'Server error.' });
  }
});

// 3) STATUS endpoint
app.get('/api/status', async (req, res) => {
  try {
    const { discordId } = req.query;
    if (!discordId) {
      return res.status(400).json({ error: 'Missing discordId' });
    }
    await db.read();
    const confirmed = !!db.data.ipconfirmed[discordId];
    return res.json({ confirmed });
  } catch (err) {
    console.error('[/api/status] Error:', err);
    return res.status(500).json({ error: 'Server error' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Backend running on port ${PORT}`));
