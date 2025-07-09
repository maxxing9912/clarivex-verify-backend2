// server.js (Render backend)
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

// setup LowDB v5+ with defaults
const file = path.join(__dirname, 'db.json');
const adapter = new JSONFile(file);
const defaultData = {
  verifycodes: {},
  verifydata: {},
  ipconfirmed: {}
};
const db = new Low(adapter, defaultData);

async function initDB() {
  await db.read();
  await db.write();
}
initDB();

// simple healthcheck
app.get('/', (req, res) => {
  res.send('Backend is running');
});

// Endpoint che riceve POST dal frontend Vercel
// body: { discordId, code, fingerprint, ip, robloxUsername }
app.post('/api/verify', async (req, res) => {
  const { discordId, code, fingerprint, ip, robloxUsername } = req.body;
  if (!discordId || !code || !fingerprint || !ip || !robloxUsername) {
    return res.status(400).json({ error: 'Missing required parameters.' });
  }

  await db.read();

  // Controlla che il codice corrisponda
  const savedCode = db.data.verifycodes[discordId];
  if (savedCode !== code) {
    return res.status(400).json({ error: 'Invalid verification code.' });
  }

  // Hash di IP/fingerprint
  const hashData = (d) => crypto.createHash('sha256').update(d).digest('hex');
  const ipHash = hashData(ip);
  const fpHash = hashData(fingerprint);

  // Salva i dati e marca conferma
  db.data.verifydata[discordId] = {
    robloxUsername,
    code,
    fingerprintHash: fpHash,
    ipHash,
    timestamp: Date.now()
  };
  db.data.ipconfirmed[discordId] = true;
  // rimuovi il codice temporaneo
  delete db.data.verifycodes[discordId];

  await db.write();
  return res.json({ success: true });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Backend running on port ${PORT}`));
