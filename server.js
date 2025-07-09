// server.js (CommonJS)

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

// Percorso del file database
const file = path.join(__dirname, 'db.json');
// Adapter per JSONFile
const adapter = new JSONFile(file);
// Inizializza Low con dati di default
const defaultData = { verifycodes: {}, verifydata: {}, ipconfirmed: {} };
const db = new Low(adapter, defaultData);

// Funzione per inizializzare dati se mancanti
async function initDB() {
  await db.read();
  // Se non esistono dati, scrivi quelli di default
  if (!db.data) {
    db.data = defaultData;
    await db.write();
  }
}

initDB().catch(console.error);

// Funzione hash (SHA256)
function hashData(data) {
  return crypto.createHash('sha256').update(data).digest('hex');
}

// Endpoint test
app.get('/', (req, res) => {
  res.send('Backend is running');
});

// Endpoint per confermare device e IP (chiamato dal frontend)
app.post('/api/verify', async (req, res) => {
  const { discordId, robloxUsername, code, fingerprint, ip } = req.body;
  if (!discordId || !code || !fingerprint || !ip) {
    return res.status(400).json({ error: 'Missing required data' });
  }

  await db.read();

  const savedCode = db.data.verifycodes[discordId];
  if (savedCode !== code) {
    return res.status(400).json({ error: 'Invalid verification code' });
  }

  const ipHash = hashData(ip);

  db.data.verifydata[discordId] = { robloxUsername, code, fingerprint, ipHash, timestamp: Date.now() };
  db.data.ipconfirmed[discordId] = true;
  delete db.data.verifycodes[discordId];

  await db.write();

  res.json({ success: true });
});

// Endpoint per verificare stato conferma device/IP
app.get('/api/status', async (req, res) => {
  const discordId = req.query.discordId;
  if (!discordId) return res.status(400).json({ error: 'Missing discordId' });

  await db.read();
  const confirmed = db.data.ipconfirmed[discordId] || false;
  res.json({ confirmed });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Backend running on port ${PORT}`));
