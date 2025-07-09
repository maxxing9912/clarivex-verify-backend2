const express = require('express');
const crypto = require('crypto');
const bodyParser = require('body-parser');
const cors = require('cors');
const path = require('path');

// lowdb v3+ importazione corretta per CommonJS
const { Low } = require('lowdb');
const { JSONFile } = require('lowdb/node');

const app = express();
app.use(cors());
app.use(bodyParser.json());

// Setup lowdb con file JSON
const file = path.join(__dirname, 'db.json');
const adapter = new JSONFile(file);
const db = new Low(adapter);

// Inizializza DB se vuoto
async function initDB() {
  await db.read();
  db.data ||= {}; // se db.data non esiste, inizializza come oggetto vuoto
  await db.write();
}
initDB();

// Funzione per hash SHA256
function hashData(data) {
  return crypto.createHash('sha256').update(data).digest('hex');
}

app.get('/', (req, res) => {
  res.send('Backend is running');
});

// API per ricevere conferma verify
app.post('/api/verify', async (req, res) => {
  const { discordId, robloxId, code, fingerprint, ip } = req.body;
  if (!discordId || !code || !fingerprint || !ip) {
    return res.status(400).json({ error: 'Missing required data' });
  }

  await db.read();

  // Leggi codice salvato per quell'utente
  const savedCode = db.data[`verifycode_${discordId}`];

  if (savedCode !== code) {
    return res.status(400).json({ error: 'Invalid verification code' });
  }

  // Salva dati hash ip e fingerprint
  const ipHash = hashData(ip);
  db.data[`verifydata_${discordId}`] = { robloxId, code, fingerprint, ipHash, timestamp: Date.now() };
  db.data[`ipconfirmed_${discordId}`] = true;
  await db.write();

  res.json({ success: true });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Backend running on port ${PORT}`));
