const express = require('express');
const crypto = require('crypto');
const bodyParser = require('body-parser');
const cors = require('cors');
const { Low, JSONFile } = require('lowdb');
const path = require('path');

const app = express();
app.use(cors());
app.use(bodyParser.json());

// Setup lowdb
const file = path.join(__dirname, 'db.json');
const adapter = new JSONFile(file);
const db = new Low(adapter);

async function initDB() {
  await db.read();
  db.data ||= {}; // inizializza se vuoto
  await db.write();
}
initDB();

// Funzione per hash SHA256 (per IP e fingerprint)
function hashData(data) {
  return crypto.createHash('sha256').update(data).digest('hex');
}

app.get('/', (req, res) => {
  res.send('Backend is running');
});

app.post('/api/verify', async (req, res) => {
  const { discordId, robloxUsername, code, fingerprint, ip } = req.body;

  // Controllo dati obbligatori
  if (!discordId || !code || !fingerprint || !ip) {
    return res.status(400).json({ success: false, error: 'Missing required data' });
  }

  await db.read();

  // Recupera codice salvato per utente
  const savedCode = db.data[`verifycode_${discordId}`];
  if (savedCode !== code) {
    return res.status(400).json({ success: false, error: 'Invalid verification code' });
  }

  // Hasha fingerprint e IP
  const fingerprintHash = hashData(fingerprint);
  const ipHash = hashData(ip);

  // Salva i dati di verifica con timestamp
  db.data[`verifydata_${discordId}`] = {
    robloxUsername,
    code,
    fingerprint: fingerprintHash,
    ipHash,
    timestamp: Date.now()
  };
  db.data[`ipconfirmed_${discordId}`] = true;
  await db.write();

  res.json({ success: true });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Backend running on port ${PORT}`));
