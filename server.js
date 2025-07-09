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

// Percorso del file DB
const file = path.join(__dirname, 'db.json');
const adapter = new JSONFile(file);
// Default data richiesti da lowdb v5+
const defaultData = {
  verifycodes: {},
  verifydata: {},
  ipconfirmed: {}
};
const db = new Low(adapter, defaultData);

// Inizializza il DB (crea db.json se non esiste)
async function initDB() {
  await db.read();
  await db.write();
}
initDB();

// Funzione di hashing IP/fingerprint
function hashData(data) {
  return crypto.createHash('sha256').update(data).digest('hex');
}

// Endpoint di root
app.get('/', (req, res) => {
  res.send('Backend is running');
});

// Endpoint chiamato dal link di conferma
// Esempio: GET /api/confirm?discordId=123&code=ABCD1234&fingerprint=xyz
app.get('/api/confirm', async (req, res) => {
  const { discordId, code, fingerprint } = req.query;
  await db.read();

  // Verifica esistenza e corrispondenza del code
  if (!db.data.verifycodes[discordId] || db.data.verifycodes[discordId] !== code) {
    return res.status(400).send('<h1>Codice non valido o non trovato.</h1>');
  }

  // Registra conferma
  db.data.ipconfirmed[discordId] = {
    fingerprintHash: hashData(fingerprint || ''),
    confirmedAt: Date.now()
  };
  await db.write();

  // Risposta HTML semplice
  res.send(`
    <h1>Device confermato!</h1>
    <p>Ora torna su Discord e clicca “Complete Verification”.</p>
  `);
});

// Endpoint per salvare il codice e altri dati (opzionale, se userai POST invece di query string)
app.post('/api/save-code', async (req, res) => {
  const { discordId, code } = req.body;
  if (!discordId || !code) {
    return res.status(400).json({ error: 'Missing parameters' });
  }
  await db.read();
  db.data.verifycodes[discordId] = code;
  await db.write();
  res.json({ success: true });
});

// Avvia server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Backend running on port ${PORT}`));
