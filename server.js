// server.js
import express from 'express';
import crypto from 'crypto';
import bodyParser from 'body-parser';
import cors from 'cors';
import path from 'path';
import { Low } from 'lowdb';
import { JSONFile } from 'lowdb/node';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(cors());
app.use(bodyParser.json());

// Setup lowdb
const file = path.join(__dirname, 'db.json');
const adapter = new JSONFile(file);
const db = new Low(adapter);

// Funzione per inizializzare dati default se mancanti
async function initDB() {
  await db.read();
  if (!db.data) {
    db.data = {
      verifycodes: {},
      verifydata: {},
      ipconfirmed: {}
    };
    await db.write();
  }
  if (!db.data.verifycodes) db.data.verifycodes = {};
  if (!db.data.verifydata) db.data.verifydata = {};
  if (!db.data.ipconfirmed) db.data.ipconfirmed = {};
}
await initDB();

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

  // Assicura struttura dati
  if (!db.data.verifycodes) db.data.verifycodes = {};
  if (!db.data.verifydata) db.data.verifydata = {};
  if (!db.data.ipconfirmed) db.data.ipconfirmed = {};

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
  if (!db.data) db.data = {};
  if (!db.data.ipconfirmed) db.data.ipconfirmed = {};

  const confirmed = db.data.ipconfirmed[discordId] || false;
  res.json({ confirmed });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Backend running on port ${PORT}`));
