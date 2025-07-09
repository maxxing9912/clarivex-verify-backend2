import express from 'express';
import crypto from 'crypto';
import bodyParser from 'body-parser';
import cors from 'cors';
import { Low } from 'lowdb';
import { JSONFile } from 'lowdb/node';
import path from 'path';
import { fileURLToPath } from 'url';

// Per __dirname in ESM:
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(cors());
app.use(bodyParser.json());

// lowdb setup
const file = path.join(__dirname, 'db.json');
const adapter = new JSONFile(file);
const db = new Low(adapter);

// Inizializza DB con dati di default
async function initDB() {
  await db.read();
  db.data ||= { verifycodes: {}, verifydata: {}, ipconfirmed: {} }; // struttura base
  await db.write();
}
await initDB();

function hashData(data) {
  return crypto.createHash('sha256').update(data).digest('hex');
}

app.get('/', (req, res) => {
  res.send('Backend is running');
});

app.post('/api/verify', async (req, res) => {
  const { discordId, robloxId, code, fingerprint, ip } = req.body;
  if (!discordId || !code || !fingerprint || !ip) {
    return res.status(400).json({ error: 'Missing required data' });
  }

  await db.read();

  const savedCode = db.data.verifycodes[discordId];
  if (savedCode !== code) {
    return res.status(400).json({ error: 'Invalid verification code' });
  }

  const ipHash = hashData(ip);

  db.data.verifydata[discordId] = { robloxId, code, fingerprint, ipHash, timestamp: Date.now() };
  db.data.ipconfirmed[discordId] = true;
  // Rimuovi codice temporaneo se vuoi:
  delete db.data.verifycodes[discordId];

  await db.write();

  res.json({ success: true });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Backend running on port ${PORT}`));
