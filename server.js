// server.js
const express = require('express');
const crypto = require('crypto');
const bodyParser = require('body-parser');
const cors = require('cors');
const { Low } = require('lowdb');
const { JSONFile } = require('lowdb/node');
const path = require('path');

const app = express();
app.use(cors());
app.use(bodyParser.json());

// LowDB setup with default data {}
const file = path.join(__dirname, 'db.json');
const adapter = new JSONFile(file);
const db = new Low(adapter, {});      // ← pass default data here

// Initialize DB
(async () => {
  await db.read();
  // After read, db.data is guaranteed (either file contents or the default {})
  await db.write();
})();

// Utility: SHA256 hash for IP
function hashData(data) {
  return crypto.createHash('sha256').update(data).digest('hex');
}

// Health-check
app.get('/', (req, res) => {
  res.send('Backend is running');
});

// Verification endpoint
app.post('/api/verify', async (req, res) => {
  const { discordId, robloxId, code, fingerprint, ip } = req.body;
  if (!discordId || !code || !fingerprint || !ip) {
    return res.status(400).json({ error: 'Missing required data' });
  }

  // Ensure latest disk contents
  await db.read();

  // Hash IP
  const ipHash = hashData(ip);

  // Fetch saved code
  const savedCode = db.data[`verifycode_${discordId}`];
  if (savedCode !== code) {
    return res.status(400).json({ error: 'Invalid verification code' });
  }

  // Store verification details
  db.data[`verifydata_${discordId}`] = { robloxId, code, fingerprint, ipHash, timestamp: Date.now() };
  db.data[`ipconfirmed_${discordId}`] = true;

  // Persist
  await db.write();

  return res.json({ success: true });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Backend running on port ${PORT}`));
