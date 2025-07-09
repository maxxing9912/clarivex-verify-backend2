// server.js
const express = require('express');
const crypto = require('crypto');
const bodyParser = require('body-parser');
const cors = require('cors');

// LowDB imports (note the `/node` path for JSONFile)
const { Low } = require('lowdb');
const { JSONFile } = require('lowdb/node');

const path = require('path');

// Setup Express
const app = express();
app.use(cors());
app.use(bodyParser.json());

// LowDB setup
const file = path.join(__dirname, 'db.json');
const adapter = new JSONFile(file);
const db = new Low(adapter);

// Initialize DB with an IIFE
(async () => {
  await db.read();
  db.data ||= {};   // if no data, initialize as empty object
  await db.write();
})();

// Utility: SHA256 hash (for IP hashing)
function hashData(data) {
  return crypto.createHash('sha256').update(data).digest('hex');
}

// Health-check route
app.get('/', (req, res) => {
  res.send('Backend is running');
});

// Verification endpoint
app.post('/api/verify', async (req, res) => {
  const { discordId, robloxId, code, fingerprint, ip } = req.body;

  // Basic validation
  if (!discordId || !code || !fingerprint || !ip) {
    return res.status(400).json({ error: 'Missing required data' });
  }

  // Ensure DB is up-to-date
  await db.read();

  // Hash the IP for privacy
  const ipHash = hashData(ip);

  // Retrieve the saved code
  const savedCode = db.data[`verifycode_${discordId}`];
  if (savedCode !== code) {
    return res.status(400).json({ error: 'Invalid verification code' });
  }

  // Store verification details
  db.data[`verifydata_${discordId}`] = {
    robloxId,
    code,
    fingerprint,
    ipHash,
    timestamp: Date.now(),
  };
  db.data[`ipconfirmed_${discordId}`] = true;

  // Persist to disk
  await db.write();

  // Success response
  return res.json({ success: true });
});

// Listen on the port provided by Render, or 3000 locally
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Backend running on port ${PORT}`));
