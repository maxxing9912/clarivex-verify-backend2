const express = require('express');
const crypto = require('crypto');
const bodyParser = require('body-parser');
const cors = require('cors');
const { Low, JSONFile } = require('lowdb');
const path = require('path');

const app = express();
app.use(cors());
app.use(bodyParser.json());

// lowdb setup
const file = path.join(__dirname, 'db.json');
const adapter = new JSONFile(file);
const db = new Low(adapter);

async function initDB() {
    await db.read();
    db.data ||= {};          // initialize if empty
    await db.write();
}
initDB();

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

    const ipHash = hashData(ip);
    const savedCode = db.data[`verifycode_${discordId}`];

    if (savedCode !== code) {
        return res.status(400).json({ error: 'Invalid verification code' });
    }

    db.data[`verifydata_${discordId}`] = { robloxId, code, fingerprint, ipHash, timestamp: Date.now() };
    db.data[`ipconfirmed_${discordId}`] = true;
    await db.write();

    res.json({ success: true });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Backend running on port ${PORT}`));