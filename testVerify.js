const fetch = require('node-fetch');

async function testVerify() {
    const res = await fetch('http://localhost:3000/api/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            discordId: '123456',
            robloxId: '98765',
            code: 'ABC123',
            fingerprint: 'testfingerprint',
            ip: '1.2.3.4'
        }),
    });
    const data = await res.json();
    console.log(data);
}

testVerify();