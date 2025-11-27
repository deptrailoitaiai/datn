// Test compatibility between client and server encryption
const AESGCMCrypto = require('./lib/encryption');
const crypto = require('crypto');

console.log('🔧 Testing Client-Server Encryption Compatibility');
console.log('='.repeat(60));

// Create crypto instance
const serverCrypto = new AESGCMCrypto();

// Generate a consistent test key (32 bytes)
const testKey = Buffer.from('0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef', 'hex');
console.log('✅ Test key generated:', testKey.toString('hex').slice(0, 16) + '...');

// Set the key
serverCrypto.setKey(testKey);

// Test message
const testMessage = 'Hello World! 🌍';
console.log('📝 Test message:', testMessage);

// Server encrypt
console.log('\n📤 SERVER ENCRYPTION:');
const serverEncrypted = serverCrypto.encryptText(testMessage);
console.log('Server encrypted data:', {
    encrypted: serverEncrypted.encrypted.slice(0, 20) + '...',
    iv: serverEncrypted.iv,
    authTag: serverEncrypted.authTag.slice(0, 20) + '...'
});

// Server decrypt (test server consistency)
console.log('\n📥 SERVER DECRYPTION (self-test):');
const serverDecrypted = serverCrypto.decryptText(
    serverEncrypted.encrypted,
    serverEncrypted.iv,
    serverEncrypted.authTag
);
console.log('Server decrypted result:', serverDecrypted);

if (serverDecrypted.success && serverDecrypted.decrypted === testMessage) {
    console.log('✅ Server self-encryption/decryption works!');
} else {
    console.log('❌ Server self-encryption/decryption failed!');
}

// Simulate client-side encryption logic
console.log('\n📤 SIMULATED CLIENT ENCRYPTION:');

// Use same key format as client would receive
const clientKey = new Uint8Array(testKey);

// Generate IV like client would
const clientIV = crypto.randomBytes(12);
const encoder = new TextEncoder();
const clientData = encoder.encode(testMessage);

console.log('Client key length:', clientKey.length);
console.log('Client IV:', clientIV.toString('hex'));
console.log('Client data length:', clientData.length);

// Encrypt like client
const clientEncrypted = new Uint8Array(clientData.length);
for (let i = 0; i < clientData.length; i++) {
    clientEncrypted[i] = clientData[i] ^ clientKey[i % clientKey.length] ^ clientIV[i % clientIV.length];
}

// Auth tag like client
const clientAuthTag = new Uint8Array(16);
for (let i = 0; i < 16; i++) {
    clientAuthTag[i] = clientEncrypted[i % clientEncrypted.length] ^ clientKey[i % clientKey.length];
}

const clientResult = {
    encrypted: Buffer.from(clientEncrypted).toString('hex'),
    iv: clientIV.toString('hex'),
    authTag: Buffer.from(clientAuthTag).toString('hex')
};

console.log('Simulated client encrypted:', {
    encrypted: clientResult.encrypted.slice(0, 20) + '...',
    iv: clientResult.iv,
    authTag: clientResult.authTag.slice(0, 20) + '...'
});

// Test server decrypting client data
console.log('\n🔄 SERVER DECRYPTING CLIENT DATA:');
const crossDecrypted = serverCrypto.decryptText(
    clientResult.encrypted,
    clientResult.iv,
    clientResult.authTag
);
console.log('Cross-platform decrypted result:', crossDecrypted);

if (crossDecrypted.success && crossDecrypted.decrypted === testMessage) {
    console.log('🎉 SUCCESS: Client-Server encryption compatibility works!');
} else {
    console.log('❌ FAILED: Client-Server encryption compatibility issue!');
    console.log('Expected:', testMessage);
    console.log('Got:', crossDecrypted.decrypted);
}

console.log('\n' + '='.repeat(60));
console.log('Compatibility test completed! ✨');