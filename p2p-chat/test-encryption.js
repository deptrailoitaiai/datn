// Test script to verify encryption/decryption compatibility
const AESGCMCrypto = require('./lib/encryption');

// Test with sample data
const crypto = new AESGCMCrypto();
const testKey = Buffer.from('0123456789012345678901234567890123456789012345678901234567890123', 'hex'); // 32 bytes key
const testMessage = 'Hello World! This is a test message for encryption.';

console.log('🔧 Testing Encryption/Decryption Compatibility');
console.log('='.repeat(50));

// Set the key
crypto.setKey(testKey);
console.log('✅ Key set:', testKey.toString('hex'));

// Test text encryption
console.log('\n📝 Testing Text Encryption:');
console.log('Original message:', testMessage);

const encryptResult = crypto.encryptText(testMessage);
if (encryptResult.success) {
    console.log('✅ Encryption successful');
    console.log('Encrypted:', encryptResult.encrypted);
    console.log('IV:', encryptResult.iv);
    console.log('AuthTag:', encryptResult.authTag);
    
    // Test decryption
    const decryptResult = crypto.decryptText(
        encryptResult.encrypted, 
        encryptResult.iv, 
        encryptResult.authTag
    );
    
    if (decryptResult.success) {
        console.log('✅ Decryption successful');
        console.log('Decrypted message:', decryptResult.decrypted);
        
        if (decryptResult.decrypted === testMessage) {
            console.log('🎉 SUCCESS: Messages match perfectly!');
        } else {
            console.log('❌ ERROR: Messages do not match');
            console.log('Expected:', testMessage);
            console.log('Got:', decryptResult.decrypted);
        }
    } else {
        console.log('❌ Decryption failed:', decryptResult.error);
    }
} else {
    console.log('❌ Encryption failed:', encryptResult.error);
}

// Test file encryption
console.log('\n📄 Testing File Encryption:');
const testFileData = Buffer.from('This is test file content for encryption testing. 🔒📁');
console.log('Original file data:', testFileData.toString());

const fileEncryptResult = crypto.encryptFile(testFileData);
if (fileEncryptResult.success) {
    console.log('✅ File encryption successful');
    
    const fileDecryptResult = crypto.decryptFile(
        fileEncryptResult.encrypted,
        fileEncryptResult.iv,
        fileEncryptResult.authTag
    );
    
    if (fileDecryptResult.success) {
        console.log('✅ File decryption successful');
        console.log('Decrypted file data:', fileDecryptResult.decrypted.toString());
        
        if (Buffer.compare(fileDecryptResult.decrypted, testFileData) === 0) {
            console.log('🎉 SUCCESS: File data matches perfectly!');
        } else {
            console.log('❌ ERROR: File data does not match');
        }
    } else {
        console.log('❌ File decryption failed:', fileDecryptResult.error);
    }
} else {
    console.log('❌ File encryption failed:', fileEncryptResult.error);
}

console.log('\n' + '='.repeat(50));
console.log('Test completed! ✨');