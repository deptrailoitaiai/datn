const fs = require('fs');
const path = require('path');
const AESGCMCrypto = require('./lib/encryption');

async function testBinaryFileEncryption() {
    console.log('🧪 Testing Binary File Encryption/Decryption');
    console.log('==========================================');
    
    try {
        // Create a small binary file with various byte values
        const binaryData = Buffer.from([
            0x48, 0x65, 0x6C, 0x6C, 0x6F, // "Hello"
            0x00, 0x01, 0x02, 0x03, 0x04, // null bytes and low values
            0xFF, 0xFE, 0xFD, 0xFC, 0xFB, // high values
            0x7F, 0x80, 0x81, 0x82, 0x83  // boundary values
        ]);
        
        const filePath = path.join(__dirname, 'test-binary.bin');
        fs.writeFileSync(filePath, binaryData);
        
        console.log('📄 Created binary file with', binaryData.length, 'bytes');
        console.log('📊 Binary data (hex):', binaryData.toString('hex'));
        
        // Create crypto instance
        const crypto = new AESGCMCrypto();
        
        // Generate a test key (32 bytes)  
        const testKeyStr = 'binary-test-key-32-bytes-long!!!';
        const testKey = Buffer.alloc(32);
        Buffer.from(testKeyStr).copy(testKey);
        console.log('🔑 Test key length:', testKey.length);
        crypto.setKey(testKey);
        
        console.log('\n🔐 Encrypting binary file...');
        
        // Encrypt the binary data
        const encryptionResult = await crypto.encryptFile(binaryData);
        
        if (encryptionResult.success) {
            console.log('✅ Binary encryption successful!');
            console.log('🔐 Encrypted data length:', encryptionResult.encrypted.length);
            
            // Decrypt
            console.log('\n🔓 Decrypting binary file...');
            const decryptionResult = await crypto.decryptFile(
                encryptionResult.encrypted,
                encryptionResult.iv,
                encryptionResult.authTag
            );
            
            if (decryptionResult.success) {
                console.log('✅ Binary decryption successful!');
                
                const decryptedBuffer = Buffer.from(decryptionResult.decrypted);
                console.log('📄 Decrypted data (hex):', decryptedBuffer.toString('hex'));
                
                // Compare
                if (binaryData.equals(decryptedBuffer)) {
                    console.log('\n🎉 SUCCESS: Binary data matches perfectly!');
                    
                    // Save decrypted file
                    const outputPath = path.join(__dirname, 'test-binary-decrypted.bin');
                    fs.writeFileSync(outputPath, decryptedBuffer);
                    console.log(`💾 Decrypted binary saved as: ${outputPath}`);
                    
                } else {
                    console.log('\n❌ FAILURE: Binary data mismatch!');
                    console.log('Original length:', binaryData.length);
                    console.log('Decrypted length:', decryptedBuffer.length);
                    console.log('First 10 bytes original:', binaryData.slice(0, 10).toString('hex'));
                    console.log('First 10 bytes decrypted:', decryptedBuffer.slice(0, 10).toString('hex'));
                }
                
            } else {
                console.log('❌ Binary decryption failed:', decryptionResult.error);
            }
            
        } else {
            console.log('❌ Binary encryption failed:', encryptionResult.error);
        }
        
    } catch (error) {
        console.error('❌ Test error:', error.message);
        console.error(error.stack);
    }
}

// Run the test
testBinaryFileEncryption();