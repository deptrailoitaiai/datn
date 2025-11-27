const fs = require('fs');
const path = require('path');
const AESGCMCrypto = require('./lib/encryption');

async function testFileEncryption() {
    console.log('🧪 Testing File Encryption/Decryption');
    console.log('=====================================');
    
    try {
        // Read test file
        const filePath = path.join(__dirname, 'test-file.txt');
        const fileContent = fs.readFileSync(filePath, 'utf8');
        
        console.log('📄 Original file content:');
        console.log(fileContent);
        console.log(`📊 File size: ${fileContent.length} characters`);
        
        console.log('\n🔐 Setting up encryption...');
        
        // Create crypto instance
        const crypto = new AESGCMCrypto();
        
        // Generate a test key (32 bytes)
        const testKey = Buffer.from('this-is-a-32-byte-key-for-test!!', 'utf8');
        crypto.setKey(testKey);
        
        console.log('\n🔐 Encrypting file content...');
        
        // Encrypt the file content as text
        const encryptionResult = await crypto.encryptText(fileContent);
        
        if (encryptionResult.success) {
            console.log('✅ Encryption successful!');
            console.log('🔐 Encrypted data length:', encryptionResult.encrypted.length);
            console.log('🔐 IV:', encryptionResult.iv);
            console.log('🔐 AuthTag:', encryptionResult.authTag);
            
            // Now decrypt
            console.log('\n🔓 Decrypting file content...');
            const decryptionResult = await crypto.decryptText(
                encryptionResult.encrypted,
                encryptionResult.iv,
                encryptionResult.authTag
            );
            
            if (decryptionResult.success) {
                console.log('✅ Decryption successful!');
                
                const decryptedText = decryptionResult.decrypted;
                
                console.log('📄 Decrypted file content:');
                console.log(decryptedText);
                
                // Compare
                if (fileContent === decryptedText) {
                    console.log('\n🎉 SUCCESS: Original and decrypted content match perfectly!');
                    
                    // Write decrypted content to verify
                    const outputPath = path.join(__dirname, 'test-file-decrypted.txt');
                    fs.writeFileSync(outputPath, decryptedText);
                    console.log(`💾 Decrypted file saved as: ${outputPath}`);
                    
                } else {
                    console.log('\n❌ FAILURE: Content mismatch!');
                    console.log('Original length:', fileContent.length);
                    console.log('Decrypted length:', decryptedText.length);
                    console.log('Original start:', fileContent.substring(0, 50));
                    console.log('Decrypted start:', decryptedText.substring(0, 50));
                }
                
            } else {
                console.log('❌ Decryption failed:', decryptionResult.error);
            }
            
        } else {
            console.log('❌ Encryption failed:', encryptionResult.error);
        }
        
    } catch (error) {
        console.error('❌ Test error:', error.message);
    }
}

// Run the test
testFileEncryption();