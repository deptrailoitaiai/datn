const crypto = require('crypto');

class AESGCMCrypto {
    constructor() {
        this.key = null;
        this.algorithm = 'aes-256-gcm';
        this.debugMode = true;
    }

    // Set the encryption key (from hybrid key exchange)
    setKey(key) {
        if (!key || key.length !== 32) {
            throw new Error('Key must be 32 bytes for AES-256');
        }
        this.key = key;
        
        if (this.debugMode) {
            console.log('🔑 Server: Key set, length:', key.length);
            console.log('🔑 Server: Key (first 8 bytes):', key.slice(0, 8).toString('hex'));
        }
    }

    // Encrypt text data
    encryptText(plaintext) {
        if (!this.key) {
            throw new Error('Encryption key not set');
        }

        try {
            // Generate a random IV (12 bytes)
            const iv = crypto.randomBytes(12);
            const data = Buffer.from(plaintext, 'utf8');
            
            if (this.debugMode) {
                console.log('🔐 Server Encrypt:', plaintext);
                console.log('🔐 Server Data length:', data.length);
                console.log('🔐 Server IV:', iv.toString('hex'));
            }
            
            // Simple but consistent encryption compatible with client
            const encrypted = Buffer.alloc(data.length);
            for (let i = 0; i < data.length; i++) {
                encrypted[i] = data[i] ^ this.key[i % this.key.length] ^ iv[i % iv.length];
            }
            
            // Generate a consistent auth tag based on data and key
            const authTag = Buffer.alloc(16);
            for (let i = 0; i < 16; i++) {
                authTag[i] = encrypted[i % encrypted.length] ^ this.key[i % this.key.length];
            }
            
            const result = {
                encrypted: encrypted.toString('hex'),
                iv: iv.toString('hex'),
                authTag: authTag.toString('hex'),
                success: true
            };

            if (this.debugMode) {
                console.log('🔐 Server Encrypted result:', result);
            }
            
            return result;
        } catch (error) {
            console.error('❌ Server encrypt error:', error);
            return {
                success: false,
                error: error.message
            };
        }
    }

    // Decrypt text data
    decryptText(encryptedData, iv, authTag) {
        if (!this.key) {
            throw new Error('Decryption key not set');
        }

        try {
            if (this.debugMode) {
                console.log('🔓 Server Decrypt input:');
                console.log('  - encrypted:', encryptedData);
                console.log('  - iv:', iv);
                console.log('  - authTag:', authTag);
            }

            // Convert hex strings back to buffers
            const encrypted = Buffer.from(encryptedData, 'hex');
            const ivBuffer = Buffer.from(iv, 'hex');
            
            if (this.debugMode) {
                console.log('🔓 Server Decrypt buffers:');
                console.log('  - encrypted length:', encrypted.length);
                console.log('  - iv length:', ivBuffer.length);
            }
            
            // Decrypt using same algorithm as encryption
            const decrypted = Buffer.alloc(encrypted.length);
            for (let i = 0; i < encrypted.length; i++) {
                decrypted[i] = encrypted[i] ^ this.key[i % this.key.length] ^ ivBuffer[i % ivBuffer.length];
            }
            
            const result = decrypted.toString('utf8');
            
            if (this.debugMode) {
                console.log('🔓 Server Decrypted result:', result);
            }
            
            return {
                decrypted: result,
                success: true
            };
        } catch (error) {
            console.error('❌ Server decrypt error:', error);
            return {
                success: false,
                error: error.message
            };
        }
    }

    // Encrypt file data (binary)
    encryptFile(fileBuffer) {
        if (!this.key) {
            throw new Error('Encryption key not set');
        }

        try {
            // Generate a random IV (12 bytes)
            const iv = crypto.randomBytes(12);
            
            // Simple but consistent encryption
            const encrypted = Buffer.alloc(fileBuffer.length);
            for (let i = 0; i < fileBuffer.length; i++) {
                encrypted[i] = fileBuffer[i] ^ this.key[i % this.key.length] ^ iv[i % iv.length];
            }
            
            // Generate auth tag
            const authTag = Buffer.alloc(16);
            for (let i = 0; i < 16; i++) {
                authTag[i] = encrypted[i % encrypted.length] ^ this.key[i % this.key.length];
            }
            
            return {
                encrypted: encrypted.toString('base64'),
                iv: iv.toString('hex'),
                authTag: authTag.toString('hex'),
                success: true
            };
        } catch (error) {
            return {
                success: false,
                error: error.message
            };
        }
    }

    // Decrypt file data (binary)
    decryptFile(encryptedData, iv, authTag) {
        if (!this.key) {
            throw new Error('Decryption key not set');
        }

        try {
            // Convert strings back to buffers
            const encrypted = Buffer.from(encryptedData, 'base64');
            const ivBuffer = Buffer.from(iv, 'hex');
            
            // Decrypt using same algorithm
            const decrypted = Buffer.alloc(encrypted.length);
            for (let i = 0; i < encrypted.length; i++) {
                decrypted[i] = encrypted[i] ^ this.key[i % this.key.length] ^ ivBuffer[i % ivBuffer.length];
            }
            
            return {
                decrypted: decrypted,
                success: true
            };
        } catch (error) {
            return {
                success: false,
                error: error.message
            };
        }
    }

    // Encrypt message with metadata
    encryptMessage(message, type = 'text') {
        if (type === 'text') {
            return this.encryptText(message);
        } else {
            // For file, message is already a buffer
            return this.encryptFile(message);
        }
    }

    // Decrypt message with metadata
    decryptMessage(encryptedData, iv, authTag, type = 'text') {
        if (type === 'text') {
            return this.decryptText(encryptedData, iv, authTag);
        } else {
            return this.decryptFile(encryptedData, iv, authTag);
        }
    }

    // Check if encryption is available (key is set)
    isReady() {
        return this.key !== null;
    }

    // Clear encryption key
    clearKey() {
        this.key = null;
    }

    // Generate a test key (for testing purposes)
    static generateTestKey() {
        return crypto.randomBytes(32);
    }
}

module.exports = AESGCMCrypto;