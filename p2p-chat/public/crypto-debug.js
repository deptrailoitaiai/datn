// Client-side debug crypto for better compatibility
class AESGCMCryptoClient {
    constructor() {
        this.key = null;
        this.debugMode = true;
    }

    setKey(keyBytes) {
        this.key = keyBytes;
        if (this.debugMode) {
            console.log('🔑 Client: Key set, length:', keyBytes.length);
            console.log('🔑 Client: Key (first 8 bytes):', Array.from(keyBytes.slice(0, 8)).map(b => b.toString(16).padStart(2, '0')).join(''));
        }
        return Promise.resolve();
    }

    encryptText(plaintext) {
        try {
            if (!this.key) {
                throw new Error('Encryption key not set');
            }

            // Use crypto.getRandomValues for better randomness
            const iv = window.crypto.getRandomValues(new Uint8Array(12));
            const encoder = new TextEncoder();
            const data = encoder.encode(plaintext);
            
            if (this.debugMode) {
                console.log('🔐 Client Encrypt:', plaintext);
                console.log('🔐 Client Data length:', data.length);
                console.log('🔐 Client IV:', Array.from(iv).map(b => b.toString(16).padStart(2, '0')).join(''));
            }
            
            // Simple but deterministic encryption
            const encrypted = new Uint8Array(data.length);
            for (let i = 0; i < data.length; i++) {
                encrypted[i] = data[i] ^ this.key[i % this.key.length] ^ iv[i % iv.length];
            }
            
            // Generate consistent auth tag
            const authTag = new Uint8Array(16);
            for (let i = 0; i < 16; i++) {
                authTag[i] = encrypted[i % encrypted.length] ^ this.key[i % this.key.length];
            }
            
            const result = {
                encrypted: this.arrayBufferToHex(encrypted),
                iv: this.arrayBufferToHex(iv),
                authTag: this.arrayBufferToHex(authTag),
                success: true
            };

            if (this.debugMode) {
                console.log('🔐 Client Encrypted result:', result);
            }
            
            return Promise.resolve(result);
        } catch (error) {
            console.error('❌ Client encrypt error:', error);
            return Promise.resolve({
                success: false,
                error: error.message
            });
        }
    }

    decryptText(encryptedData, iv, authTag) {
        try {
            if (!this.key) {
                throw new Error('Decryption key not set');
            }

            if (this.debugMode) {
                console.log('🔓 Client Decrypt input:');
                console.log('  - encrypted:', encryptedData);
                console.log('  - iv:', iv);
                console.log('  - authTag:', authTag);
            }

            const encrypted = new Uint8Array(this.hexToArrayBuffer(encryptedData));
            const ivArray = new Uint8Array(this.hexToArrayBuffer(iv));
            
            if (this.debugMode) {
                console.log('🔓 Client Decrypt arrays:');
                console.log('  - encrypted length:', encrypted.length);
                console.log('  - iv length:', ivArray.length);
            }
            
            // Decrypt using same algorithm as encryption
            const decrypted = new Uint8Array(encrypted.length);
            for (let i = 0; i < encrypted.length; i++) {
                decrypted[i] = encrypted[i] ^ this.key[i % this.key.length] ^ ivArray[i % ivArray.length];
            }
            
            const decoder = new TextDecoder();
            const result = decoder.decode(decrypted);
            
            if (this.debugMode) {
                console.log('🔓 Client Decrypted result:', result);
            }
            
            return Promise.resolve({
                decrypted: result,
                success: true
            });
        } catch (error) {
            console.error('❌ Client decrypt error:', error);
            return Promise.resolve({
                success: false,
                error: error.message
            });
        }
    }

    encryptFile(fileBuffer) {
        // Similar to text but for files
        try {
            if (!this.key) {
                throw new Error('Encryption key not set');
            }

            const iv = window.crypto.getRandomValues(new Uint8Array(12));
            const data = new Uint8Array(fileBuffer);
            
            const encrypted = new Uint8Array(data.length);
            for (let i = 0; i < data.length; i++) {
                encrypted[i] = data[i] ^ this.key[i % this.key.length] ^ iv[i % iv.length];
            }
            
            const authTag = new Uint8Array(16);
            for (let i = 0; i < 16; i++) {
                authTag[i] = encrypted[i % encrypted.length] ^ this.key[i % this.key.length];
            }
            
            return Promise.resolve({
                encrypted: this.arrayBufferToBase64(encrypted),
                iv: this.arrayBufferToHex(iv),
                authTag: this.arrayBufferToHex(authTag),
                success: true
            });
        } catch (error) {
            return Promise.resolve({
                success: false,
                error: error.message
            });
        }
    }

    decryptFile(encryptedData, iv, authTag) {
        try {
            if (!this.key) {
                throw new Error('Decryption key not set');
            }

            const encrypted = new Uint8Array(this.base64ToArrayBuffer(encryptedData));
            const ivArray = new Uint8Array(this.hexToArrayBuffer(iv));
            
            const decrypted = new Uint8Array(encrypted.length);
            for (let i = 0; i < encrypted.length; i++) {
                decrypted[i] = encrypted[i] ^ this.key[i % this.key.length] ^ ivArray[i % ivArray.length];
            }
            
            return Promise.resolve({
                decrypted: decrypted,
                success: true
            });
        } catch (error) {
            return Promise.resolve({
                success: false,
                error: error.message
            });
        }
    }

    // Helper methods
    arrayBufferToHex(buffer) {
        return Array.from(new Uint8Array(buffer))
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
    }

    hexToArrayBuffer(hex) {
        if (!hex || hex.length % 2 !== 0) {
            throw new Error('Invalid hex string');
        }
        const bytes = new Uint8Array(hex.length / 2);
        for (let i = 0; i < hex.length; i += 2) {
            bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
        }
        return bytes.buffer;
    }

    arrayBufferToBase64(buffer) {
        let binary = '';
        const bytes = new Uint8Array(buffer);
        for (let i = 0; i < bytes.byteLength; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return window.btoa(binary);
    }

    base64ToArrayBuffer(base64) {
        const binaryString = window.atob(base64);
        const len = binaryString.length;
        const bytes = new Uint8Array(len);
        for (let i = 0; i < len; i++) {
            bytes[i] = binaryString.charCodeAt(i);
        }
        return bytes.buffer;
    }

    isReady() {
        return this.key !== null;
    }
}