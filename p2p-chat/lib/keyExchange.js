const crypto = require('crypto');

class HybridKeyExchange {
    constructor() {
        this.kyberKeyPair = null;
        this.x25519KeyPair = null;
        this.sharedSecret = null;
        this.derivedKey = null;
    }

    // Generate X25519 key pair
    generateX25519KeyPair() {
        const keyPair = crypto.generateKeyPairSync('x25519');
        this.x25519KeyPair = {
            publicKey: keyPair.publicKey,
            privateKey: keyPair.privateKey
        };
        return {
            publicKey: keyPair.publicKey.export({ type: 'spki', format: 'der' }),
            privateKey: keyPair.privateKey.export({ type: 'pkcs8', format: 'der' })
        };
    }

    // Simulate Kyber key generation (using crypto.random for demo)
    generateKyberKeyPair() {
        // In real implementation, use pqc-kyber library
        // For now, simulate with random bytes for demo purposes
        const publicKey = crypto.randomBytes(1568); // Kyber768 public key size
        const privateKey = crypto.randomBytes(2400); // Kyber768 private key size
        
        this.kyberKeyPair = {
            publicKey: publicKey,
            privateKey: privateKey
        };
        
        return {
            publicKey: publicKey,
            privateKey: privateKey
        };
    }

    // Simulate Kyber encapsulation
    kyberEncapsulate(publicKey) {
        // In real implementation, use pqc-kyber library
        // For now, simulate with random shared secret and ciphertext
        const sharedSecret = crypto.randomBytes(32); // 32 bytes shared secret
        const ciphertext = crypto.randomBytes(1088); // Kyber768 ciphertext size
        
        return {
            sharedSecret: sharedSecret,
            ciphertext: ciphertext
        };
    }

    // Simulate Kyber decapsulation
    kyberDecapsulate(ciphertext, privateKey) {
        // In real implementation, use pqc-kyber library
        // For demo, return a consistent shared secret based on input
        const hash = crypto.createHash('sha256');
        hash.update(ciphertext);
        hash.update(privateKey);
        return hash.digest();
    }

    // Perform X25519 key exchange
    x25519Exchange(peerPublicKeyDer) {
        if (!this.x25519KeyPair) {
            throw new Error('X25519 key pair not generated');
        }

        const peerPublicKey = crypto.createPublicKey({
            key: peerPublicKeyDer,
            type: 'spki',
            format: 'der'
        });

        const sharedSecret = crypto.diffieHellman({
            privateKey: this.x25519KeyPair.privateKey,
            publicKey: peerPublicKey
        });

        return sharedSecret;
    }

    // Combine Kyber and X25519 shared secrets and derive final key
    async deriveHybridKey(kyberSharedSecret, x25519SharedSecret, salt = null) {
        // Combine both shared secrets
        const combinedSecret = Buffer.concat([kyberSharedSecret, x25519SharedSecret]);
        
        // Use provided salt or generate one
        const keySalt = salt || crypto.randomBytes(32);
        
        try {
            // Derive key using scrypt
            const derivedKey = await new Promise((resolve, reject) => {
                crypto.scrypt(combinedSecret, keySalt, 32, { N: 2**16, r: 8, p: 1 }, (err, derivedKey) => {
                    if (err) reject(err);
                    else resolve(derivedKey);
                });
            });

            this.derivedKey = derivedKey;
            this.sharedSecret = combinedSecret;

            return {
                key: derivedKey,
                salt: keySalt
            };
        } catch (error) {
            throw new Error(`Key derivation failed: ${error.message}`);
        }
    }

    // Initialize key exchange as the initiator
    async initiate() {
        try {
            // Generate both key pairs
            const kyberKeys = this.generateKyberKeyPair();
            const x25519Keys = this.generateX25519KeyPair();

            return {
                kyberPublicKey: kyberKeys.publicKey,
                x25519PublicKey: x25519Keys.publicKey,
                success: true
            };
        } catch (error) {
            return {
                success: false,
                error: error.message
            };
        }
    }

    // Respond to key exchange as the responder
    async respond(peerKyberPublicKey, peerX25519PublicKey) {
        try {
            // Generate own key pairs
            const kyberKeys = this.generateKyberKeyPair();
            const x25519Keys = this.generateX25519KeyPair();

            // Perform Kyber encapsulation with peer's public key
            const kyberResult = this.kyberEncapsulate(peerKyberPublicKey);
            
            // Perform X25519 key exchange
            const x25519SharedSecret = this.x25519Exchange(peerX25519PublicKey);

            // Derive hybrid key
            const keyResult = await this.deriveHybridKey(
                kyberResult.sharedSecret, 
                x25519SharedSecret
            );

            return {
                kyberCiphertext: kyberResult.ciphertext,
                x25519PublicKey: x25519Keys.publicKey,
                derivedKey: keyResult.key,
                salt: keyResult.salt,
                success: true
            };
        } catch (error) {
            return {
                success: false,
                error: error.message
            };
        }
    }

    // Complete key exchange as the initiator
    async complete(kyberCiphertext, peerX25519PublicKey, salt) {
        try {
            if (!this.kyberKeyPair || !this.x25519KeyPair) {
                throw new Error('Key pairs not generated');
            }

            // Perform Kyber decapsulation
            const kyberSharedSecret = this.kyberDecapsulate(
                kyberCiphertext, 
                this.kyberKeyPair.privateKey
            );

            // Perform X25519 key exchange
            const x25519SharedSecret = this.x25519Exchange(peerX25519PublicKey);

            // Derive hybrid key with provided salt
            const keyResult = await this.deriveHybridKey(
                kyberSharedSecret, 
                x25519SharedSecret, 
                salt
            );

            return {
                derivedKey: keyResult.key,
                success: true
            };
        } catch (error) {
            return {
                success: false,
                error: error.message
            };
        }
    }

    // Get the derived key for encryption
    getDerivedKey() {
        return this.derivedKey;
    }

    // Clear sensitive data
    clear() {
        this.kyberKeyPair = null;
        this.x25519KeyPair = null;
        this.sharedSecret = null;
        this.derivedKey = null;
    }
}

module.exports = HybridKeyExchange;