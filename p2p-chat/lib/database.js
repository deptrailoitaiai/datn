const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const bcrypt = require('bcrypt');

class Database {
    constructor() {
        // Create database in app directory
        const dbPath = path.join(__dirname, 'chat.db');
        this.db = new sqlite3.Database(dbPath);
        this.init();
    }

    init() {
        // Create users table
        this.db.serialize(() => {
            this.db.run(`
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            `);

            // Create shared_keys table for storing derived keys between users
            this.db.run(`
                CREATE TABLE IF NOT EXISTS shared_keys (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user1_id INTEGER NOT NULL,
                    user2_id INTEGER NOT NULL,
                    derived_key BLOB NOT NULL,
                    salt BLOB NOT NULL,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user1_id) REFERENCES users (id),
                    FOREIGN KEY (user2_id) REFERENCES users (id),
                    UNIQUE(user1_id, user2_id)
                )
            `);

            // Create messages table for chat history
            this.db.run(`
                CREATE TABLE IF NOT EXISTS messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    from_user_id INTEGER NOT NULL,
                    to_user_id INTEGER,
                    room_id TEXT,
                    message TEXT NOT NULL,
                    encrypted BOOLEAN DEFAULT FALSE,
                    iv BLOB,
                    auth_tag BLOB,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (from_user_id) REFERENCES users (id),
                    FOREIGN KEY (to_user_id) REFERENCES users (id)
                )
            `);

            // Create file_transfers table
            this.db.run(`
                CREATE TABLE IF NOT EXISTS file_transfers (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    from_user_id INTEGER NOT NULL,
                    to_user_id INTEGER,
                    room_id TEXT,
                    file_name TEXT NOT NULL,
                    file_size INTEGER,
                    encrypted BOOLEAN DEFAULT FALSE,
                    iv BLOB,
                    auth_tag BLOB,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (from_user_id) REFERENCES users (id),
                    FOREIGN KEY (to_user_id) REFERENCES users (id)
                )
            `);

            console.log('📊 Database initialized successfully');
        });
    }

    // User operations
    async createUser(username, password) {
        return new Promise((resolve, reject) => {
            bcrypt.hash(password, 10, (err, hash) => {
                if (err) {
                    reject(err);
                    return;
                }

                this.db.run(
                    'INSERT INTO users (username, password_hash) VALUES (?, ?)',
                    [username, hash],
                    function(err) {
                        if (err) {
                            if (err.code === 'SQLITE_CONSTRAINT_UNIQUE') {
                                reject(new Error('Username already exists'));
                            } else {
                                reject(err);
                            }
                        } else {
                            resolve({
                                id: this.lastID,
                                username: username,
                                created_at: new Date().toISOString()
                            });
                        }
                    }
                );
            });
        });
    }

    async getUserByUsername(username) {
        return new Promise((resolve, reject) => {
            this.db.get(
                'SELECT * FROM users WHERE username = ?',
                [username],
                (err, row) => {
                    if (err) {
                        reject(err);
                    } else {
                        resolve(row);
                    }
                }
            );
        });
    }

    async getUserById(id) {
        return new Promise((resolve, reject) => {
            this.db.get(
                'SELECT id, username, created_at FROM users WHERE id = ?',
                [id],
                (err, row) => {
                    if (err) {
                        reject(err);
                    } else {
                        resolve(row);
                    }
                }
            );
        });
    }

    async verifyPassword(password, hash) {
        return bcrypt.compare(password, hash);
    }

    // Message operations
    async saveMessage(fromUserId, toUserId, roomId, message, encrypted = false, iv = null, authTag = null) {
        return new Promise((resolve, reject) => {
            this.db.run(
                'INSERT INTO messages (from_user_id, to_user_id, room_id, message, encrypted, iv, auth_tag) VALUES (?, ?, ?, ?, ?, ?, ?)',
                [fromUserId, toUserId, roomId, message, encrypted, iv, authTag],
                function(err) {
                    if (err) {
                        reject(err);
                    } else {
                        resolve({
                            id: this.lastID,
                            from_user_id: fromUserId,
                            to_user_id: toUserId,
                            room_id: roomId,
                            message: message,
                            encrypted: encrypted,
                            iv: iv,
                            auth_tag: authTag,
                            created_at: new Date().toISOString()
                        });
                    }
                }
            );
        });
    }

    async getMessageHistory(roomId, limit = 50, offset = 0) {
        return new Promise((resolve, reject) => {
            this.db.all(`
                SELECT m.*, u.username as from_username 
                FROM messages m
                JOIN users u ON m.from_user_id = u.id
                WHERE m.room_id = ?
                ORDER BY m.created_at DESC
                LIMIT ? OFFSET ?
            `, [roomId, limit, offset], (err, rows) => {
                if (err) {
                    reject(err);
                } else {
                    resolve(rows.reverse()); // Reverse to get chronological order
                }
            });
        });
    }

    async getUserMessages(userId, limit = 100) {
        return new Promise((resolve, reject) => {
            this.db.all(`
                SELECT m.*, 
                       u1.username as from_username,
                       u2.username as to_username
                FROM messages m
                JOIN users u1 ON m.from_user_id = u1.id
                LEFT JOIN users u2 ON m.to_user_id = u2.id
                WHERE m.from_user_id = ? OR m.to_user_id = ?
                ORDER BY m.created_at ASC
                LIMIT ?
            `, [userId, userId, limit], (err, rows) => {
                if (err) {
                    reject(err);
                } else {
                    resolve(rows);
                }
            });
        });
    }

    // File transfer operations
    async saveFileTransfer(fromUserId, toUserId, roomId, fileName, fileSize, encrypted = false, iv = null, authTag = null) {
        return new Promise((resolve, reject) => {
            this.db.run(
                'INSERT INTO file_transfers (from_user_id, to_user_id, room_id, file_name, file_size, encrypted, iv, auth_tag) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                [fromUserId, toUserId, roomId, fileName, fileSize, encrypted, iv, authTag],
                function(err) {
                    if (err) {
                        reject(err);
                    } else {
                        resolve({
                            id: this.lastID,
                            from_user_id: fromUserId,
                            to_user_id: toUserId,
                            room_id: roomId,
                            file_name: fileName,
                            file_size: fileSize,
                            encrypted: encrypted,
                            iv: iv,
                            auth_tag: authTag,
                            created_at: new Date().toISOString()
                        });
                    }
                }
            );
        });
    }

    // Shared key operations
    async saveSharedKey(user1Id, user2Id, derivedKey, salt) {
        // Ensure user1_id < user2_id for uniqueness
        if (user1Id > user2Id) {
            [user1Id, user2Id] = [user2Id, user1Id];
        }
        return new Promise((resolve, reject) => {
            this.db.run(
                'INSERT OR REPLACE INTO shared_keys (user1_id, user2_id, derived_key, salt) VALUES (?, ?, ?, ?)',
                [user1Id, user2Id, derivedKey, salt],
                function(err) {
                    if (err) {
                        reject(err);
                    } else {
                        resolve({
                            id: this.lastID,
                            user1_id: user1Id,
                            user2_id: user2Id,
                            derived_key: derivedKey,
                            salt: salt,
                            created_at: new Date().toISOString()
                        });
                    }
                }
            );
        });
    }

    async getSharedKey(user1Id, user2Id) {
        // Ensure user1_id < user2_id
        if (user1Id > user2Id) {
            [user1Id, user2Id] = [user2Id, user1Id];
        }
        return new Promise((resolve, reject) => {
            this.db.get(
                'SELECT * FROM shared_keys WHERE user1_id = ? AND user2_id = ?',
                [user1Id, user2Id],
                (err, row) => {
                    if (err) {
                        reject(err);
                    } else {
                        resolve(row);
                    }
                }
            );
        });
    }

    // Get all users (for search functionality)
    async getAllUsers() {
        return new Promise((resolve, reject) => {
            this.db.all(
                'SELECT id, username, created_at FROM users ORDER BY username',
                (err, rows) => {
                    if (err) {
                        reject(err);
                    } else {
                        resolve(rows);
                    }
                }
            );
        });
    }

    // Search users by username
    async searchUsers(searchTerm) {
        return new Promise((resolve, reject) => {
            this.db.all(
                'SELECT id, username, created_at FROM users WHERE username LIKE ? ORDER BY username',
                [`%${searchTerm}%`],
                (err, rows) => {
                    if (err) {
                        reject(err);
                    } else {
                        resolve(rows);
                    }
                }
            );
        });
    }

    close() {
        this.db.close();
    }
}

module.exports = Database;