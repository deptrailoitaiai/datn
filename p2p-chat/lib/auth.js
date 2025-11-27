const jwt = require('jsonwebtoken');
const Database = require('./database');

const JWT_SECRET = 'p2p-chat-secret-key-2024'; // In production, use environment variable

class AuthService {
    constructor() {
        this.db = new Database();
    }

    // Generate JWT token
    generateToken(user) {
        return jwt.sign(
            { 
                userId: user.id,
                id: user.id, 
                username: user.username 
            }, 
            JWT_SECRET, 
            { expiresIn: '24h' }
        );
    }

    // Verify JWT token
    verifyToken(token) {
        try {
            return jwt.verify(token, JWT_SECRET);
        } catch (error) {
            throw new Error('Invalid token');
        }
    }

    // Register new user
    async register(username, password) {
        try {
            // Validate input
            if (!username || !password) {
                throw new Error('Username and password are required');
            }

            if (username.length < 3) {
                throw new Error('Username must be at least 3 characters');
            }

            if (password.length < 6) {
                throw new Error('Password must be at least 6 characters');
            }

            // Create user
            const user = await this.db.createUser(username, password);
            
            console.log('👤 New user registered:', username);
            return {
                success: true,
                user: {
                    id: user.id,
                    username: user.username,
                    created_at: user.created_at
                }
            };
        } catch (error) {
            console.error('Registration error:', error.message);
            return {
                success: false,
                message: error.message
            };
        }
    }

    // Login user
    async login(username, password) {
        try {
            // Validate input
            if (!username || !password) {
                throw new Error('Username and password are required');
            }

            // Get user from database
            const user = await this.db.getUserByUsername(username);
            if (!user) {
                throw new Error('Invalid username or password');
            }

            // Verify password
            const isValidPassword = await this.db.verifyPassword(password, user.password_hash);
            if (!isValidPassword) {
                throw new Error('Invalid username or password');
            }

            // Generate token
            const token = this.generateToken(user);

            console.log('✅ User logged in:', username);
            return {
                success: true,
                token: token,
                user: {
                    id: user.id,
                    username: user.username,
                    created_at: user.created_at
                }
            };
        } catch (error) {
            console.error('Login error:', error.message);
            return {
                success: false,
                message: error.message
            };
        }
    }

    // Get user by ID (for authentication middleware)
    async getUserById(id) {
        return await this.db.getUserById(id);
    }

    // Search users
    async searchUsers(searchTerm) {
        return await this.db.searchUsers(searchTerm);
    }

    // Get all users
    async getAllUsers() {
        return await this.db.getAllUsers();
    }

    // Authentication middleware
    authenticateToken(req, res, next) {
        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

        if (!token) {
            return res.status(401).json({ message: 'Access token required' });
        }

        try {
            const user = this.verifyToken(token);
            req.user = user;
            next();
        } catch (error) {
            return res.status(403).json({ message: 'Invalid or expired token' });
        }
    }
}

module.exports = AuthService;