const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const path = require('path');
const crypto = require('crypto');
const AuthService = require('./lib/auth');
const Database = require('./lib/database');

const app = express();
const server = http.createServer(app);
const authService = new AuthService();
const database = new Database();
const io = socketIo(server, {
    cors: {
        origin: "*",
        methods: ["GET", "POST"]
    }
});

// Middleware
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Store connected clients
let connectedClients = new Map();
let roomId = null;

// Authentication routes
app.post('/api/auth/register', async (req, res) => {
    try {
        const { username, password } = req.body;
        const result = await authService.register(username, password);
        
        if (result.success) {
            res.status(201).json(result);
        } else {
            res.status(400).json(result);
        }
    } catch (error) {
        console.error('Register endpoint error:', error);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const result = await authService.login(username, password);
        
        if (result.success) {
            res.status(200).json(result);
        } else {
            res.status(401).json(result);
        }
    } catch (error) {
        console.error('Login endpoint error:', error);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
});

// Get users (for search functionality)
app.get('/api/users', authService.authenticateToken.bind(authService), async (req, res) => {
    try {
        const searchTerm = req.query.search;
        const users = searchTerm 
            ? await authService.searchUsers(searchTerm)
            : await authService.getAllUsers();
        
        res.json({ success: true, users });
    } catch (error) {
        console.error('Get users error:', error);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
});

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

io.on('connection', (socket) => {
    console.log(`User connected: ${socket.id}`);
    
    // Handle authentication
    socket.on('authenticate', async (data) => {
        try {
            const { token } = data;
            const decoded = authService.verifyToken(token);
            
            if (decoded) {
                // Store user information with socket
                socket.userId = decoded.userId;
                socket.username = decoded.username;
                socket.authenticated = true;
                
                console.log(`User authenticated: ${socket.username} (${socket.userId})`);
                socket.emit('authenticated', { success: true, username: socket.username });
                
                // Load and send all messages for this user
                try {
                    const messages = await database.getUserMessages(socket.userId);
                    socket.emit('load-user-messages', { messages });
                    console.log(`Loaded ${messages.length} messages for user ${socket.username}`);
                } catch (error) {
                    console.error('Error loading user messages:', error);
                }
                
                // Add authenticated client to the room
                if (connectedClients.size < 2) {
                    connectedClients.set(socket.id, {
                        socketId: socket.id,
                        userId: socket.userId,
                        username: socket.username,
                        connected: true,
                        keyExchangeComplete: false
                    });
                    
                    // Room management logic continues below...
                    handleRoomJoining(socket);
                } else {
                    socket.emit('room-full', { message: 'Room is full. Only 2 users allowed.' });
                    socket.disconnect();
                }
            } else {
                socket.emit('authentication-failed', { message: 'Invalid token' });
                socket.disconnect();
            }
        } catch (error) {
            console.error('Authentication error:', error);
            socket.emit('authentication-failed', { message: 'Authentication failed' });
            socket.disconnect();
        }
    });
    
    // Require authentication for all other events
    const requireAuth = (eventHandler) => {
        return (...args) => {
            if (!socket.authenticated) {
                socket.emit('authentication-required', { message: 'Please authenticate first' });
                return;
            }
            return eventHandler(...args);
        };
    };
    
    function handleRoomJoining(socket) {
        
        // If this is the first client, create a room
        if (connectedClients.size === 1) {
            roomId = `room_${Date.now()}`;
            socket.join(roomId);
            console.log(`Created room: ${roomId}`);
        } else {
            // Second client joins the existing room
            socket.join(roomId);
            console.log(`Client joined room: ${roomId}`);
            
            // Load old messages and send to both clients
            loadAndSendOldMessages(roomId);
            
            // Load shared key if exists and send to clients
            loadAndSendSharedKey(socket);
            
            // Notify both clients that they can start key exchange or use existing key
            io.to(roomId).emit('ready-for-key-exchange', {
                message: 'Both users connected. Ready for secure key exchange or use existing key.',
                clients: Array.from(connectedClients.keys())
            });
        }
    }

    // Handle key exchange initiation
    socket.on('initiate-key-exchange', requireAuth((data) => {
        socket.to(roomId).emit('key-exchange-request', {
            from: socket.id,
            kyberPublicKey: data.kyberPublicKey,
            x25519PublicKey: data.x25519PublicKey
        });
    }));

    // Handle key exchange response
    socket.on('key-exchange-response', requireAuth((data) => {
        console.log('Server: Key exchange response received, broadcasting to initiator');
        
        socket.to(roomId).emit('key-exchange-complete', {
            from: socket.id,
            kyberCiphertext: data.kyberCiphertext,
            x25519PublicKey: data.x25519PublicKey,
            salt: data.salt
        });
        
        // Mark key exchange as complete for both users
        connectedClients.forEach((client, id) => {
            client.keyExchangeComplete = true;
        });
        
        // Notify both clients that secure channel is established
        io.to(roomId).emit('secure-channel-ready', {
            message: 'Secure channel established! You can now chat securely.'
        });
    }));

    // Handle storing shared key after key derivation
    socket.on('store-shared-key', requireAuth(async (data) => {
        const { derivedKey, salt } = data;
        const clients = Array.from(connectedClients.values());
        if (clients.length === 2) {
            const user1 = clients[0].userId;
            const user2 = clients[1].userId;
            try {
                await database.saveSharedKey(user1, user2, Buffer.from(derivedKey, 'hex'), Buffer.from(salt, 'hex'));
                console.log('Shared key stored for users:', user1, user2);
            } catch (error) {
                console.error('Error storing shared key:', error);
            }
        }
    }));

    // Handle chat messages
    socket.on('chat-message', requireAuth(async (data) => {
        console.log('💬 [SERVER DEBUG] Received message from', socket.id);
        console.log('💬 [SERVER DEBUG] Message data:', JSON.stringify(data, null, 2));
        console.log('💬 [SERVER DEBUG] Encrypted flag:', data.encrypted);
        
        // Use toUserId from data if provided (for direct messaging)
        const toUserId = data.toUserId || Array.from(connectedClients.values()).find(c => c.socketId !== socket.id)?.userId;
        
        // Save message to database
        try {
            await database.saveMessage(
                socket.userId,
                toUserId,
                roomId,
                data.message,
                data.encrypted,
                data.encrypted && data.iv ? Buffer.from(data.iv, 'hex') : null,
                data.encrypted && data.authTag ? Buffer.from(data.authTag, 'hex') : null
            );
            console.log(`Message saved: from ${socket.userId} to ${toUserId}`);
        } catch (error) {
            console.error('Error saving message:', error);
        }
        
        const messageToRelay = {
            from: socket.id,
            fromUserId: socket.userId,
            fromUsername: socket.username,
            message: data.message,
            encrypted: data.encrypted,
            timestamp: new Date().toISOString()
        };
        
        // Add IV and authTag if encrypted
        if (data.encrypted && data.iv && data.authTag) {
            messageToRelay.iv = data.iv;
            messageToRelay.authTag = data.authTag;
        }
        
        console.log('[SERVER DEBUG] Relaying message:', JSON.stringify(messageToRelay, null, 2));
        socket.to(roomId).emit('chat-message', messageToRelay);
    }));

    // Handle file transfer
    socket.on('file-transfer', requireAuth(async (data) => {
        console.log('[SERVER DEBUG] Received file transfer from', socket.id);
        console.log('[SERVER DEBUG] File data:', JSON.stringify(data, null, 2));
        
        const clients = Array.from(connectedClients.values());
        const toUserId = clients.find(c => c.socketId !== socket.id)?.userId;
        
        // Save file transfer to database
        try {
            await database.saveFileTransfer(
                socket.userId,
                toUserId,
                roomId,
                data.fileName,
                data.fileData.length,
                data.encrypted,
                data.encrypted && data.iv ? Buffer.from(data.iv, 'hex') : null,
                data.encrypted && data.authTag ? Buffer.from(data.authTag, 'hex') : null
            );
        } catch (error) {
            console.error('Error saving file transfer:', error);
        }
        
        const fileToRelay = {
            from: socket.id,
            fileName: data.fileName,
            fileData: data.fileData,
            encrypted: data.encrypted,
            timestamp: new Date().toISOString()
        };
        
        // Add IV and authTag if encrypted
        if (data.encrypted && data.iv && data.authTag) {
            fileToRelay.iv = data.iv;
            fileToRelay.authTag = data.authTag;
        }
        
        console.log('[SERVER DEBUG] Relaying file:', JSON.stringify(fileToRelay, null, 2));
        socket.to(roomId).emit('file-transfer', fileToRelay);
    }));

    // Handle disconnection
    socket.on('disconnect', () => {
        console.log(`User disconnected: ${socket.id}`);
        connectedClients.delete(socket.id);
        
        // Notify remaining client
        socket.to(roomId).emit('user-disconnected', {
            message: 'Other user disconnected. Secure session ended.',
            disconnectedUser: socket.id
        });
        
        // Reset room if no clients
        if (connectedClients.size === 0) {
            roomId = null;
        }
    });

    // Send current connection status
    socket.emit('connection-status', {
        yourId: socket.id,
        connectedUsers: connectedClients.size,
        roomReady: connectedClients.size === 2
    });
});

function loadAndSendOldMessages(roomId) {
        database.getMessageHistory(roomId).then(messages => {
            io.to(roomId).emit('old-messages', { messages });
        }).catch(error => {
            console.error('Error loading old messages:', error);
        });
    }

    async function loadAndSendSharedKey(socket) {
        const clients = Array.from(connectedClients.values());
        if (clients.length === 2) {
            const user1 = clients[0].userId;
            const user2 = clients[1].userId;
            try {
                const sharedKey = await database.getSharedKey(user1, user2);
                if (sharedKey) {
                    io.to(roomId).emit('shared-key-loaded', {
                        derivedKey: sharedKey.derived_key.toString('hex'),
                        salt: sharedKey.salt.toString('hex')
                    });
                }
            } catch (error) {
                console.error('Error loading shared key:', error);
            }
        }
    }

const PORT = process.env.PORT || 3000;
server.listen(PORT, '0.0.0.0', () => {
    console.log(`P2P Chat Server running on port ${PORT}`);
    console.log(`Open http://localhost:${PORT} to start chatting`);
});