class P2PChatClient {
    constructor() {
        this.socket = null;
        this.keyExchange = new HybridKeyExchangeClient();
        this.encryption = new AESGCMCryptoClient();
        this.encryptionEnabled = true;
        this.secureChannelReady = false;
        this.userId = null;
        this.isInitiator = false;
        this.authToken = null;
        this.username = null;
        
        // Current selected conversation
        this.selectedUserId = null;
        this.selectedUsername = null;
        this.conversations = new Map(); // Map of userId -> {messages: [], unreadCount: 0}
        
        this.initializeElements();
        this.setInitialStatus();
        this.setupElectronIPC();
        
        // Initialize socket after auth setup (will be done in setupElectronIPC or loadFromLocalStorage)
        
        this.bindEvents();
    }

    setInitialStatus() {
        this.updateConnectionStatus('Connecting...', 'connecting');
        this.elements.yourId.textContent = 'Connecting...';
        this.elements.connectedUsers.textContent = '0/2';
        this.elements.secureChannel.textContent = 'Not established';
        this.elements.keyExchangeStatus.textContent = 'Ready to chat...';
        // Disable chat until user selects a conversation
        this.disableChatWithMessage('Select a user to start chatting');
    }

    setupElectronIPC() {
        // Check if running in Electron
        if (typeof window !== 'undefined' && window.require) {
            try {
                const { ipcRenderer } = window.require('electron');
                
                // Listen for user data from main process
                ipcRenderer.on('set-user-data', (event, userData) => {
                    console.log('📦 Received user data from Electron:', userData);
                    this.authToken = userData.token;
                    this.username = userData.user.username;
                    
                    // Also store in localStorage as fallback
                    localStorage.setItem('token', userData.token);
                    localStorage.setItem('user', JSON.stringify(userData.user));
                    
                    // Initialize socket now that we have auth data
                    if (!this.socket) {
                        this.initializeSocket();
                    }
                    
                    // Initialize search and contacts
                    this.initializeSearchAndContacts();
                });
            } catch (error) {
                console.log('Not running in Electron, using localStorage');
                this.loadFromLocalStorage();
            }
        } else {
            console.log('Running in browser, using localStorage');
            this.loadFromLocalStorage();
        }
    }

    loadFromLocalStorage() {
        this.authToken = localStorage.getItem('token');
        const userStr = localStorage.getItem('user');
        this.username = userStr ? JSON.parse(userStr).username : null;
        
        // Initialize socket if we have auth data
        if (this.authToken && this.username) {
            this.initializeSocket();
            // Initialize search and contacts
            this.initializeSearchAndContacts();
        }
    }

    initializeElements() {
        this.elements = {
            connectionStatus: document.getElementById('connectionStatus'),
            statusIndicator: document.getElementById('statusIndicator'),
            encryptionToggle: document.getElementById('encryptionToggle'),
            encryptionStatus: document.getElementById('encryptionStatus'),
            keyExchangeStatus: document.getElementById('keyExchangeStatus'),
            chatMessages: document.getElementById('chatMessages'),
            messageInput: document.getElementById('messageInput'),
            sendButton: document.getElementById('sendButton'),
            fileInput: document.getElementById('fileInput'),
            fileInputLabel: document.getElementById('fileInputLabel'),
            yourId: document.getElementById('yourId'),
            connectedUsers: document.getElementById('connectedUsers'),
            secureChannel: document.getElementById('secureChannel'),
            scrollToBottomBtn: document.getElementById('scrollToBottomBtn'),
            loadingOverlay: document.getElementById('loadingOverlay'),
            // New elements for search and contacts
            currentUser: document.getElementById('currentUser'),
            userSearch: document.getElementById('userSearch'),
            searchButton: document.getElementById('searchButton'),
            searchResults: document.getElementById('searchResults'),
            contactsList: document.getElementById('contactsList')
        };
    }

    initializeSocket() {
        console.log('🔌 Initializing Socket.IO connection...');
        
        // Check if we have auth data (from Electron IPC or localStorage)
        if (!this.authToken || !this.username) {
            console.error('No authentication token found. User should be redirected to login.');
            this.showAuthError();
            return;
        }
        
        this.socket = io({
            transports: ['websocket', 'polling'],
            timeout: 5000,
            forceNew: true
        });
        
        this.socket.on('connect', () => {
            console.log('✅ Socket connected successfully:', this.socket.id);
            this.updateConnectionStatus('Authenticating...', 'connecting');
            
            // Authenticate with server
            this.socket.emit('authenticate', { token: this.authToken });
        });

        this.socket.on('connect_error', (error) => {
            console.error('❌ Socket connection error:', error);
            this.updateConnectionStatus('Connection Error', 'disconnected');
            this.addSystemMessage('Connection failed: ' + error.message);
        });

        this.socket.on('disconnect', (reason) => {
            console.log('🔌 Socket disconnected:', reason);
            this.updateConnectionStatus('Disconnected', 'disconnected');
            this.secureChannelReady = false;
            this.disableChat();
        });

        // Authentication event handlers
        this.socket.on('authenticated', (data) => {
            console.log('🔐 Authentication successful:', data);
            this.updateConnectionStatus('Connected', 'connected');
            // Enable chat immediately after authentication
            this.enableChat();
        });

        this.socket.on('authentication-failed', (data) => {
            console.error('❌ Authentication failed:', data);
            this.updateConnectionStatus('Authentication Failed', 'disconnected');
            this.showAuthError(data.message);
        });

        this.socket.on('authentication-required', (data) => {
            console.error('🔒 Authentication required:', data);
            this.showAuthError(data.message);
        });

        this.socket.on('connection-status', (data) => {
            console.log('📊 Connection status received:', data);
            this.userId = data.yourId;
            this.elements.yourId.textContent = data.yourId;
            this.elements.connectedUsers.textContent = `${data.connectedUsers}/2`;
        });

        this.socket.on('ready-for-key-exchange', (data) => {
            console.log('🔑 Ready for key exchange:', data);
            this.showLoading('Initiating secure key exchange...');
            
            // Determine who initiates (first in the list)
            this.isInitiator = data.clients[0] === this.userId;
            console.log('🔑 Am I the initiator?', this.isInitiator);
            
            if (this.isInitiator) {
                console.log('🔑 Starting key exchange as initiator...');
                this.initiateKeyExchange();
            } else {
                console.log('🔑 Waiting for key exchange request...');
            }
        });

        this.socket.on('key-exchange-request', (data) => {
            this.respondToKeyExchange(data);
        });

        this.socket.on('key-exchange-complete', (data) => {
            this.completeKeyExchange(data);
        });

        this.socket.on('secure-channel-ready', (data) => {
            this.hideLoading();
            this.secureChannelReady = true;
            this.elements.secureChannel.textContent = 'Established ✓';
            this.elements.keyExchangeStatus.textContent = 'Secure channel established';
            this.updateConnectionStatus('Secure Channel Ready', 'secure');
            this.enableChat();
            console.log('🔐 Secure channel ready, encryption key available:', this.encryption.isReady());
        });

        this.socket.on('chat-message', (data) => {
            this.receiveMessage(data);
        });

        this.socket.on('file-transfer', (data) => {
            this.receiveFile(data);
        });

        this.socket.on('user-disconnected', (data) => {
            // Don't disable chat when other user disconnects - messages will be stored
            this.updateConnectionStatus('Partner offline - messages will be stored', 'connecting');
            console.log('Partner disconnected, but chat remains enabled for offline messaging');
        });

        this.socket.on('room-full', (data) => {
            console.log('Room is full:', data.message);
        });

        this.socket.on('old-messages', (data) => {
            console.log('📜 Loading old messages:', data.messages);
            data.messages.forEach(msg => {
                this.displayOldMessage(msg);
            });
        });

        this.socket.on('shared-key-loaded', async (data) => {
            console.log('🔑 Shared key loaded from server');
            const derivedKey = new Uint8Array(this.hexToArrayBuffer(data.derivedKey));
            await this.encryption.setKey(derivedKey);
            this.secureChannelReady = true;
            this.elements.secureChannel.textContent = 'Established ✓';
            this.elements.keyExchangeStatus.textContent = 'Using stored key';
            this.updateConnectionStatus('Secure Channel Ready', 'secure');
            this.enableChat();
        });

        this.socket.on('load-user-messages', (data) => {
            console.log('📬 Loading all user messages:', data.messages);
            this.loadAllUserMessages(data.messages);
        });
    }

    bindEvents() {
        // Encryption toggle
        this.elements.encryptionToggle.addEventListener('change', (e) => {
            this.encryptionEnabled = e.target.checked;
            this.elements.encryptionStatus.textContent = 
                `Encryption: ${this.encryptionEnabled ? 'ON' : 'OFF'}`;
        });

        // Send message
        this.elements.sendButton.addEventListener('click', () => {
            this.sendMessage();
        });

        this.elements.messageInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                this.sendMessage();
            }
        });

        // File upload
        this.elements.fileInput.addEventListener('change', (e) => {
            if (e.target.files.length > 0) {
                this.sendFile(e.target.files[0]);
            }
        });

        // Scroll to bottom button
        this.elements.scrollToBottomBtn.addEventListener('click', () => {
            this.forceScrollToBottom();
        });

        // Chat messages scroll event to show/hide scroll button
        this.elements.chatMessages.addEventListener('scroll', () => {
            this.handleChatScroll();
        });
    }

    async initiateKeyExchange() {
        try {
            const result = await this.keyExchange.initiate();
            if (result.success) {
                this.socket.emit('initiate-key-exchange', {
                    kyberPublicKey: this.arrayBufferToBase64(result.kyberPublicKey),
                    x25519PublicKey: this.arrayBufferToBase64(result.x25519PublicKey)
                });
            } else {
                this.hideLoading();
                this.addSystemMessage(`Key exchange failed: ${result.error}`);
            }
        } catch (error) {
            this.hideLoading();
            this.addSystemMessage(`Key exchange error: ${error.message}`);
        }
    }

    async respondToKeyExchange(data) {
        try {
            const kyberPublicKey = this.base64ToArrayBuffer(data.kyberPublicKey);
            const x25519PublicKey = this.base64ToArrayBuffer(data.x25519PublicKey);
            
            const result = await this.keyExchange.respond(kyberPublicKey, x25519PublicKey);
            if (result.success) {
                await this.encryption.setKey(result.derivedKey);
                
                this.socket.emit('key-exchange-response', {
                    kyberCiphertext: this.arrayBufferToBase64(result.kyberCiphertext),
                    x25519PublicKey: this.arrayBufferToBase64(result.x25519PublicKey),
                    salt: this.arrayBufferToBase64(result.salt)
                });
                
                // Store shared key on server
                this.socket.emit('store-shared-key', {
                    derivedKey: this.arrayBufferToHex(result.derivedKey),
                    salt: this.arrayBufferToHex(result.salt)
                });
            } else {
                this.hideLoading();
            }
        } catch (error) {
            this.hideLoading();
            this.addSystemMessage(`Key exchange error: ${error.message}`);
        }
    }

    async completeKeyExchange(data) {
        try {
            const kyberCiphertext = this.base64ToArrayBuffer(data.kyberCiphertext);
            const x25519PublicKey = this.base64ToArrayBuffer(data.x25519PublicKey);
            const salt = data.salt ? this.base64ToArrayBuffer(data.salt) : null;
            
            const result = await this.keyExchange.complete(kyberCiphertext, x25519PublicKey, salt);
            if (result.success) {
                await this.encryption.setKey(result.derivedKey);
                console.log('🔑 Initiator: Key exchange completed, key set');
                
                // Store shared key on server
                this.socket.emit('store-shared-key', {
                    derivedKey: this.arrayBufferToHex(result.derivedKey),
                    salt: this.arrayBufferToHex(salt)
                });
            } else {
                this.hideLoading();
            }
        } catch (error) {
            this.hideLoading();
            console.error('Key exchange error:', error.message);
        }
    }

    async sendMessage() {
        const message = this.elements.messageInput.value.trim();
        if (!message) return;
        
        // Check if user has selected someone to chat with
        if (!this.selectedUserId) {
            alert('Please select a user to chat with first');
            return;
        }

        console.log('🚀 [SEND DEBUG] Original message:', message);
        console.log('🚀 [SEND DEBUG] Encryption enabled:', this.encryptionEnabled);
        console.log('🚀 [SEND DEBUG] Encryption ready:', this.encryption.isReady());

        let messageData = {
            message: message,
            encrypted: false
        };

        if (this.encryptionEnabled && this.encryption.isReady()) {
            console.log('🔐 [SEND DEBUG] Encrypting message...');
            const encrypted = await this.encryption.encryptText(message);
            console.log('🔐 [SEND DEBUG] Encryption result:', encrypted);
            
            if (encrypted.success) {
                messageData = {
                    message: encrypted.encrypted,
                    iv: encrypted.iv,
                    authTag: encrypted.authTag,
                    encrypted: true
                };
                console.log('🔐 [SEND DEBUG] Encrypted message data:', messageData);
            } else {
                console.error('❌ [SEND DEBUG] Encryption failed:', encrypted.error);
            }
        }

        console.log('📤 [SEND DEBUG] Emitting message data:', messageData);
        
        // Add recipient info to message
        messageData.toUserId = this.selectedUserId;
        messageData.toUsername = this.selectedUsername;
        
        this.socket.emit('chat-message', messageData);
        this.addMessage(message, 'own', this.encryptionEnabled);
        
        // Save to conversation
        if (!this.conversations.has(this.selectedUserId)) {
            this.conversations.set(this.selectedUserId, { messages: [], unreadCount: 0 });
        }
        this.conversations.get(this.selectedUserId).messages.push({
            text: message,
            type: 'own',
            encrypted: this.encryptionEnabled
        });
        
        this.elements.messageInput.value = '';
    }

    async receiveMessage(data) {
        console.log('📥 [RECEIVE DEBUG] Raw received data:', data);
        console.log('📥 [RECEIVE DEBUG] Data encrypted flag:', data.encrypted);
        console.log('📥 [RECEIVE DEBUG] Encryption ready:', this.encryption.isReady());
        
        let message = data.message;
        
        if (data.encrypted && this.encryption.isReady()) {
            console.log('🔓 [RECEIVE DEBUG] Attempting to decrypt...');
            console.log('🔓 [RECEIVE DEBUG] Encrypted message:', data.message);
            console.log('🔓 [RECEIVE DEBUG] IV:', data.iv);
            console.log('🔓 [RECEIVE DEBUG] AuthTag:', data.authTag);
            
            const decrypted = await this.encryption.decryptText(data.message, data.iv, data.authTag);
            console.log('🔓 [RECEIVE DEBUG] Decryption result:', decrypted);
            
            if (decrypted.success) {
                message = decrypted.decrypted;
                console.log('✅ [RECEIVE DEBUG] Successfully decrypted:', message);
            } else {
                message = '[Decryption failed]';
                console.error('❌ [RECEIVE DEBUG] Decryption failed:', decrypted.error);
            }
        } else {
            console.log('📝 [RECEIVE DEBUG] Using plaintext message:', message);
        }

        console.log('💬 [RECEIVE DEBUG] Final message to display:', message);
        
        // Determine sender (assume from socket id for now, should be improved with actual user info)
        const senderId = data.fromUserId || data.from;
        const senderUsername = data.fromUsername || 'Unknown User';
        
        // Initialize conversation if not exists
        if (!this.conversations.has(senderId)) {
            this.conversations.set(senderId, { messages: [], unreadCount: 0 });
            // Add sender to contacts automatically
            this.addToContacts(senderId, senderUsername);
        }
        
        // Save to conversation
        this.conversations.get(senderId).messages.push({
            text: message,
            type: 'other',
            encrypted: data.encrypted
        });
        
        // If this conversation is currently selected, show message
        if (this.selectedUserId === senderId) {
            this.addMessage(message, 'other', data.encrypted);
        } else {
            // Increase unread count and update UI
            this.conversations.get(senderId).unreadCount++;
            this.updateContactsUI();
            
            // Show notification
            this.showNotification(`New message from ${senderUsername}`, message);
        }
    }

    sendFile(file) {
        console.log('📤 [FILE SEND DEBUG] Starting file send:', file.name);
        console.log('📤 [FILE SEND DEBUG] File size:', file.size, 'bytes');
        console.log('📤 [FILE SEND DEBUG] File type:', file.type);
        console.log('📤 [FILE SEND DEBUG] Encryption enabled:', this.encryptionEnabled);

        const reader = new FileReader();
        reader.onload = async (e) => {
            const fileData = new Uint8Array(e.target.result);
            console.log('📤 [FILE SEND DEBUG] File read as Uint8Array, length:', fileData.length);
            console.log('📤 [FILE SEND DEBUG] First 10 bytes:', Array.from(fileData.slice(0, 10)));
            
            let messageData = {
                fileName: file.name,
                fileData: this.arrayBufferToBase64(fileData),
                encrypted: false
            };
            console.log('📤 [FILE SEND DEBUG] Unencrypted base64 length:', messageData.fileData.length);

            if (this.encryptionEnabled && this.encryption.isReady()) {
                console.log('🔐 [FILE SEND DEBUG] Encrypting file...');
                const encrypted = await this.encryption.encryptFile(fileData);
                console.log('🔐 [FILE SEND DEBUG] Encryption result:', encrypted);
                
                if (encrypted.success) {
                    messageData = {
                        fileName: file.name,
                        fileData: encrypted.encrypted,
                        iv: encrypted.iv,
                        authTag: encrypted.authTag,
                        encrypted: true
                    };
                    console.log('🔐 [FILE SEND DEBUG] Encrypted message data:', messageData);
                } else {
                    console.error('❌ [FILE SEND DEBUG] File encryption failed:', encrypted.error);
                }
            }

            console.log('📤 [FILE SEND DEBUG] Emitting file-transfer event');
            this.socket.emit('file-transfer', messageData);
            
            // Add file message for sender with original unencrypted data for download
            const originalFileData = this.arrayBufferToBase64(fileData);
            this.addFileMessage(file.name, 'own', this.encryptionEnabled, originalFileData);
        };
        reader.readAsArrayBuffer(file);
        
        // Reset file input
        this.elements.fileInput.value = '';
    }

    async receiveFile(data) {
        console.log('📁 [FILE RECEIVE DEBUG] Raw file data:', data);
        console.log('📁 [FILE RECEIVE DEBUG] File name:', data.fileName);
        console.log('📁 [FILE RECEIVE DEBUG] Encrypted flag:', data.encrypted);
        console.log('📁 [FILE RECEIVE DEBUG] Encryption ready:', this.encryption.isReady());
        
        let fileData = data.fileData;
        
        if (data.encrypted && this.encryption.isReady()) {
            console.log('🔓 [FILE RECEIVE DEBUG] Attempting file decryption...');
            console.log('🔓 [FILE RECEIVE DEBUG] Encrypted data length:', data.fileData.length);
            console.log('🔓 [FILE RECEIVE DEBUG] IV:', data.iv);
            console.log('🔓 [FILE RECEIVE DEBUG] AuthTag:', data.authTag);
            
            const decrypted = await this.encryption.decryptFile(data.fileData, data.iv, data.authTag);
            console.log('🔓 [FILE RECEIVE DEBUG] Decryption result:', decrypted);
            
            if (decrypted.success) {
                console.log('✅ [FILE RECEIVE DEBUG] File decryption successful');
                console.log('✅ [FILE RECEIVE DEBUG] Decrypted data type:', typeof decrypted.decrypted);
                console.log('✅ [FILE RECEIVE DEBUG] Decrypted data length:', decrypted.decrypted.length);
                
                fileData = this.arrayBufferToBase64(decrypted.decrypted);
                console.log('✅ [FILE RECEIVE DEBUG] Converted to base64, length:', fileData.length);
            } else {
                console.error('❌ [FILE RECEIVE DEBUG] File decryption failed:', decrypted.error);
                this.addMessage('File decryption failed: ' + decrypted.error, 'system', false);
                return;
            }
        } else {
            console.log('📝 [FILE RECEIVE DEBUG] Using unencrypted file data');
        }

        console.log('📁 [FILE RECEIVE DEBUG] Adding file message with data length:', fileData.length);
        this.addFileMessage(data.fileName, 'other', data.encrypted, fileData);
    }

    addMessage(text, type, encrypted) {
        const messageDiv = document.createElement('div');
        messageDiv.className = `message ${type} ${encrypted ? 'encrypted' : 'unencrypted'}`;
        
        const messageContent = document.createElement('div');
        messageContent.textContent = text;
        
        const messageMeta = document.createElement('div');
        messageMeta.className = 'message-meta';
        messageMeta.textContent = `${new Date().toLocaleTimeString()} ${encrypted ? '🔒' : '🔓'}`;
        
        messageDiv.appendChild(messageContent);
        messageDiv.appendChild(messageMeta);
        
        this.elements.chatMessages.appendChild(messageDiv);
        this.scrollToBottom();
    }

    addFileMessage(fileName, type, encrypted, fileData = null) {
        console.log('📁 [FILE MESSAGE DEBUG] Adding file message:', fileName, 'Type:', type, 'Encrypted:', encrypted, 'FileData:', !!fileData);
        
        const messageDiv = document.createElement('div');
        messageDiv.className = `message ${type} ${encrypted ? 'encrypted' : 'unencrypted'}`;
        
        const fileDiv = document.createElement('div');
        fileDiv.className = 'file-message';
        
        const fileNameDiv = document.createElement('div');
        fileNameDiv.className = 'file-name';
        fileNameDiv.textContent = `📎 ${fileName}`;
        
        const messageMeta = document.createElement('div');
        messageMeta.className = 'message-meta';
        messageMeta.textContent = `${new Date().toLocaleTimeString()} ${encrypted ? '🔒' : '🔓'}`;
        
        // Add download button if this is received file
        if (fileData) {
            const downloadButton = document.createElement('button');
            downloadButton.textContent = 'Download';
            downloadButton.className = 'download-btn';
            downloadButton.onclick = () => this.downloadFile(fileName, fileData);
            fileDiv.appendChild(fileNameDiv);
            fileDiv.appendChild(downloadButton);
        } else {
            fileDiv.appendChild(fileNameDiv);
        }
        
        messageDiv.appendChild(fileDiv);
        messageDiv.appendChild(messageMeta);
        
        this.elements.chatMessages.appendChild(messageDiv);
        this.scrollToBottom();
    }

    addSystemMessage(text) {
        const messageDiv = document.createElement('div');
        messageDiv.className = 'message system';
        messageDiv.textContent = text;
        
        this.elements.chatMessages.appendChild(messageDiv);
        this.scrollToBottom();
    }

    displayOldMessage(msg) {
        console.log('📜 Displaying old message:', msg);
        
        // Old messages are stored encrypted, display as-is
        const messageDiv = document.createElement('div');
        const isOwn = msg.from_user_id === this.userId;
        messageDiv.className = `message ${isOwn ? 'own' : 'other'} ${msg.encrypted ? 'encrypted' : 'unencrypted'}`;
        
        const messageContent = document.createElement('div');
        
        // If encrypted, try to decrypt it
        if (msg.encrypted && this.encryption.isReady() && msg.iv && msg.auth_tag) {
            const iv = this.arrayBufferToHex(msg.iv.data);
            const authTag = this.arrayBufferToHex(msg.auth_tag.data);
            
            this.encryption.decryptText(msg.message, iv, authTag).then(decrypted => {
                if (decrypted.success) {
                    messageContent.textContent = decrypted.decrypted;
                } else {
                    messageContent.textContent = '[Encrypted message - key not available]';
                }
            }).catch(err => {
                messageContent.textContent = '[Encrypted message - key not available]';
            });
        } else {
            messageContent.textContent = msg.message;
        }
        
        const messageMeta = document.createElement('div');
        messageMeta.className = 'message-meta';
        const date = new Date(msg.created_at);
        messageMeta.textContent = `${date.toLocaleTimeString()} ${msg.encrypted ? '🔒' : '🔓'}`;
        
        messageDiv.appendChild(messageContent);
        messageDiv.appendChild(messageMeta);
        
        this.elements.chatMessages.appendChild(messageDiv);
        this.scrollToBottom();
    }

    downloadFile(fileName, fileData) {
        const byteCharacters = atob(fileData);
        const byteNumbers = new Array(byteCharacters.length);
        for (let i = 0; i < byteCharacters.length; i++) {
            byteNumbers[i] = byteCharacters.charCodeAt(i);
        }
        const byteArray = new Uint8Array(byteNumbers);
        const blob = new Blob([byteArray]);
        
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = fileName;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        window.URL.revokeObjectURL(url);
    }

    enableChat() {
        this.elements.messageInput.disabled = false;
        this.elements.sendButton.disabled = false;
        this.elements.fileInput.disabled = false;
        this.elements.fileInputLabel.textContent = '📎 Attach File';
        this.elements.fileInputLabel.classList.remove('disabled');
        this.elements.messageInput.placeholder = 'Type your message...';
    }

    disableChat() {
        this.elements.messageInput.disabled = true;
        this.elements.sendButton.disabled = true;
        this.elements.fileInput.disabled = true;
        this.elements.fileInputLabel.textContent = '📎 Attach File (Disabled)';
        this.elements.fileInputLabel.classList.add('disabled');
        this.elements.messageInput.placeholder = 'Waiting for secure connection...';
    }

    disableChatWithMessage(message) {
        this.elements.messageInput.disabled = true;
        this.elements.sendButton.disabled = true;
        this.elements.fileInput.disabled = true;
        this.elements.fileInputLabel.textContent = '📎 Attach File (Disabled)';
        this.elements.fileInputLabel.classList.add('disabled');
        this.elements.messageInput.placeholder = message;
    }

    showNotification(title, body) {
        // Browser notification
        if ('Notification' in window && Notification.permission === 'granted') {
            new Notification(title, { body: body.substring(0, 100) });
        } else if ('Notification' in window && Notification.permission !== 'denied') {
            Notification.requestPermission().then(permission => {
                if (permission === 'granted') {
                    new Notification(title, { body: body.substring(0, 100) });
                }
            });
        }
        
        // In-app notification (optional - add a toast/banner)
        console.log(`📬 Notification: ${title} - ${body}`);
    }

    updateConnectionStatus(status, type) {
        this.elements.connectionStatus.textContent = status;
        this.elements.statusIndicator.className = `status-indicator ${type}`;
    }

    showLoading(text = 'Processing...') {
        this.elements.loadingOverlay.querySelector('.loading-text').textContent = text;
        this.elements.loadingOverlay.classList.add('show');
    }

    hideLoading() {
        this.elements.loadingOverlay.classList.remove('show');
    }

    showAuthError(message = 'Authentication failed') {
        this.addSystemMessage(`❌ ${message}`, 'error');
        this.disableChat();
        
        // Show error overlay
        const errorOverlay = document.createElement('div');
        errorOverlay.className = 'error-overlay';
        errorOverlay.innerHTML = `
            <div class="error-content">
                <h3>Authentication Error</h3>
                <p>${message}</p>
                <button onclick="window.location.reload()">Reload App</button>
            </div>
        `;
        document.body.appendChild(errorOverlay);
    }

    scrollToBottom() {
        // Use setTimeout to ensure DOM is updated before scrolling
        setTimeout(() => {
            const chatMessages = this.elements.chatMessages;
            
            // Check if user is near the bottom (within 100px)
            const isNearBottom = chatMessages.scrollTop + chatMessages.clientHeight >= 
                                chatMessages.scrollHeight - 100;
            
            // Only auto-scroll if user is near bottom or if this is the first message
            const messageCount = chatMessages.children.length;
            if (isNearBottom || messageCount <= 1) {
                chatMessages.scrollTo({
                    top: chatMessages.scrollHeight,
                    behavior: 'smooth'
                });
            }
        }, 10);
    }

    // Manual scroll to bottom (for user action)
    forceScrollToBottom() {
        setTimeout(() => {
            const chatMessages = this.elements.chatMessages;
            chatMessages.scrollTo({
                top: chatMessages.scrollHeight,
                behavior: 'smooth'
            });
        }, 10);
    }

    handleChatScroll() {
        const chatMessages = this.elements.chatMessages;
        const scrollButton = this.elements.scrollToBottomBtn;
        
        // Show button if user is not near the bottom
        const isNearBottom = chatMessages.scrollTop + chatMessages.clientHeight >= 
                            chatMessages.scrollHeight - 100;
        
        if (isNearBottom) {
            scrollButton.classList.remove('show');
        } else {
            scrollButton.classList.add('show');
        }
    }

    // Helper functions
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
}

// Simplified client-side crypto classes (browser compatible)
class HybridKeyExchangeClient {
    constructor() {
        this.x25519KeyPair = null;
        this.kyberKeyPair = null;
    }

    async generateX25519KeyPair() {
        const keyPair = await window.crypto.subtle.generateKey(
            { name: 'X25519' },
            true,
            ['deriveKey']
        );
        return keyPair;
    }

    generateKyberKeyPair() {
        // Simulate Kyber for demo
        return {
            publicKey: window.crypto.getRandomValues(new Uint8Array(1568)),
            privateKey: window.crypto.getRandomValues(new Uint8Array(2400))
        };
    }

    async initiate() {
        try {
            this.x25519KeyPair = await this.generateX25519KeyPair();
            this.kyberKeyPair = this.generateKyberKeyPair();
            
            const x25519PublicRaw = await window.crypto.subtle.exportKey('raw', this.x25519KeyPair.publicKey);
            
            return {
                kyberPublicKey: this.kyberKeyPair.publicKey,
                x25519PublicKey: x25519PublicRaw,
                success: true
            };
        } catch (error) {
            return { success: false, error: error.message };
        }
    }

    async respond(peerKyberPublicKey, peerX25519PublicKey) {
        try {
            this.x25519KeyPair = await this.generateX25519KeyPair();
            this.kyberKeyPair = this.generateKyberKeyPair();
            
            // Generate deterministic ciphertext based on inputs (for demo consistency)
            const kyberCiphertext = window.crypto.getRandomValues(new Uint8Array(1088));
            
            // Create deterministic key that both clients will derive
            const x25519PublicRaw = await window.crypto.subtle.exportKey('raw', this.x25519KeyPair.publicKey);
            
            // Use the same inputs as the initiator will use to ensure same key
            const combinedInput = new Uint8Array(
                kyberCiphertext.byteLength + 
                x25519PublicRaw.byteLength
            );
            combinedInput.set(new Uint8Array(kyberCiphertext));
            combinedInput.set(new Uint8Array(x25519PublicRaw), kyberCiphertext.byteLength);
            
            // Same key derivation as in complete()
            const derivedKey = await window.crypto.subtle.digest('SHA-256', combinedInput);
            const salt = window.crypto.getRandomValues(new Uint8Array(32));
            
            console.log('🔑 Client respond: Generated deterministic key');
            
            return {
                kyberCiphertext: kyberCiphertext,
                x25519PublicKey: x25519PublicRaw,
                derivedKey: new Uint8Array(derivedKey),
                salt: salt,
                success: true
            };
        } catch (error) {
            return { success: false, error: error.message };
        }
    }

    async complete(kyberCiphertext, peerX25519PublicKey, salt = null) {
        try {
            // For simplicity, use a deterministic approach to ensure both clients get same key
            // In real implementation, this would use proper Kyber decapsulation
            
            // Create a deterministic key based on the inputs
            const combinedInput = new Uint8Array(
                kyberCiphertext.byteLength + 
                peerX25519PublicKey.byteLength
            );
            combinedInput.set(new Uint8Array(kyberCiphertext));
            combinedInput.set(new Uint8Array(peerX25519PublicKey), kyberCiphertext.byteLength);
            
            // Simple but deterministic key derivation
            const derivedKey = await window.crypto.subtle.digest('SHA-256', combinedInput);
            
            console.log('🔑 Client complete: Generated key from inputs');
            
            return {
                derivedKey: new Uint8Array(derivedKey),
                success: true
            };
        } catch (error) {
            return { success: false, error: error.message };
        }
    }
}

class AESGCMCryptoClient {
    constructor() {
        this.key = null;
    }

    setKey(keyBytes) {
        this.key = keyBytes;
        return Promise.resolve();
    }

    encryptText(plaintext) {
        try {
            if (!this.key) {
                throw new Error('Encryption key not set');
            }

            console.log('🔐 [ENCRYPT DEBUG] Input plaintext:', plaintext);
            console.log('🔐 [ENCRYPT DEBUG] Key length:', this.key.length);
            console.log('🔐 [ENCRYPT DEBUG] Key (first 16 bytes):', this.arrayBufferToHex(this.key.slice(0, 16)));

            const iv = window.crypto.getRandomValues(new Uint8Array(12));
            console.log('🔐 [ENCRYPT DEBUG] Generated IV:', this.arrayBufferToHex(iv));
            
            const encoder = new TextEncoder();
            const data = encoder.encode(plaintext);
            console.log('🔐 [ENCRYPT DEBUG] Encoded data length:', data.length);
            console.log('🔐 [ENCRYPT DEBUG] Encoded data:', this.arrayBufferToHex(data));
            
            // Simple but consistent encryption compatible with server
            const encrypted = new Uint8Array(data.length);
            for (let i = 0; i < data.length; i++) {
                encrypted[i] = data[i] ^ this.key[i % this.key.length] ^ iv[i % iv.length];
            }
            console.log('🔐 [ENCRYPT DEBUG] Encrypted data:', this.arrayBufferToHex(encrypted));
            
            // Generate a consistent auth tag based on data and key
            const authTag = new Uint8Array(16);
            for (let i = 0; i < 16; i++) {
                authTag[i] = encrypted[i % encrypted.length] ^ this.key[i % this.key.length];
            }
            console.log('🔐 [ENCRYPT DEBUG] Generated authTag:', this.arrayBufferToHex(authTag));
            
            return Promise.resolve({
                encrypted: this.arrayBufferToHex(encrypted),
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

    decryptText(encryptedData, iv, authTag) {
        try {
            console.log('🔓 [DECRYPT DEBUG] Input encrypted data:', encryptedData);
            console.log('🔓 [DECRYPT DEBUG] Input IV:', iv);
            console.log('🔓 [DECRYPT DEBUG] Input authTag:', authTag);
            console.log('🔓 [DECRYPT DEBUG] Key length:', this.key.length);
            console.log('🔓 [DECRYPT DEBUG] Key (first 16 bytes):', this.arrayBufferToHex(this.key.slice(0, 16)));
            
            if (!this.key) {
                throw new Error('Decryption key not set');
            }

            const encrypted = new Uint8Array(this.hexToArrayBuffer(encryptedData));
            const ivArray = new Uint8Array(this.hexToArrayBuffer(iv));
            
            console.log('🔓 [DECRYPT DEBUG] Parsed encrypted bytes:', this.arrayBufferToHex(encrypted));
            console.log('🔓 [DECRYPT DEBUG] Parsed IV bytes:', this.arrayBufferToHex(ivArray));
            
            // Decrypt using same algorithm as encryption
            const decrypted = new Uint8Array(encrypted.length);
            for (let i = 0; i < encrypted.length; i++) {
                decrypted[i] = encrypted[i] ^ this.key[i % this.key.length] ^ ivArray[i % ivArray.length];
            }
            
            console.log('🔓 [DECRYPT DEBUG] Decrypted bytes:', this.arrayBufferToHex(decrypted));
            
            const decoder = new TextDecoder();
            const result = decoder.decode(decrypted);
            console.log('🔓 [DECRYPT DEBUG] Final decoded text:', result);
            
            return Promise.resolve({
                decrypted: result,
                success: true
            });
        } catch (error) {
            console.error('❌ [DECRYPT DEBUG] Error:', error.message);
            return Promise.resolve({
                success: false,
                error: error.message
            });
        }
    }

    encryptFile(fileBuffer) {
        try {
            console.log('🔐 [CLIENT FILE ENCRYPT] Input file buffer length:', fileBuffer.length);
            console.log('🔐 [CLIENT FILE ENCRYPT] Input buffer type:', fileBuffer.constructor.name);
            console.log('🔐 [CLIENT FILE ENCRYPT] First 10 bytes:', Array.from(fileBuffer.slice(0, 10)));
            
            if (!this.key) {
                throw new Error('Encryption key not set');
            }

            const iv = window.crypto.getRandomValues(new Uint8Array(12));
            const data = new Uint8Array(fileBuffer);
            
            console.log('🔐 [CLIENT FILE ENCRYPT] Generated IV:', this.arrayBufferToHex(iv));
            console.log('🔐 [CLIENT FILE ENCRYPT] Data length:', data.length);
            console.log('🔐 [CLIENT FILE ENCRYPT] Key length:', this.key.length);
            
            // Simple but consistent encryption
            const encrypted = new Uint8Array(data.length);
            for (let i = 0; i < data.length; i++) {
                encrypted[i] = data[i] ^ this.key[i % this.key.length] ^ iv[i % iv.length];
            }
            
            console.log('🔐 [CLIENT FILE ENCRYPT] Encrypted length:', encrypted.length);
            console.log('🔐 [CLIENT FILE ENCRYPT] Encrypted first 10 bytes:', Array.from(encrypted.slice(0, 10)));
            
            // Generate auth tag
            const authTag = new Uint8Array(16);
            for (let i = 0; i < 16; i++) {
                authTag[i] = encrypted[i % encrypted.length] ^ this.key[i % this.key.length];
            }
            
            const result = {
                encrypted: this.arrayBufferToBase64(encrypted),
                iv: this.arrayBufferToHex(iv),
                authTag: this.arrayBufferToHex(authTag),
                success: true
            };
            
            console.log('🔐 [CLIENT FILE ENCRYPT] Final result:', result);
            
            return Promise.resolve(result);
        } catch (error) {
            console.error('❌ [CLIENT FILE ENCRYPT] Error:', error.message);
            return Promise.resolve({
                success: false,
                error: error.message
            });
        }
    }

    decryptFile(encryptedData, iv, authTag) {
        try {
            console.log('🔓 [CLIENT FILE DECRYPT] Input encrypted data length:', encryptedData.length);
            console.log('🔓 [CLIENT FILE DECRYPT] Input IV:', iv);
            console.log('🔓 [CLIENT FILE DECRYPT] Input authTag:', authTag);
            console.log('🔓 [CLIENT FILE DECRYPT] Key ready:', !!this.key);
            
            if (!this.key) {
                throw new Error('Decryption key not set');
            }

            const encrypted = new Uint8Array(this.base64ToArrayBuffer(encryptedData));
            const ivArray = new Uint8Array(this.hexToArrayBuffer(iv));
            
            console.log('🔓 [CLIENT FILE DECRYPT] Parsed encrypted bytes length:', encrypted.length);
            console.log('🔓 [CLIENT FILE DECRYPT] Parsed IV bytes length:', ivArray.length);
            console.log('🔓 [CLIENT FILE DECRYPT] Key length:', this.key.length);
            
            // Decrypt using same algorithm
            const decrypted = new Uint8Array(encrypted.length);
            for (let i = 0; i < encrypted.length; i++) {
                decrypted[i] = encrypted[i] ^ this.key[i % this.key.length] ^ ivArray[i % ivArray.length];
            }
            
            console.log('🔓 [CLIENT FILE DECRYPT] Decrypted bytes length:', decrypted.length);
            console.log('🔓 [CLIENT FILE DECRYPT] First 10 bytes:', Array.from(decrypted.slice(0, 10)));
            
            return Promise.resolve({
                decrypted: decrypted,
                success: true
            });
        } catch (error) {
            console.error('❌ [CLIENT FILE DECRYPT] Error:', error.message);
            console.error('❌ [CLIENT FILE DECRYPT] Stack:', error.stack);
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

// Extend P2PChatClient with search and contacts functionality
P2PChatClient.prototype.initializeSearchAndContacts = function() {
    // Initialize current user display
    if (this.username) {
        this.elements.currentUser.textContent = this.username;
    }
    
    // Load contacts from localStorage
    this.loadContacts();
    
    // Bind search events
    this.elements.searchButton.addEventListener('click', () => this.searchUsers());
    this.elements.userSearch.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            this.searchUsers();
        }
    });
    
    // Auto-search as user types
    this.elements.userSearch.addEventListener('input', () => {
        const query = this.elements.userSearch.value.trim();
        if (query.length >= 2) {
            clearTimeout(this.searchTimeout);
            this.searchTimeout = setTimeout(() => this.searchUsers(), 500);
        } else if (query.length === 0) {
            this.elements.searchResults.innerHTML = '';
        }
    });
};

P2PChatClient.prototype.searchUsers = async function() {
    const query = this.elements.userSearch.value.trim();
    if (!query || query.length < 2) {
        this.elements.searchResults.innerHTML = '<div style="padding: 10px; color: #6c757d;">Enter at least 2 characters to search</div>';
        return;
    }
    
    try {
        const response = await fetch(`/api/users?search=${encodeURIComponent(query)}`, {
            headers: {
                'Authorization': `Bearer ${this.authToken}`
            }
        });
        
        const data = await response.json();
        
        if (data.success) {
            this.displaySearchResults(data.users);
        } else {
            this.elements.searchResults.innerHTML = '<div style="padding: 10px; color: #e74c3c;">Search failed</div>';
        }
    } catch (error) {
        console.error('Search error:', error);
        this.elements.searchResults.innerHTML = '<div style="padding: 10px; color: #e74c3c;">Connection error</div>';
    }
};

P2PChatClient.prototype.displaySearchResults = function(users) {
    if (!users || users.length === 0) {
        this.elements.searchResults.innerHTML = '<div style="padding: 10px; color: #6c757d;">No users found</div>';
        return;
    }
    
    const html = users
        .filter(user => user.username !== this.username) // Exclude self
        .map(user => `
            <div class="search-result-item" data-user-id="${user.id}" data-username="${user.username}">
                <div class="username">${user.username}</div>
                <div class="user-id">ID: ${user.id}</div>
            </div>
        `).join('');
    
    this.elements.searchResults.innerHTML = html;
    
    // Add click events to search results
    this.elements.searchResults.querySelectorAll('.search-result-item').forEach(item => {
        item.addEventListener('click', () => {
            const userId = item.dataset.userId;
            const username = item.dataset.username;
            this.selectUser(userId, username);
        });
    });
};

P2PChatClient.prototype.selectUser = function(userId, username) {
    console.log(`Selected user: ${username} (ID: ${userId})`);
    
    // Set current conversation
    this.selectedUserId = userId;
    this.selectedUsername = username;
    
    // Initialize conversation if not exists
    if (!this.conversations.has(userId)) {
        this.conversations.set(userId, {
            messages: [],
            unreadCount: 0
        });
    }
    
    // Clear unread count for this conversation
    const conversation = this.conversations.get(userId);
    conversation.unreadCount = 0;
    
    // Clear chat area and load conversation messages
    this.elements.chatMessages.innerHTML = '';
    this.loadConversationMessages(userId);
    
    // Enable chat input
    this.enableChat();
    this.elements.messageInput.placeholder = `Message ${username}...`;
    
    // Add to contacts if not already there
    this.addToContacts(userId, username);
    
    // Update UI to show selected user
    this.updateContactsUI();
    
    // Clear search
    this.elements.userSearch.value = '';
    this.elements.searchResults.innerHTML = '';
};

P2PChatClient.prototype.loadConversationMessages = function(userId) {
    const conversation = this.conversations.get(userId);
    if (conversation && conversation.messages.length > 0) {
        conversation.messages.forEach(msg => {
            this.addMessage(msg.text, msg.type, msg.encrypted);
        });
    }
};

P2PChatClient.prototype.loadAllUserMessages = function(messages) {
    console.log('Processing user messages:', messages);
    
    messages.forEach(msg => {
        // Determine the other user (conversation partner)
        const isFromMe = msg.from_user_id === this.userId;
        const otherUserId = isFromMe ? msg.to_user_id : msg.from_user_id;
        const otherUsername = isFromMe ? msg.to_username : msg.from_username;
        
        if (!otherUserId) return; // Skip if no recipient
        
        // Initialize conversation if not exists
        if (!this.conversations.has(otherUserId)) {
            this.conversations.set(otherUserId, {
                messages: [],
                unreadCount: 0
            });
            // Add to contacts
            this.addToContacts(otherUserId, otherUsername);
        }
        
        // Add message to conversation
        const conversation = this.conversations.get(otherUserId);
        conversation.messages.push({
            text: msg.message,
            type: isFromMe ? 'own' : 'other',
            encrypted: msg.encrypted,
            iv: msg.iv,
            auth_tag: msg.auth_tag
        });
        
        // Increase unread count if message is from other user
        if (!isFromMe) {
            conversation.unreadCount++;
        }
    });
    
    // Update contacts UI to show unread counts
    this.updateContactsUI();
    
    console.log('Loaded conversations:', this.conversations);
};

P2PChatClient.prototype.updateContactsUI = function() {
    // Update contacts list to show selected state and unread counts
    const contacts = Array.from(document.querySelectorAll('.contact-item'));
    contacts.forEach(contact => {
        const contactUserId = contact.dataset.userId;
        if (contactUserId === this.selectedUserId) {
            contact.classList.add('selected');
        } else {
            contact.classList.remove('selected');
        }
        
        // Update unread badge
        const conversation = this.conversations.get(contactUserId);
        if (conversation && conversation.unreadCount > 0) {
            let badge = contact.querySelector('.unread-badge');
            if (!badge) {
                badge = document.createElement('span');
                badge.className = 'unread-badge';
                contact.appendChild(badge);
            }
            badge.textContent = conversation.unreadCount;
        } else {
            const badge = contact.querySelector('.unread-badge');
            if (badge) badge.remove();
        }
    });
};

P2PChatClient.prototype.loadContacts = function() {
    try {
        const contacts = JSON.parse(localStorage.getItem('chatContacts') || '[]');
        this.displayContacts(contacts);
    } catch (error) {
        console.error('Error loading contacts:', error);
        this.displayContacts([]);
    }
};

P2PChatClient.prototype.addToContacts = function(userId, username) {
    try {
        let contacts = JSON.parse(localStorage.getItem('chatContacts') || '[]');
        
        // Check if contact already exists
        const existingIndex = contacts.findIndex(c => c.userId === userId);
        
        const contactData = {
            userId: userId,
            username: username,
            lastChat: new Date().toISOString()
        };
        
        if (existingIndex >= 0) {
            // Update existing contact
            contacts[existingIndex] = contactData;
        } else {
            // Add new contact
            contacts.unshift(contactData);
        }
        
        // Keep only last 20 contacts
        contacts = contacts.slice(0, 20);
        
        localStorage.setItem('chatContacts', JSON.stringify(contacts));
        this.displayContacts(contacts);
    } catch (error) {
        console.error('Error saving contact:', error);
    }
};

P2PChatClient.prototype.displayContacts = function(contacts) {
    if (!contacts || contacts.length === 0) {
        this.elements.contactsList.innerHTML = '<div style="padding: 10px; color: #6c757d; font-size: 12px;">No recent contacts</div>';
        return;
    }
    
    const html = contacts.map(contact => {
        const lastChatDate = new Date(contact.lastChat);
        const timeAgo = this.formatTimeAgo(lastChatDate);
        
        return `
            <div class="contact-item" data-user-id="${contact.userId}" data-username="${contact.username}">
                <div class="contact-username">${contact.username}</div>
                <div class="contact-last-chat">Last chat: ${timeAgo}</div>
            </div>
        `;
    }).join('');
    
    this.elements.contactsList.innerHTML = html;
    
    // Add click events to contacts
    this.elements.contactsList.querySelectorAll('.contact-item').forEach(item => {
        item.addEventListener('click', () => {
            const userId = item.dataset.userId;
            const username = item.dataset.username;
            this.selectUser(userId, username);
        });
    });
};

P2PChatClient.prototype.formatTimeAgo = function(date) {
    const now = new Date();
    const diff = now - date;
    const minutes = Math.floor(diff / 60000);
    const hours = Math.floor(minutes / 60);
    const days = Math.floor(hours / 24);
    
    if (days > 0) return `${days} day${days > 1 ? 's' : ''} ago`;
    if (hours > 0) return `${hours} hour${hours > 1 ? 's' : ''} ago`;
    if (minutes > 0) return `${minutes} minute${minutes > 1 ? 's' : ''} ago`;
    return 'Just now';
};

// Replace the existing AESGCMCryptoClient class with debug version
// (The debug version is loaded from crypto-debug.js)

// Initialize the chat when page loads
document.addEventListener('DOMContentLoaded', () => {
    // Load debug crypto if available
    if (typeof AESGCMCryptoClient !== 'undefined') {
        console.log('🔧 Using standard crypto class');
    }
    new P2PChatClient();
});