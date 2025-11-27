// Simple server connectivity test
console.log('🧪 Testing server connectivity...');

// Test if server is running
fetch('http://localhost:3000')
    .then(response => {
        if (response.ok) {
            console.log('✅ Server is running and accessible');
            return response.text();
        } else {
            console.log('❌ Server responded with error:', response.status);
        }
    })
    .then(html => {
        if (html && html.includes('P2P Encrypted Chat')) {
            console.log('✅ Server is serving the correct content');
        } else {
            console.log('❌ Server content is not correct');
        }
    })
    .catch(error => {
        console.error('❌ Cannot connect to server:', error);
        console.log('Make sure server is running: cd p2p-chat && node server.js');
    });

// Test Socket.IO connection
const socket = io('http://localhost:3000', {
    transports: ['websocket', 'polling'],
    timeout: 5000
});

socket.on('connect', () => {
    console.log('✅ Socket.IO connection successful');
    console.log('Socket ID:', socket.id);
    socket.disconnect();
});

socket.on('connect_error', (error) => {
    console.error('❌ Socket.IO connection failed:', error);
});

setTimeout(() => {
    console.log('🔚 Test completed');
}, 3000);