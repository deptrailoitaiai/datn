# P2P Encrypted Chat - Testing Guide

## Hướng dẫn Test Ứng dụng

### 1. Cài đặt Dependencies

```bash
cd /home/tienminh/dotienminh/whereIBeatTheWorld/datn/demo/p2p-chat
npm install
```

### 2. Chạy trực tiếp (không dùng Docker)

```bash
# Terminal 1 - Start server
npm start

# Terminal 2 - Mở browser 1
# Truy cập: http://localhost:3000

# Terminal 3 - Mở browser 2  
# Truy cập: http://localhost:3000 (tab mới)
```

### 3. Chạy với Docker (Recommended for Wireshark monitoring)

```bash
# Build và chạy containers
docker-compose up --build

# Containers sẽ chạy trên:
# - Server: http://localhost:3000
# - Client 1: http://localhost:3001  
# - Client 2: http://localhost:3002
```

### 4. Test Cases

#### Test 1: Kết nối P2P
- Mở 2 browser tabs/windows
- Truy cập cùng URL
- Verify: Cả 2 clients kết nối thành công
- Expected: "Both users connected. Ready for secure key exchange."

#### Test 2: Key Exchange
- Sau khi 2 clients kết nối
- Verify: Key exchange tự động diễn ra
- Expected: "Secure channel established! You can now chat securely."

#### Test 3: Encrypted Chat
- Đảm bảo toggle encryption = ON
- Gửi tin nhắn từ client 1 → client 2
- Verify: Tin nhắn có icon 🔒 (encrypted)

#### Test 4: Unencrypted Chat  
- Toggle encryption = OFF
- Gửi tin nhắn từ client 2 → client 1
- Verify: Tin nhắn có icon 🔓 (unencrypted)

#### Test 5: File Transfer (Encrypted)
- Toggle encryption = ON
- Upload file "sample-test.txt" từ client 1
- Verify: File được gửi với icon 🔒
- Download file tại client 2
- Verify: Nội dung file chính xác

#### Test 6: File Transfer (Unencrypted)
- Toggle encryption = OFF
- Upload file từ client 2
- Verify: File được gửi với icon 🔓

### 5. Wireshark Monitoring (Docker only)

```bash
# Capture network traffic
sudo wireshark

# Monitor interface: docker0 hoặc br-* (Docker bridge)
# Filter: tcp.port == 3000

# So sánh traffic khi:
# - Encryption ON vs OFF
# - Message vs File transfer
```

### 6. Expected Results

✅ **Encryption ON**: Data không đọc được trong Wireshark
❌ **Encryption OFF**: Data có thể đọc được plaintext  
🔄 **Key Exchange**: Thành công trong ~1-2 giây
📊 **Performance**: Smooth real-time chat
🔧 **UI**: Toggle hoạt động mượt mà

### 7. Troubleshooting

#### Problem: Không kết nối được (Connection failed)
**Symptoms:** Browser shows "Connecting..." hoặc "Connection Error"

**Solutions:**
```bash
# 1. Kiểm tra server đang chạy
cd p2p-chat
node server.js
# Should show: "P2P Chat Server running on port 3000"

# 2. Kiểm tra port không bị chiếm
lsof -i :3000
# Nếu có process khác, kill nó hoặc đổi port

# 3. Test connection
curl http://localhost:3000
# Should return HTML content

# 4. Restart browser completely
# Close all tabs, restart browser

# 5. Disable browser extensions
# Some extensions block WebSocket connections

# 6. Check firewall/antivirus
# Temporarily disable to test
```

#### Problem: 2 tabs không thấy nhau
**Symptoms:** Mỗi tab hiển thị "Waiting for second user"

**Solutions:**
1. **Refresh both tabs** cùng lúc
2. **Check browser console** (F12) for errors:
   - Socket connection errors
   - JavaScript errors
   - Network blocking
3. **Use different browsers:**
   - Tab 1: Chrome `http://localhost:3000`
   - Tab 2: Firefox `http://localhost:3000`
4. **Clear browser cache** and cookies
5. **Private/Incognito mode** test

#### Problem: Key exchange thất bại
- Check: Browser console errors
- Fix: Refresh cả 2 tabs
- Check: Both clients connected first

#### Problem: File upload không hoạt động
- Check: File size < 10MB
- Check: Secure channel đã established
- Check: File trong thư mục `test-files/`

#### Problem: "[Decryption failed]" messages
- Check: Both clients completed key exchange
- Check: Browser console for crypto errors
- Fix: Restart both clients

### 8. Architecture Overview

```
Client 1 ←→ Socket.IO Server ←→ Client 2
    ↓              ↓              ↓
Kyber+X25519   Key Exchange   Kyber+X25519
    ↓              ↓              ↓  
  AES-GCM ←→  scrypt KDF  ←→  AES-GCM
```

### 9. Security Features

- **Post-Quantum**: Kyber768 encryption
- **ECDH**: X25519 key exchange  
- **KDF**: scrypt key derivation
- **Symmetric**: AES-256-GCM
- **Forward Secrecy**: New keys per session
- **Authenticated**: GCM authentication tags