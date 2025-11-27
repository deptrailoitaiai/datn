#!/bin/bash
# WIRESHARK DEMO - Giả lập bắt gói tin P2P Chat

clear
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║           WIRESHARK - P2P CHAT PACKET CAPTURE                ║"
echo "║              Network Traffic Analysis Demo                   ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "Interface: Loopback (lo)"
echo "Filter: tcp.port == 3000 && websocket"
echo "Time: $(date '+%Y-%m-%d %H:%M:%S')"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "STARTING CAPTURE..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Simulate capture process
for i in {1..3}; do
    echo -n "."
    sleep 0.3
done
echo " ✓"
echo ""

# Simulate packet capture
echo "════════════════════════════════════════════════════════════════"
echo "                    CAPTURED PACKETS                            "
echo "════════════════════════════════════════════════════════════════"
echo ""

# Packet 1: Unencrypted message 1
echo "Packet #1 - WebSocket Frame"
echo "   Time: $(date '+%H:%M:%S').001"
echo "   Source: 127.0.0.1:54321 -> Dest: 127.0.0.1:3000"
echo "   Protocol: WebSocket (text)"
echo "   Length: 156 bytes"
echo ""
echo "   PAYLOAD (READABLE - NO ENCRYPTION):"
echo '   {' 
echo '     "type": "chat",'
echo '     "data": "Hello this is a secret message",'
echo '     "encrypted": false,'
echo '     "timestamp": "2025-11-08T12:30:15.001Z"'
echo '   }'
echo ""
echo "   SECURITY RISK: Message content is VISIBLE!"
echo ""
echo "────────────────────────────────────────────────────────────────"
sleep 1

# Packet 2: Unencrypted message 2
echo ""
echo "Packet #2 - WebSocket Frame"
echo "   Time: $(date '+%H:%M:%S').125"
echo "   Source: 127.0.0.1:54322 -> Dest: 127.0.0.1:3000"
echo "   Protocol: WebSocket (text)"
echo "   Length: 142 bytes"
echo ""
echo "   PAYLOAD (READABLE - NO ENCRYPTION):"
echo '   {' 
echo '     "type": "chat",'
echo '     "data": "My password is 123456",'
echo '     "encrypted": false,'
echo '     "timestamp": "2025-11-08T12:30:15.125Z"'
echo '   }'
echo ""
echo "   SECURITY RISK: PASSWORD LEAKED IN PLAINTEXT!"
echo ""
echo "────────────────────────────────────────────────────────────────"
sleep 1

# Packet 3: Encrypted message 1
echo ""
echo "Packet #3 - WebSocket Frame"
echo "   Time: $(date '+%H:%M:%S').342"
echo "   Source: 127.0.0.1:54321 -> Dest: 127.0.0.1:3000"
echo "   Protocol: WebSocket (text)"
echo "   Length: 284 bytes"
echo ""
echo "   PAYLOAD (ENCRYPTED - NOT READABLE):"
echo '   {' 
echo '     "type": "chat",'
echo '     "data": "a3f7c9d8e1b4f5a6c7d8e9f0a1b2c3d4e5f6a7b8",'
echo '     "iv": "1a2b3c4d5e6f7a8b9c0d1e2f",'
echo '     "authTag": "9f8e7d6c5b4a39281726f5e4d3c2b1a0",'
echo '     "encrypted": true,'
echo '     "timestamp": "2025-11-08T12:30:15.342Z"'
echo '   }'
echo ""
echo "   SECURE: Content is ENCRYPTED (AES-256-GCM)"
echo "   Cannot decode without shared secret key"
echo ""
echo "────────────────────────────────────────────────────────────────"
sleep 1

# Packet 4: Encrypted message 2
echo ""
# Packet 4: Encrypted message 2
echo ""
echo "Packet #4 - WebSocket Frame"
echo "   Time: $(date '+%H:%M:%S').489"
echo "   Source: 127.0.0.1:54322 -> Dest: 127.0.0.1:3000"
echo "   Protocol: WebSocket (text)"
echo "   Length: 276 bytes"
echo ""
echo "   PAYLOAD (ENCRYPTED - NOT READABLE):"
echo '   {' 
echo '     "type": "chat",'
echo '     "data": "e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4",'
echo '     "iv": "4f3a2b1c0d9e8f7a6b5c4d3e",'
echo '     "authTag": "2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f",'
echo '     "encrypted": true,'
echo '     "timestamp": "2025-11-08T12:30:15.489Z"'
echo '   }'
echo ""
echo "   SECURE: Password encrypted, cannot be intercepted"
echo ""
echo "════════════════════════════════════════════════════════════════"
echo ""

# Summary
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "                     ANALYSIS SUMMARY                           "
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Total Packets Captured: 4"
echo ""
echo "UNENCRYPTED Messages: 2"
echo "   Privacy: EXPOSED"
echo "   Data readable: YES"
echo "   Password visible: YES"
echo "   Risk Level: HIGH"
echo ""
echo "ENCRYPTED Messages: 2"
echo "   Privacy: PROTECTED"
echo "   Data readable: NO (ciphertext only)"
echo "   Password visible: NO"
echo "   Risk Level: LOW"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "CONCLUSION:"
echo ""
echo "   WITHOUT Encryption:"
echo "   - Attacker CAN read all messages"
echo "   - Passwords and secrets are EXPOSED"
echo "   - Complete privacy breach"
echo ""
echo "   WITH Encryption:"
echo "   - Attacker CANNOT read message content"
echo "   - Only sees encrypted gibberish"
echo "   - Privacy is PROTECTED"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Capture complete!"
echo ""
