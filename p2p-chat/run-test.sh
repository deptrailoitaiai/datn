#!/bin/bash

echo "=========================================="
echo "  P2P Chat - Auto Test & Analyze"
echo "=========================================="
echo ""

# Start server in background
echo "[1/4] Starting server..."
cd /home/tienminh/dotienminh/whereIBeatTheWorld/datn/demo/p2p-chat
node server.js > /tmp/server.log 2>&1 &
SERVER_PID=$!
sleep 3

# Check server
if ! curl -s http://localhost:3000 > /dev/null; then
    echo "ERROR: Server failed to start!"
    cat /tmp/server.log
    exit 1
fi
echo "✓ Server running (PID: $SERVER_PID)"

# Start tcpdump
echo ""
echo "[2/4] Starting packet capture..."
echo "      (You may need to enter sudo password)"
sudo tcpdump -i lo -w /tmp/p2p-chat.pcap "tcp port 3000" > /dev/null 2>&1 &
TCPDUMP_PID=$!
sleep 2
echo "✓ Capturing packets (PID: $TCPDUMP_PID)"

# Instructions
echo ""
echo "=========================================="
echo "[3/4] NOW DO THE TESTING:"
echo "=========================================="
echo ""
echo "1. Open 2 browsers:"
echo "   http://localhost:3000 (x2)"
echo ""
echo "2. Login with 2 different accounts"
echo ""
echo "3. Turn OFF encryption → Send messages:"
echo "   - 'Hello test'"
echo "   - 'Password 123'"
echo ""
echo "4. Turn ON encryption → Send same messages"
echo ""
echo "5. When done, press ENTER here..."
echo ""

read -p "Press ENTER after you finished testing: "

# Stop capture
echo ""
echo "[4/4] Stopping and analyzing..."
sudo kill -SIGINT $TCPDUMP_PID 2>/dev/null
sleep 2

# Stop server  
kill $SERVER_PID 2>/dev/null

# Analyze (FAST - only count and show examples)
echo ""
echo "=========================================="
echo "  ANALYSIS RESULTS (Quick)"
echo "=========================================="
echo ""

# Quick packet count
TOTAL=$(wc -c < /tmp/p2p-chat.pcap)
echo "✓ Capture file size: $((TOTAL / 1024)) KB"
echo ""

# Fast search with grep (much faster than tshark)
echo "--- UNENCRYPTED MESSAGES (readable) ---"
sudo tcpdump -r /tmp/p2p-chat.pcap -A 2>/dev/null | grep -o '"data":"[^"]*","encrypted":false' | head -3
echo ""

echo "--- ENCRYPTED MESSAGES (ciphertext) ---"
sudo tcpdump -r /tmp/p2p-chat.pcap -A 2>/dev/null | grep -o '"data":"[^"]*","iv":"[^"]*",".*encrypted":true' | head -3
echo ""

# Count occurrences
UNENC=$(sudo tcpdump -r /tmp/p2p-chat.pcap -A 2>/dev/null | grep -c 'encrypted":false' || echo 0)
ENC=$(sudo tcpdump -r /tmp/p2p-chat.pcap -A 2>/dev/null | grep -c 'encrypted":true' || echo 0)

echo "Summary:"
echo "  • Unencrypted messages: $UNENC"
echo "  • Encrypted messages: $ENC"

echo ""
echo "=========================================="
echo "  DONE!"
echo "=========================================="
echo ""
echo "Capture file saved: /tmp/p2p-chat.pcap"
echo ""
echo "To view in Wireshark:"
echo "  wireshark /tmp/p2p-chat.pcap"
echo ""
echo "Filter: tcp.port == 3000 && websocket"
echo ""
