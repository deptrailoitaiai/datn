#!/bin/bash

echo "======================================"
echo "  P2P Chat - Wireshark Demo"
echo "======================================"
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Cleanup function
cleanup() {
    echo -e "\n${YELLOW}Đang dọn dẹp...${NC}"
    sudo pkill -9 tcpdump 2>/dev/null
    pkill -9 node 2>/dev/null
    exit 0
}

trap cleanup SIGINT SIGTERM

# Step 1: Start server
echo -e "${BLUE}Bước 1: Khởi động server...${NC}"
cd /home/tienminh/dotienminh/whereIBeatTheWorld/datn/demo/p2p-chat
node server.js > /tmp/server.log 2>&1 &
SERVER_PID=$!
sleep 3

# Check server
if curl -s http://localhost:3000 > /dev/null; then
    echo -e "${GREEN}✓ Server đang chạy (PID: $SERVER_PID)${NC}"
else
    echo -e "${RED}✗ Server không khởi động được!${NC}"
    cat /tmp/server.log
    exit 1
fi

# Step 2: Start tcpdump
echo -e "\n${BLUE}Bước 2: Bắt đầu capture gói tin...${NC}"
sudo tcpdump -i lo -w /tmp/p2p-chat-capture.pcap "tcp port 3000" > /dev/null 2>&1 &
TCPDUMP_PID=$!
sleep 2

if ps -p $TCPDUMP_PID > /dev/null; then
    echo -e "${GREEN}✓ tcpdump đang capture (PID: $TCPDUMP_PID)${NC}"
else
    echo -e "${RED}✗ tcpdump không chạy được!${NC}"
    kill $SERVER_PID 2>/dev/null
    exit 1
fi

# Step 3: Instructions
echo -e "\n${GREEN}======================================"
echo "  SẴN SÀNG TEST!"
echo "======================================${NC}"
echo ""
echo -e "${YELLOW}Hãy làm theo các bước sau:${NC}"
echo ""
echo -e "${BLUE}1. Mở 2 trình duyệt:${NC}"
echo "   • Browser 1: http://localhost:3000"
echo "   • Browser 2: http://localhost:3000 (chế độ ẩn danh hoặc browser khác)"
echo ""
echo -e "${BLUE}2. Đăng ký/Đăng nhập với 2 tài khoản khác nhau${NC}"
echo ""
echo -e "${RED}3. TEST KHÔNG MÃ HÓA:${NC}"
echo "   • Tắt toggle 'Enable Encryption' ở CẢ 2 clients (OFF)"
echo "   • Gửi tin nhắn:"
echo "     - 'Hello this is a test message'"
echo "     - 'My password is 123456'"
echo "     - 'Secret data ABC'"
echo ""
echo -e "${GREEN}4. TEST CÓ MÃ HÓA:${NC}"
echo "   • Bật toggle 'Enable Encryption' ở CẢ 2 clients (ON)"
echo "   • Đợi thông báo 'Secure channel established! 🔒'"
echo "   • Gửi lại CÙNG các tin nhắn trên"
echo ""
echo -e "${YELLOW}5. Khi xong, nhấn Ctrl+C ở đây để dừng và phân tích${NC}"
echo ""

# Wait for user
read -p "Nhấn Enter khi bạn đã GỬI XONG TẤT CẢ TIN NHẮN..."

# Stop capture
echo -e "\n${BLUE}Đang dừng capture...${NC}"
sudo pkill -SIGINT tcpdump
sleep 2

# Stop server
kill $SERVER_PID 2>/dev/null
echo -e "${GREEN}✓ Đã dừng server${NC}"

# Step 4: Analyze
echo -e "\n${BLUE}======================================"
echo "  PHÂN TÍCH GÓI TIN"
echo "======================================${NC}"
echo ""

# Check if capture file exists
if [ ! -f /tmp/p2p-chat-capture.pcap ]; then
    echo -e "${RED}✗ Không tìm thấy file capture!${NC}"
    exit 1
fi

PACKETS=$(sudo tcpdump -r /tmp/p2p-chat-capture.pcap 2>/dev/null | wc -l)
echo -e "${GREEN}✓ Đã bắt được: $PACKETS packets${NC}"
echo ""

# Extract WebSocket data
echo -e "${YELLOW}Đang phân tích WebSocket messages...${NC}"
echo ""

# Use tshark if available, otherwise suggest manual analysis
if command -v tshark &> /dev/null; then
    echo -e "${BLUE}─── TIN NHẮN KHÔNG MÃ HÓA (có thể đọc được) ───${NC}"
    sudo tshark -r /tmp/p2p-chat-capture.pcap -Y 'websocket.payload contains "encrypted\":false"' -T fields -e websocket.payload 2>/dev/null | head -10
    
    echo -e "\n${BLUE}─── TIN NHẮN CÓ MÃ HÓA (không đọc được) ───${NC}"
    sudo tshark -r /tmp/p2p-chat-capture.pcap -Y 'websocket.payload contains "encrypted\":true"' -T fields -e websocket.payload 2>/dev/null | head -10
else
    echo -e "${YELLOW}Cài tshark để phân tích chi tiết: sudo apt-get install tshark${NC}"
    echo ""
    echo -e "${BLUE}Hoặc mở file capture bằng Wireshark GUI:${NC}"
    echo "  wireshark /tmp/p2p-chat-capture.pcap"
fi

echo ""
echo -e "${GREEN}======================================"
echo "  HOÀN THÀNH!"
echo "======================================${NC}"
echo ""
echo "File capture được lưu tại: /tmp/p2p-chat-capture.pcap"
echo ""
echo -e "${BLUE}Để xem chi tiết:${NC}"
echo "  • Wireshark GUI: wireshark /tmp/p2p-chat-capture.pcap"
echo "  • Filter trong Wireshark: tcp.port == 3000 && websocket"
echo ""
