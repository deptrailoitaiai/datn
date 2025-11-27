#!/bin/bash

echo "🔧 P2P Chat Debug & Connection Test"
echo "=================================="

# Check if we're in the right directory
if [ ! -f "server.js" ]; then
    echo "❌ Not in p2p-chat directory"
    echo "Run: cd p2p-chat"
    exit 1
fi

echo "✅ In correct directory: $(pwd)"

# Check if Node.js is available
if ! command -v node &> /dev/null; then
    echo "❌ Node.js not found"
    exit 1
fi

echo "✅ Node.js available: $(node --version)"

# Check if dependencies are installed
if [ ! -d "node_modules" ]; then
    echo "❌ Dependencies not installed"
    echo "Run: npm install"
    exit 1
fi

echo "✅ Dependencies installed"

# Check if server is already running
if lsof -i :3000 &> /dev/null; then
    echo "⚠️  Port 3000 is already in use"
    echo "Current process using port 3000:"
    lsof -i :3000
    echo ""
    echo "To kill existing process:"
    echo "pkill -f 'node server.js'"
else
    echo "✅ Port 3000 is available"
fi

# Test server files
echo ""
echo "📁 Checking essential files:"

files=("server.js" "package.json" "public/index.html" "public/app.js" "public/style.css" "lib/encryption.js")

for file in "${files[@]}"; do
    if [ -f "$file" ]; then
        echo "✅ $file"
    else
        echo "❌ $file - MISSING!"
    fi
done

echo ""
echo "🚀 Ready to start server!"
echo "Run: node server.js"
echo ""
echo "📱 Then open TWO browser tabs:"
echo "Tab 1: http://localhost:3000"
echo "Tab 2: http://localhost:3000"
echo ""
echo "🐛 If connection issues:"
echo "1. Check browser console (F12)"
echo "2. Try different browsers"
echo "3. Refresh both tabs together"
echo "4. Clear browser cache"