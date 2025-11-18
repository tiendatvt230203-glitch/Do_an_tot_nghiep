#!/bin/bash
# Start all services from current directory

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=========================================="
echo "  STARTING EMAIL GATEWAY"
echo "=========================================="
echo "Directory: $SCRIPT_DIR"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "ERROR: Must run as root"
    exit 1
fi

# Stop old processes
echo "[1/4] Stopping old processes..."
pkill -9 -f "$SCRIPT_DIR/smtp_new.py" 2>/dev/null || true
pkill -9 -f "$SCRIPT_DIR/api_updated.py" 2>/dev/null || true
sleep 2
echo "  Done"

# Check if required files exist
echo ""
echo "[2/4] Checking files..."
if [ ! -f "smtp_new.py" ]; then
    echo "  ❌ smtp_new.py not found!"
    exit 1
fi
if [ ! -f "api_updated.py" ]; then
    echo "  ❌ api_updated.py not found!"
    exit 1
fi
echo "  ✅ All files found"

# Install dependencies
echo ""
echo "[3/4] Checking dependencies..."
pip3 install -q aiosmtpd sqlalchemy psycopg2-binary fastapi uvicorn python-multipart jinja2 spf dkimpy dnspython 2>/dev/null || true
echo "  ✅ Dependencies installed"

# Create static and templates directories
mkdir -p static templates

# Copy app.js to static
if [ -f "app.js" ]; then
    cp app.js static/
fi

# Start services
echo ""
echo "[4/4] Starting services..."

# Start SMTP server (with -u for unbuffered output)
nohup python3 -u smtp_new.py > smtp.log 2>&1 &
SMTP_PID=$!
echo "  SMTP Server: PID $SMTP_PID"

# Start API server (with -u for unbuffered output)
nohup python3 -u api_updated.py > api.log 2>&1 &
API_PID=$!
echo "  API Server: PID $API_PID"

sleep 3

echo ""
echo "=========================================="
echo "  STATUS"
echo "=========================================="

# Check if processes are running
if ps -p $SMTP_PID > /dev/null 2>&1; then
    echo "✅ SMTP Server running (PID: $SMTP_PID)"
else
    echo "❌ SMTP Server failed! Check smtp.log"
fi

if ps -p $API_PID > /dev/null 2>&1; then
    echo "✅ API Server running (PID: $API_PID)"
else
    echo "❌ API Server failed! Check api.log"
fi

echo ""
echo "Logs:"
echo "  SMTP: tail -f $SCRIPT_DIR/smtp.log"
echo "  API:  tail -f $SCRIPT_DIR/api.log"
echo ""
echo "Ports:"
ss -tlnp | grep ":25 " || echo "  Port 25: Not listening yet..."
ss -tlnp | grep ":8000 " || echo "  Port 8000: Not listening yet..."
echo ""
echo "To stop: ./stop.sh"
echo ""
