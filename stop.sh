#!/bin/bash
# Stop all services

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=========================================="
echo "  STOPPING EMAIL GATEWAY"
echo "=========================================="

if [ "$EUID" -ne 0 ]; then
    echo "ERROR: Must run as root"
    exit 1
fi

echo "Stopping processes..."
pkill -9 -f "$SCRIPT_DIR/smtp_new.py" 2>/dev/null && echo "  ✅ SMTP server stopped" || echo "  ℹ️  SMTP server not running"
pkill -9 -f "$SCRIPT_DIR/api_updated.py" 2>/dev/null && echo "  ✅ API server stopped" || echo "  ℹ️  API server not running"

echo ""
echo "All services stopped!"
echo ""
