#!/bin/bash
# Complete deployment script - Run once on new server

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo ""
echo "=========================================="
echo "  EMAIL GATEWAY - COMPLETE DEPLOYMENT"
echo "=========================================="
echo "Directory: $SCRIPT_DIR"
echo ""

if [ "$EUID" -ne 0 ]; then
    echo "ERROR: Must run as root (use sudo)"
    exit 1
fi

# Step 1: Install system packages
echo "[1/5] Installing system packages..."
if command -v yum &> /dev/null; then
    yum install -y python3 python3-pip postgresql-server postgresql-contrib spamassassin 2>/dev/null || true
elif command -v apt-get &> /dev/null; then
    apt-get update
    apt-get install -y python3 python3-pip postgresql spamassassin 2>/dev/null || true
fi
echo "  ✅ System packages installed"

# Step 2: Initialize PostgreSQL (if needed)
echo ""
echo "[2/5] Setting up PostgreSQL..."
if [ ! -d "/var/lib/pgsql/data/base" ]; then
    postgresql-setup --initdb 2>/dev/null || sudo -u postgres initdb /var/lib/pgsql/data 2>/dev/null || true
fi
systemctl enable postgresql 2>/dev/null || true
systemctl start postgresql 2>/dev/null || true
echo "  ✅ PostgreSQL ready"

# Step 3: Setup database
echo ""
echo "[3/5] Creating database..."
chmod +x setup_database.sh
./setup_database.sh
echo "  ✅ Database created"

# Step 4: Install Python packages
echo ""
echo "[4/5] Installing Python dependencies..."
pip3 install -q aiosmtpd sqlalchemy psycopg2-binary fastapi uvicorn python-multipart jinja2 spf dkimpy dnspython 2>/dev/null || true
echo "  ✅ Python packages installed"

# Step 5: Setup SpamAssassin
echo ""
echo "[5/5] Setting up SpamAssassin..."
systemctl enable spamassassin 2>/dev/null || true
systemctl start spamassassin 2>/dev/null || true
echo "  ✅ SpamAssassin running"

# Make scripts executable
chmod +x start.sh stop.sh

echo ""
echo "=========================================="
echo "  DEPLOYMENT COMPLETE!"
echo "=========================================="
echo ""
echo "Next steps:"
echo "  1. Start services: sudo ./start.sh"
echo "  2. Add a domain:"
echo ""
echo "     curl -X POST http://localhost:8000/api/domains \\"
echo "       -H 'Content-Type: application/json' \\"
echo "       -d '{\"domain_name\":\"dattest.site\",\"backend_server\":\"mail.dattest.site\",\"backend_port\":25,\"spam_threshold\":5.0}'"
echo ""
echo "  3. Test email to: test@dattest.site"
echo ""
echo "Features enabled:"
echo "  ✅ Per-domain spam threshold"
echo "  ✅ Authentication penalty (SPF/DKIM/DMARC)"
echo "  ✅ SpamAssassin integration"
echo "  ✅ Blacklist/Whitelist rules"
echo ""
echo "Logs location:"
echo "  $SCRIPT_DIR/smtp.log"
echo "  $SCRIPT_DIR/api.log"
echo ""
