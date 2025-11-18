#!/bin/bash
# Complete installation for BRAND NEW server (Rocky Linux 9)

set -e

echo ""
echo "=========================================="
echo "  EMAIL GATEWAY - NEW SERVER SETUP"
echo "=========================================="
echo ""

if [ "$EUID" -ne 0 ]; then
    echo "ERROR: Must run as root (use: sudo bash INSTALL_NEW_SERVER.sh)"
    exit 1
fi

INSTALL_DIR="/home/rockylinux/python_email_gateway"

echo "This will:"
echo "  1. Install all required packages"
echo "  2. Setup PostgreSQL"
echo "  3. Create database"
echo "  4. Setup SpamAssassin"
echo "  5. Install Python dependencies"
echo "  6. Start email gateway services"
echo ""
read -p "Continue? (y/n) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    exit 1
fi

echo ""
echo "[1/8] Installing system packages..."
yum install -y python3 python3-pip postgresql-server postgresql-contrib spamassassin net-tools
echo "  ✅ Done"

echo ""
echo "[2/8] Initializing PostgreSQL..."
if [ ! -d "/var/lib/pgsql/data/base" ]; then
    postgresql-setup --initdb
fi
systemctl enable postgresql
systemctl start postgresql
echo "  ✅ PostgreSQL started"

echo ""
echo "[3/8] Configuring PostgreSQL for local access..."
# Allow local connections without password
sed -i 's/ident/trust/g' /var/lib/pgsql/data/pg_hba.conf
systemctl restart postgresql
sleep 2
echo "  ✅ PostgreSQL configured"

echo ""
echo "[4/8] Creating database..."
sudo -u postgres psql << 'PSQL'
DROP DATABASE IF EXISTS email_gateway;
CREATE DATABASE email_gateway;
\c email_gateway

CREATE TABLE domains (
    id SERIAL PRIMARY KEY,
    domain_name VARCHAR(255) NOT NULL UNIQUE,
    backend_server VARCHAR(255) NOT NULL,
    backend_port INTEGER DEFAULT 25,
    spam_threshold FLOAT DEFAULT 5.0,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE emails (
    id SERIAL PRIMARY KEY,
    domain_id INTEGER REFERENCES domains(id),
    message_id VARCHAR(500),
    subject TEXT,
    from_address VARCHAR(255),
    to_address VARCHAR(255),
    sender_ip VARCHAR(45),
    body TEXT,
    status VARCHAR(50) DEFAULT 'received',
    block_reason TEXT,
    spam_score FLOAT DEFAULT 0.0,
    spam_result VARCHAR(20) DEFAULT 'pending',
    spf_result VARCHAR(20) DEFAULT 'none',
    dkim_result VARCHAR(20) DEFAULT 'none',
    dmarc_result VARCHAR(20) DEFAULT 'none',
    matched_rule_id INTEGER,
    received_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE filter_rules (
    id SERIAL PRIMARY KEY,
    rule_name VARCHAR(255) NOT NULL,
    rule_type VARCHAR(20) NOT NULL CHECK (rule_type IN ('blacklist', 'whitelist')),
    scope_type VARCHAR(20) NOT NULL CHECK (scope_type IN ('common', 'domain', 'mail_address')),
    scope_value VARCHAR(255),
    filter_field VARCHAR(20) NOT NULL CHECK (filter_field IN ('subject', 'mail_address', 'sender_domain', 'body', 'ip')),
    match_type VARCHAR(20) NOT NULL CHECK (match_type IN ('match', 'include', 'start', 'end', 'regex')),
    match_value TEXT NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    priority INTEGER DEFAULT 100,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_emails_domain_id ON emails(domain_id);
CREATE INDEX idx_emails_status ON emails(status);
CREATE INDEX idx_emails_spam_result ON emails(spam_result);
CREATE INDEX idx_emails_matched_rule ON emails(matched_rule_id);
CREATE INDEX idx_filter_rules_active ON filter_rules(is_active);
PSQL
echo "  ✅ Database created"

echo ""
echo "[5/8] Installing Python packages..."
pip3 install aiosmtpd sqlalchemy psycopg2-binary fastapi uvicorn python-multipart jinja2 pyspf dkimpy dnspython
echo "  ✅ Python packages installed"

echo ""
echo "[6/8] Setting up SpamAssassin..."
systemctl enable spamassassin
systemctl start spamassassin
echo "  ✅ SpamAssassin running"

echo ""
echo "[7/8] Disabling Postfix (if exists)..."
systemctl stop postfix 2>/dev/null || true
systemctl disable postfix 2>/dev/null || true
echo "  ✅ Port 25 available"

echo ""
echo "[8/8] Setting up firewall..."
firewall-cmd --permanent --add-port=25/tcp 2>/dev/null || true
firewall-cmd --permanent --add-port=8000/tcp 2>/dev/null || true
firewall-cmd --reload 2>/dev/null || true
echo "  ✅ Firewall configured"

echo ""
echo "=========================================="
echo "  INSTALLATION COMPLETE!"
echo "=========================================="
echo ""
echo "Server is ready!"
echo ""
echo "Next steps:"
echo "  1. Copy email gateway code to: $INSTALL_DIR"
echo "  2. cd $INSTALL_DIR"
echo "  3. sudo ./start.sh"
echo ""
echo "To add your first domain:"
echo "  curl -X POST http://localhost:8000/api/domains \\"
echo "    -H 'Content-Type: application/json' \\"
echo "    -d '{\"domain_name\":\"yourdomain.com\",\"backend_server\":\"mail.yourdomain.com\",\"backend_port\":25,\"spam_threshold\":5.0}'"
echo ""
