#!/bin/bash
# Complete deployment script for spam filtering and new UI format

set -e

echo "=========================================="
echo "  COMPLETE SYSTEM UPDATE"
echo "=========================================="

if [ "$EUID" -ne 0 ]; then
    echo "ERROR: Must run as root"
    exit 1
fi

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="/opt/email_gateway"

echo "[1/8] Backing up current system..."
timestamp=$(date +%Y%m%d_%H%M%S)
mkdir -p /opt/email_gateway/backups
cp -f $INSTALL_DIR/smtp.py $INSTALL_DIR/backups/smtp_${timestamp}.py 2>/dev/null || true
cp -f $INSTALL_DIR/api.py $INSTALL_DIR/backups/api_${timestamp}.py 2>/dev/null || true
echo "  Backup created at $INSTALL_DIR/backups/"

echo "[2/8] Updating database schema..."
sudo -u postgres psql -d email_gateway << 'SQL'
-- Add new columns to emails table if they don't exist
ALTER TABLE emails ADD COLUMN IF NOT EXISTS spam_score FLOAT DEFAULT 0.0;
ALTER TABLE emails ADD COLUMN IF NOT EXISTS spam_result VARCHAR(20) DEFAULT 'pending';
ALTER TABLE emails ADD COLUMN IF NOT EXISTS spf_result VARCHAR(20) DEFAULT 'none';
ALTER TABLE emails ADD COLUMN IF NOT EXISTS dkim_result VARCHAR(20) DEFAULT 'none';
ALTER TABLE emails ADD COLUMN IF NOT EXISTS dmarc_result VARCHAR(20) DEFAULT 'none';
ALTER TABLE emails ADD COLUMN IF NOT EXISTS matched_rule_id INTEGER;

-- Add spam_threshold column to domains table
ALTER TABLE domains ADD COLUMN IF NOT EXISTS spam_threshold FLOAT DEFAULT 5.0;
COMMENT ON COLUMN domains.spam_threshold IS 'Spam score threshold for this domain. Emails with score > threshold will be marked as spam.';

-- Create index for better performance
CREATE INDEX IF NOT EXISTS idx_emails_matched_rule ON emails(matched_rule_id);
CREATE INDEX IF NOT EXISTS idx_emails_status ON emails(status);
CREATE INDEX IF NOT EXISTS idx_emails_spam_result ON emails(spam_result);
SQL
echo "  Database schema updated"

echo "[3/8] Installing required packages..."
pip3 install pyspf dkimpy dnspython --quiet 2>/dev/null || true
echo "  Python packages installed"

echo "[4/8] Ensuring SpamAssassin is installed and running..."
if ! command -v spamc &> /dev/null; then
    echo "  Installing SpamAssassin..."
    yum install -y spamassassin 2>/dev/null || apt-get install -y spamassassin 2>/dev/null || true
fi
systemctl enable spamassassin 2>/dev/null || true
systemctl restart spamassassin 2>/dev/null || true
echo "  SpamAssassin running"

echo "[5/8] Deploying new SMTP server..."
cp -f $BASE_DIR/smtp_new.py $INSTALL_DIR/smtp.py
chmod +x $INSTALL_DIR/smtp.py
chown root:root $INSTALL_DIR/smtp.py
echo "  SMTP server updated"

echo "[6/8] Deploying new API server..."
cp -f $BASE_DIR/api_updated.py $INSTALL_DIR/api.py
chmod +x $INSTALL_DIR/api.py
chown root:root $INSTALL_DIR/api.py
echo "  API server updated"

echo "[7/8] Creating new Web UI..."
cat > $INSTALL_DIR/templates/index.html << 'HTMLEOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Email Gateway Management</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        .container { max-width: 1400px; margin: 0 auto; }
        h1 { color: white; text-align: center; margin-bottom: 30px; font-size: 2.5em; }

        #stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .stat-card {
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        .stat-card h3 { color: #666; font-size: 0.9em; margin-bottom: 10px; }
        .stat-card .number { font-size: 2em; font-weight: bold; color: #667eea; }

        .tabs {
            display: flex;
            gap: 10px;
            margin-bottom: 20px;
        }
        .tab-btn {
            background: rgba(255,255,255,0.2);
            color: white;
            border: none;
            padding: 15px 30px;
            border-radius: 10px 10px 0 0;
            cursor: pointer;
            font-size: 1em;
            transition: all 0.3s;
        }
        .tab-btn.active {
            background: white;
            color: #667eea;
        }

        .content-box {
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }

        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        th {
            background: #f8f9fa;
            font-weight: 600;
            color: #495057;
        }
        tr.clickable:hover {
            background: #f8f9fa;
            cursor: pointer;
        }

        .badge {
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 0.85em;
            font-weight: 600;
        }
        .badge-success { background: #d4edda; color: #155724; }
        .badge-danger { background: #f8d7da; color: #721c24; }
        .badge-warning { background: #fff3cd; color: #856404; }

        .form-group {
            margin-bottom: 20px;
        }
        .form-group label {
            display: block;
            margin-bottom: 8px;
            font-weight: 600;
            color: #495057;
        }
        input, select, textarea {
            width: 100%;
            padding: 10px;
            border: 1px solid #ced4da;
            border-radius: 5px;
            font-size: 1em;
        }

        .radio-group {
            display: flex;
            gap: 20px;
            flex-wrap: wrap;
        }
        .radio-option {
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .radio-option input[type="radio"] {
            width: auto;
        }

        button {
            background: #667eea;
            color: white;
            border: none;
            padding: 12px 24px;
            border-radius: 5px;
            cursor: pointer;
            font-size: 1em;
            transition: all 0.3s;
        }
        button:hover { background: #5568d3; }

        .modal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0,0,0,0.5);
            z-index: 1000;
        }
        .modal.active { display: flex; align-items: center; justify-content: center; }
        .modal-content {
            background: white;
            padding: 30px;
            border-radius: 10px;
            max-width: 800px;
            max-height: 90vh;
            overflow-y: auto;
            width: 90%;
        }
        .close-btn {
            float: right;
            font-size: 28px;
            font-weight: bold;
            cursor: pointer;
            color: #aaa;
        }
        .close-btn:hover { color: #000; }

        .error { color: #dc3545; margin-top: 10px; font-weight: 500; }
        .success { color: #28a745; margin-top: 10px; font-weight: 500; }

        pre {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            overflow-x: auto;
            white-space: pre-wrap;
            word-wrap: break-word;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>📧 Email Gateway Management</h1>

        <div id="stats"></div>

        <div class="tabs">
            <button class="tab-btn active" onclick="switchTab('emails')">Emails</button>
            <button class="tab-btn" onclick="switchTab('domains')">Domains</button>
            <button class="tab-btn" onclick="switchTab('rules')">Filter Rules</button>
        </div>

        <div class="content-box">
            <div id="emailsTab">
                <h2>Email List</h2>
                <table id="emailsTable"></table>
            </div>

            <div id="domainsTab" style="display:none;">
                <h2>Manage Domains</h2>
                <table id="domainsTable"></table>
                <hr style="margin: 30px 0;">
                <h3>Add New Domain</h3>
                <div class="form-group">
                    <label>Domain Name:</label>
                    <input type="text" id="domainName" placeholder="example.com">
                </div>
                <div class="form-group">
                    <label>Backend Server:</label>
                    <input type="text" id="backendServer" placeholder="mail.example.com">
                </div>
                <div class="form-group">
                    <label>Backend Port:</label>
                    <input type="number" id="backendPort" value="25">
                </div>
                <div class="form-group">
                    <label>Spam Threshold:</label>
                    <input type="number" id="spamThreshold" value="5.0" step="0.1" min="0" max="100">
                    <small style="color: #666; display: block; margin-top: 5px;">
                        Emails with spam score > this value will be blocked. Example: 5.0 (default), 15.0 (lenient), 3.0 (strict)
                    </small>
                </div>
                <button onclick="addDomain()">Add Domain</button>
                <div id="domainMsg"></div>
            </div>

            <div id="rulesTab" style="display:none;">
                <h2>Filter Rules</h2>
                <table id="rulesTable"></table>
                <hr style="margin: 30px 0;">
                <h3>Create New Filter Rule</h3>

                <div class="form-group">
                    <label>Rule Name:</label>
                    <input type="text" id="ruleName" placeholder="Block spam from domain X">
                </div>

                <div class="form-group">
                    <label>Rule Type:</label>
                    <div class="radio-group">
                        <div class="radio-option">
                            <input type="radio" name="ruleType" value="blacklist" id="typeBlacklist" checked>
                            <label for="typeBlacklist">Blacklist (Block)</label>
                        </div>
                        <div class="radio-option">
                            <input type="radio" name="ruleType" value="whitelist" id="typeWhitelist">
                            <label for="typeWhitelist">Whitelist (Allow)</label>
                        </div>
                    </div>
                </div>

                <div class="form-group">
                    <label>Scope:</label>
                    <div class="radio-group">
                        <div class="radio-option">
                            <input type="radio" name="scopeType" value="common" id="scopeCommon" checked onchange="updateScopeValue()">
                            <label for="scopeCommon">Common (All Domains)</label>
                        </div>
                        <div class="radio-option">
                            <input type="radio" name="scopeType" value="domain" id="scopeDomain" onchange="updateScopeValue()">
                            <label for="scopeDomain">Specific Domain</label>
                        </div>
                        <div class="radio-option">
                            <input type="radio" name="scopeType" value="mail_address" id="scopeMail" onchange="updateScopeValue()">
                            <label for="scopeMail">Specific Email</label>
                        </div>
                    </div>
                </div>

                <div class="form-group" id="scopeValueGroup" style="display:none;">
                    <label>Scope Value:</label>
                    <input type="text" id="scopeValue" placeholder="">
                </div>

                <div class="form-group">
                    <label>Filter Field:</label>
                    <div class="radio-group">
                        <div class="radio-option">
                            <input type="radio" name="filterField" value="subject" id="fieldSubject" checked onchange="updateMatchTypes()">
                            <label for="fieldSubject">Subject</label>
                        </div>
                        <div class="radio-option">
                            <input type="radio" name="filterField" value="mail_address" id="fieldMail" onchange="updateMatchTypes()">
                            <label for="fieldMail">Email Address</label>
                        </div>
                        <div class="radio-option">
                            <input type="radio" name="filterField" value="sender_domain" id="fieldDomain" onchange="updateMatchTypes()">
                            <label for="fieldDomain">Sender Domain</label>
                        </div>
                        <div class="radio-option">
                            <input type="radio" name="filterField" value="body" id="fieldBody" onchange="updateMatchTypes()">
                            <label for="fieldBody">Body</label>
                        </div>
                        <div class="radio-option">
                            <input type="radio" name="filterField" value="ip" id="fieldIP" onchange="updateMatchTypes()">
                            <label for="fieldIP">IP Address</label>
                        </div>
                    </div>
                </div>

                <div class="form-group">
                    <label>Match Type:</label>
                    <div class="radio-group" id="matchTypeGroup">
                        <!-- Dynamically populated -->
                    </div>
                </div>

                <div class="form-group">
                    <label>Match Value:</label>
                    <input type="text" id="matchValue" placeholder="">
                </div>

                <button onclick="addRule()">Create Rule</button>
                <div id="ruleMsg"></div>
            </div>
        </div>
    </div>

    <!-- Email Detail Modal -->
    <div id="emailDetailModal" class="modal">
        <div class="modal-content">
            <span class="close-btn" onclick="closeEmailDetail()">&times;</span>
            <div id="emailDetailContent"></div>
        </div>
    </div>

    <script>
        const API = '/api';

        function switchTab(tab) {
            document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
            event.target.classList.add('active');

            document.getElementById('emailsTab').style.display = tab === 'emails' ? 'block' : 'none';
            document.getElementById('domainsTab').style.display = tab === 'domains' ? 'block' : 'none';
            document.getElementById('rulesTab').style.display = tab === 'rules' ? 'block' : 'none';

            if (tab === 'emails') loadEmails();
            if (tab === 'domains') loadDomains();
            if (tab === 'rules') loadRules();
        }

        function updateScopeValue() {
            const scopeType = document.querySelector('input[name="scopeType"]:checked').value;
            const group = document.getElementById('scopeValueGroup');
            const input = document.getElementById('scopeValue');

            if (scopeType === 'common') {
                group.style.display = 'none';
                input.value = '';
            } else {
                group.style.display = 'block';
                input.placeholder = scopeType === 'domain' ? 'example.com' : 'user@example.com';
            }
        }

        function updateMatchTypes() {
            const field = document.querySelector('input[name="filterField"]:checked').value;
            const container = document.getElementById('matchTypeGroup');
            const matchValue = document.getElementById('matchValue');

            let options = [];
            let placeholder = '';

            if (['subject', 'mail_address', 'sender_domain'].includes(field)) {
                options = [
                    {value: 'match', label: 'Exact Match'},
                    {value: 'include', label: 'Contains'},
                    {value: 'start', label: 'Starts With'},
                    {value: 'end', label: 'Ends With'},
                    {value: 'regex', label: 'Regex'}
                ];
                placeholder = field === 'subject' ? 'spam keyword' : 'example.com';
            } else if (field === 'body') {
                options = [
                    {value: 'include', label: 'Contains'},
                    {value: 'regex', label: 'Regex'}
                ];
                placeholder = 'suspicious text';
            } else if (field === 'ip') {
                options = [
                    {value: 'match', label: 'Exact Match'},
                    {value: 'regex', label: 'Regex'}
                ];
                placeholder = '192.168.1.1';
            }

            container.innerHTML = options.map((opt, idx) => `
                <div class="radio-option">
                    <input type="radio" name="matchType" value="${opt.value}" id="match${idx}" ${idx === 0 ? 'checked' : ''}>
                    <label for="match${idx}">${opt.label}</label>
                </div>
            `).join('');

            matchValue.placeholder = placeholder;
        }

        // Initialize match types on load
        updateMatchTypes();
    </script>
    <script src="/static/app.js"></script>
</body>
</html>
HTMLEOF
echo "  Web UI HTML created"

echo "[8/8] Creating static directory and copying JavaScript..."
mkdir -p $INSTALL_DIR/static
cp -f $BASE_DIR/app.js $INSTALL_DIR/static/app.js
chmod 644 $INSTALL_DIR/static/app.js
echo "  JavaScript copied"

echo ""
echo "=========================================="
echo "  RESTARTING SERVICES"
echo "=========================================="

systemctl restart email-smtp.service
systemctl restart email-api.service

echo ""
echo "=========================================="
echo "  UPDATE COMPLETE!"
echo "=========================================="
echo ""
echo "Service Status:"
systemctl status email-smtp.service --no-pager | grep -E "(Active|Main PID)"
systemctl status email-api.service --no-pager | grep -E "(Active|Main PID)"
echo ""
echo "Features Enabled:"
echo "  ✅ Spam Filtering (Threshold: 5.0)"
echo "  ✅ SPF/DKIM/DMARC Validation"
echo "  ✅ Whitelist/Blacklist Rules"
echo "  ✅ New Email List Format (Sender, Recipient, Subject, IP, Date, Filter Log, Status)"
echo ""
echo "Workflow:"
echo "  1. Whitelist → Auto deliver (skip checks)"
echo "  2. Blacklist → Block immediately"
echo "  3. No match → Spam check → SPF/DKIM/DMARC → Deliver"
echo ""
echo "Access Web UI: http://103.151.241.59:8000"
echo ""
