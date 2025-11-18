// Complete Web UI JavaScript for Email Gateway

const API = '/api';

// Load statistics
async function loadStats() {
    const res = await fetch(`${API}/stats`);
    const data = await res.json();
    document.getElementById('stats').innerHTML = `
        <div class="stat-card">
            <h3>Total Emails</h3>
            <div class="number">${data.total_emails}</div>
        </div>
        <div class="stat-card">
            <h3>Delivered</h3>
            <div class="number" style="color:#28a745">${data.delivered_emails}</div>
        </div>
        <div class="stat-card">
            <h3>Blocked</h3>
            <div class="number" style="color:#dc3545">${data.blocked_emails}</div>
        </div>
        <div class="stat-card">
            <h3>Spam</h3>
            <div class="number" style="color:#ffc107">${data.spam_emails}</div>
        </div>
        <div class="stat-card">
            <h3>Active Rules</h3>
            <div class="number">${data.total_rules}</div>
        </div>
    `;
}

// Load emails with new format
async function loadEmails() {
    const res = await fetch(`${API}/emails`);
    const data = await res.json();
    const table = document.getElementById('emailsTable');

    // New header format
    table.innerHTML = `<tr>
        <th>Sender</th>
        <th>Recipient</th>
        <th>Subject</th>
        <th>Sender IP</th>
        <th>Date</th>
        <th>Filter Log</th>
        <th>Status</th>
    </tr>`;

    data.emails.forEach(e => {
        // Format date
        const date = new Date(e.received_at).toLocaleString('en-US', {
            year: 'numeric',
            month: '2-digit',
            day: '2-digit',
            hour: '2-digit',
            minute: '2-digit',
            hour12: false
        }).replace(',', '');

        // Color-code filter log
        let filterBadge = '';
        if (e.filter_log === 'Whitelist') {
            filterBadge = `<span class="badge badge-success">${e.filter_log}</span>`;
        } else if (e.filter_log === 'Blacklist') {
            filterBadge = `<span class="badge badge-danger">${e.filter_log}</span>`;
        } else if (e.filter_log === 'Spam') {
            filterBadge = `<span class="badge badge-warning">${e.filter_log}</span>`;
        } else if (e.filter_log === 'Safe') {
            filterBadge = `<span class="badge badge-success">${e.filter_log}</span>`;
        } else {
            filterBadge = `<span>${e.filter_log}</span>`;
        }

        // Color-code delivery status
        let statusBadge = '';
        if (e.delivery_status === 'Delivered') {
            statusBadge = `<span class="badge badge-success">${e.delivery_status}</span>`;
        } else {
            statusBadge = `<span class="badge badge-danger">${e.delivery_status}</span>`;
        }

        table.innerHTML += `<tr class="clickable" onclick="showEmailDetail(${e.id})">
            <td>${e.from}</td>
            <td>${e.to}</td>
            <td>${e.subject || '(No subject)'}</td>
            <td>${e.sender_ip || 'N/A'}</td>
            <td>${date}</td>
            <td>${filterBadge}</td>
            <td>${statusBadge}</td>
        </tr>`;
    });
}

// Show email detail modal
async function showEmailDetail(emailId) {
    const res = await fetch(`${API}/emails/${emailId}`);
    const email = await res.json();

    let statusColor = 'warning';
    if (email.delivery_status === 'Delivered') statusColor = 'success';
    if (email.delivery_status === 'Undelivered') statusColor = 'danger';

    const content = `
        <div class="email-detail">
            <h3>${email.subject || '(No subject)'}</h3>

            <div style="display: flex; gap: 20px; margin: 15px 0;">
                <div><strong>Filter Result:</strong> <span class="badge badge-${email.filter_log === 'Whitelist' || email.filter_log === 'Safe' ? 'success' : 'danger'}">${email.filter_log}</span></div>
                <div><strong>Delivery Status:</strong> <span class="badge badge-${statusColor}">${email.delivery_status}</span></div>
            </div>

            ${email.block_reason ? `<p style="color: #dc3545; background: #ffe6e6; padding: 10px; border-radius: 5px;"><strong>Block Reason:</strong> ${email.block_reason}</p>` : ''}

            <hr>

            <p><strong>From:</strong> ${email.from}</p>
            <p><strong>To:</strong> ${email.to}</p>
            <p><strong>Domain:</strong> ${email.domain}</p>
            <p><strong>Sender IP:</strong> ${email.sender_ip}</p>
            <p><strong>Received At:</strong> ${new Date(email.received_at).toLocaleString()}</p>

            <hr>

            <p><strong>Security Checks:</strong></p>
            <table style="width: 100%; margin-top: 10px;">
                <tr style="background: #f8f9fa;">
                    <th style="padding: 10px; text-align: left; width: 30%;">Check</th>
                    <th style="padding: 10px; text-align: left;">Result</th>
                </tr>
                <tr>
                    <td style="padding: 10px;"><strong>Blacklist/Whitelist</strong></td>
                    <td style="padding: 10px;">
                        ${email.filter_log === 'Whitelist' ? '✅ <span style="color: #28a745;">Whitelisted</span>' :
                          email.filter_log === 'Blacklist' ? '🚫 <span style="color: #dc3545;">Blacklisted</span>' :
                          '➡️ No match (continue to spam check)'}
                    </td>
                </tr>
                <tr style="background: #f8f9fa;">
                    <td style="padding: 10px;"><strong>Spam Filter</strong></td>
                    <td style="padding: 10px;">
                        ${email.spam_result === 'skipped' ? '⏭️ Skipped (whitelisted/blacklisted)' :
                          email.spam_result === 'spam' ? `🚫 <span style="color: #dc3545;">SPAM (Score: ${email.spam_score.toFixed(2)})</span>` :
                          email.spam_result === 'safe' ? `✅ <span style="color: #28a745;">SAFE (Score: ${email.spam_score.toFixed(2)})</span>` :
                          '⏳ Pending'}
                    </td>
                </tr>
                <tr>
                    <td style="padding: 10px;"><strong>SPF</strong></td>
                    <td style="padding: 10px;">
                        ${email.spf_result === 'pass' ? '✅ Pass' :
                          email.spf_result === 'fail' ? '❌ Fail' :
                          email.spf_result === 'softfail' ? '⚠️ Soft Fail' :
                          email.spf_result === 'neutral' ? '🔵 Neutral' :
                          '➖ None'}
                    </td>
                </tr>
                <tr style="background: #f8f9fa;">
                    <td style="padding: 10px;"><strong>DKIM</strong></td>
                    <td style="padding: 10px;">
                        ${email.dkim_result === 'pass' ? '✅ Pass' :
                          email.dkim_result === 'fail' ? '❌ Fail' :
                          '➖ None'}
                    </td>
                </tr>
                <tr>
                    <td style="padding: 10px;"><strong>DMARC</strong></td>
                    <td style="padding: 10px;">
                        ${email.dmarc_result === 'reject' ? '🚫 Reject Policy' :
                          email.dmarc_result === 'quarantine' ? '⚠️ Quarantine Policy' :
                          '➖ None'}
                    </td>
                </tr>
            </table>

            <hr>

            <p><strong>Email Body:</strong></p>
            <pre>${email.body || '(No body content)'}</pre>
        </div>
    `;

    document.getElementById('emailDetailContent').innerHTML = content;
    document.getElementById('emailDetailModal').classList.add('active');
}

function closeEmailDetail() {
    document.getElementById('emailDetailModal').classList.remove('active');
}

// Load domains
async function loadDomains() {
    const res = await fetch(`${API}/domains`);
    const data = await res.json();
    const table = document.getElementById('domainsTable');

    table.innerHTML = `<tr>
        <th>ID</th>
        <th>Domain</th>
        <th>Backend Server</th>
        <th>Port</th>
        <th>Spam Threshold</th>
        <th>Status</th>
        <th>Actions</th>
    </tr>`;

    data.domains.forEach(d => {
        table.innerHTML += `<tr>
            <td>${d.id}</td>
            <td><strong>${d.domain_name}</strong></td>
            <td>${d.backend_server}</td>
            <td>${d.backend_port}</td>
            <td>
                <input type="number" id="threshold_${d.id}" value="${d.spam_threshold}" step="0.1" min="0" max="100" style="width: 70px; padding: 5px;">
                <button onclick="updateSpamThreshold(${d.id})" style="background:#28a745; font-size: 0.85em; padding: 6px 12px; margin-left: 5px;">Update</button>
            </td>
            <td><span class="badge badge-${d.is_active ? 'success' : 'danger'}">${d.is_active ? 'Active' : 'Inactive'}</span></td>
            <td><button onclick="deleteDomain(${d.id}, '${d.domain_name}')" style="background:#dc3545;">Delete</button></td>
        </tr>`;
    });
}

async function addDomain() {
    const domain_name = document.getElementById('domainName').value.trim();
    const backend_server = document.getElementById('backendServer').value.trim();
    const backend_port = parseInt(document.getElementById('backendPort').value);
    const spam_threshold = parseFloat(document.getElementById('spamThreshold').value);

    const msg = document.getElementById('domainMsg');

    if (!domain_name || !backend_server || !backend_port) {
        msg.innerHTML = '<p class="error">All fields are required</p>';
        return;
    }

    try {
        const res = await fetch(`${API}/domains`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({domain_name, backend_server, backend_port, spam_threshold})
        });

        if (res.ok) {
            msg.innerHTML = '<p class="success">Domain added successfully!</p>';
            document.getElementById('domainName').value = '';
            document.getElementById('backendServer').value = '';
            document.getElementById('backendPort').value = '25';
            document.getElementById('spamThreshold').value = '5.0';
            loadDomains();
            loadStats();
        } else {
            const err = await res.json();
            msg.innerHTML = `<p class="error">${err.detail}</p>`;
        }
    } catch (e) {
        msg.innerHTML = `<p class="error">Error: ${e.message}</p>`;
    }
}

async function updateSpamThreshold(domainId) {
    const spam_threshold = parseFloat(document.getElementById(`threshold_${domainId}`).value);

    if (isNaN(spam_threshold) || spam_threshold < 0) {
        alert('Invalid spam threshold value');
        return;
    }

    try {
        const res = await fetch(`${API}/domains/${domainId}`, {
            method: 'PATCH',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({spam_threshold})
        });

        if (res.ok) {
            alert(`Spam threshold updated to ${spam_threshold}`);
            loadDomains();
        } else {
            const err = await res.json();
            alert(`Error: ${err.detail}`);
        }
    } catch (e) {
        alert(`Error: ${e.message}`);
    }
}

async function deleteDomain(id, name) {
    if (!confirm(`Delete domain "${name}"?`)) return;

    try {
        const res = await fetch(`${API}/domains/${id}`, {method: 'DELETE'});
        if (res.ok) {
            loadDomains();
            loadStats();
        } else {
            const err = await res.json();
            alert(`Error: ${err.detail}`);
        }
    } catch (e) {
        alert(`Error: ${e.message}`);
    }
}

// Load filter rules
async function loadRules() {
    const res = await fetch(`${API}/rules`);
    const data = await res.json();
    const table = document.getElementById('rulesTable');

    table.innerHTML = `<tr>
        <th>ID</th>
        <th>Name</th>
        <th>Type</th>
        <th>Scope</th>
        <th>Filter</th>
        <th>Match</th>
        <th>Value</th>
        <th>Priority</th>
        <th>Status</th>
        <th>Actions</th>
    </tr>`;

    data.rules.forEach(r => {
        const scope = r.scope_value ? `${r.scope_type}:${r.scope_value}` : r.scope_type;
        table.innerHTML += `<tr>
            <td>${r.id}</td>
            <td><strong>${r.rule_name}</strong></td>
            <td><span class="badge badge-${r.rule_type === 'whitelist' ? 'success' : 'danger'}">${r.rule_type}</span></td>
            <td>${scope}</td>
            <td>${r.filter_field}</td>
            <td>${r.match_type}</td>
            <td style="max-width: 200px; overflow: hidden; text-overflow: ellipsis;">${r.match_value}</td>
            <td>${r.priority}</td>
            <td><span class="badge badge-${r.is_active ? 'success' : 'danger'}">${r.is_active ? 'Active' : 'Inactive'}</span></td>
            <td>
                <button onclick="toggleRule(${r.id})" style="background:#ffc107; font-size: 0.85em; padding: 6px 12px;">Toggle</button>
                <button onclick="deleteRule(${r.id}, '${r.rule_name}')" style="background:#dc3545; font-size: 0.85em; padding: 6px 12px;">Delete</button>
            </td>
        </tr>`;
    });
}

async function addRule() {
    const msg = document.getElementById('ruleMsg');

    const rule_name = document.getElementById('ruleName').value.trim();
    const rule_type = document.querySelector('input[name="ruleType"]:checked').value;
    const scope_type = document.querySelector('input[name="scopeType"]:checked').value;
    const scope_value = scope_type === 'common' ? null : document.getElementById('scopeValue').value.trim();
    const filter_field = document.querySelector('input[name="filterField"]:checked').value;
    const match_type = document.querySelector('input[name="matchType"]:checked').value;
    const match_value = document.getElementById('matchValue').value.trim();

    if (!rule_name || !match_value) {
        msg.innerHTML = '<p class="error">Rule name and match value are required</p>';
        return;
    }

    if (scope_type !== 'common' && !scope_value) {
        msg.innerHTML = '<p class="error">Scope value is required for domain/email scope</p>';
        return;
    }

    try {
        const res = await fetch(`${API}/rules`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                rule_name,
                rule_type,
                scope_type,
                scope_value,
                filter_field,
                match_type,
                match_value,
                priority: 100
            })
        });

        if (res.ok) {
            msg.innerHTML = '<p class="success">Rule created successfully!</p>';
            document.getElementById('ruleName').value = '';
            document.getElementById('matchValue').value = '';
            loadRules();
            loadStats();
        } else {
            const err = await res.json();
            msg.innerHTML = `<p class="error">${err.detail}</p>`;
        }
    } catch (e) {
        msg.innerHTML = `<p class="error">Error: ${e.message}</p>`;
    }
}

async function deleteRule(id, name) {
    if (!confirm(`Delete rule "${name}"?`)) return;

    try {
        const res = await fetch(`${API}/rules/${id}`, {method: 'DELETE'});
        if (res.ok) {
            loadRules();
            loadStats();
        } else {
            const err = await res.json();
            alert(`Error: ${err.detail}`);
        }
    } catch (e) {
        alert(`Error: ${e.message}`);
    }
}

async function toggleRule(id) {
    try {
        const res = await fetch(`${API}/rules/${id}/toggle`, {method: 'PATCH'});
        if (res.ok) {
            loadRules();
        } else {
            const err = await res.json();
            alert(`Error: ${err.detail}`);
        }
    } catch (e) {
        alert(`Error: ${e.message}`);
    }
}

// Initialize on page load
window.onload = () => {
    loadStats();
    loadEmails();
    setInterval(loadStats, 30000); // Refresh stats every 30 seconds
};
