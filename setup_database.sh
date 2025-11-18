#!/bin/bash
# Database setup script

echo "=========================================="
echo "  DATABASE SETUP"
echo "=========================================="

if [ "$EUID" -ne 0 ]; then
    echo "ERROR: Must run as root"
    exit 1
fi

echo ""
echo "Creating database and tables..."

sudo -u postgres psql << 'PSQL'
-- Drop database if exists (CLEAN START)
DROP DATABASE IF EXISTS email_gateway;

-- Create database
CREATE DATABASE email_gateway;

-- Connect to database
\c email_gateway

-- Create domains table
CREATE TABLE domains (
    id SERIAL PRIMARY KEY,
    domain_name VARCHAR(255) NOT NULL UNIQUE,
    backend_server VARCHAR(255) NOT NULL,
    backend_port INTEGER DEFAULT 25,
    spam_threshold FLOAT DEFAULT 5.0,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create emails table
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

-- Create filter rules table
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

-- Create indexes
CREATE INDEX idx_emails_domain_id ON emails(domain_id);
CREATE INDEX idx_emails_status ON emails(status);
CREATE INDEX idx_emails_spam_result ON emails(spam_result);
CREATE INDEX idx_emails_matched_rule ON emails(matched_rule_id);
CREATE INDEX idx_filter_rules_active ON filter_rules(is_active);

PSQL

echo ""
echo "✅ Database created successfully!"
echo ""
echo "Tables:"
echo "  - domains (with spam_threshold)"
echo "  - emails (with spam_score, spf_result, dkim_result, dmarc_result)"
echo "  - filter_rules"
echo ""
