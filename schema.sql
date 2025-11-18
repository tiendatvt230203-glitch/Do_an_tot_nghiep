-- Email Gateway Database Schema
-- Simple and clean

-- Drop existing tables
DROP TABLE IF EXISTS emails CASCADE;
DROP TABLE IF EXISTS domains CASCADE;

-- Domains table
CREATE TABLE domains (
    id SERIAL PRIMARY KEY,
    domain_name VARCHAR(255) UNIQUE NOT NULL,
    backend_server VARCHAR(255) NOT NULL,
    backend_port INTEGER DEFAULT 25,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Emails table
CREATE TABLE emails (
    id SERIAL PRIMARY KEY,
    domain_id INTEGER REFERENCES domains(id) ON DELETE CASCADE,
    message_id VARCHAR(500),
    subject TEXT,
    from_address VARCHAR(255),
    to_address VARCHAR(255),
    sender_ip VARCHAR(45),
    status VARCHAR(50) DEFAULT 'received',
    received_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for performance
CREATE INDEX idx_emails_domain_id ON emails(domain_id);
CREATE INDEX idx_emails_received_at ON emails(received_at);
CREATE INDEX idx_emails_status ON emails(status);
CREATE INDEX idx_domains_name ON domains(domain_name);
