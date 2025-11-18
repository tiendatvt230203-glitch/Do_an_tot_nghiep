-- Add API Key authentication system
-- Run this migration to add API key support

-- Drop existing tables if they exist (to fix column size)
DROP TABLE IF EXISTS api_key_logs CASCADE;
DROP TABLE IF EXISTS api_keys CASCADE;

-- Create API keys table
CREATE TABLE api_keys (
    id SERIAL PRIMARY KEY,
    key_name VARCHAR(255) NOT NULL,           -- Description of this key
    api_key VARCHAR(128) UNIQUE NOT NULL,     -- The actual API key
    is_active BOOLEAN DEFAULT TRUE,           -- Enable/disable key
    created_by VARCHAR(100),                  -- Who created this key
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_used_at TIMESTAMP,                   -- Track last usage
    expires_at TIMESTAMP,                     -- Optional expiration
    permissions TEXT,                         -- JSON: {"read": true, "write": true, "delete": false}

    -- Rate limiting
    rate_limit_requests INTEGER DEFAULT 1000, -- Max requests per hour
    rate_limit_window INTEGER DEFAULT 3600    -- Window in seconds (1 hour)
);

-- Create API key usage log
CREATE TABLE api_key_logs (
    id SERIAL PRIMARY KEY,
    api_key_id INTEGER REFERENCES api_keys(id) ON DELETE CASCADE,
    endpoint VARCHAR(255),                    -- Which API endpoint was called
    method VARCHAR(10),                       -- GET, POST, etc.
    ip_address VARCHAR(45),                   -- Client IP
    user_agent TEXT,                          -- Client user agent
    status_code INTEGER,                      -- Response status
    request_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    response_time_ms INTEGER                  -- Response time in milliseconds
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_api_keys_key ON api_keys(api_key);
CREATE INDEX IF NOT EXISTS idx_api_keys_active ON api_keys(is_active);
CREATE INDEX IF NOT EXISTS idx_api_key_logs_key_id ON api_key_logs(api_key_id);
CREATE INDEX IF NOT EXISTS idx_api_key_logs_request_time ON api_key_logs(request_time);

-- Insert default admin API key (change this immediately after deployment!)
-- Key: admin_default_key_CHANGE_ME_12345678
INSERT INTO api_keys (key_name, api_key, is_active, created_by, permissions)
VALUES (
    'Default Admin Key - CHANGE IMMEDIATELY',
    'c8f3d4a7e92b1f5a6c3e8d2b9f4a7e1c5d8b3f6a9e2c7d4f1a8b5e3c9d6f2a7e4',
    TRUE,
    'system',
    '{"read": true, "write": true, "delete": true, "admin": true}'
) ON CONFLICT (api_key) DO NOTHING;

COMMENT ON TABLE api_keys IS 'Stores API keys for authentication';
COMMENT ON TABLE api_key_logs IS 'Logs all API requests for monitoring and audit';
