-- Add spam_threshold column to domains table
-- Each domain can have its own spam threshold

ALTER TABLE domains ADD COLUMN IF NOT EXISTS spam_threshold FLOAT DEFAULT 5.0;

-- Update comment
COMMENT ON COLUMN domains.spam_threshold IS 'Spam score threshold for this domain. Emails with score > threshold will be marked as spam.';

-- Example: Set different thresholds for different domains
-- UPDATE domains SET spam_threshold = 15.0 WHERE domain_name = 'dattest.site';
-- UPDATE domains SET spam_threshold = 12.0 WHERE domain_name = 'tienddat.online';
