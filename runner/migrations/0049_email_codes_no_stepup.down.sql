SET LOCAL lock_timeout = '3s';

ALTER TABLE email_codes DROP CONSTRAINT email_codes_purpose;
ALTER TABLE email_codes ADD CONSTRAINT email_codes_purpose CHECK (purpose IN ('login', 'verify', 'reauth', 'stepup'));
ALTER TABLE email_codes DROP CONSTRAINT email_codes_owner;
ALTER TABLE email_codes ADD CONSTRAINT email_codes_owner CHECK ((purpose IN ('verify', 'reauth', 'stepup')) = (user_id IS NOT NULL));
