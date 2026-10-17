SET LOCAL lock_timeout = '3s';

-- The older constraints cannot hold a `reauth` row; the codes live ten minutes anyway.
DELETE FROM email_codes WHERE purpose = 'reauth';
ALTER TABLE email_codes DROP CONSTRAINT email_codes_owner;
ALTER TABLE email_codes ADD CONSTRAINT email_codes_owner CHECK ((purpose = 'verify') = (user_id IS NOT NULL));
ALTER TABLE email_codes DROP CONSTRAINT email_codes_purpose;
ALTER TABLE email_codes ADD CONSTRAINT email_codes_purpose CHECK (purpose IN ('login', 'verify'));
