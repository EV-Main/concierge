SET LOCAL lock_timeout = '3s';

ALTER TABLE email_codes ADD COLUMN binding BYTEA;
