-- An operation is confirmed by a second factor (`second_factor`), never by a mailed code: the
-- `stepup` purpose goes.
--
-- Contracting: a binary from before this migration that still issues a `stepup` code is
-- refused by the narrowed CHECK. The `binding` column stays: that binary reads and writes it on
-- every code path, so it is dropped by a later migration, once no such binary runs.
SET LOCAL lock_timeout = '3s';

DELETE FROM email_codes WHERE purpose = 'stepup';
ALTER TABLE email_codes DROP CONSTRAINT email_codes_owner;
ALTER TABLE email_codes ADD CONSTRAINT email_codes_owner CHECK ((purpose IN ('verify', 'reauth')) = (user_id IS NOT NULL));
ALTER TABLE email_codes DROP CONSTRAINT email_codes_purpose;
ALTER TABLE email_codes ADD CONSTRAINT email_codes_purpose CHECK (purpose IN ('login', 'verify', 'reauth'));
