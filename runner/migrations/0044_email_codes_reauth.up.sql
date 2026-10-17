-- A re-authentication code (#166): proves the signed-in account's own address for ONE
-- act, like a `verify` code but spent for a different thing, so a sign-in code (anyone's
-- to ask for) or a verification code can never stand in for it, and its own daily budget
-- is counted apart from verification's.
--
-- Additive: a binary from before this migration writes only `login`/`verify` rows, both
-- still legal, and never reads a `reauth` row.
SET LOCAL lock_timeout = '3s';

ALTER TABLE email_codes DROP CONSTRAINT email_codes_purpose;
ALTER TABLE email_codes ADD CONSTRAINT email_codes_purpose CHECK (purpose IN ('login', 'verify', 'reauth'));
ALTER TABLE email_codes DROP CONSTRAINT email_codes_owner;
ALTER TABLE email_codes ADD CONSTRAINT email_codes_owner CHECK ((purpose IN ('verify', 'reauth')) = (user_id IS NOT NULL));
