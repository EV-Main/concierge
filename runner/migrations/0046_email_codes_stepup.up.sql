-- A step-up code (`/auth/stepup/*`): proves the signed-in account's own address for ONE
-- operation, whose details ride in the mail. Its own purpose so that no sign-in,
-- verification or re-authentication code can stand in for it, and so its daily budget is
-- counted apart from theirs.
--
-- Additive: a binary from before this migration writes only `login`/`verify`/`reauth`
-- rows, all still legal, and never reads a `stepup` row.
SET LOCAL lock_timeout = '3s';

ALTER TABLE email_codes DROP CONSTRAINT email_codes_purpose;
ALTER TABLE email_codes ADD CONSTRAINT email_codes_purpose CHECK (purpose IN ('login', 'verify', 'reauth', 'stepup'));
ALTER TABLE email_codes DROP CONSTRAINT email_codes_owner;
ALTER TABLE email_codes ADD CONSTRAINT email_codes_owner CHECK ((purpose IN ('verify', 'reauth', 'stepup')) = (user_id IS NOT NULL));
