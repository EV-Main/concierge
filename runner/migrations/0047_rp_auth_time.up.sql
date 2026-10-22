-- The `auth_time` of the `evinvest.ltd` session that authorized a relying-party code, kept
-- on the code and on the client session it opens, so the client's access tokens carry the
-- person's last interactive authentication (D24(1)): a relying party proves a fresh
-- re-authentication with its own token, never with this plane's. A refresh re-mints from
-- the session row, so the claim never moves forward without a new authorization.
--
-- Additive and nullable: a binary from before this migration writes neither column, and
-- a NULL is a token without the claim, which no proof accepts.
SET LOCAL lock_timeout = '3s';

ALTER TABLE rp_codes ADD COLUMN auth_time BIGINT;
ALTER TABLE rp_sessions ADD COLUMN auth_time BIGINT;
