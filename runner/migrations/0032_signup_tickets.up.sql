-- Sign-up tickets: what lets a password sign-up started on a scope's host confirm its
-- address without the CSRF double-submit, whose cookie that host cannot read.
--
-- `POST /auth/password/signup` mails a verification code and hands the caller a ticket;
-- `POST /auth/password/signup/confirm {ticket, code}` spends the code through the same
-- path as `/auth/email/verify/confirm` — the address is verified on THIS account and its
-- password stays. That is the point: a code SIGN-IN on an unverified password account is
-- a mailbox taking the account over (0029: sessions revoked, password dropped), which is
-- right against a squatter and wrong against the person who registered a minute ago.
-- The ticket is what tells the two apart: only the browser that signed up holds it.
--
-- 256 random bits, stored as a SHA-256 digest (never the ticket), spent once, alive as
-- long as a code (`CODE_TTL_SECS`). It is bound to the account's `token_version` and to
-- the password's `updated_at`: a takeover, a revoke-all or a new password since issuance
-- kills it. Rows are reaped a day past expiry by the insert path.
--
-- `lock_timeout`: the foreign key takes SHARE ROW EXCLUSIVE on `users` while the table is
-- created, and migrations run ON BOOT. SET LOCAL: a session SET would outlive this
-- migration on the pooled connection.
--
-- REVERSIBILITY: `0032_signup_tickets.down.sql` drops the table; an outstanding ticket
-- is lost and its holder confirms the address the CSRF way, on evinvest.ltd.
SET LOCAL lock_timeout = '3s';

CREATE TABLE signup_tickets (
    ticket_hash      BYTEA PRIMARY KEY,
    user_id          UUID NOT NULL REFERENCES users (id),
    token_version    BIGINT NOT NULL,
    password_set_at  BIGINT NOT NULL,
    issued_at        BIGINT NOT NULL,
    expires_at       BIGINT NOT NULL,
    spent_at         BIGINT,
    CONSTRAINT signup_tickets_hash_len CHECK (octet_length(ticket_hash) = 32)
);

CREATE INDEX signup_tickets_expires_idx ON signup_tickets (expires_at);
