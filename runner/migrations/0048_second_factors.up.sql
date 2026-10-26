-- Second factors (`runner/src/second_factor`): what an account proves itself with beyond its
-- sign-in, asked for before money leaves. One table for every kind: `kind` names it, and
-- everything the kind keeps lives in `material`, sealed (AES-256-GCM, bound to the row's id,
-- account and kind), because a TOTP secret has to be read back to be checked.
--
-- A row with `confirmed_at` NULL is an enrolment begun and not yet proven; it is dead ten
-- minutes after `created_at` and the next enrolment of the account deletes it.
--
-- `second_factor_recovery_codes` holds the one-time codes that recover an account whose
-- factors are lost, as SHA-256 digests (each code carries 80 random bits).
--
-- `second_factor_guard` counts wrong answers per ACCOUNT, across every factor and the
-- recovery codes, in the database so every replica sees one count.
--
-- `security_notice` is the mail telling an account a factor was added, removed or reset.
-- It is addressed to the account's verified address, like a code, not to a subscriber.
--
-- Additive: an older binary reads none of it.
SET LOCAL lock_timeout = '3s';

CREATE TABLE second_factors (
    id           UUID PRIMARY KEY,
    user_id      UUID NOT NULL REFERENCES users (id),
    kind         TEXT NOT NULL,
    label        TEXT NOT NULL,
    material     BYTEA NOT NULL,
    created_at   BIGINT NOT NULL,
    confirmed_at BIGINT,
    last_used_at BIGINT,
    CONSTRAINT second_factors_kind CHECK (kind IN ('totp')),
    CONSTRAINT second_factors_label_len CHECK (char_length(label) BETWEEN 1 AND 64)
);
CREATE INDEX second_factors_user_idx ON second_factors (user_id);

CREATE TABLE second_factor_recovery_codes (
    user_id    UUID NOT NULL REFERENCES users (id),
    digest     BYTEA NOT NULL,
    created_at BIGINT NOT NULL,
    used_at    BIGINT,
    PRIMARY KEY (user_id, digest),
    CONSTRAINT second_factor_recovery_codes_digest_len CHECK (octet_length(digest) = 32)
);

CREATE TABLE second_factor_guard (
    user_id           UUID PRIMARY KEY REFERENCES users (id),
    window_started_at BIGINT NOT NULL,
    window_wrong      INTEGER NOT NULL,
    day_started_at    BIGINT NOT NULL,
    day_wrong         INTEGER NOT NULL,
    locked_until      BIGINT,
    CONSTRAINT second_factor_guard_counts CHECK (window_wrong >= 0 AND day_wrong >= 0)
);

ALTER TABLE notification_deliveries DROP CONSTRAINT notification_deliveries_subscriber;
ALTER TABLE notification_deliveries ADD CONSTRAINT notification_deliveries_subscriber CHECK (subscriber_id IS NOT NULL OR kind IN ('email_code', 'security_notice'));
ALTER TABLE notification_deliveries DROP CONSTRAINT notification_deliveries_kind;
ALTER TABLE notification_deliveries ADD CONSTRAINT notification_deliveries_kind
    CHECK (kind IN ('notification', 'confirm', 'owner_removal_self_accept', 'payout_approval', 'payout_outcome', 'payment_consent', 'payment_approval', 'fee_policy_approval', 'fee_policy_notice', 'kyc_verdict_alert', 'payment_outcome', 'email_code', 'approval_request', 'approval_outcome', 'security_notice'));
