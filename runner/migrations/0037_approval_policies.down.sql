-- Lossy: every installed scope policy goes and each scope is back on the default; a live
-- `concierge:*` proposal loses what it would do and the executor of a newer binary voids it.
SET LOCAL lock_timeout = '3s';

DROP TABLE scope_approval_policies;
ALTER TABLE approvals DROP CONSTRAINT approvals_scope_delay;
-- NOT VALID: a `concierge:*` row with a roster of one may already exist; the floor binds
-- again for every row written from here.
ALTER TABLE approvals DROP CONSTRAINT approvals_platform_roster;
ALTER TABLE approvals ADD CONSTRAINT approvals_platform_roster CHECK (level = 'scope' OR roster_size >= 2) NOT VALID;
ALTER TABLE approvals DROP CONSTRAINT approvals_action_is_ours;
ALTER TABLE approvals DROP COLUMN action;
