-- Lossy: every installed scope policy goes and each scope is back on the default; a live
-- `concierge:*` proposal loses what it would do and the executor of a newer binary voids it.
SET LOCAL lock_timeout = '3s';

DROP TABLE scope_approval_policies;
ALTER TABLE approvals DROP CONSTRAINT approvals_scope_delay;
ALTER TABLE approvals DROP CONSTRAINT approvals_action_is_ours;
ALTER TABLE approvals DROP COLUMN action;
