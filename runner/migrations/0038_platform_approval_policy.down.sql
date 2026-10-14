-- Lossy: the installed platform policies and the roster's change stamp go; live platform
-- decisions are no longer voided by a change of the owners. The two constraints come back
-- NOT VALID: a VOID that never passed and a `roster_changed` event may already exist.
SET LOCAL lock_timeout = '3s';

DROP TRIGGER users_owner_roster_inserted ON users;
DROP TRIGGER users_owner_roster_updated ON users;
DROP FUNCTION platform_roster_changed();
ALTER TABLE approval_events DROP CONSTRAINT approval_events_event;
ALTER TABLE approval_events ADD CONSTRAINT approval_events_event CHECK (event IN
    ('opened', 'voted', 'passed', 'rejected', 'vetoed', 'expired', 'withdrawn', 'executed', 'execution_failed', 'voided', 'lapsed')) NOT VALID;
ALTER TABLE approvals DROP CONSTRAINT approvals_passed;
ALTER TABLE approvals ADD CONSTRAINT approvals_passed CHECK ((passed_at IS NULL) = (executable_at IS NULL)
    AND (state NOT IN ('passed', 'executed', 'execution_failed', 'void') OR passed_at IS NOT NULL)) NOT VALID;
DROP TABLE platform_roster;
DROP TABLE platform_approval_policies;
