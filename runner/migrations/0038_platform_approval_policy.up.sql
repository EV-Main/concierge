-- The owners' decisions D24(2) (`docs/SCOPES-AND-APPROVALS.md` §5.2, §5.7): after the owner
-- roster changes, platform decisions pause, and the live ones are void.
--
--   platform_approval_policies — every platform policy ever installed, one row per version,
--                                written only by an executed `concierge:platform_policy`.
--                                No row: the default, version 1, 48 h.
--   platform_roster            — one row: when the owner roster last changed. 0 at this
--                                migration: what moved before it is not a change it can date.
--
-- WHY A TRIGGER ON `users`: the roster moves on many paths — an executed admission or
-- removal, a resignation, the genesis seed, a hold, a suspension, a reinstatement, the hold
-- sweep's lapse — written by this binary AND by the previous one during a rollout. The one
-- place every one of them passes is the row. The trigger stamps the change and voids every
-- live platform decision in the same transaction as the seat moving, with its history row.
-- It takes `platform_roster` FIRST: `ApprovalRepository::propose` holds that row FOR SHARE
-- while it opens a platform decision, so a change either waits for the open to commit and
-- then voids it, or commits first and the open sees the pause.
--
-- What counts as a change of the roster: a row becoming or ceasing to be an `owner`, and an
-- owner's `status` moving (a suspended owner has no say, so suspending one changes who
-- decides). Time is `clock_timestamp()`, the store's clock, as everywhere in approvals.
--
-- `approvals_passed` widens: a VOID by roster change may never have passed. Every row
-- already written satisfies the narrower rule it replaces.
--
-- `lock_timeout`: the trigger and the ALTERs take locks on `users` and `approvals`, which
-- every request reads; migrations run ON BOOT. SET LOCAL: a session SET would outlive this
-- migration on the pooled connection.
--
-- REVERSIBILITY: `0038_platform_approval_policy.down.sql` drops all of it. Lossy: the
-- installed platform policies and the last change's stamp go, and the constraints come back
-- NOT VALID over rows written in the meantime.
SET LOCAL lock_timeout = '3s';

CREATE TABLE platform_approval_policies (
    version        BIGINT PRIMARY KEY,
    cooldown_secs  INTEGER NOT NULL,
    approval_id    UUID NOT NULL UNIQUE REFERENCES approvals (id),
    installed_at   BIGINT NOT NULL,
    CONSTRAINT platform_approval_policies_version CHECK (version >= 2),
    CONSTRAINT platform_approval_policies_cooldown CHECK (cooldown_secs BETWEEN 0 AND 1209600)
);

CREATE TABLE platform_roster (
    singleton   BOOLEAN PRIMARY KEY DEFAULT TRUE,
    changed_at  BIGINT NOT NULL,
    CONSTRAINT platform_roster_singleton CHECK (singleton)
);
INSERT INTO platform_roster (singleton, changed_at) VALUES (TRUE, 0);

ALTER TABLE approvals DROP CONSTRAINT approvals_passed;
ALTER TABLE approvals ADD CONSTRAINT approvals_passed CHECK ((passed_at IS NULL) = (executable_at IS NULL)
    AND (state NOT IN ('passed', 'executed', 'execution_failed') OR passed_at IS NOT NULL));

ALTER TABLE approval_events DROP CONSTRAINT approval_events_event;
ALTER TABLE approval_events ADD CONSTRAINT approval_events_event CHECK (event IN
    ('opened', 'voted', 'passed', 'rejected', 'vetoed', 'expired', 'withdrawn', 'executed', 'execution_failed', 'voided', 'lapsed', 'roster_changed'));

CREATE FUNCTION platform_roster_changed() RETURNS TRIGGER
LANGUAGE plpgsql AS $$
DECLARE
    at BIGINT := floor(extract(epoch FROM clock_timestamp()))::BIGINT;
BEGIN
    UPDATE platform_roster SET changed_at = at;
    WITH voided AS (
        UPDATE approvals
        SET state = 'void', void_reason = 'the platform owners changed while it was live', decided_at = at, version = version + 1
        WHERE level = 'platform' AND state IN ('open', 'passed')
        RETURNING id, version
    )
    INSERT INTO approval_events (approval_id, event, version, detail, at)
    SELECT id, 'roster_changed', version, jsonb_build_object('user_id', NEW.id), at FROM voided;
    RETURN NULL;
END
$$;

CREATE TRIGGER users_owner_roster_updated
AFTER UPDATE OF role, status ON users
FOR EACH ROW
WHEN ((OLD.role = 'owner') IS DISTINCT FROM (NEW.role = 'owner') OR (NEW.role = 'owner' AND OLD.status IS DISTINCT FROM NEW.status))
EXECUTE FUNCTION platform_roster_changed();

CREATE TRIGGER users_owner_roster_inserted
AFTER INSERT ON users
FOR EACH ROW
WHEN (NEW.role = 'owner')
EXECUTE FUNCTION platform_roster_changed();
