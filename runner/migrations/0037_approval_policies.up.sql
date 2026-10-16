-- This plane's own approval kinds (`docs/SCOPES-AND-APPROVALS.md` §5.3, §5.6, §5.7):
-- `concierge:scope_admin_grant` and `concierge:scope_policy_change`, executed by this
-- plane's executor loop. EXPAND only.
--
--   approvals.action          — what a passed `concierge:*` proposal does, stored at open
--                               (`domain::approvals::Action`): the executor acts on what
--                               was approved, never on something read later. NULL for a
--                               service's proposal, which this plane never executes.
--   scope_approval_policies   — every policy a scope was ever measured against, one row per
--                               version, written only by an executed policy change. A scope
--                               with no row is on the default, version 1, so the first
--                               installed version is 2.
--
-- The delay floor is a CHECK as well as a domain rule, on both tables: an hour is the least
-- an owner gets to see a scope's decision and stop it, and a row that slipped past one copy
-- of the rule must be refused by the other. `approvals_scope_delay` holds for every row
-- written so far (the default delay is that hour) and for the previous binary's, which
-- only ever writes the default.
--
-- `lock_timeout`: the ALTERs take ACCESS EXCLUSIVE on `approvals` and the foreign keys
-- SHARE ROW EXCLUSIVE on `tenants`, which every `GetMe` reads; migrations run ON BOOT.
-- SET LOCAL: a session SET would outlive this migration on the pooled connection.
--
-- REVERSIBILITY: `0037_approval_policies.down.sql` drops both. Lossy: every installed
-- policy goes (each scope is back on the default), and a `concierge:*` proposal still
-- live loses what it would do — the executor then voids it.
SET LOCAL lock_timeout = '3s';

ALTER TABLE approvals ADD COLUMN action JSONB;
ALTER TABLE approvals ADD CONSTRAINT approvals_action_is_ours CHECK (action IS NULL OR proposer = 'concierge');
ALTER TABLE approvals ADD CONSTRAINT approvals_scope_delay CHECK (level = 'platform' OR delay_secs >= 3600);
-- The opener of a `concierge:*` proposal is kept off its roster (D23), so with two owners
-- one of them opening leaves a roster of one: still two people, the one who asked and the
-- one who decides. 0036's floor of two on the ROSTER stays for every service's proposal,
-- whose roster nobody is taken off.
ALTER TABLE approvals DROP CONSTRAINT approvals_platform_roster;
ALTER TABLE approvals ADD CONSTRAINT approvals_platform_roster
    CHECK (level = 'scope' OR roster_size >= 2 OR (proposer = 'concierge' AND roster_size >= 1));

CREATE TABLE scope_approval_policies (
    scope        TEXT NOT NULL REFERENCES tenants (id),
    version      BIGINT NOT NULL,
    quorum_bps   INTEGER NOT NULL,
    delay_secs   INTEGER NOT NULL,
    ttl_secs     INTEGER NOT NULL,
    -- `domain::approvals::Threshold`s, checked against the catalogs in force when installed.
    thresholds   JSONB NOT NULL,
    -- The executed `concierge:scope_policy_change` that installed it.
    approval_id  UUID NOT NULL UNIQUE REFERENCES approvals (id),
    installed_at BIGINT NOT NULL,
    PRIMARY KEY (scope, version),
    CONSTRAINT scope_approval_policies_version CHECK (version >= 2),
    CONSTRAINT scope_approval_policies_quorum CHECK (quorum_bps BETWEEN 5001 AND 10000),
    CONSTRAINT scope_approval_policies_delay CHECK (delay_secs BETWEEN 3600 AND 259200),
    CONSTRAINT scope_approval_policies_ttl CHECK (ttl_secs BETWEEN 3600 AND 259200)
);
