-- Approvals: the consilium generalised to every scope (`docs/SCOPES-AND-APPROVALS.md` §5,
-- `approvals.proto`). EXPAND only: three new tables, nothing existing is touched, so the
-- previous binary keeps working beside this one — it never reads them.
--
--   approvals        — one proposal. What it is ABOUT (kind, scope, subject_ref, fields,
--                      payload_hash) is written at open and never changes; WHO decides
--                      (level, escalated_by, roster_size, threshold, policy_version,
--                      delay_secs) is resolved at open and frozen with the roster, so a
--                      roster or policy that moves later cannot move a live proposal.
--   approval_voters  — the frozen roster and each member's vote. Nobody is excluded from
--                      it: the proposing service cannot prove which person asked it, so
--                      `requested_by` is information and keeps nobody off (§5.2).
--   approval_events  — "what happened to this proposal", appended in the SAME transaction
--                      as the transition it records, as `governance_event` is.
--
-- WHY `scope` HAS NO FOREIGN KEY: `main` is the implicit root and has no `tenants` row.
-- The writer checks the scope against the registry inside the opening transaction.
--
-- WHY NO `executable` STATE: a passed proposal becomes pullable when the clock passes
-- `executable_at`, and an open one expires when it passes `expires_at`; both are read as
-- predicates, so nothing has to sweep for either to take effect (the consilia's rule).
--
-- Domain time is BIGINT unix seconds, supplied by the application, as everywhere here.
--
-- `lock_timeout`: the foreign keys take SHARE ROW EXCLUSIVE on `users`, which every request
-- reads and migrations run ON BOOT. SET LOCAL: a session SET would outlive this migration
-- on the pooled connection.
--
-- REVERSIBILITY: `0036_approvals.down.sql` drops all three. Lossy: every proposal, vote and
-- its history goes, and a proposer holding an approval id finds nothing under it.
SET LOCAL lock_timeout = '3s';

CREATE TABLE approvals (
    id                   UUID PRIMARY KEY,
    kind                 TEXT NOT NULL,
    -- The kind's namespace: its only proposer and only executor (§5.1).
    proposer             TEXT NOT NULL,
    scope                TEXT NOT NULL,
    level                TEXT NOT NULL,
    escalated_by         TEXT[] NOT NULL DEFAULT '{}',
    state                TEXT NOT NULL DEFAULT 'open',
    subject_ref          TEXT NOT NULL,
    -- `domain::approvals::Field`s in the kind's display order.
    fields               JSONB NOT NULL,
    payload_hash         TEXT NOT NULL,
    requested_by         UUID REFERENCES users (id),
    reason               TEXT NOT NULL,
    roster_size          INTEGER NOT NULL,
    threshold            INTEGER NOT NULL,
    policy_version       BIGINT NOT NULL,
    delay_secs           BIGINT NOT NULL,
    created_at           BIGINT NOT NULL,
    expires_at           BIGINT NOT NULL,
    passed_at            BIGINT,
    executable_at        BIGINT,
    decided_at           BIGINT,
    vetoed_by            UUID REFERENCES users (id),
    veto_reason          TEXT NOT NULL DEFAULT '',
    void_reason          TEXT NOT NULL DEFAULT '',
    outcome              TEXT,
    outcome_detail       TEXT NOT NULL DEFAULT '',
    -- The client whose credential opened it; empty for the bridge token. Audit only: a
    -- namespace is the unit of authority, so this authorises nothing.
    requested_by_client  TEXT NOT NULL DEFAULT '',
    dedupe_key           TEXT NOT NULL,
    version              BIGINT NOT NULL DEFAULT 0,
    CONSTRAINT approvals_kind CHECK (kind ~ '^[a-z][a-z0-9_]*:[a-z][a-z0-9_]*$' AND split_part(kind, ':', 1) = proposer),
    CONSTRAINT approvals_scope CHECK (scope ~ '^[a-z][a-z0-9_]{0,31}$'),
    CONSTRAINT approvals_level CHECK (level IN ('platform', 'scope')),
    -- A scope kind in scope `main` is the owners' (§5.2), so a scope-level row never
    -- names the root.
    CONSTRAINT approvals_root_is_platform CHECK (level = 'platform' OR scope <> 'main'),
    CONSTRAINT approvals_state CHECK (state IN ('open', 'passed', 'executed', 'execution_failed', 'rejected', 'vetoed', 'expired', 'cancelled', 'void')),
    CONSTRAINT approvals_subject_ref CHECK (octet_length(subject_ref) <= 128 AND subject_ref ~ '^[a-z][a-z0-9_]{0,31}:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'),
    CONSTRAINT approvals_payload_hash CHECK (payload_hash ~ '^[0-9a-f]{64}$'),
    CONSTRAINT approvals_reason CHECK (octet_length(reason) BETWEEN 1 AND 500),
    CONSTRAINT approvals_veto_reason CHECK (octet_length(veto_reason) <= 500),
    CONSTRAINT approvals_outcome_detail CHECK (octet_length(outcome_detail) <= 200 AND octet_length(void_reason) <= 200),
    CONSTRAINT approvals_dedupe_key CHECK (octet_length(dedupe_key) BETWEEN 1 AND 128),
    -- Fewer than two owners would let one person decide for the platform (§5.2).
    CONSTRAINT approvals_platform_roster CHECK (level = 'scope' OR roster_size >= 2),
    CONSTRAINT approvals_threshold CHECK (threshold BETWEEN 1 AND roster_size),
    CONSTRAINT approvals_ttl CHECK (expires_at > created_at AND expires_at - created_at <= 259200),
    CONSTRAINT approvals_delay CHECK (delay_secs >= 0),
    CONSTRAINT approvals_decided CHECK ((state IN ('open', 'passed')) = (decided_at IS NULL)),
    CONSTRAINT approvals_passed CHECK ((passed_at IS NULL) = (executable_at IS NULL)
        AND (state NOT IN ('passed', 'executed', 'execution_failed', 'void') OR passed_at IS NOT NULL)),
    CONSTRAINT approvals_vetoed CHECK ((state = 'vetoed') = (vetoed_by IS NOT NULL)),
    CONSTRAINT approvals_outcome CHECK (outcome IS NULL OR outcome IN ('executed', 'failed', 'void')),
    CONSTRAINT approvals_outcome_state CHECK ((state NOT IN ('executed', 'execution_failed') OR outcome IS NOT NULL)
        AND (outcome IS NULL OR state IN ('executed', 'execution_failed', 'void')))
);

-- One subject is decided once at a time (§5.4). A unique index rather than a check in
-- the writer, so two concurrent proposes of the same subject cannot both land.
CREATE UNIQUE INDEX approvals_live_subject_idx ON approvals (kind, scope, subject_ref) WHERE state IN ('open', 'passed');
-- `Propose` is idempotent per proposer namespace.
CREATE UNIQUE INDEX approvals_dedupe_idx ON approvals (proposer, dedupe_key);
-- `PullApproved`: oldest executable first.
CREATE INDEX approvals_pull_idx ON approvals (proposer, executable_at) WHERE state = 'passed';
-- The rolling 24h window a scope-level escalation sums over.
CREATE INDEX approvals_window_idx ON approvals (kind, scope, created_at) WHERE level = 'scope';
-- `ListApprovals`: newest first.
CREATE INDEX approvals_recent_idx ON approvals (created_at DESC, id DESC);
CREATE INDEX approvals_requested_by_idx ON approvals (requested_by) WHERE requested_by IS NOT NULL;

CREATE TABLE approval_voters (
    approval_id  UUID NOT NULL REFERENCES approvals (id),
    user_id      UUID NOT NULL REFERENCES users (id),
    vote         TEXT NOT NULL DEFAULT 'pending',
    voted_at     BIGINT,
    PRIMARY KEY (approval_id, user_id),
    CONSTRAINT approval_voters_vote CHECK (vote IN ('pending', 'for', 'against')),
    CONSTRAINT approval_voters_voted CHECK ((vote = 'pending') = (voted_at IS NULL))
);

-- "What am I still to vote on", and the visibility of a proposal to its roster.
CREATE INDEX approval_voters_user_idx ON approval_voters (user_id);

CREATE TABLE approval_events (
    id             BIGSERIAL PRIMARY KEY,
    approval_id    UUID NOT NULL REFERENCES approvals (id),
    event          TEXT NOT NULL,
    -- The person who acted, when one did. NULL for a service's act (then `actor_client`
    -- names it) and for the lazy expiry, which nobody performed.
    actor_user_id  UUID REFERENCES users (id),
    -- The client id, or `bridge` for the money plane; empty when a person acted or nobody did.
    actor_client   TEXT NOT NULL DEFAULT '',
    version        BIGINT NOT NULL,
    detail         JSONB NOT NULL DEFAULT '{}',
    at             BIGINT NOT NULL,
    CONSTRAINT approval_events_event CHECK (event IN ('opened', 'voted', 'passed', 'rejected', 'vetoed', 'expired', 'withdrawn', 'executed', 'execution_failed', 'voided')),
    CONSTRAINT approval_events_one_actor CHECK (actor_user_id IS NULL OR actor_client = '')
);

CREATE INDEX approval_events_approval_idx ON approval_events (approval_id, id);
