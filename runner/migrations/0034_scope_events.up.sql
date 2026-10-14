-- The relying-party streams and the scope catalog (`docs/SCOPES-AND-APPROVALS.md` §4, §5.1,
-- §6). EXPAND only: three new tables, two helper functions and one trigger on `tenants`.
-- The previous binary names its columns and never reads these tables, so it keeps working
-- beside this one; what it writes while both run (a grant, a sign-in, a role change) is
-- caught by the next boot's reconcile (`infrastructure::scope_events::reconcile`).
--
--   scope_members  — who is VISIBLE to a scope (§4.1): signed in through one of its clients,
--                    or held a grant in its namespace. Only ever inserted: visibility only
--                    grows. `lifecycle_sequence` is the user's `row_version` the join's
--                    MEMBER_JOINED snapshot is as of, and the floor of the lifecycle rows a
--                    relying party is served for this user. `sequence` is the per-(scope,
--                    user) counter GRANTS_CHANGED and MEMBER_JOINED carry; `permissions` the
--                    concrete set the last of them stated, so a change that leaves it equal
--                    emits nothing.
--   scope_outbox   — the ScopeEvents stream. Same mechanics as `user_outbox`: `position` is
--                    the cursor, `event_id` the dedupe key, rows are never deleted, and every
--                    append takes one transaction-scoped advisory lock before it is assigned
--                    a position, so position order is commit order and a reader that skips
--                    ahead never skips a row that commits later. `payload` is the snapshot
--                    at full fidelity (§4.3 parks the POSITION and replays from here).
--   scope_catalogs — every scope catalog ever published (approval kinds + notification
--                    topics), one row per version, keyed by NAMESPACE rather than tenant:
--                    the money plane publishes `bank`, which has no tenant row.
--                    `published_by` is the client id, or `bridge` for the money plane.
--
-- SCOPE_CHANGED is written by the DATABASE: the registry is written by migration and
-- configuration, never by an RPC, so a trigger on `tenants` is the one place every change
-- passes. It fires on an insert and on every `version` move — 0031's triggers already bump
-- the version for a change to the scope or to its clients' audience/disabled/tenant.
--
-- Backfill: one SCOPE_CHANGED per existing scope, so a reader starting from 0 learns every
-- scope. Members and their grants are backfilled by the boot's reconcile, which needs the
-- catalog resolution that lives in Rust.
--
-- `lock_timeout`: the foreign keys take SHARE ROW EXCLUSIVE on `tenants` and `users`, the
-- trigger SHARE ROW EXCLUSIVE on `tenants`; every `GetMe` reads `tenants` and migrations run
-- ON BOOT. SET LOCAL: a session SET would outlive this migration on the pooled connection.
--
-- REVERSIBILITY: `0034_scope_events.down.sql` drops all of it. Lossy: the stream positions
-- relying parties hold become meaningless (a re-run starts again from 1) and every
-- published scope catalog is lost until its publisher republishes.
SET LOCAL lock_timeout = '3s';

CREATE TABLE scope_members (
    scope               TEXT NOT NULL REFERENCES tenants (id),
    user_id             UUID NOT NULL REFERENCES users (id),
    joined_at           BIGINT NOT NULL,
    joined_by           TEXT NOT NULL,
    lifecycle_sequence  BIGINT NOT NULL,
    sequence            BIGINT NOT NULL,
    permissions         TEXT[] NOT NULL,
    PRIMARY KEY (scope, user_id),
    CONSTRAINT scope_members_joined_by CHECK (joined_by IN ('sign_in', 'grant')),
    CONSTRAINT scope_members_sequence CHECK (sequence >= 1 AND lifecycle_sequence >= 0)
);

-- The lifecycle filter and a role change look members up by user.
CREATE INDEX scope_members_user_idx ON scope_members (user_id);

CREATE TABLE scope_outbox (
    event_id      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    position      BIGSERIAL NOT NULL UNIQUE,
    scope         TEXT NOT NULL REFERENCES tenants (id),
    kind          TEXT NOT NULL,
    occurred_at   BIGINT NOT NULL,
    sequence      BIGINT NOT NULL,
    user_id       UUID REFERENCES users (id),
    auth_subject  TEXT,
    payload       JSONB NOT NULL,
    CONSTRAINT scope_outbox_kind CHECK (kind IN ('SCOPE_CHANGED', 'GRANTS_CHANGED', 'MEMBER_JOINED')),
    CONSTRAINT scope_outbox_user CHECK ((kind = 'SCOPE_CHANGED') = (user_id IS NULL) AND (user_id IS NULL) = (auth_subject IS NULL)),
    CONSTRAINT scope_outbox_sequence CHECK (sequence >= 1)
);

CREATE TABLE scope_catalogs (
    namespace     TEXT NOT NULL,
    version       BIGINT NOT NULL,
    catalog       JSONB NOT NULL,
    published_at  BIGINT NOT NULL,
    published_by  TEXT NOT NULL,
    PRIMARY KEY (namespace, version),
    -- `concierge` is this plane's own built-in catalog and is never published.
    CONSTRAINT scope_catalogs_namespace CHECK (namespace ~ '^[a-z][a-z0-9_]{0,31}$' AND namespace NOT IN ('concierge', 'iam', 'seat')),
    CONSTRAINT scope_catalogs_version CHECK (version >= 1),
    CONSTRAINT scope_catalogs_published_by CHECK (published_by ~ '^[a-z][a-z0-9_]{0,31}$')
);

-- The one writer of `scope_outbox`, so the lock that makes position order commit order is
-- taken on every path — Rust and trigger alike — and its key lives in one place.
CREATE FUNCTION scope_outbox_append(p_scope TEXT, p_kind TEXT, p_occurred_at BIGINT, p_sequence BIGINT, p_user UUID, p_subject TEXT, p_payload JSONB)
RETURNS VOID
LANGUAGE plpgsql AS $$
BEGIN
    -- "SCOPEV"; distinct from user_outbox's "OUTBOX" so the two streams do not serialise
    -- each other.
    PERFORM pg_advisory_xact_lock(91548558574934);
    INSERT INTO scope_outbox (scope, kind, occurred_at, sequence, user_id, auth_subject, payload)
    VALUES (p_scope, p_kind, p_occurred_at, p_sequence, p_user, p_subject, p_payload);
END
$$;

-- The whole `Scope` message as it stands, field for field with `scopes.proto`.
CREATE FUNCTION scope_snapshot(p_scope TEXT) RETURNS JSONB
LANGUAGE SQL STABLE AS $$
    SELECT jsonb_build_object(
        'id', t.id,
        'namespace', t.namespace,
        'parent', t.parent,
        'display_name', t.display_name,
        'origins', to_jsonb(t.origins),
        'return_paths', to_jsonb(t.return_paths),
        'observers', to_jsonb(t.observers),
        'state', t.state,
        'version', t.version,
        'created_at', t.created_at,
        'clients', coalesce((
            SELECT jsonb_agg(jsonb_build_object('client_id', c.client_id, 'audience', c.audience, 'disabled', c.disabled_at IS NOT NULL) ORDER BY c.client_id)
            FROM rp_clients c WHERE c.tenant_id = t.id
        ), '[]'::JSONB)
    )
    FROM tenants t WHERE t.id = p_scope
$$;

CREATE FUNCTION tenants_scope_changed() RETURNS TRIGGER
LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'INSERT' OR NEW.version IS DISTINCT FROM OLD.version THEN
        PERFORM scope_outbox_append(NEW.id, 'SCOPE_CHANGED', extract(epoch FROM now())::BIGINT, NEW.version, NULL, NULL, scope_snapshot(NEW.id));
    END IF;
    RETURN NULL;
END
$$;

CREATE TRIGGER tenants_scope_changed
AFTER INSERT OR UPDATE ON tenants
FOR EACH ROW EXECUTE FUNCTION tenants_scope_changed();

DO $$
DECLARE
    existing RECORD;
BEGIN
    FOR existing IN SELECT id, version FROM tenants ORDER BY id LOOP
        PERFORM scope_outbox_append(existing.id, 'SCOPE_CHANGED', extract(epoch FROM now())::BIGINT, existing.version, NULL, NULL, scope_snapshot(existing.id));
    END LOOP;
END $$;
