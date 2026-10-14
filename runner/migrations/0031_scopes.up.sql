-- Scopes: a tenant seen as a direction (`docs/SCOPES-AND-APPROVALS.md` §3). EXPAND only —
-- every new column has a constant default, so the previous binary, which names its
-- columns, keeps reading and writing `tenants` and `rp_clients` unchanged.
--
--   parent        — `main`, the implicit root, which has no row of its own. Pinned to
--                   `main` by CHECK until a nested scope is actually wanted: relaxing a
--                   CHECK later is a migration either way, and loosening is the safe
--                   direction to discover it in.
--   display_name  — plain text, at most 80 bytes.
--   origins       — the https origins of the scope's hosts (subdomains of evinvest.ltd,
--                   never the bare host), exactly as a browser sends `Origin`. They widen CORS and the `Origin` check on the sign-in routes
--                   only, so the shape is held HERE as well as in code
--                   (`domain::scopes::is_sign_in_origin`): a row a configuration slip
--                   could write with `http://`, a path or a foreign host would otherwise
--                   be one boot away from trusting it.
--   return_paths  — the paths an OAuth `returnTo` may name on those origins, matched
--                   exactly (no prefix, no query): this is what keeps `returnTo` from
--                   being an open redirect.
--   state         — active | frozen | closed. A closed scope's origins stop counting.
--   observers     — client ids that may READ this scope's streams (no stream reads it
--                   yet). Not a foreign key — Postgres has none over an array — so an
--                   unknown id is inert rather than refused.
--   version       — bumped by trigger on every change to the scope or to its clients'
--                   audience/disabled/tenant, so `Scope.version` means "anything in the
--                   message moved" without every writer having to remember it. A
--                   client's secret rotation is not part of the message and does not
--                   bump it.
--
-- Seeds: `sa` gets its host (`https://sa.evinvest.ltd`; the panel lands on `/`, and
-- `/auth/login` is the panel's own sign-in entry that runs the silent relying-party
-- trip) and names `invest` as an observer (§3: invest runs the `service_arb`
-- allocation). New: tenant `invest` and its relying-party client `invest` (aud
-- `invest`). The client has no secret here, as `sa` had none in 0025: the boot writes
-- it from `RP_CLIENT_SECRET_INVEST`, and until then the client obtains no token.
-- `granting_seats_hold_all` is TRUE for `invest` as for `sa`: allocation management was
-- the global admins' (`bank:allocation:manage`) and nobody may grant themselves the
-- alias that replaces it, so FALSE would leave a lone owner unable to reach it.
--
-- `lock_timeout`: ALTER TABLE takes ACCESS EXCLUSIVE on `tenants`, which every `GetMe`
-- reads, the triggers take SHARE ROW EXCLUSIVE on `rp_clients`, and re-adding the
-- revocation-reason CHECK holds ACCESS EXCLUSIVE on `rp_sessions` while it scans the
-- table (one row per client sign-in, small); migrations run ON BOOT. SET LOCAL, not SET: sqlx runs this on a connection borrowed from the service's
-- pool, and a session SET would outlive it.
--
-- REVERSIBILITY: `0031_scopes.down.sql`. Lossy for `invest` only: its client, the codes
-- and sessions it issued, the grants and catalogs of its namespace are deleted.
SET LOCAL lock_timeout = '3s';

-- IMMUTABLE helpers so the array CHECKs read as one rule each; a CHECK cannot hold a
-- subquery over `unnest`. They mirror `domain::scopes` rule for rule, so a row the boot
-- would drop as malformed cannot be written in the first place.
--
-- A NULL element is refused explicitly: `bool_and` skips NULLs, so without the
-- `array_position` guard `ARRAY[NULL]` would pass and then fail to decode. The host is
-- a SUBdomain of evinvest.ltd — the bare host is `PUBLIC_ORIGIN`, this plane's own,
-- never a scope's — and a port is 1-65535 and never the default 443.
CREATE FUNCTION scope_origins_valid(origins TEXT[]) RETURNS BOOLEAN
LANGUAGE SQL IMMUTABLE STRICT AS $$
    SELECT array_position(origins, NULL) IS NULL AND coalesce(bool_and(
        o ~ '^https://([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+evinvest\.ltd(:[1-9][0-9]{0,4})?$'
        AND coalesce(substring(o FROM ':([0-9]+)$')::INTEGER BETWEEN 1 AND 65535, TRUE)
        AND o !~ ':443$'
    ), TRUE)
    FROM unnest(origins) AS o
$$;

CREATE FUNCTION scope_return_paths_valid(paths TEXT[]) RETURNS BOOLEAN
LANGUAGE SQL IMMUTABLE STRICT AS $$
    SELECT array_position(paths, NULL) IS NULL
       AND coalesce(bool_and(p = '/' OR p ~ '^(/[A-Za-z0-9._~%!$&''()*+,;=:@-]+)+$'), TRUE)
    FROM unnest(paths) AS p
$$;

ALTER TABLE tenants
    ADD COLUMN parent        TEXT   NOT NULL DEFAULT 'main',
    ADD COLUMN display_name  TEXT   NOT NULL DEFAULT '',
    ADD COLUMN origins       TEXT[] NOT NULL DEFAULT '{}',
    ADD COLUMN return_paths  TEXT[] NOT NULL DEFAULT '{}',
    ADD COLUMN state         TEXT   NOT NULL DEFAULT 'active',
    ADD COLUMN observers     TEXT[] NOT NULL DEFAULT '{}',
    ADD COLUMN version       BIGINT NOT NULL DEFAULT 1,
    -- `main` is the implicit root and never a row.
    ADD CONSTRAINT tenants_not_main CHECK (id <> 'main' AND namespace <> 'main'),
    ADD CONSTRAINT tenants_parent CHECK (parent = 'main'),
    ADD CONSTRAINT tenants_display_name_len CHECK (octet_length(display_name) <= 80),
    ADD CONSTRAINT tenants_origins CHECK (cardinality(origins) <= 16 AND scope_origins_valid(origins)),
    ADD CONSTRAINT tenants_return_paths CHECK (cardinality(return_paths) <= 16 AND scope_return_paths_valid(return_paths)),
    ADD CONSTRAINT tenants_state CHECK (state IN ('active', 'frozen', 'closed')),
    -- `array_to_string` drops NULL elements, hence the explicit guard.
    ADD CONSTRAINT tenants_observers CHECK (cardinality(observers) <= 16 AND array_position(observers, NULL) IS NULL AND array_to_string(observers, ' ') ~ '^([a-z][a-z0-9_]{0,31}( [a-z][a-z0-9_]{0,31})*)?$'),
    ADD CONSTRAINT tenants_version CHECK (version >= 1);

UPDATE tenants
SET display_name = 'Service-Arb',
    origins = ARRAY['https://sa.evinvest.ltd'],
    return_paths = ARRAY['/', '/auth/login'],
    observers = ARRAY['invest']
WHERE id = 'sa';

INSERT INTO tenants (id, namespace, granting_seats_hold_all, created_at, display_name, origins, return_paths)
VALUES ('invest', 'invest', TRUE, extract(epoch FROM now())::BIGINT, 'EV Invest', ARRAY['https://invest.evinvest.ltd'], ARRAY['/cabinet']);

INSERT INTO rp_clients (client_id, audience, redirect_uris, tenant_id, created_at)
VALUES ('invest', 'invest', ARRAY['https://invest.evinvest.ltd/cabinet/auth/callback'], 'invest', extract(epoch FROM now())::BIGINT);

-- A closed scope's clients are refused like disabled ones, and a session of theirs is
-- ended at its next refresh under its own reason, so the record says why.
ALTER TABLE rp_sessions DROP CONSTRAINT rp_sessions_revoked_reason;
ALTER TABLE rp_sessions ADD CONSTRAINT rp_sessions_revoked_reason
    CHECK (revoked_reason IN ('refresh_reuse', 'code_replay', 'access_denied', 'tokens_revoked', 'upstream_revoked', 'scope_closed'));

-- Created after the seeds, so every scope starts at version 1.
CREATE FUNCTION tenants_bump_version() RETURNS TRIGGER
LANGUAGE plpgsql AS $$
BEGIN
    IF ROW(NEW.*) IS DISTINCT FROM ROW(OLD.*) THEN
        NEW.version := OLD.version + 1;
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER tenants_bump_version
BEFORE UPDATE ON tenants
FOR EACH ROW EXECUTE FUNCTION tenants_bump_version();

CREATE FUNCTION rp_clients_bump_scope_version() RETURNS TRIGGER
LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'UPDATE'
       AND NEW.audience IS NOT DISTINCT FROM OLD.audience
       AND NEW.disabled_at IS NOT DISTINCT FROM OLD.disabled_at
       AND NEW.tenant_id IS NOT DISTINCT FROM OLD.tenant_id THEN
        RETURN NULL;
    END IF;
    IF TG_OP IN ('UPDATE', 'DELETE') THEN
        UPDATE tenants SET version = version + 1 WHERE id = OLD.tenant_id;
    END IF;
    IF TG_OP IN ('UPDATE', 'INSERT') AND (TG_OP = 'INSERT' OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id) THEN
        UPDATE tenants SET version = version + 1 WHERE id = NEW.tenant_id;
    END IF;
    RETURN NULL;
END
$$;

CREATE TRIGGER rp_clients_bump_scope_version
AFTER INSERT OR UPDATE OR DELETE ON rp_clients
FOR EACH ROW EXECUTE FUNCTION rp_clients_bump_scope_version();
