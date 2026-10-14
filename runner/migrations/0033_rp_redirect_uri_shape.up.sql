-- The shape of a relying party's redirect URI, held at the column: absolute `https://`,
-- a host with no userinfo, no fragment, no whitespace or control characters. A code is
-- sent to whatever is registered here, so a row that breaks the shape is a redirect the
-- registry should never have been able to hold. `relying_party::check_registered_redirects`
-- refuses such a row at boot; this is the same rule where a hand-written INSERT meets it.
--
-- NOT VALID: the rows already there (the `sa` and `invest` seeds, and whatever was
-- registered by hand since) are not re-read under an ACCESS EXCLUSIVE lock at boot, and a
-- row that broke the shape would turn this migration into a crash loop. The seeds
-- conform; `VALIDATE CONSTRAINT rp_clients_redirect_uris_shape` once production is known
-- to agree. New and updated rows are checked from here on.
--
-- An array is checked through an IMMUTABLE function because a CHECK takes no subquery.
--
-- `lock_timeout`: ADD CONSTRAINT takes ACCESS EXCLUSIVE on `rp_clients`, briefly, and
-- migrations run ON BOOT. SET LOCAL: a session SET would outlive this migration on the
-- pooled connection.
--
-- REVERSIBILITY: `0033_rp_redirect_uri_shape.down.sql` drops the constraint and the
-- function; nothing else depends on them.
SET LOCAL lock_timeout = '3s';

CREATE FUNCTION rp_redirect_uris_wellformed(uris TEXT[]) RETURNS BOOLEAN
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE AS $$
    SELECT coalesce(bool_and(uri ~ '^https://[^/?#@[:space:][:cntrl:]]+([/?][^#[:space:][:cntrl:]]*)?$'), TRUE)
    FROM unnest(uris) AS uri
$$;

ALTER TABLE rp_clients
    ADD CONSTRAINT rp_clients_redirect_uris_shape CHECK (rp_redirect_uris_wellformed(redirect_uris)) NOT VALID;
