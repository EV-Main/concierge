-- Lossy: the scope stream, its membership record and every published scope catalog go.
-- A relying party's stored position means nothing afterwards; its projection is rebuilt
-- from 0 once the stream is back.
SET LOCAL lock_timeout = '3s';

DROP TRIGGER tenants_scope_changed ON tenants;
DROP FUNCTION tenants_scope_changed();
DROP FUNCTION scope_snapshot(TEXT);
DROP FUNCTION scope_outbox_append(TEXT, TEXT, BIGINT, BIGINT, UUID, TEXT, JSONB);
DROP TABLE scope_catalogs;
DROP TABLE scope_outbox;
DROP TABLE scope_members;
