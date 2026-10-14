-- Lossy for `invest` only: its client, the codes and sessions it issued, and the grants
-- and catalogs of its namespace go with it. `sa` keeps everything 0026 gave it.
SET LOCAL lock_timeout = '3s';

DROP TRIGGER rp_clients_bump_scope_version ON rp_clients;
DROP FUNCTION rp_clients_bump_scope_version();
DROP TRIGGER tenants_bump_version ON tenants;
DROP FUNCTION tenants_bump_version();

DELETE FROM rp_sessions WHERE client_id IN (SELECT client_id FROM rp_clients WHERE tenant_id = 'invest');
DELETE FROM rp_codes WHERE client_id IN (SELECT client_id FROM rp_clients WHERE tenant_id = 'invest');
DELETE FROM catalogs WHERE tenant_id = 'invest';
DELETE FROM rp_clients WHERE tenant_id = 'invest';
DELETE FROM grants WHERE namespace = 'invest';
DELETE FROM tenants WHERE id = 'invest';

ALTER TABLE tenants
    DROP CONSTRAINT tenants_not_main,
    DROP COLUMN parent,
    DROP COLUMN display_name,
    DROP COLUMN origins,
    DROP COLUMN return_paths,
    DROP COLUMN state,
    DROP COLUMN observers,
    DROP COLUMN version;

DROP FUNCTION scope_return_paths_valid(TEXT[]);
DROP FUNCTION scope_origins_valid(TEXT[]);
