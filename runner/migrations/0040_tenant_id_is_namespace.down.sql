-- Lossless: only the constraint goes.
SET LOCAL lock_timeout = '3s';

ALTER TABLE tenants DROP CONSTRAINT tenants_id_is_namespace;
