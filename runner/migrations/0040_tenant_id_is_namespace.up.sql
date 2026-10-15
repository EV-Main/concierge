-- A tenant IS its namespace (`scopes.proto`, `Scope.namespace`: "Equal to `id` for every
-- scope but `main`"; `main` is never a row, `tenants_not_main`). Until now nothing held the
-- two together, and this plane keys by both: catalogs and clients by `tenant_id`, grants,
-- the catalog check and the scope roster by `namespace`. A row where they differ lets a
-- catalog be checked under one name and enforced under the other.
--
-- Every row written so far (the `sa` and `invest` seeds, 0026 and 0031) has id = namespace,
-- and the registry has no writer but migrations. A row that does not is named here rather
-- than left to the bare CHECK violation, so whoever meets it on boot knows which tenant to
-- look at; the migration then refuses and the binary does not start.
SET LOCAL lock_timeout = '3s';

DO $$
DECLARE
    split TEXT;
BEGIN
    SELECT string_agg(format('%s/%s', id, namespace), ', ' ORDER BY id) INTO split FROM tenants WHERE id <> namespace;
    IF split IS NOT NULL THEN
        RAISE EXCEPTION 'tenants whose namespace is not their id (id/namespace): %', split;
    END IF;
END
$$;

ALTER TABLE tenants ADD CONSTRAINT tenants_id_is_namespace CHECK (id = namespace);
