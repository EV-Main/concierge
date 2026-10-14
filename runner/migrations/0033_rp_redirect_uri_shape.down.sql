SET LOCAL lock_timeout = '3s';

ALTER TABLE rp_clients DROP CONSTRAINT rp_clients_redirect_uris_shape;
DROP FUNCTION rp_redirect_uris_wellformed(TEXT[]);
