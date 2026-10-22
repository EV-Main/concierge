SET LOCAL lock_timeout = '3s';

ALTER TABLE rp_sessions DROP COLUMN auth_time;
ALTER TABLE rp_codes DROP COLUMN auth_time;
