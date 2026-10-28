-- The step-up code's `binding`: 0049 kept it because v0.24.0 read it on every code path.
-- From v0.26.0 on no binary does.
SET LOCAL lock_timeout = '3s';

ALTER TABLE email_codes DROP COLUMN binding;
