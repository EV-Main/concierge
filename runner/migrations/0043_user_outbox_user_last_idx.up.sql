-- Serves "last outbox row per user" (`ORDER BY position DESC LIMIT 1` per `user_id`), which
-- `announce_seats` runs for every user on every boot. Without it the lateral walks the
-- `position` index backwards or seq-scans the outbox.
--
-- Plain CREATE INDEX, not CONCURRENTLY: sqlx runs each migration in a transaction, and
-- CONCURRENTLY cannot run inside one. The build blocks outbox writes for its duration;
-- at today's outbox volume that is well under the lock budget. Revisit (no-transaction
-- migration) if the outbox grows large before this ships.
SET LOCAL lock_timeout = '3s';

CREATE INDEX IF NOT EXISTS user_outbox_user_last_idx ON user_outbox (user_id, position DESC);
