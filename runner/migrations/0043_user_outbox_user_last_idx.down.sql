-- The index is purely an accelerator; dropping it changes no results, only boot-time cost.
SET LOCAL lock_timeout = '3s';

DROP INDEX IF EXISTS user_outbox_user_last_idx;
