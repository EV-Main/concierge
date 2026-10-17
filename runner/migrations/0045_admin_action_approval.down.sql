SET LOCAL lock_timeout = '3s';

-- Lossy: the link from an audit row to the approval that authorized it goes; the rows stay.
DROP INDEX admin_action_approval_idx;
ALTER TABLE admin_action DROP COLUMN approval_id;
