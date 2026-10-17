-- Which approval authorized an operator-visible act on a person (reorganisation, expand step).
--
-- `admin_action.proposal_id` points at a legacy `user_proposal`; the decisions about people
-- now also pass through `approvals` (`concierge:owner_admission`, `concierge:user_suspension`,
-- ...), and an audit row for the act they carry out must name the decision that authorized it
-- the way the legacy row names its proposal.
--
-- Additive: a nullable column. A binary from before this migration never writes or reads it.
SET LOCAL lock_timeout = '3s';

ALTER TABLE admin_action ADD COLUMN approval_id UUID REFERENCES approvals (id);
CREATE INDEX admin_action_approval_idx ON admin_action (approval_id) WHERE approval_id IS NOT NULL;
