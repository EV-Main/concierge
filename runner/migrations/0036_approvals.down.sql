-- Lossy: every proposal, its frozen roster, the votes and the history go. A proposer
-- still holding an approval id finds nothing under it and has to propose again.
SET LOCAL lock_timeout = '3s';

DROP TABLE approval_events;
DROP TABLE approval_voters;
DROP TABLE approvals;
