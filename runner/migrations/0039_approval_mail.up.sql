-- The approval mail (`docs/SCOPES-AND-APPROVALS.md` §5.5): typed rows in the governance
-- queue, rendered by this plane's own templates from the kind's labels and typed fields.
--
--   notification_deliveries.kind — two more kinds: `approval_request` (to each roster
--                                  member, queued in the transaction that opens the
--                                  proposal) and `approval_outcome` (to `requested_by`).
--   approvals.mailed_state       — the last state `requested_by` was told about. The
--                                  outcome mail is queued by a sweep, not by the act that
--                                  ends the proposal: an expiry and a lapse are LAZY (no act
--                                  writes them until somebody touches the proposal) and the
--                                  void on a change of the owners is written by a trigger
--                                  (0038), so no single code path sees every ending.
--
-- WHY A BACKFILL HERE: every proposal already decided would otherwise read as "not yet
-- told" and its requester would get a mail about a decision of days ago. The table is the
-- approvals of one release; the UPDATE is one statement over a few rows. It projects the
-- lazy endings the way `Decision::effective_state` does (72 h execution window).
SET LOCAL lock_timeout = '3s';

ALTER TABLE notification_deliveries DROP CONSTRAINT notification_deliveries_kind;
ALTER TABLE notification_deliveries ADD CONSTRAINT notification_deliveries_kind
    CHECK (kind IN ('notification', 'confirm', 'owner_removal_self_accept', 'payout_approval', 'payout_outcome', 'payment_consent', 'payment_approval', 'fee_policy_approval', 'fee_policy_notice', 'kyc_verdict_alert', 'payment_outcome', 'email_code', 'approval_request', 'approval_outcome'));

ALTER TABLE approvals ADD COLUMN mailed_state TEXT;

UPDATE approvals SET mailed_state = CASE
    WHEN state = 'open' AND expires_at <= floor(extract(epoch FROM clock_timestamp()))::BIGINT THEN 'expired'
    WHEN state = 'passed' AND executable_at + 259200 <= floor(extract(epoch FROM clock_timestamp()))::BIGINT THEN 'void'
    WHEN state = 'open' THEN NULL
    ELSE state
END;
