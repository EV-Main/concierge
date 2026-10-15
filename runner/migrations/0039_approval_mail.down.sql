-- Lossy: queued approval mail not yet sent is dropped (the previous binary cannot render
-- it and would park it), and which outcomes were already told is forgotten.
SET LOCAL lock_timeout = '3s';

ALTER TABLE approvals DROP COLUMN mailed_state;
DELETE FROM notification_deliveries WHERE kind IN ('approval_request', 'approval_outcome');
ALTER TABLE notification_deliveries DROP CONSTRAINT notification_deliveries_kind;
ALTER TABLE notification_deliveries ADD CONSTRAINT notification_deliveries_kind
    CHECK (kind IN ('notification', 'confirm', 'owner_removal_self_accept', 'payout_approval', 'payout_outcome', 'payment_consent', 'payment_approval', 'fee_policy_approval', 'fee_policy_notice', 'kyc_verdict_alert', 'payment_outcome', 'email_code'));
