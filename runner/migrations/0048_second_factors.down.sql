SET LOCAL lock_timeout = '3s';

-- The older constraints cannot hold a `security_notice` row.
DELETE FROM notification_deliveries WHERE kind = 'security_notice';
ALTER TABLE notification_deliveries DROP CONSTRAINT notification_deliveries_kind;
ALTER TABLE notification_deliveries ADD CONSTRAINT notification_deliveries_kind
    CHECK (kind IN ('notification', 'confirm', 'owner_removal_self_accept', 'payout_approval', 'payout_outcome', 'payment_consent', 'payment_approval', 'fee_policy_approval', 'fee_policy_notice', 'kyc_verdict_alert', 'payment_outcome', 'email_code', 'approval_request', 'approval_outcome'));
ALTER TABLE notification_deliveries DROP CONSTRAINT notification_deliveries_subscriber;
ALTER TABLE notification_deliveries ADD CONSTRAINT notification_deliveries_subscriber CHECK (subscriber_id IS NOT NULL OR kind = 'email_code');

DROP TABLE second_factor_guard;
DROP TABLE second_factor_recovery_codes;
DROP TABLE second_factors;
