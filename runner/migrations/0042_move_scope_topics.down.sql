-- Back under the old keys. Lossy where a subscriber followed both: one row survives, the
-- old key's. Anything followed on the new keys since — natively, not through the move —
-- comes back under the old ones too, which is what the previous binary offers.
SET LOCAL lock_timeout = '3s';

DELETE FROM notification_subscriptions fresh
 WHERE fresh.topic = 'invest:fund:quy-nhon'
   AND EXISTS (SELECT 1 FROM notification_subscriptions stale WHERE stale.subscriber_id = fresh.subscriber_id AND stale.topic = 'fund:quy-nhon');
UPDATE notification_subscriptions SET topic = 'fund:quy-nhon', updated_at = now() WHERE topic = 'invest:fund:quy-nhon';

DELETE FROM notification_subscriptions fresh
 WHERE fresh.topic = 'bank:money-movement'
   AND EXISTS (SELECT 1 FROM notification_subscriptions stale WHERE stale.subscriber_id = fresh.subscriber_id AND stale.topic = 'account:money-movement');
UPDATE notification_subscriptions SET topic = 'account:money-movement', updated_at = now() WHERE topic = 'bank:money-movement';

UPDATE notifications SET topic = 'fund:quy-nhon' WHERE topic = 'invest:fund:quy-nhon';

-- Opt-outs (0041) are kept under whichever key they were written.
