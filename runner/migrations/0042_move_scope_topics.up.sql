-- Two topics this plane used to own move to the scope that emits on them
-- (docs/SCOPES-AND-APPROVALS.md §6, D21): `fund:quy-nhon` → `invest:fund:quy-nhon`,
-- `account:money-movement` → `bank:money-movement`. What a subscriber chose travels with
-- it, account-less subscribers included; where one already follows the new key, that row
-- stands and the old one goes.
--
-- The fund's inbox history moves too, so it shows where the topic now lives. The
-- `account:money-movement` rows do NOT: nothing ever emitted on that key — every row under
-- it is a trace this plane wrote itself (a payment consent, a fee notice, a decision opened
-- in someone's name), and it stays this plane's trace topic, written by this binary and by
-- the previous one alike.
--
-- Until the emitters move, the binary takes an old key wherever a topic is named and stands
-- it for the new one; that alias is dropped at the contract step (ORG-RESTRUCTURE-PLAN §12).
SET LOCAL lock_timeout = '3s';

DELETE FROM notification_subscriptions stale
 WHERE stale.topic = 'fund:quy-nhon'
   AND EXISTS (SELECT 1 FROM notification_subscriptions fresh WHERE fresh.subscriber_id = stale.subscriber_id AND fresh.topic = 'invest:fund:quy-nhon');
UPDATE notification_subscriptions SET topic = 'invest:fund:quy-nhon', updated_at = now() WHERE topic = 'fund:quy-nhon';

DELETE FROM notification_subscriptions stale
 WHERE stale.topic = 'account:money-movement'
   AND EXISTS (SELECT 1 FROM notification_subscriptions fresh WHERE fresh.subscriber_id = stale.subscriber_id AND fresh.topic = 'bank:money-movement');
UPDATE notification_subscriptions SET topic = 'bank:money-movement', updated_at = now() WHERE topic = 'account:money-movement';

UPDATE notifications SET topic = 'invest:fund:quy-nhon' WHERE topic = 'fund:quy-nhon';
