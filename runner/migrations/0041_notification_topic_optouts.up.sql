-- "Switched a topic off" becomes a row. Until now an unsubscribe deleted the subscription,
-- so an account that never touched a topic and one that turned it off read the same — and
-- a scope topic published with `default_subscribed` could not be applied without following
-- it again for everyone who had left it.
--
-- A table of its own, not a flag on `notification_subscriptions`: the previous binary reads
-- every row there as "following", so during the rollout and after an image rollback it would
-- mail everyone who had switched the topic off. Unsubscribing still deletes the subscription
-- row, and an older binary keeps reading exactly what it read before.
--
-- Numbered 0041: 0040 is taken by `tenant_id_is_namespace` on a parallel branch.
SET LOCAL lock_timeout = '3s';

CREATE TABLE notification_topic_optouts (
    subscriber_id UUID NOT NULL REFERENCES notification_subscribers (id),
    topic         TEXT NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (subscriber_id, topic),
    CONSTRAINT notification_topic_optouts_topic_len CHECK (char_length(topic) <= 64)
);
