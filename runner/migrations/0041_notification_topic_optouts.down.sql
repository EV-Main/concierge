-- Lossy: who switched a topic off is forgotten, and a `default_subscribed` topic follows
-- them again once a binary that applies the default runs.
SET LOCAL lock_timeout = '3s';

DROP TABLE notification_topic_optouts;
