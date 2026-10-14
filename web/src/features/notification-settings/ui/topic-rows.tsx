import { useT } from "@evinvest/i18n/react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle, ListRow, ListRows, Switch, Toggle } from "@evinvest/uikit";

import type { AuthAnswer } from "../../../shared/api/auth-api";
import { useElement } from "../../../shared/element/element-context";
import { setTopic, type NotificationSettings } from "../api/notification-settings-api";

export function TopicRows({ settings, busy, write }: { settings: NotificationSettings; busy: boolean; write: (request: () => Promise<AuthAnswer<NotificationSettings>>) => Promise<void> }) {
  const t = useT();
  const { api } = useElement();
  return (
    <Card>
      <CardHeader>
        <CardTitle>{t("notif.whatYouFollow", "What you follow")}</CardTitle>
        <CardDescription>{t("notif.topicsSub", "Email a copy for these. Unsubscribing is one click — no confirmation step.")}</CardDescription>
      </CardHeader>
      <CardContent>
        <ListRows>
          {settings.topics.map((topic) => (
            // Topic label and description are server copy, rendered verbatim.
            <ListRow key={topic.topic} label={topic.label} description={topic.description} className="flex-wrap">
              <div className="flex shrink-0 items-center gap-3">
                {/* A pressed/unpressed pair: "Following" is a state the reader is in, and aria-pressed says so. */}
                <Toggle variant="outline" size="xs" pressed={topic.subscribed} disabled={busy} onPressedChange={(pressed) => void write(() => setTopic(api, topic.topic, pressed, topic.emailEnabled))} className="px-3 text-xs">
                  {topic.subscribed ? t("notif.following", "Following") : t("notif.follow", "Follow")}
                </Toggle>
                <Switch
                  checked={topic.subscribed && topic.emailEnabled && settings.emailEnabled}
                  disabled={busy || !topic.subscribed || !settings.emailEnabled}
                  onCheckedChange={(v) => void write(() => setTopic(api, topic.topic, true, v))}
                  aria-label={t("notif.a11y.emailCopyFor", "Email copy for {topic}", { topic: topic.label })}
                />
              </div>
            </ListRow>
          ))}
        </ListRows>
      </CardContent>
    </Card>
  );
}
