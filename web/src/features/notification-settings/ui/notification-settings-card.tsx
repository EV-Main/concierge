import { useT } from "@evinvest/i18n/react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle, ListRow, ListRows, Skeleton, Switch } from "@evinvest/uikit";
import { useEffect, useState } from "react";

import type { AuthAnswer } from "../../../shared/api/auth-api";
import { useElement } from "../../../shared/element/element-context";
import { readSettings, setChannel, type NotificationSettings } from "../api/notification-settings-api";
import { TopicRows } from "./topic-rows";

type Read = { kind: "loading" } | { kind: "ready"; settings: NotificationSettings } | { kind: "unavailable" } | { kind: "failed" };

/** Delivery channels and followed topics. Platform pages only. */
export function NotificationSettingsCard() {
  const t = useT();
  const { api } = useElement();
  const [read, setRead] = useState<Read>({ kind: "loading" });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let live = true;
    void readSettings(api).then((answer) => {
      if (!live) return;
      setRead(answer.ok ? { kind: "ready", settings: answer.body } : { kind: answer.error === "unavailable" ? "unavailable" : "failed" });
    });
    return () => {
      live = false;
    };
  }, [api]);

  async function write(request: () => Promise<AuthAnswer<NotificationSettings>>) {
    setBusy(true);
    setError(null);
    const answer = await request();
    setBusy(false);
    if (answer.ok) setRead({ kind: "ready", settings: answer.body });
    else setError(t("notif.saveFailed", "That change was not saved. Try again."));
  }

  if (read.kind === "unavailable" || read.kind === "failed") {
    const text = read.kind === "unavailable" ? t("notif.unavailable", "Notification settings are not available here yet.") : t("account.unavailable", "This could not be loaded. Try again in a moment.");
    return <p className="m-0 text-sm text-ink-soft">{text}</p>;
  }
  const settings = read.kind === "ready" ? read.settings : null;
  return (
    <div className="flex flex-col gap-4">
      <Card>
        <CardHeader>
          <CardTitle>{t("notif.delivery", "Delivery")}</CardTitle>
          <CardDescription>{t("notif.deliverySub", "Choose where notifications reach you. Both can be off.")}</CardDescription>
        </CardHeader>
        <CardContent>
          <ListRows>
            <ListRow label={t("notif.inApp", "In the app")} description={t("notif.inAppSub", "On by default. Turn this off and notifications stop appearing in your cabinet.")}>
              {settings ? <Switch checked={settings.inAppEnabled} disabled={busy} onCheckedChange={(v) => void write(() => setChannel(api, "in_app", v))} aria-label={t("notif.a11y.inApp", "In-app notifications")} /> : <Skeleton className="h-5 w-9 rounded-full" />}
            </ListRow>
            <ListRow
              label={t("ui.email", "Email")}
              description={settings ? (settings.emailVerified ? t("notif.emailVerified", "Sent to {email} · verified", { email: settings.email }) : t("notif.emailUnverified", "{email} · unverified, so email is not sent", { email: settings.email })) : undefined}
            >
              {settings ? <Switch checked={settings.emailEnabled} disabled={busy || !settings.emailVerified} onCheckedChange={(v) => void write(() => setChannel(api, "email", v))} aria-label={t("notif.a11y.email", "Email notifications")} /> : <Skeleton className="h-5 w-9 rounded-full" />}
            </ListRow>
          </ListRows>
        </CardContent>
      </Card>
      {settings && <TopicRows settings={settings} busy={busy} write={write} />}
      {error && <p role="alert" className="m-0 text-sm text-accent-error">{error}</p>}
    </div>
  );
}
