import { useT } from "@evinvest/i18n/react";
import { Badge, Button, Card, CardContent, CardDescription, CardHeader, CardTitle, ListRow, ListRows, Skeleton, Spinner } from "@evinvest/uikit";

import { deviceOf, metaOf } from "../model/device";
import { useSessions } from "../model/use-sessions";

/** Where the account is signed in; revoke anything not recognised. Platform pages only. */
export function SessionsCard() {
  const t = useT();
  const { sessions, error, busy, revoke, revokeOthers } = useSessions();
  const hasOthers = (sessions ?? []).some((s) => !s.current);
  return (
    <Card>
      <CardHeader>
        <CardTitle>{t("ui.sessionsDevices", "Sessions & devices")}</CardTitle>
        <CardDescription>{t("settings.sessionsSub", "Where you're signed in — revoke anything you don't recognise")}</CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-3">
        {error && <p role="alert" className="m-0 text-sm text-accent-error">{error}</p>}
        {sessions === undefined ? (
          <Skeleton className="h-12 w-full" />
        ) : sessions === null ? (
          <p className="m-0 text-sm text-ink-soft">{t("account.unavailable", "This could not be loaded. Try again in a moment.")}</p>
        ) : sessions.length === 0 ? (
          <p className="m-0 text-center text-sm text-ink-soft">{t("settings.noSessions", "No active sessions.")}</p>
        ) : (
          <ListRows>
            {sessions.map((s) => {
              const { label, icon: Icon } = deviceOf(s.userAgent, t);
              return (
                // Wraps below `sm`: side by side, the device and its meta line were clipped on a phone.
                <ListRow key={s.id} className="flex-wrap">
                  <div className="flex min-w-0 flex-1 items-start gap-3">
                    <span className="flex size-9 shrink-0 items-center justify-center rounded-lg border border-border bg-secondary text-ink">
                      <Icon className="size-4.5" aria-hidden />
                    </span>
                    <div className="min-w-0 flex-1">
                      <p className="m-0 text-sm font-medium text-ink">{label}</p>
                      <p className="m-0 break-words text-xs leading-snug text-ink-soft">{metaOf(s, t)}</p>
                    </div>
                  </div>
                  {s.current ? (
                    <Badge variant="outline">{t("settings.thisDevice", "This device")}</Badge>
                  ) : (
                    <Button variant="outline" size="sm" disabled={busy} onClick={() => void revoke(s.id)}>
                      {t("settings.revoke", "Revoke")}
                    </Button>
                  )}
                </ListRow>
              );
            })}
          </ListRows>
        )}
        {hasOthers && (
          <Button variant="outline" disabled={busy} onClick={() => void revokeOthers()} className="w-full min-w-0 shrink truncate">
            {busy && <Spinner aria-hidden />} {t("settings.signOutOthers", "Sign out all other devices")}
          </Button>
        )}
      </CardContent>
    </Card>
  );
}
