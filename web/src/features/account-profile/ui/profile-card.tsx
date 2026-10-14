import { useT } from "@evinvest/i18n/react";
import { Avatar, AvatarFallback, Badge, Card, CardContent, ListRow, ListRows } from "@evinvest/uikit";

import type { SessionUser } from "../../../shared/api/session";
import { displayName, initialsOfName } from "../../../shared/lib/identity";

/**
 * Who the reader is, from the platform session — the one account read a scope host may
 * make. Personal details (legal name, phone, address…) are not here: concierge exposes no
 * HTTP route for them yet, and part of them moves to the scopes (ORG-RESTRUCTURE-PLAN §4.5).
 */
export function ProfileCard({ user }: { user: SessionUser }) {
  const t = useT();
  const name = user.username ?? displayName(user.email, t);
  return (
    <Card>
      <CardContent className="flex flex-col gap-4">
        <div className="flex min-w-0 items-center gap-3">
          <Avatar className="size-12">
            <AvatarFallback className="bg-primary-ink/15 font-semibold text-primary-ink">{initialsOfName(user.username ?? "", user.email)}</AvatarFallback>
          </Avatar>
          <div className="flex min-w-0 flex-col">
            <span className="truncate text-base font-semibold text-ink">{name}</span>
            <span className="truncate text-sm text-ink-soft">{user.email}</span>
          </div>
        </div>
        <ListRows>
          <ListRow label={t("ui.email", "Email")} description={user.email}>
            <Badge variant={user.emailVerified ? "success" : "outline"}>{user.emailVerified ? t("auth.email.verified", "Verified") : t("auth.email.unverified", "Not verified")}</Badge>
          </ListRow>
          <ListRow label={t("auth.username.title", "Username")} value={user.username ? `@${user.username}` : t("account.none", "None")} />
        </ListRows>
      </CardContent>
    </Card>
  );
}
