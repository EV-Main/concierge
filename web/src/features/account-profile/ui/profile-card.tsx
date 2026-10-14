import { useT } from "@evinvest/i18n/react";
import { Alert, AlertDescription, Avatar, AvatarFallback, Badge, Card, CardContent, ListRow, ListRows, Skeleton } from "@evinvest/uikit";

import type { SessionUser } from "../../../shared/api/session";
import { displayName, initialsOfName } from "../../../shared/lib/identity";
import { useProfile } from "../model/use-profile";

/**
 * Who the reader is. Personal details (legal name, phone, address…) are not here: the
 * plane serves no identity-document fields to a browser, and part of them moves to the
 * scopes (ORG-RESTRUCTURE-PLAN §4.5).
 */
export function ProfileCard({ user }: { user: SessionUser }) {
  const t = useT();
  const profile = useProfile(user);
  if (!profile) return <Skeleton className="h-48 w-full rounded-xl" />;
  const name = profile.preferredName ?? profile.username ?? displayName(profile.email, t);
  return (
    <Card>
      <CardContent className="flex flex-col gap-4">
        {profile.breakGlass && (
          <Alert variant="destructive">
            <AlertDescription>{t("account.breakGlass", "Your role comes from emergency access, not from your account. It is temporary and is not a seat.")}</AlertDescription>
          </Alert>
        )}
        <div className="flex min-w-0 items-center gap-3">
          <Avatar className="size-12">
            <AvatarFallback className="bg-primary-ink/15 font-semibold text-primary-ink">{initialsOfName(profile.preferredName ?? profile.username ?? "", profile.email)}</AvatarFallback>
          </Avatar>
          <div className="flex min-w-0 flex-col">
            <span className="truncate text-base font-semibold text-ink">{name}</span>
            <span className="truncate text-sm text-ink-soft">{profile.email}</span>
          </div>
        </div>
        <ListRows>
          <ListRow label={t("ui.email", "Email")} description={profile.email}>
            <Badge variant={profile.emailVerified ? "success" : "outline"}>{profile.emailVerified ? t("auth.email.verified", "Verified") : t("auth.email.unverified", "Not verified")}</Badge>
          </ListRow>
          <ListRow label={t("auth.username.title", "Username")} value={profile.username ? `@${profile.username}` : t("account.none", "None")} />
          {profile.kycLevel !== null && <ListRow label={t("account.kycLevel", "Verification level")} value={t("account.kycLevelValue", "Level {level}", { level: profile.kycLevel })} />}
        </ListRows>
      </CardContent>
    </Card>
  );
}
