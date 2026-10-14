import { useT } from "@evinvest/i18n/react";
import { Skeleton, Tabs, TabsContent, TabsList, TabsTrigger } from "@evinvest/uikit";

import { ProfileCard } from "../../../features/account-profile";
import { NotificationSettingsCard } from "../../../features/notification-settings";
import type { AccountSection } from "../../../shared/config/origin";
import { useElement } from "../../../shared/element/element-context";
import { offerLinkToHost } from "../../../shared/element/offer-link";
import { useSession } from "../../../shared/model/use-session";
import { ManageOnPlatform } from "../../../shared/ui/manage-on-platform";
import { SecurityTab } from "./security-tab";

const SECTIONS: readonly AccountSection[] = ["profile", "security", "notifications"];

export function sectionOf(raw: string | null): AccountSection {
  return SECTIONS.find((s) => s === raw) ?? "profile";
}

/**
 * The account page a host mounts on its own `/account`: profile, security, notifications.
 * It never redirects: signed out, it says so and leaves sign-in to the host.
 */
export function AccountView({ section, onSection }: { section: AccountSection; onSection: (next: AccountSection) => void }) {
  const t = useT();
  const { api, host, platform } = useElement();
  const { session, refresh } = useSession(api);

  if (session.kind === "loading") return <Skeleton className="h-64 w-full rounded-xl" />;
  if (session.kind !== "signedIn") {
    const text = session.kind === "anonymous" ? t("account.signedOut", "Sign in to see your account.") : t("account.unavailable", "This could not be loaded. Try again in a moment.");
    return <p className="m-0 text-sm text-ink-soft">{text}</p>;
  }

  const labels: Record<AccountSection, string> = { profile: t("ui.profile", "Profile"), security: t("ui.security", "Security"), notifications: t("ui.notifications", "Notifications") };
  return (
    <div className="flex w-full min-w-0 flex-col gap-4" onClick={(e) => offerLinkToHost(e, host)}>
      <Tabs value={section} onValueChange={(v) => onSection(sectionOf(v))}>
        <TabsList>
          {SECTIONS.map((s) => (
            <TabsTrigger key={s} value={s}>
              {labels[s]}
            </TabsTrigger>
          ))}
        </TabsList>
        <TabsContent value="profile">
          <ProfileCard user={session.user} />
        </TabsContent>
        <TabsContent value="security">
          <SecurityTab onChanged={() => void refresh()} />
        </TabsContent>
        <TabsContent value="notifications">{platform ? <NotificationSettingsCard /> : <ManageOnPlatform section="notifications" title={labels.notifications} />}</TabsContent>
      </Tabs>
    </div>
  );
}
