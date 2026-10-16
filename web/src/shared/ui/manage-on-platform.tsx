import { useT } from "@evinvest/i18n/react";
import { Button, Card, CardContent, CardDescription, CardHeader, CardTitle } from "@evinvest/uikit";
import { ExternalLink } from "lucide-react";

import { platformAccountUrl, type AccountSection } from "../config/origin";
import { useElement } from "../element/element-context";

/**
 * What a scope host shows in place of an action on the session: the platform's own account
 * page, in a new tab. The plane accepts those actions from its origin only (§3.9 F), and
 * a new tab keeps the reader's place on the host.
 */
export function ManageOnPlatform({ section, title }: { section: AccountSection; title: string }) {
  const t = useT();
  const { api } = useElement();
  return (
    <Card>
      <CardHeader>
        <CardTitle>{title}</CardTitle>
        <CardDescription>{t("account.managedOnPlatform", "These settings are managed on evinvest.ltd, where your account lives.")}</CardDescription>
      </CardHeader>
      <CardContent>
        {/* `asChild`: the kit's `Button href` takes no `target`. The outline variant sets no
            text colour or decoration, so without them a host with no preflight paints the
            user agent's link blue and underline. */}
        <Button asChild variant="outline" className="text-ink no-underline">
          <a href={platformAccountUrl(api.origin, section)} target="_blank" rel="noopener noreferrer">
            {t("account.openOnPlatform", "Open on evinvest.ltd")}
            <ExternalLink className="size-4" aria-hidden />
          </a>
        </Button>
      </CardContent>
    </Card>
  );
}
