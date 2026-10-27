import { useT } from "@evinvest/i18n/react";
import { Button } from "@evinvest/uikit";
import { ExternalLink } from "lucide-react";
import { useState, type ComponentType } from "react";

import { platformAccountUrl } from "../../../shared/config/origin";
import { useElement } from "../../../shared/element/element-context";
import { SECOND_FACTORS_CHANGED } from "../../../shared/element/events";
import { Enrolment, type ReauthSlotProps } from "./enrolment";

/**
 * The account has no factor that gives what the operation needs. Enrolment answers the
 * platform origin only, so on a scope host the reader sets it up there and comes back.
 */
export function StepupNoFactor({ reauth, onReady }: { reauth: ComponentType<ReauthSlotProps>; onReady: () => void }) {
  const t = useT();
  const { api, platform } = useElement();
  const [enrolling, setEnrolling] = useState(false);

  if (enrolling) {
    return (
      <ul className="m-0 flex list-none flex-col p-0">
        <Enrolment
          reauth={reauth}
          onEnrolled={() => {
            document.dispatchEvent(new Event(SECOND_FACTORS_CHANGED));
            onReady();
          }}
          onCancel={() => setEnrolling(false)}
        />
      </ul>
    );
  }
  return (
    <div className="flex flex-col gap-3">
      <p className="m-0 text-sm text-ink">{t("auth.stepup.required", "This operation needs two-step verification, and your account has no second factor for it yet.")}</p>
      {platform ? (
        <Button size="sm" className="self-start" onClick={() => setEnrolling(true)}>
          {t("auth.secondFactor.add", "Add authenticator app")}
        </Button>
      ) : (
        <div className="flex flex-wrap items-center gap-3">
          {/* `asChild`: the kit's `Button href` takes no `target` (shared/ui/manage-on-platform.tsx). */}
          <Button asChild variant="outline" size="sm" className="text-ink no-underline">
            <a href={platformAccountUrl(api.origin, "security")} target="_blank" rel="noopener noreferrer">
              {t("auth.stepup.setUp", "Set it up on evinvest.ltd")}
              <ExternalLink className="size-4" aria-hidden />
            </a>
          </Button>
          <Button size="sm" onClick={onReady}>
            {t("auth.stepup.tryAgain", "I've set it up — try again")}
          </Button>
        </div>
      )}
    </div>
  );
}
