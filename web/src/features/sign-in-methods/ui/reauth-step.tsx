import { useT } from "@evinvest/i18n/react";
import { Button } from "@evinvest/uikit";
import { useEffect, useId, useRef } from "react";

import type { ReauthMethod } from "../model/reauth";
import { ReauthMethods } from "./reauth-methods";

/**
 * The confirmation the plane asks for before a sensitive act on an old session. It takes
 * focus when it opens, so a keyboard reader lands on it rather than on the button that
 * opened it; `onCancel` hands focus back to whoever asked.
 */
export function ReauthStep({ methods, onConfirmed, onCancel }: { methods: ReauthMethod[]; onConfirmed: () => void; onCancel: () => void }) {
  const t = useT();
  const titleId = useId();
  const panel = useRef<HTMLElement>(null);

  useEffect(() => {
    panel.current?.focus();
  }, []);

  return (
    <li className="list-none pb-3">
      <section ref={panel} tabIndex={-1} aria-labelledby={titleId} className="flex flex-col gap-3 rounded-md border border-ink/10 p-3">
        <div className="flex flex-col gap-1">
          <h3 id={titleId} className="m-0 text-sm font-semibold">
            {t("auth.reauth.title", "Confirm it is you")}
          </h3>
          <p className="m-0 text-xs text-ink-soft">{t("auth.reauth.sub", "You signed in a while ago. Confirm again to change your passkeys.")}</p>
        </div>
        <ReauthMethods methods={methods} onConfirmed={onConfirmed} />
        <Button variant="ghost" size="sm" className="self-start" onClick={onCancel}>
          {t("auth.reauth.cancel", "Cancel")}
        </Button>
      </section>
    </li>
  );
}
