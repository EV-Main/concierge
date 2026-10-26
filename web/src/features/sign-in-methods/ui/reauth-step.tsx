import { useT } from "@evinvest/i18n/react";
import { Button } from "@evinvest/uikit";
import { useEffect, useId, useRef, type ReactNode } from "react";

/**
 * The confirmation the plane asks for before a sensitive act on an old session. It takes
 * focus when it opens, so a keyboard reader lands on it rather than on the button that
 * opened it; `onCancel` hands focus back to whoever asked.
 */
export function ReauthStep({ sub, onCancel, children }: { sub: string; onCancel: () => void; children: ReactNode }) {
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
          <p className="m-0 text-xs text-ink-soft">{sub}</p>
        </div>
        {children}
        <Button variant="ghost" size="sm" className="self-start" onClick={onCancel}>
          {t("auth.reauth.cancel", "Cancel")}
        </Button>
      </section>
    </li>
  );
}
