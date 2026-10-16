import { useT } from "@evinvest/i18n/react";
import { cn } from "@evinvest/uikit";
import type { MouseEvent } from "react";

import { BUILD } from "../../../shared/config/build";
import { useElement } from "../../../shared/element/element-context";
import { loginHref } from "../../../shared/lib/return-to";
import { CHIP_FOCUS } from "../lib/chip-parts";
import { openSignIn } from "../lib/open-sign-in";

/**
 * Signed out — the sign-in CTA. A primary-ink outline pill by hand rather than the uikit
 * `Button`, as in the cabinet: the colours the hover changes start as arbitrary properties
 * so a host's own primary-ink text utility cannot pin them (chip-parts.ts).
 *
 * The click opens the platform's dialog over the page; the href is the fallback when the
 * dialog cannot be loaded (or JavaScript is off): the platform's OAuth login coming back
 * to this host — an absolute URL off the platform, or the platform would land on its own
 * page of the same path.
 */
export function SignInCta({ intent, returnTo, onSignedIn }: { intent: string | null; returnTo: string | null; onSignedIn: () => void }) {
  const t = useT();
  const { api } = useElement();
  const fallback = loginHref(api.origin, null, returnTo);

  const open = (e: MouseEvent<HTMLAnchorElement>) => {
    if (e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
    e.preventDefault();
    void openSignIn({ origin: api.origin, registryPath: BUILD.registryPath, intent, returnTo, onSignedIn }).then((opened) => {
      if (!opened) location.assign(fallback);
    });
  };

  return (
    // i18n-max: 20 — a fixed-height pill in a host's header row, `px-4` and no truncation.
    <a
      href={fallback}
      onClick={open}
      data-cta="sign-in"
      className={cn(
        "inline-flex h-9 items-center justify-center rounded-md! border! [border-color:var(--color-primary-ink)]! [background-color:transparent]! px-4! font-mono text-xs tracking-wider [color:var(--color-primary-ink)]! tabular-nums transition-all hover:border-primary! hover:bg-primary! hover:text-on-primary!",
        CHIP_FOCUS,
      )}
    >
      {t("auth.signIn", "Sign in")}
    </a>
  );
}
