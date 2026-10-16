import { useT } from "@evinvest/i18n/react";
import { KeyRound } from "lucide-react";
import type { ReactNode } from "react";

import { passkeysSupported } from "../../../shared/lib/webauthn";
import { PROVIDERS, type Provider } from "../api/sign-in-api";
import { SECONDARY } from "./parts";
import { GithubMark, GoogleMark } from "./provider-marks";

const LABEL: Record<Provider, string> = { google: "Google", github: "GitHub" };
const MARK: Record<Provider, ReactNode> = { google: <GoogleMark />, github: <GithubMark /> };

export function Providers({ hrefFor, onPasskey }: { hrefFor: (provider: Provider) => string; onPasskey: () => void }) {
  const t = useT();
  return (
    <>
      <div className="flex items-center gap-3.5 text-(length:--sign-in-text-fine) font-medium text-ink-soft">
        <span className="h-px flex-1 bg-ink/6" />
        {t("auth.orContinueWith", "Or continue with")}
        <span className="h-px flex-1 bg-ink/6" />
      </div>
      <div className="flex flex-col gap-2">
        {passkeysSupported() && (
          <button type="button" className={SECONDARY} onClick={onPasskey}>
            <KeyRound className="size-4" aria-hidden />
            {t("auth.usePasskey", "Use a passkey")}
          </button>
        )}
        {PROVIDERS.map((provider) => (
          // A full top-level navigation: the provider's consent screen is another origin.
          <a key={provider} href={hrefFor(provider)} className={SECONDARY}>
            {MARK[provider]}
            {LABEL[provider]}
          </a>
        ))}
      </div>
    </>
  );
}
