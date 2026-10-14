import { useT } from "@evinvest/i18n/react";
import { Dialog, DialogContent, Logo } from "@evinvest/uikit";

import { useElement } from "../../../shared/element/element-context";
import { passkeySignIn, passwordSignIn, passwordSignUp, requestCode, verifyCode } from "../api/sign-in-api";
import { errorText, oauthErrorText } from "../model/errors";
import { loginHref } from "../model/return-to";
import { firstScreen, useSignInFlow } from "../model/use-sign-in-flow";
import { CodeEntry } from "./code-entry";
import { CodeScreen } from "./code-screen";
import { PasswordScreen } from "./password-screen";
import { Providers } from "./providers";
import { SignUpScreen } from "./signup-screen";
import { VerifyStart } from "./verify-start";
import { Turnstile } from "../../../shared/ui/turnstile";

export interface SignInDialogProps {
  open: boolean;
  intent: string | null;
  returnTo: string | null;
  sitekey: string | null;
  /** `?auth_error=` an OAuth round trip left on the page. */
  oauthError: string | null;
  onDismiss: () => void;
  onSignedIn: () => void;
}

/**
 * "Sign in or create an account" — one dialog for every method, over the host's page.
 * The element remounts it on every opening, so each one starts on its first screen.
 */
export function SignInDialog({ open, intent, returnTo, sitekey, oauthError, onDismiss, onSignedIn }: SignInDialogProps) {
  const t = useT();
  const { api } = useElement();
  const flow = useSignInFlow(firstScreen(intent));
  const { screen, busy, human, go, run, spending, setError } = flow;
  const settle = (answer: { ok: true } | { ok: false; error: Parameters<typeof errorText>[1] }) => (answer.ok ? onSignedIn() : setError(errorText(t, answer.error)));

  const challenge = <Turnstile sitekey={sitekey} generation={flow.generation} onToken={flow.setToken} onUnavailable={() => flow.captchaFailed(errorText(t, "captcha_load"))} />;
  const shown = flow.error ?? (screen.kind === "code" && oauthError ? oauthErrorText(t, oauthError) : null);

  return (
    <Dialog open={open} onOpenChange={(next) => !next && !busy && onDismiss()}>
      <DialogContent className="max-w-[min(25rem,calc(100%-2rem))] gap-6 rounded-2xl px-7 pt-8 pb-7 sm:max-w-100">
        <Logo className="mx-auto h-7 w-auto text-ink" />
        {screen.kind === "code" && (
          <CodeScreen
            busy={busy}
            human={human}
            challenge={challenge}
            onSubmit={(email) =>
              run(async () => {
                const answer = await spending((tk) => requestCode(api, email, tk));
                if (answer.ok) go({ kind: "codeSent", email });
                else setError(errorText(t, answer.error));
              })
            }
            onPassword={() => go({ kind: "password" })}
          >
            <Providers hrefFor={(provider) => loginHref(api.origin, provider, returnTo)} onPasskey={() => run(async () => settle(await passkeySignIn(api)))} />
          </CodeScreen>
        )}
        {screen.kind === "codeSent" && (
          <CodeEntry
            title={t("auth.code.title", "Check your email")}
            description={t("auth.code.desc", "We sent a 6 digit sign in code to {email}", { email: screen.email })}
            busy={busy}
            human={human}
            challenge={challenge}
            onCode={(code) => run(async () => settle(await verifyCode(api, screen.email, code)))}
            onResend={() =>
              run(async () => {
                const answer = await spending((tk) => requestCode(api, screen.email, tk));
                if (!answer.ok) setError(errorText(t, answer.error));
              })
            }
            onBack={() => go({ kind: "code" })}
          />
        )}
        {screen.kind === "password" && (
          <PasswordScreen
            busy={busy}
            human={human}
            challenge={challenge}
            onSubmit={(identifier, password) => run(async () => settle(await spending((tk) => passwordSignIn(api, identifier, password, tk))))}
            onCode={() => go({ kind: "code" })}
            onSignUp={() => go({ kind: "signup" })}
          />
        )}
        {screen.kind === "signup" && (
          <SignUpScreen
            busy={busy}
            human={human}
            challenge={challenge}
            onSubmit={(email, password, verify) =>
              run(async () => {
                const answer = await spending((tk) => passwordSignUp(api, email, password, tk));
                if (!answer.ok) return setError(errorText(t, answer.error));
                if (verify) go({ kind: "verifyNow", email });
                else onSignedIn();
              })
            }
            onSignIn={() => go({ kind: "password" })}
          />
        )}
        {screen.kind === "verifyNow" && (
          <VerifyStart
            email={screen.email}
            busy={busy}
            human={human}
            challenge={challenge}
            onSend={() =>
              run(async () => {
                const answer = await spending((tk) => requestCode(api, screen.email, tk));
                if (answer.ok) go({ kind: "verifyCode", email: screen.email });
                else setError(errorText(t, answer.error));
              })
            }
            onLater={onSignedIn}
          />
        )}
        {screen.kind === "verifyCode" && (
          <CodeEntry
            title={t("auth.verify.title", "Confirm your email")}
            description={t("auth.code.desc", "We sent a 6 digit sign in code to {email}", { email: screen.email })}
            busy={busy}
            human={human}
            challenge={challenge}
            onCode={(code) => run(async () => settle(await verifyCode(api, screen.email, code)))}
            onResend={() =>
              run(async () => {
                const answer = await spending((tk) => requestCode(api, screen.email, tk));
                if (!answer.ok) setError(errorText(t, answer.error));
              })
            }
            onBack={onSignedIn}
            backLabel={t("auth.verify.later", "Verify later")}
          />
        )}
        {shown && (
          <p role="status" className="-mt-3 mb-0 text-center text-xs leading-snug text-accent-error">
            {shown}
          </p>
        )}
      </DialogContent>
    </Dialog>
  );
}
