import { useT } from "@evinvest/i18n/react";
import { Dialog, DialogContent, Logo } from "@evinvest/uikit";

import { useElement } from "../../../shared/element/element-context";
import { confirmSignUp, passkeySignIn, passwordSignIn, passwordSignUp, requestCode, resendSignUpCode, verifyCode } from "../api/sign-in-api";
import { errorText, oauthErrorText } from "../model/errors";
import { loginHref } from "../model/return-to";
import { firstScreen, useSignInFlow } from "../model/use-sign-in-flow";
import { CodeEntry } from "./code-entry";
import { CodeScreen } from "./code-screen";
import { ConfirmOnPlatform } from "./confirm-on-platform";
import { PasswordScreen } from "./password-screen";
import { Providers } from "./providers";
import { SignUpScreen } from "./signup-screen";
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
  const signedUp = screen.kind === "confirmSignUp" || screen.kind === "confirmOnPlatform";
  const shown = flow.error ?? (screen.kind === "code" && oauthError ? oauthErrorText(t, oauthError) : null);

  return (
    // Past sign-up the account is already signed in: closing the confirmation must still tell the host.
    <Dialog open={open} onOpenChange={(next) => !next && !busy && (signedUp ? onSignedIn() : onDismiss())}>
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
                const answer = await spending((tk) => passwordSignUp(api, email, password, verify, tk));
                if (!answer.ok) return setError(errorText(t, answer.error));
                // Signed in either way. Any ticket means the address can be confirmed here, even
                // when the first code did not go out; no ticket after asking to verify sends the
                // reader to the platform.
                const { verification, ticket, ticketLost } = answer.body;
                if (ticket) go({ kind: "confirmSignUp", email, ticket, sent: verification === "sent" });
                else if (ticketLost) go({ kind: "confirmOnPlatform" });
                else onSignedIn();
              })
            }
            onSignIn={() => go({ kind: "password" })}
          />
        )}
        {screen.kind === "confirmSignUp" && (
          <CodeEntry
            title={t("auth.verify.title", "Confirm your email")}
            description={
              screen.sent
                ? t("auth.verify.desc", "Your account is ready. Enter the 6 digit code we sent to {email} to verify it, or skip and verify later in Settings.", { email: screen.email })
                : t("auth.verify.notSent", "Your account is ready, but the code to {email} was not sent. Send it again to verify your email, or skip and verify later.", { email: screen.email })
            }
            resendNow={!screen.sent}
            busy={busy}
            human={human}
            challenge={challenge}
            onCode={(code) => run(async () => settle(await confirmSignUp(api, screen.ticket, code)))}
            onResend={() =>
              run(async () => {
                const answer = await spending((tk) => resendSignUpCode(api, screen.ticket, tk));
                if (!answer.ok) setError(errorText(t, answer.error));
                else if (!screen.sent) go({ ...screen, sent: true });
              })
            }
            onBack={onSignedIn}
            backLabel={t("auth.verify.later", "Verify later")}
          />
        )}
        {screen.kind === "confirmOnPlatform" && <ConfirmOnPlatform onDone={onSignedIn} />}
        {shown && (
          <p role="status" className="-mt-3 mb-0 text-center text-xs leading-snug text-accent-error">
            {shown}
          </p>
        )}
      </DialogContent>
    </Dialog>
  );
}
