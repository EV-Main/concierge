import { useState } from "react";

import type { AuthAnswer } from "../../../shared/api/auth-api";

export type Screen =
  | { kind: "code" }
  | { kind: "codeSent"; email: string }
  | { kind: "password" }
  | { kind: "signup" }
  /** Signed up and asked to verify now: mail the code (it needs a fresh Turnstile token). */
  | { kind: "verifyNow"; email: string }
  | { kind: "verifyCode"; email: string };

/** `data-intent`: `signup` opens the sign-up screen; `signin` and `login` (the chip's word) the code screen. */
export function firstScreen(intent: string | null): Screen {
  return intent === "signup" ? { kind: "signup" } : { kind: "code" };
}

/**
 * The dialog's step, its one error line, the busy flag, and the Turnstile token. A token is
 * single-use: whoever spends it bumps `generation` and the widget re-arms.
 */
export function useSignInFlow(initial: Screen) {
  const [screen, setScreen] = useState<Screen>(initial);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [token, setToken] = useState<string | null>(null);
  const [generation, setGeneration] = useState(0);
  const [captchaBroken, setCaptchaBroken] = useState(false);

  function go(next: Screen) {
    setError(null);
    setScreen(next);
  }

  /**
   * Send the challenge token with one request. The plane refuses `origin` and
   * `captcha_unavailable` before Cloudflare consumed it, so those leave it for the retry;
   * anything else spent it.
   */
  async function spending<B>(request: (token: string) => Promise<AuthAnswer<B>>): Promise<AuthAnswer<B>> {
    const answer = await request(token ?? "");
    if (answer.ok || (answer.error !== "captcha_unavailable" && answer.error !== "origin")) {
      setToken(null);
      setGeneration((g) => g + 1);
    }
    return answer;
  }

  /** Runs a step with the form locked; handlers call it and return at once. */
  function run(action: () => Promise<void>): void {
    setBusy(true);
    setError(null);
    void action().finally(() => setBusy(false));
  }

  return {
    screen,
    error,
    busy,
    generation,
    human: token !== null && !captchaBroken,
    go,
    run,
    spending,
    setError,
    setToken,
    captchaFailed: (message: string) => {
      setCaptchaBroken(true);
      setError(message);
    },
  };
}
