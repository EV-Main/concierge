import { useRef, useState } from "react";

import type { AuthAnswer, AuthError } from "../../../shared/api/auth-api";

/** What the plane asks for before it runs an act: a fresh sign-in, or a proved factor. */
export type Guard = "reauth" | "factor";

type Act = () => Promise<AuthAnswer<unknown>>;

type Stage = { kind: "idle" } | { kind: Guard; act: Act; passed: Guard[] };

function guardOf(error: AuthError): Guard | null {
  if (error === "reauth_required") return "reauth";
  if (error === "second_factor_required") return "factor";
  return null;
}

/**
 * Runs an act and, when the plane answers with a guard, opens that step and retries the act
 * once after it. The same guard asked again after it passed is shown as an error, not a loop.
 */
export function useGuardedAct() {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<AuthError | null>(null);
  const [stage, setStage] = useState<Stage>({ kind: "idle" });
  const opener = useRef<HTMLElement | null>(null);

  const giveFocusBack = () => {
    const target = opener.current;
    opener.current = null;
    // Deferred: the step unmounts in this same update, and focus() on a node about to leave is lost.
    if (target) queueMicrotask(() => target.isConnected && target.focus());
  };

  async function attempt(act: Act, passed: Guard[]) {
    setBusy(true);
    setError(null);
    const answer = await act();
    setBusy(false);
    const guard = answer.ok ? null : guardOf(answer.error);
    if (guard && !passed.includes(guard)) return setStage({ kind: guard, act, passed });
    setStage({ kind: "idle" });
    if (!answer.ok) setError(answer.error);
    giveFocusBack();
  }

  return {
    busy,
    error,
    stage: stage.kind,
    start: (act: Act) => {
      opener.current = document.activeElement instanceof HTMLElement ? document.activeElement : null;
      return attempt(act, []);
    },
    passed: () => {
      if (stage.kind !== "idle") void attempt(stage.act, [...stage.passed, stage.kind]);
    },
    cancel: () => {
      setStage({ kind: "idle" });
      giveFocusBack();
    },
    clear: () => setError(null),
  };
}
