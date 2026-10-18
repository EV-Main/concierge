import { useRef, useState } from "react";

import type { AuthAnswer, AuthError } from "../../../shared/api/auth-api";
import { outcomeOf } from "./reauth";

/**
 * A sensitive act. `gesture`: the browser only runs it from a user click (a WebAuthn
 * registration, in Safari), so after a confirmation the reader clicks once more instead of
 * the act running off the end of an async chain.
 */
export interface Act {
  run: () => Promise<AuthAnswer<true>>;
  gesture: boolean;
}

type Stage = { kind: "idle" } | { kind: "confirm"; act: Act } | { kind: "ready"; act: Act };

/**
 * Runs sensitive acts and, when the plane answers `reauth_required`, opens the confirmation
 * step and retries the act ONCE after it. A second `reauth_required` is shown as an error.
 */
export function useReauthGate(onDone: () => void) {
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

  async function attempt(act: Act, confirmedBefore: boolean) {
    setBusy(true);
    setError(null);
    const outcome = outcomeOf(await act.run(), confirmedBefore);
    setBusy(false);
    switch (outcome.step) {
      case "done":
        setStage({ kind: "idle" });
        giveFocusBack();
        onDone();
        return;
      case "reauth":
        opener.current ??= document.activeElement instanceof HTMLElement ? document.activeElement : null;
        setStage({ kind: "confirm", act });
        return;
      case "error":
        setStage({ kind: "idle" });
        setError(outcome.error);
        giveFocusBack();
        return;
    }
  }

  return {
    busy,
    error,
    stage: stage.kind,
    start: (act: Act) => {
      opener.current = document.activeElement instanceof HTMLElement ? document.activeElement : null;
      return attempt(act, false);
    },
    confirmed: () => {
      if (stage.kind === "idle") return;
      if (stage.act.gesture) setStage({ kind: "ready", act: stage.act });
      else void attempt(stage.act, true);
    },
    proceed: () => {
      if (stage.kind === "ready") void attempt(stage.act, true);
    },
    cancel: () => {
      setStage({ kind: "idle" });
      giveFocusBack();
    },
  };
}
