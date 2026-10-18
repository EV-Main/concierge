import { useState } from "react";

import type { AuthAnswer, AuthError } from "../../../shared/api/auth-api";

/**
 * One try at a confirmation: the busy flag and the refusal it ended in. `run` resolves true
 * when the plane accepted, so a caller can move on without reading the state back.
 */
export function useAttempt(onConfirmed: () => void) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<AuthError | null>(null);

  async function run(attempt: () => Promise<AuthAnswer<unknown>>): Promise<boolean> {
    setBusy(true);
    setError(null);
    const answer = await attempt();
    setBusy(false);
    if (answer.ok) {
      onConfirmed();
      return true;
    }
    setError(answer.error);
    return false;
  }

  return { busy, error, setError, run };
}
