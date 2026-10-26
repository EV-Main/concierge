import { useEffect, useState } from "react";

import type { AuthAnswer, AuthError } from "../../../shared/api/auth-api";
import type { FactorCeremony } from "../api/second-factor-api";

/**
 * One factor answered under a ceremony the plane opened. A ceremony is spent by one answer,
 * right or wrong, so every refusal opens the next one before the reader can answer again.
 * `open` must be stable (`useCallback`): a new one opens a new ceremony.
 */
export function useFactorCeremony<R>(
  open: () => Promise<AuthAnswer<FactorCeremony>>,
  submit: (ceremony: string, factor: string, response: unknown) => Promise<AuthAnswer<R>>,
  onAccepted: (result: R) => void,
) {
  const [ceremony, setCeremony] = useState<FactorCeremony | null>(null);
  const [round, setRound] = useState(0);
  const [opening, setOpening] = useState(true);
  const [busy, setBusy] = useState(false);
  const [refused, setRefused] = useState<AuthError | null>(null);
  const [unopened, setUnopened] = useState<AuthError | null>(null);

  useEffect(() => {
    let live = true;
    void open().then((answer) => {
      if (!live) return;
      setOpening(false);
      setCeremony(answer.ok ? answer.body : null);
      if (!answer.ok) setUnopened(answer.error);
    });
    return () => {
      live = false;
    };
  }, [open, round]);

  const reopen = () => {
    setUnopened(null);
    setOpening(true);
    setRound((r) => r + 1);
  };

  async function answer(factor: string, response: unknown) {
    if (!ceremony || busy || opening) return;
    setBusy(true);
    setRefused(null);
    const answered = await submit(ceremony.ceremony, factor, response);
    setBusy(false);
    if (answered.ok) return onAccepted(answered.body);
    setRefused(answered.error);
    reopen();
  }

  return {
    ceremony,
    opening,
    busy: busy || opening,
    /** Why the last answer was refused. */
    refused,
    /** Why no ceremony could be opened; `retry` asks again. */
    unopened,
    generation: round,
    answer,
    retry: () => {
      setRefused(null);
      reopen();
    },
  };
}
