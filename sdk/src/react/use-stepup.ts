import { useCallback, useEffect, useRef, useState } from 'react';

import type { StepupProofDetail } from '../index';
import type { StepupRequest } from './stepup-dialog';

export interface Stepup {
  open: boolean;
  /**
   * Open the step-up dialog for one operation. Resolves with the proof to
   * forward to the backend, or null when the user dismisses it or the host
   * unmounts. A call for the same operation while the dialog is open shares its
   * one answer; a call for another operation then is refused (the promise
   * rejects), since a proof is good for one `intentHash` only.
   */
  requestProof: (intentHash: string, minAal: number) => Promise<string | null>;
  /** Spread into `<StepupDialog scriptUrl={…} {...dialogProps} />`. */
  dialogProps: {
    open: boolean;
    request: StepupRequest | null;
    onOpenChange: (open: boolean) => void;
    onProof: (detail: StepupProofDetail) => void;
  };
}

interface Pending {
  request: StepupRequest;
  answer: Promise<string | null>;
  settle: (proof: string | null) => void;
}

/**
 * "This operation needs a second factor": a host awaits
 * `requestProof(intentHash, minAal)` and sends the proof with the operation.
 * Which operations need one and how much assurance is the host's backend's
 * vocabulary, so the host decides that, not this hook.
 */
export function useStepup(): Stepup {
  const [open, setOpen] = useState(false);
  const [request, setRequest] = useState<StepupRequest | null>(null);
  const pending = useRef<Pending | null>(null);

  const settle = useCallback((proof: string | null) => {
    const current = pending.current;
    pending.current = null;
    current?.settle(proof);
  }, []);

  // A caller awaiting a dialog that will never answer would hang its operation for good.
  useEffect(() => () => settle(null), [settle]);

  const requestProof = useCallback((intentHash: string, minAal: number) => {
    const current = pending.current;
    if (current) {
      if (current.request.intentHash === intentHash && current.request.minAal === minAal) return current.answer;
      return Promise.reject(new Error('a step-up is already open for another operation'));
    }
    let resolve: (proof: string | null) => void = () => {};
    const answer = new Promise<string | null>(r => {
      resolve = r;
    });
    const asked = { intentHash, minAal };
    pending.current = { request: asked, answer, settle: resolve };
    setRequest(asked);
    setOpen(true);
    return answer;
  }, []);

  const onOpenChange = useCallback(
    (next: boolean) => {
      setOpen(next);
      // After a proof `settle(proof)` has already run, so this is a no-op then.
      if (!next) settle(null);
    },
    [settle],
  );
  const onProof = useCallback((detail: StepupProofDetail) => settle(detail.proof), [settle]);

  return { open, requestProof, dialogProps: { open, request, onOpenChange, onProof } };
}
