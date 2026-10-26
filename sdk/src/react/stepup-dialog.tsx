import { API_VERSION } from '@evinvest/mfe';
import { RemoteElement } from '@evinvest/mfe/react';
import { useState, type ReactNode } from 'react';

import { CLOSE_EVENT, STEPUP_PROOF_EVENT, STEPUP_TAG, type StepupProofDetail } from '../index';

/** The operation a step-up is for. */
export interface StepupRequest {
  /** The operation's hash as the host's backend stored it: 64 lowercase hex. */
  intentHash: string;
  /** The least assurance level the operation needs. There is no default. */
  minAal: number;
}

export interface StepupDialogProps {
  /** Bundle URL from the concierge registry (`conciergeEntry(entries, 'stepup')`). */
  scriptUrl: string;
  open: boolean;
  /** What to confirm; null only before the first opening (`useStepup` has nothing to ask yet). */
  request: StepupRequest | null;
  /** Called with false when the user dismisses the dialog, or once a proof is in. */
  onOpenChange: (open: boolean) => void;
  /**
   * The account proved a factor for this operation. Forward `proof` to the
   * backend; it is good for this one operation until `expiresAt` (unix
   * seconds). Runs before `onOpenChange(false)`.
   */
  onProof: (detail: StepupProofDetail) => void;
  minApiVersion?: number;
  /**
   * Shown while the dialog is open and the bundle loads, and for good if it
   * fails. Hidden while closed.
   */
  fallback?: ReactNode;
}

function proofOf(detail: unknown): StepupProofDetail {
  const { proof, expiresAt } = (typeof detail === 'object' && detail !== null ? detail : {}) as Record<string, unknown>;
  if (typeof proof !== 'string' || proof === '' || typeof expiresAt !== 'number') {
    throw new Error(`${STEPUP_PROOF_EVENT} carried no proof; is the bundle older than this wrapper?`);
  }
  return { proof, expiresAt };
}

/**
 * The concierge step-up dialog: the signed-in account proves a second factor
 * for one operation. Works on evinvest.ltd and on the scope hosts concierge
 * lists for step-up. The element draws its own backdrop and traps focus; the
 * host only says whether it is open and for what. Mounted on the first open
 * and kept, as `ReauthDialog` is.
 */
export function StepupDialog({ scriptUrl, open, request, onOpenChange, onProof, minApiVersion = API_VERSION, fallback = null }: StepupDialogProps) {
  const [armed, setArmed] = useState(open);
  // Latched during render, not in an effect: the first open mounts in the same commit.
  if (open && !armed) setArmed(true);
  if (!armed) return null;
  if (request === null) throw new Error('StepupDialog opened with no request');

  return (
    <RemoteElement
      tag={STEPUP_TAG}
      scriptUrl={scriptUrl}
      minApiVersion={minApiVersion}
      attributes={{ open, 'intent-hash': request.intentHash, 'min-aal': String(request.minAal) }}
      events={{
        // Proof first, closed second: `useStepup` reads a close with no proof
        // before it as a dismissal.
        [STEPUP_PROOF_EVENT]: event => {
          onProof(proofOf(event.detail));
          onOpenChange(false);
        },
        [CLOSE_EVENT]: () => onOpenChange(false),
      }}
      fallback={open ? fallback : null}
    />
  );
}
