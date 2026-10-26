// The host's half of a step-up (concierge docs/STEPUP-PROOF.md). A money-plane page, on
// evinvest.ltd or a scope host concierge lists, needs the signed-in account to prove a
// second factor for ONE operation: it opens the step-up element with the operation's
// `intent-hash` and the least assurance it needs (`min-aal`), and gets back an opaque proof
// to forward to its own backend. Which kinds of factor the account holds stays inside the
// element.

import { CLOSE_EVENT } from './sign-in';

/**
 * The account proved a factor for this operation. Bubbles, `composed`; the detail is
 * {@link StepupProofDetail}.
 */
export const STEPUP_PROOF_EVENT = 'ev:stepup-proof';

export interface StepupProofDetail {
  /** Opaque to the host: forwarded as is to the backend that stored the `intent-hash`. */
  proof: string;
  /** Unix seconds. */
  expiresAt: number;
}

/** What the step-up element dispatches; at most one of the two per opening. */
export interface StepupEventMap {
  [STEPUP_PROOF_EVENT]: CustomEvent<StepupProofDetail>;
  /** Dismissed by the user (Escape, the backdrop, the close button, Cancel). */
  [CLOSE_EVENT]: CustomEvent<null>;
}

export type StepupEventName = keyof StepupEventMap;
