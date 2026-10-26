// The element events beyond @evinvest/mfe's three. `ev:close` is a dialog's "dismissed by
// the user", as @evinvest/concierge's CLOSE_EVENT spells it on the host side; `ev:reauthenticated`
// is its REAUTHENTICATED_EVENT and `ev:stepup-proof` its STEPUP_PROOF_EVENT. All bubble and
// are composed, like the events of @evinvest/mfe; only the step-up proof carries a detail.

export const CLOSE_EVENT = "ev:close";

/** Fired only after the plane has answered the proof, so `ev_access` already carries the new `auth_time`. */
export const REAUTHENTICATED_EVENT = "ev:reauthenticated";

/** The proof for the host's backend, opaque to the host; `expiresAt` in unix seconds. */
export const STEPUP_PROOF_EVENT = "ev:stepup-proof";

export interface StepupProofDetail {
  proof: string;
  expiresAt: number;
}

function dispatch<T>(source: EventTarget, type: string, detail: T): void {
  source.dispatchEvent(new CustomEvent<T>(type, { bubbles: true, composed: true, detail }));
}

export function dispatchClose(source: EventTarget): void {
  dispatch(source, CLOSE_EVENT, null);
}

export function dispatchReauthenticated(source: EventTarget): void {
  dispatch(source, REAUTHENTICATED_EVENT, null);
}

export function dispatchStepupProof(source: EventTarget, detail: StepupProofDetail): void {
  dispatch(source, STEPUP_PROOF_EVENT, detail);
}
