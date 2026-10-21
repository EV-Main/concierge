// The host's half of re-authentication (concierge#171). A host on evinvest.ltd
// whose backend refuses an act with `403 reauth_required` opens the reauth
// element; the user proves themselves again (email code, password or passkey),
// concierge moves the session's `auth_time` to now and re-sets `ev_access`, and
// the host retries the act once. Re-authentication is evinvest.ltd only: on any
// other origin the element sends nothing and says to confirm on the platform.

import { CLOSE_EVENT } from './sign-in';

/**
 * The user confirmed. Fired only after concierge accepted the proof, so the
 * `ev_access` cookie already carries the fresh `auth_time`. Bubbles,
 * `composed`, no detail.
 */
export const REAUTHENTICATED_EVENT = 'ev:reauthenticated';

/** What the reauth element dispatches; at most one of the two per opening. */
export interface ReauthEventMap {
  [REAUTHENTICATED_EVENT]: CustomEvent<null>;
  /** Dismissed by the user (Escape, the backdrop, the close button, Cancel). */
  [CLOSE_EVENT]: CustomEvent<null>;
}

export type ReauthEventName = keyof ReauthEventMap;
