// The element events beyond @evinvest/mfe's three. `ev:close` is a dialog's "dismissed by
// the user", as @evinvest/concierge's CLOSE_EVENT spells it on the host side; `ev:reauthenticated`
// is its REAUTHENTICATED_EVENT. Both bubble, are composed and carry no detail, like the
// events of @evinvest/mfe.

export const CLOSE_EVENT = "ev:close";

/** Fired only after the plane has answered the proof, so `ev_access` already carries the new `auth_time`. */
export const REAUTHENTICATED_EVENT = "ev:reauthenticated";

function dispatch(source: EventTarget, type: string): void {
  source.dispatchEvent(new CustomEvent<null>(type, { bubbles: true, composed: true, detail: null }));
}

export function dispatchClose(source: EventTarget): void {
  dispatch(source, CLOSE_EVENT);
}

export function dispatchReauthenticated(source: EventTarget): void {
  dispatch(source, REAUTHENTICATED_EVENT);
}
