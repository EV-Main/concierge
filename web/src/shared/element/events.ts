// The element events beyond @evinvest/mfe's three. `ev:close` is the sign-in dialog's
// "dismissed by the user", as @evinvest/concierge's CLOSE_EVENT spells it on the host side.

export const CLOSE_EVENT = "ev:close";

export function dispatchClose(source: EventTarget): void {
  source.dispatchEvent(new CustomEvent<null>(CLOSE_EVENT, { bubbles: true, composed: true, detail: null }));
}
