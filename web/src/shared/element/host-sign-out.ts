import { dispatchSignOut } from "@evinvest/mfe";

import { isPlatformPage, platformLogoutUrl } from "../config/origin";

/**
 * Sign-out the host owns: the `signout` event ends the host's session, and on a scope host
 * the page then goes to the platform's confirmation so the platform session ends too —
 * otherwise the next "Sign in" there would silently reopen the host's session.
 *
 * The navigation follows the event synchronously, so a host's handler must end its session
 * with a request that survives unload (`keepalive`, `sendBeacon`) or on its own server.
 */
export function signOutOnHost(host: HTMLElement, origin: string): void {
  dispatchSignOut(host);
  if (!isPlatformPage(origin)) location.assign(platformLogoutUrl(origin));
}
