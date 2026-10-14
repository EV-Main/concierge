// The signed-out chip opens the platform's sign-in dialog rather than a login page. A
// dialog already on the page (a host that mounted <mfe-concierge-sign-in> itself) is the
// host's: the chip only opens it and the host hears the events. Otherwise the chip mounts
// its own, loaded through the published registry beside this bundle, and owns its events.

import { API_VERSION, fetchRegistry, findEntry, HOST_ATTRS, loadElement, SIGNED_IN_EVENT } from "@evinvest/mfe";

import { CLOSE_EVENT } from "../../../shared/element/events";

const SIGN_IN = { name: "concierge.sign-in", tag: "mfe-concierge-sign-in" } as const;

export interface OpenSignIn {
  /** The identity plane's origin, whose registry names the bundle. */
  origin: string;
  registryPath: string;
  intent: string | null;
  returnTo: string | null;
  /** The platform session now exists: re-read it. */
  onSignedIn: () => void;
}

/** False when the dialog could not be loaded; the caller then follows its plain link. */
export async function openSignIn({ origin, registryPath, intent, returnTo, onSignedIn }: OpenSignIn): Promise<boolean> {
  const existing = document.querySelector(SIGN_IN.tag);
  if (existing) {
    existing.setAttribute("open", "");
    return true;
  }
  const registry = await fetchRegistry(new URL(registryPath, origin));
  const entry = registry.ok ? findEntry(registry.value, SIGN_IN.name) : undefined;
  if (!entry || entry.tag !== SIGN_IN.tag) return false;
  if (!(await loadElement(SIGN_IN.tag, entry.scriptUrl, { minApiVersion: API_VERSION }))) return false;

  const dialog = document.createElement(SIGN_IN.tag);
  if (intent) dialog.setAttribute(HOST_ATTRS.intent, intent);
  if (returnTo) dialog.setAttribute(HOST_ATTRS.returnTo, returnTo);
  dialog.addEventListener(CLOSE_EVENT, () => dialog.removeAttribute("open"));
  dialog.addEventListener(SIGNED_IN_EVENT, () => {
    dialog.removeAttribute("open");
    onSignedIn();
  });
  // Set before connecting: the element reads its configuration as it connects.
  dialog.setAttribute("open", "");
  document.body.appendChild(dialog);
  return true;
}
