// The signed-out chip opens the platform's sign-in dialog rather than a login page. It
// always mounts its own, loaded through the published registry beside this bundle, and owns
// its events. It never opens an <mfe-concierge-sign-in> it did not create: the first one in
// the DOM may be a lookalike or one configured with another origin and return target. The
// bundle must come from the registry's own origin, so a registry entry cannot pull in a
// script from elsewhere. (A script already running on the host page is out of reach here.)

import { API_VERSION, fetchRegistry, findEntry, HOST_ATTRS, loadElement, SIGNED_IN_EVENT } from "@evinvest/mfe";

import { CLOSE_EVENT } from "../../../shared/element/events";

const SIGN_IN = { name: "concierge.sign-in", tag: "mfe-concierge-sign-in" } as const;
/** Marks the dialog this chip mounted, so a later click reopens it instead of mounting another. */
const OWNED_ATTR = "data-chip-dialog";

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
  const mine = document.querySelector(`${SIGN_IN.tag}[${OWNED_ATTR}]`);
  if (mine) {
    mine.setAttribute("open", "");
    return true;
  }
  const registryUrl = new URL(registryPath, origin);
  const registry = await fetchRegistry(registryUrl, { allowedPrefix: new URL("./", registryUrl).href });
  const entry = registry.ok ? findEntry(registry.value, SIGN_IN.name) : undefined;
  if (!entry || entry.tag !== SIGN_IN.tag || !sameOrigin(entry.scriptUrl, registryUrl)) return false;
  if (!(await loadElement(SIGN_IN.tag, entry.scriptUrl, { minApiVersion: API_VERSION }))) return false;

  const dialog = document.createElement(SIGN_IN.tag);
  dialog.setAttribute(OWNED_ATTR, "");
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

function sameOrigin(scriptUrl: string, registryUrl: URL): boolean {
  try {
    return new URL(scriptUrl, registryUrl).origin === registryUrl.origin;
  } catch {
    return false;
  }
}
