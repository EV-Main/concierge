// The script of the platform sign-in page, `sign-in.html` (publicly
// `/api/auth/mfe/sign-in.html`). concierge's authorize route sends a browser here when a
// relying party needs a session the browser does not have: none at all, `prompt=select_account`,
// or one minted before the account's `token_version` (`runner/src/web/authorize.rs`). The
// page names the app, mounts `<mfe-concierge-sign-in open>` from this build, and goes back
// to `return_to` once the person is signed in. Dismissing the dialog goes back too, with
// `auth_error`, which authorize answers to the client as `access_denied` instead of
// sending the browser here again. No React here, and no inline script (the page's CSP).
import { negotiate } from "@evinvest/i18n";
import { HOST_ATTRS, SIGNED_IN_EVENT } from "@evinvest/mfe";

import { CLOSE_EVENT } from "../shared/element/events";
import { leaveOnce, startAuthorizePage } from "../shared/lib/authorize-page";

const TAG = "mfe-concierge-sign-in";
const CANCELLED = "auth_error=cancelled";

/** `return_to` with the refusal added; the checked value always has a query already. */
function cancelled(returnTo: string): string {
  const hash = returnTo.indexOf("#");
  return hash < 0 ? `${returnTo}&${CANCELLED}` : `${returnTo.slice(0, hash)}&${CANCELLED}${returnTo.slice(hash)}`;
}

function mountDialog(mount: HTMLElement, returnTo: string): void {
  const element = document.createElement(TAG);
  const leave = leaveOnce();
  element.addEventListener(SIGNED_IN_EVENT, () => leave(returnTo));
  element.addEventListener(CLOSE_EVENT, () => leave(cancelled(returnTo)));
  // The page text is English, but the dialog speaks the reader's language: the element
  // reads the nearest `[lang]`, so it gets its own from the browser's preferences.
  element.setAttribute("lang", negotiate(navigator.languages.join(",")));
  // OAuth providers land on `data-return-to`, so they come back through authorize too.
  element.setAttribute(HOST_ATTRS.returnTo, returnTo);
  // Every attribute is set before the element connects: it reads them on its first render.
  element.setAttribute("open", "");
  mount.append(element);
}

async function start(): Promise<void> {
  const mount = document.getElementById("sign-in-mount");
  const lead = document.getElementById("sign-in-lead");
  const refusal = document.getElementById("sign-in-refusal");
  if (!mount || !lead || !refusal) return;

  const page = await startAuthorizePage();
  if (page.kind === "refused") {
    refusal.hidden = false;
    return;
  }
  if (page.appName) lead.textContent = `Sign in to continue to ${page.appName}.`;
  mountDialog(mount, page.returnTo);
}

void start();
