// The script of the platform confirmation page, `reauth.html` (publicly
// `/api/auth/mfe/reauth.html`). concierge's authorize route sends a browser here when a
// client asked for `max_age` and the session is older (`runner/src/web/authorize.rs`,
// `CONFIRM_PATH`). The page names the app that asks, mounts `<mfe-concierge-reauth open>`,
// which this build ships as its own bundle, and goes back to `return_to` on either outcome:
// the authorize route decides between a code and `access_denied`, so the page never judges
// the result itself. No React here: the element brings its own, and this file only wires
// it to the URL. The page's CSP refuses inline script, so all of it lives in this file.
import { CLOSE_EVENT, REAUTHENTICATED_EVENT } from "../shared/element/events";
import { leaveOnce, startAuthorizePage } from "../shared/lib/authorize-page";

const TAG = "mfe-concierge-reauth";

function mountDialog(mount: HTMLElement, returnTo: string): void {
  const element = document.createElement(TAG);
  const leave = leaveOnce();
  element.addEventListener(REAUTHENTICATED_EVENT, () => leave(returnTo));
  element.addEventListener(CLOSE_EVENT, () => leave(returnTo));
  element.setAttribute("open", "");
  mount.append(element);
}

async function start(): Promise<void> {
  const mount = document.getElementById("reauth-mount");
  const lead = document.getElementById("reauth-lead");
  const refusal = document.getElementById("reauth-refusal");
  if (!mount || !lead || !refusal) return;

  const page = await startAuthorizePage();
  if (page.kind === "refused") {
    refusal.hidden = false;
    return;
  }
  if (page.appName) lead.textContent = `${page.appName} asks you to confirm it's you.`;
  mountDialog(mount, page.returnTo);
}

void start();
