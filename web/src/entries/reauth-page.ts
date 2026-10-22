// The script of the platform confirmation page, `reauth.html` (publicly
// `/api/auth/mfe/reauth.html`). concierge's authorize route sends a browser here when a
// client asked for `max_age` and the session is older (`runner/src/web/authorize.rs`,
// `CONFIRM_PATH`). The page names the app that asks, mounts `<mfe-concierge-reauth open>`,
// which this build ships as its own bundle, and goes back to `return_to` on either outcome:
// the authorize route decides between a code and `access_denied`, so the page never judges
// the result itself. No React here: the element brings its own, and this file only wires
// it to the URL. The page's CSP refuses inline script, so all of it lives in this file.
import { fetchClientName } from "../shared/api/client-name";
import { CLOSE_EVENT, REAUTHENTICATED_EVENT } from "../shared/element/events";
import { authorizeReturnTo } from "../shared/lib/authorize-return";

const TAG = "mfe-concierge-reauth";
// Beside the page's own directory (`/api/auth/mfe/` → `/api/auth/clients/`), so it also
// holds where concierge is reached without the conductor's `/api` prefix.
const CLIENTS_DIR = "../clients/";

function mountDialog(mount: HTMLElement, returnTo: string): void {
  const element = document.createElement(TAG);
  // The element reports one outcome per opening; the guard covers a late second one anyway,
  // because a second `replace` would cancel the first navigation for nothing.
  let leaving = false;
  const leave = () => {
    if (leaving) return;
    leaving = true;
    location.replace(returnTo);
  };
  element.addEventListener(REAUTHENTICATED_EVENT, leave);
  element.addEventListener(CLOSE_EVENT, leave);
  element.setAttribute("open", "");
  mount.append(element);
}

async function start(): Promise<void> {
  const mount = document.getElementById("reauth-mount");
  const lead = document.getElementById("reauth-lead");
  const refusal = document.getElementById("reauth-refusal");
  if (!mount || !lead || !refusal) return;

  const target = authorizeReturnTo(new URLSearchParams(location.search).get("return_to"), location.origin);
  if (!target) {
    refusal.hidden = false;
    return;
  }

  // The name comes from the registry by the client id inside the checked `return_to`,
  // never from the query, so a link cannot dress this page up as another app.
  const client = await fetchClientName(new URL(CLIENTS_DIR, location.href), target.clientId);
  if (client.kind === "unknown") {
    refusal.hidden = false;
    return;
  }
  if (client.kind === "named") lead.textContent = `${client.name} asks you to confirm it's you.`;
  mountDialog(mount, target.href);
}

void start();
