// The script of the platform confirmation page, `reauth.html` (publicly
// `/api/auth/mfe/reauth.html`). concierge's authorize route sends a browser here when a
// client asked for `max_age` and the session is older (`runner/src/web/authorize.rs`,
// `CONFIRM_PATH`). The page mounts `<mfe-concierge-reauth open>`, which this build ships
// as its own bundle, and goes back to `return_to` on either outcome: the authorize route
// decides between a code and `access_denied`, so the page never judges the result itself.
// No React here: the element brings its own, and this file only wires it to the URL.
import { CLOSE_EVENT, REAUTHENTICATED_EVENT } from "../shared/element/events";
import { authorizeReturnTo } from "../shared/lib/authorize-return";

const TAG = "mfe-concierge-reauth";

function start(): void {
  const mount = document.getElementById("reauth-mount");
  const refusal = document.getElementById("reauth-refusal");
  if (!mount || !refusal) return;

  const returnTo = authorizeReturnTo(new URLSearchParams(location.search).get("return_to"), location.origin);
  if (!returnTo) {
    refusal.hidden = false;
    return;
  }

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

start();
