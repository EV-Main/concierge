// The script of the platform account page, `account.html`, served at `/account`. The tab
// lives in `?section=`: handed to the element once, and rewritten in place on every switch
// the element announces, so a reload or a shared link opens the same tab. The chip in the
// bar is the page's sign-in when nobody is signed in. The page's CSP refuses inline
// script, so all of it lives in this file.
import { SECTION_EVENT } from "../shared/element/events";

const TAG = "mfe-concierge-account";
const SECTION = "section";

const element = document.querySelector(TAG);
if (!element) throw new Error(`account.html has no <${TAG}>`);

const asked = new URLSearchParams(location.search).get(SECTION);
if (asked) element.setAttribute("data-section", asked);

element.addEventListener(SECTION_EVENT, (event) => {
  const { section } = (event as CustomEvent<{ section: string }>).detail;
  const url = new URL(location.href);
  url.searchParams.set(SECTION, section);
  history.replaceState(history.state, "", url);
});
