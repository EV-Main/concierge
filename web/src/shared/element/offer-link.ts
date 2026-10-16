import { delegatedHref, dispatchNavigate } from "@evinvest/mfe";
import type { MouseEvent } from "react";

/**
 * Offer a plain same-origin link click inside the element to the host's router
 * (`ev:navigate`), and cancel the browser's navigation only if the host took it. The
 * element renders in its own React root, outside the host's tree, so its links are plain
 * `<a href>`s; a host that does not listen keeps the full page load.
 */
export function offerLinkToHost(e: MouseEvent<HTMLElement>, host: HTMLElement): void {
  if (!(e.target instanceof Element)) return;
  const anchor = e.target.closest("a[href]");
  if (!(anchor instanceof HTMLAnchorElement) || !e.currentTarget.contains(anchor)) return;
  const href = delegatedHref(e, anchor, window.location);
  if (href === null) return;
  if (dispatchNavigate(host, href)) e.preventDefault();
}
