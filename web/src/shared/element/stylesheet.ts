// The element's stylesheet goes in as an already-filled `<style>`, not a `<link>`: a sheet
// arriving late from the network makes Chrome rebuild the document's font set and the host
// re-wraps its text (measured on the landing for the account chip, CLS 0.004–0.005), and
// a cross-origin `<link>` read for readiness would need CORS on the bundle directory. The
// CSS is inlined into the bundle at build time, so it is here before the first render.

export function attachStylesheet(tag: string, css: string): void {
  for (const node of Array.from(document.head.querySelectorAll("style"))) {
    if (node.dataset["mfe"] === tag) return;
  }
  const style = document.createElement("style");
  style.dataset["mfe"] = tag;
  // Filled before it is attached: an empty `<style>` filled afterwards triggers the same font-set rebuild.
  style.textContent = css;
  document.head.appendChild(style);
}
