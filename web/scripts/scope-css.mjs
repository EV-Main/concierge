// Turns one Tailwind build into the stylesheet an element inserts into a host page.
//
// The element renders in the host's LIGHT DOM, under the host's preflight. The contract
// (@evinvest/mfe) puts remote styles in the `reamfe` layer, below every layer of the host,
// so the host always wins on its own elements. Taken alone that also lets the host's
// preflight (`* { padding: 0 }`, `button { font: inherit }`, in `base`) beat every utility
// of ours on OUR elements — the account chip answered that with a hand-placed `!` on each
// such class. These bundles carry whole forms, so the rule is applied mechanically:
//
//   - utilities are compiled `important` and nested under `:where(<tag>)`: an important
//     declaration in the lowest layer beats every normal one above it, and the nesting
//     keeps it off the host's own elements, which also use `.p-4`;
//   - everything else Tailwind emits (theme variables, the kit's tokens and keyframes)
//     stays normal inside `reamfe`, so the host's own copy wins as before;
//   - `@property` registrations are hoisted to the top level, where they are valid.
//
// Utilities arrive in the marker layer `evmfe-scope` (see styles/mfe.css); a build without
// it is a broken template and throws.

const MARKER = "evmfe-scope";

/** Top-level statements of `css`: `{ prelude, body }` for blocks, `{ text }` for the rest. */
function topLevel(css) {
  const items = [];
  let start = 0;
  let depth = 0;
  let open = -1;
  for (let i = 0; i < css.length; i++) {
    const c = css[i];
    if (c === '"' || c === "'") {
      const end = css.indexOf(c, i + 1);
      i = end === -1 ? css.length : end;
    } else if (c === "/" && css[i + 1] === "*") {
      const end = css.indexOf("*/", i + 2);
      i = end === -1 ? css.length : end + 1;
    } else if (c === "{") {
      if (depth === 0) open = i;
      depth++;
    } else if (c === "}") {
      depth--;
      if (depth === 0) {
        items.push({ prelude: css.slice(start, open).trim(), body: css.slice(open + 1, i) });
        start = i + 1;
      }
    } else if (c === ";" && depth === 0) {
      items.push({ text: css.slice(start, i + 1).trim() });
      start = i + 1;
    }
  }
  if (depth !== 0) throw new Error("scope-css: unbalanced braces in the Tailwind output");
  const tail = css.slice(start).trim();
  if (tail) items.push({ text: tail });
  return items;
}

/**
 * @param {string} css   Tailwind output for one element.
 * @param {string} tag   The element's tag; utilities apply inside it only.
 * @param {string} layer The host-contract layer (`REMOTE_LAYER` of @evinvest/mfe).
 */
export function scopeCss(css, tag, layer) {
  const hoisted = [];
  const rest = [];
  let utilities = null;
  for (const item of topLevel(css)) {
    if ("text" in item) {
      rest.push(item.text);
    } else if (item.prelude === `@layer ${MARKER}`) {
      utilities = item.body;
    } else if (item.prelude.startsWith("@property")) {
      hoisted.push(`${item.prelude}{${item.body}}`);
    } else {
      rest.push(`${item.prelude}{${item.body}}`);
    }
  }
  if (utilities === null) throw new Error(`scope-css: no @layer ${MARKER} block — styles/mfe.css lost its utilities import`);
  return `${hoisted.join("\n")}\n@layer ${layer}{\n${rest.join("\n")}\n:where(${tag}){\n${utilities}\n}\n}\n`;
}
