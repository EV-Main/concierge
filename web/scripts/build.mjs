// Builds the concierge elements into dist/: one self-registering ESM file per
// element, each with its own React, its own stylesheet inlined (scope-css.mjs) and only
// the catalogue keys its own modules render, plus registry.json in the @evinvest/mfe
// format. Hosts load dist/ under EV_MFE_BASE_PATH (default /api/auth/mfe/, concierge's
// /auth/mfe/* behind the conductor's /api/auth rewrite).
//
// Per element, two esbuild passes: the first only lists the modules the entry pulls in,
// which decides both what Tailwind scans (our sources and the uikit components actually
// used — sourcing the whole kit triples the sheet) and which catalogue keys ship.
import { spawnSync } from "node:child_process";
import { mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { collect } from "@evinvest/i18n/extract";
import { resolveCatalogue } from "@evinvest/i18n/policy";
import { parseRegistry, REMOTE_LAYER } from "@evinvest/mfe";
import { build, transform } from "esbuild";

import { config } from "./config.mjs";
import { scopeCss } from "./scope-css.mjs";

const ROOT = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const DIST = path.join(ROOT, "dist");
const WORK = path.join(ROOT, ".build");
const LOCALES = ["ru", "vi", "fr", "de"];
// Tailwind v4's own floor; esbuild lowers CSS nesting for it.
const CSS_TARGET = ["chrome111", "safari16.4", "firefox128"];

const ELEMENTS = [
  { id: "sign-in", name: "concierge.sign-in", tag: "mfe-concierge-sign-in", kind: "component" },
  { id: "account", name: "concierge.account", tag: "mfe-concierge-account", kind: "page" },
  { id: "account-chip", name: "concierge.account-chip", tag: "mfe-concierge-account-chip", kind: "component" },
  { id: "reauth", name: "concierge.reauth", tag: "mfe-concierge-reauth", kind: "component" },
  { id: "stepup", name: "concierge.stepup", tag: "mfe-concierge-stepup", kind: "component" },
];

const readJson = (file) => JSON.parse(readFileSync(file, "utf8"));
const english = readJson(path.join(ROOT, "messages/en/common.json"));
const translated = Object.fromEntries(
  LOCALES.map((locale) => {
    let catalogue = {};
    try {
      catalogue = readJson(path.join(ROOT, `messages/${locale}/common.json`));
    } catch {
      // An untranslated locale renders English; `npm run i18n:check` is what reports it.
    }
    return [locale, resolveCatalogue(locale, english, catalogue).messages];
  }),
);
const extraction = collect({ root: path.join(ROOT, "src") });
if (extraction.errors.length > 0) throw new Error(`unreadable t() calls:\n${extraction.errors.join("\n")}`);

/** Serves the two per-element virtual modules: the stylesheet and the catalogue slice. */
function virtualModules({ css, messages }) {
  return {
    name: "mfe-virtual",
    setup(b) {
      b.onResolve({ filter: /^virtual:mfe\// }, (args) => ({ path: args.path, namespace: "mfe-virtual" }));
      b.onLoad({ filter: /.*/, namespace: "mfe-virtual" }, (args) => {
        if (args.path === "virtual:mfe/css") return { contents: css, loader: "text" };
        if (args.path === "virtual:mfe/messages") return { contents: JSON.stringify(messages), loader: "json" };
        return { errors: [{ text: `unknown virtual module ${args.path}` }] };
      });
    },
  };
}

const common = {
  bundle: true,
  format: "esm",
  platform: "browser",
  target: ["es2022"],
  jsx: "automatic",
  tsconfig: path.join(ROOT, "tsconfig.json"),
  define: {
    // React reads process.env.NODE_ENV; a host page has no `process`.
    "process.env.NODE_ENV": '"production"',
    __EV_BUILD__: JSON.stringify({
      publicOrigin: config.publicOrigin,
      allowOriginOverride: config.allowOriginOverride,
      turnstileSiteKey: config.turnstileSiteKey,
      saPanelUrl: config.saPanelUrl,
      registryPath: `${config.basePath}registry.json`,
    }),
  },
  logLevel: "warning",
};

/** The modules that survive tree-shaking: the kit's barrel lists every component as an input. */
async function modulesOf(entry) {
  const result = await build({ ...common, entryPoints: [entry], write: false, outdir: WORK, metafile: true, plugins: [virtualModules({ css: "", messages: {} })] });
  const kept = new Set();
  for (const output of Object.values(result.metafile.outputs)) {
    for (const [input, { bytesInOutput }] of Object.entries(output.inputs)) if (bytesInOutput > 0) kept.add(path.resolve(ROOT, input));
  }
  return [...kept];
}

function tailwind(element, modules) {
  const sources = modules.filter((file) => file.startsWith(path.join(ROOT, "src")) || file.includes(`${path.sep}@evinvest${path.sep}uikit${path.sep}dist${path.sep}`));
  const input = path.join(WORK, `${element.id}.css`);
  const output = path.join(WORK, `${element.id}.out.css`);
  const lines = ['@import "../styles/mfe.css";', ...sources.map((file) => `@source ${JSON.stringify(path.relative(WORK, file))};`)];
  writeFileSync(input, `${lines.join("\n")}\n`);
  const run = spawnSync(path.join(ROOT, "node_modules/.bin/tailwindcss"), ["-i", input, "-o", output], { cwd: ROOT, encoding: "utf8" });
  if (run.status !== 0) throw new Error(`tailwindcss failed for ${element.id}:\n${run.stderr}`);
  return readFileSync(output, "utf8");
}

function catalogueFor(modules) {
  const files = new Set(modules);
  const keys = new Set(extraction.entries.filter((entry) => files.has(path.resolve(ROOT, "src", entry.where.replace(/:\d+$/, "")))).map((entry) => entry.key));
  return Object.fromEntries(LOCALES.map((locale) => [locale, Object.fromEntries(Object.entries(translated[locale]).filter(([key]) => keys.has(key)))]));
}

rmSync(DIST, { recursive: true, force: true });
rmSync(WORK, { recursive: true, force: true });
mkdirSync(DIST, { recursive: true });
mkdirSync(WORK, { recursive: true });

const registry = [];
for (const element of ELEMENTS) {
  const entry = path.join(ROOT, `src/entries/${element.id}.tsx`);
  const modules = await modulesOf(entry);
  const scoped = scopeCss(tailwind(element, modules), element.tag, REMOTE_LAYER);
  const { code: css } = await transform(scoped, { loader: "css", minify: true, target: CSS_TARGET, legalComments: "none" });
  const result = await build({
    ...common,
    entryPoints: { [element.id]: entry },
    entryNames: "[name]-[hash]",
    chunkNames: "[name]-[hash]",
    outdir: DIST,
    minify: true,
    legalComments: "linked",
    metafile: true,
    plugins: [virtualModules({ css, messages: catalogueFor(modules) })],
  });
  const output = Object.keys(result.metafile.outputs).find((file) => file.endsWith(".js"));
  if (!output) throw new Error(`no bundle written for ${element.id}`);
  const file = path.basename(output);
  registry.push({ name: element.name, tag: element.tag, scriptUrl: `${config.basePath}${file}`, kind: element.kind });
  console.log(`${element.tag}  ${file}  ${(result.metafile.outputs[output].bytes / 1024).toFixed(1)} KiB (css ${(css.length / 1024).toFixed(1)} KiB)`);
}

const checked = parseRegistry(registry);
if (!checked.ok) throw new Error(`registry.json would not parse: ${checked.error}`);
writeFileSync(path.join(DIST, "registry.json"), `${JSON.stringify(registry, null, 2)}\n`);

// The platform pages concierge's authorize route sends a browser to
// (runner/src/web/authorize.rs): dist/reauth.html when a client asks for `max_age`, and
// dist/sign-in.html when there is no session to authorize with. Each loads its element's
// bundle from the registry above, its own script and the shared page sheet; every file a
// page names is hashed, so only the page itself is short-lived. Pages are not elements:
// they stay out of registry.json.
const HASHED = /^[A-Za-z0-9-]+-[A-Z0-9]{8}\.(?:js|css)$/;
const PAGES = [
  { page: "reauth", tag: "mfe-concierge-reauth" },
  { page: "sign-in", tag: "mfe-concierge-sign-in" },
];

async function emitHashed(entryPoints, options = {}) {
  const result = await build({ ...common, ...options, entryPoints, entryNames: "[name]-[hash]", outdir: DIST, minify: true, legalComments: "none", metafile: true });
  const [output, ...rest] = Object.keys(result.metafile.outputs);
  if (!output || rest.length > 0) throw new Error(`expected one file for ${Object.keys(entryPoints).join(", ")}, got ${Object.keys(result.metafile.outputs).join(", ")}`);
  return path.basename(output);
}

const pageCssIn = path.join(WORK, "platform-page.out.css");
const pageCssRun = spawnSync(path.join(ROOT, "node_modules/.bin/tailwindcss"), ["-i", path.join(ROOT, "styles/platform-page.css"), "-o", pageCssIn], { cwd: ROOT, encoding: "utf8" });
if (pageCssRun.status !== 0) throw new Error(`tailwindcss failed for platform-page:\n${pageCssRun.stderr}`);
const pageCss = await emitHashed({ "platform-page": pageCssIn }, { target: CSS_TARGET });

for (const { page, tag } of PAGES) {
  const element = registry.find((entry) => entry.tag === tag);
  if (!element) throw new Error(`${page}.html needs the ${tag} bundle`);
  const files = {
    "%ELEMENT_JS%": path.basename(element.scriptUrl),
    "%PAGE_JS%": await emitHashed({ [`${page}-page`]: path.join(ROOT, `src/entries/${page}-page.ts`) }),
    "%PAGE_CSS%": pageCss,
  };
  let html = readFileSync(path.join(ROOT, `pages/${page}.html`), "utf8");
  for (const [slot, file] of Object.entries(files)) {
    if (!HASHED.test(file)) throw new Error(`${page}.html: unexpected file name ${file}`);
    if (!html.includes(slot)) throw new Error(`${page}.html: the template has no ${slot}`);
    html = html.replaceAll(slot, file);
  }
  writeFileSync(path.join(DIST, `${page}.html`), html);
  console.log(`${page}.html  ${Object.values(files).join("  ")}`);
}
