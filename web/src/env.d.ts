// Inlined by scripts/build.mjs; parsed in shared/config/build.ts.
declare const __EV_BUILD__: unknown;

// The element's stylesheet, compiled and scoped per bundle (scripts/scope-css.mjs).
declare module "virtual:mfe/css" {
  const css: string;
  export default css;
}

// The policy-resolved catalogue of each translated locale, cut to the keys this bundle renders.
declare module "virtual:mfe/messages" {
  const catalogues: unknown;
  export default catalogues;
}
