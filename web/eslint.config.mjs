import js from "@eslint/js";
import reactHooks from "eslint-plugin-react-hooks";
import tseslint from "typescript-eslint";

// The same two local guards the cabinet carries (banking cabinet/frontend/eslint.config.mjs),
// because these bundles are the cabinet's auth and account screens moved here.
const ARBITRARY = "-\\[(?!\\d+(?:\\.\\d+)?(?:d|s|l)?v[hw]\\])(?:#|\\d)";

export default tseslint.config(
  { ignores: ["dist/**", ".build/**", "node_modules/**"] },
  js.configs.recommended,
  {
    files: ["src/**/*.{ts,tsx}"],
    extends: [...tseslint.configs.recommendedTypeChecked],
    languageOptions: { parserOptions: { projectService: true, tsconfigRootDir: import.meta.dirname } },
    plugins: { "react-hooks": reactHooks },
    rules: {
      ...reactHooks.configs.recommended.rules,
      // Build-time configuration is inlined by scripts/build.mjs and parsed once in
      // src/shared/config/build.ts; nothing in a browser bundle has a `process`.
      "no-restricted-properties": ["error", { object: "process", property: "env", message: "Read build configuration through src/shared/config/build.ts." }],
      "no-restricted-syntax": [
        "error",
        { selector: `Literal[value=/${ARBITRARY}/]`, message: "Arbitrary Tailwind value — use a scale step, or a CSS custom property for a genuine one-off." },
        { selector: `TemplateElement[value.raw=/${ARBITRARY}/]`, message: "Arbitrary Tailwind value — use a scale step, or a CSS custom property for a genuine one-off." },
      ],
    },
  },
  {
    files: ["scripts/**/*.mjs", "eslint.config.mjs"],
    languageOptions: { globals: { process: "readonly", console: "readonly", URL: "readonly" } },
  },
);
