// ESLint 9 flat config.
// TypeScript sources get type-aware typescript-eslint rules (via the TS project service), the
// React Hooks rules (including the React Compiler checks) and the Vite React Refresh rule.
// Plain JavaScript config files get the base recommended rules only.
import js from "@eslint/js";
import reactHooks from "eslint-plugin-react-hooks";
import reactRefresh from "eslint-plugin-react-refresh";
import { defineConfig, globalIgnores } from "eslint/config";
import globals from "globals";
import tseslint from "typescript-eslint";

// Everything this console renders can be attacker-controlled (package metadata, file names,
// evidence). These sinks turn text into markup, so they are banned outright; render text as
// React children instead (see src/components/CodeBlock.tsx).
const htmlInjectionSinks = [
  {
    selector: "JSXAttribute[name.name='dangerouslySetInnerHTML']",
    message: "Never inject HTML. Render untrusted text as React children (see CodeBlock).",
  },
  {
    selector: "AssignmentExpression[left.type='MemberExpression'][left.property.name=/^(innerHTML|outerHTML)$/]",
    message: "Do not assign innerHTML/outerHTML. Build DOM through React.",
  },
  {
    selector: "CallExpression[callee.property.name=/^(insertAdjacentHTML|createContextualFragment)$/]",
    message: "Do not parse strings as HTML.",
  },
  {
    selector: "CallExpression[callee.object.name='document'][callee.property.name=/^(write|writeln)$/]",
    message: "Do not use document.write.",
  },
];

export default defineConfig([
  globalIgnores(["dist/", "coverage/", "node_modules/"]),
  {
    name: "warden/typescript",
    files: ["**/*.{ts,tsx}"],
    extends: [
      js.configs.recommended,
      tseslint.configs.recommendedTypeChecked,
      reactHooks.configs.flat["recommended-latest"],
      reactRefresh.configs.vite,
    ],
    languageOptions: {
      ecmaVersion: 2022,
      globals: globals.browser,
      parserOptions: {
        projectService: true,
        tsconfigRootDir: import.meta.dirname,
      },
    },
    rules: {
      "no-eval": "error",
      "no-new-func": "error",
      "no-script-url": "error",
      "no-restricted-syntax": ["error", ...htmlInjectionSinks],
      "@typescript-eslint/no-unused-vars": ["error", { argsIgnorePattern: "^_", varsIgnorePattern: "^_" }],
    },
  },
  {
    name: "warden/typescript-config-files",
    files: ["*.config.ts"],
    languageOptions: { globals: globals.node },
  },
  {
    name: "warden/javascript",
    files: ["**/*.js"],
    extends: [js.configs.recommended],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: "module",
      globals: globals.node,
    },
  },
]);
