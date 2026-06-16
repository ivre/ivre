import js from "@eslint/js";
import reactHooks from "eslint-plugin-react-hooks";
import reactRefresh from "eslint-plugin-react-refresh";
import globals from "globals";
import tseslint from "typescript-eslint";

export default tseslint.config(
  {
    ignores: ["dist", "node_modules", "playwright-report", "test-results"],
  },
  {
    extends: [js.configs.recommended, ...tseslint.configs.recommended],
    files: ["**/*.{ts,tsx}"],
    languageOptions: {
      ecmaVersion: 2022,
      globals: globals.browser,
    },
    plugins: {
      "react-hooks": reactHooks,
      "react-refresh": reactRefresh,
    },
    rules: {
      ...reactHooks.configs.recommended.rules,
      "react-refresh/only-export-components": [
        "warn",
        { allowConstantExport: true },
      ],
      // Enforce LF line endings: the whole tree is LF and the
      // repository .gitattributes pins it, so reject CRLF here too
      // (lint runs in CI, catching it before it lands).
      "linebreak-style": ["error", "unix"],
    },
  },
  {
    // shadcn/ui-managed components legitimately export the component
    // alongside its `cva` variants helper. The CLI generates them in
    // this shape; suppressing the rule keeps drop-in updates from the
    // upstream registry working without local edits.
    files: ["src/components/ui/**/*.{ts,tsx}"],
    rules: {
      "react-refresh/only-export-components": "off",
    },
  },
);
