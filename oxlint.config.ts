import { defineConfig } from "oxlint";
import core from "ultracite/oxlint/core";
import vitest from "ultracite/oxlint/vitest";

export default defineConfig({
  env: core.env,
  extends: [core, vitest],
  ignorePatterns: core.ignorePatterns,
  overrides: [
    {
      // Protocol tests walk one registration/refresh flow per test and assert
      // every step of it; splitting them would hide the sequence.
      files: ["**/*.test.ts"],
      plugins: ["vitest"],
      rules: {
        "vitest/max-expects": "off",
      },
    },
  ],
});
