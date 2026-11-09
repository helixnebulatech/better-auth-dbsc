import { readFileSync } from "node:fs";

import { defineConfig } from "vitest/config";

const { version } = JSON.parse(
  readFileSync(new URL("package.json", import.meta.url), "utf-8")
) as { version: string };

export const createVitestConfig = (environment: "node" | "edge-runtime") =>
  defineConfig({
    define: { __PACKAGE_VERSION__: JSON.stringify(version) },
    test: {
      environment,
      include: ["src/**/*.test.ts"],
      setupFiles: ["src/__fixtures__/fake-clock.ts"],
      typecheck: { enabled: true },
    },
  });
