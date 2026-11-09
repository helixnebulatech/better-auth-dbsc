import { readFileSync } from "node:fs";

import { defineConfig } from "tsdown";

const { version } = JSON.parse(
  readFileSync(new URL("package.json", import.meta.url), "utf-8")
) as { version: string };

export default defineConfig({
  define: { __PACKAGE_VERSION__: JSON.stringify(version) },
  dts: { compilerOptions: { emitDeclarationOnly: false } },
  entry: ["src/index.ts", "src/client.ts"],
  fixedExtension: false,
  format: ["esm"],
  platform: "neutral",
  sourcemap: true,
  target: "es2022",
  tsconfig: "tsconfig.build.json",
});
