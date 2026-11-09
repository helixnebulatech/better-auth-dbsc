import { mergeConfig } from "vitest/config";

import { createVitestConfig } from "./vitest.config";

// Convex, Cloudflare Workers and Vercel Edge: no Node built-ins.
export default mergeConfig(createVitestConfig("edge-runtime"), {
  test: { exclude: ["**/*.node.test.ts"] },
});
