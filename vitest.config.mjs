import { configDefaults, defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    // scripts/dev-sandbox.mjs links the real home's transcript and editor
    // directories — ~/.cursor holds whole extensions, test files included —
    // and vitest must never collect those.
    exclude: [...configDefaults.exclude, "**/.dev-sandbox/**"],
    // The CLI tests drive the compiled tree; build it once per run.
    globalSetup: ["./test/global-setup.mjs"],
  },
});
