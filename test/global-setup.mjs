import { execFileSync } from "node:child_process";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

/**
 * Compile `build/` once before any test runs. The CLI's install, gateway,
 * doctor and `watch` tests drive the compiled tree: those commands copy the
 * guard, MCP and gateway bundles that sit beside build/main, exactly as the
 * shipped CLI does. Compiling here (rather than in each file) keeps a fresh
 * build for every run, local or CI, and never two compilers writing at once.
 * The ONNX runtime is staged too, for the classifier tests.
 */
export default function setup() {
  const root = join(dirname(fileURLToPath(import.meta.url)), "..");
  const tsc = createRequire(import.meta.url).resolve("typescript/bin/tsc");
  execFileSync(process.execPath, [tsc, "-p", join(root, "tsconfig.json")], { cwd: root, stdio: "inherit" });
  execFileSync(process.execPath, [join(root, "scripts", "stage-runtime.mjs")], { cwd: root, stdio: "ignore" });
}
