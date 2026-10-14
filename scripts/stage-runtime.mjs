// Stage the ONNX Runtime WASM build the injection classifier runs on
// (main/lib/injection-classifier.ts) into build/runtime/, which
// electron-builder ships as Resources/runtime/. Three files out of
// onnxruntime-web's dist — the single-threaded-capable SIMD wasm, its
// emscripten glue, and the small ESM entry — nothing else of that package
// (a devDependency, so none of its 130 MB reaches the app on its own).
//
// Why WASM and not onnxruntime-node: the app is a hardened-runtime, notarized
// bundle, and a native .node/.dylib has to be signed by our Team ID to load.
// That rules out downloading the runtime after install, and bundling the
// native one costs ~85 MB per arch. The wasm build is ~13 MB, arch-neutral,
// runs under the allow-jit entitlement the app already carries, and measured
// 26–77 ms per classification here — plenty for an after-the-fact transcript
// scan. The MODEL (≈82 MB of data) is not staged at all: model-assets.ts
// downloads it, sha256-pinned, when the person turns the feature on.
import { copyFileSync, mkdirSync, statSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const src = join(here, "..", "node_modules", "onnxruntime-web", "dist");
const out = join(here, "..", "build", "runtime", "onnxruntime-web");
export const RUNTIME_FILES = ["ort.wasm.min.mjs", "ort-wasm-simd-threaded.mjs", "ort-wasm-simd-threaded.wasm"];

mkdirSync(out, { recursive: true });
let total = 0;
for (const file of RUNTIME_FILES) {
  copyFileSync(join(src, file), join(out, file));
  total += statSync(join(out, file)).size;
}
console.log(`staged onnxruntime-web wasm runtime → build/runtime/onnxruntime-web (${(total / 1e6).toFixed(1)} MB)`);
