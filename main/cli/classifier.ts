import { join } from "node:path";
import { PROMPT_GUARD_2_22M_DOORMAN_1, injectionModelManifest, modelDir, modelStatus, reverifyModel, type ModelManifest } from "../lib/model-assets.js";
import { loadInjectionClassifier, runtimePresent, wasmPipeline, type InjectionClassifier } from "../lib/injection-classifier.js";
import { doormanModelSource, planInjectionModel, type InjectionModelPlan } from "../lib/injection-model-choice.js";
import { injectionModelSourceFromEnv } from "../lib/policy-env.js";
import { selectedInjectionModel, type GuardPolicy } from "../guard/policy.js";

/**
 * The injection classifier as the CLI runs it: the same WASM runtime, the same
 * sha256-pinned models in `<userData>/models`, the same plan for which model
 * runs (lib/injection-model-choice.ts) as the app. The one difference is that
 * the CLI never downloads on its own: `doorman model download` does that.
 */

/** `build/runtime/onnxruntime-web`, staged by scripts/stage-runtime.mjs —
 * beside `build/main` in the repo and in the npm package alike. */
export function runtimeDir(): string {
  return join(__dirname, "..", "..", "runtime", "onnxruntime-web");
}

export function modelsRoot(dataDir: string): string {
  return join(dataDir, "models");
}

/** Where doorman-1 is fetched from: DOORMAN_INJECTION_CLASSIFIER_SOURCE, else the pinned Hugging Face URL. */
export function doormanSource(env: NodeJS.ProcessEnv): string | undefined {
  return doormanModelSource(injectionModelSourceFromEnv(env), PROMPT_GUARD_2_22M_DOORMAN_1.base_url);
}

export function modelPlan(dataDir: string, policy: GuardPolicy, env: NodeJS.ProcessEnv): InjectionModelPlan {
  return planInjectionModel({
    selected: selectedInjectionModel(policy.injection_classifier),
    installed: (model) => modelStatus(modelsRoot(dataDir), injectionModelManifest(model)).present,
    doormanSource: doormanSource(env),
  });
}

/** The classifier for the model that runs, or null when its files or the
 * runtime are missing. Re-hashes the model before loading, as the app does:
 * what runs must be what was pinned. */
export async function loadClassifier(
  dataDir: string,
  policy: GuardPolicy,
  env: NodeJS.ProcessEnv,
  log: (message: string) => void,
): Promise<{ classifier: InjectionClassifier | null; manifest: ModelManifest; changed: string[] }> {
  const manifest = injectionModelManifest(modelPlan(dataDir, policy, env).effective);
  const root = modelsRoot(dataDir);
  if (!modelStatus(root, manifest).present || !runtimePresent(runtimeDir())) return { classifier: null, manifest, changed: [] };
  const changed = await reverifyModel(root, manifest);
  if (changed.length > 0) return { classifier: null, manifest, changed };
  const classifier = await loadInjectionClassifier({
    loadPipeline: (dir) => wasmPipeline(runtimeDir(), dir, manifest.windowing),
    modelDir: modelDir(root, manifest),
    model: manifest.name,
    windowing: manifest.windowing,
    log,
  });
  return { classifier, manifest, changed };
}
