/**
 * The injection classifier — a small local model that re-judges the guard's OWN
 * `injected_instruction` findings, so a regex hit the model is confident is
 * benign stops interrupting.
 *
 * This is the injection twin of the credential second opinion
 * (guard/second-opinion.ts), and it obeys the same one rule that keeps the
 * whole security feature honest: **the deterministic detectors own recall.**
 * The model may only ADJUST a finding the regexes already raised — soften a
 * lone phrase match the model reads as ordinary tool output — never invent one.
 * `injected_instruction` is the one semantic detector where a classifier earns
 * its keep: "is this text trying to steer the agent" is a judgement, not a
 * pattern, and Llama Prompt Guard 2 (measured here at ~5 ms per call once warm)
 * makes it far better than the two-phrase heuristic alone.
 *
 * Unlike the guard's per-call second opinion, this runs in the MAIN app process
 * over the transcript scan — the model loads once and stays warm, so a fresh
 * `node` per tool call never pays the 300 ms cold start, and the guard bundle
 * stays self-contained (nothing here ships into userData).
 *
 * Absent until asked for. The bundle ships only the runtime — ONNX Runtime's
 * WASM build, ~14 MB, signed with the app (scripts/stage-runtime.mjs) — and the
 * MODEL is data the app downloads, sha256-pinned, when the person turns the
 * feature on (lib/model-assets.ts). Until then `loadInjectionClassifier`
 * returns `null`, and a `null` classifier is not an error: every consumer treats
 * "no verdict" as "leave the detectors' finding exactly as it was".
 */

/** A model's answer for one span of text. `score` is P(malicious) in [0,1]. */
export interface InjectionVerdict {
  malicious: boolean;
  score: number;
}

/** The name a finding, the Rules screen and Analytics use for the model. */
export const INJECTION_CLASSIFIER_LABEL = "Llama Prompt Guard 2";

/**
 * What the row records about the model's look at a regex hit. `stoodDown` is
 * the capture engine's decision (injectionMarkerStands with the live
 * threshold), not re-derived here, so the record and the behaviour can never
 * disagree.
 */
export function injectionAssist(verdict: InjectionVerdict, stoodDown: boolean): FindingAssist {
  return {
    by: "injection_classifier",
    model: INJECTION_CLASSIFIER_LABEL,
    verdict: stoodDown ? "stood_down" : verdict.malicious ? "confirmed" : "unsure",
    score: Math.round(verdict.score * 1000) / 1000,
  };
}

/** What a loaded model exposes. Injected everywhere so tests never need ONNX. */
export interface InjectionClassifier {
  readonly model: string;
  classify(text: string): Promise<InjectionVerdict | null>;
}

import { existsSync, readFileSync } from "node:fs";
import type { FindingAssist } from "./findings.js";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
export type { InjectionClassifierConfig } from "../guard/policy.js";
import type { InjectionClassifierConfig } from "../guard/policy.js";

export const INJECTION_CLASSIFIER_DEFAULT_MODEL = "Llama-Prompt-Guard-2-22M";

/**
 * Only `injected_instruction` is a judgement the model may overrule. The other
 * two marker detectors are FACTS about the bytes — a zero-width character
 * (`invisible_unicode`) or a rendered exfil link (`exfil_render_link`) is there
 * or it isn't, and no semantic model gets a vote on that.
 */
export function markerIsClassifiable(marker: string | undefined): boolean {
  return marker !== undefined && marker.startsWith("injected_instruction");
}

/**
 * The decision, pure and total: should this regex marker still stand?
 *
 * Returns `false` (suppress) only when the detector fired, the marker is the
 * semantic one, the model actually answered, and it was confidently benign.
 * Every other branch — feature off, non-semantic marker, model absent, model
 * unsure or malicious — keeps the detector's marker, so recall is never lowered
 * by a missing, slow or hedging model.
 */
export function injectionMarkerStands(
  marker: string | undefined,
  verdict: InjectionVerdict | null,
  cfg: InjectionClassifierConfig,
): boolean {
  if (marker === undefined) return false; // nothing to keep
  if (!cfg.enabled) return true;
  if (!markerIsClassifiable(marker)) return true;
  if (verdict === null) return true; // no answer → detector wins
  if (verdict.malicious) return true;
  return verdict.score > cfg.suppress_below; // benign-but-not-confident → keep
}

/**
 * Load the classifier, or return `null` if the runtime or the model file is not
 * present. Never throws: a security add-on that crashes the capture pipeline is
 * one that gets turned off.
 *
 * `deps` is injected so this is exercisable without the real ONNX runtime; the
 * production caller passes the dynamic import.
 */
export interface InjectionClassifierDeps {
  /** Dynamic import of the pipeline factory; absent/throwing → no classifier. */
  loadPipeline?: (modelDir: string, model: string) => Promise<InjectionRunner | null>;
  /** Directory holding the model + tokenizer; absent → no classifier. */
  modelDir?: string;
  model?: string;
  log?: (message: string) => void;
}

/** The minimal surface a loaded pipeline must offer — one text in, scores out.
 * `label` is the model's class name; `score` its probability. */
export type InjectionRunner = (
  text: string,
) => Promise<Array<{ label: string; score: number }> | null>;

/** Class names Prompt Guard 2 / the injection classifiers use for "malicious". */
const MALICIOUS_LABELS = new Set(["malicious", "injection", "label_1", "1", "jailbreak", "unsafe"]);

export async function loadInjectionClassifier(
  deps: InjectionClassifierDeps,
): Promise<InjectionClassifier | null> {
  const model = deps.model ?? INJECTION_CLASSIFIER_DEFAULT_MODEL;
  if (!deps.loadPipeline || !deps.modelDir) return null;
  let runner: InjectionRunner | null;
  try {
    runner = await deps.loadPipeline(deps.modelDir, model);
  } catch (err) {
    deps.log?.(`injection classifier unavailable: ${err instanceof Error ? err.message : String(err)}`);
    return null;
  }
  if (!runner) return null;
  return {
    model,
    async classify(text: string): Promise<InjectionVerdict | null> {
      const trimmed = text.trim();
      if (trimmed === "") return null;
      try {
        const out = await runner(trimmed);
        if (out === null || out.length === 0) return null; // the runner declined to judge
        const malicious = out.find((r) => MALICIOUS_LABELS.has(r.label.toLowerCase()));
        // A model that names only the benign class still tells us P(malicious).
        const score = malicious ? malicious.score : 1 - (out[0]?.score ?? 1);
        return { malicious: score >= 0.5, score };
      } catch (err) {
        deps.log?.(`injection classify failed: ${err instanceof Error ? err.message : String(err)}`);
        return null;
      }
    },
  };
}

/** Is the staged WASM runtime (scripts/stage-runtime.mjs) where we expect it? */
export function runtimePresent(runtimeDir: string): boolean {
  return ["ort.wasm.min.mjs", "ort-wasm-simd-threaded.mjs", "ort-wasm-simd-threaded.wasm"].every((f) => existsSync(join(runtimeDir, f)));
}

/**
 * Prompt Guard's 512-token window. An output is scored per window and the most
 * malicious window wins — but ONLY an output the model read in full may be
 * softened: a verdict over the first two pages of a ten-page result says
 * nothing about page nine, and the regex that fired there is right until
 * something that read page nine says otherwise. Longer outputs return "no
 * verdict" (null), which every consumer treats as "the detector stands".
 * Two windows ≈ a full 512-token pass costs ~0.9 s on the main thread here,
 * so the cap is also what keeps a giant tool result from stalling the app.
 */
export const TOKENS_PER_WINDOW = 512;
export const MAX_WINDOWS = 2;

/**
 * Cut an encoded output (`[CLS] … [SEP]`, as the tokenizer returns it) into the
 * windows the model reads, or `null` when it is too long to read in full.
 *
 * Every window is wrapped in its own `[CLS]` … `[SEP]`: DeBERTa classifies from
 * the first position, so a window sliced straight out of the id list — page two
 * starting mid-sentence — is scored from an ordinary word and reads as benign.
 * Measured on the shipped model: an attack sentence after ~700 tokens of README
 * scored 0.165 sliced (stood down) and 0.996 wrapped.
 */
export function classifierWindows(ids: readonly number[]): number[][] | null {
  if (ids.length < 2) return ids.length === 0 ? [] : [[...ids]];
  const cls = ids[0]!;
  const sep = ids[ids.length - 1]!;
  const body = ids.slice(1, -1);
  const perWindow = TOKENS_PER_WINDOW - 2;
  if (body.length > perWindow * MAX_WINDOWS) return null;
  if (body.length <= perWindow) return [[...ids]];
  const windows: number[][] = [];
  for (let offset = 0; offset < body.length; offset += perWindow) {
    windows.push([cls, ...body.slice(offset, offset + perWindow), sep]);
  }
  return windows;
}

/**
 * The production pipeline factory: ONNX Runtime's WASM build (staged into
 * Resources/runtime by scripts/stage-runtime.mjs — code, signed with the app)
 * running the downloaded model (lib/model-assets.ts — data, sha256-pinned), with
 * the standalone `@huggingface/tokenizers` for the DeBERTa tokenizer. No native
 * code, so nothing here needs a Team-ID signature to load, which is what lets
 * the model arrive after install. Returns `null` when either half is missing.
 */
export async function wasmPipeline(runtimeDir: string, modelDir: string): Promise<InjectionRunner | null> {
  const modelFile = join(modelDir, "model.quant.onnx");
  if (!runtimePresent(runtimeDir) || !existsSync(modelFile)) return null;
  // A REAL dynamic import: with `module: CommonJS` TypeScript would otherwise
  // lower `import()` to `require()`, and the runtime entry is an ES module.
  const dynamicImport = new Function("u", "return import(u)") as (u: string) => Promise<OrtModule>;
  const ort = await dynamicImport(pathToFileURL(join(runtimeDir, "ort.wasm.min.mjs")).href);
  // Both artifacts named outright as file URLs. The entry's own prefix guessing
  // reads the importing URL for a `dist/` segment, and a packaged app that
  // happens to live under a directory called dist/ sends it looking for a
  // package named "dist" — seen in an e2e run from a dist/mac-arm64 build.
  ort.env.wasm.wasmPaths = {
    mjs: pathToFileURL(join(runtimeDir, "ort-wasm-simd-threaded.mjs")).href,
    wasm: pathToFileURL(join(runtimeDir, "ort-wasm-simd-threaded.wasm")).href,
  };
  ort.env.wasm.numThreads = 1;
  ort.env.wasm.proxy = false;
  const tokenizersModule = (await import("@huggingface/tokenizers")) as unknown as { Tokenizer: TokenizerCtor };
  const tokenizer = new tokenizersModule.Tokenizer(
    JSON.parse(readFileSync(join(modelDir, "tokenizer.json"), "utf8")),
    JSON.parse(readFileSync(join(modelDir, "tokenizer_config.json"), "utf8")),
  );
  const config = JSON.parse(readFileSync(join(modelDir, "config.json"), "utf8")) as { id2label?: Record<string, string> };
  const id2label = config.id2label ?? { "0": "BENIGN", "1": "MALICIOUS" };
  const session = await ort.InferenceSession.create(readFileSync(modelFile), { executionProviders: ["wasm"] });
  const softmax = (logits: number[]): number[] => {
    const max = Math.max(...logits);
    const exps = logits.map((x) => Math.exp(x - max));
    const sum = exps.reduce((a, b) => a + b, 0);
    return exps.map((x) => x / sum);
  };
  return async (text: string) => {
    // Too long to read in full → no verdict. Never a benign guess over a prefix.
    const windows = classifierWindows(tokenizer.encode(text).ids);
    if (windows === null) return null;
    let best: number[] | undefined;
    for (const windowIds of windows) {
      // Unpadded, so every position is real text.
      const windowMask = windowIds.map(() => 1);
      const feeds: Record<string, unknown> = {};
      for (const name of session.inputNames) {
        const src = name.includes("mask") ? windowMask : name.includes("type") ? windowIds.map(() => 0) : windowIds;
        feeds[name] = new ort.Tensor("int64", BigInt64Array.from(src.map((v) => BigInt(v))), [1, src.length]);
      }
      const out = await session.run(feeds);
      const probs = softmax(Array.from(Object.values(out)[0]!.data as ArrayLike<number>).map(Number));
      // Most malicious window wins: an attack buried in page 3 is still an attack.
      if (!best || (probs[1] ?? 0) > (best[1] ?? 0)) best = probs;
    }
    const probs = best ?? [1, 0];
    return Object.entries(id2label).map(([index, label]) => ({ label, score: probs[Number(index)] ?? 0 }));
  };
}

/** The slice of onnxruntime-web this file touches. */
interface OrtModule {
  env: { wasm: { wasmPaths: string | { mjs: string; wasm: string }; numThreads: number; proxy: boolean } };
  Tensor: new (type: string, data: BigInt64Array, dims: number[]) => unknown;
  InferenceSession: {
    create(model: Uint8Array, options: { executionProviders: string[] }): Promise<{
      inputNames: string[];
      run(feeds: Record<string, unknown>): Promise<Record<string, { data: ArrayLike<number> }>>;
    }>;
  };
}
type TokenizerCtor = new (
  tokenizerJson: unknown,
  tokenizerConfig: unknown,
) => { encode(text: string): { ids: number[]; attention_mask?: number[] } };
