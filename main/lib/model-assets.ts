/**
 * Pinned model assets the app downloads AFTER install — the Llama Prompt
 * Guard 2 22M ONNX models behind the injection classifier
 * (lib/injection-classifier.ts): the stock build, and Doorman's fine-tuned
 * `doorman-1` build, which is the default selection
 * (`injection_classifier.model`).
 *
 * The bundle carries code only (the WASM runtime, signed with the app); the
 * model is ~82 MB of data nobody should pay for in the DMG unless they turn the
 * feature on. So it lives in <userData>/models/<name>/ and arrives on demand.
 *
 * Trust model, in one line: every file is pinned by exact byte size AND sha256
 * against a fixed repository revision, so what runs is what was reviewed — a
 * moved tag, a re-uploaded file or a tampered mirror fails verification and
 * leaves NOTHING on disk (write to a temp path, verify, rename). No hash, no
 * file; no file, the classifier is simply absent and the regex rules decide
 * alone, exactly as before the download.
 *
 * Pure where it can be: the manifest, the status check and the verify step take
 * a `fetch`-shaped function and a directory, so the tests never touch the
 * network.
 */

import { createHash } from "node:crypto";
import { createReadStream, existsSync, mkdirSync, readFileSync, renameSync, rmSync, statSync, writeFileSync } from "node:fs";
import { open, readFile } from "node:fs/promises";
import { isAbsolute, join } from "node:path";
import { Readable } from "node:stream";
import { fileURLToPath } from "node:url";
import type { InjectionModelId } from "../guard/policy.js";
import { DOORMAN_MODEL_BASE_URL } from "./model-sources.js";

export interface PinnedFile {
  /** Path inside the model directory. */
  name: string;
  /** Exact byte size — a cheap first check before hashing. */
  size: number;
  /** Lowercase hex sha256 of the whole file. */
  sha256: string;
}

export interface ModelManifest {
  /** Directory name under <userData>/models/. */
  name: string;
  /** Human label for Settings. */
  label: string;
  /** The model build the app ships pins for — what Settings shows as the
   * installed version, and what changes when a newer revision is pinned (the
   * old files then fail the size/hash pins and the app fetches the update). */
  version: string;
  /** Where the files come from — a URL prefix the file name is appended to.
   * Pinned to a REVISION, never a branch: the hash pin is what matters, this
   * just keeps a re-tagged branch from wasting a download. Empty when the
   * build has no public home yet (doorman-1 until lib/model-sources.ts is
   * set) — an operator may supply one (DownloadOptions.source). */
  base_url: string;
  files: PinnedFile[];
  /** The redistribution notice the license obliges the app to show. */
  notice: string;
  /** How the model reads a tool output — what it was trained and calibrated
   * on. `prefix`: the first 2 × 512-token windows (classifierWindows).
   * `focus`: crops around the regex hit (lib/injection-focus.ts). */
  windowing: "prefix" | "focus";
}

/**
 * gravitee-io/Llama-Prompt-Guard-2-22M-onnx @ da68d0f6 (Hugging Face) — an
 * int8-quantized ONNX export of meta-llama/Llama-Prompt-Guard-2-22M, ungated,
 * with the original tokenizer. Hashes computed 2026-09-04 against that revision.
 * The model weights are under the Llama 4 Community License (LICENSE + NOTICE
 * travel with them); the DeBERTa-xsmall base is MIT.
 */
export const PROMPT_GUARD_2_22M: ModelManifest = {
  name: "Llama-Prompt-Guard-2-22M",
  label: "Llama Prompt Guard 2 22M (int8 ONNX)",
  version: "2026.09 (rev da68d0f6)",
  base_url: "https://huggingface.co/gravitee-io/Llama-Prompt-Guard-2-22M-onnx/resolve/da68d0f6023c7aeaf6b256eec549de295d5e8740/",
  files: [
    { name: "config.json", size: 1006, sha256: "db1a6dabb734766632a009e17fa72ac4d110505f4be0651654dafc30002461cc" },
    { name: "tokenizer.json", size: 8649291, sha256: "92c8b45d0b12ae0dd9680fbfe9804503542c377d65838558cd0b48a795385dde" },
    { name: "tokenizer_config.json", size: 1475, sha256: "b1c18af55c6bab08e20873c67d7dc5783eda002a7934f543c4db33f3f89c5099" },
    { name: "special_tokens_map.json", size: 970, sha256: "b2f1b2f15f29a6b6d9d6ea4eca1675d2c231a71477f151d48f79cc83a625ba21" },
    { name: "model.quant.onnx", size: 72542430, sha256: "38c3f03e30a4d5d229aeb7bf638e778322f8179d0ed0d4953eb22f88d8e0cf6b" },
    { name: "LICENSE", size: 7553, sha256: "90ae4807183070953bd8da5d7be81c4494920fb54c74359383c8a4536bf003c3" },
    { name: "NOTICE", size: 111, sha256: "6d70b1303958ace2c652d10ffcb63cdd8436d49bc0e81c97373df4e329fad0c9" },
  ],
  notice: "Built with Llama. Llama 4 is licensed under the Llama 4 Community License, Copyright © Meta Platforms, Inc. All Rights Reserved.",
  windowing: "prefix",
};

/**
 * doorman-1 — Doorman's fine-tuned injection model, the DEFAULT selection:
 * Llama Prompt Guard 2 22M fine-tuned on focus-window crops of agent tool
 * output (round-4 blend), int8 ONNX (per-channel), the same tokenizer as
 * stock. Temperature is baked into its head and its validation-chosen
 * stand-down point (0.2026) rounds to the default 0.2, so the threshold does
 * not move with the model. It reads FOCUS windows — the manifest carries the
 * windowing, so the model and how it reads switch together.
 *
 * Its download location is ONE value, `DOORMAN_MODEL_BASE_URL` in
 * lib/model-sources.ts — empty until the model is published, and overridden
 * by DOORMAN_INJECTION_CLASSIFIER_SOURCE (an http(s) prefix or a local
 * directory). Either way every file is verified against these pins, so
 * publishing changes the URL, never a pin. With no usable source the app runs
 * the stock model instead (main/index.ts injectionModels).
 *
 * Derived from Llama, so the Llama 4 Community License travels with the
 * weights (LICENSE + NOTICE, the same files as stock), the name starts with
 * "Llama", and "Built with Llama" stays shown.
 */
export const PROMPT_GUARD_2_22M_DOORMAN_1: ModelManifest = {
  name: "Llama-Prompt-Guard-2-22M-doorman-1",
  label: "Llama Prompt Guard 2 22M, Doorman fine-tune (int8 ONNX)",
  version: "2026.10 (doorman-1)",
  base_url: DOORMAN_MODEL_BASE_URL,
  files: [
    { name: "config.json", size: 843, sha256: "58d7584401982309334efddb53fad7ebeb6c12a0fe84c8f59923a98589893fe4" },
    { name: "tokenizer.json", size: 8649291, sha256: "92c8b45d0b12ae0dd9680fbfe9804503542c377d65838558cd0b48a795385dde" },
    { name: "tokenizer_config.json", size: 1475, sha256: "b1c18af55c6bab08e20873c67d7dc5783eda002a7934f543c4db33f3f89c5099" },
    { name: "special_tokens_map.json", size: 970, sha256: "b2f1b2f15f29a6b6d9d6ea4eca1675d2c231a71477f151d48f79cc83a625ba21" },
    { name: "model.quant.onnx", size: 87326881, sha256: "dcdfbfa68c59544f33b5ab7ebf17dadb841375189fb9f0aa5a27a7455cdd79f2" },
    { name: "LICENSE", size: 7553, sha256: "90ae4807183070953bd8da5d7be81c4494920fb54c74359383c8a4536bf003c3" },
    { name: "NOTICE", size: 111, sha256: "6d70b1303958ace2c652d10ffcb63cdd8436d49bc0e81c97373df4e329fad0c9" },
  ],
  notice: "Built with Llama. Llama 4 is licensed under the Llama 4 Community License, Copyright © Meta Platforms, Inc. All Rights Reserved.",
  windowing: "focus",
};

/** The manifest for a model id. No id (the setting was never written) is
 * doorman-1, the default; only an explicit `stock` selects stock. */
export function injectionModelManifest(model: InjectionModelId | undefined): ModelManifest {
  return model === "stock" ? PROMPT_GUARD_2_22M : PROMPT_GUARD_2_22M_DOORMAN_1;
}

export function manifestBytes(manifest: ModelManifest): number {
  return manifest.files.reduce((sum, f) => sum + f.size, 0);
}

export function modelDir(modelsRoot: string, manifest: ModelManifest): string {
  return join(modelsRoot, manifest.name);
}

export interface ModelStatus {
  /** Every pinned file is present at its pinned size AND recorded as verified
   * against its pinned sha256 (VERIFIED_FILE, written by downloadModel). Size
   * alone is not enough: a new build of the same architecture has weights of
   * the SAME byte size, and an old file must never pass for a new pin.
   * (Hashes are checked when a file is written or adopted; re-hashing 80 MB
   * on every Settings open is not worth it — a corrupted file fails at load
   * and the classifier reports absent.) */
  present: boolean;
  missing: string[];
  bytes_total: number;
}

/** In each model directory: file name → the sha256 it was verified against
 * when written (or adopted). A dotfile, removed with the directory. */
export const VERIFIED_FILE = ".verified.json";

function readVerified(dir: string): Record<string, string> {
  try {
    const parsed = JSON.parse(readFileSync(join(dir, VERIFIED_FILE), "utf8")) as unknown;
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return {};
    const out: Record<string, string> = {};
    for (const [name, digest] of Object.entries(parsed)) if (typeof digest === "string") out[name] = digest;
    return out;
  } catch {
    return {};
  }
}

function writeVerified(dir: string, verified: Record<string, string>): void {
  const tmp = join(dir, `${VERIFIED_FILE}.tmp`);
  writeFileSync(tmp, JSON.stringify(verified));
  renameSync(tmp, join(dir, VERIFIED_FILE));
}

/** On disk at its pinned size and recorded as verified against its pin. */
function fileHeld(dir: string, file: PinnedFile, verified: Record<string, string>): boolean {
  const path = join(dir, file.name);
  return verified[file.name] === file.sha256 && existsSync(path) && statSync(path).size === file.size;
}

export function modelStatus(modelsRoot: string, manifest: ModelManifest): ModelStatus {
  const dir = modelDir(modelsRoot, manifest);
  const verified = readVerified(dir);
  const missing = manifest.files.filter((file) => !fileHeld(dir, file, verified)).map((file) => file.name);
  return { present: missing.length === 0, missing, bytes_total: manifestBytes(manifest) };
}

export async function sha256File(path: string): Promise<string> {
  const hash = createHash("sha256");
  hash.update(await readFile(path));
  return hash.digest("hex");
}

/** The slice of fetch the downloader needs — injectable for tests. */
export type FetchLike = (url: string, init?: { signal?: AbortSignal }) => Promise<{
  ok: boolean;
  status: number;
  body: ReadableStream<Uint8Array> | null;
}>;

export interface DownloadProgress {
  file: string;
  bytes_done: number;
  bytes_total: number;
}

export interface DownloadOptions {
  fetchImpl?: FetchLike;
  signal?: AbortSignal;
  onProgress?: (progress: DownloadProgress) => void;
  /** Overrides `manifest.base_url`: an http(s) URL prefix, or a local
   * directory (absolute path or file:// URL) holding the files. Either way
   * every file is verified against the manifest's pins. */
  source?: string;
}

/** Where downloadModel reads from: a URL prefix, or a local directory. */
export type ModelSource = { kind: "url"; base: string } | { kind: "dir"; dir: string };

/** Parse an operator-supplied source; `undefined` for anything else (a
 * relative path, another scheme, empty). */
export function parseModelSource(raw: string | undefined): ModelSource | undefined {
  const s = raw?.trim() ?? "";
  if (s === "") return undefined;
  if (/^https?:\/\//i.test(s)) return { kind: "url", base: s.endsWith("/") ? s : `${s}/` };
  if (/^file:\/\//i.test(s)) {
    try {
      return { kind: "dir", dir: fileURLToPath(s) };
    } catch {
      return undefined;
    }
  }
  if (isAbsolute(s)) return { kind: "dir", dir: s };
  return undefined;
}

/**
 * Bring the manifest's directory to exactly what it pins. First, every file
 * already on disk at its pinned size that is not yet recorded as verified for
 * THIS pin — an install written before the record existed, or the previous
 * build's same-sized weights — is hashed: a match is adopted (recorded, no
 * download); anything else is replaced. Then each missing file: stream to
 * `<name>.part`, verify size + sha256, rename over the old one, record it. A
 * failed verification deletes the part file and throws — the directory never
 * holds a file recorded against a pin it did not match. A source is needed
 * only when something has to be fetched.
 */
export async function downloadModel(
  modelsRoot: string,
  manifest: ModelManifest,
  options: DownloadOptions = {},
): Promise<ModelStatus> {
  // An explicit source must parse even when nothing turns out to be missing.
  const explicit = options.source === undefined ? undefined : parseModelSource(options.source);
  if (options.source !== undefined && !explicit) throw new Error("the model source must be an http(s) URL or an absolute directory");
  const dir = modelDir(modelsRoot, manifest);
  mkdirSync(dir, { recursive: true });
  const verified = readVerified(dir);
  let adopted = false;
  for (const file of manifest.files) {
    if (verified[file.name] === file.sha256) continue;
    const path = join(dir, file.name);
    if (!existsSync(path) || statSync(path).size !== file.size) continue;
    if ((await sha256File(path)) !== file.sha256) continue; // replaced below
    verified[file.name] = file.sha256;
    adopted = true;
  }
  if (adopted) writeVerified(dir, verified);
  const todo = manifest.files.filter((file) => !fileHeld(dir, file, verified));
  if (todo.length === 0) return modelStatus(modelsRoot, manifest);
  const source = explicit ?? (manifest.base_url === "" ? undefined : { kind: "url" as const, base: manifest.base_url });
  if (!source) throw new Error(`${manifest.name} has no public download yet — name a source (DOORMAN_INJECTION_CLASSIFIER_SOURCE)`);
  // A local directory goes through the same FetchLike seam, so an install from
  // disk takes the downloader's own verify-then-rename path, byte for byte.
  const fetchImpl: FetchLike =
    source.kind === "dir"
      ? async (path) =>
          existsSync(path) && statSync(path).isFile()
            ? { ok: true, status: 200, body: Readable.toWeb(createReadStream(path)) as ReadableStream<Uint8Array> }
            : { ok: false, status: 404, body: null }
      : (options.fetchImpl ?? (fetch as unknown as FetchLike));
  const total = manifestBytes(manifest);
  let done = total - todo.reduce((sum, f) => sum + f.size, 0);

  for (const file of todo) {
    const target = join(dir, file.name);
    const part = `${target}.part`;
    rmSync(part, { force: true });
    const res = await fetchImpl(source.kind === "dir" ? join(source.dir, file.name) : source.base + file.name, options.signal ? { signal: options.signal } : {});
    if (!res.ok || !res.body) throw new Error(`${file.name}: ${source.kind === "dir" ? "not in the source directory" : `HTTP ${res.status}`}`);
    const hash = createHash("sha256");
    const handle = await open(part, "w");
    let written = 0;
    try {
      const reader = res.body.getReader();
      for (;;) {
        const { done: finished, value } = await reader.read();
        if (finished) break;
        if (!value) continue;
        written += value.byteLength;
        if (written > file.size) throw new Error(`${file.name}: larger than pinned (${file.size} bytes)`);
        hash.update(value);
        await handle.write(value);
        options.onProgress?.({ file: file.name, bytes_done: done + written, bytes_total: total });
      }
    } finally {
      await handle.close();
    }
    const digest = hash.digest("hex");
    if (written !== file.size || digest !== file.sha256) {
      rmSync(part, { force: true });
      throw new Error(
        written !== file.size
          ? `${file.name}: size ${written} ≠ pinned ${file.size}`
          : `${file.name}: sha256 mismatch — refusing to keep it`,
      );
    }
    renameSync(part, target);
    verified[file.name] = file.sha256;
    writeVerified(dir, verified);
    done += written;
  }
  return modelStatus(modelsRoot, manifest);
}

/** Remove a downloaded model (Settings → "Remove"). Never touches anything else. */
export function removeModel(modelsRoot: string, manifest: ModelManifest): void {
  rmSync(modelDir(modelsRoot, manifest), { recursive: true, force: true });
}
