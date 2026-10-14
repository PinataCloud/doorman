/**
 * Pinned model assets the app downloads AFTER install — currently the
 * Llama Prompt Guard 2 22M ONNX model behind the injection classifier
 * (lib/injection-classifier.ts).
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
import { existsSync, mkdirSync, renameSync, rmSync, statSync } from "node:fs";
import { open, readFile } from "node:fs/promises";
import { join } from "node:path";

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
   * just keeps a re-tagged branch from wasting a download. */
  base_url: string;
  files: PinnedFile[];
  /** The redistribution notice the license obliges the app to show. */
  notice: string;
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
};

export function manifestBytes(manifest: ModelManifest): number {
  return manifest.files.reduce((sum, f) => sum + f.size, 0);
}

export function modelDir(modelsRoot: string, manifest: ModelManifest): string {
  return join(modelsRoot, manifest.name);
}

export interface ModelStatus {
  /** Every pinned file is present at its pinned size. (Hashes are verified at
   * download time; re-hashing 80 MB on every Settings open is not worth it —
   * a corrupted file fails at load and the classifier reports absent.) */
  present: boolean;
  missing: string[];
  bytes_total: number;
}

export function modelStatus(modelsRoot: string, manifest: ModelManifest): ModelStatus {
  const dir = modelDir(modelsRoot, manifest);
  const missing: string[] = [];
  for (const file of manifest.files) {
    const path = join(dir, file.name);
    if (!existsSync(path) || statSync(path).size !== file.size) missing.push(file.name);
  }
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
}

/**
 * Download every missing file of the manifest into its directory. Each file:
 * stream to `<name>.part`, verify size + sha256, rename into place. A failed
 * verification deletes the part file and throws — the directory never holds a
 * file that did not match its pin. Files already present at the pinned size
 * are kept (the hash was checked when they were written).
 */
export async function downloadModel(
  modelsRoot: string,
  manifest: ModelManifest,
  options: DownloadOptions = {},
): Promise<ModelStatus> {
  const fetchImpl: FetchLike = options.fetchImpl ?? (fetch as unknown as FetchLike);
  const dir = modelDir(modelsRoot, manifest);
  mkdirSync(dir, { recursive: true });
  const total = manifestBytes(manifest);
  let done = manifest.files
    .filter((f) => existsSync(join(dir, f.name)) && statSync(join(dir, f.name)).size === f.size)
    .reduce((sum, f) => sum + f.size, 0);

  for (const file of manifest.files) {
    const target = join(dir, file.name);
    if (existsSync(target) && statSync(target).size === file.size) continue;
    const part = `${target}.part`;
    rmSync(part, { force: true });
    const res = await fetchImpl(manifest.base_url + file.name, options.signal ? { signal: options.signal } : {});
    if (!res.ok || !res.body) throw new Error(`${file.name}: HTTP ${res.status}`);
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
    done += written;
  }
  return modelStatus(modelsRoot, manifest);
}

/** Remove a downloaded model (Settings → "Remove"). Never touches anything else. */
export function removeModel(modelsRoot: string, manifest: ModelManifest): void {
  rmSync(modelDir(modelsRoot, manifest), { recursive: true, force: true });
}
