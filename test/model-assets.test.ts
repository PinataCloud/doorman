import { createHash } from "node:crypto";
import { existsSync, mkdtempSync, readdirSync, rmSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  PROMPT_GUARD_2_22M,
  downloadModel,
  manifestBytes,
  modelDir,
  modelStatus,
  removeModel,
  type FetchLike,
  type ModelManifest,
} from "../main/lib/model-assets.js";

const sha = (s: string) => createHash("sha256").update(s).digest("hex");
const bodyOf = (text: string, chunk = 5): ReadableStream<Uint8Array> => {
  const bytes = new TextEncoder().encode(text);
  let i = 0;
  return new ReadableStream({
    pull(controller) {
      if (i >= bytes.length) return controller.close();
      controller.enqueue(bytes.slice(i, i + chunk));
      i += chunk;
    },
  });
};
/** A fetch serving `files` by name; anything else 404s. */
const serving = (files: Record<string, string>): FetchLike & { hits: string[] } => {
  const hits: string[] = [];
  const impl = (async (url: string) => {
    const name = url.split("/").pop()!;
    hits.push(name);
    const text = files[name];
    return text === undefined ? { ok: false, status: 404, body: null } : { ok: true, status: 200, body: bodyOf(text) };
  }) as FetchLike & { hits: string[] };
  impl.hits = hits;
  return impl;
};

const manifest = (files: Record<string, string>, tamper: Partial<Record<string, string>> = {}): ModelManifest => ({
  name: "tiny-model",
  label: "Tiny",
  version: "test",
  base_url: "https://example.test/repo/resolve/abc123/",
  files: Object.entries(files).map(([name, text]) => ({ name, size: Buffer.byteLength(text), sha256: tamper[name] ?? sha(text) })),
  notice: "Built with Tiny.",
});

describe("model assets", () => {
  let root: string;
  beforeEach(() => {
    root = mkdtempSync(join(tmpdir(), "doorman-models-"));
  });
  afterEach(() => rmSync(root, { recursive: true, force: true }));

  it("the shipped manifest is pinned to a revision, names every file with a size and a sha256, and carries the Llama notice", () => {
    expect(PROMPT_GUARD_2_22M.base_url).toMatch(/\/resolve\/[0-9a-f]{40}\/$/);
    for (const f of PROMPT_GUARD_2_22M.files) {
      expect(f.size).toBeGreaterThan(0);
      expect(f.sha256).toMatch(/^[0-9a-f]{64}$/);
    }
    expect(PROMPT_GUARD_2_22M.files.map((f) => f.name)).toEqual(
      expect.arrayContaining(["config.json", "tokenizer.json", "tokenizer_config.json", "model.quant.onnx", "LICENSE", "NOTICE"]),
    );
    expect(manifestBytes(PROMPT_GUARD_2_22M)).toBeGreaterThan(80_000_000);
    expect(PROMPT_GUARD_2_22M.notice).toMatch(/^Built with Llama\./);
  });

  it("downloads every file, verifies it, and reports progress up to the manifest total", async () => {
    const files = { "config.json": '{"id2label":{"0":"A"}}', "model.onnx": "x".repeat(1234) };
    const m = manifest(files);
    const progress: number[] = [];
    const status = await downloadModel(root, m, { fetchImpl: serving(files), onProgress: (p) => progress.push(p.bytes_done) });
    expect(status.present).toBe(true);
    expect(readdirSync(modelDir(root, m)).sort()).toEqual(["config.json", "model.onnx"]);
    expect(progress[progress.length - 1]).toBe(manifestBytes(m));
    expect(modelStatus(root, m)).toEqual({ present: true, missing: [], bytes_total: manifestBytes(m) });
  });

  it("a sha256 mismatch leaves NOTHING behind for that file and throws", async () => {
    const files = { "config.json": "{}", "model.onnx": "y".repeat(500) };
    const m = manifest(files, { "model.onnx": sha("something else") });
    await expect(downloadModel(root, m, { fetchImpl: serving(files) })).rejects.toThrow(/sha256 mismatch/);
    expect(existsSync(join(modelDir(root, m), "model.onnx"))).toBe(false);
    expect(existsSync(join(modelDir(root, m), "model.onnx.part"))).toBe(false);
    expect(existsSync(join(modelDir(root, m), "config.json"))).toBe(true); // the good one stays
    expect(modelStatus(root, m).missing).toEqual(["model.onnx"]);
  });

  it("a file larger than its pin is cut off and rejected; a short one fails the size check", async () => {
    const files = { "model.onnx": "z".repeat(100) };
    const tooBig = manifest(files);
    tooBig.files[0]!.size = 40;
    await expect(downloadModel(root, tooBig, { fetchImpl: serving(files) })).rejects.toThrow(/larger than pinned/);
    const tooSmall = manifest(files);
    tooSmall.files[0]!.size = 400;
    await expect(downloadModel(root, tooSmall, { fetchImpl: serving(files) })).rejects.toThrow(/size 100 ≠ pinned 400/);
    expect(readdirSync(modelDir(root, tooSmall))).toEqual([]);
  });

  it("skips files already present at the pinned size, so a retry only fetches what is missing", async () => {
    const files = { "config.json": "{}", "model.onnx": "q".repeat(300) };
    const m = manifest(files);
    mkdirSync(modelDir(root, m), { recursive: true });
    writeFileSync(join(modelDir(root, m), "config.json"), "{}");
    const fetchImpl = serving(files);
    await downloadModel(root, m, { fetchImpl });
    expect(fetchImpl.hits).toEqual(["model.onnx"]);
  });

  it("a build that pins a newer revision calls the old model absent and fetches only what changed", async () => {
    // This IS the auto-update path, and there is no other machinery behind it:
    // `present` means every file pinned by THIS build is on disk at its pinned
    // size, so a newer pin makes the old weights fail and `ensureInjectionModel`
    // downloads over them at the next boot — nobody presses anything.
    const v1 = { "config.json": "{}", "model.onnx": "old".repeat(100) };
    const m1 = manifest(v1);
    await downloadModel(root, m1, { fetchImpl: serving(v1) });
    expect(modelStatus(root, m1).present).toBe(true);

    const v2 = { "config.json": "{}", "model.onnx": "new".repeat(140) };
    const m2 = manifest(v2);
    m2.version = "next";
    // The app sees the model it pins as NOT installed, which is what starts it.
    expect(modelStatus(root, m2).present).toBe(false);
    expect(modelStatus(root, m2).missing).toEqual(["model.onnx"]);

    const fetchImpl = serving(v2);
    await downloadModel(root, m2, { fetchImpl });
    // Only the file that moved is re-fetched; the tokenizer-shaped small files
    // that didn't change cost nothing.
    expect(fetchImpl.hits).toEqual(["model.onnx"]);
    expect(modelStatus(root, m2).present).toBe(true);
  });

  it("an HTTP error names the file; remove deletes only the model directory", async () => {
    const m = manifest({ "config.json": "{}", "missing.onnx": "m" });
    await expect(downloadModel(root, m, { fetchImpl: serving({ "config.json": "{}" }) })).rejects.toThrow(/missing\.onnx: HTTP 404/);
    writeFileSync(join(root, "unrelated.txt"), "keep me");
    removeModel(root, m);
    expect(existsSync(modelDir(root, m))).toBe(false);
    expect(existsSync(join(root, "unrelated.txt"))).toBe(true);
  });
});
