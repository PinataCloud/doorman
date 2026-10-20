import { createHash } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { DOORMAN_MODEL_BASE_URL } from "../main/lib/model-sources.js";
import { doormanModelSource, planInjectionModel } from "../main/lib/injection-model-choice.js";
import {
  PROMPT_GUARD_2_22M,
  PROMPT_GUARD_2_22M_DOORMAN_1,
  VERIFIED_FILE,
  downloadModel,
  injectionModelManifest,
  manifestBytes,
  modelDir,
  modelStatus,
  parseModelSource,
  removeModel,
  reverifyModel,
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
  windowing: "prefix",
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
    expect(readdirSync(modelDir(root, m)).sort()).toEqual([VERIFIED_FILE, "config.json", "model.onnx"]);
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

  it("a build that pins a newer revision gets its own folder, fetches only what changed — even at the same byte size — and leaves the old one", async () => {
    // This IS the auto-update path, and there is no other machinery behind it:
    // `present` means every file pinned by THIS build is on disk and recorded
    // as verified against THIS pin, so a newer pin finds its folder empty and
    // `ensureInjectionModel` downloads it at the next boot. A retrained model of
    // the same architecture has weights of the SAME size, so size alone must
    // not pass. The old revision stays: the app and the CLI update separately,
    // and the one still pinning it must not re-download over the other.
    const v1 = { "config.json": "{}", "model.onnx": "old".repeat(100) };
    const m1 = manifest(v1);
    await downloadModel(root, m1, { fetchImpl: serving(v1) });
    expect(modelStatus(root, m1).present).toBe(true);

    const v2 = { "config.json": "{}", "model.onnx": "new".repeat(100) }; // same size
    const m2 = manifest(v2);
    m2.version = "next";
    expect(modelDir(root, m2)).not.toBe(modelDir(root, m1));
    // The app sees the model it pins as NOT installed, which is what starts it.
    expect(modelStatus(root, m2).present).toBe(false);

    const fetchImpl = serving(v2);
    await downloadModel(root, m2, { fetchImpl });
    // Only the file that moved is fetched; the unchanged one is linked from
    // the old revision's folder.
    expect(fetchImpl.hits).toEqual(["model.onnx"]);
    expect(modelStatus(root, m2).present).toBe(true);
    expect(readFileSync(join(modelDir(root, m2), "model.onnx"), "utf8")).toBe(v2["model.onnx"]);
    // …and the build still pinning the old weights keeps them.
    expect(modelStatus(root, m1).present).toBe(true);
    expect(await reverifyModel(root, m1)).toEqual([]);
  });

  it("adopts an install from before revision folders without a download", async () => {
    const files = { "config.json": "{}", "model.onnx": "w".repeat(300) };
    const m = manifest(files);
    // What a build without revision folders left: `<name>/` and its record.
    const legacy = join(root, m.name);
    mkdirSync(legacy, { recursive: true });
    for (const [name, text] of Object.entries(files)) writeFileSync(join(legacy, name), text);
    writeFileSync(join(legacy, VERIFIED_FILE), JSON.stringify(Object.fromEntries(m.files.map((f) => [f.name, f.sha256]))));
    expect(modelStatus(root, m).present).toBe(false);

    const fetchImpl = serving(files);
    await downloadModel(root, m, { fetchImpl });
    expect(fetchImpl.hits).toEqual([]);
    expect(modelStatus(root, m).present).toBe(true);
    // The old folder stays for the build that still reads it.
    expect(readdirSync(legacy).sort()).toEqual([VERIFIED_FILE, "config.json", "model.onnx"]);
  });

  it("keeps its own revision and the newest other one, and prunes older ones", async () => {
    const versions = ["a", "b", "c"].map((v) => ({ "config.json": "{}", "model.onnx": v.repeat(200) }));
    const manifests = versions.map((v) => manifest(v));
    for (const [i, m] of manifests.entries()) {
      await downloadModel(root, m, { fetchImpl: serving(versions[i]!) });
      await new Promise((resolve) => setTimeout(resolve, 15)); // distinct record times
    }
    // c was fetched last: it keeps itself and b (the newest other), not a.
    expect(modelStatus(root, manifests[2]!).present).toBe(true);
    expect(modelStatus(root, manifests[1]!).present).toBe(true);
    expect(existsSync(modelDir(root, manifests[0]!))).toBe(false);
  });

  it("a file changed on disk after it was verified (same size) is caught at load, loses its record, and is re-fetched alone", async () => {
    const files = { "config.json": "{}", "model.onnx": "w".repeat(500) };
    const m = manifest(files);
    await downloadModel(root, m, { fetchImpl: serving(files) });
    expect(await reverifyModel(root, m)).toEqual([]); // untouched: nothing to do
    // Flip one byte: same size, so the cheap status check still says present…
    const path = join(modelDir(root, m), "model.onnx");
    const bytes = readFileSync(path);
    bytes[250] = bytes[250]! ^ 0xff;
    writeFileSync(path, bytes);
    expect(modelStatus(root, m).present).toBe(true);
    // …but the load-time re-hash catches it, and from then on it is absent.
    expect(await reverifyModel(root, m)).toEqual(["model.onnx"]);
    expect(modelStatus(root, m)).toMatchObject({ present: false, missing: ["model.onnx"] });
    const fetchImpl = serving(files);
    await downloadModel(root, m, { fetchImpl });
    expect(fetchImpl.hits).toEqual(["model.onnx"]);
    expect(readFileSync(path, "utf8")).toBe(files["model.onnx"]);
    expect(modelStatus(root, m).present).toBe(true);
  });

  it("adopts an install written before the verified record existed by hashing it once — no download when it matches", async () => {
    const files = { "config.json": "{}", "model.onnx": "a".repeat(400) };
    const m = { ...manifest(files), base_url: "" }; // no source either: nothing to fetch
    mkdirSync(modelDir(root, m), { recursive: true });
    for (const [name, text] of Object.entries(files)) writeFileSync(join(modelDir(root, m), name), text);
    expect(modelStatus(root, m).present).toBe(false); // size alone proves nothing
    expect((await downloadModel(root, m)).present).toBe(true);
    expect(modelStatus(root, m).present).toBe(true);
    // A same-sized file that does NOT match is replaced, which needs a source.
    const other = { ...manifest({ "config.json": "{}", "model.onnx": "b".repeat(400) }), base_url: "" };
    expect(modelStatus(root, other).present).toBe(false);
    await expect(downloadModel(root, other)).rejects.toThrow(/no public download yet/);
    expect(modelStatus(root, other).present).toBe(false);
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

describe("the doorman-1 model (the default selection)", () => {
  let root: string;
  beforeEach(() => {
    root = mkdtempSync(join(tmpdir(), "obf-models-"));
  });
  afterEach(() => rmSync(root, { recursive: true, force: true }));

  it("is pinned file-for-file to the fine-tuned package — weights, tokenizer, and the Llama LICENSE + NOTICE", () => {
    const m = PROMPT_GUARD_2_22M_DOORMAN_1;
    // Derived from Llama: the name starts with "Llama" and the attribution stays.
    expect(m.name).toBe("Llama-Prompt-Guard-2-22M-doorman-1");
    expect(m.label).toMatch(/^Llama /);
    expect(m.notice).toBe(PROMPT_GUARD_2_22M.notice);
    expect(m.notice).toMatch(/^Built with Llama\./);
    expect(m.files).toEqual([
      { name: "config.json", size: 843, sha256: "58d7584401982309334efddb53fad7ebeb6c12a0fe84c8f59923a98589893fe4" },
      { name: "tokenizer.json", size: 8649291, sha256: "92c8b45d0b12ae0dd9680fbfe9804503542c377d65838558cd0b48a795385dde" },
      { name: "tokenizer_config.json", size: 1475, sha256: "b1c18af55c6bab08e20873c67d7dc5783eda002a7934f543c4db33f3f89c5099" },
      { name: "special_tokens_map.json", size: 970, sha256: "b2f1b2f15f29a6b6d9d6ea4eca1675d2c231a71477f151d48f79cc83a625ba21" },
      { name: "model.quant.onnx", size: 87326881, sha256: "dcdfbfa68c59544f33b5ab7ebf17dadb841375189fb9f0aa5a27a7455cdd79f2" },
      { name: "LICENSE", size: 7553, sha256: "90ae4807183070953bd8da5d7be81c4494920fb54c74359383c8a4536bf003c3" },
      { name: "NOTICE", size: 111, sha256: "6d70b1303958ace2c652d10ffcb63cdd8436d49bc0e81c97373df4e329fad0c9" },
    ]);
    // The same tokenizer and the same license files as stock — only the weights and config moved.
    const stock = new Map(PROMPT_GUARD_2_22M.files.map((f) => [f.name, f.sha256]));
    for (const name of ["tokenizer.json", "tokenizer_config.json", "special_tokens_map.json", "LICENSE", "NOTICE"]) {
      expect(m.files.find((f) => f.name === name)!.sha256, name).toBe(stock.get(name));
    }
    // Its own directory, so switching models never overwrites the stock one.
    expect(modelDir(root, m)).not.toBe(modelDir(root, PROMPT_GUARD_2_22M));
    // Its download location is the ONE config value: the published Hugging
    // Face repo, pinned to a commit (the pins above still decide what runs).
    expect(m.base_url).toBe(DOORMAN_MODEL_BASE_URL);
    expect(DOORMAN_MODEL_BASE_URL).toBe("https://huggingface.co/PinataCloud/Llama-Doorman-22M/resolve/4a43fec65a670e48835d8e8c85c705b4b0d1c907/");
    expect(DOORMAN_MODEL_BASE_URL).toMatch(/^https:\/\/huggingface\.co\/[^/]+\/[^/]+\/resolve\/[0-9a-f]{40}\/$/);
    // The model and how it reads travel together.
    expect(m.windowing).toBe("focus");
    expect(PROMPT_GUARD_2_22M.windowing).toBe("prefix");
    expect(m.version).toBe("2026.10 (doorman-1)");
  });

  it("picks up the published URL from lib/model-sources.ts — that one line is all publishing changes", async () => {
    const url = "https://huggingface.co/example-org/example-repo/resolve/0123456789abcdef0123456789abcdef01234567/";
    vi.resetModules();
    vi.doMock("../main/lib/model-sources.js", () => ({ DOORMAN_MODEL_BASE_URL: url }));
    try {
      const fresh = await import("../main/lib/model-assets.js");
      expect(fresh.PROMPT_GUARD_2_22M_DOORMAN_1.base_url).toBe(url);
      // The pins do not move with the URL.
      expect(fresh.PROMPT_GUARD_2_22M_DOORMAN_1.files).toEqual(PROMPT_GUARD_2_22M_DOORMAN_1.files);
      // …and a download then goes to it, verified against those pins.
      const files = { "config.json": "{}", "model.onnx": "u".repeat(64) };
      const tiny = { ...manifest(files), base_url: fresh.PROMPT_GUARD_2_22M_DOORMAN_1.base_url };
      const urls: string[] = [];
      await fresh.downloadModel(root, tiny, {
        fetchImpl: async (u, init) => {
          urls.push(u);
          return serving(files)(u, init);
        },
      });
      expect(urls).toEqual([`${url}config.json`, `${url}model.onnx`]);
    } finally {
      vi.doUnmock("../main/lib/model-sources.js");
      vi.resetModules();
    }
  });

  it("no setting (or the default chosen) is doorman-1; only an explicit stock choice is stock", () => {
    expect(injectionModelManifest(undefined)).toBe(PROMPT_GUARD_2_22M_DOORMAN_1);
    expect(injectionModelManifest("doorman-1")).toBe(PROMPT_GUARD_2_22M_DOORMAN_1);
    expect(injectionModelManifest("stock")).toBe(PROMPT_GUARD_2_22M);
  });
});

describe("which model runs: selected vs effective (lib/injection-model-choice.ts)", () => {
  const installed = (...models: string[]) => (m: string) => models.includes(m);

  it("doorman-1 selected but not downloadable falls back to STOCK — never to no model", () => {
    expect(planInjectionModel({ selected: "doorman-1", installed: installed(), doormanSource: undefined })).toEqual({
      selected: "doorman-1",
      effective: "stock",
      fallback: "unpublished",
    });
  });

  it("a failed download (or one still on its way) also runs stock, and says which", () => {
    expect(planInjectionModel({ selected: "doorman-1", installed: installed("stock"), doormanSource: "https://x/", doormanError: "model.quant.onnx: sha256 mismatch" }).fallback).toBe(
      "download_failed",
    );
    expect(planInjectionModel({ selected: "doorman-1", installed: installed("stock"), doormanSource: "/pkg" })).toEqual({
      selected: "doorman-1",
      effective: "stock",
      fallback: "not_installed",
    });
  });

  it("switches to doorman-1 by itself once it is installed; an explicit stock choice is always stock", () => {
    expect(planInjectionModel({ selected: "doorman-1", installed: installed("doorman-1"), doormanSource: undefined })).toEqual({ selected: "doorman-1", effective: "doorman-1" });
    expect(planInjectionModel({ selected: "stock", installed: installed("doorman-1", "stock"), doormanSource: "/pkg" })).toEqual({ selected: "stock", effective: "stock" });
  });

  it("the environment's source beats the config URL; empty config and no env is nowhere", () => {
    expect(doormanModelSource(undefined, "")).toBeUndefined();
    expect(doormanModelSource(undefined, "https://huggingface.co/o/r/resolve/abc/")).toBe("https://huggingface.co/o/r/resolve/abc/");
    expect(doormanModelSource("/opt/pkg", "https://huggingface.co/o/r/resolve/abc/")).toBe("/opt/pkg");
  });
});

describe("the doorman-1 download path", () => {
  let root: string;
  beforeEach(() => {
    root = mkdtempSync(join(tmpdir(), "obf-models-"));
  });
  afterEach(() => rmSync(root, { recursive: true, force: true }));

  it("a source is an http(s) URL prefix or an absolute directory — nothing else", () => {
    expect(parseModelSource("https://models.example.test/doorman-1")).toEqual({ kind: "url", base: "https://models.example.test/doorman-1/" });
    expect(parseModelSource(" http://127.0.0.1:8000/pkg/ ")).toEqual({ kind: "url", base: "http://127.0.0.1:8000/pkg/" });
    expect(parseModelSource("/opt/models/doorman-1")).toEqual({ kind: "dir", dir: "/opt/models/doorman-1" });
    // A file URL names a drive on Windows; built from this platform's own absolute path.
    const abs = resolve("/opt/models/doorman-1");
    expect(parseModelSource(pathToFileURL(abs).href)).toEqual({ kind: "dir", dir: abs });
    for (const bad of [undefined, "", "  ", "models/doorman-1", "s3://bucket/prefix", "ftp://x/y"]) expect(parseModelSource(bad), String(bad)).toBeUndefined();
  });

  it("with no public URL and no source, the download refuses by name instead of guessing a host", async () => {
    const m = { ...manifest({ "model.onnx": "w".repeat(10) }), base_url: "" };
    const fetchImpl = serving({ "model.onnx": "w".repeat(10) });
    await expect(downloadModel(root, m, { fetchImpl })).rejects.toThrow(/no public download yet.*DOORMAN_INJECTION_CLASSIFIER_SOURCE/);
    await expect(downloadModel(root, m, { fetchImpl, source: "relative/dir" })).rejects.toThrow(/http\(s\) URL or an absolute directory/);
    expect(fetchImpl.hits).toEqual([]);
  });

  it("an operator URL replaces the empty base and is verified against the pins like any download", async () => {
    const files = { "config.json": "{}", "model.onnx": "o".repeat(321) };
    const m = { ...manifest(files), base_url: "" };
    const urls: string[] = [];
    const fetchImpl: FetchLike = async (url, init) => {
      urls.push(url);
      return serving(files)(url, init);
    };
    expect((await downloadModel(root, m, { fetchImpl, source: "https://mirror.example.test/pkg" })).present).toBe(true);
    expect(urls).toEqual(["https://mirror.example.test/pkg/config.json", "https://mirror.example.test/pkg/model.onnx"]);
    rmSync(modelDir(root, m), { recursive: true, force: true });
    const tampered = { ...manifest(files, { "model.onnx": sha("not this") }), base_url: "" };
    await expect(downloadModel(root, tampered, { fetchImpl, source: "https://mirror.example.test/pkg/" })).rejects.toThrow(/sha256 mismatch/);
    expect(existsSync(join(modelDir(root, tampered), "model.onnx"))).toBe(false);
  });

  it("installs from a local directory through the same verify-then-rename path", async () => {
    const files = { "config.json": "{}", "model.onnx": "l".repeat(2048), LICENSE: "license text", NOTICE: "Built with Llama." };
    const pkg = join(root, "package");
    mkdirSync(pkg);
    for (const [name, text] of Object.entries(files)) writeFileSync(join(pkg, name), text);
    const m = { ...manifest(files), base_url: "" };
    const models = join(root, "models");
    const progress: number[] = [];
    const status = await downloadModel(models, m, { source: pkg, onProgress: (p) => progress.push(p.bytes_done) });
    expect(status.present).toBe(true);
    expect(progress[progress.length - 1]).toBe(manifestBytes(m));
    expect(readdirSync(modelDir(models, m)).sort()).toEqual([VERIFIED_FILE, "LICENSE", "NOTICE", "config.json", "model.onnx"]);
    // A file in the directory that does not match its pin is refused and leaves nothing.
    rmSync(modelDir(models, m), { recursive: true, force: true });
    writeFileSync(join(pkg, "model.onnx"), "L".repeat(2048));
    await expect(downloadModel(models, m, { source: `file://${pkg}` })).rejects.toThrow(/model\.onnx: sha256 mismatch/);
    expect(existsSync(join(modelDir(models, m), "model.onnx"))).toBe(false);
    expect(existsSync(join(modelDir(models, m), "model.onnx.part"))).toBe(false);
    writeFileSync(join(pkg, "model.onnx"), files["model.onnx"]);
    rmSync(join(pkg, "NOTICE"));
    await expect(downloadModel(models, m, { source: pkg })).rejects.toThrow(/NOTICE: not in the source directory/);
  });
});
