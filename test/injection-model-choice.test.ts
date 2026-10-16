import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { InjectionModelId } from "../main/guard/policy.js";
import {
  fetchInjectionModels,
  injectionModelsMissing,
  planInjectionModel,
  type InjectionModelFetchDeps,
} from "../main/lib/injection-model-choice.js";
import { downloadModel, modelStatus, type ModelManifest } from "../main/lib/model-assets.js";

/**
 * Doorman's fine-tuned model is the default selection, but must never leave
 * anyone with NO model while it cannot be downloaded: the app runs stock in
 * its place and switches over once it installs. These drive the real
 * downloader (verify-then-rename, .verified.json) over two tiny stand-in
 * manifests, through the same orchestration the app runs at boot.
 */
const sha = (s: string) => createHash("sha256").update(s).digest("hex");
const tiny = (name: string, files: Record<string, string>, base_url: string): ModelManifest => ({
  name,
  label: name,
  version: "test",
  base_url,
  files: Object.entries(files).map(([file, text]) => ({ name: file, size: Buffer.byteLength(text), sha256: sha(text) })),
  notice: "Built with Llama.",
  windowing: name === "fine" ? "focus" : "prefix",
});

describe("fallback to stock and the switch-over", () => {
  let root: string;
  let pkg: string;
  const stockFiles = { "config.json": "{}", "model.quant.onnx": "s".repeat(300) };
  const fineFiles = { "config.json": '{"fine":1}', "model.quant.onnx": "f".repeat(300) };
  let stock: ModelManifest;
  let fine: ModelManifest;
  let selected: InjectionModelId;
  let source: string | undefined;
  let errors: Map<string, string>;
  let downloads: InjectionModelId[];

  const manifestOf = (m: InjectionModelId) => (m === "stock" ? stock : fine);
  const deps = (): InjectionModelFetchDeps => ({
    plan: () =>
      planInjectionModel({
        selected,
        installed: (m) => modelStatus(root, manifestOf(m)).present,
        doormanSource: source,
        ...(errors.has("fine") ? { doormanError: errors.get("fine")! } : {}),
      }),
    doormanSource: () => source,
    stockInstalled: () => modelStatus(root, stock).present,
    download: async (m) => {
      downloads.push(m);
      try {
        // Stock comes from a "Hugging Face" directory; the fine-tuned model from the source.
        await downloadModel(root, manifestOf(m), { source: m === "stock" ? join(pkg, "stock") : source! });
        errors.delete(manifestOf(m).name);
        return { ok: true };
      } catch (err) {
        errors.set(manifestOf(m).name, String(err));
        return { ok: false, error: String(err) };
      }
    },
  });

  beforeEach(() => {
    root = mkdtempSync(join(tmpdir(), "dm-choice-"));
    pkg = join(root, "packages");
    for (const [dir, files] of [["stock", stockFiles], ["fine", fineFiles]] as const) {
      mkdirSync(join(pkg, dir), { recursive: true });
      for (const [name, text] of Object.entries(files)) writeFileSync(join(pkg, dir, name), text);
    }
    stock = tiny("stock", stockFiles, "");
    fine = tiny("fine", fineFiles, "");
    selected = "doorman-1";
    source = undefined;
    errors = new Map();
    downloads = [];
  });
  afterEach(() => rmSync(root, { recursive: true, force: true }));

  it("doorman-1 selected with no source: stock is fetched and runs — never no model", async () => {
    expect(injectionModelsMissing(deps())).toBe(true);
    expect(await fetchInjectionModels(deps())).toEqual({ ok: true, fetched: ["stock"] });
    expect(deps().plan()).toEqual({ selected: "doorman-1", effective: "stock", fallback: "unpublished" });
    expect(injectionModelsMissing(deps())).toBe(false); // nothing more to do until a source exists
  });

  it("a failed doorman-1 download (bad sha) falls back to stock, then switches over once a good copy installs", async () => {
    source = join(pkg, "fine");
    writeFileSync(join(source, "model.quant.onnx"), "X".repeat(300)); // tampered
    const first = await fetchInjectionModels(deps());
    expect(first.ok).toBe(false);
    expect(first.fetched).toEqual(["doorman-1", "stock"]);
    expect(first.error).toMatch(/doorman-1: .*sha256 mismatch/);
    expect(deps().plan()).toEqual({ selected: "doorman-1", effective: "stock", fallback: "download_failed" });
    expect(modelStatus(root, stock).present).toBe(true);
    // The retry finds a good copy: doorman-1 installs and becomes the model that runs.
    writeFileSync(join(source, "model.quant.onnx"), fineFiles["model.quant.onnx"]);
    expect(injectionModelsMissing(deps())).toBe(true);
    expect(await fetchInjectionModels(deps())).toEqual({ ok: true, fetched: ["doorman-1"] });
    expect(deps().plan()).toEqual({ selected: "doorman-1", effective: "doorman-1" });
    expect(injectionModelsMissing(deps())).toBe(false);
  });

  it("with a working source, doorman-1 installs first and stock is never fetched", async () => {
    source = join(pkg, "fine");
    expect(await fetchInjectionModels(deps())).toEqual({ ok: true, fetched: ["doorman-1"] });
    expect(modelStatus(root, stock).present).toBe(false);
    expect(deps().plan().effective).toBe("doorman-1");
  });

  it("an explicit stock choice fetches stock only, even with a source for doorman-1", async () => {
    selected = "stock";
    source = join(pkg, "fine");
    expect(await fetchInjectionModels(deps())).toEqual({ ok: true, fetched: ["stock"] });
    expect(modelStatus(root, fine).present).toBe(false);
    expect(deps().plan()).toEqual({ selected: "stock", effective: "stock" });
  });
});
