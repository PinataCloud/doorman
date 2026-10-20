/**
 * What a person reads inside a Docker Sandbox (`sbx`) versus on their own
 * machine: the desktop app can't run in a sandbox, so held calls are answered
 * by `doorman watch` started from the host, and a model download the
 * sandbox's policy proxy refuses (HTTP 403) needs a host-side
 * `sbx policy allow network` rule naming the host that was blocked. Another
 * Doorman process is named by the sandbox, not by a pid only the container
 * knows.
 *
 * Runs the COMPILED CLI (build/main, compiled by vitest's global setup):
 * `guard install` copies the guard bundle that sits beside it.
 */
import { mkdirSync, mkdtempSync, readFileSync, rmSync, truncateSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PassThrough, Readable } from "node:stream";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

/* eslint-disable @typescript-eslint/no-require-imports */
const build = join(__dirname, "..", "..", "build", "main");
const { main } = require(join(build, "cli", "index.js")) as { main(argv: string[], io: unknown): Promise<number> };
const { heartbeatPath } = require(join(build, "guard", "handshake.js")) as { heartbeatPath(guardDir: string): string };
const { guardDir } = require(join(build, "enforcement.js")) as { guardDir(dataDir: string): string };
const { lockPath, takeLock } = require(join(build, "lib", "data-owner.js")) as {
  lockPath(dataDir: string, name: string): string;
  takeLock(dataDir: string, name: string, record: { pid: number; by: "app" | "cli"; command?: string; model?: string }): boolean;
};
const assets = require(join(build, "lib", "model-assets.js")) as {
  injectionModelManifest(model: string): { files: { name: string; size: number; sha256: string }[] };
  modelDir(modelsRoot: string, manifest: unknown): string;
  VERIFIED_FILE: string;
};

/** What sbx 0.46.0 sets in every sandbox's processes. */
const SANDBOX_ENV = {
  SANDBOX_NAME: "doorman",
  SANDBOX_ID: "0f3c9a1e",
  WORKSPACE_DIR: "/workspace",
  HTTPS_PROXY: "http://gateway.docker.internal:3128",
};

const ALLOW = 'sbx policy allow network --sandbox doorman "huggingface.co,**.hf.co"';

let root: string;
let home: string;
let appData: string;
let dataDir: string;
let saved: { HOME?: string; USERPROFILE?: string; DOORMAN_APPDATA_DIR?: string };
let extraEnv: Record<string, string>;
let ioExtra: Record<string, unknown>;

async function dm(argv: string[]): Promise<{ code: number; out: string; err: string }> {
  const stdout = new PassThrough();
  const stderr = new PassThrough();
  let out = "";
  let err = "";
  stdout.on("data", (c) => (out += String(c)));
  stderr.on("data", (c) => (err += String(c)));
  const code = await main(argv, {
    env: { HOME: home, DOORMAN_APPDATA_DIR: appData, NO_COLOR: "1", ...extraEnv },
    home,
    platform: process.platform,
    version: "0.0.0-test",
    stdout,
    stderr,
    stdin: Readable.from([""]),
    now: () => Date.now(),
    verbose: false,
    ...ioExtra,
  });
  return { code, out, err };
}

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), "doorman-cli-sbx-"));
  home = join(root, "home");
  appData = join(root, "appdata");
  dataDir = join(appData, "Doorman");
  mkdirSync(join(home, ".claude"), { recursive: true });
  mkdirSync(appData, { recursive: true });
  saved = { HOME: process.env.HOME, USERPROFILE: process.env.USERPROFILE, DOORMAN_APPDATA_DIR: process.env.DOORMAN_APPDATA_DIR };
  // enforcement.ts resolves every hook document from homedir(), which reads
  // HOME on POSIX and USERPROFILE on Windows.
  process.env.HOME = home;
  process.env.USERPROFILE = home;
  process.env.DOORMAN_APPDATA_DIR = appData;
  extraEnv = {};
  ioExtra = {};
});

afterEach(() => {
  for (const [key, value] of Object.entries(saved)) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
  rmSync(root, { recursive: true, force: true });
});

const answersLine = (out: string) => out.split("\n").find((l) => l.trimStart().startsWith("answers"));

describe("who answers held calls", () => {
  it("in a sandbox, points at doorman watch run from the host, not the app", async () => {
    extraEnv = SANDBOX_ENV;
    const installed = await dm(["guard", "install"]);
    expect(installed.code, installed.err).toBe(0);
    expect(answersLine(installed.out)).toContain("Claude Code asks in its own prompt (run on your computer: sbx exec -it doorman doorman watch)");
    expect(installed.out).not.toContain("open Doorman");
    expect(answersLine((await dm(["guard", "status"])).out)).toContain("(run on your computer: sbx exec -it doorman doorman watch)");
  });

  it("outside a sandbox, still says to open Doorman or run doorman watch", async () => {
    const installed = await dm(["guard", "install"]);
    expect(installed.code, installed.err).toBe(0);
    expect(answersLine(installed.out)).toContain("Claude Code asks in its own prompt (open Doorman or run doorman watch)");
    expect(answersLine((await dm(["guard", "status"])).out)).toContain("(open Doorman or run doorman watch)");
  });
});

describe("a model download the network refuses", () => {
  /** The Hub redirects model files to its CDN; the proxy refuses the CDN. */
  const CDN = "https://us.aws.cdn.hf.co/repos/ab/cd/model.onnx?X-Amz=1";
  const refuse = (status: number) => {
    ioExtra.fetch = async (url: string) => ({ ok: false, status, url: url.includes("huggingface.co") ? CDN : url, body: null });
  };
  const record = () => JSON.parse(readFileSync(join(dataDir, "models", ".auto-download.json"), "utf8")) as { failures: number; error?: string };

  it("in a sandbox, the explicit download names the blocked host and the allow command", async () => {
    extraEnv = SANDBOX_ENV;
    refuse(403);
    const r = await dm(["model", "download", "--model", "stock"]);
    expect(r.code).toBe(1);
    expect(r.err).toContain("Couldn't download stock: the sandbox's network policy blocked us.aws.cdn.hf.co");
    expect(r.err).toContain(`  ${ALLOW}\n`);
    expect(r.err).toContain("doorman model download");
  });

  it("in a sandbox, doorman model and doorman status show the background failure the same way", async () => {
    extraEnv = SANDBOX_ENV;
    refuse(403);
    expect((await dm(["model", "download", "--auto"])).code).toBe(1);
    // The record's error stays the string its readers expect.
    expect(record()).toMatchObject({ failures: 1, error: expect.stringContaining("HTTP 403") });
    const fix = `the sandbox's network policy blocked us.aws.cdn.hf.co; on your computer run ${ALLOW}, then here: doorman model download`;
    expect((await dm(["model"])).out).toContain(fix);
    expect((await dm(["status"])).out).toContain(fix);
  });

  it("in a sandbox, other HTTP errors keep today's retry advice", async () => {
    extraEnv = SANDBOX_ENV;
    refuse(503);
    expect((await dm(["model", "download", "--model", "stock"])).err).toMatch(/Couldn't download stock: \S+: HTTP 503\n/);
    await dm(["model", "download", "--auto"]);
    expect((await dm(["model"])).out).toMatch(/the background download failed \(doorman-1: \S+: HTTP 503\); retry now: doorman model download/);
  });

  it("outside a sandbox, a 403 reads as it does today", async () => {
    refuse(403);
    const r = await dm(["model", "download", "--model", "stock"]);
    expect(r.err).toMatch(/^doorman: Couldn't download stock: \S+: HTTP 403\n$/);
    await dm(["model", "download", "--auto"]);
    const model = (await dm(["model"])).out;
    expect(model).toMatch(/the background download failed \(doorman-1: \S+: HTTP 403\); retry now: doorman model download/);
    expect(model).not.toContain("sbx");
  });
});

describe("another Doorman process, named the way a person can find it", () => {
  /** A `doorman watch` answering held calls: alive, and not this process. */
  const other = process.ppid;
  const watching = () => {
    const dir = guardDir(dataDir);
    mkdirSync(dir, { recursive: true });
    writeFileSync(heartbeatPath(dir), `${JSON.stringify({ at: new Date().toISOString(), pid: other, version: "cli-0.0.0-test" })}\n`);
  };

  it("in a sandbox, names the sandbox instead of the container's pid", async () => {
    extraEnv = SANDBOX_ENV;
    watching();
    const watch = await dm(["watch", "--auto", "deny"]);
    expect(watch.code).toBe(1);
    expect(watch.err).toContain("`doorman watch` in sandbox doorman is already answering held calls.");
    const guard = await dm(["guard", "status"]);
    expect(answersLine(guard.out)).toContain("doorman watch in sandbox doorman");
    const status = await dm(["status"]);
    expect(status.out).toMatch(/app\s+doorman watch running in sandbox doorman\n/);
    const download = await dm(["model", "download"]);
    expect(download.err).toContain("Doorman is running in sandbox doorman, and it keeps the classifier's model itself");
    for (const r of [watch, guard, status, download]) expect(r.out + r.err).not.toContain(`pid ${other}`);
  });

  it("outside a sandbox, still names the pid", async () => {
    watching();
    expect((await dm(["watch", "--auto", "deny"])).err).toContain(`\`doorman watch\` (pid ${other}) is already answering held calls.`);
    expect(answersLine((await dm(["guard", "status"])).out)).toContain(`doorman watch (pid ${other})`);
    expect((await dm(["status"])).out).toMatch(new RegExp(`app\\s+doorman watch running \\(pid ${other}\\)\\n`));
    expect((await dm(["model", "download"])).err).toContain(`Doorman is running (pid ${other}), and it keeps`);
  });
});

describe("a model download while the background one runs", () => {
  it("waits for it with its progress, fetches nothing beside it, and reports what it got", async () => {
    extraEnv = SANDBOX_ENV;
    // The background download (`model download --auto`, which the kit's
    // guard install starts), 4 MB into stock's weights.
    expect(takeLock(dataDir, "model-download", { pid: process.ppid, by: "cli", command: "model download --auto", model: "stock" })).toBe(true);
    const manifest = assets.injectionModelManifest("stock");
    const dir = assets.modelDir(join(dataDir, "models"), manifest);
    mkdirSync(dir, { recursive: true });
    const weights = manifest.files.reduce((a, b) => (b.size > a.size ? b : a));
    writeFileSync(join(dir, `${weights.name}.part`), "");
    truncateSync(join(dir, `${weights.name}.part`), 4_000_000);
    const asked: string[] = [];
    ioExtra.fetch = async (url: string) => {
      asked.push(url);
      return { ok: false, status: 503, url, body: null };
    };
    // Once its progress shows, the background download finishes: every file
    // at its pinned size and recorded as verified, the lock released.
    const stderr = new PassThrough();
    let err = "";
    let finished = false;
    stderr.on("data", (c) => {
      err += String(c);
      if (finished || !err.includes("4.0 MB of")) return;
      finished = true;
      rmSync(join(dir, `${weights.name}.part`));
      for (const f of manifest.files) {
        writeFileSync(join(dir, f.name), "");
        truncateSync(join(dir, f.name), f.size);
      }
      writeFileSync(join(dir, assets.VERIFIED_FILE), JSON.stringify(Object.fromEntries(manifest.files.map((f) => [f.name, f.sha256]))));
      rmSync(lockPath(dataDir, "model-download"));
    });
    ioExtra.stderr = stderr;
    const r = await dm(["model", "download", "--model", "stock"]);
    expect(r.code, err).toBe(0);
    expect(err).toContain("The model is already downloading in the background. Waiting for it to finish (Ctrl-C stops waiting, not the download).\n");
    expect(err).toMatch(/Downloading \S+: 4\.0 MB of \S+ MB \(\d+%\)/);
    expect(err).not.toContain("pid");
    expect(r.out).toBe("The background download finished: stock is installed and verified.\n");
    expect(asked).toEqual([]);
  });

  it("leaves the app's download to the app", async () => {
    expect(takeLock(dataDir, "model-download", { pid: process.ppid, by: "app", model: "doorman-1" })).toBe(true);
    const r = await dm(["model", "download"]);
    expect(r.code).toBe(1);
    expect(r.err).toBe("doorman: The app is already downloading the model; `doorman model` shows its progress.\n");
  });
});
