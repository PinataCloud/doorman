/**
 * What a person reads inside a Docker Sandbox (`sbx`) versus on their own
 * machine: the desktop app can't run in a sandbox, so held calls are answered
 * by `doorman watch` started from the host, and a model download the
 * sandbox's policy proxy refuses (HTTP 403) needs a host-side
 * `sbx policy allow network` rule naming the host that was blocked.
 *
 * Runs the COMPILED CLI (build/main, compiled by vitest's global setup):
 * `guard install` copies the guard bundle that sits beside it.
 */
import { mkdirSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PassThrough, Readable } from "node:stream";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

/* eslint-disable @typescript-eslint/no-require-imports */
const build = join(__dirname, "..", "..", "build", "main");
const { main } = require(join(build, "cli", "index.js")) as { main(argv: string[], io: unknown): Promise<number> };

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
let saved: { HOME?: string; DOORMAN_APPDATA_DIR?: string };
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
  saved = { HOME: process.env.HOME, DOORMAN_APPDATA_DIR: process.env.DOORMAN_APPDATA_DIR };
  // enforcement.ts resolves every hook document from homedir().
  process.env.HOME = home;
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
