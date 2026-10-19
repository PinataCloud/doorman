import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PassThrough, Readable } from "node:stream";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { NpmRunner } from "../../main/cli/commands/update.js";
import type { CliEnvironment } from "../../main/cli/context.js";
import { main } from "../../main/cli/index.js";
import { CHECK_WAIT_MS, UPDATE_CHECK_INTERVAL_MS, compareVersions, updateCachePath } from "../../main/cli/update-check.js";
import type { FetchLike } from "../../main/lib/model-assets.js";

/**
 * The CLI's update check (main/cli/update-check.ts) and `doorman update`:
 * what a person sees when a newer CLI is out, how often the registry is asked,
 * and that being offline or scripted never costs them anything.
 */

describe("compareVersions", () => {
  it("orders releases numerically and a release above its pre-releases", () => {
    expect(compareVersions("0.10.0", "0.9.9")).toBeGreaterThan(0);
    expect(compareVersions("1.2.3", "1.2.3")).toBe(0);
    expect(compareVersions("v1.2.3", "1.2.3")).toBe(0);
    expect(compareVersions("1.2.0", "1.2.0-beta.1")).toBeGreaterThan(0);
    expect(compareVersions("1.2.0-beta.10", "1.2.0-beta.9")).toBeGreaterThan(0);
    expect(compareVersions("1.2.0-alpha", "1.2.0-beta")).toBeLessThan(0);
    expect(compareVersions("2.0.0-rc.1", "1.9.9")).toBeGreaterThan(0);
  });
});

describe("the update check and `doorman update`", () => {
  let root: string;
  let home: string;
  let appData: string;
  let dataDir: string;
  let savedHome: string | undefined;

  beforeEach(() => {
    root = mkdtempSync(join(tmpdir(), "doorman-update-"));
    home = join(root, "home");
    appData = join(root, "appdata");
    dataDir = join(appData, "Doorman");
    mkdirSync(home, { recursive: true });
    savedHome = process.env.HOME;
    process.env.HOME = home;
  });

  afterEach(() => {
    if (savedHome === undefined) delete process.env.HOME;
    else process.env.HOME = savedHome;
    rmSync(root, { recursive: true, force: true });
  });

  /** A registry answering `latest` with `version` (or failing / hanging). */
  function registry(answer: { version: string } | "fail" | "hang") {
    const calls: string[] = [];
    const fetchImpl: FetchLike = (url, init) => {
      calls.push(url);
      if (answer === "fail") return Promise.reject(new Error("getaddrinfo ENOTFOUND registry.npmjs.org"));
      if (answer === "hang") {
        return new Promise((_resolve, reject) => init?.signal?.addEventListener("abort", () => reject(init.signal?.reason)));
      }
      return Promise.resolve({ ok: true, status: 200, body: new Response(JSON.stringify(answer)).body });
    };
    return { fetchImpl, calls };
  }

  async function run(
    argv: string[],
    opts: { fetch?: FetchLike; tty?: boolean; env?: Record<string, string>; now?: number; packageDir?: string; runNpm?: NpmRunner } = {},
  ) {
    const stdout = new PassThrough();
    const stderr = Object.assign(new PassThrough(), { isTTY: opts.tty ?? true });
    let out = "";
    let err = "";
    stdout.on("data", (c: Buffer) => (out += c.toString()));
    stderr.on("data", (c: Buffer) => (err += c.toString()));
    const io: CliEnvironment = {
      env: { HOME: home, DOORMAN_APPDATA_DIR: appData, NO_COLOR: "1", ...opts.env },
      home,
      platform: process.platform,
      version: "0.2.0",
      packageName: "@pinata/doorman",
      stdout,
      stderr,
      stdin: Readable.from([""]),
      now: () => opts.now ?? Date.now(),
      verbose: false,
      ...(opts.fetch ? { fetch: opts.fetch } : {}),
      ...(opts.packageDir ? { packageDir: opts.packageDir } : {}),
      ...(opts.runNpm ? { runNpm: opts.runNpm } : {}),
    };
    const code = await main(argv, io);
    return { code, out, err };
  }

  it("says a newer CLI is out on stderr, after the command, and keeps --json output clean", async () => {
    const reg = registry({ version: "0.3.0" });
    const r = await run(["config", "get", "retention_days", "--json"], { fetch: reg.fetchImpl });
    expect(r.code).toBe(0);
    expect(JSON.parse(r.out)).toBeTypeOf("number");
    expect(r.err).toContain("Doorman CLI 0.3.0 is available (you have 0.2.0). Update with `doorman update`.");
    expect(reg.calls).toEqual(["https://registry.npmjs.org/@pinata%2fdoorman/latest"]);
  });

  it("asks the registry at most once a day, and still reminds from the cached answer", async () => {
    const reg = registry({ version: "0.3.0" });
    const t0 = Date.parse("2026-10-20T09:00:00Z");
    await run(["config", "get", "retention_days"], { fetch: reg.fetchImpl, now: t0 });
    const second = await run(["config", "get", "retention_days"], { fetch: reg.fetchImpl, now: t0 + 60 * 60_000 });
    expect(reg.calls).toHaveLength(1);
    expect(second.err).toContain("0.3.0 is available");
    await run(["config", "get", "retention_days"], { fetch: reg.fetchImpl, now: t0 + UPDATE_CHECK_INTERVAL_MS + 1 });
    expect(reg.calls).toHaveLength(2);
  });

  it("says nothing when the CLI is current", async () => {
    const r = await run(["config", "get", "retention_days"], { fetch: registry({ version: "0.2.0" }).fetchImpl });
    expect(r.err).toBe("");
  });

  it("offline costs one failed check a day and no message", async () => {
    const reg = registry("fail");
    const t0 = Date.parse("2026-10-20T09:00:00Z");
    const r = await run(["config", "get", "retention_days"], { fetch: reg.fetchImpl, now: t0 });
    expect(r.code).toBe(0);
    expect(r.err).toBe("");
    await run(["config", "get", "retention_days"], { fetch: reg.fetchImpl, now: t0 + 60_000 });
    expect(reg.calls).toHaveLength(1);
    expect(JSON.parse(readFileSync(updateCachePath(dataDir), "utf8")).error).toContain("ENOTFOUND");
  });

  it("never holds a command up for a registry that doesn't answer", async () => {
    const started = Date.now();
    const r = await run(["config", "get", "retention_days"], { fetch: registry("hang").fetchImpl });
    expect(r.code).toBe(0);
    expect(Date.now() - started).toBeLessThan(CHECK_WAIT_MS + 1500);
    expect(JSON.parse(readFileSync(updateCachePath(dataDir), "utf8")).error).toBe("the registry did not answer in time");
  });

  it("makes no request when turned off, under CI, or when stderr is not a terminal", async () => {
    const offSwitches: { env?: Record<string, string>; tty?: boolean }[] = [{ env: { DOORMAN_NO_UPDATE_CHECK: "1" } }, { env: { CI: "true" } }, { tty: false }];
    for (const opts of offSwitches) {
      const reg = registry({ version: "0.3.0" });
      const r = await run(["config", "get", "retention_days"], { fetch: reg.fetchImpl, ...opts });
      expect(reg.calls).toEqual([]);
      expect(r.err).toBe("");
    }
  });

  /** A fake global npm: `root -g` points at `globalRoot`; `install` rewrites the package's version. */
  function fakeNpm(globalRoot: string, packageDir: string, installs: string[][]): NpmRunner {
    return (args) => {
      if (args[0] === "root") return { status: 0, output: `${globalRoot}\n` };
      installs.push([...args]);
      const spec = args[args.length - 1]!;
      writeFileSync(join(packageDir, "package.json"), JSON.stringify({ name: "@pinata/doorman", version: spec.split("@").pop() }));
      return { status: 0, output: "changed 1 package" };
    };
  }

  function installedPackage(base: string): string {
    const dir = join(base, "@pinata", "doorman");
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "@pinata/doorman", version: "0.2.0" }));
    return dir;
  }

  it("updates a global install with npm and says from what to what", async () => {
    const globalRoot = join(root, "npm", "node_modules");
    const packageDir = installedPackage(globalRoot);
    const installs: string[][] = [];
    const r = await run(["update"], { fetch: registry({ version: "0.3.0" }).fetchImpl, packageDir, runNpm: fakeNpm(globalRoot, packageDir, installs) });
    expect(r.code).toBe(0);
    expect(installs).toEqual([["install", "--global", "--no-audit", "--no-fund", "@pinata/doorman@0.3.0"]]);
    expect(r.out).toContain("Updated the Doorman CLI from 0.2.0 to 0.3.0.");
  });

  it("fails loudly when npm didn't install the new version", async () => {
    const globalRoot = join(root, "npm", "node_modules");
    const packageDir = installedPackage(globalRoot);
    const npm: NpmRunner = (args) => (args[0] === "root" ? { status: 0, output: globalRoot } : { status: 1, output: "npm ERR! code EACCES" });
    const r = await run(["update"], { fetch: registry({ version: "0.3.0" }).fetchImpl, packageDir, runNpm: npm });
    expect(r.code).toBe(1);
    expect(r.err).toContain("npm couldn't install @pinata/doorman@0.3.0");
    expect(r.err).toContain("EACCES");
  });

  it("only reports with --check, and installs nothing when already current", async () => {
    const globalRoot = join(root, "npm", "node_modules");
    const packageDir = installedPackage(globalRoot);
    const installs: string[][] = [];
    const check = await run(["update", "--check"], { fetch: registry({ version: "0.3.0" }).fetchImpl, packageDir, runNpm: fakeNpm(globalRoot, packageDir, installs) });
    expect(check.out).toContain("Doorman CLI 0.3.0 is available (you have 0.2.0).");
    const current = await run(["update"], { fetch: registry({ version: "0.2.0" }).fetchImpl, packageDir, runNpm: fakeNpm(globalRoot, packageDir, installs) });
    expect(current.out).toContain("0.2.0 is up to date");
    expect(installs).toEqual([]);
  });

  it("tells a project install how to update instead of touching npm's global packages", async () => {
    const projectDir = installedPackage(join(root, "project", "node_modules"));
    const installs: string[][] = [];
    const r = await run(["update"], {
      fetch: registry({ version: "0.3.0" }).fetchImpl,
      packageDir: projectDir,
      runNpm: fakeNpm(join(root, "npm", "node_modules"), projectDir, installs),
    });
    expect(r.out).toContain("run `npm install @pinata/doorman@0.3.0` there");
    expect(installs).toEqual([]);
  });

  it("says why it couldn't check when the registry is unreachable", async () => {
    const r = await run(["update"], { fetch: registry("fail").fetchImpl });
    expect(r.code).toBe(1);
    expect(r.err).toContain("couldn't check for updates");
  });
});
