/**
 * The desktop app and the CLI share one data directory and may run at the same
 * time, or one after the other at different versions. Nothing they share may
 * collide: the store and prefs (one writer at a time, lib/data-owner.ts), the
 * models folder (one download at a time, one folder per pinned revision), the
 * guard bundle (a newer build's never replaced, never reported as tampering)
 * and prefs keys a newer build added (never dropped).
 *
 * These drive the COMPILED tree (vitest's global setup builds it), as the CLI
 * does: the guard bundle is copied from the compiled guard/ beside build/main.
 */
import { spawn, type ChildProcess } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PassThrough, Readable } from "node:stream";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

/* eslint-disable @typescript-eslint/no-require-imports */
const build = join(__dirname, "..", "build", "main");
const { main } = require(join(build, "cli", "index.js")) as { main(argv: string[], io: unknown): Promise<number> };
const owner = require(join(build, "lib", "data-owner.js")) as typeof import("../main/lib/data-owner.js");
const enforcement = require(join(build, "enforcement.js")) as typeof import("../main/enforcement.js");
const { sanitizePrefs, defaultPrefs } = require(join(build, "state.js")) as typeof import("../main/state.js");
const { heartbeatPath } = require(join(build, "guard", "handshake.js")) as typeof import("../main/guard/handshake.js");

let root: string;
let home: string;
let appData: string;
let dataDir: string;
let saved: { HOME?: string; DOORMAN_APPDATA_DIR?: string };
/** Real, live processes that are not this one: what another Doorman looks like. */
let others: ChildProcess[];

function otherProcess(): number {
  const child = spawn(process.execPath, ["-e", "setTimeout(() => {}, 60000)"], { stdio: "ignore" });
  others.push(child);
  return child.pid!;
}

async function dm(argv: string[]): Promise<{ code: number; out: string; err: string }> {
  const stdout = new PassThrough();
  const stderr = new PassThrough();
  let out = "";
  let err = "";
  stdout.on("data", (c) => (out += String(c)));
  stderr.on("data", (c) => (err += String(c)));
  const code = await main(argv, {
    env: { HOME: home, DOORMAN_APPDATA_DIR: appData, NO_COLOR: "1", DOORMAN_INJECTION_CLASSIFIER: "off" },
    home,
    platform: process.platform,
    version: "0.0.0-test",
    stdout,
    stderr,
    stdin: Readable.from([""]),
    now: () => Date.now(),
    verbose: false,
  });
  return { code, out, err };
}

/** One Claude Code session, so a scan has something to write. */
function seedTranscript(name = "5e55a0b1-2c3d-4e5f-8a9b-0c1d2e3f4a5b"): void {
  const project = join(home, ".claude", "projects", "-Users-dev-app");
  mkdirSync(project, { recursive: true });
  const usage = { input_tokens: 10, output_tokens: 5, cache_creation_input_tokens: 0, cache_read_input_tokens: 0 };
  const lines = [
    { type: "user", uuid: `p-${name}`, timestamp: new Date().toISOString(), sessionId: name, cwd: "/Users/dev/app", message: { role: "user", content: "hello" } },
    { type: "assistant", timestamp: new Date().toISOString(), sessionId: name, cwd: "/Users/dev/app", message: { id: `m-${name}`, model: "claude-opus-5", role: "assistant", content: [{ type: "tool_use", id: `t-${name}`, name: "Bash", input: { command: "printenv" } }], usage } },
  ];
  writeFileSync(join(project, `${name}.jsonl`), `${lines.map((l) => JSON.stringify(l)).join("\n")}\n`);
}

const storeFile = (name: string) => join(dataDir, "store", name);

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), "doorman-coexist-"));
  home = join(root, "home");
  appData = join(root, "appdata");
  dataDir = join(appData, "Doorman");
  others = [];
  saved = { HOME: process.env.HOME, DOORMAN_APPDATA_DIR: process.env.DOORMAN_APPDATA_DIR };
  process.env.HOME = home;
  process.env.DOORMAN_APPDATA_DIR = appData;
  mkdirSync(join(home, ".claude"), { recursive: true });
  mkdirSync(dataDir, { recursive: true });
  writeFileSync(join(dataDir, "prefs.json"), JSON.stringify({ ...defaultPrefs(), vscode_extension: false }));
});

afterEach(() => {
  for (const child of others) child.kill();
  for (const [key, value] of Object.entries(saved)) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
  rmSync(root, { recursive: true, force: true });
});

describe("one writer at a time", () => {
  it("a lock names a live holder; a dead holder's lock is stale and taken over", () => {
    const other = otherProcess();
    expect(owner.takeLock(dataDir, "cli-writer", { pid: other, by: "cli", command: "scan" })).toBe(true);
    expect(owner.takeLock(dataDir, "cli-writer", { pid: process.pid, by: "cli" })).toBe(false);
    expect(owner.liveLock(dataDir, "cli-writer")?.pid).toBe(other);
    owner.releaseLock(dataDir, "cli-writer", process.pid); // not ours: stays
    expect(owner.liveLock(dataDir, "cli-writer")?.pid).toBe(other);

    // A pid that is gone: its lock no longer counts.
    writeFileSync(owner.lockPath(dataDir, "cli-writer"), JSON.stringify({ pid: 2 ** 22 + 12345, at: new Date().toISOString(), by: "cli" }));
    expect(owner.liveLock(dataDir, "cli-writer")).toBeUndefined();
    expect(owner.takeLock(dataDir, "cli-writer", { pid: process.pid, by: "cli" })).toBe(true);
  });

  it("an app that is starting owns the data before its heartbeat exists; a long-dead start does not", () => {
    const app = otherProcess();
    const at = (ms: number) => new Date(Date.now() - ms).toISOString();
    mkdirSync(owner.locksDir(dataDir), { recursive: true });
    writeFileSync(join(owner.locksDir(dataDir), "app.json"), JSON.stringify({ pid: app, at: at(1_000), by: "app" }));
    expect(owner.appOwner(dataDir)?.pid).toBe(app);
    // Past the start-up grace without a heartbeat: a crashed app whose pid lives on.
    writeFileSync(join(owner.locksDir(dataDir), "app.json"), JSON.stringify({ pid: app, at: at(owner.APP_START_GRACE_MS + 1_000), by: "app" }));
    expect(owner.appOwner(dataDir)).toBeUndefined();
    // …with a fresh heartbeat it is the running app.
    mkdirSync(enforcement.guardDir(dataDir), { recursive: true });
    writeFileSync(heartbeatPath(enforcement.guardDir(dataDir)), JSON.stringify({ at: new Date().toISOString(), pid: app, version: "0.2.0" }));
    expect(owner.appOwner(dataDir)?.pid).toBe(app);
  });

  it("the app waits at start for a CLI command that is writing, and goes ahead when it ends", async () => {
    const cli = otherProcess();
    owner.takeLock(dataDir, "cli-writer", { pid: cli, by: "cli", command: "scan" });
    const logs: string[] = [];
    const claimed = owner.claimForApp(dataDir, { pid: process.pid, pollMs: 10, log: (m) => logs.push(m) });
    await new Promise((resolve) => setTimeout(resolve, 60));
    expect(owner.liveLock(dataDir, "app")?.pid).toBe(process.pid); // marked first
    owner.releaseLock(dataDir, "cli-writer", cli);
    await expect(claimed).resolves.toBe("waited");
    expect(logs[0]).toContain("waiting for `doorman scan`");
  });

  it("…but never for ever", async () => {
    owner.takeLock(dataDir, "cli-writer", { pid: otherProcess(), by: "cli", command: "scan" });
    await expect(owner.claimForApp(dataDir, { pid: process.pid, pollMs: 5, timeoutMs: 40 })).resolves.toBe("timed_out");
  });

  it("while the app is starting, CLI changes are refused and reads work on a copy", async () => {
    seedTranscript();
    const app = otherProcess();
    mkdirSync(owner.locksDir(dataDir), { recursive: true });
    writeFileSync(owner.lockPath(dataDir, "app"), JSON.stringify({ pid: app, at: new Date().toISOString(), by: "app" }));

    const refused = await dm(["rules", "set", "secret_egress", "block"]);
    expect(refused.code).toBe(1);
    expect(refused.err).toContain(`Doorman is running (pid ${app})`);
    expect((await dm(["scan"])).code).toBe(0);
    // The scan read the transcript into a copy: the real store is untouched.
    expect(existsSync(storeFile("turns.jsonl"))).toBe(false);
    expect(existsSync(owner.lockPath(dataDir, "cli-writer"))).toBe(false);
  });

  it("while another CLI command writes, a second one reads a copy and refuses changes", async () => {
    seedTranscript();
    const cli = otherProcess();
    owner.takeLock(dataDir, "cli-writer", { pid: cli, by: "cli", command: "scan" });

    const refused = await dm(["rules", "set", "secret_egress", "block"]);
    expect(refused.code).toBe(1);
    expect(refused.err).toContain(`\`doorman scan\` (pid ${cli}) is changing this data right now`);
    expect((await dm(["scan"])).code).toBe(0);
    expect(existsSync(storeFile("turns.jsonl"))).toBe(false);
    expect(owner.liveLock(dataDir, "cli-writer")?.pid).toBe(cli); // theirs, untouched
  });

  it("with nobody else around the CLI writes, and lets go when the command ends", async () => {
    seedTranscript();
    expect((await dm(["scan"])).code).toBe(0);
    expect(readFileSync(storeFile("turns.jsonl"), "utf8")).toContain("5e55a0b1-2c3d-4e5f-8a9b-0c1d2e3f4a5b");
    expect(existsSync(owner.lockPath(dataDir, "cli-writer"))).toBe(false);
  });

  it("a CLI scan stops at the next file when the app starts meanwhile", async () => {
    const { CliContext } = require(join(build, "cli", "context.js")) as typeof import("../main/cli/context.js");
    for (const id of ["5e55a0b1-0000-4000-8000-000000000001", "5e55a0b1-0000-4000-8000-000000000002"]) seedTranscript(id);
    const io = {
      env: { HOME: home, DOORMAN_APPDATA_DIR: appData, DOORMAN_INJECTION_CLASSIFIER: "off" },
      home,
      platform: process.platform,
      version: "0.0.0-test",
      stdout: new PassThrough(),
      stderr: new PassThrough(),
      stdin: Readable.from([""]),
      now: () => Date.now(),
      verbose: false,
    };
    // The app shows up right after this command claimed the data.
    const ctx = new CliContext(io);
    let asked = 0;
    ctx.running = () => (asked++ === 0 ? undefined : { pid: 1 });
    const handle = await ctx.openEngine({ scan: true });
    expect(handle.snapshot).toBe(false);
    handle.close();
    ctx.releaseWrite();
    // Stopped before reading a file: nothing half-written for the app to inherit.
    expect(existsSync(storeFile("turns.jsonl"))).toBe(false);
    // Nobody showing up: the same scan reads both sessions.
    const ctx2 = new CliContext(io);
    const handle2 = await ctx2.openEngine({ scan: true });
    handle2.close();
    ctx2.releaseWrite();
    const turns = readFileSync(storeFile("turns.jsonl"), "utf8");
    expect(turns).toContain("000000000001");
    expect(turns).toContain("000000000002");
  });

  it("the CLI leaves the models folder to a running app", async () => {
    const app = otherProcess();
    mkdirSync(owner.locksDir(dataDir), { recursive: true });
    writeFileSync(owner.lockPath(dataDir, "app"), JSON.stringify({ pid: app, at: new Date().toISOString(), by: "app" }));
    for (const argv of [["model", "download"], ["model", "remove"]]) {
      const r = await dm(argv);
      expect(r.code, argv.join(" ")).toBe(1);
      expect(r.err).toContain("it keeps the classifier's model itself");
    }
  });

  it("the CLI doesn't start a download the app is already running", async () => {
    owner.takeLock(dataDir, "model-download", { pid: otherProcess(), by: "app", model: "doorman-1" });
    const r = await dm(["model", "download"]);
    expect(r.code).toBe(1);
    expect(r.err).toContain("The app is already downloading the model");
  });
});

describe("one guard bundle, whichever build copied it", () => {
  const stampPath = () => join(enforcement.guardDir(dataDir), "bundle.json");
  const stamp = () => enforcement.readGuardBundleStamp(dataDir)!;
  /** Make the copied bundle another build's: change a file and stamp it as that build would. */
  function becomeOtherBuild(revision: number): void {
    const file = join(enforcement.guardDir(dataDir), "custom-rules.js");
    writeFileSync(file, `${readFileSync(file, "utf8")}\n// another build\n`);
    const files = { ...stamp().files };
    files["custom-rules.js"] = require("node:crypto").createHash("sha256").update(readFileSync(file)).digest("hex");
    writeFileSync(stampPath(), JSON.stringify({ writer: "app", revision, files }));
  }
  const intact = () => {
    const h = enforcement.guardBundleHashes(dataDir);
    return Object.entries(h.shipped).every(([f, hash]) => h.copied[f] === hash);
  };

  it("copying the bundle stamps who copied it and every file's hash", () => {
    expect(enforcement.refreshGuardBundle(dataDir)).toBe(true);
    expect(stamp().writer).toBe("cli");
    expect(Object.keys(stamp().files)).toEqual(expect.arrayContaining(["guard.js", "custom-rules.js"]));
    expect(intact()).toBe(true);
  });

  it("a newer build's bundle is its guard, not tampering — and is never downgraded", () => {
    enforcement.refreshGuardBundle(dataDir);
    becomeOtherBuild(4_000_000_000);
    expect(intact()).toBe(true);
    const report = enforcement.checkGuardIntegrity(dataDir, true, { heal: false });
    expect(report.bundle_modified).toEqual([]);
    expect(enforcement.refreshGuardBundle(dataDir)).toBe(false);
    expect(readFileSync(join(enforcement.guardDir(dataDir), "custom-rules.js"), "utf8")).toContain("// another build");
  });

  it("an older build's bundle is intact too, and the newer build upgrades it", () => {
    enforcement.refreshGuardBundle(dataDir);
    becomeOtherBuild(-1);
    expect(intact()).toBe(true);
    expect(enforcement.refreshGuardBundle(dataDir)).toBe(true);
    expect(readFileSync(join(enforcement.guardDir(dataDir), "custom-rules.js"), "utf8")).not.toContain("// another build");
  });

  it("a file edited after it was copied matches neither build: modified", () => {
    enforcement.refreshGuardBundle(dataDir);
    becomeOtherBuild(4_000_000_000);
    writeFileSync(join(enforcement.guardDir(dataDir), "guard.js"), "process.exit(0)\n");
    expect(enforcement.checkGuardIntegrity(dataDir, true, { heal: false }).bundle_modified).toContain("guard.js");
  });

  it("a stamp claiming this very build must match this build's files", () => {
    enforcement.refreshGuardBundle(dataDir);
    becomeOtherBuild(stamp().revision); // same revision, different file: not a different build
    expect(enforcement.checkGuardIntegrity(dataDir, true, { heal: false }).bundle_modified).toContain("custom-rules.js");
  });
});

describe("prefs a newer build wrote", () => {
  it("keeps keys this build doesn't know, top level and policy, and drops retired ones", () => {
    const raw = {
      ...defaultPrefs(),
      notify_daily_digest: true, // retired: folded into notify_spend_digest
      future_setting: { on: true },
      policy: { ...defaultPrefs().policy, future_policy: ["x"] },
      retention_days: 12, // known but invalid: not carried
    } as unknown as Parameters<typeof sanitizePrefs>[0];
    const prefs = sanitizePrefs(raw) as unknown as Record<string, unknown> & { policy: Record<string, unknown> };
    expect(prefs.future_setting).toEqual({ on: true });
    expect(prefs.policy.future_policy).toEqual(["x"]);
    expect(prefs).not.toHaveProperty("notify_daily_digest");
    expect(prefs.retention_days).toBe(defaultPrefs().retention_days);
    // …and they survive this build's next write.
    const again = sanitizePrefs({ ...prefs, notify_held: false } as unknown as Parameters<typeof sanitizePrefs>[0]) as unknown as Record<string, unknown>;
    expect(again.future_setting).toEqual({ on: true });
  });
});
