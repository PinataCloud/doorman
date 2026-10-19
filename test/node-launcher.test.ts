/**
 * The guard and Doorman's MCP servers run on a Node.js runtime Doorman knows
 * is on the machine — never on whatever `node` the starting agent's PATH has,
 * because without one the hook silently didn't run (every agent allows on a
 * hook that fails to start). lib/node-launcher.ts.
 *
 * The integrity cases drive the COMPILED tree (the guard bundle is copied
 * from build/main/guard), like the CLI tests.
 */
import { spawnSync } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { LAUNCHER, launcherPath, readRuntimes, renderLauncher, writeLauncher } from "../main/lib/node-launcher.js";

/* eslint-disable @typescript-eslint/no-require-imports */
const build = join(__dirname, "..", "build", "main");
const enforcement = require(join(build, "enforcement.js")) as typeof import("../main/enforcement.js");
const ELECTRON = join(__dirname, "..", "node_modules", "electron", "dist", "Electron.app", "Contents", "MacOS", "Electron");

const unix = process.platform !== "win32";
let root: string;
let guard: string;
let saved: string | undefined;

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), "doorman-launcher-"));
  guard = join(root, "doorman", "guard");
  saved = process.env.HOME;
  process.env.HOME = join(root, "home");
  mkdirSync(join(root, "home", ".claude"), { recursive: true });
});

afterEach(() => {
  if (saved === undefined) delete process.env.HOME;
  else process.env.HOME = saved;
  rmSync(root, { recursive: true, force: true });
});

/** Run the launcher on a one-line script, with NO node on the PATH. */
function runWithoutNodeOnPath(code: string): { status: number | null; out: string; err: string } {
  const script = join(root, "probe.js");
  writeFileSync(script, code);
  const r = spawnSync(launcherPath(guard), [script], { env: { PATH: "/usr/bin:/bin", HOME: root }, encoding: "utf8" });
  return { status: r.status, out: r.stdout, err: r.stderr };
}

describe.skipIf(!unix)("the node launcher", () => {
  it("tries the CLI's node, then the app's runtime, then the PATH — paths quoted for sh", () => {
    const text = renderLauncher({ cli: "/opt/it's here/node", app: "/Applications/Doorman.app/Contents/MacOS/Doorman" });
    const lines = text.split("\n");
    expect(lines[0]).toBe("#!/bin/sh");
    const cli = lines.findIndex((l) => l.includes(`'/opt/it'\\''s here/node'`));
    const app = lines.findIndex((l) => l.includes("ELECTRON_RUN_AS_NODE=1 exec '/Applications/Doorman.app/Contents/MacOS/Doorman'"));
    const path = lines.indexOf('exec node "$@"');
    expect(cli).toBeGreaterThan(0);
    expect(app).toBeGreaterThan(cli);
    expect(path).toBeGreaterThan(app);
  });

  it("each build records its own runtime and keeps the other's; the launcher is executable", () => {
    writeLauncher(guard, { kind: "app", path: "/Applications/Doorman.app/Contents/MacOS/Doorman" });
    writeLauncher(guard, { kind: "cli", path: process.execPath });
    expect(readRuntimes(guard)).toEqual({ app: "/Applications/Doorman.app/Contents/MacOS/Doorman", cli: process.execPath });
    expect(statSync(launcherPath(guard)).mode & 0o111).not.toBe(0);
    expect(readFileSync(launcherPath(guard), "utf8")).toBe(renderLauncher(readRuntimes(guard)));
  });

  it("runs a script with no node on the PATH at all — the CLI's runtime", () => {
    writeLauncher(guard, { kind: "cli", path: process.execPath });
    const r = runWithoutNodeOnPath("console.log('ran on', process.version)");
    expect(r.status).toBe(0);
    expect(r.out).toContain(`ran on ${process.version}`);
  });

  it.skipIf(!existsSync(ELECTRON))("…and on the app's own runtime when the CLI's is gone", () => {
    writeLauncher(guard, { kind: "cli", path: join(root, "uninstalled", "node") });
    writeLauncher(guard, { kind: "app", path: ELECTRON });
    const r = runWithoutNodeOnPath("console.log('electron', typeof process.versions.electron)");
    expect(r.status).toBe(0);
    expect(r.out).toContain("electron string");
  });

  it("with nothing recorded it is `node` on the PATH, as before", () => {
    writeLauncher(guard, { kind: "cli", path: join(root, "uninstalled", "node") });
    expect(runWithoutNodeOnPath("0").err).toMatch(/node: (command )?not found/);
  });
});

describe.skipIf(!unix)("the guard, wired through the launcher", () => {
  const dataDir = () => root;

  it("the hook command starts the launcher, and the copied bundle writes it", () => {
    enforcement.refreshGuardBundle(dataDir());
    const command = enforcement.guardCommand(dataDir());
    expect(command).toBe(`"${launcherPath(guard)}" "${join(guard, "guard.js")}"`);
    expect(existsSync(launcherPath(guard))).toBe(true);
    // The real hook, run the way an agent's shell runs it, with no node on the PATH.
    const call = JSON.stringify({ session_id: "s", transcript_path: "/tmp/x.jsonl", hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command: "ls" }, cwd: "/tmp" });
    const r = spawnSync("/bin/sh", ["-c", command], { input: call, env: { PATH: "/usr/bin:/bin", HOME: join(root, "home") }, encoding: "utf8" });
    expect(r.stderr).not.toMatch(/not found/);
    expect(r.status).toBe(0);
  });

  it("an edited launcher, or one that lost its exec bit, is drift — and healing rewrites it", () => {
    enforcement.refreshGuardBundle(dataDir());
    writeFileSync(launcherPath(guard), "#!/bin/sh\nexit 0\n");
    expect(enforcement.checkGuardIntegrity(dataDir(), true, { heal: false }).bundle_modified).toContain(LAUNCHER);
    enforcement.refreshGuardBundle(dataDir());
    chmodSync(launcherPath(guard), 0o644);
    const healed = enforcement.checkGuardIntegrity(dataDir(), true);
    expect(healed.healed_bundle).toBe(true);
    expect(statSync(launcherPath(guard)).mode & 0o111).not.toBe(0);
    expect(enforcement.checkGuardIntegrity(dataDir(), true, { heal: false }).bundle_modified).toEqual([]);
  });

  it("an entry an older build wrote (`node \"…/guard.js\"`) still reads as an intact guard", () => {
    const { defaultPrefs } = require(join(build, "state.js")) as typeof import("../main/state.js");
    expect(enforcement.installGuard(dataDir(), defaultPrefs().policy).ok).toBe(true);
    // What a build before the launcher wrote: the same entry, a bare `node`.
    const settings = join(root, "home", ".claude", "settings.json");
    const ours = readFileSync(settings, "utf8");
    const legacy = ours.split(`\\"${launcherPath(guard)}\\" `).join("node ");
    expect(legacy).not.toBe(ours);
    writeFileSync(settings, legacy);
    expect(enforcement.checkGuardIntegrity(dataDir(), true, { heal: false }).status).toBe("healthy");
  });
});
