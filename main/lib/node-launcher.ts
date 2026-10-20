/**
 * The Node.js runtime Doorman's own hooks and servers run on.
 *
 * Everything Doorman installs into another program — the guard hook in each
 * agent, Doorman's MCP server, the MCP gateway — is a Node script that the
 * OTHER program starts. A bare `node` made that depend on Node.js being on that
 * program's PATH, and it often isn't: Claude Code's native installer and Codex
 * need no Node.js at all. Without it the hook never started, which every agent
 * treats as "allow", so the guard was silently off while Doorman said it was on.
 *
 * So the command names a launcher Doorman writes beside the guard,
 * `<guard dir>/node-runtime`, which runs the script on a runtime Doorman knows
 * is on this machine, in order: the Node.js the doorman CLI runs on (absolute
 * path, fastest), the desktop app's own runtime (its executable with
 * ELECTRON_RUN_AS_NODE), and only then `node` from the PATH. The app and the
 * CLI each record their runtime in `<guard dir>/runtimes.json` and write the
 * same launcher from it, so the command in every agent's settings is the same
 * whichever of them installed it — and stays valid when one is removed.
 *
 * A runtime being there is not the same as it running the guard: the 0.5.2
 * AppImage was there on every Ubuntu machine and exited 9 on every hook call
 * (see APP_SHIM). So each recorded runtime is PROBED once — a one-line script
 * it must run and answer — whenever its file changes, the result goes into
 * runtimes.json, and a runtime that failed is left out of the launcher so the
 * next one runs the guard. When none works, `runtimeHealth` says so and every
 * screen that reports the guard shows it as not working.
 *
 * The launcher's contract is `node-runtime <script> [args…]`: a script path
 * first, never node options (the app's runtime takes none, see APP_SHIM).
 *
 * Windows keeps the bare `node` for now: its hosts run hook commands through
 * cmd or PowerShell, where a quoted path on its own is not a command.
 */

import { spawnSync, type SpawnSyncReturns } from "node:child_process";
import { createHash } from "node:crypto";
import { accessSync, chmodSync, constants, mkdirSync, mkdtempSync, readFileSync, renameSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, dirname, join } from "node:path";

export const LAUNCHER = "node-runtime";
const RUNTIMES = "runtimes.json";

export type RuntimeKind = "cli" | "app";
/** Launcher order: the CLI's Node.js first (fastest start), then the app's. */
const KINDS: readonly RuntimeKind[] = ["cli", "app"];

/** One runtime's last probe. Tied to the file it ran: a different path, or the
 * same path with a different size or mtime (an update), is probed again. */
export interface RuntimeProbe {
  path: string;
  /** `<size>:<mtime ms>` of the runtime when it was probed. */
  stamp: string;
  /** `missing`: not there (or not executable) — the launcher's `[ -x ]` skips
   * it on its own, and keeps it for when it comes back. `failed`: there, but
   * it did not run the probe script, so the launcher leaves it out. */
  outcome: "ok" | "failed" | "missing";
  /** Why it failed, e.g. `bad option: --no-sandbox (exit 9)`. */
  error?: string;
}

/** Absolute runtime paths, each recorded by the build that runs on it, and
 * what each did when probed. */
export interface RuntimeRecord {
  /** The doorman CLI's Node.js (process.execPath). */
  cli?: string;
  /** The desktop app's executable (a Linux AppImage file), run with ELECTRON_RUN_AS_NODE=1. */
  app?: string;
  probes?: Partial<Record<RuntimeKind, RuntimeProbe>>;
}

export function usesLauncher(platform: NodeJS.Platform = process.platform): boolean {
  return platform !== "win32";
}

export function launcherPath(guardDir: string): string {
  return join(guardDir, LAUNCHER);
}

/** The interpreter as a program to execute (an MCP entry's `command`). */
export function nodeProgram(guardDir: string, platform: NodeJS.Platform = process.platform): string {
  return usesLauncher(platform) ? launcherPath(guardDir) : "node";
}

/** The interpreter as the start of a shell command line (a hook command). */
export function nodeCommandPrefix(guardDir: string, platform: NodeJS.Platform = process.platform): string {
  return usesLauncher(platform) ? `"${launcherPath(guardDir)}"` : "node";
}

/** For a script under `<data>/doorman/<part>/`: the interpreter beside the guard. */
export function nodeProgramForScript(script: string, platform: NodeJS.Platform = process.platform): string {
  return nodeProgram(join(dirname(dirname(script)), "guard"), platform);
}

function readProbe(raw: unknown): RuntimeProbe | undefined {
  if (!raw || typeof raw !== "object") return undefined;
  const p = raw as Record<string, unknown>;
  if (typeof p.path !== "string" || typeof p.stamp !== "string") return undefined;
  if (p.outcome !== "ok" && p.outcome !== "failed" && p.outcome !== "missing") return undefined;
  return { path: p.path, stamp: p.stamp, outcome: p.outcome, ...(typeof p.error === "string" ? { error: p.error } : {}) };
}

export function readRuntimes(guardDir: string): RuntimeRecord {
  try {
    const raw: unknown = JSON.parse(readFileSync(join(guardDir, RUNTIMES), "utf8"));
    if (!raw || typeof raw !== "object") return {};
    const r = raw as Record<string, unknown>;
    const out: RuntimeRecord = {};
    if (typeof r.cli === "string" && r.cli.startsWith("/")) out.cli = r.cli;
    if (typeof r.app === "string" && r.app.startsWith("/")) out.app = r.app;
    if (r.probes && typeof r.probes === "object") {
      const probes: Partial<Record<RuntimeKind, RuntimeProbe>> = {};
      for (const kind of KINDS) {
        const probe = readProbe((r.probes as Record<string, unknown>)[kind]);
        if (probe) probes[kind] = probe;
      }
      if (Object.keys(probes).length > 0) out.probes = probes;
    }
    return out;
  } catch {
    return {};
  }
}

/** A path inside single quotes, for /bin/sh. */
function sq(path: string): string {
  return `'${path.replace(/'/g, `'\\''`)}'`;
}

/**
 * How the launcher starts the app's runtime on a script. A Linux AppImage is
 * not the Electron binary: its AppRun script runs first and, when
 * `unshare -Ur true` fails (Ubuntu's default
 * kernel.apparmor_restrict_unprivileged_userns=1), puts `--no-sandbox` in
 * FRONT of the arguments. Electron in node mode rejects it — "bad option:
 * --no-sandbox", exit 9 — and every agent reads exit 9 from a hook as "allow".
 * AppRun adds the flag only when no argument already is `--no-sandbox`, so the
 * launcher passes it itself, after `--`, where node takes it as an argument;
 * this line drops it and runs the script as the main module. The same line
 * runs the plain Electron binary (macOS, the .deb) unchanged.
 */
const APP_SHIM = 'const a=process.argv;if(a[1]==="--no-sandbox")a.splice(1,1);a[1]=require("path").resolve(a[1]);require("module").runMain()';

/** The exec line that runs `"$@"` (script and its arguments) on one runtime. */
function runtimeExec(kind: RuntimeKind, path: string): string {
  return kind === "cli"
    ? `exec ${sq(path)} "$@"`
    : `ELECTRON_RUN_AS_NODE=1 exec ${sq(path)} -e ${sq(APP_SHIM)} -- --no-sandbox "$@"`;
}

/** A runtime the launcher runs: recorded, and not known to fail. */
function launchable(runtimes: RuntimeRecord, kind: RuntimeKind): string | undefined {
  const path = runtimes[kind];
  if (!path) return undefined;
  const probe = runtimes.probes?.[kind];
  return probe && probe.path === path && probe.outcome === "failed" ? undefined : path;
}

/** The launcher for these runtimes — deterministic, so its hash is checkable. */
export function renderLauncher(runtimes: RuntimeRecord): string {
  const lines = [
    "#!/bin/sh",
    "# Written by Doorman (main/lib/node-launcher.ts): runs a Doorman script on a",
    "# Node.js runtime known to be on this machine, so the guard and Doorman's MCP",
    "# servers never depend on `node` being on the PATH of the agent starting them.",
  ];
  for (const kind of KINDS) {
    const path = launchable(runtimes, kind);
    if (path) lines.push(`if [ -x ${sq(path)} ]; then ${runtimeExec(kind, path)}; fi`);
  }
  lines.push('exec node "$@"', "");
  return lines.join("\n");
}

export function launcherHash(runtimes: RuntimeRecord): string {
  return createHash("sha256").update(renderLauncher(runtimes)).digest("hex");
}

export interface OwnRuntime {
  kind: RuntimeKind;
  path: string;
}

/** This process's runtime: which kind, and the path that will still run it later. */
export function ownRuntime(): OwnRuntime {
  if (process.versions.electron) {
    // A Linux AppImage runs from a mount that vanishes when it quits: the
    // AppImage file itself is what stays runnable.
    return { kind: "app", path: process.env.APPIMAGE || process.execPath };
  }
  return { kind: "cli", path: process.execPath };
}

/** What the runtimes did when last probed. */
export interface RuntimeHealth {
  /** At least one recorded runtime runs the guard. */
  ok: boolean;
  /** The runtime the launcher runs first, when one works. */
  using?: { kind: RuntimeKind; path: string };
  runtimes: { kind: RuntimeKind; path: string; outcome: RuntimeProbe["outcome"] | "unprobed"; error?: string }[];
  /** One sentence, when none works. */
  error?: string;
}

/** `Node.js at /usr/bin/node`, `the Doorman app at …/Doorman.AppImage`. */
export function runtimeLabel(kind: RuntimeKind, path: string): string {
  return kind === "cli" ? `Node.js at ${path}` : `the Doorman app at ${path}`;
}

/**
 * The verdict a runtimes.json carries. A runtime nobody probed (an older
 * build recorded it) neither proves nor disproves anything; the launcher
 * still tries it.
 */
export function runtimeHealth(runtimes: RuntimeRecord): RuntimeHealth {
  const list: RuntimeHealth["runtimes"] = [];
  for (const kind of KINDS) {
    const path = runtimes[kind];
    if (!path) continue;
    const probe = runtimes.probes?.[kind];
    if (probe && probe.path === path) list.push({ kind, path, outcome: probe.outcome, ...(probe.error ? { error: probe.error } : {}) });
    else list.push({ kind, path, outcome: "unprobed" });
  }
  const working = list.find((r) => r.outcome === "ok") ?? list.find((r) => r.outcome === "unprobed");
  if (working) return { ok: true, using: { kind: working.kind, path: working.path }, runtimes: list };
  const why = list.map((r) => `${runtimeLabel(r.kind, r.path)}: ${r.outcome === "missing" ? "not found" : (r.error ?? "failed")}`);
  return {
    ok: false,
    runtimes: list,
    error: `The guard can't start on this computer, so agents run their tools unguarded (${why.length > 0 ? why.join("; ") : "no runtime is recorded"})`,
  };
}

/** `<size>:<mtime>` of an executable runtime, or undefined when it isn't one. */
function runtimeStamp(path: string): string | undefined {
  try {
    accessSync(path, constants.X_OK);
    const st = statSync(path);
    return st.isFile() ? `${st.size}:${Math.trunc(st.mtimeMs)}` : undefined;
  } catch {
    return undefined;
  }
}

const PROBE_MARK = "doorman-runtime-ok";
const PROBE_TIMEOUT_MS = 15_000;

/**
 * The environment an agent would start the hook in, as near as this process
 * can tell: without what an AppImage's AppRun exported into THIS process (its
 * mount on PATH and LD_LIBRARY_PATH, APPDIR) and without anything that changes
 * how node starts.
 */
export function probeEnv(env: NodeJS.ProcessEnv = process.env): NodeJS.ProcessEnv {
  const out: NodeJS.ProcessEnv = { ...env };
  for (const key of ["ELECTRON_RUN_AS_NODE", "NODE_OPTIONS", "APPDIR", "APPIMAGE", "ARGV0", "OWD"]) delete out[key];
  const mount = env.APPDIR;
  if (mount) {
    for (const key of ["PATH", "LD_LIBRARY_PATH"]) {
      const kept = (out[key] ?? "").split(delimiter).filter((p) => p !== "" && !p.startsWith(mount));
      if (kept.length > 0) out[key] = kept.join(delimiter);
      else delete out[key];
    }
  }
  return out;
}

/** Why a probe run failed, in one line: the runtime's own last stderr line
 * (minus its leading program path) and its exit code. */
function probeError(r: SpawnSyncReturns<string>): string {
  if (r.error) {
    const code = (r.error as NodeJS.ErrnoException).code;
    return code === "ETIMEDOUT" ? `no answer within ${PROBE_TIMEOUT_MS / 1000} seconds` : r.error.message;
  }
  const line = (r.stderr ?? "")
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l !== "")
    .pop()
    ?.replace(/^\/\S*: /, "")
    .slice(0, 200);
  const how = r.signal ? `killed by ${r.signal}` : `exit ${r.status}`;
  return line ? `${line} (${how})` : how === "exit 0" ? "it ran, but did not answer" : how;
}

/** Run `argv` on a one-line script that must answer; ok, or why not. */
function runProbe(argv: [string, ...string[]]): { ok: true } | { ok: false; error: string } {
  const dir = mkdtempSync(join(tmpdir(), "doorman-probe-"));
  try {
    const script = join(dir, "probe.js");
    writeFileSync(script, `process.stdout.write(${JSON.stringify(PROBE_MARK)});\n`);
    const r = spawnSync(argv[0], [...argv.slice(1), script], {
      input: "",
      encoding: "utf8",
      timeout: PROBE_TIMEOUT_MS,
      killSignal: "SIGKILL",
      env: probeEnv(),
    });
    if (!r.error && r.status === 0 && (r.stdout ?? "").includes(PROBE_MARK)) return { ok: true };
    return { ok: false, error: probeError(r) };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

/** Run a one-line script on one runtime, exactly as the launcher would start it. */
export function probeRuntime(kind: RuntimeKind, path: string): RuntimeProbe {
  const stamp = runtimeStamp(path);
  if (stamp === undefined) return { path, stamp: "missing", outcome: "missing" };
  const r = runProbe(["/bin/sh", "-c", runtimeExec(kind, path), "sh"]);
  return r.ok ? { path, stamp, outcome: "ok" } : { path, stamp, outcome: "failed", error: r.error };
}

/** Run a one-line script through the launcher on disk: what an agent starts. */
export function probeLauncher(guardDir: string): { ok: true } | { ok: false; error: string } {
  const path = launcherPath(guardDir);
  try {
    accessSync(path, constants.X_OK);
  } catch {
    return { ok: false, error: `${path} is missing or not executable` };
  }
  return runProbe([path]);
}

/**
 * Bring runtimes.json and the launcher up to date: record `own` (this build's
 * runtime), probe each recorded runtime whose file changed since its last
 * probe — every one with `fresh` — and rewrite the launcher from the results.
 * Writes only what differs (a launcher that lost its exec bit counts), so the
 * common call, nothing changed, costs a stat per runtime and no spawn.
 * `persist: false` probes and reports without writing anything.
 */
export function updateRuntimes(
  guardDir: string,
  options: { own?: OwnRuntime; fresh?: boolean; persist?: boolean } = {},
): RuntimeHealth {
  if (!usesLauncher()) return { ok: true, runtimes: [] };
  const before = readRuntimes(guardDir);
  const next: RuntimeRecord = {};
  if (before.cli) next.cli = before.cli;
  if (before.app) next.app = before.app;
  if (options.own) next[options.own.kind] = options.own.path;
  const probes: Partial<Record<RuntimeKind, RuntimeProbe>> = {};
  for (const kind of KINDS) {
    const path = next[kind];
    if (!path) continue;
    const prior = before.probes?.[kind];
    const reuse = !options.fresh && prior !== undefined && prior.path === path && prior.stamp === (runtimeStamp(path) ?? "missing");
    probes[kind] = reuse ? prior : probeRuntime(kind, path);
  }
  if (Object.keys(probes).length > 0) next.probes = probes;
  if (options.persist !== false) {
    mkdirSync(guardDir, { recursive: true });
    const write = (name: string, text: string, mode: number) => {
      const temp = join(guardDir, `${name}.doorman.tmp`);
      writeFileSync(temp, text, { mode });
      chmodSync(temp, mode);
      renameSync(temp, join(guardDir, name));
    };
    const json = `${JSON.stringify(next, null, 2)}\n`;
    let onDisk: string | undefined;
    try {
      onDisk = readFileSync(join(guardDir, RUNTIMES), "utf8");
    } catch {
      onDisk = undefined;
    }
    if (onDisk !== json) write(RUNTIMES, json, 0o644);
    if (launcherOnDiskHash(guardDir) !== launcherHash(next)) write(LAUNCHER, renderLauncher(next), 0o755);
  }
  return runtimeHealth(next);
}

/**
 * Record this build's runtime and (re)write the launcher from every recorded
 * one that works. Called whenever the guard bundle is copied in. No-op on
 * Windows.
 */
export function writeLauncher(guardDir: string, own: OwnRuntime = ownRuntime(), options: { fresh?: boolean } = {}): RuntimeHealth {
  return updateRuntimes(guardDir, { own, ...(options.fresh ? { fresh: true } : {}) });
}

/** The launcher's hash as it is on disk, or undefined when it is missing or
 * not executable (an agent can't start it either way). */
export function launcherOnDiskHash(guardDir: string): string | undefined {
  const path = launcherPath(guardDir);
  try {
    accessSync(path, constants.X_OK);
    return createHash("sha256").update(readFileSync(path)).digest("hex");
  } catch {
    return undefined;
  }
}
