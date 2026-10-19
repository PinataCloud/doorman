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
 * Windows keeps the bare `node` for now: its hosts run hook commands through
 * cmd or PowerShell, where a quoted path on its own is not a command.
 */

import { createHash } from "node:crypto";
import { accessSync, chmodSync, constants, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";

export const LAUNCHER = "node-runtime";
const RUNTIMES = "runtimes.json";

/** Absolute runtime paths, each recorded by the build that runs on it. */
export interface RuntimeRecord {
  /** The doorman CLI's Node.js (process.execPath). */
  cli?: string;
  /** The desktop app's executable, run with ELECTRON_RUN_AS_NODE=1. */
  app?: string;
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

export function readRuntimes(guardDir: string): RuntimeRecord {
  try {
    const raw: unknown = JSON.parse(readFileSync(join(guardDir, RUNTIMES), "utf8"));
    if (!raw || typeof raw !== "object") return {};
    const r = raw as Record<string, unknown>;
    const out: RuntimeRecord = {};
    if (typeof r.cli === "string" && r.cli.startsWith("/")) out.cli = r.cli;
    if (typeof r.app === "string" && r.app.startsWith("/")) out.app = r.app;
    return out;
  } catch {
    return {};
  }
}

/** A path inside single quotes, for /bin/sh. */
function sq(path: string): string {
  return `'${path.replace(/'/g, `'\\''`)}'`;
}

/** The launcher for these runtimes — deterministic, so its hash is checkable. */
export function renderLauncher(runtimes: RuntimeRecord): string {
  const lines = [
    "#!/bin/sh",
    "# Written by Doorman (main/lib/node-launcher.ts): runs a Doorman script on a",
    "# Node.js runtime known to be on this machine, so the guard and Doorman's MCP",
    "# servers never depend on `node` being on the PATH of the agent starting them.",
  ];
  if (runtimes.cli) lines.push(`if [ -x ${sq(runtimes.cli)} ]; then exec ${sq(runtimes.cli)} "$@"; fi`);
  if (runtimes.app) lines.push(`if [ -x ${sq(runtimes.app)} ]; then ELECTRON_RUN_AS_NODE=1 exec ${sq(runtimes.app)} "$@"; fi`);
  lines.push('exec node "$@"', "");
  return lines.join("\n");
}

export function launcherHash(runtimes: RuntimeRecord): string {
  return createHash("sha256").update(renderLauncher(runtimes)).digest("hex");
}

/** This process's runtime: which kind, and the path that will still run it later. */
export function ownRuntime(): { kind: keyof RuntimeRecord; path: string } {
  if (process.versions.electron) {
    // A Linux AppImage runs from a mount that vanishes when it quits: the
    // AppImage file itself is what stays runnable.
    return { kind: "app", path: process.env.APPIMAGE || process.execPath };
  }
  return { kind: "cli", path: process.execPath };
}

/**
 * Record this build's runtime and (re)write the launcher from every recorded
 * one. Called whenever the guard bundle is copied in. No-op on Windows.
 */
export function writeLauncher(guardDir: string, own: { kind: keyof RuntimeRecord; path: string } = ownRuntime()): void {
  if (!usesLauncher()) return;
  mkdirSync(guardDir, { recursive: true });
  const runtimes = { ...readRuntimes(guardDir), [own.kind]: own.path };
  const write = (name: string, text: string, mode: number) => {
    const temp = join(guardDir, `${name}.doorman.tmp`);
    writeFileSync(temp, text, { mode });
    chmodSync(temp, mode);
    renameSync(temp, join(guardDir, name));
  };
  write(RUNTIMES, `${JSON.stringify(runtimes, null, 2)}\n`, 0o644);
  write(LAUNCHER, renderLauncher(runtimes), 0o755);
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
