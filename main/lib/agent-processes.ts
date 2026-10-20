/**
 * Which coding agents are RUNNING on this Mac right now — a process-table
 * read, nothing more.
 *
 * The ledger knows every session that ever wrote a transcript, but a
 * transcript cannot say whether the agent that wrote it is still alive, so
 * "active" used to mean "wrote something recently". This module reads `ps`
 * (pid, parent, tty, start time, command) and `lsof` (each agent's working
 * directory; `/proc/<pid>/cwd` on Linux) and recognises the agent CLIs by
 * their command line. The fold that joins a process to a ledger session
 * lives in live-sessions.ts.
 *
 * Pure parsers over the tools' text output, plus one runner that shells out.
 * Nothing here is uploaded; the process table never leaves the machine.
 */

import { execFile } from "node:child_process";
import { readlinkSync } from "node:fs";
import type { TurnSource } from "./turns.js";

/** One running agent. `tty` is the controlling terminal's device name
 * (`ttys003`), or undefined when the agent runs headless (`claude -p` in a
 * script, a hook-spawned child) — nothing can be focused then. */
export interface AgentProcess {
  pid: number;
  ppid: number;
  source: TurnSource;
  /** The agent's argv as ps prints it, for the row's tooltip. */
  command: string;
  tty?: string;
  /** ISO instant the process started (ps `lstart`). */
  started_at: string;
  cwd?: string;
  /** The terminal application the process runs inside, from the nearest
   * ancestor that is a macOS app bundle — "Terminal", "iTerm2", "ghostty",
   * "Cursor", … Undefined when no ancestor is an app (a launchd job, ssh). */
  terminal_app?: string;
  /** Whether a tmux server sits between the agent and its terminal — the
   * tty then belongs to tmux's pane, not to a window the app can focus. */
  tmux?: boolean;
}

/** One row of the whole process table — kept so presence records (the
 * guard's ppid) can be walked up to the agent that spawned the hook. */
export interface ProcessRow {
  pid: number;
  ppid: number;
  tty?: string;
  started_at: string;
  command: string;
}

/** Agent CLIs by the basename of their executable. Node-hosted CLIs (an npm
 * install of Claude Code runs as `node …/cli.js`) are recognised by the
 * package path in the script argument instead — see `sourceForCommand`. */
const BINARY_SOURCES: readonly { test: RegExp; source: TurnSource }[] = [
  { test: /^claude$/, source: "claude-code" },
  { test: /^codex(-[a-z0-9_]+-apple-darwin)?$/, source: "codex" },
  { test: /^gemini$/, source: "gemini-cli" },
  { test: /^copilot$/, source: "copilot-cli" },
  { test: /^goose$/, source: "goose" },
  { test: /^qwen$/, source: "qwen-code" },
  { test: /^hermes$/, source: "hermes" },
  { test: /^openclaw$/, source: "openclaw" },
];

const SCRIPT_SOURCES: readonly { test: RegExp; source: TurnSource }[] = [
  { test: /@anthropic-ai\/claude-code\//, source: "claude-code" },
  { test: /@openai\/codex\//, source: "codex" },
  { test: /@google\/gemini-cli\//, source: "gemini-cli" },
  { test: /@github\/copilot\//, source: "copilot-cli" },
  { test: /@qwen-code\/qwen-code\//, source: "qwen-code" },
  { test: /\/openclaw\/(dist|bin)\//, source: "openclaw" },
];

const RUNTIMES = new Set(["node", "bun", "deno"]);

/** Subcommands that are not a person's session even though the binary is the
 * agent's: MCP stdio servers, one-shot helpers, our own installs. */
const NOT_A_SESSION = /^(mcp\b|--version|-v\b|doctor\b|update\b|install\b|migrate-installer\b|login\b|logout\b|completion\b|exec\b|--help|-h\b)/;

/** Which agent a command line is, or undefined for everything else. */
export function sourceForCommand(command: string): TurnSource | undefined {
  const argv = splitArgv(command);
  if (argv.length === 0) return undefined;
  const exe = basename(argv[0]!);
  let source: TurnSource | undefined;
  let rest: string[];
  if (RUNTIMES.has(exe)) {
    // `node [flags] script args…` — the first non-flag argument is the script.
    const idx = argv.findIndex((a, i) => i > 0 && !a.startsWith("-"));
    if (idx < 0) return undefined;
    const script = argv[idx]!;
    source = SCRIPT_SOURCES.find((s) => s.test.test(script))?.source;
    rest = argv.slice(idx + 1);
  } else {
    source = BINARY_SOURCES.find((s) => s.test.test(exe))?.source;
    rest = argv.slice(1);
  }
  if (!source) return undefined;
  if (NOT_A_SESSION.test(rest.join(" "))) return undefined;
  return source;
}

function basename(path: string): string {
  const i = path.lastIndexOf("/");
  return i < 0 ? path : path.slice(i + 1);
}

/** ps prints argv space-joined with no quoting, so a path with a space is
 * ambiguous — good enough for recognising an executable, which is all this
 * does. */
function splitArgv(command: string): string[] {
  return command.trim().split(/\s+/).filter((a) => a !== "");
}

/**
 * Parse `ps -axo pid=,ppid=,tty=,lstart=,command=`. `lstart` is a fixed
 * 24-character `Mon Sep  7 16:24:18 2026` (weekday, month, day, time, year),
 * so the row is split positionally: three integers-ish columns, then the five
 * lstart words, then the rest is the command.
 */
export function parsePsTable(text: string, now: Date = new Date()): ProcessRow[] {
  const rows: ProcessRow[] = [];
  for (const line of text.split("\n")) {
    const m = /^\s*(\d+)\s+(\d+)\s+(\S+)\s+(\S{3}\s+\S{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4})\s+(.*)$/.exec(line);
    if (!m) continue;
    const tty = m[3]!;
    rows.push({
      pid: Number(m[1]),
      ppid: Number(m[2]),
      ...(tty === "??" || tty === "?" || tty === "-" ? {} : { tty }),
      started_at: parseLstart(m[4]!, now),
      command: m[5]!.trim(),
    });
  }
  return rows;
}

const MONTHS: Record<string, number> = {
  Jan: 0, Feb: 1, Mar: 2, Apr: 3, May: 4, Jun: 5, Jul: 6, Aug: 7, Sep: 8, Oct: 9, Nov: 10, Dec: 11,
};

/** `lstart` is local time with no zone; build the Date in local time. A
 * malformed value falls back to `now` rather than to the epoch — a process
 * that "started in 1970" would sort as the oldest thing on the machine. */
export function parseLstart(text: string, now: Date): string {
  const m = /^\S{3}\s+(\S{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\s+(\d{4})$/.exec(text.trim());
  if (!m) return now.toISOString();
  const month = MONTHS[m[1]!];
  if (month === undefined) return now.toISOString();
  const d = new Date(Number(m[6]), month, Number(m[2]), Number(m[3]), Number(m[4]), Number(m[5]));
  return Number.isNaN(d.getTime()) ? now.toISOString() : d.toISOString();
}

/** Parse `lsof -a -d cwd -Fpn -p <pids>`: a `p<pid>` line opens each
 * process, `n<path>` names its cwd. */
export function parseLsofCwd(text: string): Map<number, string> {
  const out = new Map<number, string>();
  let pid: number | undefined;
  for (const line of text.split("\n")) {
    if (line.startsWith("p")) pid = Number(line.slice(1));
    else if (line.startsWith("n") && pid !== undefined) out.set(pid, line.slice(1));
  }
  return out;
}

/** The app BUNDLE name from a path like `/Applications/iTerm.app/Contents/MacOS/ShellLauncher`
 * → "iTerm" — the name `open -a` and AppleScript both accept, and stable
 * across the helper executables a terminal launches shells through (iTerm2's
 * login line names ShellLauncher, not iTerm2). Undefined when the command is
 * not inside a bundle. */
export function appNameForCommand(command: string): string | undefined {
  const m = /\/([^/]+)\.app\/Contents\//.exec(command);
  if (!m) return undefined;
  return m[1]!;
}

/** Terminal-ish bundles worth naming. Anything else inside a `.app` (an
 * editor's integrated terminal, Claude Desktop) is still returned — the
 * fold only uses the name to pick a focus strategy, and unknown apps get
 * the generic "activate" one. */
export function terminalAncestor(
  proc: ProcessRow,
  table: ReadonlyMap<number, ProcessRow>,
): { app?: string; tmux: boolean } {
  let tmux = false;
  let cur: ProcessRow | undefined = table.get(proc.ppid);
  for (let hops = 0; cur && hops < 12; hops += 1) {
    if (/(^|\/)tmux(:|\s|$)/.test(cur.command)) tmux = true;
    const app = appNameForCommand(cur.command);
    if (app) return { app, tmux };
    if (cur.pid <= 1) break;
    cur = table.get(cur.ppid);
  }
  return { tmux };
}

/** Recognise the agents in a parsed table and decorate them with cwd and
 * terminal ancestry. Pure — the runner below supplies both inputs. */
export function agentProcesses(
  rows: readonly ProcessRow[],
  cwds: ReadonlyMap<number, string>,
  ownPid?: number,
): AgentProcess[] {
  const table = new Map(rows.map((r) => [r.pid, r]));
  const out: AgentProcess[] = [];
  for (const row of rows) {
    if (row.pid === ownPid) continue;
    const source = sourceForCommand(row.command);
    if (!source) continue;
    // A `claude` whose parent is itself a `claude` is a subprocess of the
    // same session (a resumed fork, a nested tool) — one row per session.
    const parent = table.get(row.ppid);
    if (parent && sourceForCommand(parent.command) === source) continue;
    const anc = terminalAncestor(row, table);
    const cwd = cwds.get(row.pid);
    out.push({
      pid: row.pid,
      ppid: row.ppid,
      source,
      command: row.command,
      ...(row.tty === undefined ? {} : { tty: row.tty }),
      started_at: row.started_at,
      ...(cwd === undefined ? {} : { cwd }),
      ...(anc.app === undefined ? {} : { terminal_app: anc.app }),
      ...(anc.tmux ? { tmux: true } : {}),
    });
  }
  return out.sort((a, b) => a.pid - b.pid);
}

/** Walk from a pid (typically the guard hook's parent) up to the nearest
 * agent process — the hook may sit under a `sh -c` wrapper. Undefined when
 * the chain reaches launchd without meeting one. */
export function agentAncestorPid(
  pid: number,
  table: ReadonlyMap<number, ProcessRow>,
  agents: ReadonlySet<number>,
): number | undefined {
  let cur = table.get(pid);
  for (let hops = 0; cur && hops < 8; hops += 1) {
    if (agents.has(cur.pid)) return cur.pid;
    if (cur.pid <= 1) return undefined;
    cur = table.get(cur.ppid);
  }
  return undefined;
}

export interface ProcessInventory {
  at: string;
  rows: ProcessRow[];
  agents: AgentProcess[];
}

/** A process's cwd, remembered by (pid, start time) so lsof — the expensive
 * half of a tick — runs only for agents not seen before. An agent's cwd does
 * not move (the CLIs never chdir), and a recycled pid has a new start time. */
const cwdCache = new Map<number, { started_at: string; cwd: string | undefined }>();

function run(file: string, args: string[], timeoutMs: number): Promise<string> {
  return new Promise((resolve) => {
    execFile(file, args, { timeout: timeoutMs, maxBuffer: 8 * 1024 * 1024 }, (err, stdout) => {
      // lsof exits 1 when any pid had nothing to report — its stdout is
      // still the answer for the others. ps failing yields an empty table.
      resolve(typeof stdout === "string" ? stdout : err ? "" : String(stdout));
    });
  });
}

/** Read the process table and each agent's cwd. ~30–80 ms on a busy Mac;
 * the caller decides the cadence. Never throws. */
export async function readProcessInventory(now: Date = new Date()): Promise<ProcessInventory> {
  const ps = await run("/bin/ps", ["-axo", "pid=,ppid=,tty=,lstart=,command="], 4_000);
  const rows = parsePsTable(ps, now);
  const candidates = rows.filter((r) => sourceForCommand(r.command) !== undefined && r.pid !== process.pid);
  const cwds = new Map<number, string>();
  const lookup: ProcessRow[] = [];
  for (const r of candidates) {
    const hit = cwdCache.get(r.pid);
    if (hit && hit.started_at === r.started_at) {
      if (hit.cwd !== undefined) cwds.set(r.pid, hit.cwd);
    } else lookup.push(r);
  }
  if (lookup.length > 0) {
    const found =
      process.platform === "linux"
        ? procCwds(lookup)
        : parseLsofCwd(await run("/usr/sbin/lsof", ["-a", "-d", "cwd", "-Fpn", "-p", lookup.map((r) => r.pid).join(",")], 4_000));
    for (const r of lookup) {
      const cwd = found.get(r.pid);
      cwdCache.set(r.pid, { started_at: r.started_at, cwd });
      if (cwd !== undefined) cwds.set(r.pid, cwd);
    }
  }
  // Forget pids that are gone, so the cache tracks the table, not history.
  const alive = new Set(candidates.map((r) => r.pid));
  for (const pid of cwdCache.keys()) if (!alive.has(pid)) cwdCache.delete(pid);
  return { at: now.toISOString(), rows, agents: agentProcesses(rows, cwds, process.pid) };
}

/** Linux: each process's cwd is its `/proc/<pid>/cwd` link. Ubuntu keeps
 * lsof in /usr/bin, not /usr/sbin, when it installs it at all, so every
 * agent there had no cwd and could not join its session. A process that has
 * exited since ps, or is another user's, has no readable link and no cwd. */
function procCwds(rows: readonly ProcessRow[]): Map<number, string> {
  const out = new Map<number, string>();
  for (const r of rows) {
    try {
      out.set(r.pid, readlinkSync(`/proc/${r.pid}/cwd`));
    } catch {
      // gone, or not ours
    }
  }
  return out;
}
