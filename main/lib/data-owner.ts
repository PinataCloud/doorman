/**
 * Who may write the shared data directory right now — the desktop app and the
 * CLI use one store, one prefs file, one guard and one models folder, and only
 * one of them may write at a time.
 *
 * Three small lock files under `<userData>/doorman/locks/`, each naming the pid
 * that holds it (a lock whose process is gone is stale, so a crash never wedges
 * anything):
 *
 *  · `app.json` — the app owns the data. Written the moment the app starts,
 *    before it touches anything, because the guard heartbeat (which the CLI
 *    also honours) only starts once the app can answer held calls, seconds
 *    later. Counted while its pid lives and either it is young (the app is
 *    still starting) or the heartbeat is fresh — so a crashed app whose pid was
 *    reused doesn't block the CLI for ever.
 *  · `cli-writer.json` — a CLI command is writing. Taken BEFORE that command
 *    checks for the app (the app writes its marker before checking for this
 *    one), so the two can never both decide to write: whichever looks second
 *    sees the other. The app waits for it to clear at start; a long CLI scan
 *    stops at the next file once it sees the app's marker.
 *  · `model-download.json` — a model download is running (app or CLI), so the
 *    other one waits for it rather than fetching the same files.
 */

import { closeSync, mkdirSync, openSync, readFileSync, rmSync, writeFileSync, writeSync } from "node:fs";
import { join } from "node:path";
import { heartbeatFresh, heartbeatPath, pidAlive } from "../guard/handshake.js";

export interface LockRecord {
  pid: number;
  /** ISO time the lock was taken. */
  at: string;
  /** Who holds it: "app", or "cli" (with the command, for messages). */
  by: "app" | "cli";
  command?: string;
  /** model-download only: the model being fetched now. */
  model?: string;
}

export type LockName = "app" | "cli-writer" | "model-download";

/** How long a just-started app counts as the owner without its heartbeat. */
export const APP_START_GRACE_MS = 2 * 60_000;
/** A lock older than this is stale whatever its pid says (pids are reused). */
const LOCK_MAX_AGE_MS = 24 * 60 * 60_000;

export function locksDir(userDataDir: string): string {
  return join(userDataDir, "doorman", "locks");
}

export function lockPath(userDataDir: string, name: LockName): string {
  return join(locksDir(userDataDir), `${name}.json`);
}

function readRecord(path: string): LockRecord | undefined {
  try {
    const raw: unknown = JSON.parse(readFileSync(path, "utf8"));
    if (!raw || typeof raw !== "object") return undefined;
    const r = raw as Partial<LockRecord>;
    if (typeof r.pid !== "number" || typeof r.at !== "string" || (r.by !== "app" && r.by !== "cli")) return undefined;
    return r as LockRecord;
  } catch {
    return undefined;
  }
}

/** The lock's record when its holder is alive and the lock not ancient. */
export function liveLock(userDataDir: string, name: LockName, now: number = Date.now()): LockRecord | undefined {
  const record = readRecord(lockPath(userDataDir, name));
  if (!record) return undefined;
  const age = now - Date.parse(record.at);
  if (!Number.isFinite(age) || age > LOCK_MAX_AGE_MS || !pidAlive(record.pid)) return undefined;
  return record;
}

/**
 * Take a lock for `record.pid`. True when it is now held by that pid —
 * including when it already was. False when another live process holds it.
 * A stale lock is replaced.
 */
export function takeLock(userDataDir: string, name: LockName, record: Omit<LockRecord, "at">, now: number = Date.now()): boolean {
  mkdirSync(locksDir(userDataDir), { recursive: true });
  const path = lockPath(userDataDir, name);
  const full: LockRecord = { ...record, at: new Date(now).toISOString() };
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      const fd = openSync(path, "wx");
      try {
        writeSync(fd, JSON.stringify(full));
      } finally {
        closeSync(fd);
      }
      return true;
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== "EEXIST") throw err;
      const holder = liveLock(userDataDir, name, now);
      if (holder) return holder.pid === record.pid;
      rmSync(path, { force: true }); // stale: its process is gone
    }
  }
  return false;
}

/** Rewrite a lock this pid holds (e.g. which model a download is on). */
export function updateLock(userDataDir: string, name: LockName, pid: number, patch: Partial<Omit<LockRecord, "pid" | "at" | "by">>): void {
  const path = lockPath(userDataDir, name);
  const record = readRecord(path);
  if (!record || record.pid !== pid) return;
  writeFileSync(path, JSON.stringify({ ...record, ...patch }));
}

/** Pass a lock `fromPid` holds to `toPid` (a command handing its download to
 * the detached child it started). */
export function handOverLock(userDataDir: string, name: LockName, fromPid: number, toPid: number): void {
  const path = lockPath(userDataDir, name);
  const record = readRecord(path);
  if (!record || record.pid !== fromPid) return;
  writeFileSync(path, JSON.stringify({ ...record, pid: toPid }));
}

/** Release a lock — only if `pid` holds it, so nobody frees another's. */
export function releaseLock(userDataDir: string, name: LockName, pid: number): void {
  const path = lockPath(userDataDir, name);
  const record = readRecord(path);
  if (record && record.pid !== pid) return;
  rmSync(path, { force: true });
}

/** The app that owns the data right now, if any (not counting `selfPid`). */
export function appOwner(userDataDir: string, now: number = Date.now(), selfPid: number = process.pid): LockRecord | undefined {
  const record = liveLock(userDataDir, "app", now);
  if (!record || record.pid === selfPid) return undefined;
  if (now - Date.parse(record.at) <= APP_START_GRACE_MS) return record;
  let beat: string | undefined;
  try {
    beat = readFileSync(heartbeatPath(join(userDataDir, "doorman", "guard")), "utf8");
  } catch {
    beat = undefined;
  }
  return heartbeatFresh(beat, now) ? record : undefined;
}

/**
 * The app's side of the hand-over, at start: mark the data as the app's, then
 * wait for a CLI command that is writing to finish (a long scan stops at its
 * next file once it sees the marker). Resolves with how it ended; after
 * `timeoutMs` the app goes ahead — a wedged CLI must not keep it from starting.
 */
export async function claimForApp(
  userDataDir: string,
  options: { pid?: number; timeoutMs?: number; pollMs?: number; log?: (message: string) => void } = {},
): Promise<"free" | "waited" | "timed_out"> {
  const pid = options.pid ?? process.pid;
  // The app is a single instance, so its marker is simply overwritten.
  mkdirSync(locksDir(userDataDir), { recursive: true });
  writeFileSync(lockPath(userDataDir, "app"), JSON.stringify({ pid, at: new Date().toISOString(), by: "app" } satisfies LockRecord));
  const started = Date.now();
  const timeout = options.timeoutMs ?? 60_000;
  let waited = false;
  for (;;) {
    const writer = liveLock(userDataDir, "cli-writer");
    if (!writer || writer.pid === pid) return waited ? "waited" : "free";
    if (!waited) options.log?.(`waiting for \`doorman ${writer.command ?? "…"}\` (pid ${writer.pid}) to finish writing`);
    waited = true;
    if (Date.now() - started >= timeout) {
      options.log?.(`\`doorman ${writer.command ?? "…"}\` (pid ${writer.pid}) is still writing after ${Math.round(timeout / 1000)}s; going ahead`);
      return "timed_out";
    }
    await new Promise((resolve) => setTimeout(resolve, options.pollMs ?? 100));
  }
}
