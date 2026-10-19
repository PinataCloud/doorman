/**
 * The CLI's side of the app's ensureInjectionModel: the classifier's model
 * arrives on its own. When the classifier is on, the runtime is in the package
 * and a model the plan needs is not on disk, a command starts
 * `doorman model download --auto` as a DETACHED child and gets on with its own
 * work — the person's command is never held up by a 96 MB download, and the
 * child outlives it. The next commands use the model once it has verified.
 *
 * A CLI run lasts seconds, so what the app keeps in memory lives in two files
 * beside the models: a lock while a download runs (so two commands never fetch
 * the same files at once) and the last attempt's outcome, which spaces retries
 * out the way the app's widening delay does. It never starts while another
 * Doorman owns the data — the app downloads for itself, and `doorman watch`
 * already started one when it began — nor with the classifier off
 * (`DOORMAN_INJECTION_CLASSIFIER=off` included).
 *
 * Like the app's, this is also the update path: a CLI that pins newer weights
 * finds the old ones failing their pin and fetches the new ones.
 */

import { closeSync, existsSync, mkdirSync, openSync, readFileSync, rmSync, statSync, writeFileSync, writeSync } from "node:fs";
import { join } from "node:path";
import { defaultInjectionClassifierConfig, type InjectionModelId } from "../guard/policy.js";
import { runtimePresent } from "../lib/injection-classifier.js";
import { fetchInjectionModels, injectionModelsMissing, type InjectionModelFetchDeps } from "../lib/injection-model-choice.js";
import { downloadModel, injectionModelManifest, manifestBytes, modelDir, modelStatus, PROMPT_GUARD_2_22M_DOORMAN_1 } from "../lib/model-assets.js";
import { injectionModelSourceFromEnv } from "../lib/policy-env.js";
import { doormanSource, modelPlan, modelsRoot, runtimeDir } from "./classifier.js";
import type { CliContext } from "./context.js";

/** The child the CLI starts: the arguments after the CLI's own entry point. */
export const AUTO_DOWNLOAD_ARGS = ["model", "download", "--auto"] as const;

/** Commands that never start one: the explicit download itself, and the two
 * that are about to change what the plan needs (the next command catches up). */
const NO_AUTO_DOWNLOAD = new Set(["model download", "model remove", "model select"]);

/** After the n-th failure in a row, wait this long before trying again: the
 * app's 1 / 5 / 30 minutes, then once a day (a CLI has no "next launch"). */
export const AUTO_DOWNLOAD_RETRY_MS = [60_000, 5 * 60_000, 30 * 60_000, 24 * 60 * 60_000];

/** A lock older than this is stale whatever its pid says (pids get reused). */
const LOCK_MAX_AGE_MS = 24 * 60 * 60_000;

interface DownloadLock {
  pid: number;
  started_at: string;
  /** The model being fetched right now (doorman-1 first, then a stock fallback). */
  model?: InjectionModelId;
}

interface AttemptRecord {
  last_attempt_at: string;
  /** Failures in a row; 0 after a success. */
  failures: number;
  error?: string;
}

/** What `doorman model` and `doorman status` show about the background download. */
export type AutoDownloadView =
  | { status: "running"; pid: number; model: InjectionModelId; bytes_done: number; bytes_total: number }
  | { status: "failed"; error: string; next_attempt_at: string }
  | { status: "idle" };

const lockPath = (dataDir: string) => join(modelsRoot(dataDir), ".auto-download.lock");
const recordPath = (dataDir: string) => join(modelsRoot(dataDir), ".auto-download.json");

function readJson(path: string): unknown {
  try {
    return JSON.parse(readFileSync(path, "utf8"));
  } catch {
    return undefined;
  }
}

function pidAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    // EPERM: alive, just not ours to signal.
    return (err as NodeJS.ErrnoException).code === "EPERM";
  }
}

/** The lock of a download that is running now; undefined when there is none or it is stale. */
function liveLock(dataDir: string, now: number): DownloadLock | undefined {
  const raw = readJson(lockPath(dataDir));
  if (!raw || typeof raw !== "object" || !("pid" in raw) || typeof raw.pid !== "number") return undefined;
  const lock = raw as DownloadLock;
  const started = Date.parse(lock.started_at);
  if (!Number.isFinite(started) || now - started > LOCK_MAX_AGE_MS || !pidAlive(lock.pid)) return undefined;
  return lock;
}

function readRecord(dataDir: string): AttemptRecord | undefined {
  const raw = readJson(recordPath(dataDir));
  if (!raw || typeof raw !== "object" || !("last_attempt_at" in raw) || typeof raw.last_attempt_at !== "string") return undefined;
  const failures = "failures" in raw && typeof raw.failures === "number" ? raw.failures : 0;
  const error = "error" in raw && typeof raw.error === "string" ? raw.error : undefined;
  return { last_attempt_at: raw.last_attempt_at, failures, ...(error !== undefined ? { error } : {}) };
}

/** When the next attempt may start after `record`'s failures (0 = now). */
function nextAttemptAt(record: AttemptRecord | undefined): number {
  if (!record || record.failures === 0) return 0;
  const delay = AUTO_DOWNLOAD_RETRY_MS[Math.min(record.failures, AUTO_DOWNLOAD_RETRY_MS.length) - 1]!;
  return Date.parse(record.last_attempt_at) + delay;
}

/** The app's injectionModelFetchDeps, for the CLI's data directory. */
function fetchDeps(ctx: CliContext, onModel: (model: InjectionModelId) => void): InjectionModelFetchDeps {
  const root = modelsRoot(ctx.dataDir);
  return {
    plan: () => modelPlan(ctx.dataDir, ctx.policy(), ctx.io.env),
    doormanSource: () => doormanSource(ctx.io.env),
    stockInstalled: () => modelStatus(root, injectionModelManifest("stock")).present,
    async download(model) {
      onModel(model);
      const manifest = injectionModelManifest(model);
      // doorman-1 comes from the environment's source when one is named (the app's startModelDownload).
      const source = manifest.name === PROMPT_GUARD_2_22M_DOORMAN_1.name ? injectionModelSourceFromEnv(ctx.io.env) : undefined;
      try {
        await downloadModel(root, manifest, { ...(source === undefined ? {} : { source }), ...(ctx.io.fetch ? { fetchImpl: ctx.io.fetch } : {}) });
        return { ok: true };
      } catch (err) {
        return { ok: false, error: err instanceof Error ? err.message : String(err) };
      }
    },
  };
}

/** Whether a background download should start now. */
function autoDownloadDue(ctx: CliContext): boolean {
  const cfg = ctx.policy().injection_classifier ?? defaultInjectionClassifierConfig();
  if (!cfg.enabled || !runtimePresent(runtimeDir())) return false;
  if (!injectionModelsMissing(fetchDeps(ctx, () => {}))) return false;
  if (ctx.running()) return false;
  const now = ctx.io.now();
  if (liveLock(ctx.dataDir, now)) return false;
  return now >= nextAttemptAt(readRecord(ctx.dataDir));
}

/** Take the lock for a new download; false when another command just took it. */
function takeLock(dataDir: string, now: number): boolean {
  mkdirSync(modelsRoot(dataDir), { recursive: true }); // a fresh install has no models yet
  const path = lockPath(dataDir);
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      const fd = openSync(path, "wx");
      writeSync(fd, JSON.stringify({ pid: process.pid, started_at: new Date(now).toISOString() } satisfies DownloadLock));
      closeSync(fd);
      return true;
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== "EEXIST" || liveLock(dataDir, now)) return false;
      rmSync(path, { force: true }); // stale: its download died
    }
  }
  return false;
}

/**
 * Start the background download if it is due. Never throws and never delays
 * the command: a failure to start is the same as not starting, and the next
 * command tries again. Returns whether a download was started.
 */
export function maybeStartModelDownload(ctx: CliContext, commandName: string): boolean {
  if (!ctx.io.spawnDetached || NO_AUTO_DOWNLOAD.has(commandName)) return false;
  try {
    if (!autoDownloadDue(ctx)) return false;
    const now = ctx.io.now();
    if (!takeLock(ctx.dataDir, now)) return false;
    const pid = ctx.io.spawnDetached(AUTO_DOWNLOAD_ARGS);
    if (pid === undefined) {
      rmSync(lockPath(ctx.dataDir), { force: true });
      return false;
    }
    writeFileSync(lockPath(ctx.dataDir), JSON.stringify({ pid, started_at: new Date(now).toISOString() } satisfies DownloadLock));
    const stderr = ctx.io.stderr as NodeJS.WritableStream & { isTTY?: boolean };
    if (stderr.isTTY === true) {
      const plan = modelPlan(ctx.dataDir, ctx.policy(), ctx.io.env);
      const model = plan.selected === "doorman-1" && doormanSource(ctx.io.env) !== undefined ? "doorman-1" : "stock";
      const size = (manifestBytes(injectionModelManifest(model)) / 1e6).toFixed(0);
      stderr.write(ctx.style.dim(`Downloading the injection classifier (${model}, ${size} MB) in the background; \`doorman model\` shows its progress.\n`));
    }
    ctx.log(`started the model download in the background (pid ${pid})`);
    return true;
  } catch (err) {
    ctx.log(`couldn't start the model download: ${err instanceof Error ? err.message : String(err)}`);
    return false;
  }
}

/**
 * The background child (`doorman model download --auto`): fetch what the plan
 * needs — doorman-1 first, then the stock model it falls back to — record the
 * outcome for the retry spacing, and release the lock.
 */
export async function runAutoDownload(ctx: CliContext): Promise<{ ok: boolean; error?: string; fetched: InjectionModelId[] }> {
  const path = lockPath(ctx.dataDir);
  const started = new Date(ctx.io.now()).toISOString();
  mkdirSync(modelsRoot(ctx.dataDir), { recursive: true });
  try {
    // The app started meanwhile: it downloads for itself. Not a failure.
    if (ctx.running()) return { ok: true, fetched: [] };
    const result = await fetchInjectionModels(
      fetchDeps(ctx, (model) => writeFileSync(path, JSON.stringify({ pid: process.pid, started_at: started, model } satisfies DownloadLock))),
    );
    const previous = readRecord(ctx.dataDir);
    const record: AttemptRecord = result.ok
      ? { last_attempt_at: started, failures: 0 }
      : { last_attempt_at: started, failures: (previous?.failures ?? 0) + 1, error: result.error ?? "download failed" };
    writeFileSync(recordPath(ctx.dataDir), JSON.stringify(record));
    return result;
  } finally {
    rmSync(path, { force: true });
  }
}

/** The background download as `doorman model` reports it. */
export function autoDownloadView(ctx: CliContext): AutoDownloadView {
  const lock = liveLock(ctx.dataDir, ctx.io.now());
  if (lock) {
    const model = lock.model ?? modelPlan(ctx.dataDir, ctx.policy(), ctx.io.env).selected;
    const manifest = injectionModelManifest(model);
    const root = modelsRoot(ctx.dataDir);
    const dir = modelDir(root, manifest);
    const missing = new Set(modelStatus(root, manifest).missing);
    let done = 0;
    for (const file of manifest.files) {
      if (!missing.has(file.name)) done += file.size;
      else if (existsSync(join(dir, `${file.name}.part`))) done += statSync(join(dir, `${file.name}.part`)).size;
    }
    return { status: "running", pid: lock.pid, model, bytes_done: done, bytes_total: manifestBytes(manifest) };
  }
  const record = readRecord(ctx.dataDir);
  if (record?.error !== undefined && record.failures > 0) {
    return { status: "failed", error: record.error, next_attempt_at: new Date(nextAttemptAt(record)).toISOString() };
  }
  return { status: "idle" };
}

/** A download the person asked for must not race the background one over the same files. */
export function backgroundDownloadPid(ctx: CliContext): number | undefined {
  return liveLock(ctx.dataDir, ctx.io.now())?.pid;
}
