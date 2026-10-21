/**
 * The CLI's side of the app's ensureInjectionModel: the classifier's model
 * arrives on its own. When the classifier is on, the runtime is in the package
 * and a model the plan needs is not on disk, a command starts
 * `doorman model download --auto` as a DETACHED child and gets on with its own
 * work — the person's command is never held up by a 96 MB download, and the
 * child outlives it. The next commands use the model once it has verified.
 *
 * The download holds the model-download lock the app takes too
 * (lib/data-owner.ts), so the app and the CLI never fetch the same files at
 * once: whichever starts second waits for the other's download and uses it.
 * The last attempt's outcome sits beside the models and spaces retries out the
 * way the app's widening delay does. Nothing starts while another Doorman owns
 * the data — the app downloads for itself, and `doorman watch` started one when
 * it began — nor with the classifier off (`DOORMAN_INJECTION_CLASSIFIER=off`),
 * nor from a script: under CI or with stderr not a terminal (a kit's setup
 * step, a pipeline), a 96 MB download nobody asked for is not this command's
 * to start. A download a Docker Sandbox's network policy refused is not
 * retried on its own either: nothing changes until someone allows the hosts
 * from the host, and then `doorman model download` is the retry.
 *
 * Like the app's, this is also the update path: a CLI that pins newer weights
 * finds them missing and fetches them (into their own folder, beside the
 * app's: lib/model-assets.ts modelDir).
 */

import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { defaultInjectionClassifierConfig, type InjectionModelId } from "../guard/policy.js";
import { handOverLock, liveLock, releaseLock, takeLock, updateLock, type LockRecord } from "../lib/data-owner.js";
import { runtimePresent } from "../lib/injection-classifier.js";
import { fetchInjectionModels, injectionModelsMissing, type InjectionModelFetchDeps } from "../lib/injection-model-choice.js";
import {
  bytesOnDisk,
  downloadModel,
  injectionModelManifest,
  manifestBytes,
  ModelDownloadHttpError,
  modelStatus,
  PROMPT_GUARD_2_22M_DOORMAN_1,
} from "../lib/model-assets.js";
import { injectionModelSourceFromEnv } from "../lib/policy-env.js";
import { doormanSource, modelPlan, modelsRoot, runtimeDir } from "./classifier.js";
import type { CliContext } from "./context.js";
import { MODEL_HOSTS, sandboxAllowCommand, sandboxPolicyBlock } from "./docker-sandbox.js";

/** The child the CLI starts: the arguments after the CLI's own entry point. */
export const AUTO_DOWNLOAD_ARGS = ["model", "download", "--auto"] as const;

/** Commands that never start one: the explicit download itself, the two
 * that are about to change what the plan needs (the next command catches up),
 * and `changelog`, which reads a bundled file (and runs under `update`). */
const NO_AUTO_DOWNLOAD = new Set(["model download", "model remove", "model select", "changelog"]);

/** After the n-th failure in a row, wait this long before trying again: the
 * app's 1 / 5 / 30 minutes, then once a day (a CLI has no "next launch"). */
export const AUTO_DOWNLOAD_RETRY_MS = [60_000, 5 * 60_000, 30 * 60_000, 24 * 60 * 60_000];

/** A download a server answered with an HTTP error: the status, and the host
 * that answered (after redirects, so possibly the CDN, not the Hub). */
export interface DownloadRefusal {
  status: number;
  host: string;
}

/** The refusal behind a downloadModel error, if it was one. */
export function downloadRefusal(err: unknown): DownloadRefusal | undefined {
  if (!(err instanceof ModelDownloadHttpError)) return undefined;
  try {
    return { status: err.status, host: new URL(err.url).host };
  } catch {
    return undefined;
  }
}

interface AttemptRecord {
  last_attempt_at: string;
  /** Failures in a row; 0 after a success. */
  failures: number;
  error?: string;
  /** When `error` was a server's HTTP answer: which status, from which host. */
  refused?: DownloadRefusal;
  /** This run of failures has been told to the person (the notice after a
   * command, or `doorman model` / `doorman status` showing it): once per run,
   * not once per retry. */
  noticed?: boolean;
}

/** A download the Docker Sandbox's policy proxy refused: the sandbox, the
 * host it blocked (after a redirect, the CDN rather than the Hub), and the
 * host-side command that lets the model's downloads through. */
export interface SandboxBlock {
  sandbox: string;
  host: string;
  allow: string;
}

/** The sandbox block behind a refusal, in this environment; undefined outside
 * a sandbox and for any other failure. */
export function sandboxBlock(env: NodeJS.ProcessEnv, refused: DownloadRefusal | undefined): SandboxBlock | undefined {
  const sandbox = sandboxPolicyBlock(env, refused?.status);
  if (!sandbox || !refused) return undefined;
  return { sandbox: sandbox.name, host: refused.host, allow: sandboxAllowCommand(sandbox, MODEL_HOSTS) };
}

/** What `doorman model` and `doorman status` show about a model download.
 * A failure the sandbox's policy caused carries `blocked`, and has no next
 * attempt (`next_attempt_at: null`): it waits for `doorman model download`. */
export type AutoDownloadView =
  | { status: "running"; by: "app" | "cli"; pid: number; model: InjectionModelId; bytes_done: number; bytes_total: number }
  | { status: "failed"; error: string; refused?: DownloadRefusal; blocked?: SandboxBlock; next_attempt_at: string | null }
  | { status: "idle" };

const recordPath = (dataDir: string) => join(modelsRoot(dataDir), ".auto-download.json");

function readRefusal(raw: unknown): DownloadRefusal | undefined {
  if (!raw || typeof raw !== "object" || !("status" in raw) || !("host" in raw)) return undefined;
  return typeof raw.status === "number" && typeof raw.host === "string" ? { status: raw.status, host: raw.host } : undefined;
}

function readRecord(dataDir: string): AttemptRecord | undefined {
  let raw: unknown;
  try {
    raw = JSON.parse(readFileSync(recordPath(dataDir), "utf8"));
  } catch {
    return undefined;
  }
  if (!raw || typeof raw !== "object" || !("last_attempt_at" in raw) || typeof raw.last_attempt_at !== "string") return undefined;
  const failures = "failures" in raw && typeof raw.failures === "number" ? raw.failures : 0;
  const error = "error" in raw && typeof raw.error === "string" ? raw.error : undefined;
  const refused = "refused" in raw ? readRefusal(raw.refused) : undefined;
  const noticed = "noticed" in raw && raw.noticed === true;
  return {
    last_attempt_at: raw.last_attempt_at,
    failures,
    ...(error !== undefined ? { error } : {}),
    ...(refused ? { refused } : {}),
    ...(noticed ? { noticed } : {}),
  };
}

/** A failed run of background downloads nobody has been told about yet. */
export function unnoticedDownloadFailure(ctx: CliContext): boolean {
  const record = readRecord(ctx.dataDir);
  return record !== undefined && record.failures > 0 && record.error !== undefined && record.noticed !== true;
}

/** Record that the current run of failures has been told. Best effort: a
 * record that can't be rewritten only means the notice comes once more. */
export function markDownloadFailureNoticed(ctx: CliContext): void {
  const record = readRecord(ctx.dataDir);
  if (!record || record.failures === 0 || record.noticed === true) return;
  try {
    writeFileSync(recordPath(ctx.dataDir), JSON.stringify({ ...record, noticed: true }));
  } catch {
    // the next command says it again
  }
}

/** When the next attempt may start after `record`'s failures (0 = now;
 * Infinity = not on its own: the sandbox's policy refused the last one). */
function nextAttemptAt(env: NodeJS.ProcessEnv, record: AttemptRecord | undefined): number {
  if (!record || record.failures === 0) return 0;
  if (sandboxBlock(env, record.refused)) return Infinity;
  const delay = AUTO_DOWNLOAD_RETRY_MS[Math.min(record.failures, AUTO_DOWNLOAD_RETRY_MS.length) - 1]!;
  return Date.parse(record.last_attempt_at) + delay;
}

/** The model download running now — this CLI's, another's or the app's. */
export function activeDownload(ctx: CliContext): LockRecord | undefined {
  return liveLock(ctx.dataDir, "model-download", ctx.io.now());
}

/** The app's injectionModelFetchDeps, for the CLI's data directory.
 * `onFailed` hears each model's failure, with the refusal behind it if any. */
function fetchDeps(
  ctx: CliContext,
  onModel: (model: InjectionModelId) => void,
  onFailed: (model: InjectionModelId, refused: DownloadRefusal | undefined) => void = () => {},
): InjectionModelFetchDeps {
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
        onFailed(model, downloadRefusal(err));
        return { ok: false, error: err instanceof Error ? err.message : String(err) };
      }
    },
  };
}

/** Whether the classifier could use a model and one it needs is missing. */
function modelsWanted(ctx: CliContext): boolean {
  const cfg = ctx.policy().injection_classifier ?? defaultInjectionClassifierConfig();
  return cfg.enabled && runtimePresent(runtimeDir()) && injectionModelsMissing(fetchDeps(ctx, () => {}));
}

/** Whether this run is a script's — CI, or stderr not a terminal — where
 * nobody would see a notice or wait for a download. */
export function scriptedRun(ctx: CliContext): boolean {
  const ci = ctx.io.env.CI;
  if (ci !== undefined && ci !== "" && ci !== "0" && ci.toLowerCase() !== "false") return true;
  return ctx.io.stderr.isTTY !== true;
}

/** Whether a background download should start now. */
function autoDownloadDue(ctx: CliContext): boolean {
  if (scriptedRun(ctx) || !modelsWanted(ctx)) return false;
  if (ctx.running()) return false;
  if (activeDownload(ctx)) return false;
  return ctx.io.now() >= nextAttemptAt(ctx.io.env, readRecord(ctx.dataDir));
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
    if (!takeLock(ctx.dataDir, "model-download", { pid: process.pid, by: "cli", command: "model download --auto" }, now)) return false;
    const pid = ctx.io.spawnDetached(AUTO_DOWNLOAD_ARGS);
    if (pid === undefined) {
      releaseLock(ctx.dataDir, "model-download", process.pid);
      return false;
    }
    handOverLock(ctx.dataDir, "model-download", process.pid, pid);
    // Only on a terminal (autoDownloadDue): the person who will wait for it.
    const plan = modelPlan(ctx.dataDir, ctx.policy(), ctx.io.env);
    const model = plan.selected === "doorman-1" && doormanSource(ctx.io.env) !== undefined ? "doorman-1" : "stock";
    const size = (manifestBytes(injectionModelManifest(model)) / 1e6).toFixed(0);
    const ui = ctx.errUi;
    ctx.io.stderr.write(
      `${ui.mark("info", ui.style.dim(`Downloading the injection classifier (${model}, ${size} MB) in the background; until it's ready, injection findings come from the rules alone. \`doorman model\` shows its progress.`))}\n`,
    );
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
 * outcome for the retry spacing, and release the lock. Started by hand it
 * takes the lock itself, and does nothing while another download holds it.
 */
export async function runAutoDownload(ctx: CliContext): Promise<{ ok: boolean; error?: string; fetched: InjectionModelId[] }> {
  // Started by hand (the sbx kit's startup step does), nothing to do when
  // the classifier is off or has what it needs.
  if (!modelsWanted(ctx)) return { ok: true, fetched: [] };
  const started = new Date(ctx.io.now()).toISOString();
  mkdirSync(modelsRoot(ctx.dataDir), { recursive: true });
  if (!takeLock(ctx.dataDir, "model-download", { pid: process.pid, by: "cli", command: "model download --auto" }, ctx.io.now())) {
    return { ok: true, fetched: [] }; // someone else's download is running
  }
  try {
    // The app started meanwhile: it downloads for itself. Not a failure.
    if (ctx.running()) return { ok: true, fetched: [] };
    const failed = new Map<InjectionModelId, DownloadRefusal | undefined>();
    const result = await fetchInjectionModels(
      fetchDeps(
        ctx,
        (model) => updateLock(ctx.dataDir, "model-download", process.pid, { model }),
        (model, refused) => failed.set(model, refused),
      ),
    );
    const previous = readRecord(ctx.dataDir);
    // fetchInjectionModels reports the first model that failed (doorman-1
    // before stock, in the order they are fetched); keep that one's refusal.
    const refused = [...failed.values()][0];
    const record: AttemptRecord = result.ok
      ? { last_attempt_at: started, failures: 0 }
      : {
          last_attempt_at: started,
          failures: (previous?.failures ?? 0) + 1,
          error: result.error ?? "download failed",
          ...(refused ? { refused } : {}),
          // A retry that fails again continues the run the person was already told about.
          ...(previous && previous.failures > 0 && previous.noticed === true ? { noticed: true } : {}),
        };
    writeFileSync(recordPath(ctx.dataDir), JSON.stringify(record));
    return result;
  } finally {
    releaseLock(ctx.dataDir, "model-download", process.pid);
  }
}

/**
 * Record what `doorman model download` got, so the background download and
 * the views agree with it: a success ends a run of failures (whatever was
 * wrong may be fixed — the background download may try the rest), and a
 * refusal from the sandbox's policy is recorded as one, already told, so no
 * background attempt repeats it. Any other failure leaves the record as it
 * was. Best effort, like the notice.
 */
export function recordExplicitDownload(ctx: CliContext, outcome: { ok: true } | { ok: false; error: string; refused: DownloadRefusal | undefined }): void {
  const previous = readRecord(ctx.dataDir);
  const at = new Date(ctx.io.now()).toISOString();
  let record: AttemptRecord | undefined;
  if (outcome.ok) {
    if (previous && previous.failures > 0) record = { last_attempt_at: at, failures: 0 };
  } else if (outcome.refused && sandboxBlock(ctx.io.env, outcome.refused)) {
    record = { last_attempt_at: at, failures: (previous?.failures ?? 0) + 1, error: outcome.error, refused: outcome.refused, noticed: true };
  }
  if (!record) return;
  try {
    mkdirSync(modelsRoot(ctx.dataDir), { recursive: true });
    writeFileSync(recordPath(ctx.dataDir), JSON.stringify(record));
  } catch {
    // the views fall back to the previous record
  }
}

/** The model download as `doorman model` reports it. */
export function autoDownloadView(ctx: CliContext): AutoDownloadView {
  const lock = activeDownload(ctx);
  if (lock) {
    const named = lock.model === "doorman-1" || lock.model === "stock" ? lock.model : undefined;
    const model = named ?? modelPlan(ctx.dataDir, ctx.policy(), ctx.io.env).selected;
    const progress = bytesOnDisk(modelsRoot(ctx.dataDir), injectionModelManifest(model));
    return { status: "running", by: lock.by, pid: lock.pid, model, ...progress };
  }
  const record = readRecord(ctx.dataDir);
  if (record?.error !== undefined && record.failures > 0) {
    const blocked = sandboxBlock(ctx.io.env, record.refused);
    const next = nextAttemptAt(ctx.io.env, record);
    return {
      status: "failed",
      error: record.error,
      ...(record.refused ? { refused: record.refused } : {}),
      ...(blocked ? { blocked } : {}),
      next_attempt_at: Number.isFinite(next) ? new Date(next).toISOString() : null,
    };
  }
  return { status: "idle" };
}
