/**
 * The CLI's counterpart of the app's updater (main/updater.ts): find out when
 * a newer `doorman` is published and say so, at most once a day.
 *
 * The app updates from this repo's GitHub releases; the CLI is an npm package,
 * so it asks the npm registry for its own package's `latest` dist-tag. That is
 * a plain GET to registry.npmjs.org carrying no data about this machine. The
 * answer is cached in `<data>/cli-update.json` for a day, failures included,
 * so a command never waits on the network more than once a day and never more
 * than CHECK_WAIT_MS then. Installing the update is `doorman update`.
 *
 * Skipped entirely (no request) when DOORMAN_NO_UPDATE_CHECK or
 * NO_UPDATE_NOTIFIER is set, under CI, and when stderr is not a terminal: a
 * script piping doorman's output never sees the notice or makes the call.
 */

import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { FetchLike } from "../lib/model-assets.js";
import type { CliContext } from "./context.js";

/** How long a registry answer (or a failure) stands before the next check. */
export const UPDATE_CHECK_INTERVAL_MS = 24 * 60 * 60 * 1000;
/** How long a command waits, at its end, for a check it started. */
export const CHECK_WAIT_MS = 1500;

export interface UpdateCache {
  /** The package the answer is about (a renamed test build checks its own). */
  package: string;
  checked_at: string;
  latest?: string;
  error?: string;
}

/** What `doorman update --check` and the notice report. */
export interface UpdateStatus {
  package: string;
  current: string;
  latest?: string;
  update_available: boolean;
  checked_at?: string;
  error?: string;
}

export function updateCachePath(dataDir: string): string {
  return join(dataDir, "cli-update.json");
}

export function readUpdateCache(dataDir: string, packageName: string): UpdateCache | undefined {
  try {
    const raw: unknown = JSON.parse(readFileSync(updateCachePath(dataDir), "utf8"));
    if (!raw || typeof raw !== "object" || !("package" in raw) || !("checked_at" in raw)) return undefined;
    if (raw.package !== packageName || typeof raw.checked_at !== "string") return undefined;
    return {
      package: packageName,
      checked_at: raw.checked_at,
      ...("latest" in raw && typeof raw.latest === "string" ? { latest: raw.latest } : {}),
      ...("error" in raw && typeof raw.error === "string" ? { error: raw.error } : {}),
    };
  } catch {
    return undefined;
  }
}

function writeUpdateCache(dataDir: string, cache: UpdateCache): void {
  try {
    mkdirSync(dataDir, { recursive: true });
    writeFileSync(updateCachePath(dataDir), `${JSON.stringify(cache, null, 2)}\n`);
  } catch {
    // an unwritable cache only means the next command checks again
  }
}

/**
 * Order two versions: `x.y.z` numerically, then a release above any of its
 * pre-releases (`1.2.0` > `1.2.0-beta.1`), pre-release identifiers compared
 * numerically where both are numbers. Negative, zero or positive, like a
 * sort comparator.
 */
export function compareVersions(a: string, b: string): number {
  const parse = (v: string) => {
    const [core = "", pre] = v.trim().replace(/^v/, "").split("+")[0]!.split(/-(.*)/s);
    return { nums: core.split(".").map((n) => Number.parseInt(n, 10) || 0), pre: pre ? pre.split(".") : [] };
  };
  const x = parse(a);
  const y = parse(b);
  for (let i = 0; i < 3; i++) {
    const d = (x.nums[i] ?? 0) - (y.nums[i] ?? 0);
    if (d !== 0) return d;
  }
  if (x.pre.length === 0 || y.pre.length === 0) return y.pre.length - x.pre.length;
  for (let i = 0; i < Math.max(x.pre.length, y.pre.length); i++) {
    const p = x.pre[i];
    const q = y.pre[i];
    if (p === undefined) return -1;
    if (q === undefined) return 1;
    const pn = /^\d+$/.test(p);
    const qn = /^\d+$/.test(q);
    if (pn && qn && Number(p) !== Number(q)) return Number(p) - Number(q);
    if (pn !== qn) return pn ? -1 : 1;
    if (p !== q) return p < q ? -1 : 1;
  }
  return 0;
}

/** Why the automatic check is off here, or undefined when it runs. */
export function updateCheckDisabled(ctx: CliContext): string | undefined {
  const env = ctx.io.env;
  const on = (v: string | undefined) => v !== undefined && v !== "" && v !== "0" && v.toLowerCase() !== "false";
  if (on(env.DOORMAN_NO_UPDATE_CHECK)) return "DOORMAN_NO_UPDATE_CHECK is set";
  if (on(env.NO_UPDATE_NOTIFIER)) return "NO_UPDATE_NOTIFIER is set";
  if (on(env.CI)) return "running under CI";
  const stderr = ctx.io.stderr as NodeJS.WritableStream & { isTTY?: boolean };
  if (stderr.isTTY !== true) return "stderr is not a terminal";
  return undefined;
}

/** `https://registry.npmjs.org/@pinata%2fdoorman/latest` for `@pinata/doorman`. */
export function latestUrl(packageName: string, registry = "https://registry.npmjs.org"): string {
  return `${registry.replace(/\/$/, "")}/${packageName.replace("/", "%2f")}/latest`;
}

/** The registry's `latest` version of the package. Throws on any failure. */
export async function fetchLatestVersion(packageName: string, fetchImpl: FetchLike, signal: AbortSignal, registry?: string): Promise<string> {
  const res = await fetchImpl(latestUrl(packageName, registry), { signal });
  if (!res.ok) throw new Error(res.status === 404 ? `${packageName} is not on the registry` : `the registry answered HTTP ${res.status}`);
  const body: unknown = JSON.parse(await new Response(res.body).text());
  if (!body || typeof body !== "object" || !("version" in body) || typeof body.version !== "string") throw new Error("the registry's answer has no version");
  return body.version;
}

function statusOf(packageName: string, current: string, cache: UpdateCache | undefined): UpdateStatus {
  return {
    package: packageName,
    current,
    update_available: cache?.latest !== undefined && compareVersions(cache.latest, current) > 0,
    ...(cache?.latest !== undefined ? { latest: cache.latest } : {}),
    ...(cache ? { checked_at: cache.checked_at } : {}),
    ...(cache?.error !== undefined ? { error: cache.error } : {}),
  };
}

/** Ask the registry now (no cache), record the answer, and report. `cancel`
 * stops the request early; that is recorded like any failure. */
export async function checkForUpdate(ctx: CliContext, packageName: string, current: string, timeoutMs = 10_000, cancel?: AbortSignal): Promise<UpdateStatus> {
  const fetchImpl: FetchLike = ctx.io.fetch ?? ((url, init) => fetch(url, init));
  const signal = cancel ? AbortSignal.any([AbortSignal.timeout(timeoutMs), cancel]) : AbortSignal.timeout(timeoutMs);
  let cache: UpdateCache;
  try {
    const latest = await fetchLatestVersion(packageName, fetchImpl, signal, ctx.io.env.DOORMAN_NPM_REGISTRY);
    cache = { package: packageName, checked_at: new Date(ctx.io.now()).toISOString(), latest };
  } catch (err) {
    const previous = readUpdateCache(ctx.dataDir, packageName);
    cache = {
      package: packageName,
      checked_at: new Date(ctx.io.now()).toISOString(),
      // A failed check keeps the last good answer: being offline must not
      // hide an update the CLI already knew about.
      ...(previous?.latest !== undefined ? { latest: previous.latest } : {}),
      error: err instanceof Error ? (err.name === "TimeoutError" || err.name === "AbortError" ? "the registry did not answer in time" : err.message) : String(err),
    };
  }
  writeUpdateCache(ctx.dataDir, cache);
  return statusOf(packageName, current, cache);
}

/** What the last check found, without asking again. */
export function cachedUpdateStatus(ctx: CliContext, packageName: string, current: string): UpdateStatus {
  return statusOf(packageName, current, readUpdateCache(ctx.dataDir, packageName));
}

/**
 * The automatic check for one command: started when the command starts, so the
 * request runs while the command works. The returned function, awaited when the
 * command is done, waits at most CHECK_WAIT_MS more, then cancels a request
 * still open (recorded as a failure, so an offline machine is not asked again
 * for a day and no exit is held up), and gives the notice line to print if an
 * update is available. Never throws.
 */
export function startUpdateCheck(ctx: CliContext, packageName: string, current: string): () => Promise<string | undefined> {
  if (updateCheckDisabled(ctx) !== undefined) return async () => undefined;
  const cache = readUpdateCache(ctx.dataDir, packageName);
  const fresh = cache !== undefined && ctx.io.now() - Date.parse(cache.checked_at) < UPDATE_CHECK_INTERVAL_MS;
  const cancel = new AbortController();
  const pending: Promise<UpdateStatus> = fresh
    ? Promise.resolve(statusOf(packageName, current, cache))
    : checkForUpdate(ctx, packageName, current, 10_000, cancel.signal).catch(() => statusOf(packageName, current, cache));
  return async () => {
    let timer: NodeJS.Timeout | undefined;
    const late = new Promise<"late">((resolve) => {
      timer = setTimeout(() => resolve("late"), CHECK_WAIT_MS);
    });
    let status = await Promise.race([pending, late]);
    clearTimeout(timer);
    if (status === "late") {
      cancel.abort();
      status = await pending;
    }
    if (!status.update_available || status.latest === undefined) return undefined;
    return `Doorman CLI ${status.latest} is available (you have ${current}). Update with \`doorman update\`.`;
  };
}
