/**
 * Auto-update wiring (electron-updater). On an unsigned build Squirrel.Mac
 * cannot apply an update, so what ships there is the plumbing (poll, compare,
 * report); a signed build runs the full loop: check → download (progress in
 * Settings) → install + relaunch on its own, deferred only while a held tool
 * call awaits an answer.
 *
 * The feed is whatever the build baked into `app-update.yml` (electron-builder's
 * `publish` block). A build with no feed configured has no such file, and the
 * updater stays off rather than polling nothing.
 */

import { app } from "electron";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { describeUpdateError } from "./lib/format.js";
import type { Store } from "./state.js";

export const UPDATE_CHECK_INTERVAL_MS = 60 * 60_000;

export interface UpdaterModule {
  autoUpdater: {
    autoDownload: boolean;
    autoInstallOnAppQuit: boolean;
    checkForUpdates(): Promise<unknown>;
    /** `isSilent` skips the installer UI; `isForceRunAfter` relaunches. */
    quitAndInstall(isSilent?: boolean, isForceRunAfter?: boolean): void;
    on(event: string, listener: (...args: unknown[]) => void): void;
  };
}

/** How long the Settings row gets to say "installing" before the restart. */
export const INSTALL_DELAY_MS = 1_500;
/** While a held tool call is waiting on the person, restarting would drop the
 * hold (the guard falls back to the agent's own prompt) — re-check this often. */
export const INSTALL_RETRY_MS = 5_000;

let timer: NodeJS.Timeout | undefined;
let installTimer: NodeJS.Timeout | undefined;
let updater: UpdaterModule["autoUpdater"] | undefined;

/** Restart into the downloaded update (no-op when nothing is downloaded). */
export function installUpdate(): boolean {
  if (!updater) return false;
  try {
    updater.quitAndInstall(true, true);
    return true;
  } catch {
    return false;
  }
}

/** Optional hooks for the app shell. A finished download installs itself (see
 * below), so there is no plain "downloaded" hook — but the one case where the
 * install WAITS ON THE PERSON (they are looking at the window) is exactly the
 * moment to tell them "update now": that is `onReady`, fired once per version
 * when the self-install first defers to them. */
export interface UpdaterHandlers {
  onAvailable?(version: string | undefined): void;
  onReady?(version: string | undefined): void;
}

/** The version of a downloaded update that has not been installed yet, if any
 * — what the "update now" reminder is about. */
export function pendingUpdateVersion(store: Store): string | undefined | null {
  const u = store.snapshot().updater;
  if (u.status !== "downloaded" && u.status !== "installing") return null;
  return u.version;
}

/** Reminders are raised on every open of the app, and on focus at most once
 * per this interval — coming back from another window every minute must not
 * mean a banner every minute. */
export const UPDATE_REMINDER_INTERVAL_MS = 30 * 60_000;
const remindedAt = new Map<string, number>();

/**
 * Whether an "update now" reminder is due, and record it if so. `open`
 * (the person just brought the app up) and `ready` (the download landed while
 * they were looking) always remind, debounced to one per minute so the two
 * paths can't double up; `focus` reminds at most every UPDATE_REMINDER_INTERVAL_MS.
 */
export function updateReminderDue(
  version: string | undefined,
  reason: "open" | "focus" | "ready",
  now: number = Date.now(),
): boolean {
  const key = version ?? "downloaded";
  const last = remindedAt.get(key);
  const minGap = reason === "focus" ? UPDATE_REMINDER_INTERVAL_MS : 60_000;
  if (last !== undefined && now - last < minGap) return false;
  remindedAt.set(key, now);
  return true;
}

/** How long a restart waits for the person to look away. Unbounded by default:
 * while the window is focused the sidebar offers "Update now", so there is no
 * reason to ever pull the rug; the moment the window is out of sight it goes.
 * Tests and a future policy can set a cap. */
export const MAX_ATTENTION_WAIT_MS = Number.POSITIVE_INFINITY;

/** Seams the app shell fills in, and tests fake: the module loader
 * (electron-updater is unusable outside a packaged app), the packaged flag,
 * the delays, whether the person is looking at the window right now, and a
 * hook fired just before the restart so the shell can remember to bring the
 * window back if it was open. */
export interface UpdaterDeps {
  loadModule?: () => UpdaterModule;
  isPackaged?: boolean;
  /** Whether this build carries an update feed (`app-update.yml` beside the
   * app's resources). Absent = look for the file. */
  feedConfigured?: () => boolean;
  installDelayMs?: number;
  installRetryMs?: number;
  maxAttentionWaitMs?: number;
  /** Window exists, is visible and focused. Absent = "not looking". */
  isUserLooking?: () => boolean;
  /** Window exists and is visible (focused or not). Decides whether the window
   * comes back after the relaunch. Absent = falls back to isUserLooking. */
  isWindowOpen?: () => boolean;
  /** About to quit into the update. `reopen` says the window should come back
   * after the relaunch (it was open, or the person asked for this check). */
  onBeforeInstall?: (context: { version: string | undefined; reopen: boolean }) => void;
  now?: () => number;
}

let handlers: UpdaterHandlers = {};
let scheduledInstall: string | undefined;
let installDeps: UpdaterDeps = {};
/** The current check was asked for by hand (Settings, tray, menu) — the person
 * is watching the row, so the restart follows the download straight away. */
let manualRequested = false;

/**
 * A downloaded update installs ITSELF — silently, then relaunches. What it
 * waits for, in order:
 *  · a tool call the guard is holding for the person's answer (store.approvals)
 *    — restarting mid-hold would drop it; re-checked on a short interval;
 *  · the person looking at the window (isUserLooking) — a menu-bar app is out
 *    of sight most of the time, so this usually means "now"; when the window
 *    IS focused the restart waits for them to switch away, at most
 *    MAX_ATTENTION_WAIT_MS. A check they asked for by hand skips this wait:
 *    they are watching the progress bar for exactly this.
 */
function scheduleInstall(store: Store, version: string | undefined, deps: UpdaterDeps): void {
  const key = version ?? "downloaded";
  if (scheduledInstall === key) return; // an hourly re-check must not re-arm a restart
  scheduledInstall = key;
  const now = deps.now ?? Date.now;
  const armedAt = now();
  const manual = manualRequested;
  manualRequested = false;
  const label = version ? ` ${version}` : "";
  let readyAnnounced = false;
  const attempt = () => {
    installTimer = undefined;
    if (!updater) return;
    const retry = (message: string) => {
      store.setUpdater({ status: "installing", ...(version ? { version } : {}), message });
      installTimer = setTimeout(attempt, deps.installRetryMs ?? INSTALL_RETRY_MS);
      installTimer.unref?.();
    };
    if (store.snapshot().approvals.length > 0) {
      retry(`Update${label} ready — installing once the held tool call is answered.`);
      return;
    }
    const looking = deps.isUserLooking?.() === true;
    const waited = now() - armedAt;
    if (looking && !manual && waited < (deps.maxAttentionWaitMs ?? MAX_ATTENTION_WAIT_MS)) {
      // The install is now waiting on the person: say so, once per version.
      if (!readyAnnounced) {
        readyAnnounced = true;
        handlers.onReady?.(version);
      }
      retry(`Update${label} ready — installs when you switch away, or Update now in the sidebar.`);
      return;
    }
    store.setUpdater({ status: "installing", ...(version ? { version } : {}), message: `Installing update${label} and restarting…` });
    try {
      const open = deps.isWindowOpen ? deps.isWindowOpen() : looking;
      deps.onBeforeInstall?.({ version, reopen: open || manual });
      updater.quitAndInstall(true, true);
    } catch (err) {
      store.setUpdater({ status: "error", message: describeUpdateError(err instanceof Error ? err.message : String(err)) });
    }
  };
  installTimer = setTimeout(attempt, deps.installDelayMs ?? INSTALL_DELAY_MS);
  installTimer.unref?.();
}

/** A check the person asked for (Settings button, tray, app menu): the
 * download that follows installs the moment it lands, no looking-away wait. */
export async function checkForUpdatesManually(store: Store): Promise<void> {
  manualRequested = true;
  await initUpdater(store);
}

export async function initUpdater(store: Store, next: UpdaterHandlers = {}, deps: UpdaterDeps = {}): Promise<void> {
  handlers = { ...handlers, ...next };
  installDeps = { ...installDeps, ...deps };
  if (updater) {
    // Already wired (a manual "Check for updates" after boot): just check again.
    try {
      await updater.checkForUpdates();
    } catch (err) {
      store.setUpdater({
        status: "error",
        message: describeUpdateError(err instanceof Error ? err.message : String(err)),
      });
    }
    return;
  }
  if (!(deps.isPackaged ?? app.isPackaged)) {
    store.setUpdater({ status: "unsupported", message: "Updates are disabled in development.", checked_at: new Date().toISOString() });
    return;
  }
  const feedConfigured = deps.feedConfigured ?? (() => existsSync(join(process.resourcesPath ?? "", "app-update.yml")));
  if (!feedConfigured()) {
    store.setUpdater({ status: "unsupported", message: "Automatic updates aren't set up for this build.", checked_at: new Date().toISOString() });
    return;
  }
  let mod: UpdaterModule;
  try {
    // Required lazily: in a dev run the module is present but unusable.
    mod = deps.loadModule ? deps.loadModule() : (require("electron-updater") as UpdaterModule);
  } catch (err) {
    store.setUpdater({ status: "error", message: `electron-updater unavailable: ${String(err)}` });
    return;
  }
  const { autoUpdater } = mod;
  updater = autoUpdater;
  // Auto-update from upstream: download in the background WITH progress in
  // Settings, then install and relaunch on its own once the download lands —
  // no notification, no "restart to update" button to find. Quit-time install
  // stays on as the fallback for a download that finished during shutdown.
  autoUpdater.autoDownload = true;
  autoUpdater.autoInstallOnAppQuit = true;
  autoUpdater.on("checking-for-update", () => store.setUpdater({ status: "checking" }));
  autoUpdater.on("update-available", (info: unknown) => {
    const version = (info as { version?: string } | undefined)?.version;
    store.setUpdater({
      status: "available",
      ...(version ? { version } : {}),
      outdated: true,
      message: "Update available — downloading…",
      checked_at: new Date().toISOString(),
    });
    handlers.onAvailable?.(version);
  });
  autoUpdater.on("download-progress", (raw: unknown) => {
    const p = (raw ?? {}) as { percent?: number; transferred?: number; total?: number; bytesPerSecond?: number };
    const percent = Math.max(0, Math.min(100, Number.isFinite(p.percent) ? (p.percent as number) : 0));
    const version = store.snapshot().updater.version;
    store.setUpdater({
      status: "downloading",
      ...(version ? { version } : {}),
      progress: {
        percent,
        transferred: Number.isFinite(p.transferred) ? (p.transferred as number) : 0,
        total: Number.isFinite(p.total) ? (p.total as number) : 0,
        bytes_per_second: Number.isFinite(p.bytesPerSecond) ? (p.bytesPerSecond as number) : 0,
      },
      message: `Downloading update${version ? ` ${version}` : ""}… ${Math.round(percent)}%`,
    });
  });
  autoUpdater.on("update-downloaded", (info: unknown) => {
    const version = (info as { version?: string } | undefined)?.version;
    store.setUpdater({
      status: "downloaded",
      ...(version ? { version } : {}),
      progress: { percent: 100, transferred: 0, total: 0, bytes_per_second: 0 },
      message: "Update downloaded — installing…",
    });
    scheduleInstall(store, version, installDeps);
  });
  autoUpdater.on("update-not-available", () => {
    manualRequested = false;
    // The only event that can clear it: `setUpdater` merges, so `outdated`
    // survives the download/error states in between on purpose.
    store.setUpdater({ status: "idle", outdated: false, message: "Up to date.", checked_at: new Date().toISOString() });
  });
  autoUpdater.on("error", (err: unknown) => {
    manualRequested = false;
    store.setUpdater({
      status: "error",
      message: describeUpdateError(err instanceof Error ? err.message : String(err)),
      checked_at: new Date().toISOString(),
    });
  });
  const check = async () => {
    try {
      await autoUpdater.checkForUpdates();
    } catch (err) {
      store.setUpdater({
        status: "error",
        message: describeUpdateError(err instanceof Error ? err.message : String(err)),
      });
    }
  };
  timer = setInterval(() => void check(), UPDATE_CHECK_INTERVAL_MS);
  timer.unref?.();
  await check();
}

export function stopUpdater(): void {
  if (timer) clearInterval(timer);
  if (installTimer) clearTimeout(installTimer);
  timer = undefined;
  installTimer = undefined;
  updater = undefined;
  scheduledInstall = undefined;
  manualRequested = false;
  installDeps = {};
  remindedAt.clear();
}
