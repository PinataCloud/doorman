import { EventEmitter } from "node:events";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("electron", () => ({ app: { isPackaged: true, getPath: () => "/tmp" } }));

import { Store } from "../main/state.js";
import {
  checkForUpdatesManually,
  initUpdater,
  pendingUpdateVersion,
  stopUpdater,
  updateReminderDue,
  UPDATE_REMINDER_INTERVAL_MS,
  type UpdaterModule,
} from "../main/updater.js";

class FakeAutoUpdater extends EventEmitter {
  autoDownload = false;
  autoInstallOnAppQuit = false;
  checks = 0;
  installs: Array<[boolean | undefined, boolean | undefined]> = [];
  async checkForUpdates(): Promise<unknown> {
    this.checks += 1;
    return undefined;
  }
  quitAndInstall(isSilent?: boolean, isForceRunAfter?: boolean): void {
    this.installs.push([isSilent, isForceRunAfter]);
  }
}

describe("the updater", () => {
  let dir: string;
  let store: Store;
  let fake: FakeAutoUpdater;
  const mod = (): UpdaterModule => ({ autoUpdater: fake as unknown as UpdaterModule["autoUpdater"] });

  beforeEach(async () => {
    dir = mkdtempSync(join(tmpdir(), "doorman-upd-"));
    store = new Store({ appVersion: "0.0.0", dataDir: dir, readPrefs: () => ({}), writePrefs: () => {}, onChange: () => {} });
    fake = new FakeAutoUpdater();
    vi.useFakeTimers();
    await initUpdater(store, {}, { loadModule: mod, isPackaged: true, feedConfigured: () => true, installDelayMs: 50, installRetryMs: 100 });
  });
  afterEach(() => {
    stopUpdater();
    vi.useRealTimers();
    rmSync(dir, { recursive: true, force: true });
  });

  it("stays off, without loading the module, when the build carries no update feed", async () => {
    stopUpdater();
    let loaded = false;
    await initUpdater(store, {}, { loadModule: () => ((loaded = true), mod()), isPackaged: true, feedConfigured: () => false });
    expect(loaded).toBe(false);
    expect(store.snapshot().updater.status).toBe("unsupported");
    expect(store.snapshot().updater.message).toContain("aren't set up");
  });

  it("downloads in the background and installs on quit as the fallback; checks once at start", () => {
    expect(fake.autoDownload).toBe(true);
    expect(fake.autoInstallOnAppQuit).toBe(true);
    expect(fake.checks).toBe(1);
  });

  it("reports download progress the Settings meter can draw, clamped to 0–100", () => {
    fake.emit("update-available", { version: "1.2.3" });
    expect(store.snapshot().updater).toMatchObject({ status: "available", version: "1.2.3" });
    fake.emit("download-progress", { percent: 42.4, transferred: 42_000_000, total: 100_000_000, bytesPerSecond: 5_000_000 });
    const u = store.snapshot().updater;
    expect(u.status).toBe("downloading");
    expect(u.version).toBe("1.2.3");
    expect(u.progress).toEqual({ percent: 42.4, transferred: 42_000_000, total: 100_000_000, bytes_per_second: 5_000_000 });
    expect(u.message).toBe("Downloading update 1.2.3… 42%");
    fake.emit("download-progress", { percent: 250 });
    expect(store.snapshot().updater.progress?.percent).toBe(100);
    fake.emit("download-progress", {});
    expect(store.snapshot().updater.progress).toEqual({ percent: 0, transferred: 0, total: 0, bytes_per_second: 0 });
  });

  it("a finished download installs itself — silently, relaunching — after a short beat, with no notification hook to fire", async () => {
    fake.emit("update-downloaded", { version: "1.2.3" });
    expect(store.snapshot().updater).toMatchObject({ status: "downloaded", version: "1.2.3" });
    expect(fake.installs).toEqual([]);
    await vi.advanceTimersByTimeAsync(50);
    expect(store.snapshot().updater).toMatchObject({ status: "installing", message: "Installing update 1.2.3 and restarting…" });
    expect(fake.installs).toEqual([[true, true]]);
    // A re-check that reports the same download again must not re-arm a restart.
    fake.emit("update-downloaded", { version: "1.2.3" });
    await vi.advanceTimersByTimeAsync(200);
    expect(fake.installs).toHaveLength(1);
  });

  it("waits while a held tool call is pending, then installs once it is answered", async () => {
    store.setApprovals([{ id: "req-1" } as never]);
    fake.emit("update-downloaded", { version: "2.0.0" });
    await vi.advanceTimersByTimeAsync(50);
    expect(fake.installs).toEqual([]);
    expect(store.snapshot().updater).toMatchObject({ status: "installing", message: expect.stringContaining("once the held tool call is answered") });
    await vi.advanceTimersByTimeAsync(100);
    expect(fake.installs).toEqual([]); // still held
    store.setApprovals([]);
    await vi.advanceTimersByTimeAsync(100);
    expect(fake.installs).toEqual([[true, true]]);
  });

  it("waits for the person to look away when the window is focused, then restarts and asks the shell to reopen it", async () => {
    let looking = true;
    const before: unknown[] = [];
    stopUpdater();
    await initUpdater(store, {}, { loadModule: mod, isPackaged: true, feedConfigured: () => true, installDelayMs: 50, installRetryMs: 100, isUserLooking: () => looking, isWindowOpen: () => true, onBeforeInstall: (c) => before.push(c) });
    fake.emit("update-downloaded", { version: "3.0.0" });
    await vi.advanceTimersByTimeAsync(50);
    expect(fake.installs).toEqual([]);
    expect(store.snapshot().updater.message).toMatch(/installs when you switch away, or Update now in the sidebar/);
    await vi.advanceTimersByTimeAsync(300);
    expect(fake.installs).toEqual([]); // still looking
    looking = false;
    await vi.advanceTimersByTimeAsync(100);
    expect(fake.installs).toEqual([[true, true]]);
    // The window was OPEN (just unfocused) when the restart came, so it comes back after the relaunch.
    expect(before).toEqual([{ version: "3.0.0", reopen: true }]);
  });

  it("tells the shell ONCE, per version, when the install starts waiting on the person — the 'update now' moment", async () => {
    let looking = true;
    const ready: unknown[] = [];
    stopUpdater();
    await initUpdater(store, { onReady: (v) => ready.push(v) }, { loadModule: mod, isPackaged: true, feedConfigured: () => true, installDelayMs: 50, installRetryMs: 100, isUserLooking: () => looking, isWindowOpen: () => true });
    fake.emit("update-downloaded", { version: "3.0.0" });
    await vi.advanceTimersByTimeAsync(50);
    expect(ready).toEqual(["3.0.0"]);
    expect(pendingUpdateVersion(store)).toBe("3.0.0");
    // Every retry while they keep looking stays quiet — one announcement, not one per 5 s.
    await vi.advanceTimersByTimeAsync(500);
    expect(ready).toEqual(["3.0.0"]);
    // An hourly re-check re-emitting the same download re-arms nothing.
    fake.emit("update-downloaded", { version: "3.0.0" });
    await vi.advanceTimersByTimeAsync(50);
    expect(ready).toEqual(["3.0.0"]);
    looking = false;
    await vi.advanceTimersByTimeAsync(100);
    expect(fake.installs).toEqual([[true, true]]);
  });

  it("does not announce a download that installs straight away (nobody looking, or a manual check)", async () => {
    const ready: unknown[] = [];
    stopUpdater();
    await initUpdater(store, { onReady: (v) => ready.push(v) }, { loadModule: mod, isPackaged: true, feedConfigured: () => true, installDelayMs: 50, installRetryMs: 100, isUserLooking: () => false });
    fake.emit("update-downloaded", { version: "3.0.0" });
    await vi.advanceTimersByTimeAsync(50);
    expect(fake.installs).toEqual([[true, true]]);
    expect(ready).toEqual([]);
    expect(pendingUpdateVersion(store)).toBe("3.0.0"); // status "installing" — still the pending version until the restart
  });

  it("reminders: every open and the ready moment (debounced to a minute), focus at most every half hour, per version", () => {
    stopUpdater(); // clears the reminder ledger
    const t0 = 1_000_000;
    expect(updateReminderDue("3.0.0", "ready", t0)).toBe(true);
    expect(updateReminderDue("3.0.0", "open", t0 + 10_000)).toBe(false); // the two paths can't double up
    expect(updateReminderDue("3.0.0", "open", t0 + 61_000)).toBe(true);
    expect(updateReminderDue("3.0.0", "focus", t0 + 61_000 + 10 * 60_000)).toBe(false);
    expect(updateReminderDue("3.0.0", "focus", t0 + 61_000 + UPDATE_REMINDER_INTERVAL_MS)).toBe(true);
    // A different version is its own ledger.
    expect(updateReminderDue("3.1.0", "focus", t0 + 61_000 + UPDATE_REMINDER_INTERVAL_MS)).toBe(true);
    expect(pendingUpdateVersion(store)).toBeNull();
  });

  it("with a cap configured, past it the restart goes while the window is focused (unbounded by default — the sidebar offers Update now)", async () => {
    stopUpdater();
    let t = 1_000_000;
    await initUpdater(store, {}, { loadModule: mod, isPackaged: true, feedConfigured: () => true, installDelayMs: 50, installRetryMs: 100, maxAttentionWaitMs: 250, isUserLooking: () => true, now: () => t });
    fake.emit("update-downloaded", { version: "3.0.0" });
    t += 50;
    await vi.advanceTimersByTimeAsync(50);
    expect(fake.installs).toEqual([]);
    t += 100;
    await vi.advanceTimersByTimeAsync(100);
    expect(fake.installs).toEqual([]);
    t += 200; // 350 ms since armed > 250 cap
    await vi.advanceTimersByTimeAsync(100);
    expect(fake.installs).toEqual([[true, true]]);
  });

  it("a check the person asked for skips the looking-away wait — they are watching the bar", async () => {
    stopUpdater();
    const before: unknown[] = [];
    await initUpdater(store, {}, { loadModule: mod, isPackaged: true, feedConfigured: () => true, installDelayMs: 50, installRetryMs: 100, isUserLooking: () => true, onBeforeInstall: (c) => before.push(c) });
    await checkForUpdatesManually(store);
    fake.emit("update-downloaded", { version: "4.0.0" });
    await vi.advanceTimersByTimeAsync(50);
    expect(fake.installs).toEqual([[true, true]]);
    expect(before).toEqual([{ version: "4.0.0", reopen: true }]);
    // Out of sight and automatic: install now, nothing to reopen.
    stopUpdater();
    before.length = 0;
    fake = new FakeAutoUpdater();
    await initUpdater(store, {}, { loadModule: mod, isPackaged: true, feedConfigured: () => true, installDelayMs: 50, isUserLooking: () => false, onBeforeInstall: (c) => before.push(c) });
    fake.emit("update-downloaded", { version: "4.0.1" });
    await vi.advanceTimersByTimeAsync(50);
    expect(before).toEqual([{ version: "4.0.1", reopen: false }]);
  });

  it("not-available and error land in the row; a manual check re-checks without re-wiring", async () => {
    fake.emit("update-not-available");
    expect(store.snapshot().updater).toMatchObject({ status: "idle", message: "Up to date." });
    fake.emit("error", new Error("net down"));
    expect(store.snapshot().updater.status).toBe("error");
    await initUpdater(store);
    expect(fake.checks).toBe(2);
  });

  it("stays out of development builds", async () => {
    stopUpdater();
    const fresh = new Store({ appVersion: "0.0.0", dataDir: dir, readPrefs: () => ({}), writePrefs: () => {}, onChange: () => {} });
    await initUpdater(fresh, {}, { loadModule: mod, isPackaged: false });
    expect(fresh.snapshot().updater).toMatchObject({ status: "unsupported" });
  });
});
