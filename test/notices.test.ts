/**
 * The in-window notice stack (the delivery rail of last resort under macOS
 * banners) and the delivery-check plumbing around it: Store notice semantics,
 * the persisted once-per-episode "notifications are blocked" flag, and the
 * mirror/probe behaviour in notifications.ts.
 */

import { beforeEach, describe, expect, it, vi } from "vitest";

const mocked = vi.hoisted(() => {
  class FakeNotification {
    static supported = true;
    static created: FakeNotification[] = [];
    static isSupported(): boolean {
      return FakeNotification.supported;
    }
    opts: Record<string, unknown>;
    shown = false;
    closed = false;
    private handlers = new Map<string, Array<(...args: unknown[]) => void>>();
    constructor(opts: Record<string, unknown>) {
      this.opts = opts;
      FakeNotification.created.push(this);
    }
    on(event: string, cb: (...args: unknown[]) => void): this {
      const list = this.handlers.get(event) ?? [];
      list.push(cb);
      this.handlers.set(event, list);
      return this;
    }
    show(): void {
      this.shown = true;
    }
    close(): void {
      this.closed = true;
    }
    emit(event: string, ...args: unknown[]): void {
      for (const cb of this.handlers.get(event) ?? []) cb(...args);
    }
  }
  return { FakeNotification };
});

// The desktop tree carries its own node_modules, so from main/* the
// specifier "electron" resolves THERE — mocking bare "electron" from this test
// file would mock a different module id and leave the real one in place.
vi.mock("../node_modules/electron/index.js", () => ({
  Notification: mocked.FakeNotification,
}));

import {
  deliver,
  notifyFindings,
  probeNotificationDelivery,
  inWindowFallbackNeeded,
  setNoticeSink,
  statusBannerText,
  testNotification,
  type NoticeMirror,
} from "../main/notifications.js";
import { MAX_NOTICES, PREFS_DEFAULTS_VERSION, Store, UPDATED_NOTICE_ID, hiddenConfidenceBands, updatedNotice, type AppNotice, UPDATE_READY_NOTICE_ID, updateReadyNotice } from "../main/state.js";
import type { FindingRow } from "../main/lib/findings.js";

const { FakeNotification } = mocked;

function makeStore(persisted: Record<string, unknown> = {}) {
  const writes: Record<string, unknown>[] = [];
  const store = new Store({
    appVersion: "0.0.0-test",
    dataDir: "/tmp/nowhere",
    nodePlatform: "darwin",
    readPrefs: () => persisted,
    writePrefs: (prefs) => writes.push(prefs as unknown as Record<string, unknown>),
    onChange: () => {},
  });
  return { store, writes };
}

function notice(id: string, extra: Partial<AppNotice> = {}): AppNotice {
  return {
    id,
    kind: "info",
    title: "t-" + id,
    body: "b-" + id,
    at: "2026-09-02T00:00:00.000Z",
    ...extra,
  };
}

describe("Store notices", () => {
  it("pushes newest-last, replaces same id in place, dismisses by id", () => {
    const { store } = makeStore();
    store.pushNotice(notice("a"));
    store.pushNotice(notice("b"));
    expect(store.snapshot().notices.map((n) => n.id)).toEqual(["a", "b"]);

    // Re-raising an alert must not stack a duplicate.
    store.pushNotice(notice("a", { body: "updated" }));
    expect(store.snapshot().notices.map((n) => n.id)).toEqual(["b", "a"]);
    expect(store.snapshot().notices[1]!.body).toBe("updated");

    store.dismissNotice("b");
    expect(store.snapshot().notices.map((n) => n.id)).toEqual(["a"]);
    // Dismissing something already gone is a no-op, not an error.
    store.dismissNotice("b");
    expect(store.snapshot().notices).toHaveLength(1);
  });

  it("caps the stack at MAX_NOTICES, dropping oldest", () => {
    const { store } = makeStore();
    for (let i = 0; i < MAX_NOTICES + 3; i++) store.pushNotice(notice("n" + i));
    const ids = store.snapshot().notices.map((n) => n.id);
    expect(ids).toHaveLength(MAX_NOTICES);
    expect(ids[ids.length - 1]).toBe("n" + (MAX_NOTICES + 2));
  });
});

describe("updateReadyNotice", () => {
  it("is a sticky card with an Update now action and a stable id, so reminders replace rather than stack", () => {
    const a = updateReadyNotice("3.0.0", "2026-09-06T00:00:00Z");
    expect(a.id).toBe(UPDATE_READY_NOTICE_ID);
    expect(a.sticky).toBe(true);
    expect(a.action).toBe("install-update");
    expect(a.title).toContain("v3.0.0");
    expect(a.body).toMatch(/Update now/);
    expect(updateReadyNotice(undefined).title).toContain("an update");
  });
});

describe("Store.setNotificationCheck", () => {
  it("ok clears a refusal, blocked sets it, unknown leaves it as it was", () => {
    const { store } = makeStore();
    store.setNotificationCheck("blocked", "UNErrorDomain error 1");
    expect(store.snapshot().notifications_blocked).toBe(true);
    expect(store.snapshot().notification_check.status).toBe("blocked");
    // Silence after a refusal: still blocked as far as anyone knows.
    store.setNotificationCheck("unknown", "no response from Notification Center");
    expect(store.snapshot().notifications_blocked).toBe(true);
    expect(store.snapshot().notification_check).toMatchObject({ status: "unknown", error: "no response from Notification Center" });
    store.setNotificationCheck("ok");
    expect(store.snapshot().notifications_blocked).toBe(false);
    expect(store.snapshot().notification_check.status).toBe("ok");
    // Silence after a healthy answer does not invent a problem either.
    store.setNotificationCheck("unknown", "no response from Notification Center");
    expect(store.snapshot().notifications_blocked).toBe(false);
  });
});

describe("notify_blocked_alerted pref", () => {
  it("defaults false, persists a true round-trip, ignores junk", () => {
    expect(makeStore().store.prefs().notify_blocked_alerted).toBe(false);
    expect(makeStore({ notify_blocked_alerted: true }).store.prefs().notify_blocked_alerted).toBe(true);
    expect(makeStore({ notify_blocked_alerted: "yes" }).store.prefs().notify_blocked_alerted).toBe(false);

    const { store, writes } = makeStore();
    store.setPrefs({ notify_blocked_alerted: true });
    expect(writes[0]!.notify_blocked_alerted).toBe(true);
  });
});

describe("prefs defaults and the one-time default migration", () => {
  it("ships the menu-bar title off", () => {
    const { store } = makeStore();
    expect(store.prefs().tray_display).toBe("none");
    expect(store.prefs().defaults_v).toBe(PREFS_DEFAULTS_VERSION);
  });

  it("hides false positives by default, and keeps the choice to show them", () => {
    expect(makeStore().store.prefs().show_false_positives).toBe(false);
    expect(makeStore({ show_false_positives: true }).store.prefs().show_false_positives).toBe(true);
    // Anything but a boolean is the default, not a truthy surprise.
    expect(makeStore({ show_false_positives: "yes" }).store.prefs().show_false_positives).toBe(false);
    const { store, writes } = makeStore();
    store.setPrefs({ show_false_positives: true });
    expect(writes[0]!.show_false_positives).toBe(true);
    expect(store.prefs().show_false_positives).toBe(true);
  });

  it("ticks every confidence band by default, and keeps the set a person ticks", () => {
    const v5 = { defaults_v: 5 };
    expect(makeStore().store.prefs().confidence_bands).toEqual(["high", "medium", "low"]);
    expect(hiddenConfidenceBands(makeStore().store.prefs())).toEqual([]);
    expect(makeStore({ ...v5, confidence_bands: ["high", "medium"] }).store.prefs().confidence_bands).toEqual(["high", "medium"]);
    expect(hiddenConfidenceBands(makeStore({ ...v5, confidence_bands: ["high", "medium"] }).store.prefs())).toEqual(["low"]);
    expect(hiddenConfidenceBands(makeStore({ ...v5, confidence_bands: ["low", "medium", "high"] }).store.prefs())).toEqual([]);
    // High is a band like the others: unticked, sure rows fold away too.
    expect(hiddenConfidenceBands(makeStore({ ...v5, confidence_bands: ["medium"] }).store.prefs())).toEqual(["high", "low"]);
    // Canonical order, unknown values dropped, and never empty — an empty or
    // junk set is the default, never "show nothing".
    expect(makeStore({ ...v5, confidence_bands: ["low", "nope", "high"] }).store.prefs().confidence_bands).toEqual(["high", "low"]);
    expect(makeStore({ ...v5, confidence_bands: [] }).store.prefs().confidence_bands).toEqual(["high", "medium", "low"]);
    expect(makeStore({ ...v5, confidence_bands: ["yes"] }).store.prefs().confidence_bands).toEqual(["high", "medium", "low"]);
    expect(makeStore({ ...v5, confidence_bands: "high" }).store.prefs().confidence_bands).toEqual(["high", "medium", "low"]);
    // v5 moves every earlier install once: a stored ["high"] may only be the
    // old default, so it is not read as a choice; from v5 on it is.
    expect(makeStore({ defaults_v: 4, confidence_bands: ["high"] }).store.prefs().confidence_bands).toEqual(["high", "medium", "low"]);
    expect(makeStore({ confidence_bands: ["high", "medium"] }).store.prefs().confidence_bands).toEqual(["high", "medium", "low"]);
    expect(makeStore({ ...v5, confidence_bands: ["high"] }).store.prefs().confidence_bands).toEqual(["high"]);
    const { store, writes } = makeStore();
    store.setPrefs({ confidence_bands: ["high", "low"] });
    expect(writes[0]!.confidence_bands).toEqual(["high", "low"]);
    expect(store.prefs().confidence_bands).toEqual(["high", "low"]);
  });

  it("notifies about CRITICAL findings only, and nothing on a schedule", () => {
    // A banner interrupts whatever the person is doing in another app. The
    // default set is "bad, and yours to act on now": a critical finding and a
    // held call (which is blocking a session). Reports — high/medium findings,
    // the warn-rule coaching banner, the launch digest, the daily spend digest
    // — are a screen you open, not a banner. The weekly Monday digest stays on
    // as the one roll-up that replaces per-event chatter.
    const p = makeStore().store.prefs();
    expect(p.notify_findings).toBe("critical");
    expect(p.notify_coaching).toBe(false);
    expect(p.notify_startup_digest).toBe(false);
    expect(p.notify_spend_digest).toBe(false);
    expect(p.notify_held).toBe(true);
    expect(p.notify_security_digest).toBe(true);
    // Both digests land weekly unless asked otherwise: the daily one is the
    // noisier choice, so it is opted into, never defaulted into.
    expect(p.spend_digest_period).toBe("weekly");
    expect(p.security_digest_period).toBe("weekly");
  });

  it("tunes an existing install down once, then leaves its choices alone", () => {
    const old = makeStore({
      notify_findings: "high",
      notify_coaching: true,
      notify_startup_digest: true,
      notify_daily_digest: true,
    });
    expect(old.store.prefs().notify_findings).toBe("critical");
    expect(old.store.prefs().notify_coaching).toBe(false);
    expect(old.store.prefs().notify_startup_digest).toBe(false);
    // The v3 decision still reaches the RETIRED key: this file's
    // `notify_daily_digest: true` predates v3, so it is ignored, and the fold
    // into the new shape therefore finds nothing to turn on. A shape change
    // must not resurrect a default a migration already turned off.
    expect(old.store.prefs().notify_spend_digest).toBe(false);

    // Someone who WANTS every high finding after the migration keeps it.
    const chosen = makeStore({ notify_findings: "high", notify_coaching: true, defaults_v: PREFS_DEFAULTS_VERSION });
    expect(chosen.store.prefs().notify_findings).toBe("high");
    expect(chosen.store.prefs().notify_coaching).toBe(true);
  });

  it("folds the retired daily/weekly spend flags into one digest and one period", () => {
    // A file that already owns the v3 generation, so the flags are the
    // person's live choice rather than a pre-migration leftover.
    const v = PREFS_DEFAULTS_VERSION;
    const weekly = makeStore({ defaults_v: v, notify_weekly_digest: true }).store.prefs();
    expect(weekly.notify_spend_digest).toBe(true);
    expect(weekly.spend_digest_period).toBe("weekly");

    // Daily wins over weekly when a file carries both: it is the noisier
    // setting and somebody chose it, so collapsing to weekly would quietly
    // take it away. The duplicate banner is what the rework removes.
    const both = makeStore({ defaults_v: v, notify_daily_digest: true, notify_weekly_digest: true }).store.prefs();
    expect(both.notify_spend_digest).toBe(true);
    expect(both.spend_digest_period).toBe("daily");

    // Neither set: off, and the period is the default rather than undefined.
    const none = makeStore({ defaults_v: v }).store.prefs();
    expect(none.notify_spend_digest).toBe(false);
    expect(none.spend_digest_period).toBe("weekly");

    // The new keys win outright over any leftover legacy pair.
    const current = makeStore({
      defaults_v: v,
      notify_daily_digest: true,
      notify_spend_digest: false,
      spend_digest_period: "weekly",
    }).store.prefs();
    expect(current.notify_spend_digest).toBe(false);
    expect(current.spend_digest_period).toBe("weekly");
  });

  it("moves a default ONCE for a file that predates it, then leaves the person's choice alone", () => {
    // Prefs persist as a whole object the first time anything changes, so an
    // install that ever opened Settings already holds the OLD default and it
    // is indistinguishable from a deliberate choice. Without this, "on by
    // default" would only ever reach fresh installs.
    const old = makeStore({ tray_display: "spend" });
    expect(old.store.prefs().tray_display).toBe("none");

    // A file that has SEEN this generation keeps whatever it says, including a
    // value that happens to match the superseded default.
    const owned = makeStore({ tray_display: "spend", defaults_v: PREFS_DEFAULTS_VERSION });
    expect(owned.store.prefs().tray_display).toBe("spend");

    // Turning it off after the migration sticks: the write records the
    // version, so the next load doesn't re-apply the new default.
    const { store, writes } = makeStore({ tray_display: "spend" });
    store.setPrefs({ tray_display: "spend" });
    const written = writes[writes.length - 1]!;
    expect(written.defaults_v).toBe(PREFS_DEFAULTS_VERSION);
    expect(makeStore(written).store.prefs().tray_display).toBe("spend");
  });

  it("v4 switches the VS Code companion on for every install, once", () => {
    // Fresh install: on.
    expect(makeStore().store.prefs().vscode_extension).toBe(true);
    // An install from before v4 holding the old default — or even an explicit
    // off from that era — comes on: the decision was "on by default even where
    // installed", because the companion is how the guard asks in VS Code and
    // how the doctor learns a window's real trust state.
    expect(makeStore({ vscode_extension: false }).store.prefs().vscode_extension).toBe(true);
    expect(makeStore({ vscode_extension: false, defaults_v: 3 }).store.prefs().vscode_extension).toBe(true);
    // An off chosen AFTER v4 sticks.
    expect(makeStore({ vscode_extension: false, defaults_v: PREFS_DEFAULTS_VERSION }).store.prefs().vscode_extension).toBe(false);
    const { store, writes } = makeStore({ vscode_extension: false });
    store.setPrefs({ vscode_extension: false });
    expect(makeStore(writes[writes.length - 1]!).store.prefs().vscode_extension).toBe(false);
  });

  it("leaves the keys a migration does not name untouched", () => {
    // Neither key is in DEFAULT_MIGRATIONS, so a stored value that differs
    // from the shipped default survives with no version recorded at all.
    const { store } = makeStore({ retention_days: 7, notify_held: false });
    expect(store.prefs().retention_days).toBe(7);
    expect(store.prefs().notify_held).toBe(false);
  });
});

describe("notification mirror + probe", () => {
  beforeEach(() => {
    FakeNotification.created.length = 0;
    FakeNotification.supported = true;
  });

  it("deliver mirrors into the notice sink even when the platform has no notifications", () => {
    const seen: NoticeMirror[] = [];
    setNoticeSink((n) => seen.push(n));
    FakeNotification.supported = false;
    deliver("title", "body", undefined, "spend");
    expect(seen).toEqual([{ title: "title", body: "body", nav: "spend" }]);
    // The isSupported gate still holds for the OS banner itself.
    expect(FakeNotification.created).toHaveLength(0);
  });

  it("notifyFindings sends a BANNER above threshold and never an in-window toast", () => {
    // The window already says it: a new finding is on the Radar and counted in
    // the sidebar badge before this runs, so the toast was a third copy of a
    // fact on screen — and findings arrive in bursts, which made it the most
    // frequent thing in the app. The banner stays: it is for when you're
    // somewhere else.
    const seen: NoticeMirror[] = [];
    setNoticeSink((n) => seen.push(n));
    const row = {
      finding_id: "f1",
      detector: "secret_egress",
      severity: "high",
      status: "open",
    } as unknown as FindingRow;

    notifyFindings([row], "critical", () => {});
    expect(seen).toHaveLength(0);
    expect(FakeNotification.created).toHaveLength(0);

    notifyFindings([row], "high", () => {});
    expect(seen).toHaveLength(0);
    expect(FakeNotification.created).toHaveLength(1);
    expect(FakeNotification.created[0]!.opts.title).toContain("Security Radar");

    // Every OTHER message goes out as a banner too — and, while banners are
    // landing, ONLY as a banner: the in-window stack is the fallback, not a
    // second copy (see the refusal test at the end of this block).
    deliver("digest", "body", undefined, "radar");
    expect(seen).toHaveLength(0);
    expect(FakeNotification.created).toHaveLength(2);
  });

  it("probe resolves ok on show and withdraws the banner it sent", async () => {
    const pending = probeNotificationDelivery();
    const sent = FakeNotification.created[0]!;
    expect(sent.shown).toBe(true);
    expect(sent.opts.silent).toBe(true);
    sent.emit("show");
    await expect(pending).resolves.toEqual({ ok: true });
    expect(sent.closed).toBe(true);
  });

  it("probe resolves blocked on failed", async () => {
    const pending = probeNotificationDelivery();
    FakeNotification.created[0]!.emit("failed", null, "UNErrorDomain error 1");
    const result = await pending;
    expect(result.ok).toBe(false);
    expect(result.error).toContain("UNErrorDomain");
    // A refusal is evidence; it is NOT marked undetermined.
    expect(result.undetermined).toBeUndefined();
  });

  it("once macOS has refused a banner, the in-window stack takes over — the fallback is the only time a message shows inside", () => {
    // The refusal above flipped the module's deliveryRefused flag (there is no
    // reset on purpose: a refusal is sticky until relaunch, exactly as in the
    // app). From here on every message lands in the window as well.
    expect(inWindowFallbackNeeded()).toBe(true);
    const seen: NoticeMirror[] = [];
    setNoticeSink((n) => seen.push(n));
    deliver("digest", "body", undefined, "integrations");
    expect(seen).toEqual([{ title: "digest", body: "body", nav: "integrations" }]);
  });

  it("silence from Notification Center is undetermined, never a refusal", async () => {
    // A slow boot or the OS permission prompt still on screen both look like
    // silence. Recording that as "blocked" raised the sticky alert on healthy
    // installs, so the timeout says so explicitly and the caller keeps the
    // last real answer.
    vi.useFakeTimers();
    try {
      const pending = probeNotificationDelivery();
      await vi.advanceTimersByTimeAsync(4001);
      const result = await pending;
      expect(result.ok).toBe(false);
      expect(result.undetermined).toBe(true);
      expect(result.error).toContain("no response");
    } finally {
      vi.useRealTimers();
    }
  });

  it("a platform with no notifications is undetermined for the test and the probe too", async () => {
    FakeNotification.supported = false;
    await expect(probeNotificationDelivery()).resolves.toMatchObject({ ok: false, undetermined: true });
    await expect(testNotification()).resolves.toMatchObject({ ok: false, undetermined: true });
  });

  // Withdrawal is a request the OS may decline (Focus mode, an unauthorized
  // build), so whatever survives on screen has to be the status, not the words
  // "delivery check".
  it("probe carries the status summary when it is given one", () => {
    void probeNotificationDelivery({ todayTokens: 4120, windowTokens: 38_900, openFindings: 3 });
    const sent = FakeNotification.created[0]!;
    expect(sent.opts.subtitle).toBe("3 exposures to review");
    expect(String(sent.opts.body)).toContain("4.1k");
    expect(String(sent.opts.body)).toContain("38.9k tokens");
    // Tokens, never dollars.
    expect(String(sent.opts.body)).not.toContain("$");
    expect(String(sent.opts.body)).not.toContain("delivery check");
  });

  it("the Settings test banner states the same summary, plus what a held call looks like", () => {
    void testNotification(undefined, { todayTokens: 0, windowTokens: 0, openFindings: 0, heldNow: 2 });
    const sent = FakeNotification.created[0]!;
    expect(sent.opts.title).toContain("notifications are working");
    expect(sent.opts.subtitle).toBe("2 calls waiting on you");
    expect(String(sent.opts.body)).toContain("Deny and Allow");
    expect(sent.opts.silent).toBe(false);
  });
});

describe("statusBannerText", () => {
  const base = { todayTokens: 1, windowTokens: 2, openFindings: 0 };

  it("says the usage on every banner, in tokens", () => {
    expect(statusBannerText({ todayTokens: 0, windowTokens: 12_500, openFindings: 0 }).body).toBe(
      "Today 0 · last 7 days 12.5k tokens.",
    );
  });

  it("ranks the security line by what needs a person now", () => {
    // A broken guard outranks everything: findings may have STOPPED arriving.
    expect(
      statusBannerText({ ...base, openFindings: 9, heldNow: 4, guardHealthy: false }).subtitle,
    ).toContain("guard was changed");
    // Then a stopped session, then the review queue, then silence.
    expect(statusBannerText({ ...base, openFindings: 9, heldNow: 4 }).subtitle).toBe("4 calls waiting on you");
    expect(statusBannerText({ ...base, openFindings: 1, heldNow: 0 }).subtitle).toBe("1 exposure to review");
    expect(statusBannerText(base).subtitle).toBe("Radar all clear");
  });
});

describe("the \"an update installed itself\" notice", () => {
  it("is a one-line acknowledgement that shows itself out", () => {
    const n = updatedNotice("0.28.0", "2026-09-05T12:00:00.000Z");
    expect(n.title).toBe("Updated to v0.28.0");
    // No body and no action = the renderer draws it as one compact line, and
    // there is nothing to reach for that a short fuse would snatch away.
    expect(n.body).toBe("");
    expect(n.nav).toBeUndefined();
    expect(n.action).toBeUndefined();
    expect(n.ttl_ms).toBe(4_000);
    // Never sticky: nothing here needs acknowledging by hand.
    expect(n.sticky).toBeFalsy();
  });

  it("replaces its predecessor instead of stacking", () => {
    const { store } = makeStore();
    store.pushNotice(updatedNotice("0.28.0"));
    store.pushNotice(updatedNotice("0.29.0"));
    const updates = store.snapshot().notices.filter((n) => n.id === UPDATED_NOTICE_ID);
    expect(updates).toHaveLength(1);
    expect(updates[0]!.title).toBe("Updated to v0.29.0");
  });
});
