import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { describe, expect, it } from "vitest";

import {
  COPILOT_CHAT_BUCKET,
  COPILOT_COMPLETIONS_BUCKET,
  COPILOT_PREMIUM_BUCKET,
  describeQuota,
  governingBucket,
  newerQuota,
  parseQuotaBucket,
  parseQuotaSnapshots,
  quotaStatus,
  quotaWindow,
  type CopilotQuotaBucket,
} from "../main/lib/copilot-quota.js";
import { copilotSource } from "../main/lib/copilot-transcript.js";
import type { SourceIo } from "../main/lib/transcript-sources.js";

/** A snapshot exactly as Copilot CLI 1.0.83 writes it (captured on this Mac). */
const snapshot = (over: Record<string, unknown> = {}) => ({
  isUnlimitedEntitlement: false,
  entitlementRequests: 200,
  usedRequests: 6,
  usageAllowedWithExhaustedQuota: false,
  overage: 0,
  overageAllowedWithExhaustedQuota: false,
  remainingPercentage: 96.9,
  resetDate: "2026-10-01T00:00:00Z",
  ...over,
});

const AT = "2026-09-08T18:26:34.382Z";

describe("reading one quota bucket", () => {
  it("takes the percentage from Copilot's own figure, not used/entitlement", () => {
    // 6/200 would be 3.0%; Copilot says 96.9 remaining because requests carry
    // fractional multipliers. Its number is the one a person is metered on.
    const bucket = parseQuotaBucket(COPILOT_CHAT_BUCKET, snapshot())!;
    expect(bucket.used_percentage).toBeCloseTo(3.1, 5);
    expect(bucket.used).toBe(6);
    expect(bucket.entitlement).toBe(200);
    expect(bucket.resets_at).toBe("2026-10-01T00:00:00.000Z");
  });

  it("reads an unlimited entitlement as nothing used, whatever the percentage says", () => {
    const bucket = parseQuotaBucket("chat", snapshot({ isUnlimitedEntitlement: true, remainingPercentage: 0 }))!;
    expect(bucket.unlimited).toBe(true);
    expect(bucket.used_percentage).toBe(0);
  });

  it("clamps a percentage outside 0–100 rather than showing it", () => {
    expect(parseQuotaBucket("chat", snapshot({ remainingPercentage: -20 }))!.used_percentage).toBe(100);
    expect(parseQuotaBucket("chat", snapshot({ remainingPercentage: 140 }))!.used_percentage).toBe(0);
  });

  it("is not fooled by an object that isn't a snapshot", () => {
    expect(parseQuotaBucket("chat", { cacheTtlSeconds: 1800 })).toBeUndefined();
    expect(parseQuotaBucket("chat", "nope")).toBeUndefined();
  });
});

/**
 * The governing bucket is the number a person acts on, so every way of getting
 * it wrong is a wrong alarm — and one of them (a zero entitlement reading as
 * 100% used) is live on the account this was written against.
 */
describe("which bucket actually constrains agent work", () => {
  const bucket = (over: Partial<CopilotQuotaBucket> & { id: string }): CopilotQuotaBucket => ({
    entitlement: 200,
    used: 6,
    used_percentage: 3.1,
    unlimited: false,
    allowed_when_exhausted: false,
    overage: 0,
    overage_allowed: false,
    ...over,
  });

  it("NEVER lets a zero-entitlement bucket govern — that is a plan that includes none, not a full one", () => {
    // Exactly this Mac: premium_interactions is entitlement 0 / remaining 0,
    // which reads as 100% used. Letting it govern would alarm permanently on an
    // account that has simply never had a premium entitlement.
    const buckets = [
      bucket({ id: COPILOT_CHAT_BUCKET }),
      bucket({ id: COPILOT_PREMIUM_BUCKET, entitlement: 0, used: 0, used_percentage: 100 }),
    ];
    expect(governingBucket(buckets)?.id).toBe(COPILOT_CHAT_BUCKET);
  });

  it("ignores completions — an exhausted ghost-text quota cannot stop an agent turn", () => {
    const buckets = [
      bucket({ id: COPILOT_CHAT_BUCKET, used_percentage: 10 }),
      bucket({ id: COPILOT_COMPLETIONS_BUCKET, entitlement: 2000, used_percentage: 99 }),
    ];
    expect(governingBucket(buckets)?.id).toBe(COPILOT_CHAT_BUCKET);
  });

  it("ignores an unlimited bucket and takes the tightest of the rest", () => {
    const buckets = [
      bucket({ id: "chat", used_percentage: 20 }),
      bucket({ id: "premium_interactions", used_percentage: 80 }),
      bucket({ id: "other", unlimited: true, used_percentage: 0 }),
    ];
    expect(governingBucket(buckets)?.id).toBe("premium_interactions");
  });

  it("is absent when nothing can run out", () => {
    expect(governingBucket([bucket({ id: "chat", unlimited: true })])).toBeUndefined();
    expect(governingBucket([bucket({ id: "chat", entitlement: 0 })])).toBeUndefined();
    expect(governingBucket([])).toBeUndefined();
  });
});

describe("the window, the status and the sentence", () => {
  const quota = (chat: Record<string, unknown>) =>
    parseQuotaSnapshots({ quotaSnapshots: { chat: snapshot(chat), premium_interactions: snapshot({ entitlementRequests: 0, remainingPercentage: 0 }) } }, AT);

  it("reports the governing window at Copilot's own precision", () => {
    expect(quotaWindow(quota({}))).toEqual({ used_percentage: 3.1, resets_at: "2026-10-01T00:00:00.000Z" });
  });

  it("separates exhausted-and-stopped from exhausted-and-still-costing", () => {
    expect(quotaStatus(quota({}))).toBe("within_limit");
    expect(quotaStatus(quota({ remainingPercentage: 5 }))).toBe("approaching_limit");
    expect(quotaStatus(quota({ remainingPercentage: 0 }))).toBe("exhausted");
    expect(quotaStatus(quota({ remainingPercentage: 0, overage: 3 }))).toBe("exhausted_on_overage");
    expect(quotaStatus(quota({ remainingPercentage: 0, usageAllowedWithExhaustedQuota: true }))).toBe(
      "exhausted_still_serving",
    );
  });

  it("says it in one sentence with the counts behind it", () => {
    expect(describeQuota(quota({}))).toBe("3% of this month's Copilot chat request quota used (6 of 200).");
  });

  it("has nothing to report when nothing constrains", () => {
    const unlimited = parseQuotaSnapshots({ quotaSnapshots: { chat: snapshot({ isUnlimitedEntitlement: true }) } }, AT);
    expect(quotaWindow(unlimited)).toBeUndefined();
    expect(quotaStatus(unlimited)).toBeUndefined();
    expect(describeQuota(unlimited)).toBeUndefined();
    expect(parseQuotaSnapshots({}, AT)).toBeUndefined();
  });
});

describe("merging readings", () => {
  it("keeps the newest and never sums — the counter is account-wide", () => {
    const older = parseQuotaSnapshots({ quotaSnapshots: { chat: snapshot({ usedRequests: 2, remainingPercentage: 99.1 }) } }, "2026-09-08T18:12:37.366Z")!;
    const newer = parseQuotaSnapshots({ quotaSnapshots: { chat: snapshot({ usedRequests: 6, remainingPercentage: 96.9 }) } }, AT)!;
    expect(newerQuota(older, newer)).toBe(newer);
    expect(newerQuota(newer, older)).toBe(newer);
    expect(newerQuota(undefined, older)).toBe(older);
    // A month roll-over RESETS the counter; "newest wins" survives that, a
    // high-water mark would not.
    const afterReset = parseQuotaSnapshots({ quotaSnapshots: { chat: snapshot({ usedRequests: 0, remainingPercentage: 100 }) } }, "2026-10-01T00:05:00.000Z")!;
    expect(newerQuota(newer, afterReset)).toBe(afterReset);
  });
});

/**
 * The parser end to end. `quotaSnapshots` rides `model.model_call_success` and
 * NOT `assistant.usage` (which this Copilot build never persists) — the reason
 * every Copilot turn used to settle `unknown`.
 */
describe("in the transcript parser", () => {
  const events = (lines: unknown[]) => lines.map((l) => JSON.stringify(l)).join("\n");
  const io = (files: Record<string, string>): SourceIo => ({
    readText: (p) => files[p],
    listDir: () => [],
    stat: (p) => (files[p] === undefined ? undefined : { size: files[p]!.length, mtimeMs: 0, isDirectory: false }),
    querySqlite: () => [],
  });
  const path = "/h/.copilot/session-state/s1/events.jsonl";

  const log = events([
    { id: "e1", type: "session.start", timestamp: "2026-09-08T18:00:00.000Z", data: { sessionId: "s1", selectedModel: "gpt-5.6-luna" } },
    { id: "e2", type: "user.message", timestamp: "2026-09-08T18:00:01.000Z", data: { content: "hello" } },
    { id: "e3", type: "assistant.message", timestamp: "2026-09-08T18:00:02.000Z", data: { content: "hi", messageId: "m1" } },
    {
      id: "e4",
      type: "model.model_call_success",
      timestamp: AT,
      data: { quotaSnapshots: { chat: snapshot(), completions: snapshot({ entitlementRequests: 2000, usedRequests: 0, remainingPercentage: 100 }) } },
    },
  ]);

  it("hands back the plan window, named for the rail it came from", () => {
    const result = copilotSource.parse(path, io({ [path]: log }));
    expect(result.plan_window).toMatchObject({
      source: "copilot-cli",
      used_percentage: 3.1,
      window_id: "chat",
      used: 6,
      entitlement: 200,
      status: "within_limit",
      resets_at: "2026-10-01T00:00:00.000Z",
    });
    expect(result.plan_window?.label).toContain("3%");
  });

  it("settles the session's turns as plan-covered, which the missing event used to prevent", () => {
    const result = copilotSource.parse(path, io({ [path]: log }));
    const assistant = result.turns.filter((t) => t.role === "assistant");
    expect(assistant.length).toBeGreaterThan(0);
    for (const turn of assistant) expect(turn.settlement).toBe("subscription");
  });

  it("reports no window when the log never stated one", () => {
    const quiet = events([{ id: "e1", type: "session.start", timestamp: "2026-09-08T18:00:00.000Z", data: { sessionId: "s1" } }]);
    expect(copilotSource.parse(path, io({ [path]: quiet })).plan_window).toBeUndefined();
  });
});

/**
 * The real Copilot logs on THIS machine. A quota field renamed upstream shows
 * up here as a window that suddenly cannot be read — the failure a fixture
 * written from today's shape can never catch.
 */
const STATE = `${homedir()}/.copilot/session-state`;
describe.skipIf(!existsSync(STATE))("against the Copilot sessions on this Mac", () => {
  const realIo: SourceIo = {
    readText: (p) => {
      try {
        return readFileSync(p, "utf8");
      } catch {
        return undefined;
      }
    },
    listDir: (p) => {
      try {
        return readdirSync(p);
      } catch {
        return [];
      }
    },
    stat: (p) => {
      try {
        const s = statSync(p);
        return { size: s.size, mtimeMs: s.mtimeMs, isDirectory: s.isDirectory() };
      } catch {
        return undefined;
      }
    },
    querySqlite: () => [],
  };

  it("finds a readable quota window in EVERY log that carries one", () => {
    const docs = copilotSource.discover(STATE, realIo);
    // Not "some window somewhere": every document whose log contains the event
    // that carries quotaSnapshots must yield a window. A renamed field would
    // otherwise pass as "none of these had one".
    const carriers = docs.filter((p) => (realIo.readText(p) ?? "").includes('"model.model_call_success"'));
    const windows = docs
      .map((p) => copilotSource.parse(p, realIo).plan_window)
      .filter((w): w is NonNullable<typeof w> => w !== undefined);
    expect(windows.length, `${carriers.length} log(s) carry a model call`).toBe(carriers.length);
    if (windows.length === 0) return; // no model call has ever run here
    for (const w of windows) {
      expect(w.used_percentage, JSON.stringify(w)).toBeGreaterThanOrEqual(0);
      expect(w.used_percentage).toBeLessThanOrEqual(100);
      // The governing bucket must never be the one with no entitlement.
      expect(w.entitlement === undefined || w.entitlement > 0).toBe(true);
      if (w.resets_at) expect(Number.isFinite(Date.parse(w.resets_at))).toBe(true);
    }
  });
});
