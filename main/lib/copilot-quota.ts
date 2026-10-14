/**
 * GitHub Copilot's own quota meter — how much of this month's plan is gone, and
 * when it comes back.
 *
 * WHY THIS AND NOT DOLLARS. Copilot does not bill per token; it bills per
 * REQUEST against a monthly entitlement, and the client is never told what a
 * request cost. The reader beside this one (copilot-transcript.ts) therefore
 * derives USD from token counts at API rates, and deliberately refuses to
 * convert `total_nano_aiu` into money — the unit's relation to a credit is
 * undocumented and a plausible-looking conversion would be a fabricated number.
 * What Copilot DOES state exactly is the quota, and that is what this reads.
 *
 * WHERE IT LIVES (verified on this Mac against Copilot CLI 1.0.83, 2026-09-11 —
 * 9 of 9 model calls carried it, nothing else did): the `quotaSnapshots` object
 * on a **`model.model_call_success`** event's `data`. NOT on `assistant.usage`,
 * which the schema documents and which this build never persists at all —
 * which is why settlement for every Copilot turn had been reading `unknown`
 * while the answer sat on the neighbouring event.
 *
 * THE SHAPE, one entry per quota bucket:
 *
 *     "chat": { isUnlimitedEntitlement: false, entitlementRequests: 200,
 *               usedRequests: 6, usageAllowedWithExhaustedQuota: false,
 *               overage: 0, overageAllowedWithExhaustedQuota: false,
 *               remainingPercentage: 96.9, resetDate: "2026-10-01T00:00:00Z" }
 *
 * THREE THINGS THAT WOULD OTHERWISE BE READ WRONG:
 *
 *  1. `usedRequests` is ACCOUNT-WIDE and monotonic ACROSS sessions — observed
 *     climbing 2 → 3 → 4 → 5 → 6 through five separate sessions. So the
 *     newest snapshot anywhere on the machine is the truth, and snapshots must
 *     never be summed.
 *  2. `remainingPercentage` is finer-grained than `usedRequests` (98.7 then
 *     98.6 at the same `usedRequests: 3` — requests carry fractional
 *     multipliers). It is Copilot's own figure, so it is what the meter shows;
 *     `used`/`entitlement` are carried alongside for the human sentence.
 *  3. `entitlementRequests: 0` means THE PLAN INCLUDES NONE OF THIS, and it
 *     comes with `remainingPercentage: 0`. Read naively as "0% remaining" that
 *     is a permanent 100%-used alarm — which is exactly what this Mac's
 *     `premium_interactions` bucket would have raised, on an account that has
 *     simply never had a premium entitlement. A bucket with no entitlement is
 *     not a window at all and is never the governing one.
 *
 * `completions` is excluded from the governing choice on evidence, not taste:
 * it is the inline ghost-text surface, and it sat at `usedRequests: 0` through
 * all nine agent model calls while `chat` climbed. An exhausted completions
 * quota cannot stop an agent turn, so letting it govern would report a ceiling
 * the agent never meets.
 *
 * Pure: parsing only, no fs, no clock.
 */

/** Copilot's bucket keys, as it writes them. Not an enum — a new bucket must
 * show up as itself rather than be dropped. */
export const COPILOT_CHAT_BUCKET = "chat";
export const COPILOT_PREMIUM_BUCKET = "premium_interactions";
export const COPILOT_COMPLETIONS_BUCKET = "completions";

/** Buckets that cannot gate an agent turn — see the header. */
const NON_AGENT_BUCKETS = new Set([COPILOT_COMPLETIONS_BUCKET]);

export interface CopilotQuotaBucket {
  /** Copilot's own key: "chat", "premium_interactions", … */
  id: string;
  /** Requests included in the window. 0 = the plan includes none of this. */
  entitlement: number;
  used: number;
  /** 0–100, from Copilot's `remainingPercentage` — see header note 2. */
  used_percentage: number;
  unlimited: boolean;
  /** Copilot keeps serving this bucket after the quota is gone. */
  allowed_when_exhausted: boolean;
  /** Requests served beyond the entitlement (billed as overage). */
  overage: number;
  overage_allowed: boolean;
  /** ISO instant the window resets, when Copilot stated one. */
  resets_at?: string;
}

export interface CopilotQuota {
  /** When this snapshot was observed — the event's own timestamp. */
  at: string;
  /** Every bucket Copilot reported, in its own order. */
  buckets: CopilotQuotaBucket[];
  /** The bucket that actually constrains agent work, when one does. */
  governing?: CopilotQuotaBucket;
}

function num(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

function obj(value: unknown): Record<string, unknown> | undefined {
  return value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : undefined;
}

function iso(value: unknown): string | undefined {
  if (typeof value !== "string" || value === "") return undefined;
  const ms = Date.parse(value);
  return Number.isFinite(ms) ? new Date(ms).toISOString() : undefined;
}

/** One bucket, or undefined when the entry is not a quota snapshot at all. */
export function parseQuotaBucket(id: string, value: unknown): CopilotQuotaBucket | undefined {
  const snap = obj(value);
  if (!snap) return undefined;
  const remaining = num(snap.remainingPercentage);
  const entitlement = num(snap.entitlementRequests);
  const used = num(snap.usedRequests);
  // A snapshot states at least a remaining percentage or an entitlement;
  // anything with neither is some other object that happened to sit here.
  if (remaining === undefined && entitlement === undefined) return undefined;
  const unlimited = snap.isUnlimitedEntitlement === true;
  return {
    id,
    entitlement: entitlement ?? 0,
    used: used ?? 0,
    // Clamped, because a percentage outside 0–100 is not a number this app
    // will put in front of someone.
    used_percentage: unlimited ? 0 : Math.min(100, Math.max(0, 100 - (remaining ?? 0))),
    unlimited,
    allowed_when_exhausted: snap.usageAllowedWithExhaustedQuota === true,
    overage: num(snap.overage) ?? 0,
    overage_allowed: snap.overageAllowedWithExhaustedQuota === true,
    ...(iso(snap.resetDate) === undefined ? {} : { resets_at: iso(snap.resetDate)! }),
  };
}

/**
 * The bucket a person is actually running out of: the tightest one that can
 * gate an agent turn. Undefined when none can — an unlimited plan, or one
 * whose only buckets are entitlement-less (nothing to run out OF).
 */
export function governingBucket(buckets: readonly CopilotQuotaBucket[]): CopilotQuotaBucket | undefined {
  let best: CopilotQuotaBucket | undefined;
  for (const bucket of buckets) {
    if (bucket.unlimited) continue; // never constrains
    if (bucket.entitlement <= 0) continue; // the plan includes none of this
    if (NON_AGENT_BUCKETS.has(bucket.id)) continue;
    if (!best || bucket.used_percentage > best.used_percentage) best = bucket;
  }
  return best;
}

/** Read the `quotaSnapshots` off one event's `data`. Undefined when absent. */
export function parseQuotaSnapshots(data: unknown, at: string): CopilotQuota | undefined {
  const snapshots = obj(obj(data)?.quotaSnapshots);
  if (!snapshots) return undefined;
  const buckets: CopilotQuotaBucket[] = [];
  for (const [id, value] of Object.entries(snapshots)) {
    const bucket = parseQuotaBucket(id, value);
    if (bucket) buckets.push(bucket);
  }
  if (buckets.length === 0) return undefined;
  const governing = governingBucket(buckets);
  return { at, buckets, ...(governing ? { governing } : {}) };
}

/**
 * The newer of two readings. Account-wide and monotonic (header note 1), so
 * "newest wins" is the whole merge — never a sum, and never a max of used
 * counts, which would survive a month roll-over as a stuck high-water mark.
 */
export function newerQuota(a: CopilotQuota | undefined, b: CopilotQuota | undefined): CopilotQuota | undefined {
  if (!a) return b;
  if (!b) return a;
  return Date.parse(b.at) > Date.parse(a.at) ? b : a;
}

/**
 * The plan-limit window this rail reports (`PlanLimitWindowSchema`), or
 * undefined when nothing constrains. Monthly: Copilot's entitlement resets on
 * the first of the month, which is why this cannot ride one of the Claude
 * windows (`five_hour` / `seven_day`) and gets its own.
 */
export function quotaWindow(quota: CopilotQuota | undefined): { used_percentage: number; resets_at?: string } | undefined {
  const governing = quota?.governing;
  if (!governing) return undefined;
  return {
    // One decimal is Copilot's own precision; more would invent significance.
    used_percentage: Math.round(governing.used_percentage * 10) / 10,
    ...(governing.resets_at === undefined ? {} : { resets_at: governing.resets_at }),
  };
}

/**
 * Copilot's own verdict on the window, for `PlanLimitSnapshot.status` — a free
 * string, deliberately not an enum (the schema's own convention, so provider
 * wording changes never reject a snapshot).
 */
export function quotaStatus(quota: CopilotQuota | undefined): string | undefined {
  const governing = quota?.governing;
  if (!governing) return undefined;
  if (governing.used_percentage >= 100) {
    // Exhausted is not the same as STOPPED: Copilot may keep serving on
    // overage, or because the plan allows use past the quota. The status says
    // which, because one of them costs money and the other does not.
    if (governing.overage > 0 || governing.overage_allowed) return "exhausted_on_overage";
    if (governing.allowed_when_exhausted) return "exhausted_still_serving";
    return "exhausted";
  }
  return governing.used_percentage >= 90 ? "approaching_limit" : "within_limit";
}

/** One sentence for the app, or undefined when there is no window to describe. */
export function describeQuota(quota: CopilotQuota | undefined): string | undefined {
  const governing = quota?.governing;
  if (!governing) return undefined;
  const label = governing.id === COPILOT_PREMIUM_BUCKET ? "premium request" : `${governing.id} request`;
  const pct = Math.round(governing.used_percentage);
  const of = governing.entitlement > 0 ? ` (${governing.used} of ${governing.entitlement})` : "";
  return `${pct}% of this month's Copilot ${label} quota used${of}.`;
}
