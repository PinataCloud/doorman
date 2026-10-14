/**
 * One call, one decision — across the several hook events a host fires for it.
 *
 * Cursor fires `beforeShellExecution` AND (per its doc, possibly) `preToolUse`
 * for the same shell command. Without this file that call is evaluated twice:
 * held twice, asked twice, denied twice. The host descriptor says which events
 * belong to one call (hosts/types.ts CallIdentity); this file remembers the
 * decision the FIRST event reached and lets the later event repeat it instead
 * of deciding again.
 *
 * Rules:
 *  · Only ACROSS events. A record is replayed only for a payload whose event
 *    name differs from the recorded one. The same call under the same event
 *    is a repeat, and a repeat is evaluated afresh — this is de-duplication of
 *    one call, never a grant for the next (review: grants are one-use).
 *  · Short-lived. A final decision is replayable for DEDUP_WINDOW_MS after it
 *    was reached; a `pending` record (the first event is holding) is waited on
 *    for at most its own hold window plus slack, then treated as absent.
 *  · Best effort. Every fs failure means "no record": the worst case is the
 *    duplicate evaluation this file exists to remove, never a skipped one.
 *
 * Files under `<guardDir>/dedup/`, one per call key, pruned on write. Same
 * rendezvous model as handshake.ts (files, not sockets) for the same reasons.
 *
 * Self-containment rule: copied verbatim into userData, run with plain `node`;
 * imports only its siblings.
 */

import { createHash } from "node:crypto";
import { mkdirSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { CallIdentity } from "./hosts/types.js";

/** How long a FINAL decision can be repeated for a later event of the same call. */
export const DEDUP_WINDOW_MS = 10_000;
/** Records older than this are litter (a hold that never resolved). */
export const DEDUP_PRUNE_MS = 10 * 60_000;
export const DEDUP_POLL_MS = 100;

export interface DedupRecord {
  /** The host event that reached (or is reaching) the decision. */
  event: string;
  /** `pending` while the first event is still holding. */
  decision: "pending" | "allow" | "ask" | "deny";
  /** The agent-facing reason printed with the decision; undefined for allow. */
  reason?: string;
  /** ISO instant the record was written. */
  at: string;
  /** Wall-clock budget (ms) a duplicate may wait on a pending record. */
  pending_budget_ms?: number;
}

/** A record whose decision has been reached. */
export type FinalDedupRecord = Omit<DedupRecord, "decision"> & { decision: "allow" | "ask" | "deny" };

export function dedupDir(guardDir: string): string {
  return join(guardDir, "dedup");
}

export function dedupPath(guardDir: string, host: string, identity: CallIdentity): string {
  const hash = createHash("sha1").update(`${host}\0${identity.key}`).digest("hex").slice(0, 24);
  return join(dedupDir(guardDir), `${hash}.json`);
}

export function readDedup(guardDir: string, host: string, identity: CallIdentity): DedupRecord | undefined {
  try {
    const raw = JSON.parse(readFileSync(dedupPath(guardDir, host, identity), "utf8")) as Partial<DedupRecord>;
    if (!raw || typeof raw.event !== "string" || typeof raw.at !== "string") return undefined;
    if (raw.decision !== "pending" && raw.decision !== "allow" && raw.decision !== "ask" && raw.decision !== "deny") return undefined;
    return {
      event: raw.event,
      decision: raw.decision,
      at: raw.at,
      ...(typeof raw.reason === "string" ? { reason: raw.reason } : {}),
      ...(typeof raw.pending_budget_ms === "number" ? { pending_budget_ms: raw.pending_budget_ms } : {}),
    };
  } catch {
    return undefined;
  }
}

/** Best-effort, never throws. Prunes stale siblings on the way. */
export function writeDedup(guardDir: string, host: string, identity: CallIdentity, record: DedupRecord, nowMs: number = Date.now()): void {
  try {
    const dir = dedupDir(guardDir);
    mkdirSync(dir, { recursive: true });
    writeFileSync(dedupPath(guardDir, host, identity), JSON.stringify(record));
    for (const name of readdirSync(dir)) {
      const path = join(dir, name);
      try {
        if (nowMs - statSync(path).mtimeMs > DEDUP_PRUNE_MS) rmSync(path, { force: true });
      } catch {
        // someone else's problem
      }
    }
  } catch {
    // no record → the duplicate is evaluated; never worse than before
  }
}

/**
 * Whether `record` decides `identity`'s payload: a different event, and either
 * a final decision inside the window or a pending one inside its budget.
 * Pure, so the rules above are testable without a clock.
 */
export function dedupApplies(record: DedupRecord, identity: CallIdentity, nowMs: number): boolean {
  if (record.event === identity.event) return false;
  const age = nowMs - Date.parse(record.at);
  if (!Number.isFinite(age) || age < 0) return false;
  if (record.decision === "pending") return age <= (record.pending_budget_ms ?? 0);
  return age <= DEDUP_WINDOW_MS;
}

const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * The decision an earlier event of this call reached, if one applies — waiting
 * out a pending hold first. Returns undefined when this payload must decide
 * for itself. NOT unref'd, for the same reason handshake.ts's sleep isn't: an
 * idle event loop would exit the guard mid-wait as a silent fail-open.
 */
export async function priorDecision(
  guardDir: string,
  host: string,
  identity: CallIdentity,
  options: { pollMs?: number; now?: () => number } = {},
): Promise<FinalDedupRecord | undefined> {
  const now = options.now ?? Date.now;
  const pollMs = options.pollMs ?? DEDUP_POLL_MS;
  for (;;) {
    const record = readDedup(guardDir, host, identity);
    if (!record || !dedupApplies(record, identity, now())) return undefined;
    if (record.decision !== "pending") return { ...record, decision: record.decision };
    await sleep(pollMs);
  }
}
