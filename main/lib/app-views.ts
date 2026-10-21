/**
 * The views the app's screens read, folded from the engine's stores: the
 * Radar's annotated rows, the Analytics windows, alerts by use-case and the
 * two exports. Main's snapshot (index.ts recompute and the export handlers)
 * and the CLI (main/cli) both build them here, so a number in the terminal is
 * the number on the screen. Pure apart from what the engine hands in.
 */

import type { CaptureEngine } from "../capture.js";
import type { GuardPolicy } from "../guard/policy.js";
import { customDetectorLabels } from "../guard/custom-rules.js";
import { accountForRow, familyNoun } from "./account.js";
import { buildDetectionsExport, validateDetectionsExport, type DetectionsExport, type SchemaProblem } from "./detection-schema.js";
import { annotateExposure, createPlaceResolver, exposureKey, type PlaceKind } from "./exposures.js";
import {
  SEVERITY_RANK,
  confidenceOf,
  localDetectorLabel,
  ruleModeOf,
  summarizeRuleStats,
  thingKey,
  type FindingConfidence,
  type FindingRow,
  type RuleStatsWindow,
  type WindowStats,
} from "./findings.js";
import { buildLedgerExport, validateLedgerExport, type LedgerExport } from "./ledger-export.js";
import { maskTurnText } from "./masking.js";
import type { SessionSummary } from "./turns.js";

export type RadarRow = FindingRow & { place: string; place_kind: PlaceKind; exposure_key: string };

/**
 * The rows as the Radar receives them: stamped with the exposure (rule ×
 * place) each belongs to, resolved over EVERY row passed in so every reader
 * groups on the same key. A row minted before accounts existed, or by the
 * guard's spool at hold time, gets a THIN account from its own fields
 * (lib/account.ts) so its card is still titled by the exposure, not the rule;
 * a stored account's family WORD is re-derived from its label, so a row
 * written by an older build reads with today's spelling. Nothing is stored.
 */
export function radarRows(findings: readonly FindingRow[], home: string | undefined, limit = findings.length): RadarRow[] {
  const places = createPlaceResolver(findings, { home });
  return findings.slice(0, limit).map((row) => {
    const thin = row.account === undefined ? accountForRow(row) : undefined;
    const account = thin ?? row.account;
    const refreshed =
      account === undefined
        ? undefined
        : (() => {
            const { family_noun: _stale, ...rest } = account;
            const noun = familyNoun(account.credential_family);
            return noun === undefined ? rest : { ...rest, family_noun: noun };
          })();
    return annotateExposure(refreshed === undefined ? row : { ...row, account: refreshed }, places);
  });
}

/**
 * The rows the Radar feed reads, before any filter: a row in a confidence
 * band the person has not ticked (state.ts hiddenConfidenceBands) is out, and
 * false positives are out unless `prefs.show_false_positives` brings them
 * back. MIRRORS renderer/screens/radar.jsx (`inBand`, `withoutFp`).
 */
export function radarFeedRows<T extends FindingRow>(
  rows: readonly T[],
  options: { hiddenBands: readonly FindingConfidence[]; showFalsePositives: boolean },
): T[] {
  return rows.filter(
    (row) => !options.hiddenBands.includes(confidenceOf(row)) && (options.showFalsePositives || row.status !== "false_positive"),
  );
}

export type FindingOutcome = "blocked" | "held" | "warned" | "excepted" | "observed";

/** What the guard DID with a row. MIRRORS renderer/components.jsx findingOutcome.
 * A row with a hold resolution was held, whatever the guard wrote once it was
 * answered (a denied hold is recorded as `deny`). */
export function findingOutcome(row: Pick<FindingRow, "enforced" | "resolution">): FindingOutcome {
  if (row.resolution) return "held";
  if (row.enforced === "deny") return "blocked";
  if (row.enforced === "ask") return "held";
  if (row.enforced === "warn") return "warned";
  if (row.enforced === "excepted") return "excepted";
  return "observed";
}

/** Whether the call behind a row actually ran (warned, excepted, observed, or
 * held and allowed). MIRRORS renderer/screens/radar.jsx exposureRan. */
export function exposureRan(row: Pick<FindingRow, "enforced" | "resolution">): boolean {
  if (row.enforced === "deny") return false;
  if (row.enforced === "ask") return row.resolution === "allowed";
  return true;
}

/** WHERE an exposure is, in one word: the project its face ran in, else the
 * place main resolved (a host, a server, a sink). MIRRORS
 * renderer/screens/radar.jsx exposurePlace. */
export function exposurePlace(face: Pick<RadarRow, "cwd" | "place">): string {
  return (face.cwd || face.place || "").split("/").filter(Boolean).pop() || "";
}

/** "4s", "1m 12s": a hold's duration. MIRRORS renderer/screens/radar.jsx fmtHold. */
export function fmtHold(ms: number): string {
  if (!Number.isFinite(ms) || ms < 0) return "—";
  const s = Math.round(ms / 1000);
  if (s < 60) return `${s}s`;
  return `${Math.floor(s / 60)}m ${s % 60}s`;
}

export type HoldEndingKey = "allowed" | "denied" | "passed" | "pending";

/** How a held call ended, in the app's words; undefined for a row never
 * held. `key` buckets the endings ("denied" covers both refusals). MIRRORS
 * renderer/screens/radar.jsx holdEnding. */
export function holdEnding(row: Pick<FindingRow, "enforced" | "resolution">): { key: HoldEndingKey; label: string } | undefined {
  if (findingOutcome(row) !== "held") return undefined;
  switch (row.resolution) {
    case "allowed":
      return { key: "allowed", label: "Allowed by you" };
    case "denied":
      return { key: "denied", label: "Denied by you" };
    case "timeout":
      return { key: "denied", label: "Denied — no answer" };
    case "unavailable":
      return { key: "denied", label: "Denied — nobody could be asked" };
    case "unattended":
      return { key: "passed", label: "Passed to the agent's own prompt" };
    default:
      return { key: "pending", label: "No answer recorded" };
  }
}

/** Where a held call was answered, by a person. MIRRORS radar.jsx DECIDED_VIA_LABELS. */
const DECIDED_VIA_LABELS: Partial<Record<NonNullable<FindingRow["decided_via"]>, string>> = {
  panel: "the floating panel",
  window: "the app window",
  notification: "a notification",
  editor: "the editor",
  terminal: "the terminal",
};

/** The held rows' endings as one line: "Denied by you after 12s" for one
 * hold, "2 allowed by you · 1 denied — no answer" for several; `via` names
 * the surface a person answered a single hold from. Undefined when nothing
 * was held. MIRRORS renderer/screens/radar.jsx holdSummary. */
export function holdSummary(rows: readonly Pick<FindingRow, "enforced" | "resolution" | "hold_ms" | "decided_via">[]): { text: string; via?: string } | undefined {
  const held = rows.filter((r) => findingOutcome(r) === "held");
  if (held.length === 0) return undefined;
  const buckets = new Map<string, { key: HoldEndingKey; label: string; n: number }>();
  for (const r of held) {
    const e = holdEnding(r)!;
    const b = buckets.get(e.label) ?? { ...e, n: 0 };
    b.n += 1;
    buckets.set(e.label, b);
  }
  const parts = [...buckets.values()];
  if (held.length === 1) {
    const r = held[0]!;
    const e = parts[0]!;
    const after = e.key !== "pending" && typeof r.hold_ms === "number" && Number.isFinite(r.hold_ms) ? ` after ${fmtHold(r.hold_ms)}` : "";
    const via = r.decided_via ? DECIDED_VIA_LABELS[r.decided_via] : undefined;
    return { text: e.label + after, ...(via ? { via } : {}) };
  }
  return { text: parts.map((p) => `${p.n} ${p.label.charAt(0).toLowerCase()}${p.label.slice(1)}`).join(" · ") };
}

/** A closed card's outcome words, or undefined when its sightings were only
 * observed (the rest state, not news): "blocked", "held, then denied",
 * "mixed outcomes". MIRRORS renderer/screens/radar.jsx closedOutcome. */
export function closedOutcome(rows: readonly Pick<FindingRow, "enforced" | "resolution">[]): string | undefined {
  const outcomes = [...new Set(rows.map(findingOutcome))];
  if (outcomes.length > 1) return "mixed outcomes";
  const o = outcomes[0];
  if (o === undefined || o === "observed") return undefined;
  if (o !== "held") return o;
  const ends = [...new Set(rows.map((r) => holdEnding(r)!.key))];
  return ends.length === 1 && (ends[0] === "allowed" || ends[0] === "denied") ? `held, then ${ends[0]}` : "held";
}

/** One Radar card: an exposure (rule × place) in one triage bucket. */
export interface ExposureGroup<T extends RadarRow> {
  key: string;
  /** The worst row, most recent first among equals: the card's face. */
  face: T;
  rows: T[];
  bucket: "open" | "triaged";
  /** Distinct things (rule × exposed name) under the card. */
  things: number;
  sessions: number;
  latest: string;
  earliest: string;
  /** What the guard did, over every row; "mixed" when they disagree. */
  outcome: FindingOutcome | "mixed";
  /** False when every call on the card was stopped before it ran. */
  ran: boolean;
}

/**
 * The Radar's cards: rows sorted worst-first (severity, then most recent) and
 * grouped on `exposure_key` per triage bucket, so open and triaged rows never
 * share a card. MIRRORS renderer/screens/radar.jsx sortFindings +
 * groupFindings.
 */
export function exposureGroups<T extends RadarRow>(rows: readonly T[]): ExposureGroup<T>[] {
  const sorted = [...rows].sort(
    (a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] || (a.last_seen_at < b.last_seen_at ? 1 : a.last_seen_at > b.last_seen_at ? -1 : 0),
  );
  const groups = new Map<string, { group: ExposureGroup<T>; things: Set<string>; sessions: Set<string>; outcomes: Set<FindingOutcome> }>();
  for (const row of sorted) {
    const bucket = row.status === "open" ? "open" : "triaged";
    const key = `${row.exposure_key} ${bucket}`;
    let entry = groups.get(key);
    if (!entry) {
      entry = {
        group: { key, face: row, rows: [], bucket, things: 0, sessions: 0, latest: row.last_seen_at, earliest: row.first_seen_at, outcome: "observed", ran: false },
        things: new Set(),
        sessions: new Set(),
        outcomes: new Set(),
      };
      groups.set(key, entry);
    }
    const { group } = entry;
    group.rows.push(row);
    entry.things.add(thingKey(row));
    if (row.session_id) entry.sessions.add(row.session_id);
    entry.outcomes.add(findingOutcome(row));
    if (exposureRan(row)) group.ran = true;
    if (row.last_seen_at > group.latest) group.latest = row.last_seen_at;
    if (row.first_seen_at < group.earliest) group.earliest = row.first_seen_at;
  }
  return [...groups.values()].map(({ group, things, sessions, outcomes }) => ({
    ...group,
    things: things.size,
    sessions: sessions.size,
    outcome: outcomes.size === 1 ? [...outcomes][0]! : "mixed",
  }));
}

/** Open-finding counts per session, so a ledger row can say "· 2 alerts". */
export function alertsBySession(findings: Iterable<FindingRow>): Map<string, number> {
  const out = new Map<string, number>();
  for (const row of findings) {
    if (row.status !== "open" || !row.session_id) continue;
    out.set(row.session_id, (out.get(row.session_id) ?? 0) + 1);
  }
  return out;
}

/** Session → use-case, so the usage graphs can split by task type. */
export function sessionTaskLookup(sessions: readonly SessionSummary[]): (id: string) => string | undefined {
  const byId = new Map<string, string>();
  for (const s of sessions) if (s.task) byId.set(s.id, s.task);
  return (id) => byId.get(id);
}

/**
 * Open findings grouped by the use-case of the session they fired in, most
 * alerts first. Findings with no session (or a session older than the turn
 * retention window, so its class is unknowable) fold into "other" rather than
 * being dropped — a finding that cannot be attributed is still a finding.
 */
export function alertsByTask(
  findings: Iterable<FindingRow>,
  taskOf: (sessionId: string) => string | undefined,
): { task: string; alerts: number; sessions: number }[] {
  const alerts = new Map<string, number>();
  const sessions = new Map<string, Set<string>>();
  for (const finding of findings) {
    if (finding.status !== "open") continue;
    const task = (finding.session_id ? taskOf(finding.session_id) : undefined) ?? "other";
    alerts.set(task, (alerts.get(task) ?? 0) + 1);
    if (finding.session_id) {
      let set = sessions.get(task);
      if (!set) sessions.set(task, (set = new Set()));
      set.add(finding.session_id);
    }
  }
  return [...alerts.entries()]
    .map(([task, count]) => ({ task, alerts: count, sessions: sessions.get(task)?.size ?? 0 }))
    .sort((a, b) => b.alerts - a.alerts || a.task.localeCompare(b.task));
}

/** Open exposure keys per finding, resolved over EVERY finding passed in so
 * the keys match the Radar's cards (`radarRows`). */
function openExposureKeys(findings: Iterable<FindingRow>, home: string | undefined): { row: FindingRow; key: string }[] {
  const all = [...findings];
  const places = createPlaceResolver(all, { home });
  return all
    .filter((row) => row.status === "open")
    .map((row) => ({ row, key: exposureKey(row.detector, places.placeOf(row)) }));
}

/** Distinct open exposures (Radar cards) touching each session. */
export function exposuresBySession(findings: Iterable<FindingRow>, home: string | undefined): Map<string, number> {
  const keys = new Map<string, Set<string>>();
  for (const { row, key } of openExposureKeys(findings, home)) {
    if (!row.session_id) continue;
    let set = keys.get(row.session_id);
    if (!set) keys.set(row.session_id, (set = new Set()));
    set.add(key);
  }
  return new Map([...keys].map(([id, set]) => [id, set.size]));
}

/**
 * Distinct open exposures per use-case, most first. An exposure seen in
 * sessions of several use-cases counts once in EACH, so the rows can sum past
 * the Radar total. Unattributable findings fold into "other", as in
 * `alertsByTask`.
 */
export function exposuresByTask(
  findings: Iterable<FindingRow>,
  taskOf: (sessionId: string) => string | undefined,
  home: string | undefined,
): { task: string; exposures: number; sessions: number }[] {
  const keys = new Map<string, Set<string>>();
  const sessions = new Map<string, Set<string>>();
  for (const { row, key } of openExposureKeys(findings, home)) {
    const task = (row.session_id ? taskOf(row.session_id) : undefined) ?? "other";
    let k = keys.get(task);
    if (!k) keys.set(task, (k = new Set()));
    k.add(key);
    if (row.session_id) {
      let s = sessions.get(task);
      if (!s) sessions.set(task, (s = new Set()));
      s.add(row.session_id);
    }
  }
  return [...keys.entries()]
    .map(([task, set]) => ({ task, exposures: set.size, sessions: sessions.get(task)?.size ?? 0 }))
    .sort((a, b) => b.exposures - a.exposures || a.task.localeCompare(b.task));
}

/**
 * One Analytics window: the per-rule stats plus the denominators that turn
 * "17 sessions had a finding" into "a third of the sessions that ran did".
 * Counted off the session store rather than `sessions_total`, which is every
 * session ever KEPT — retention prunes sessions while their findings live on,
 * so that denominator can shrink below its own numerator. A session counts for
 * the window it ENDED in.
 */
export function ruleStatsWindow(
  findings: readonly FindingRow[],
  sessions: readonly SessionSummary[],
  days: RuleStatsWindow,
  now: Date,
  labels: Record<string, string>,
): WindowStats {
  const stats = summarizeRuleStats(findings, days, now, labels);
  const cutoff = new Date(now.getTime() - days * 86_400_000).toISOString();
  const prevCutoff = new Date(now.getTime() - 2 * days * 86_400_000).toISOString();
  let ran = 0;
  let ranBefore = 0;
  for (const s of sessions) {
    if (s.ended_at >= cutoff) ran += 1;
    else if (s.ended_at >= prevCutoff) ranBefore += 1;
  }
  return { ...stats, window_sessions: ran, prev_window_sessions: ranBefore };
}

/** Every detection the Radar shows, as the schema-valid bundle
 * (lib/detection-schema.ts), with the schema problems if it breaks it. Masked
 * like the report: fingerprints stand in for values. */
export function detectionsExportFor(
  engine: Pick<CaptureEngine, "shownFindings">,
  policy: GuardPolicy,
  appVersion: string,
  generatedAt: Date,
): { bundle: DetectionsExport; problems: SchemaProblem[] } {
  const labels = customDetectorLabels(policy.custom_rules ?? []);
  const bundle = buildDetectionsExport({
    rows: engine.shownFindings(),
    app_version: appVersion,
    generated_at: generatedAt,
    labelOf: (id) => localDetectorLabel(id, labels),
    modeOf: (id) => ruleModeOf(id, policy),
  });
  return { bundle, problems: validateDetectionsExport(bundle) };
}

/**
 * The Event Ledger as the schema-valid bundle (lib/ledger-export.ts): every
 * session, or one, with its turns — text redacted, removed values as the same
 * fingerprints the detections carry. Undefined when there is no such session.
 */
export function ledgerExportFor(
  engine: Pick<CaptureEngine, "sessions" | "turnsBySession" | "shownFindings" | "fingerprintsOf">,
  sessionId: string | undefined,
  appVersion: string,
  generatedAt: Date,
): { bundle: LedgerExport; problems: SchemaProblem[] } | undefined {
  const all = engine.sessions();
  const sessions = sessionId !== undefined && sessionId !== "" ? all.filter((s) => s.id === sessionId) : all;
  if (sessions.length === 0) return undefined;
  // Grouped once: per-session scans of the whole store and the whole ledger
  // made the export quadratic in sessions.
  const turns = engine.turnsBySession();
  const detections = new Map<string, string[]>();
  for (const f of engine.shownFindings()) {
    if (!f.session_id) continue;
    const list = detections.get(f.session_id);
    if (list) list.push(f.finding_id);
    else detections.set(f.session_id, [f.finding_id]);
  }
  const bundle = buildLedgerExport({
    sessions,
    turnsOf: (id) => turns.get(id) ?? [],
    detectionIdsOf: (id) => detections.get(id) ?? [],
    mask: maskTurnText,
    fingerprintsOf: (raw, masked) => engine.fingerprintsOf(raw, masked),
    app_version: appVersion,
    generated_at: generatedAt,
  });
  return { bundle, problems: validateLedgerExport(bundle) };
}
