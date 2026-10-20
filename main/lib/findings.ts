/**
 * The local findings ledger for the Security Radar. Rows carry the same finding
 * shape the detectors emit (masked excerpt, named key, occurrence count) plus
 * local lifecycle: status, first/last seen, and — for guard-hook findings —
 * what enforcement actually did, and how long the person took to decide.
 *
 * Identity is the detector's own rule (securityFindingId over detector + session +
 * key_name), so the same exposure seen by the backfill, the live watcher and
 * the PreToolUse guard converges on ONE row instead of three.
 */

import type { SecurityDetectorId, SecuritySeverity, SecurityFinding } from "../guard/security-detect.js";
import { securityFindingId } from "../guard/security-detect.js";
import type { ApprovalResolution, ApprovalVia } from "../guard/handshake.js";
import { DETECTOR_LABELS, SEVERITY_RANK } from "../guard/policy.js";
import { customDetectorId, isCustomDetectorId, type CustomDetectorId, type CustomRule } from "../guard/custom-rules.js";
import type { FlowDetectorId } from "./flow-rules.js";
import type { McpDetectorId } from "../guard/mcp-poison.js";
import type { EgressDetectorId } from "./egress-intel.js";
import { countSecurityGroups } from "./security-grouping.js";
import { createPlaceResolver, exposureKey, type PlaceKind } from "./exposures.js";
import type { TurnSource } from "./turns.js";
import type { ExposureAccount } from "./account.js";
import type { EnforcementMode } from "../guard/policy.js";
import { DETECTION_SCHEMA_VERSION, upgradeFindingRow } from "./detection-schema.js";
import { maskFindingRow } from "./masking.js";

/**
 * Where a finding came from. `TurnSource` covers the two rails with
 * transcripts; a guard-hook row can also carry the `source` of any registered
 * host (guard/hosts/index.ts), which has findings and held calls but no
 * transcript and no ledger. The renderer labels it through the host list on
 * the snapshot, and an unknown value renders as itself.
 */
export type FindingSource = TurnSource | (string & {});

export type FindingStatus = "open" | "resolved" | "false_positive" | "accepted_risk";

/** The gateway's description-change (rug pull) finding — gateway-install.ts. */
export type McpChangeDetectorId = "mcp_tool_changed";
/** The guard's own entry or bundle was altered — lib/guard-integrity.ts. */
export type IntegrityDetectorId = "guard_tampered";

/** The shipped radar-only ids — enumerable, so they can carry a label map. */
export type StaticLocalDetectorId =
  | SecurityDetectorId
  | FlowDetectorId
  | McpDetectorId
  | McpChangeDetectorId
  | EgressDetectorId
  | IntegrityDetectorId;

/**
 * Everything a LOCAL row's detector column can hold: the shared per-unit
 * detectors, the radar-only session-flow / MCP / egress / integrity rules,
 * and a person's own `custom:<id>` rules. The radar-only ids are
 * deliberately NOT SecurityDetectorId — they never enter the guard's per-
 * detector policy, and the guard bundle
 * never learns they exist. Radar-only, structurally. (Custom rules carry
 * their own mode instead — see guard/custom-rules.ts.)
 */
export type LocalDetectorId = StaticLocalDetectorId | CustomDetectorId;

/** A finding whose detector may be radar-only — what mintFindingRow takes. */
export type LocalFinding = Omit<SecurityFinding, "detector"> & { detector: LocalDetectorId };

/** DETECTOR_LABELS plus the radar-only ids, for surfaces (notifications)
 * that label rows rather than guard decisions. Custom rules are not here —
 * they are labelled by their own text through `localDetectorLabel`. */
export const LOCAL_DETECTOR_LABELS: Record<StaticLocalDetectorId, string> = {
  ...DETECTOR_LABELS,
  wallet_address_tampered: "Wallet address from outside, then written or paid to (session flow)",
  flow_secret_egress: "Secret read, then network egress (session flow)",
  flow_injection_followed: "Injected instruction, then acted on (session flow)",
  flow_fetch_then_exec: "Fetched content, then executed (session flow)",
  flow_fetch_then_install: "Fetched content named a package, then installed (session flow)",
  flow_insecure_code_executed: "Insecure code written, then executed (session flow)",
  flow_read_then_send: "Private data read, then sent (session flow)",
  flow_sql_second_order: "Database result, then a later query (session flow)",
  agent_loop: "Agent loop (same call repeated)",
  unknown_mcp_server: "Unapproved MCP server",
  mcp_tool_poisoning: "MCP tool poisoning",
  mcp_tool_changed: "MCP tool description changed",
  egress_new_destination: "New external destination",
  guard_tampered: "Guard entry or bundle altered",
};

/**
 * The one way to turn a detector id into words. Shipped ids come from the map;
 * a custom id takes the label the row (or the policy) recorded for it, else the
 * bare id minus its namespace — never `undefined`, never a crash on a rule
 * someone has since deleted.
 */
export function localDetectorLabel(id: string, customLabels?: Record<string, string> | undefined): string {
  const known = (LOCAL_DETECTOR_LABELS as Record<string, string>)[id];
  if (known) return known;
  if (customLabels && typeof customLabels[id] === "string") return customLabels[id]!;
  if (isCustomDetectorId(id)) return `Your rule: ${id.slice("custom:".length)}`;
  return id;
}

/**
 * The level a rule is working at under `policy` — what a sighting records as
 * `rule_mode`. A guard detector reads its mode (or `off` when disabled); a
 * person's rule carries its own; everything else the app mints is Radar-only.
 * Undefined for a custom id no rule in the policy owns any more.
 */
export function ruleModeOf(
  detector: string,
  policy: { modes: Partial<Record<string, EnforcementMode>>; disabled: readonly string[]; custom_rules?: readonly CustomRule[] },
): FindingRuleMode | undefined {
  if (isCustomDetectorId(detector)) {
    const rule = policy.custom_rules?.find((r) => customDetectorId(r.id) === detector);
    if (!rule) return undefined;
    return rule.enabled === false ? "off" : rule.mode;
  }
  if (!GUARD_DETECTORS.has(detector)) return "radar";
  if (policy.disabled.includes(detector)) return "off";
  return policy.modes[detector] ?? "observe";
}

/** The detectors the guard can enforce. `injected_instruction` shares their
 * label map but scans tool OUTPUT, which a PreToolUse guard never sees — so
 * it records as `radar`, the same way policy.ts leaves it out of its catalog. */
const GUARD_DETECTORS: ReadonlySet<string> = new Set(Object.keys(DETECTOR_LABELS).filter((id) => id !== "injected_instruction"));

/** Where a row came from: transcripts on disk, the PreToolUse guard, an MCP
 * config file or the gateway's observations (no session to anchor to), or the
 * guard-integrity check. */
export type FindingOrigin = "transcript" | "guard" | "config" | "gateway" | "integrity";

/** How a held call was decided. Widens the reply's surface with the two
 * non-human endings (hold.ts HoldTelemetry). */
export type DecidedVia = ApprovalVia | "timeout" | "app-absent";

/** What enforcement did with a sighting. `excepted`: a scoped ignore rule
 * (an approval-panel Allow, a manual exception) dropped the
 * finding before the decision, so the call ran unheld — recorded, never
 * silent. */
export type FindingEnforced = "ask" | "deny" | "warn" | "excepted";

/** The exception behind an `excepted` sighting — guard/policy.ts
 * ScopedIgnoreRule, copied onto the row at the time it applied. */
export interface FindingException {
  pattern: string;
  detector?: string;
  cwd_prefix?: string;
  expires_at?: string;
  note?: string;
  origin?: "approval" | "manual";
}

/**
 * What a model made of a rule's hit. `stood_down` is the only verdict that
 * changes anything (confidence → medium, no banner, no armed escalation);
 * `confirmed` and `unsure` leave the row exactly as the rule minted it and are
 * recorded so the Radar can say the model looked.
 */
export interface FindingAssist {
  /** The app's injection classifier (Prompt Guard over tool output) or the
   * guard's credential second opinion (a local model asked before a hold). */
  by: "injection_classifier" | "second_opinion";
  /** Human label — "Llama Prompt Guard 2", or the local model id. */
  model: string;
  verdict: "stood_down" | "confirmed" | "unsure";
  /** P(malicious) in 0–1 — the classifier only; the second opinion answers in words. */
  score?: number;
}

/** What the rule was set to when the row was recorded — the guard's four
 * modes, `off` for a disabled rule, `radar` for a rule the guard never
 * enforces (session flow, MCP, egress, integrity). */
export type FindingRuleMode = EnforcementMode | "off" | "radar";

/** A value redaction removed from the row's evidence, as a fingerprint —
 * lib/evidence-vault.ts. Never the value. */
export interface SecretFingerprint {
  label: string;
  length: number;
  /** HMAC-SHA256 under this machine's vault key, 16 hex characters. */
  fingerprint: string;
  primary?: boolean;
}

/**
 * One detection. The shape is fixed by lib/detection-schema.ts:
 * add a field here and the schema must learn it too, or the ledger check and
 * the export fail — test/detection-schema.test.ts holds the two
 * together with a fully-populated row.
 */
export interface FindingRow {
  /** lib/detection-schema.ts DETECTION_SCHEMA_VERSION; stamped on write and
   * on read, so rows from before the schema read as the current version. */
  schema_version?: number;
  finding_id: string;
  detector: LocalDetectorId;
  severity: SecuritySeverity;
  /** Absent means high — the detector's own certainty, or a classifier's
   * adjustment of it (medium = a guess the fold and the notifier treat as
   * observe-grade). Mirrors SecurityFinding.confidence. */
  confidence?: "high" | "medium" | "low";
  /** A model's second look at this row, when one ran. The rule fired first —
   * a model never adds a finding — and this says what it made of the hit, so
   * the person can see the reasoning behind a softened (or confirmed) row. */
  assist?: FindingAssist;
  /** What happened, in quotable fields and a sentence (lib/account.ts,
   *): the source, the sink, the family, the gap, and whether the
   * value looks like a placeholder. Read off the raw unit at scan time and
   * persisted — it carries paths, command words and hosts, never a value. */
  account?: ExposureAccount;
  key_name?: string;
  excerpt: string;
  occurrences: number;
  tool_name?: string;
  target?: string;
  source: FindingSource;
  origin: FindingOrigin;
  session_id?: string;
  /** The ledger turn this row sits under. For a tool_output-derived row this is
   * the ASSISTANT turn that issued the call, not the transcript line the
   * result arrived on — that line is never a ledger turn, so anchoring to it
   * left every injection and exfil-link row in the ledger's orphan pile. */
  turn_id?: string;
  /** Session-flow rows (flow_*, agent_loop, a custom `after` rule) span TWO
   * calls; `turn_id` is the sink's. These name where the flow BEGAN — the read,
   * the fetch, the first repeat — so the card can state the gap and the ledger
   * can mark both ends. Absent on per-unit rows. */
  source_turn_id?: string;
  source_at?: string;
  /** agent_loop only: what the assistant turns spanning the run cost, in USD,
   * summed from the priced turns in [source_at, last_seen]. Absent when no turn
   * in the span was priced — never 0, which would read as "free". A number
   * rather than a suffix on the excerpt, so Analytics can add it up. */
  burned_usd?: number;
  /** agent_loop only: input+output tokens of the assistant turns spanning the
   * run — the figure the screens show, since a dollar derived
   * on-device is an estimate the app cannot stand behind. Absent when no turn
   * in the span carried usage — never 0, which would read as "free". */
  burned_tokens?: number;
  /** Config-anchored rows (origin "config"): the app whose config file this is
   * — "Cursor", "Claude Desktop" — since `source` can only name a capture
   * rail and those apps are not rails. */
  config_host?: string;
  /** The working directory of the call, when the guard or transcript knew it —
   * what a scoped ignore rule is anchored to. */
  cwd?: string;
  status: FindingStatus;
  first_seen_at: string;
  last_seen_at: string;
  /** What the guard did when it saw this: held ("ask"), refused ("deny"), let
   * it run with a coaching banner ("warn"), or let it run because an exception
   * of the person's applied ("excepted" — see `exception`);
   * absent = observed. */
  enforced?: FindingEnforced;
  /** The exception that let an "excepted" call through — the policy's scoped
   * ignore rule as it stood at the time (pattern, detector, directory, expiry,
   * note, origin), so the row can say WHICH allowance did it even after the
   * rule is removed. */
  exception?: FindingException;
  /** For a call the guard HELD: how the confirmation ended. Absent means the
   * detector never held anything (observe, straight block, or transcript-side). */
  resolution?: ApprovalResolution;
  /** For a held call: when the hold was raised and answered, through which
   * surface, and how long that took — the raw material for "median time to
   * approve" and the per-surface split. Absent on rows older than this field. */
  held_at?: string;
  decided_at?: string;
  decided_via?: DecidedVia;
  hold_ms?: number;
  /** The person allowed it and scoped an ignore rule to the project. */
  allow_scope?: "project";
  /** A custom rule's label at the time it fired, so the row still reads when
   * the rule is edited or deleted. */
  detector_label?: string;
  /** The rule's mode at the newest sighting — the level it was working at,
   * which the policy alone cannot say once someone changes it. */
  rule_mode?: FindingRuleMode;
  /** The app build that recorded the newest sighting — which version of the
   * detectors fired. */
  app_version?: string;
  /** The values redacted from the evidence, as fingerprints. The
   * value itself sits in the Keychain-encrypted evidence vault, if at all. */
  secrets?: SecretFingerprint[];
  /** SNAPSHOT-ONLY (lib/exposures.ts): the place this row's exposure is about
   * and the key the renderer groups on. Stamped by main when it builds the
   * snapshot; never written to the ledger, never present on stored rows. */
  place?: string;
  place_kind?: PlaceKind;
  exposure_key?: string;
}

export interface FindingContext {
  source: FindingSource;
  origin: FindingOrigin;
  session_id?: string;
  turn_id?: string;
  source_turn_id?: string;
  source_at?: string;
  burned_usd?: number;
  burned_tokens?: number;
  config_host?: string;
  cwd?: string;
  at: string;
  enforced?: FindingEnforced;
  resolution?: ApprovalResolution;
  held_at?: string;
  decided_at?: string;
  decided_via?: DecidedVia;
  hold_ms?: number;
  allow_scope?: "project";
  detector_label?: string;
  assist?: FindingAssist;
  exception?: FindingException;
  account?: ExposureAccount;
  rule_mode?: FindingRuleMode;
  app_version?: string;
  secrets?: SecretFingerprint[];
}

/**
 * Whether the call behind a row never ran: the guard refused it, a
 * hold ended in a denial or was never answered, or nobody could be asked and
 * the default denied. Nothing of it reached any transcript, so the guard's
 * own line is the whole record — the screens show it masked, with a note in
 * place of VIEW RAW. `allowed` and `unattended` (the host's own fallback let
 * it through) mean it ran. MIRRORED in renderer/components.jsx.
 */
export function callNeverRan(row: Pick<FindingRow, "enforced" | "resolution">): boolean {
  if (row.resolution === "denied" || row.resolution === "unavailable") return true;
  const held = row.enforced === "deny" || row.enforced === "ask";
  return held && row.resolution !== "allowed" && row.resolution !== "unattended";
}

/**
 * Whether there is a document behind a row to read its evidence from:
 * a config row's file, or a session's transcript — and the call actually ran.
 * Gateway and integrity rows, a guard line that named no session, and a call
 * that never ran have none by design — and a row the app cannot back with
 * evidence is not shown (capture.ts rowShown).
 */
export function evidenceReadable(row: Pick<FindingRow, "enforced" | "resolution" | "origin" | "session_id" | "target">): boolean {
  if (callNeverRan(row)) return false;
  return row.origin === "config" ? row.target !== undefined : row.session_id !== undefined;
}

export function mintFindingRow(finding: LocalFinding, context: FindingContext): FindingRow {
  // Free-text fields a detector copied from the RAW call (a Bash target is the
  // command's first word) are masked here, once, so no row — and nothing built
  // from one — ever carries a value. The id is minted from the detector's own
  // key first, so masking never changes a finding's identity.
  return maskFindingRow({
    schema_version: DETECTION_SCHEMA_VERSION,
    finding_id: securityFindingId([
      finding.detector,
      context.session_id ?? "",
      finding.key_name ?? "",
    ]),
    detector: finding.detector,
    severity: finding.severity,
    key_name: finding.key_name,
    excerpt: finding.excerpt,
    occurrences: finding.occurrences,
    tool_name: finding.tool_name,
    target: finding.target,
    source: context.source,
    origin: context.origin,
    session_id: context.session_id,
    turn_id: context.turn_id,
    ...(context.source_turn_id === undefined ? {} : { source_turn_id: context.source_turn_id }),
    ...(context.source_at === undefined ? {} : { source_at: context.source_at }),
    ...(context.burned_usd === undefined ? {} : { burned_usd: context.burned_usd }),
    ...(context.burned_tokens === undefined ? {} : { burned_tokens: context.burned_tokens }),
    ...(context.config_host === undefined ? {} : { config_host: context.config_host }),
    ...(context.cwd === undefined ? {} : { cwd: context.cwd }),
    status: "open",
    first_seen_at: context.at,
    last_seen_at: context.at,
    enforced: context.enforced,
    resolution: context.resolution,
    ...(context.held_at === undefined ? {} : { held_at: context.held_at }),
    ...(context.decided_at === undefined ? {} : { decided_at: context.decided_at }),
    ...(context.decided_via === undefined ? {} : { decided_via: context.decided_via }),
    ...(context.hold_ms === undefined ? {} : { hold_ms: context.hold_ms }),
    ...(context.allow_scope === undefined ? {} : { allow_scope: context.allow_scope }),
    ...(context.detector_label === undefined ? {} : { detector_label: context.detector_label }),
    ...(finding.confidence === undefined ? {} : { confidence: finding.confidence }),
    ...(context.assist === undefined ? {} : { assist: context.assist }),
    ...(context.account === undefined ? {} : { account: context.account }),
    ...(context.exception === undefined ? {} : { exception: context.exception }),
    ...(context.rule_mode === undefined ? {} : { rule_mode: context.rule_mode }),
    ...(context.app_version === undefined ? {} : { app_version: context.app_version }),
    ...(context.secrets === undefined || context.secrets.length === 0 ? {} : { secrets: context.secrets }),
  });
}

/**
 * Merge a re-observation into an existing row. IDEMPOTENT under re-scans: a
 * whole-file re-parse re-mints the same finding, so occurrences take the max,
 * not the sum, and timestamps only widen. Status is local triage state and is
 * never reset by an observation.
 */
export function mergeFinding(existing: FindingRow, incoming: FindingRow): FindingRow {
  // The SIGHTING-scoped fields (excerpt, severity, turn, flow ends, level,
  // build, fingerprints…) describe one sighting and travel together: the
  // newest one's win. An OLDER sighting arriving late — a restart re-mints
  // every tool_output of a changed file, and a session split across
  // `<id>.jsonl` + `agent-*.jsonl` re-mints earlier calls — only fills gaps,
  // or the card would show one call's excerpt beside another's fingerprints.
  const newer = incoming.last_seen_at >= existing.last_seen_at;
  const pick = <T>(fresh: T | undefined, kept: T | undefined): T | undefined =>
    newer ? (fresh ?? kept) : (kept ?? fresh);
  const optional = <K extends keyof FindingRow>(key: K): Partial<Pick<FindingRow, K>> => {
    const value = pick(incoming[key], existing[key]);
    return value === undefined ? {} : ({ [key]: value } as Partial<Pick<FindingRow, K>>);
  };
  const merged: FindingRow = {
    ...existing,
    severity: newer ? incoming.severity : existing.severity,
    excerpt: newer ? incoming.excerpt : existing.excerpt,
    occurrences: Math.max(existing.occurrences, incoming.occurrences),
    ...optional("tool_name"),
    ...optional("target"),
    ...optional("turn_id"),
    // A flow's ends move with the newest sighting (a longer loop, a later
    // sink); a re-scan that lost them keeps the old.
    ...optional("source_turn_id"),
    ...optional("source_at"),
    ...optional("burned_usd"),
    ...optional("burned_tokens"),
    ...((existing.config_host ?? incoming.config_host) !== undefined ? { config_host: existing.config_host ?? incoming.config_host } : {}),
    ...((existing.cwd ?? incoming.cwd) !== undefined ? { cwd: existing.cwd ?? incoming.cwd } : {}),
    first_seen_at:
      incoming.first_seen_at < existing.first_seen_at
        ? incoming.first_seen_at
        : existing.first_seen_at,
    last_seen_at:
      incoming.last_seen_at > existing.last_seen_at
        ? incoming.last_seen_at
        : existing.last_seen_at,
    // A resolution is the end of the story for a held call, so it OUTRANKS the
    // "detected" line the guard wrote before the hold — otherwise a call the
    // person denied would keep reading as merely "asked".
    // An exception applying to a LATER sighting is the newest truth about the
    // thing: it now runs unheld, whatever an earlier line said.
    enforced: incoming.resolution
      ? incoming.enforced
      : incoming.enforced === "excepted"
        ? "excepted"
        : (existing.enforced ?? incoming.enforced),
    resolution: incoming.resolution ?? existing.resolution,
    ...((incoming.exception ?? existing.exception) !== undefined ? { exception: incoming.exception ?? existing.exception } : {}),
    // Decision telemetry travels with the resolution line and is kept
    // thereafter; a later plain re-observation never erases how it was decided.
    ...(incoming.resolution
      ? {
          ...(incoming.held_at === undefined ? {} : { held_at: incoming.held_at }),
          ...(incoming.decided_at === undefined ? {} : { decided_at: incoming.decided_at }),
          ...(incoming.decided_via === undefined ? {} : { decided_via: incoming.decided_via }),
          ...(incoming.hold_ms === undefined ? {} : { hold_ms: incoming.hold_ms }),
          ...(incoming.allow_scope === undefined ? {} : { allow_scope: incoming.allow_scope }),
        }
      : {}),
    ...optional("detector_label"),
    // The newest look wins; a re-scan without a model (feature off, model
    // gone) does not erase what the model once said.
    ...optional("assist"),
    // The newest sighting's account goes with its excerpt; a re-scan that
    // produced none keeps the old one.
    ...optional("account"),
    // The level, build and fingerprints travel with the newest sighting, like
    // its excerpt; a sighting that carried none keeps what was known.
    ...optional("rule_mode"),
    ...optional("app_version"),
    ...optional("secrets"),
    schema_version: DETECTION_SCHEMA_VERSION,
  };
  // The band is the NEWEST sighting's, absent and all — every merge site
  // hands in a row a detector just minted, and absent means the detector
  // was sure this time. Carrying the first value forward would keep a row
  // the Radar folds away hidden after the rule, or a model, had
  // since confirmed it; `...existing` above would do exactly that.
  if (!newer) return merged;
  if (incoming.confidence === undefined) delete merged.confidence;
  else merged.confidence = incoming.confidence;
  return merged;
}

/** Fold the findings JSONL (append-only, whole rows, last state wins — except
 * observations, which merge). Tolerates malformed lines; upgrades rows written
 * before the detection schema (lib/detection-schema.ts). */
export function foldFindingLines(lines: readonly string[], stats?: { upgraded: number }): Map<string, FindingRow> {
  const rows = new Map<string, FindingRow>();
  for (const line of lines) {
    const trimmed = line.trim();
    if (trimmed === "") continue;
    let row: FindingRow | undefined;
    let parsed: unknown;
    try {
      parsed = JSON.parse(trimmed);
      row = upgradeFindingRow(parsed);
    } catch {
      continue;
    }
    if (!row) continue;
    // Counted so the caller can rewrite a ledger whose stored lines still
    // carry what the upgrade just masked, instead of leaving it on disk.
    if (stats && JSON.stringify(row) !== JSON.stringify(parsed)) stats.upgraded += 1;
    rows.set(row.finding_id, row);
  }
  return rows;
}

export interface RadarSummary {
  /** Individual open rows — still what "how much did we detect" asks. */
  open: number;
  by_severity: Record<SecuritySeverity, number>;
  by_detector: Partial<Record<string, number>>;
  /** Distinct open GROUPS (lib/security-grouping.ts) — the number every
   * human-facing surface shows: the hero, the sidebar badge, the feed's pill.
   * One `.env` habit across forty sessions is one thing to decide about, and
   * badging it "40" measures how busy the week was, not how much there is to do. */
  open_groups: number;
  by_severity_groups: Record<SecuritySeverity, number>;
  /** Distinct open EXPOSURES (lib/exposures.ts) — rule × place — the layer
   * above groups and the number the hero, badge and menu bar now carry: one
   * repo full of fixture secrets is one decision, not sixty-seven. */
  open_exposures: number;
  by_severity_exposures: Record<SecuritySeverity, number>;
  affected_sessions: number;
  latest_detected_at?: string;
}

/** The band a row is read at. Absent means high (mintFindingRow only writes
 * the field when a detector lowered it), so every reader asks through this. */
export type FindingConfidence = NonNullable<FindingRow["confidence"]>;
export const CONFIDENCE_BANDS: readonly FindingConfidence[] = ["high", "medium", "low"];
export function confidenceOf(row: Pick<FindingRow, "confidence">): FindingConfidence {
  return row.confidence ?? "high";
}

export interface SummaryOptions {
  /**
   * Bands left out of EVERY number here — the Radar folds low- and
   * medium-confidence rows away by default, and the hero, the badge, the
   * tray and the "Needs review" tab must print what the list shows. Rows in
   * a hidden band stay in the ledger and in the snapshot's `findings`; only
   * the counts stop seeing them. Empty or absent: every row counts.
   */
  hide_confidence?: readonly FindingConfidence[];
}

/**
 * The headline numbers over the rows a surface shows (CaptureEngine
 * `shownFindings`). Places are resolved over EVERY row passed in, triaged and
 * hidden-band rows included, exactly as lib/app-views.ts `radarRows` stamps
 * the cards: a project root learned from a reviewed row folds this week's
 * subdirectory into it on the Radar, so it must here too, or the hero and
 * `doorman status` count two exposures where the feed and `doorman findings`
 * show one card.
 */
export function summarizeFindings(rows: Iterable<FindingRow>, options: SummaryOptions = {}): RadarSummary {
  const every = [...rows];
  const hidden = new Set(options.hide_confidence ?? []);
  const summary: RadarSummary = {
    open: 0,
    by_severity: { critical: 0, high: 0, medium: 0, low: 0 },
    by_detector: {},
    open_groups: 0,
    by_severity_groups: { critical: 0, high: 0, medium: 0, low: 0 },
    open_exposures: 0,
    by_severity_exposures: { critical: 0, high: 0, medium: 0, low: 0 },
    affected_sessions: 0,
  };
  const sessions = new Set<string>();
  const openRows: FindingRow[] = [];
  for (const row of every) {
    if (row.status !== "open") continue;
    if (hidden.has(confidenceOf(row))) continue;
    openRows.push(row);
    summary.open += 1;
    summary.by_severity[row.severity] += 1;
    summary.by_detector[row.detector] = (summary.by_detector[row.detector] ?? 0) + 1;
    if (row.session_id) sessions.add(row.session_id);
    if (!summary.latest_detected_at || row.last_seen_at > summary.latest_detected_at) {
      summary.latest_detected_at = row.last_seen_at;
    }
  }
  summary.affected_sessions = sessions.size;
  const grouped = countSecurityGroups(openRows);
  summary.open_groups = grouped.groups;
  summary.by_severity_groups = grouped.by_severity;
  const exposures = countExposures(openRows, every);
  summary.open_exposures = exposures.count;
  summary.by_severity_exposures = exposures.by_severity;
  return summary;
}

/** Distinct exposures over `rows`, each at its WORST row's severity. Places
 * are resolved over `placesFrom`, the whole row set the rows were picked from,
 * so the keys are the ones the Radar's cards group on (`radarRows`). */
export function countExposures(
  rows: readonly FindingRow[],
  placesFrom: Iterable<Pick<FindingRow, "cwd">>,
): {
  count: number;
  by_severity: Record<SecuritySeverity, number>;
} {
  const resolver = createPlaceResolver(placesFrom);
  const worst = new Map<string, SecuritySeverity>();
  for (const row of rows) {
    const key = exposureKey(row.detector, resolver.placeOf(row));
    const seen = worst.get(key);
    if (!seen || SEVERITY_RANK[row.severity] > SEVERITY_RANK[seen]) worst.set(key, row.severity);
  }
  const by_severity: Record<SecuritySeverity, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const severity of worst.values()) by_severity[severity] += 1;
  return { count: worst.size, by_severity };
}

// ── Per-rule statistics (the Analytics screen, the graduation view) ──────────

/** The windows the Analytics screen offers. Computed in main for each, because
 * the snapshot's findings array is capped and the renderer cannot re-window. */
export const RULE_STATS_WINDOWS = [7, 14, 30, 90] as const;
export type RuleStatsWindow = (typeof RULE_STATS_WINDOWS)[number];

export interface RuleStat {
  detector: string;
  /** The label at the time, so a deleted custom rule still reads. */
  label: string;
  /** Rows seen in the window. */
  fired: number;
  /** Distinct EXPOSURES this rule flagged in the window — rule × place
   * (lib/exposures.ts). The number a person should read: sixty-seven fixture
   * secrets in one repo are one exposure. */
  exposures: number;
  /** Distinct THINGS this rule flagged in the window — rule × exposed name; the
   * same `.env` read across forty sessions is one thing. What there is to
   * rotate or pattern-match, under the exposure. */
  things: number;
  /** New exposures surfaced per day across the window, oldest day first —
   * an exposure counts on the day it was FIRST seen. */
  daily: number[];
  sessions: number;
  worst?: SecuritySeverity;
  /** What enforcement did, over the window's rows. */
  blocked: number;
  held: number;
  allowed: number;
  denied: number;
  timed_out: number;
  warned: number;
  /** Rows a model stood down after this rule fired (FindingAssist) — kept on
   * the Radar at medium confidence, never announced. Optional so a stat built
   * before the field existed (tests, older report fixtures) still types. */
  stood_down?: number;
  /** Rows in the window a person judged FALSE POSITIVE. Not in
   * `fired`, `things`, `exposures` or `sessions` — a rejected hit is not a
   * sighting — but said here so the rule's noise is a fact, not a hole.
   * Optional so an older stat fixture still types. */
  rejected?: number;
  /** agent_loop only: USD the window's stuck loops burned (sum of the rows'
   * `burned_usd`). Absent when no row in the window carried a price. Folded,
   * not shown — the screens print `burned_tokens`. */
  burned_usd?: number;
  /** agent_loop only: tokens the window's stuck loops burned (sum of the
   * rows' `burned_tokens`). Absent when no row in the window carried usage. */
  burned_tokens?: number;
  /** Median milliseconds from hold to decision, over the rows that carry it. */
  median_hold_ms?: number;
  last_fired_at?: string;
}

/** One day of the window, as exposures (not things, not rows) surfaced, by the
 * WORST outcome any of the exposure's rows had — blocked outranks held
 * outranks warned. */
export interface StatsDay {
  date: string;
  blocked: number;
  held: number;
  warned: number;
  observed: number;
  total: number;
}

export interface WindowStats {
  days: RuleStatsWindow;
  /** Rows in the window (sightings). */
  total: number;
  /** Distinct exposures — rule × place — the headline number. */
  exposures: number;
  /** Exposures whose first sighting is inside the window: what is NEW. */
  new_exposures: number;
  /** Distinct things — detector × exposed name — under the exposures. */
  things: number;
  /** Things whose first sighting is inside the window. */
  new_things: number;
  /** New exposures per day, by worst outcome. */
  daily: StatsDay[];
  /** Distinct sessions with a finding in the window (any status but
   * false_positive — see `rejected`). */
  sessions: number;
  /** The same, one window earlier — the comparison that turns a count into a
   * direction. Sessions in [cutoff - days, cutoff). */
  prev_sessions: number;
  /** The window immediately before this one, over the two measures the screen
   * leads with. Optional so a snapshot written before the field existed (older
   * report fixtures, tests) still types; the renderer then states the counts
   * without a direction rather than inventing one.
   *
   * `new_exposures` counts exposures whose FIRST sighting anywhere falls in
   * [cutoff - days, cutoff) — the same rule the current window uses, applied a
   * window earlier. `stopped` is the subset the guard blocked or held. Both
   * read an exposure's worst outcome across its whole life, exactly as the
   * current window's day buckets do, so the two halves of a delta are the same
   * measurement. */
  prev?: { new_exposures: number; stopped: number };
  /** Sessions that RAN in the window / in the one before it — the denominators
   * that make the above a rate. Filled at snapshot time from the session
   * store, which this function cannot see. */
  window_sessions?: number;
  prev_window_sessions?: number;
  rules: RuleStat[];
  /** Decision latency across every held row in the window. */
  decisions: number;
  /** Rows a model stood down across every rule in the window. */
  stood_down?: number;
  /** Rows in the window a person marked false positive. Counted in
   * nothing else here: not `total`, not a thing, not an exposure, not a
   * session, not a day bucket — the verdict says the rule was wrong, and a
   * screen that kept adding them up would keep repeating the mistake. */
  rejected?: number;
  /** USD burned by agent loops in the window — the sum of `burned_usd` over the
   * loop rows that carried one. Absent when none did. Folded, not shown. */
  burned_usd?: number;
  /** Tokens burned by agent loops in the window — the sum of `burned_tokens`
   * over the loop rows that carried one. Absent when none did, so the screen
   * says nothing rather than "0 tokens". */
  burned_tokens?: number;
  median_hold_ms?: number;
  /** How the held calls were answered, by surface. */
  decided_via: Record<DecidedVia, number>;
  scoped_allows: number;
}

function median(values: number[]): number | undefined {
  if (values.length === 0) return undefined;
  const sorted = [...values].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  return sorted.length % 2 === 1 ? sorted[mid]! : Math.round((sorted[mid - 1]! + sorted[mid]!) / 2);
}

/**
 * Per-rule counters over one window, most-fired first. Counts ROWS (one per
 * detector × session × key) so a rule that fires on one habit forty sessions
 * running reads as forty firings — the question here is "how noisy is this
 * rule", where the radar hero's question is "how many decisions".
 */
/** The identity of a THING: the rule and the exposed name, whatever session or
 * triage state it sits in. Mirrors the feed's grouping minus the axes the
 * analytics question doesn't have. */
export function thingKey(row: Pick<FindingRow, "detector" | "key_name" | "target" | "excerpt">): string {
  return `${row.detector}\u0000${row.key_name || row.target || row.excerpt || ""}`;
}

const OUTCOME_RANK = { blocked: 3, held: 2, warned: 1, observed: 0 } as const;
type Outcome = keyof typeof OUTCOME_RANK;

function rowOutcome(row: FindingRow): Outcome {
  if (row.enforced === "deny") return "blocked";
  if (row.enforced === "ask" || row.resolution) return "held";
  if (row.enforced === "warn") return "warned";
  return "observed";
}

/** Local calendar day of an ISO instant — the bucket the charts are drawn in. */
function dayOf(iso: string): string {
  const d = new Date(iso);
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;
}

export function summarizeRuleStats(
  rows: Iterable<FindingRow>,
  days: RuleStatsWindow,
  now: Date = new Date(),
  customLabels?: Record<string, string>,
): WindowStats {
  const cutoffMs = now.getTime() - days * 86_400_000;
  const cutoff = new Date(cutoffMs).toISOString();
  // One window earlier, for the direction of travel.
  const prevCutoff = new Date(cutoffMs - days * 86_400_000).toISOString();
  const prevSessions = new Set<string>();
  type Seen = { first: string; outcome: Outcome };
  type Acc = RuleStat & { _sessions: Set<string>; _holds: number[]; _things: Set<string>; _exposures: Map<string, Seen> };
  // Places are resolved over EVERY row, false positives included: a project
  // root learned from a rejected row still folds this week's subdirectory
  // into it. Everything COUNTED below reads `all`, which leaves them out —
  // a false positive is the person saying the rule was wrong, so it is not a
  // sighting, not a thing, not an exposure and not news. They are tallied
  // once, per rule and overall, as `rejected`.
  const every = [...rows];
  const places = createPlaceResolver(every);
  const all = every.filter((row) => row.status !== "false_positive");
  const rejectedByRule = new Map<string, number>();
  let rejected = 0;
  const byRule = new Map<string, Acc>();
  const sessions = new Set<string>();
  const holds: number[] = [];
  let stoodDown = 0;
  let burned: number | undefined;
  let burnedTokens: number | undefined;
  const via: Record<DecidedVia, number> = { panel: 0, window: 0, notification: 0, editor: 0, terminal: 0, timeout: 0, "app-absent": 0 };
  // Every exposure in the window, with the earliest sighting we know of (which
  // may predate the window — then it is not NEW) and its worst outcome; and
  // every thing, for the secondary count.
  const exposures = new Map<string, Seen>();
  const things = new Map<string, { first: string }>();
  let total = 0;
  let scoped = 0;
  const dayIndex = new Map<string, number>();
  const daily: StatsDay[] = [];
  for (let i = days - 1; i >= 0; i -= 1) {
    const date = dayOf(new Date(now.getTime() - i * 86_400_000).toISOString());
    dayIndex.set(date, daily.length);
    daily.push({ date, blocked: 0, held: 0, warned: 0, observed: 0, total: 0 });
  }
  const note = (map: Map<string, Seen>, key: string, row: FindingRow, outcome: Outcome) => {
    const seen = map.get(key);
    if (!seen) map.set(key, { first: row.first_seen_at, outcome });
    else {
      if (row.first_seen_at < seen.first) seen.first = row.first_seen_at;
      if (OUTCOME_RANK[outcome] > OUTCOME_RANK[seen.outcome]) seen.outcome = outcome;
    }
  };
  // The previous window, before the main loop narrows to this one. It has to be
  // its own pass over EVERY row: an exposure's first sighting is the earliest
  // across all its rows, and the loop below drops the rows that ended before
  // `cutoff` — which are precisely the previous window's.
  const everSeen = new Map<string, Seen>();
  for (const row of all) note(everSeen, exposureKey(row.detector, places.placeOf(row)), row, rowOutcome(row));
  const prevCutoffMs = cutoffMs - days * 86_400_000;
  const prev = { new_exposures: 0, stopped: 0 };
  for (const seen of everSeen.values()) {
    const at = Date.parse(seen.first);
    if (!Number.isFinite(at) || at < prevCutoffMs || at >= cutoffMs) continue;
    prev.new_exposures += 1;
    if (seen.outcome === "blocked" || seen.outcome === "held") prev.stopped += 1;
  }
  for (const row of every) {
    if (row.status !== "false_positive" || row.last_seen_at < cutoff) continue;
    rejected += 1;
    rejectedByRule.set(row.detector, (rejectedByRule.get(row.detector) ?? 0) + 1);
  }
  for (const row of all) {
    if (row.last_seen_at < cutoff) {
      if (row.last_seen_at >= prevCutoff && row.session_id) prevSessions.add(row.session_id);
      continue;
    }
    total += 1;
    if (row.session_id) sessions.add(row.session_id);
    const thing = thingKey(row);
    const exposure = exposureKey(row.detector, places.placeOf(row));
    const outcome = rowOutcome(row);
    note(exposures, exposure, row, outcome);
    const t = things.get(thing);
    if (!t) things.set(thing, { first: row.first_seen_at });
    else if (row.first_seen_at < t.first) t.first = row.first_seen_at;
    let stat = byRule.get(row.detector);
    if (!stat) {
      stat = {
        detector: row.detector,
        label: row.detector_label ?? localDetectorLabel(row.detector, customLabels),
        fired: 0,
        exposures: 0,
        things: 0,
        daily: daily.map(() => 0),
        sessions: 0,
        blocked: 0,
        held: 0,
        allowed: 0,
        denied: 0,
        timed_out: 0,
        warned: 0,
        stood_down: 0,
        _sessions: new Set(),
        _holds: [],
        _things: new Set(),
        _exposures: new Map(),
      };
      byRule.set(row.detector, stat);
    }
    stat.fired += 1;
    stat._things.add(thing);
    note(stat._exposures, exposure, row, outcome);
    if (row.session_id) stat._sessions.add(row.session_id);
    if (!stat.worst || SEVERITY_RANK[row.severity] > SEVERITY_RANK[stat.worst]) stat.worst = row.severity;
    if (!stat.last_fired_at || row.last_seen_at > stat.last_fired_at) stat.last_fired_at = row.last_seen_at;
    if (row.enforced === "deny") stat.blocked += 1;
    if (row.enforced === "warn") stat.warned += 1;
    if (row.assist?.verdict === "stood_down") {
      stat.stood_down = (stat.stood_down ?? 0) + 1;
      stoodDown += 1;
    }
    if (typeof row.burned_usd === "number" && Number.isFinite(row.burned_usd)) {
      stat.burned_usd = (stat.burned_usd ?? 0) + row.burned_usd;
      burned = (burned ?? 0) + row.burned_usd;
    }
    if (typeof row.burned_tokens === "number" && Number.isFinite(row.burned_tokens)) {
      stat.burned_tokens = (stat.burned_tokens ?? 0) + row.burned_tokens;
      burnedTokens = (burnedTokens ?? 0) + row.burned_tokens;
    }
    if (row.enforced === "ask" || row.resolution) stat.held += 1;
    if (row.resolution === "allowed") stat.allowed += 1;
    if (row.resolution === "denied") stat.denied += 1;
    if (row.resolution === "timeout") stat.timed_out += 1;
    if (typeof row.hold_ms === "number" && Number.isFinite(row.hold_ms)) {
      stat._holds.push(row.hold_ms);
      holds.push(row.hold_ms);
    }
    if (row.decided_via && row.decided_via in via) via[row.decided_via] += 1;
    if (row.allow_scope === "project") scoped += 1;
  }
  // An exposure counts on the day it was FIRST seen — a re-sighting of a known
  // exposure is not news. Exposures first seen before the window are in
  // `exposures` (still open business) but in no day bucket and not NEW.
  const isNew = (first: string): number | undefined => {
    const idx = dayIndex.get(dayOf(first));
    return idx === undefined || Date.parse(first) < cutoffMs ? undefined : idx;
  };
  let newExposures = 0;
  for (const seen of exposures.values()) {
    const idx = isNew(seen.first);
    if (idx === undefined) continue;
    newExposures += 1;
    const day = daily[idx]!;
    day[seen.outcome] += 1;
    day.total += 1;
  }
  let newThings = 0;
  for (const t of things.values()) if (isNew(t.first) !== undefined) newThings += 1;
  const rules = [...byRule.values()]
    .map(({ _sessions, _holds, _things, _exposures, ...stat }) => {
      const m = median(_holds);
      const perDay = daily.map(() => 0);
      for (const seen of _exposures.values()) {
        const idx = isNew(seen.first);
        if (idx !== undefined) perDay[idx] += 1;
      }
      // A rule whose only rows in the window were rejected has no entry here
      // — nothing real fired — so its rejections show only in the overall
      // count. The rule that did fire carries its own beside its sightings.
      return {
        ...stat,
        exposures: _exposures.size,
        things: _things.size,
        daily: perDay,
        sessions: _sessions.size,
        rejected: rejectedByRule.get(stat.detector) ?? 0,
        ...(m === undefined ? {} : { median_hold_ms: m }),
      };
    })
    .sort((a, b) => b.exposures - a.exposures || b.things - a.things || b.fired - a.fired || a.detector.localeCompare(b.detector));
  const overall = median(holds);
  return {
    days,
    total,
    exposures: exposures.size,
    new_exposures: newExposures,
    things: things.size,
    new_things: newThings,
    daily,
    sessions: sessions.size,
    prev_sessions: prevSessions.size,
    prev,
    rules,
    decisions: holds.length,
    stood_down: stoodDown,
    rejected,
    ...(burned === undefined ? {} : { burned_usd: burned }),
    ...(burnedTokens === undefined ? {} : { burned_tokens: burnedTokens }),
    ...(overall === undefined ? {} : { median_hold_ms: overall }),
    decided_via: via,
    scoped_allows: scoped,
  };
}

export { SEVERITY_RANK } from "../guard/policy.js";
