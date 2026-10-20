/**
 * The capture engine: day-zero backfill + live watch over the on-disk
 * transcript trees, the local turn store, the search index, and the Security
 * Radar's transcript-side scanning.
 *
 * Ground truth is what the agents already write to disk — Claude Code's
 * ~/.claude/projects/<slug>/*.jsonl and Codex's ~/.codex/sessions rollouts —
 * so capture needs NO hook, NO network and no cooperation from the tools.
 * Changed files are re-parsed WHOLE: turn ids are stable, so re-parsing
 * converges instead of duplicating, and detection merges idempotently.
 *
 * Everything the engine persists lives under <userData>/store/:
 *   turns.jsonl    — the turn store (append-only; rewritten on retention prune)
 *   titles.json    — session titles (auto_summary from transcripts, else auto_prompt)
 *   findings.jsonl — radar rows (append-only, last state per finding_id wins)
 *   cursors.json   — per-file size+mtime, so unchanged files are skipped, plus
 *                    the session ids each file parsed to (the on-disk test)
 *   shown.json     — what the newest scan decided can be shown: the rails it
 *                    listed, the sessions on disk, the evidence verdicts
 *   evidence-vault.jsonl — the raw window behind each detection, Keychain-
 *                    encrypted (lib/evidence-vault.ts; absent without a keychain)
 */

import {
  appendFileSync,
  chmodSync,
  existsSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  statSync,
  watch,
  writeFileSync,
  type FSWatcher,
} from "node:fs";
import { createHash } from "node:crypto";
import { homedir } from "node:os";
import { join } from "node:path";
import { parseClaudeTranscript, type DetectUnit } from "./lib/cc-transcript.js";
import { parseCodexRollout, rolloutSessionId, shadowAiIdForOriginator } from "./lib/codex-rollout.js";
import { TRANSCRIPT_SOURCES, sourceLabel } from "./lib/transcript-sources-registry.js";
import type {
  SourceIo,
  TranscriptParseResult,
  TranscriptSourceDescriptor,
} from "./lib/transcript-sources.js";
import { createSourceIo, pruneSqliteSnapshots } from "./lib/source-io.js";
import {
  armedInjectionTaints,
  commandOf,
  credentialFamiliesInOutput,
  evaluateFlowFindings,
  injectionMarkerIn,
  parsedInput,
  FLOW_MAX_GAP_MS,
  type ArmedInjectionTaint,
} from "./lib/flow-rules.js";
import { matchCustomRules, type CustomRule } from "./guard/custom-rules.js";
import { ruleShown } from "./guard/rule-scope.js";
import { accountForFlow, accountForUnit, accountable } from "./lib/account.js";
import { alignRedactedValues, extractRedactedSecrets } from "./lib/reveal.js";
import { validateDetection } from "./lib/detection-schema.js";
import { CUT_LABEL, maskText, maskTurnText } from "./lib/masking.js";
import { sandboxLocalId, sandboxRecords, type SandboxBundle, type SandboxImportResult } from "./lib/sandbox-import.js";
import type { EvidenceVault } from "./lib/evidence-vault.js";
import type { FlowOptions } from "./lib/flow-rules.js";
import { applicableIgnoreRules, defaultInjectionClassifierConfig, selectedInjectionModel, type GuardPolicy, type InjectionModelId } from "./guard/policy.js";
import { injectionAssist, injectionMarkerStands, markerIsClassifiable, type InjectionVerdict } from "./lib/injection-classifier.js";
import type { DecidedVia } from "./lib/findings.js";
import { MCP_POISON_PATTERNS, scanMcpConfigText, scanMcpToolOutput } from "./guard/mcp-poison.js";
import { classifyDestination, extractHosts, isNotableFirstSight } from "./lib/egress-intel.js";
import { createIndex, indexDocument, searchIndex, type SearchIndex } from "./lib/fts.js";
import {
  callNeverRan,
  evidenceReadable,
  foldFindingLines,
  mergeFinding,
  mintFindingRow,
  ruleModeOf,
  type FindingException,
  type FindingRow,
  type FindingSource,
  type FindingStatus,
  type SecretFingerprint,
} from "./lib/findings.js";
import {
  deriveAutoTitle,
  groupSessions,
  titleWriteApplies,
  type LedgerTurn,
  type PlanWindowReading,
  type SessionSummary,
  type SessionTitle,
  type TitleRecord,
  type TurnSource,
} from "./lib/turns.js";
import { RAW_EVIDENCE_MAX_CHARS, revealEvidenceForFinding, rawWindow, type RawEvidence, type ScoredEvidence } from "./lib/reveal.js";
import {
  buildTraceReport,
  countOccurrences,
  literalForms,
  traceShape,
  type RawSighting,
  type TraceReport,
} from "./lib/secret-trace.js";
import { redact } from "./guard/redact.js";
import { detectSecurityFindings } from "./guard/security-detect.js";
import type { ApprovalResolution } from "./guard/handshake.js";

const RESCAN_INTERVAL_MS = 60_000;
const WATCH_DEBOUNCE_MS = 1_500;
const PRUNE_INTERVAL_MS = 6 * 60 * 60_000;

export interface EngineDeps {
  /** <userData>/store */
  storeDir: string;
  /** The Keychain-encrypted evidence vault (lib/evidence-vault.ts). Absent —
   * tests, a box with no keychain — and detections keep only their masked
   * row; Reveal re-reads the transcript as it always has. */
  vault?: EvidenceVault;
  /** Stamped on every sighting as `app_version`: which build's detectors fired. */
  appVersion?: string;
  claudeProjectsDir: string;
  codexSessionsDir: string;
  /**
   * The REGISTERED transcript sources (lib/transcript-sources-registry.ts) —
   * every host beyond Claude Code and Codex whose sessions this engine reads.
   * Injectable so a test can drive the whole pipeline with one fake descriptor
   * instead of a real editor's database; defaults to the registry.
   */
  sources?: readonly TranscriptSourceDescriptor[];
  /** The reads those descriptors perform. Defaults to the real fs+sqlite io
   * (lib/source-io.ts) rooted at `<storeDir>/sqlite-snapshots`. */
  sourceIo?: SourceIo;
  /** The home the descriptors resolve their roots and presence paths against,
   * and the environment they read overrides from (CODEX_HOME-style). */
  home?: string;
  env?: NodeJS.ProcessEnv;
  policy(): GuardPolicy;
  retentionDays(): number;
  /** Engine state changed — recompute + broadcast (caller debounces). */
  onUpdate(): void;
  /** New OPEN findings observed after the initial backfill (live only). */
  onNewFindings(rows: FindingRow[]): void;
  /** New warn-mode guard findings — the coaching banner (never threshold-gated,
   * a warn is an explicit per-rule choice). Optional: tests and headless runs
   * don't notify. */
  onWarned?(rows: FindingRow[]): void;
  /** The armed-sessions map changed (guard/armed.ts) — the caller publishes it
   * into the guard directory. Optional for the same reason. */
  onArmedChange?(sessions: Record<string, { taints: ArmedInjectionTaint[]; updated_at: string }>): void;
  /** Read back what the guard currently considers armed, so a relaunch does
   * not start empty and disarm a session that is still poisoned the moment
   * another one publishes. */
  readArmed?(): Record<string, { taints: ArmedInjectionTaint[]; updated_at: string }>;
  /** The injection classifier (lib/injection-classifier.ts), when the app has
   * one loaded. Resolves `null` for "no verdict" — absent runtime, absent
   * model, empty text, a failure — and every consumer then leaves the
   * detectors' finding exactly as it was. Optional: tests and headless runs
   * have none, which is the same as `null` every time. */
  classifyInjection?(text: string): Promise<InjectionVerdict | null>;
  /** The model `classifyInjection` actually runs right now (the EFFECTIVE
   * one: stock while the selected fine-tuned model is not installed) — what
   * the verdict cache is keyed by. Absent: the policy's selection. */
  injectionModelInUse?(): InjectionModelId;
  log(message: string): void;
  /** Asked between files while scanning: true ends the scan there, keeping the
   * cursors of what was read — a CLI command an app that is starting up waits
   * for (lib/data-owner.ts). */
  shouldStop?(): boolean;
}

interface FileCursor {
  size: number;
  mtimeMs: number;
}

interface SpoolRecord {
  at?: string;
  /** The host's own `source` string (guard/hosts/<host>.ts). Two values today,
   * one per registered host — a string, not a union, because the registry is
   * what decides which hosts exist. */
  source?: string;
  session_id?: string;
  tool_name?: string;
  cwd?: string;
  decision?: string;
  /** The guard is holding this call: the approval banner is the notification,
   * so this finding must not raise a second one (see notifications.ts). */
  held?: boolean;
  /** Present on the second line the guard writes for a HELD call: how the
   * confirmation ended. */
  resolution?: string;
  /** Decision telemetry, on the same second line (guard/hold.ts HoldTelemetry). */
  held_at?: string;
  decided_at?: string;
  decided_via?: string;
  hold_ms?: number;
  allow_scope?: string;
  /** Warn-mode detectors that fired at interrupt-grade confidence. */
  warned?: string[];
  /** Labels for custom-rule ids among the findings. */
  detector_labels?: Record<string, string>;
  /** The credential second opinion, when the guard ran it (guard.ts
   * SecondOpinionTelemetry): which detectors' findings a local model judged,
   * and what it said — names, never values. */
  second_opinion?: {
    model?: string;
    judged?: Array<{ detector?: string; key_name?: string; verdict?: string }>;
  };
  /** Findings a scoped exception dropped before the decision (guard.ts) —
   * each with the ignore rule that applied. Never enforced, always recorded. */
  excepted?: unknown[];
  findings?: unknown[];
}

const RESOLUTIONS = ["allowed", "denied", "timeout", "unattended", "unavailable"] as const;
const DECIDED_VIA = ["panel", "window", "notification", "editor", "terminal", "timeout", "app-absent"] as const;

/** The exception a spooled `excepted` finding carries — the guard's
 * ScopedIgnoreRule, taken field by field so a malformed line yields no
 * exception rather than a garbage one. */
function parseFindingException(value: unknown): FindingException | undefined {
  if (!value || typeof value !== "object") return undefined;
  const r = value as Record<string, unknown>;
  if (typeof r.pattern !== "string" || r.pattern === "") return undefined;
  const out: FindingException = { pattern: r.pattern };
  if (typeof r.detector === "string" && r.detector !== "") out.detector = r.detector;
  if (typeof r.cwd_prefix === "string" && r.cwd_prefix !== "") out.cwd_prefix = r.cwd_prefix;
  if (isoOrUndefined(r.expires_at) !== undefined) out.expires_at = r.expires_at as string;
  if (typeof r.note === "string" && r.note !== "") out.note = r.note;
  if (r.origin === "approval" || r.origin === "manual") out.origin = r.origin;
  return out;
}

function parseResolution(value: unknown): ApprovalResolution | undefined {
  return (RESOLUTIONS as readonly string[]).includes(value as string)
    ? (value as ApprovalResolution)
    : undefined;
}

function parseDecidedVia(value: unknown): DecidedVia | undefined {
  return (DECIDED_VIA as readonly string[]).includes(value as string) ? (value as DecidedVia) : undefined;
}

function isoOrUndefined(value: unknown): string | undefined {
  return typeof value === "string" && Number.isFinite(Date.parse(value)) ? value : undefined;
}

/** A dry run of one custom rule over the stored transcripts — what the Rules
 * screen shows before a rule is saved, so a pattern's noise level is known
 * before it can hold anything (the dogfooding rule, built in). */
export interface CustomRuleDryRun {
  days: number;
  files: number;
  matches: number;
  sessions: number;
  /** Masked, capped — the first few hits, so the person can see WHAT matched. */
  samples: { at: string; tool_name?: string; excerpt: string; session_id: string }[];
}

/** Store files that carry raw text or finding context — kept owner-only. */
const PRIVATE_STORE_FILES = ["findings.jsonl", "turns.jsonl", "cursors.json", "shown.json"] as const;
/** How many scanned tool_output line ids a run remembers (see scanParsed). */
const SCANNED_OUTPUT_LINES_MAX = 50_000;

/**
 *: how long a fresh sighting is shown on trust before its evidence is
 * judged. The guard's row lands before the host writes the transcript line,
 * and a scan can fall in between; ten minutes is far past any host's write
 * lag and far short of the retention window.
 */
const EVIDENCE_GRACE_MS = 10 * 60_000;
/** Sightings judged per scan — enough that a ledger settles within a few
 * ticks, few enough that one tick never re-reads every transcript. */
const EVIDENCE_JUDGED_PER_SCAN = 24;
/** The vault's key for a sighting: the finding and the excerpt the card shows. */
const sightingKey = (row: Pick<FindingRow, "finding_id" | "excerpt">) => `${row.finding_id}\u0000${row.excerpt}`;
/** A short stable digest: how shown.json names a sighting and a set of
 * documents, so the file holds no excerpt and no path. */
const digest = (text: string) => createHash("sha256").update(text).digest("base64url").slice(0, 22);
/** An evidence verdict (judgeEvidence): whether the sighting could be shown,
 * the digest of the documents it was judged against, and its own digest. */
interface EvidenceVerdict {
  ok: boolean;
  cursor: string;
  hash: string;
}
/** What a Reveal returns: the raw window, or why there is none. */
type RevealResult = ({ ok: true } & RawEvidence) | { ok: false; error: string };

export class CaptureEngine {
  readonly turns = new Map<string, LedgerTurn>();
  readonly titles = new Map<string, SessionTitle>();
  /**
   * session id → the shadow-AI catalog id whose APP produced it, when that is
   * something other than the rail's own CLI. Only Codex populates this today:
   * ChatGPT Desktop's Codex mode writes rollouts into ~/.codex/sessions stamped
   * `originator: "Codex Desktop"`, so those sessions are metered here but
   * belong to a different row on the coverage map. Persisted beside titles.json
   * because it is derived at parse time and files are only re-parsed on change.
   */
  readonly sessionApps = new Map<string, string>();
  /**
   * Every finding row the app has ever recorded, hidden rules included — the
   * store of record behind findings.jsonl. Read it directly ONLY for
   * persistence and the merge logic; anything a person or a connected agent
   * can see goes through `shownFindings()` / `shownFinding()` below, which
   * apply the rule scope (guard/rule-scope.ts). Named `ledger` rather
   * than `findings` so that a reader has to choose which of the two it wants.
   */
  readonly ledger = new Map<string, FindingRow>();
  /** Sightings whose evidence could not be reproduced this run (keepEvidence). */
  private readonly unreproducible = new Set<string>();
  /** Rules whose rows already logged a schema problem this run. */
  private readonly schemaWarned = new Set<string>();
  /**
   * rail → its newest plan-headroom reading (lib/turns.ts PlanWindowReading).
   * Deliberately NOT persisted: it is a point observation of a live quota, and
   * a stale one restored at boot would be shown as current until the next
   * model call. A rail with no reading yet simply has no meter.
   */
  private readonly planWindows = new Map<string, PlanWindowReading>();
  private index: SearchIndex = createIndex();
  private cursors = new Map<string, FileCursor>();
  private watchers: FSWatcher[] = [];
  private timers: NodeJS.Timeout[] = [];
  private watchDebounce: NodeJS.Timeout | undefined;
  private scanning = false;
  private scanQueued = false;
  private initialScanDone = false;
  /** Source lines whose tool_output units were already scanned this run.
   * Outputs anchor to transcript LINE ids, which never become turns, so the
   * freshIds filter below can't dedupe them — and a live file re-parses on
   * every touch, which without this would re-scan every output each time. */
  private scannedOutputLines = new Set<string>();
  /** Line id → credential families in that output; see memoizedOutputFamilies. */
  private outputFamiliesCache = new Map<string, readonly string[]>();
  /** Line id → injection marker in that output (`""` = none), same rationale. */
  private injectionMarkerCache = new Map<string, string>();
  /** Line id → the classifier's verdict on that output. Only lines whose regex
   * marker the model may overrule are ever asked; a `null` (no answer) is not
   * cached so a transient failure is re-asked next scan. */
  private injectionVerdictCache = new Map<string, InjectionVerdict>();
  /** The model whose verdicts the cache holds (the effective one — see
   * EngineDeps.injectionModelInUse); a change re-asks every line. */
  private injectionVerdictModel: string | undefined;
  /** Line ids whose `injected_instruction` marker the classifier stood down —
   * what the sync scans read (reconcileInjectionMarkers refreshes it). */
  private injectionSuppressed = new Set<string>();
  /** Sessions currently carrying a live injection taint — mirrored into the
   * guard's armed.json via deps.onArmedChange (the next-call escalation). */
  private armed = new Map<string, { taints: ArmedInjectionTaint[]; updated_at: string }>();
  /** External destinations this machine has ever sent to — the durable set that
   * makes "first time we've reached here" answerable (egress-intel #6).
   * Persisted to egress-seen.json; grows slowly, never pruned by retention
   * (a destination's history is the point). */
  private egressSeen = new Set<string>();
  /** The io the registered descriptors read through, built on first use so a
   * test that injects one never creates the snapshot directory. */
  private io: SourceIo | undefined;
  /**
   * Which sessions still have a transcript on disk — per rail, the
   * session ids the newest scan LISTED: by filename, plus whatever each
   * document parsed to this launch (`fileSessions`), so a Codex rollout whose
   * metadata names a different id than its filename still counts. A rail
   * whose root is absent or unreadable is not in the map, and nothing of its
   * is judged. Read-side only: `shownFindings` / `sessions` / `search` hide
   * what is not here, the store keeps it, and a file put back shows again on
   * the next scan. Rebuilt by every scan, AFTER the scan's parses, from
   * `fileSessions` — which is persisted with each file's cursor, because an
   * unchanged file is not re-parsed after a restart and a session whose id is
   * not its filename would otherwise be hidden while its transcript exists.
   * Saved in shown.json with `railsListed`, so an engine that has not scanned
   * yet (the CLI, a relaunch) starts from the newest scan's listing.
   */
  private sessionsOnDisk = new Map<string, Set<string>>();
  private fileSessions = new Map<string, Set<string>>();
  /**
   * Whether a sighting could be reproduced from its transcript the last time
   * the engine looked — keyed by sighting (finding id + excerpt)
   * like the vault, with the cursor of the files it was judged against, so a
   * file that changes is judged again. Until a row is judged it is shown: a
   * row is hidden on a verdict, never on a guess. Saved in shown.json after
   * every scan; only an engine with no vault (the CLI) reads them back, since
   * it cannot judge a sighting the app could show from its vault. An engine
   * with a vault rebuilds them over its first scans.
   */
  private readonly evidenceVerdicts = new Map<string, EvidenceVerdict>();
  /** shown.json as last read or written, so an unchanged view is not rewritten. */
  private shownSaved: string | undefined;
  /**
   * The rails the newest scan listed in full — every root present and read
   * without a throw. Wider than `sessionsOnDisk`: a host that keeps many
   * sessions in one database is listed but names none of them, so its rows
   * are never judged off disk, yet its documents can still be re-read to
   * judge a sighting. A rail not here is not judged at all: an unmounted
   * volume must hide nothing.
   */
  private readonly railsListed = new Set<string>();
  /**
   * Sessions pulled from a Docker Sandbox (LedgerTurn.sandbox,
   * lib/sandbox-import.ts). Their transcripts are in the sandbox, never on
   * this disk, so the on-disk rule (`sessionOnDisk`) does not judge them.
   */
  private readonly sandboxSessions = new Set<string>();

  status: "starting" | "scanning" | "watching" = "starting";
  filesSeen = 0;
  lastScanAt: string | undefined;

  constructor(private readonly deps: EngineDeps) {}

  // ---- persistence ----------------------------------------------------------

  private path(name: string): string {
    return join(this.deps.storeDir, name);
  }

  private load(): void {
    let ledgerUpgraded = false;
    mkdirSync(this.deps.storeDir, { recursive: true });
    // The ledger files hold raw turn text and every finding's context — the
    // same owner-only mode as the vault, including files an older build
    // created world-readable (a mode on write only applies to a new file).
    for (const name of PRIVATE_STORE_FILES) {
      try {
        if (existsSync(this.path(name))) chmodSync(this.path(name), 0o600);
      } catch {
        // best effort: ~/Library is 0700 anyway
      }
    }
    // The armed map lives in the guard's own file, not in this store, and it is
    // published WHOLE on every change. Starting empty meant the first publish
    // after a relaunch erased every session whose transcript had not changed
    // since — which, for an agent waiting at its next tool call, is all of
    // them. The engine's own prune drops whatever has since aged out.
    try {
      for (const [sessionId, entry] of Object.entries(this.deps.readArmed?.() ?? {})) {
        this.armed.set(sessionId, entry);
      }
    } catch {
      // an unreadable armed.json arms nothing, which is the existing direction
    }
    try {
      const lines = readFileSync(this.path("turns.jsonl"), "utf8").split("\n");
      for (const line of lines) {
        if (line.trim() === "") continue;
        try {
          const turn = JSON.parse(line) as LedgerTurn;
          if (turn && typeof turn.id === "string" && typeof turn.at === "string") {
            this.turns.set(turn.id, turn);
            if (turn.sandbox !== undefined) this.sandboxSessions.add(turn.session_id);
          }
        } catch {
          // one bad line must not lose the store
        }
      }
    } catch {
      // no store yet
    }
    try {
      const raw = JSON.parse(readFileSync(this.path("titles.json"), "utf8")) as Record<
        string,
        SessionTitle
      >;
      for (const [id, title] of Object.entries(raw)) {
        if (title && typeof title.text === "string") this.titles.set(id, title);
      }
    } catch {
      // none yet
    }
    try {
      const lines = readFileSync(this.path("findings.jsonl"), "utf8").split("\n");
      const stats = { upgraded: 0 };
      for (const [id, row] of foldFindingLines(lines, stats)) this.ledger.set(id, row);
      // A row the upgrade CHANGED on read — masked a value an older build
      // stored in its target or account — is rewritten below, so the file on
      // disk stops holding it, not just the copy in memory.
      ledgerUpgraded = stats.upgraded > 0;
    } catch {
      // none yet
    }
    let surfacesLoaded = false;
    try {
      const raw = JSON.parse(readFileSync(this.path("surfaces.json"), "utf8")) as Record<
        string,
        string
      >;
      for (const [id, app] of Object.entries(raw)) {
        if (typeof app === "string" && app !== "") this.sessionApps.set(id, app);
      }
      surfacesLoaded = true;
    } catch {
      // none yet
    }
    try {
      const raw = JSON.parse(readFileSync(this.path("cursors.json"), "utf8")) as Record<
        string,
        FileCursor & { sessions?: unknown[] }
      >;
      for (const [path, cursor] of Object.entries(raw)) {
        if (!cursor || typeof cursor.size !== "number") continue;
        // A cursor written before the sessions rode along is dropped, so its
        // file is re-parsed once and learns them — skipping it would leave a
        // session whose id is not its filename hidden while it is on disk.
        if (!Array.isArray(cursor.sessions)) continue;
        this.cursors.set(path, { size: cursor.size, mtimeMs: cursor.mtimeMs });
        this.fileSessions.set(path, new Set(cursor.sessions.filter((id): id is string => typeof id === "string")));
      }
    } catch {
      // none yet
    }
    // ONE-TIME BACKFILL. Surfaces are read at parse time and a file is only
    // re-parsed when it changes, so a store written before this existed would
    // never learn which of its sessions came from ChatGPT Desktop. Dropping the
    // cursors once re-reads every transcript — the same work as a first launch,
    // yielding between files — and the empty surfaces.json written below stops
    // it happening again on the next boot.
    if (!surfacesLoaded && this.cursors.size > 0) {
      this.cursors.clear();
      this.persistSurfaces();
    }
    try {
      const raw = JSON.parse(readFileSync(this.path("egress-seen.json"), "utf8")) as unknown;
      if (Array.isArray(raw)) for (const h of raw) if (typeof h === "string") this.egressSeen.add(h);
    } catch {
      // none yet
    }
    this.loadShown();
    const turnsPruned = this.pruneRetention();
    this.rebuildIndex();
    if (ledgerUpgraded || turnsPruned) this.rewriteStores();
    else this.pruneVault();
  }

  /** Compact the evidence vault against the ledger and the retention window
   * (lib/evidence-vault.ts prune) — on its own schedule, not only when turns
   * happened to be pruned, so a kept value never outlives its window. */
  private pruneVault(): void {
    const cutoffMs = this.retentionCutoffMs();
    this.deps.vault?.prune(new Set(this.ledger.keys()), cutoffMs === undefined ? undefined : new Date(cutoffMs).toISOString());
  }

  private persistCursors(): void {
    try {
      writeFileSync(
        this.path("cursors.json"),
        `${JSON.stringify(
          Object.fromEntries(
            [...this.cursors].map(([path, cursor]) => [path, { ...cursor, sessions: [...(this.fileSessions.get(path) ?? [])] }]),
          ),
          null,
          2,
        )}\n`,
        { mode: 0o600 },
      );
    } catch (err) {
      this.deps.log(`couldn't write cursors: ${String(err)}`);
    }
  }

  private persistSurfaces(): void {
    try {
      writeFileSync(
        this.path("surfaces.json"),
        `${JSON.stringify(Object.fromEntries(this.sessionApps), null, 2)}\n`,
      );
    } catch (err) {
      this.deps.log(`couldn't write surfaces: ${String(err)}`);
    }
  }

  /** Catalog ids the ledger holds sessions for beyond the registered sources —
   * what tells the coverage map that ChatGPT Desktop is captured after all. */
  capturedAppIds(): string[] {
    return [...new Set(this.sessionApps.values())].sort();
  }

  private persistEgressSeen(): void {
    try {
      writeFileSync(this.path("egress-seen.json"), `${JSON.stringify([...this.egressSeen])}\n`);
    } catch (err) {
      this.deps.log(`couldn't write egress-seen: ${String(err)}`);
    }
  }

  /**
   * Egress-destination pass over fresh tool_call units: extract external hosts,
   * classify them, and mint a radar-only `egress_new_destination` finding the
   * FIRST time this machine sends to a host in an exfil-shaped class (paste,
   * webhook, file-share, cloud storage, unknown). Expected dev traffic (AI
   * endpoints, code hosts, package registries) is tracked as seen but never
   * flagged — see egress-intel isNotableFirstSight. Low severity: informational,
   * never notifies at the default threshold.
   */
  private scanEgress(units: readonly DetectUnit[], source: TurnSource): void {
    const rows: FindingRow[] = [];
    let changed = false;
    for (const unit of units) {
      if (unit.kind !== "tool_call") continue;
      for (const host of extractHosts(unit.raw)) {
        if (this.egressSeen.has(host)) continue;
        this.egressSeen.add(host);
        changed = true;
        const profile = classifyDestination(host);
        if (!isNotableFirstSight(profile.class)) continue;
        rows.push(
          mintFindingRow(
            {
              detector: "egress_new_destination",
              severity: "low",
              key_name: host,
              excerpt: `First send to ${host} — ${profile.label}. ${profile.note}`,
              occurrences: 1,
              ...(unit.tool_name === undefined ? {} : { tool_name: unit.tool_name }),
              target: host,
            },
            { source, origin: "transcript", session_id: unit.session_id, turn_id: unit.turn_id, at: unit.at },
          ),
        );
      }
    }
    if (changed) this.persistEgressSeen();
    if (rows.length > 0) this.ingestFindingRows(rows);
  }

  private persistTitles(): void {
    try {
      writeFileSync(
        this.path("titles.json"),
        `${JSON.stringify(Object.fromEntries(this.titles), null, 2)}\n`,
      );
    } catch (err) {
      this.deps.log(`couldn't write titles: ${String(err)}`);
    }
  }

  private appendTurns(turns: readonly LedgerTurn[]): void {
    if (turns.length === 0) return;
    try {
      appendFileSync(
        this.path("turns.jsonl"),
        turns.map((t) => JSON.stringify(t)).join("\n") + "\n",
        { mode: 0o600 },
      );
    } catch (err) {
      this.deps.log(`couldn't append turns: ${String(err)}`);
    }
  }

  private appendFindings(rows: readonly FindingRow[]): void {
    if (rows.length === 0) return;
    // The detection schema is the ledger's contract (lib/detection-schema.ts).
    // A row that breaks it is still written — dropping a detection is worse
    // than recording an odd one — but it is said out loud, once per rule, so a
    // new field that never reached the schema is caught in a dev run.
    for (const row of rows) {
      const problems = validateDetection(row);
      if (problems.length === 0 || this.schemaWarned.has(row.detector)) continue;
      this.schemaWarned.add(row.detector);
      this.deps.log(`finding ${row.finding_id} (${row.detector}) breaks the detection schema: ${problems.slice(0, 3).map((p) => `${p.path} ${p.message}`).join("; ")}`);
    }
    try {
      appendFileSync(
        this.path("findings.jsonl"),
        rows.map((r) => JSON.stringify(r)).join("\n") + "\n",
        { mode: 0o600 },
      );
    } catch (err) {
      this.deps.log(`couldn't append findings: ${String(err)}`);
    }
  }

  /** Rewrite the turn store after a prune — and compact the findings ledger
   * while we're here (it accumulates one line per status change). */
  private rewriteStores(): void {
    try {
      writeFileSync(
        this.path("turns.jsonl"),
        [...this.turns.values()].map((t) => JSON.stringify(t)).join("\n") +
          (this.turns.size > 0 ? "\n" : ""),
        { mode: 0o600 },
      );
      writeFileSync(
        this.path("findings.jsonl"),
        [...this.ledger.values()].map((r) => JSON.stringify(r)).join("\n") +
          (this.ledger.size > 0 ? "\n" : ""),
        { mode: 0o600 },
      );
    } catch (err) {
      this.deps.log(`couldn't rewrite stores: ${String(err)}`);
    }
    // A detection that left the ledger takes its kept values with it.
    this.pruneVault();
  }

  // ---- lifecycle --------------------------------------------------------------

  async start(): Promise<void> {
    this.load();
    this.status = "scanning";
    this.deps.onUpdate();
    await this.scan();
    this.initialScanDone = true;
    this.status = "watching";
    this.deps.onUpdate();

    // Snapshots of a host's live SQLite database outlive nothing: drop the
    // ones whose source is gone before the watchers start.
    if (this.deps.sourceIo === undefined) {
      const live = this.presentSources().flatMap((source) => this.sourceDocuments(source));
      pruneSqliteSnapshots(join(this.deps.storeDir, "sqlite-snapshots"), live);
    }

    const watchRoots = [
      this.deps.claudeProjectsDir,
      this.deps.codexSessionsDir,
      ...this.presentSources().flatMap((source) => this.rootsOf(source)),
    ];
    for (const dir of watchRoots) {
      if (!existsSync(dir)) continue;
      try {
        const watcher = watch(dir, { recursive: true }, () => this.scheduleScan());
        watcher.on("error", (err) => this.deps.log(`watch error on ${dir}: ${String(err)}`));
        this.watchers.push(watcher);
      } catch (err) {
        this.deps.log(`couldn't watch ${dir}: ${String(err)}`);
      }
    }
    // The interval rescan backstops the watcher (roots created after launch,
    // editors that clone-and-rename) — it stats files and skips unchanged ones,
    // so an idle pass costs almost nothing.
    const rescan = setInterval(() => this.scheduleScan(), RESCAN_INTERVAL_MS);
    rescan.unref?.();
    this.timers.push(rescan);
    const prune = setInterval(() => {
      if (this.pruneRetention()) {
        this.rebuildIndex();
        this.rewriteStores();
        this.deps.onUpdate();
      } else {
        this.pruneVault();
      }
    }, PRUNE_INTERVAL_MS);
    prune.unref?.();
    this.timers.push(prune);
  }

  /** Load the store from disk without scanning or watching: the CLI's read
   * path. `scan()` then brings it up to date with the transcripts once. */
  open(): void {
    this.load();
  }

  stop(): void {
    for (const watcher of this.watchers) watcher.close();
    this.watchers = [];
    for (const timer of this.timers) clearInterval(timer);
    this.timers = [];
    if (this.watchDebounce) clearTimeout(this.watchDebounce);
  }

  private scheduleScan(): void {
    if (this.watchDebounce) clearTimeout(this.watchDebounce);
    this.watchDebounce = setTimeout(() => void this.scan(), WATCH_DEBOUNCE_MS);
  }

  // ---- scanning ---------------------------------------------------------------

  claudePresent(): boolean {
    return existsSync(this.deps.claudeProjectsDir);
  }

  codexPresent(): boolean {
    return existsSync(this.deps.codexSessionsDir);
  }

  // ---- registered sources -------------------------------------------------

  private get registry(): readonly TranscriptSourceDescriptor[] {
    return this.deps.sources ?? TRANSCRIPT_SOURCES;
  }

  private get home(): string {
    return this.deps.home ?? homedir();
  }

  private get env(): NodeJS.ProcessEnv {
    return this.deps.env ?? process.env;
  }

  private sourceIo(): SourceIo {
    this.io ??=
      this.deps.sourceIo ??
      createSourceIo({
        snapshotDir: join(this.deps.storeDir, "sqlite-snapshots"),
        log: (message) => this.deps.log(message),
      });
    return this.io;
  }

  /** Is this host on this machine? `presencePaths` are home-relative by
   * contract, but an app bundle lives at an absolute path, so both are read. */
  sourcePresent(source: TranscriptSourceDescriptor): boolean {
    return source.presencePaths.some((path) =>
      existsSync(path.startsWith("/") ? path : join(this.home, path)),
    ) || this.rootsOf(source).some((path) => existsSync(path));
  }

  /** The registered descriptors whose host is installed here — the only ones
   * the engine reads, watches or reports. */
  presentSources(): TranscriptSourceDescriptor[] {
    return this.registry.filter((source) => this.sourcePresent(source));
  }

  /**
   * Every rail the ledger can name — the two native ones plus every REGISTERED
   * source, whether or not its host is on this machine. The snapshot builds
   * `CaptureStatus.sources` from this, so the renderer's labels and rail chips
   * come from the registry instead of a second hard-coded pair.
   */
  sourceIndex(): Array<{ id: TurnSource; label: string; present: boolean; metered: boolean }> {
    return [
      {
        id: "claude-code" as TurnSource,
        label: sourceLabel("claude-code", this.registry),
        present: this.claudePresent(),
        metered: true,
      },
      {
        id: "codex" as TurnSource,
        label: sourceLabel("codex", this.registry),
        present: this.codexPresent(),
        metered: true,
      },
      ...this.registry.map((source) => ({
        id: source.id,
        label: source.label,
        present: this.sourcePresent(source),
        metered: source.metered,
      })),
    ];
  }

  /** Every session document of one present descriptor, across all its roots.
   * `discover` is the descriptor's, so a throwing parser package can only
   * cost its own host — never the scan. */
  private sourceDocuments(source: TranscriptSourceDescriptor): string[] {
    return this.listSourceDocuments(source).paths;
  }

  /** sourceDocuments, plus whether the listing is COMPLETE: every root that
   * exists was listed without a throw, and at least one exists. Only a
   * complete listing may say a session is off disk (sessionsOnDisk). */
  private listSourceDocuments(source: TranscriptSourceDescriptor): { paths: string[]; complete: boolean } {
    const paths: string[] = [];
    const io = this.sourceIo();
    let complete = false;
    for (const root of this.rootsOf(source)) {
      if (!existsSync(root)) continue;
      complete = true;
      try {
        for (const path of source.discover(root, io)) paths.push(path);
      } catch (err) {
        this.deps.log(`couldn't list ${source.id} documents under ${root}: ${String(err)}`);
        complete = false;
      }
    }
    return { paths, complete };
  }

  private rootsOf(source: TranscriptSourceDescriptor): string[] {
    try {
      return source.roots(this.home, this.env);
    } catch (err) {
      this.deps.log(`couldn't resolve ${source.id} roots: ${String(err)}`);
      return [];
    }
  }

  /**
   * The change cursor for a session document. A SQLite database's newest rows
   * live in its `-wal` companion, so the main file's size and mtime alone are
   * a cursor that never moves while an editor is running — the companions
   * count too.
   */
  private documentCursor(path: string): FileCursor | undefined {
    let stat;
    try {
      stat = statSync(path);
    } catch {
      return undefined;
    }
    if (!stat.isFile()) return undefined;
    let size = stat.size;
    let mtimeMs = stat.mtimeMs;
    for (const suffix of ["-wal", "-shm"]) {
      try {
        const side = statSync(`${path}${suffix}`);
        size += side.size;
        mtimeMs = Math.max(mtimeMs, side.mtimeMs);
      } catch {
        // no companion — a quiescent database, or a plain JSON document
      }
    }
    return { size, mtimeMs };
  }

  /** Backfill + incremental scan of one registered source. Mirrors scanRoot:
   * a per-document size+mtime cursor, a yield between documents, and a parse
   * failure that costs one document rather than the pass. */
  private async scanSource(
    source: TranscriptSourceDescriptor,
    cutoffMs: number | undefined,
  ): Promise<boolean> {
    let changed = false;
    const listing = this.listSourceDocuments(source);
    if (listing.complete) this.railsListed.add(source.id);
    else this.railsListed.delete(source.id);
    // A host that names the session in the document's path can be judged for
    // sessions off disk; one that doesn't (a database holding many chats)
    // cannot, and its rows are always shown.
    const onDisk = new Set<string>();
    let named = listing.complete;
    for (const path of listing.paths) {
      let id: string | undefined;
      try {
        id = source.sessionIdOf(path);
      } catch {
        id = undefined;
      }
      if (id === undefined) named = false;
      else onDisk.add(id);
    }
    for (const path of listing.paths) {
      if (this.stopRequested()) break;
      const stat = this.documentCursor(path);
      if (!stat) continue;
      this.filesSeen += 1;
      if (cutoffMs !== undefined && stat.mtimeMs < cutoffMs) continue;
      const cursor = this.cursors.get(path);
      if (cursor && cursor.size === stat.size && cursor.mtimeMs === stat.mtimeMs) continue;
      try {
        changed = (await this.processSourceDocument(path, source)) || changed;
      } catch (err) {
        this.deps.log(`couldn't parse ${path}: ${String(err)}`);
      }
      this.cursors.set(path, stat);
      await new Promise<void>((resolve) => setImmediate(resolve));
    }
    // What each document parsed to counts too — read AFTER the parses above,
    // so a session named only inside its document shows on the first scan.
    for (const path of listing.paths) for (const parsed of this.fileSessions.get(path) ?? []) onDisk.add(parsed);
    if (named) this.sessionsOnDisk.set(source.id, onDisk);
    else this.sessionsOnDisk.delete(source.id);
    return changed;
  }

  /** One document of a registered source, through the SAME pipeline the two
   * native rails run: stable-id turn upsert, titles, then redact → detectors →
   * flow rules → arming over its detect units, stamped with the descriptor's
   * own source id. */
  private async processSourceDocument(
    path: string,
    source: TranscriptSourceDescriptor,
  ): Promise<boolean> {
    let parsed: TranscriptParseResult;
    try {
      parsed = source.parse(path, this.sourceIo());
    } catch (err) {
      // A parser is third-party code from the engine's point of view: one bad
      // document must not take the watcher down or stop the other hosts.
      this.deps.log(`${source.id} parser threw on ${path}: ${String(err)}`);
      return false;
    }
    this.recordPlanWindow(parsed.plan_window);
    this.fileSessions.set(path, new Set(parsed.turns.map((turn) => turn.session_id)));
    const fresh = this.absorb(parsed, source.id);
    await this.scanParsed(parsed, source.id, fresh);
    return fresh.length > 0;
  }

  /**
   * Keep the newest plan-headroom reading per rail.
   *
   * NEWEST, never accumulated: a host's quota counter is account-wide (Copilot's
   * `usedRequests` was observed climbing across five separate sessions), so
   * adding two readings would double-count the same requests, and keeping a
   * high-water mark would survive the monthly reset as a stuck alarm. A
   * re-parse of an old document therefore cannot move the number backwards.
   */
  private recordPlanWindow(reading: PlanWindowReading | undefined): boolean {
    if (!reading) return false;
    const current = this.planWindows.get(reading.source);
    if (current && Date.parse(current.at) >= Date.parse(reading.at)) return false;
    this.planWindows.set(reading.source, reading);
    return true;
  }

  /** The newest plan-headroom reading per rail, newest rail first. */
  planWindowList(): PlanWindowReading[] {
    return [...this.planWindows.values()].sort((a, b) => (a.at < b.at ? 1 : -1));
  }

  /** shouldStop, asked at most every quarter second and sticky once true. */
  private stopping = false;
  private stopAskedAt = 0;
  private stopRequested(): boolean {
    if (this.stopping) return true;
    const ask = this.deps.shouldStop;
    if (!ask) return false;
    const now = Date.now();
    if (now - this.stopAskedAt < 250) return false;
    this.stopAskedAt = now;
    this.stopping = ask();
    if (this.stopping) this.deps.log("another Doorman is taking over the store: stopping this scan at the files read so far");
    return this.stopping;
  }

  async scan(): Promise<void> {
    if (this.scanning) {
      this.scanQueued = true;
      return;
    }
    this.scanning = true;
    try {
      const cutoffMs = this.retentionCutoffMs();
      this.filesSeen = 0;
      let changed = false;
      changed = (await this.scanRoot(this.deps.claudeProjectsDir, "claude-code", cutoffMs)) || changed;
      if (!this.stopRequested()) changed = (await this.scanRoot(this.deps.codexSessionsDir, "codex", cutoffMs)) || changed;
      // Every REGISTERED host that is actually on this machine, through the
      // same cursor/parse/detect pipeline. A descriptor that throws costs its
      // own documents and nothing else.
      for (const source of this.presentSources()) {
        if (this.stopRequested()) break;
        try {
          changed = (await this.scanSource(source, cutoffMs)) || changed;
        } catch (err) {
          this.deps.log(`couldn't scan ${source.id}: ${String(err)}`);
        }
      }
      // With every rail listed, judge the sightings whose evidence is not yet
      // known to be showable. A verdict that hides or shows a row
      // is a change the screens need to hear about.
      if (this.judgeEvidence(Date.now())) changed = true;
      this.lastScanAt = new Date().toISOString();
      this.persistCursors();
      this.persistShown();
      if (changed || this.status === "scanning") this.deps.onUpdate();
    } finally {
      this.scanning = false;
      if (this.scanQueued) {
        this.scanQueued = false;
        void this.scan();
      }
    }
  }

  private async scanRoot(
    root: string,
    source: TurnSource,
    cutoffMs: number | undefined,
  ): Promise<boolean> {
    if (!existsSync(root)) {
      this.sessionsOnDisk.delete(source);
      this.railsListed.delete(source);
      return false;
    }
    let entries: string[];
    try {
      entries = (readdirSync(root, { recursive: true }) as string[]).filter((p) =>
        p.endsWith(".jsonl"),
      );
    } catch (err) {
      this.deps.log(`couldn't list ${root}: ${String(err)}`);
      this.sessionsOnDisk.delete(source);
      this.railsListed.delete(source);
      return false;
    }
    this.railsListed.add(source);
    // Which sessions the listing accounts for — by NAME, before any parse, the
    // same way sessionTranscriptFiles finds them: `<sessionId>.jsonl` for
    // Claude Code (its agent-* siblings ride on the parent), the rollout
    // filename for Codex — plus what each document parsed to this launch.
    const onDisk = new Set<string>();
    for (const rel of entries) {
      const name = rel.split("/").pop() ?? rel;
      const id = source === "codex" ? rolloutSessionId(name) : name.replace(/\.jsonl$/, "");
      if (id) onDisk.add(id);
    }
    let changed = false;
    for (const rel of entries) {
      if (this.stopRequested()) break;
      const path = join(root, rel);
      let stat;
      try {
        stat = statSync(path);
      } catch {
        continue;
      }
      if (!stat.isFile()) continue;
      this.filesSeen += 1;
      if (cutoffMs !== undefined && stat.mtimeMs < cutoffMs) continue;
      const cursor = this.cursors.get(path);
      if (cursor && cursor.size === stat.size && cursor.mtimeMs === stat.mtimeMs) continue;
      try {
        changed = (await this.processFile(path, source)) || changed;
      } catch (err) {
        this.deps.log(`couldn't parse ${path}: ${String(err)}`);
      }
      this.cursors.set(path, { size: stat.size, mtimeMs: stat.mtimeMs });
      // Yield between files: the day-zero backfill runs on Electron's main
      // thread, and a couple hundred transcripts parsed back-to-back would
      // freeze the window that just opened.
      await new Promise<void>((resolve) => setImmediate(resolve));
    }
    // What each document parsed to (this launch, or persisted with its cursor)
    // counts too — after the parses, so a session whose id is not its filename
    // shows on the very scan that first reads it.
    for (const rel of entries) for (const parsed of this.fileSessions.get(join(root, rel)) ?? []) onDisk.add(parsed);
    this.sessionsOnDisk.set(source, onDisk);
    return changed;
  }

  private async processFile(path: string, source: TurnSource): Promise<boolean> {
    const contents = readFileSync(path, "utf8");
    const fileName = path.split("/").pop() ?? path;

    let turns: LedgerTurn[];
    let detect: DetectUnit[];
    let firstPromptBySession = new Map<string, string>();

    if (source === "claude-code") {
      const fallback = fileName.replace(/\.jsonl$/, "");
      const parsed = parseClaudeTranscript(contents, fallback);
      turns = parsed.turns;
      detect = parsed.detect;
      for (const record of parsed.titles) {
        if (titleWriteApplies(record.title.origin, this.titles.get(record.session_id)?.origin)) {
          this.titles.set(record.session_id, record.title);
        }
      }
      for (const turn of parsed.turns) {
        if (turn.role === "user" && turn.text && !firstPromptBySession.has(turn.session_id)) {
          firstPromptBySession.set(turn.session_id, turn.text);
        }
      }
    } else {
      const fallback = rolloutSessionId(fileName) ?? fileName.replace(/\.jsonl$/, "");
      const parsed = parseCodexRollout(contents, fallback);
      turns = parsed.turns;
      detect = parsed.detect;
      if (parsed.first_prompt) firstPromptBySession.set(parsed.session_id, parsed.first_prompt);
      // Which SURFACE ran Codex. Only a value that names a separate catalog row
      // is recorded — the terminal's own originators are the rail itself and
      // need no attribution.
      const appId = shadowAiIdForOriginator(parsed.originator);
      if (appId && this.sessionApps.get(parsed.session_id) !== appId) {
        this.sessionApps.set(parsed.session_id, appId);
        this.persistSurfaces();
      }
    }

    this.fileSessions.set(path, new Set(turns.map((turn) => turn.session_id)));
    const fresh = this.absorb({ turns, detect, titles: [] }, source, firstPromptBySession);
    await this.scanParsed({ detect }, source, fresh);
    return fresh.length > 0;
  }

  /**
   * Fold one parsed document into the store: titles, the turn upsert (ids are
   * stable, so a whole-document re-parse only ADDS), and the deterministic
   * first-prompt title. Returns the turns seen for the first time.
   *
   * `firstPrompts` is the raw, untruncated first prompt per session when the
   * parser reports one; without it the first prompt is taken from the parse's
   * own user turns, which is what a registry descriptor gives us.
   */
  private absorb(
    parsed: { turns: LedgerTurn[]; detect: DetectUnit[]; titles?: TitleRecord[] },
    source: TurnSource,
    firstPrompts?: ReadonlyMap<string, string>,
  ): LedgerTurn[] {
    for (const record of parsed.titles ?? []) {
      if (titleWriteApplies(record.title.origin, this.titles.get(record.session_id)?.origin)) {
        this.titles.set(record.session_id, record.title);
      }
    }
    const fresh: LedgerTurn[] = [];
    for (const turn of parsed.turns) {
      // A descriptor's turns carry their own source by contract; stamping the
      // registry's id here as well means a parser can never file its sessions
      // under somebody else's rail.
      if (turn.source !== source) turn.source = source;
      if (this.turns.has(turn.id)) continue;
      this.turns.set(turn.id, turn);
      fresh.push(turn);
      this.indexTurn(turn);
    }
    this.appendTurns(fresh);

    // Deterministic titles: a first prompt names the session when nothing
    // better exists. Redact-before-derive, same as the hooks.
    const prompts = firstPrompts ?? this.firstPromptsOf(parsed.turns);
    for (const [sessionId, prompt] of prompts) {
      if (!titleWriteApplies("auto_prompt", this.titles.get(sessionId)?.origin)) continue;
      const title = deriveAutoTitle(redact(prompt));
      if (title) this.titles.set(sessionId, { text: title, origin: "auto_prompt" });
    }
    this.persistTitles();
    return fresh;
  }

  private firstPromptsOf(turns: readonly LedgerTurn[]): Map<string, string> {
    const out = new Map<string, string>();
    for (const turn of turns) {
      if (turn.role === "user" && turn.text && !out.has(turn.session_id)) {
        out.set(turn.session_id, turn.text);
      }
    }
    return out;
  }

  /**
   * The detection pipeline over one parsed document — the same one for every
   * rail: the classifier's say on the injection markers, then the per-unit
   * detectors, the egress pass and the session-flow rules.
   *
   * Only units belonging to turns first seen in this pass are scanned
   * (re-parses re-emit old units; their findings already exist and merge
   * idempotently, so skipping them is purely an optimisation). tool_output
   * units anchor to LINE ids rather than turn ids, so they dedupe against
   * their own once-per-run set instead.
   */
  private async scanParsed(
    parsed: { detect: DetectUnit[] },
    source: TurnSource,
    fresh: readonly LedgerTurn[],
  ): Promise<void> {
    const freshIds = new Set(fresh.map((turn) => turn.id));
    const units = parsed.detect.filter((u) =>
      u.kind === "tool_output"
        ? !this.scannedOutputLines.has(u.turn_id)
        : freshIds.has(u.turn_id) || u.turn_id.endsWith(":tail"),
    );
    for (const unit of units) {
      if (unit.kind === "tool_output") this.scannedOutputLines.add(unit.turn_id);
    }
    // Bounded for a long-running app: the oldest lines go first (a Set keeps
    // insertion order). Forgetting one only costs a re-scan of that output,
    // whose findings merge idempotently.
    if (this.scannedOutputLines.size > SCANNED_OUTPUT_LINES_MAX) {
      let excess = this.scannedOutputLines.size - Math.floor(SCANNED_OUTPUT_LINES_MAX * 0.9);
      for (const id of this.scannedOutputLines) {
        if (excess-- <= 0) break;
        this.scannedOutputLines.delete(id);
      }
    }
    // The classifier's say on the injection markers BEFORE the sync scans read
    // them — both the Radar row's confidence and the arming taint come from the
    // same verdict. A no-op without a classifier or with the feature off.
    await this.reconcileInjectionMarkers(parsed.detect);
    this.scanUnits(units, source);
    this.scanEgress(units, source);
    this.scanFlows(parsed.detect, source);
  }

  private scanUnits(units: readonly DetectUnit[], source: TurnSource): void {
    if (units.length === 0) return;
    const policy = this.deps.policy();
    const rows: FindingRow[] = [];
    const nowMs = Date.now();
    for (const unit of units) {
      const redacted = redact(unit.raw);
      // Scoped ignore rules are judged per unit: a "not in this project" allow
      // from the approval panel applies to transcript findings from that
      // project too, and to nothing else.
      const options = {
        disabled: policy.disabled,
        ignore: applicableIgnoreRules(policy.ignore, unit.cwd, nowMs),
        // The person's wallets (chains watched, hashed own addresses), so a
        // transcript row names "your cold storage" the way the guard does.
        ...(policy.wallets === undefined ? {} : { wallets: policy.wallets }),
      };
      const found = detectSecurityFindings(
        {
          kind: unit.kind,
          text: redacted,
          ...(unit.kind === "tool_call" ? { raw_text: unit.raw } : {}),
          tool_name: unit.tool_name,
          target: unit.target,
        },
        options,
      );
      // A regex injection hit the classifier read as ordinary output stays on
      // the Radar — recall is the detectors' — but at medium confidence, the
      // band the fold and the notifier treat as observe-grade.
      const softened = unit.kind === "tool_output" && this.injectionSuppressed.has(this.lineKey(unit));
      // What the model said, for the row to carry — only where it was asked
      // (a classifiable marker) and answered (a cached verdict).
      const verdict =
        unit.kind === "tool_output" && markerIsClassifiable(this.regexInjectionMarker(unit))
          ? this.injectionVerdictCache.get(this.lineKey(unit))
          : undefined;
      // The values redaction removed from this unit, recovered once for every
      // finding on it — what lets an account name the credential family and
      // judge whether the value looks like a placeholder (lib/account.ts).
      const secrets = found.some((f) => accountable(f.detector)) ? extractRedactedSecrets(unit.raw) : [];
      for (const finding of found) {
        if (softened && finding.detector === "injected_instruction") finding.confidence = "medium";
        const assist = verdict && finding.detector === "injected_instruction" ? injectionAssist(verdict, softened) : undefined;
        const account = accountForUnit(finding, unit, secrets, unit.cwd);
        rows.push(
          this.keepEvidence(mintFindingRow(finding, {
            source,
            origin: "transcript",
            session_id: unit.session_id,
            // A tool_output unit's own line is not a ledger turn; the row
            // anchors to the assistant turn that made the call instead.
            turn_id: unit.anchor_turn_id ?? unit.turn_id,
            ...(unit.cwd === undefined ? {} : { cwd: unit.cwd }),
            at: unit.at,
            ...(assist === undefined ? {} : { assist }),
            ...(account === undefined ? {} : { account }),
          }), [unit]),
        );
      }
      // The person's own `when` rules, over the same tool calls the detectors
      // read — so a custom rule's radar row exists whether or not the guard
      // was installed when the call ran.
      if (unit.kind === "tool_call" && policy.custom_rules && policy.custom_rules.length > 0) {
        for (const finding of this.customRuleFindings(policy.custom_rules, unit, redacted)) {
          rows.push(
            mintFindingRow(finding, {
              source,
              origin: "transcript",
              session_id: unit.session_id,
              turn_id: unit.turn_id,
              ...(unit.cwd === undefined ? {} : { cwd: unit.cwd }),
              at: unit.at,
              detector_label: finding.label,
            }),
          );
        }
      }
      // An MCP tool's OUTPUT gets the poisoning patterns on top — that is
      // where a poisoned description's behaviour (and a rug-pull's payload)
      // actually surfaces in a transcript.
      if (unit.kind === "tool_output" && unit.tool_name?.startsWith("mcp__")) {
        for (const finding of scanMcpToolOutput(redacted, unit.tool_name)) {
          rows.push(
            mintFindingRow(finding, {
              source,
              origin: "transcript",
              session_id: unit.session_id,
              turn_id: unit.turn_id,
              at: unit.at,
            }),
          );
        }
      }
    }
    this.ingestFindingRows(rows);
  }

  /** Findings from the MCP config watcher — no session, origin "config". */
  ingestConfigFindings(rows: readonly FindingRow[]): void {
    this.ingestFindingRows(rows);
  }

  /**
   * What a Docker Sandbox recorded, from a `doorman sbx pull` drop file
   * (lib/sandbox-import.ts): its turns, titles and detections, masked and
   * scoped `@<sandbox>`. Idempotent — the ids are stable across pulls, a turn
   * is never rewritten, and a detection is merged like any re-observation
   * (`mergeFinding`: triage made here is kept), and only a row that changed is
   * appended — so ingesting the same bundle twice writes nothing the second
   * time. Nothing is announced: these are a sandbox's history, not news.
   */
  importSandboxBundle(bundle: SandboxBundle): SandboxImportResult {
    const records = sandboxRecords(bundle);
    const fresh: LedgerTurn[] = [];
    const sessions = new Set<string>();
    for (const turn of records.turns) {
      sessions.add(turn.session_id);
      this.sandboxSessions.add(turn.session_id);
      if (this.turns.has(turn.id)) continue;
      this.turns.set(turn.id, turn);
      this.indexTurn(turn);
      fresh.push(turn);
    }
    this.appendTurns(fresh);
    let titled = false;
    for (const [sessionId, title] of records.titles) {
      const current = this.titles.get(sessionId);
      if (current?.text === title.text && current.origin === title.origin) continue;
      this.titles.set(sessionId, title);
      titled = true;
    }
    if (titled) this.persistTitles();
    const changed: FindingRow[] = [];
    let added = 0;
    for (const row of records.findings) {
      const existing = this.ledger.get(row.finding_id);
      if (existing === undefined) {
        this.ledger.set(row.finding_id, row);
        changed.push(row);
        added += 1;
        continue;
      }
      const merged = mergeFinding(existing, row);
      if (JSON.stringify(merged) === JSON.stringify(existing)) continue;
      this.ledger.set(row.finding_id, merged);
      changed.push(merged);
    }
    this.appendFindings(changed);
    if (fresh.length > 0 || titled || changed.length > 0) this.deps.onUpdate();
    return {
      sandbox: records.sandbox,
      sessions: sessions.size,
      turns_added: fresh.length,
      findings_added: added,
      findings_updated: changed.length - added,
    };
  }

  /**
   * The findings the app SHOWS — every ledger row whose rule is in scope
   * (guard/rule-scope.ts) and whose evidence the app can still put
   * on screen: the transcript on disk and inside the retention window
   *, and the sighting reproducible from it or kept in the vault
   *. The one read path for the snapshot, the tray, notifications,
   * the report, the ledger views, the AI assistant and the MCP tool: a hidden
   * rule's rows and an evidence-less session's rows stay in `ledger` and
   * reach none of them.
   */
  shownFindings(): FindingRow[] {
    const cutoff = this.retentionCutoffIso();
    const now = Date.now();
    const out: FindingRow[] = [];
    for (const row of this.ledger.values()) if (this.rowShown(row, cutoff, now)) out.push(row);
    return out;
  }

  /** One shown finding by id — undefined for a hidden row exactly as for an
   * unknown id, so a caller cannot tell the two apart. */
  shownFinding(findingId: string): FindingRow | undefined {
    const row = this.ledger.get(findingId);
    return row !== undefined && this.rowShown(row, this.retentionCutoffIso(), Date.now()) ? row : undefined;
  }

  private rowShown(row: FindingRow, retentionCutoff: string | undefined, nowMs: number): boolean {
    if (!ruleShown(row.detector)) return false;
    if (row.origin === "transcript" && retentionCutoff !== undefined && row.last_seen_at < retentionCutoff) return false;
    // Pulled from a Docker Sandbox: shown there, so shown here. Its documents
    // are in the sandbox — there is nothing on this disk to judge it by.
    if (row.sandbox !== undefined) return true;
    // A row with no document behind it: a call the guard refused
    // or held without a recorded allow never ran, so no transcript holds it
    // — shown, since the guard stopping something is worth seeing; the card
    // keeps the masked line and offers no VIEW RAW (renderer callNeverRan). A gateway
    // or integrity line, or a guard line that named no session, is not
    // shown at all. Every other row is judged by its documents, whichever
    // path minted it: the hook fires first and so owns a row's origin, but
    // the transcript behind the row is the same file.
    if (!evidenceReadable(row)) return callNeverRan(row);
    // The hook's row lands before the host writes the transcript line, so a
    // sighting this fresh is shown on trust and judged once it has settled.
    if (nowMs - Date.parse(row.last_seen_at) < EVIDENCE_GRACE_MS) return true;
    if (row.session_id !== undefined && !this.sessionOnDisk(row.source, row.session_id)) return false;
    return this.evidenceHeld(row);
  }

  /**
   * Whether the app can still put this sighting's evidence on screen
   *: the vault holds it, or the transcript reproduced it the last
   * time `judgeEvidence` looked. Unjudged is shown.
   */
  private evidenceHeld(row: FindingRow): boolean {
    return this.evidenceVerdicts.get(sightingKey(row))?.ok ?? true;
  }

  /**
   * Judge the sightings whose evidence is not yet known to be showable
   * by running the Reveal for each — the very routine VIEW RAW
   * runs, so every way it can come up empty is a verdict here: the file
   * gone, the file present but the sighting no longer in it (scrubbed,
   * compacted, a prompt the parser never yielded), a vault blob that no
   * longer decrypts, a config file edited clean. A verdict stands until the
   * documents it was judged against change; an exact reproduction is vaulted
   * by the Reveal itself. Only rows on a rail the newest scan listed in full
   * are judged, and a session listed as off disk is hidden already and judged
   * when it is back. Bounded per scan and parsed once per document, so a
   * large ledger is worked through over a few ticks rather than re-read
   * whole in one. Returns whether any verdict changed what is shown.
   */
  private judgeEvidence(nowMs: number): boolean {
    const candidates: FindingRow[] = [];
    for (const row of this.ledger.values()) {
      if (!this.judgedByEvidence(row)) continue;
      if (nowMs - Date.parse(row.last_seen_at) < EVIDENCE_GRACE_MS) continue;
      if (row.origin !== "config") {
        if (!this.railsListed.has(row.source)) continue;
        if (!this.sessionOnDisk(row.source, row.session_id!)) continue;
      }
      candidates.push(row);
    }
    if (candidates.length === 0) return false;
    // Newest first: the cards a person is looking at settle first.
    candidates.sort((a, b) => (a.last_seen_at < b.last_seen_at ? 1 : a.last_seen_at > b.last_seen_at ? -1 : 0));
    const documents = new Map<string, string[]>();
    const parsed = new Map<string, DetectUnit[] | undefined>();
    let judged = 0;
    let changed = false;
    for (const row of candidates) {
      if (judged >= EVIDENCE_JUDGED_PER_SCAN) break;
      const paths = this.evidenceDocuments(row, documents);
      const cursor = this.documentsCursor(paths);
      const previous = this.evidenceVerdicts.get(sightingKey(row));
      if (previous !== undefined && previous.cursor === cursor) continue;
      judged += 1;
      let ok: boolean;
      try {
        ok = this.reveal(row, { documents: paths, parsed }).ok;
      } catch (err) {
        this.deps.log(`couldn't judge the evidence for ${row.finding_id}: ${String(err)}`);
        continue;
      }
      if (this.recordVerdict(row, ok, cursor)) changed = true;
    }
    return changed;
  }

  /** Which rows the evidence judge reaches: those with a document to re-read
   * (lib/findings.ts `evidenceReadable` — the same line the screens draw when
   * deciding whether to offer VIEW RAW at all). */
  private judgedByEvidence(row: FindingRow): boolean {
    return row.sandbox === undefined && ruleShown(row.detector) && evidenceReadable(row);
  }

  /** The documents a row's evidence is read from — its config file, or its
   * session's transcripts (listed once per session in `documents`). */
  private evidenceDocuments(row: FindingRow, documents?: Map<string, string[]>): string[] {
    if (row.origin === "config") return row.target === undefined ? [] : [row.target];
    if (row.session_id === undefined) return [];
    const key = `${row.source}\u0000${row.session_id}`;
    let known = documents?.get(key);
    if (known === undefined) {
      known = this.sessionDocuments(row.session_id, row.source);
      documents?.set(key, known);
    }
    return known;
  }

  /** Keep what a Reveal found as the row's verdict. Returns whether it
   * changed what is shown. */
  private recordVerdict(row: FindingRow, ok: boolean, cursor: string): boolean {
    const key = sightingKey(row);
    const previous = this.evidenceVerdicts.get(key);
    this.evidenceVerdicts.set(key, { ok, cursor, hash: previous?.hash ?? digest(key) });
    return (previous?.ok ?? true) !== ok;
  }

  /** One digest for the state of a set of documents — their paths, sizes
   * and mtimes — so a verdict can tell whether what it judged has changed. */
  private documentsCursor(paths: readonly string[]): string {
    return digest(
      paths
        .map((path) => {
          const c = this.documentCursor(path);
          return `${path}@${c?.size ?? 0}@${c?.mtimeMs ?? 0}`;
        })
        .join("\n"),
    );
  }

  /**
   * Save what the newest scan decided can be shown (shown.json): the rails it
   * listed in full, the sessions each holds on disk, and the evidence
   * verdicts. The CLI reads the store, often a copy of it, without scanning;
   * without this it knew of no transcript and no verdict, so `doorman status`
   * and `doorman findings` counted every row the app had hidden. Written only
   * when it changed.
   */
  private persistShown(): void {
    const verdicts: Record<string, { ok: boolean; cursor: string }> = {};
    for (const v of this.evidenceVerdicts.values()) verdicts[v.hash] = { ok: v.ok, cursor: v.cursor };
    const text = `${JSON.stringify({
      listed: [...this.railsListed],
      on_disk: Object.fromEntries([...this.sessionsOnDisk].map(([rail, ids]) => [rail, [...ids]])),
      verdicts,
    })}\n`;
    if (text === this.shownSaved) return;
    try {
      writeFileSync(this.path("shown.json"), text, { mode: 0o600 });
      this.shownSaved = text;
    } catch (err) {
      this.deps.log(`couldn't write shown.json: ${String(err)}`);
    }
  }

  /**
   * Read back what persistShown saved, so an engine that has not scanned
   * yet (the CLI, the app relaunching) hides what the app hides. The
   * listing is taken as it was saved; a scan replaces it. The verdicts only
   * when this engine has no vault: one with a vault judges for itself, since a
   * verdict can rest on a vault blob it may not be able to open.
   */
  private loadShown(): void {
    let text: string;
    let saved: { listed?: unknown; on_disk?: unknown; verdicts?: unknown };
    try {
      text = readFileSync(this.path("shown.json"), "utf8");
      saved = JSON.parse(text) as typeof saved;
    } catch {
      return; // none yet: every row is shown until the first scan, as before
    }
    if (!saved || typeof saved !== "object") return;
    this.shownSaved = text;
    if (Array.isArray(saved.listed)) for (const rail of saved.listed) if (typeof rail === "string") this.railsListed.add(rail);
    if (saved.on_disk && typeof saved.on_disk === "object") {
      for (const [rail, ids] of Object.entries(saved.on_disk)) {
        if (Array.isArray(ids)) this.sessionsOnDisk.set(rail, new Set(ids.filter((id): id is string => typeof id === "string")));
      }
    }
    if (this.deps.vault || !saved.verdicts || typeof saved.verdicts !== "object") return;
    const verdicts = saved.verdicts as Record<string, { ok?: unknown; cursor?: unknown } | undefined>;
    if (Object.keys(verdicts).length === 0) return;
    for (const row of this.ledger.values()) {
      const key = sightingKey(row);
      const hash = digest(key);
      const v = verdicts[hash];
      if (typeof v?.ok === "boolean" && typeof v.cursor === "string") this.evidenceVerdicts.set(key, { ok: v.ok, cursor: v.cursor, hash });
    }
  }

  /**
   * The documents a session's evidence is read from: the files named after
   * it (`sessionTranscriptFiles`), else the files whose parse yielded it —
   * a Codex rollout whose metadata id is not its filename, a Claude Code
   * session whose file was renamed — so a session the scan lists as on disk
   * is never judged against an empty listing.
   */
  private sessionDocuments(sessionId: string, source: FindingSource): string[] {
    const named = this.sessionTranscriptFiles(sessionId, source);
    if (named.length > 0) return named;
    const parsed: string[] = [];
    for (const [path, sessions] of this.fileSessions) if (sessions.has(sessionId) && existsSync(path)) parsed.push(path);
    return parsed;
  }

  /** Every detect unit of one session, re-read from its documents — what the
   * reveal and the evidence judge reproduce a sighting against. */
  private sessionUnits(
    sessionId: string,
    source: FindingSource,
    paths: readonly string[],
    parsed?: Map<string, DetectUnit[] | undefined>,
  ): DetectUnit[] {
    const descriptor = this.registry.find((s) => s.id === source);
    const units: DetectUnit[] = [];
    for (const path of paths) {
      // A document holding many sessions (an editor's database) is read once
      // per pass, however many of its sessions are judged.
      let all = parsed?.get(path);
      if (all === undefined && !parsed?.has(path)) {
        all = this.parseForDryRun(path, source as TurnSource, descriptor)?.detect;
        parsed?.set(path, all);
      }
      if (!all) continue;
      for (const unit of all) if (unit.session_id === sessionId) units.push(unit);
    }
    return units;
  }

  /** Reproduce a row's sighting from its session's units, with the options
   * capture gave the detectors — the flow evaluator needs the same ones, or
   * a custom `after` rule and the unapproved-server rule cannot reproduce
   * their rows. */
  private reproduceSighting(row: FindingRow, units: readonly DetectUnit[]): ScoredEvidence | undefined {
    const policy = this.deps.policy();
    return revealEvidenceForFinding(row, units, {
      ...(policy.approved_mcp_servers ? { approvedMcpServers: policy.approved_mcp_servers } : {}),
      ...(policy.custom_rules ? { customRules: policy.custom_rules } : {}),
      ...(policy.wallets === undefined ? {} : { detect: { wallets: policy.wallets } }),
    });
  }

  /**
   * Is a session's transcript still on disk, as far as the newest scan could
   * tell? True when the rail was not listed in full (root absent or
   * unreadable, a host that does not name sessions in paths) — an unmounted
   * volume must hide nothing — and before any scan (this launch's or the one
   * shown.json saved).
   */
  private sessionOnDisk(source: string, sessionId: string): boolean {
    if (this.sandboxSessions.has(sessionId)) return true;
    const onDisk = this.sessionsOnDisk.get(source);
    return onDisk === undefined || onDisk.has(sessionId);
  }

  /** The `when` half of the custom rules over one tool_call unit. The command
   * is redacted before it is matched — a rule can never probe for a value. */
  private customRuleFindings(rules: readonly CustomRule[], unit: DetectUnit, redacted: string) {
    const command = commandOf(unit);
    return matchCustomRules(rules, {
      tool_name: unit.tool_name,
      tool_input: parsedInput(unit),
      command: command === undefined ? undefined : redact(command),
      target: unit.target,
      cwd: unit.cwd,
      redacted,
    });
  }

  /**
   * Every session document touched within `days` — both native roots and every
   * present registered source. A custom rule's dry run reads exactly what the
   * live scan reads, so "what would this have matched?" can never quietly
   * exclude a host the guard is about to enforce against.
   */
  private recentTranscriptFiles(
    days: number,
  ): Array<{ path: string; source: TurnSource; descriptor?: TranscriptSourceDescriptor }> {
    const cutoffMs = Date.now() - days * 86_400_000;
    const out: Array<{ path: string; source: TurnSource; descriptor?: TranscriptSourceDescriptor }> = [];
    for (const descriptor of this.presentSources()) {
      for (const path of this.sourceDocuments(descriptor)) {
        const stat = this.documentCursor(path);
        if (stat && stat.mtimeMs >= cutoffMs) out.push({ path, source: descriptor.id, descriptor });
      }
    }
    for (const [root, source] of [
      [this.deps.claudeProjectsDir, "claude-code"],
      [this.deps.codexSessionsDir, "codex"],
    ] as const) {
      if (!existsSync(root)) continue;
      let entries: string[];
      try {
        entries = (readdirSync(root, { recursive: true }) as string[]).filter((p) => p.endsWith(".jsonl"));
      } catch {
        continue;
      }
      for (const rel of entries) {
        const path = join(root, rel);
        try {
          const stat = statSync(path);
          if (stat.isFile() && stat.mtimeMs >= cutoffMs) out.push({ path, source });
        } catch {
          // vanished between list and stat
        }
      }
    }
    return out;
  }

  /**
   * Run ONE custom rule over the last `days` of transcripts and report what it
   * would have matched — without minting anything. The editor's dry run,
   * offered rather than required (a saved rule enforces from the next tool
   * call): a rule that would have fired 300 times in two weeks is a rule to
   * narrow before it holds a call.
   */
  /** One document's detect units for a read-only pass (the dry run, the reveal):
   * the descriptor's parser when the document belongs to a registered source,
   * the native parsers otherwise. Never throws — a document that can't be read
   * is one the dry run doesn't count. */
  private parseForDryRun(
    path: string,
    source: TurnSource,
    descriptor: TranscriptSourceDescriptor | undefined,
  ): { detect: DetectUnit[] } | undefined {
    if (descriptor) {
      try {
        return descriptor.parse(path, this.sourceIo());
      } catch (err) {
        this.deps.log(`${descriptor.id} parser threw on ${path}: ${String(err)}`);
        return undefined;
      }
    }
    let contents: string;
    try {
      contents = readFileSync(path, "utf8");
    } catch {
      return undefined;
    }
    const fileName = path.split("/").pop() ?? path;
    try {
      return source === "codex"
        ? parseCodexRollout(contents, rolloutSessionId(fileName) ?? fileName.replace(/\.jsonl$/, ""))
        : parseClaudeTranscript(contents, fileName.replace(/\.jsonl$/, ""));
    } catch (err) {
      this.deps.log(`couldn't parse ${path}: ${String(err)}`);
      return undefined;
    }
  }

  async dryRunCustomRule(rule: CustomRule, days = 14): Promise<CustomRuleDryRun> {
    const files = this.recentTranscriptFiles(days);
    const result: CustomRuleDryRun = { days, files: files.length, matches: 0, sessions: 0, samples: [] };
    const sessions = new Set<string>();
    const sample = (at: string, tool_name: string | undefined, excerpt: string, session_id: string) => {
      if (result.samples.length >= 6) return;
      result.samples.push({ at, ...(tool_name === undefined ? {} : { tool_name }), excerpt: excerpt.slice(0, 200), session_id });
    };
    for (const { path, source, descriptor } of files) {
      const parsed = this.parseForDryRun(path, source, descriptor);
      if (!parsed) continue;
      if (rule.after) {
        // A flow rule: the taint→sink evaluation over each session's units.
        const bySession = new Map<string, DetectUnit[]>();
        for (const unit of parsed.detect) {
          const list = bySession.get(unit.session_id);
          if (list) list.push(unit);
          else bySession.set(unit.session_id, [unit]);
        }
        for (const units of bySession.values()) {
          const flows = evaluateFlowFindings(units, {
            customRules: [rule],
            familiesIn: (unit) => this.memoizedOutputFamilies(unit),
            injectionIn: (unit) => this.memoizedInjectionMarker(unit),
          }).filter((f) => f.detector === `custom:${rule.id}`);
          for (const flow of flows) {
            result.matches += flow.occurrences;
            sessions.add(flow.session_id);
            sample(flow.at, flow.tool_name, flow.excerpt, flow.session_id);
          }
        }
      } else {
        for (const unit of parsed.detect) {
          if (unit.kind !== "tool_call") continue;
          const hits = this.customRuleFindings([rule], unit, redact(unit.raw));
          if (hits.length === 0) continue;
          result.matches += 1;
          sessions.add(unit.session_id);
          sample(unit.at, unit.tool_name, hits[0]!.excerpt, unit.session_id);
        }
      }
      // Same yield as the backfill: this runs on the main thread.
      await new Promise<void>((resolve) => setImmediate(resolve));
    }
    result.sessions = sessions.size;
    return result;
  }

  /**
   * Session-flow pass (lib/flow-rules.ts): cross-call rules over the file's
   * FULL unit list, per session — a source in an old turn must still pair with
   * a sink in a fresh one, so this cannot use scanUnits' fresh-only filter.
   * Identical flows re-mint identical rows and merge idempotently.
   */
  private scanFlows(detect: readonly DetectUnit[], source: TurnSource): void {
    if (detect.length === 0) return;
    const policy = this.deps.policy();
    const bySession = new Map<string, DetectUnit[]>();
    for (const unit of detect) {
      const list = bySession.get(unit.session_id);
      if (list) list.push(unit);
      else bySession.set(unit.session_id, [unit]);
    }
    const rows: FindingRow[] = [];
    let armedChanged = false;
    for (const [sessionId, units] of bySession) {
      // What arms the guard's next-call escalation: injection taints still live
      // at the end of this session's units. Recomputed on every touch of the
      // session's file, so a taint that goes stale (30 calls / 30 min) disarms
      // on the next scan; the guard re-checks the time bound at read time too.
      const taints = armedInjectionTaints(units, {
        injectionIn: (unit) => this.memoizedInjectionMarker(unit),
      });
      const existing = this.armed.get(sessionId);
      if (taints.length === 0) {
        if (existing) {
          this.armed.delete(sessionId);
          armedChanged = true;
        }
      } else if (!existing || JSON.stringify(existing.taints) !== JSON.stringify(taints)) {
        this.armed.set(sessionId, { taints, updated_at: new Date().toISOString() });
        armedChanged = true;
      }
      const flows = evaluateFlowFindings(units, {
        // Flow rules run per session, and a session's units share a cwd in
        // practice — the first unit's is the scope the ignore rules are judged by.
        ignore: applicableIgnoreRules(policy.ignore, units.find((u) => u.cwd)?.cwd),
        familiesIn: (unit) => this.memoizedOutputFamilies(unit),
        injectionIn: (unit) => this.memoizedInjectionMarker(unit),
        ...(policy.approved_mcp_servers ? { approvedMcpServers: policy.approved_mcp_servers } : {}),
        ...(policy.custom_rules ? { customRules: policy.custom_rules } : {}),
      });
      const sessionCwd = units.find((u) => u.cwd)?.cwd;
      for (const flow of flows) {
        // What a loop burned is the point of reporting it, and only the engine
        // holds the turn store — so the figures are stated here rather than in
        // the pure rule module. The screens show the TOKENS; the
        // priced twin rides along for the record. A span with no usage leaves
        // the field absent rather than claiming 0, the same honesty rule the
        // ledger follows. Both ride the row as NUMBERS so Analytics can total
        // the window's loops.
        const burned = flow.detector === "agent_loop" ? this.burnedByLoop(flow) : undefined;
        // Both ends of the flow, for the account: where the value came from
        // and where it went (lib/account.ts).
        const sourceUnit = units.find((u) => u.turn_id === flow.source_turn_id && u.kind !== "prompt");
        const sinkUnit = units.find((u) => u.turn_id === flow.sink_turn_id && u.kind === "tool_call");
        const account =
          sourceUnit && sinkUnit && accountable(flow.detector)
            ? accountForFlow(flow, sourceUnit, sinkUnit, extractRedactedSecrets(sourceUnit.raw), sessionCwd)
            : undefined;
        rows.push(
          this.keepEvidence(mintFindingRow(flow, {
            source,
            origin: "transcript",
            session_id: flow.session_id,
            turn_id: flow.sink_turn_id,
            ...(account === undefined ? {} : { account }),
            // Both ends of the flow, so the card can state the gap and the
            // ledger can mark where it began as well as where it landed.
            source_turn_id: flow.source_turn_id,
            source_at: flow.source_at,
            ...(burned?.usd === undefined ? {} : { burned_usd: burned.usd }),
            ...(burned?.tokens === undefined ? {} : { burned_tokens: burned.tokens }),
            ...(sessionCwd === undefined ? {} : { cwd: sessionCwd }),
            at: flow.at,
            ...(flow.detector_label === undefined ? {} : { detector_label: flow.detector_label }),
          }), units, {
            ...(policy.approved_mcp_servers ? { approvedMcpServers: policy.approved_mcp_servers } : {}),
            ...(policy.custom_rules ? { customRules: policy.custom_rules } : {}),
          }),
        );
      }
    }
    if (this.pruneArmed() || armedChanged) this.publishArmed();
    this.ingestFindingRows(rows);
  }

  /** Drop armed entries whose taints have all aged out by wall clock — a
   * session that simply stopped must not stay armed forever. Returns whether
   * anything was dropped. */
  private pruneArmed(): boolean {
    const cutoff = Date.now() - FLOW_MAX_GAP_MS;
    let pruned = false;
    for (const [sessionId, entry] of this.armed) {
      const live = entry.taints.filter((t) => Date.parse(t.at) >= cutoff);
      if (live.length === 0) {
        this.armed.delete(sessionId);
        pruned = true;
      }
    }
    return pruned;
  }

  private publishArmed(): void {
    this.deps.onArmedChange?.(Object.fromEntries(this.armed));
  }

  /**
   * What the assistant turns spanning a loop burned: input+output tokens, and
   * the priced twin in USD. Sums the session's assistant turns in
   * `[source_at, at]` — the same window the run occupied. Each figure is
   * undefined when no turn in the span carried it (no usage recorded, or every
   * model unpriced), because "0" would read as "this was free" when what we
   * mean is "we don't know".
   */
  private burnedByLoop(flow: { session_id: string; source_at: string; at: string }): { usd?: number; tokens?: number } {
    let cost = 0;
    let priced = 0;
    let tokens = 0;
    let metered = 0;
    for (const turn of this.turns.values()) {
      if (turn.session_id !== flow.session_id || turn.role !== "assistant") continue;
      if (turn.at < flow.source_at || turn.at > flow.at) continue;
      if (turn.usage) {
        tokens += turn.usage.input_tokens + turn.usage.output_tokens;
        metered += 1;
      }
      if (typeof turn.cost !== "number") continue;
      cost += turn.cost;
      priced += 1;
    }
    return {
      ...(priced === 0 ? {} : { usd: cost }),
      ...(metered === 0 ? {} : { tokens }),
    };
  }

  /** Redacting a 64 KB output on EVERY file touch is the expensive part of the
   * flow pass, and a transcript line never changes — so the probe caches by
   * line id. Bounded: cleared wholesale past 4096 entries rather than LRU'd. */
  private memoizedOutputFamilies(unit: DetectUnit): readonly string[] {
    const key = `${unit.turn_id}:${unit.raw.length}`;
    const cached = this.outputFamiliesCache.get(key);
    if (cached) return cached;
    if (this.outputFamiliesCache.size > 4096) this.outputFamiliesCache.clear();
    const families = credentialFamiliesInOutput(unit.raw);
    this.outputFamiliesCache.set(key, families);
    return families;
  }

  private lineKey(unit: DetectUnit): string {
    return `${unit.turn_id}:${unit.raw.length}`;
  }

  /** Same deal for the injection probe, which re-runs the detectors over the
   * output. `""` is cached for "no marker" so a clean output isn't re-probed. */
  private regexInjectionMarker(unit: DetectUnit): string | undefined {
    const key = this.lineKey(unit);
    const cached = this.injectionMarkerCache.get(key);
    if (cached !== undefined) return cached === "" ? undefined : cached;
    if (this.injectionMarkerCache.size > 4096) this.injectionMarkerCache.clear();
    const marker = injectionMarkerIn(unit);
    this.injectionMarkerCache.set(key, marker ?? "");
    return marker;
  }

  /** The marker the flow rules and the arming read: the regex's, unless the
   * injection classifier stood it down (reconcileInjectionMarkers). */
  private memoizedInjectionMarker(unit: DetectUnit): string | undefined {
    const marker = this.regexInjectionMarker(unit);
    if (marker !== undefined && this.injectionSuppressed.has(this.lineKey(unit))) return undefined;
    return marker;
  }

  /**
   * Ask the classifier about every tool_output line whose regex marker it may
   * overrule (lib/injection-classifier.ts markerIsClassifiable), cache the
   * verdicts, and refresh the suppressed set. Adjust-only by construction: a
   * line with no regex marker is never sent, so the model cannot add a finding.
   */
  private async reconcileInjectionMarkers(detect: readonly DetectUnit[]): Promise<void> {
    const cfg = this.deps.policy().injection_classifier ?? defaultInjectionClassifierConfig();
    const classify = this.deps.classifyInjection;
    if (!cfg.enabled || !classify) {
      if (this.injectionSuppressed.size > 0) this.injectionSuppressed.clear();
      return;
    }
    const model = this.deps.injectionModelInUse?.() ?? selectedInjectionModel(cfg);
    if (model !== this.injectionVerdictModel) {
      this.injectionVerdictCache.clear();
      this.injectionVerdictModel = model;
    }
    for (const unit of detect) {
      if (unit.kind !== "tool_output") continue;
      const marker = this.regexInjectionMarker(unit);
      if (!markerIsClassifiable(marker)) continue;
      const key = this.lineKey(unit);
      let verdict: InjectionVerdict | null = this.injectionVerdictCache.get(key) ?? null;
      if (verdict === null) {
        try {
          verdict = await classify(unit.raw);
        } catch {
          verdict = null;
        }
        if (verdict !== null) {
          if (this.injectionVerdictCache.size > 4096) this.injectionVerdictCache.clear();
          this.injectionVerdictCache.set(key, verdict);
        }
      }
      if (injectionMarkerStands(marker, verdict, cfg)) this.injectionSuppressed.delete(key);
      else this.injectionSuppressed.add(key);
    }
  }

  /** Merge freshly minted rows into the ledger; notify on the genuinely new. */
  private ingestFindingRows(rows: readonly FindingRow[]): void {
    if (rows.length === 0) return;
    const changed: FindingRow[] = [];
    const brandNew: FindingRow[] = [];
    for (const minted of rows) {
      const row = this.stampSighting(minted, this.ledger.get(minted.finding_id));
      const existing = this.ledger.get(row.finding_id);
      if (existing) {
        const merged = mergeFinding(existing, row);
        this.ledger.set(row.finding_id, merged);
        changed.push(merged);
      } else {
        this.ledger.set(row.finding_id, row);
        changed.push(row);
        // A classifier-softened injection row is recorded, not announced.
        if (!(row.detector === "injected_instruction" && row.confidence === "medium")) brandNew.push(row);
      }
    }
    this.appendFindings(changed);
    // Recorded, not announced: a hidden rule's row lands in the ledger above
    // and stops there (guard/rule-scope.ts).
    const announce = brandNew.filter((row) => ruleShown(row.detector));
    if (this.initialScanDone && announce.length > 0) this.deps.onNewFindings(announce);
  }

  /**
   * What a sighting records about the moment it happened, beyond what its
   * detector said: the level the rule was working at and the build that
   * fired it (lib/detection-schema.ts `rule_mode`, `app_version`).
   *
   * Only a sighting NEWER than what the row already holds is stamped: a
   * whole-file re-scan re-mints every old unit, and stamping those with
   * today's policy would rewrite "blocked under `block`" as "observe" the day
   * someone relaxed the rule. An old sighting carries no stamp, and the merge
   * keeps the row's own.
   */
  private stampSighting(row: FindingRow, existing?: FindingRow): FindingRow {
    if (existing && row.last_seen_at <= existing.last_seen_at) return row;
    const mode = ruleModeOf(row.detector, this.deps.policy());
    return {
      ...row,
      ...(mode === undefined ? {} : { rule_mode: mode }),
      ...(this.deps.appVersion === undefined ? {} : { app_version: this.deps.appVersion }),
    };
  }

  /**
   * Keep a transcript detection's raw evidence in the vault, and put the
   * fingerprints of what it redacted on the row. Done once per sighting: a
   * row the vault already holds with this excerpt is left as it is, so a
   * whole-file re-scan costs a map lookup, not a second detection pass.
   */
  private keepEvidence(row: FindingRow, units: readonly DetectUnit[], options: FlowOptions = {}): FindingRow {
    const vault = this.deps.vault;
    // Cheap checks first: `available()` is the one that may reach the keychain
    // (and, on a Mac whose Safe Storage item another build made, prompt), so it
    // is asked only for a sighting that genuinely needs keeping.
    if (!vault || vault.has(row.finding_id, row.excerpt)) return row;
    // A sighting that did not reproduce once won't on the next scan either
    // (a custom `when` rule, a row whose detector changed) — remembered for the
    // run, so a re-scan doesn't repeat the whole reproduction for nothing.
    const attempt = `${row.finding_id}\u0000${row.excerpt}`;
    if (this.unreproducible.has(attempt)) return row;
    if (!vault.available()) return row;
    const policy = this.deps.policy();
    let scored: ScoredEvidence | undefined;
    try {
      scored = revealEvidenceForFinding(row, units, {
        ...options,
        // The memoized readers the scan itself used, so a flow's reproduction
        // re-uses them instead of re-reading every output in the session.
        familiesIn: (unit) => this.memoizedOutputFamilies(unit),
        injectionIn: (unit) => this.memoizedInjectionMarker(unit),
        ...(policy.wallets === undefined ? {} : { detect: { wallets: policy.wallets } }),
      });
    } catch (err) {
      this.deps.log(`couldn't read evidence for ${row.finding_id}: ${String(err)}`);
      return row;
    }
    // Only a unit that re-detects with this very excerpt is this sighting; a
    // near match may be a sibling call with a different credential, and the
    // vault would then present it as what was reported.
    if (!scored?.exact) {
      if (this.unreproducible.size > 8192) this.unreproducible.clear();
      this.unreproducible.add(attempt);
      return row;
    }
    const evidence = scored.evidence;
    vault.put(row.finding_id, row.excerpt, evidence, row.last_seen_at);
    const secrets = vault.fingerprints(evidence.secrets);
    return secrets.length > 0 ? { ...row, secrets } : row;
  }

  /** Findings arriving from the PreToolUse guard's spool. Always "live". */
  ingestSpoolLines(lines: readonly string[]): void {
    const changed: FindingRow[] = [];
    const brandNew: FindingRow[] = [];
    const warned: FindingRow[] = [];
    for (const line of lines) {
      if (line.trim() === "") continue;
      let record: SpoolRecord;
      try {
        record = JSON.parse(line) as SpoolRecord;
      } catch {
        continue;
      }
      if (!record || !Array.isArray(record.findings)) continue;
      const at = typeof record.at === "string" ? record.at : new Date().toISOString();
      const recordSource =
        typeof record.source === "string" && record.source !== "" ? record.source : "claude-code";
      // What an exception waved through. Minted as its own kind of row —
      // `enforced: "excepted"`, carrying the rule — and never announced: the
      // person chose this, and the Radar's job is to keep the
      // choice visible, not to nag about it. Triage lands on accepted_risk for
      // the same reason; an existing open row keeps its own status on merge.
      if (Array.isArray(record.excepted)) {
        for (const raw of record.excepted) {
          if (!raw || typeof raw !== "object") continue;
          const finding = raw as Parameters<typeof mintFindingRow>[0] & { exception?: unknown };
          if (typeof finding.detector !== "string" || typeof finding.excerpt !== "string") continue;
          const exception = parseFindingException(finding.exception);
          const minted = mintFindingRow(finding, {
            source: recordSource,
            origin: "guard",
            session_id: record.session_id,
            ...(typeof record.cwd === "string" && record.cwd !== "" ? { cwd: record.cwd } : {}),
            at,
            enforced: "excepted",
            ...(exception === undefined ? {} : { exception }),
          });
          const row = this.stampSighting(minted, this.ledger.get(minted.finding_id));
          const existing = this.ledger.get(row.finding_id);
          const next = existing ? mergeFinding(existing, row) : { ...row, status: "accepted_risk" as const };
          this.ledger.set(row.finding_id, next);
          changed.push(next);
        }
      }
      const recordEnforced =
        record.decision === "deny"
          ? ("deny" as const)
          : record.decision === "ask"
            ? ("ask" as const)
            : record.decision === "warn"
              ? ("warn" as const)
              : undefined;
      const warnedDetectors = new Set(Array.isArray(record.warned) ? record.warned : []);
      const resolution = parseResolution(record.resolution);
      const held = record.held === true;
      const labels = record.detector_labels && typeof record.detector_labels === "object" ? record.detector_labels : {};
      const judged = Array.isArray(record.second_opinion?.judged) ? record.second_opinion!.judged : [];
      const soModel = typeof record.second_opinion?.model === "string" ? record.second_opinion.model : "local model";
      /** The local model's verdict on THIS finding, if the guard asked it. */
      const secondOpinionAssist = (detector: string, keyName: string | undefined) => {
        const j = judged.find(
          (x) => x && x.detector === detector && (x.key_name === undefined || keyName === undefined || x.key_name === keyName),
        );
        if (!j) return undefined;
        const verdict = j.verdict === "not_credential" ? "stood_down" : j.verdict === "credential" ? "confirmed" : "unsure";
        return { by: "second_opinion" as const, model: soModel, verdict: verdict as "stood_down" | "confirmed" | "unsure" };
      };
      // Decision telemetry rides the resolution line only.
      const telemetry = resolution
        ? {
            ...(isoOrUndefined(record.held_at) === undefined ? {} : { held_at: record.held_at as string }),
            ...(isoOrUndefined(record.decided_at) === undefined ? {} : { decided_at: record.decided_at as string }),
            ...(parseDecidedVia(record.decided_via) === undefined ? {} : { decided_via: parseDecidedVia(record.decided_via) }),
            ...(typeof record.hold_ms === "number" && Number.isFinite(record.hold_ms) ? { hold_ms: Math.round(record.hold_ms) } : {}),
            ...(record.allow_scope === "project" ? { allow_scope: "project" as const } : {}),
          }
        : {};
      for (const raw of record.findings) {
        if (!raw || typeof raw !== "object") continue;
        const finding = raw as Parameters<typeof mintFindingRow>[0];
        if (typeof finding.detector !== "string" || typeof finding.excerpt !== "string") continue;
        // On a mixed record (some detectors held the call, others were only
        // warn-mode) each finding wears what happened to ITS detector.
        const enforced = warnedDetectors.has(finding.detector) ? ("warn" as const) : recordEnforced;
        const label = typeof labels[finding.detector] === "string" ? labels[finding.detector] : undefined;
        const minted = mintFindingRow(finding, {
          // Older guard lines predate the field and can only have come from
          // Claude Code; new shared-bundle lines identify their host.
          source: recordSource,
          origin: "guard",
          session_id: record.session_id,
          ...(typeof record.cwd === "string" && record.cwd !== "" ? { cwd: record.cwd } : {}),
          at,
          enforced,
          resolution,
          ...telemetry,
          ...(label === undefined ? {} : { detector_label: label }),
          ...(() => {
            const assist = secondOpinionAssist(finding.detector, finding.key_name);
            return assist === undefined ? {} : { assist };
          })(),
        });
        const row = this.stampSighting(minted, this.ledger.get(minted.finding_id));
        const existing = this.ledger.get(row.finding_id);
        if (existing) {
          const merged = mergeFinding(existing, { ...row, enforced, resolution });
          this.ledger.set(row.finding_id, merged);
          changed.push(merged);
        } else {
          this.ledger.set(row.finding_id, row);
          changed.push(row);
          if (record.decision === "warn" && enforced === "warn") {
            // A pure-warn call gets the coaching banner instead of a plain
            // findings banner — explicit per-rule choice, never threshold-gated.
            warned.push(row);
          } else if (!held) {
            // A held call is announced by its approval banner (which carries
            // the Allow/Deny buttons); a findings banner alongside it would be
            // the same event twice, a fraction of a second apart.
            brandNew.push(row);
          }
        }
      }
    }
    if (changed.length > 0) {
      this.appendFindings(changed);
      this.deps.onUpdate();
    }
    // Same scope as ingestFindingRows: a hidden rule is recorded, never announced.
    const announce = brandNew.filter((row) => ruleShown(row.detector));
    const coach = warned.filter((row) => ruleShown(row.detector));
    if (announce.length > 0) this.deps.onNewFindings(announce);
    if (coach.length > 0) this.deps.onWarned?.(coach);
  }

  // ---- retention ----------------------------------------------------------------

  private retentionCutoffMs(): number | undefined {
    const days = this.deps.retentionDays();
    if (!days || days <= 0) return undefined;
    return Date.now() - days * 86_400_000;
  }

  private retentionCutoffIso(): string | undefined {
    const ms = this.retentionCutoffMs();
    return ms === undefined ? undefined : new Date(ms).toISOString();
  }

  /** Drop turns older than the window. Returns true when anything was pruned. */
  pruneRetention(): boolean {
    const cutoffMs = this.retentionCutoffMs();
    if (cutoffMs === undefined) return false;
    const cutoffIso = new Date(cutoffMs).toISOString();
    let pruned = false;
    for (const [id, turn] of this.turns) {
      if (turn.at < cutoffIso) {
        this.turns.delete(id);
        pruned = true;
      }
    }
    return pruned;
  }

  /** Re-apply retention immediately (a Settings change shouldn't wait 6h). */
  applyRetentionNow(): void {
    if (this.pruneRetention()) {
      this.rebuildIndex();
      this.rewriteStores();
    }
    // A widened window needs files re-read that the cutoff skipped.
    this.cursors.clear();
    this.scheduleScan();
    this.deps.onUpdate();
  }

  // ---- search + reads -------------------------------------------------------------

  private indexTurn(turn: LedgerTurn): void {
    const parts = [turn.text ?? "", (turn.tools ?? []).join(" "), turn.model ?? ""];
    const text = parts.join(" ").trim();
    if (text !== "") indexDocument(this.index, turn.id, text);
  }

  private rebuildIndex(): void {
    this.index = createIndex();
    for (const turn of this.turns.values()) this.indexTurn(turn);
  }

  search(query: string, limit = 50): LedgerTurn[] {
    const ids = searchIndex(this.index, query);
    const hits: LedgerTurn[] = [];
    for (const id of ids) {
      const turn = this.turns.get(id);
      if (turn && this.sessionOnDisk(turn.source, turn.session_id)) hits.push(turn);
    }
    hits.sort((a, b) => (a.at < b.at ? 1 : a.at > b.at ? -1 : 0));
    return hits.slice(0, limit);
  }

  sessionTurns(sessionId: string, offset = 0, limit = 50): { turns: LedgerTurn[]; total: number } {
    const all: LedgerTurn[] = [];
    for (const turn of this.turns.values()) {
      if (turn.session_id === sessionId) all.push(turn);
    }
    all.sort((a, b) => (a.at < b.at ? -1 : a.at > b.at ? 1 : 0));
    return { turns: all.slice(offset, offset + limit), total: all.length };
  }

  /** Fingerprints of the values redaction removes from `raw` — the vault's
   * keyed hashes, so a ledger export and a detection name one value alike.
   * The cap's `[redacted:cut]` word is not one: nothing matched it.
   * Empty without a vault. */
  fingerprintsOf(raw: string, masked: string = maskTurnText(raw)): SecretFingerprint[] {
    const vault = this.deps.vault;
    if (!vault) return [];
    const secrets = alignRedactedValues(raw, masked).filter((s) => s.label !== CUT_LABEL);
    return secrets.length === 0 ? [] : vault.fingerprints(secrets);
  }

  /** Every stored turn grouped by session, oldest first — one pass, for the
   * ledger export (sessionTurns per session would scan the store each time). */
  turnsBySession(): Map<string, LedgerTurn[]> {
    const out = new Map<string, LedgerTurn[]>();
    for (const turn of this.turns.values()) {
      const list = out.get(turn.session_id);
      if (list) list.push(turn);
      else out.set(turn.session_id, [turn]);
    }
    for (const list of out.values()) list.sort((a, b) => (a.at < b.at ? -1 : a.at > b.at ? 1 : 0));
    return out;
  }

  /** The sessions the Ledger lists — those whose transcript is still on disk
   *; the turns of a deleted transcript stay in the store, unlisted,
   * until retention prunes them or the file comes back. */
  sessions(): SessionSummary[] {
    const listed: LedgerTurn[] = [];
    for (const turn of this.turns.values()) if (this.sessionOnDisk(turn.source, turn.session_id)) listed.push(turn);
    return groupSessions(listed, this.titles);
  }

  /** The RAW stored text of one turn — the ledger shows redacted text by
   * default and asks for this on an explicit click. Local display only. */
  turnRaw(turnId: string): { ok: true; text: string } | { ok: false } {
    const turn = this.turns.get(turnId);
    if (!turn || typeof turn.text !== "string") return { ok: false };
    return { ok: true, text: turn.text };
  }

  /**
   * The transcript files a session was parsed out of, located by NAME rather
   * than by a persisted map: Claude Code writes `<sessionId>.jsonl` (its
   * `agent-*.jsonl` subagent siblings carry the parent's session id on their
   * lines), Codex encodes the id in the rollout filename. Name-addressable
   * means this works after a restart without re-scanning everything.
   */
  private sessionTranscriptFiles(sessionId: string, source: FindingSource): string[] {
    // A REGISTERED source names its own documents: `sessionIdOf` when the host
    // encodes the id in the path, otherwise every document it has (the reveal
    // filters by session id after parsing anyway).
    const descriptor = this.registry.find((s) => s.id === source);
    if (descriptor) {
      const documents = this.sourceDocuments(descriptor);
      const named = documents.filter((path) => {
        try {
          return descriptor.sessionIdOf(path) === sessionId;
        } catch {
          return false;
        }
      });
      return named.length > 0 ? named : documents;
    }
    // A hook-only host (guarded, not metered) has no transcript at all — say so
    // by finding nothing, rather than reading Claude Code's tree in its name.
    if (source !== "claude-code" && source !== "codex") return [];
    const root = source === "codex" ? this.deps.codexSessionsDir : this.deps.claudeProjectsDir;
    if (!existsSync(root)) return [];
    let entries: string[];
    try {
      entries = (readdirSync(root, { recursive: true }) as string[]).filter((p) =>
        p.endsWith(".jsonl"),
      );
    } catch {
      return [];
    }
    const files: string[] = [];
    if (source === "codex") {
      for (const rel of entries) {
        const name = rel.split("/").pop() ?? rel;
        if (rolloutSessionId(name) === sessionId) files.push(join(root, rel));
      }
      return files;
    }
    const dirs = new Set<string>();
    for (const rel of entries) {
      const name = rel.split("/").pop() ?? rel;
      if (name === `${sessionId}.jsonl`) {
        files.push(join(root, rel));
        dirs.add(rel.slice(0, rel.length - name.length));
      }
    }
    for (const rel of entries) {
      const name = rel.split("/").pop() ?? rel;
      if (name.startsWith("agent-") && dirs.has(rel.slice(0, rel.length - name.length))) {
        files.push(join(root, rel));
      }
    }
    return files;
  }

  /**
   * The RAW window the masked excerpt stands for, on an explicit click: the
   * evidence vault's copy of THIS sighting when it has one (Keychain-encrypted,
   * lib/evidence-vault.ts), else a fresh re-read of the transcript, which is
   * then kept in the vault. The ledger's copy stays masked either way.
   */
  revealFinding(findingId: string): RevealResult {
    const row = this.ledger.get(findingId);
    if (!row) return { ok: false, error: "Finding not found." };
    if (row.sandbox !== undefined) {
      const local = sandboxLocalId(row.finding_id, row.sandbox);
      return { ok: false, error: `The evidence stays in sandbox ${row.sandbox}: \`sbx exec ${row.sandbox} doorman findings show ${local} --evidence\` reads it there.` };
    }
    const result = this.reveal(row);
    // What the click found is a verdict too: a card whose raw
    // window could not be produced does not stay up to fail again.
    if (this.judgedByEvidence(row) && this.recordVerdict(row, result.ok, this.documentsCursor(this.evidenceDocuments(row)))) {
      this.persistShown();
      this.deps.onUpdate();
    }
    return result;
  }

  /**
   * The Reveal proper, over a row: what VIEW RAW returns and what the
   * evidence judge asks — one routine, so the two can never
   * disagree. `prepared` lets the judge list a session's documents and parse
   * each once for many rows.
   */
  private reveal(row: FindingRow, prepared: { documents?: string[]; parsed?: Map<string, DetectUnit[] | undefined> } = {}): RevealResult {
    // What the vault kept when the detection fired comes first: it is the
    // evidence as reported, and it survives the transcript being rotated or
    // deleted. The account is recomputed (it is derived, never kept).
    // The vault is asked for THIS card's sighting — the one whose excerpt the
    // card shows — never merely the newest of the finding's, which after a
    // merge can be a different call holding a different credential.
    const kept = this.deps.vault?.get(row.finding_id, row.excerpt);
    if (kept) {
      const { vaulted_at: _vaultedAt, account: keptAccount, ...evidence } = kept;
      const account = keptAccount ?? row.account;
      return { ok: true, ...evidence, ...(account === undefined ? {} : { account }), evidence_source: "vault" };
    }
    // Config-anchored rows have no transcript — the evidence is the config
    // file itself, re-read and re-scanned so a since-edited file says so.
    if (row.origin === "config") return this.configEvidence(row);
    if (!row.session_id) {
      return { ok: false, error: "No session is recorded for this finding, so its transcript can't be located." };
    }
    const files = prepared.documents ?? this.sessionDocuments(row.session_id, row.source);
    if (files.length === 0) {
      return { ok: false, error: "The transcript for this session is no longer on disk." };
    }
    const scored = this.reproduceSighting(row, this.sessionUnits(row.session_id, row.source, files, prepared.parsed));
    const evidence = scored?.evidence;
    if (!scored || !evidence) {
      // The file is here but re-running the detectors over it does not find
      // this sighting: the line was written in a shape the parser skips, the
      // transcript was compacted or scrubbed, or the rule has changed since.
      // A call the guard refused never reaches here — the screens offer no
      // Reveal for it (lib/findings.ts evidenceReadable).
      return {
        ok: false,
        error: "Couldn't find this sighting in the transcript on disk — the file is there, but reading it back doesn't reproduce what was reported.",
      };
    }
    // Reproduced from the transcript: keep it now, so the next Reveal no
    // longer depends on the file still being there (a row minted before the
    // vault existed, or by the guard, gets its evidence this way). Only an
    // EXACT reproduction is kept: a near match is shown, never stored as the
    // evidence behind this card's excerpt.
    if (scored.exact) this.deps.vault?.put(row.finding_id, row.excerpt, evidence, row.last_seen_at);
    return { ok: true, ...evidence, evidence_source: "transcript" };
  }

  /** A config row's evidence: its file, re-read and re-scanned, the window
   * centred on the pattern. What Reveal shows and what the evidence judge
   * asks, so the two can never disagree. */
  private configEvidence(row: FindingRow): ({ ok: true } & RawEvidence) | { ok: false; error: string } {
    const path = row.target;
    if (!path) return { ok: false, error: "No config path is recorded for this finding." };
    let contents: string;
    try {
      contents = readFileSync(path, "utf8");
    } catch {
      return { ok: false, error: "The config file this finding came from is no longer readable." };
    }
    const still = scanMcpConfigText(contents, path);
    const match = still.find((f) => f.key_name === (row.key_name ?? "") || maskText(f.key_name ?? "") === (row.key_name ?? ""));
    if (!match) {
      return { ok: false, error: "The pattern no longer matches — the config appears to have been edited." };
    }
    // Centre the raw window on the matched pattern rather than the file head:
    // ~/.claude.json can be hundreds of KB of history before the mcpServers block.
    const patternName = (row.key_name ?? "").split(" · ", 1)[0] ?? "";
    const pattern = MCP_POISON_PATTERNS.find(([name]) => name === patternName)?.[1];
    const hit = pattern ? pattern.exec(contents) : null;
    const centered = hit
      ? {
          raw: contents.slice(
            Math.max(0, hit.index - RAW_EVIDENCE_MAX_CHARS / 2),
            hit.index + RAW_EVIDENCE_MAX_CHARS / 2,
          ),
          truncated: contents.length > RAW_EVIDENCE_MAX_CHARS,
        }
      : rawWindow(contents, undefined);
    return { ok: true, ...centered, tool_name: row.tool_name, target: path, at: row.last_seen_at, secrets: [], evidence_source: "config" };
  }

  /**
   * SECRET TRACE (lib/secret-trace.ts): everywhere `value` appears in what
   * the agents on this Mac wrote — every transcript document on disk, all
   * time, plus the local turn store (which keeps a turn's text after the
   * transcript it came from is gone). A literal search, never a lookup: the
   * ledger holds no value, and its fingerprints are keyed HMACs of the values
   * a detection caught — not an index of every value the agents wrote — so the
   * same re-read the reveal does for one finding runs here over every file.
   *
   * The value is held only for the duration of the call and is never logged;
   * what comes back carries its shape (length, tail, family) and the places.
   * Yields between files — this runs on the main thread, like the dry run.
   */
  async traceSecret(
    value: string,
    onProgress?: (progress: { done: number; total: number }) => void,
  ): Promise<TraceReport> {
    const forms = literalForms(value);
    const containsValue = (text: string) => forms.some((f) => text.includes(f));
    const sightings: RawSighting[] = [];
    const files: Array<{ path: string; source: string }> = [];
    const home = this.deps.home ?? homedir();

    // The turn store first: prompts and replies survive here after a
    // transcript is pruned or deleted, and an assistant's own prose is not a
    // detect unit at all.
    for (const turn of this.turns.values()) {
      if (typeof turn.text !== "string" || !containsValue(turn.text)) continue;
      sightings.push({
        session_id: turn.session_id,
        turn_id: turn.id,
        at: turn.at,
        source: turn.source,
        kind: turn.role === "user" ? "prompt" : "assistant",
        ...(turn.cwd === undefined ? {} : { cwd: turn.cwd }),
        occurrences: countOccurrences(turn.text, value),
      });
    }

    const documents = this.recentTranscriptFiles(Number.POSITIVE_INFINITY);
    let done = 0;
    onProgress?.({ done, total: documents.length });
    for (const { path, source, descriptor } of documents) {
      done += 1;
      let parsed: { detect: DetectUnit[] } | undefined;
      if (descriptor) {
        // A registered source's document may be a database — no raw text to
        // pre-filter on, so it is parsed and its units read.
        parsed = this.parseForDryRun(path, source, descriptor);
      } else {
        // A native JSONL document is read once and parsed only when the raw
        // bytes carry the literal — a read of every file, a parse of the few.
        let contents: string;
        try {
          contents = readFileSync(path, "utf8");
        } catch {
          continue;
        }
        if (!containsValue(contents)) {
          if (done % 25 === 0) {
            onProgress?.({ done, total: documents.length });
            await new Promise<void>((resolve) => setImmediate(resolve));
          }
          continue;
        }
        parsed = this.parseForDryRun(path, source, descriptor);
      }
      let hit = false;
      if (parsed) {
        for (const unit of parsed.detect) {
          if (!containsValue(unit.raw)) continue;
          hit = true;
          sightings.push({
            session_id: unit.session_id,
            turn_id: unit.anchor_turn_id ?? unit.turn_id,
            at: unit.at,
            source,
            kind: unit.kind,
            ...(unit.tool_name === undefined ? {} : { tool_name: unit.tool_name }),
            ...(unit.target === undefined ? {} : { target: unit.target }),
            ...(unit.cwd === undefined ? {} : { cwd: unit.cwd }),
            occurrences: countOccurrences(unit.raw, value),
          });
        }
      }
      if (hit) files.push({ path, source });
      onProgress?.({ done, total: documents.length });
      await new Promise<void>((resolve) => setImmediate(resolve));
    }
    onProgress?.({ done: documents.length, total: documents.length });

    let since: string | undefined;
    for (const turn of this.turns.values()) if (since === undefined || turn.at < since) since = turn.at;
    const sourceLabels = new Set<string>();
    if (this.claudePresent()) sourceLabels.add(sourceLabel("claude-code", this.registry));
    if (this.codexPresent()) sourceLabels.add(sourceLabel("codex", this.registry));
    for (const s of this.presentSources()) sourceLabels.add(s.label);

    return buildTraceReport({
      shape: traceShape(value),
      sightings,
      findings: this.shownFindings(),
      files,
      coverage: {
        turns: this.turns.size,
        files_scanned: documents.length,
        sources: [...sourceLabels],
        ...(since === undefined ? {} : { since }),
        scanned_at: new Date().toISOString(),
      },
      labelOf: (source) => sourceLabel(source as TurnSource, this.registry),
      home,
    });
  }

  /** Triage a whole group at once: one append, one recompute, one broadcast. */
  setFindingStatuses(findingIds: readonly string[], status: FindingStatus): number {
    const changed: FindingRow[] = [];
    for (const id of findingIds) {
      const row = this.ledger.get(id);
      if (!row || row.status === status) continue;
      const next = { ...row, status };
      this.ledger.set(id, next);
      changed.push(next);
    }
    if (changed.length === 0) return 0;
    this.appendFindings(changed);
    this.deps.onUpdate();
    return changed.length;
  }

  setFindingStatus(findingId: string, status: FindingStatus): boolean {
    const row = this.ledger.get(findingId);
    if (!row) return false;
    const next = { ...row, status };
    this.ledger.set(findingId, next);
    this.appendFindings([next]);
    this.deps.onUpdate();
    return true;
  }
}
