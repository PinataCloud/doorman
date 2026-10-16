/**
 * One AppState snapshot is the only thing that crosses to the renderer, and
 * every mutation broadcasts it to BOTH the window and the tray — which is why
 * they can never disagree (same contract as main/state.ts).
 *
 * The store itself does no I/O: prefs read/write and the broadcast are
 * dependency-injected, which keeps it testable and keeps every filesystem
 * decision in index.ts where the paths live.
 */

import { CONFIDENCE_BANDS, type FindingConfidence, type FindingRow, type RadarSummary, type RuleStatsWindow, type WindowStats } from "./lib/findings.js";
import type { GuardIntegrityReport } from "./lib/guard-integrity.js";
import type { GuardHostSummary } from "./enforcement.js";
import { parseCustomRules } from "./guard/custom-rules.js";
import { RULE_PACKS, RULE_PACK_IDS, defaultEnabledPacks } from "./guard/rule-packs.js";
import type { SpendGraphs } from "./lib/spend.js";
import type { PlanWindowReading } from "./lib/turns.js";
import type { SessionSummary } from "./lib/turns.js";
import { emptyLiveState, type LiveState } from "./lib/live-sessions.js";
import {
  ALL_DETECTORS,
  DEFAULT_MODES,
  SECURITY_LEVELS,
  defaultPolicy,
  levelModes,
  levelOfModes,
  normalizeConfirm,
  normalizeWallets,
  parseIgnoreRule,
  parseMcpPermissions,
  type EnforcementMode,
  type GuardPolicy,
  type SecurityLevel,
  normalizeSecondOpinion,
  normalizeInjectionClassifierConfig,
  type InjectionModelId,
} from "./guard/policy.js";
import type { InjectionModelFallback } from "./lib/injection-model-choice.js";
import type { SecurityDetectorId } from "./guard/security-detect.js";
import { DETECTOR_GUIDANCE } from "./lib/ai-guidance.js";
import type { ApprovalRequest } from "./guard/handshake.js";
import type { McpInventoryState } from "./lib/mcp-inventory.js";
import type { ShadowAiState } from "./lib/shadow-ai.js";
import type { McpHostStatus } from "./mcp-install.js";
import type { EditorExtensionStatus } from "./vscode-ext-install.js";

export interface McpServerState {
  enabled: boolean;
  hosts: McpHostStatus[];
  /** Why the last register/unregister could not touch a document. */
  error?: string;
}

/** The VS Code companion extension (vscode-ext-install.ts): the switch, and
 * per editor build whether it is here, drivable, and which version it has. */
export interface EditorExtensionState {
  enabled: boolean;
  hosts: EditorExtensionStatus[];
  /** Why the last install/removal could not reach an editor. */
  error?: string;
}
import type { DoctorState } from "./lib/doctor.js";

/** Minimum severity band that fires a macOS notification. */
export type NotifyThreshold = "off" | "critical" | "high" | "medium";

/** What the menu-bar title shows beside the glyph. */
export type TrayDisplay = "spend" | "alerts" | "none";

/** How often a digest lands: 09:00 every day, or Monday 09:00. The two
 * digests carry one each, so a person can have security daily and spend
 * weekly. */
export type DigestPeriod = "daily" | "weekly";

/**
 * One saved rule set: the mode map and the packs as they stood, under a name
 * the person gave them.
 *
 * It carries `level` as well as `modes` so a restored set can say what it was
 * a variation OF — a set saved off Protective that restores while the control
 * reads Locked down would otherwise be un-placeable. `null` is a set that
 * matched no level even when it was saved.
 */
export interface SavedRuleSet {
  id: string;
  name: string;
  /** ISO-8601, and the list's sort key. */
  saved_at: string;
  level: SecurityLevel | null;
  modes: Partial<Record<SecurityDetectorId, EnforcementMode>>;
  packs: string[];
}

/** How many saved sets are kept. The prefs file is read on every boot and
 * written on every change; an unbounded list of thirty-key maps is a slow leak
 * into it. Saving past the cap drops the OLDEST, which is the one the person
 * is least likely to be holding on to. */
export const SAVED_RULE_SETS_MAX = 20;

/** Longest name a saved set may carry. Long enough for "Before the security
 * audit", short enough that the Advanced list stays one line per set. */
export const SAVED_RULE_SET_NAME_MAX = 60;

export interface Prefs {
  /** Days of turns kept locally. 0 = keep everything. */
  retention_days: number;
  notify_findings: NotifyThreshold;
  /** The spend digest, and how often it lands. One switch and one period
   * rather than a boolean per period: `notify_daily_digest` +
   * `notify_weekly_digest` could express "both", which sent two banners about
   * the same money and which nobody chose on purpose. Legacy files fold into
   * this on read (see parsePrefs). */
  notify_spend_digest: boolean;
  spend_digest_period: DigestPeriod;
  /** One digest banner when the app starts (after the first scan) — doubles as
   * the notification-delivery check, so Settings can say "delivering" without
   * anyone pressing Test. */
  notify_startup_digest: boolean;
  /** Banner for a HELD tool call. Default on — the floating panel is the real
   * prompt either way, so turning this off silences the banner, not the hold. */
  notify_held: boolean;
  /** Coaching banner for a warn-mode rule (default on). Never severity-gated —
   * a warn is an explicit per-rule choice, so its heads-up isn't optional the
   * way threshold findings are; this only silences the banner, not the record. */
  notify_coaching: boolean;
  /** Register Doorman's own MCP server with the MCP-capable agents on this
   * Mac (mcp-install.ts), so an agent can ask the guard before it acts. Off by
   * default: it writes into the hosts' shared MCP configs. */
  mcp_answers: boolean;
  /** Install Doorman's companion extension into the VS Code builds on this
   * Mac (vscode-ext-install.ts), so spend, the guard's state and a held tool
   * call appear in the editor. Off by default: it installs software into
   * someone else's application. */
  vscode_extension: boolean;
  /** MCP servers the person has marked "I recognize this" — the local half of
   * approved-server list livePolicy() hands the guard. Lets the
   * unknown_mcp_server radar rule tell a known server from a new one. */
  mcp_recognized: string[];
  /** The one-time "the OS is dropping our notifications" alert has fired.
   * Not a user-facing setting: persisted so the alert survives restarts as
   * ONCE, and reset by any later check that finds delivery working — so a new
   * blocked episode (permission revoked months later) alerts once again. */
  notify_blocked_alerted: boolean;
  /** The version that ran last. On boot a difference means an update installed
   * itself since — the one in-window "Updated to vX" notice comes from this. */
  last_run_version?: string;
  /** The window was open (or the person asked for the check) when the update
   * restarted the app — bring it back once, then clear. */
  reopen_after_update?: boolean;
  /** Menu-bar title: today's spend, open exposures to review, or glyph only. */
  tray_display: TrayDisplay;
  /** The enforcement policy — also written to the guard's policy.json. */
  policy: GuardPolicy;
  /**
   * The person turned the guard ON through this app (or it was found installed
   * at boot). What lets the integrity check tell "someone removed the guard's
   * entry" from "the person switched it off": a missing entry is only
   * tampering when this says it should be there. Cleared by the app's own
   * uninstall, never by the watcher.
   */
  guard_wanted: boolean;
  /** Shipped rule packs (guard/rule-packs.ts) switched on. Absent in an older
   * prefs file = the packs' own defaults. */
  rule_packs_enabled: string[];
  /**
   * The security level this Mac is ON — where the dot sits on the
   * four-stop control.
   *
   * Stored rather than derived, even though `levelOfModes` can read a level
   * straight out of `policy.modes`, because the two answer different
   * questions. Derivation says which level the modes ARE; this says which one
   * the person CHOSE. Hand-edit one rule and the modes are no longer any
   * level — the control then reads "Custom", but it still has to know which
   * stop to draw the dot on, and which level the edit is a departure FROM (the
   * count the confirm sheet puts in front of you before it overwrites).
   *
   * Absent in an older prefs file: read back as whatever the modes already
   * are, so an install that never touched a rule lands on Protective and one
   * that drifted lands on Custom, without either being asked.
   */
  security_level?: SecurityLevel;
  /**
   * Rule sets saved by hand, newest first.
   *
   * Moving the level OVERWRITES every mode, which is the whole point of a
   * preset — so the confirm offers to save what is about to be lost, and this
   * is where it goes. Nothing writes here on its own: an automatic snapshot on
   * every move would fill the list with sets nobody named and nobody wants.
   */
  saved_rule_sets: SavedRuleSet[];
  /** When each recognized MCP server was recognized — so a tool description
   * that changes AFTER that moment can un-recognize it (the rug pull). */
  mcp_recognized_at: Record<string, string>;
  /** The security digest: held / denied / new rules / new servers / new
   * destinations over the period. 09:00 daily, or Monday 09:00 weekly. */
  notify_security_digest: boolean;
  security_digest_period: DigestPeriod;
  /**
   * Show the exposures a person has judged FALSE POSITIVE.
   *
   * Off by default: a false positive is the one verdict that says "this was
   * never a finding", so the Radar's whole feed and the Event Ledger's inline
   * cards leave them out unless asked. The rows stay in the ledger with their
   * verdict, still reopenable, and Analytics counts them under `rejected`
   * rather than as sightings. A deep link to one still lands on it.
   */
  show_false_positives: boolean;
  /**
   * The confidence bands the Radar shows — a set, in any order:
   * `high` (rows a rule was sure of), `medium` (the heuristic hits a detector
   * minted at medium and the rows a model stood down to it — the injection
   * classifier and the guard's second opinion leave their reasoning on
   * those), `low`. Never empty: a set that showed nothing would be a Radar
   * with no feed and no way back, so the sanitizer and the menu both keep at
   * least one ticked.
   *
   * Every band by default — "Any confidence" (v5, 2026-10-06; it was
   * `["high"]` from 2026-09-28, when medium was unticked too). A
   * band not here is out of the Radar's feed in BOTH views, and out of the
   * open count the hero, the sidebar badge, the menu bar and the "Needs
   * review" tab print (summarizeFindings' confidence floor). The rows stay
   * in the ledger with their band, still count in Analytics (where "stood
   * down" is its own number), and a deep link to one still lands on it. A
   * re-sighting at high confidence surfaces the row again — the band follows
   * the newest sighting (mergeFinding).
   */
  confidence_bands: FindingConfidence[];
  /**
   * The first-run setup flow should be showing.
   *
   * Set true exactly once, on the FIRST boot of a fresh install — the moment
   * `announceUpdateOutcome` finds no version recorded — and cleared when the
   * flow is finished or skipped. Deliberately left UNSET on every install that
   * predates the flow: an upgrade must never drop someone back into setup for
   * a machine that is already reporting. Anyone who skipped it (or arrived by
   * upgrade) reaches it from the app menu, which sets this true again.
   *
   * Not a "has been onboarded" flag. It records that the flow is OPEN, so the
   * renderer needs no second signal and re-opening is one pref write.
   */
  onboarding_open?: boolean;
  /**
   * Which generation of DEFAULTS this file has seen (`PREFS_DEFAULTS_VERSION`).
   *
   * Prefs persist as a whole object the first time anything is changed, so a
   * shipped default that later moves never reaches an existing install: the
   * old value is already on disk and indistinguishable from a deliberate
   * choice. This lets a default move ONCE — the keys listed under a version
   * take the new default until the file records that version, after which the
   * person's own value (including one that matches the old default) is
   * theirs again and nothing re-applies.
   */
  defaults_v: number;
}

export const RETENTION_CHOICES = [7, 30, 90, 0] as const;

/**
 * The confidence bands NOT ticked — what the snapshot's summary
 * leaves out of its counts, so the hero, the badge and the tray print what
 * the feed shows. The renderer keeps its own copy of this rule
 * (components.jsx `hiddenConfidenceBands`) for the feed and the menu that
 * ticks a band; the two must agree.
 */
export function hiddenConfidenceBands(prefs: Pick<Prefs, "confidence_bands">): FindingConfidence[] {
  return CONFIDENCE_BANDS.filter((b) => !prefs.confidence_bands.includes(b));
}

export function defaultPrefs(): Prefs {
  // The policy default is NOT empty any more — the shown credential rules ship
  // on ask or warn (see guard/policy.ts DEFAULT_MODES). One source of truth.
  return {
    retention_days: 30,
    // CRITICAL ONLY, and nothing on a timer. A banner is an interruption of
    // whatever the person is doing in another app, so the default earns its
    // place only when something is both bad and theirs to act on now: a
    // critical finding, a held call (which is blocking a session), a tampered
    // guard. Everything below that — high/medium findings, the warn-rule
    // coaching banner (the publish pack ships default-on at warn, so it fires
    // on ordinary work), the launch digest, the daily 09:00 spend digest —
    // is a REPORT, and reports belong on a screen the person opens. All of
    // them are one switch away in Settings, and the weekly Monday digest still
    // rolls the week up in one banner.
    notify_findings: "critical",
    notify_spend_digest: false,
    spend_digest_period: "weekly",
    // The launch-time delivery check does NOT depend on this: with the digest
    // off, index.ts runs a silent probe instead, so Settings can still say
    // whether macOS is delivering.
    notify_startup_digest: false,
    notify_held: true,
    notify_coaching: false,
    mcp_answers: false,
    // On by default (v4): the editor companion is how the guard asks in VS
    // Code and how the doctor learns a window's real trust and hook state. An
    // explicit off, made after v4, is kept.
    vscode_extension: true,
    mcp_recognized: [],
    notify_blocked_alerted: false,
    // Glyph only. The menu-bar title is the app's most public surface — it
    // sits in a bar the person shares on every screen share and screenshot —
    // and a running dollar figure there is not something to opt INTO by
    // default. Both numbers are one click away in the menu.
    tray_display: "none",
    policy: defaultPolicy(),
    guard_wanted: false,
    rule_packs_enabled: defaultEnabledPacks(),
    // No `security_level`: it is absent until something sets it, and the read
    // path below derives it from the modes instead. Writing the default here
    // would claim a choice nobody made.
    saved_rule_sets: [],
    mcp_recognized_at: {},
    notify_security_digest: true,
    security_digest_period: "weekly",
    show_false_positives: false,
    confidence_bands: [...CONFIDENCE_BANDS],
    defaults_v: PREFS_DEFAULTS_VERSION,
  };
}

/**
 * Bump this when a shipped default MOVES, and list the keys it governs below.
 *
 * v2 (2026-09-03): `tray_display`
 * spend → none (the menu bar is the app's most public surface, and a running
 * dollar figure there shouldn't be the default).
 *
 * v3 (2026-09-03): notifications tuned down to CRITICAL ONLY —
 * `notify_findings` high → critical, and the three banners that fire on a
 * schedule or on ordinary work rather than on something bad
 * (`notify_coaching`, `notify_startup_digest`, `notify_daily_digest`) default
 * off. An install that had already chosen any of these keeps its choice from
 * v3 onwards; this moves them once.
 *
 * v4 (2026-09-21): `vscode_extension` false → true. The companion is
 * how the guard asks inside VS Code and how the doctor learns a window's real
 * trust and hook state; an install that never found the switch was
 * unguarded in the one surface the guard is meant to cover. Moves EVERY
 * existing install on, and an off chosen from v4 onwards is kept.
 *
 * v5 (2026-10-06): `confidence_bands` ["high"] → every band ("Any
 * confidence"). A stored ["high"] cannot say whether someone chose it or the
 * v4 default wrote it, so EVERY existing install moves once; a set chosen
 * from v5 onwards is kept.
 */
export const PREFS_DEFAULTS_VERSION = 5;

/** Keys whose stored value is ignored until the file records that version.
 *
 * Typed by NAME rather than `keyof Prefs`, because a generation can move the
 * default of a key that a later shape change retires — `notify_daily_digest`
 * folded into `notify_spend_digest` in the digest rework, and v3's decision to
 * turn it off for existing installs still has to apply to the legacy value on
 * the way in, or a pre-v3 file would come back with the daily banner on. */
const DEFAULT_MIGRATIONS: Record<number, readonly string[]> = {
  2: ["tray_display"],
  3: ["notify_findings", "notify_coaching", "notify_startup_digest", "notify_daily_digest"],
  4: ["vscode_extension"],
  5: ["confidence_bands"],
};

/** The prefs file as it may be found ON DISK: the current shape plus the keys
 * a shape change retired but the read path still folds in. Kept as its own
 * type so `Prefs` stays exactly what the app runs on — a retired key that
 * lingers in the live interface gets read somewhere by accident. */
type LegacyPrefs = Partial<Prefs> & {
  /** Retired in the digest rework (2026-09-06) — the two of them fold into
   * `notify_spend_digest` + `spend_digest_period`. */
  notify_daily_digest?: boolean;
  notify_weekly_digest?: boolean;
};

/** Has this file already seen the generation that moved `key`? */
function ownsDefault(raw: LegacyPrefs, key: string): boolean {
  const seen = typeof raw.defaults_v === "number" ? raw.defaults_v : 1;
  for (const [version, keys] of Object.entries(DEFAULT_MIGRATIONS)) {
    if (keys.includes(key) && seen < Number(version)) return false;
  }
  return true;
}

export interface UpdaterState {
  status: "idle" | "checking" | "available" | "downloading" | "downloaded" | "installing" | "error" | "unsupported";
  version?: string;
  message?: string;
  /** A newer version EXISTS and this copy is not it — true from the moment a
   * check finds one until the app restarts into it. Distinct from `status`,
   * which describes what the updater is doing right now: a download that
   * stalls or fails leaves the person outdated with `status: "error"`, and
   * that is exactly when the Updates card has to say so. */
  outdated?: boolean;
  /** Live download progress while `status === "downloading"` (electron-updater's
   * download-progress event) — what the Settings row draws its bar from. */
  progress?: { percent: number; transferred: number; total: number; bytes_per_second: number };
}

export interface SourceStat {
  sessions: number;
  turns: number;
  /** input+output tokens over the rail's sessions. A rail with turns but no
   * tokens is UNMETERED, not idle — several hosts read through the
   * transcript-source registry record no usage at all — and the coverage
   * card says "tokens not reported" rather than showing a confident 0. */
  tokens: number;
  last_at?: string;
}

/** One rail on the snapshot: its totals, plus who it is and whether its host
 * is on this machine. The label comes from the transcript-source registry
 * (main/lib/transcript-sources-registry.ts), so the renderer names a newly
 * registered host without an edit of its own. */
export interface CaptureSourceStatus extends SourceStat {
  id: string;
  label: string;
  /** The host is installed here — the UI says "not installed" rather than
   * showing an empty graph with no explanation. */
  present: boolean;
  /** The host records token counts at all. A source that doesn't is shown as
   * activity ("seen, not metered"), never as $0 of spend. */
  metered: boolean;
}

export interface CaptureStatus {
  status: "starting" | "scanning" | "watching";
  files: number;
  turns: number;
  last_scan_at?: string;
  /** The two native rails, kept as their own booleans because half the app
   * asks about them by name. Every rail — these two included — also appears in
   * `sources` below. */
  claude_code_present: boolean;
  codex_present: boolean;
  /**
   * Per-rail totals, keyed by `TurnSource` (`claude-code`, `codex`, `cursor`,
   * `gemini-cli`, `copilot-cli`, `claude-desktop`, `vscode-copilot`): one entry
   * per rail the ledger can name, in registry order. Keyed by the SAME id a
   * turn, a finding and the shadow-AI catalog use, so a consumer never has to
   * translate between two spellings.
   */
  sources: Record<string, CaptureSourceStatus>;
  /**
   * Totals for sessions one rail carried on behalf of a DIFFERENT app, keyed by
   * shadow-AI catalog id — ChatGPT Desktop's Codex mode today, which writes
   * into `~/.codex/sessions` rather than anywhere of its own. Distinct from
   * `sources` because there is no TurnSource for it: the turns really are Codex
   * turns. They are EXCLUDED from the Codex entry, so the two never
   * double-count the same spend.
   */
  apps?: Record<string, SourceStat>;
}

export interface RadarState {
  summary: RadarSummary;
  /** Newest rows (all statuses); the renderer filters. */
  findings: FindingRow[];
  /** Open findings grouped by the USE CASE of the session they fired in
   * (lib/task-class.ts), most first — "which kind of work is risky". Computed
   * in main because both `findings` and `sessions` are capped in the snapshot,
   * so the renderer cannot do this join honestly itself. */
  alerts_by_task: { task: string; alerts: number; sessions: number }[];
  guard_installed: boolean;
  /** One row per REGISTERED guard host (guard/hosts/index.ts): is the host on
   * this machine, and is the guard's entry in its document? The renderer names
   * hosts from this instead of hard-coding Claude Code and Codex. */
  guard_hosts?: GuardHostSummary[];
  /** Why the last guard sync couldn't reach the hook documents (usually a
   * malformed settings.json the merge refuses to touch). Absent when healthy.
   * Without this, the app would show the policy it WANTS while the guard on
   * disk quietly runs an older one. */
  guard_sync_error?: string;
  /** Per-rule counters over each Analytics window (lib/findings.ts
   * summarizeRuleStats) — computed in main over EVERY stored finding, because
   * the `findings` array above is capped. */
  rule_stats: Partial<Record<RuleStatsWindow, WindowStats>>;
  /** Is the guard's entry still where the app put it, and is the copied bundle
   * still what the app shipped? (lib/guard-integrity.ts) */
  integrity?: GuardIntegrityReport;
}

/** What the UI calls the host OS. The renderer has no `process`, and hardcoding
 * "macOS" into copy means a Windows build ships lies rather than a compile
 * error. Everything platform-specific in the UI reads this. */
export type HostPlatform = "macos" | "windows" | "linux";

/**
 * A message the app needs the person to SEE, delivered in the window itself —
 * the rail of last resort under the OS banner. Main mirrors every findings /
 * digest banner here (so a refused banner still lands somewhere) and posts the
 * one-time "your notifications are blocked" alert. Living in AppState rather
 * than a fire-and-forget IPC event means a notice raised while the window is
 * closed is still there when it reopens.
 */
export interface AppNotice {
  id: string;
  kind: "info" | "warn";
  title: string;
  body: string;
  /** Screen the notice's open action navigates to. */
  nav?: "radar" | "spend" | "ledger" | "settings" | "integrations";
  /** Sticky notices wait for an explicit dismiss; the rest auto-expire. */
  sticky?: boolean;
  /** Override how long this one waits before retiring itself (renderer
   * default: 10s with an action to reach for, 5s without). For the notices
   * that are an acknowledgement rather than a message — "Updated to vX" is
   * read in the time it takes to appear, and outstays its welcome after that. */
  ttl_ms?: number;
  /** Extra action the renderer offers on this notice. */
  action?: "open-notification-settings" | "install-update";
  at: string;
}

/** The id the "an update is ready — update now" notice always carries: every
 * reminder REPLACES the previous one rather than stacking, and the shell can
 * retire it by id the moment the update is no longer pending. */
export const UPDATE_READY_NOTICE_ID = "update-ready";

/**
 * "Update vX is ready" — the one notice that asks for something, so it is a
 * full card: a body that says what happens either way, an **Update now** button
 * wired to the installer, and sticky (it waits for the click or a dismiss,
 * never a timer — a reminder that retires itself before it is read is not a
 * reminder). Raised whenever the app is opened or brought to front while a
 * downloaded update is waiting on the person (see index.ts remindUpdateReady).
 */
export function updateReadyNotice(version: string | undefined, at: string = new Date().toISOString()): AppNotice {
  const label = version ? `v${version}` : "an update";
  return {
    id: UPDATE_READY_NOTICE_ID,
    kind: "info",
    sticky: true,
    title: `Doorman ${label} is ready to install`,
    body: "Update now restarts the app into it in a few seconds. Otherwise it installs on its own the next time this window is out of sight.",
    action: "install-update",
    at,
  };
}

/** Newest-last cap on the notice stack — a burst must never wallpaper the
 * window; the tray and each screen's own numbers carry the full story. */
export const MAX_NOTICES = 4;

/** The id the "an update installed itself" notice always carries, so a second
 * announcement replaces the first rather than stacking. */
export const UPDATED_NOTICE_ID = "updated-version";

/**
 * "Updated to vX" — an acknowledgement, not a message, and shaped like one.
 *
 * It used to carry a sentence about the update and a button to Settings, which
 * made it a full card that sat there for the full ten seconds after an event
 * the person neither asked about nor has to do anything about. Nothing is
 * required of them, nothing was lost, and the version is on the Updates card
 * for anyone who wants it — so: no body, no action (which keeps the card to a
 * single line), and a four-second fuse. It still holds while the pointer is
 * over the stack, like every other notice.
 */
export function updatedNotice(version: string, at: string = new Date().toISOString()): AppNotice {
  return { id: UPDATED_NOTICE_ID, kind: "info", title: `Updated to v${version}`, body: "", ttl_ms: 4_000, at };
}

export interface ModelAssistState {
  injection_classifier: {
    enabled: boolean;
    ready: boolean;
    model: string;
    /** The pinned build of the model that RUNS (model-assets.ts `version`). */
    version: string;
    /** Every pinned file of the model that runs is on disk and recorded as
     * verified against its sha256 pin (lib/model-assets.ts modelStatus). */
    installed: boolean;
    /** The WASM runtime shipped with this build is present. */
    runtime_present: boolean;
    /** A download is in flight — bytes so far and the total. */
    downloading?: { bytes_done: number; bytes_total: number };
    /** The last download attempt of the model that runs failed with this message. */
    download_error?: string;
    /** Which model was selected, which one runs (lib/injection-model-choice.ts). */
    model_choice?: {
      selected: InjectionModelId;
      effective: InjectionModelId;
      /** Why `effective` is not `selected`. */
      fallback?: InjectionModelFallback;
      /** The selected model's last download failure (fallback `download_failed`). */
      selected_error?: string;
      /** DOORMAN_INJECTION_CLASSIFIER_MODEL pins the choice — the control is read-only. */
      env?: boolean;
      /** The selected model is downloading right now. */
      selected_downloading?: boolean;
    };
  };
  second_opinion: { enabled: boolean; model: string };
  /** One of the DOORMAN_INJECTION_CLASSIFIER* / DOORMAN_SECOND_OPINION* variables is set. */
  env: boolean;
}

export interface AppState {
  appVersion: string;
  dataDir: string;
  platform: HostPlatform;
  /** macOS launched this copy from a Gatekeeper translocation mount — the
   * setup flow's first step offers the move to /Applications. */
  translocated: boolean;
  /** The OS refused to deliver a notification (unsigned build, or the person
   * turned them off). The UI says so instead of letting a blocked session look
   * like a frozen agent. */
  notifications_blocked: boolean;
  /** Result of the last explicit permission check (Settings → Notifications).
   * "unknown" until someone asks — macOS has no API to read the state back. */
  notification_check: { status: "unknown" | "ok" | "blocked"; at?: string; error?: string };
  /** In-window notices, oldest first — see AppNotice. */
  notices: AppNotice[];
  /** Tool calls the guard is holding open RIGHT NOW, oldest first. A non-empty
   * queue means a session is stopped mid-flight waiting on this window. */
  approvals: ApprovalRequest[];
  capture: CaptureStatus;
  /** 7-day and 30-day folds — the UI's range toggle picks one. */
  graphs: SpendGraphs;
  graphs30: SpendGraphs;
  /**
   * How much of each host's own PLAN allowance is gone — the headroom question,
   * which the cost folds above cannot answer: a subscription's dollar figure
   * goes flat while the requests it includes run out. One newest reading per
   * rail, from the host's own stated figure (lib/turns.ts PlanWindowReading);
   * a rail that states none simply has no row.
   */
  plan_windows: PlanWindowReading[];
  /** Newest sessions, capped — the full list never crosses the bridge. */
  sessions: SessionSummary[];
  sessions_total: number;
  /** Agents running on this Mac right now, joined to their ledger sessions —
   * the ledger's "Now" rail and the tray's count. lib/live-sessions.ts. */
  live: LiveState;
  radar: RadarState;
  /** MCP servers on this machine — config, usage, poisoning findings, personal
   * allowlist and a shipped risk profile, merged. See lib/mcp-inventory.ts. */
  mcp: McpInventoryState;
  /** Other AI tools installed on this Mac and whether the guard covers them.
   * See lib/shadow-ai.ts. */
  shadow_ai: ShadowAiState;
  /** Doorman's own MCP server (mcp-install.ts): the switch, and per host
   * whether it is here and whether our entry is in its MCP config. */
  mcp_server: McpServerState;
  /** The VS Code companion extension (vscode-ext-install.ts): the switch, and
   * per editor build what it has installed. */
  editor_extension: EditorExtensionState;
  /** The shipped rule packs (guard/rule-packs.ts), for the Rules screen —
   * static per build, carried in the snapshot so the renderer needs no second
   * channel. */
  rule_packs: { id: string; label: string; blurb: string; rules: number; default_on: boolean; default_mode: string }[];
  /** What Doorman ships each detector on (guard/policy.ts DEFAULT_MODES,
   * `observe` where that map is silent) — static per build, carried beside
   * `rule_packs` for the same reason. The Rules screen needs it to say how far
   * this machine has drifted from the shipped defaults, and to grey out the
   * restore button when it hasn't. */
  default_modes: Record<SecurityDetectorId, EnforcementMode>;
  /**
   * Per-detector "what it means" and "what to do about it"
   * (lib/ai-guidance.ts), carried for the same reason as `default_modes`:
   * static per build, and the renderer must not hold a second copy.
   *
   * The Radar's exposure cards read it. It was written for the
   * assistant's prompt, and that is exactly why it suits a card: the same two
   * questions, answered deterministically from the product's own position
   * rather than invented per surface. One table, two readers.
   */
  detector_guidance: Record<string, { blurb: string; fix: string }>;
  /**
   * The whole security-level ladder, carried in the snapshot for the
   * same reason as `default_modes`: static per build, and the renderer must
   * not hold a second copy of it.
   *
   * The Guardrails screen reads this to draw what each stop DOES before you
   * move to it — the per-category outcome bars, the "what's protected" tally,
   * and the rung each rule would land on. A renderer-side mirror of the table
   * would be a table that can disagree with the guard, which is the failure
   * the level is supposed to prevent.
   */
  level_modes: Record<SecurityLevel, Record<SecurityDetectorId, EnforcementMode>>;
  /** The model-assisted rules: what is on, whether the classifier's model is
   * on disk, and whether the environment (not a person) chose — for the
   * Rules screen's per-rule notes. No Settings surface since 2026-09-05. */
  model_assist: ModelAssistState;
  /** The setup doctor's latest report + what it last repaired (lib/doctor.ts). */
  doctor: DoctorState;
  prefs: Prefs;
  updater: UpdaterState;
}

export function hostPlatform(nodePlatform: string): HostPlatform {
  if (nodePlatform === "darwin") return "macos";
  if (nodePlatform === "win32") return "windows";
  return "linux";
}

export interface StoreDeps {
  appVersion: string;
  dataDir: string;
  /** `process.platform`; the Store maps it to a HostPlatform. */
  nodePlatform?: string;
  /** Running from a Gatekeeper translocation mount (lib/hook-health.ts). */
  translocated?: boolean;
  readPrefs(): Partial<Prefs>;
  writePrefs(prefs: Prefs): void;
  onChange(state: AppState): void;
}

function emptyGraphs(days: number): SpendGraphs {
  return {
    cost_days: [],
    token_days: [],
    models: [],
    model_rows: [],
    today_cost: 0,
    today_tokens: 0,
    window_cost: 0,
    window_tokens: 0,
    prev_window_cost: 0,
    prev_window_tokens: 0,
    covered_cost: 0,
    overage_cost: 0,
    billed_cost: 0,
    unknown_cost: 0,
    covered_tokens: 0,
    overage_tokens: 0,
    billed_tokens: 0,
    unknown_tokens: 0,
    unpriced_turns: 0,
    by_task: [],
    time_days: [],
    time_tasks: [],
    time_rails: [],
    window_seconds: 0,
    prev_window_seconds: 0,
    today_seconds: 0,
    window_sessions: 0,
    days,
  };
}

function sanitizePrefs(raw: LegacyPrefs): Prefs {
  const base = defaultPrefs();
  if (typeof raw.retention_days === "number" && (RETENTION_CHOICES as readonly number[]).includes(raw.retention_days)) {
    base.retention_days = raw.retention_days;
  }
  // The four keys v3 tuned down carry an ownsDefault() guard, like
  // tray_display before them: a file written before v3 holds the louder
  // value and cannot be told apart from a deliberate choice, so it is ignored
  // exactly once.
  if (
    (raw.notify_findings === "off" || raw.notify_findings === "critical" || raw.notify_findings === "high" || raw.notify_findings === "medium") &&
    ownsDefault(raw, "notify_findings")
  ) {
    base.notify_findings = raw.notify_findings;
  }
  // The spend digest, from whichever shape the file is in. The new keys win
  // outright; otherwise the retired pair folds in — on if either was on, and
  // DAILY if the daily one was, because that was the deliberate, noisier
  // choice and collapsing it to weekly would quietly take it away. A file with
  // both set loses the duplicate banner, which is the point of the rework.
  if (typeof raw.notify_spend_digest === "boolean") {
    base.notify_spend_digest = raw.notify_spend_digest;
    if (raw.spend_digest_period === "daily" || raw.spend_digest_period === "weekly") {
      base.spend_digest_period = raw.spend_digest_period;
    }
  } else {
    const daily = raw.notify_daily_digest === true && ownsDefault(raw, "notify_daily_digest");
    const weekly = raw.notify_weekly_digest === true;
    if (daily || weekly) {
      base.notify_spend_digest = true;
      base.spend_digest_period = daily ? "daily" : "weekly";
    }
  }
  if (typeof raw.notify_startup_digest === "boolean" && ownsDefault(raw, "notify_startup_digest")) {
    base.notify_startup_digest = raw.notify_startup_digest;
  }
  if (typeof raw.notify_held === "boolean") base.notify_held = raw.notify_held;
  if (typeof raw.notify_coaching === "boolean" && ownsDefault(raw, "notify_coaching")) {
    base.notify_coaching = raw.notify_coaching;
  }
  if (typeof raw.mcp_answers === "boolean") base.mcp_answers = raw.mcp_answers;
  if (typeof raw.vscode_extension === "boolean" && ownsDefault(raw, "vscode_extension")) {
    base.vscode_extension = raw.vscode_extension;
  }
  if (Array.isArray(raw.mcp_recognized)) {
    base.mcp_recognized = raw.mcp_recognized.filter(
      (s): s is string => typeof s === "string" && s.trim() !== "",
    );
  }
  if (typeof raw.notify_blocked_alerted === "boolean") base.notify_blocked_alerted = raw.notify_blocked_alerted;
  if (typeof raw.last_run_version === "string" && raw.last_run_version !== "") base.last_run_version = raw.last_run_version;
  if (typeof raw.reopen_after_update === "boolean") base.reopen_after_update = raw.reopen_after_update;
  if (
    (raw.tray_display === "spend" || raw.tray_display === "alerts" || raw.tray_display === "none") &&
    ownsDefault(raw, "tray_display")
  ) {
    base.tray_display = raw.tray_display;
  }
  if (typeof raw.guard_wanted === "boolean") base.guard_wanted = raw.guard_wanted;
  // Tri-state on purpose (see the field): absent is not the same as false, so
  // this only ever copies a value the file actually carries.
  if (typeof raw.onboarding_open === "boolean") base.onboarding_open = raw.onboarding_open;
  if (Array.isArray(raw.rule_packs_enabled)) {
    base.rule_packs_enabled = raw.rule_packs_enabled.filter(
      (id): id is string => typeof id === "string" && RULE_PACK_IDS.includes(id),
    );
  }
  if (SECURITY_LEVELS.includes(raw.security_level as SecurityLevel)) {
    base.security_level = raw.security_level as SecurityLevel;
  }
  if (Array.isArray(raw.saved_rule_sets)) {
    base.saved_rule_sets = raw.saved_rule_sets
      .map((entry) => parseSavedRuleSet(entry))
      .filter((entry): entry is SavedRuleSet => entry !== undefined)
      .slice(0, SAVED_RULE_SETS_MAX);
  }
  if (raw.mcp_recognized_at && typeof raw.mcp_recognized_at === "object" && !Array.isArray(raw.mcp_recognized_at)) {
    base.mcp_recognized_at = Object.fromEntries(
      Object.entries(raw.mcp_recognized_at as Record<string, unknown>).filter(
        (e): e is [string, string] => typeof e[1] === "string" && Number.isFinite(Date.parse(e[1])),
      ),
    );
  }
  if (typeof raw.notify_security_digest === "boolean") base.notify_security_digest = raw.notify_security_digest;
  if (typeof raw.show_false_positives === "boolean") base.show_false_positives = raw.show_false_positives;
  if (Array.isArray(raw.confidence_bands) && ownsDefault(raw, "confidence_bands")) {
    // Canonical order, known bands only, and never empty.
    const bands = CONFIDENCE_BANDS.filter((b) => (raw.confidence_bands as unknown[]).includes(b));
    if (bands.length > 0) base.confidence_bands = bands;
  }
  // Was nested inside `if (raw.policy) { if (modes) {` — so a prefs file with
  // no policy.modes silently lost its chosen period. Cleaning up as I passed.
  if (raw.security_digest_period === "daily" || raw.security_digest_period === "weekly") {
    base.security_digest_period = raw.security_digest_period;
  }
  if (raw.policy && typeof raw.policy === "object") {
    const modes = raw.policy.modes;
    if (modes && typeof modes === "object") {
      for (const [detector, mode] of Object.entries(modes)) {
        // A mode for a rule outside the catalog (a hidden rule, or a
        // key from some other build) is dropped rather than carried into the
        // snapshot — the renderer and anything connected read prefs whole.
        if (!(ALL_DETECTORS as readonly string[]).includes(detector)) continue;
        if (mode === "warn" || mode === "ask" || mode === "block") {
          base.policy.modes[detector as SecurityDetectorId] = mode as EnforcementMode;
        } else if (mode === "observe") {
          // Explicit observe is KEPT, not dropped: absence now means "take the
          // default", and one of the defaults is ask — so dropping it here would
          // undo the choice on the next round-trip through this function.
          base.policy.modes[detector as SecurityDetectorId] = "observe";
        }
      }
    }
    if (Array.isArray(raw.policy.disabled)) {
      base.policy.disabled = raw.policy.disabled.filter((d: unknown): d is SecurityDetectorId =>
        typeof d === "string" && (ALL_DETECTORS as readonly string[]).includes(d),
      );
    }
    if (Array.isArray(raw.policy.ignore)) {
      base.policy.ignore = raw.policy.ignore
        .map((rule) => parseIgnoreRule(rule))
        .filter((rule): rule is NonNullable<typeof rule> => rule !== undefined);
    }
    if (typeof raw.policy.armed_escalation === "boolean") {
      base.policy.armed_escalation = raw.policy.armed_escalation;
    }
    if (raw.policy.second_opinion && typeof raw.policy.second_opinion === "object") {
      base.policy.second_opinion = normalizeSecondOpinion(raw.policy.second_opinion);
    }
    if (raw.policy.injection_classifier && typeof raw.policy.injection_classifier === "object") {
      base.policy.injection_classifier = normalizeInjectionClassifierConfig(raw.policy.injection_classifier);
    }
    const customRules = parseCustomRules(raw.policy.custom_rules);
    if (customRules.length > 0) base.policy.custom_rules = customRules;
    const permissions = parseMcpPermissions(raw.policy.mcp_permissions);
    if (permissions) base.policy.mcp_permissions = permissions;
    if (typeof raw.policy.mcp_armed_escalation === "boolean") {
      base.policy.mcp_armed_escalation = raw.policy.mcp_armed_escalation;
    }
    if (raw.policy.wallets && typeof raw.policy.wallets === "object") {
      base.policy.wallets = normalizeWallets(raw.policy.wallets);
    }
    base.policy.confirm = normalizeConfirm(raw.policy.confirm);
  }
  /* A file written before levels existed carries modes and no level. Read the
     level out of the modes rather than assuming one: an install that never
     touched a rule lands on Protective (whose map IS `DEFAULT_MODES`), and one
     that drifted lands on Custom — which is what it is. Deliberately NOT
     persisted here; parsePrefs describes the file, and writing a level back
     would turn a derived reading into a recorded choice. */
  if (base.security_level === undefined) {
    const derived = levelOfModes(base.policy.modes);
    if (derived !== null) base.security_level = derived;
  }
  return base;
}

/** One entry of `saved_rule_sets`, or undefined for anything malformed —
 * same posture as `parseIgnoreRule`: a set that cannot be read is dropped, not
 * repaired into something nobody saved. */
function parseSavedRuleSet(raw: unknown): SavedRuleSet | undefined {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return undefined;
  const entry = raw as Record<string, unknown>;
  const id = typeof entry.id === "string" ? entry.id.trim() : "";
  const name = typeof entry.name === "string" ? entry.name.trim() : "";
  const savedAt = typeof entry.saved_at === "string" ? entry.saved_at : "";
  if (id === "" || name === "" || !Number.isFinite(Date.parse(savedAt))) return undefined;
  const modes: Partial<Record<SecurityDetectorId, EnforcementMode>> = {};
  if (entry.modes && typeof entry.modes === "object" && !Array.isArray(entry.modes)) {
    for (const [detector, mode] of Object.entries(entry.modes as Record<string, unknown>)) {
      if (!(ALL_DETECTORS as readonly string[]).includes(detector)) continue;
      if (mode === "observe" || mode === "warn" || mode === "ask" || mode === "block") {
        modes[detector as SecurityDetectorId] = mode;
      }
    }
  }
  return {
    id: id.slice(0, 64),
    name: name.slice(0, SAVED_RULE_SET_NAME_MAX),
    saved_at: savedAt,
    level: SECURITY_LEVELS.includes(entry.level as SecurityLevel) ? (entry.level as SecurityLevel) : null,
    modes,
    packs: Array.isArray(entry.packs)
      ? entry.packs.filter((id): id is string => typeof id === "string" && RULE_PACK_IDS.includes(id))
      : [],
  };
}

export class Store {
  private state: AppState;

  constructor(private readonly deps: StoreDeps) {
    this.state = {
      appVersion: deps.appVersion,
      dataDir: deps.dataDir,
      platform: hostPlatform(deps.nodePlatform ?? process.platform),
      translocated: deps.translocated === true,
      notifications_blocked: false,
      notification_check: { status: "unknown" },
      notices: [],
      approvals: [],
      capture: {
        status: "starting",
        files: 0,
        turns: 0,
        claude_code_present: false,
        codex_present: false,
        // The two native rails, so the first paint before the first scan still
        // has rails to name; the registry fills the rest in on that scan.
        sources: {
          "claude-code": {
            id: "claude-code",
            label: "Claude Code",
            present: false,
            metered: true,
            sessions: 0,
            turns: 0,
            tokens: 0,
          },
          codex: {
            id: "codex",
            label: "Codex",
            present: false,
            metered: true,
            sessions: 0,
            turns: 0,
            tokens: 0,
          },
        },
      },
      graphs: emptyGraphs(7),
      graphs30: emptyGraphs(30),
      plan_windows: [],
      sessions: [],
      sessions_total: 0,
      live: emptyLiveState(),
      radar: {
        summary: {
          open: 0,
          by_severity: { critical: 0, high: 0, medium: 0, low: 0 },
          by_detector: {},
          open_groups: 0,
          by_severity_groups: { critical: 0, high: 0, medium: 0, low: 0 },
          open_exposures: 0,
          by_severity_exposures: { critical: 0, high: 0, medium: 0, low: 0 },
          affected_sessions: 0,
        },
        findings: [],
        alerts_by_task: [],
        guard_installed: false,
        rule_stats: {},
      },
      mcp: { servers: [], recognized_count: 0, stale_recognitions: 0, gatewayed_count: 0 },
      shadow_ai: { tools: [], installed_count: 0, uncovered_installed: 0, guardable_uncovered: 0, active_uncovered: 0, guarded_installed: 0, metered_unguarded: 0, guardable_unguarded: 0, active_unguarded: 0 },
      mcp_server: { enabled: false, hosts: [] },
      editor_extension: { enabled: false, hosts: [] },
      model_assist: {
        injection_classifier: { enabled: true, ready: false, model: "Llama Prompt Guard 2", version: "", installed: false, runtime_present: false },
        second_opinion: { enabled: false, model: "" },
        env: false,
      },
      rule_packs: RULE_PACKS.map((p) => ({
        id: p.id,
        label: p.label,
        blurb: p.blurb,
        rules: p.rules.length,
        default_on: p.default_on,
        default_mode: [...new Set(p.rules.map((r) => r.mode))].join(" / "),
      })),
      default_modes: Object.fromEntries(
        ALL_DETECTORS.map((id) => [id, DEFAULT_MODES[id] ?? "observe"]),
      ) as Record<SecurityDetectorId, EnforcementMode>,
      detector_guidance: DETECTOR_GUIDANCE,
      level_modes: Object.fromEntries(
        SECURITY_LEVELS.map((level) => [
          level,
          Object.fromEntries(
            ALL_DETECTORS.map((id) => [id, levelModes(level)[id] ?? "observe"]),
          ),
        ]),
      ) as Record<SecurityLevel, Record<SecurityDetectorId, EnforcementMode>>,
      doctor: { status: "idle" },
      prefs: sanitizePrefs(deps.readPrefs()),
      updater: { status: "idle" },
    };
  }

  snapshot(): AppState {
    return this.state;
  }

  set(patch: Partial<AppState>): void {
    this.state = { ...this.state, ...patch };
    this.deps.onChange(this.state);
  }

  prefs(): Prefs {
    return this.state.prefs;
  }

  setPrefs(patch: Partial<Prefs>): Prefs {
    const next = sanitizePrefs({ ...this.state.prefs, ...patch });
    this.deps.writePrefs(next);
    this.set({ prefs: next });
    return next;
  }

  setApprovals(approvals: ApprovalRequest[]): void {
    this.set({ approvals });
  }

  setNotificationsBlocked(): void {
    if (!this.state.notifications_blocked) this.set({ notifications_blocked: true });
  }

  /** Same id replaces in place (a re-raised alert must not stack), and the
   * list is capped newest-last. */
  pushNotice(notice: AppNotice): void {
    const others = this.state.notices.filter((n) => n.id !== notice.id);
    this.set({ notices: [...others, notice].slice(-MAX_NOTICES) });
  }

  dismissNotice(id: string): void {
    if (!this.state.notices.some((n) => n.id === id)) return;
    this.set({ notices: this.state.notices.filter((n) => n.id !== id) });
  }

  setNotificationCheck(status: "ok" | "blocked" | "unknown", error?: string): void {
    this.set({
      notification_check: { status, at: new Date().toISOString(), error },
      // A successful test clears a stale refusal — permission can be granted
      // after the fact, and the banner in Settings must not outlive the problem.
      // An undetermined check (silence, not a refusal) leaves the flag alone:
      // it is neither proof the OS delivers nor proof it refuses.
      ...(status === "unknown" ? {} : { notifications_blocked: status === "blocked" }),
    });
  }

  setUpdater(patch: Partial<UpdaterState> & Pick<UpdaterState, "status">): void {
    this.set({ updater: { ...this.state.updater, ...patch } });
  }

  setDoctor(doctor: DoctorState): void {
    this.set({ doctor });
  }
}
