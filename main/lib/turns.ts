/**
 * The ledger's data model: one TURN per record, sessions derived by folding.
 *
 * A turn is the billing/attention grain of a coding-agent session: a user
 * prompt, or one assistant response (one Anthropic message id / one Codex
 * token_count settlement). Turns are what the store persists, what full-text
 * search indexes, and what the Security Radar scans — sessions are never
 * stored, always derived, so a re-parse can only converge, not drift.
 */

import { classifySession, type TaskClass } from "./task-class.js";

/** The hosts whose sessions the ledger can hold. The first two are read by the
 * engine directly; the rest arrive through transcript-sources.ts descriptors.
 * Ids match the guard host `source` strings (guard/hosts/*.ts) so a finding
 * and the session it came from name the same rail — except the last two, which
 * are apps no guard adapter can reach (their ids are their shadow-AI catalog
 * ids instead, so the coverage map joins on the same string). */
export type TurnSource =
  | "claude-code"
  | "codex"
  | "cursor"
  | "gemini-cli"
  | "copilot-cli"
  | "claude-desktop"
  | "vscode-copilot"
  // 2026-09-06: the hosts whose
  // sessions the registry reads next. Guard-only hosts (Crush, Kimi Code,
  // Kiro, Factory Droid) have no member here until a parser exists for them.
  | "hermes"
  | "openclaw"
  | "goose"
  | "qwen-code"
  | "grok-build";

/** Settlement of one turn's cost: `subscription` is plan-covered, `credits`
 * is paid overage on top of a plan, `billed` is API-metered spend on the
 * person's own key (a host reporting BYOK), `unknown` is honestly
 * unattributed (never a synonym for billed). Without `billed` the app could
 * not express the one funding mode it sometimes positively knows. */
export type SettlementMode = "subscription" | "credits" | "billed" | "unknown";

export interface TurnUsage {
  input_tokens: number;
  output_tokens: number;
  cache_read_tokens: number;
  cache_write_tokens: number;
  /** SUBSET of cache_write_tokens with the 1-hour TTL (bills 2x input). */
  cache_write_1h_tokens: number;
  web_search_requests: number;
}

export interface LedgerTurn {
  /** Stable dedup key: CC = the Anthropic message id; Codex = session id +
   * cumulative token total (monotonic, so a re-parse mints the same id). */
  id: string;
  source: TurnSource;
  session_id: string;
  role: "user" | "assistant";
  /** ISO instant. */
  at: string;
  model?: string;
  usage?: TurnUsage;
  /** USD, derived locally from the built-in pricing table. Absent when the
   * model is unknown — never silently zero (`cost_unknown` says so). */
  cost?: number;
  cost_unknown?: boolean;
  /** A provider-reported charge, distinct from a local token-price estimate. */
  reported_cost?: number;
  /** A frozen Grok turn can report incomplete usage (e.g. cancelled subagents). */
  usage_incomplete?: boolean;
  settlement?: SettlementMode;
  /** Prompt or assistant text, capped at TURN_TEXT_MAX_CHARS. Local-only:
   * stored on this machine, searched on this machine, never sent anywhere. */
  text?: string;
  /** Tool names invoked in this assistant turn, in call order (capped). */
  tools?: string[];
  cwd?: string;
  git_branch?: string;
}

/**
 * How much of a host's own PLAN allowance is gone — the headroom figure, as
 * distinct from the cost figures on a turn.
 *
 * A subscription host meters the person against a window it alone knows: GitHub
 * Copilot against a monthly request entitlement, Claude Code against its 5-hour
 * and 7-day windows. A transcript parser that sees such a reading hands one of
 * these back, source-agnostically, so the engine has one shape to keep and the
 * app one shape to show. Derived from the host's OWN stated figure — never
 * computed from our token counts, which price a different thing.
 *
 * A reading is a POINT observation, not an accumulation: the newest one wins
 * and readings are never summed (a host's counter is usually account-wide, so
 * adding two would double-count the same requests).
 */
export interface PlanWindowReading {
  source: TurnSource;
  /** When the host stated it. */
  at: string;
  /** 0–100 of the window that actually constrains this host's work. */
  used_percentage: number;
  /** ISO instant the window resets, when the host says. */
  resets_at?: string;
  /** Which window this is, in the host's own words ("chat", "5h"). */
  window_id?: string;
  /** The counts behind the percentage, when the host states them — for the
   * human sentence ("6 of 200"), never for recomputing the percentage. */
  used?: number;
  entitlement?: number;
  /** The host's own verdict, a free string (the PlanLimitSnapshot convention,
   * so provider wording changes never reject a reading). */
  status?: string;
  /** One sentence the app can show as-is. */
  label?: string;
}

/** Cap stored text so a pasted log can't balloon the store; detection scans
 * the full text at ingest before the cap is applied. */
export const TURN_TEXT_MAX_CHARS = 4_000;
export const TURN_TOOLS_MAX = 32;

/** Cap on a tool OUTPUT kept for scanning — matches the detector's own
 * MAX_SCAN_CHARS, so keeping more would only hold memory the scan never
 * reads. Tool outputs are detect units only, never ledger turns. */
export const TOOL_OUTPUT_MAX_CHARS = 64_000;

export type SessionTitleOrigin = "auto_prompt" | "auto_summary";

export interface SessionTitle {
  text: string;
  origin: SessionTitleOrigin;
}

/**
 * Which title wins: a transcript title
 * (`auto_summary`, Claude Code's own ai-title record) outranks and self-replaces;
 * a first-prompt title (`auto_prompt`) never overwrites anything.
 */
export function titleWriteApplies(
  next: SessionTitleOrigin,
  existing: SessionTitleOrigin | undefined,
): boolean {
  if (existing === undefined) return true;
  if (next === "auto_summary") return true;
  return false;
}

export interface SessionSummary {
  id: string;
  source: TurnSource;
  title?: string;
  title_origin?: SessionTitleOrigin;
  cost: number;
  cost_unknown_turns: number;
  input_tokens: number;
  output_tokens: number;
  cache_read_tokens: number;
  cache_write_tokens: number;
  turns: number;
  prompts: number;
  /** Most-used first. */
  models: string[];
  started_at: string;
  ended_at: string;
  cwd?: string;
  git_branch?: string;
  /** Deterministic use-case classification (lib/task-class.ts) — coding,
   * testing, infra, research, … — derived from the session's tool mix + prompt
   * keywords. A local analytics dimension. */
  task?: TaskClass;
  /** Cost-weighted settlement split (USD): covered = subscription,
   * overage = credits, billed = API-metered on the person's own key,
   * unknown = unattributed — cost-weighted, never event- or token-weighted. */
  covered_cost: number;
  overage_cost: number;
  billed_cost: number;
  unknown_cost: number;
  /** The same split, token-weighted (input+output) — what the ledger's split
   * line shows; the cost split stays for the engine. */
  covered_tokens: number;
  overage_tokens: number;
  billed_tokens: number;
  unknown_tokens: number;
  /** Open radar findings anchored to this session — filled at snapshot time
   * (the fold itself doesn't know about findings). */
  alerts?: number;
  /** The newest turn's role and whether it invoked tools — what the live
   * sessions rail reads to say "waiting for you" (the assistant answered in
   * text and stopped) rather than "working" (a tool run is in flight). */
  last_role?: "user" | "assistant";
  last_turn_tools?: number;
  /** The host's documented resume command for this session (`claude --resume
   * <id>`), filled at snapshot time — the ledger's Continue button shows
   * only when one exists. lib/terminal-handoff.ts. */
  resume_command?: string;
}

export interface TitleRecord {
  session_id: string;
  title: SessionTitle;
}

/** Fold turns (any order) into per-session summaries, newest activity first. */
export function groupSessions(
  turns: readonly LedgerTurn[],
  titles: ReadonlyMap<string, SessionTitle>,
): SessionSummary[] {
  const byId = new Map<string, SessionSummary & { modelCounts: Map<string, number> }>();
  // Turns per session, kept only to classify the use-case at finalize —
  // classification reads the tool mix + prompt text the fold doesn't retain.
  const turnsById = new Map<string, LedgerTurn[]>();
  for (const turn of turns) {
    const list = turnsById.get(turn.session_id);
    if (list) list.push(turn);
    else turnsById.set(turn.session_id, [turn]);
    let s = byId.get(turn.session_id);
    if (!s) {
      s = {
        id: turn.session_id,
        source: turn.source,
        cost: 0,
        cost_unknown_turns: 0,
        input_tokens: 0,
        output_tokens: 0,
        cache_read_tokens: 0,
        cache_write_tokens: 0,
        turns: 0,
        prompts: 0,
        models: [],
        started_at: turn.at,
        ended_at: turn.at,
        covered_cost: 0,
        overage_cost: 0,
        billed_cost: 0,
        unknown_cost: 0,
        covered_tokens: 0,
        overage_tokens: 0,
        billed_tokens: 0,
        unknown_tokens: 0,
        modelCounts: new Map(),
      };
      byId.set(turn.session_id, s);
    }
    if (turn.at < s.started_at) s.started_at = turn.at;
    if (turn.at >= s.ended_at) {
      s.ended_at = turn.at;
      s.last_role = turn.role;
      s.last_turn_tools = turn.tools?.length ?? 0;
    }
    s.cwd ??= turn.cwd;
    s.git_branch ??= turn.git_branch;
    if (turn.role === "user") {
      s.prompts += 1;
      continue;
    }
    s.turns += 1;
    if (turn.model) s.modelCounts.set(turn.model, (s.modelCounts.get(turn.model) ?? 0) + 1);
    if (turn.usage) {
      s.input_tokens += turn.usage.input_tokens;
      s.output_tokens += turn.usage.output_tokens;
      s.cache_read_tokens += turn.usage.cache_read_tokens;
      s.cache_write_tokens += turn.usage.cache_write_tokens;
    }
    if (turn.cost_unknown) s.cost_unknown_turns += 1;
    const cost = turn.cost ?? 0;
    const tokens = turn.usage ? turn.usage.input_tokens + turn.usage.output_tokens : 0;
    s.cost += cost;
    switch (turn.settlement) {
      case "subscription":
        s.covered_cost += cost;
        s.covered_tokens += tokens;
        break;
      case "credits":
        s.overage_cost += cost;
        s.overage_tokens += tokens;
        break;
      case "billed":
        s.billed_cost += cost;
        s.billed_tokens += tokens;
        break;
      default:
        s.unknown_cost += cost;
        s.unknown_tokens += tokens;
        break;
    }
  }
  const out: SessionSummary[] = [];
  for (const s of byId.values()) {
    const { modelCounts, ...summary } = s;
    summary.models = [...modelCounts.entries()]
      .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
      .map(([model]) => model);
    summary.task = classifySession(turnsById.get(s.id) ?? []);
    const title = titles.get(s.id);
    if (title) {
      summary.title = title.text;
      summary.title_origin = title.origin;
    }
    out.push(summary);
  }
  out.sort((a, b) => (a.ended_at < b.ended_at ? 1 : a.ended_at > b.ended_at ? -1 : a.id.localeCompare(b.id)));
  return out;
}

/**
 * Deterministic session title from the first prompt, applied to text that the
 * caller has ALREADY redacted (redact-before-truncate, so a secret can't
 * survive by straddling the cut). Returns undefined for slash/shell commands
 * so a junk title never blocks a later real one.
 */
export const AUTO_TITLE_MAX_LENGTH = 80;
const DECLARATION_LINE_RE = /^\s*(feature|feat|issue):\s*(.+)$/i;

export function deriveAutoTitle(redactedPrompt: string): string | undefined {
  let pastHeader = false;
  for (const rawLine of redactedPrompt.split(/\r\n|\r|\n/)) {
    if (!pastHeader && DECLARATION_LINE_RE.exec(rawLine)?.[2]?.trim()) continue;
    pastHeader = true;
    const line = rawLine.replace(/\s+/g, " ").trim();
    if (!line) continue;
    if (line.startsWith("/") || line.startsWith("!")) return undefined;
    if (/^\[redacted(?::[a-z0-9_]+)?\]( \[redacted(?::[a-z0-9_]+)?\])*$/i.test(line)) continue;
    if (line.length <= AUTO_TITLE_MAX_LENGTH) return line;
    const cut = line.slice(0, AUTO_TITLE_MAX_LENGTH);
    const lastSpace = cut.lastIndexOf(" ");
    // Only break at the word boundary when it doesn't gut the title.
    return `${lastSpace > AUTO_TITLE_MAX_LENGTH / 2 ? cut.slice(0, lastSpace) : cut}…`;
  }
  return undefined;
}
