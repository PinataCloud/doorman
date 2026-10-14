/**
 * GitHub Copilot CLI — transcript source (`~/.copilot/session-state/<id>/events.jsonl`).
 *
 * WHAT COPILOT CLI PERSISTS. Every session gets its own directory under the
 * config home's `session-state/`, holding `workspace.yaml` (id, created_at,
 * updated_at, name, user_named, summary_count, fork_count, the persisted cwd)
 * and `events.jsonl` — a newline-delimited log of the runtime's own session
 * events. That JSONL is the same file the CLI hands hooks as `transcriptPath`
 * (`agentStop`), and it is what this reader parses. A second store,
 * `~/.copilot/session-store.db` (SQLite: sessions/turns/checkpoints/…), is a
 * derived INDEX over these files — `/chronicle reindex` rebuilds it from them —
 * so the JSONL is the ground truth and we never open the database.
 *
 * ENVELOPE (schemas/session-events.schema.json, "JSON Schema for session events
 * emitted by the Copilot CLI runtime"):
 *   { id: uuid, timestamp: ISO-8601, parentId: uuid|null, ephemeral?: bool,
 *     agentId?: string, type: "<event type>", data: { … } }
 * `id` is minted once when the event is written, which makes
 * `copilot:<sessionId>:<eventId>` a stable turn id across re-parses (rule 1).
 *
 * THE EVENTS THIS READER USES (139 types exist; these are the ledger-relevant
 * ones):
 *   · `session.start` / `session.resume` — sessionId, selectedModel, and
 *     `context` (WorkingDirectoryContext: cwd, gitRoot, repository, branch,
 *     headCommit); `session.context_changed` carries the same shape on a cd.
 *   · `session.model_change` — newModel.
 *   · `session.title_changed` — the CLI's own generated session title, taken
 *     as an `auto_summary` title (it outranks a first-prompt title, same
 *     precedence as Claude Code's ai-title record).
 *   · `user.message` — `content` (what the human typed) and
 *     `transformedContent` (the XML-wrapped model-facing version, deliberately
 *     ignored). `source` marks a NON-human origin (`skill-pdf` for a hidden
 *     skill injection, `agent-<id>` for an inter-agent prompt) and
 *     `isAutopilotContinuation` an auto-injected one: neither is a prompt turn,
 *     though both are still scanned.
 *   · `assistant.message` — `content`, `messageId`, `toolRequests[]`
 *     ({toolCallId, name, arguments, mcpServerName, mcpToolName}).
 *   · `assistant.usage` — the per-model-call token record: model, inputTokens,
 *     outputTokens, cacheReadTokens, cacheWriteTokens, reasoningTokens,
 *     quotaSnapshots, copilotUsage.totalNanoAiu, isByok.
 *   · `tool.execution_start` / `tool.execution_complete` — toolCallId,
 *     toolName, `arguments` (opaque JSON), shellToolInfo, and the result
 *     (`result.content`, `result.detailedContent`) or `error`.
 *   · `session.shutdown` — the session's own final accounting: totalNanoAiu,
 *     totalPremiumRequests, and `modelMetrics[model].usage` with the four
 *     token buckets. Used only as a fallback (see METERING below).
 *
 * `inputTokens` IS THE TOTAL, NOT THE UNCACHED PART. The CLI's own accounting
 * computes `inputTokensUncached = max(0, inputTokens - cacheReadTokens -
 * cacheWriteTokens)` (app.js, the tokenDetails reducer), so this reader
 * subtracts the two cache buckets out of `inputTokens` before pricing —
 * exactly the correction the Codex rollout reader makes for
 * `cached_input_tokens`. Not doing it would double-bill every cached prompt.
 * `reasoningTokens` is a SUBSET of `outputTokens` and is never added.
 *
 * METERING — honest, and it degrades honestly. `assistant.usage` is the real
 * per-call record; when it is present in the log its token counts price the
 * turn. It is UNVERIFIED whether every build persists it (the relay path in
 * app.js re-emits `assistant.usage` through `emitEphemeral`, and an ephemeral
 * event is by definition "not persisted to the session event log on disk"), so
 * this reader never depends on it:
 *   1. an assistant turn is minted per model call from its `assistant.message`
 *      event id, WITH usage when the call's `assistant.usage` follows it, and
 *      without (cost_unknown) when it does not — same id either way, so a
 *      re-parse of a session that has since settled updates the row instead of
 *      minting a second one;
 *   2. if a whole document carried no usage at all, the session's own
 *      `session.shutdown` totals become one settlement turn PER MODEL
 *      (`copilot:<id>:shutdown:<model>`), which is the host's own final
 *      accounting rather than a guess. Only the last shutdown in a file is
 *      used (its totals are cumulative), and the fallback is skipped entirely
 *      when per-call usage already produced turns, so nothing double-counts.
 * `assistant.message.outputTokens` is deliberately NOT read as usage: a turn
 * priced on output alone would under-report, which is a wrong number rather
 * than a missing one.
 *
 * COST IS DERIVED, NOT REPORTED. Copilot bills the user in premium requests /
 * AI credits — `copilotUsage.totalNanoAiu` (nano-AI units) and
 * `quotaSnapshots[*].overageEntitlement` ("1 credit = $0.01"). We do NOT
 * convert nano-AIU to dollars: the unit's relation to a credit is not
 * documented, and a plausible-looking conversion would be a fabricated number.
 * USD comes from the built-in pricing table applied to the token counts, the
 * same way every other rail in this app derives it.
 *
 * SETTLEMENT follows the quota snapshot riding the usage event, and later
 * turns inherit the last verdict (the Codex rule): entitlement unlimited, or
 * quota still available → `subscription`; quota exhausted with overage
 * allowed/used → `credits`; anything else, and every BYOK call (paid straight
 * to the provider, covered by no Copilot plan), stays `unknown`.
 *
 * MODEL IDS. Copilot's catalog names Anthropic models with dots
 * (`claude-sonnet-4.5`) where the pricing table uses dashes
 * (`anthropic/claude-sonnet-4-5`), so the lookup normalizes dots to dashes for
 * `claude*` only — OpenAI and Google keep their dotted names in the table. The
 * ledger still reports the model exactly as Copilot recorded it.
 *
 * TOOL NAMES are mapped to the Claude Code names every detector keys on, using
 * GitHub's own published table (the same one in guard/hosts/copilot.ts, which
 * this file deliberately does not import — the guard directory is copied into
 * userData and must stay self-contained). An MCP call, which carries
 * `mcpServerName`/`mcpToolName`, is rendered `mcp__<server>__<tool>`; any other
 * unknown name passes through untouched, so a rename upstream loses a mapping,
 * never a detection.
 *
 * SOURCES, all fetched 2026-09-06 (this surface moves — keep the date):
 *  · https://docs.github.com/en/copilot/concepts/agents/copilot-cli/chronicle
 *    ("Every Copilot CLI session is persisted as a set of files in the
 *    `~/.copilot/session-state/` directory"; the session store is "a subset of
 *    the full data stored in the session files")
 *  · https://docs.github.com/en/copilot/how-tos/copilot-cli/use-copilot-cli/chronicle
 *    (`/session`, `copilot --resume [SESSION-ID]`, `--continue`,
 *    `/chronicle reindex` rebuilds the store from the session history)
 *  · https://docs.github.com/en/copilot/reference/hooks-reference
 *    (`sessionStart`/`sessionEnd`/`agentStop` payloads — `transcriptPath` is
 *    the events.jsonl above; the hook rail is a fallback we do not need)
 *  · the published package @github/copilot 1.0.83 (`npm view`, tarball read on
 *    this Mac, never executed): `schemas/session-events.schema.json` — the 139
 *    event definitions quoted above; `app.js` — `$A = "session-state"`, the
 *    copilot-home resolution `[settings.configDir, process.env.COPILOT_HOME,
 *    os.homedir()/.copilot]`, `workspace.yaml`, and the uncached-input
 *    reducer; `copilot-sdk/docs/examples.md` — "session.workspacePath // e.g.
 *    ~/.copilot/session-state/<id>" and the tool-argument shapes
 *    (`arguments.path` for `edit`/`create`).
 *
 * On the machine this was written on, `~/.copilot` held config.json, logs/,
 * ide/ and hooks/ but NO session-state directory (the CLI had only been
 * launched once, in stdio server mode, and writes a session directory per
 * interactive session), so the fixtures are SYNTHETIC documents shaped by the
 * schema above rather than captured transcripts — see
 * test/fixtures/transcripts/copilot/_provenance.json.
 */

/*
 * METERING, SECOND SOURCE (2026-09-08). `assistant.usage` is indeed NOT
 * persisted by CLI 1.0.83 (0 of 10 model calls on this Mac), so the reader
 * above lived on the shutdown fallback. But the sibling
 * `~/.copilot/session-store.db` is not only a derived index: its
 * `assistant_usage_events` table holds the exact per-call record the log
 * drops — `session_id, turn_index, agent_id, model, input_tokens,
 * output_tokens, cache_read_tokens, cache_write_tokens, reasoning_tokens,
 * total_nano_aiu, request_multiplier, initiator, created_at`, one row per model
 * call, in call order. The descriptor's `parse` reads that session's rows
 * through `io.querySqlite` (read-only, WAL-snapshotted by the engine, never a
 * write) and hands them to the parser, which pairs the k-th row of an agent
 * with the k-th `assistant.message` of that agent — the CLI writes both at the
 * same moment, so the pairing is by construction, not by guess. A row with no
 * message (a truncated log) still becomes a priced settlement turn
 * (`copilot:<session>:usage:<rowid>`); a message with no row stays unpriced.
 * Persisted `assistant.usage` events, when a build writes them, win over the
 * table (the rows are ignored) so nothing counts twice; the shutdown fallback
 * still applies only when neither produced a priced turn. `input_tokens` is the
 * TOTAL prompt side here too, and gets the same cache subtraction.
 *
 * VS CODE'S AGENT MODE WRITES HERE (2026-09-08). VS Code 1.136's Copilot Chat
 * hosts agent sessions on the Copilot CLI SDK and stores them in this very
 * `session-state/`, marking `workspace.yaml`'s `client_name: vscode` (the CLI
 * writes `github/cli`). Those sessions are attributed to the `vscode-copilot`
 * source — the rail the legacy chatSessions reader already owns — so VS Code
 * sessions appear metered under their own name and never as "Copilot CLI".
 */

import { join } from "node:path";
import { toolTarget, type DetectUnit, type TranscriptParseResult } from "./cc-transcript.js";
import {
  describeQuota,
  newerQuota,
  parseQuotaSnapshots,
  quotaStatus,
  quotaWindow,
  type CopilotQuota,
} from "./copilot-quota.js";
import { deriveCost, inferModelProvider } from "./pricing.js";
import type { SourceIo, TranscriptSourceDescriptor } from "./transcript-sources.js";
import {
  TOOL_OUTPUT_MAX_CHARS,
  TURN_TEXT_MAX_CHARS,
  TURN_TOOLS_MAX,
  type LedgerTurn,
  type SettlementMode,
  type TitleRecord,
  type TurnUsage,
  type TurnSource,
} from "./turns.js";

/** The session-document directory, relative to the resolved Copilot home. */
const SESSION_STATE_DIR = "session-state";
/** The event log inside one session's directory. */
const EVENTS_FILE = "events.jsonl";

/** Copilot's built-in tool names → the Claude Code names the detectors key on.
 * GitHub's own table (hooks reference, PascalCase dialect); kept in step with
 * guard/hosts/copilot.ts, which cannot be imported from here. */
const TOOL_NAMES: Record<string, string> = {
  bash: "Bash",
  powershell: "Bash",
  local_shell: "Bash",
  view: "Read",
  create: "Write",
  edit: "Edit",
  str_replace_editor: "Edit",
  apply_patch: "Edit",
  grep: "Grep",
  rg: "Grep",
  glob: "Glob",
  web_fetch: "WebFetch",
  web_search: "WebSearch",
  ask_user: "AskUserQuestion",
  update_todo: "TodoWrite",
  task: "Task",
};

function str(value: unknown): string | undefined {
  return typeof value === "string" && value !== "" ? value : undefined;
}

function obj(value: unknown): Record<string, unknown> | undefined {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;
}

function toInt(value: unknown): number {
  const n = typeof value === "number" ? value : Number(value);
  if (!Number.isFinite(n) || n <= 0) return 0;
  return Math.floor(n);
}

/** Copilot names Anthropic models with dots; the pricing table uses dashes. */
function pricingModelKey(model: string): string {
  const m = model.trim().toLowerCase();
  return m.startsWith("claude") ? m.replace(/\./g, "-") : m;
}

/** The Claude-side name for a Copilot tool call, MCP tools included. */
function mappedToolName(data: Record<string, unknown>, rawName: string | undefined): string {
  const server = str(data.mcpServerName);
  const tool = str(data.mcpToolName);
  if (server && tool) return `mcp__${server}__${tool}`;
  const name = rawName ?? "tool";
  return TOOL_NAMES[name] ?? name;
}

/** `arguments` is opaque JSON: an object on the wire, a JSON string in some
 * dialects. Return both the parsed object (for target extraction) and the text
 * the detectors scan — unparsable text is kept, never dropped. */
function toolArguments(value: unknown): { parsed: unknown; raw: string } {
  if (typeof value === "string") {
    try {
      return { parsed: JSON.parse(value), raw: value };
    } catch {
      return { parsed: undefined, raw: value };
    }
  }
  if (value === undefined || value === null) return { parsed: undefined, raw: "" };
  try {
    return { parsed: value, raw: JSON.stringify(value) };
  } catch {
    return { parsed: undefined, raw: "" };
  }
}

/**
 * Settlement from the quota snapshots riding one `assistant.usage` event.
 *
 * `undefined` is NO OBSERVATION — the event carried neither a BYOK flag nor a
 * quota snapshot — and the session's last verdict carries forward. Anything
 * else is a reading that REPLACES it, including an explicit "unknown" (a
 * snapshot that shows the quota exhausted with no overage allowed). Treating a
 * contrary reading like a missing one is what let a BYOK turn after an
 * included one keep reading as plan-covered.
 *
 * A BYOK call is metered straight to the person's own provider key: that is
 * API-billed spend (`billed`), the one funding mode the host states outright,
 * and it is covered by no Copilot plan.
 */
function settlementOf(data: Record<string, unknown>): SettlementMode | undefined {
  if (data.isByok === true) return "billed";
  const snapshots = obj(data.quotaSnapshots);
  if (!snapshots) return data.isByok === false ? "unknown" : undefined;
  let verdict: SettlementMode = "unknown";
  for (const value of Object.values(snapshots)) {
    const snap = obj(value);
    if (!snap) continue;
    const remaining = snap.remainingPercentage;
    if (
      snap.isUnlimitedEntitlement === true ||
      snap.hasQuota === true ||
      (typeof remaining === "number" && Number.isFinite(remaining) && remaining > 0)
    ) {
      return "subscription";
    }
    const overage = snap.overage;
    if (
      snap.overageAllowedWithExhaustedQuota === true ||
      (typeof overage === "number" && overage > 0)
    ) {
      verdict = "credits";
    }
  }
  return verdict;
}

function usageOf(data: Record<string, unknown>): TurnUsage {
  const cacheRead = toInt(data.cacheReadTokens);
  const cacheWrite = toInt(data.cacheWriteTokens);
  return {
    // `inputTokens` is the TOTAL prompt side; the cache buckets come out of it.
    input_tokens: Math.max(0, toInt(data.inputTokens) - cacheRead - cacheWrite),
    output_tokens: toInt(data.outputTokens),
    cache_read_tokens: cacheRead,
    cache_write_tokens: cacheWrite,
    cache_write_1h_tokens: 0,
    web_search_requests: 0,
  };
}

/** USD from the built-in pricing table, or undefined when the model is unknown. */
function costOf(model: string | undefined, usage: TurnUsage): number | undefined {
  if (!model) return undefined;
  const key = pricingModelKey(model);
  const provider = inferModelProvider(key);
  if (!provider) return undefined;
  return deriveCost({
    model_provider: provider,
    model: key,
    input_tokens: usage.input_tokens,
    output_tokens: usage.output_tokens,
    cached_tokens: usage.cache_read_tokens + usage.cache_write_tokens,
    cache_read_tokens: usage.cache_read_tokens,
    cache_write_tokens: usage.cache_write_tokens,
    web_search_requests: 0,
  });
}

/** One row of `assistant_usage_events` (session-store.db), as `querySqlite`
 * returns it. Only the columns the reader uses are typed; extras ride along. */
export interface CopilotUsageRow {
  id?: unknown;
  turn_index?: unknown;
  agent_id?: unknown;
  model?: unknown;
  input_tokens?: unknown;
  output_tokens?: unknown;
  cache_read_tokens?: unknown;
  cache_write_tokens?: unknown;
  created_at?: unknown;
  [column: string]: unknown;
}

export interface ParseCopilotOptions {
  /** The rail these turns belong to; `copilot-cli` unless the session's
   * `workspace.yaml` says VS Code hosted it. */
  source?: TurnSource;
  /** This session's `assistant_usage_events` rows, in `id` order. */
  usageRows?: readonly CopilotUsageRow[];
}

/** The SQL the descriptor runs against session-store.db for one session. */
export const USAGE_ROWS_SQL =
  "SELECT id, turn_index, agent_id, model, input_tokens, output_tokens, cache_read_tokens, cache_write_tokens, created_at " +
  "FROM assistant_usage_events WHERE session_id = ? ORDER BY id";

/** `session-state/<id>/events.jsonl` → the sibling `session-store.db` of that
 * Copilot home (CLI and VS Code-hosted sessions share one database). */
export function copilotUsageDbPath(eventsPath: string): string | undefined {
  const parts = eventsPath.split(/[\/]/);
  if (parts.length < 4 || parts.at(-1) !== EVENTS_FILE) return undefined;
  return [...parts.slice(0, -3), "session-store.db"].join("/");
}

/** `client_name:` out of a session's `workspace.yaml` — a flat key: value
 * document, read without a YAML parser. */
export function clientNameOf(workspaceYaml: string | undefined): string | undefined {
  if (!workspaceYaml) return undefined;
  const match = /^client_name:\s*["']?([^"'\n]+?)["']?\s*$/m.exec(workspaceYaml);
  return match ? match[1].trim() : undefined;
}

/** Which rail a Copilot session belongs to, from its client name: VS Code's
 * Copilot Chat passes `clientName: "vscode"` to the SDK; the CLI writes
 * `github/cli`. Anything unknown is the CLI's rail. */
export function copilotSourceFor(clientName: string | undefined): TurnSource {
  return clientName && /^vscode\b/i.test(clientName.trim()) ? "vscode-copilot" : "copilot-cli";
}

function usageOfRow(row: CopilotUsageRow): TurnUsage {
  return usageOf({
    inputTokens: row.input_tokens,
    outputTokens: row.output_tokens,
    cacheReadTokens: row.cache_read_tokens,
    cacheWriteTokens: row.cache_write_tokens,
  });
}

/** One model call in flight: the text + tool names since the last settlement,
 * and the assistant.message event id that will name its turn. */
interface PendingCall {
  turnId?: string;
  at?: string;
  texts: string[];
  tools: string[];
  units: DetectUnit[];
  lastTurnId?: string;
}

function emptyCall(): PendingCall {
  return { texts: [], tools: [], units: [] };
}

/**
 * Parse one `events.jsonl`. Total by construction: a half-written trailing
 * line, an unknown event type or a missing field yields less, never a throw.
 * `fallbackSessionId` comes from the document's directory name.
 */
export function parseCopilotSession(
  contents: string,
  fallbackSessionId: string,
  options: ParseCopilotOptions = {},
): TranscriptParseResult {
  const source: TurnSource = options.source ?? "copilot-cli";
  // Persisted usage events win; the table fills in only when the log has none.
  const logHasUsage = contents.includes('"assistant.usage"');
  /** Per agent, the table rows not yet paired with a message, in call order. */
  const rowsByAgent = new Map<string, CopilotUsageRow[]>();
  if (!logHasUsage) {
    for (const row of options.usageRows ?? []) {
      const agent = str(row.agent_id) ?? "main";
      const list = rowsByAgent.get(agent) ?? [];
      list.push(row);
      rowsByAgent.set(agent, list);
    }
  }
  const turns: LedgerTurn[] = [];
  const detect: DetectUnit[] = [];
  let sessionId = fallbackSessionId;
  let cwd: string | undefined;
  let branch: string | undefined;
  let selectedModel: string | undefined;
  let settlement: SettlementMode = "unknown";
  let title: string | undefined;
  let meteredTurns = 0;
  let fallbackSeq = 0;
  /** Per agent (main conversation + each sub-agent), the call in flight. */
  const calls = new Map<string, PendingCall>();
  /** toolCallId → mapped tool name, so an output can name its tool. */
  const toolNameByCallId = new Map<string, string>();
  /** The last `session.shutdown` seen: its totals are cumulative. */
  let shutdown: { at: string; data: Record<string, unknown> } | undefined;
  /** The newest quota reading in this log. Account-wide and monotonic, so the
   * newest anywhere on the machine wins — never a sum (lib/copilot-quota.ts). */
  let quota: CopilotQuota | undefined;

  const callFor = (agent: string): PendingCall => {
    let call = calls.get(agent);
    if (!call) {
      call = emptyCall();
      calls.set(agent, call);
    }
    return call;
  };

  const applyContext = (context: unknown): void => {
    const ctx = obj(context);
    if (!ctx) return;
    cwd = str(ctx.cwd) ?? cwd;
    branch = str(ctx.branch) ?? branch;
  };

  /** Anchor a scan unit: to the agent's last settled turn, else hold it for
   * the next one (a tool call before any assistant turn exists). */
  const anchor = (call: PendingCall, unit: DetectUnit): void => {
    if (call.lastTurnId) detect.push({ ...unit, turn_id: call.lastTurnId });
    else call.units.push(unit);
  };

  /** Emit the agent's in-flight call as an assistant turn. `usage` is absent
   * when the document carried no `assistant.usage` for it. Returns whether a
   * turn was actually minted. */
  const flushCall = (
    call: PendingCall,
    at: string | undefined,
    model: string | undefined,
    usage: TurnUsage | undefined,
    turnSettlement: SettlementMode,
  ): boolean => {
    const id = call.turnId;
    const instant = at ?? call.at;
    if (!id || !instant) return false;
    if (call.texts.length === 0 && call.tools.length === 0 && usage === undefined) return false;
    const cost = usage ? costOf(model, usage) : undefined;
    const text = call.texts.length > 0 ? call.texts.join("\n") : undefined;
    turns.push({
      id,
      source,
      session_id: sessionId,
      role: "assistant",
      at: instant,
      ...(model === undefined ? {} : { model }),
      ...(usage === undefined ? {} : { usage }),
      ...(cost === undefined ? {} : { cost }),
      ...(cost === undefined ? { cost_unknown: true } : {}),
      settlement: turnSettlement,
      ...(text === undefined ? {} : { text: text.slice(0, TURN_TEXT_MAX_CHARS) }),
      ...(call.tools.length === 0 ? {} : { tools: call.tools.slice(0, TURN_TOOLS_MAX) }),
      ...(cwd === undefined ? {} : { cwd }),
      ...(branch === undefined ? {} : { git_branch: branch }),
    });
    for (const unit of call.units) detect.push({ ...unit, turn_id: id });
    call.lastTurnId = id;
    call.turnId = undefined;
    call.at = undefined;
    call.texts = [];
    call.tools = [];
    call.units = [];
    return true;
  };

  for (const raw of contents.split("\n")) {
    const line = raw.trim();
    if (line === "") continue;
    let event: Record<string, unknown>;
    try {
      const parsed: unknown = JSON.parse(line);
      const record = obj(parsed);
      if (!record) continue;
      event = record;
    } catch {
      // A line the CLI is still writing, or a truncated log.
      continue;
    }
    const type = str(event.type);
    if (!type) continue;
    const at = str(event.timestamp);
    const data = obj(event.data) ?? {};
    const agent = str(event.agentId) ?? "main";
    // Every persisted event carries a UUID; the counter is only a floor for a
    // malformed line, and stays stable because earlier lines never change.
    const eventId = str(event.id) ?? `e${fallbackSeq++}`;

    switch (type) {
      case "session.start":
      case "session.resume": {
        sessionId = str(data.sessionId) ?? sessionId;
        selectedModel = str(data.selectedModel) ?? selectedModel;
        applyContext(data.context);
        continue;
      }
      case "session.context_changed": {
        applyContext(data);
        continue;
      }
      case "session.model_change": {
        selectedModel = str(data.newModel) ?? selectedModel;
        continue;
      }
      // WHERE THE QUOTA ACTUALLY IS (verified against CLI 1.0.83, 2026-09-11:
      // 9 of 9 model calls carried `quotaSnapshots` here and no other event
      // did). The schema documents them on `assistant.usage`, which this build
      // never persists — so until this case existed the settlement verdict
      // below never had a reading to work from and EVERY Copilot turn, VS
      // Code's agent mode included, settled `unknown` while the answer sat on
      // the neighbouring event.
      case "model.model_call_success": {
        if (at) quota = newerQuota(quota, parseQuotaSnapshots(data, new Date(at).toISOString()));
        const verdict = settlementOf(data);
        if (verdict !== undefined) settlement = verdict;
        continue;
      }
      case "session.title_changed": {
        title = str(data.title) ?? title;
        continue;
      }
      case "user.message": {
        const content = str(data.content);
        if (!content || !at) continue;
        const id = `copilot:${sessionId}:${eventId}`;
        // A `source` marks a non-human origin (hidden skill injection, an
        // inter-agent prompt); autopilot continuations are auto-injected.
        const human = data.source === undefined && data.isAutopilotContinuation !== true;
        if (human) {
          turns.push({
            id,
            source,
            session_id: sessionId,
            role: "user",
            at,
            text: content.slice(0, TURN_TEXT_MAX_CHARS),
            ...(cwd === undefined ? {} : { cwd }),
            ...(branch === undefined ? {} : { git_branch: branch }),
          });
        }
        detect.push({
          kind: "prompt",
          raw: content,
          session_id: sessionId,
          turn_id: id,
          at,
          ...(cwd === undefined ? {} : { cwd }),
        });
        continue;
      }
      case "assistant.message": {
        const call = callFor(agent);
        // The FIRST message of a call names the turn — it is written before
        // the usage event, so the id is the same whether or not usage lands.
        call.turnId ??= `copilot:${sessionId}:${eventId}`;
        call.at ??= at;
        const content = str(data.content);
        if (content) call.texts.push(content);
        const requests = Array.isArray(data.toolRequests) ? data.toolRequests : [];
        for (const request of requests) {
          const req = obj(request);
          if (!req) continue;
          const name = mappedToolName(req, str(req.name));
          call.tools.push(name);
          const callId = str(req.toolCallId);
          if (callId) toolNameByCallId.set(callId, name);
        }
        // The table's next row for this agent is this call's usage record
        // (see METERING, SECOND SOURCE): settle the turn now, exactly where a
        // persisted assistant.usage event would have.
        const row = rowsByAgent.get(agent)?.shift();
        if (row) {
          const rowModel = str(row.model);
          const turnModel = rowModel === undefined || rowModel === "unknown" ? selectedModel : rowModel;
          if (flushCall(call, at, turnModel, usageOfRow(row), settlement)) meteredTurns += 1;
        }
        continue;
      }
      case "assistant.usage": {
        const call = callFor(agent);
        const verdict = settlementOf(data);
        if (verdict !== undefined) settlement = verdict;
        const model = str(data.model);
        const turnModel = model === "unknown" ? selectedModel : model ?? selectedModel;
        call.turnId ??= `copilot:${sessionId}:${eventId}`;
        if (flushCall(call, at, turnModel, usageOf(data), settlement)) meteredTurns += 1;
        continue;
      }
      case "tool.execution_start": {
        if (!at) continue;
        const callId = str(data.toolCallId);
        const name = mappedToolName(data, str(data.toolName));
        if (callId) toolNameByCallId.set(callId, name);
        const args = toolArguments(data.arguments);
        const shell = obj(data.shellToolInfo);
        const displayCommand = str(shell?.displayCommand);
        const target =
          toolTarget(name, args.parsed) ??
          (displayCommand ? displayCommand.trim().split(/\s+/, 1)[0] : undefined);
        anchor(callFor(agent), {
          kind: "tool_call",
          raw: args.raw !== "" ? args.raw : (displayCommand ?? ""),
          tool_name: name,
          ...(target === undefined ? {} : { target }),
          session_id: sessionId,
          turn_id: "",
          at,
          ...(cwd === undefined ? {} : { cwd }),
        });
        continue;
      }
      case "tool.execution_complete": {
        if (!at) continue;
        const result = obj(data.result);
        const error = obj(data.error);
        const text =
          str(result?.detailedContent) ?? str(result?.content) ?? str(error?.message);
        if (!text) continue;
        const callId = str(data.toolCallId);
        const name = callId ? toolNameByCallId.get(callId) : undefined;
        anchor(callFor(agent), {
          kind: "tool_output",
          raw: text.slice(0, TOOL_OUTPUT_MAX_CHARS),
          ...(name === undefined ? {} : { tool_name: name }),
          session_id: sessionId,
          turn_id: "",
          at,
          ...(cwd === undefined ? {} : { cwd }),
        });
        continue;
      }
      case "session.shutdown": {
        if (at) shutdown = { at, data };
        continue;
      }
      default:
        continue;
    }
  }

  // A response the log never settled (the session is still running, or this
  // build does not persist assistant.usage) is still a turn — unpriced.
  for (const call of calls.values()) {
    flushCall(call, undefined, selectedModel, undefined, settlement);
    for (const unit of call.units) {
      detect.push({ ...unit, turn_id: call.lastTurnId ?? `copilot:${sessionId}:tail` });
    }
  }

  // Table rows the log had no message for (a truncated or still-growing log):
  // priced settlement turns of their own, so the spend is never lost. Keyed on
  // the row id, which never changes once written.
  for (const rows of rowsByAgent.values()) {
    for (const row of rows) {
      const rowId = row.id === undefined || row.id === null ? undefined : String(row.id);
      const at = str(row.created_at);
      if (rowId === undefined || !at) continue;
      const model = str(row.model);
      const usage = usageOfRow(row);
      const cost = costOf(model, usage);
      turns.push({
        id: `copilot:${sessionId}:usage:${rowId}`,
        source,
        session_id: sessionId,
        role: "assistant",
        at: new Date(at).toISOString(),
        ...(model === undefined ? {} : { model }),
        usage,
        ...(cost === undefined ? { cost_unknown: true } : { cost }),
        settlement,
        ...(cwd === undefined ? {} : { cwd }),
        ...(branch === undefined ? {} : { git_branch: branch }),
      });
      meteredTurns += 1;
    }
  }

  // Nothing in the document carried token counts: fall back to the session's
  // own closing accounting, one settlement turn per model.
  if (meteredTurns === 0 && shutdown) {
    const metrics = obj(shutdown.data.modelMetrics);
    for (const [model, value] of Object.entries(metrics ?? {})) {
      const metric = obj(value);
      const metricUsage = obj(metric?.usage);
      if (!metricUsage) continue;
      const usage = usageOf({
        // The shutdown totals report the same four buckets as a usage event.
        inputTokens: metricUsage.inputTokens,
        outputTokens: metricUsage.outputTokens,
        cacheReadTokens: metricUsage.cacheReadTokens,
        cacheWriteTokens: metricUsage.cacheWriteTokens,
      });
      if (
        usage.input_tokens === 0 &&
        usage.output_tokens === 0 &&
        usage.cache_read_tokens === 0 &&
        usage.cache_write_tokens === 0
      ) {
        continue;
      }
      const cost = costOf(model, usage);
      turns.push({
        id: `copilot:${sessionId}:shutdown:${model}`,
        source,
        session_id: sessionId,
        role: "assistant",
        at: shutdown.at,
        model,
        usage,
        ...(cost === undefined ? { cost_unknown: true } : { cost }),
        settlement,
        ...(cwd === undefined ? {} : { cwd }),
        ...(branch === undefined ? {} : { git_branch: branch }),
      });
    }
  }

  const titles: TitleRecord[] = title
    ? [{ session_id: sessionId, title: { text: title, origin: "auto_summary" } }]
    : [];
  const window = quotaWindow(quota);
  return {
    turns,
    titles,
    detect,
    ...(window && quota
      ? {
          plan_window: {
            source,
            at: quota.at,
            used_percentage: window.used_percentage,
            ...(window.resets_at === undefined ? {} : { resets_at: window.resets_at }),
            ...(quota.governing === undefined
              ? {}
              : {
                  window_id: quota.governing.id,
                  used: quota.governing.used,
                  entitlement: quota.governing.entitlement,
                }),
            ...(quotaStatus(quota) === undefined ? {} : { status: quotaStatus(quota)! }),
            ...(describeQuota(quota) === undefined ? {} : { label: describeQuota(quota)! }),
          },
        }
      : {}),
  };
}

/** The session id encoded in a document's path: `<session-state>/<id>/events.jsonl`. */
export function copilotSessionIdFromPath(path: string): string | undefined {
  const parts = path.split(/[\\/]/).filter((p) => p !== "");
  const last = parts.at(-1);
  if (!last) return undefined;
  if (last === EVENTS_FILE) return parts.at(-2);
  return last.endsWith(".jsonl") ? last.slice(0, -".jsonl".length) : undefined;
}

export const copilotSource: TranscriptSourceDescriptor = {
  id: "copilot-cli",
  label: "Copilot CLI",
  // The CLI's own footprint, not `~/.copilot`, which VS Code's Copilot Chat shim also creates.
  presencePaths: [".copilot/session-state"],

  /** `COPILOT_HOME` replaces `~/.copilot` wholesale (app.js resolves the home
   * as settings.configDir → $COPILOT_HOME → $HOME/.copilot), so the session
   * documents move with it. */
  roots(home: string, env: NodeJS.ProcessEnv): string[] {
    const override = str(env.COPILOT_HOME)?.trim();
    return [join(override && override !== "" ? override : join(home, ".copilot"), SESSION_STATE_DIR)];
  },

  /** One document per session directory. A bare `<id>.jsonl` sitting directly
   * in the root is accepted too — cheap tolerance for an older/flat layout. */
  discover(root: string, io: SourceIo): string[] {
    const out: string[] = [];
    for (const entry of io.listDir(root)) {
      if (entry.startsWith(".")) continue;
      const child = join(root, entry);
      const stat = io.stat(child);
      if (stat?.isDirectory) {
        const events = join(child, EVENTS_FILE);
        if (io.stat(events)) out.push(events);
      } else if (stat && entry.endsWith(".jsonl")) {
        out.push(child);
      }
    }
    return out.sort();
  },

  parse(path: string, io: SourceIo): TranscriptParseResult {
    const contents = io.readText(path);
    if (contents === undefined) return { turns: [], titles: [], detect: [] };
    const sessionId = copilotSessionIdFromPath(path) ?? "unknown";
    // Who hosted the session: the sibling workspace.yaml's client_name.
    const dir = path.slice(0, path.length - EVENTS_FILE.length);
    const source = path.endsWith(EVENTS_FILE) ? copilotSourceFor(clientNameOf(io.readText(join(dir, "workspace.yaml")))) : "copilot-cli";
    // The exact per-call usage the log drops (METERING, SECOND SOURCE). A
    // missing, locked or older database (no table yet) just means no rows.
    let usageRows: CopilotUsageRow[] | undefined;
    const dbPath = copilotUsageDbPath(path);
    if (dbPath && io.stat(dbPath)) {
      try {
        usageRows = io.querySqlite(dbPath, USAGE_ROWS_SQL, [sessionId]) as CopilotUsageRow[];
      } catch {
        usageRows = undefined;
      }
    }
    return parseCopilotSession(contents, sessionId, { source, usageRows });
  },

  sessionIdOf(path: string): string | undefined {
    return copilotSessionIdFromPath(path);
  },

  /** Copilot records its own token counts — per model call in
   * `assistant.usage`, and per model at `session.shutdown`. */
  metered: true,
};
