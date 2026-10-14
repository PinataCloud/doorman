/**
 * Goose session reading — the `goose` TranscriptSourceDescriptor.
 *
 * Goose (Block, now the Agentic AI Foundation) keeps every session in ONE
 * SQLite database, `sessions.db`, since 1.10 — the per-session `.jsonl` files
 * before that are dead on disk and are not read here. The database is where
 * the CLI and the desktop app both write, so one reader covers both.
 *
 * WHERE THE DATABASE LIVES — `crates/goose/src/config/paths.rs`:
 *   - `GOOSE_PATH_ROOT` set (absolute) → `<root>/data/sessions/sessions.db`.
 *   - Otherwise etcetera's `choose_app_strategy({ top_level_domain: "Block",
 *     author: "Block", app_name: "goose" })`, whose Apple strategy joins the
 *     bundle id `Block.block.goose` under `~/Library/Application Support/`,
 *     and whose XDG strategy lands under `~/.local/share/`. paths.rs's own
 *     comment names `~/Library/Application Support/Block/goose/` as the
 *     legacy layout it must keep working, and `goose info` on older Linux
 *     builds printed `~/.local/share/goose/sessions/sessions.db` — so every
 *     spelling is a root here, and a root that does not exist costs nothing.
 *
 * SCHEMA — `crates/goose/src/session/session_manager.rs` (fetched 2026-09-06,
 * block/goose `main`), verbatim column names:
 *   sessions(id TEXT PK, name, description, user_set_name, session_type,
 *            working_dir, created_at, updated_at, extension_data,
 *            total_tokens, input_tokens, output_tokens, cache_read_tokens,
 *            cache_write_tokens, accumulated_total_tokens,
 *            accumulated_input_tokens, accumulated_output_tokens,
 *            accumulated_cache_read_tokens, accumulated_cache_write_tokens,
 *            accumulated_cost REAL, schedule_id, recipe_json,
 *            user_recipe_values_json, provider_name, model_config_json,
 *            goose_mode, archived_at, project_id, parent_session_id)
 *   messages(id INTEGER PK AUTOINCREMENT, message_id TEXT, session_id,
 *            role TEXT ('user'|'assistant'), content_json TEXT,
 *            created_timestamp INTEGER, timestamp, tokens INTEGER,
 *            metadata_json TEXT)
 *   usage_ledger(session_id, created_timestamp, model, input_tokens,
 *            output_tokens, total_tokens, cache_read_tokens,
 *            cache_write_tokens, cost, cost_source, is_compaction)
 *
 * `created_timestamp` is unix SECONDS, except that Goose itself guards for
 * millisecond values (`CASE WHEN created_timestamp > 10_000_000_000 THEN
 * created_timestamp / 1000`) — the same threshold is applied here.
 *
 * `content_json` is `Vec<MessageContentBlock>` from
 * `crates/goose-provider-types/src/conversation/message.rs`, serde-tagged on
 * `type` in camelCase:
 *   {type:"text", text}
 *   {type:"toolRequest", id, toolCall:{status:"success", value:{name, arguments}}
 *                                    | {status:"error", error}}
 *   {type:"toolResponse", id, toolResult:{status:"success",
 *                                          value:{content:[{type:"text",text}…], isError?}}
 *                                       | {status:"error", error}}
 *   {type:"thinking"|"redactedThinking"|"image"|"document"|
 *         "toolConfirmationRequest"|"actionRequired"|"systemNotification"|"error", …}
 * A tool RESPONSE travels in a `user`-role message (the MCP result is what the
 * user side hands back), so a user message can be a tool result rather than a
 * prompt — the two are told apart by the block types.
 *
 * `metadata_json` is `MessageMetadata` (camelCase): `userVisible`,
 * `agentVisible`, `inference:{provider, requestedModel, resolvedModel}`,
 * `usage:{inputTokens, outputTokens, totalTokens, cacheReadTokens,
 * cacheWriteTokens, cost, costSource, isCompaction}` — the per-message usage
 * newer builds attach to the assistant message the provider answered with.
 *
 * NUMBERS (rule 2 — honest, never invented):
 *   - Per assistant turn, `metadata.usage` when Goose recorded it, priced by
 *     Goose's own `cost` when present (host-reported), else by the built-in
 *     pricing table from the recorded model, else `cost_unknown`.
 *   - Older databases carry no per-message usage; there the SESSION's
 *     `accumulated_*` totals land on the last assistant turn (so the session
 *     sums right; the per-turn split is unknowable) with `accumulated_cost`
 *     as host-reported cost when set. Documented in the turn's shape only —
 *     the ledger shows a session total, which is exactly what it is.
 *   - `messages.tokens` is Goose's own token-count estimate for context
 *     management, NOT provider usage, and is deliberately not read.
 *   - Cache buckets are emitted as recorded; settlement is never claimed —
 *     Goose runs on the user's own provider keys, and the database says
 *     nothing about a plan.
 *
 * WHAT IS DELIBERATELY NOT READ: `usage_ledger` (per-API-call rows including
 * a `carried_forward` reconciliation row Goose synthesises when totals and the
 * ledger disagree — summing it alongside message usage would double-count),
 * `thread_messages`, and messages with `userVisible: false` on the user side
 * (compaction summaries and agent-injected context, never a human prompt).
 */

import { toolTarget, type DetectUnit, type TranscriptParseResult } from "./cc-transcript.js";
import { deriveCost, inferModelProvider } from "./pricing.js";
import type { SourceIo, TranscriptSourceDescriptor } from "./transcript-sources.js";
import {
  type LedgerTurn,
  type TitleRecord,
  type TurnUsage,
  TOOL_OUTPUT_MAX_CHARS,
  TURN_TEXT_MAX_CHARS,
  TURN_TOOLS_MAX,
} from "./turns.js";

/** upstream SESSIONS_FOLDER / DB_NAME (session_manager.rs). */
const SESSIONS_FOLDER = "sessions";
const DB_NAME = "sessions.db";
/** upstream: `created_timestamp > 10_000_000_000` means milliseconds. */
const MILLISECOND_TIMESTAMP_THRESHOLD = 10_000_000_000;

/** Every data directory Goose has used, home-relative, newest first. */
const DATA_DIRS = [
  "Library/Application Support/Block.block.goose",
  "Library/Application Support/Block/goose",
  "Library/Application Support/goose",
  ".local/share/Block/goose",
  ".local/share/goose",
];

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

function toCost(value: unknown): number | undefined {
  const n = typeof value === "number" ? value : Number(value);
  return Number.isFinite(n) && n > 0 ? n : undefined;
}

function parseJson(value: unknown): unknown {
  const text = typeof value === "string" ? value : value instanceof Uint8Array ? new TextDecoder().decode(value) : undefined;
  if (!text) return undefined;
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return undefined;
  }
}

/** Goose's `created_timestamp`: unix seconds, or milliseconds past the threshold. */
function isoOfEpoch(value: unknown): string | undefined {
  const n = typeof value === "number" ? value : Number(value);
  if (!Number.isFinite(n) || n <= 0) return undefined;
  const ms = n > MILLISECOND_TIMESTAMP_THRESHOLD ? n : n * 1000;
  const d = new Date(ms);
  return Number.isNaN(d.getTime()) ? undefined : d.toISOString();
}

/** `sessions.created_at` — SQLite's `CURRENT_TIMESTAMP` text ("YYYY-MM-DD HH:MM:SS", UTC). */
function isoOfSqlite(value: unknown): string | undefined {
  const text = str(value);
  if (!text) return undefined;
  const normalized = /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/.test(text) ? `${text.replace(" ", "T")}Z` : text;
  const ms = Date.parse(normalized);
  return Number.isNaN(ms) ? undefined : new Date(ms).toISOString();
}

/**
 * Every query is best-effort: a database Goose is mid-write on, a column an
 * older build never added, a corrupt page — all mean "nothing to read here",
 * never a throw out of `parse` (contract rule: total).
 */
function query(io: SourceIo, path: string, sql: string, params?: readonly unknown[]): Record<string, unknown>[] {
  try {
    return io.querySqlite(path, sql, params) ?? [];
  } catch {
    return [];
  }
}

const SESSIONS_SQL =
  "SELECT id, name, description, user_set_name, working_dir, created_at, provider_name, model_config_json, " +
  "accumulated_input_tokens, accumulated_output_tokens, accumulated_cache_read_tokens, " +
  "accumulated_cache_write_tokens, accumulated_cost FROM sessions";
const MESSAGES_SQL =
  "SELECT id, role, content_json, created_timestamp, metadata_json FROM messages WHERE session_id = ? " +
  "ORDER BY created_timestamp, id";

/** The text of a run of content blocks — `text` blocks only; thinking is the
 * model's reasoning stream, not its answer. */
function blocksText(blocks: unknown[]): string {
  const parts: string[] = [];
  for (const raw of blocks) {
    const block = obj(raw);
    if (block?.type === "text") {
      const text = str(block.text);
      if (text) parts.push(text);
    }
  }
  return parts.join("\n").trim();
}

/** What a tool RETURNED, out of a toolResponse block's `toolResult`. */
function toolResultText(result: unknown): string | undefined {
  const envelope = obj(result);
  if (!envelope) return undefined;
  if (envelope.status === "error") return str(envelope.error);
  const value = obj(envelope.value);
  if (!value) return undefined;
  const parts: string[] = [];
  if (Array.isArray(value.content)) {
    for (const raw of value.content) {
      const item = obj(raw);
      if (!item) continue;
      const text = str(item.text);
      if (text) parts.push(text);
      else if (item.type !== undefined && item.type !== "text") parts.push(JSON.stringify(item));
    }
  }
  const text = parts.join("\n");
  return text === "" ? undefined : text;
}

/** Goose's own tool naming is `<extension>__<tool>` (`developer__shell`), with
 * `command` for the shell and `path` for the file tools. */
function gooseToolTarget(name: string, args: unknown): string | undefined {
  const a = obj(args);
  if (!a) return undefined;
  const command = str(a.command);
  if (command) {
    const head = command.trim().split(/\s+/, 1)[0];
    return head === "" ? undefined : head;
  }
  return toolTarget(name, a) ?? str(a.path) ?? str(a.source) ?? str(a.url);
}

/** The model a session ran on, from `model_config_json` (a serde `ModelConfig`
 * — the field has been spelled `model_name` and `modelName`, both accepted). */
function sessionModel(row: Record<string, unknown>): string | undefined {
  const config = obj(parseJson(row.model_config_json));
  return str(config?.model_name) ?? str(config?.modelName) ?? str(config?.model);
}

function usageOf(source: Record<string, unknown>, keys: {
  input: string;
  output: string;
  cacheRead: string;
  cacheWrite: string;
}): TurnUsage | undefined {
  const input = toInt(source[keys.input]);
  const output = toInt(source[keys.output]);
  const cacheRead = toInt(source[keys.cacheRead]);
  const cacheWrite = toInt(source[keys.cacheWrite]);
  if (input === 0 && output === 0 && cacheRead === 0 && cacheWrite === 0) return undefined;
  return {
    input_tokens: input,
    output_tokens: output,
    cache_read_tokens: cacheRead,
    cache_write_tokens: cacheWrite,
    cache_write_1h_tokens: 0,
    web_search_requests: 0,
  };
}

function priceOf(model: string | undefined, provider: string | undefined, usage: TurnUsage): number | undefined {
  if (!model) return undefined;
  return deriveCost({
    model_provider: inferModelProvider(model) ?? provider ?? "unknown",
    model,
    input_tokens: usage.input_tokens,
    output_tokens: usage.output_tokens,
    cached_tokens: usage.cache_read_tokens,
    cache_read_tokens: usage.cache_read_tokens,
    cache_write_tokens: usage.cache_write_tokens,
    web_search_requests: 0,
  });
}

/** One session's turns, titles and detect units, appended onto the accumulators. */
function parseSession(
  session: Record<string, unknown>,
  messages: Record<string, unknown>[],
  out: { turns: LedgerTurn[]; detect: DetectUnit[]; titles: TitleRecord[] },
): void {
  const sessionId = str(session.id);
  if (!sessionId) return;
  const cwd = str(session.working_dir);
  const withCwd = cwd === undefined ? {} : { cwd };
  const model = sessionModel(session);
  const provider = str(session.provider_name);
  const sessionStart = isoOfSqlite(session.created_at);

  // toolRequest id → the assistant turn that made the call, so the response
  // (which arrives in the next user-role message) anchors next to it.
  const requestTurn = new Map<string, { turn: string; name: string }>();
  let lastAssistant: LedgerTurn | undefined;
  let lastAt: string | undefined;
  let sawPerMessageUsage = false;

  for (const row of messages) {
    const rowId = toInt(row.id);
    if (rowId === 0) continue;
    const at = isoOfEpoch(row.created_timestamp) ?? lastAt ?? sessionStart;
    if (!at) continue;
    lastAt = at;
    const turnId = `goose:${sessionId}:${rowId}`;
    const blocks = ((): unknown[] => {
      const parsed = parseJson(row.content_json);
      return Array.isArray(parsed) ? parsed : [];
    })();
    const meta = obj(parseJson(row.metadata_json));
    const role = str(row.role);

    if (role === "user") {
      // Tool responses ride user-role messages; a human prompt is text without them.
      let sawResponse = false;
      for (const raw of blocks) {
        const block = obj(raw);
        if (block?.type !== "toolResponse") continue;
        sawResponse = true;
        const output = toolResultText(block.toolResult);
        if (output === undefined) continue;
        const requestId = str(block.id);
        const anchor = requestId ? requestTurn.get(requestId) : undefined;
        out.detect.push({
          kind: "tool_output",
          raw: output.slice(0, TOOL_OUTPUT_MAX_CHARS),
          ...(anchor?.name === undefined ? {} : { tool_name: anchor.name }),
          session_id: sessionId,
          turn_id: turnId,
          ...(anchor === undefined ? {} : { anchor_turn_id: anchor.turn }),
          at,
          ...withCwd,
        });
      }
      if (sawResponse) continue;
      // `userVisible: false` marks compaction summaries and agent-injected
      // context — never a person's words.
      if (meta && meta.userVisible === false) continue;
      const text = blocksText(blocks);
      if (text === "") continue;
      out.turns.push({
        id: turnId,
        source: "goose",
        session_id: sessionId,
        role: "user",
        at,
        text: text.slice(0, TURN_TEXT_MAX_CHARS),
        ...withCwd,
      });
      out.detect.push({ kind: "prompt", raw: text, session_id: sessionId, turn_id: turnId, at, ...withCwd });
      continue;
    }
    if (role !== "assistant") continue;

    const text = blocksText(blocks);
    const named: string[] = [];
    for (const raw of blocks) {
      const block = obj(raw);
      if (block?.type !== "toolRequest") continue;
      const call = obj(block.toolCall);
      const value = obj(call?.value);
      const name = str(value?.name);
      if (!name) continue; // an errored request never named a tool to run
      named.push(name);
      const args = value?.arguments ?? {};
      const requestId = str(block.id);
      if (requestId) requestTurn.set(requestId, { turn: turnId, name });
      const target = gooseToolTarget(name, args);
      out.detect.push({
        kind: "tool_call",
        raw: JSON.stringify(args),
        tool_name: name,
        ...(target === undefined ? {} : { target }),
        session_id: sessionId,
        turn_id: turnId,
        at,
        ...withCwd,
      });
    }
    const inference = obj(meta?.inference);
    const turnModel = str(inference?.resolvedModel) ?? str(inference?.requestedModel) ?? model;
    const turnProvider = str(inference?.provider) ?? provider;
    const messageUsage = obj(meta?.usage);
    const usage = messageUsage
      ? usageOf(messageUsage, {
          input: "inputTokens",
          output: "outputTokens",
          cacheRead: "cacheReadTokens",
          cacheWrite: "cacheWriteTokens",
        })
      : undefined;
    if (usage) sawPerMessageUsage = true;
    if (!usage && text === "" && named.length === 0) continue; // an empty placeholder

    const turn: LedgerTurn = {
      id: turnId,
      source: "goose",
      session_id: sessionId,
      role: "assistant",
      at,
      ...(turnModel === undefined ? {} : { model: turnModel }),
      ...withCwd,
    };
    if (usage) {
      turn.usage = usage;
      const hostCost = toCost(messageUsage?.cost);
      const cost = hostCost ?? priceOf(turnModel, turnProvider, usage);
      if (cost === undefined) turn.cost_unknown = true;
      else turn.cost = cost;
    }
    if (text !== "") turn.text = text.slice(0, TURN_TEXT_MAX_CHARS);
    if (named.length > 0) turn.tools = named.slice(0, TURN_TOOLS_MAX);
    out.turns.push(turn);
    lastAssistant = turn;
  }

  // No per-message usage anywhere in the session: the session's accumulated
  // totals are the only honest numbers, and they land on the last assistant
  // turn so the session sums to what Goose recorded.
  if (!sawPerMessageUsage && lastAssistant) {
    const usage = usageOf(session, {
      input: "accumulated_input_tokens",
      output: "accumulated_output_tokens",
      cacheRead: "accumulated_cache_read_tokens",
      cacheWrite: "accumulated_cache_write_tokens",
    });
    if (usage) {
      lastAssistant.usage = usage;
      const cost = toCost(session.accumulated_cost) ?? priceOf(lastAssistant.model ?? model, provider, usage);
      if (cost === undefined) lastAssistant.cost_unknown = true;
      else lastAssistant.cost = cost;
    }
  }

  // Goose names a session itself (`description`) once it has content; a
  // person's own name (`user_set_name`) wins — both are the host's own title.
  const userNamed = session.user_set_name === 1 || session.user_set_name === true;
  const title = (userNamed ? str(session.name) : undefined) ?? str(session.description)?.trim() ?? str(session.name)?.trim();
  if (title && out.turns.some((t) => t.session_id === sessionId)) {
    out.titles.push({ session_id: sessionId, title: { text: title, origin: "auto_summary" } });
  }
}

/** Parse one Goose `sessions.db`. Pure over `io`, idempotent, never throws. */
export function parseGooseSessionsDb(path: string, io: SourceIo): TranscriptParseResult {
  const out = { turns: [] as LedgerTurn[], detect: [] as DetectUnit[], titles: [] as TitleRecord[] };
  const sessions = query(io, path, SESSIONS_SQL);
  for (const session of sessions) {
    const id = str(session.id);
    if (!id) continue;
    const messages = query(io, path, MESSAGES_SQL, [id]);
    if (messages.length === 0) continue;
    parseSession(session, messages, out);
  }
  out.turns.sort((a, b) => (a.at < b.at ? -1 : a.at > b.at ? 1 : a.id.localeCompare(b.id)));
  return out;
}

export const gooseSource: TranscriptSourceDescriptor = {
  id: "goose",
  label: "Goose",
  presencePaths: [".config/goose", "Library/Application Support/goose", "Library/Application Support/Block.block.goose", "Library/Application Support/Block/goose"],

  /** Every sessions directory Goose has ever written to (see the header). */
  roots(home, env) {
    const roots: string[] = [];
    const override = str(env["GOOSE_PATH_ROOT"]);
    if (override && override.startsWith("/")) roots.push(`${override}/data/${SESSIONS_FOLDER}`);
    for (const dir of DATA_DIRS) roots.push(`${home}/${dir}/${SESSIONS_FOLDER}`);
    return [...new Set(roots)];
  },

  /** The one database under a sessions directory. */
  discover(root, io) {
    const db = `${root}/${DB_NAME}`;
    return io.stat(db)?.isDirectory === false ? [db] : [];
  },

  parse(path, io) {
    return parseGooseSessionsDb(path, io);
  },

  /** A whole database is many sessions; the id comes from the rows. */
  sessionIdOf() {
    return undefined;
  },

  metered: true,
};
