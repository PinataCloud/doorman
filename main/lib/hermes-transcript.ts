/**
 * Hermes Agent session reading — the `hermes` TranscriptSourceDescriptor.
 *
 * Hermes (Nous Research) keeps every CLI and gateway session in ONE SQLite
 * database, `$HERMES_HOME/state.db` (default `~/.hermes/state.db`), in WAL
 * mode with external readers explicitly supported. The engine's SourceIo
 * opens it read-only from a WAL snapshot, so this file never touches the live
 * database and never writes.
 *
 * Schema, per https://hermes-agent.nousresearch.com/docs/developer-guide/session-storage
 * (fetched 2026-09-06; docs-derived — no Hermes install was available to
 * record against, so every column is read defensively):
 *
 *   sessions  id TEXT PK · source (cli / telegram / …) · model · title
 *             started_at, ended_at   REAL, Unix epoch seconds (time.time())
 *             input_tokens, output_tokens, cache_read_tokens,
 *             cache_write_tokens, reasoning_tokens          INTEGER (session totals)
 *             estimated_cost_usd, actual_cost_usd, cost_status, cost_source,
 *             billing_provider, billing_mode, pricing_version
 *             message_count, tool_call_count, api_call_count
 *             cwd, git_branch, git_repo_root, parent_session_id, …
 *   messages  id INTEGER PK AUTOINCREMENT · session_id · role · content
 *             tool_calls  TEXT — JSON, OpenAI style:
 *                         [{ id, type, function: { name, arguments: "<json>" } }]
 *             tool_call_id, tool_name  (set on the tool-result rows)
 *             timestamp REAL epoch seconds · token_count INTEGER · finish_reason …
 *   session_model_usage (session_id, model, task) → per-model token rows
 *
 * The schema is versioned (v23+ at the time of writing) and "simple column
 * additions are declarative", so an older database may lack any of the
 * newer columns. Every query here first asks `pragma_table_info` which columns
 * exist and selects only those; a missing column reads as null, never as a
 * thrown query.
 *
 * NUMBERS (rule 2 — honest, never invented):
 *   - Tokens live on the SESSION (per-message rows carry only `token_count`,
 *     a context-size estimate, not billing usage). So the session's usage and
 *     its host-reported cost are placed on the session's LAST assistant turn
 *     and on no other turn — the ledger's per-session roll-up is exact, the
 *     per-turn view shows one metered turn per session, and a re-parse puts
 *     the numbers on the same turn (the last assistant `messages.id`, which
 *     only grows). A session with every counter at zero (Hermes's ACP editor
 *     sessions, issue #6775) gets NO usage — activity, not spend.
 *   - `reasoning_tokens` is kept OUT of `output_tokens`: whether Hermes stores
 *     it as a separate bucket or a subset of output is not documented, and
 *     adding a subset would double-count. VERIFY against a real database.
 *   - Cost: `actual_cost_usd` when > 0 (the provider billed it), else
 *     `estimated_cost_usd` when > 0 (Hermes priced it), else our own
 *     `deriveCost` by provider/model, else `cost_unknown` — never $0.
 *   - Settlement is absent (= unknown) unless `billing_mode` is literally
 *     "subscription"; the documented values are not enumerated. VERIFY.
 *
 * TURNS. `user` rows become user turns (+ a prompt detect unit); `assistant`
 * rows become assistant turns carrying the tool names from `tool_calls` (+ a
 * tool_call detect unit per call); `tool` rows are tool OUTPUT detect units
 * anchored to the assistant turn whose call id they answer, never ledger
 * turns; `system` rows are Hermes's own scaffolding and are skipped. Turn ids
 * are `hermes:<session_id>:<messages.id>` — both halves are Hermes's own, so a
 * re-parse mints exactly the same id (rule 1). A row without a timestamp
 * inherits the previous row's, then the session's `started_at`.
 *
 * `title` is what Hermes generated for the session — an `auto_summary` title
 * in the ledger's precedence vocabulary.
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

const HERMES_DIR = ".hermes";
const STATE_DB = "state.db";

const SESSION_COLUMNS = [
  "id",
  "source",
  "model",
  "title",
  "started_at",
  "ended_at",
  "input_tokens",
  "output_tokens",
  "cache_read_tokens",
  "cache_write_tokens",
  "reasoning_tokens",
  "estimated_cost_usd",
  "actual_cost_usd",
  "billing_mode",
  "cwd",
  "git_branch",
] as const;

const MESSAGE_COLUMNS = [
  "id",
  "session_id",
  "role",
  "content",
  "tool_calls",
  "tool_call_id",
  "tool_name",
  "timestamp",
] as const;

function str(value: unknown): string | undefined {
  return typeof value === "string" && value !== "" ? value : undefined;
}

function num(value: unknown): number | undefined {
  const n = typeof value === "number" ? value : typeof value === "bigint" ? Number(value) : Number(value);
  return Number.isFinite(n) ? n : undefined;
}

function toInt(value: unknown): number {
  const n = num(value);
  if (n === undefined || n <= 0) return 0;
  return Math.floor(n);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Epoch seconds (Hermes's `time.time()` floats) → an ISO instant. */
function isoOf(value: unknown): string | undefined {
  const n = num(value);
  if (n === undefined || n <= 0) return undefined;
  // A value already in milliseconds (a future schema change) would land in
  // the year 50,000+; treat anything past 1e11 as ms rather than seconds.
  const ms = n > 1e11 ? n : n * 1000;
  const d = new Date(ms);
  return Number.isNaN(d.getTime()) ? undefined : d.toISOString();
}

/**
 * Every query is best-effort: a database Hermes is mid-write on, a table an
 * older build never created — all mean "nothing to read here", never a throw
 * out of `parse` (contract rule: total).
 */
function query(io: SourceIo, path: string, sql: string, params?: readonly unknown[]): Record<string, unknown>[] {
  try {
    return io.querySqlite(path, sql, params) ?? [];
  } catch {
    return [];
  }
}

/** The subset of `wanted` columns this database's `table` actually has. */
function existingColumns(io: SourceIo, path: string, table: string, wanted: readonly string[]): string[] {
  const rows = query(io, path, `SELECT name FROM pragma_table_info('${table}')`);
  const have = new Set(rows.map((r) => str(r.name)).filter((n): n is string => n !== undefined));
  return wanted.filter((c) => have.has(c));
}

interface ToolCall {
  id?: string;
  name: string;
  arguments: unknown;
}

/** `messages.tool_calls` → the calls in it. OpenAI's shape is the documented
 * one; a flat `{name, arguments}` is tolerated. `arguments` is usually a JSON
 * STRING — kept as parsed JSON when it parses, as text otherwise. */
function parseToolCalls(raw: unknown): ToolCall[] {
  let list: unknown = raw;
  if (typeof raw === "string") {
    if (raw.trim() === "") return [];
    try {
      list = JSON.parse(raw);
    } catch {
      return [];
    }
  }
  if (!Array.isArray(list)) return [];
  const out: ToolCall[] = [];
  for (const item of list) {
    if (!isRecord(item)) continue;
    const fn = isRecord(item.function) ? item.function : item;
    const name = str(fn.name);
    if (!name) continue;
    let args: unknown = fn.arguments;
    if (typeof args === "string") {
      try {
        args = JSON.parse(args);
      } catch {
        // keep the text
      }
    }
    out.push({ id: str(item.id), name, arguments: args ?? {} });
  }
  return out;
}

/** Hermes's own argument names (tools/*.py), then the shared rule. */
function hermesToolTarget(name: string, args: unknown): string | undefined {
  if (!isRecord(args)) return undefined;
  if (name === "terminal") {
    const command = str(args.command);
    if (!command) return undefined;
    const head = command.trim().split(/\s+/, 1)[0];
    return head === "" ? undefined : head;
  }
  const urls = Array.isArray(args.urls) ? args.urls.find((u): u is string => typeof u === "string") : undefined;
  return toolTarget(name, args) ?? str(args.path) ?? str(args.url) ?? urls ?? str(args.pattern) ?? str(args.query);
}

function argsText(args: unknown): string {
  if (typeof args === "string") return args;
  try {
    return JSON.stringify(args);
  } catch {
    return String(args);
  }
}

interface SessionRow {
  id: string;
  model?: string;
  title?: string;
  started_at?: string;
  usage?: TurnUsage;
  cost?: number;
  cost_unknown?: boolean;
  settlement?: "subscription";
  cwd?: string;
  git_branch?: string;
}

function readSession(row: Record<string, unknown>): SessionRow | undefined {
  const id = str(row.id);
  if (!id) return undefined;
  const session: SessionRow = { id };
  const model = str(row.model);
  if (model) session.model = model;
  const title = str(row.title);
  if (title) session.title = title;
  const started = isoOf(row.started_at);
  if (started) session.started_at = started;
  const cwd = str(row.cwd);
  if (cwd) session.cwd = cwd;
  const branch = str(row.git_branch);
  if (branch) session.git_branch = branch;

  const usage: TurnUsage = {
    input_tokens: toInt(row.input_tokens),
    output_tokens: toInt(row.output_tokens),
    cache_read_tokens: toInt(row.cache_read_tokens),
    cache_write_tokens: toInt(row.cache_write_tokens),
    cache_write_1h_tokens: 0,
    web_search_requests: 0,
  };
  const metered =
    usage.input_tokens + usage.output_tokens + usage.cache_read_tokens + usage.cache_write_tokens > 0;
  if (metered) {
    session.usage = usage;
    const actual = num(row.actual_cost_usd);
    const estimated = num(row.estimated_cost_usd);
    if (actual !== undefined && actual > 0) session.cost = actual;
    else if (estimated !== undefined && estimated > 0) session.cost = estimated;
    else {
      const derived = model
        ? deriveCost({
            model_provider: inferModelProvider(model) ?? "unknown",
            model,
            input_tokens: usage.input_tokens,
            output_tokens: usage.output_tokens,
            cached_tokens: usage.cache_read_tokens,
            cache_read_tokens: usage.cache_read_tokens,
            cache_write_tokens: usage.cache_write_tokens,
            web_search_requests: 0,
          })
        : undefined;
      if (derived === undefined) session.cost_unknown = true;
      else session.cost = derived;
    }
    if (str(row.billing_mode) === "subscription") session.settlement = "subscription";
  }
  return session;
}

/**
 * Parse one Hermes `state.db`: every session's messages → turns, titles and
 * detect units. Exported for tests; the descriptor's `parse` is this over the
 * engine's io.
 */
export function parseHermesDatabase(path: string, io: SourceIo): TranscriptParseResult {
  const turns: LedgerTurn[] = [];
  const titles: TitleRecord[] = [];
  const detect: DetectUnit[] = [];

  const sessionCols = existingColumns(io, path, "sessions", SESSION_COLUMNS);
  const messageCols = existingColumns(io, path, "messages", MESSAGE_COLUMNS);
  if (!sessionCols.includes("id") || !messageCols.includes("session_id") || !messageCols.includes("id")) {
    return { turns, titles, detect };
  }

  const sessions = new Map<string, SessionRow>();
  for (const row of query(io, path, `SELECT ${sessionCols.join(", ")} FROM sessions`)) {
    const session = readSession(row);
    if (session) sessions.set(session.id, session);
  }
  for (const session of sessions.values()) {
    if (session.title) {
      titles.push({ session_id: session.id, title: { text: session.title, origin: "auto_summary" } });
    }
  }

  const rows = query(io, path, `SELECT ${messageCols.join(", ")} FROM messages ORDER BY session_id, id`);

  // Per session: the last assistant turn (where the session's usage lands),
  // the last instant seen (for rows without one) and call id → anchor turn.
  const lastAssistant = new Map<string, LedgerTurn>();
  const lastAt = new Map<string, string>();
  const anchorByCall = new Map<string, string>();

  for (const row of rows) {
    const sessionId = str(row.session_id);
    const msgId = num(row.id);
    if (!sessionId || msgId === undefined) continue;
    const session = sessions.get(sessionId) ?? { id: sessionId };
    const role = str(row.role);
    const at = isoOf(row.timestamp) ?? lastAt.get(sessionId) ?? session.started_at;
    if (!at) continue; // no instant anywhere — unchartable
    lastAt.set(sessionId, at);
    const id = `hermes:${sessionId}:${msgId}`;
    const scope = {
      ...(session.cwd === undefined ? {} : { cwd: session.cwd }),
    };
    const content = str(row.content);

    if (role === "user") {
      if (!content) continue;
      turns.push({
        id,
        source: "hermes",
        session_id: sessionId,
        role: "user",
        at,
        text: content.slice(0, TURN_TEXT_MAX_CHARS),
        ...scope,
        ...(session.git_branch === undefined ? {} : { git_branch: session.git_branch }),
      });
      detect.push({ kind: "prompt", raw: content, session_id: sessionId, turn_id: id, at, ...scope });
      continue;
    }

    if (role === "assistant") {
      const calls = parseToolCalls(row.tool_calls);
      if (!content && calls.length === 0) continue; // an empty placeholder row
      const turn: LedgerTurn = {
        id,
        source: "hermes",
        session_id: sessionId,
        role: "assistant",
        at,
        ...scope,
        ...(session.git_branch === undefined ? {} : { git_branch: session.git_branch }),
      };
      if (session.model) turn.model = session.model;
      if (content) turn.text = content.slice(0, TURN_TEXT_MAX_CHARS);
      const named: string[] = [];
      for (const call of calls) {
        named.push(call.name);
        if (call.id) anchorByCall.set(`${sessionId}:${call.id}`, id);
        const target = hermesToolTarget(call.name, call.arguments);
        detect.push({
          kind: "tool_call",
          raw: argsText(call.arguments),
          tool_name: call.name,
          ...(target === undefined ? {} : { target }),
          session_id: sessionId,
          turn_id: id,
          at,
          ...scope,
        });
      }
      if (named.length > 0) turn.tools = named.slice(0, TURN_TOOLS_MAX);
      turns.push(turn);
      lastAssistant.set(sessionId, turn);
      continue;
    }

    if (role === "tool") {
      if (!content) continue;
      const callId = str(row.tool_call_id);
      const anchor = callId ? anchorByCall.get(`${sessionId}:${callId}`) : undefined;
      const toolName = str(row.tool_name);
      detect.push({
        kind: "tool_output",
        raw: content.slice(0, TOOL_OUTPUT_MAX_CHARS),
        ...(toolName === undefined ? {} : { tool_name: toolName }),
        session_id: sessionId,
        turn_id: id,
        at,
        ...(anchor === undefined ? {} : { anchor_turn_id: anchor }),
        ...scope,
      });
    }
    // `system` and anything else: Hermes's own scaffolding, never spend.
  }

  // The session's numbers land on its LAST assistant turn (see NUMBERS).
  for (const [sessionId, turn] of lastAssistant) {
    const session = sessions.get(sessionId);
    if (!session?.usage) continue;
    turn.usage = session.usage;
    if (session.cost !== undefined) turn.cost = session.cost;
    if (session.cost_unknown) turn.cost_unknown = true;
    if (session.settlement) turn.settlement = session.settlement;
  }

  turns.sort((a, b) => (a.at < b.at ? -1 : a.at > b.at ? 1 : a.id.localeCompare(b.id)));
  return { turns, titles, detect };
}

export const hermesSource: TranscriptSourceDescriptor = {
  id: "hermes",
  label: "Hermes Agent",
  presencePaths: [HERMES_DIR],

  /** `$HERMES_HOME` moves the whole directory (hermes_constants
   * .get_hermes_home()). Both are returned when it is set: the override is
   * where Hermes writes now, the default is where it wrote before. */
  roots(home, env) {
    const override = str(env["HERMES_HOME"]?.trim());
    const roots = [`${home}/${HERMES_DIR}`];
    if (override) roots.unshift(override);
    return [...new Set(roots)];
  },

  /** One document per root: the database itself, when it exists. */
  discover(root, io) {
    const db = `${root}/${STATE_DB}`;
    const stat = io.stat(db);
    return stat && !stat.isDirectory ? [db] : [];
  },

  parse(path, io) {
    try {
      return parseHermesDatabase(path, io);
    } catch {
      return { turns: [], titles: [], detect: [] };
    }
  },

  /** A database holds every session — the path names none of them. */
  sessionIdOf() {
    return undefined;
  },

  metered: true,
};
