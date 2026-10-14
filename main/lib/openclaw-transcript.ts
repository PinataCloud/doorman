/**
 * OpenClaw session reading — the `openclaw` TranscriptSourceDescriptor.
 *
 * OpenClaw (an always-on agent gateway: messaging channels, cron, heartbeats)
 * records every agent session to disk itself. The writer is not OpenClaw's own
 * code but the pi coding agent's `SessionManager`, which OpenClaw embeds
 * (`@mariozechner/pi-coding-agent`, session file version 3), so the on-disk
 * shape is pi's — verified against the copy inside the OpenClaw 2026.3.8
 * installed on this Mac (`node_modules/@mariozechner/pi-coding-agent/dist/
 * core/session-manager.js` and `@mariozechner/pi-ai/dist/types.d.ts`,
 * 2026-09-06). The docs' own examples
 * (docs.openclaw.ai/reference/token-use, /reference/session-management-
 * compaction) match it line for line.
 *
 *   <state>/agents/<agentId>/sessions/<ISO-ts-with-dashes>_<sessionId>.jsonl
 *   <state>/agents/<agentId>/sessions/<sessionId>.jsonl          (older name)
 *   <state>/agents/<agentId>/sessions/sessions.json              (the index — skipped)
 *
 * `<state>` is `$OPENCLAW_STATE_DIR` (or the legacy `$CLAWDBOT_STATE_DIR`),
 * else `~/.openclaw`. The index is being superseded by a per-agent SQLite
 * store on newer builds, so nothing here depends on it.
 *
 * ONE JSON ENTRY PER LINE, a tree rather than a list (v2+ entries carry
 * `id` — 8 hex chars, unique within the file — and `parentId`; `/rewind` and
 * branching create siblings). Entry types, all with `{ type, id, parentId,
 * timestamp (ISO) }` except the header:
 *   session      { version, id: <sessionId>, timestamp, cwd, parentSession? } — line 1
 *   message      { message }  where message is pi-ai's
 *                  UserMessage   { role:"user", content: string | [{type:"text",text}|{type:"image"}], timestamp(ms) }
 *                  AssistantMessage { role:"assistant", content:[{type:"text"|"thinking"|"toolCall"{id,name,arguments}}],
 *                                     api, provider, model, usage:{input,output,cacheRead,cacheWrite,totalTokens,
 *                                     cost:{input,output,cacheRead,cacheWrite,total}}, stopReason, errorMessage?, timestamp(ms) }
 *                  ToolResultMessage { role:"toolResult", toolCallId, toolName, content:[{type:"text",text}|{type:"image"}],
 *                                      details?, isError, timestamp(ms) }
 *   session_info { name }                — the session's display name (a title)
 *   model_change { provider, modelId }   — the assistant messages carry model anyway
 *   compaction, branch_summary, custom, custom_message, label, thinking_level_change — skipped
 * Older (v1) files have no `id`/`parentId`, and the oldest have the message
 * fields FLAT on the line (`{"type":"message","role":"assistant",…,
 * "timestamp":1770355978327}`); both are read.
 *
 * METERING — every assistant message carries pi-ai's normalized `usage`,
 * whatever the provider. `input`/`output`/`cacheRead`/`cacheWrite` map 1:1
 * onto TurnUsage (`totalTokens` is their sum and is ignored). `cost.total` is
 * pi-ai's OWN figure from the model's configured price — `models.providers.
 * *.models[].cost` in openclaw.json, USD per million — and is 0 for a model
 * with no price. So: a `cost.total > 0` is honoured as the host's number;
 * otherwise the turn is priced from the built-in pricing table by `provider/model`
 * (OpenRouter-style `vendor/model` ids are split first), and a model neither
 * side can price is `cost_unknown`, never $0. SETTLEMENT is absent (= unknown):
 * nothing on the line says whether the provider was a paid key or a
 * subscription OAuth session.
 *
 * WHAT IS DELIBERATELY KEPT: heartbeat and cron runs. OpenClaw's own dashboard
 * classifies them by message content; they write to the same tree and spend
 * the same tokens, so they are turns like any other here (a rail hiding its
 * background spend would be the one thing a spend monitor must not do).
 *
 * STABLE IDS (rule 1): `openclaw:<sessionId>:<entry.id>` — the entry id is
 * minted once and never changes across re-reads or branching; a v1 line
 * without one falls back to its 0-based line number, which is stable in an
 * append-only file. Tool results are detect units anchored to the assistant
 * turn whose `toolCall.id` they answer.
 *
 * LOCAL TEXT (rule 3): prompt/assistant text stays on this machine, capped.
 */

import path from "node:path";
import type { DetectUnit, TranscriptParseResult } from "./cc-transcript.js";
import { deriveCost, inferModelProvider, splitVendorPrefixedModel } from "./pricing.js";
import type { SourceIo, TranscriptSourceDescriptor } from "./transcript-sources.js";
import {
  type LedgerTurn,
  type TitleRecord,
  type TurnUsage,
  TOOL_OUTPUT_MAX_CHARS,
  TURN_TEXT_MAX_CHARS,
  TURN_TOOLS_MAX,
} from "./turns.js";

const SOURCE = "openclaw" as const;
const STATE_DIR = ".openclaw";
const AGENTS_DIR = "agents";
const SESSIONS_DIR = "sessions";
const SESSION_INDEX = "sessions.json";

const UUID_RE = "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}";
/** `<ts>_<uuid>.jsonl` (pi's SessionManager) or `<uuid>.jsonl` (older OpenClaw). */
const SESSION_FILENAME_RE = new RegExp(`^(?:.+_)?(${UUID_RE})\\.jsonl$`, "i");

function str(value: unknown): string | undefined {
  return typeof value === "string" && value !== "" ? value : undefined;
}

function toInt(value: unknown): number {
  const n = typeof value === "number" ? value : Number(value);
  if (!Number.isFinite(n) || n <= 0) return 0;
  return Math.floor(n);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** An ISO instant from an ISO string or pi-ai's epoch-ms `timestamp`. */
function isoOf(value: unknown): string | undefined {
  if (typeof value === "string") {
    return value !== "" && !Number.isNaN(Date.parse(value)) ? value : undefined;
  }
  if (typeof value !== "number" || !Number.isFinite(value) || value <= 0) return undefined;
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? undefined : d.toISOString();
}

/** `OPENCLAW_STATE_DIR` / legacy `CLAWDBOT_STATE_DIR`, else `~/.openclaw`. */
export function openclawStateDir(home: string, env: NodeJS.ProcessEnv): string {
  const configured = str(env.OPENCLAW_STATE_DIR?.trim()) ?? str(env.CLAWDBOT_STATE_DIR?.trim());
  return configured ?? path.join(home, STATE_DIR);
}

/** The text of a pi-ai content value: a string, or its `text` blocks. Thinking
 * blocks are the model's own reasoning, not its answer — dropped. */
function contentText(value: unknown): string {
  if (typeof value === "string") return value;
  if (!Array.isArray(value)) return "";
  const parts: string[] = [];
  for (const block of value) {
    if (!isRecord(block)) continue;
    if (block.type === "text" && typeof block.text === "string" && block.text !== "") parts.push(block.text);
  }
  return parts.join("\n");
}

interface ToolCallBlock {
  id?: string;
  name: string;
  arguments: unknown;
}

function toolCalls(content: unknown): ToolCallBlock[] {
  if (!Array.isArray(content)) return [];
  const out: ToolCallBlock[] = [];
  for (const block of content) {
    if (!isRecord(block) || block.type !== "toolCall") continue;
    const name = str(block.name);
    if (!name) continue;
    out.push({ id: str(block.id), name, arguments: block.arguments ?? {} });
  }
  return out;
}

/** What the call is pointed at — the shell program for `exec`, the path for
 * the file tools, the URL for `web_fetch`; undefined rather than a guess. */
function openclawToolTarget(name: string, args: unknown): string | undefined {
  if (!isRecord(args)) return undefined;
  if (name === "exec" || name === "bash") {
    const command = str(args.command);
    if (!command) return undefined;
    const head = command.trim().split(/\s+/, 1)[0];
    return head === "" ? undefined : head;
  }
  return str(args.path) ?? str(args.file_path) ?? str(args.url);
}

/** pi-ai `Usage` → the ledger's `TurnUsage`; undefined when nothing was counted. */
function usageOf(raw: unknown): TurnUsage | undefined {
  if (!isRecord(raw)) return undefined;
  const usage: TurnUsage = {
    input_tokens: toInt(raw.input),
    output_tokens: toInt(raw.output),
    cache_read_tokens: toInt(raw.cacheRead),
    cache_write_tokens: toInt(raw.cacheWrite),
    cache_write_1h_tokens: 0,
    web_search_requests: 0,
  };
  const total = usage.input_tokens + usage.output_tokens + usage.cache_read_tokens + usage.cache_write_tokens;
  return total > 0 ? usage : undefined;
}

/** The host's own cost when it priced the call, else undefined. */
function hostCost(raw: unknown): number | undefined {
  if (!isRecord(raw) || !isRecord(raw.cost)) return undefined;
  const total = raw.cost.total;
  return typeof total === "number" && Number.isFinite(total) && total > 0 ? total : undefined;
}

/** Price a turn from the built-in pricing table: `vendor/model` ids are split first
 * (OpenRouter's convention), then the model's own name, then OpenClaw's
 * `provider` field decides the vendor. */
function derivedCost(provider: string | undefined, model: string, usage: TurnUsage): number | undefined {
  const split = splitVendorPrefixedModel(model);
  const modelId = split?.model ?? model;
  const vendor =
    split?.provider ??
    inferModelProvider(modelId) ??
    (provider && provider !== "openrouter" ? provider : undefined);
  if (!vendor) return undefined;
  return deriveCost({
    model_provider: vendor,
    model: modelId,
    input_tokens: usage.input_tokens,
    output_tokens: usage.output_tokens,
    cached_tokens: usage.cache_read_tokens,
    cache_read_tokens: usage.cache_read_tokens,
    cache_write_tokens: usage.cache_write_tokens,
    web_search_requests: 0,
  });
}

interface Entry {
  type: string;
  id?: string;
  at?: string;
  /** The message payload — nested (v2+) or the line itself (flat v1). */
  message?: Record<string, unknown>;
  raw: Record<string, unknown>;
}

/** Fold one line into an Entry; undefined for a line still being written. */
function readEntry(line: string, index: number): Entry | undefined {
  let parsed: unknown;
  try {
    parsed = JSON.parse(line);
  } catch {
    return undefined;
  }
  if (!isRecord(parsed)) return undefined;
  const type = str(parsed.type);
  if (!type) return undefined;
  const nested = isRecord(parsed.message) ? parsed.message : undefined;
  // Flat v1 line: the role sits on the line itself.
  const message = nested ?? (str(parsed.role) ? parsed : undefined);
  const at = isoOf(parsed.timestamp) ?? (message ? isoOf(message.timestamp) : undefined);
  return {
    type,
    id: str(parsed.id) ?? `line${index}`,
    ...(at === undefined ? {} : { at }),
    ...(type === "message" && message ? { message } : {}),
    raw: parsed,
  };
}

/**
 * Parse one OpenClaw session document. `fallbackSessionId` is used when the
 * header line is missing or unreadable (a file whose first line is still
 * being written).
 */
export function parseOpenclawSession(contents: string, fallbackSessionId: string): TranscriptParseResult {
  const turns: LedgerTurn[] = [];
  const detect: DetectUnit[] = [];
  const titles: TitleRecord[] = [];

  const lines = contents.split("\n");
  let sessionId = fallbackSessionId;
  let cwd: string | undefined;
  /** toolCall id → the assistant turn that made it (tool results anchor here). */
  const callTurn = new Map<string, string>();
  let lastAssistantTurn: string | undefined;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!.trim();
    if (line === "") continue;
    const entry = readEntry(line, i);
    if (!entry) continue;

    if (entry.type === "session") {
      const id = str(entry.raw.id);
      if (id) sessionId = id;
      const dir = str(entry.raw.cwd);
      if (dir) cwd = dir;
      continue;
    }
    if (entry.type === "session_info") {
      const name = str(entry.raw.name)?.trim();
      if (name) titles.push({ session_id: sessionId, title: { text: name, origin: "auto_summary" } });
      continue;
    }
    if (entry.type !== "message" || !entry.message) continue;
    const at = entry.at;
    if (!at) continue; // no instant — unchartable, the same rule every source applies
    const message = entry.message;
    const id = `openclaw:${sessionId}:${entry.id}`;
    const withCwd = cwd === undefined ? {} : { cwd };
    const role = str(message.role);

    if (role === "user") {
      const text = contentText(message.content).trim();
      if (text === "") continue;
      turns.push({ id, source: SOURCE, session_id: sessionId, role: "user", at, text: text.slice(0, TURN_TEXT_MAX_CHARS), ...withCwd });
      detect.push({ kind: "prompt", raw: text, session_id: sessionId, turn_id: id, at, ...withCwd });
      continue;
    }

    if (role === "toolResult") {
      const output = contentText(message.content);
      if (output === "") continue;
      const callId = str(message.toolCallId);
      const anchor = (callId && callTurn.get(callId)) ?? lastAssistantTurn;
      const toolName = str(message.toolName);
      detect.push({
        kind: "tool_output",
        raw: output.slice(0, TOOL_OUTPUT_MAX_CHARS),
        ...(toolName === undefined ? {} : { tool_name: toolName }),
        session_id: sessionId,
        turn_id: id,
        ...(anchor === undefined ? {} : { anchor_turn_id: anchor }),
        at,
        ...withCwd,
      });
      continue;
    }

    if (role !== "assistant") continue;
    const text = contentText(message.content).trim();
    const calls = toolCalls(message.content);
    const usage = usageOf(message.usage);
    // An errored or aborted call with nothing on it is not a turn: no tokens
    // were spent and nothing was said (stopReason "error" lines look like this).
    if (!usage && text === "" && calls.length === 0) continue;

    const turn: LedgerTurn = { id, source: SOURCE, session_id: sessionId, role: "assistant", at, ...withCwd };
    const model = str(message.model);
    if (model) turn.model = model;
    if (usage) {
      turn.usage = usage;
      const own = hostCost(message.usage);
      const cost = own ?? (model ? derivedCost(str(message.provider), model, usage) : undefined);
      if (cost === undefined) turn.cost_unknown = true;
      else turn.cost = cost;
    }
    if (text !== "") turn.text = text.slice(0, TURN_TEXT_MAX_CHARS);

    const named: string[] = [];
    for (const call of calls) {
      named.push(call.name);
      if (call.id) callTurn.set(call.id, id);
      const target = openclawToolTarget(call.name, call.arguments);
      detect.push({
        kind: "tool_call",
        raw: JSON.stringify(call.arguments),
        tool_name: call.name,
        ...(target === undefined ? {} : { target }),
        session_id: sessionId,
        turn_id: id,
        at,
        ...withCwd,
      });
    }
    if (named.length > 0) turn.tools = named.slice(0, TURN_TOOLS_MAX);
    turns.push(turn);
    lastAssistantTurn = id;
  }

  turns.sort((a, b) => (a.at < b.at ? -1 : a.at > b.at ? 1 : a.id.localeCompare(b.id)));
  return { turns, titles, detect };
}

export const openclawSource: TranscriptSourceDescriptor = {
  id: SOURCE,
  label: "OpenClaw",
  presencePaths: [STATE_DIR],

  /** Every agent's sessions live under one `agents/` directory in the state dir. */
  roots(home, env) {
    return [path.join(openclawStateDir(home, env), AGENTS_DIR)];
  },

  /** `<root>/<agentId>/sessions/*.jsonl` — the index and any directory skipped. */
  discover(root, io) {
    const found: string[] = [];
    for (const agent of io.listDir(root).sort()) {
      const sessions = path.join(root, agent, SESSIONS_DIR);
      if (io.stat(sessions)?.isDirectory !== true) continue;
      for (const name of io.listDir(sessions).sort()) {
        if (!name.endsWith(".jsonl") || name === SESSION_INDEX) continue;
        const full = path.join(sessions, name);
        if (io.stat(full)?.isDirectory === false) found.push(full);
      }
    }
    return found;
  },

  parse(filePath, io) {
    const contents = io.readText(filePath);
    if (contents === undefined || contents === "") return { turns: [], titles: [], detect: [] };
    return parseOpenclawSession(contents, openclawSource.sessionIdOf(filePath) ?? filePath);
  },

  sessionIdOf(filePath) {
    const name = filePath.split(/[\\/]/).pop() ?? "";
    return SESSION_FILENAME_RE.exec(name)?.[1]?.toLowerCase();
  },

  metered: true,
};
