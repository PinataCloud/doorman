/**
 * Gemini CLI session reading — the `gemini-cli` TranscriptSourceDescriptor.
 *
 * Gemini CLI records every conversation to disk itself (its "chat recording
 * service"), which is the only ground truth this app needs: no hook, no
 * gateway, no provider call. One file per session under the project's temp
 * directory:
 *
 *   ~/.gemini/tmp/<project-id>/chats/session-<YYYY-MM-DDTHH-mm>-<id8>.jsonl
 *   ~/.gemini/tmp/<project-id>/chats/<parentSessionId>/<sessionId>.jsonl   (subagents)
 *
 * `<project-id>` is a per-project directory: historically the sha256 hex of the
 * project root, now a human-readable slug claimed in ~/.gemini/projects.json.
 * Either way the directory holds a `.project_root` marker file whose contents
 * are the absolute project root — that is where a turn's `cwd` comes from.
 *
 * TWO ON-DISK FORMATS, both read here:
 *   - LEGACY `.json` — the whole `ConversationRecord` as one JSON object.
 *   - CURRENT `.jsonl` — an append log whose lines are, in any mix:
 *       * a partial metadata record (`{sessionId, projectHash, startTime, …}`),
 *       * a full `MessageRecord` (upsert by `id` — a message is REWRITTEN in
 *         place when its tokens or tool results arrive later),
 *       * `{"$set": {…}}` metadata patch (whose `messages` key, when present,
 *         REPLACES the whole message list), or
 *       * `{"$rewindTo": "<messageId>"}` — drop that message and everything
 *         after it (`/rewind`; an unknown id clears the conversation).
 *     Replaying those in order is exactly upstream `loadConversationRecord`,
 *     and it is what makes a re-parse converge rather than duplicate.
 *
 * VERIFIED AGAINST UPSTREAM (fetched 2026-09-06, google-gemini/gemini-cli
 * `main` @ 85aca163f6c73ac6ce380b5447359146b8adcae4, latest release v0.58.0):
 *   - packages/core/src/services/chatRecordingTypes.ts — `ConversationRecord`,
 *     `MessageRecord`, `TokensSummary`, `ToolCallRecord`, `SESSION_FILE_PREFIX`.
 *   - packages/core/src/services/chatRecordingService.ts — the filename
 *     (`${SESSION_FILE_PREFIX}${timestamp}-${sessionId.slice(0,8)}.jsonl`,
 *     timestamp = `new Date().toISOString().slice(0,16).replace(/:/g,'-')`),
 *     the `.json` → `.jsonl` migration, `appendRecord`/`updateMetadata`/
 *     `pushMessage`, `recordMessageTokens`, `recordToolCalls`,
 *     `loadConversationRecord`, `parseLegacyRecordFallback`.
 *   - packages/core/src/utils/paths.ts — `GEMINI_DIR = '.gemini'`, and
 *     `homedir()` honouring the `GEMINI_CLI_HOME` env override.
 *   - packages/core/src/config/storage.ts — `TMP_DIR_NAME = 'tmp'`,
 *     `getProjectTempDir()`, `listProjectChatFiles()` (`.json` OR `.jsonl`).
 *   - packages/core/src/config/projectRegistry.ts — `PROJECT_ROOT_FILE =
 *     '.project_root'`, the slug registry and the sha256 legacy hash.
 *   - packages/core/src/utils/sessionUtils.ts — `isIgnoredUserContent`.
 *   - packages/core/src/config/models.ts — the model ids that appear in
 *     `MessageRecord.model`.
 *   Raw blobs were read at raw.githubusercontent.com/google-gemini/gemini-cli/main/…
 *
 * NUMBERS (rule 2 — honest, never invented):
 *   `TokensSummary` maps 1:1 onto the Gemini API's usageMetadata, with the
 *   field comments upstream spells out:
 *     input   = promptTokenCount        (INCLUDES the cached prefix)
 *     cached  = cachedContentTokenCount (a SUBSET of promptTokenCount)
 *     output  = candidatesTokenCount    (EXCLUDES thinking tokens)
 *     thoughts= thoughtsTokenCount      (billed at the OUTPUT rate)
 *     tool    = toolUsePromptTokenCount (billed at the INPUT rate)
 *   So: `input_tokens` = input − cached + tool, `cache_read_tokens` = cached,
 *   `output_tokens` = output + thoughts. Note the contrast with Codex, where
 *   `reasoning_output_tokens` is a SUBSET of `output_tokens` and adding it
 *   would double-count — here `thoughts` is a separate bucket, so it must be
 *   added. Gemini reports no cache-WRITE bucket (implicit caching costs
 *   nothing to write), so `cache_write_tokens` is 0.
 *
 *   Cost comes from the built-in pricing table via `deriveCost`. The current
 *   defaults (`gemini-2.5-pro`, `gemini-2.5-flash`, `gemini-3.1-pro-preview`,
 *   `gemini-3.1-flash-lite`, `gemini-3.5-flash`) are priced; the preview ids
 *   (`gemini-3-pro-preview`, `gemini-3-flash-preview`) and the Gemma models
 *   are not, and those turns come back `cost_unknown` rather than $0.
 *
 *   SETTLEMENT is deliberately absent (= unknown): the record says nothing
 *   about whether the session ran on a Code Assist subscription, a free tier
 *   or a paid API key, and guessing would be a lie.
 *
 * WHAT IS DELIBERATELY NOT READ:
 *   - `~/.gemini/antigravity/` — Google's Antigravity IDE, a different product
 *     with a different on-disk shape. Skipped by name in `discover`.
 *   - `<project-id>/logs.json` — the legacy prompt log
 *     (`{sessionId, messageId, timestamp, type, message}[]`,
 *     packages/core/src/core/logger.ts). Every prompt in it is already a `user`
 *     message in the session file, so reading it would duplicate turns.
 *   - `<project-id>/checkpoints/` — `/chat save` writes a named checkpoint of
 *     the *chat history* there, not a new session; its turns are the session's
 *     own and would double-count.
 */

import path from "node:path";
import { toolTarget, type DetectUnit, type TranscriptParseResult } from "./cc-transcript.js";
import { deriveCost, inferModelProvider } from "./pricing.js";
import {
  type LedgerTurn,
  type TitleRecord,
  type TurnUsage,
  TOOL_OUTPUT_MAX_CHARS,
  TURN_TEXT_MAX_CHARS,
  TURN_TOOLS_MAX,
} from "./turns.js";
import type { SourceIo, TranscriptSourceDescriptor } from "./transcript-sources.js";

/** upstream GEMINI_DIR (utils/paths.ts). */
const GEMINI_DIR = ".gemini";
/** upstream TMP_DIR_NAME (config/storage.ts). */
const TMP_DIR_NAME = "tmp";
/** upstream PROJECT_ROOT_FILE (config/projectRegistry.ts). */
const PROJECT_ROOT_FILE = ".project_root";
/** upstream SESSION_FILE_PREFIX (services/chatRecordingTypes.ts). */
const SESSION_FILE_PREFIX = "session-";
/** Google's Antigravity IDE keeps its own state under ~/.gemini — not Gemini CLI. */
const ANTIGRAVITY_DIR = "antigravity";
const CHATS_DIR = "chats";

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

/**
 * Flatten a `PartListUnion` (a string, a Part, or an array of either) to text.
 * Parts marked `thought: true` are the model's own reasoning stream, not its
 * answer, so they are dropped — they'd otherwise dominate the stored text and
 * the search index.
 */
function partsText(value: unknown): string {
  if (typeof value === "string") return value;
  if (Array.isArray(value)) return value.map(partsText).join("");
  if (!isRecord(value)) return "";
  if (value.thought === true) return "";
  return typeof value.text === "string" ? value.text : "";
}

/**
 * The text a tool RETURNED, out of a `ToolCallRecord.result` (a `PartListUnion`
 * of `functionResponse` parts, per the masking-sync in chatRecordingService).
 * `response` is a free-form object; its `output`/`error` string is the useful
 * payload when present, else the whole object serialized — a tool's output is
 * exactly where injected instructions arrive from outside, so nothing is
 * dropped just because the shape is unfamiliar.
 */
function toolResultText(result: unknown): string | undefined {
  const parts: string[] = [];
  const walk = (value: unknown): void => {
    if (typeof value === "string") {
      if (value !== "") parts.push(value);
      return;
    }
    if (Array.isArray(value)) {
      for (const item of value) walk(item);
      return;
    }
    if (!isRecord(value)) return;
    const fr = value.functionResponse;
    if (isRecord(fr)) {
      const response = fr.response;
      if (typeof response === "string") {
        if (response !== "") parts.push(response);
      } else if (isRecord(response)) {
        const direct = str(response.output) ?? str(response.error);
        parts.push(direct ?? JSON.stringify(response));
      } else if (response !== undefined) {
        parts.push(JSON.stringify(response));
      }
      return;
    }
    if (typeof value.text === "string" && value.text !== "") parts.push(value.text);
  };
  walk(result);
  const text = parts.join("\n");
  return text === "" ? undefined : text;
}

/**
 * The upstream `isIgnoredUserContent` (utils/sessionUtils.ts): slash commands,
 * `?` help, and the two ambient wrappers Gemini CLI injects as user messages.
 * None is a human prompt — as a turn, a title or search text each is pollution,
 * the same call cc-transcript and codex-rollout make for their hosts.
 */
function isIgnoredUserContent(trimmed: string): boolean {
  return (
    trimmed.length === 0 ||
    trimmed.startsWith("/") ||
    trimmed.startsWith("?") ||
    trimmed.startsWith("<session_context>") ||
    trimmed.startsWith("<hook_context>")
  );
}

/** Gemini's own tool argument names, then the shared cc-transcript rule. */
function geminiToolTarget(name: string, args: unknown): string | undefined {
  if (!isRecord(args)) return undefined;
  if (name === "run_shell_command") {
    const command = str(args.command);
    if (!command) return undefined;
    const head = command.trim().split(/\s+/, 1)[0];
    return head === "" ? undefined : head;
  }
  return (
    toolTarget(name, args) ??
    str(args.absolute_path) ??
    str(args.dir_path) ??
    str(args.pattern) ??
    str(args.url) ??
    str(args.prompt)
  );
}

// ---------------------------------------------------------------------------
// The on-disk record shapes (structural mirrors of chatRecordingTypes.ts).
// ---------------------------------------------------------------------------

interface GeminiToolCall {
  id?: string;
  name?: string;
  args?: unknown;
  result?: unknown;
  status?: string;
  timestamp?: string;
}

interface GeminiMessage {
  id: string;
  timestamp?: string;
  type?: string;
  content?: unknown;
  toolCalls?: GeminiToolCall[];
  tokens?: Record<string, unknown> | null;
  model?: string;
}

interface GeminiMetadata {
  sessionId?: string;
  projectHash?: string;
  summary?: string;
  directories?: unknown;
  kind?: string;
}

/**
 * Replay a session document into `{metadata, messages}` — the append log's
 * fold, or a legacy whole-file record. TOTAL: a half-written line, a truncated
 * file or a record of an unfamiliar shape is skipped, never thrown on.
 */
function readConversation(contents: string): { meta: GeminiMetadata; messages: GeminiMessage[] } {
  const meta: GeminiMetadata = {};
  const byId = new Map<string, GeminiMessage>();
  const order: string[] = [];

  const applyMeta = (source: Record<string, unknown>): void => {
    if (str(source.sessionId)) meta.sessionId = source.sessionId as string;
    if (str(source.projectHash)) meta.projectHash = source.projectHash as string;
    if (str(source.summary)) meta.summary = source.summary as string;
    if (Array.isArray(source.directories)) meta.directories = source.directories;
    if (str(source.kind)) meta.kind = source.kind as string;
  };
  const upsert = (msg: GeminiMessage): void => {
    if (!byId.has(msg.id)) order.push(msg.id);
    byId.set(msg.id, msg);
  };
  const replaceAll = (list: unknown): void => {
    byId.clear();
    order.length = 0;
    if (!Array.isArray(list)) return;
    for (const item of list) {
      if (isRecord(item) && str(item.id)) upsert(item as unknown as GeminiMessage);
    }
  };

  // Legacy `.json`: the whole ConversationRecord as one object. Recognised the
  // same way upstream's parseLegacyRecordFallback does — a `sessionId` — plus a
  // `messages` array, so a one-line `.jsonl` (metadata only) still folds below.
  try {
    const whole: unknown = JSON.parse(contents);
    if (isRecord(whole) && str(whole.sessionId) && Array.isArray(whole.messages)) {
      applyMeta(whole);
      replaceAll(whole.messages);
      return { meta, messages: order.map((id) => byId.get(id)!) };
    }
  } catch {
    // Not one JSON object — the append log below.
  }

  for (const raw of contents.split("\n")) {
    const line = raw.trim();
    if (line === "") continue;
    let record: unknown;
    try {
      record = JSON.parse(line);
    } catch {
      continue; // a line the CLI is still writing
    }
    if (!isRecord(record)) continue;

    if (str(record.$rewindTo)) {
      const target = record.$rewindTo as string;
      const idx = order.indexOf(target);
      if (idx === -1) {
        byId.clear();
        order.length = 0;
      } else {
        for (const id of order.splice(idx)) byId.delete(id);
      }
      continue;
    }
    if (isRecord(record.$set)) {
      const patch = record.$set;
      applyMeta(patch);
      if ("messages" in patch) replaceAll(patch.messages);
      continue;
    }
    if (str(record.id)) {
      upsert(record as unknown as GeminiMessage);
      continue;
    }
    if (str(record.sessionId)) applyMeta(record);
  }

  return { meta, messages: order.map((id) => byId.get(id)!) };
}

/** `~/.gemini/tmp/<project-id>` for a `…/chats/[<parent>/]<file>` path. */
function projectDirOf(filePath: string): string | undefined {
  const match = /^(.*)[\\/]chats[\\/]/.exec(filePath);
  return match?.[1];
}

/** `TokensSummary` → the ledger's `TurnUsage`. See NUMBERS in the header. */
function usageOf(tokens: Record<string, unknown>): TurnUsage {
  const prompt = toInt(tokens.input);
  const cached = Math.min(toInt(tokens.cached), prompt);
  return {
    input_tokens: prompt - cached + toInt(tokens.tool),
    output_tokens: toInt(tokens.output) + toInt(tokens.thoughts),
    cache_read_tokens: cached,
    cache_write_tokens: 0,
    cache_write_1h_tokens: 0,
    web_search_requests: 0,
  };
}

/**
 * Parse one Gemini CLI session document. `fallbackSessionId` stands in when the
 * file carries no metadata record yet (a session whose first line is still
 * being written); the file name only holds the first 8 characters of the id,
 * so for a `session-*` document that fallback is the path itself rather than a
 * truncated id that would never match the real one.
 */
export function parseGeminiSession(
  contents: string,
  fallbackSessionId: string,
  cwd?: string,
): TranscriptParseResult {
  const turns: LedgerTurn[] = [];
  const detect: DetectUnit[] = [];
  const titles: TitleRecord[] = [];
  const { meta, messages } = readConversation(contents);
  const sessionId = meta.sessionId ?? fallbackSessionId;
  const dir =
    cwd ??
    (Array.isArray(meta.directories) ? str(meta.directories[0]) : undefined);
  const withCwd = dir === undefined ? {} : { cwd: dir };

  if (meta.summary) {
    titles.push({
      session_id: sessionId,
      title: { text: meta.summary, origin: "auto_summary" },
    });
  }

  for (const msg of messages) {
    const at = str(msg.timestamp);
    if (!at) continue; // no instant — unchartable, same rule as cc-transcript
    const id = `gemini:${sessionId}:${msg.id}`;

    if (msg.type === "user") {
      const text = partsText(msg.content).trim();
      if (isIgnoredUserContent(text)) continue;
      turns.push({
        id,
        source: "gemini-cli",
        session_id: sessionId,
        role: "user",
        at,
        text: text.slice(0, TURN_TEXT_MAX_CHARS),
        ...withCwd,
      });
      detect.push({ kind: "prompt", raw: text, session_id: sessionId, turn_id: id, at, ...withCwd });
      continue;
    }
    // 'info' | 'error' | 'warning' are the CLI's own banners — never spend.
    if (msg.type !== "gemini") continue;

    const text = partsText(msg.content).trim();
    const calls = Array.isArray(msg.toolCalls) ? msg.toolCalls : [];
    const tokens = isRecord(msg.tokens) ? msg.tokens : undefined;
    // A gemini message with nothing on it is a placeholder the CLI rewrites
    // later (tokens and tool results arrive on their own append-log lines).
    if (!tokens && text === "" && calls.length === 0) continue;

    const turn: LedgerTurn = {
      id,
      source: "gemini-cli",
      session_id: sessionId,
      role: "assistant",
      at,
      ...withCwd,
    };
    const model = str(msg.model);
    if (model) turn.model = model;
    if (tokens) {
      const usage = usageOf(tokens);
      turn.usage = usage;
      // Without a recorded model there is nothing to price against — honest
      // unknown, never a guessed default (Codex has one model, Gemini does not).
      const cost = model
        ? deriveCost({
            model_provider: inferModelProvider(model) ?? "google",
            model,
            input_tokens: usage.input_tokens,
            output_tokens: usage.output_tokens,
            cached_tokens: usage.cache_read_tokens,
            cache_read_tokens: usage.cache_read_tokens,
            cache_write_tokens: usage.cache_write_tokens,
            web_search_requests: 0,
          })
        : undefined;
      if (cost === undefined) turn.cost_unknown = true;
      else turn.cost = cost;
    }
    if (text !== "") turn.text = text.slice(0, TURN_TEXT_MAX_CHARS);

    const named: string[] = [];
    for (const call of calls) {
      const name = str(call?.name);
      if (!name) continue;
      named.push(name);
      const callAt = str(call.timestamp) ?? at;
      const args = call.args ?? {};
      const target = geminiToolTarget(name, args);
      detect.push({
        kind: "tool_call",
        raw: JSON.stringify(args),
        tool_name: name,
        ...(target === undefined ? {} : { target }),
        session_id: sessionId,
        turn_id: id,
        at: callAt,
        ...withCwd,
      });
      const output = toolResultText(call.result);
      if (output === undefined) continue;
      detect.push({
        kind: "tool_output",
        raw: output.slice(0, TOOL_OUTPUT_MAX_CHARS),
        tool_name: name,
        ...(target === undefined ? {} : { target }),
        session_id: sessionId,
        turn_id: id,
        at: callAt,
        ...withCwd,
      });
    }
    if (named.length > 0) turn.tools = named.slice(0, TURN_TOOLS_MAX);
    turns.push(turn);
  }

  turns.sort((a, b) => (a.at < b.at ? -1 : a.at > b.at ? 1 : a.id.localeCompare(b.id)));
  return { turns, titles, detect };
}

/**
 * A subagent document is named for its FULL session id (`<sessionId>.jsonl`);
 * a main document only carries the first 8 characters of it, which is not the
 * id and must never be treated as one.
 */
const SUBAGENT_FILENAME_RE = /^([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\.jsonl?$/i;

function isSessionDocument(name: string): boolean {
  if (!name.endsWith(".json") && !name.endsWith(".jsonl")) return false;
  return name.startsWith(SESSION_FILE_PREFIX) || SUBAGENT_FILENAME_RE.test(name);
}

export const geminiSource: TranscriptSourceDescriptor = {
  id: "gemini-cli",
  label: "Gemini CLI",
  presencePaths: [GEMINI_DIR],

  /**
   * `GEMINI_CLI_HOME` replaces the home directory upstream's `homedir()`
   * returns, so the gemini dir moves wholesale. Both roots are returned when it
   * is set: the override is where the CLI writes now, and the real home is
   * where it wrote before the variable existed. A root that doesn't exist costs
   * nothing — `discover` returns [] for it.
   */
  roots(home, env) {
    const override = str(env["GEMINI_CLI_HOME"]);
    const roots = [path.join(home, GEMINI_DIR, TMP_DIR_NAME)];
    if (override) roots.unshift(path.join(override, GEMINI_DIR, TMP_DIR_NAME));
    return [...new Set(roots)];
  },

  /**
   * Every session document under `~/.gemini/tmp`: one `chats/` directory per
   * project id, plus one nesting level for a parent session's subagents.
   */
  discover(root, io) {
    const found: string[] = [];
    const files = (dir: string): void => {
      for (const name of io.listDir(dir).sort()) {
        const full = path.join(dir, name);
        if (isSessionDocument(name)) {
          if (io.stat(full)?.isDirectory === false) found.push(full);
        }
      }
    };
    for (const project of io.listDir(root).sort()) {
      if (project === ANTIGRAVITY_DIR) continue;
      const chats = path.join(root, project, CHATS_DIR);
      if (io.stat(chats)?.isDirectory !== true) continue;
      files(chats);
      // chats/<parentSessionId>/<sessionId>.jsonl
      for (const entry of io.listDir(chats).sort()) {
        const nested = path.join(chats, entry);
        if (io.stat(nested)?.isDirectory === true) files(nested);
      }
    }
    return found;
  },

  parse(filePath, io) {
    const contents = io.readText(filePath);
    if (contents === undefined || contents === "") {
      return { turns: [], titles: [], detect: [] };
    }
    const projectDir = projectDirOf(filePath);
    const cwd = projectDir
      ? str(io.readText(path.join(projectDir, PROJECT_ROOT_FILE))?.trim())
      : undefined;
    return parseGeminiSession(contents, geminiSource.sessionIdOf(filePath) ?? filePath, cwd);
  },

  sessionIdOf(filePath) {
    const name = filePath.split(/[\\/]/).pop() ?? "";
    return SUBAGENT_FILENAME_RE.exec(name)?.[1];
  },

  metered: true,
};
