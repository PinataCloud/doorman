/**
 * Qwen Code session reading — the `qwen-code` TranscriptSourceDescriptor.
 *
 * Qwen Code (Alibaba, QwenLM/qwen-code) forked Gemini CLI, but its chat
 * recording DIVERGED: it is NOT the `$set`/`$rewindTo` append log
 * gemini-transcript.ts replays. Verified against upstream on 2026-09-06
 * (QwenLM/qwen-code `main`, `packages/core/src/services/chatRecordingService.ts`
 * and `packages/core/src/config/storage.ts`, read via the GitHub contents API):
 *
 *   FILE      `<base>/projects/<sanitized-cwd>/chats/<sessionId>.jsonl`
 *             where `<base>` is `$QWEN_HOME` or `~/.qwen` (`Storage.
 *             getGlobalQwenDir`) and `getProjectDir()` = `<base>/projects/
 *             <sanitizeCwd(projectRoot)>`. The service's own doc comment still
 *             says `~/.qwen/tmp/<project_id>/chats/`, the older hashed layout
 *             — so `tmp/` is walked too. There is NO `.project_root` marker:
 *             every record carries `cwd` itself.
 *   RECORD    append-only JSONL, one `ChatRecord` per line, a tree by
 *             `uuid`/`parentUuid` (branches from `/rewind`), "never rewrite
 *             the file":
 *               { uuid, parentUuid, sessionId, timestamp (ISO), cwd, version,
 *                 gitBranch?, type: 'user'|'assistant'|'tool_result'|'system',
 *                 subtype?, provenance?, message?: Content, usageMetadata?,
 *                 model?, contextWindowSize?, toolCallResult?, systemPayload? }
 *             `message` is the Gemini API `Content` (`{role, parts}`), parts
 *             being `{text}`, `{text, thought: true}`, `{functionCall:{id?,
 *             name, args}}` or `{functionResponse:{id?, name, response}}`.
 *   USER      `recordUserMessage` → type 'user', no subtype. Other user-role
 *             records are tagged: 'slash_command', 'at_command',
 *             'mid_turn_user_message' (a real person typing mid-turn — kept),
 *             'goal_runtime', 'agent_launch_prompt', 'cron', … (not a person).
 *   ASSISTANT `recordAssistantTurn` → type 'assistant', `model`, optional
 *             `message` (text + functionCall parts) and `usageMetadata`
 *             (`GenerateContentResponseUsageMetadata`: promptTokenCount,
 *             candidatesTokenCount, cachedContentTokenCount,
 *             thoughtsTokenCount, toolUsePromptTokenCount, totalTokenCount).
 *   TOOL      `recordToolResult` → type 'tool_result' with functionResponse
 *             parts plus `toolCallResult:{callId, resultDisplay, status, …}`.
 *   TITLE     type 'system', subtype 'custom_title', `systemPayload:
 *             {customTitle, titleSource?: 'manual'|'auto'}` (last wins).
 *
 * NUMBERS (rule 2): the usage maths is Gemini's — `promptTokenCount` INCLUDES
 * the cached prefix (`cachedContentTokenCount` is a subset), thoughts bill at
 * the output rate and `toolUsePromptTokenCount` at the input rate, so
 * `input_tokens` = prompt − cached + tool, `cache_read_tokens` = cached,
 * `output_tokens` = candidates + thoughts, no cache-write bucket. Cost comes
 * from the built-in pricing table by `provider/model`; the Qwen models
 * (`qwen3-coder-plus`, …) are not in it today, so those turns are
 * `cost_unknown` — never $0. Settlement is absent (a Qwen OAuth login, a
 * ModelScope key and an OpenRouter key all write the same record).
 *
 * REWINDS: a `/rewind` leaves the abandoned branch's records in the file and
 * continues from an earlier `parentUuid`. Every record is still a request the
 * provider billed, so every branch is read; the ledger is spend, not a
 * conversation view.
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

/** upstream QWEN_DIR / PROJECT_DIR_NAME / TMP_DIR_NAME (config/storage.ts). */
const QWEN_DIR = ".qwen";
const PROJECT_DIR_NAME = "projects";
const TMP_DIR_NAME = "tmp";
const CHATS_DIR = "chats";

/** User-role subtypes that are still a PERSON typing. Every other tagged user
 * record is machinery (slash commands, @-expansions, cron, agent launches). */
const HUMAN_USER_SUBTYPES: ReadonlySet<string> = new Set(["mid_turn_user_message"]);

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

function isoOf(value: unknown): string | undefined {
  const text = str(value);
  if (!text) return undefined;
  return Number.isNaN(Date.parse(text)) ? undefined : text;
}

/** The non-thought text of a `Content`'s parts. */
function partsText(message: Record<string, unknown> | undefined): string {
  const parts = Array.isArray(message?.parts) ? message.parts : [];
  const out: string[] = [];
  for (const raw of parts) {
    const part = obj(raw);
    if (!part || part.thought === true) continue;
    const text = str(part.text);
    if (text) out.push(text);
  }
  return out.join("").trim();
}

/** A functionResponse's payload as text: its `output`/`error` string when it
 * has one, else the whole response serialized — a tool's output is where
 * injected instructions arrive from, so nothing is dropped for its shape. */
function responseText(response: unknown): string | undefined {
  if (typeof response === "string") return response === "" ? undefined : response;
  const record = obj(response);
  if (!record) return response === undefined ? undefined : JSON.stringify(response);
  return str(record.output) ?? str(record.error) ?? JSON.stringify(record);
}

/** Qwen Code's tool argument names (Gemini's), then the shared rule. */
function qwenToolTarget(name: string, args: unknown): string | undefined {
  const a = obj(args);
  if (!a) return undefined;
  if (name === "run_shell_command" || name === "shell") {
    const command = str(a.command);
    if (!command) return undefined;
    const head = command.trim().split(/\s+/, 1)[0];
    return head === "" ? undefined : head;
  }
  return (
    toolTarget(name, a) ??
    str(a.absolute_path) ??
    str(a.file_path) ??
    str(a.dir_path) ??
    str(a.pattern) ??
    str(a.url) ??
    str(a.prompt)
  );
}

/** `GenerateContentResponseUsageMetadata` → the ledger's usage (see NUMBERS). */
function usageOf(meta: Record<string, unknown>): TurnUsage | undefined {
  const prompt = toInt(meta.promptTokenCount);
  const cached = Math.min(toInt(meta.cachedContentTokenCount), prompt);
  const usage: TurnUsage = {
    input_tokens: prompt - cached + toInt(meta.toolUsePromptTokenCount),
    output_tokens: toInt(meta.candidatesTokenCount) + toInt(meta.thoughtsTokenCount),
    cache_read_tokens: cached,
    cache_write_tokens: 0,
    cache_write_1h_tokens: 0,
    web_search_requests: 0,
  };
  if (usage.input_tokens === 0 && usage.output_tokens === 0 && usage.cache_read_tokens === 0) return undefined;
  return usage;
}

/**
 * Parse one Qwen Code session document. `fallbackSessionId` (the file's name)
 * stands in until a record names the session. TOTAL: a half-written line is
 * skipped, never thrown on.
 */
export function parseQwenSession(contents: string, fallbackSessionId: string): TranscriptParseResult {
  const turns: LedgerTurn[] = [];
  const detect: DetectUnit[] = [];
  const titles: TitleRecord[] = [];
  let sessionId = fallbackSessionId;
  let title: string | undefined;
  // functionCall id → the assistant turn that issued it; `uuid` → turn id for
  // the parentUuid fallback when a call carried no id.
  const callTurn = new Map<string, { turn: string; name: string }>();
  const assistantByUuid = new Map<string, string>();
  let lastAssistantTurn: string | undefined;

  for (const raw of contents.split("\n")) {
    const line = raw.trim();
    if (line === "") continue;
    let record: Record<string, unknown> | undefined;
    try {
      record = obj(JSON.parse(line));
    } catch {
      continue; // a line the CLI is still writing
    }
    if (!record) continue;
    const recordSession = str(record.sessionId);
    if (recordSession) sessionId = recordSession;
    const uuid = str(record.uuid);
    const at = isoOf(record.timestamp);
    if (!uuid || !at) continue;
    const id = `qwen:${sessionId}:${uuid}`;
    const cwd = str(record.cwd);
    const withCwd = cwd === undefined ? {} : { cwd };
    const branch = str(record.gitBranch);
    const withBranch = branch === undefined ? {} : { git_branch: branch };
    const type = str(record.type);
    const subtype = str(record.subtype);
    const message = obj(record.message);

    if (type === "user") {
      if (subtype !== undefined && !HUMAN_USER_SUBTYPES.has(subtype)) continue;
      const text = partsText(message);
      if (text === "") continue;
      turns.push({
        id,
        source: "qwen-code",
        session_id: sessionId,
        role: "user",
        at,
        text: text.slice(0, TURN_TEXT_MAX_CHARS),
        ...withCwd,
        ...withBranch,
      });
      detect.push({ kind: "prompt", raw: text, session_id: sessionId, turn_id: id, at, ...withCwd });
      continue;
    }

    if (type === "assistant") {
      const text = partsText(message);
      const parts = Array.isArray(message?.parts) ? message.parts : [];
      const named: string[] = [];
      const calls: { name: string; args: unknown; callId: string | undefined }[] = [];
      for (const rawPart of parts) {
        const call = obj(obj(rawPart)?.functionCall);
        const name = str(call?.name);
        if (!call || !name) continue;
        calls.push({ name, args: call.args ?? {}, callId: str(call.id) });
      }
      const meta = obj(record.usageMetadata);
      const usage = meta ? usageOf(meta) : undefined;
      if (!usage && text === "" && calls.length === 0) continue;
      const turn: LedgerTurn = {
        id,
        source: "qwen-code",
        session_id: sessionId,
        role: "assistant",
        at,
        ...withCwd,
        ...withBranch,
      };
      const model = str(record.model);
      if (model) turn.model = model;
      if (usage) {
        turn.usage = usage;
        const cost = model
          ? deriveCost({
              model_provider: inferModelProvider(model) ?? "alibaba",
              model,
              input_tokens: usage.input_tokens,
              output_tokens: usage.output_tokens,
              cached_tokens: usage.cache_read_tokens,
              cache_read_tokens: usage.cache_read_tokens,
              cache_write_tokens: 0,
              web_search_requests: 0,
            })
          : undefined;
        if (cost === undefined) turn.cost_unknown = true;
        else turn.cost = cost;
      }
      if (text !== "") turn.text = text.slice(0, TURN_TEXT_MAX_CHARS);
      for (const call of calls) {
        named.push(call.name);
        if (call.callId) callTurn.set(call.callId, { turn: id, name: call.name });
        const target = qwenToolTarget(call.name, call.args);
        detect.push({
          kind: "tool_call",
          raw: JSON.stringify(call.args),
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
      assistantByUuid.set(uuid, id);
      lastAssistantTurn = id;
      continue;
    }

    if (type === "tool_result") {
      const parts = Array.isArray(message?.parts) ? message.parts : [];
      const parent = str(record.parentUuid);
      const parentTurn = parent ? assistantByUuid.get(parent) : undefined;
      const result = obj(record.toolCallResult);
      let emitted = false;
      for (const rawPart of parts) {
        const response = obj(obj(rawPart)?.functionResponse);
        if (!response) continue;
        const output = responseText(response.response);
        if (output === undefined) continue;
        emitted = true;
        const callId = str(response.id) ?? str(result?.callId);
        const known = callId ? callTurn.get(callId) : undefined;
        const toolName = str(response.name) ?? known?.name;
        const anchor = known?.turn ?? parentTurn ?? lastAssistantTurn;
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
      }
      // No functionResponse part (an older writer, or a display-only result):
      // the `resultDisplay` string is what the model was shown.
      const display = str(result?.resultDisplay);
      if (!emitted && display) {
        const callId = str(result?.callId);
        const known = callId ? callTurn.get(callId) : undefined;
        const anchor = known?.turn ?? parentTurn ?? lastAssistantTurn;
        detect.push({
          kind: "tool_output",
          raw: display.slice(0, TOOL_OUTPUT_MAX_CHARS),
          ...(known === undefined ? {} : { tool_name: known.name }),
          session_id: sessionId,
          turn_id: id,
          ...(anchor === undefined ? {} : { anchor_turn_id: anchor }),
          at,
          ...withCwd,
        });
      }
      continue;
    }

    if (type === "system" && subtype === "custom_title") {
      const payload = obj(record.systemPayload);
      const text = str(payload?.customTitle)?.trim();
      if (text) title = text; // last wins, as in upstream's restore
    }
  }

  if (title && turns.length > 0) {
    // Qwen's own title — /rename or its auto-titler — the auto_summary tier,
    // same rank as Claude Code's ai-title record.
    titles.push({ session_id: sessionId, title: { text: title, origin: "auto_summary" } });
  }
  turns.sort((a, b) => (a.at < b.at ? -1 : a.at > b.at ? 1 : a.id.localeCompare(b.id)));
  return { turns, titles, detect };
}

/** `<sessionId>.jsonl` — the whole id is the file name (unlike Gemini's 8 chars). */
const SESSION_FILE_RE = /^([^/\\]+)\.jsonl$/;

export const qwenSource: TranscriptSourceDescriptor = {
  id: "qwen-code",
  label: "Qwen Code",
  presencePaths: [QWEN_DIR],

  /** `$QWEN_HOME` replaces `~/.qwen` wholesale; both are returned when it is
   * set (the override is where the CLI writes now, the real home where it
   * wrote before). `projects/` is the current layout, `tmp/` the older one. */
  roots(home, env) {
    const bases = [`${home}/${QWEN_DIR}`];
    const override = str(env["QWEN_HOME"]);
    if (override) bases.unshift(override);
    const roots: string[] = [];
    for (const base of bases) roots.push(`${base}/${PROJECT_DIR_NAME}`, `${base}/${TMP_DIR_NAME}`);
    return [...new Set(roots)];
  },

  /** `<root>/<project>/chats/*.jsonl`. */
  discover(root, io) {
    const found: string[] = [];
    for (const project of io.listDir(root).sort()) {
      const chats = `${root}/${project}/${CHATS_DIR}`;
      if (io.stat(chats)?.isDirectory !== true) continue;
      for (const name of io.listDir(chats).sort()) {
        if (!SESSION_FILE_RE.test(name)) continue;
        const full = `${chats}/${name}`;
        if (io.stat(full)?.isDirectory === false) found.push(full);
      }
    }
    return found;
  },

  parse(filePath, io) {
    const contents = io.readText(filePath);
    if (contents === undefined || contents === "") return { turns: [], titles: [], detect: [] };
    return parseQwenSession(contents, qwenSource.sessionIdOf(filePath) ?? filePath);
  },

  sessionIdOf(filePath) {
    const name = filePath.split(/[\\/]/).pop() ?? "";
    return SESSION_FILE_RE.exec(name)?.[1];
  },

  metered: true,
};
