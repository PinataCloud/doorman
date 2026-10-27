/**
 * Claude Code transcript parsing — the day-zero backfill's ground truth.
 *
 * Reads the on-disk JSONL at ~/.claude/projects/<cwd-slug>/<sessionId>.jsonl
 * (and its agent-*.jsonl subagent siblings) and yields ledger turns. One
 * collapsing rule applies: one Anthropic `message.id` streams as several content-block lines carrying
 * IDENTICAL usage, so usage is taken from the first line per id — anything
 * else over-reports roughly 2x. Text and tool_use blocks, by contrast, are
 * spread ACROSS those lines, so they are merged per id.
 */

import { deriveCost, inferModelProvider } from "./pricing.js";
import {
  type LedgerTurn,
  type PlanWindowReading,
  type TitleRecord,
  type TurnUsage,
  TOOL_OUTPUT_MAX_CHARS,
  TURN_TEXT_MAX_CHARS,
  TURN_TOOLS_MAX,
} from "./turns.js";

/** One unit of text the Security Radar should scan, with its provenance.
 * `raw` is pre-redaction — the caller redacts before detection, and passes
 * `raw` on only for the detectors that need it (hardcoded_credential).
 * `tool_output` is what a tool RETURNED (a tool_result block) — scanned for
 * injected instructions and exfil links, never stored as a ledger turn. */
export interface DetectUnit {
  kind: "prompt" | "tool_call" | "tool_output";
  raw: string;
  tool_name?: string;
  target?: string;
  session_id: string;
  turn_id: string;
  at: string;
  /** tool_output only: the ASSISTANT turn whose tool_use this result answers.
   * `turn_id` is the transcript line the result arrived on (the dedup key),
   * which is never a ledger turn — so a finding minted from this unit anchors
   * to `anchor_turn_id` and lands in the ledger next to the call it came from. */
  anchor_turn_id?: string;
  /** The agent's working directory when this unit was recorded — what a
   * cwd-scoped ignore or custom rule is judged against. */
  cwd?: string;
}

export interface TranscriptParseResult {
  turns: LedgerTurn[];
  titles: TitleRecord[];
  detect: DetectUnit[];
  /** The host's own plan-headroom reading, when this document stated one.
   * Additive and optional: a parser that has no such signal omits it, and the
   * engine keeps only the newest across every document. */
  plan_window?: PlanWindowReading;
}

function toInt(value: unknown): number {
  const n = typeof value === "number" ? value : Number(value);
  if (!Number.isFinite(n) || n <= 0) return 0;
  return Math.floor(n);
}

function str(value: unknown): string | undefined {
  return typeof value === "string" && value !== "" ? value : undefined;
}

const CLAUDE_INTERNAL_USER_TAGS = new Set([
  "command-args",
  "command-message",
  "command-name",
  "local-command-caveat",
  "local-command-stderr",
  "local-command-stdout",
  "system-reminder",
  "task-notification",
]);

function isInternalUserText(text: string): boolean {
  const tag = /^<\/?([a-z][\w-]*)(?:\s|>)/i.exec(text)?.[1];
  return tag !== undefined && CLAUDE_INTERNAL_USER_TAGS.has(tag.toLowerCase());
}

/** The Bash program name, or a file-tool path — what security-detect calls the target. */
export function toolTarget(toolName: string | undefined, input: unknown): string | undefined {
  if (!input || typeof input !== "object") return undefined;
  const obj = input as Record<string, unknown>;
  if (toolName === "Bash" || toolName === "shell") {
    const command = str(obj.command);
    if (!command) return undefined;
    const head = command.trim().split(/\s+/, 1)[0];
    return head === "" ? undefined : head;
  }
  return str(obj.file_path) ?? str(obj.path) ?? str(obj.notebook_path);
}

/** Flatten a tool_result block's content: a plain string, or text blocks. */
function toolResultText(content: unknown): string | undefined {
  if (typeof content === "string") return content === "" ? undefined : content;
  if (!Array.isArray(content)) return undefined;
  const parts: string[] = [];
  for (const block of content) {
    if (!block || typeof block !== "object") continue;
    const b = block as Record<string, unknown>;
    if (b.type === "text" && typeof b.text === "string" && b.text !== "") parts.push(b.text);
  }
  return parts.length > 0 ? parts.join("\n") : undefined;
}

interface AssistantAccumulator {
  turn: LedgerTurn;
  texts: string[];
  toolUnits: DetectUnit[];
}

/**
 * Parse one transcript file's contents. `fallbackSessionId` (from the file
 * name) covers lines that don't carry their own sessionId — subagent files
 * carry the parent's, which is exactly the merge we want.
 */
export function parseClaudeTranscript(
  contents: string,
  fallbackSessionId: string,
): TranscriptParseResult {
  const byMessageId = new Map<string, AssistantAccumulator>();
  const order: AssistantAccumulator[] = [];
  const prompts: LedgerTurn[] = [];
  const promptUnits: DetectUnit[] = [];
  const titles = new Map<string, TitleRecord>();
  /** tool_use id → what was called, so a tool_result can say whose output it is.
   * Assistant lines precede their tool_result in the file, so one pass suffices. */
  const toolUseInfo = new Map<string, { tool_name?: string; target?: string; turn_id: string }>();
  let lastTimestamp: string | undefined;

  for (const raw of contents.split("\n")) {
    const line = raw.trim();
    if (line === "") continue;
    let obj: Record<string, unknown>;
    try {
      const parsed = JSON.parse(line);
      if (typeof parsed !== "object" || parsed === null) continue;
      obj = parsed as Record<string, unknown>;
    } catch {
      continue;
    }

    const sessionId = str(obj.sessionId) ?? fallbackSessionId;
    const at = str(obj.timestamp) ?? lastTimestamp;
    if (str(obj.timestamp)) lastTimestamp = obj.timestamp as string;

    // Claude Code's own transcript title — the auto_summary tier. Two shapes,
    // current and legacy; the LAST record wins (summaries improve over time).
    if (obj.type === "ai-title" || obj.type === "summary") {
      const text = str(obj.aiTitle) ?? str(obj.summary);
      const forSession = str(obj.sessionId) ?? fallbackSessionId;
      if (text) titles.set(forSession, { session_id: forSession, title: { text, origin: "auto_summary" } });
      continue;
    }

    if (obj.type === "user") {
      if (obj.isSidechain === true) continue;
      const msg = obj.message as Record<string, unknown> | undefined;
      if (!msg || typeof msg !== "object") continue;
      const content = msg.content;
      // Array content is where tool_result blocks live — what the tool RETURNED.
      // Not a human prompt and not a ledger turn; scanned because tool output is
      // exactly where injected instructions and exfil links arrive from outside.
      if (Array.isArray(content)) {
        if (!at) continue;
        const id = str(obj.uuid);
        if (!id) continue;
        for (const block of content) {
          if (!block || typeof block !== "object") continue;
          const b = block as Record<string, unknown>;
          if (b.type !== "tool_result") continue;
          const text = toolResultText(b.content);
          if (!text) continue;
          const info = str(b.tool_use_id) ? toolUseInfo.get(b.tool_use_id as string) : undefined;
          promptUnits.push({
            kind: "tool_output",
            raw: text.slice(0, TOOL_OUTPUT_MAX_CHARS),
            ...(info?.tool_name === undefined ? {} : { tool_name: info.tool_name }),
            ...(info?.target === undefined ? {} : { target: info.target }),
            session_id: sessionId,
            turn_id: id,
            ...(info === undefined ? {} : { anchor_turn_id: info.turn_id }),
            at,
            ...(str(obj.cwd) === undefined ? {} : { cwd: str(obj.cwd) }),
          });
        }
        continue;
      }
      if (typeof content !== "string" || content === "") continue;
      // Command wrappers (<command-name>…) and ambient attachments are not
      // human prompts; they'd pollute both search and titles.
      if (isInternalUserText(content)) continue;
      if (!at) continue;
      const id = str(obj.uuid);
      if (!id) continue;
      const turn: LedgerTurn = {
        id,
        source: "claude-code",
        session_id: sessionId,
        role: "user",
        at,
        text: content.slice(0, TURN_TEXT_MAX_CHARS),
        cwd: str(obj.cwd),
        git_branch: str(obj.gitBranch),
      };
      prompts.push(turn);
      promptUnits.push({
        kind: "prompt",
        raw: content,
        session_id: sessionId,
        turn_id: id,
        at,
        ...(turn.cwd === undefined ? {} : { cwd: turn.cwd }),
      });
      continue;
    }

    if (obj.type !== "assistant") continue;
    const msg = obj.message as Record<string, unknown> | undefined;
    if (!msg || typeof msg !== "object") continue;
    const id = str(msg.id);
    const model = str(msg.model);
    const usage = msg.usage as Record<string, unknown> | undefined;
    if (!id || !model || !usage || typeof usage !== "object") continue;
    // Claude Code writes synthetic assistant lines (error banners etc.) with
    // model "<synthetic>" and zero usage — noise in the model legend, not spend.
    if (model === "<synthetic>") continue;

    let acc = byMessageId.get(id);
    if (!acc) {
      const turnUsage: TurnUsage = {
        input_tokens: toInt(usage.input_tokens),
        output_tokens: toInt(usage.output_tokens),
        cache_read_tokens: toInt(usage.cache_read_input_tokens),
        cache_write_tokens: toInt(usage.cache_creation_input_tokens),
        cache_write_1h_tokens: 0,
        web_search_requests: 0,
      };
      const cacheCreation = usage.cache_creation as Record<string, unknown> | undefined;
      if (cacheCreation && typeof cacheCreation === "object" && !Array.isArray(cacheCreation)) {
        turnUsage.cache_write_1h_tokens = Math.min(
          toInt(cacheCreation.ephemeral_1h_input_tokens),
          turnUsage.cache_write_tokens,
        );
      }
      const serverToolUse = usage.server_tool_use as Record<string, unknown> | undefined;
      if (serverToolUse && typeof serverToolUse === "object" && !Array.isArray(serverToolUse)) {
        turnUsage.web_search_requests = toInt(serverToolUse.web_search_requests);
      }
      const provider = inferModelProvider(model) ?? "anthropic";
      const cost = deriveCost({
        model_provider: provider,
        model,
        input_tokens: turnUsage.input_tokens,
        output_tokens: turnUsage.output_tokens,
        cached_tokens: turnUsage.cache_read_tokens + turnUsage.cache_write_tokens,
        cache_read_tokens: turnUsage.cache_read_tokens,
        cache_write_tokens: turnUsage.cache_write_tokens,
        cache_write_1h_tokens: turnUsage.cache_write_1h_tokens,
        web_search_requests: turnUsage.web_search_requests,
      });
      acc = {
        turn: {
          id,
          source: "claude-code",
          session_id: sessionId,
          role: "assistant",
          at: at ?? "",
          model,
          usage: turnUsage,
          cost,
          cost_unknown: cost === undefined ? true : undefined,
          cwd: str(obj.cwd),
          git_branch: str(obj.gitBranch),
        },
        texts: [],
        toolUnits: [],
      };
      byMessageId.set(id, acc);
      order.push(acc);
    }
    if (!acc.turn.at && at) acc.turn.at = at;

    // Content blocks are SPREAD across the id's lines — merge them all.
    const content = msg.content;
    if (Array.isArray(content)) {
      for (const block of content) {
        if (!block || typeof block !== "object") continue;
        const b = block as Record<string, unknown>;
        if (b.type === "text" && typeof b.text === "string" && b.text !== "") {
          acc.texts.push(b.text);
        } else if (b.type === "tool_use" && typeof b.name === "string") {
          const inputJson = JSON.stringify(b.input ?? {});
          const target = toolTarget(b.name, b.input);
          const toolUseId = str(b.id);
          if (toolUseId) {
            toolUseInfo.set(toolUseId, {
              tool_name: b.name,
              ...(target === undefined ? {} : { target }),
              turn_id: id,
            });
          }
          acc.toolUnits.push({
            kind: "tool_call",
            raw: inputJson,
            tool_name: b.name,
            target,
            session_id: sessionId,
            turn_id: id,
            at: acc.turn.at || (at ?? ""),
            ...(acc.turn.cwd === undefined ? {} : { cwd: acc.turn.cwd }),
          });
        }
      }
    }
  }

  const turns: LedgerTurn[] = [...prompts];
  const detect: DetectUnit[] = [...promptUnits];
  for (const acc of order) {
    if (!acc.turn.at) continue; // no timestamp anywhere for this id — unchartable
    if (acc.texts.length > 0) {
      acc.turn.text = acc.texts.join("\n").slice(0, TURN_TEXT_MAX_CHARS);
    }
    if (acc.toolUnits.length > 0) {
      acc.turn.tools = acc.toolUnits.slice(0, TURN_TOOLS_MAX).map((u) => u.tool_name ?? "?");
    }
    turns.push(acc.turn);
    detect.push(...acc.toolUnits);
  }
  turns.sort((a, b) => (a.at < b.at ? -1 : a.at > b.at ? 1 : a.id.localeCompare(b.id)));
  return { turns, titles: [...titles.values()], detect };
}
