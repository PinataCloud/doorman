/**
 * Codex rollout parsing — ~/.codex/sessions/YYYY/MM/DD/rollout-<ts>-<uuid>.jsonl.
 *
 * This app reads the rollout's own `event_msg/token_count` records — the on-disk token ground
 * truth. `last_token_usage` is the finished request's usage; the cumulative
 * `total_token_usage.total_tokens` is monotonic, which makes
 * `codex:<session>:<cumulative>` a stable turn id across re-parses.
 *
 * Settlement (subscription vs paid overage) follows an observed rule
 * (settlementOf below): primary window < 100%
 * proves subscription; at 100% with credits available, credits is inferred;
 * anything else the provider reports is honestly unknown. A turn takes the
 * verdict of the snapshot that rides its own token_count event, and later turns
 * inherit it only until the NEXT REPORTED reading — a record with no
 * `rate_limits` block at all is no observation and carries the verdict forward,
 * while a reported exhaustion retracts it. Instants before the first snapshot
 * stay unattributed.
 */

import { homedir } from "node:os";
import { join } from "node:path";
import { deriveCost, inferModelProvider } from "./pricing.js";
import type { DetectUnit } from "./cc-transcript.js";
import {
  type LedgerTurn,
  type SettlementMode,
  TOOL_OUTPUT_MAX_CHARS,
  TURN_TEXT_MAX_CHARS,
  TURN_TOOLS_MAX,
} from "./turns.js";

/** Codex's home: `$CODEX_HOME` when set, else `~/.codex`. */
export function codexHomeDir(env: NodeJS.ProcessEnv = process.env, home: string = homedir()): string {
  const override = env.CODEX_HOME?.trim();
  return override && override !== "" ? override : join(home, ".codex");
}

export interface RolloutParseResult {
  turns: LedgerTurn[];
  detect: DetectUnit[];
  /** First human prompt (raw), for the auto_prompt title tier. */
  first_prompt?: string;
  session_id: string;
  /**
   * `session_meta.originator` — the SURFACE Codex ran on, verbatim
   * (`codex-tui`, `codex_exec`, `Codex Desktop`, `codex_vscode`). Without it
   * ChatGPT Desktop's Codex-mode sessions were metered under "Codex" while the
   * coverage map still listed the app as uncovered. Undefined on rollouts
   * written before Codex stamped it.
   */
  originator?: string;
}

/** Codex `originator` values that mean ChatGPT Desktop's Codex mode rather
 * than the terminal. Matched case-insensitively on the whole value, so a new
 * surface string does not silently get attributed to the desktop app. */
const CHATGPT_DESKTOP_ORIGINATORS = new Set(["codex desktop", "codex_desktop"]);

/** The shadow-AI catalog id a rollout's surface belongs to, when it is an app
 * the coverage map lists separately from the Codex CLI. */
export function shadowAiIdForOriginator(originator: string | undefined): string | undefined {
  if (!originator) return undefined;
  return CHATGPT_DESKTOP_ORIGINATORS.has(originator.trim().toLowerCase())
    ? "chatgpt-desktop"
    : undefined;
}

function str(value: unknown): string | undefined {
  return typeof value === "string" && value !== "" ? value : undefined;
}

function toInt(value: unknown): number {
  const n = typeof value === "number" ? value : Number(value);
  if (!Number.isFinite(n) || n <= 0) return 0;
  return Math.floor(n);
}

/** Ambient context Codex injects as user messages: XML-ish wrappers
 * (<environment_context>, <user_instructions>) and the unwrapped AGENTS.md
 * injection ("# AGENTS.md instructions for <path>…"). Neither is a human
 * prompt — as titles, turns or search text they are pure pollution. */
function isAmbientUserText(text: string): boolean {
  return text.startsWith("<") || /^#\s*AGENTS\.md instructions/i.test(text);
}

/**
 * How ONE `token_count` record settles.
 *
 * `undefined` means NO OBSERVATION — the record carried no `rate_limits` block
 * at all, which is most of them — and the last known verdict carries forward.
 * An explicit `"unknown"` is the opposite: the provider DID report, and what it
 * reported (allowance exhausted with no credits, or a utilization value outside
 * 0-100 we refuse to interpret) supports no funding claim, so it RETRACTS the
 * previous one.
 *
 * Collapsing those two into one value was the bug: a session that ran to 100%
 * with `has_credits: false` kept reporting "subscription" for every later turn,
 * because the contrary reading looked exactly like no reading. The 0-100 range
 * check matters too — a negative or >100 percentage is malformed input, not
 * evidence of coverage.
 */
function settlementOf(
  rateLimits: Record<string, unknown> | undefined,
): SettlementMode | undefined {
  if (!rateLimits || typeof rateLimits !== "object") return undefined;
  const primary = rateLimits.primary as Record<string, unknown> | undefined;
  const pct = primary && typeof primary === "object" ? primary.used_percent : undefined;
  if (typeof pct !== "number" || !Number.isFinite(pct) || pct < 0 || pct > 100) return "unknown";
  if (pct < 100) return "subscription";
  const credits = rateLimits.credits as Record<string, unknown> | undefined;
  if (credits && typeof credits === "object") {
    if (credits.has_credits === true || credits.unlimited === true) return "credits";
  }
  return "unknown";
}

/** `fallbackSessionId` comes from the rollout filename (the conversation id). */
export function parseCodexRollout(contents: string, fallbackSessionId: string): RolloutParseResult {
  const turns: LedgerTurn[] = [];
  const detect: DetectUnit[] = [];
  let sessionId = fallbackSessionId;
  let cwd: string | undefined;
  let model: string | undefined;
  let originator: string | undefined;
  let settlement: SettlementMode = "unknown";
  let firstPrompt: string | undefined;
  /** Assistant commentary + tool calls since the last token_count, which is
   * the settlement point they belong to. */
  let pendingTexts: string[] = [];
  let pendingTools: DetectUnit[] = [];
  let promptSeq = 0;
  let lastPromptText: string | undefined;
  /** function_call call_id → tool name, so a *_call_output can name its tool. */
  const toolNameByCallId = new Map<string, string>();

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
    const payload = obj.payload as Record<string, unknown> | undefined;
    if (!payload || typeof payload !== "object") continue;
    const at = str(obj.timestamp);

    if (obj.type === "session_meta") {
      sessionId = str(payload.session_id) ?? str(payload.id) ?? sessionId;
      cwd = str(payload.cwd) ?? cwd;
      originator = str(payload.originator) ?? originator;
      continue;
    }

    if (obj.type === "turn_context") {
      model = str(payload.model) ?? model;
      cwd = str(payload.cwd) ?? cwd;
      continue;
    }

    if (obj.type === "response_item") {
      // Tool calls, for the Radar. `function_call.arguments` is a JSON string;
      // local_shell_call carries the command directly.
      const kind = payload.type;
      if (kind === "message" && payload.role === "user") {
        // Older rollouts carry the human prompt as a response_item message
        // (content[].input_text) instead of an event_msg/user_message — the
        // same dual shape the repo's importer reads. Newer rollouts can emit
        // BOTH for one prompt, so an identical back-to-back text is skipped.
        const content = payload.content;
        if (Array.isArray(content) && at) {
          const text = content
            .map((c) =>
              c && typeof c === "object" && (c as { type?: string }).type === "input_text"
                ? str((c as { text?: unknown }).text) ?? ""
                : "",
            )
            .join("")
            .trim();
          if (text !== "" && !isAmbientUserText(text) && text !== lastPromptText) {
            const id = `codex:${sessionId}:p${promptSeq}`;
            promptSeq += 1;
            lastPromptText = text;
            firstPrompt ??= text;
            turns.push({
              id,
              source: "codex",
              session_id: sessionId,
              role: "user",
              at,
              text: text.slice(0, TURN_TEXT_MAX_CHARS),
              cwd,
            });
            detect.push({ kind: "prompt", raw: text, session_id: sessionId, turn_id: id, at });
          }
        }
        continue;
      }
      if (kind === "function_call" || kind === "custom_tool_call") {
        const name = str(payload.name) ?? "tool";
        const callId = str(payload.call_id) ?? str(payload.id);
        if (callId) toolNameByCallId.set(callId, name);
        const args = str(payload.arguments) ?? str(payload.input) ?? "";
        if (args && at) {
          pendingTools.push({
            kind: "tool_call",
            raw: args,
            tool_name: name,
            target: shellTargetFromArgs(name, args),
            session_id: sessionId,
            turn_id: "", // assigned when the settling token_count arrives
            at,
            ...(cwd === undefined ? {} : { cwd }),
          });
        }
      } else if (kind === "local_shell_call") {
        const callId = str(payload.call_id) ?? str(payload.id);
        if (callId) toolNameByCallId.set(callId, "shell");
        const action = payload.action as Record<string, unknown> | undefined;
        const command = Array.isArray(action?.command) ? action.command.join(" ") : str(action?.command);
        if (command && at) {
          pendingTools.push({
            kind: "tool_call",
            raw: JSON.stringify({ command }),
            tool_name: "shell",
            target: command.trim().split(/\s+/, 1)[0],
            session_id: sessionId,
            turn_id: "",
            at,
            ...(cwd === undefined ? {} : { cwd }),
          });
        }
      } else if (
        kind === "function_call_output" ||
        kind === "custom_tool_call_output" ||
        kind === "local_shell_call_output"
      ) {
        // Best-effort: the field shape varies by Codex version (`output` as a
        // plain string, or a JSON envelope with its own `output` field). A shape
        // this parse doesn't recognise is skipped, never thrown on.
        const text = rolloutOutputText(payload.output);
        if (text && at) {
          const callId = str(payload.call_id) ?? str(payload.id);
          const name = callId ? toolNameByCallId.get(callId) : undefined;
          pendingTools.push({
            kind: "tool_output",
            raw: text.slice(0, TOOL_OUTPUT_MAX_CHARS),
            ...(name === undefined ? {} : { tool_name: name }),
            session_id: sessionId,
            turn_id: "",
            at,
            ...(cwd === undefined ? {} : { cwd }),
          });
        }
      }
      continue;
    }

    if (obj.type !== "event_msg") continue;
    const eventType = payload.type;

    if (eventType === "user_message") {
      const message = str(payload.message);
      if (!message || !at) continue;
      // Codex wraps ambient context (<environment_context>, <user_instructions>)
      // as user messages — and injects AGENTS.md unwrapped; not human prompts.
      if (isAmbientUserText(message)) continue;
      if (message === lastPromptText) continue; // response_item twin already recorded
      const id = `codex:${sessionId}:p${promptSeq}`;
      promptSeq += 1;
      lastPromptText = message;
      firstPrompt ??= message;
      turns.push({
        id,
        source: "codex",
        session_id: sessionId,
        role: "user",
        at,
        text: message.slice(0, TURN_TEXT_MAX_CHARS),
        cwd,
      });
      detect.push({ kind: "prompt", raw: message, session_id: sessionId, turn_id: id, at });
      continue;
    }

    if (eventType === "agent_message") {
      const message = str(payload.message);
      if (message) pendingTexts.push(message);
      continue;
    }

    if (eventType !== "token_count") continue;
    const info = payload.info as Record<string, unknown> | undefined;
    const rateLimits = payload.rate_limits as Record<string, unknown> | undefined;
    // An absent reading carries the last verdict forward; a reported one
    // replaces it, including when it reports something unattributable.
    const verdict = settlementOf(rateLimits);
    if (verdict !== undefined) settlement = verdict;
    if (!info || typeof info !== "object" || !at) continue;
    const last = info.last_token_usage as Record<string, unknown> | undefined;
    const total = info.total_token_usage as Record<string, unknown> | undefined;
    if (!last || typeof last !== "object" || !total || typeof total !== "object") continue;
    const cumulative = toInt(total.total_tokens);
    if (cumulative === 0) continue;

    const usage = {
      input_tokens: Math.max(0, toInt(last.input_tokens) - toInt(last.cached_input_tokens)),
      output_tokens: toInt(last.output_tokens),
      cache_read_tokens: toInt(last.cached_input_tokens),
      cache_write_tokens: toInt(last.cache_write_input_tokens),
      cache_write_1h_tokens: 0,
      web_search_requests: 0,
    };
    const turnModel = model ?? "gpt-5-codex";
    const provider = inferModelProvider(turnModel) ?? "openai";
    const cost = deriveCost({
      model_provider: provider,
      model: turnModel,
      input_tokens: usage.input_tokens,
      output_tokens: usage.output_tokens,
      cached_tokens: usage.cache_read_tokens + usage.cache_write_tokens,
      cache_read_tokens: usage.cache_read_tokens,
      cache_write_tokens: usage.cache_write_tokens,
      web_search_requests: 0,
    });
    const id = `codex:${sessionId}:${cumulative}`;
    turns.push({
      id,
      source: "codex",
      session_id: sessionId,
      role: "assistant",
      at,
      model: turnModel,
      usage,
      cost,
      cost_unknown: cost === undefined ? true : undefined,
      settlement,
      text: pendingTexts.length > 0 ? pendingTexts.join("\n").slice(0, TURN_TEXT_MAX_CHARS) : undefined,
      tools: (() => {
        // Only CALLS name the turn's tool chips — outputs are scan units, not calls.
        const calls = pendingTools.filter((u) => u.kind === "tool_call");
        return calls.length > 0 ? calls.slice(0, TURN_TOOLS_MAX).map((u) => u.tool_name ?? "?") : undefined;
      })(),
      cwd,
    });
    for (const unit of pendingTools) detect.push({ ...unit, turn_id: id });
    pendingTexts = [];
    pendingTools = [];
  }

  // Tool calls after the last token_count never settled into a turn — scan
  // them anyway, anchored to the session.
  for (const unit of pendingTools) detect.push({ ...unit, turn_id: `codex:${sessionId}:tail` });

  return {
    turns,
    detect,
    first_prompt: firstPrompt,
    session_id: sessionId,
    ...(originator === undefined ? {} : { originator }),
  };
}

/** A *_call_output's text: a plain string, or a JSON envelope carrying `output`. */
function rolloutOutputText(output: unknown): string | undefined {
  if (typeof output !== "string" || output === "") return undefined;
  try {
    const parsed = JSON.parse(output) as Record<string, unknown> | unknown;
    if (parsed && typeof parsed === "object" && typeof (parsed as Record<string, unknown>).output === "string") {
      const inner = (parsed as Record<string, unknown>).output as string;
      return inner === "" ? undefined : inner;
    }
  } catch {
    // Not an envelope — the string itself is the output.
  }
  return output;
}

/** Best-effort target for a JSON-stringified tool argument blob. */
function shellTargetFromArgs(toolName: string, args: string): string | undefined {
  try {
    const parsed = JSON.parse(args) as Record<string, unknown>;
    if (typeof parsed !== "object" || parsed === null) return undefined;
    const command = parsed.command;
    if (typeof command === "string" && command.trim() !== "") {
      return command.trim().split(/\s+/, 1)[0];
    }
    if (Array.isArray(command) && typeof command[0] === "string") return command[0];
    const path = parsed.file_path ?? parsed.path;
    return typeof path === "string" && path !== "" ? path : undefined;
  } catch {
    return toolName === "shell" ? args.trim().split(/\s+/, 1)[0] : undefined;
  }
}

/** The rollout filename's conversation id. */
const ROLLOUT_FILENAME_RE = /^rollout-\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}-([0-9a-f-]{36})\.jsonl$/i;

export function rolloutSessionId(filePath: string): string | undefined {
  const name = filePath.split(/[\\/]/).pop() ?? "";
  return ROLLOUT_FILENAME_RE.exec(name)?.[1];
}
