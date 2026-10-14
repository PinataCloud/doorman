/** Grok Build local capture. Source-derived, 2026-09-06:
 * https://github.com/xai-org/grok-build/blob/main/crates/codegen/xai-grok-shell/src/extensions/notification.rs
 * https://github.com/xai-org/grok-build/blob/main/crates/codegen/xai-grok-shell/src/session/storage/mod.rs
 *
 * Meter ONLY durable turn_completed. usage.json/signals.json are mutable
 * aggregates, and response_completed overlaps the terminal bill. Prompt IDs
 * survive fork replay, so billing IDs deliberately do not include the copied
 * session ID. Input includes cache; reasoning is already inside output.
 * Reported costs are preferred: a multi-call turn cannot be priced correctly
 * against a per-request long-context threshold using its aggregate tokens.
 */
import { createHash } from "node:crypto";
import { basename, dirname, join } from "node:path";
import { grokHost } from "../guard/hosts/grok.js";
import { toolTarget, type DetectUnit, type TranscriptParseResult } from "./cc-transcript.js";
import type { TranscriptSourceDescriptor } from "./transcript-sources.js";
import { type LedgerTurn, type TurnUsage, TURN_TEXT_MAX_CHARS, TURN_TOOLS_MAX, TOOL_OUTPUT_MAX_CHARS } from "./turns.js";

type Obj = Record<string, unknown>;
const obj = (v: unknown): Obj | undefined => v !== null && typeof v === "object" && !Array.isArray(v) ? v as Obj : undefined;
const str = (v: unknown): string | undefined => typeof v === "string" && v.trim() !== "" ? v : undefined;
const count = (v: unknown): number => typeof v === "number" && Number.isSafeInteger(v) && v >= 0 ? v : 0;
const hash = (v: string): string => createHash("sha256").update(v).digest("hex").slice(0, 24);
function json(text: string | undefined): Obj | undefined {
  try { return text ? obj(JSON.parse(text)) : undefined; } catch { return undefined; }
}
function instant(v: unknown): string | undefined {
  const ms = typeof v === "number" ? v * 1000 : typeof v === "string" ? Date.parse(v) : NaN;
  return Number.isFinite(ms) && ms > 0 && ms <= 8.64e15 ? new Date(ms).toISOString() : undefined;
}
function usageOf(row: Obj): TurnUsage | undefined {
  if (!["inputTokens", "outputTokens", "cachedReadTokens", "cacheCreationTokens"].some(k => typeof row[k] === "number")) return undefined;
  const input = count(row.inputTokens);
  const read = Math.min(input, count(row.cachedReadTokens));
  const write = Math.min(input - read, count(row.cacheCreationTokens));
  return { input_tokens: input - read - write, output_tokens: count(row.outputTokens),
    cache_read_tokens: read, cache_write_tokens: write, cache_write_1h_tokens: 0, web_search_requests: 0 };
}
function toolOutput(update: Obj): string {
  if (update.rawOutput !== undefined) return typeof update.rawOutput === "string" ? update.rawOutput : JSON.stringify(update.rawOutput);
  return (Array.isArray(update.content) ? update.content : []).map((raw) => {
    const content = obj(obj(raw)?.content);
    return content?.type === "text" ? str(content.text) ?? "" : "";
  }).join("\n");
}

export function parseGrokSession(contents: string, sessionId: string, summaryText?: string): TranscriptParseResult {
  const result: TranscriptParseResult = { turns: [], titles: [], detect: [] };
  const summary = json(summaryText);
  const cwd = str(obj(summary?.info)?.cwd);
  const context = cwd ? { cwd } : {};
  let model: string | undefined;
  let userText = "";
  let userAt: string | undefined;
  let assistantText = "";
  let calls: string[] = [];
  let pending: Array<Omit<DetectUnit, "turn_id">> = [];
  const toolNames = new Map<string, string>();
  const seen = new Set<string>();
  const flushUser = () => {
    if (userText && userAt) {
      const id = `grok:user:${sessionId}:${hash(userAt + userText)}`;
      result.turns.push({ id, source: "grok-build", session_id: sessionId, role: "user", at: userAt,
        text: userText.slice(0, TURN_TEXT_MAX_CHARS), ...context });
      result.detect.push({ kind: "prompt", raw: userText, session_id: sessionId, turn_id: id, at: userAt, ...context });
    }
    userText = ""; userAt = undefined;
  };
  for (const line of contents.split("\n")) {
    const record = json(line);
    if (!record) continue;
    const params = obj(record.params) ?? record;
    const update = obj(params.update);
    if (!update) continue;
    const at = instant(record.timestamp);
    if (!at) continue; // no fabricated timestamps for legacy untimed records
    const kind = str(update.sessionUpdate);
    if (kind === "user_message_chunk") {
      const content = obj(update.content);
      if (content?.type === "text") {
        userAt ??= at;
        userText += str(content.text) ?? "";
      }
      continue;
    }
    flushUser();
    if (kind === "model_changed" || kind === "response_started") model = str(update.model_id) ?? str(update.model) ?? model;
    if (kind === "agent_message_chunk") {
      const content = obj(update.content);
      if (content?.type === "text") assistantText += str(content.text) ?? "";
    }
    if (kind === "tool_call") {
      const id = str(update.toolCallId);
      const name = str(obj(update._meta)?.toolName) ?? str(update.toolName) ?? str(update.title);
      if (id && name) {
        toolNames.set(id, name);
        calls.push(name);
        const input = obj(update.rawInput) ?? {};
        const normalized = grokHost.normalizeInput({ toolName: name, toolInput: input });
        const tool = normalized?.tool_name ?? name;
        const args = normalized?.tool_input ?? input;
        pending.push({ kind: "tool_call", raw: JSON.stringify(args), tool_name: tool,
          ...(toolTarget(tool, args) ? { target: toolTarget(tool, args)! } : {}), session_id: sessionId, at, ...context });
      }
    }
    if (kind === "tool_call_update") {
      const raw = toolOutput(update);
      if (raw) {
        const name = toolNames.get(String(update.toolCallId));
        pending.push({ kind: "tool_output", raw: raw.slice(0, TOOL_OUTPUT_MAX_CHARS),
          ...(name ? { tool_name: name } : {}), session_id: sessionId, at, ...context });
      }
    }
    if (kind !== "turn_completed") continue;
    const prompt = str(update.prompt_id);
    if (!prompt) continue;
    if (seen.has(prompt)) { assistantText = ""; calls = []; pending = []; continue; }
    seen.add(prompt);
    const bill = obj(update.usage);
    const models = obj(bill?.modelUsage);
    // A breakdown replaces the aggregate, never adds to it. No latest-model
    // attribution for multi-model usage with a missing breakdown.
    const rows: Array<[string | undefined, Obj | undefined]> = models && Object.keys(models).length
      ? Object.entries(models).map(([name, row]) => [name, obj(row)])
      : [[model, bill]];
    const text = str(update.agent_result) ?? assistantText;
    let anchor: string | undefined;
    for (const [name, row] of rows) {
      const id = `grok:prompt:${prompt}:${name ? hash(name) : "activity"}`;
      const usage = row ? usageOf(row) : undefined;
      const incomplete = bill?.usageIsIncomplete === true || row?.usageIsIncomplete === true;
      const ticks = row?.costUsdTicks;
      const reported = !incomplete && bill?.costIsPartial !== true && row?.costIsPartial !== true &&
        typeof ticks === "number" && Number.isSafeInteger(ticks) && ticks > 0 ? ticks / 1e10 : undefined;
      const turn: LedgerTurn = { id, source: "grok-build", session_id: sessionId, role: "assistant", at, ...context,
        ...(name ? { model: name } : {}), ...(usage ? { usage } : {}),
        ...(incomplete ? { usage_incomplete: true } : {}),
        ...(reported !== undefined ? { cost: reported, reported_cost: reported } : usage ? { cost_unknown: true } : {}),
      };
      if (!anchor) {
        anchor = id;
        if (text) turn.text = text.slice(0, TURN_TEXT_MAX_CHARS);
        if (calls.length) turn.tools = calls.slice(0, TURN_TOOLS_MAX);
      }
      result.turns.push(turn);
    }
    if (anchor) for (const [index, unit] of pending.entries()) result.detect.push({ ...unit,
      turn_id: unit.kind === "tool_output" ? `${anchor}:output:${index}` : anchor,
      ...(unit.kind === "tool_output" ? { anchor_turn_id: anchor } : {}),
    });
    assistantText = ""; calls = []; pending = [];
  }
  // In-flight assistant chunks are not immutable ledger records. The live
  // PreToolUse hook guards them; retrospective capture settles at turn end.
  const title = str(summary?.generated_title) ?? str(summary?.session_summary);
  if (title) result.titles.push({ session_id: sessionId, title: { text: title, origin: "auto_summary" } });
  return result;
}

export const grokSource: TranscriptSourceDescriptor = {
  id: "grok-build", label: "Grok Build", presencePaths: [".grok"], metered: true,
  roots: (home, env) => [...new Set([join(env.GROK_HOME?.trim() || join(home, ".grok"), "sessions"), join(home, ".grok", "sessions")])],
  discover(root, io) {
    const found: string[] = [];
    for (const project of io.listDir(root).sort()) {
      const dir = join(root, project);
      if (!io.stat(dir)?.isDirectory) continue;
      for (const session of io.listDir(dir).sort()) {
        const file = join(dir, session, "updates.jsonl");
        if (io.stat(file)?.isDirectory === false) found.push(file);
      }
    }
    return found;
  },
  parse: (path, io) => parseGrokSession(io.readText(path) ?? "", basename(dirname(path)), io.readText(join(dirname(path), "summary.json"))),
  sessionIdOf: (path) => basename(path) === "updates.jsonl" ? basename(dirname(path)) : undefined,
};
