/**
 * Doorman's own MCP server — the agent's door into the guard, over stdio.
 *
 * Copilot's agent mode in VS Code and the Copilot CLI (and every other MCP
 * host on this Mac) can spawn this instead of guessing what the guard will do:
 *   command: node   args: ["<userData>/doorman/mcp/doorman-mcp.js"]
 * Four tools, all answered from what is already on this disk, so they work
 * with the app closed:
 *   · doorman_check_tool_call  — run the SAME detectors and policy the
 *     PreToolUse guard runs, on a call the agent is about to make. The
 *     answer is the decision (allow / ask / deny), the rules by name and what
 *     to do instead — so an agent can ask before it is blocked.
 *   · doorman_explain_last_block — why the guard held or denied recent calls
 *     in this session (the guard's spool), with the remedy per rule.
 *   · doorman_session_spend    — what the ledger has metered for a session or
 *     a working directory: tokens by model, unmetered turns counted. Tokens,
 *     never dollars — the name predates that and is kept so agents'
 *     configs keep working.
 *   · doorman_status           — is the app running (heartbeat), which rules
 *     hold or block, which hosts the guard registry knows.
 *
 * NEVER a value: the check returns rule names and counts, never the redacted
 * excerpt; the spool rows are already masked and only their names travel;
 * usage is numbers. Nothing here writes anything.
 *
 * Wire: newline-delimited JSON-RPC 2.0 (the MCP stdio transport). We print
 * one line per response and nothing else on stdout; diagnostics go to stderr.
 *
 * Self-containment rule: copied verbatim to userData and run with plain `node`.
 * Imports only the SIBLING guard bundle (`../guard/*.js`, copied to the
 * neighbouring directory by the same installer) — like the gateway does.
 */

import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { evaluateToolCall, type GuardHookInput } from "../guard/decision.js";
import { appListening } from "../guard/handshake.js";
import { HOSTS, hostLabel } from "../guard/hosts/index.js";
import { DETECTOR_LABELS, parsePolicy, type GuardPolicy } from "../guard/policy.js";
import { agentFacingReason, remedyFor } from "../guard/remedy.js";
import { ruleShown } from "../guard/rule-scope.js";

export const MCP_SERVER_NAME = "doorman";
export const MCP_SERVER_VERSION = "1";
/** The newest revision both VS Code 1.136 and Copilot CLI 1.0.83 speak; a
 * client asking for an older one gets its own version echoed (we use nothing
 * revision-specific). */
const DEFAULT_PROTOCOL_VERSION = "2025-11-25";

/** Where the server finds what it reads. Resolved from the script's own
 * location by default (`<userData>/doorman/mcp/`), injectable for tests. */
export interface McpPaths {
  guardDir: string;
  storeDir: string;
}

export function defaultPaths(scriptDir: string): McpPaths {
  return {
    guardDir: join(scriptDir, "..", "guard"),
    storeDir: join(scriptDir, "..", "..", "store"),
  };
}

export interface McpReadIo {
  readText(path: string): string | undefined;
  appListening(guardDir: string): boolean;
  now(): number;
}

export function realIo(): McpReadIo {
  return {
    readText(path) {
      try {
        return existsSync(path) ? readFileSync(path, "utf8") : undefined;
      } catch {
        return undefined;
      }
    },
    appListening: (guardDir) => appListening(guardDir),
    now: () => Date.now(),
  };
}

// ---- tools ------------------------------------------------------------------

export const TOOLS = [
  {
    name: "doorman_check_tool_call",
    description:
      "Ask Doorman's security guard, before making a tool call, whether it would allow, hold or block it — the same rules and policy the PreToolUse guard applies. Returns the decision, the rules by name and what to do. Use it before a shell command that touches credentials, the network or infrastructure, and before writing a file that may contain a secret. If the answer is hold or block, ask the user; do not reword the call until it passes.",
    inputSchema: {
      type: "object",
      properties: {
        tool_name: {
          type: "string",
          description: "Claude-style tool name: Bash, Write, Edit, Read, WebFetch, or mcp__<server>__<tool>. Defaults to Bash when `command` is given.",
        },
        tool_input: { type: "object", description: "The tool's arguments (e.g. { command } for Bash, { file_path, content } for Write)." },
        command: { type: "string", description: "Shortcut for a shell command: same as tool_name Bash with { command }." },
        cwd: { type: "string", description: "Working directory the call runs in (scopes project rules)." },
        session_id: { type: "string", description: "The agent session id, if known." },
      },
    },
  },
  {
    name: "doorman_explain_last_block",
    description:
      "Why Doorman held or blocked recent tool calls: which rule fired, on which tool, how it was resolved, and what to do next. Call this rather than retrying a blocked call.",
    inputSchema: {
      type: "object",
      properties: {
        session_id: { type: "string", description: "Only this agent session (recommended when known)." },
        cwd: { type: "string", description: "Only calls made from this working directory." },
        limit: { type: "integer", minimum: 1, maximum: 20, description: "How many recent decisions (default 3)." },
      },
    },
  },
  {
    name: "doorman_session_spend",
    description:
      "What Doorman has metered so far: model calls and their input/output token counts by model, plus how many calls carried no token counts. Token counts only — no dollar figures. Filter by session id or working directory; defaults to the last 24 hours across every agent on this computer.",
    inputSchema: {
      type: "object",
      properties: {
        session_id: { type: "string" },
        cwd: { type: "string" },
        since_hours: { type: "number", minimum: 0.1, maximum: 24 * 90, description: "Window in hours (default 24)." },
      },
    },
  },
  {
    name: "doorman_status",
    description: "Whether the Doorman app is running to answer holds, which rules currently hold or block a call, and which agent hosts the guard knows.",
    inputSchema: { type: "object", properties: {} },
  },
] as const;

export const SERVER_INSTRUCTIONS =
  "Doorman guards tool calls on this computer. Before a shell command that reads credentials, reaches the network or changes infrastructure, and before writing a file that may hold a secret, call doorman_check_tool_call and follow its answer. If a tool call was blocked or held, call doorman_explain_last_block rather than retrying or working around it; the person decides in the Doorman app.";

type ToolResult = { text: string; isError?: boolean };

function obj(value: unknown): Record<string, unknown> | undefined {
  return value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : undefined;
}
function str(value: unknown): string | undefined {
  return typeof value === "string" && value !== "" ? value : undefined;
}

function readPolicy(paths: McpPaths, io: McpReadIo): GuardPolicy {
  return parsePolicy(io.readText(join(paths.guardDir, "policy.json")));
}

function labelOf(id: string, labels?: Record<string, string>): string {
  return labels?.[id] ?? (DETECTOR_LABELS as Record<string, string>)[id] ?? id;
}

export function checkToolCall(args: Record<string, unknown>, paths: McpPaths, io: McpReadIo): ToolResult {
  const command = str(args.command);
  const toolName = str(args.tool_name) ?? (command ? "Bash" : undefined);
  const toolInput = obj(args.tool_input) ?? (command ? { command } : undefined);
  if (!toolName || !toolInput) {
    return { text: "Give either `command` (a shell command) or `tool_name` + `tool_input`.", isError: true };
  }
  const input: GuardHookInput = {
    tool_name: toolName,
    tool_input: toolInput,
    ...(str(args.cwd) ? { cwd: str(args.cwd) } : {}),
    ...(str(args.session_id) ? { session_id: str(args.session_id) } : {}),
  };
  const policy = readPolicy(paths, io);
  const result = evaluateToolCall(input, policy);
  const decision = result.decision;
  // Only rules the app shows are named to the agent (guard/rule-scope.ts,
  //): a hidden rule's finding is recorded by the guard, not reported.
  const fired = [...new Set(result.findings.map((f) => f.detector as string))].filter(ruleShown);
  const warned = decision.warned.filter((id) => ruleShown(id));
  if (decision.decision === "allow") {
    const lines = ["Decision: allow — the guard would let this call run."];
    if (fired.length > 0) {
      lines.push(`Recorded, not held: ${fired.map((id) => labelOf(id)).join(", ")}.`);
    }
    if (warned.length > 0) {
      lines.push(`Heads-up rules that would fire: ${warned.map((id) => labelOf(id)).join(", ")}.`);
    }
    return { text: lines.join("\n") };
  }
  const verb = decision.decision === "deny" ? "deny — the guard would block this call" : "ask — the guard would hold this call for the person to approve";
  const next =
    decision.decision === "deny"
      ? "Do not make this call or work around it; ask the user how to proceed."
      : "If you make this call, the user is asked first; do not work around the hold.";
  return {
    text: [
      `Decision: ${verb}.`,
      `Rules: ${decision.detectors.map((id) => labelOf(id)).join(", ")}.`,
      `What to do: ${remedyFor(decision.detectors)} ${next}`,
    ].join("\n"),
  };
}

interface SpoolRow {
  at?: string;
  session_id?: string;
  source?: string;
  tool_name?: string;
  cwd?: string;
  decision?: string;
  resolution?: string;
  findings?: { detector?: string }[];
  detector_labels?: Record<string, string>;
}

export function explainLastBlock(args: Record<string, unknown>, paths: McpPaths, io: McpReadIo): ToolResult {
  const text = io.readText(join(paths.guardDir, "spool.jsonl"));
  const sessionId = str(args.session_id);
  const cwd = str(args.cwd);
  const limit = typeof args.limit === "number" && args.limit >= 1 ? Math.min(20, Math.floor(args.limit)) : 3;
  const rows: SpoolRow[] = [];
  for (const line of (text ?? "").split("\n")) {
    if (line.trim() === "") continue;
    try {
      const row = obj(JSON.parse(line)) as SpoolRow | undefined;
      if (row) rows.push(row);
    } catch {
      // a half-written line
    }
  }
  // The guard writes one line per stage (detection, then resolution); fold on
  // (at-second, session, tool) is overkill — keep the LAST line per
  // (session_id, tool_name, at) so a resolution wins over its detection line.
  const held = rows.filter((r) => r.decision === "ask" || r.decision === "deny" || r.resolution !== undefined);
  const filtered = held.filter((r) => (!sessionId || r.session_id === sessionId) && (!cwd || r.cwd === cwd));
  const recent = filtered.slice(-limit).reverse();
  if (recent.length === 0) {
    return {
      text: sessionId || cwd
        ? "Doorman has held or blocked nothing for that session or directory. If a call failed, the cause was not the guard."
        : "Doorman has held or blocked nothing recently on this computer.",
    };
  }
  const policy = readPolicy(paths, io);
  const out = recent.map((r) => {
    const detectors = [...new Set((r.findings ?? []).map((f) => f.detector).filter((d): d is string => typeof d === "string"))].filter(ruleShown);
    const named = detectors.map((id) => labelOf(id, r.detector_labels));
    const outcome =
      r.resolution === "allowed"
        ? "the person allowed it"
        : r.resolution === "denied"
          ? "the person denied it"
          : r.resolution === "timeout"
            ? "nobody answered in time"
            : r.decision === "deny"
              ? "blocked by policy"
              : "held for approval";
    const reason = agentFacingReason({
      decision: r.decision === "deny" ? "deny" : "ask",
      reason: `Doorman flagged this tool call: ${named.join(", ") || "a rule"}.`,
      detectors,
      resolution: r.resolution as never,
      policy,
    });
    return `${r.at ?? "?"} · ${r.tool_name ?? "tool"} on ${hostLabel(r.source)} — ${outcome}.\n${reason}`;
  });
  return { text: out.join("\n\n") };
}

interface StoredTurn {
  role?: string;
  at?: string;
  session_id?: string;
  source?: string;
  cwd?: string;
  model?: string;
  cost?: number;
  cost_unknown?: boolean;
  usage?: { input_tokens?: number; output_tokens?: number };
}

export function sessionSpend(args: Record<string, unknown>, paths: McpPaths, io: McpReadIo): ToolResult {
  const text = io.readText(join(paths.storeDir, "turns.jsonl"));
  const sessionId = str(args.session_id);
  const cwd = str(args.cwd);
  const hours = typeof args.since_hours === "number" && args.since_hours > 0 ? args.since_hours : 24;
  const since = io.now() - hours * 3_600_000;
  const byModel = new Map<string, { calls: number; input: number; output: number }>();
  const bySource = new Map<string, number>();
  let unmetered = 0;
  let sessions = new Set<string>();
  for (const line of (text ?? "").split("\n")) {
    if (line.trim() === "") continue;
    let turn: StoredTurn | undefined;
    try {
      turn = obj(JSON.parse(line)) as StoredTurn | undefined;
    } catch {
      continue;
    }
    if (!turn || turn.role !== "assistant") continue;
    if (sessionId && turn.session_id !== sessionId) continue;
    if (cwd && turn.cwd !== cwd) continue;
    const at = turn.at ? Date.parse(turn.at) : NaN;
    if (!sessionId && (!Number.isFinite(at) || at < since)) continue;
    if (turn.session_id) sessions.add(turn.session_id);
    // Tokens, never dollars: the on-device price is an estimate the app does
    // not stand behind, and an agent would repeat it as fact.
    const input = turn.usage?.input_tokens ?? 0;
    const output = turn.usage?.output_tokens ?? 0;
    if (input + output > 0) {
      const key = turn.model ?? "unknown model";
      const row = byModel.get(key) ?? { calls: 0, input: 0, output: 0 };
      row.calls += 1;
      row.input += input;
      row.output += output;
      byModel.set(key, row);
      bySource.set(turn.source ?? "?", (bySource.get(turn.source ?? "?") ?? 0) + input + output);
    } else {
      unmetered += 1;
    }
  }
  const scope = sessionId ? `session ${sessionId}` : cwd ? `${cwd} (last ${hours}h)` : `every agent on this computer (last ${hours}h)`;
  if (byModel.size === 0 && unmetered === 0) return { text: `Doorman has metered nothing for ${scope}.` };
  const totalIn = [...byModel.values()].reduce((sum, r) => sum + r.input, 0);
  const totalOut = [...byModel.values()].reduce((sum, r) => sum + r.output, 0);
  const n = (v: number) => v.toLocaleString("en-US");
  const lines = [`Metered for ${scope}: ${n(totalIn + totalOut)} tokens (${n(totalIn)} in / ${n(totalOut)} out) across ${sessions.size} session(s).`];
  for (const [model, row] of [...byModel].sort((a, b) => b[1].input + b[1].output - (a[1].input + a[1].output))) {
    lines.push(`· ${model}: ${row.calls} call(s), ${n(row.input)} in / ${n(row.output)} out tokens`);
  }
  if (bySource.size > 1) {
    lines.push(`By agent: ${[...bySource].map(([s, tokens]) => `${hostLabel(s)} ${n(tokens)} tokens`).join(", ")}.`);
  }
  if (unmetered > 0) lines.push(`${unmetered} call(s) carried no token counts and are not in the total.`);
  lines.push("No dollar figure is given: Doorman reports measured tokens, not an estimated cost.");
  return { text: lines.join("\n") };
}

export function status(paths: McpPaths, io: McpReadIo): ToolResult {
  const policy = readPolicy(paths, io);
  const hold: string[] = [];
  const block: string[] = [];
  for (const [id, mode] of Object.entries(policy.modes)) {
    if (mode === "ask") hold.push(labelOf(id));
    else if (mode === "block") block.push(labelOf(id));
  }
  const listening = io.appListening(paths.guardDir);
  return {
    text: [
      listening
        ? "The Doorman app is running: a held call waits for the person to answer there."
        : // Absent app = the unattended rule (confirm.unattended, review F1), not
          // the timeout one: a host with its own prompt is handed the question,
          // every other host gets a deny by default.
          `The Doorman app is not running: a call that needs approval is handed to the agent's own prompt where it has one, and otherwise ${policy.confirm.unattended === "deny" ? "denied (not run) until the app is open" : "warned about and continued"} rather than held.`,
      block.length > 0 ? `Rules that block: ${block.join(", ")}.` : "No rule blocks outright.",
      hold.length > 0 ? `Rules that hold for approval: ${hold.join(", ")}.` : "No rule holds a call.",
      `Hold window: ${policy.confirm.hold_seconds}s, then ${policy.confirm.on_timeout}.`,
      `When the app can't ask: ${policy.confirm.unattended === "deny" ? "deny" : "continue with a warning"}.`,
      `Guard hosts known: ${HOSTS.map((h) => h.label).join(", ")}.`,
    ].join("\n"),
  };
}

// ---- JSON-RPC ---------------------------------------------------------------

type JsonRpcId = string | number | null;

export interface JsonRpcMessage {
  jsonrpc?: string;
  id?: JsonRpcId;
  method?: string;
  params?: unknown;
}

function reply(id: JsonRpcId, result: unknown): string {
  return JSON.stringify({ jsonrpc: "2.0", id, result });
}
function error(id: JsonRpcId, code: number, message: string): string {
  return JSON.stringify({ jsonrpc: "2.0", id, error: { code, message } });
}

/** One incoming line → zero or one outgoing line. Pure over `paths`/`io`. */
export function handleMessage(raw: string, paths: McpPaths, io: McpReadIo): string | undefined {
  let message: JsonRpcMessage;
  try {
    const parsed = JSON.parse(raw);
    const record = obj(parsed);
    if (!record) return error(null, -32600, "Invalid Request");
    message = record as JsonRpcMessage;
  } catch {
    return error(null, -32700, "Parse error");
  }
  const id = message.id === undefined ? null : message.id;
  const method = str(message.method);
  const isNotification = message.id === undefined;
  if (!method) return isNotification ? undefined : error(id, -32600, "Invalid Request");
  const params = obj(message.params) ?? {};

  switch (method) {
    case "initialize":
      return reply(id, {
        protocolVersion: str(params.protocolVersion) ?? DEFAULT_PROTOCOL_VERSION,
        capabilities: { tools: { listChanged: false } },
        serverInfo: { name: MCP_SERVER_NAME, title: "Doorman", version: MCP_SERVER_VERSION },
        instructions: SERVER_INSTRUCTIONS,
      });
    case "ping":
      return reply(id, {});
    case "tools/list":
      return reply(id, { tools: TOOLS });
    case "tools/call": {
      const name = str(params.name);
      const args = obj(params.arguments) ?? {};
      let result: ToolResult;
      try {
        switch (name) {
          case "doorman_check_tool_call":
            result = checkToolCall(args, paths, io);
            break;
          case "doorman_explain_last_block":
            result = explainLastBlock(args, paths, io);
            break;
          case "doorman_session_spend":
            result = sessionSpend(args, paths, io);
            break;
          case "doorman_status":
            result = status(paths, io);
            break;
          default:
            return error(id, -32602, `Unknown tool: ${name ?? "(none)"}`);
        }
      } catch (err) {
        result = { text: `Doorman could not answer: ${String(err)}`, isError: true };
      }
      return reply(id, {
        content: [{ type: "text", text: result.text }],
        ...(result.isError ? { isError: true } : {}),
      });
    }
    default:
      if (isNotification) return undefined; // notifications/initialized, notifications/cancelled, …
      return error(id, -32601, `Method not found: ${method}`);
  }
}

// ---- process ----------------------------------------------------------------

function main(): void {
  const paths = defaultPaths(__dirname);
  const io = realIo();
  let buffer = "";
  process.stdin.setEncoding("utf8");
  process.stdin.on("data", (chunk: string) => {
    buffer += chunk;
    let index: number;
    while ((index = buffer.indexOf("\n")) >= 0) {
      const line = buffer.slice(0, index).replace(/\r$/, "");
      buffer = buffer.slice(index + 1);
      if (line.trim() === "") continue;
      let out: string | undefined;
      try {
        out = handleMessage(line, paths, io);
      } catch (err) {
        process.stderr.write(`[doorman mcp] ${String(err)}\n`);
        out = undefined;
      }
      if (out !== undefined) process.stdout.write(`${out}\n`);
    }
  });
  process.stdin.on("end", () => process.exit(0));
}

// Only run when invoked directly (not when imported by a test).
if (process.argv[1] && process.argv[1].endsWith("doorman-mcp.js")) {
  main();
}
