/**
 * Cursor host adapter for the PreToolUse guard.
 *
 * VERIFIED AGAINST THE VENDOR DOCS on 2026-09-05:
 *  - https://cursor.com/docs/hooks (the official reference; every fact below
 *    that is not marked otherwise comes from it)
 *  - https://github.com/johnlindquist/cursor-hooks (community typings, used
 *    only to cross-check payload field names — it disagrees on two points,
 *    noted inline; the official doc wins)
 *
 * What the docs say, and what this file therefore does:
 *
 * DOCUMENTS. `hooks.json` is read at four levels, highest priority first:
 * enterprise (`/Library/Application Support/Cursor/hooks.json` on macOS),
 * team (cloud, Enterprise only — no file), project
 * (`<project-root>/.cursor/hooks.json`), user (`~/.cursor/hooks.json`). We
 * install into the user document; the project one is offered so a repo can be
 * guarded on its own; the enterprise one is `system` — read by the doctor,
 * never written.
 *
 * SCHEMA. `{ version: 1, hooks: { "<event>": [ { command, type, timeout,
 * matcher, failClosed, loop_limit } ] } }`. `type` defaults to `"command"`;
 * `timeout` is in SECONDS; `failClosed` defaults to false. We write
 * `{ type, command, timeout }` and nothing else — in particular never
 * `failClosed`, because rule 1 is fail open: a crashed or slow guard must not
 * take the user's session down with it.
 *
 * EVENTS we register under, all three confirmed present in the current doc:
 *   beforeShellExecution — shell commands, before they run
 *   beforeMCPExecution   — MCP tool calls, before they run
 *   preToolUse           — the generic tool event (Shell|Read|Write|Grep|
 *                          Delete|Task|MCP:<name>)
 * The doc does not say whether `preToolUse` ALSO fires for shell and MCP calls
 * alongside the two specific events. We normalize all of them anyway — missing
 * a shell call would be a hole. If both fire, `callIdentity` below joins them
 * into ONE call so the guard decides once (guard/dedup.ts): `tool_use_id`
 * where the payload carries it (only `preToolUse` does, per the doc), else
 * conversation + generation + the call's primary argument — the only fields
 * the two events share. Docs-derived; a recorded double-fire is still owed.
 *
 * RESPONSE. `{ permission: "allow" | "ask" | "deny", user_message,
 * agent_message }` — SNAKE_CASE per the official doc (the community typings
 * show `userMessage`/`agentMessage`; blog reports say Cursor tolerates both,
 * but only snake_case is documented, so that is what we print). `ask` is
 * native on the blocking events, which is why this host holds and asks rather
 * than warning like Codex.
 *
 * EXIT CODES. 0 = success, use the JSON on stdout; 2 = block; any other
 * non-zero = the hook failed and the action PROCEEDS (fail open) unless
 * `failClosed` is set. We always exit 0 and let the JSON carry the verdict —
 * exit 2 would be a second way to say "deny" with no room for a reason.
 *
 * MCP NAMES. `beforeMCPExecution` carries the plain `tool_name` plus
 * `mcp_server_name` (the key from `mcp.json`) — names are NOT server-qualified
 * on the wire; we qualify them ourselves into `mcp__<server>__<tool>`, which
 * is the vocabulary every detector and the per-server MCP permissions key on.
 * `preToolUse` reports MCP calls as `MCP:<name>` with no documented server
 * field; when the server cannot be derived the tool name passes through
 * unchanged rather than inventing a server segment that MCP permissions would
 * then match against.
 *
 * UNVERIFIED (no recorded payload exists yet — the fixtures are derived from
 * the doc, not captured): the exact `tool_input` field names per built-in
 * `preToolUse` tool beyond Shell's `command`/`working_directory`; whether
 * Cursor emits an `Edit` or web-fetch tool at all (the doc lists neither); and
 * whether `beforeMCPExecution.tool_input` is always a JSON string (the doc
 * says `"<json params>"`, the community typings call the field `arguments`
 * and pass an object). normalizeInput accepts both shapes for that reason.
 */

// NOTE for whoever wires the registry: this is a VALUE import from the parent
// directory, so the userData copy of the guard bundle must keep `hosts/` as a
// subdirectory next to `policy.js`. A flattened copy is MODULE_NOT_FOUND at
// hook time, which fails the guard OPEN while the app still says "enforcing"
// — the exact failure GUARD_FILES' comment in enforcement.ts warns about.
import type { GuardHookInput } from "../decision.js";
import { HOOK_TIMEOUT_FAST_SECONDS, HOOK_TIMEOUT_SLACK_SECONDS, isGuardCommand } from "../policy.js";
import type { GuardHostDescriptor, HostDecision, HostDocument, HostEmit, CallIdentity } from "./types.js";

/** The events our command is registered under. Order is the write order. */
export const CURSOR_HOOK_EVENTS = [
  "beforeShellExecution",
  "beforeMCPExecution",
  "preToolUse",
] as const;

type CursorHookEvent = (typeof CURSOR_HOOK_EVENTS)[number];

/** One entry in `hooks.<event>[]`. Unknown keys are preserved on foreign
 * entries — we only ever rewrite our own. */
interface CursorHookHandler {
  command?: string;
  type?: string;
  timeout?: number;
  matcher?: string;
  failClosed?: boolean;
  [key: string]: unknown;
}

const INVALID_DOCUMENT = "~/.cursor/hooks.json";

function isOurs(handler: CursorHookHandler | null | undefined): boolean {
  return (
    !!handler &&
    typeof handler === "object" &&
    isGuardCommand(handler.command)
  );
}

/** The per-hook `timeout`, in seconds. It must EXCEED the hold window: Cursor
 * kills a hook that overruns, and a killed hook is a fail-open — which would
 * quietly turn "deny when nobody answers" into "allow when nobody answers".
 * Mirrors hookTimeoutSeconds() in policy.ts. */
function timeoutSecondsFor(holdSeconds: number): number {
  if (!Number.isFinite(holdSeconds) || holdSeconds <= 0) return HOOK_TIMEOUT_FAST_SECONDS;
  return Math.round(holdSeconds) + HOOK_TIMEOUT_SLACK_SECONDS;
}

function parseDocument(docText: string | undefined): Record<string, unknown> {
  if (!docText || docText.trim() === "") return {};
  let parsed: unknown;
  try {
    parsed = JSON.parse(docText);
  } catch {
    // A malformed hooks.json must not be destroyed by us — refuse instead.
    throw new Error(`${INVALID_DOCUMENT} is not valid JSON; not touching it`);
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error(`${INVALID_DOCUMENT} is not a JSON object; not touching it`);
  }
  return parsed as Record<string, unknown>;
}

function hooksContainer(doc: Record<string, unknown>): Record<string, unknown> {
  const hooks = doc.hooks;
  // `hooks: []` is valid JSON that Cursor ignores, and a named event set on an
  // array vanishes at JSON.stringify time — so an inert shape is replaced,
  // never written into.
  if (hooks && typeof hooks === "object" && !Array.isArray(hooks)) {
    return hooks as Record<string, unknown>;
  }
  return {};
}

function record(value: unknown): Record<string, unknown> | undefined {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;
}

function text(value: unknown): string | undefined {
  return typeof value === "string" && value !== "" ? value : undefined;
}

function firstText(obj: Record<string, unknown>, keys: readonly string[]): string | undefined {
  for (const key of keys) {
    const value = text(obj[key]);
    if (value !== undefined) return value;
  }
  return undefined;
}

function documents(home: string, _env: NodeJS.ProcessEnv): HostDocument[] {
  const base = home.endsWith("/") ? home.slice(0, -1) : home;
  return [
    { path: `${base}/.cursor/hooks.json`, level: "user" },
    // Relative to a project root the caller supplies.
    { path: ".cursor/hooks.json", level: "project" },
    // MDM-managed, highest priority; read by the doctor, never written.
    { path: "/Library/Application Support/Cursor/hooks.json", level: "system" },
  ];
}

function merge(docText: string | undefined, command: string, holdSeconds: number): string {
  const doc = parseDocument(docText);
  // Canonical form BEFORE any mutation, so an unchanged document round-trips
  // byte-for-byte instead of being rewritten.
  const before = JSON.stringify(doc);
  const hooks = hooksContainer(doc);
  const desired: CursorHookHandler = {
    type: "command",
    command,
    timeout: Math.max(1, timeoutSecondsFor(holdSeconds)),
  };
  const matchesDesired = (h: CursorHookHandler): boolean =>
    h.type === desired.type &&
    h.command === desired.command &&
    h.timeout === desired.timeout &&
    Object.keys(h).length === Object.keys(desired).length;

  for (const event of CURSOR_HOOK_EVENTS) {
    const existing = Array.isArray(hooks[event]) ? (hooks[event] as CursorHookHandler[]) : [];
    const next: CursorHookHandler[] = [];
    let placed = false;
    for (const handler of existing) {
      if (!isOurs(handler)) {
        // Somebody else's entry, kept exactly as written — including any keys
        // this file has never heard of.
        next.push(handler);
        continue;
      }
      if (placed) continue; // a stray second copy of ours
      placed = true;
      next.push(matchesDesired(handler) ? handler : { ...desired });
    }
    if (!placed) next.push({ ...desired });
    hooks[event] = next;
  }
  doc.hooks = hooks;
  // `version` is required by the schema; create it, never overwrite a value
  // the user (or a future Cursor) put there.
  if (doc.version === undefined) doc.version = 1;

  if (docText !== undefined && JSON.stringify(doc) === before) return docText;
  return `${JSON.stringify(doc, null, 2)}\n`;
}

function remove(docText: string | undefined): string | undefined {
  if (!docText || docText.trim() === "") return undefined;
  let doc: Record<string, unknown>;
  try {
    const parsed = JSON.parse(docText);
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return undefined;
    doc = parsed as Record<string, unknown>;
  } catch {
    return undefined;
  }
  const hooks = record(doc.hooks);
  if (!hooks) return undefined;
  let removed = false;
  // Sweep EVERY event, not just the three we register today: an older build
  // may have installed under an event we have since dropped, and that copy is
  // still ours to clean up.
  for (const [event, value] of Object.entries(hooks)) {
    if (!Array.isArray(value)) continue;
    const handlers = value as CursorHookHandler[];
    const kept = handlers.filter((h) => !isOurs(h));
    if (kept.length === handlers.length) continue;
    removed = true;
    if (kept.length > 0) hooks[event] = kept;
    else delete hooks[event];
  }
  if (!removed) return undefined;
  if (Object.keys(hooks).length === 0) delete doc.hooks;
  return `${JSON.stringify(doc, null, 2)}\n`;
}

function installed(docText: string | undefined, command: string): boolean {
  if (!docText || docText.trim() === "") return false;
  let doc: unknown;
  try {
    doc = JSON.parse(docText);
  } catch {
    return false;
  }
  const hooks = record(record(doc)?.hooks);
  if (!hooks) return false;
  // Every event we register under must carry exactly this command: a document
  // that guards shell but not MCP is not installed, it is half-installed, and
  // the doctor should say so and re-run the merge.
  return CURSOR_HOOK_EVENTS.every((event) => {
    const value = hooks[event];
    if (!Array.isArray(value)) return false;
    return (value as CursorHookHandler[]).some((h) => !!h && typeof h === "object" && h.command === command);
  });
}

/** The server segment of an MCP call. `mcp_server_name` is the documented
 * field; a qualified `tool_name` ("server.tool", "server/tool") is the
 * fallback for payload shapes we have not recorded. */
function splitMcpName(
  toolName: string,
  serverName: string | undefined,
): { server?: string; tool: string } {
  const bare = toolName.startsWith("MCP:") ? toolName.slice("MCP:".length) : toolName;
  if (serverName) return { server: serverName, tool: bare };
  const match = /^([^./:]+)[./:]{1,2}(.+)$/.exec(bare);
  if (match) return { server: match[1], tool: match[2] };
  return { tool: bare };
}

function mcpToolName(toolName: string, serverName: string | undefined): string {
  const { server, tool } = splitMcpName(toolName, serverName);
  // No server → pass the name through unchanged. Inventing a segment would
  // make per-server MCP permissions match a server that does not exist.
  return server ? `mcp__${server}__${tool}` : tool;
}

/** MCP arguments arrive as a JSON string (`tool_input`, per the doc) or as an
 * object (`arguments`, per the community typings). A string that does not
 * parse is kept verbatim under `tool_input` so the detectors still scan it. */
function mcpArguments(payload: Record<string, unknown>): unknown {
  const raw = payload.tool_input ?? payload.arguments ?? payload.tool_args;
  if (typeof raw === "string") {
    try {
      const parsed = JSON.parse(raw);
      if (parsed && typeof parsed === "object") return parsed;
    } catch {
      // not JSON — fall through
    }
    return { tool_input: raw };
  }
  return raw ?? {};
}

function cwdOf(payload: Record<string, unknown>, toolInput?: Record<string, unknown>): string | undefined {
  const direct = firstText(payload, ["cwd", "working_directory", "workspace_root"]);
  if (direct) return direct;
  if (toolInput) {
    const fromInput = firstText(toolInput, ["cwd", "working_directory"]);
    if (fromInput) return fromInput;
  }
  const roots = payload.workspace_roots;
  if (Array.isArray(roots)) {
    for (const root of roots) {
      const value = text(root);
      if (value !== undefined) return value;
    }
  }
  return undefined;
}

/** `input` minus the keys a mapping consumed — the aliases are folded into the
 * guard key, never kept twice. */
function without(input: Record<string, unknown>, keys: readonly string[]): Record<string, unknown> {
  const rest: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(input)) if (!keys.includes(key)) rest[key] = value;
  return rest;
}

/**
 * Cursor's `preToolUse` tool names, mapped onto the guard's vocabulary. The
 * doc lists `Shell | Read | Write | Grep | Delete | Task | MCP:<name>`;
 * `Edit`-shaped and fetch-shaped names are handled defensively because the
 * doc's list is not framed as exhaustive. Anything unrecognised passes through
 * under its own name with its own input — still redacted, still scanned, just
 * not renamed.
 */
function normalizePreToolUse(
  toolName: string,
  toolInput: Record<string, unknown>,
): { tool_name: string; tool_input: unknown } {
  switch (toolName) {
    // Keys the mapping did not read ride along under their own names (P2,
    // 2026-09-10): the doc's per-tool field list is unverified, and a field we
    // did not guess is still text the detectors scan.
    case "Shell": {
      const command = firstText(toolInput, ["command", "cmd", "commandLine"]);
      if (command === undefined) break;
      return { tool_name: "Bash", tool_input: { ...without(toolInput, ["command", "cmd", "commandLine"]), command } };
    }
    case "Read": {
      const filePath = firstText(toolInput, ["file_path", "path", "filePath"]);
      if (filePath === undefined) break;
      return { tool_name: "Read", tool_input: { ...without(toolInput, ["file_path", "path", "filePath"]), file_path: filePath } };
    }
    case "Write": {
      const filePath = firstText(toolInput, ["file_path", "path", "filePath"]);
      if (filePath === undefined) break;
      const content = firstText(toolInput, ["content", "contents", "text"]) ?? "";
      return {
        tool_name: "Write",
        tool_input: { ...without(toolInput, ["file_path", "path", "filePath", "content", "contents", "text"]), file_path: filePath, content },
      };
    }
    case "Edit":
    case "SearchReplace": {
      const filePath = firstText(toolInput, ["file_path", "path", "filePath"]);
      const oldString = firstText(toolInput, ["old_string", "oldString", "search"]);
      const newString = firstText(toolInput, ["new_string", "newString", "replace"]);
      if (filePath === undefined || oldString === undefined) break;
      return {
        tool_name: "Edit",
        tool_input: {
          ...without(toolInput, ["file_path", "path", "filePath", "old_string", "oldString", "search", "new_string", "newString", "replace"]),
          file_path: filePath,
          old_string: oldString,
          new_string: newString ?? "",
        },
      };
    }
    case "Fetch":
    case "WebFetch": {
      const url = firstText(toolInput, ["url", "uri"]);
      if (url === undefined) break;
      return { tool_name: "WebFetch", tool_input: { ...without(toolInput, ["url", "uri"]), url } };
    }
    default:
      break;
  }
  if (toolName.startsWith("MCP:")) {
    const server = firstText(toolInput, ["mcp_server_name"]);
    return { tool_name: mcpToolName(toolName, server), tool_input: toolInput };
  }
  return { tool_name: toolName, tool_input: toolInput };
}

/** The argument that names what a normalized call DOES — the join key across
 * events when the wire gives no call id. */
function primaryArgument(input: GuardHookInput): string {
  const args = record(input.tool_input) ?? {};
  const first = firstText(args, ["command", "file_path", "url"]);
  return first ?? JSON.stringify(args);
}

function callIdentity(raw: unknown, normalized: GuardHookInput): CallIdentity | undefined {
  const payload = record(raw);
  if (!payload) return undefined;
  const event = text(payload.hook_event_name);
  if (!event) return undefined;
  const conversation = firstText(payload, ["conversation_id", "session_id"]) ?? "";
  const generation = firstText(payload, ["generation_id"]) ?? "";
  // A generation is one model turn; without it two identical commands in one
  // conversation would join, and joining two calls is worse than asking twice.
  if (generation === "") return undefined;
  return {
    event,
    key: `${conversation}\u0000${generation}\u0000${normalized.tool_name ?? ""}\u0000${primaryArgument(normalized)}`,
  };
}

function normalizeInput(raw: unknown): GuardHookInput | undefined {
  const payload = record(raw);
  if (!payload) return undefined;
  const session = firstText(payload, ["conversation_id", "session_id"]);
  const event = text(payload.hook_event_name);

  if (event === "beforeShellExecution") {
    const command = firstText(payload, ["command"]);
    if (command === undefined) return undefined;
    return {
      tool_name: "Bash",
      tool_input: { command },
      cwd: cwdOf(payload),
      session_id: session,
    };
  }

  if (event === "beforeMCPExecution") {
    const toolName = firstText(payload, ["tool_name"]);
    if (toolName === undefined) return undefined;
    const server = firstText(payload, ["mcp_server_name", "server_name"]);
    return {
      tool_name: mcpToolName(toolName, server),
      tool_input: mcpArguments(payload),
      cwd: cwdOf(payload),
      session_id: session,
    };
  }

  if (event === "preToolUse") {
    const toolName = firstText(payload, ["tool_name"]);
    if (toolName === undefined) return undefined;
    const toolInput = record(payload.tool_input) ?? {};
    const mapped = normalizePreToolUse(toolName, toolInput);
    return {
      tool_name: mapped.tool_name,
      tool_input: mapped.tool_input,
      cwd: cwdOf(payload, toolInput),
      session_id: session,
    };
  }

  // Every other event (afterFileEdit, sessionStart, stop, …) is not a tool
  // call we evaluate.
  return undefined;
}

function emit(decision: HostDecision, reason?: string): HostEmit {
  // Allow prints NOTHING (rule 2: we add a check, never remove one — a printed
  // `permission: "allow"` would suppress Cursor's own approval prompt).
  if (decision === "allow") return { exitCode: 0 };
  const message = reason ?? "Doorman security policy";
  return {
    stdout: JSON.stringify({
      permission: decision,
      user_message: message,
      agent_message: message,
    }),
    // Always 0: the JSON carries the verdict, and exit 2 would be a second,
    // reason-less way to say deny.
    exitCode: 0,
  };
}

export const cursorHost: GuardHostDescriptor = {
  id: "cursor",
  label: "Cursor",
  source: "cursor",
  documents,
  merge,
  remove,
  installed,
  normalizeInput,
  callIdentity,
  emit,
  // Cursor has a native ask on every blocking event, so an unanswerable hold
  // becomes its own confirmation prompt rather than a warning we shout past.
  warn: (reason: string) => emit("ask", reason),
  supportsNativeAsk: true,
  exitSemantics: "fail-open",
  presencePaths: [".cursor"],
};
