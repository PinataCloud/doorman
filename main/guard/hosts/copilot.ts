/**
 * GitHub Copilot CLI — guard host adapter.
 *
 * Sources, all fetched 2026-09-05 (record the date: this surface is moving):
 *  · https://docs.github.com/en/copilot/reference/hooks-reference
 *  · https://docs.github.com/en/copilot/how-tos/copilot-cli/customize-copilot/use-hooks
 *  · https://docs.github.com/en/enterprise-cloud@latest/copilot/tutorials/copilot-cli-hooks
 *  · https://docs.github.com/en/copilot/how-tos/copilot-sdk/hooks/pre-tool-use
 *
 * WHERE HOOK DOCUMENTS LIVE (hooks reference, "Configuration file locations").
 * Copilot loads hook files from five places and RUNS EVERY MATCHING ENTRY FROM
 * ALL OF THEM ("When the same event appears in multiple sources, all hook
 * entries from all sources are run"), so we never have to displace anyone:
 *   1. policy   `/etc/github-copilot/policy.d/*.json`   (admin, never written)
 *   2. project  `.github/hooks/*.json`                  (repository root)
 *   3. user     `~/.copilot/hooks/`  — or `$COPILOT_HOME/hooks/`
 *   4. project settings `.github/copilot/settings.json` → `hooks`
 *   5. user settings    `~/.copilot/settings.json`      → `hooks`
 *   6. plugins  a plugin's own `hooks.json`
 * A USER-LEVEL LOCATION EXISTS (3), so the app can guard this host once per
 * machine rather than once per repository — that was an open question, and
 * it resolves in our favour. Both of our documents are OUR OWN FILE, `doorman.json`, inside
 * those directories: the directories are globbed, so we never merge into
 * somebody else's hook file. The policy directory is read-only to us and is
 * a glob, not one path, so it is not modelled as a `system` document here.
 *
 * DOCUMENT SCHEMA (hooks reference):
 *   { "version": 1,
 *     "hooks": { "preToolUse": [ { "type": "command", "bash": "…",
 *                                  "powershell": "…", "cwd": "…",
 *                                  "env": {…}, "timeoutSec": 30,
 *                                  "matcher": "regex" } ] } }
 * We write `bash` only (this app is macOS-only) and no `matcher` — an
 * unmatched security hook is a partial bypass, and the field is compiled as
 * `^(?:PATTERN)$`, i.e. anchored, so a narrowed one silently skips tools.
 *
 * STDIN PAYLOAD. Two dialects, selected by the event NAME in the config:
 *  · camelCase `preToolUse` → `{ sessionId, timestamp, cwd, toolName, toolArgs }`
 *  · PascalCase `PreToolUse` → Claude's own shape `{ hook_event_name,
 *    session_id, cwd, tool_name, tool_input }` with tool names already mapped
 *    to Claude's ("Hooks configured with the PascalCase event name PreToolUse
 *    … apply Claude's matcher semantics").
 * We register the documented camelCase event and normalize; `normalizeInput`
 * accepts BOTH, because the PascalCase dialect is the one a shared
 * Open-Plugins document would deliver and it costs six lines to honour.
 *
 * `toolArgs` IS A JSON STRING — the docs contradict themselves and the string
 * is what the CLI actually sends: the tutorial and the how-to both show
 * `"toolArgs":"{\"command\":\"ls\"}"`, while the reference's TypeScript block
 * types it `unknown` and calls it "parsed". github/copilot-cli#3349 exists
 * precisely because hooks that assume an object read nothing and fail open.
 * So: parse a string, accept an already-parsed object, and when a string will
 * not parse keep the text under `_raw` rather than dropping it — the
 * detectors scan the serialized input, so unparsable text still gets scanned.
 *
 * TOOL NAMES. GitHub publishes the mapping itself (hooks reference, PascalCase
 * dialect), and this adapter uses exactly that table — see TOOL_NAMES below.
 * Argument field names are NOT in the hooks reference; `path` / `file_text` /
 * `old_str` / `new_str` are what the SDK examples read, so the rename table is
 * best-effort and every unknown key is preserved verbatim.
 *
 * MCP TOOL NAMING IS UNVERIFIED. The hooks reference does not say how an MCP
 * tool appears in `toolName`; the CLI's permission flags use `Server(tool)`
 * and community reports show both `server:tool` and a sanitized
 * `server-tool`. We map only the unambiguous forms (`mcp__s__t` already, and
 * `server:tool`) and pass everything else through untouched with its parsed
 * args — a wrong mapping would hide a call from the mcp__ detectors, whereas
 * a pass-through is still fully scanned by every text detector.
 * 2026-09-08, against CLI 1.0.83's runtime: model-facing tool names must match
 * /^[a-zA-Z0-9_-]+$/ (the runtime sanitizes anything else), so `server:tool`
 * can never reach `toolName` in the camelCase dialect — that branch is kept
 * only for the PascalCase/Claude dialect. `server/tool` is the separate
 * `namespacedName`, not the hook's name. Still no real MCP sample recorded.
 *
 * OUTPUT CONTRACT. stdout is `{ permissionDecision: "allow"|"deny"|"ask",
 * permissionDecisionReason? }`; Copilot also honours Claude's
 * `hookSpecificOutput` wrapper (that is the shape in github/copilot-cli#3037,
 * where the CLI acted on it). `ask` has been honoured since CLI 1.0.66 — the
 * same issue: an `ask` from a hook started prompting on every call at that
 * version — so this host gets a NATIVE ask and never needs the Codex-style
 * "warn and continue" path. We deliberately print NOTHING on allow: an
 * explicit `permissionDecision: "allow"` SUPPRESSES Copilot's own approval
 * prompt (changelog for 1.0.66), which would remove a check we did not add.
 *
 * EXIT CODES — THE INVARIANT THAT FLIPS HERE. For `preToolUse`, exit 2,
 * crashes and any other non-zero exit all FAIL CLOSED: the tool call is
 * denied, and at exit 2 "any stdout JSON is merged with the deny decision …
 * even if that JSON reports permissionDecision: allow". So `emit` returns
 * exit code 0 for EVERY decision, including deny — a non-zero exit would be a
 * deny we never decided, on any crash. TIMEOUTS, by contrast, FAIL OPEN
 * ("Timeouts are fail-open for every event, including preToolUse"), default
 * 30 s — which is why `merge` writes `timeoutSec` from the hold window: a
 * hold that outlives the timeout is a SILENT ALLOW.
 *
 * KNOWN ISSUES to keep in view (github/copilot-cli): plugin-declared
 * `hooks.json` hooks never fire (#2540, and #3659); preToolUse is not enforced
 * for subagents spawned via the `task` tool (#2392, referenced from #2540);
 * an extension that registers hooks via `joinSession` can replace the
 * hooks.json pipeline entirely (#2076); `hookSpecificOutput.updatedInput` is
 * ignored (#2013 — we never rewrite args, so it does not affect us).
 *
 * VS CODE COPILOT CHAT READS THIS DOCUMENT TOO (verified against VS Code
 * 1.136.2 / bundled Copilot Chat 0.64.1, 2026-09-08; docs:
 * https://code.visualstudio.com/docs/agent-customization/hooks). Its agent
 * hooks (`chat.useHooks`, preview, default ON) load `~/.copilot/hooks/*.json`
 * and the repo's `.github/hooks/*.json` — the same directories as the CLI —
 * and accept the CLI's `preToolUse`/`bash`/`timeoutSec` spelling. So the ONE
 * document above already guards VS Code's agent mode; a second document would
 * fire twice on both products. What differs is the wire:
 *  · stdin is Claude's shape — `{ hook_event_name: "PreToolUse", session_id,
 *    transcript_path?, tool_name, tool_input, tool_use_id }` — but `tool_name`
 *    is VS Code's OWN vocabulary (`run_in_terminal`, `create_file`,
 *    `replace_string_in_file`, …), never Claude's, and `cwd` is absent unless
 *    the hook entry sets one. VSCODE_TOOL_NAMES / VSCODE_ARG_RENAMES map it.
 *  · the decision is read ONLY from `hookSpecificOutput.permissionDecision`
 *    (a bare top-level `permissionDecision` is ignored — the hook "succeeds"
 *    and the call runs). emit() therefore prints BOTH shapes in one object.
 *  · exit 2 is a blocking deny with stderr as the message; any other non-zero
 *    exit is a warning. We still exit 0 for every decision.
 *  · `matcher` is parsed but NOT applied; we never write one anyway.
 * The payload's product is recognized by `tool_use_id` (VS Code always sends
 * it; the CLI's camelCase dialect never does) or a VS Code tool name, and
 * reported as the `vscode-copilot` source — the id the ledger already uses for
 * VS Code's chat sessions — through the `dialects` seam in types.ts.
 * An MCP tool arrives as `mcp_<server-slug>_<tool>` with the slug capped at 18
 * characters; the join is ambiguous when either half carries an underscore, so
 * it is passed through unchanged (still fully scanned) rather than mis-split.
 *
 * Self-containment rule: this directory is copied verbatim into userData and
 * run with plain `node`, so nothing here imports outside main/guard/.
 */

import type { GuardHookInput } from "../decision.js";
import {
  HOOK_TIMEOUT_FAST_SECONDS,
  HOOK_TIMEOUT_SLACK_SECONDS,
  isGuardCommand,
} from "../policy.js";
import type { GuardHostDescriptor, HostDialect, HostDocument, HostEmit } from "./types.js";

/** Our own file inside the globbed hook directories — never anyone else's. */
const DOCUMENT_BASENAME = "doorman.json";
const USER_DOCUMENT_DIR = ".copilot/hooks";
const PROJECT_DOCUMENT_DIR = ".github/hooks";
const DOCUMENT_LABEL = "the Copilot CLI hook document";

/** Copilot's built-in tool names → the Claude Code names every detector keys
 * on. This is GitHub's own table (hooks reference, PascalCase dialect), not a
 * guess: bash/powershell→Bash, view→Read, create→Write,
 * edit|str_replace_editor|apply_patch→Edit, grep|rg→Grep, glob→Glob,
 * web_fetch→WebFetch, web_search→WebSearch, ask_user→AskUserQuestion,
 * update_todo→TodoWrite, task→Agent (literal `Task` also accepted; we emit
 * `Task`, which is what Claude Code sends and what the detectors see). */
const TOOL_NAMES: Record<string, string> = {
  bash: "Bash",
  powershell: "Bash",
  view: "Read",
  create: "Write",
  edit: "Edit",
  str_replace_editor: "Edit",
  apply_patch: "Edit",
  grep: "Grep",
  rg: "Grep",
  glob: "Glob",
  web_fetch: "WebFetch",
  web_search: "WebSearch",
  ask_user: "AskUserQuestion",
  update_todo: "TodoWrite",
  task: "Task",
};

/** Per-tool argument renames, applied on top of the caller's own keys (every
 * unlisted key is preserved). Copilot's file tools speak the text-editor
 * dialect (`path`, `file_text`, `old_str`, `new_str`); Claude's detectors read
 * `file_path`, `content`, `old_string`, `new_string`. */
const ARG_RENAMES: Record<string, [from: string, to: string][]> = {
  Read: [["path", "file_path"]],
  Write: [
    ["path", "file_path"],
    ["file_text", "content"],
    ["text", "content"],
  ],
  Edit: [
    ["path", "file_path"],
    ["old_str", "old_string"],
    ["new_str", "new_string"],
  ],
  Grep: [["path", "file_path"]],
  Glob: [["path", "file_path"]],
};

/** VS Code Copilot Chat's tool names (the Copilot Chat extension's ToolName
 * enum, 0.64.1) → Claude's. Anything unlisted passes through unchanged. */
const VSCODE_TOOL_NAMES: Record<string, string> = {
  run_in_terminal: "Bash",
  create_and_run_task: "Bash",
  create_file: "Write",
  replace_string_in_file: "Edit",
  multi_replace_string_in_file: "Edit",
  insert_edit_into_file: "Edit",
  edit_notebook_file: "Edit",
  read_file: "Read",
  grep_search: "Grep",
  file_search: "Glob",
  fetch_webpage: "WebFetch",
  runSubagent: "Task",
};

/** VS Code's camelCase argument keys → Claude's, per Claude tool. Unlisted keys
 * are preserved (the detectors scan the serialized input regardless). */
const VSCODE_ARG_RENAMES: Record<string, [from: string, to: string][]> = {
  Write: [["filePath", "file_path"]],
  Edit: [
    ["filePath", "file_path"],
    ["oldString", "old_string"],
    ["newString", "new_string"],
    // insert_edit_into_file carries the inserted code as `code`.
    ["code", "new_string"],
  ],
  Read: [["filePath", "file_path"]],
  Grep: [["query", "pattern"]],
  Glob: [["query", "pattern"]],
};

/** VS Code's `tool_use_id` is the discriminator: the CLI's camelCase dialect
 * never carries it. A VS Code tool name is accepted as a second signal for a
 * payload that lost the id. */
export function isVscodePayload(raw: unknown): boolean {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return false;
  const payload = raw as Record<string, unknown>;
  if (typeof payload.tool_name !== "string") return false;
  if (typeof payload.tool_use_id === "string" && payload.tool_use_id !== "") return true;
  return payload.tool_name in VSCODE_TOOL_NAMES || payload.tool_name.startsWith("mcp_");
}

/** VS Code's tool call in Claude's vocabulary. `fetch_webpage` takes a list of
 * urls; the first becomes `url` so the WebFetch detectors see it, and the list
 * stays. `multi_replace_string_in_file` edits several files in one call; the
 * first target is `file_path` and every replacement is kept under `edits`. */
export function normalizeVscodeTool(toolName: string, input: unknown): { tool_name: string; tool_input: unknown } {
  const claudeName = VSCODE_TOOL_NAMES[toolName] ?? toolName;
  if (!input || typeof input !== "object" || Array.isArray(input)) return { tool_name: claudeName, tool_input: input ?? {} };
  let args: Record<string, unknown> = { ...(input as Record<string, unknown>) };
  if (toolName === "multi_replace_string_in_file" && Array.isArray(args.replacements)) {
    const edits = args.replacements.map((r) =>
      r && typeof r === "object" ? renameKeys(r as Record<string, unknown>, VSCODE_ARG_RENAMES.Edit) : r,
    );
    const first = edits.find((e) => e && typeof e === "object") as Record<string, unknown> | undefined;
    const { replacements: _dropped, ...rest } = args;
    args = { ...(first?.file_path === undefined ? {} : { file_path: first.file_path }), edits, ...rest };
  }
  if (toolName === "fetch_webpage" && Array.isArray(args.urls) && typeof args.urls[0] === "string" && !("url" in args)) {
    args = { url: args.urls[0], ...args };
  }
  const renames = VSCODE_ARG_RENAMES[claudeName];
  return { tool_name: claudeName, tool_input: renames ? renameKeys(args, renames) : args };
}

function renameKeys(args: Record<string, unknown>, renames: [from: string, to: string][]): Record<string, unknown> {
  const out: Record<string, unknown> = { ...args };
  for (const [from, to] of renames) {
    if (from in out && !(to in out)) {
      out[to] = out[from];
      delete out[from];
    }
  }
  return out;
}

export const vscodeDialect: HostDialect = {
  source: "vscode-copilot",
  label: "VS Code + Copilot",
  claims: isVscodePayload,
};

interface HookEntry {
  type?: string;
  bash?: string;
  powershell?: string;
  exec?: string;
  timeoutSec?: number;
  [key: string]: unknown;
}

function isOurEntry(entry: unknown): entry is HookEntry {
  if (!entry || typeof entry !== "object" || Array.isArray(entry)) return false;
  const record = entry as HookEntry;
  for (const key of ["bash", "powershell", "exec"] as const) {
    const value = record[key];
    if (isGuardCommand(value)) return true;
  }
  return false;
}

/**
 * The per-hook timeout, from the hold window, exactly as policy.ts's
 * `hookTimeoutSeconds` derives it: hold + slack when we may hold, the fast
 * timeout when we never will. A timeout here is a SILENT ALLOW, so this
 * number must always leave the hold room to finish.
 */
export function copilotTimeoutSeconds(holdSeconds: number): number {
  if (!Number.isFinite(holdSeconds) || holdSeconds <= 0) return HOOK_TIMEOUT_FAST_SECONDS;
  return Math.max(1, Math.round(holdSeconds)) + HOOK_TIMEOUT_SLACK_SECONDS;
}

function parseDocument(docText: string | undefined, onInvalid: "throw" | "undefined"): Record<string, unknown> | undefined {
  if (docText === undefined || docText.trim() === "") return {};
  try {
    const parsed = JSON.parse(docText);
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
      return parsed as Record<string, unknown>;
    }
  } catch {
    if (onInvalid === "throw") throw new Error(`${DOCUMENT_LABEL} is not valid JSON; not touching it`);
    return undefined;
  }
  if (onInvalid === "throw") throw new Error(`${DOCUMENT_LABEL} is not a JSON object; not touching it`);
  return undefined;
}

function preToolUseOf(settings: Record<string, unknown>): { hooks: Record<string, unknown>; entries: unknown[] } {
  const hooks =
    settings.hooks && typeof settings.hooks === "object" && !Array.isArray(settings.hooks)
      ? (settings.hooks as Record<string, unknown>)
      : {};
  const entries = Array.isArray(hooks.preToolUse) ? (hooks.preToolUse as unknown[]) : [];
  return { hooks, entries };
}

function merge(docText: string | undefined, command: string, holdSeconds: number): string {
  const settings = parseDocument(docText, "throw") as Record<string, unknown>;
  const before = JSON.stringify(settings);
  const { hooks, entries } = preToolUseOf(settings);
  const desired: HookEntry = {
    type: "command",
    bash: command,
    timeoutSec: copilotTimeoutSeconds(holdSeconds),
  };
  const matchesDesired = (entry: HookEntry): boolean =>
    entry.type === desired.type &&
    entry.bash === desired.bash &&
    entry.timeoutSec === desired.timeoutSec &&
    Object.keys(entry).length === Object.keys(desired).length;
  let placed = false;
  const next: unknown[] = [];
  for (const entry of entries) {
    if (!isOurEntry(entry)) {
      // Somebody else's entry — in our own file that means a hand-edit, and a
      // hand-edit is still theirs. Preserved byte-for-byte.
      next.push(entry);
      continue;
    }
    if (placed) continue; // a stray second copy of ours
    placed = true;
    next.push(matchesDesired(entry) ? entry : desired);
  }
  if (!placed) next.push(desired);
  hooks.preToolUse = next;
  settings.hooks = hooks;
  settings.version = typeof settings.version === "number" ? settings.version : 1;
  if (docText !== undefined && JSON.stringify(settings) === before) return docText;
  return `${JSON.stringify(settings, null, 2)}\n`;
}

function remove(docText: string | undefined): string | undefined {
  if (!docText || docText.trim() === "") return undefined;
  const settings = parseDocument(docText, "undefined");
  if (!settings) return undefined;
  const hooks = settings.hooks;
  if (!hooks || typeof hooks !== "object" || Array.isArray(hooks)) return undefined;
  const container = hooks as Record<string, unknown>;
  if (!Array.isArray(container.preToolUse)) return undefined;
  const entries = container.preToolUse as unknown[];
  const kept = entries.filter((entry) => !isOurEntry(entry));
  if (kept.length === entries.length) return undefined;
  if (kept.length > 0) container.preToolUse = kept;
  else delete container.preToolUse;
  if (Object.keys(container).length === 0) delete settings.hooks;
  return `${JSON.stringify(settings, null, 2)}\n`;
}

function installed(docText: string | undefined, command: string): boolean {
  if (!docText || docText.trim() === "") return false;
  let settings: Record<string, unknown> | undefined;
  try {
    settings = parseDocument(docText, "undefined");
  } catch {
    return false;
  }
  if (!settings) return false;
  const { entries } = preToolUseOf(settings);
  return entries.some(
    (entry) => isOurEntry(entry) && (entry as HookEntry).bash === command,
  );
}

/** `toolArgs` as an object. A string is parsed (that is what the CLI sends);
 * an object is taken as-is (that is what the reference claims and what the
 * SDK delivers); anything else — including a string that will not parse —
 * is kept as text under `_raw` so the detectors still scan it. */
export function parseToolArgs(value: unknown): Record<string, unknown> {
  if (value && typeof value === "object" && !Array.isArray(value)) {
    return value as Record<string, unknown>;
  }
  if (typeof value === "string") {
    const text = value.trim();
    if (text === "") return {};
    try {
      const parsed = JSON.parse(text);
      if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
        return parsed as Record<string, unknown>;
      }
    } catch {
      // fall through — an unparsable string is still text worth scanning
    }
    return { _raw: value };
  }
  if (value === undefined || value === null) return {};
  return { _raw: value };
}

/** Copilot's tool name in Claude's vocabulary. Unknown names pass through
 * unchanged, except the two unambiguous MCP spellings. */
export function normalizeToolName(toolName: string): string {
  const mapped = TOOL_NAMES[toolName];
  if (mapped) return mapped;
  if (toolName.startsWith("mcp__")) return toolName;
  // `server:tool` is the only MCP spelling we can recognize without guessing;
  // see the MCP note in the header.
  const colon = toolName.indexOf(":");
  if (colon > 0 && colon < toolName.length - 1 && !toolName.includes(" ")) {
    return `mcp__${toolName.slice(0, colon)}__${toolName.slice(colon + 1)}`;
  }
  return toolName;
}

function renameArgs(claudeName: string, args: Record<string, unknown>): Record<string, unknown> {
  const renames = ARG_RENAMES[claudeName];
  if (!renames) return args;
  const out: Record<string, unknown> = { ...args };
  for (const [from, to] of renames) {
    if (from in out && !(to in out)) {
      out[to] = out[from];
      delete out[from];
    }
  }
  return out;
}

function normalizeInput(raw: unknown): GuardHookInput | undefined {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return undefined;
  const payload = raw as Record<string, unknown>;

  const event = payload.hook_event_name ?? payload.hookEventName;
  if (typeof event === "string" && event !== "PreToolUse" && event !== "preToolUse") return undefined;

  const cwd = typeof payload.cwd === "string" && payload.cwd !== "" ? payload.cwd : undefined;
  const sessionRaw = payload.sessionId ?? payload.session_id;
  const session_id = typeof sessionRaw === "string" && sessionRaw !== "" ? sessionRaw : undefined;

  // The PascalCase dialect already speaks Claude: tool_name is the Claude name
  // and tool_input is an object. Take it as it stands — unless it is VS Code
  // Copilot Chat on the wire (see the header), whose tool_name is VS Code's
  // own vocabulary and gets the same mapping treatment the CLI's does.
  if (typeof payload.tool_name === "string" && payload.tool_name !== "") {
    const mapped = isVscodePayload(payload)
      ? normalizeVscodeTool(payload.tool_name, payload.tool_input)
      : { tool_name: payload.tool_name, tool_input: payload.tool_input ?? {} };
    return {
      ...(session_id ? { session_id } : {}),
      tool_name: mapped.tool_name,
      tool_input: mapped.tool_input,
      ...(cwd ? { cwd } : {}),
    };
  }

  const toolName = payload.toolName;
  if (typeof toolName !== "string" || toolName === "") return undefined;
  const claudeName = normalizeToolName(toolName);
  const args = renameArgs(claudeName, parseToolArgs(payload.toolArgs));
  return {
    ...(session_id ? { session_id } : {}),
    tool_name: claudeName,
    tool_input: args,
    ...(cwd ? { cwd } : {}),
  };
}

/** Every decision exits 0. A non-zero exit is a DENY on this host, and we
 * never deny by accident — not on a crash, not on a bug in a later edit.
 *
 * One object, two readers: the CLI reads the top-level `permissionDecision`;
 * VS Code Copilot Chat reads only `hookSpecificOutput.permissionDecision` and
 * strips the wrapper when `hookEventName` is not the event it fired (so it is
 * named). Each product ignores the other's keys. */
function emit(decision: "allow" | "ask" | "deny", reason?: string): HostEmit {
  if (decision === "allow") return { exitCode: 0 };
  const permissionDecisionReason = reason ?? "Doorman security policy";
  return {
    stdout: JSON.stringify({
      permissionDecision: decision,
      permissionDecisionReason,
      hookSpecificOutput: {
        hookEventName: "PreToolUse",
        permissionDecision: decision,
        permissionDecisionReason,
      },
    }),
    exitCode: 0,
  };
}

function documents(home: string, env: NodeJS.ProcessEnv): HostDocument[] {
  const copilotHome = env.COPILOT_HOME && env.COPILOT_HOME.trim() !== "" ? env.COPILOT_HOME.trim() : undefined;
  const userDir = copilotHome
    ? `${copilotHome.replace(/\/+$/, "")}/hooks`
    : `${home.replace(/\/+$/, "")}/${USER_DOCUMENT_DIR}`;
  return [
    { path: `${userDir}/${DOCUMENT_BASENAME}`, level: "user" },
    { path: `${PROJECT_DOCUMENT_DIR}/${DOCUMENT_BASENAME}`, level: "project" },
  ];
}

export const copilotHost: GuardHostDescriptor = {
  id: "copilot",
  label: "Copilot CLI",
  source: "copilot-cli",
  documents,
  merge,
  remove,
  installed,
  normalizeInput,
  emit,
  warn: (reason: string) => emit("ask", reason),
  supportsNativeAsk: true,
  exitSemantics: "fail-closed",
  // No fixedTimeoutSeconds: merge() writes timeoutSec itself. (Copilot's own
  // default, if we ever failed to, is 30 s — and it fails OPEN.)
  // PRESENCE IS EITHER PRODUCT, not just the CLI. This one document is what
  // guards VS Code's agent mode too (see the header), so a machine with VS Code
  // and no Copilot CLI still needs it written — and `~/.copilot` may not exist
  // there yet, since it is the CLI SDK that creates it. Listing `~/.copilot`
  // alone meant those machines were reported as "no host to install into" and
  // ran agent mode unguarded while the setup check said nothing.
  //
  // The VS Code user-data directories are spelled out here rather than imported
  // because this directory is copied verbatim into userData and run with plain
  // `node` — nothing in main/guard/ may import outside it. lib/vscode.ts holds
  // the canonical family list, and test/hosts-copilot.test.ts fails if the two
  // ever disagree. Every platform's spelling is listed: one that is not this
  // machine's simply never exists.
  presencePaths: [
    ".copilot",
    "Library/Application Support/Code",
    "Library/Application Support/Code - Insiders",
    "Library/Application Support/VSCodium",
    "AppData/Roaming/Code",
    "AppData/Roaming/Code - Insiders",
    "AppData/Roaming/VSCodium",
    ".config/Code",
    ".config/Code - Insiders",
    ".config/VSCodium",
  ],
  dialects: [vscodeDialect],
};
