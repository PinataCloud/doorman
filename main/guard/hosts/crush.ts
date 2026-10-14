/**
 * Crush (Charmbracelet) host adapter — a Claude-family descriptor
 * (hosts/claude-family.ts). Crush ships ONE hook event, PreToolUse, and
 * advertises Claude Code compatibility for the stdin payload and exit codes;
 * its document is a FLAT array of handlers rather than Claude's groups.
 *
 * Sources, fetched 2026-09-06 (docs-derived — no live recording yet):
 *   [1] https://github.com/charmbracelet/crush/blob/main/docs/hooks/README.md
 *   [2] https://github.com/charmbracelet/crush/issues/3156 (compat gaps)
 *
 * DOCUMENTS [1]. Global `~/.config/crush/crush.json` (absolute paths only);
 * project `crush.json` or `.crush.json` at the project root. Project settings
 * override global ones — the doctor reads the project files.
 *
 * SCHEMA [1]. `hooks.PreToolUse: [ { name?, matcher?, command, timeout } ]`.
 * `timeout` in SECONDS (default 30). `matcher` is a regex on the tool name;
 * omitted = every tool, which is what we want (a narrowed matcher on a
 * security hook is a partial bypass), so we write none.
 *
 * STDIN [1]. `event`, `session_id`, `cwd`, `tool_name`, `tool_input`.
 * Note the event field is `event`, not `hook_event_name`.
 *
 * STDOUT [1]. Exit 0 + `{ decision: "allow"|"deny"|null, reason, context,
 * updated_input, halt }`; multiple hooks compose, first deny wins. Exit 2
 * blocks with stderr as the reason; exit 49 halts the turn; other non-zero =
 * non-blocking (fail-open). No native ask — `decision` has no `ask` — so this
 * host takes the Codex path. No user-facing message field either: `context`
 * goes to the MODEL, so a warning is silent here (rule 3 still lets the call
 * run). We deny with `{ decision: "deny", reason }` at exit 0.
 *
 * SUBAGENTS [1]. "PreToolUse only fires on the top-level agent's tool calls.
 * Sub-agents run without hook interception" — a documented hole the coverage
 * copy should state.
 *
 * TOOLS [1]. `bash{command}`, `edit`/`write`/`multiedit` with `file_path`,
 * `view`/`ls`/`grep`/`glob` read-only; MCP tools are `mcp_<server>_<tool>`
 * (matcher `^mcp_`). The per-tool argument keys beyond `command`/`file_path`
 * are not in the hooks doc — `content`, `old_string`/`new_string`, `url` are
 * taken from Crush's Claude-compatible tool set and marked VERIFY.
 */

import { join } from "node:path";
import { claudeFamilyHost, mcpFirstUnderscore } from "./claude-family.js";
import type { GuardHostDescriptor, HostDocument } from "./types.js";

export const crushHost: GuardHostDescriptor = claudeFamilyHost({
  id: "crush",
  label: "Crush",
  source: "crush",
  presencePaths: [".config/crush", ".local/share/crush"],
  documents(home: string): HostDocument[] {
    return [
      { path: join(home, ".config", "crush", "crush.json"), level: "user" },
      { path: "crush.json", level: "project" },
      { path: ".crush.json", level: "project" },
    ];
  },
  invalidDocument: "~/.config/crush/crush.json",
  style: "flat",
  event: "PreToolUse",
  acceptedEvents: ["PreToolUse"],
  timeoutUnit: "seconds",
  tools: {
    bash: { to: "Bash", args: { command: "command" } },
    write: { to: "Write", args: { file_path: "file_path", content: "content" } },
    edit: { to: "Edit", args: { file_path: "file_path", old_string: "old_string", new_string: "new_string" } },
    view: { to: "Read", args: { file_path: "file_path" } },
    fetch: { to: "WebFetch", args: { url: "url" } },
  },
  mcpName: (toolName) => mcpFirstUnderscore(toolName),
  decision: "decision-deny",
  warn: "silent",
  supportsNativeAsk: false,
  exitSemantics: "fail-open",
});
