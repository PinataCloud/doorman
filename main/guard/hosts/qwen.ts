/**
 * Qwen Code host adapter — a Claude-family descriptor (hosts/claude-family.ts).
 * Qwen Code is Alibaba's fork of Gemini CLI, but its HOOK protocol is Claude
 * Code's, not Gemini's: `hooks.PreToolUse` groups, `hookSpecificOutput.
 * permissionDecision` with a native `ask`, exit 2 blocks.
 *
 * Sources, fetched 2026-09-06 (docs-derived — no live recording yet; the
 * fixtures under test/fixtures/hooks/qwen/ say so in `_provenance`):
 *   [1] https://qwenlm.github.io/qwen-code-docs/en/users/features/hooks/
 *   [2] https://github.com/QwenLM/qwen-code/blob/main/docs/users/features/hooks.md
 *
 * DOCUMENTS [1]. User `~/.qwen/settings.json`; project `.qwen/settings.json`
 * ("requires trusted folder status"). No documented env override of the user
 * directory. We install user-level and return the project document for the
 * doctor.
 *
 * SCHEMA [1][2]. `hooks.PreToolUse: [ { matcher, sequential?, hooks: [ { type:
 * "command", command, name?, timeout } ] } ]`. `timeout` is in MILLISECONDS
 * for command hooks ("default 60000") — merge() multiplies. Matcher is a regex
 * against the tool id; we write `"*"`? No — Qwen documents regex matchers
 * (`^run_shell_command$`), so the match-all we write is `".*"`.
 *
 * STDIN [1]. `session_id`, `transcript_path`, `cwd`, `hook_event_name`,
 * `timestamp`, `permission_mode`, `tool_name`, `tool_input`, `tool_use_id`,
 * `tool_call_id?`.
 *
 * STDOUT [1][2]. `hookSpecificOutput: { hookEventName, permissionDecision:
 * allow|deny|ask, permissionDecisionReason (required), updatedInput?,
 * additionalContext? }`; top-level `decision`/`reason`/`systemMessage` also
 * accepted. `ask` "pauses and asks the user to confirm the tool call in the
 * TUI" [2] — a NATIVE ask, so this host holds nothing itself.
 *
 * EXIT CODES [1]. 0 = parse stdout; 2 = block, stderr as feedback; other =
 * non-blocking (fail-open). We always exit 0 and let the JSON carry it.
 *
 * TOOLS [1][2]. `run_shell_command{command}`, `write_file{file_path, content}`,
 * `edit{file_path, old_string, new_string}`, `read_file{file_path |
 * absolute_path}`, `web_fetch{url | prompt}`, plus `glob`, `grep`, `ls`,
 * `web_search` (pass through). MCP naming is NOT documented [2] — names pass
 * through untouched unless already `mcp__…`. VERIFY on a recording.
 *
 * COMMENTS. Like Gemini CLI, Qwen Code strips a BOM and `//` / `/* *\/`
 * comments, then `JSON.parse`s (verified 2026-10-19) — comments are legal, a
 * trailing comma is fatal. A commented settings.json is edited in place.
 */

import { join } from "node:path";
import { claudeFamilyHost } from "./claude-family.js";
import type { GuardHostDescriptor, HostDocument } from "./types.js";

const QWEN_DIR = ".qwen";

export const qwenHost: GuardHostDescriptor = claudeFamilyHost({
  id: "qwen",
  label: "Qwen Code",
  source: "qwen-code",
  presencePaths: [QWEN_DIR],
  documents(home: string): HostDocument[] {
    return [
      { path: join(home, QWEN_DIR, "settings.json"), level: "user" },
      { path: join(".qwen", "settings.json"), level: "project" },
    ];
  },
  invalidDocument: "~/.qwen/settings.json",
  jsonDialect: { trailingCommas: false },
  style: "grouped",
  event: "PreToolUse",
  acceptedEvents: ["PreToolUse"],
  timeoutUnit: "milliseconds",
  matcher: ".*",
  tools: {
    run_shell_command: { to: "Bash", args: { command: "command" } },
    write_file: { to: "Write", args: { file_path: ["file_path", "absolute_path"], content: "content" } },
    edit: {
      to: "Edit",
      args: { file_path: ["file_path", "absolute_path"], old_string: "old_string", new_string: "new_string" },
    },
    replace: {
      to: "Edit",
      args: { file_path: ["file_path", "absolute_path"], old_string: "old_string", new_string: "new_string" },
    },
    read_file: { to: "Read", args: { file_path: ["file_path", "absolute_path"] } },
    web_fetch: { to: "WebFetch", args: { url: "url", prompt: "prompt" } },
  },
  decision: "hook-specific",
  warn: "system-message",
  supportsNativeAsk: true,
  exitSemantics: "fail-open",
});
