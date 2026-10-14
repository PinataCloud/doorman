/**
 * Factory Droid host adapter — a Claude-family descriptor
 * (hosts/claude-family.ts). Droid's hooks are Claude Code's with camelCase
 * extras (`permissionMode`, `updatedInput`) and its own tool names.
 *
 * Sources, fetched 2026-09-06 (docs-derived — no live recording yet):
 *   [1] https://docs.factory.ai/reference/hooks-reference
 *   [2] https://docs.factory.ai/cli/configuration/hooks-guide
 *   [3] https://docs.factory.ai/droid-cli/settings
 *
 * DOCUMENTS [1][3]. User scope `~/.factory/settings.json` (or
 * `~/.factory/hooks.json`); project `.factory/settings.json` / `.factory/
 * hooks.json`; legacy `.factory/hooks/hooks.json` is migrated by Droid. We
 * install into `~/.factory/settings.json` — the personal configuration file
 * [3] — and return the project settings document for the doctor.
 * **Droid snapshots hooks at startup and warns when they are modified
 * externally** [2], so a running session shows a notice when the guard is
 * installed mid-session; the entry takes effect for the next session.
 *
 * SCHEMA [1]. `hooks.PreToolUse: [ { matcher, commandRegex?, hooks: [ { type:
 * "command", command, timeout } ] } ]`; `timeout` in SECONDS (default 60).
 * `matcher` is a tool-name pattern; we write `".*"`.
 *
 * STDIN [1]. `session_id`, `transcript_path`, `cwd`, `permission_mode`,
 * `hook_event_name`, `tool_name`, `tool_input`.
 *
 * STDOUT [1][2]. `hookSpecificOutput: { hookEventName, permissionDecision:
 * allow|deny|ask, permissionDecisionReason, updatedInput }`, plus `continue`,
 * `stopReason`, `suppressOutput`, `systemMessage`. `ask` is native.
 *
 * EXIT CODES [1]. 0 success; 2 blocks (stderr as feedback); other non-zero =
 * non-blocking. We always exit 0 with JSON.
 *
 * TOOLS [1]. `Execute{command}` → Bash; `Create{file_path, content}` → Write;
 * `Edit{file_path, new_content}` → Edit (Droid's Edit carries the NEW content,
 * not an old/new pair — `new_content` lands in `new_string`, and there is no
 * `old_string`); `Read{file_path}` → Read; `FetchUrl{url}` → WebFetch;
 * `ApplyPatch{file_path, patch}`, `LS`, `Glob`, `Grep`, `WebSearch` pass
 * through. MCP tools are already `mcp__<server>__<tool>` [1].
 */

import { join } from "node:path";
import { claudeFamilyHost } from "./claude-family.js";
import type { GuardHostDescriptor, HostDocument } from "./types.js";

const FACTORY_DIR = ".factory";

export const droidHost: GuardHostDescriptor = claudeFamilyHost({
  id: "droid",
  label: "Factory Droid",
  source: "droid",
  presencePaths: [FACTORY_DIR],
  documents(home: string): HostDocument[] {
    return [
      { path: join(home, FACTORY_DIR, "settings.json"), level: "user" },
      { path: join(".factory", "settings.json"), level: "project" },
    ];
  },
  invalidDocument: "~/.factory/settings.json",
  style: "grouped",
  event: "PreToolUse",
  acceptedEvents: ["PreToolUse"],
  timeoutUnit: "seconds",
  matcher: ".*",
  tools: {
    Execute: { to: "Bash", args: { command: "command" } },
    Create: { to: "Write", args: { file_path: "file_path", content: "content" } },
    Edit: { to: "Edit", args: { file_path: "file_path", old_string: "old_string", new_string: ["new_content", "new_string"] } },
    Read: { to: "Read", args: { file_path: "file_path" } },
    FetchUrl: { to: "WebFetch", args: { url: "url" } },
  },
  decision: "hook-specific",
  warn: "system-message",
  supportsNativeAsk: true,
  exitSemantics: "fail-open",
});
