/**
 * Kimi Code (Moonshot AI) host adapter — a Claude-family descriptor
 * (hosts/claude-family.ts) and the first host whose document is TOML.
 *
 * Sources, fetched 2026-09-06 (docs-derived — no live recording yet):
 *   [1] https://moonshotai.github.io/kimi-code/en/customization/hooks
 *   [2] https://www.kimi.com/code/docs/en/kimi-code-cli/customization/hooks.html
 *   [3] https://moonshotai.github.io/kimi-cli/en/configuration/config-files.html
 *       (the legacy Python `kimi-cli`, `~/.kimi/config.toml`)
 *
 * DOCUMENTS [1][3]. `~/.kimi-code/config.toml` for the current Node
 * `kimi-code`; the legacy `kimi-cli` reads `~/.kimi/config.toml`. We install
 * into the current one; the legacy file is returned as a `system`-level
 * document so the doctor can see an old install. No project document is
 * documented for hooks.
 *
 * SCHEMA [1]. A `[[hooks]]` table array with EXACTLY four allowed fields —
 * `event` (required), `matcher` (optional regex), `command` (required),
 * `timeout` (seconds, 1–600, default 30). "Extra fields will cause the config
 * file to fail to load", so the surgery writes nothing else and never a
 * `name`. We write no matcher (omit = all).
 *
 * STDIN [1]. `hook_event_name`, `session_id`, `session_title`, `client_type`,
 * `cwd`; PreToolUse adds `tool_name`, `tool_input`.
 *
 * STDOUT / EXIT [1]. Exit 2 blocks with stderr as the reason; other non-zero
 * and timeouts fail OPEN. A stdout JSON `{ hookSpecificOutput: {
 * permissionDecision: "deny", permissionDecisionReason } }` is documented as
 * accepted too [2], and it keeps the reason — so we deny that way at exit 0
 * rather than losing the words on stderr. No `ask`, no user-message field:
 * warnings are silent (stdout at exit 0 "may append to context", i.e. goes to
 * the MODEL, which is not who a warning is for).
 *
 * TOOLS [1]. Only `Bash{command}` is shown in the docs (the legacy CLI called
 * it `Shell`). `WriteFile`, `StrReplaceFile`, `ReadFile`, `WebFetch` are
 * referenced without their argument keys — mapped on the obvious names and
 * marked VERIFY; unknown keys are dropped for mapped tools, so a wrong guess
 * yields a smaller input, never a wrong one. MCP naming undocumented; names
 * pass through.
 */

import { join } from "node:path";
import { claudeFamilyHost } from "./claude-family.js";
import type { GuardHostDescriptor, HostDocument } from "./types.js";

export const kimiHost: GuardHostDescriptor = claudeFamilyHost({
  id: "kimi",
  label: "Kimi Code",
  source: "kimi-code",
  presencePaths: [".kimi-code", ".kimi"],
  documents(home: string): HostDocument[] {
    return [
      { path: join(home, ".kimi-code", "config.toml"), level: "user" },
      // The legacy Python CLI's file: read for the doctor, never written.
      { path: join(home, ".kimi", "config.toml"), level: "system" },
    ];
  },
  invalidDocument: "~/.kimi-code/config.toml",
  documentFormat: "toml",
  style: "toml",
  event: "PreToolUse",
  acceptedEvents: ["PreToolUse"],
  timeoutUnit: "seconds",
  tools: {
    Bash: { to: "Bash", args: { command: "command" } },
    Shell: { to: "Bash", args: { command: "command" } },
    WriteFile: { to: "Write", args: { file_path: ["path", "file_path"], content: "content" } },
    StrReplaceFile: {
      to: "Edit",
      args: {
        file_path: ["path", "file_path"],
        old_string: ["old_str", "old_string"],
        new_string: ["new_str", "new_string"],
      },
    },
    ReadFile: { to: "Read", args: { file_path: ["path", "file_path"] } },
    WebFetch: { to: "WebFetch", args: { url: "url" } },
  },
  decision: "hook-specific",
  warn: "silent",
  supportsNativeAsk: false,
  exitSemantics: "fail-open",
});
