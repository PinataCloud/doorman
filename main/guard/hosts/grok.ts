/** Grok Build's command-hook protocol. Verified against xai-org/grok-build
 * docs/user-guide/10-hooks.md on 2026-09-06; fixtures are source-derived.
 * Global JSON hook files avoid editing the user's TOML configuration.
 * https://github.com/xai-org/grok-build/tree/main/crates/codegen/xai-grok-pager/docs/user-guide
 */
import { join } from "node:path";
import { claudeFamilyHost } from "./claude-family.js";
import type { GuardHostDescriptor } from "./types.js";

const family = claudeFamilyHost({
  id: "grok", label: "Grok Build", source: "grok-build",
  presencePaths: [".grok"],
  documents: (home, env) => [{
    path: join(env.GROK_HOME?.trim() || join(home, ".grok"), "hooks", "doorman.json"), level: "user",
  }],
  invalidDocument: "Grok hooks/doorman.json",
  style: "grouped", event: "PreToolUse", acceptedEvents: ["PreToolUse", "pre_tool_use"],
  timeoutUnit: "seconds", matcher: ".*",
  tools: {
    run_terminal_command: { to: "Bash", args: { command: "command" } },
    read_file: { to: "Read", args: { file_path: ["target_file", "path", "file_path"] } },
    search_replace: { to: "Edit", args: {
      file_path: ["file_path", "path"], old_string: ["old_string", "old_str"], new_string: ["new_string", "new_str"],
    } },
    write_file: { to: "Write", args: { file_path: ["path", "file_path"], content: "content" } },
    web_fetch: { to: "WebFetch", args: { url: "url" } },
  },
  mcpName: (name) => !name.startsWith("mcp__") && name.includes("__") ? `mcp__${name}` : undefined,
  decision: "hook-specific", warn: "silent", supportsNativeAsk: true, exitSemantics: "fail-open",
});

export const grokHost: GuardHostDescriptor = {
  ...family,
  presencePathsFor: (home, env) => [env.GROK_HOME?.trim() || join(home, ".grok")],
  normalizeInput(raw) {
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) return undefined;
    const input = raw as Record<string, unknown>;
    return family.normalizeInput({
      ...input,
      hook_event_name: input.hook_event_name ?? input.hookEventName,
      session_id: input.session_id ?? input.sessionId,
      tool_name: input.tool_name ?? input.toolName,
      tool_input: input.tool_input ?? input.toolInput,
      cwd: input.cwd ?? input.workspaceRoot,
    });
  },
  warn: (reason) => family.emit("ask", reason),
};
