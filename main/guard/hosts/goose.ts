/**
 * Goose (Block / Agentic AI Foundation) host adapter — a Claude-family
 * descriptor (hosts/claude-family.ts). Goose reads hooks only from PLUGIN
 * directories, so our hook document is our own file inside a plugin we own,
 * and the plugin's manifest is a static artefact the installer writes beside
 * it (types.ts `artifacts`).
 *
 * Sources, fetched 2026-09-06 (docs-derived — no live recording yet):
 *   [1] https://goose-docs.ai/docs/guides/context-engineering/hooks/
 *   [2] https://github.com/aaif-goose/goose/pull/9304 (PreToolUse denial)
 *
 * DOCUMENTS [1]. Hooks live in `hooks/hooks.json` inside a plugin directory
 * under `~/.agents/plugins/<name>/` (user) or `<project>/.agents/plugins/
 * <name>/`; a plugin needs a `plugin.json` manifest (`name`, `version`,
 * `description`). No `config.yaml` route is documented. Ours:
 *   ~/.agents/plugins/doorman/plugin.json        (artefact, static)
 *   ~/.agents/plugins/doorman/hooks/hooks.json   (the hook document)
 * The directory is ours alone, so the document never carries anyone else's
 * entry in practice; the surgery still preserves one if it appears.
 *
 * SCHEMA [1]. Claude's grouped shape: `hooks.PreToolUse: [ { matcher, hooks:
 * [ { type: "command", command, timeout, on_failure } ] } ]`. `timeout` in
 * SECONDS (default 30); `on_failure` is `"allow"` (default) or `"block"` — we
 * never write `block` (rule 1: fail open). `matcher` regex; `".*"` = all.
 *
 * STDIN [1]. `event`, `session_id`, `matcher_context`, `tool_name`,
 * `tool_input`, `working_dir`, `tool_call_id`. The cwd field is `working_dir`.
 *
 * STDOUT [1][2]. Decision signals, in order: exit 2 (stderr reason); stdout
 * `{"decision":"block","reason"}` (any exit code); exit 0 + empty = allow;
 * anything else = NO DECISION (a failure, logged, call proceeds). "stdout must
 * start with `{` and decision must be exactly `block`". No user-message field
 * exists, so a warning is silent. No native ask → the Codex path.
 *
 * TOOLS [1]. `developer__shell{command, timeout_secs}` → Bash;
 * `developer__write{path, content}` → Write; `developer__edit{path, before,
 * after}` → Edit; `developer__tree`, `developer__read_image` pass through.
 * MCP extension tools use their registered ids, `<extension>__<tool>` — we
 * qualify any other `a__b` name as `mcp__a__b`, the vocabulary the per-server
 * MCP permissions key on.
 */

import { join } from "node:path";
import { claudeFamilyHost } from "./claude-family.js";
import type { GuardHostDescriptor, HostArtifact, HostDocument } from "./types.js";

const PLUGIN_DIR = [".agents", "plugins", "doorman"] as const;

/** The static manifest — no machine paths, identical on every Mac. */
export const GOOSE_PLUGIN_MANIFEST = `${JSON.stringify(
  {
    name: "doorman",
    version: "1.0.0",
    description: "Doorman Guardrails — holds or blocks risky tool calls before they run.",
  },
  null,
  2,
)}\n`;

function gooseMcpName(toolName: string): string | undefined {
  if (toolName.startsWith("mcp__") || toolName.startsWith("developer__")) return undefined;
  const cut = toolName.indexOf("__");
  if (cut <= 0 || cut + 2 >= toolName.length) return undefined;
  return `mcp__${toolName.slice(0, cut)}__${toolName.slice(cut + 2)}`;
}

export const gooseHost: GuardHostDescriptor = claudeFamilyHost({
  id: "goose",
  label: "Goose",
  source: "goose",
  presencePaths: [".config/goose", "/Applications/Goose.app"],
  documents(home: string): HostDocument[] {
    return [
      { path: join(home, ...PLUGIN_DIR, "hooks", "hooks.json"), level: "user" },
      { path: join(".agents", "plugins", "doorman", "hooks", "hooks.json"), level: "project" },
    ];
  },
  artifacts(home: string): HostArtifact[] {
    return [{ path: join(home, ...PLUGIN_DIR, "plugin.json"), content: GOOSE_PLUGIN_MANIFEST }];
  },
  invalidDocument: "~/.agents/plugins/doorman/hooks/hooks.json",
  style: "grouped",
  event: "PreToolUse",
  acceptedEvents: ["PreToolUse"],
  timeoutUnit: "seconds",
  matcher: ".*",
  cwdField: "working_dir",
  tools: {
    developer__shell: { to: "Bash", args: { command: "command" } },
    developer__write: { to: "Write", args: { file_path: "path", content: "content" } },
    developer__edit: { to: "Edit", args: { file_path: "path", old_string: "before", new_string: "after" } },
  },
  mcpName: (toolName) => gooseMcpName(toolName),
  decision: "decision-block",
  warn: "silent",
  supportsNativeAsk: false,
  exitSemantics: "fail-open",
});
