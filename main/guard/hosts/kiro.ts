/**
 * Kiro CLI (AWS) host adapter — a Claude-family descriptor
 * (hosts/claude-family.ts) for Kiro's 3.x standalone hook files.
 *
 * Sources, fetched 2026-09-06 (docs-derived — no live recording yet):
 *   [1] https://kiro.dev/docs/cli/v3/hooks-migration/   (the v1 file schema)
 *   [2] https://kiro.dev/docs/cli/hooks/                 (stdin, exit codes, tools)
 *   [3] https://kiro.dev/changelog/cli/2-13/             (global `~/.kiro/hooks/`)
 *   [4] https://kiro.dev/docs/hooks/types/               (matcher categories)
 *
 * DOCUMENTS [1][3]. CLI 3.0 moved hooks out of the agent config into
 * standalone `.kiro/hooks/*.json` files; CLI 2.13 (v3 track) added GLOBAL
 * hooks in `~/.kiro/hooks/`, which "fire in every workspace". The directory
 * is globbed, so — like Copilot — we write our OWN file rather than merging
 * into anybody's: `~/.kiro/hooks/doorman.json` (user) and `.kiro/hooks/
 * doorman.json` (project, doctor). The 2.x embedded `hooks.preToolUse` in
 * `~/.kiro/agents/<name>.json` is NOT written: `kiro-cli agent migrate`
 * retires it.
 *
 * SCHEMA [1]. `{ version: "v1", hooks: [ { name, trigger, matcher?, action:
 * { type: "command", command }, timeout, enabled } ] }`; `timeout` in
 * SECONDS; PreToolUse matchers match tool names — we write `".*"`.
 *
 * STDIN [2]. `hook_event_name` ("preToolUse" in the 2.x docs; PascalCase
 * "PreToolUse" is the 3.x trigger name — both accepted), `cwd`, `session_id`,
 * `tool_name`, `tool_input`.
 *
 * EXIT CODES [2]. 0 = allow ("STDOUT captured but not shown"); 2 = block,
 * STDERR returned to the LLM; other = STDERR shown as a warning, call
 * proceeds. No JSON verdict is documented, so deny is a bare exit 2 and the
 * reason — which only STDERR could carry — is lost on the wire (spool and
 * app keep it). No native ask; warnings are silent.
 *
 * TOOLS [2][4]. Canonical `execute_bash{command}` (alias `shell`) → Bash;
 * `fs_write{command: create|str_replace|insert|append, path, file_text,
 * old_str, new_str}` (alias `write`) → Write (path + file_text) — a
 * str_replace carries `old_str`/`new_str`, mapped into Edit's keys when the
 * write has no file_text; `fs_read{operations[]|path}` (alias `read`) →
 * Read; `use_aws` passes through; MCP tools are `@server/tool` →
 * `mcp__server__tool`.
 */

import { join } from "node:path";
import type { GuardHookInput } from "../decision.js";
import { claudeFamilyHost } from "./claude-family.js";
import type { GuardHostDescriptor, HostDocument } from "./types.js";

const KIRO_DIR = ".kiro";
const OUR_FILE = "doorman.json";

const base = claudeFamilyHost({
  id: "kiro",
  label: "Kiro CLI",
  source: "kiro",
  presencePaths: [KIRO_DIR],
  documents(home: string): HostDocument[] {
    return [
      { path: join(home, KIRO_DIR, "hooks", OUR_FILE), level: "user" },
      { path: join(".kiro", "hooks", OUR_FILE), level: "project" },
    ];
  },
  invalidDocument: "~/.kiro/hooks/doorman.json",
  style: "kiro",
  event: "PreToolUse",
  acceptedEvents: ["PreToolUse", "preToolUse"],
  timeoutUnit: "seconds",
  matcher: ".*",
  tools: {
    execute_bash: { to: "Bash", args: { command: "command" } },
    shell: { to: "Bash", args: { command: "command" } },
    fs_read: { to: "Read", args: { file_path: "path" } },
    read: { to: "Read", args: { file_path: "path" } },
  },
  mcpName: (toolName) => {
    // `@server/tool` [2] — the one unambiguous MCP shape.
    const m = /^@([^/]+)\/(.+)$/.exec(toolName);
    return m ? `mcp__${m[1]}__${m[2]}` : undefined;
  },
  decision: "exit-2",
  warn: "silent",
  supportsNativeAsk: false,
  exitSemantics: "fail-open",
});

const str = (value: unknown): string | undefined =>
  typeof value === "string" && value !== "" ? value : undefined;

/**
 * Kiro's `fs_write` is one tool with a `command` discriminator; `fs_read`
 * batches `operations`. Both need more than a key rename, so they are handled
 * ahead of the family's table and everything else falls through to it.
 */
function normalizeKiroInput(raw: unknown): GuardHookInput | undefined {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return undefined;
  const payload = raw as Record<string, unknown>;
  const toolName = str(payload.tool_name);
  const input =
    payload.tool_input && typeof payload.tool_input === "object" && !Array.isArray(payload.tool_input)
      ? (payload.tool_input as Record<string, unknown>)
      : {};
  const common = { session_id: str(payload.session_id), cwd: str(payload.cwd) };
  if (toolName === "fs_write" || toolName === "write") {
    const event = str(payload.hook_event_name);
    if (event !== undefined && event !== "PreToolUse" && event !== "preToolUse") return undefined;
    const mode = str(input.command);
    // Unconsumed keys (`command`, `insert_line`, …) ride along — P2, 2026-09-10.
    const { path: _path, old_str: _old, new_str: _new, file_text: _text, ...rest } = input;
    if (mode === "str_replace" || (mode !== "create" && input.file_text === undefined && input.old_str !== undefined)) {
      return {
        ...common,
        tool_name: "Edit",
        tool_input: { ...rest, file_path: input.path, old_string: input.old_str, new_string: input.new_str },
      };
    }
    return {
      ...common,
      tool_name: "Write",
      tool_input: { ...rest, file_path: input.path, content: input.file_text ?? input.new_str },
    };
  }
  if ((toolName === "fs_read" || toolName === "read") && Array.isArray(input.operations)) {
    const event = str(payload.hook_event_name);
    if (event !== undefined && event !== "PreToolUse" && event !== "preToolUse") return undefined;
    // EVERY operation is kept: `file_path` is the first path — the one field the Read vocabulary
    // names and `target` is derived from — and `file_paths` carries all of
    // them, so a `.env` in position two is in the text the detectors scan
    // (decision.ts hands them the whole tool_input, redacted). Operations
    // without a path (a Search by pattern, a malformed entry) ride along under
    // `operations` rather than being dropped, and `batch` says whether every
    // operation was understood, for the approval card and the spool.
    const ops = input.operations.filter(
      (op): op is Record<string, unknown> => !!op && typeof op === "object" && !Array.isArray(op),
    );
    const paths = ops.map((op) => str(op.path)).filter((p): p is string => p !== undefined);
    const pathless = ops.filter((op) => str(op.path) === undefined);
    const complete = pathless.length === 0 && ops.length === input.operations.length;
    return {
      ...common,
      tool_name: "Read",
      tool_input: {
        file_path: paths[0],
        ...(paths.length > 1 ? { file_paths: paths } : {}),
        ...(pathless.length > 0 ? { operations: pathless } : {}),
        batch: { operations: input.operations.length, complete },
      },
    };
  }
  return base.normalizeInput(raw);
}

export const kiroHost: GuardHostDescriptor = { ...base, normalizeInput: normalizeKiroInput };
