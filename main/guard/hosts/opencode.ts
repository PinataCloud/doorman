/**
 * OpenCode host adapter for the PreToolUse guard — the second PLUGIN-artefact
 * host after OpenClaw (2026-09-10).
 *
 * OpenCode has no shell-hook seam. Its extension point is a PLUGIN: a
 * JavaScript module in `~/.config/opencode/plugins/` (or a project's
 * `.opencode/plugins/`) exporting an async function that returns hooks, and
 * the one gate before a tool runs is `"tool.execute.before"`. So this host is
 * wired in two halves, exactly like OpenClaw:
 *
 *  · the HOOK DOCUMENT is our own small sidecar, `<config>/doorman-guard.json`
 *    — `{ command, timeoutMs }` — so the document holds the marker every
 *    generic check reads (installer, doctor, integrity) and the plugin file
 *    itself is the same bytes on every machine. It sits BESIDE the plugins
 *    directory, never inside it: every file in that directory is loaded as a
 *    plugin;
 *  · the ARTEFACT is `<config>/plugins/doorman-guard.js`, whose hook spawns
 *    the guard bundle with a Claude-shaped envelope on stdin and turns the
 *    guard's `{"decision":"deny"}` into a thrown Error — which is how an
 *    OpenCode plugin blocks a call.
 *
 * PURE, like every descriptor here: document text in / document text out,
 * artefact paths from `home`/`env`, artefact content a constant. No fs, no
 * process, no imports outside main/guard/.
 *
 * ── The host, as documented (2026-09-10) ───────────────────────────────────
 * Sources, all fetched 2026-09-10 — DOCS-DERIVED, no live run yet (OpenCode
 * is not installed on the development Mac; the fixtures say so):
 *   [1] https://opencode.ai/docs/plugins/  (locations, module shape, the
 *       `tool.execute.before` example that throws to block, load order)
 *   [2] https://opencode.ai/docs/config/   (`~/.config/opencode/opencode.json`,
 *       `OPENCODE_CONFIG_DIR` "for agents, commands, modes, and plugins",
 *       `~/.config/opencode/plugins/` and `.opencode/plugins/`)
 *   [3] github.com/sst/opencode `packages/plugin/src/index.ts` — the Hooks
 *       type: `"tool.execute.before"?: (input: { tool; sessionID; callID },
 *       output: { args }) => Promise<void>`; `"permission.ask"?: (input:
 *       Permission, output: { status: "ask"|"deny"|"allow" })`
 *   [4] github.com/sst/opencode `packages/opencode/src/plugin/index.ts` —
 *       `trigger()` runs each plugin's hook in sequence with NO catch around
 *       the call, so a thrown Error propagates to the tool runner (the
 *       documented way to block [1])
 *   [5] github.com/sst/opencode `packages/opencode/src/tool/*.ts` — tool ids
 *       and parameter names: `bash{command, timeout, workdir}` (shell/id.ts:
 *       `ToolID = "bash"`), `edit{filePath, oldString, newString, replaceAll}`,
 *       `write{filePath, content}`, `read{filePath, offset, limit}`,
 *       `webfetch{url, format, timeout}`, `apply_patch{patchText}` (the
 *       `*** Begin Patch` format), `task{description, prompt, subagent_type,
 *       task_id?, command?, background?}`, plus glob/grep/list/todo/skill/
 *       question/websearch/lsp; MCP tools are registered as
 *       `sanitize(server) + "_" + sanitize(tool)` (mcp/catalog.ts) — a single
 *       underscore between two sanitized halves, so the server cannot be
 *       recovered from the name and such calls pass through under it.
 *
 * WHY NOT `permission.ask`. It is a real allow/deny/ask seam, but it fires
 * only for calls OpenCode's own `permission` config routes to a prompt, so a
 * plugin relying on it covers exactly what the user already configured to
 * ask — and community reports (anomalyco/opencode#7006) say it may not fire
 * at all. `tool.execute.before` sees every tool call whatever the permission
 * config says, including under `--auto`. It can deny; it cannot ask. So
 * `supportsNativeAsk: false`: the app mediates the question through the hold
 * handshake (the plugin's timeout is the hold window plus slack), and an ask
 * nobody can answer follows `confirm.unattended` (deny by default).
 *
 * RUNTIME. OpenCode runs plugins under Bun [1]; the plugin uses only
 * `node:child_process`, `node:fs`, `node:path`, `node:os` and `node:url`,
 * which Bun implements. The guard command begins with `node` — resolved
 * through the PATH OpenCode inherited; a machine where `node` is not on PATH
 * inside OpenCode gets a spawn error, which is a silent allow (rule 1). The
 * doctor cannot see this; a live run is what closes it.
 *
 * FAILURE SEMANTICS. A hook that throws blocks ([4]); anything else the plugin
 * does — a guard spawn error, a timeout, unparseable stdout, a non-zero exit —
 * ends in `return` and the call proceeds. Our own exit code never reaches
 * OpenCode: `exitSemantics: "fail-open"`.
 */

import { join } from "node:path";
import type { GuardHookInput } from "../decision.js";
import { HOOK_TIMEOUT_SLACK_SECONDS } from "../policy.js";
import { DEFAULT_REASON } from "./claude.js";
import type { GuardHostDescriptor, HostArtifact, HostDocument, HostEmit } from "./types.js";

/** The artefact's basename (minus extension) and the sidecar's stem. */
export const OPENCODE_PLUGIN_ID = "doorman-guard";
const SIDECAR_FILENAME = `${OPENCODE_PLUGIN_ID}.json`;
const PLUGIN_FILENAME = `${OPENCODE_PLUGIN_ID}.js`;
const INVALID_DOCUMENT = `~/.config/opencode/${SIDECAR_FILENAME}`;
/** The envelope's event name — ours, so normalizeInput can tell the
 * plugin's payload from a stray Claude-shaped one. */
const EVENT = "tool.execute.before";

/** `OPENCODE_CONFIG_DIR` when set [2], else `$XDG_CONFIG_HOME/opencode`, else
 * `~/.config/opencode`. */
export function opencodeConfigDir(home: string, env: NodeJS.ProcessEnv): string {
  const configured = env.OPENCODE_CONFIG_DIR?.trim();
  if (configured) return configured;
  const xdg = env.XDG_CONFIG_HOME?.trim();
  return join(xdg || join(home, ".config"), "opencode");
}

export function opencodePluginPath(home: string, env: NodeJS.ProcessEnv): string {
  return join(opencodeConfigDir(home, env), "plugins", PLUGIN_FILENAME);
}

export function opencodeSidecarPath(home: string, env: NodeJS.ProcessEnv): string {
  return join(opencodeConfigDir(home, env), SIDECAR_FILENAME);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

const str = (value: unknown): string | undefined =>
  typeof value === "string" && value !== "" ? value : undefined;

function parseSidecar(docText: string | undefined): Record<string, unknown> {
  if (!docText || docText.trim() === "") return {};
  let parsed: unknown;
  try {
    parsed = JSON.parse(docText);
  } catch {
    throw new Error(`${INVALID_DOCUMENT} is not valid JSON; not touching it`);
  }
  return isRecord(parsed) ? parsed : {};
}

function timeoutMsFor(holdSeconds: number, timeoutSeconds?: number): number {
  const seconds = timeoutSeconds ?? holdSeconds + HOOK_TIMEOUT_SLACK_SECONDS;
  return Math.max(1, Math.round(seconds)) * 1000;
}

// --- document surgery (the sidecar) -----------------------------------------

function mergeOpencode(docText: string | undefined, command: string, holdSeconds: number, timeoutSeconds?: number): string {
  const sidecar = parseSidecar(docText);
  const before = JSON.stringify(sidecar);
  // Own exactly two keys; anything else somebody put here survives.
  sidecar.command = command;
  sidecar.timeoutMs = timeoutMsFor(holdSeconds, timeoutSeconds);
  if (docText !== undefined && JSON.stringify(sidecar) === before) return docText;
  return `${JSON.stringify(sidecar, null, 2)}\n`;
}

function removeOpencode(docText: string | undefined): string | undefined {
  if (!docText || docText.trim() === "") return undefined;
  let sidecar: Record<string, unknown>;
  try {
    const parsed: unknown = JSON.parse(docText);
    if (!isRecord(parsed)) return undefined;
    sidecar = parsed;
  } catch {
    return undefined;
  }
  if (!("command" in sidecar) && !("timeoutMs" in sidecar)) return undefined;
  delete sidecar.command;
  delete sidecar.timeoutMs;
  // Our file, our two keys: nothing else in it means nothing left to keep.
  // The installer removes the artefact alongside; an empty sidecar is inert.
  return `${JSON.stringify(sidecar, null, 2)}\n`;
}

function installedOpencode(docText: string | undefined, command: string): boolean {
  if (!docText || docText.trim() === "") return false;
  try {
    const parsed: unknown = JSON.parse(docText);
    return isRecord(parsed) && parsed.command === command;
  } catch {
    return false;
  }
}

// --- input normalization -------------------------------------------------------

/** EVERY `*** Add File:` / `*** Update File:` / `*** Delete File:` /
 * `*** Move to:` path in an apply_patch text, in order. */
function patchPaths(input: string | undefined): string[] {
  if (!input) return [];
  const paths: string[] = [];
  for (const match of input.matchAll(/^\*\*\* (?:(?:Add|Update|Delete) File|Move to): (.+)$/gm)) paths.push(match[1]!.trim());
  return paths;
}

/** `input` minus the keys a mapping consumed — aliases are folded, never kept twice. */
function without(input: Record<string, unknown>, keys: readonly string[]): Record<string, unknown> {
  const rest: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(input)) if (!keys.includes(key)) rest[key] = value;
  return rest;
}

function normalizeOpencodeInput(raw: unknown): GuardHookInput | undefined {
  if (!isRecord(raw)) return undefined;
  const event = str(raw.hook_event_name);
  // Only our envelope. A payload with no event name but a tool name is still
  // evaluated — looking at one extra call beats skipping a real one.
  if (event !== undefined && event !== EVENT) return undefined;
  const toolName = str(raw.tool_name);
  if (!toolName) return undefined;
  const input = isRecord(raw.tool_input) ? raw.tool_input : {};
  const base = {
    session_id: str(raw.session_id),
    // The plugin's `ctx.directory` (the project the session runs in); bash's
    // own `workdir` is where THIS command runs, so it wins when present.
    cwd: str(input.workdir) ?? str(raw.cwd),
  };
  // Host keys the table did not consume ride along under their own names
  // (P2): the detectors scan the whole redacted input.
  switch (toolName) {
    case "bash":
      return { ...base, tool_name: "Bash", tool_input: { ...input, command: input.command } };
    case "edit":
      return {
        ...base,
        tool_name: "Edit",
        tool_input: {
          ...without(input, ["filePath", "oldString", "newString"]),
          file_path: input.filePath,
          old_string: input.oldString,
          new_string: input.newString,
        },
      };
    case "write":
      return {
        ...base,
        tool_name: "Write",
        tool_input: { ...without(input, ["filePath"]), file_path: input.filePath, content: input.content },
      };
    case "read":
      return { ...base, tool_name: "Read", tool_input: { ...without(input, ["filePath"]), file_path: input.filePath } };
    case "webfetch": {
      const url = str(input.url);
      if (!url) return { ...base, tool_name: toolName, tool_input: input };
      return { ...base, tool_name: "WebFetch", tool_input: { ...input, url } };
    }
    case "apply_patch": {
      // A multi-file patch is a write of its whole text (the content detectors
      // scan the body); `file_path` is the first file it names and
      // `file_paths` every one of them (F4) — best-effort, never invented.
      const patch = str(input.patchText);
      const paths = patchPaths(patch);
      return {
        ...base,
        tool_name: "Write",
        tool_input: {
          ...without(input, ["patchText"]),
          ...(paths[0] === undefined ? {} : { file_path: paths[0] }),
          ...(paths.length > 1 ? { file_paths: paths } : {}),
          content: patch,
        },
      };
    }
    default:
      // glob, grep, list, task, todowrite, skill, question, websearch, lsp and
      // every MCP tool (`<server>_<tool>`, unsplittable): through under their
      // own name and arguments, so custom rules still match and no detector
      // is fooled by a name we did not translate.
      return { ...base, tool_name: toolName, tool_input: input };
  }
}

// --- output ----------------------------------------------------------------------

const NO_ASK_SUFFIX =
  "Doorman could not ask in the app; OpenCode's tool hook cannot ask on its own, so this call is continuing.";

/** The plugin reads exactly this: `decision` plus a reason. `ask` is what the
 * plugin lets through (the `continue` setting) — see the header. */
function warnOpencode(reason: string): HostEmit {
  const message = reason && reason.trim() !== "" ? reason : DEFAULT_REASON;
  return { stdout: JSON.stringify({ decision: "ask", reason: `${message} ${NO_ASK_SUFFIX}` }), exitCode: 0 };
}

function emitOpencode(decision: "allow" | "ask" | "deny", reason?: string): HostEmit {
  if (decision === "allow") return { exitCode: 0 };
  const message = reason ?? DEFAULT_REASON;
  if (decision === "ask") return warnOpencode(message);
  return { stdout: JSON.stringify({ decision: "deny", reason: message }), exitCode: 0 };
}

// --- the plugin artefact ---------------------------------------------------------

/**
 * `plugins/doorman-guard.js` — the plugin. Plain JavaScript, Node built-ins
 * only (Bun implements them), no OpenCode import, no machine path baked in:
 * the guard command comes from the sidecar next to the plugins directory,
 * located relative to this file (so `OPENCODE_CONFIG_DIR` needs no second
 * lookup), with `OPENCODE_CONFIG_DIR` / `~/.config/opencode` as fallbacks.
 *
 * Rule 1 everywhere: a spawn error, a timeout, an exit code, unparseable
 * stdout — all end in `return`, and the call proceeds. Only an explicit
 * `{"decision":"deny"}` from the guard throws, which is how a plugin blocks.
 */
export const OPENCODE_PLUGIN_SOURCE = `// Doorman Guardrails — OpenCode plugin. Written and kept current by the
// Doorman Mac app; edits here are overwritten on the next install/sync.
// Every tool call is offered to the Doorman guard (a separate process) before
// OpenCode runs it. The guard's only verdicts are allow (silence) and deny —
// a deny is thrown, which is how an OpenCode plugin blocks a call.
import { spawn } from "node:child_process";
import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const PLUGIN_ID = ${JSON.stringify(OPENCODE_PLUGIN_ID)};
const EVENT = ${JSON.stringify(EVENT)};
const SIDECAR = ${JSON.stringify(SIDECAR_FILENAME)};
const DEFAULT_TIMEOUT_MS = 75000;
const MAX_STDOUT_BYTES = 65536;

function isRecord(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Where the sidecar may be: beside this file's directory, then the
 * configured/default config dir. First readable one wins. */
function sidecarCandidates(env = process.env, selfUrl = import.meta.url) {
  const out = [];
  try {
    out.push(join(dirname(dirname(fileURLToPath(selfUrl))), SIDECAR));
  } catch {}
  const configured = env.OPENCODE_CONFIG_DIR && env.OPENCODE_CONFIG_DIR.trim();
  if (configured) out.push(join(configured, SIDECAR));
  const xdg = env.XDG_CONFIG_HOME && env.XDG_CONFIG_HOME.trim();
  out.push(join(xdg || join(homedir(), ".config"), "opencode", SIDECAR));
  return out;
}

/** The sidecar's { command, timeoutMs }, or undefined when none is readable. */
function readSidecar(env = process.env, selfUrl = import.meta.url) {
  for (const path of sidecarCandidates(env, selfUrl)) {
    try {
      const parsed = JSON.parse(readFileSync(path, "utf8"));
      if (isRecord(parsed) && typeof parsed.command === "string" && parsed.command !== "") return parsed;
    } catch {}
  }
  return undefined;
}

/** The Claude-shaped envelope the guard's OpenCode adapter normalizes. */
function envelopeFor(input, output, ctx) {
  const i = isRecord(input) ? input : {};
  const o = isRecord(output) ? output : {};
  const c = isRecord(ctx) ? ctx : {};
  const out = {
    hook_event_name: EVENT,
    tool_name: i.tool,
    tool_input: isRecord(o.args) ? o.args : {},
  };
  if (i.sessionID !== undefined) out.session_id = i.sessionID;
  if (i.callID !== undefined) out.tool_call_id = i.callID;
  if (typeof c.directory === "string" && c.directory !== "") out.cwd = c.directory;
  if (typeof c.worktree === "string" && c.worktree !== "") out.worktree = c.worktree;
  return out;
}

/**
 * Run the guard once. Resolves to the guard's decision object, or undefined
 * for silence (allow), a non-zero exit, a spawn error, a timeout or output
 * that is not JSON — every one of those lets the call proceed.
 */
function runGuard(command, payload, timeoutMs) {
  return new Promise((resolve) => {
    let child;
    let settled = false;
    const done = (value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(value);
    };
    const timer = setTimeout(() => {
      try { if (child) child.kill("SIGKILL"); } catch {}
      done(undefined);
    }, timeoutMs);
    try {
      child = spawn(command, { shell: true, stdio: ["pipe", "pipe", "ignore"] });
    } catch {
      done(undefined);
      return;
    }
    let stdout = "";
    child.stdout.on("data", (chunk) => {
      if (stdout.length < MAX_STDOUT_BYTES) stdout += String(chunk);
    });
    child.on("error", () => done(undefined));
    child.on("close", (code) => {
      if (code !== 0) { done(undefined); return; }
      const text = stdout.trim();
      if (text === "") { done(undefined); return; }
      try {
        const parsed = JSON.parse(text);
        done(isRecord(parsed) ? parsed : undefined);
      } catch {
        done(undefined);
      }
    });
    try {
      child.stdin.on("error", () => {});
      child.stdin.end(JSON.stringify(payload));
    } catch {
      done(undefined);
    }
  });
}

/** The tool.execute.before hook for one plugin context. Throws to block. */
function createHook(ctx, env = process.env, selfUrl = import.meta.url) {
  return async (input, output) => {
    const config = readSidecar(env, selfUrl);
    if (!config) return;
    const timeoutMs = typeof config.timeoutMs === "number" && config.timeoutMs > 0 ? config.timeoutMs : DEFAULT_TIMEOUT_MS;
    const answer = await runGuard(config.command, envelopeFor(input, output, ctx), timeoutMs);
    if (!answer) return;
    if (answer.decision === "deny") {
      const reason = typeof answer.reason === "string" && answer.reason !== "" ? answer.reason : "Doorman security policy";
      throw new Error(reason);
    }
    // "ask" with nobody to answer (the app's \`continue\` setting): the guard
    // has said so in its reason; the plugin has no channel to a person here,
    // so the call proceeds.
  };
}

/**
 * THE ONE EXPORT. OpenCode calls a plugin module's exported functions with the
 * plugin context and keeps the hooks they return; helpers exported beside the
 * plugin would be called as plugins too. The helpers above are therefore
 * reachable only as properties of this function (tests read them there).
 */
export const DoormanGuard = async (ctx) => ({
  [EVENT]: createHook(ctx),
});
DoormanGuard.internals = { PLUGIN_ID, EVENT, sidecarCandidates, readSidecar, envelopeFor, runGuard, createHook };
`;

function artifactsOpencode(home: string, env: NodeJS.ProcessEnv): HostArtifact[] {
  return [{ path: opencodePluginPath(home, env), content: OPENCODE_PLUGIN_SOURCE }];
}

export const opencodeHost: GuardHostDescriptor = {
  id: "opencode",
  label: "OpenCode",
  source: "opencode",

  documents(home: string, env: NodeJS.ProcessEnv): HostDocument[] {
    return [
      { path: opencodeSidecarPath(home, env), level: "user" },
      // OpenCode's own config, read for the doctor's presence/health picture
      // only — the sidecar is ours to write, this file is not.
      { path: join(opencodeConfigDir(home, env), "opencode.json"), level: "system" },
    ];
  },

  merge: mergeOpencode,
  remove: removeOpencode,
  installed: installedOpencode,
  normalizeInput: normalizeOpencodeInput,
  emit: emitOpencode,
  warn: warnOpencode,

  supportsNativeAsk: false,
  // A throwing hook blocks; everything else the plugin does proceeds, and our
  // own exit code never reaches OpenCode (the plugin swallows it).
  exitSemantics: "fail-open",
  // No fixedTimeoutSeconds: merge() writes `timeoutMs` into the sidecar itself.

  presencePaths: [".config/opencode", ".local/share/opencode"],
  documentFormat: "json",
  artifacts: artifactsOpencode,
};
