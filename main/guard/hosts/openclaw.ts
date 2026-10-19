/**
 * OpenClaw host adapter for the PreToolUse guard — the first PLUGIN-artefact
 * host.
 *
 * OpenClaw has no shell-hook seam at all. Its "internal hooks" are JavaScript
 * handlers run inside the gateway process for coarse, observe-only events, and
 * the only gate before a tool runs is the typed plugin hook `before_tool_call`.
 * So this host is wired in two halves:
 *
 *  · the HOOK DOCUMENT is `openclaw.json` — we enable a plugin entry there and
 *    carry the guard command (and the per-call timeout) in that entry's
 *    `config`, so the document holds the marker every generic check reads and
 *    the plugin file itself is the same bytes on every machine;
 *  · the ARTEFACTS are a three-file plugin directory under
 *    `<state>/extensions/doorman-guard/`, whose handler spawns the guard
 *    bundle with a Claude-shaped envelope on stdin and turns the guard's
 *    `{"decision":"deny"}` into `{ block: true, blockReason }`.
 *
 * PURE, like every descriptor here: document text in / document text out,
 * artefact paths from `home`/`env`, artefact contents are constants. No fs,
 * no process, no imports outside main/guard/ (the whole directory is copied
 * into userData and run with plain `node`).
 *
 * ── The host, as verified ─────────────────────────────────────────────────
 * Read off the OpenClaw **2026.3.8 (3caab92)** installed on this Mac
 * (`dist/*.js`, 2026-09-06) — the installed version, not the docs, decides
 * what the plugin file may assume:
 *   - state dir: `OPENCLAW_STATE_DIR` (or legacy `CLAWDBOT_STATE_DIR`), else
 *     `~/.openclaw` (`resolveConfigDir`); the config file is
 *     `<state>/openclaw.json` (`OPENCLAW_CONFIG_PATH` can move it — not
 *     modelled; the doctor would show the entry as missing, never break).
 *   - plugin discovery: `plugins.load.paths`, then `<workspace>/.openclaw/
 *     extensions/*`, then `<state>/extensions/*` (`resolveConfigDir()/
 *     extensions`), then bundled. A directory needs `openclaw.plugin.json`
 *     with `id` AND `configSchema` ("plugin manifest requires configSchema"),
 *     plus an entry file from `["index.ts","index.js","index.mjs","index.cjs"]`
 *     or `package.json` → `openclaw.extensions`.
 *   - enable state (`resolveEnableState`): `plugins.deny` wins; then
 *     `entries[id].enabled === false` disables; then a NON-EMPTY
 *     `plugins.allow` that lacks the id → "not in allowlist"; then
 *     `entries[id].enabled === true` enables; a non-bundled plugin with no
 *     entry is enabled by default. We write `enabled: true` explicitly and add
 *     ourselves to a non-empty allow list.
 *   - module shape (`resolvePluginModuleExport`): the default export (or the
 *     module itself) may be a function, or an object with `register` or
 *     `activate`; `register(api)` is called synchronously and a returned
 *     promise is IGNORED ("async registration is ignored"). There is no
 *     `openclaw/plugin-sdk/plugin-entry` subpath in this version — the docs'
 *     `definePluginEntry` is an identity over that object — so the plugin
 *     imports nothing from OpenClaw.
 *   - the api (`createApi`): `id`, `pluginConfig` (= `entries[id].config`),
 *     `config`, `logger{info,warn,error,debug}`, `on(hookName, handler, opts)`
 *     for typed hooks (`registerHook` is the legacy string-event form).
 *   - `before_tool_call` (pi-embedded runner): event `{ toolName, params,
 *     runId?, toolCallId? }`, ctx `{ toolName, agentId?, sessionKey?,
 *     sessionId?, runId?, toolCallId? }`; a result `{ block: true,
 *     blockReason }` denies ("Tool call blocked by plugin hook" when no
 *     reason), `{ params }` rewrites; a THROWING handler is logged and the
 *     call proceeds — fail open, which is also our rule 1. Newer builds add
 *     `toolKind`, `toolInputKind`, `derivedPaths` to the event and
 *     `requireApproval` to the result (docs.openclaw.ai/plugins/hooks,
 *     2026.3.28+); the envelope forwards the former when present.
 *   - tool parameters (pi-coding-agent + OpenClaw's own tools): `exec{command,
 *     workdir?, pty?, background?, yieldMs?, timeout?, elevated?}`,
 *     `write{path|file_path, content}`, `edit{path|file_path, oldText|
 *     old_string, newText|new_string}`, `read{path|file_path, offset?, limit?}`,
 *     `apply_patch{input}` (the `*** Begin Patch` format), `web_fetch{url}`.
 *     BOTH spellings are real, and the hook sees the one the MODEL chose:
 *     OpenClaw's `CLAUDE_PARAM_GROUPS` accepts either and its
 *     `normalizeToolParams` folds `file_path`/`old_string`/`new_string` onto
 *     pi's names only when the tool executes — i.e. AFTER `before_tool_call`.
 *     Recorded live 2026-09-08 (`openclaw agent --local`, Claude Opus 4.6):
 *     every write/read/edit arrived as `file_path` (+ `old_string`/
 *     `new_string`); a normalizer reading only `path` lost the target of all
 *     three, which is what the live fixtures under test/fixtures/
 *     hooks/openclaw/ now pin.
 *
 * NATIVE ASK, FEATURE-DETECTED (2026-09-10). `requireApproval` in a `before_tool_call` result
 * routes the call to a human on a chat surface or the local UI and FAILS
 * CLOSED — "Unknown, malformed, mismatched, missing, and timed-out decisions
 * fail closed"; no route → "The call is blocked because no connected approval
 * surface can resolve it" (docs.openclaw.ai/plugins/plugin-permission-requests,
 * fetched 2026-09-10; sub-fields title ≤80, description ≤512, severity
 * "critical"|"warning", allowedDecisions, timeoutMs default 120 000 cap
 * 600 000, onResolution). It exists only on builds from 2026.3.28 and only
 * reaches a person when `approvals.plugin.enabled` is routed in openclaw.json.
 * The INSTALLED 2026.3.8 (re-read from its `dist/` on 2026-09-10) merges
 * exactly `params`, `block` and `blockReason` from the result — a
 * `requireApproval` returned to it is DROPPED and the call runs. So the plugin
 * decides per call whether the runtime can ask (`supportsApproval(api)`: the
 * config routes plugin approvals AND the runtime version is ≥ 2026.3.28 — from
 * `api.runtime.version` when the api carries one, else the `package.json`
 * beside the running OpenClaw entry; unknown = no) and says so on the envelope
 * as `native_ask`. The guard's `supportsNativeAskFor` reads that flag: with it
 * the question is handed to OpenClaw (`{"decision":"ask","approval":true}` →
 * `requireApproval`, allow-once or deny only — never allow-always, a grant we
 * would not see again); without it an unattended ask follows
 * `confirm.unattended` (deny by default) exactly as before. The app's own hold
 * still comes FIRST whenever it is listening; the native ask is the path for a
 * gateway agent whose person is on Slack, not at the Mac.
 *
 * SMOKE-TESTED 2026-09-06 against that install, under a throwaway
 * `OPENCLAW_STATE_DIR` holding exactly what merge() + artifacts() write:
 * `openclaw plugins list` → "Doorman Guardrails · doorman-guard · loaded ·
 * <state>/extensions/doorman-guard/index.js · 1.0.0"; `plugins info --json`
 * → `status: "loaded", hookCount: 1` (the typed before_tool_call hook — so
 * register() found its config through api.pluginConfig); `plugins doctor` →
 * "No plugin issues detected." Two WARNINGS OpenClaw prints and we accept:
 * "plugins.allow is empty; discovered non-bundled plugins may auto-load" (an
 * allow list is the user's policy over ALL plugins — we join a non-empty one,
 * never create one) and "loaded without install/load-path provenance" (keyed
 * on `plugins.installs` records, which only `openclaw plugins install` writes;
 * a `plugins.load.paths` entry for the same directory did not silence it, so
 * it is not added). The gateway itself was not started.
 *
 * LIVE-TESTED 2026-09-08, same install, end to end: the app's own installer
 * (enforcement.ts installGuard, HOME + OPENCLAW_STATE_DIR pointed at a
 * throwaway) wrote the entry and the three files; `openclaw plugins info`
 * reported `status: "loaded", hookCount: 1`; two `openclaw agent --local`
 * turns (Claude Opus 4.6 via the stored Anthropic profile) called exec, write,
 * read and edit. A block-mode custom rule on `exec` came back to the model as
 * the tool result `{"status":"error","error":"Doorman flagged this tool
 * call: …"}` (the runner throws our blockReason, pi renders it as the tool's
 * error) while the un-flagged calls ran; the guard's spool carried the
 * session id OpenClaw passed in ctx; a whole turn including the spawn took
 * under nine seconds. uninstallGuard then left openclaw.json byte-equivalent
 * to the original and removed the plugin directory, and `plugins list` no
 * longer showed it. The recorded envelopes are the write/read/edit/exec
 * fixtures under test/fixtures/hooks/openclaw/ and the session file
 * is test/fixtures/transcripts/openclaw/agents/main/sessions/
 * doorman-e2e-1.jsonl. One CLI quirk seen there: `openclaw agent
 * --session-id X` puts X in ctx.sessionId (so in our envelope) while the
 * store may keep appending to the agent's existing session file — the
 * gateway's own sessions do not do this.
 *
 * KNOWN GAP: MCP tools are reported to bypass `before_tool_call` (community
 * report, unverified); the MCP gateway root for OpenClaw is the fix, not this
 * file. In OpenClaw's Codex-harness mode Codex's own `hooks.json` is NOT read
 * and its PreToolUse is relayed to `before_tool_call` — this one plugin
 * covers that mode too.
 */

import { join } from "node:path";
import type { GuardHookInput } from "../decision.js";
import { HOOK_TIMEOUT_SLACK_SECONDS } from "../policy.js";
import { DEFAULT_REASON } from "./claude.js";
import type { GuardHostDescriptor, HostArtifact, HostDocument, HostEmit } from "./types.js";
import { readHostJson, writeHostJson, type JsoncDialect } from "../jsonc.js";

/** The plugin's id — the `plugins.entries` key, the manifest id and the
 * artefact directory name. Byte-stable: OpenClaw keys consent on it. */
export const OPENCLAW_PLUGIN_ID = "doorman-guard";

const CONFIG_FILENAME = "openclaw.json";
const INVALID_DOCUMENT = "~/.openclaw/openclaw.json";
const EVENT = "before_tool_call";

/** OpenClaw parses openclaw.json as JSON, then falls back to JSON5 (verified
 * 2026-10-19): comments and trailing commas are legal and edited in place.
 * JSON5-only syntax (unquoted keys, single quotes, hex…) is legal for OpenClaw
 * too, but the guard can't edit it without rewriting the file — so it is
 * refused by name rather than called invalid. */
const DIALECT: JsoncDialect = { trailingCommas: true, json5: true };

/** `OPENCLAW_STATE_DIR` (or the legacy `CLAWDBOT_STATE_DIR`) exactly as the
 * CLI resolves it, else `~/.openclaw`. */
export function openclawStateDir(home: string, env: NodeJS.ProcessEnv): string {
  const configured = env.OPENCLAW_STATE_DIR?.trim() || env.CLAWDBOT_STATE_DIR?.trim();
  return configured || join(home, ".openclaw");
}

/** The plugin directory OpenClaw discovers as a global extension. */
export function openclawPluginDir(home: string, env: NodeJS.ProcessEnv): string {
  return join(openclawStateDir(home, env), "extensions", OPENCLAW_PLUGIN_ID);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

const str = (value: unknown): string | undefined =>
  typeof value === "string" && value !== "" ? value : undefined;

function parseConfig(docText: string | undefined): Record<string, unknown> {
  if (!docText || docText.trim() === "") return {};
  // Never destroy a config we cannot read: refuse loudly instead.
  const parsed = readHostJson(docText, DIALECT, INVALID_DOCUMENT);
  if (!isRecord(parsed)) return {};
  return parsed;
}

/** The config, or undefined when it is blank, unreadable or not an object —
 * for uninstall and the installed check, which never refuse. */
function tryParseConfig(docText: string | undefined): Record<string, unknown> | undefined {
  if (!docText || docText.trim() === "") return undefined;
  try {
    const parsed = readHostJson(docText, DIALECT, INVALID_DOCUMENT);
    return isRecord(parsed) ? parsed : undefined;
  } catch {
    return undefined;
  }
}

/** The per-call budget in milliseconds: the hold window plus the same slack
 * policy.ts applies, so a held call is never cut off by the plugin runner. */
function timeoutMsFor(holdSeconds: number, timeoutSeconds?: number): number {
  const seconds = timeoutSeconds ?? holdSeconds + HOOK_TIMEOUT_SLACK_SECONDS;
  return Math.max(1, Math.round(seconds)) * 1000;
}

function mergeOpenclaw(
  docText: string | undefined,
  command: string,
  holdSeconds: number,
  timeoutSeconds?: number,
): string {
  const settings = parseConfig(docText);
  const before = JSON.stringify(settings);

  const plugins = isRecord(settings.plugins) ? settings.plugins : {};
  const entries = isRecord(plugins.entries) ? plugins.entries : {};
  const existing = isRecord(entries[OPENCLAW_PLUGIN_ID]) ? entries[OPENCLAW_PLUGIN_ID] : {};
  const existingConfig = isRecord(existing.config) ? existing.config : {};
  // Keep whatever else the entry carries (a `hooks` block someone added) and
  // own only the three keys the plugin reads.
  entries[OPENCLAW_PLUGIN_ID] = {
    ...existing,
    enabled: true,
    config: { ...existingConfig, command, timeoutMs: timeoutMsFor(holdSeconds, timeoutSeconds) },
  };
  plugins.entries = entries;
  // A non-empty allow list is an allowlist ("not in allowlist" otherwise);
  // empty or absent means every discovered plugin may load, so we leave it.
  if (Array.isArray(plugins.allow) && plugins.allow.length > 0 && !plugins.allow.includes(OPENCLAW_PLUGIN_ID)) {
    plugins.allow = [...plugins.allow, OPENCLAW_PLUGIN_ID];
  }
  settings.plugins = plugins;

  if (docText !== undefined && JSON.stringify(settings) === before) return docText;
  return writeHostJson(docText, settings, DIALECT, INVALID_DOCUMENT);
}

function removeOpenclaw(docText: string | undefined): string | undefined {
  // Uninstall is best-effort: a document we cannot parse has nothing of ours
  // we can safely take out of it.
  const settings = tryParseConfig(docText);
  if (!settings) return undefined;
  const plugins = settings.plugins;
  if (!isRecord(plugins)) return undefined;
  let removed = false;
  if (isRecord(plugins.entries) && OPENCLAW_PLUGIN_ID in plugins.entries) {
    delete plugins.entries[OPENCLAW_PLUGIN_ID];
    removed = true;
    if (Object.keys(plugins.entries).length === 0) delete plugins.entries;
  }
  // Take our id back out of the allow list — but only while somebody else
  // stays on it: an allow list that empties flips from "these plugins" to
  // "every plugin", which is not a change an uninstall may make.
  if (Array.isArray(plugins.allow) && plugins.allow.includes(OPENCLAW_PLUGIN_ID)) {
    const rest = plugins.allow.filter((id) => id !== OPENCLAW_PLUGIN_ID);
    if (rest.length > 0) {
      plugins.allow = rest;
      removed = true;
    }
  }
  if (!removed) return undefined;
  if (Object.keys(plugins).length === 0) delete settings.plugins;
  return writeHostJson(docText, settings, DIALECT, INVALID_DOCUMENT);
}

function installedOpenclaw(docText: string | undefined, command: string): boolean {
  const settings = tryParseConfig(docText);
  if (!settings || !isRecord(settings.plugins) || !isRecord(settings.plugins.entries)) return false;
  const entry = settings.plugins.entries[OPENCLAW_PLUGIN_ID];
  if (!isRecord(entry) || entry.enabled !== true || !isRecord(entry.config)) return false;
  return entry.config.command === command;
}

// --- input normalization ---------------------------------------------------

/** EVERY `*** Add File:` / `*** Update File:` / `*** Delete File:` / `*** Move to:` path in an
 * apply_patch input, in order — the targets when the runtime sent no
 * derivedPaths. (Was first-only before 2026-09-10; a multi-file patch's second
 * file is an effect too — review F4.) */
function patchPaths(input: string | undefined): string[] {
  if (!input) return [];
  const paths: string[] = [];
  for (const match of input.matchAll(/^\*\*\* (?:(?:Add|Update|Delete) File|Move to): (.+)$/gm)) paths.push(match[1]!.trim());
  return paths;
}

function normalizeOpenclawInput(raw: unknown): GuardHookInput | undefined {
  if (!isRecord(raw)) return undefined;
  const event = str(raw.hook_event_name);
  // Only the gate. A payload with no event name at all but a tool name is
  // still evaluated — looking at one extra call beats skipping a real one.
  if (event !== undefined && event !== EVENT) return undefined;
  const toolName = str(raw.tool_name);
  if (!toolName) return undefined;
  const input = isRecord(raw.tool_input) ? raw.tool_input : {};
  const derived = Array.isArray(raw.derived_paths) ? raw.derived_paths.map(str).filter((p): p is string => !!p) : [];
  const base = {
    session_id: str(raw.session_id),
    // `exec` carries its own working directory; the envelope's cwd (when the
    // plugin could name one) wins because it scopes every tool the same way.
    cwd: str(raw.cwd) ?? str(input.workdir),
  };

  switch (toolName) {
    // Host keys the table did not consume ride along under their own names
    // (P2, 2026-09-10): the detectors scan the whole redacted input, and a
    // smaller input was never a safer one. Aliases are folded, not kept twice.
    case "exec":
      return { ...base, tool_name: "Bash", tool_input: { ...input, command: input.command } };
    case "write": {
      const { path: _path, ...rest } = input;
      return {
        ...base,
        tool_name: "Write",
        tool_input: { ...rest, file_path: input.file_path ?? input.path, content: input.content },
      };
    }
    case "edit": {
      const { path: _path, oldText: _old, newText: _new, ...rest } = input;
      return {
        ...base,
        tool_name: "Edit",
        tool_input: {
          ...rest,
          file_path: input.file_path ?? input.path,
          old_string: input.old_string ?? input.oldText,
          new_string: input.new_string ?? input.newText,
        },
      };
    }
    case "apply_patch": {
      // A multi-file patch is a write of its whole text: the content detectors
      // scan the patch body (that is where a pasted secret would sit). The
      // path is the first file the patch names and `file_paths` is every one
      // of them (F4: the second file is an effect too) — best-effort, never
      // invented.
      const patch = str(input.input);
      const paths = derived.length > 0 ? derived : patchPaths(patch);
      const { input: _patch, ...rest } = input;
      return {
        ...base,
        tool_name: "Write",
        tool_input: {
          ...rest,
          ...(paths[0] === undefined ? {} : { file_path: paths[0] }),
          ...(paths.length > 1 ? { file_paths: paths } : {}),
          content: patch,
        },
      };
    }
    case "read": {
      const { path: _path, ...rest } = input;
      return { ...base, tool_name: "Read", tool_input: { ...rest, file_path: input.file_path ?? input.path } };
    }
    case "web_fetch": {
      const url = str(input.url);
      if (!url) return { ...base, tool_name: toolName, tool_input: input };
      return { ...base, tool_name: "WebFetch", tool_input: { ...input, url } };
    }
    default:
      // process, browser, message, web_search, image_generate, view_image,
      // memory tools, plugin tools: through with their own name and arguments,
      // so custom rules can still match and no detector is fooled by a name we
      // did not translate.
      return { ...base, tool_name: toolName, tool_input: input };
  }
}

// --- output ----------------------------------------------------------------

const NO_ASK_SUFFIX =
  "Doorman could not ask in the app; OpenClaw does not support a native ask here, " +
  "so this call is continuing.";

/** The plugin reads exactly this: `decision` plus a reason. This `ask` is the
 * one the plugin lets through (the `continue` setting) — see the header. */
function warnOpenclaw(reason: string): HostEmit {
  const message = reason && reason.trim() !== "" ? reason : DEFAULT_REASON;
  return { stdout: JSON.stringify({ decision: "ask", reason: `${message} ${NO_ASK_SUFFIX}` }), exitCode: 0 };
}

/** Only printed when the envelope said the runtime can ask (`native_ask`):
 * `approval: true` is what the plugin turns into `requireApproval`. */
function emitOpenclaw(decision: "allow" | "ask" | "deny", reason?: string): HostEmit {
  // Allow prints NOTHING (guard.ts rule 2): OpenClaw's own approval flow
  // stays exactly as it was.
  if (decision === "allow") return { exitCode: 0 };
  const message = reason ?? DEFAULT_REASON;
  if (decision === "ask") return { stdout: JSON.stringify({ decision: "ask", reason: message, approval: true }), exitCode: 0 };
  return { stdout: JSON.stringify({ decision: "deny", reason: message }), exitCode: 0 };
}

/** Whether THIS envelope's runtime can carry an ask to a person — what the
 * plugin's `supportsApproval` decided, on the wire as `native_ask`. */
function supportsNativeAskFor(raw: unknown): boolean {
  return isRecord(raw) && raw.native_ask === true;
}

// --- the plugin artefacts --------------------------------------------------

/** `openclaw.plugin.json` — `id` and `configSchema` are REQUIRED by the loader. */
export const OPENCLAW_PLUGIN_MANIFEST = `${JSON.stringify(
  {
    id: OPENCLAW_PLUGIN_ID,
    name: "Doorman Guardrails",
    version: "1.0.0",
    description:
      "Runs every tool call past the Doorman guard before it executes. Installed and kept current by the Doorman Mac app.",
    configSchema: {
      type: "object",
      additionalProperties: false,
      properties: {
        command: {
          type: "string",
          description: "The guard command line the Doorman Mac app installed.",
        },
        timeoutMs: {
          type: "number",
          description: "Per-call budget in milliseconds; exceeds the app's hold window.",
        },
      },
    },
  },
  null,
  2,
)}\n`;

/** `package.json` — ESM, and the entry named for loaders that read the
 * `openclaw.extensions` field instead of the default candidates. */
export const OPENCLAW_PLUGIN_PACKAGE = `${JSON.stringify(
  {
    name: OPENCLAW_PLUGIN_ID,
    version: "1.0.0",
    private: true,
    type: "module",
    openclaw: { extensions: ["./index.js"] },
  },
  null,
  2,
)}\n`;

/**
 * `index.js` — the plugin. Plain JavaScript, Node built-ins only, no
 * OpenClaw import (see the header), no machine path baked in: the guard
 * command comes from `api.pluginConfig` (what openclaw.json's entry carries),
 * with a direct read of openclaw.json as the fallback for a runtime that does
 * not pass plugin config.
 *
 * Rule 1 everywhere: a spawn error, a timeout, an exit code, unparseable
 * stdout — all end in `undefined`, and the call proceeds. Only an explicit
 * `{"decision":"deny"}` from the guard blocks.
 */
export const OPENCLAW_PLUGIN_SOURCE = `// Doorman Guardrails — OpenClaw plugin. Written and kept current by the
// Doorman Mac app; edits here are overwritten on the next install/sync.
// Every tool call is offered to the Doorman guard (a separate process) before
// OpenClaw runs it. The guard's only verdicts are allow (silence) and deny; a
// call the guard wanted to hold but nobody could answer is logged and continues.
import { spawn } from "node:child_process";
import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

export const PLUGIN_ID = ${JSON.stringify(OPENCLAW_PLUGIN_ID)};
const EVENT = ${JSON.stringify(EVENT)};
const DEFAULT_TIMEOUT_MS = 75000;
const MAX_STDOUT_BYTES = 65536;

function isRecord(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Past whitespace and comments from \`i\`. */
function skipTrivia(text, i) {
  for (;;) {
    while (i < text.length && /\\s/.test(text[i])) i++;
    if (text.startsWith("//", i)) {
      const end = text.indexOf("\\n", i);
      i = end === -1 ? text.length : end;
    } else if (text.startsWith("/*", i)) {
      const end = text.indexOf("*/", i + 2);
      i = end === -1 ? text.length : end + 2;
    } else {
      return i;
    }
  }
}

/** openclaw.json as OpenClaw reads it: JSON, where comments and trailing
 * commas are legal (string-aware — a "//" inside a value survives). */
export function parseConfigText(raw) {
  const text = raw.replace(/^\\uFEFF/, "");
  try {
    return JSON.parse(text);
  } catch {
    // commented — strip, then parse
  }
  let out = "";
  let i = 0;
  while (i < text.length) {
    const ch = text[i];
    if (ch === '"') {
      let j = i + 1;
      while (j < text.length && text[j] !== '"') j += text[j] === "\\\\" ? 2 : 1;
      out += text.slice(i, j + 1);
      i = j + 1;
    } else if (text.startsWith("//", i) || text.startsWith("/*", i)) {
      out += " ";
      i = skipTrivia(text, i);
    } else if (ch === "," && "}]".includes(text[skipTrivia(text, i + 1)] || "x")) {
      i++;
    } else {
      out += ch;
      i++;
    }
  }
  return JSON.parse(out);
}

/** The entry's config: api.pluginConfig first, then openclaw.json itself. */
export function readPluginConfig(api, env = process.env) {
  const own = api && isRecord(api.pluginConfig) ? api.pluginConfig : undefined;
  if (own && typeof own.command === "string" && own.command !== "") return own;
  try {
    const state = (env.OPENCLAW_STATE_DIR && env.OPENCLAW_STATE_DIR.trim()) || join(homedir(), ".openclaw");
    const parsed = parseConfigText(readFileSync(join(state, "openclaw.json"), "utf8"));
    const entry = parsed && parsed.plugins && parsed.plugins.entries && parsed.plugins.entries[PLUGIN_ID];
    const config = entry && isRecord(entry.config) ? entry.config : undefined;
    if (config && typeof config.command === "string" && config.command !== "") return config;
  } catch {
    // no config to read — register() says so and installs nothing
  }
  return undefined;
}

/** The first OpenClaw build whose \`before_tool_call\` result honours
 * \`requireApproval\` (docs.openclaw.ai/plugins/plugin-permission-requests). */
export const APPROVAL_MIN_VERSION = "2026.3.28";

/** \`YYYY.M.D\` (OpenClaw's scheme) → comparable tuple, or undefined. */
export function parseVersion(text) {
  if (typeof text !== "string") return undefined;
  const m = /^v?(\\d{4})\\.(\\d{1,2})\\.(\\d{1,3})/.exec(text.trim());
  return m ? [Number(m[1]), Number(m[2]), Number(m[3])] : undefined;
}

export function versionAtLeast(text, floor) {
  const a = parseVersion(text);
  const b = parseVersion(floor);
  if (!a || !b) return false;
  for (let i = 0; i < 3; i++) {
    if (a[i] !== b[i]) return a[i] > b[i];
  }
  return true;
}

/** The running OpenClaw's version: the api's own, else the package.json beside
 * the entry script that started this process. Undefined when unknown. */
export function runtimeVersion(api, argv = process.argv, read = readFileSync) {
  const rt = api && isRecord(api.runtime) ? api.runtime : undefined;
  if (rt && typeof rt.version === "string" && rt.version !== "") return rt.version;
  try {
    const entry = typeof argv[1] === "string" ? argv[1] : "";
    if (entry === "") return undefined;
    const pkg = JSON.parse(String(read(join(entry.replace(/\\/[^/]*$/, ""), "package.json"), "utf8")));
    return isRecord(pkg) && typeof pkg.version === "string" ? pkg.version : undefined;
  } catch {
    return undefined;
  }
}

/**
 * Whether a \`requireApproval\` we return would reach a person: the config
 * routes plugin approvals AND the runtime is new enough to honour the field
 * (2026.3.8 drops it silently — the call would run). Unknown version = no.
 */
export function supportsApproval(api, argv, read) {
  const config = api && isRecord(api.config) ? api.config : undefined;
  const approvals = config && isRecord(config.approvals) ? config.approvals : undefined;
  const plugin = approvals && isRecord(approvals.plugin) ? approvals.plugin : undefined;
  if (!plugin || plugin.enabled !== true) return false;
  return versionAtLeast(runtimeVersion(api, argv, read), APPROVAL_MIN_VERSION);
}

/** The Claude-shaped envelope the guard's OpenClaw adapter normalizes.
 * \`nativeAsk\` says whether this runtime can carry an ask to a person. */
export function envelopeFor(event, ctx, nativeAsk = false) {
  const e = isRecord(event) ? event : {};
  const c = isRecord(ctx) ? ctx : {};
  const out = {
    hook_event_name: EVENT,
    tool_name: e.toolName,
    tool_input: isRecord(e.params) ? e.params : {},
  };
  // Only ever present as \`true\`: the guard reads its absence as "cannot ask".
  if (nativeAsk === true) out.native_ask = true;
  if (e.toolKind !== undefined) out.tool_kind = e.toolKind;
  if (e.toolInputKind !== undefined) out.tool_input_kind = e.toolInputKind;
  if (Array.isArray(e.derivedPaths)) out.derived_paths = e.derivedPaths;
  const toolCallId = e.toolCallId !== undefined ? e.toolCallId : c.toolCallId;
  if (toolCallId !== undefined) out.tool_call_id = toolCallId;
  const runId = e.runId !== undefined ? e.runId : c.runId;
  if (runId !== undefined) out.run_id = runId;
  const sessionId = c.sessionId !== undefined ? c.sessionId : c.sessionKey;
  if (sessionId !== undefined) out.session_id = sessionId;
  if (c.agentId !== undefined) out.agent_id = c.agentId;
  return out;
}

/**
 * A command that starts with a bare \`node\` runs on the SAME Node binary that
 * is running OpenClaw (process.execPath). The gateway's launchd service is
 * started with a minimal, best-guess PATH (OpenClaw's buildMinimalServicePath),
 * so \`node\` resolving there is not a given — while the runtime this plugin
 * is executing in plainly exists. Anything else is spawned verbatim.
 */
export function resolveGuardCommand(command) {
  if (typeof command !== "string") return command;
  const head = /^\\s*node(?=\\s)/.exec(command);
  if (!head || typeof process.execPath !== "string" || process.execPath === "") return command;
  return JSON.stringify(process.execPath) + command.slice(head[0].length);
}

/**
 * Run the guard once. Resolves to the guard's decision object, or undefined
 * for silence (allow), a non-zero exit, a spawn error, a timeout or output
 * that is not JSON — every one of those lets the call proceed.
 */
export function runGuard(command, payload, timeoutMs) {
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
      child = spawn(resolveGuardCommand(command), { shell: true, stdio: ["pipe", "pipe", "ignore"] });
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

/** OpenClaw's approval timeout: its default, capped at its ceiling. */
const APPROVAL_TIMEOUT_MS = 120000;

/** The \`requireApproval\` for a guard ask: allow-once or deny only — an
 * allow-always would be a standing grant the guard never sees again. */
export function approvalFor(event, reason) {
  const e = isRecord(event) ? event : {};
  const tool = typeof e.toolName === "string" && e.toolName !== "" ? e.toolName : "tool call";
  return {
    title: ("Doorman: approve " + tool).slice(0, 80),
    description: String(reason).slice(0, 512),
    severity: "critical",
    allowedDecisions: ["allow-once", "deny"],
    timeoutMs: APPROVAL_TIMEOUT_MS,
  };
}

/** The before_tool_call handler for one guard command. \`nativeAsk\` is
 * supportsApproval(api), decided once at register(). */
export function createHandler(command, timeoutMs, logger, nativeAsk = false) {
  return async (event, ctx) => {
    const answer = await runGuard(command, envelopeFor(event, ctx, nativeAsk), timeoutMs);
    if (!answer) return undefined;
    const reason = typeof answer.reason === "string" && answer.reason !== "" ? answer.reason : "Doorman security policy";
    if (answer.decision === "deny") return { block: true, blockReason: reason };
    if (answer.decision === "ask") {
      // The guard prints \`approval: true\` only when we told it the runtime
      // can ask; hand the question to OpenClaw, which fails closed on a
      // timeout or a missing route. Otherwise this is the \`continue\` path.
      if (answer.approval === true && nativeAsk) return { requireApproval: approvalFor(event, reason) };
      if (logger && typeof logger.warn === "function") logger.warn("[doorman-guard] " + reason);
    }
    return undefined;
  };
}

export default {
  id: PLUGIN_ID,
  name: "Doorman Guardrails",
  description: "Runs every tool call past the Doorman guard before it executes.",
  register(api) {
    const config = readPluginConfig(api);
    const logger = api && api.logger;
    if (!config) {
      if (logger && typeof logger.warn === "function") {
        logger.warn("[doorman-guard] no guard command configured (plugins.entries." + PLUGIN_ID + ".config.command); nothing registered");
      }
      return;
    }
    const timeoutMs = typeof config.timeoutMs === "number" && config.timeoutMs > 0 ? config.timeoutMs : DEFAULT_TIMEOUT_MS;
    const nativeAsk = supportsApproval(api);
    if (logger && typeof logger.info === "function") {
      logger.info("[doorman-guard] native approvals " + (nativeAsk ? "on (approvals.plugin routed, runtime >= " + APPROVAL_MIN_VERSION + ")" : "off — the Doorman app mediates asks"));
    }
    api.on(EVENT, createHandler(config.command, timeoutMs, logger, nativeAsk), { timeoutMs });
  },
};
`;

function artifactsOpenclaw(home: string, env: NodeJS.ProcessEnv): HostArtifact[] {
  const dir = openclawPluginDir(home, env);
  return [
    { path: join(dir, "openclaw.plugin.json"), content: OPENCLAW_PLUGIN_MANIFEST },
    { path: join(dir, "package.json"), content: OPENCLAW_PLUGIN_PACKAGE },
    { path: join(dir, "index.js"), content: OPENCLAW_PLUGIN_SOURCE },
  ];
}

export const openclawHost: GuardHostDescriptor = {
  id: "openclaw",
  label: "OpenClaw",
  source: "openclaw",

  documents(home: string, env: NodeJS.ProcessEnv): HostDocument[] {
    return [{ path: join(openclawStateDir(home, env), CONFIG_FILENAME), level: "user" }];
  },

  merge: mergeOpenclaw,
  remove: removeOpenclaw,
  installed: installedOpenclaw,
  normalizeInput: normalizeOpenclawInput,
  emit: emitOpenclaw,
  warn: warnOpenclaw,

  // Static: no. Per envelope: whatever the plugin's supportsApproval decided
  // for the runtime it is running in (see the header).
  supportsNativeAsk: false,
  supportsNativeAskFor,
  // The runner logs a failed or throwing handler and proceeds; our own exit
  // code never reaches OpenClaw at all (the plugin swallows it).
  exitSemantics: "fail-open",
  // No fixedTimeoutSeconds: merge() writes `timeoutMs` into the entry itself.

  presencePaths: [".openclaw"],
  // JSON, falling back to JSON5 — see DIALECT.
  documentFormat: "json5",
  artifacts: artifactsOpenclaw,
};
