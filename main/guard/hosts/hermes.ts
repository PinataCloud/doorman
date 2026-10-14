/**
 * Hermes Agent (Nous Research) host adapter for the PreToolUse guard — since
 * 2026-09-10 a PLUGIN host.
 *
 * PURE, like every descriptor here: document text in / document text out,
 * stdin JSON → GuardHookInput, decision → stdout + exit code, artefact paths
 * from `home`/`env` and artefact contents constants. No fs, no process, no
 * imports outside main/guard/ (the whole directory is copied into userData and
 * run with plain `node`).
 *
 * ── Why a plugin, not the shell hook (2026-09-10) ──────────────────────────
 * Hermes offers two pre-tool seams. A SHELL HOOK (config.yaml `hooks:
 * pre_tool_call`) can block or modify only: the docs and the installed source
 * agree that `approve` "escalates to the human-approval gate" for PYTHON
 * PLUGIN hooks and is unavailable to shell hooks. So the shell hook — live-
 * verified 2026-09-08 on 0.21.1 — could never ask; an unattended ask on it is
 * a deny. The plugin can: `{"action": "approve", "message", "rule_key"}` runs
 * `request_tool_approval()` (once / session / always / deny), and every ending
 * nobody grants — a denial, a timeout, a headless run with no TTY or route —
 * is BLOCKED by Hermes's own `_resolve_block_from_details` ("fail-closed: if
 * the gate itself errors, block"). A callback past `plugins.hook_callback_
 * timeout` is blocked too ("Timed-out or still-running pre_tool_call callbacks
 * fail closed"). Both seams register on the same hook manager and BOTH would
 * fire for one call, so the plugin replaces the shell hook: merge() drops a
 * legacy shell-hook entry in the same pass, and remove() takes both out.
 *
 * ONE CAVEAT, FOUND LIVE (2026-09-10): the gate prompts a person only in an
 * interactive CLI or a gateway session. A one-shot `hermes -z` run is a
 * "single_query" context and follows `approvals.single_query_mode`, whose
 * default is APPROVE — the first live turn's escalated call ran. Cron follows
 * `approvals.cron_mode`; `--yolo` approves everything. So the plugin asks
 * Hermes's own presence check (`tools.approval._presence`) per call and puts
 * `native_ask: true` on the envelope only when a person can answer; otherwise
 * the guard's unattended rule decides (deny by default) and the plugin blocks
 * with that reason. Verified live on the second turn (see slice 9).
 *
 * Sources for the plugin path, read 2026-09-10 off the Hermes `main` checkout
 * that `pip install -e` put in a throwaway venv (0.21.1 + main, 61afcde):
 *   [4] hermes_cli/plugins.py — `register_hook(name, callback)` (VALID_HOOKS
 *       includes `pre_tool_call`); `invoke_hook("pre_tool_call", tool_name=,
 *       args=, task_id=, session_id=, tool_call_id=, turn_id=, api_request_id=,
 *       middleware_trace=)`; `_get_pre_tool_call_directive_details` reads
 *       `{"action": "block", "message"}` (message REQUIRED, becomes the tool
 *       result), `{"action": "approve", "message"?, "rule_key"?}` (rule_key is
 *       the `[a]lways` allowlist grain, default the tool name) and
 *       `{"action": "modify", "args"}`; first valid directive wins;
 *       `_resolve_block_from_details` runs the gate for approve, fail-closed;
 *       `PluginContext.get_config(key)` reads `plugins.entries.<id>.settings.
 *       <key>`; `_resolve_hook_callback_timeout` reads `plugins.hook_callback_
 *       timeout` (default 30 s, the docs cap it at 600).
 *   [5] hermes_cli/plugins_discovery.py + plugins_manifest.py — user plugins
 *       live in `$HERMES_HOME/plugins/<name>/` with a `plugin.yaml` (only
 *       `name` is identity; `version`/`description`/`provides_hooks` are
 *       display) and an `__init__.py` exporting `register(ctx)`; a directory
 *       plugin loads ONLY when `plugins.enabled` lists its name ("None =
 *       opt-in default (nothing enabled)"); `plugins.disabled` wins.
 *   [1] https://hermes-agent.nousresearch.com/docs/user-guide/features/plugins
 *       and …/hooks (re-fetched 2026-09-10): `pre_llm_call` is observer-only
 *       (cannot block — so Hermes has NO prompt gate to wire), shell hooks fire
 *       for every tool including MCP, delegate_task and execute_code.
 *
 * DOCUMENT. Still `$HERMES_HOME/config.yaml` (default `~/.hermes/config.yaml`),
 * the whole agent's configuration; the surgery is LINE-BASED over YAML block
 * structure (no YAML library ships in the guard bundle) and refuses — throws,
 * "not touching it" — anything it cannot follow. What we write:
 *
 *   plugins:
 *     enabled:
 *       - doorman-guard            # the opt-in; appended to an existing list
 *     hook_callback_timeout: 75     # hold + slack; never LOWERED, capped 600
 *     entries:
 *       doorman-guard:
 *         settings:
 *           command: '<the guard command>'   # what ctx.get_config reads
 *           timeout: 75
 *
 * `hook_callback_timeout` is a global knob (every plugin's bounded hooks):
 * raising it is the one change we make outside our own keys, and remove()
 * leaves it (we cannot know what it was, and a larger budget breaks nobody).
 *
 * ARTEFACTS. `$HERMES_HOME/plugins/doorman-guard/{plugin.yaml,__init__.py}` —
 * standard-library Python, no Hermes import, no machine path: the command
 * comes from the settings above. The hook spawns the guard with the shell
 * hook's stdin shape (`hook_event_name`, `tool_name`, `tool_input`,
 * `session_id`, `cwd`, `extra{task_id, tool_call_id, turn_id, api_request_id}`)
 * plus `native_ask` and `via: "plugin"`; maps `deny`/`block` → block,
 * `ask` + `approval: true` → approve with `rule_key = doorman:<tool>:<sha256
 * of the arguments>` (so Hermes's [a]lways means "this exact call again", not
 * "this tool forever"); anything else → None, the call proceeds (rule 1).
 *
 * ACTIVATION. Plugins are discovered at process start: a Hermes already
 * running when the app installs the guard picks the plugin up on its next
 * start, not before. No first-use consent prompt applies to a directory plugin
 * that declares no capabilities (the consent gate is `capabilities:`); the
 * pre-2026-09-10 shell-hook install's `shell-hooks-allowlist.json` entry is
 * stale after upgrade and the installer strips it once
 * (withoutLegacyAllowlistEntries). `HERMES_SAFE_MODE=1` skips shell hooks;
 * whether it also skips plugin hooks is UNVERIFIED.
 *
 * TOOL NAMES [3] → the guard's vocabulary (unchanged; re-verified 2026-09-08):
 *   terminal    { command|code, background, timeout, workdir, pty, notify } → Bash
 *   write_file  { path, content }                              → Write
 *   patch       { path, old_string, new_string, replace_all }  → Edit
 *   read_file   { path, offset, limit }                        → Read
 *   web_extract { urls: string[], char_limit }                 → WebFetch
 * Host keys the table does not consume ride along (P2). MCP tools reach the
 * hook as `mcp__<server>__<tool>` (tools/mcp_tool_schema.py
 * `mcp_prefixed_tool_name`, read 2026-09-10) — already the guard's own MCP
 * vocabulary, so the per-server MCP rules key on them unchanged. Hermes's MCP
 * servers are `mcp_servers:` in config.yaml (tools/mcp_tool_config.py); the
 * app's MCP inventory reads JSON configs only and does not list them yet.
 *
 * LIVE-TESTED 2026-09-08 (shell hook, 0.21.1 — superseded) and 2026-09-10
 * (plugin — see the review's slice 9 for what ran and what it showed).
 */

import type { GuardHookInput } from "../decision.js";
import { HOOK_TIMEOUT_SLACK_SECONDS, isGuardCommand } from "../policy.js";
import type {
  GuardHostDescriptor,
  HostArtifact,
  HostDecision,
  HostDocument,
  HostEmit,
} from "./types.js";

/** The one event we evaluate. */
const EVENT = "pre_tool_call";
const DEFAULT_REASON = "Doorman security policy";
const NOT_TOUCHING = "~/.hermes/config.yaml is not a YAML document this guard can follow; not touching it";

const str = (value: unknown): string | undefined =>
  typeof value === "string" && value !== "" ? value : undefined;

/** `$HERMES_HOME`, honoured exactly as Hermes does; else `~/.hermes`. */
export function hermesHome(home: string, env: NodeJS.ProcessEnv): string {
  const configured = env.HERMES_HOME?.trim();
  return configured || `${home}/.hermes`;
}

// --- a minimal YAML scalar reader/writer ------------------------------------

/** The value text of a `key: value` line → the scalar it denotes. Single- and
 * double-quoted scalars are unquoted; a plain scalar loses a trailing
 * ` # comment`. Enough for a command string and an integer, which is all we
 * ever read. */
function yamlScalar(raw: string): string {
  const text = raw.trim();
  if (text.startsWith("'")) {
    let out = "";
    for (let i = 1; i < text.length; i++) {
      const ch = text[i]!;
      if (ch === "'") {
        if (text[i + 1] === "'") {
          out += "'";
          i++;
          continue;
        }
        return out;
      }
      out += ch;
    }
    return out; // unterminated: best effort
  }
  if (text.startsWith('"')) {
    let out = "";
    for (let i = 1; i < text.length; i++) {
      const ch = text[i]!;
      if (ch === "\\") {
        const next = text[i + 1];
        const map: Record<string, string> = { n: "\n", t: "\t", r: "\r", '"': '"', "\\": "\\", "/": "/" };
        if (next !== undefined && map[next] !== undefined) {
          out += map[next];
          i++;
          continue;
        }
        out += ch;
        continue;
      }
      if (ch === '"') return out;
      out += ch;
    }
    return out;
  }
  const hash = text.indexOf(" #");
  return (hash >= 0 ? text.slice(0, hash) : text).trim();
}

/** A single-quoted YAML scalar — the one quoting that survives a command line
 * full of double quotes and backslashes without escaping rules. */
function yamlQuote(value: string): string {
  return `'${value.replace(/'/g, "''")}'`;
}

// --- the line model ----------------------------------------------------------

const indentOf = (line: string): number => line.length - line.trimStart().length;
/** Blank lines and comments are transparent to structure (kept, never read). */
const transparent = (line: string): boolean => {
  const t = line.trim();
  return t === "" || t.startsWith("#");
};
const KEY_LINE = /^([A-Za-z0-9_.\-"']+):(?:\s+(.*))?$/;

interface Item {
  /** Line index of the `- ` line. */
  start: number;
  /** One past the last line belonging to this item (transparent lines at the
   * tail are NOT included, so an insert after it lands before them). */
  end: number;
  fields: Record<string, string>;
}

interface Layout {
  lines: string[];
  /** Index of the top-level `hooks:` line, or -1. */
  hooksAt: number;
  /** Indentation of `hooks:`'s children (defined when hooksAt ≥ 0). */
  childIndent: number;
  /** Where the `hooks:` block ends (index of the first line after it). */
  hooksEnd: number;
  /** Index of the `pre_tool_call:` child line, or -1. */
  eventAt: number;
  eventEnd: number;
  /** Indentation of the sequence items' `- `. */
  itemIndent: number;
  items: Item[];
}

/** The index of the first non-transparent line at or below `indent`, from
 * `from` — i.e. where a block whose children sit deeper than `indent` ends. */
function blockEnd(lines: string[], from: number, indent: number): number {
  for (let i = from; i < lines.length; i++) {
    const line = lines[i]!;
    if (transparent(line)) continue;
    if (indentOf(line) <= indent) return i;
  }
  return lines.length;
}

const isItemLine = (trimmed: string): boolean => trimmed.startsWith("- ") || trimmed === "-";

/** Where a sequence under a key at `keyIndent` ends: the first structural
 * line shallower than the key, or at the key's column that is not a `- `. */
function sequenceEnd(lines: string[], from: number, keyIndent: number): number {
  for (let i = from; i < lines.length; i++) {
    const line = lines[i]!;
    if (transparent(line)) continue;
    const indent = indentOf(line);
    if (indent < keyIndent) return i;
    if (indent === keyIndent && !isItemLine(line.trim())) return i;
  }
  return lines.length;
}

/** The indentation step a document uses, read off `hooks:`'s children. */
const stepOf = (layout: Layout): number => (layout.childIndent > 0 ? layout.childIndent : 2);

/** Trim trailing transparent lines off a block's end index. */
function tightEnd(lines: string[], start: number, end: number): number {
  let e = end;
  while (e > start && transparent(lines[e - 1]!)) e--;
  return e;
}

function readLayout(docText: string): Layout {
  const head = docText.trimStart();
  if (head.startsWith("{") || head.startsWith("[")) throw new Error(NOT_TOUCHING);
  const lines = docText.split("\n");
  const layout: Layout = {
    lines,
    hooksAt: -1,
    childIndent: 2,
    hooksEnd: -1,
    eventAt: -1,
    eventEnd: -1,
    itemIndent: -1,
    items: [],
  };
  // Top level: every column-0 line must be a key, a comment, a blank or a
  // document marker — anything else is a document we don't understand.
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    if (transparent(line) || line === "---" || line === "...") continue;
    if (indentOf(line) > 0) continue;
    const m = KEY_LINE.exec(line.trimEnd());
    if (!m) throw new Error(NOT_TOUCHING);
    if (m[1] === "hooks") {
      if (layout.hooksAt >= 0) throw new Error(NOT_TOUCHING); // duplicate key
      // `hooks: {}` / `hooks: []` / `hooks: ~` — not a block we can extend.
      if (m[2] !== undefined && !m[2].startsWith("#")) throw new Error(NOT_TOUCHING);
      layout.hooksAt = i;
    }
  }
  if (layout.hooksAt < 0) return layout;

  layout.hooksEnd = blockEnd(lines, layout.hooksAt + 1, 0);
  // Children indentation: the first structural line inside the block.
  let childIndent: number | undefined;
  for (let i = layout.hooksAt + 1; i < layout.hooksEnd; i++) {
    const line = lines[i]!;
    if (transparent(line)) continue;
    const indent = indentOf(line);
    const t = line.trim();
    // A `- ` at the children's own column is the previous key's sequence
    // (YAML lets a list sit flush with its parent key), not a child key.
    if (childIndent !== undefined && indent === childIndent && isItemLine(t)) continue;
    if (childIndent === undefined) childIndent = indent;
    if (indent !== childIndent) continue; // a grandchild
    const m = KEY_LINE.exec(t);
    if (!m) throw new Error(NOT_TOUCHING); // a sequence directly under hooks:
    if (m[1] === EVENT) {
      if (layout.eventAt >= 0) throw new Error(NOT_TOUCHING);
      if (m[2] !== undefined && !m[2].startsWith("#")) throw new Error(NOT_TOUCHING);
      layout.eventAt = i;
    }
  }
  layout.childIndent = childIndent ?? 2;
  if (layout.eventAt < 0) return layout;

  layout.eventEnd = sequenceEnd(lines, layout.eventAt + 1, layout.childIndent);
  // Items: `- ` lines at one shared indentation, at or deeper than the key
  // (YAML allows a sequence at the same column as its parent key).
  for (let i = layout.eventAt + 1; i < layout.eventEnd; i++) {
    const line = lines[i]!;
    if (transparent(line)) continue;
    const indent = indentOf(line);
    const t = line.trim();
    if (layout.itemIndent < 0) {
      if (!isItemLine(t)) throw new Error(NOT_TOUCHING); // a mapping, not a list
      layout.itemIndent = indent;
    }
    if (indent !== layout.itemIndent) continue; // a field line
    if (!isItemLine(t)) throw new Error(NOT_TOUCHING);
    const end = itemEnd(lines, i, layout.itemIndent, layout.eventEnd);
    layout.items.push({ start: i, end: tightEnd(lines, i + 1, end), fields: readFields(lines, i, end) });
  }
  return layout;
}

/** One past the last line of the item starting at `start`: the next `- ` at
 * the item indentation, or the sequence's end. */
function itemEnd(lines: string[], start: number, itemIndent: number, limit: number): number {
  for (let i = start + 1; i < limit; i++) {
    const line = lines[i]!;
    if (transparent(line)) continue;
    const indent = indentOf(line);
    if (indent < itemIndent) return i;
    if (indent === itemIndent && isItemLine(line.trim())) return i;
  }
  return limit;
}

/** The `key: value` pairs of one item (the `- key: value` head line included). */
function readFields(lines: string[], start: number, end: number): Record<string, string> {
  const fields: Record<string, string> = {};
  for (let i = start; i < end; i++) {
    const line = lines[i]!;
    if (transparent(line)) continue;
    let t = line.trim();
    if (i === start) t = t.replace(/^-\s*/, "");
    const m = KEY_LINE.exec(t);
    if (!m) continue; // a continuation line of a multi-line scalar — not ours
    if (m[2] === undefined) continue;
    fields[m[1]!.replace(/^["']|["']$/g, "")] = yamlScalar(m[2]);
  }
  return fields;
}

const isOurs = (item: Item): boolean => isGuardCommand(item.fields.command);

/** Hermes clamps the plugin callback budget to this (`plugins.hook_callback_timeout`, [4]). */
const HERMES_PLUGIN_TIMEOUT_MAX_SECONDS = 600;

/** The per-call budget we ask Hermes for: the installer's (hold + slack), within Hermes's cap. */
function timeoutFor(holdSeconds: number, timeoutSeconds?: number): number {
  const wanted = Math.round(timeoutSeconds ?? holdSeconds + HOOK_TIMEOUT_SLACK_SECONDS);
  return Math.min(HERMES_PLUGIN_TIMEOUT_MAX_SECONDS, Math.max(1, wanted));
}

const join = (lines: string[]): string => lines.join("\n");

// --- generic block-mapping surgery (the `plugins:` tree) ---------------------
//
// The same line model as the hooks block above, generalized to a PATH of
// mapping keys: `plugins` → `entries` → `doorman-guard` → `settings`. Every
// step refuses (throws NOT_TOUCHING) a key it finds with an inline value
// (`plugins: {}`), a sequence where a mapping should be, or a top level it
// cannot read — the fail-safe is always "leave config.yaml exactly as it was".

interface KeyHit {
  /** Line index of the `key:` line. */
  at: number;
  indent: number;
  /** Inline value text after the colon, undefined when the key opens a block. */
  value: string | undefined;
  /** One past the last line of the key's block (transparent tail excluded). */
  end: number;
}

/** Assert the document's top level is readable (keys, comments, blanks, markers). */
function assertTopLevel(lines: string[]): void {
  const first = lines.find((l) => !transparent(l));
  if (first !== undefined && (first.trimStart().startsWith("{") || first.trimStart().startsWith("["))) throw new Error(NOT_TOUCHING);
  for (const line of lines) {
    if (transparent(line) || line === "---" || line === "..." || indentOf(line) > 0) continue;
    if (!KEY_LINE.test(line.trimEnd())) throw new Error(NOT_TOUCHING);
  }
}

/** The child key `key` directly under the mapping whose block spans
 * (`from`, `end`) at children indentation `childIndent`; undefined if absent. */
function findKey(lines: string[], from: number, end: number, childIndent: number, key: string): KeyHit | undefined {
  for (let i = from; i < end; i++) {
    const line = lines[i]!;
    if (transparent(line)) continue;
    const indent = indentOf(line);
    if (indent < childIndent) return undefined;
    if (indent !== childIndent) continue;
    const t = line.trim();
    if (isItemLine(t)) continue;
    const m = KEY_LINE.exec(t);
    if (!m) throw new Error(NOT_TOUCHING);
    if (m[1]!.replace(/^["']|["']$/g, "") !== key) continue;
    const value = m[2] !== undefined && !m[2].startsWith("#") ? m[2] : undefined;
    const blockEndAt = blockEnd(lines, i + 1, indent);
    return { at: i, indent, value, end: tightEnd(lines, i + 1, blockEndAt) };
  }
  return undefined;
}

/** Children indentation inside a mapping opened at `at`, or `fallback`. */
function childIndentIn(lines: string[], at: number, end: number, fallback: number): number {
  for (let i = at + 1; i < end; i++) {
    if (!transparent(lines[i]!)) return indentOf(lines[i]!);
  }
  return fallback;
}

/** A mapping's block bounds: for the document root, everything. */
interface Scope {
  /** Line index of the opening key, or -1 for the root. */
  at: number;
  from: number;
  end: number;
  childIndent: number;
}

const rootScope = (lines: string[]): Scope => ({ at: -1, from: 0, end: lines.length, childIndent: 0 });

function scopeOf(lines: string[], hit: KeyHit): Scope {
  if (hit.value !== undefined) throw new Error(NOT_TOUCHING); // `key: {}` / `key: ~`
  const step = 2;
  return { at: hit.at, from: hit.at + 1, end: hit.end, childIndent: childIndentIn(lines, hit.at, hit.end, hit.indent + step) };
}

/** Find (or create, at the scope's child indentation) the mapping `key`
 * inside `scope`; returns the child's scope. Mutates `lines`. */
function ensureMapping(lines: string[], scope: Scope, key: string): Scope {
  const hit = findKey(lines, scope.from, scope.end, scope.childIndent, key);
  if (hit) return scopeOf(lines, hit);
  const at = scope.at < 0 ? tightEnd(lines, 0, lines.length) : scope.end;
  const line = `${" ".repeat(scope.childIndent)}${key}:`;
  lines.splice(at, 0, line);
  return { at, from: at + 1, end: at + 1, childIndent: scope.childIndent + 2 };
}

/** Set `key: value` inside `scope`, replacing an inline value or appending. */
function setScalar(lines: string[], scope: Scope, key: string, value: string): void {
  const hit = findKey(lines, scope.from, scope.end, scope.childIndent, key);
  if (hit) {
    if (hit.value === undefined && hit.end > hit.at + 1) throw new Error(NOT_TOUCHING); // a block where a scalar belongs
    lines[hit.at] = `${" ".repeat(hit.indent)}${key}: ${value}`;
    return;
  }
  lines.splice(scope.end, 0, `${" ".repeat(scope.childIndent)}${key}: ${value}`);
}

function readScalar(lines: string[], scope: Scope, key: string): string | undefined {
  const hit = findKey(lines, scope.from, scope.end, scope.childIndent, key);
  return hit?.value === undefined ? undefined : yamlScalar(hit.value);
}

/** The scalar items of the sequence `key` inside `scope`; undefined if absent.
 * Throws on an inline (`key: [a]`) or mapping-shaped value. */
function readSequence(lines: string[], scope: Scope, key: string): { hit: KeyHit; items: { at: number; value: string }[]; itemIndent: number } | undefined {
  const hit = findKey(lines, scope.from, scope.end, scope.childIndent, key);
  if (!hit) return undefined;
  if (hit.value !== undefined) {
    if (/^\[\s*\]$/.test(hit.value.trim())) return { hit, items: [], itemIndent: hit.indent + 2 }; // `key: []`
    throw new Error(NOT_TOUCHING); // a flow sequence with content
  }
  const items: { at: number; value: string }[] = [];
  let itemIndent = -1;
  for (let i = hit.at + 1; i < hit.end; i++) {
    const line = lines[i]!;
    if (transparent(line)) continue;
    const t = line.trim();
    if (!isItemLine(t)) throw new Error(NOT_TOUCHING); // a mapping, not a list
    if (itemIndent < 0) itemIndent = indentOf(line);
    if (indentOf(line) !== itemIndent) continue;
    items.push({ at: i, value: yamlScalar(t.replace(/^-\s*/, "")) });
  }
  return { hit, items, itemIndent: itemIndent < 0 ? hit.indent + 2 : itemIndent };
}

function ensureSequenceItem(lines: string[], scope: Scope, key: string, item: string): void {
  const seq = readSequence(lines, scope, key);
  if (!seq) {
    lines.splice(scope.end, 0, `${" ".repeat(scope.childIndent)}${key}:`, `${" ".repeat(scope.childIndent + 2)}- ${item}`);
    return;
  }
  if (seq.items.some((i) => i.value === item)) return;
  if (seq.hit.value !== undefined) {
    // `key: []` → open it as a block sequence.
    lines[seq.hit.at] = `${" ".repeat(seq.hit.indent)}${key}:`;
    lines.splice(seq.hit.at + 1, 0, `${" ".repeat(seq.itemIndent)}- ${item}`);
    return;
  }
  const last = seq.items[seq.items.length - 1];
  lines.splice(last ? last.at + 1 : seq.hit.at + 1, 0, `${" ".repeat(seq.itemIndent)}- ${item}`);
}

/** Remove `item` from the sequence `key`; drops the key when it empties. */
function removeSequenceItem(lines: string[], scope: Scope, key: string, item: string): boolean {
  let seq: ReturnType<typeof readSequence>;
  try {
    seq = readSequence(lines, scope, key);
  } catch {
    return false;
  }
  if (!seq) return false;
  const ours = seq.items.filter((i) => i.value === item);
  if (ours.length === 0) return false;
  for (const i of [...ours].reverse()) lines.splice(i.at, 1);
  if (ours.length === seq.items.length) lines.splice(seq.hit.at, seq.hit.end - ours.length - seq.hit.at);
  return true;
}

/** Remove the key and its whole block. */
function removeKey(lines: string[], scope: Scope, key: string): boolean {
  let hit: KeyHit | undefined;
  try {
    hit = findKey(lines, scope.from, scope.end, scope.childIndent, key);
  } catch {
    return false;
  }
  if (!hit) return false;
  lines.splice(hit.at, hit.end - hit.at);
  return true;
}

/** Whether a mapping opened at `hit` has any structural line left. */
function hasStructure(lines: string[], scope: Scope): boolean {
  const end = scope.at < 0 ? lines.length : blockEnd(lines, scope.at + 1, indentOf(lines[scope.at]!));
  for (let i = scope.from; i < end; i++) if (!transparent(lines[i]!)) return true;
  return false;
}

// --- the plugin entry in config.yaml ------------------------------------------

/** What Hermes reads: `plugins.enabled` opts the plugin in; `plugins.entries.
 * <id>.settings.*` is what `ctx.get_config()` returns; `plugins.hook_callback_
 * timeout` bounds every plugin `pre_tool_call` callback (fail-closed). */
export const HERMES_PLUGIN_ID = "doorman-guard";

/** Strip the LEGACY shell-hook entry (pre-2026-09-10 installs). Returns the
 * text unchanged when none is present; never throws on a document it cannot
 * follow (the caller's top-level check speaks for that). */
function withoutLegacyShellHook(docText: string): string {
  let layout: Layout;
  try {
    layout = readLayout(docText);
  } catch {
    return docText;
  }
  const ours = layout.items.filter(isOurs);
  if (ours.length === 0) return docText;
  const lines = [...layout.lines];
  for (const item of [...ours].reverse()) lines.splice(item.start, item.end - item.start);
  if (ours.length === layout.items.length) {
    lines.splice(layout.eventAt, 1);
    const hooksEnd = blockEnd(lines, layout.hooksAt + 1, 0);
    let structural = false;
    for (let i = layout.hooksAt + 1; i < hooksEnd; i++) if (!transparent(lines[i]!)) structural = true;
    if (!structural) lines.splice(layout.hooksAt, 1);
  }
  return join(lines);
}

function mergeHermes(
  docText: string | undefined,
  command: string,
  holdSeconds: number,
  timeoutSeconds?: number,
): string {
  const timeout = timeoutFor(holdSeconds, timeoutSeconds);
  if (docText === undefined || docText.trim() === "") {
    const fresh = [
      "plugins:",
      "  enabled:",
      `    - ${HERMES_PLUGIN_ID}`,
      `  hook_callback_timeout: ${timeout}`,
      "  entries:",
      `    ${HERMES_PLUGIN_ID}:`,
      "      settings:",
      `        command: ${yamlQuote(command)}`,
      `        timeout: ${timeout}`,
      "",
    ];
    return `${docText ?? ""}${join(fresh)}`;
  }
  // An upgrade from the shell-hook install drops that entry in the same pass:
  // both firing would evaluate every call twice, and the shell hook cannot ask.
  const base = withoutLegacyShellHook(docText);
  const lines = base.split("\n");
  assertTopLevel(lines);
  const before = join(lines);
  const root = rootScope(lines);
  // `plugins:` → `enabled:` (+ ours), `hook_callback_timeout` (never lowered),
  // `entries:` → id → `settings:` → command/timeout.
  const plugins = ensureMapping(lines, root, "plugins");
  const refreshed = (): Scope => scopeOf(lines, findKey(lines, 0, lines.length, 0, "plugins")!);
  ensureSequenceItem(lines, plugins, "enabled", HERMES_PLUGIN_ID);
  {
    const p = refreshed();
    const existing = Number(readScalar(lines, p, "hook_callback_timeout"));
    const want = Number.isFinite(existing) && existing > 0 ? Math.max(existing, timeout) : timeout;
    if (existing !== want || !Number.isFinite(existing)) setScalar(lines, p, "hook_callback_timeout", String(Math.min(HERMES_PLUGIN_TIMEOUT_MAX_SECONDS, want)));
  }
  const entries = ensureMapping(lines, refreshed(), "entries");
  const entry = ensureMapping(lines, entries, HERMES_PLUGIN_ID);
  const settings = ensureMapping(lines, entry, "settings");
  setScalar(lines, settings, "command", yamlQuote(command));
  const settingsAgain = scopeOf(lines, findKey(lines, entry.from, blockEnd(lines, entry.at + 1, indentOf(lines[entry.at]!)), entry.childIndent, "settings")!);
  setScalar(lines, settingsAgain, "timeout", String(timeout));
  const after = join(lines);
  if (after === before && base === docText) return docText;
  return after.endsWith("\n") ? after : `${after}\n`;
}

function removeHermes(docText: string | undefined): string | undefined {
  if (docText === undefined || docText.trim() === "") return undefined;
  const stripped = withoutLegacyShellHook(docText);
  const lines = stripped.split("\n");
  try {
    assertTopLevel(lines);
  } catch {
    return stripped === docText ? undefined : stripped;
  }
  let removed = stripped !== docText;
  let plugins: KeyHit | undefined;
  try {
    plugins = findKey(lines, 0, lines.length, 0, "plugins");
  } catch {
    plugins = undefined;
  }
  if (plugins && plugins.value === undefined) {
    const scope = scopeOf(lines, plugins);
    // entries.<id> — and `entries:` itself when ours was the only entry.
    let entriesHit: KeyHit | undefined;
    try {
      entriesHit = findKey(lines, scope.from, scope.end, scope.childIndent, "entries");
    } catch {
      entriesHit = undefined;
    }
    if (entriesHit && entriesHit.value === undefined) {
      const entries = scopeOf(lines, entriesHit);
      if (removeKey(lines, entries, HERMES_PLUGIN_ID)) {
        removed = true;
        const again = findKey(lines, 0, lines.length, 0, "plugins")!;
        const s = scopeOf(lines, again);
        const e = findKey(lines, s.from, s.end, s.childIndent, "entries")!;
        if (!hasStructure(lines, scopeOf(lines, e))) lines.splice(e.at, 1);
      }
    }
    const again = findKey(lines, 0, lines.length, 0, "plugins");
    if (again && again.value === undefined && removeSequenceItem(lines, scopeOf(lines, again), "enabled", HERMES_PLUGIN_ID)) removed = true;
    // `hook_callback_timeout` stays: we may have raised it, we cannot know
    // what it was, and a larger budget breaks nobody.
    const last = findKey(lines, 0, lines.length, 0, "plugins");
    if (last && last.value === undefined && !hasStructure(lines, scopeOf(lines, last))) lines.splice(last.at, 1);
  }
  if (!removed) return undefined;
  return join(lines);
}

function installedHermes(docText: string | undefined, command: string): boolean {
  if (docText === undefined || docText.trim() === "") return false;
  try {
    const lines = docText.split("\n");
    assertTopLevel(lines);
    const plugins = findKey(lines, 0, lines.length, 0, "plugins");
    if (!plugins || plugins.value !== undefined) return false;
    const scope = scopeOf(lines, plugins);
    const enabled = readSequence(lines, scope, "enabled");
    if (!enabled || !enabled.items.some((i) => i.value === HERMES_PLUGIN_ID)) return false;
    const entries = findKey(lines, scope.from, scope.end, scope.childIndent, "entries");
    if (!entries || entries.value !== undefined) return false;
    const entry = findKey(lines, entries.at + 1, entries.end, childIndentIn(lines, entries.at, entries.end, entries.indent + 2), HERMES_PLUGIN_ID);
    if (!entry || entry.value !== undefined) return false;
    const settings = findKey(lines, entry.at + 1, entry.end, childIndentIn(lines, entry.at, entry.end, entry.indent + 2), "settings");
    if (!settings || settings.value !== undefined) return false;
    return readScalar(lines, scopeOf(lines, settings), "command") === command;
  } catch {
    return false;
  }
}

/** The legacy shell-hook consent file. Kept only so an UPGRADE can take our
 * stale consent entry out; the plugin path needs no consent entry. Exposed
 * for tests and the installer's one-time cleanup. */
export function withoutLegacyAllowlistEntries(docText: string | undefined): string | undefined {
  if (docText === undefined || docText.trim() === "") return undefined;
  let parsed: unknown;
  try {
    parsed = JSON.parse(docText);
  } catch {
    return undefined;
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return undefined;
  const root = parsed as Record<string, unknown>;
  if (!Array.isArray(root.approvals)) return undefined;
  const kept = root.approvals.filter((a) => !(a && typeof a === "object" && (a as Record<string, unknown>).event === EVENT && isGuardCommand((a as Record<string, unknown>).command)));
  if (kept.length === root.approvals.length) return undefined;
  return `${JSON.stringify({ ...root, approvals: kept }, null, 2)}\n`;
}

// --- input normalization -----------------------------------------------------

function normalizeHermesInput(raw: unknown): GuardHookInput | undefined {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return undefined;
  const payload = raw as Record<string, unknown>;
  const event = str(payload.hook_event_name);
  // Only pre_tool_call. A payload with no event name but a tool name is still
  // evaluated — one extra look beats one missed call.
  if (event !== undefined && event !== EVENT) return undefined;
  const toolName = str(payload.tool_name);
  if (!toolName) return undefined;
  const input =
    payload.tool_input && typeof payload.tool_input === "object" && !Array.isArray(payload.tool_input)
      ? (payload.tool_input as Record<string, unknown>)
      : {};
  const base = {
    session_id: str(payload.session_id),
    cwd: str(payload.cwd),
  };
  switch (toolName) {
    case "terminal": {
      // `background`, `timeout`, `workdir`, `pty`, `notify` ride along (P2,
      // 2026-09-10): `workdir` is where a relative command lands, and every
      // key is text the detectors scan. `code` is the tool's legacy alias for
      // `command` (terminal_tool.py still honours it), so a model that used it
      // is not a blind spot; the alias is folded, not kept twice.
      const { code: _code, command: _command, ...rest } = input;
      return { ...base, tool_name: "Bash", tool_input: { ...rest, command: input.command ?? input.code } };
    }
    case "write_file": {
      const { path: _path, ...rest } = input;
      return { ...base, tool_name: "Write", tool_input: { ...rest, file_path: input.path, content: input.content } };
    }
    case "patch": {
      const { path: _path, ...rest } = input;
      return {
        ...base,
        tool_name: "Edit",
        tool_input: { ...rest, file_path: input.path, old_string: input.old_string, new_string: input.new_string },
      };
    }
    case "read_file": {
      const { path: _path, ...rest } = input;
      return { ...base, tool_name: "Read", tool_input: { ...rest, file_path: input.path } };
    }
    case "web_extract": {
      const urls = Array.isArray(input.urls) ? input.urls.filter((u): u is string => typeof u === "string") : [];
      const url = str(input.url) ?? urls[0];
      if (!url) return { ...base, tool_name: toolName, tool_input: input };
      return { ...base, tool_name: "WebFetch", tool_input: urls.length > 1 ? { url, urls } : { url } };
    }
    default:
      return { ...base, tool_name: toolName, tool_input: input };
  }
}

// --- output ------------------------------------------------------------------

/** What the plugin reads back from the guard: `decision` plus a reason, and
 * `approval: true` on an ask — printed only when the envelope said the runtime
 * can ask (`native_ask`, which the plugin always sets). */
function emitHermes(decision: HostDecision, reason?: string): HostEmit {
  // Allow prints NOTHING (guard.ts rule 2): Hermes's own approval machinery
  // (hardline blocks, dangerous-command prompts) stays exactly as it was.
  if (decision === "allow") return { exitCode: 0 };
  const message = reason ?? DEFAULT_REASON;
  if (decision === "ask") return { stdout: JSON.stringify({ decision: "ask", reason: message, approval: true }), exitCode: 0 };
  // Exit 0 + Claude Code's own block shape, which both the plugin and a legacy
  // shell hook read — the reason travels in the field Hermes reads first.
  return { stdout: JSON.stringify({ decision: "block", reason: message }), exitCode: 0 };
}

/** Per envelope: the plugin stamps `native_ask: true`; a legacy shell-hook
 * payload has no such flag and cannot ask. */
function supportsNativeAskFor(raw: unknown): boolean {
  return !!raw && typeof raw === "object" && !Array.isArray(raw) && (raw as Record<string, unknown>).native_ask === true;
}

// --- the plugin artefacts -----------------------------------------------------

export function hermesPluginDir(home: string, env: NodeJS.ProcessEnv): string {
  return `${hermesHome(home, env)}/plugins/${HERMES_PLUGIN_ID}`;
}

/** `plugin.yaml` — `name` is the key `plugins.enabled` matches ([5]: only
 * `name` is read as identity; the rest is display). */
export const HERMES_PLUGIN_MANIFEST = [
  `name: ${HERMES_PLUGIN_ID}`,
  'version: "1.0"',
  "description: Runs every tool call past the Doorman guard before it executes. Installed and kept current by the Doorman Mac app.",
  "provides_hooks:",
  "  - pre_tool_call",
  "",
].join("\n");

/**
 * `__init__.py` — the plugin. Standard library only, no Hermes import, no
 * machine path baked in: the guard command comes from `ctx.get_config()`,
 * i.e. `plugins.entries.doorman-guard.settings.command` in config.yaml.
 *
 * Rule 1 everywhere it is ours to decide: a spawn error, unparseable stdout, a
 * non-zero exit — all `return None`, and the call proceeds. Two endings are
 * Hermes's, not ours, and both FAIL CLOSED by its design: a callback past
 * `plugins.hook_callback_timeout` is blocked, and an `approve` nobody grants
 * (denied, timed out, or no TTY/route) is blocked with Hermes's own message.
 */
export const HERMES_PLUGIN_SOURCE = `"""Doorman Guardrails — Hermes Agent plugin.

Written and kept current by the Doorman Mac app; edits here are overwritten on
the next install/sync. Every tool call is offered to the Doorman guard (a
separate process) before Hermes runs it. The guard answers allow (silence),
deny (blocked, the reason becomes the tool result) or ask — which this plugin
escalates to Hermes's own approval gate (once / session / always / deny; a
headless run denies).
"""

import hashlib
import json
import os
import shlex
import subprocess

PLUGIN_ID = ${JSON.stringify(HERMES_PLUGIN_ID)}
EVENT = ${JSON.stringify(EVENT)}
DEFAULT_TIMEOUT_SECONDS = 75
MAX_STDOUT_BYTES = 65536
_DEFAULT_REASON = "Doorman security policy"


def can_ask():
    """Whether an 'approve' directive would reach a PERSON right now.

    Hermes's gate (tools/approval.py '_run_approval_gate') prompts a human
    only in an interactive CLI or a gateway session. Every other context
    resolves on its own: a one-shot '-z' run follows 'approvals.
    single_query_mode' (default approve — verified live 2026-09-10: the
    escalated call RAN), cron follows 'approvals.cron_mode', and '--yolo'
    approves everything. Claiming a native ask there would hand the guard's
    question to an auto-approver, so this asks Hermes's own presence check
    and answers False whenever that check is unavailable or says nobody is
    there — the guard then applies its unattended rule (deny by default).
    """
    try:
        from tools.approval import _presence  # Hermes internal; guarded on purpose

        _callback, is_cli, is_gateway, _is_ask = _presence()
        return bool(is_cli or is_gateway)
    except Exception:
        return False


def envelope_for(tool_name, args, kwargs, cwd=None, native_ask=None):
    """The Claude-shaped payload the guard's Hermes adapter normalizes — the
    shell hook's shape, plus native_ask (whether this plugin can escalate to a
    human right now) and via (which seam delivered it)."""
    extra = {}
    for key in ("task_id", "tool_call_id", "turn_id", "api_request_id"):
        value = kwargs.get(key)
        if value:
            extra[key] = value
    payload = {
        "hook_event_name": EVENT,
        "tool_name": tool_name,
        "tool_input": args if isinstance(args, dict) else {},
        "session_id": kwargs.get("session_id") or None,
        "cwd": cwd if cwd is not None else os.getcwd(),
        "extra": extra,
        "native_ask": bool(can_ask() if native_ask is None else native_ask),
        "via": "plugin",
    }
    return payload


def run_guard(command, payload, timeout_seconds):
    """Run the guard once. Returns its decision dict, or None for silence
    (allow), a non-zero exit, a spawn error, a timeout or output that is not
    JSON — every one of those lets the call proceed."""
    try:
        argv = shlex.split(os.path.expanduser(command))
    except Exception:
        return None
    if not argv:
        return None
    try:
        proc = subprocess.run(
            argv,
            input=json.dumps(payload).encode("utf-8"),
            capture_output=True,
            timeout=timeout_seconds,
            check=False,
        )
    except Exception:
        return None
    if proc.returncode != 0:
        return None
    text = proc.stdout[:MAX_STDOUT_BYTES].decode("utf-8", "replace").strip()
    if not text:
        return None
    try:
        answer = json.loads(text)
    except Exception:
        return None
    return answer if isinstance(answer, dict) else None


def rule_key_for(tool_name, args):
    """The grain of Hermes's [a]lways answer: this tool with exactly these
    arguments — never the whole tool, which the default would grant."""
    try:
        digest = hashlib.sha256(json.dumps(args, sort_keys=True, default=str).encode("utf-8")).hexdigest()[:16]
    except Exception:
        digest = "unhashable"
    return "doorman:%s:%s" % (tool_name, digest)


def directive_for(answer, tool_name, args):
    """Map the guard's answer onto Hermes's pre_tool_call directive."""
    if not isinstance(answer, dict):
        return None
    decision = answer.get("decision") or answer.get("action")
    reason = answer.get("reason") or answer.get("message") or _DEFAULT_REASON
    if not isinstance(reason, str) or not reason:
        reason = _DEFAULT_REASON
    if decision in ("deny", "block"):
        return {"action": "block", "message": reason}
    if decision == "ask" and answer.get("approval") is True:
        return {"action": "approve", "message": reason, "rule_key": rule_key_for(tool_name, args)}
    return None


def make_hook(command, timeout_seconds):
    def on_pre_tool_call(tool_name, args=None, **kwargs):
        answer = run_guard(command, envelope_for(tool_name, args, kwargs), timeout_seconds)
        return directive_for(answer, tool_name, args if isinstance(args, dict) else {})

    return on_pre_tool_call


def register(ctx):
    command = ctx.get_config("command")
    if not isinstance(command, str) or not command:
        return
    timeout = ctx.get_config("timeout", DEFAULT_TIMEOUT_SECONDS)
    try:
        timeout_seconds = float(timeout)
    except Exception:
        timeout_seconds = float(DEFAULT_TIMEOUT_SECONDS)
    if timeout_seconds <= 0:
        timeout_seconds = float(DEFAULT_TIMEOUT_SECONDS)
    ctx.register_hook(EVENT, make_hook(command, timeout_seconds))
`;

function artifactsHermes(home: string, env: NodeJS.ProcessEnv): HostArtifact[] {
  const dir = hermesPluginDir(home, env);
  return [
    { path: `${dir}/plugin.yaml`, content: HERMES_PLUGIN_MANIFEST },
    { path: `${dir}/__init__.py`, content: HERMES_PLUGIN_SOURCE },
  ];
}

export const hermesHost: GuardHostDescriptor = {
  id: "hermes",
  label: "Hermes Agent",
  source: "hermes",

  documents(home: string, env: NodeJS.ProcessEnv): HostDocument[] {
    return [{ path: `${hermesHome(home, env)}/config.yaml`, level: "user" }];
  },

  merge: mergeHermes,
  remove: removeHermes,
  installed: installedHermes,
  normalizeInput: normalizeHermesInput,
  emit: emitHermes,

  /** The `continue` path: no user-visible channel from the hook, so silence —
   * the plugin sees nothing and the call runs; the app's notification is the
   * surface. */
  warn(): HostEmit {
    return { exitCode: 0 };
  },

  // Static: no (a legacy shell-hook payload cannot ask). Per envelope: yes
  // when the plugin built it AND Hermes's presence check says a person can
  // answer (interactive CLI or gateway) — its `approve` then runs Hermes's
  // own gate; a one-shot or cron run says no and gets our unattended rule.
  supportsNativeAsk: false,
  supportsNativeAskFor,
  // Hermes's plugin runner drops a callback's return on error and proceeds;
  // its own fail-closed endings (timeout, ungranted approve) are Hermes's
  // verdicts, not an exit code of ours.
  exitSemantics: "fail-open",
  // No fixedTimeoutSeconds: merge() writes `plugins.hook_callback_timeout`
  // (seconds, ≤ 600) and the entry's own `timeout` itself.
  presencePaths: [".hermes"],
  documentFormat: "yaml",
  artifacts: artifactsHermes,
};
