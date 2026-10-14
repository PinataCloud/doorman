/**
 * The Claude-family factory — one descriptor builder for every host that
 * speaks a DIALECT of Claude Code's PreToolUse protocol: Qwen Code, Factory Droid,
 * Crush, Goose, Kimi Code and Kiro CLI today. Each host differs from Claude
 * Code in a handful of knobs — where its document lives and what shape the
 * hook entry takes (grouped JSON, flat JSON array, TOML table array, Kiro's
 * versioned array), the event name, the timeout field's unit, its tool names
 * and argument keys, and how a verdict goes back (`hookSpecificOutput`,
 * `decision`, or the bare exit code). Everything else — the three rules in
 * hosts/types.ts, idempotent surgery, foreign-entry preservation — is the same
 * for all of them, so it lives here exactly once.
 *
 * PURE, like every descriptor: document text in / document text out, stdin
 * JSON → GuardHookInput, decision → stdout + exit code. No fs, no process, no
 * imports outside main/guard/ (the directory is copied to userData and run
 * with plain `node`).
 *
 * Per-host facts (paths, field names, exit codes) live in the host files with
 * their sources; this file holds only the mechanics they share.
 */

import type { GuardHookInput } from "../decision.js";
import { HOOK_TIMEOUT_SLACK_SECONDS, isGuardCommand } from "../policy.js";
import type {
  GuardHostDescriptor,
  HostArtifact,
  HostDecision,
  HostDocument,
  HostDocumentFormat,
  HostEmit,
  HostExitSemantics,
} from "./types.js";

/** The message an empty reason falls back to — the same words Claude Code's
 * own descriptor prints, because a person reads it in their session. */
export const FAMILY_DEFAULT_REASON = "Doorman security policy";

/** The display name we give our handler where the host's schema has one. */
export const FAMILY_HANDLER_NAME = "Doorman";

// ---------------------------------------------------------------------------
// Spec
// ---------------------------------------------------------------------------

/**
 * How the host's hook document is laid out.
 *  - `grouped`: Claude Code's own three-level shape — `hooks.<event>` is an
 *    array of `{ matcher?, hooks: [{ type: "command", command, timeout }] }`
 *    groups (Qwen Code, Factory Droid, Goose).
 *  - `flat`: `hooks.<event>` is an array of handlers `{ name?, matcher?,
 *    command, timeout }` with no group level (Crush).
 *  - `kiro`: `{ version: "v1", hooks: [{ name, trigger, matcher?, action:
 *    { type: "command", command }, timeout, enabled }] }` — one array for
 *    every trigger, the trigger named per entry (Kiro CLI 3.x).
 *  - `toml`: a `[[hooks]]` table array with `event`, `matcher?`, `command`,
 *    `timeout` (Kimi Code). Byte-preserving: we append our table and remove
 *    exactly our lines; nothing else is reformatted.
 */
export type FamilyDocumentStyle = "grouped" | "flat" | "kiro" | "toml";

/**
 * How a verdict is printed.
 *  - `hook-specific`: Claude Code's `{ hookSpecificOutput: { hookEventName,
 *    permissionDecision, permissionDecisionReason } }`, exit 0 — `ask` is a
 *    real verdict on these hosts.
 *  - `decision-deny` / `decision-block`: `{ decision: "deny"|"block", reason }`
 *    at exit 0 (Crush says `deny`, Goose says `block`).
 *  - `exit-2`: the host documents no JSON verdict; exit 2 blocks and takes its
 *    reason from STDERR (HostEmit.stderr — the spool row and the app record it
 *    too).
 */
export type FamilyDecisionStyle = "hook-specific" | "decision-deny" | "decision-block" | "exit-2";

/**
 * How "we wanted to ask, nobody could answer" is shown when the host has no
 * native ask: `system-message` prints `{ systemMessage }` (Claude Code's
 * field, honoured by Qwen Code and Droid); `silent` prints nothing and exits
 * 0 — on a host whose stdout is the decision channel, any prose is either
 * ignored or misread, and a warning nobody sees still lets the call continue
 * (rule 3).
 */
export type FamilyWarnStyle = "system-message" | "silent";

/** One host tool → the guard's vocabulary. `to` is the guard tool name;
 * `args` maps each guard argument key to the host key(s) it is read from, in
 * order of preference. Keys the host doesn't send are omitted, never invented. */
export interface FamilyToolMap {
  to: "Bash" | "Write" | "Edit" | "Read" | "WebFetch";
  args: Record<string, string | readonly string[]>;
}

export interface ClaudeFamilySpec {
  id: string;
  label: string;
  source: string;
  presencePaths: string[];
  documents(home: string, env: NodeJS.ProcessEnv): HostDocument[];
  /** The path spelled in the "not touching it" error — the user-level document. */
  invalidDocument: string;
  documentFormat?: HostDocumentFormat;
  style: FamilyDocumentStyle;
  /** The event the entry is registered under ("PreToolUse", "BeforeTool"…). */
  event: string;
  /** The event names accepted on stdin (case-exact); the payload's own event
   * field may be `hook_event_name` or `event`. Absent field → still evaluated. */
  acceptedEvents: readonly string[];
  /** Unit of the timeout field the surgery writes. */
  timeoutUnit: "seconds" | "milliseconds";
  /** The matcher written on our own entry; undefined writes none. */
  matcher?: string;
  /** Payload key carrying the working directory (`cwd` for most, Goose's
   * `working_dir`). */
  cwdField?: string;
  tools: Readonly<Record<string, FamilyToolMap>>;
  /** Rewrite an MCP tool name into `mcp__<server>__<tool>`; undefined when the
   * name is not an MCP call. Absent → names pass through untouched. */
  mcpName?(toolName: string, payload: Record<string, unknown>): string | undefined;
  decision: FamilyDecisionStyle;
  warn: FamilyWarnStyle;
  supportsNativeAsk: boolean;
  exitSemantics: HostExitSemantics;
  /** The no-native-ask suffix appended to a warning (names the host). */
  noAskSuffix?: string;
  artifacts?(home: string, env: NodeJS.ProcessEnv): HostArtifact[];
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

const str = (value: unknown): string | undefined =>
  typeof value === "string" && value !== "" ? value : undefined;

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

function isOurCommand(command: unknown): boolean {
  return isGuardCommand(command);
}

function timeoutValue(spec: ClaudeFamilySpec, holdSeconds: number, timeoutSeconds?: number): number {
  const seconds = Math.max(1, Math.round(timeoutSeconds ?? holdSeconds + HOOK_TIMEOUT_SLACK_SECONDS));
  return spec.timeoutUnit === "milliseconds" ? seconds * 1000 : seconds;
}

function parseJsonDocument(docText: string | undefined, invalidDocument: string): Record<string, unknown> {
  if (!docText || docText.trim() === "") return {};
  let parsed: unknown;
  try {
    parsed = JSON.parse(docText);
  } catch {
    // Never destroy a document we cannot read: refuse loudly instead.
    throw new Error(`${invalidDocument} is not valid JSON; not touching it`);
  }
  if (!isRecord(parsed)) return {};
  return parsed;
}

function tryParseJson(docText: string | undefined): Record<string, unknown> | undefined {
  if (!docText || docText.trim() === "") return undefined;
  try {
    const parsed: unknown = JSON.parse(docText);
    return isRecord(parsed) ? parsed : undefined;
  } catch {
    return undefined;
  }
}

/** `hooks` as an object of event arrays — an inert `hooks: []` is replaced. */
function hooksObject(settings: Record<string, unknown>): Record<string, unknown> {
  return isRecord(settings.hooks) ? settings.hooks : {};
}

// ---------------------------------------------------------------------------
// Grouped JSON (Claude Code's shape) — Qwen Code, Factory Droid, Goose
// ---------------------------------------------------------------------------

interface GroupedHandler {
  type?: string;
  command?: string;
  timeout?: number;
  name?: string;
  [key: string]: unknown;
}

interface Group {
  matcher?: string;
  hooks?: GroupedHandler[];
  [key: string]: unknown;
}

function mergeGrouped(
  spec: ClaudeFamilySpec,
  docText: string | undefined,
  command: string,
  timeout: number,
): string {
  const settings = parseJsonDocument(docText, spec.invalidDocument);
  const before = JSON.stringify(settings);
  const hooks = hooksObject(settings);
  const groups: Group[] = Array.isArray(hooks[spec.event]) ? (hooks[spec.event] as Group[]) : [];
  const desired: GroupedHandler = { type: "command", command, timeout };
  const matchesDesired = (h: GroupedHandler): boolean =>
    h.type === desired.type &&
    h.command === desired.command &&
    h.timeout === desired.timeout &&
    Object.keys(h).length === Object.keys(desired).length;

  let placed = false;
  const next: Group[] = [];
  for (const group of groups) {
    if (!isRecord(group) || !Array.isArray(group.hooks)) {
      next.push(group);
      continue;
    }
    const kept: GroupedHandler[] = [];
    let touched = false;
    for (const handler of group.hooks as GroupedHandler[]) {
      if (!isRecord(handler) || !isOurCommand(handler.command)) {
        // Somebody else's handler — not ours to touch, ever.
        kept.push(handler);
        continue;
      }
      if (placed) {
        touched = true; // a stray second copy of ours
        continue;
      }
      placed = true;
      if (matchesDesired(handler)) kept.push(handler);
      else {
        // Update IN PLACE — never remove-and-append; group order is part of
        // a document other tools wrote.
        kept.push(desired);
        touched = true;
      }
    }
    if (kept.length === 0) continue;
    if (kept.length === 1 && isOurCommand(kept[0]!.command)) {
      // Our own group: hold the canonical matcher — a narrowed matcher on a
      // security hook is a partial bypass, not a preference.
      const ours: Group = { ...group, hooks: kept };
      if (spec.matcher !== undefined) ours.matcher = spec.matcher;
      else delete ours.matcher;
      if (JSON.stringify(ours) !== JSON.stringify(group)) touched = true;
      next.push(touched ? ours : group);
    } else {
      next.push(touched ? { ...group, hooks: kept } : group);
    }
  }
  if (!placed) {
    next.push({ ...(spec.matcher === undefined ? {} : { matcher: spec.matcher }), hooks: [desired] });
  }
  hooks[spec.event] = next;
  settings.hooks = hooks;
  if (docText !== undefined && JSON.stringify(settings) === before) return docText;
  return `${JSON.stringify(settings, null, 2)}\n`;
}

function removeGrouped(spec: ClaudeFamilySpec, docText: string | undefined): string | undefined {
  const settings = tryParseJson(docText);
  if (!settings) return undefined;
  const hooks = settings.hooks;
  if (!isRecord(hooks) || !Array.isArray(hooks[spec.event])) return undefined;
  let removed = false;
  const next: Group[] = [];
  for (const group of hooks[spec.event] as Group[]) {
    if (!isRecord(group) || !Array.isArray(group.hooks)) {
      next.push(group);
      continue;
    }
    const kept = (group.hooks as GroupedHandler[]).filter((h) => !(isRecord(h) && isOurCommand(h.command)));
    if (kept.length !== group.hooks.length) removed = true;
    if (kept.length > 0) next.push(kept.length === group.hooks.length ? group : { ...group, hooks: kept });
  }
  if (!removed) return undefined;
  if (next.length > 0) hooks[spec.event] = next;
  else delete hooks[spec.event];
  if (Object.keys(hooks).length === 0) delete settings.hooks;
  return `${JSON.stringify(settings, null, 2)}\n`;
}

function installedGrouped(spec: ClaudeFamilySpec, docText: string | undefined, command: string): boolean {
  const settings = tryParseJson(docText);
  if (!settings) return false;
  const hooks = settings.hooks;
  if (!isRecord(hooks) || !Array.isArray(hooks[spec.event])) return false;
  for (const group of hooks[spec.event] as Group[]) {
    if (!isRecord(group) || !Array.isArray(group.hooks)) continue;
    for (const handler of group.hooks as GroupedHandler[]) {
      if (isRecord(handler) && handler.type === "command" && handler.command === command) return true;
    }
  }
  return false;
}

// ---------------------------------------------------------------------------
// Flat JSON array — Crush
// ---------------------------------------------------------------------------

interface FlatHandler {
  name?: string;
  matcher?: string;
  command?: string;
  timeout?: number;
  [key: string]: unknown;
}

function mergeFlat(
  spec: ClaudeFamilySpec,
  docText: string | undefined,
  command: string,
  timeout: number,
): string {
  const settings = parseJsonDocument(docText, spec.invalidDocument);
  const before = JSON.stringify(settings);
  const hooks = hooksObject(settings);
  const entries: FlatHandler[] = Array.isArray(hooks[spec.event]) ? (hooks[spec.event] as FlatHandler[]) : [];
  const desired: FlatHandler = {
    name: FAMILY_HANDLER_NAME,
    ...(spec.matcher === undefined ? {} : { matcher: spec.matcher }),
    command,
    timeout,
  };
  const matchesDesired = (h: FlatHandler): boolean => JSON.stringify(h) === JSON.stringify(desired);
  let placed = false;
  const next: FlatHandler[] = [];
  for (const entry of entries) {
    // A foreign entry of any shape (including a grouped one Crush would not
    // understand) is preserved verbatim.
    if (!isRecord(entry) || !isOurCommand(entry.command)) {
      next.push(entry);
      continue;
    }
    if (placed) continue; // a stray second copy of ours
    placed = true;
    next.push(matchesDesired(entry) ? entry : desired);
  }
  if (!placed) next.push(desired);
  hooks[spec.event] = next;
  settings.hooks = hooks;
  if (docText !== undefined && JSON.stringify(settings) === before) return docText;
  return `${JSON.stringify(settings, null, 2)}\n`;
}

function removeFlat(spec: ClaudeFamilySpec, docText: string | undefined): string | undefined {
  const settings = tryParseJson(docText);
  if (!settings) return undefined;
  const hooks = settings.hooks;
  if (!isRecord(hooks) || !Array.isArray(hooks[spec.event])) return undefined;
  const entries = hooks[spec.event] as FlatHandler[];
  const kept = entries.filter((e) => !(isRecord(e) && isOurCommand(e.command)));
  if (kept.length === entries.length) return undefined;
  if (kept.length > 0) hooks[spec.event] = kept;
  else delete hooks[spec.event];
  if (Object.keys(hooks).length === 0) delete settings.hooks;
  return `${JSON.stringify(settings, null, 2)}\n`;
}

function installedFlat(spec: ClaudeFamilySpec, docText: string | undefined, command: string): boolean {
  const settings = tryParseJson(docText);
  if (!settings) return false;
  const hooks = settings.hooks;
  if (!isRecord(hooks) || !Array.isArray(hooks[spec.event])) return false;
  return (hooks[spec.event] as FlatHandler[]).some((e) => isRecord(e) && e.command === command);
}

// ---------------------------------------------------------------------------
// Kiro's versioned array — `{ version: "v1", hooks: [ { trigger, action } ] }`
// ---------------------------------------------------------------------------

interface KiroHook {
  name?: string;
  trigger?: string;
  matcher?: string;
  action?: { type?: string; command?: string; [key: string]: unknown };
  timeout?: number;
  enabled?: boolean;
  [key: string]: unknown;
}

const KIRO_VERSION = "v1";

function kiroCommandOf(hook: unknown): unknown {
  return isRecord(hook) && isRecord(hook.action) ? hook.action.command : undefined;
}

function mergeKiro(
  spec: ClaudeFamilySpec,
  docText: string | undefined,
  command: string,
  timeout: number,
): string {
  const settings = parseJsonDocument(docText, spec.invalidDocument);
  if (settings.hooks !== undefined && !Array.isArray(settings.hooks)) {
    // Our own file, in Kiro's schema: `hooks` is an array of triggers. Any
    // other shape is not a Kiro hooks document, and we don't overwrite it.
    throw new Error(`${spec.invalidDocument} is not a Kiro hooks file (\`hooks\` is not an array); not touching it`);
  }
  const before = JSON.stringify(settings);
  const entries: KiroHook[] = Array.isArray(settings.hooks) ? (settings.hooks as KiroHook[]) : [];
  const desired: KiroHook = {
    name: FAMILY_HANDLER_NAME,
    trigger: spec.event,
    ...(spec.matcher === undefined ? {} : { matcher: spec.matcher }),
    action: { type: "command", command },
    timeout,
    enabled: true,
  };
  const matchesDesired = (h: KiroHook): boolean => JSON.stringify(h) === JSON.stringify(desired);
  let placed = false;
  const next: KiroHook[] = [];
  for (const entry of entries) {
    if (!isOurCommand(kiroCommandOf(entry))) {
      next.push(entry);
      continue;
    }
    if (placed) continue;
    placed = true;
    next.push(matchesDesired(entry) ? entry : desired);
  }
  if (!placed) next.push(desired);
  const ordered: Record<string, unknown> = { version: KIRO_VERSION, ...settings, hooks: next };
  if (typeof settings.version === "string") ordered.version = settings.version;
  if (docText !== undefined && JSON.stringify(ordered) === before) return docText;
  return `${JSON.stringify(ordered, null, 2)}\n`;
}

function removeKiro(docText: string | undefined): string | undefined {
  const settings = tryParseJson(docText);
  if (!settings || !Array.isArray(settings.hooks)) return undefined;
  const entries = settings.hooks as KiroHook[];
  const kept = entries.filter((e) => !isOurCommand(kiroCommandOf(e)));
  if (kept.length === entries.length) return undefined;
  settings.hooks = kept;
  return `${JSON.stringify(settings, null, 2)}\n`;
}

function installedKiro(docText: string | undefined, command: string): boolean {
  const settings = tryParseJson(docText);
  if (!settings || !Array.isArray(settings.hooks)) return false;
  return (settings.hooks as KiroHook[]).some(
    (e) => isRecord(e) && e.enabled !== false && kiroCommandOf(e) === command,
  );
}

// ---------------------------------------------------------------------------
// TOML `[[hooks]]` table array — Kimi Code. Byte-preserving line surgery.
// ---------------------------------------------------------------------------

const TOML_TABLE_RE = /^\s*\[\[?\s*([A-Za-z0-9_.\-"']+)\s*\]\]?\s*(#.*)?$/;
const TOML_KEY_RE = /^\s*([A-Za-z0-9_\-]+|"[^"]*"|'[^']*')\s*=\s*(.+?)\s*$/;

/**
 * A light TOML reader: enough to know where each `[[hooks]]` table starts and
 * ends, what its `command` is, and whether the document is TOML at all. A line
 * that is neither blank, a comment, a table header nor `key = value` makes the
 * document malformed — the same "refuse rather than overwrite" posture the JSON
 * hosts take with JSON.parse. Multi-line values (arrays, strings) are accepted
 * only when they close before the next table header; a bracket-balanced
 * continuation is folded into its key.
 */
interface TomlTable {
  /** Line index of the header, or -1 for the root table. */
  start: number;
  /** Exclusive end line index. */
  end: number;
  name: string;
  isArray: boolean;
  keys: Map<string, string>;
}

function readToml(docText: string, invalidDocument: string): { lines: string[]; tables: TomlTable[] } {
  const lines = docText.split("\n");
  const tables: TomlTable[] = [];
  let current: TomlTable = { start: -1, end: lines.length, name: "", isArray: false, keys: new Map() };
  let openValue: { key: string; depth: number } | undefined;
  const bad = (i: number): never => {
    throw new Error(`${invalidDocument} is not valid TOML (line ${i + 1}); not touching it`);
  };
  const bracketDepth = (text: string): number => {
    let depth = 0;
    let quote: string | undefined;
    for (let i = 0; i < text.length; i++) {
      const ch = text[i]!;
      if (quote) {
        if (ch === "\\" && quote === '"') i++;
        else if (ch === quote) quote = undefined;
        continue;
      }
      if (ch === '"' || ch === "'") quote = ch;
      else if (ch === "#") break;
      else if (ch === "[" || ch === "{") depth++;
      else if (ch === "]" || ch === "}") depth--;
    }
    return depth;
  };
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i]!;
    const line = raw.trim();
    if (openValue) {
      openValue.depth += bracketDepth(raw);
      if (openValue.depth <= 0) openValue = undefined;
      continue;
    }
    if (line === "" || line.startsWith("#")) continue;
    const header = TOML_TABLE_RE.exec(raw);
    if (header) {
      current.end = i;
      tables.push(current);
      current = {
        start: i,
        end: lines.length,
        name: header[1]!.replace(/^["']|["']$/g, ""),
        isArray: line.startsWith("[["),
        keys: new Map(),
      };
      continue;
    }
    const kv = TOML_KEY_RE.exec(raw);
    if (!kv) bad(i);
    const key = kv![1]!.replace(/^["']|["']$/g, "");
    const value = kv![2]!;
    current.keys.set(key, value);
    const depth = bracketDepth(value);
    if (depth > 0) openValue = { key, depth };
  }
  if (openValue) bad(lines.length - 1);
  current.end = lines.length;
  tables.push(current);
  return { lines, tables };
}

/** A TOML basic string's contents, or undefined when the value is not one. */
function tomlString(value: string | undefined): string | undefined {
  if (value === undefined) return undefined;
  const m = /^"((?:[^"\\]|\\.)*)"\s*(#.*)?$/.exec(value) ?? /^'([^']*)'\s*(#.*)?$/.exec(value);
  if (!m) return undefined;
  const body = m[1]!;
  if (value.startsWith("'")) return body;
  return body.replace(/\\(["\\])/g, "$1");
}

function tomlQuote(value: string): string {
  return `"${value.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
}

function ourTomlTable(spec: ClaudeFamilySpec, command: string, timeout: number): string {
  // Exactly the fields Kimi Code allows — extra keys make the whole file
  // fail to load (its docs say so), which is a bypass nobody asked for.
  const lines = ["[[hooks]]", `event = ${tomlQuote(spec.event)}`];
  if (spec.matcher !== undefined) lines.push(`matcher = ${tomlQuote(spec.matcher)}`);
  lines.push(`command = ${tomlQuote(command)}`, `timeout = ${timeout}`);
  return lines.join("\n");
}

function mergeToml(
  spec: ClaudeFamilySpec,
  docText: string | undefined,
  command: string,
  timeout: number,
): string {
  const text = docText ?? "";
  const { lines, tables } = readToml(text, spec.invalidDocument);
  const ours = tables.filter(
    (t) => t.isArray && t.name === "hooks" && isOurCommand(tomlString(t.keys.get("command"))),
  );
  const desired = ourTomlTable(spec, command, timeout);
  const desiredKeys = new Map(
    desired
      .split("\n")
      .slice(1)
      .map((l) => TOML_KEY_RE.exec(l)!)
      .map((m) => [m[1]!, m[2]!] as const),
  );
  const matchesDesired = (t: TomlTable): boolean => {
    if (t.keys.size !== desiredKeys.size) return false;
    for (const [k, v] of desiredKeys) {
      const have = t.keys.get(k);
      if (have === undefined) return false;
      if (k === "timeout" ? have.trim() !== v : tomlString(have) !== tomlString(v)) return false;
    }
    return true;
  };
  if (ours.length === 1 && matchesDesired(ours[0]!)) return text;
  // Remove every copy of ours (bottom-up so indices stay valid), then append
  // the canonical table once.
  const out = [...lines];
  for (const t of [...ours].sort((a, b) => b.start - a.start)) {
    let end = t.end;
    // Also drop the blank lines directly above the header, which are ours.
    let start = t.start;
    while (start > 0 && out[start - 1]!.trim() === "") start--;
    // Don't eat the trailing newline of the file into the removed region.
    while (end > t.start && out[end - 1]!.trim() === "") end--;
    out.splice(start, end - start);
  }
  let body = out.join("\n").replace(/\n+$/, "");
  body = body === "" ? desired : `${body}\n\n${desired}`;
  return `${body}\n`;
}

function removeToml(spec: ClaudeFamilySpec, docText: string | undefined): string | undefined {
  if (!docText || docText.trim() === "") return undefined;
  let parsed: { lines: string[]; tables: TomlTable[] };
  try {
    parsed = readToml(docText, spec.invalidDocument);
  } catch {
    return undefined; // nothing of ours we can safely take out of it
  }
  const ours = parsed.tables.filter(
    (t) => t.isArray && t.name === "hooks" && isOurCommand(tomlString(t.keys.get("command"))),
  );
  if (ours.length === 0) return undefined;
  const out = [...parsed.lines];
  for (const t of [...ours].sort((a, b) => b.start - a.start)) {
    let end = t.end;
    let start = t.start;
    while (start > 0 && out[start - 1]!.trim() === "") start--;
    while (end > t.start && out[end - 1]!.trim() === "") end--;
    out.splice(start, end - start);
  }
  const body = out.join("\n").replace(/\n+$/, "");
  return body === "" ? "" : `${body}\n`;
}

function installedToml(spec: ClaudeFamilySpec, docText: string | undefined, command: string): boolean {
  if (!docText || docText.trim() === "") return false;
  try {
    const { tables } = readToml(docText, spec.invalidDocument);
    return tables.some(
      (t) =>
        t.isArray &&
        t.name === "hooks" &&
        tomlString(t.keys.get("event")) === spec.event &&
        tomlString(t.keys.get("command")) === command,
    );
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Input normalization
// ---------------------------------------------------------------------------

/** `mcp_<server>_<tool>` → `mcp__<server>__<tool>`, split on the FIRST
 * underscore after the prefix (server names are usually one token, tool names
 * usually are not — the same call hosts/gemini.ts makes, for the same reason).
 * Shared by the hosts that join with a single underscore (Crush). */
export function mcpFirstUnderscore(toolName: string): string | undefined {
  if (!toolName.startsWith("mcp_") || toolName.startsWith("mcp__")) return undefined;
  const rest = toolName.slice("mcp_".length);
  const cut = rest.indexOf("_");
  if (cut <= 0 || cut === rest.length - 1) return undefined;
  return `mcp__${rest.slice(0, cut)}__${rest.slice(cut + 1)}`;
}

function pick(input: Record<string, unknown>, keys: string | readonly string[]): { value: unknown; key?: string } {
  for (const key of typeof keys === "string" ? [keys] : keys) {
    if (input[key] !== undefined) return { value: input[key], key };
  }
  return { value: undefined };
}

/** Every key of `input` the mapping did not consume, unchanged. Kept rather
 * than dropped (2026-09-10): the detectors scan the whole redacted tool_input, so an argument our
 * table does not know about — a wrong guess at a key name, a host-specific
 * `workdir`, a second payload field — is still looked at. A smaller input was
 * never a safer one. */
export function unmappedKeys(input: Record<string, unknown>, consumed: ReadonlySet<string>): Record<string, unknown> {
  const rest: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(input)) if (!consumed.has(key)) rest[key] = value;
  return rest;
}

function normalizeFamilyInput(spec: ClaudeFamilySpec, raw: unknown): GuardHookInput | undefined {
  if (!isRecord(raw)) return undefined;
  const event = str(raw.hook_event_name) ?? str(raw.event);
  // Only our event. A payload with no event name at all but a tool name is
  // still evaluated — the guard would rather look at one extra call than skip
  // a real one over a missing field.
  if (event !== undefined && !spec.acceptedEvents.includes(event)) return undefined;
  const toolName = str(raw.tool_name);
  if (!toolName) return undefined;
  const input = isRecord(raw.tool_input) ? raw.tool_input : {};
  const base = {
    session_id: str(raw.session_id),
    cwd: str(raw[spec.cwdField ?? "cwd"]) ?? str(raw.cwd),
  };
  const map = spec.tools[toolName];
  if (map) {
    const mapped: Record<string, unknown> = {};
    const consumed = new Set<string>();
    for (const [guardKey, hostKeys] of Object.entries(map.args)) {
      const picked = pick(input, hostKeys);
      if (picked.value !== undefined) {
        mapped[guardKey] = picked.value;
        consumed.add(picked.key!);
      }
    }
    // Guard keys first (the vocabulary the detectors and `target` read), then
    // everything the host sent that the table did not consume.
    return { ...base, tool_name: map.to, tool_input: { ...unmappedKeys(input, consumed), ...mapped } };
  }
  const mcp = spec.mcpName?.(toolName, raw);
  // Everything else passes through with its own name and arguments: custom
  // rules can still match it, and no detector is fooled by a name we did not
  // translate.
  return { ...base, tool_name: mcp ?? toolName, tool_input: input };
}

// ---------------------------------------------------------------------------
// Output
// ---------------------------------------------------------------------------

function hookSpecificOutput(spec: ClaudeFamilySpec, decision: "ask" | "deny", reason: string): string {
  return JSON.stringify({
    hookSpecificOutput: {
      hookEventName: spec.event,
      permissionDecision: decision,
      permissionDecisionReason: reason,
    },
  });
}

function warnFamily(spec: ClaudeFamilySpec, reason: string): HostEmit {
  const message = reason && reason.trim() !== "" ? reason : FAMILY_DEFAULT_REASON;
  const suffix =
    spec.noAskSuffix ??
    `Doorman could not ask in the app; ${spec.label} does not support a native ask, so this call is continuing.`;
  if (spec.warn === "system-message") {
    return { stdout: JSON.stringify({ systemMessage: `${message} ${suffix}` }), exitCode: 0 };
  }
  // Silent: on a host whose stdout is the decision channel, prose is either
  // ignored or misread, and a warning nobody sees still lets the call run.
  return { exitCode: 0 };
}

function emitFamily(spec: ClaudeFamilySpec, decision: HostDecision, reason?: string): HostEmit {
  // Allow prints NOTHING (guard.ts rule 2): our check passed, so the host's
  // own confirmation machinery must remain exactly as it was.
  if (decision === "allow") return { exitCode: 0 };
  const message = reason ?? FAMILY_DEFAULT_REASON;
  if (decision === "ask") {
    if (!spec.supportsNativeAsk) return warnFamily(spec, message);
    // Only the hook-specific dialect has a native ask verdict.
    return { stdout: hookSpecificOutput(spec, "ask", message), exitCode: 0 };
  }
  switch (spec.decision) {
    case "hook-specific":
      return { stdout: hookSpecificOutput(spec, "deny", message), exitCode: 0 };
    case "decision-deny":
      return { stdout: JSON.stringify({ decision: "deny", reason: message }), exitCode: 0 };
    case "decision-block":
      return { stdout: JSON.stringify({ decision: "block", reason: message }), exitCode: 0 };
    case "exit-2":
      // The host takes its reason from STDERR (HostEmit.stderr, guard.ts
      // prints it): the verdict is the exit code, the words ride stderr.
      return { exitCode: 2, stderr: message };
  }
}

// ---------------------------------------------------------------------------
// The factory
// ---------------------------------------------------------------------------

export function claudeFamilyHost(spec: ClaudeFamilySpec): GuardHostDescriptor {
  const merge = (docText: string | undefined, command: string, holdSeconds: number, timeoutSeconds?: number) => {
    const timeout = timeoutValue(spec, holdSeconds, timeoutSeconds);
    switch (spec.style) {
      case "grouped":
        return mergeGrouped(spec, docText, command, timeout);
      case "flat":
        return mergeFlat(spec, docText, command, timeout);
      case "kiro":
        return mergeKiro(spec, docText, command, timeout);
      case "toml":
        return mergeToml(spec, docText, command, timeout);
    }
  };
  const remove = (docText: string | undefined) => {
    switch (spec.style) {
      case "grouped":
        return removeGrouped(spec, docText);
      case "flat":
        return removeFlat(spec, docText);
      case "kiro":
        return removeKiro(docText);
      case "toml":
        return removeToml(spec, docText);
    }
  };
  const installed = (docText: string | undefined, command: string) => {
    switch (spec.style) {
      case "grouped":
        return installedGrouped(spec, docText, command);
      case "flat":
        return installedFlat(spec, docText, command);
      case "kiro":
        return installedKiro(docText, command);
      case "toml":
        return installedToml(spec, docText, command);
    }
  };
  const descriptor: GuardHostDescriptor = {
    id: spec.id,
    label: spec.label,
    source: spec.source,
    documents: spec.documents,
    merge,
    remove,
    installed,
    normalizeInput: (raw) => normalizeFamilyInput(spec, raw),
    emit: (decision, reason) => emitFamily(spec, decision, reason),
    warn: (reason) => warnFamily(spec, reason),
    supportsNativeAsk: spec.supportsNativeAsk,
    exitSemantics: spec.exitSemantics,
    presencePaths: spec.presencePaths,
  };
  if (spec.documentFormat !== undefined) descriptor.documentFormat = spec.documentFormat;
  if (spec.artifacts) descriptor.artifacts = spec.artifacts;
  return descriptor;
}
