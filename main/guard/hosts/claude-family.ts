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
import { readHostJson, writeHostJson, type JsoncDialect } from "../jsonc.js";

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
 *    exactly our lines (plus an inert root `hooks = []`, which would collide
 *    with the table array); nothing else is reformatted.
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
  /** For a JSON style: what the host's own parser accepts beyond strict JSON
   * (comments; maybe trailing commas). Set → the descriptor's documentFormat
   * is `jsonc` (`json5` when the dialect says so), the document is read in
   * that dialect, and a commented one is edited in place so its comments
   * survive. Absent → strict JSON, exactly as before. */
  jsonDialect?: JsoncDialect;
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

function parseJsonDocument(spec: ClaudeFamilySpec, docText: string | undefined): Record<string, unknown> {
  if (!docText || docText.trim() === "") return {};
  // Never destroy a document we cannot read: refuse loudly instead.
  const parsed = readHostJson(docText, spec.jsonDialect, spec.invalidDocument);
  if (!isRecord(parsed)) return {};
  return parsed;
}

function tryParseJson(spec: ClaudeFamilySpec, docText: string | undefined): Record<string, unknown> | undefined {
  if (!docText || docText.trim() === "") return undefined;
  try {
    const parsed = readHostJson(docText, spec.jsonDialect, spec.invalidDocument);
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
  const settings = parseJsonDocument(spec, docText);
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
  return writeHostJson(docText, settings, spec.jsonDialect, spec.invalidDocument);
}

function removeGrouped(spec: ClaudeFamilySpec, docText: string | undefined): string | undefined {
  const settings = tryParseJson(spec, docText);
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
  return writeHostJson(docText, settings, spec.jsonDialect, spec.invalidDocument);
}

function installedGrouped(spec: ClaudeFamilySpec, docText: string | undefined, command: string): boolean {
  const settings = tryParseJson(spec, docText);
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
  const settings = parseJsonDocument(spec, docText);
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
  return writeHostJson(docText, settings, spec.jsonDialect, spec.invalidDocument);
}

function removeFlat(spec: ClaudeFamilySpec, docText: string | undefined): string | undefined {
  const settings = tryParseJson(spec, docText);
  if (!settings) return undefined;
  const hooks = settings.hooks;
  if (!isRecord(hooks) || !Array.isArray(hooks[spec.event])) return undefined;
  const entries = hooks[spec.event] as FlatHandler[];
  const kept = entries.filter((e) => !(isRecord(e) && isOurCommand(e.command)));
  if (kept.length === entries.length) return undefined;
  if (kept.length > 0) hooks[spec.event] = kept;
  else delete hooks[spec.event];
  if (Object.keys(hooks).length === 0) delete settings.hooks;
  return writeHostJson(docText, settings, spec.jsonDialect, spec.invalidDocument);
}

function installedFlat(spec: ClaudeFamilySpec, docText: string | undefined, command: string): boolean {
  const settings = tryParseJson(spec, docText);
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
  const settings = parseJsonDocument(spec, docText);
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
  return writeHostJson(docText, ordered, spec.jsonDialect, spec.invalidDocument);
}

function removeKiro(spec: ClaudeFamilySpec, docText: string | undefined): string | undefined {
  const settings = tryParseJson(spec, docText);
  if (!settings || !Array.isArray(settings.hooks)) return undefined;
  const entries = settings.hooks as KiroHook[];
  const kept = entries.filter((e) => !isOurCommand(kiroCommandOf(e)));
  if (kept.length === entries.length) return undefined;
  settings.hooks = kept;
  return writeHostJson(docText, settings, spec.jsonDialect, spec.invalidDocument);
}

function installedKiro(spec: ClaudeFamilySpec, docText: string | undefined, command: string): boolean {
  const settings = tryParseJson(spec, docText);
  if (!settings || !Array.isArray(settings.hooks)) return false;
  return (settings.hooks as KiroHook[]).some(
    (e) => isRecord(e) && e.enabled !== false && kiroCommandOf(e) === command,
  );
}

// ---------------------------------------------------------------------------
// TOML `[[hooks]]` table array — Kimi Code. Byte-preserving line surgery.
// ---------------------------------------------------------------------------

/** One key-path segment: bare, basic-quoted or literal-quoted (TOML 1.0). */
const TOML_SEGMENT = String.raw`(?:[A-Za-z0-9_-]+|"(?:[^"\\]|\\.)*"|'[^']*')`;
/** A dotted key path — `a`, `"kimi-code/k3".display_name`, `providers . "x:y"`. */
const TOML_PATH = String.raw`${TOML_SEGMENT}(?:\s*\.\s*${TOML_SEGMENT})*`;
const TOML_SEGMENT_RE = new RegExp(TOML_SEGMENT, "g");
const TOML_TABLE_RE = new RegExp(String.raw`^\s*\[\s*(${TOML_PATH})\s*\]\s*(?:#.*)?$`);
const TOML_ARRAY_TABLE_RE = new RegExp(String.raw`^\s*\[\[\s*(${TOML_PATH})\s*\]\]\s*(?:#.*)?$`);
const TOML_KEY_RE = new RegExp(String.raw`^\s*(${TOML_PATH})\s*=\s*(\S.*?)\s*$`);

const TOML_ESCAPES: Record<string, string> = { b: "\b", t: "\t", n: "\n", f: "\f", r: "\r", '"': '"', "\\": "\\" };

/** A basic string's body with its escapes resolved (unknown escapes kept as written). */
function tomlUnescape(body: string): string {
  return body.replace(/\\(?:u([0-9A-Fa-f]{4})|U([0-9A-Fa-f]{8})|(.))/g, (all, u4?: string, u8?: string, ch?: string) => {
    const hex = u4 ?? u8;
    if (hex !== undefined) {
      const cp = parseInt(hex, 16);
      return cp <= 0x10ffff ? String.fromCodePoint(cp) : all;
    }
    return TOML_ESCAPES[ch!] ?? all;
  });
}

/** A matched key path's segments, unquoted: `[["hooks"]]` and `[[ hooks ]]` both name `hooks`. */
function tomlKeyPath(text: string): string[] {
  return [...text.matchAll(TOML_SEGMENT_RE)].map(([seg]) =>
    seg.startsWith('"') ? tomlUnescape(seg.slice(1, -1)) : seg.startsWith("'") ? seg.slice(1, -1) : seg,
  );
}

/** Where a value scan stands at the end of a line: bracket depth and an open multi-line string. */
interface TomlValueScan {
  depth: number;
  multiline?: '"""' | "'''";
}

/**
 * Advance `scan` over one line of a value. Strings are skipped (a `#`, `[` or
 * `]` inside one is content), a comment ends the line. False when a one-line
 * string never closes — that is not TOML.
 */
function scanTomlValue(text: string, scan: TomlValueScan): boolean {
  for (let i = 0; i < text.length; i++) {
    const ch = text[i]!;
    if (scan.multiline) {
      if (scan.multiline === '"""' && ch === "\\") i++;
      else if (ch === scan.multiline[0]) {
        let run = 1;
        while (text[i + run] === ch) run++;
        // Up to two quotes right before the delimiter are content: `""""` closes.
        if (run >= 3) scan.multiline = undefined;
        i += run - 1;
      }
      continue;
    }
    if (ch === '"' || ch === "'") {
      if (text.startsWith(ch.repeat(3), i)) {
        scan.multiline = ch === '"' ? '"""' : "'''";
        i += 2;
        continue;
      }
      let j = i + 1;
      while (j < text.length && text[j] !== ch) j += ch === '"' && text[j] === "\\" ? 2 : 1;
      if (j >= text.length) return false;
      i = j;
      continue;
    }
    if (ch === "#") break;
    if (ch === "[" || ch === "{") scan.depth++;
    else if (ch === "]" || ch === "}") scan.depth--;
  }
  return true;
}

/** One `[[hooks]]` element, with any `[hooks.x]` sub-tables that directly follow it. */
interface TomlHooksTable {
  /** Line index of the `[[hooks]]` header. */
  start: number;
  /**
   * Exclusive end of its last header or key/value line. Blank and comment
   * lines after it stay with whatever follows — they are not ours to take.
   */
  end: number;
  /** Raw value text by key path (segments joined by NUL; sub-table keys prefixed). */
  keys: Map<string, string>;
}

interface TomlDocument {
  /** The document split on `\n` (a CRLF line keeps its `\r`). */
  lines: string[];
  eol: "\n" | "\r\n";
  hooks: TomlHooksTable[];
  /** A root-table `hooks = []` — inert, and in the way of `[[hooks]]`: lines [start, end). */
  emptyRootHooks?: { start: number; end: number };
  /** First line that defines `hooks` other than as `[[hooks]]` tables (or as an empty root array). */
  hooksConflict?: number;
}

/**
 * A light TOML reader: enough to know where each `[[hooks]]` table starts and
 * ends, what its `command` is, whether anything else claims the root `hooks`
 * key, and whether the document is TOML at all. A line that is neither blank,
 * a comment, a table header nor `key.path = value` makes the document
 * malformed — the same "refuse rather than overwrite" posture the JSON hosts
 * take with JSON.parse. Multi-line values (arrays, `"""`/`'''` strings) are
 * folded into their key: nothing inside one is read as a header or a key.
 *
 * A `[hooks.x]` / `[[hooks.x]]` header directly inside a `[[hooks]]` table
 * belongs to that element. Anywhere else — or a `[hooks]` table, or a root
 * `hooks` key that is not `[]` — `hooks` is not a table array we can append
 * to, and is reported as `hooksConflict`.
 */
function readToml(docText: string, invalidDocument: string): TomlDocument {
  const lines = docText.split("\n");
  const hooks: TomlHooksTable[] = [];
  let emptyRootHooks: TomlDocument["emptyRootHooks"];
  let hooksConflict: number | undefined;
  const bad = (i: number): never => {
    throw new Error(`${invalidDocument} is not valid TOML (line ${i + 1}); not touching it`);
  };
  let inRoot = true;
  /** The `[[hooks]]` element the current section belongs to, if any. */
  let element: TomlHooksTable | undefined;
  /** The current section's key path inside `element` (`[hooks.x]` → `["x"]`). */
  let prefix: string[] = [];
  /** A value still open at the end of the previous line. */
  let open: { scan: TomlValueScan; line: number; text: string; rootHooks: boolean } | undefined;
  const finish = (value: NonNullable<typeof open>, last: number): void => {
    if (!value.rootHooks) return;
    const bare = value.text
      .split("\n")
      .map((l) => l.replace(/#.*$/, ""))
      .join("")
      .replace(/\s+/g, "");
    if (bare === "[]" && emptyRootHooks === undefined) emptyRootHooks = { start: value.line, end: last + 1 };
    else hooksConflict ??= value.line;
  };
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i]!.replace(/\r$/, "");
    if (open) {
      if (!scanTomlValue(raw, open.scan)) bad(i);
      open.text += `\n${raw}`;
      if (element) element.end = i + 1;
      if (open.scan.depth <= 0 && !open.scan.multiline) {
        finish(open, i);
        open = undefined;
      }
      continue;
    }
    const line = raw.trim();
    if (line === "" || line.startsWith("#")) continue;
    const arrayHeader = TOML_ARRAY_TABLE_RE.exec(raw);
    const header = arrayHeader ?? TOML_TABLE_RE.exec(raw);
    if (header) {
      inRoot = false;
      const path = tomlKeyPath(header[1]!);
      if (path[0] !== "hooks") {
        element = undefined;
      } else if (arrayHeader && path.length === 1) {
        element = { start: i, end: i + 1, keys: new Map() };
        hooks.push(element);
        prefix = [];
      } else if (path.length > 1 && element) {
        prefix = path.slice(1);
        element.end = i + 1;
      } else {
        hooksConflict ??= i;
        element = undefined;
      }
      continue;
    }
    const kv = TOML_KEY_RE.exec(raw);
    if (!kv) bad(i);
    const path = tomlKeyPath(kv![1]!);
    const value = kv![2]!;
    const scan: TomlValueScan = { depth: 0 };
    if (!scanTomlValue(value, scan)) bad(i);
    if (element) {
      element.keys.set([...prefix, ...path].join("\0"), value);
      element.end = i + 1;
    }
    const rootHooks = inRoot && path[0] === "hooks";
    if (rootHooks && path.length > 1) hooksConflict ??= i;
    const pending = { scan, line: i, text: value, rootHooks: rootHooks && path.length === 1 };
    if (scan.depth > 0 || scan.multiline) open = pending;
    else finish(pending, i);
  }
  if (open) bad(lines.length - 1);
  return { lines, eol: docText.includes("\r\n") ? "\r\n" : "\n", hooks, emptyRootHooks, hooksConflict };
}

/** A TOML one-line string's contents, or undefined when the value is not one. */
function tomlString(value: string | undefined): string | undefined {
  if (value === undefined) return undefined;
  const basic = /^"((?:[^"\\]|\\.)*)"\s*(#.*)?$/.exec(value);
  if (basic) return tomlUnescape(basic[1]!);
  return /^'([^']*)'\s*(#.*)?$/.exec(value)?.[1];
}

function tomlQuote(value: string): string {
  return `"${value.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
}

/** Our table's fields, in order, as `[key, TOML value]`. */
function ourTomlFields(spec: ClaudeFamilySpec, command: string, timeout: number): [string, string][] {
  // Exactly the fields Kimi Code allows — extra keys make the whole file
  // fail to load (its docs say so), which is a bypass nobody asked for.
  const fields: [string, string][] = [["event", tomlQuote(spec.event)]];
  if (spec.matcher !== undefined) fields.push(["matcher", tomlQuote(spec.matcher)]);
  fields.push(["command", tomlQuote(command)], ["timeout", String(timeout)]);
  return fields;
}

/**
 * The document's text without `blocks` and without trailing newlines. Each
 * block takes the blank lines directly above it (they separated it from what
 * came before) — or, for a block at the very top, the blank lines below it.
 */
function cutTomlBlocks(lines: string[], blocks: { start: number; end: number }[]): string {
  const drop = new Array<boolean>(lines.length).fill(false);
  for (const block of blocks) {
    let { start, end } = block;
    while (start > 0 && lines[start - 1]!.trim() === "") start--;
    if (start === 0) while (end < lines.length && lines[end]!.trim() === "") end++;
    drop.fill(true, start, end);
  }
  return lines
    .filter((_, k) => !drop[k])
    .join("\n")
    .replace(/(?:\r?\n)+$/, "");
}

function mergeToml(
  spec: ClaudeFamilySpec,
  docText: string | undefined,
  command: string,
  timeout: number,
): string {
  const text = docText ?? "";
  const doc = readToml(text, spec.invalidDocument);
  if (doc.hooksConflict !== undefined) {
    // An inline `hooks = [{…}]`, a `[hooks]` table, a dotted `hooks.x`: a
    // `[[hooks]]` appended next to it redefines the key and the whole file
    // stops loading. Rewriting inline tables is not this reader's job.
    throw new Error(
      `${spec.invalidDocument} defines \`hooks\` other than as [[hooks]] tables (line ${doc.hooksConflict + 1}); not touching it`,
    );
  }
  const ours = doc.hooks.filter((t) => isOurCommand(tomlString(t.keys.get("command"))));
  const fields = ourTomlFields(spec, command, timeout);
  const only = ours.length === 1 ? ours[0]! : undefined;
  const upToDate =
    only !== undefined &&
    only.keys.size === fields.length &&
    fields.every(([k, v]) => {
      const have = only.keys.get(k);
      if (have === undefined) return false;
      return k === "timeout" ? have === v : tomlString(have) === tomlString(v);
    });
  if (upToDate && !doc.emptyRootHooks) return text;
  // Take out every copy of ours (and an inert root `hooks = []`, which would
  // collide with the table array), then append the canonical table once.
  const blocks: { start: number; end: number }[] = [...ours];
  if (doc.emptyRootHooks) blocks.push(doc.emptyRootHooks);
  const { eol } = doc;
  const desired = ["[[hooks]]", ...fields.map(([k, v]) => `${k} = ${v}`)].join(eol);
  const body = cutTomlBlocks(doc.lines, blocks);
  return `${body === "" ? desired : `${body}${eol}${eol}${desired}`}${eol}`;
}

function removeToml(spec: ClaudeFamilySpec, docText: string | undefined): string | undefined {
  if (!docText || docText.trim() === "") return undefined;
  let doc: TomlDocument;
  try {
    doc = readToml(docText, spec.invalidDocument);
  } catch {
    return undefined; // nothing of ours we can safely take out of it
  }
  const ours = doc.hooks.filter((t) => isOurCommand(tomlString(t.keys.get("command"))));
  if (ours.length === 0) return undefined;
  const body = cutTomlBlocks(doc.lines, ours);
  return body === "" ? "" : `${body}${doc.eol}`;
}

function installedToml(spec: ClaudeFamilySpec, docText: string | undefined, command: string): boolean {
  if (!docText || docText.trim() === "") return false;
  try {
    const doc = readToml(docText, spec.invalidDocument);
    // Next to any other definition of `hooks` the file does not load at all.
    if (doc.hooksConflict !== undefined || doc.emptyRootHooks) return false;
    return doc.hooks.some(
      (t) => tomlString(t.keys.get("event")) === spec.event && tomlString(t.keys.get("command")) === command,
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
        return removeKiro(spec, docText);
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
        return installedKiro(spec, docText, command);
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
  if (spec.jsonDialect) descriptor.documentFormat = spec.jsonDialect.json5 ? "json5" : "jsonc";
  if (spec.artifacts) descriptor.artifacts = spec.artifacts;
  return descriptor;
}
