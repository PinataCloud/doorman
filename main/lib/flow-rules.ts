/**
 * Session dataflow rules — the cross-call half of the Security Radar, ported
 * from Invariant Guardrails' flagship idea (its `->` operator): a sensitive
 * READ in one tool call followed by a network EGRESS in a LATER call of the
 * same session. The per-unit `secret_egress` detector only sees the two halves
 * when one command line carries both; an agent that reads `~/.aws/credentials`
 * in call 3 and runs `curl -d @-` in call 7 walks straight past it. This
 * module reasons over the session's ordered units instead.
 *
 * DELIBERATELY radar-only: `flow_secret_egress` is not in the guard's
 * ALL_DETECTORS, so it cannot be raised to ask/block, an org posture naming it
 * is dropped, and the guard bundle never learns it exists. Post-hoc evidence
 * first; enforcement is a later decision once the noise level is known.
 *
 * Same evidence invariant as security-detect.ts: excerpts are built from
 * REDACTED text and sanitized, key names name the source and sink rather than
 * any value, and the finding id (minted by the caller over detector + session
 * + key_name) hashes masked content only.
 *
 * Pure over the unit list — no fs, no Electron — so it is testable the same
 * way turns.ts is. Not part of the guard bundle: lives in lib/, imports the
 * guard's detector module (guard/security-detect.ts) for its shared patterns.
 */

import { redact } from "../guard/redact.js";
import { detectSecurityFindings } from "../guard/security-detect.js";
import { scanMcpToolOutput } from "../guard/mcp-poison.js";
import {
  customDetectorId,
  customWhenMatches,
  ruleAppliesToCwd,
  type CustomDetectorId,
  type CustomRule,
} from "../guard/custom-rules.js";
import {
  envDumpIn,
  HARNESS_TOOLS,
  invocationHeads,
  invokedCommands,
  isWriteTool,
  MAX_SCAN_CHARS,
  HEURISTIC_FAMILIES,
  networkInvocationIn,
  programOf,
  withoutIdentityFileArgs,
  readSqlArg,
  secretManagerReadIn,
  secretPathReadIn,
  SECRET_PATH_PATTERNS,
  sanitizeExcerpt,
  securityIgnoreMatcher,
  splitHeredocs,
  SQL_CLIENT_RE,
  sqlClientHeads,
  targetsOnlyLocalHosts,
  type SecurityIgnoreRule,
  type SecuritySeverity,
} from "../guard/security-detect.js";
import {
  execInvocationIn,
  FETCH_TOOL_RE,
  INJECTION_MARKER_DETECTORS,
  MCP_SERVER_RE,
  SEND_TOOL_RE,
  spendInvocationIn,
} from "../guard/armed.js";
import { DEFAULT_WALLET_CHAINS, findWalletAddresses, isKnownContractAddress, WALLET_CHAIN_LABELS } from "../guard/wallet-codec.js";
import type { DetectUnit } from "./cc-transcript.js";
import { extractRedactedSecrets, type RedactedSecret } from "./reveal.js";

export type FlowDetectorId =
  | "flow_secret_egress"
  | "flow_injection_followed"
  | "flow_fetch_then_exec"
  | "flow_fetch_then_install"
  | "flow_insecure_code_executed"
  | "flow_read_then_send"
  | "flow_sql_second_order"
  | "agent_loop"
  | "unknown_mcp_server"
  | "wallet_address_tampered";

/**
 * What a unit LEFT BEHIND that a later call can act on. One vocabulary for
 * every rule, so adding a rule is a row in FLOW_RULES rather than a second
 * pass over the units.
 *
 * `fetched_content` is text that arrived from outside (a WebFetch result, the
 * output of a `curl`), remembered as the set of words it contained; a later
 * package install NAMED by that text is the supply-chain shape. `insecure_code`
 * is a file this session wrote with a known-dangerous construct in it; running
 * that file is the other half of Invariant's "edit introduces pickle, later
 * call runs python" rule.
 */
type TaintKind =
  | "secret"
  | "injection"
  | "untrusted_fetch"
  | "fetched_content"
  | "insecure_code"
  | "private_data"
  | "sql_result"
  | "external_address";

/** What a later unit DOES. `secret_read` is both a source and a sink: reading a
 * credential is an ordinary step on its own, but doing it right after an
 * injection arrived is the injection being obeyed. `install` is a package
 * manager fetching code by name. */
type SinkKind = "egress" | "exec" | "send" | "sql" | "secret_read" | "install" | "write" | "spend";

/**
 * The rule table. Each row is "this taint, then this action, is a finding" —
 * Invariant Guardrails' `->` operator as data.
 *
 * `flow_injection_followed` is the critical one and the reason the rest exist:
 * the per-unit detectors say an injection ARRIVED, and only a flow can say the
 * agent then did what it asked.
 */
const FLOW_RULES: ReadonlyArray<{
  taint: TaintKind;
  sink: SinkKind;
  detector: FlowDetectorId;
  severity: SecuritySeverity;
}> = [
  { taint: "secret", sink: "egress", detector: "flow_secret_egress", severity: "high" },
  { taint: "secret", sink: "send", detector: "flow_secret_egress", severity: "high" },
  { taint: "injection", sink: "egress", detector: "flow_injection_followed", severity: "critical" },
  { taint: "injection", sink: "exec", detector: "flow_injection_followed", severity: "critical" },
  { taint: "injection", sink: "send", detector: "flow_injection_followed", severity: "critical" },
  { taint: "injection", sink: "secret_read", detector: "flow_injection_followed", severity: "critical" },
  { taint: "untrusted_fetch", sink: "exec", detector: "flow_fetch_then_exec", severity: "high" },
  // Invariant's code_agents notebook: read_web → `pip install <the library the
  // page named>` → run it. The install must name a package the fetched text
  // mentioned (Taint.mentions), which is what keeps "read the docs, then
  // install the dependency you already had in mind" out of it.
  { taint: "fetched_content", sink: "install", detector: "flow_fetch_then_install", severity: "high" },
  // Invariant's swe_agent notebook: a write that introduced a dangerous
  // construct, then a call that ran that file (Taint.requiresMention).
  { taint: "insecure_code", sink: "exec", detector: "flow_insecure_code_executed", severity: "medium" },
  { taint: "private_data", sink: "send", detector: "flow_read_then_send", severity: "high" },
  { taint: "sql_result", sink: "sql", detector: "flow_sql_second_order", severity: "medium" },
  // A transfer run after an injection arrived is the injection being obeyed
  // with money — the guard's armed escalation holds the same sink (armed.ts).
  { taint: "injection", sink: "spend", detector: "flow_injection_followed", severity: "critical" },
  // Address poisoning (docs/plans/wallet-leak-detection-plan.md §4): a wallet
  // address ARRIVED from outside — a fetched page, an MCP result — and a later
  // call wrote that same address into a file or paid to it. The address string
  // itself is the mention the sink must carry (Taint.requiresMention), so the
  // pairing is exact rather than "an address, then a write".
  { taint: "external_address", sink: "write", detector: "wallet_address_tampered", severity: "critical" },
  { taint: "external_address", sink: "spend", detector: "wallet_address_tampered", severity: "critical" },
];

export interface FlowFinding {
  /** A shipped flow rule's id, or a person's `custom:<id>` rule with an
   * `after` clause (guard/custom-rules.ts) — the same taint→sink evaluation,
   * with the person's `when` as the sink. */
  detector: FlowDetectorId | CustomDetectorId;
  /** Present on custom-rule findings: the label at the time it fired. */
  detector_label?: string;
  severity: SecuritySeverity;
  /** `"<source> → <sink>"` — names only, never values; doubles as identity. */
  key_name: string;
  /** `"<masked source> ⇢ <masked sink>"`, both redacted and sanitized. */
  excerpt: string;
  occurrences: number;
  tool_name?: string;
  target?: string;
  session_id: string;
  source_turn_id: string;
  sink_turn_id: string;
  /** The source's timestamp — where the flow began. Lets a caller price the
   * span (agent_loop) or state the gap without re-deriving it from units. */
  source_at: string;
  /** The sink's timestamp — when the flow completed. */
  at: string;
}

/** How far a taint reaches before it goes stale: either bound ends it. A
 * credential read half an hour or thirty calls ago feeding a curl is a
 * different session's story, not a flow. */
export const FLOW_MAX_GAP_CALLS = 30;
export const FLOW_MAX_GAP_MS = 30 * 60_000;

/** Cap the combined two-part excerpt, same order of size as per-unit ones. */
const FLOW_EXCERPT_MAX = 240;

/** Placeholder families that are privacy scrubbing, not credentials — the same
 * exemption the per-unit placeholder detector makes. */
const NON_CREDENTIAL_FAMILIES: ReadonlySet<string> = new Set(["email"]);

const FAMILY_PLACEHOLDER_RE = /\[redacted:([a-z0-9_]+)\]/g;

/** The tool input a tool_call unit carries, parsed — or undefined when the raw
 * argument blob isn't JSON (Codex local_shell units). */
export function parsedInput(unit: DetectUnit): unknown {
  try {
    const parsed = JSON.parse(unit.raw) as unknown;
    return parsed && typeof parsed === "object" ? parsed : undefined;
  } catch {
    return undefined;
  }
}

/** The command string out of a tool_call unit's JSON argument blob. Exported
 * for the engine's custom-rule pass, which needs the identical answer. */
export function commandOf(unit: DetectUnit): string | undefined {
  try {
    const parsed = JSON.parse(unit.raw) as Record<string, unknown> | unknown;
    if (!parsed || typeof parsed !== "object") return undefined;
    const record = parsed as Record<string, unknown>;
    for (const key of ["command", "cmd", "script", "commandLine"]) {
      const value = record[key];
      if (typeof value === "string" && value !== "") return value;
    }
  } catch {
    // Not JSON — Codex local_shell units and hand-rolled shapes fall through.
    return unit.tool_name && /shell|bash/i.test(unit.tool_name) ? unit.raw : undefined;
  }
  return undefined;
}

/** Credential families redact() finds in a tool OUTPUT — proof the read
 * returned a live secret, the strongest source signal there is. Injectable so
 * the caller can memoize the redaction (outputs are up to 64 KB and re-parsed
 * on every file touch); the default is the honest slow path. */
export function credentialFamiliesInOutput(raw: string): string[] {
  const families = new Set<string>();
  FAMILY_PLACEHOLDER_RE.lastIndex = 0;
  let match: RegExpExecArray | null;
  const redacted = redact(raw);
  while ((match = FAMILY_PLACEHOLDER_RE.exec(redacted)) !== null) {
    const family = match[1] ?? "";
    // The heuristic families (`generic`, `bearer`) are medium confidence per
    // unit — they observe, never interrupt. A taint built on one would promote
    // that guess into a HIGH flow finding for every later network call.
    if (!NON_CREDENTIAL_FAMILIES.has(family) && !HEURISTIC_FAMILIES.has(family)) families.add(family);
  }
  return [...families];
}

interface Taint {
  kind: TaintKind;
  /**
   * When set, the sink's command must MENTION this string (a downloaded file's
   * basename) for the pair to count. "Fetched X, then ran X" is a real chain;
   * "fetched something, then ran an unrelated build script" is a Tuesday, and
   * without this the fetch→exec rule raised 39 rows of exactly that.
   */
  requiresMention?: string;
  /**
   * For `fetched_content`: the words the fetched text contained. A later
   * install pairs only when it names a package in this set — the page named
   * the library, then the agent installed it.
   */
  mentions?: ReadonlySet<string>;
  /**
   * For `untrusted_fetch`: the sink must INVOKE the file named by
   * `requiresMention` (it is the program, or an interpreter's script argument)
   * — `wc -l README.md` mentions a download without running it.
   */
  requiresInvocation?: boolean;
  /**
   * For `secret`: what a later egress must CARRY for the pair to count — see
   * `SecretLink`. A secret taint with no link can never pair: "read a
   * credential, then ran some unrelated curl" is a Tuesday, and pairing on
   * proximity alone was 116 of 256 `flow_secret_egress` rows in one ledger.
   */
  link?: SecretLink;
  /** The source's file or target, for ignore-rule matching only. */
  sourceTarget?: string;
  /** What was read — the key_name's left half. */
  name: string;
  turn_id: string;
  at: string;
  callIndex: number;
  atMs: number;
  /** Masked one-line description for the excerpt's left half. */
  excerpt: string;
}

interface Sink {
  kind: SinkKind;
  /** The key_name's right half. */
  name: string;
  excerpt: string;
}

// ── Classification vocabulary ────────────────────────────────────────────────
//
// The sink verbs (EXEC_VERB_RE, FETCH_TOOL_RE, SEND_TOOL_RE, MCP_SERVER_RE)
// are IMPORTED from guard/armed.ts — the guard's enforceable half of the
// injection rule — so the radar and the guard can never disagree about what a
// sink is. The rest describe SESSION shapes (what a call does in sequence),
// not the per-call exposures security-detect.ts judges. Every command-shaped
// test runs against an invocation HEAD (security-detect's invocationHeads), so
// a program named in somebody else's arguments — `grep -r psql docs`,
// `git commit -m "pip install x"`, `mkdir -p src/http` — is never a sink.

/**
 * A package manager fetching code BY NAME — the sink half of fetch→install.
 * Group 1 is the package list (everything after the verb up to a pipe or
 * separator); `packagesNamed` picks the names out of it.
 */
const INSTALL_RE =
  /(?:^|\s|\|)(?:(?:pip3?|uv\s+pip|pipx|poetry|pdm)\s+(?:install|add)|uv\s+add|npm\s+(?:i|install|add)|(?:pnpm|yarn|bun)\s+(?:add|install)|npx\s+(?:-y\s+|--yes\s+)?|cargo\s+install|gem\s+install|go\s+install|brew\s+install|composer\s+require)\s+([^|;&\n]+)/i;

/** The package list of the install a command invokes, or undefined. The match
 * must start at the program (`python -m pip` included) — an `echo pip install
 * x` or a commit message that quotes one installs nothing. */
function installArgsIn(command: string): string | undefined {
  for (const head of invokedCommands(command)) {
    const candidate = head.replace(/^(?:\S*\/)?python[0-9.]*\s+-m\s+(?=pip)/, "");
    const match = INSTALL_RE.exec(candidate);
    if (match && candidate.slice(0, match.index).trim() === "") return match[1];
  }
  return undefined;
}

/** The package names in an install's argument list: flags dropped, versions
 * and extras trimmed, scoped npm names kept whole. URL installs keep the URL's
 * host as the "name" so a fetched page that named the host still pairs. */
export function packagesNamed(installArgs: string): string[] {
  const names: string[] = [];
  for (const raw of installArgs.trim().split(/\s+/)) {
    if (raw === "" || raw.startsWith("-")) continue;
    if (/^(?:git\+)?https?:\/\//i.test(raw)) {
      const host = /:\/\/([^/\s]+)/.exec(raw)?.[1];
      if (host) names.push(host.toLowerCase());
      continue;
    }
    if (raw.startsWith(".") || raw.startsWith("/")) continue;
    const name = raw.replace(/^(@[^/]+\/[^@\s]+|[^@=<>~^!\[\s]+).*$/, "$1");
    if (name && name !== "-e" && name.length <= 214) names.push(name.toLowerCase());
  }
  return names;
}

/** The lower-cased "words" a fetched text contains, for Taint.mentions.
 * Bounded so a 64 KB page costs a set, not a scan per later install. */
const MENTION_MAX_WORDS = 4000;
export function mentionsIn(text: string): Set<string> {
  const words = new Set<string>();
  for (const match of text.toLowerCase().matchAll(/[a-z0-9@][a-z0-9_.\/-]{1,213}/g)) {
    words.add(match[0].replace(/[._-]/g, "-"));
    if (words.size >= MENTION_MAX_WORDS) break;
  }
  return words;
}

function mentioned(mentions: ReadonlySet<string>, name: string): boolean {
  const folded = name.toLowerCase().replace(/[._-]/g, "-");
  if (mentions.has(folded)) return true;
  // `@scope/name` is mentioned if either half is.
  const bare = folded.split("/").pop();
  return bare !== undefined && bare !== folded && mentions.has(bare);
}

// ── Secret links ─────────────────────────────────────────────────────────────
//
// A secret→egress flow is a finding only when the egress CARRIES what was
// read: the value itself (or a common encoding of it), the secret file, a file
// the read was copied into, or a shell variable it was captured in. Values
// live only in memory for the length of one evaluation — they never reach a
// key_name, an excerpt or any returned object.

/**
 * What a secret taint's sink must carry. `values` are raw strings plus their
 * encodings; `paths` are the secret file's own pattern and the files it was
 * written to; `vars` are shell variables a secret manager's answer landed in.
 */
interface SecretLink {
  values: Set<string>;
  paths: RegExp[];
  carriers: Set<string>;
  vars: Set<string>;
}

function emptyLink(): SecretLink {
  return { values: new Set(), paths: [], carriers: new Set(), vars: new Set() };
}

/** Shorter than this and a "value" matches by accident (`admin`, `8080`). */
const MIN_LINK_VALUE = 8;
/** Bounded so a 64 KB env dump costs a set, not a scan per later curl. */
const MAX_LINK_VALUES = 400;

/** Add `value` and the encodings an exfil command would realistically use. */
function addLinkValue(link: SecretLink, value: string): void {
  const v = value.trim();
  if (v.length < MIN_LINK_VALUE || link.values.size >= MAX_LINK_VALUES) return;
  link.values.add(v);
  link.values.add(Buffer.from(v, "utf8").toString("base64").replace(/=+$/, ""));
  const uri = encodeURIComponent(v);
  if (uri !== v) link.values.add(uri);
  const json = JSON.stringify(v).slice(1, -1);
  if (json !== v) link.values.add(json);
}

/** Values the redactor recognised, minus privacy-only families. */
function credentialValues(secrets: readonly RedactedSecret[], family: string): string[] {
  return secrets.filter((s) => s.label === family && !NON_CREDENTIAL_FAMILIES.has(s.label)).map((s) => s.value);
}

/** Keys whose value is a credential however it looks. */
const SECRETISH_KEY_RE = /(?:key|token|secret|pass(?:word|wd)?|pwd|auth|cred|private|session|cookie|dsn|signature|salt|_url)$|^(?:database_url|dsn)$/i;
/** Values that are obviously templates or filler — never a link. */
const PLACEHOLDER_VALUE_RE = /^\$|\$\{|^<.*>$|^\{.*\}$|x{6,}|\*{4,}|your[_-]|changeme|example|placeholder|dummy|^(?:true|false|null|none)$/i;

/**
 * Values in the OUTPUT of a secret read (a `.env`, an env dump, a secret
 * manager's answer). `KEY=VALUE` / `key: value` / `"key": "value"` lines keep
 * a value when its key reads secret-ish, or when the value itself is long and
 * mixed enough to be one; a single-line output is the answer of
 * `op read` / `pass show` / `security -w` itself.
 */
function secretFileValues(output: string): string[] {
  const values: string[] = [];
  const text = output.slice(0, MAX_SCAN_CHARS);
  const trimmed = text.trim();
  if (trimmed !== "" && !/\n/.test(trimmed) && trimmed.length <= 4096 && !/\s/.test(trimmed)) values.push(trimmed);
  const assignment = /^\s*(?:export\s+)?["']?([A-Za-z_][A-Za-z0-9_.-]*)["']?\s*[=:]\s*["']?([^\s"'#,]+)/gm;
  let match: RegExpExecArray | null;
  while ((match = assignment.exec(text)) !== null) {
    const [, key = "", value = ""] = match;
    if (value.length < MIN_LINK_VALUE || PLACEHOLDER_VALUE_RE.test(value)) continue;
    const mixed = value.length >= 16 && /[A-Za-z]/.test(value) && /[0-9]/.test(value) && !/^[/~.]/.test(value);
    if (SECRETISH_KEY_RE.test(key) || mixed) values.push(value);
    if (values.length >= MAX_LINK_VALUES) break;
  }
  return values;
}

/** Files a command WROTE: `> f`, `>> f`, `tee f`, `cp|mv src f`. */
function writtenPaths(command: string): string[] {
  const out: string[] = [];
  for (const match of command.matchAll(/(?<![0-9&])>>?\s*([^\s&|;<>]+)/g)) out.push(match[1]!);
  for (const match of command.matchAll(/(?:^|[\s|])tee\s+(?:-a\s+)?([^\s&|;<>]+)/g)) out.push(match[1]!);
  for (const match of command.matchAll(/(?:^|[\s;&|])(?:cp|mv)\s+(?:-[A-Za-z]+\s+)*\S+\s+([^\s&|;<>]+)/g)) out.push(match[1]!);
  return out.filter((p) => p !== "" && !p.startsWith("/dev/") && p !== "-");
}

/** Shell variables a command assigned from a substitution: `X=$(…)`. */
function capturedVars(command: string): string[] {
  return [...command.matchAll(/(?:^|[\s;&|])(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=["']?(?:\$\(|`)/g)].map((m) => m[1]!);
}

/** Does `payload` carry what `link` names? */
function carriesLink(link: SecretLink, payload: string): boolean {
  for (const value of link.values) if (payload.includes(value)) return true;
  // curl/httpie's `@file` upload syntax glues the path to the `@`, which the
  // path patterns' leading-boundary class doesn't include — split it off.
  const sansIdentity = withoutIdentityFileArgs(payload).replace(/@(?=[.~/\w])/g, "@ ");
  if (link.paths.some((p) => p.test(sansIdentity))) return true;
  for (const carrier of link.carriers) {
    const base = carrier.split("/").pop() ?? carrier;
    if (payload.includes(carrier) || (base.length >= 3 && new RegExp(`(?:^|[\\s@=/'"])${escapeRegExp(base)}(?:$|[\\s'"])`).test(payload))) {
      return true;
    }
  }
  for (const name of link.vars) {
    if (new RegExp(`\\$\\{?${name}\\b`).test(payload)) return true;
  }
  return false;
}

function escapeRegExp(text: string): string {
  return text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * Harness bookkeeping whose output is the harness talking to itself — a
 * stopped task's summary, a sub-agent's report, a plan. Never a taint source:
 * a sub-agent QUOTING a fixture is not a credential read, and a TaskStop that
 * echoed a test key paired with every later curl.
 */
const FLOW_HARNESS_TOOLS: ReadonlySet<string> = new Set([
  ...HARNESS_TOOLS,
  "TaskStop",
  "TaskOutput",
  "TaskCreate",
  "TaskGet",
  "TaskList",
  "TaskUpdate",
  "TodoRead",
  "Agent",
  "SendMessage",
  "ListAgents",
  "Skill",
  "ToolSearch",
  "ScheduleWakeup",
  "ReportFindings",
  "Workflow",
  "CronCreate",
  "CronDelete",
  "CronList",
  "update_plan",
]);

function isHarnessTool(name: string | undefined): boolean {
  return name !== undefined && FLOW_HARNESS_TOOLS.has(name);
}

/** Tools whose answer is the internet talking, beyond FETCH_TOOL_RE. */
const OUTSIDE_TOOL_RE = /^(?:WebSearch|web_search|web\.run)$/i;
/** Commands that print content someone else wrote, beyond a network invocation. */
const OUTSIDE_COMMAND_RE = /(?:^|[\s;&|])gh\s+(?:issue|pr|release|discussion|gist|search|run)\s+(?:view|list|diff|download|comments?)\b/;

/** Did this call bring text from OUTSIDE into the session? */
function callFetches(unit: DetectUnit, command: string | undefined): boolean {
  if (command !== undefined) {
    return networkInvocationIn(command) !== undefined || OUTSIDE_COMMAND_RE.test(command);
  }
  const tool = unit.tool_name;
  return tool !== undefined && (FETCH_TOOL_RE.test(tool) || OUTSIDE_TOOL_RE.test(tool));
}

/** Tools that read a local file by path — the "local file" half of outsideness. */
const FILE_READ_TOOL_RE = /^(?:Read|read_file|view|NotebookRead)$/;

/**
 * Tracks, across ordered units, whether a tool OUTPUT is text from outside:
 * the answer to a fetch (same tool as the call), any MCP tool's answer, or a
 * local read of a file this session downloaded. One implementation for the
 * wallet-address taint, the injection taint and the guard's arming, so the
 * three can never disagree.
 */
class OutsideTracker {
  private lastCallFetched = false;
  private lastCallName: string | undefined;
  private lastCallTarget: string | undefined;
  private lastCallCommand: string | undefined;
  private readonly downloaded = new Set<string>();

  observeCall(unit: DetectUnit, command: string | undefined, landed?: string): void {
    this.lastCallFetched = callFetches(unit, command);
    this.lastCallName = unit.tool_name;
    this.lastCallTarget = unit.target;
    this.lastCallCommand = command;
    if (landed !== undefined) this.downloaded.add(landed);
    else if (command !== undefined && this.lastCallFetched) {
      for (const path of writtenPaths(command)) this.downloaded.add(path.split("/").pop() ?? path);
      const explicit = /(?:^|\s)(?:-o|-O|--output)[\s=]+(\S+)/.exec(command)?.[1];
      if (explicit) this.downloaded.add(explicit.split("/").pop() ?? explicit);
    }
  }

  /** The call the next output answers, for naming a source. */
  get call(): { tool?: string; target?: string; command?: string } {
    return {
      ...(this.lastCallName === undefined ? {} : { tool: this.lastCallName }),
      ...(this.lastCallTarget === undefined ? {} : { target: this.lastCallTarget }),
      ...(this.lastCallCommand === undefined ? {} : { command: this.lastCallCommand }),
    };
  }

  /** Is this output an answer from outside? */
  isOutside(unit: DetectUnit): boolean {
    if (unit.kind !== "tool_output" || isHarnessTool(unit.tool_name)) return false;
    if (this.lastCallFetched && (this.lastCallName === undefined || unit.tool_name === this.lastCallName)) return true;
    if (unit.tool_name !== undefined && MCP_SERVER_RE.test(unit.tool_name)) return true;
    // A fetch TOOL's answer is the internet by construction, whatever order
    // the parser emitted its call in.
    if (unit.tool_name !== undefined && (FETCH_TOOL_RE.test(unit.tool_name) || OUTSIDE_TOOL_RE.test(unit.tool_name))) return true;
    const target = this.lastCallTarget;
    if (target !== undefined && FILE_READ_TOOL_RE.test(unit.tool_name ?? "")) {
      const base = target.split("/").pop() ?? target;
      if (this.downloaded.has(base)) return true;
    }
    return false;
  }

  /** The fetched-content taint consumes the flag once. */
  consumeFetch(unit: DetectUnit): boolean {
    const answered =
      this.lastCallFetched && (this.lastCallName === undefined || unit.tool_name === this.lastCallName) && !isHarnessTool(unit.tool_name);
    if (answered) this.lastCallFetched = false;
    return answered;
  }
}

/** The program a command line mainly runs, for naming (`cd x && git diff` → `git diff`). */
function mainProgram(command: string): string {
  for (const head of invocationHeads(command)) {
    const words = head.split(/\s+/).filter((w) => w !== "sudo");
    const program = (words[0] ?? "").split("/").pop() ?? "";
    if (program === "" || /^(?:cd|export|set|source|\.|echo|true|:|pushd|popd)$/.test(program)) continue;
    const sub = words[1];
    return sub !== undefined && /^[a-z][a-z0-9-]{1,20}$/.test(sub) ? `${program} ${sub}` : program;
  }
  return "shell";
}

/** "in Read db.py output" / "in Bash (git diff) output" — how the value arrived. */
function sourceDescription(call: { tool?: string; target?: string; command?: string }, toolName: string | undefined): string {
  const tool = toolName ?? call.tool ?? "a tool";
  if (call.command !== undefined) return `${tool} (${mainProgram(call.command)}) output`;
  if (call.target !== undefined && call.target !== "") {
    const base = collapse(call.target).split("/").pop() ?? "";
    if (base !== "") return `${tool} ${base.slice(0, 60)} output`;
  }
  return `${tool} output`;
}

/** A credential family as a reader says it. */
function familyPhrase(family: string): string {
  return family === "credentials" ? "URL credentials" : `${family} credential`;
}

/** Scripts and executables — what a download must be for running it to matter. */
const RUNNABLE_FILE_RE =
  /\.(?:sh|bash|zsh|ksh|fish|command|py|pyw|js|mjs|cjs|ts|mts|cts|rb|pl|php|ps1|jar|bin|run|appimage|deb|pkg|dmg|exe|msi)$/i;

/** Interpreters whose first script argument is the file being run. */
const INTERPRETER_RE =
  /^(?:(?:ba|z|k|d|fi)?sh|python[0-9.]*|pypy[0-9.]*|node|deno|bun|bunx|npx|tsx|ts-node|ruby|perl|php|pwsh|powershell|osascript|java|source|\.|installer|open|sudo|env|exec|uv|pipx)$/;

/** Does this command RUN `file` — as the program, or as an interpreter's argument? */
export function invokesFile(command: string, file: string): boolean {
  const want = file.split("/").pop() ?? file;
  for (const head of invocationHeads(command)) {
    const words = head
      .split(/\s+/)
      .map((w) => w.replace(/^["']|["']$/g, ""))
      .filter((w) => w !== "");
    let i = 0;
    while (i < words.length && /^(?:sudo|env|exec|command|nohup|time)$/.test(words[i]!)) i += 1;
    const program = words[i];
    if (program === undefined) continue;
    if ((program.split("/").pop() ?? program) === want) return true;
    if (!INTERPRETER_RE.test(program.split("/").pop() ?? program)) continue;
    // The first few non-flag arguments: `deno run x.ts`, `java -jar x.jar`,
    // `uv run x.py`, `installer -pkg x.pkg -target /`.
    let seen = 0;
    for (const word of words.slice(i + 1)) {
      if (word.startsWith("-") || word === "run") continue;
      if ((word.split("/").pop() ?? word) === want) return true;
      if (++seen >= 3) break;
    }
  }
  return false;
}

/** Test code and fixtures: a dangerous construct there is usually the point. */
const TEST_FILE_RE =
  /(?:^|\/)(?:tests?|__tests__|spec|specs|fixtures?|__fixtures__|testdata|__mocks__)\/|\.(?:test|spec)\.[A-Za-z0-9]+$|(?:^|\/)test_[^/]+\.py$|_test\.(?:py|go|rb)$/i;

/**
 * Which per-unit detector a flow is the staged form of — so an ignore rule a
 * person scoped to the per-unit card also silences its flow twin.
 */
const FLOW_PARENT_DETECTOR: Partial<Record<FlowDetectorId, string>> = {
  flow_secret_egress: "secret_egress",
  flow_fetch_then_exec: "unsafe_fetch_exec",
  flow_insecure_code_executed: "insecure_code_written",
};

/**
 * A fetch that puts a runnable artefact on disk, rather than an API call whose
 * body is read and discarded. See the taint site for why this narrowing exists.
 */
// The redirect arm excludes `2>`/`&>` (stderr suppression, which is in half of
// all shell commands) and `>/dev/null` (explicitly throwing the body away) —
// both were matching, which is why the first narrowing barely moved the count.
/**
 * Where a fetch LANDED something runnable, or undefined if it didn't. Returns
 * the basename, which is what a later command would name.
 *
 * `/dev/null` and `-` are explicit discards, not downloads.
 */
function fetchLandedPath(command: string): string | undefined {
  const explicit =
    /(?:^|\s)(?:-o|-O|--output)[\s=]+(\S+)/.exec(command) ??
    /(?<![0-9&])>\s*([^\s&|>]+)/.exec(command);
  const candidate =
    explicit?.[1] ??
    // wget saves to the URL's basename by default.
    (/(?:^|\s)wget(?:\s|$)/.test(command)
      ? /https?:\/\/\S+?\/([^/?\s]+)(?:\?|\s|$)/.exec(command)?.[1]
      : undefined) ??
    // A URL that names a script is runnable wherever it lands.
    /https?:\/\/\S+?\/([^/?\s]+\.(?:sh|bash|zsh|py|rb|pl|ps1|jar|bin|run|deb|pkg|dmg|exe))\b/.exec(
      command,
    )?.[1];
  if (candidate === undefined) return undefined;
  const base = candidate.split("/").pop() ?? candidate;
  if (candidate.includes("/dev/null")) return undefined;
  // Must look like an actual filename with an extension. A `>` inside a quoted
  // string or a JSON blob otherwise yields "landed paths" like `',` or `=`,
  // which then match almost any later command — 30 rows of that survived the
  // first two narrowings.
  if (/^[A-Za-z0-9_@.-]+\.[A-Za-z0-9]{1,8}$/.test(base)) {
    // And be RUNNABLE: `gh api … > issue.json` then a script that parses it,
    // or `curl -o README.md` then `wc -l README.md`, is data, not code — json,
    // md, svg and toml downloads were 11 of 21 fetch→exec rows.
    return RUNNABLE_FILE_RE.test(base) ? base : undefined;
  }
  // An extensionless binary counts only when the command NAMED it with -o:
  // a redirect target without an extension is too often junk from a quote.
  const named = /(?:^|\s)(?:-o|-O|--output)[\s=]+(\S+)/.exec(command)?.[1];
  return named !== undefined && /^[A-Za-z0-9_@-]{2,64}$/.test(base) && (named.split("/").pop() ?? named) === base
    ? base
    : undefined;
}

/**
 * A later query that INTERPOLATES something — a command substitution, a shell
 * variable, a heredoc. Running `psql` twice in a session is ordinary work; the
 * second-order shape is a query built from what the first one returned, and a
 * shell interpolation is the only evidence of that a transcript actually
 * carries. Without this the rule raised 13 rows of routine dev queries.
 */
const SQL_INTERPOLATES_RE = /\$\(|\$\{|`[^`]*`|\$[A-Za-z_][A-Za-z0-9_]*/;

/** A client's query argument: `-c`/`--command`/`-f` (psql), `-e`/`--execute`
 * (mysql, mariadb), `--eval` (mongosh), `-q`/`--query` (clickhouse). Group 1
 * is the word, still quoted. */
const SQL_QUERY_ARG_RE =
  /(?:^|\s)(?:-c|--command|-f|--file|-e|--execute|--eval|-q|--query)(?:\s+|=)("(?:[^"\\]|\\.)*"|'[^']*'|\S+)/g;
const SHELL_WORD_RE = /"(?:[^"\\]|\\.)*"|'[^']*'|\S+/g;

/** Would the shell interpolate into this word? Single quotes are literal. */
function wordInterpolates(word: string): boolean {
  return !word.startsWith("'") && SQL_INTERPOLATES_RE.test(word);
}

/**
 * The database-client head whose QUERY is built by interpolation, or
 * undefined. Only the query counts — `psql "$DOORMAN_PG" -c 'select 1'`
 * interpolates the connection URL, which is how every script names its
 * database, not evidence a query was assembled from an earlier result. The
 * query can arrive as a flag argument, sqlite3's positional statement, a
 * heredoc, or stdin from an earlier pipe segment.
 */
function sqlInterpolatingHead(command: string): string | undefined {
  const { heredocs } = splitHeredocs(command);
  for (const heredoc of heredocs) {
    if (SQL_CLIENT_RE.test(heredoc.opener.replace(/["']/g, "")) && !heredoc.quoted && SQL_INTERPOLATES_RE.test(heredoc.body)) {
      return heredoc.opener;
    }
  }
  for (const head of sqlClientHeads(command)) {
    const queries = [...head.matchAll(SQL_QUERY_ARG_RE)].map((m) => m[1]!);
    if (programOf(head) === "sqlite3") {
      // sqlite3 [options] DATABASE [SQL]
      const words = (head.match(SHELL_WORD_RE) ?? []).slice(1).filter((w) => !w.startsWith("-"));
      if (words[1] !== undefined) queries.push(words[1]);
    }
    if (queries.some(wordInterpolates)) return head;
    if (queries.length === 0) {
      // No inline query: it comes from stdin — the rest of the pipeline.
      const rest = command.replace(head, " ").replace(/'[^']*'/g, "''");
      if (/\|\s*(?:\S*\/)?(?:psql|mysql|mariadb|sqlite3|mongosh|clickhouse-client)\b/.test(command) && SQL_INTERPOLATES_RE.test(rest)) {
        return head;
      }
    }
  }
  return undefined;
}

/** MCP servers that hold a person's own data: mail, chat, docs, trackers. */
const PRIVATE_DATA_SERVER_RE =
  /(?:gmail|mail|slack|discord|teams|drive|dropbox|notion|confluence|jira|linear|calendar|contacts|whatsapp|telegram|sheets|onedrive|sharepoint)/i;

/** Reading verbs on such a server — the data actually comes back. */
const READ_TOOL_RE = /(?:^|_)(?:get|read|list|search|fetch|query|find|download|export)(?:_|$)/i;

/** Does this tool name belong to an MCP server (and which)? */
function mcpServerOf(toolName: string | undefined): string | undefined {
  const match = MCP_SERVER_RE.exec(toolName ?? "");
  return match?.[1];
}

/** The URL a fetch-shaped tool was pointed at, if its input carries one. */
function fetchUrlOf(unit: DetectUnit): string | undefined {
  const input = parsedInput(unit);
  if (!input || typeof input !== "object") return undefined;
  const record = input as Record<string, unknown>;
  for (const key of ["url", "uri", "href", "link"]) {
    const value = record[key];
    if (typeof value === "string" && /^https?:\/\//i.test(value)) return value;
  }
  return undefined;
}

/** A runnable basename a URL's path ends in, or undefined. */
function scriptBasenameOf(url: string): string | undefined {
  const match = /https?:\/\/\S+?\/([^/?\s#]+\.(?:sh|bash|zsh|py|rb|pl|ps1|jar|bin|run|deb|pkg|dmg|exe|js|mjs))(?:[?#]|$)/i.exec(url);
  return match?.[1];
}

function collapse(text: string): string {
  return text.replace(/\s+/g, " ").trim();
}

/** A masked one-liner for a command: redacted (commands are short), collapsed. */
function commandExcerpt(command: string): string {
  return sanitizeExcerpt(collapse(redact(command))).slice(0, 110);
}

export interface FlowOptions {
  ignore?: readonly SecurityIgnoreRule[];
  /**
   * MCP servers the organization has reviewed. ABSENT or EMPTY means the org
   * has no opinion and `unknown_mcp_server` stays silent — an org that never
   * filled this in must not have every server on every machine flagged.
   */
  approvedMcpServers?: readonly string[];
  /** Memoizable override for the tool_output credential probe. */
  familiesIn?: (unit: DetectUnit) => readonly string[];
  /** The person's rules that carry an `after` clause — evaluated as extra rows
   * of the taint→sink table, with the rule's `when` as the sink test. */
  customRules?: readonly CustomRule[];
  /**
   * Memoizable override for "did an injection arrive in this tool output?".
   * Returns the marker's name, or undefined. Injectable for the same reason as
   * `familiesIn`: the default re-runs the detectors over up to 64 KB, and
   * capture re-parses whole files on every touch.
   */
  injectionIn?: (unit: DetectUnit) => string | undefined;
  /**
   * Memoizable override for the VALUES behind `familiesIn`'s families (the
   * reveal alignment, reveal.ts). Used only to link a secret taint to the
   * egress that carries it; values never leave the evaluation.
   */
  secretsIn?: (unit: DetectUnit) => readonly RedactedSecret[];
}

/**
 * Did an injection arrive in this tool output? The per-unit detectors already
 * answer this — an MCP poisoning pattern, an injected instruction, smuggled
 * invisible characters, or a data-carrying link in text that came from OUTSIDE.
 * This just re-asks them, so the flow rule and the card the user already saw
 * can never disagree about what counts.
 */
export function injectionMarkerIn(unit: DetectUnit): string | undefined {
  if (unit.kind !== "tool_output") return undefined;
  if (unit.tool_name && HARNESS_TOOLS.has(unit.tool_name)) return undefined;
  const redacted = redact(unit.raw);
  const found = detectSecurityFindings({
    kind: "tool_output",
    text: redacted,
    ...(unit.tool_name === undefined ? {} : { tool_name: unit.tool_name }),
  });
  // The marker set is guard/armed.ts' INJECTION_MARKER_DETECTORS — the same
  // one the gateway arms a connection on — so the three surfaces agree.
  const hit = found.find((f) => INJECTION_MARKER_DETECTORS.has(f.detector));
  if (hit) return hit.key_name ? `${hit.detector} (${hit.key_name})` : hit.detector;
  if (unit.tool_name?.startsWith("mcp__")) {
    const poisoned = scanMcpToolOutput(redacted, unit.tool_name)[0];
    if (poisoned) return `mcp_tool_poisoning (${poisoned.key_name.split(" · ", 1)[0]})`;
  }
  return undefined;
}

/** What this unit DOES, if anything a rule cares about. */
function classifySinks(unit: DetectUnit, command: string | undefined): Sink[] {
  const sinks: Sink[] = [];
  const tool = unit.tool_name;
  if (command !== undefined) {
    const network = networkInvocationIn(command);
    if (network !== undefined) {
      sinks.push({ kind: "egress", name: network, excerpt: commandExcerpt(command) });
    }
    const exec = execInvocationIn(command);
    if (exec !== undefined) {
      sinks.push({ kind: "exec", name: "shell execution", excerpt: commandExcerpt(command) });
    }
    const spend = spendInvocationIn(command);
    if (spend !== undefined) {
      sinks.push({
        kind: "spend",
        name: spend.replace(/^\s+/, "").split(/\s+/).slice(0, 2).join(" "),
        excerpt: commandExcerpt(command),
      });
    }
    const installArgs = installArgsIn(command);
    if (installArgs !== undefined) {
      const packages = packagesNamed(installArgs);
      if (packages.length > 0) {
        sinks.push({ kind: "install", name: `install ${packages.join(" ")}`.slice(0, 80), excerpt: commandExcerpt(command) });
      }
    }
    const sql = sqlInterpolatingHead(command);
    if (sql !== undefined) {
      sinks.push({ kind: "sql", name: programOf(sql.replace(/["']/g, "")), excerpt: commandExcerpt(command) });
    }
    // A read, not a mention; `-i <key>` is how ssh/scp/rsync authenticate.
    const read = secretPathReadIn(command);
    if (read !== undefined) {
      sinks.push({ kind: "secret_read", name: `read ${read.name}`, excerpt: commandExcerpt(command) });
    }
  } else if (tool) {
    const toolExcerpt = `${tool}${unit.target ? ` ${collapse(unit.target).slice(0, 80)}` : ""}`;
    if (FETCH_TOOL_RE.test(tool)) sinks.push({ kind: "egress", name: tool, excerpt: toolExcerpt });
    if (mcpServerOf(tool) && SEND_TOOL_RE.test(tool)) {
      sinks.push({ kind: "send", name: tool, excerpt: toolExcerpt });
    }
    // A file write is a sink only for the taints that name what must appear in
    // it (external_address); no rule pairs an unqualified write with anything.
    if (isWriteTool(tool)) {
      sinks.push({ kind: "write", name: `write ${unit.target ? collapse(unit.target).split("/").pop() ?? "file" : "file"}`, excerpt: toolExcerpt });
    }
    if (unit.target !== undefined) {
      for (const [name, pattern] of SECRET_PATH_PATTERNS) {
        if (!pattern.test(unit.target)) continue;
        sinks.push({ kind: "secret_read", name: `read ${name}`, excerpt: toolExcerpt });
        break;
      }
    }
  }
  return sinks;
}

/** Units in time order. By parsed instant, not ISO string: `…10:00:00Z` sorts
 * AFTER `…10:00:00.500Z` as text, and a `+02:00` offset breaks it outright.
 * Stable, so same-instant units keep their emission order. */
function byTime(units: readonly DetectUnit[]): DetectUnit[] {
  const at = (u: DetectUnit) => {
    const ms = Date.parse(u.at);
    return Number.isFinite(ms) ? ms : Number.POSITIVE_INFINITY;
  };
  return [...units].sort((a, b) => at(a) - at(b));
}

/**
 * Evaluate the session-flow rules over one session's units, in one pass.
 *
 * Idempotent by construction: the caller re-runs it over the whole re-parsed
 * file and identical flows produce identical key_names, which the findings
 * ledger merges (occurrences take max). Units are sorted by timestamp here so
 * the caller doesn't have to care about parser emission order.
 */
export function evaluateFlowFindings(
  units: readonly DetectUnit[],
  options: FlowOptions = {},
): FlowFinding[] {
  const familiesIn = options.familiesIn ?? ((unit: DetectUnit) => credentialFamiliesInOutput(unit.raw));
  const injectionIn = options.injectionIn ?? injectionMarkerIn;
  const secretsIn = options.secretsIn ?? ((unit: DetectUnit) => extractRedactedSecrets(unit.raw));
  const ignored = securityIgnoreMatcher(options.ignore);
  const customRules = (options.customRules ?? []).filter((r) => r.after !== undefined);

  const ordered = byTime(units);
  const findings = new Map<string, FlowFinding>();
  let taints: Taint[] = [];
  let callIndex = 0;
  // Did the most recent tool_call fetch from outside? Its tool_output is then
  // fetched content. Units are ordered, and a result follows its call — the
  // one approximation is parallel tool calls, where a result may follow a
  // different call; the cost is a missed pairing, never a false one, because
  // the install must still NAME a package the text contained.
  const outside = new OutsideTracker();
  // The secret taints the most recent call minted from a PATH (a `.env`, an
  // env dump, a secret manager): its output holds the values a later egress
  // would have to carry, so the output unit fills in their link.
  let pendingSecretReads: Taint[] = [];

  for (const unit of ordered) {
    const atMs = Date.parse(unit.at);
    if (!Number.isFinite(atMs)) continue;
    if (unit.kind === "prompt") continue;

    if (unit.kind === "tool_call") callIndex += 1;
    taints = taints.filter(
      (t) => callIndex - t.callIndex <= FLOW_MAX_GAP_CALLS && atMs - t.atMs <= FLOW_MAX_GAP_MS,
    );

    const command = unit.kind === "tool_call" ? commandOf(unit) : undefined;

    // ── Sink first, source second: a unit that is BOTH (cat .env | curl) must
    // not pair with itself — that exact shape is per-unit secret_egress's.
    if (unit.kind === "tool_call" && taints.length > 0) {
      // Self-pairing is structurally impossible: a unit is examined as a sink
      // BEFORE it can register its own taint, so `cat .env | curl …` in one
      // command stays per-unit secret_egress's finding, not a flow.
      for (const sink of classifySinks(unit, command)) {
        for (const taint of taints) {
          const rule = FLOW_RULES.find((r) => r.taint === taint.kind && r.sink === sink.kind);
          if (!rule) continue;
          // "Fetched X, then ran X" — see Taint.requiresMention. A write has no
          // command, so its payload (the raw tool input) is the haystack; the
          // fold to lower case is for EVM addresses, whose EIP-55 casing is
          // cosmetic and a copy may drop.
          if (
            taint.requiresMention !== undefined &&
            !(command ?? unit.raw).toLowerCase().includes(taint.requiresMention.toLowerCase())
          ) {
            continue;
          }
          // "The page named X, then X was installed" — see Taint.mentions.
          if (taint.mentions !== undefined) {
            const named = sink.kind === "install" ? packagesNamed(installArgsIn(command ?? "") ?? "") : [];
            if (!named.some((pkg) => mentioned(taint.mentions!, pkg))) continue;
          }
          // "Downloaded X, then RAN X" — see Taint.requiresInvocation.
          if (
            taint.requiresInvocation &&
            taint.requiresMention !== undefined &&
            !(command !== undefined && invokesFile(command, taint.requiresMention))
          ) {
            continue;
          }
          // "Read a secret, then SENT it" — see Taint.link. A secret taint
          // pairs only with an egress that carries the value, the file, a
          // copy of the file or the variable it was captured in.
          if (taint.kind === "secret") {
            const payload = command === undefined ? unit.raw : `${command}\n${unit.raw}`;
            if (taint.link === undefined || !carriesLink(taint.link, payload)) continue;
          }
          const key = `${taint.name} → ${sink.name}`;
          const id = `${rule.detector} ${key}`;
          const existing = findings.get(id);
          if (existing) {
            // One sink unit counts once, however many live taints it pairs with.
            if (existing.sink_turn_id === unit.turn_id && existing.at === unit.at) continue;
            existing.occurrences += 1;
            if (Date.parse(unit.at) > Date.parse(existing.at)) {
              existing.at = unit.at;
              existing.sink_turn_id = unit.turn_id;
            }
            continue;
          }
          const candidate: FlowFinding = {
            detector: rule.detector,
            severity: rule.severity,
            key_name: key,
            excerpt: sanitizeExcerpt(`${taint.excerpt} ⇢ ${sink.excerpt}`).slice(0, FLOW_EXCERPT_MAX),
            occurrences: 1,
            ...(unit.tool_name === undefined ? {} : { tool_name: unit.tool_name }),
            ...(unit.target === undefined ? {} : { target: unit.target }),
            session_id: unit.session_id,
            source_turn_id: taint.turn_id,
            sink_turn_id: unit.turn_id,
            source_at: taint.at,
            at: unit.at,
          };
          // A rule scoped to the flow's own id, or to the per-unit detector it
          // is the staged form of (FLOW_PARENT_DETECTOR), or unscoped. The
          // source's file joins the target for MATCHING only, so a rule
          // naming the fixture a value came from silences the pair.
          // The cast widens the parameter, not the semantics.
          const probe = {
            ...candidate,
            target: [candidate.target, taint.sourceTarget].filter((t) => t !== undefined && t !== "").join(" "),
          } as unknown as Parameters<typeof ignored>[0];
          const parent = FLOW_PARENT_DETECTOR[rule.detector];
          if (ignored(probe) || (parent !== undefined && ignored({ ...probe, detector: parent } as typeof probe))) continue;
          findings.set(id, candidate);
        }
      }
      // ── The person's own flow rules: a live taint of the named kind, and a
      //    call that satisfies the rule's `when`. Same window, same identity
      //    discipline; the excerpt pairs the taint with what the call was.
      for (const rule of customRules) {
        if (!rule.after || !rule.when || rule.enabled === false) continue;
        if (!ruleAppliesToCwd(rule, unit.cwd)) continue;
        const taint = taints.find((t) => t.kind === rule.after!.taint);
        if (!taint) continue;
        const toolInput = parsedInput(unit);
        if (
          !customWhenMatches(rule, {
            tool_name: unit.tool_name,
            tool_input: toolInput,
            command: command === undefined ? undefined : redact(command),
            target: unit.target,
            cwd: unit.cwd,
            redacted: redact(unit.raw).slice(0, 400),
          })
        ) {
          continue;
        }
        const detector = customDetectorId(rule.id);
        const key = `${taint.name} → ${rule.label}`;
        const id = `${detector} ${key}`;
        const existing = findings.get(id);
        if (existing) {
          // One sink unit counts once, however many live taints it pairs with.
          if (existing.sink_turn_id === unit.turn_id && existing.at === unit.at) continue;
          existing.occurrences += 1;
          if (Date.parse(unit.at) > Date.parse(existing.at)) {
            existing.at = unit.at;
            existing.sink_turn_id = unit.turn_id;
          }
          continue;
        }
        const sinkExcerpt =
          command !== undefined
            ? commandExcerpt(command)
            : `${unit.tool_name ?? "tool"}${unit.target ? ` ${collapse(unit.target).slice(0, 60)}` : ""}`;
        findings.set(id, {
          detector,
          detector_label: rule.label,
          severity: rule.severity,
          key_name: key,
          excerpt: sanitizeExcerpt(`${taint.excerpt} ⇢ ${sinkExcerpt}`).slice(0, FLOW_EXCERPT_MAX),
          occurrences: 1,
          ...(unit.tool_name === undefined ? {} : { tool_name: unit.tool_name }),
          ...(unit.target === undefined ? {} : { target: unit.target }),
          session_id: unit.session_id,
          source_turn_id: taint.turn_id,
          sink_turn_id: unit.turn_id,
          source_at: taint.at,
          at: unit.at,
        });
      }
    }

    // ── Source classification: this unit starts (or refreshes) a taint.
    if (unit.kind === "tool_call") {
      // A command taints by what it READS (secretPathReadIn — a mention, an
      // `rm .env` or an ssh `-i <key>` is not a read); any other tool by the
      // path it targets.
      const secretRead =
        command !== undefined
          ? secretPathReadIn(command)?.name
          : unit.target !== undefined && unit.target !== ""
            ? SECRET_PATH_PATTERNS.find(([, pattern]) => pattern.test(unit.target!))?.[0]
            : undefined;
      // Remember whether this call FETCHED (and what it landed), so the
      // tool_output that follows can register its words as fetched content and
      // a later Read of the download counts as outside (see OutsideTracker).
      const landedAny =
        command !== undefined && networkInvocationIn(command) !== undefined ? fetchLandedPath(command) : undefined;
      outside.observeCall(unit, command, landedAny);
      pendingSecretReads = [];
      // A fetch-shaped TOOL (WebFetch, mcp__fetch__*) pointed at a runnable
      // file: the same "downloaded X" taint a `curl -o X` mints, keyed on the
      // basename a later command would have to name.
      if (command === undefined && unit.tool_name !== undefined && FETCH_TOOL_RE.test(unit.tool_name)) {
        const url = fetchUrlOf(unit);
        const script = url === undefined ? undefined : scriptBasenameOf(url);
        if (script !== undefined && !targetsOnlyLocalHosts(url!)) {
          taints.push({
            kind: "untrusted_fetch",
            requiresMention: script,
            requiresInvocation: true,
            name: `fetched ${script}`,
            turn_id: unit.turn_id,
            at: unit.at,
            callIndex,
            atMs,
            excerpt: `${unit.tool_name} ${sanitizeExcerpt(collapse(redact(url!))).slice(0, 90)}`,
          });
        }
      }
      // A write that introduced a known-dangerous construct: running THAT file
      // later is the second half. The per-unit detector already judged the
      // payload; this only asks whether it fired, over the pre-redaction text.
      if (command === undefined && unit.tool_name !== undefined && isWriteTool(unit.tool_name) && unit.target) {
        const insecure = detectSecurityFindings({
          kind: "tool_call",
          text: redact(unit.raw),
          raw_text: unit.raw,
          tool_name: unit.tool_name,
          target: unit.target,
        }).find((f) => f.detector === "insecure_code_written");
        const base = unit.target.split("/").pop();
        // Test code and fixtures are excluded: a detector's own test writes
        // `shell=True` ON PURPOSE, and running the suite is not running it —
        // all 15 rows of this rule in one ledger were exactly that.
        if (insecure && base && /^[A-Za-z0-9_@.-]+\.[A-Za-z0-9]{1,5}$/.test(base) && !TEST_FILE_RE.test(unit.target)) {
          taints.push({
            kind: "insecure_code",
            requiresMention: base,
            name: `wrote ${base} (${insecure.key_name ?? "insecure code"})`,
            turn_id: unit.turn_id,
            at: unit.at,
            callIndex,
            atMs,
            excerpt: `${unit.tool_name} ${collapse(unit.target).slice(0, 80)}`,
          });
        }
      }
      // An MCP database tool's statement returns rows exactly as `psql` does.
      if (command === undefined && readSqlArg(unit.raw, unit.tool_name) !== undefined) {
        taints.push({
          kind: "sql_result",
          name: "database result",
          turn_id: unit.turn_id,
          at: unit.at,
          callIndex,
          atMs,
          excerpt: `${unit.tool_name ?? "tool"} ran a query`,
        });
      }
      if (secretRead !== undefined) {
        // The link: the secret file itself, and any file this very command
        // copied it into (`cat .env > /tmp/x`, `cp .env b`). The values it
        // printed join when its output arrives (pendingSecretReads).
        const link = emptyLink();
        const pattern = SECRET_PATH_PATTERNS.find(([name]) => name === secretRead)?.[1];
        if (pattern !== undefined) link.paths.push(pattern);
        if (command !== undefined) for (const path of writtenPaths(command)) link.carriers.add(path);
        const taint: Taint = {
          kind: "secret",
          name: secretRead,
          link,
          ...(unit.target === undefined ? {} : { sourceTarget: unit.target }),
          turn_id: unit.turn_id,
          at: unit.at,
          callIndex,
          atMs,
          excerpt: command !== undefined ? commandExcerpt(command) : `${unit.tool_name ?? "tool"} read ${secretRead}`,
        };
        taints.push(taint);
        pendingSecretReads.push(taint);
      }
      // Fetching a NON-local URL brings text from outside onto this machine —
      // the first half of fetch→exec. (The one-command form, `curl … | sh`, is
      // per-unit unsafe_fetch_exec's; this is the staged version.)
      //
      // The fetch must LAND SOMETHING RUNNABLE, which is the whole difference
      // between this rule and noise: `curl -o setup.sh`, a `> file` redirect,
      // wget (which saves by default), or a URL whose path ends in a script
      // extension. A plain `curl https://api.example/graphql` in a dev session
      // is an API call, and treating every one of them as untrusted content
      // raised 50 rows of nothing in a 14-day corpus.
      const landed =
        command !== undefined && networkInvocationIn(command) !== undefined
          ? fetchLandedPath(command)
          : undefined;
      if (landed !== undefined && command !== undefined) {
        taints.push({
          kind: "untrusted_fetch",
          requiresMention: landed,
          requiresInvocation: true,
          name: `downloaded ${landed}`,
          turn_id: unit.turn_id,
          at: unit.at,
          callIndex,
          atMs,
          excerpt: commandExcerpt(command),
        });
      }
      // A read from an MCP server holding the person's own data (mail, chat,
      // docs, tracker) — the inbox half of Invariant's canonical
      // read-then-send rule.
      const server = mcpServerOf(unit.tool_name);
      if (server && PRIVATE_DATA_SERVER_RE.test(server) && READ_TOOL_RE.test(unit.tool_name!)) {
        taints.push({
          kind: "private_data",
          name: `${server} data`,
          turn_id: unit.turn_id,
          at: unit.at,
          callIndex,
          atMs,
          excerpt: `${unit.tool_name}${unit.target ? ` ${collapse(unit.target).slice(0, 60)}` : ""}`,
        });
      }
      // A database client call: whatever it returns can be interpolated into a
      // LATER query — second-order SQL injection.
      if (command !== undefined && sqlClientHeads(command).length > 0) {
        taints.push({
          kind: "sql_result",
          name: "database result",
          turn_id: unit.turn_id,
          at: unit.at,
          callIndex,
          atMs,
          excerpt: commandExcerpt(command),
        });
      }
      if (command !== undefined && envDumpIn(command) !== undefined) {
        const link = emptyLink();
        for (const path of writtenPaths(command)) link.carriers.add(path);
        for (const name of capturedVars(command)) link.vars.add(name);
        const taint: Taint = {
          kind: "secret",
          name: "environment",
          link,
          turn_id: unit.turn_id,
          at: unit.at,
          callIndex,
          atMs,
          excerpt: commandExcerpt(command),
        };
        taints.push(taint);
        pendingSecretReads.push(taint);
      }
      // A secret manager returning plaintext is the strongest COMMAND-side
      // source there is — stronger than a path read, since the call only
      // exists to hand back a live credential. The per-unit detector records
      // the read; this makes it taint a later egress.
      const manager = command === undefined ? undefined : secretManagerReadIn(command);
      if (manager !== undefined) {
        const link = emptyLink();
        for (const path of writtenPaths(command!)) link.carriers.add(path);
        for (const name of capturedVars(command!)) link.vars.add(name);
        const taint: Taint = {
          kind: "secret",
          name: manager,
          link,
          turn_id: unit.turn_id,
          at: unit.at,
          callIndex,
          atMs,
          excerpt: commandExcerpt(command!),
        };
        taints.push(taint);
        pendingSecretReads.push(taint);
      }
    } else if (unit.kind === "tool_output") {
      // (Judged BEFORE the fetched-content branch below, which consumes the
      // lastCallFetched flag.) A wallet address that ARRIVED from outside — in the answer to a fetch,
      // a network command or any MCP tool. Not a finding on its own (an address
      // is public); the taint that makes "the agent wrote an address" into "the
      // agent wrote the address a page told it to". Reads of the repository's
      // own files are excluded: that is the project talking, not the internet.
      const fromOutside = outside.isOutside(unit);
      // The secret reads the call that this output answers made: what it
      // printed is what a later egress would have to carry.
      if (pendingSecretReads.length > 0 && !isHarnessTool(unit.tool_name)) {
        // Both what the redactor recognised and what the file's own
        // KEY=VALUE shape says is a value (secretFileValues).
        const recognised = secretsIn(unit)
          .filter((s) => s.label !== "" && !NON_CREDENTIAL_FAMILIES.has(s.label))
          .map((s) => s.value);
        const values = [...recognised, ...secretFileValues(unit.raw)];
        for (const taint of pendingSecretReads) for (const value of values) addLinkValue(taint.link!, value);
        pendingSecretReads = [];
      }
      if (fromOutside) {
        const seen = new Set<string>();
        for (const hit of findWalletAddresses(unit.raw.slice(0, MAX_SCAN_CHARS), DEFAULT_WALLET_CHAINS)) {
          if (hit.confidence === "low" || isKnownContractAddress(hit.chain, hit.value)) continue;
          const key = `${hit.chain}:${hit.value.toLowerCase()}`;
          if (seen.has(key)) continue;
          seen.add(key);
          const chainLabel = WALLET_CHAIN_LABELS[hit.chain];
          taints.push({
            kind: "external_address",
            requiresMention: hit.value,
            name: `${chainLabel} address from ${unit.tool_name ?? "a tool"}`,
            turn_id: unit.turn_id,
            at: unit.at,
            callIndex,
            atMs,
            // The value never enters the excerpt: the row says an address came
            // back and from where, which is all a reader needs to act.
            excerpt: `${unit.tool_name ?? "a tool"} returned a ${chainLabel} address [redacted]`,
          });
        }
      }
      // Text that arrived from outside, remembered as the words it contained —
      // the taint an install can be measured against. Only when the call it
      // answers actually fetched (a WebFetch, a curl); a `cat README` is this
      // repository talking, not the internet.
      if (outside.consumeFetch(unit)) {
        taints.push({
          kind: "fetched_content",
          mentions: mentionsIn(unit.raw),
          name: `content fetched by ${unit.tool_name ?? "a tool"}`,
          turn_id: unit.turn_id,
          at: unit.at,
          callIndex,
          atMs,
          excerpt: `${unit.tool_name ?? "a tool"} returned ${sanitizeExcerpt(collapse(redact(unit.raw))).slice(0, 80)}`,
        });
      }
      // A credential in what a tool printed. Harness bookkeeping is excluded
      // (FLOW_HARNESS_TOOLS), and the taint carries the values themselves, so
      // it pairs only with an egress that sends one of them.
      const families = isHarnessTool(unit.tool_name) ? [] : familiesIn(unit);
      if (families.length > 0) {
        const secrets = secretsIn(unit);
        const call = outside.call;
        const from = sourceDescription(call, unit.tool_name);
        for (const family of families) {
          const link = emptyLink();
          for (const value of credentialValues(secrets, family)) addLinkValue(link, value);
          taints.push({
            kind: "secret",
            name: `${familyPhrase(family)} in ${from}`,
            link,
            ...(call.target === undefined ? {} : { sourceTarget: call.target }),
            turn_id: unit.turn_id,
            at: unit.at,
            callIndex,
            atMs,
            excerpt: `${unit.tool_name ?? "a tool"} returned [redacted:${family}]`,
          });
        }
      }
      // Text from OUTSIDE that told the agent to do something. What the agent
      // does next is the finding — this is the taint that makes "an injection
      // arrived" into "an injection was obeyed". A local file saying "ignore
      // all previous instructions" (a detector's own test, a README) is the
      // project talking; only an answer from outside can be an injection.
      const marker = fromOutside ? injectionIn(unit) : undefined;
      if (marker !== undefined) {
        taints.push({
          kind: "injection",
          name: `injected instruction (${marker})`,
          turn_id: unit.turn_id,
          at: unit.at,
          callIndex,
          atMs,
          excerpt: `${unit.tool_name ?? "a tool"} returned ${marker}`,
        });
      }
    }
  }

  return [
    ...findings.values(),
    ...evaluateLoopFindings(ordered, ignored),
    ...evaluateUnknownServers(ordered, options.approvedMcpServers, ignored),
  ];
}

/** What the guard-side armed file carries per taint (guard/armed.ts mirrors
 * this shape; it cannot import it — the guard bundle is self-contained). */
export interface ArmedInjectionTaint {
  name: string;
  at: string;
  excerpt: string;
}

/**
 * The injection taints still LIVE at the end of a session's unit list — what
 * arms the guard's next-call escalation (guard/armed.ts). Same sources and the
 * same staleness bounds as the flow pass above, evaluated relative to the
 * session's last unit; the wall-clock half is re-checked by the guard at read
 * time, so a session that simply stopped doesn't stay armed forever.
 */
export function armedInjectionTaints(
  units: readonly DetectUnit[],
  options: Pick<FlowOptions, "injectionIn"> = {},
): ArmedInjectionTaint[] {
  const injectionIn = options.injectionIn ?? injectionMarkerIn;
  const ordered = byTime(units);
  const taints: (ArmedInjectionTaint & { callIndex: number; atMs: number })[] = [];
  let callIndex = 0;
  let lastMs = Number.NaN;
  // The same outsideness the flow pass uses: a local Read of a file that
  // SAYS "ignore all previous instructions" must not arm the guard to hold
  // the next curl at critical.
  const outside = new OutsideTracker();
  for (const unit of ordered) {
    const atMs = Date.parse(unit.at);
    if (!Number.isFinite(atMs)) continue;
    if (unit.kind === "prompt") continue;
    if (unit.kind === "tool_call") {
      callIndex += 1;
      const command = commandOf(unit);
      const landed =
        command !== undefined && networkInvocationIn(command) !== undefined
          ? fetchLandedPath(command)
          : undefined;
      outside.observeCall(unit, command, landed);
    }
    lastMs = atMs;
    if (unit.kind !== "tool_output") continue;
    if (!outside.isOutside(unit)) continue;
    const marker = injectionIn(unit);
    if (marker === undefined) continue;
    taints.push({
      name: `injected instruction (${marker})`,
      at: unit.at,
      excerpt: `${unit.tool_name ?? "a tool"} returned ${marker}`,
      callIndex,
      atMs,
    });
  }
  const lastCall = callIndex;
  return taints
    .filter(
      (t) =>
        lastCall - t.callIndex <= FLOW_MAX_GAP_CALLS &&
        (!Number.isFinite(lastMs) || lastMs - t.atMs <= FLOW_MAX_GAP_MS),
    )
    .map(({ name, at, excerpt }) => ({ name, at, excerpt }));
}

/**
 * An MCP server nobody approved.
 *
 * The prevention half of `mcp_tool_poisoning`: that detector reads a poisoned
 * server's strings, this asks whether the server had any business being
 * connected. Off unless the org published a list — see FlowOptions.
 *
 * Matching is case-insensitive on the server segment of `mcp__<server>__<tool>`,
 * which is what Claude Code derives from the config key, so an org lists the
 * same names it wrote in `mcpServers`.
 */
function evaluateUnknownServers(
  ordered: readonly DetectUnit[],
  approved: readonly string[] | undefined,
  ignored: ReturnType<typeof securityIgnoreMatcher>,
): FlowFinding[] {
  if (!approved || approved.length === 0) return [];
  const allowed = new Set(approved.map((s) => s.trim().toLowerCase()));
  const findings = new Map<string, FlowFinding>();
  for (const unit of ordered) {
    if (unit.kind !== "tool_call") continue;
    const server = mcpServerOf(unit.tool_name);
    if (!server || allowed.has(server.toLowerCase())) continue;
    const existing = findings.get(server);
    if (existing) {
      existing.occurrences += 1;
      if (Date.parse(unit.at) > Date.parse(existing.at)) {
        existing.at = unit.at;
        existing.sink_turn_id = unit.turn_id;
      }
      continue;
    }
    const candidate: FlowFinding = {
      detector: "unknown_mcp_server",
      severity: "medium",
      key_name: server,
      excerpt: `${unit.tool_name} — "${server}" is not on your recognized list`,
      occurrences: 1,
      ...(unit.tool_name === undefined ? {} : { tool_name: unit.tool_name }),
      session_id: unit.session_id,
      source_turn_id: unit.turn_id,
      sink_turn_id: unit.turn_id,
      source_at: unit.at,
      at: unit.at,
    };
    if (ignored(candidate as unknown as Parameters<typeof ignored>[0])) continue;
    findings.set(server, candidate);
  }
  return [...findings.values()];
}

/**
 * A stuck agent: the same tool call, byte-identical arguments, run over and
 * over with nothing changing in between.
 *
 * Not a security finding in the exfiltration sense — Invariant files this under
 * "agent bugs" — but it belongs on this screen for a reason no other rule here
 * has: it costs MONEY, every iteration, and this app's whole premise is knowing
 * what the agents spend. The caller prices the run (`source_at`..`at`) and
 * states the burn on the card, which is the part a spend monitor can say and a
 * pure security tool cannot.
 *
 * CONSECUTIVE is the whole discipline. The same command run four times across a
 * session is ordinary work (`npm test` after each fix); four times in a row with
 * identical arguments and no other call between is the agent not making
 * progress.
 */
export const AGENT_LOOP_MIN_REPEATS = 4;

function evaluateLoopFindings(
  ordered: readonly DetectUnit[],
  ignored: ReturnType<typeof securityIgnoreMatcher>,
): FlowFinding[] {
  const calls = ordered.filter((u) => u.kind === "tool_call");
  const findings = new Map<string, FlowFinding>();
  let runStart = 0;
  for (let i = 1; i <= calls.length; i += 1) {
    const previous = calls[i - 1]!;
    const current = i < calls.length ? calls[i] : undefined;
    const same =
      current !== undefined &&
      current.tool_name === previous.tool_name &&
      current.raw === previous.raw;
    if (same) continue;

    const length = i - runStart;
    if (length >= AGENT_LOOP_MIN_REPEATS) {
      const first = calls[runStart]!;
      const last = previous;
      const command = commandOf(first);
      // The key names the CALL, never the run length — a longer run of the same
      // loop must merge into the same row, with occurrences carrying the count.
      const key = `${first.tool_name ?? "tool"}${first.target ? ` ${collapse(first.target).slice(0, 60)}` : ""}`;
      const candidate: FlowFinding = {
        detector: "agent_loop",
        severity: "medium",
        key_name: key,
        excerpt: sanitizeExcerpt(
          `${length}× identical: ${command !== undefined ? commandExcerpt(command) : key}`,
        ).slice(0, FLOW_EXCERPT_MAX),
        occurrences: length,
        ...(first.tool_name === undefined ? {} : { tool_name: first.tool_name }),
        ...(first.target === undefined ? {} : { target: first.target }),
        session_id: first.session_id,
        source_turn_id: first.turn_id,
        sink_turn_id: last.turn_id,
        source_at: first.at,
        at: last.at,
      };
      const existing = findings.get(key);
      // Several runs of the same call in one session: keep the WORST (longest),
      // so the card describes the run actually worth looking at.
      if (!existing || length > existing.occurrences) {
        if (!ignored(candidate as unknown as Parameters<typeof ignored>[0])) {
          findings.set(key, candidate);
        }
      }
    }
    runStart = i;
  }
  // ── The retry loop: the same COMMAND STEM (program + first word — `npm
  // test`, `pytest`, `python run.py`) run over and over with the flags changed
  // each time and nothing else between. Invariant's agent_bugs notebook
  // filters SWE-agent traces for the `scroll_down` run; this is the shell
  // shape of it. A higher bar than the identical loop (eight, not four), shell
  // calls only, and the batch verbs excluded — `sed -i` over six files or
  // `git add` over six paths is bulk work, not a stuck agent.
  let varyStart = 0;
  for (let i = 1; i <= calls.length; i += 1) {
    const previous = calls[i - 1]!;
    const current = i < calls.length ? calls[i] : undefined;
    const previousStem = commandStem(previous);
    const same =
      current !== undefined &&
      current.tool_name === previous.tool_name &&
      previousStem !== undefined &&
      commandStem(current) === previousStem;
    if (same) continue;
    const length = i - varyStart;
    const first = calls[varyStart]!;
    const stem = commandStem(first);
    if (length >= AGENT_LOOP_VARYING_MIN_REPEATS && stem !== undefined) {
      const distinct = new Set(calls.slice(varyStart, i).map((c) => c.raw)).size;
      if (distinct > 1) {
        const key = `${first.tool_name ?? "tool"} ${stem} (varying arguments)`;
        const candidate: FlowFinding = {
          detector: "agent_loop",
          severity: "medium",
          key_name: key,
          excerpt: sanitizeExcerpt(`${length}× ${stem}, ${distinct} different argument sets`).slice(0, FLOW_EXCERPT_MAX),
          occurrences: length,
          ...(first.tool_name === undefined ? {} : { tool_name: first.tool_name }),
          ...(first.target === undefined ? {} : { target: first.target }),
          session_id: first.session_id,
          source_turn_id: first.turn_id,
          sink_turn_id: previous.turn_id,
          source_at: first.at,
          at: previous.at,
        };
        const existing = findings.get(key);
        if ((!existing || length > existing.occurrences) && !ignored(candidate as unknown as Parameters<typeof ignored>[0])) {
          findings.set(key, candidate);
        }
      }
    }
    varyStart = i;
  }
  return [...findings.values()];
}

export const AGENT_LOOP_VARYING_MIN_REPEATS = 8;

/** Programs whose repetition with different arguments is bulk work by nature. */
const BATCH_VERBS: ReadonlySet<string> = new Set([
  "echo", "printf", "sed", "git", "mkdir", "cp", "mv", "touch", "cat", "ls", "rm", "chmod", "chown",
  "ln", "grep", "rg", "find", "head", "tail", "wc", "sort", "cd", "pwd", "which", "test", "true", "false",
]);

/** `program firstWord` of a shell call, or undefined for non-shell calls and batch verbs. */
function commandStem(unit: DetectUnit): string | undefined {
  const command = commandOf(unit);
  if (command === undefined) return undefined;
  const words = command.trim().replace(/^(?:sudo|time|env)\s+/, "").split(/\s+/);
  const program = (words[0] ?? "").split("/").pop() ?? "";
  if (program === "" || BATCH_VERBS.has(program)) return undefined;
  const second = words[1] !== undefined && !words[1].startsWith("-") ? ` ${words[1]}` : "";
  return `${program}${second}`.slice(0, 80);
}
