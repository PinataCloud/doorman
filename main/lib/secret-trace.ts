/**
 * SECRET TRACE — the Radar's question run backwards.
 *
 * The Radar starts from a rule and says "a credential was exposed here". This
 * starts from the CREDENTIAL — the key a provider just emailed you about, the
 * password you are about to rotate, the token you found in a paste — and says
 * everywhere an AI tool on this Mac has touched it: which sessions, in whose
 * prompt or which tool call, written to which file, run in which command,
 * returned by which read, and what the guard did about each.
 *
 * It can only be answered here, on the machine. The findings ledger stores a
 * masked excerpt and a NAME, never the value and never a hash of it (a stored
 * digest would be an offline oracle for a guess — guard/security-detect.ts).
 * So nothing is looked up; the transcripts the agents wrote to disk and the
 * local turn store are re-read and searched for the literal, exactly the way
 * the reveal re-reads one transcript for one finding (lib/reveal.ts).
 *
 * What leaves this module about the value: its LENGTH, its LAST FEW
 * CHARACTERS, and the redaction family it matches. Never the value. The
 * renderer keeps the pasted text only until the answer arrives, the report
 * the assistant reads is built from this masked shape, and nothing here logs.
 *
 * Pure: the engine (capture.ts) walks the files and hands in sightings; this
 * turns them into the report the screen and the assistant both read.
 */

import { redact } from "../guard/redact.js";
import type { FindingRow } from "./findings.js";
import { createPlaceResolver } from "./exposures.js";

/** Fewer characters than this match too much to say anything honest. */
export const TRACE_MIN_CHARS = 8;

/**
 * Take the pasted text down to the value. People paste what they have in
 * front of them — a whole `export KEY=…` line, an Authorization header, a
 * quoted string from a config — and every one of those wrappers would make
 * the literal search miss the bare value in a transcript.
 */
export function normalizeTraceInput(raw: string): { ok: true; value: string } | { ok: false; error: string } {
  let value = String(raw ?? "").trim();
  // `Authorization: Bearer x`, `Bearer x`
  value = value.replace(/^(?:authorization\s*:\s*)?bearer\s+/i, "");
  // `export KEY=x`, `KEY=x`, `key: x`, `"key": "x"` — only when the rest still
  // reads as a single value, so a pasted value that happens to contain `=`
  // (a base64 tail) is left alone.
  const assignment = /^(?:export\s+)?"?[A-Za-z_][A-Za-z0-9_.-]*"?\s*[=:]\s*(.+)$/s.exec(value);
  if (assignment && !/\s/.test(assignment[1]!.trim().replace(/^["'`]|["'`]$/g, ""))) value = assignment[1]!.trim();
  // Trailing punctuation from a copied line.
  value = value.replace(/[;,]+$/, "");
  // Matching quotes or backticks around the value.
  for (const q of ['"', "'", "`"]) {
    if (value.length >= 2 && value.startsWith(q) && value.endsWith(q)) value = value.slice(1, -1);
  }
  value = value.trim();
  if (value === "") return { ok: false, error: "Paste the value to trace." };
  if (/\s/.test(value)) {
    return {
      ok: false,
      error: "One value at a time — a secret has no spaces or line breaks in it. For a multi-line key, paste one line of it.",
    };
  }
  if (value.length < TRACE_MIN_CHARS) {
    return {
      ok: false,
      error: `Too short to trace safely — paste at least ${TRACE_MIN_CHARS} characters of it, or the whole value.`,
    };
  }
  return { ok: true, value };
}

export interface TraceShape {
  /** The redaction family the value matches on its own — "anthropic", "aws". */
  family?: string;
  /** Words for the family, or for the absence of one. */
  label: string;
  /** The only characters of the value that are ever shown or stored. */
  tail: string;
  length: number;
  /** Whether redact() would have replaced it — what a cloud upload carried. */
  recognized: boolean;
}

const FAMILY_LABELS: Record<string, string> = {
  anthropic: "Anthropic API key",
  openai: "OpenAI API key",
  openrouter: "OpenRouter API key",
  aws: "AWS access key",
  azure: "Azure credential",
  github: "GitHub token",
  gitlab: "GitLab token",
  slack: "Slack token",
  stripe: "Stripe key",
  google: "Google API key",
  groq: "Groq API key",
  xai: "xAI API key",
  perplexity: "Perplexity API key",
  huggingface: "Hugging Face token",
  linear: "Linear API key",
  npm: "npm token",
  pypi: "PyPI token",
  jwt: "JSON web token",
  private_key: "private key",
  url_credentials: "URL credentials",
  doorman: "Doorman API key",
  generic: "generic API key",
  email: "email address",
  cloudflare: "Cloudflare token",
  digitalocean: "DigitalOcean token",
  sendgrid: "SendGrid key",
  twilio: "Twilio credential",
  shopify: "Shopify token",
};

/** Where a family is rotated — the provider's own key console. */
const ROTATE_URLS: Record<string, { provider: string; url: string }> = {
  anthropic: { provider: "Anthropic", url: "https://console.anthropic.com/settings/keys" },
  openai: { provider: "OpenAI", url: "https://platform.openai.com/api-keys" },
  openrouter: { provider: "OpenRouter", url: "https://openrouter.ai/settings/keys" },
  aws: { provider: "AWS IAM", url: "https://console.aws.amazon.com/iam/home#/security_credentials" },
  github: { provider: "GitHub", url: "https://github.com/settings/tokens" },
  gitlab: { provider: "GitLab", url: "https://gitlab.com/-/user_settings/personal_access_tokens" },
  slack: { provider: "Slack", url: "https://api.slack.com/apps" },
  stripe: { provider: "Stripe", url: "https://dashboard.stripe.com/apikeys" },
  google: { provider: "Google Cloud", url: "https://console.cloud.google.com/apis/credentials" },
  groq: { provider: "Groq", url: "https://console.groq.com/keys" },
  xai: { provider: "xAI", url: "https://console.x.ai/" },
  perplexity: { provider: "Perplexity", url: "https://www.perplexity.ai/settings/api" },
  huggingface: { provider: "Hugging Face", url: "https://huggingface.co/settings/tokens" },
  linear: { provider: "Linear", url: "https://linear.app/settings/account/security" },
  pypi: { provider: "PyPI", url: "https://pypi.org/manage/account/token/" },
  cloudflare: { provider: "Cloudflare", url: "https://dash.cloudflare.com/profile/api-tokens" },
  digitalocean: { provider: "DigitalOcean", url: "https://cloud.digitalocean.com/account/api/tokens" },
  sendgrid: { provider: "SendGrid", url: "https://app.sendgrid.com/settings/api_keys" },
  twilio: { provider: "Twilio", url: "https://console.twilio.com/" },
};

const PLACEHOLDER_RE = /\[redacted(?::([a-z0-9_]+))?\]/;

export function familyLabel(family: string | undefined): string {
  if (!family) return "a shape redaction doesn't recognize";
  return FAMILY_LABELS[family] ?? `${family.replace(/_/g, " ")} credential`;
}

/**
 * What the value IS, without keeping it: run the redactor over it in a neutral
 * context and read the placeholder it leaves. A fragment (the tail a console
 * shows) usually matches no family — the shape needs its prefix — and says so.
 */
export function traceShape(value: string): TraceShape {
  const probe = ` ${value} `;
  const masked = redact(probe);
  const recognized = masked !== probe;
  const family = recognized ? (PLACEHOLDER_RE.exec(masked)?.[1] ?? undefined) : undefined;
  const tailLength = value.length >= 16 ? 4 : 2;
  return {
    ...(family ? { family } : {}),
    label: familyLabel(family),
    tail: value.slice(-tailLength),
    length: value.length,
    recognized,
  };
}

export type SightingKind = "prompt" | "assistant" | "tool_call" | "tool_output";
export type SightingOutcome = "blocked" | "held_allowed" | "held_denied" | "warned" | "observed";

/** One place the value appeared: a unit of a transcript, or a stored turn. */
export interface TraceSighting {
  session_id: string;
  /** The ledger turn to open — for a tool result, the call it answered. */
  turn_id: string;
  at: string;
  source: string;
  kind: SightingKind;
  tool_name?: string;
  target?: string;
  cwd?: string;
  /** One sentence: what happened to the value here. Built by describeSighting. */
  how: string;
  occurrences: number;
  /** The Radar row that saw the same call, when one did. */
  finding_id?: string;
  outcome: SightingOutcome;
}

/** What the engine hands in before findings are matched and the sentence is written. */
export type RawSighting = Omit<TraceSighting, "how" | "outcome" | "finding_id">;

const WRITE_TOOLS = new Set([
  "write",
  "edit",
  "multiedit",
  "notebookedit",
  "create_file",
  "write_file",
  "edit_file",
  "apply_patch",
  "str_replace_editor",
  "str_replace_based_edit_tool",
  "write_to_file",
  "replace_in_file",
  "insert_edit_into_file",
]);
const SHELL_TOOLS = new Set(["bash", "shell", "execute_command", "run_terminal_cmd", "terminal", "exec", "run_shell_command", "local_shell", "container.exec"]);
const READ_TOOLS = new Set(["read", "read_file", "view", "cat", "view_file", "read_files", "readfile"]);

function toolKind(toolName: string | undefined): "write" | "shell" | "read" | "mcp" | "other" {
  const name = (toolName ?? "").toLowerCase();
  if (name.startsWith("mcp__")) return "mcp";
  if (WRITE_TOOLS.has(name)) return "write";
  if (SHELL_TOOLS.has(name)) return "shell";
  if (READ_TOOLS.has(name)) return "read";
  return "other";
}

function mcpParts(toolName: string): { server: string; tool: string } {
  const parts = toolName.split("__");
  return { server: parts[1] ?? "unknown", tool: parts.slice(2).join("__") || "a tool" };
}

/** Whether a tool target is a path rather than a program name. */
function isPath(target: string | undefined): target is string {
  return !!target && (target.startsWith("/") || target.startsWith("~") || target.startsWith("."));
}

/**
 * The sentence for a sighting — what happened to the value, in the words the
 * person would use. "Written to .env" is a place to go and delete it from;
 * "Returned by reading ~/.aws/credentials" says the agent read a file it
 * should not have; "In your prompt" says you pasted it yourself.
 */
export function describeSighting(s: Pick<RawSighting, "kind" | "tool_name" | "target">, home?: string): string {
  const short = (p: string) => shortFile(p, home);
  if (s.kind === "prompt") return "In your prompt";
  if (s.kind === "assistant") return "In the assistant's reply";
  const kind = toolKind(s.tool_name);
  if (s.kind === "tool_call") {
    if (kind === "write") return isPath(s.target) ? `Written to ${short(s.target)}` : "Written to a file";
    if (kind === "shell") return s.target && !isPath(s.target) ? `In a ${s.target} command` : "In a shell command";
    if (kind === "mcp") {
      const { server, tool } = mcpParts(s.tool_name!);
      return `Sent to MCP server ${server} (${tool})`;
    }
    if (kind === "read") return isPath(s.target) ? `In a read of ${short(s.target)}` : "In a read call";
    return s.tool_name ? `In a ${s.tool_name} call` : "In a tool call";
  }
  // tool_output
  if (kind === "read") return isPath(s.target) ? `Returned by reading ${short(s.target)}` : "Returned by a file read";
  if (kind === "write") return isPath(s.target) ? `Echoed back after writing ${short(s.target)}` : "Echoed back by a file write";
  if (kind === "shell") return s.target && !isPath(s.target) ? `Returned by a ${s.target} command` : "Returned by a shell command";
  if (kind === "mcp") return `Returned by MCP server ${mcpParts(s.tool_name!).server}`;
  return s.tool_name ? `Returned by ${s.tool_name}` : "Returned by a tool";
}

/** The rules whose row can be about THIS value. */
const CREDENTIAL_DETECTORS = new Set([
  "credential_in_prompt",
  "credential_in_tool_arg",
  "hardcoded_credential",
  "unrecognized_secret",
  "secret_egress",
  "flow_secret_egress",
]);

/** Strongest first — a call the guard blocked outranks one it later observed. */
const OUTCOME_RANK: SightingOutcome[] = ["blocked", "held_denied", "held_allowed", "warned", "observed"];

export function outcomeOfRow(row: Pick<FindingRow, "enforced" | "resolution">): SightingOutcome {
  if (row.enforced === "deny") return "blocked";
  if (row.enforced === "ask") return row.resolution === "allowed" ? "held_allowed" : "held_denied";
  if (row.enforced === "warn") return "warned";
  return "observed";
}

const NEAR_MS = 2 * 60_000;

/**
 * Attach the Radar row that saw the same call. Exact when the row anchors to
 * the sighting's turn; otherwise a credential row in the same session, for the
 * same family, within two minutes — a guard-origin row (a held call) carries
 * no turn id, only when it was held.
 */
export function attachFinding(
  s: RawSighting,
  rows: readonly FindingRow[],
  family: string | undefined,
): { finding_id?: string; outcome: SightingOutcome } {
  const inSession = rows.filter((r) => r.session_id === s.session_id && CREDENTIAL_DETECTORS.has(r.detector));
  const exact = inSession.filter((r) => r.turn_id === s.turn_id);
  // Only a row with NO turn to anchor to may match by time — a transcript row
  // that names another turn is about that turn, however close in time.
  const near =
    exact.length > 0
      ? exact
      : inSession.filter((r) => {
          if (r.turn_id !== undefined) return false;
          if (family && r.key_name && r.key_name !== family) return false;
          const at = Date.parse(r.held_at ?? r.first_seen_at);
          return Number.isFinite(at) && Math.abs(at - Date.parse(s.at)) <= NEAR_MS;
        });
  if (near.length === 0) return { outcome: "observed" };
  const best = [...near].sort((a, b) => OUTCOME_RANK.indexOf(outcomeOfRow(a)) - OUTCOME_RANK.indexOf(outcomeOfRow(b)))[0]!;
  return { finding_id: best.finding_id, outcome: outcomeOfRow(best) };
}

/** Which model provider a rail's transcript reached. */
const PROVIDER_BY_SOURCE: Record<string, string> = {
  "claude-code": "Anthropic",
  "claude-desktop": "Anthropic",
  codex: "OpenAI",
  "gemini-cli": "Google",
  "copilot-cli": "GitHub Copilot",
  "vscode-copilot": "GitHub Copilot",
  "grok-build": "xAI",
  "qwen-code": "Alibaba Cloud",
  cursor: "Cursor's model providers",
};

export function providerOf(source: string, label: string): string {
  return PROVIDER_BY_SOURCE[source] ?? `${label}'s model provider`;
}

export interface TracePlace {
  key: string;
  label: string;
  sightings: TraceSighting[];
}

export interface TraceCoverage {
  /** Turns in the local store, every rail. */
  turns: number;
  /** Transcript documents read for this trace. */
  files_scanned: number;
  /** The rails whose documents were read, by label. */
  sources: string[];
  /** Oldest turn in the store — how far back the answer reaches. */
  since?: string;
  scanned_at: string;
}

export interface TraceReport {
  shape: TraceShape;
  /** Distinct sightings (unit or turn), newest first inside each place. */
  total: number;
  /** Times the value appears, summed. */
  occurrences: number;
  sessions: number;
  first_at?: string;
  last_at?: string;
  /** Per rail: the provider its transcripts reached, and in how many sessions. */
  providers: Array<{ source: string; label: string; provider: string; sessions: number }>;
  /** Files an agent wrote the value into. */
  writes: Array<{ path: string; tool: string; at: string; session_id: string; turn_id: string }>;
  /** Shell commands that carried it. */
  commands: number;
  outcomes: Record<SightingOutcome, number>;
  /** Guard-blocked calls carrying a credential of the SAME FAMILY — a blocked
   * call never reaches a transcript, so this is the honest most that can be
   * said about the value itself. Only when the family is known. */
  blocked_family: number;
  /** Transcript files on this disk that hold the value in plain text. */
  files: Array<{ path: string; source: string }>;
  places: TracePlace[];
  coverage: TraceCoverage;
  rotate?: { provider: string; url: string };
  /** The masked report, for the clipboard. */
  markdown: string;
}

export interface BuildTraceInput {
  shape: TraceShape;
  sightings: readonly RawSighting[];
  findings: readonly FindingRow[];
  files: ReadonlyArray<{ path: string; source: string }>;
  coverage: TraceCoverage;
  labelOf(source: string): string;
  home?: string;
}

function dedupe(sightings: readonly RawSighting[]): RawSighting[] {
  const seen = new Map<string, RawSighting>();
  for (const s of sightings) {
    const key = `${s.session_id} ${s.kind} ${s.turn_id}`;
    const prior = seen.get(key);
    if (!prior) seen.set(key, s);
    else if (s.occurrences > prior.occurrences) seen.set(key, { ...prior, occurrences: s.occurrences });
  }
  return [...seen.values()];
}

export function buildTraceReport(input: BuildTraceInput): TraceReport {
  const { shape, findings, coverage, labelOf, home } = input;
  const raw = dedupe(input.sightings).sort((a, b) => Date.parse(b.at) - Date.parse(a.at));
  const sightings: TraceSighting[] = raw.map((s) => ({
    ...s,
    how: describeSighting(s, home),
    ...attachFinding(s, findings, shape.family),
  }));

  const sessions = new Set(sightings.map((s) => s.session_id));
  const ats = sightings.map((s) => Date.parse(s.at)).filter(Number.isFinite);

  const bySource = new Map<string, Set<string>>();
  for (const s of sightings) {
    let set = bySource.get(s.source);
    if (!set) bySource.set(s.source, (set = new Set()));
    set.add(s.session_id);
  }
  const providers = [...bySource.entries()]
    .map(([source, ids]) => ({ source, label: labelOf(source), provider: providerOf(source, labelOf(source)), sessions: ids.size }))
    .sort((a, b) => b.sessions - a.sessions || a.label.localeCompare(b.label));

  const writes = sightings
    .filter((s) => s.kind === "tool_call" && toolKind(s.tool_name) === "write" && isPath(s.target))
    .map((s) => ({ path: s.target!, tool: s.tool_name!, at: s.at, session_id: s.session_id, turn_id: s.turn_id }));
  const commands = sightings.filter((s) => s.kind === "tool_call" && toolKind(s.tool_name) === "shell").length;

  const outcomes: Record<SightingOutcome, number> = { blocked: 0, held_denied: 0, held_allowed: 0, warned: 0, observed: 0 };
  for (const s of sightings) outcomes[s.outcome] += 1;

  const blocked_family = shape.family
    ? findings.filter((r) => r.origin === "guard" && r.enforced === "deny" && r.key_name === shape.family && CREDENTIAL_DETECTORS.has(r.detector)).length
    : 0;

  // Places: the project a call ran in (cwd folded to its root), else the
  // directory of the file it wrote — the same resolver the Radar groups with.
  const resolver = createPlaceResolver(sightings, home === undefined ? {} : { home });
  const placeMap = new Map<string, TracePlace>();
  for (const s of sightings) {
    const place = resolver.placeOf({
      detector: "custom:trace" as FindingRow["detector"],
      target: s.target,
      tool_name: s.tool_name,
      cwd: s.cwd,
    });
    let group = placeMap.get(place.key);
    if (!group) placeMap.set(place.key, (group = { key: place.key, label: place.label, sightings: [] }));
    group.sightings.push(s);
  }
  const places = [...placeMap.values()].sort(
    (a, b) => Date.parse(b.sightings[0]!.at) - Date.parse(a.sightings[0]!.at),
  );

  const rotate = shape.family ? ROTATE_URLS[shape.family] : undefined;

  const report: Omit<TraceReport, "markdown"> = {
    shape,
    total: sightings.length,
    occurrences: sightings.reduce((n, s) => n + s.occurrences, 0),
    sessions: sessions.size,
    ...(ats.length > 0 ? { first_at: new Date(Math.min(...ats)).toISOString(), last_at: new Date(Math.max(...ats)).toISOString() } : {}),
    providers,
    writes,
    commands,
    outcomes,
    blocked_family,
    files: [...input.files].sort((a, b) => a.path.localeCompare(b.path)),
    places,
    coverage,
    ...(rotate ? { rotate } : {}),
  };
  return { ...report, markdown: traceMarkdown(report, home) };
}

const OUTCOME_WORDS: Record<SightingOutcome, string> = {
  blocked: "blocked",
  held_denied: "held, denied",
  held_allowed: "held, allowed",
  warned: "warned",
  observed: "observed",
};

/** "/Users/x/repos/a/b/.env" → "a/b/.env": enough of a path to know the file. */
export function shortFile(path: string, home?: string): string {
  let p = path.replace(/\/+$/, "");
  if (home && (p === home || p.startsWith(`${home}/`))) p = `~${p.slice(home.length)}`;
  const parts = p.split("/").filter(Boolean);
  return parts.length <= 3 ? parts.join("/") : parts.slice(-3).join("/");
}

/** "a Stripe key", "an Anthropic API key", "an AWS access key". */
export function withArticle(label: string): string {
  return `${/^[aeiou]/i.test(label) ? "an" : "a"} ${label}`;
}

function day(iso: string): string {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toISOString().slice(0, 10);
}

/** The masked report — what "Copy report" puts on the clipboard. Carries the
 * tail and the family, never the value. */
export function traceMarkdown(r: Omit<TraceReport, "markdown">, home?: string): string {
  const lines: string[] = [];
  const mask = `${"•".repeat(Math.max(4, Math.min(12, r.shape.length - r.shape.tail.length)))}${r.shape.tail}`;
  lines.push(`# Secret trace — ${mask}`);
  lines.push("");
  lines.push(`${r.shape.label}, ${r.shape.length} characters. Traced ${day(r.coverage.scanned_at)} on this Mac.`);
  lines.push("");
  if (r.total === 0) {
    lines.push(
      `Not found in anything Doorman has read: ${r.coverage.turns} turns and ${r.coverage.files_scanned} transcript files` +
        (r.coverage.sources.length > 0 ? ` from ${r.coverage.sources.join(", ")}` : "") +
        (r.coverage.since ? `, back to ${day(r.coverage.since)}.` : "."),
    );
  } else {
    lines.push(
      `Found in ${r.total} place${r.total === 1 ? "" : "s"} across ${r.sessions} session${r.sessions === 1 ? "" : "s"}` +
        (r.first_at && r.last_at ? ` (${day(r.first_at)} – ${day(r.last_at)}).` : "."),
    );
    for (const p of r.providers) {
      lines.push(`- Reached ${p.provider} through ${p.label} in ${p.sessions} session${p.sessions === 1 ? "" : "s"}.`);
    }
    if (r.writes.length > 0) lines.push(`- Written to disk by an agent: ${[...new Set(r.writes.map((w) => shortFile(w.path)))].join(", ")}.`);
    if (r.commands > 0) lines.push(`- Ran inside ${r.commands} shell command${r.commands === 1 ? "" : "s"}.`);
    lines.push(
      `- Guardrails: ${(Object.keys(OUTCOME_WORDS) as SightingOutcome[])
        .filter((k) => r.outcomes[k] > 0)
        .map((k) => `${r.outcomes[k]} ${OUTCOME_WORDS[k]}`)
        .join(", ")}.`,
    );
  }
  if (r.blocked_family > 0) {
    lines.push(`- Guardrails also blocked ${r.blocked_family} call${r.blocked_family === 1 ? "" : "s"} carrying ${withArticle(r.shape.label)} before it ran.`);
  }
  lines.push(
    r.shape.recognized
      ? `- Redaction recognizes this shape; a cloud upload carried it as a placeholder.`
      : `- Redaction does not recognize this shape; an upload would carry it verbatim.`,
  );
  if (r.files.length > 0) {
    lines.push("");
    lines.push(`Transcript files on this Mac holding it in plain text:`);
    for (const f of r.files) lines.push(`- ${f.path}`);
  }
  if (r.places.length > 0) {
    lines.push("");
    lines.push("Sightings:");
    for (const place of r.places) {
      lines.push(`- ${place.label}`);
      for (const s of place.sightings) {
        lines.push(`  - ${day(s.at)} · ${s.source} · ${s.how} · ${OUTCOME_WORDS[s.outcome]}${s.occurrences > 1 ? ` ×${s.occurrences}` : ""}`);
      }
    }
  }
  if (r.rotate) {
    lines.push("");
    lines.push(`Rotate at ${r.rotate.provider}: ${r.rotate.url}`);
  }
  return lines.join("\n");
}

/** Count of non-overlapping occurrences of `needle` in `hay`. */
export function countOccurrences(hay: string, needle: string): number {
  if (needle === "") return 0;
  let n = 0;
  let idx = hay.indexOf(needle);
  while (idx !== -1) {
    n += 1;
    idx = hay.indexOf(needle, idx + needle.length);
  }
  return n;
}

/**
 * The forms the literal can take inside a JSON transcript line: as written,
 * and JSON-escaped (a value with a `"` or `\` in it, or one an encoder wrote
 * with `\/`). Pre-filtering a document on these before parsing it keeps the
 * trace to a read of every file rather than a parse of every file.
 */
export function literalForms(value: string): string[] {
  const escaped = JSON.stringify(value).slice(1, -1);
  const forms = new Set([value, escaped, escaped.replace(/\//g, "\\/")]);
  return [...forms];
}
