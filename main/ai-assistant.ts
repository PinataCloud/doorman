/**
 * The context behind "How to fix this?" — the masked facts a coding agent
 * needs to fix a finding, assembled into a prompt the person copies into their
 * own agent. Nothing is sent anywhere by this app.
 *
 * WHAT THE PROMPT CARRIES: the masked finding fields the Radar already shows
 * (rule, masked excerpt, key name, tool/target, outcome) — for a finding, the
 * whole detection record (lib/detection-schema.ts: the rule's mode at the
 * time, the timeline, the account, and each redacted value as a fingerprint).
 * Never raw transcript text, never a revealed value, never the evidence vault.
 * The context builder is the single choke point for that (`findingContext`).
 */

import type { FindingRow, RuleStat, WindowStats } from "./lib/findings.js";
import type { TraceReport } from "./lib/secret-trace.js";
import { localDetectorLabel, thingKey } from "./lib/findings.js";
import { DETECTION_SCHEMA_ID, toDetectionRecord } from "./lib/detection-schema.js";
import { maskFindingRow, maskText } from "./lib/masking.js";
import { DETECTOR_GUIDANCE } from "./lib/ai-guidance.js";
import type { ApprovalRequest } from "./guard/handshake.js";
import { riskProfileFor, type McpServerRow } from "./lib/mcp-inventory.js";
import type { SessionSummary } from "./lib/turns.js";
import type { SpendGraphs } from "./lib/spend.js";
import { CUSTOM_TAINT_KINDS, type CustomRule } from "./guard/custom-rules.js";
import { TASK_LABELS } from "./lib/task-class.js";

/** The masked context the assistant reasons over. Built here, once, from
 * fields the Radar already renders — the boundary the privacy promise rests on. */
export type AiContextKind =
  | "finding"
  | "exposure"
  | "approval"
  | "mcp_server"
  | "rule"
  | "session"
  | "rules"
  | "exceptions"
  | "spend"
  | "posture"
  | "notifications"
  | "machine"
  | "integration"
  | "trace"
  | "general";

export interface AiContext {
  kind: AiContextKind;
  title: string;
  /** Plain text, masked, capped. */
  text: string;
}

const cap = (s: string, n: number): string => (s.length > n ? `${s.slice(0, n)}…` : s);

export function findingContext(
  rawRow: FindingRow,
  group: { rows: number; sessions: number; occurrences: number } | undefined,
  customLabels: Record<string, string>,
): AiContext {
  // Every line below reads the MASKED row (lib/masking.ts): a Bash target is
  // the command's first word and can be `STRIPE_KEY=sk_live_…`.
  const row = maskFindingRow(rawRow);
  const label = row.detector_label ?? localDetectorLabel(row.detector, customLabels);
  const guidance = DETECTOR_GUIDANCE[row.detector];
  const lines = [
    `Rule: ${label} (${row.detector})`,
    `Severity: ${row.severity}`,
    ...(guidance ? [`What the rule means: ${guidance.blurb}`, `Suggested first step: ${guidance.fix}`] : []),
    ...(row.key_name ? [`Exposed / matched: ${cap(row.key_name, 200)}`] : []),
    ...(row.tool_name || row.target ? [`Where: ${[row.tool_name, row.target].filter(Boolean).join(" → ")}`] : []),
    `Masked evidence: ${cap(row.excerpt, 400)}`,
    ...(row.confidence && row.confidence !== "high"
      ? [`Confidence: ${row.confidence} — the rule (or a model's second look) was not certain; treat as a lead, not a verdict.`]
      : []),
    ...(row.assist
      ? [`A model already looked: ${row.assist.model} said "${row.assist.verdict.replace("_", " ")}"${typeof row.assist.score === "number" ? ` (${Math.round(row.assist.score * 100)}% likely an attack)` : ""}.`]
      : []),
    ...(row.source_at
      ? [`Session flow: began ${row.source_at}, completed ${row.last_seen_at} — two tool calls, not one.`]
      : []),
    ...(typeof row.burned_tokens === "number" ? [`Tokens burned by the repeated turns: ${row.burned_tokens.toLocaleString("en-US")}`] : []),
    ...(row.config_host ? [`Config file belongs to: ${row.config_host}`] : []),
    `Outcome: ${row.resolution ?? row.enforced ?? "observed only (not held)"}`,
    `Seen: ${row.occurrences} time(s), first ${row.first_seen_at}, last ${row.last_seen_at}`,
    ...(group ? [`Group: ${group.rows} sighting(s) across ${group.sessions} session(s)`] : []),
    ...(row.cwd ? [`Working directory: ${row.cwd}`] : []),
    `Source: ${row.source} (${row.origin})`,
    ...(row.rule_mode ? [`Rule mode when last seen: ${row.rule_mode}`] : []),
    ...(row.secrets && row.secrets.length > 0
      ? [
          `Redacted values (fingerprints only — the values stay on this computer): ${row.secrets
            .map((s) => `${s.label || "unlabelled"}, ${s.length} chars, fp ${s.fingerprint}${s.primary ? " (the one this finding is about)" : ""}`)
            .join("; ")}`,
        ]
      : []),
    `Triage status: ${row.status}`,
    // The record itself, so an answer can cite any field the person could
    // export — the same masked document, not a second summary of it.
    `Detection record (${DETECTION_SCHEMA_ID}):`,
    cap(JSON.stringify(toDetectionRecord(row)), 4_000),
  ];
  return { kind: "finding", title: label, text: lines.join("\n") };
}

export function approvalContext(request: ApprovalRequest, customLabels: Record<string, string>): AiContext {
  const labels = request.detectors.map((d) => request.detector_labels?.[d] ?? localDetectorLabel(d, customLabels));
  const lines = [
    `A tool call is HELD right now waiting for the person's decision.`,
    `Rules: ${labels.join(", ")} (${request.detectors.join(", ")})`,
    `Severity: ${request.max_severity ?? "high"}`,
    `Agent: ${request.source ?? "claude-code"}`,
    `Tool: ${request.tool_name ?? "unknown"}${request.target ? ` → ${maskText(request.target)}` : ""}`,
    ...(request.server ? [`MCP server: ${request.server}${request.tool_class ? ` (${request.tool_class} call)` : ""}`] : []),
    ...(request.cwd ? [`Working directory: ${request.cwd}`] : []),
    `Why it was held: ${request.reason}`,
    `Masked preview of what the agent is about to run: ${cap(request.preview, 600)}`,
    ...(request.context_note ? [`Context: ${request.context_note}`] : []),
  ];
  return { kind: "approval", title: labels.join(" + ") || "Held tool call", text: lines.join("\n") };
}

export function mcpServerContext(row: McpServerRow): AiContext {
  const risk = row.risk ?? riskProfileFor(row.name);
  const lines = [
    `MCP server: ${row.name}`,
    ...(risk ? [`Profile: ${risk.vendor} ${risk.kind}, ${risk.hosted ? "talks to a hosted service" : "local only"} — ${risk.note}`] : ["Profile: none (unrecognized server)"]),
    `Configured in: ${row.configs.map((c) => `${c.scope} ${c.transport} (${c.path})`).join("; ") || "no watched config (seen in transcripts only)"}`,
    `Usage: ${row.calls} call(s) across ${row.sessions} session(s)${row.last_used_at ? `, last ${row.last_used_at}` : ""}`,
    `Recognized by the person: ${row.recognized ? (row.recognized_stale ? "yes, but STALE — a tool description changed since" : "yes") : "no"}`,
    `Routed through the Doorman gateway: ${row.gatewayed ? "yes" : "no"}`,
    `Open poisoning findings: ${row.poison_open}; changed tool descriptions: ${row.changed_tools}`,
    ...(row.observed_tools.length > 0
      ? [`Tools observed: ${row.observed_tools.map((t) => `${t.name} [${t.cls}${t.versions > 1 ? ", changed" : ""}]`).join(", ")}`]
      : []),
    `Gateway permissions: ${JSON.stringify(row.permissions)}`,
  ];
  return { kind: "mcp_server", title: row.name, text: lines.join("\n") };
}

const outcomeWord = (row: FindingRow): string =>
  row.resolution ?? (row.enforced === "deny" ? "blocked" : row.enforced === "ask" ? "held" : row.enforced === "warn" ? "warned" : "observed");

/**
 * An EXPOSURE (lib/exposures.ts): one rule × one place, with the things under
 * it. The Radar card's subject. Rows arrive already narrowed to the exposure.
 */
export function exposureContext(
  rawRows: readonly FindingRow[],
  place: { kind: string; label: string },
  customLabels: Record<string, string>,
): AiContext {
  const rows = rawRows.map(maskFindingRow);
  const face = rows[0];
  if (!face) return { kind: "exposure", title: "Exposure", text: "No rows." };
  const label = face.detector_label ?? localDetectorLabel(face.detector, customLabels);
  const guidance = DETECTOR_GUIDANCE[face.detector];
  const things = new Map<string, { name: string; rows: number; outcomes: Set<string>; excerpt: string }>();
  const sessions = new Set<string>();
  const outcomes = new Map<string, number>();
  let worst = face.severity;
  const rank = { critical: 4, high: 3, medium: 2, low: 1 } as const;
  for (const row of rows) {
    const key = thingKey(row);
    const name = row.key_name || row.target || "(excerpt only)";
    const t = things.get(key) ?? { name, rows: 0, outcomes: new Set<string>(), excerpt: row.excerpt };
    t.rows += 1;
    t.outcomes.add(outcomeWord(row));
    things.set(key, t);
    if (row.session_id) sessions.add(row.session_id);
    const o = outcomeWord(row);
    outcomes.set(o, (outcomes.get(o) ?? 0) + 1);
    if (rank[row.severity] > rank[worst]) worst = row.severity;
  }
  const ranked = [...things.values()].sort((a, b) => b.rows - a.rows);
  const lines = [
    `Rule: ${label} (${face.detector})`,
    `Place (${place.kind}): ${place.label}`,
    `Worst severity: ${worst}`,
    ...(guidance ? [`What the rule means: ${guidance.blurb}`, `Suggested first step: ${guidance.fix}`] : []),
    `Scale: ${things.size} distinct thing(s), ${rows.length} sighting(s), ${sessions.size} session(s)`,
    `Outcomes: ${[...outcomes.entries()].map(([k, v]) => `${k} ${v}`).join(", ")}`,
    `Things (most sighted first, max 12):`,
    ...ranked.slice(0, 12).map((t) => `  - ${cap(t.name, 120)} × ${t.rows} [${[...t.outcomes].join("/")}] — ${cap(t.excerpt, 160)}`),
    ...(ranked.length > 12 ? [`  … ${ranked.length - 12} more`] : []),
    `Triage status: ${face.status}`,
    `Source: ${face.source} (${face.origin})`,
    `First seen ${rows.reduce((m, r) => (r.first_seen_at < m ? r.first_seen_at : m), face.first_seen_at)}, last ${rows.reduce((m, r) => (r.last_seen_at > m ? r.last_seen_at : m), face.last_seen_at)}`,
  ];
  return { kind: "exposure", title: `${label} · ${place.label}`, text: lines.join("\n") };
}

/** One rule over an Analytics window — "should I graduate / silence this?". */
export function ruleContext(
  detector: string,
  stat: RuleStat | undefined,
  window: Pick<WindowStats, "days" | "sessions"> | undefined,
  mode: string,
  customRule: CustomRule | undefined,
  customLabels: Record<string, string>,
): AiContext {
  const label = stat?.label ?? customRule?.label ?? localDetectorLabel(detector, customLabels);
  const guidance = DETECTOR_GUIDANCE[detector];
  const lines = [
    `Rule: ${label} (${detector})`,
    `Current mode: ${mode}`,
    ...(guidance ? [`What the rule means: ${guidance.blurb}`, `Suggested first step: ${guidance.fix}`] : []),
    ...(customRule ? [`Definition (a rule the person wrote): ${JSON.stringify(customRule)}`] : []),
    ...(stat && window
      ? [
          `Over the last ${window.days} days: ${stat.exposures} exposure(s), ${stat.things} thing(s), ${stat.fired} sighting(s) across ${stat.sessions} session(s)`,
          `Enforcement: blocked ${stat.blocked}, held ${stat.held} (allowed ${stat.allowed}, denied ${stat.denied}, timed out ${stat.timed_out}), warned ${stat.warned}`,
          ...(stat.worst ? [`Worst severity seen: ${stat.worst}`] : []),
          ...(stat.median_hold_ms !== undefined ? [`Median time to decide a held call: ${Math.round(stat.median_hold_ms / 1000)}s`] : []),
          ...(stat.last_fired_at ? [`Last fired: ${stat.last_fired_at}`] : []),
        ]
      : [`This rule has not fired in the selected window.`]),
  ];
  return { kind: "rule", title: label, text: lines.join("\n") };
}

/** A session in the Event Ledger: its shape plus every finding that fired in it. */
export function sessionContext(rawSummary: SessionSummary, rawFindings: readonly FindingRow[], customLabels: Record<string, string>): AiContext {
  // An auto-titled session is named after its first prompt, which can be a
  // pasted key; findings' targets can be too.
  const summary = rawSummary.title ? { ...rawSummary, title: maskText(rawSummary.title) } : rawSummary;
  const findings = rawFindings.map(maskFindingRow);
  const minutes = Math.max(0, Math.round((Date.parse(summary.ended_at) - Date.parse(summary.started_at)) / 60_000));
  const lines = [
    `Session: ${summary.title ? cap(summary.title, 140) : summary.id}`,
    `Agent: ${summary.source}${summary.task ? ` · use case: ${TASK_LABELS[summary.task] ?? summary.task}` : ""}`,
    `Span: ${summary.started_at} → ${summary.ended_at} (~${minutes} min), ${summary.turns} assistant turn(s), ${summary.prompts} prompt(s)`,
    `Models: ${summary.models.join(", ") || "unknown"}`,
    `Tokens: ${(summary.input_tokens + summary.output_tokens).toLocaleString("en-US")} (plan-covered ${summary.covered_tokens.toLocaleString("en-US")}, API credits ${summary.overage_tokens.toLocaleString("en-US")}, API-key billed ${(summary.billed_tokens ?? 0).toLocaleString("en-US")}, unattributed ${summary.unknown_tokens.toLocaleString("en-US")})`,
    ...(summary.cwd ? [`Working directory: ${summary.cwd}${summary.git_branch ? ` (branch ${summary.git_branch})` : ""}`] : []),
    `Findings in this session: ${findings.length}`,
    ...findings.slice(0, 15).map((f) => {
      const label = f.detector_label ?? localDetectorLabel(f.detector, customLabels);
      return `  - [${f.severity}] ${label}${f.key_name ? ` — ${cap(f.key_name, 80)}` : ""} · ${outcomeWord(f)} · ${f.status} · ${cap(f.excerpt, 140)}`;
    }),
    ...(findings.length > 15 ? [`  … ${findings.length - 15} more`] : []),
  ];
  return { kind: "session", title: summary.title ? cap(summary.title, 60) : "Session", text: lines.join("\n") };
}

/** The custom-rule authoring subject: what exists, and the shape a new one takes. */
export function rulesAuthoringContext(customRules: readonly CustomRule[], packsEnabled: readonly string[]): AiContext {
  const lines = [
    `Custom rules on this computer: ${customRules.length}${customRules.length > 0 ? ` — ${customRules.map((r) => `${r.id} (${r.mode}, ${r.severity})`).join(", ")}` : ""}`,
    `Rule packs enabled: ${packsEnabled.join(", ") || "none"}`,
    `A custom rule is JSON: { "id": "[a-z0-9][a-z0-9_-]{0,47}", "label": "≤80 chars", "blurb": "≤240 chars, optional", "severity": "critical|high|medium|low", "mode": "observe|warn|ask|block", "when": { "tool": regex, "command": regex, "server": regex, "target": regex, "arg": { "field.path": regex } }, "after": { "taint": one of ${CUSTOM_TAINT_KINDS.join("|")} } (optional; makes the rule a session-flow rule that only observes), "scope": { "cwd_prefix": "/abs/path" } (optional) }.`,
    `Regexes are JavaScript sources WITHOUT slashes or flags (matched case-insensitively), max 400 chars, and must not nest quantifiers like (a+)+ — the app refuses pathological patterns. Every field listed under "when" must match for the rule to fire. "tool" matches the tool name (Bash, Edit, Write, Read, WebFetch, mcp__<server>__<tool>); "command" the shell command of a Bash call; "target" a program name or file path; "server" the MCP server segment.`,
    `When asked to draft a rule, reply with a one-line rationale and then exactly one \`\`\`json block holding the rule object, so the app can offer to insert it into the editor.`,
  ];
  return { kind: "rules", title: "Custom rules", text: lines.join("\n") };
}

/**
 * The exceptions subject — what Doorman AI needs to DRAFT one (Rules →
 * Exceptions → "Draft an exception for me"). The person's current exceptions
 * (patterns and scopes only — an exception carries no secret), every rule id
 * an exception may name, and the exact JSON the editor accepts, so the answer
 * can end in one block the app offers to open in the exception editor. Same
 * contract as rulesAuthoringContext: the draft is never saved on its own.
 */
export function exceptionsAuthoringContext(
  ignore: readonly { detector?: string; pattern: string; cwd_prefix?: string; expires_at?: string; origin?: string; note?: string }[],
  detectorIds: readonly string[],
): AiContext {
  const lines = [
    `Exceptions on this computer: ${ignore.length}${
      ignore.length > 0
        ? ` — ${ignore
            .slice(0, 12)
            .map((r) => `${r.detector ?? "any rule"} /${r.pattern}/${r.cwd_prefix ? ` under ${r.cwd_prefix}` : ""}${r.expires_at ? ` until ${r.expires_at.slice(0, 10)}` : ""} (${r.origin ?? "manual"})`)
            .join("; ")}${ignore.length > 12 ? "; …" : ""}`
        : ""
    }`,
    `An exception hides a finding whose VISIBLE fields match — rule id, key name, tool name, target and the masked excerpt — never the raw value, which is gone before the pattern runs. It applies from the next scan; rows already on the Radar stay until triaged.`,
    `An exception is JSON: { "pattern": regex over those visible fields (required), "detector": one of ${detectorIds.join("|")} (optional; omit = any rule, which is broad — prefer naming the rule), "cwd_prefix": "/abs/project/path" (optional; scopes it to one project, the shape the approval panel writes), "expires_days": 30|90 (optional; omit = never), "note": "why, ≤120 chars" (optional) }.`,
    `Regexes are JavaScript sources WITHOUT slashes or flags (matched case-insensitively), max 400 chars, must not match the empty string and must not nest quantifiers like (a+)+. Anchor on the finding's key name or target rather than on prose in the excerpt.`,
    `Prefer the narrowest exception that fits: one rule, one project, a lifetime. Never propose an exception for wallet_key_material, credential_in_tool_arg or secret_egress on a live-looking value — say why instead.`,
    `When asked to draft an exception, reply with a one-line rationale and then exactly one \`\`\`json block holding the exception object, so the app can offer to open it in the exception editor.`,
  ];
  return { kind: "exceptions", title: "Exceptions", text: lines.join("\n") };
}

/** The Usage screen over a window — the numbers the screen already shows.
 * Token counts, never dollars: what the assistant is told is what
 * it will say back, and the app does not show a cost it cannot stand behind. */
export function spendContext(g: SpendGraphs): AiContext {
  const tok = (n: number) => `${Math.round(n).toLocaleString("en-US")} tokens`;
  const hours = (s: number) => `${(s / 3600).toFixed(1)}h`;
  const lines = [
    `Window: last ${g.days} days · today so far ${tok(g.today_tokens)} over ${hours(g.today_seconds)} engaged`,
    `Tokens (input+output, cache traffic excluded): ${tok(g.window_tokens)} (previous window ${tok(g.prev_window_tokens)}) · plan-covered ${tok(g.covered_tokens)}, API credits ${tok(g.overage_tokens)}, API-key billed ${tok(g.billed_tokens ?? 0)}, unattributed ${tok(g.unknown_tokens)}`,
    `Engaged time: ${hours(g.window_seconds)} (previous ${hours(g.prev_window_seconds)}) across ${g.window_sessions} session(s)`,
    `By use case (engaged time, most first): ${g.by_task.slice(0, 8).map((t) => `${TASK_LABELS[t.task as keyof typeof TASK_LABELS] ?? t.task} ${hours(t.seconds)} ${tok(t.tokens)} (${t.sessions} sessions)`).join("; ") || "n/a"}`,
    `By model (tokens, most first): ${g.model_rows.slice(0, 8).map((m) => `${m.model} ${tok(m.tokens)} (${m.source})`).join("; ") || "n/a"}`,
    `Rails active: ${g.time_rails.join(", ") || "none"}`,
    "Dollar figures are deliberately not given: on-device pricing is an estimate that ignores what actually paid for a turn. Do not invent a cost.",
  ];
  return { kind: "spend", title: `Usage · ${g.days}d`, text: lines.join("\n") };
}

export interface PostureFacts {
  guard_installed: boolean;
  guard_wanted: boolean;
  integrity: string;
  rules_enforcing: number;
  rules_total: number;
  rules_holding: number;
  custom_rules: number;
  open_exposures: number;
  by_severity: Record<string, number>;
  /** Worst open exposures, already labelled and placed, max 8. */
  top: { label: string; place: string; severity: string; things: number; sightings: number }[];
  mcp_servers: number;
  mcp_unrecognized: number;
  mcp_gatewayed: number;
  held_now: number;
}

/** The whole-machine subject: what the Radar's posture line and hero say. */
export function postureContext(p: PostureFacts): AiContext {
  const lines = [
    `Guard: ${p.guard_installed ? "installed" : p.guard_wanted ? "WANTED but not installed" : "off (rules only watch)"} · integrity ${p.integrity}`,
    `Rules: ${p.rules_enforcing} of ${p.rules_total} enforce before a tool runs (${p.rules_holding} hold and ask) · ${p.custom_rules} custom rule(s)`,
    `Held right now, waiting for a decision: ${p.held_now}`,
    `Open exposures needing review: ${p.open_exposures} (${Object.entries(p.by_severity).map(([k, v]) => `${k} ${v}`).join(", ")})`,
    `Worst open exposures:`,
    ...p.top.map((t) => `  - [${t.severity}] ${t.label} · ${t.place} — ${t.things} thing(s), ${t.sightings} sighting(s)`),
    `MCP servers: ${p.mcp_servers} configured, ${p.mcp_unrecognized} not recognized, ${p.mcp_gatewayed} routed through the gateway`,
  ];
  return { kind: "posture", title: "Security posture", text: lines.join("\n") };
}

/** What the app knows about its own banners not arriving. No user content —
 * a platform, an OS status string and which switches are on. */
export interface NotificationFacts {
  platform: string;
  os_label: string;
  /** The last delivery check: refused, unanswered, or delivering. */
  status: "blocked" | "unknown" | "ok";
  /** The OS's own words when it refused, verbatim — it names the cause. */
  error?: string;
  checked_at?: string;
  app_version: string;
  /** Banners this person switched ON that the OS is now dropping. */
  wanted: readonly string[];
}

/**
 * NOTIFICATIONS AREN'T ARRIVING — the subject behind the blocked notice's
 * "How to fix this?" and the Settings row's.
 *
 * Worth its own subject rather than falling back to THIS MAC: the fix is a
 * sequence of OS steps that depends on WHICH refusal this is (never granted,
 * revoked, alert style None, a Focus mode, an unsigned dev build), and the
 * only thing that tells them apart is the OS's own error string — which the
 * machine context doesn't carry. Answering "how do I fix this?" from the spend
 * window and the security posture would be answering a different question.
 */
export function notificationsContext(f: NotificationFacts): AiContext {
  const lines = [
    `Platform: ${f.platform} · Doorman v${f.app_version}`,
    `Delivery check: ${f.status === "blocked" ? `REFUSED by ${f.os_label}` : f.status === "unknown" ? "no answer (neither proof of delivery nor a refusal)" : "delivering"}` +
      (f.checked_at ? ` · last checked ${f.checked_at}` : ""),
    ...(f.error ? [`The OS said: ${cap(f.error, 300)}`] : []),
    f.wanted.length > 0
      ? `Switched on but not arriving: ${f.wanted.join(", ")}.`
      : `No banner types are switched on.`,
    // The limits of the diagnosis, so the answer doesn't assert a cause the
    // app cannot actually see.
    `What the app CAN see: whether the OS refused a banner outright. What it CANNOT see: a banner the OS accepts and never shows — alert style set to None, Do Not Disturb, or a Focus mode. Those are silent to the app.`,
    `Still working regardless: held tool calls raise the floating prompt, and every alert appears in the app's own notice stack.`,
  ];
  return { kind: "notifications", title: `${f.os_label} notifications`, text: lines.join("\n") };
}

/** What the whole-machine subject is built from — everything the app knows,
 * each part already masked by its own builder. */
export interface MachineFacts {
  posture: PostureFacts;
  spend: SpendGraphs;
  /** Newest sessions first; the builder keeps the top few. */
  sessions: readonly SessionSummary[];
  /** The setup doctor's latest report, when one has run. */
  setup?: { ok: number; warn: number; fail: number; headline: string };
  /** The coverage map ("AI on this Mac"): every tool the local scan found and
   * what Doorman does for it. Without this the assistant could not answer
   * "is the app I use covered?" — the commonest question the Integrations
   * screen provokes — from anything but a guess. */
  coverage?: {
    tools: readonly {
      name: string;
      kind: string;
      installed: boolean;
      captured: boolean;
      guarded: boolean;
      guardable: boolean;
    }[];
  };
  app_version: string;
}

/**
 * THIS MAC — the subject a question gets when it wasn't asked beside any one
 * thing: the sidebar door, ⌘K, or an entry point with no reference.
 *
 * Why it exists: without it a general question carried NO local context. This
 * is the posture, the spend window, the newest sessions and the setup health, so a
 * ref-less question is answered from the machine the person is sitting at.
 */
/**
 * The coverage map as lines: what is covered and HOW (metered, guarded, or
 * both), what one switch would reach, what was found with no way in, and how
 * many catalog entries were looked for and not found — the last one is a
 * COUNT, not a list, so a question about a tool that isn't here is answered
 * "not on this Mac" without pasting forty names into every machine question.
 */
function coverageLines(coverage: MachineFacts["coverage"]): string[] {
  if (!coverage) return [];
  const installed = coverage.tools.filter((t) => t.installed);
  const say = (t: (typeof installed)[number]): string => {
    const how = [t.captured ? "metered" : "", t.guarded ? "guarded" : ""].filter(Boolean).join(" + ");
    if (how) return `  - ${t.name} (${t.kind}) · ${how}`;
    if (t.guardable) return `  - ${t.name} (${t.kind}) · NOT covered — the guard has an adapter, one switch wires it in`;
    return `  - ${t.name} (${t.kind}) · NOT covered — no adapter and nothing readable on disk`;
  };
  const absent = coverage.tools.length - installed.length;
  return [
    "",
    `AI TOOLS ON THIS MAC (${installed.length} found of ${coverage.tools.length} looked for)`,
    ...(installed.length > 0 ? installed.map(say) : ["  (none found)"]),
    `  ${absent} other catalogued tool(s) were looked for and not found on this computer.`,
  ];
}

export function machineContext(facts: MachineFacts): AiContext {
  const posture = postureContext(facts.posture).text;
  const spend = spendContext(facts.spend).text;
  const tok = (n: number) => `${Math.round(n).toLocaleString("en-US")} tokens`;
  const recent = facts.sessions.slice(0, 6).map((s) => {
    const minutes = Math.max(0, Math.round((Date.parse(s.ended_at) - Date.parse(s.started_at)) / 60_000));
    return `  - ${s.title ? cap(maskText(s.title), 80) : s.id} · ${s.source}${s.task ? ` · ${TASK_LABELS[s.task] ?? s.task}` : ""} · ${tok((s.input_tokens ?? 0) + (s.output_tokens ?? 0))} · ~${minutes} min · ${s.turns} turn(s)${s.cwd ? ` · ${cap(s.cwd, 60)}` : ""}`;
  });
  const setup = facts.setup
    ? `Setup health: ${facts.setup.headline} (${facts.setup.ok} ok, ${facts.setup.warn} warning(s), ${facts.setup.fail} failing)`
    : "Setup health: not checked yet";
  const lines = [
    `Doorman v${facts.app_version} · local only — nothing leaves this computer`,
    setup,
    "",
    "SECURITY POSTURE",
    posture,
    "",
    "USAGE",
    spend,
    "",
    `NEWEST SESSIONS (${recent.length} of ${facts.sessions.length} shown)`,
    ...(recent.length > 0 ? recent : ["  (no sessions yet)"]),
    ...coverageLines(facts.coverage),
  ];
  return { kind: "machine", title: "This Mac", text: lines.join("\n") };
}

/**
 * Documented places a host can be told to keep its sessions somewhere other
 * than its default folder. Static because a descriptor's `roots()` READS the
 * override but does not name it, and the assistant has to say "set X" to a
 * person whose tool writes elsewhere. The two native rails are read from
 * fixed paths (`~/.claude/projects`, `~/.codex/sessions`) and are absent here
 * on purpose — naming an override the engine ignores would send someone down
 * a dead end.
 */
const SOURCE_ENV_OVERRIDES: Readonly<Record<string, readonly string[]>> = {
  "gemini-cli": ["GEMINI_CLI_HOME"],
  "copilot-cli": ["COPILOT_HOME"],
  hermes: ["HERMES_HOME"],
  openclaw: ["OPENCLAW_STATE_DIR"],
  "qwen-code": ["QWEN_HOME"],
  "grok-build": ["GROK_HOME"],
  goose: ["GOOSE_PATH_ROOT"],
};

/** What the "How do I integrate my app?" door is answered from — the app's
 * own knowledge of every way a tool is covered, plus what is already wired on
 * this Mac. No user content: rail ids and labels, the folders the app itself
 * reads, and the guard registry. */
export interface IntegrationFacts {
  app_version: string;
  /** "darwin arm64" — the answer differs for a Linux box or a container. */
  platform: string;
  /** The person's home directory, so the folders below print as `~/…`. */
  home: string;
  /** Every rail the ledger can hold — the two native ones and the registry —
   * with whether its host is on this Mac and where the engine reads it. */
  sources: readonly {
    id: string;
    label: string;
    present: boolean;
    metered: boolean;
    roots: readonly string[];
  }[];
  /** The hosts the PreToolUse guard has an adapter for, and which it is in. */
  guard_hosts: readonly { id: string; label: string; installed: boolean }[];
  coverage?: MachineFacts["coverage"];
}

/**
 * SECRET TRACE — the masked report of the last trace (lib/secret-trace.ts):
 * the value's shape, where it went, what the guard did, and the rotate link.
 * The value itself is not in the report, so it cannot be here either; the
 * question this answers is "what do I do about it, in what order".
 */
export function traceContext(report: TraceReport | undefined): AiContext {
  if (!report) {
    return { kind: "trace", title: "Secret trace", text: "No secret has been traced in this session. The person can paste one on Security Radar → Trace a secret." };
  }
  const lines: string[] = [];
  const mask = `${"•".repeat(4)}${report.shape.tail}`;
  lines.push(`Traced value: ${mask} (${report.shape.length} characters, ${report.shape.label})`);
  lines.push(`Redaction recognizes the shape: ${report.shape.recognized ? "yes — exports and prompts carry a placeholder" : "no — an export or prompt would carry it verbatim"}`);
  if (report.total === 0) {
    lines.push(
      `Found: nowhere — ${report.coverage.turns} turns and ${report.coverage.files_scanned} transcript files searched` +
        (report.coverage.sources.length > 0 ? ` (${report.coverage.sources.join(", ")})` : "") +
        (report.coverage.since ? `, back to ${report.coverage.since.slice(0, 10)}` : ""),
    );
  } else {
    lines.push(`Found: ${report.total} sightings, ${report.occurrences} occurrences, ${report.sessions} sessions` +
      (report.first_at && report.last_at ? `, ${report.first_at.slice(0, 10)} to ${report.last_at.slice(0, 10)}` : ""));
    for (const p of report.providers) lines.push(`Reached: ${p.provider} via ${p.label}, ${p.sessions} session${p.sessions === 1 ? "" : "s"}`);
    if (report.writes.length > 0) lines.push(`Written to disk: ${report.writes.map((w) => w.path).slice(0, 8).join(", ")}${report.writes.length > 8 ? ` (+${report.writes.length - 8})` : ""}`);
    if (report.commands > 0) lines.push(`Shell commands carrying it: ${report.commands}`);
    const o = report.outcomes;
    lines.push(`Guardrails: ${o.blocked} blocked, ${o.held_denied} held and denied, ${o.held_allowed} held and allowed, ${o.warned} warned, ${o.observed} only observed`);
  }
  if (report.blocked_family > 0) lines.push(`Blocked calls carrying a ${report.shape.label} (family match, not this value): ${report.blocked_family}`);
  if (report.files.length > 0) lines.push(`Transcript files holding it in plain text: ${report.files.length}`);
  if (report.places.length > 0) {
    lines.push("SIGHTINGS");
    for (const place of report.places.slice(0, 6)) {
      lines.push(`  - ${place.label}: ${place.sightings.slice(0, 5).map((s) => `${s.at.slice(0, 10)} ${s.how} (${s.outcome})`).join("; ")}`);
    }
  }
  if (report.rotate) lines.push(`Rotate at: ${report.rotate.provider} — ${report.rotate.url}`);
  return { kind: "trace", title: `Secret trace · ${mask}`, text: cap(lines.join("\n"), 6000) };
}

/**
 * INTEGRATING A TOOL — the subject behind Integrations' "How do I integrate my
 * app?" door.
 *
 * Why its own subject rather than THIS MAC: the machine context says what is
 * covered; this one says HOW anything gets covered — which hosts the app can
 * read and where, which the guard can hold, and what neither can reach.
 * Without it the assistant answered a setup question from guesswork.
 * Everything here is the app's own configuration; nothing is a secret and
 * nothing is user content.
 */
export function integrationContext(f: IntegrationFacts): AiContext {
  const tilde = (p: string): string => (f.home && p.startsWith(f.home) ? `~${p.slice(f.home.length)}` : p);
  const present = f.sources.filter((s) => s.present);
  const absent = f.sources.filter((s) => !s.present);
  const guardIn = f.guard_hosts.filter((h) => h.installed);
  const guardOut = f.guard_hosts.filter((h) => !h.installed);
  const readLine = (s: IntegrationFacts["sources"][number]): string => {
    const env = SOURCE_ENV_OVERRIDES[s.id];
    return `  - ${s.label} · reads ${s.roots.map(tilde).join(", ") || "(no folder resolved)"}${env ? ` (override: ${env.join(", ")})` : ""} · ${s.metered ? "metered" : "activity only, no token counts on disk"}`;
  };
  const lines = [
    `Doorman v${f.app_version} on ${f.platform} · local only — nothing leaves this computer`,
    "",
    "THE WAYS IN",
    `  1. TRANSCRIPT READING — the app reads each host's own session files from disk; nothing to configure when the host writes to its default folder. A host that writes elsewhere (another machine, a container) is invisible to the app. Hosts this build can read and where:`,
    ...(present.length > 0 ? present.map(readLine) : ["  (none of the readable hosts is on this computer)"]),
    ...(absent.length > 0 ? [`  Also readable, not on this computer: ${absent.map((s) => s.label).join(", ")}.`] : []),
    `  2. THE GUARD (holding risky tool calls before they run) needs a host adapter. Adapters exist for: ${f.guard_hosts.map((h) => h.label).join(", ")}. Wired in on this computer: ${guardIn.length > 0 ? guardIn.map((h) => h.label).join(", ") : "none"}${guardOut.length > 0 ? ` · not wired: ${guardOut.map((h) => h.label).join(", ")}` : ""}. A tool outside that list can be METERED (1) but not guarded — say so rather than promising it.`,
    "",
    "NOT POSSIBLE, so say so: reading a host's session files from another machine, a container or CI; guarding a host with no adapter; recovering token counts a host never wrote down; anything in a browser.",
    ...coverageLines(f.coverage),
  ];
  return { kind: "integration", title: "Integrate a tool", text: lines.join("\n") };
}
