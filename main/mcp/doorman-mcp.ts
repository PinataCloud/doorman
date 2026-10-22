/**
 * Doorman's own MCP server — the agent's door into the guard, over stdio.
 *
 * Copilot's agent mode in VS Code and the Copilot CLI (and every other MCP
 * host on this Mac) can spawn this instead of guessing what the guard will do:
 *   command: node   args: ["<userData>/doorman/mcp/doorman-mcp.js"]
 * Five tools, all answered from what is already on this disk, so they work
 * with the app closed:
 *   · doorman_check_tool_call  — run the SAME detectors and policy the
 *     PreToolUse guard runs, on a call the agent is about to make. The
 *     answer is the decision (allow / ask / deny), the rules by name and what
 *     to do instead — so an agent can ask before it is blocked. The guard
 *     never evaluates a call to these tools (decision.ts
 *     isDoormanReadOnlyTool): the check's argument is the risky call itself.
 *   · doorman_explain_last_block — why the guard held or denied recent calls
 *     (the guard's spool), one entry per call, with the remedy per rule.
 *   · doorman_session_spend    — what the ledger has metered for a session or
 *     a working directory: tokens by model, unmetered turns counted. Tokens,
 *     never dollars — the name predates that and is kept so agents'
 *     configs keep working.
 *   · doorman_status           — is the guard installed, is the app (or
 *     `doorman watch`) answering, which rules hold or block.
 *   · doorman_propose_rule     — suggest a custom rule (the custom-rules
 *     format). It is only SAVED for review (guard/rule-proposals.ts, beside
 *     the policy, never in it): nothing applies until the person saves it in
 *     the app or runs `doorman custom-rules accept`, and a proposal can only
 *     add a new rule — never change, switch off or shadow one they have.
 * The four that read are annotated read-only: Codex under
 * `approval_policy=never` refuses a tool that does not say so. The proposal
 * tool says honestly that it writes, and the guard does not exempt it
 * (decision.ts isDoormanReadOnlyTool covers the read-only four).
 *
 * NEVER a value: the check returns rule names and counts, never the redacted
 * excerpt; the spool rows are already masked and only their names travel —
 * flattened to one line, since a tool name is whatever an MCP server chose;
 * usage is numbers. The one write is a proposal file under the guard
 * directory; the policy is never touched.
 *
 * Wire: newline-delimited JSON-RPC 2.0 (the MCP stdio transport). We print
 * one line per response and nothing else on stdout; diagnostics go to stderr.
 * Notifications and client responses are never answered; batches only under
 * the one revision that had them (2025-03-26).
 *
 * Self-containment rule: copied verbatim to userData and run with plain `node`.
 * Imports only the SIBLING guard bundle (`../guard/*.js`, copied to the
 * neighbouring directory by the same installer) — like the gateway does.
 */

import { existsSync, readFileSync, realpathSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { customDetectorId, customDetectorLabels, parseCustomRules } from "../guard/custom-rules.js";
import { DOORMAN_MCP_SERVER_NAME, evaluateToolCall, type GuardHookInput } from "../guard/decision.js";
import { appListening, heartbeatPath, readPresence } from "../guard/handshake.js";
import { HOSTS, hostLabel } from "../guard/hosts/index.js";
import { DETECTOR_LABELS, HOOK_TIMEOUT_SLACK_SECONDS, isGuardCommand, parsePolicy, type GuardPolicy } from "../guard/policy.js";
import { agentFacingReason, remedyFor, type HoldResolution } from "../guard/remedy.js";
import { rulePackShown, ruleShown } from "../guard/rule-scope.js";
import { describeRule, proposerLabel, saveProposal } from "../guard/rule-proposals.js";

export const MCP_SERVER_NAME = DOORMAN_MCP_SERVER_NAME;
export const MCP_SERVER_VERSION = "1";
/** Every MCP revision this server speaks, newest first. A client asking for
 * one of them gets it; any other request gets the newest (the client then
 * decides whether it can go on). We use nothing revision-specific except
 * batches, which only 2025-03-26 has. */
export const SUPPORTED_PROTOCOL_VERSIONS: readonly string[] = ["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"];
const LATEST_PROTOCOL_VERSION = "2025-11-25";
const BATCH_PROTOCOL_VERSION = "2025-03-26";

/** The longest message the transport reads, in characters. Bigger than any
 * call the guard itself would inspect (guard.ts reads 4 MB of stdin). */
export const MAX_MESSAGE_CHARS = 8 * 1024 * 1024;

/** Where the server finds what it reads. Resolved from the script's own
 * location by default (`<userData>/doorman/mcp/`), injectable for tests. */
export interface McpPaths {
  guardDir: string;
  storeDir: string;
}

export function defaultPaths(scriptDir: string): McpPaths {
  return {
    guardDir: join(scriptDir, "..", "guard"),
    storeDir: join(scriptDir, "..", "..", "store"),
  };
}

export interface McpReadIo {
  readText(path: string): string | undefined;
  appListening(guardDir: string): boolean;
  now(): number;
  /** Labels of the agents whose hook document carries the guard. */
  guardHosts(): string[];
  /** The path with symlinks resolved, or the path itself when it does not resolve. */
  realpath(path: string): string;
  /** The agent session this server runs under, when the guard's presence
   * records name our parent process (handshake.ts PresenceRecord). */
  currentSession(guardDir: string): { session_id: string; source: string } | undefined;
}

export function realIo(): McpReadIo {
  const readText = (path: string): string | undefined => {
    try {
      return existsSync(path) ? readFileSync(path, "utf8") : undefined;
    } catch {
      return undefined;
    }
  };
  return {
    readText,
    appListening: (guardDir) => appListening(guardDir),
    now: () => Date.now(),
    guardHosts() {
      const home = homedir();
      const labels = new Set<string>();
      for (const host of HOSTS) {
        for (const doc of host.documents(home, process.env)) {
          // The same test the installer's status uses (enforcement.ts guardHostStates).
          if (doc.level === "user" && isGuardCommand(readText(doc.path))) labels.add(host.label);
        }
      }
      return [...labels];
    },
    realpath(path) {
      try {
        return realpathSync(path);
      } catch {
        return path;
      }
    },
    currentSession(guardDir) {
      // The guard records its PARENT (the agent) per session; so does this
      // server's ppid name the agent that spawned it. A shell between either
      // of them and the agent means no match — then no session is assumed.
      let best: { session_id: string; source: string; at: string } | undefined;
      for (const record of readPresence(guardDir)) {
        if (record.pid === process.ppid && (!best || record.at > best.at)) best = record;
      }
      return best && { session_id: best.session_id, source: best.source };
    },
  };
}

// ---- tools ------------------------------------------------------------------

/** The four reading tools only read Doorman's own files (MCP 2025-06-18 ToolAnnotations). */
const READ_ONLY = { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false } as const;
/** The proposal tool writes one file, adds nothing live, and each call is a
 * new proposal — said as it is. */
const PROPOSES = { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false } as const;

export const TOOLS = [
  {
    name: "doorman_check_tool_call",
    title: "Check a tool call with Doorman",
    description:
      "Ask Doorman's security guard, before making a tool call, whether it would allow, hold or block it — the same rules and policy the PreToolUse guard applies. Returns the decision, the rules by name and what to do. Use it before a shell command that touches credentials or sends data over the network, and before writing a file that may contain a secret. Give either `command` (a shell command), or `tool_name` with `tool_input`. Doorman's rules look for sensitive information (credentials, secrets, wallet keys, personal data): an allow means no rule matched, not that the call is safe. If the answer is hold or block, ask the user; do not reword the call until it passes.",
    inputSchema: {
      type: "object",
      properties: {
        tool_name: {
          type: "string",
          description: "Claude-style tool name: Bash, Write, Edit, Read, WebFetch, or mcp__<server>__<tool>. Defaults to Bash when `command` is given.",
        },
        tool_input: { type: "object", description: "The tool's arguments (e.g. { command } for Bash, { file_path, content } for Write). Not together with `command`." },
        command: { type: "string", description: "Shortcut for a shell command: same as tool_input { command } (tool_name defaults to Bash). Not together with `tool_input`." },
        cwd: { type: "string", description: "Working directory the call runs in (scopes project rules)." },
        session_id: { type: "string", description: "The agent session id, if known." },
      },
    },
    annotations: READ_ONLY,
  },
  {
    name: "doorman_explain_last_block",
    title: "Explain Doorman's recent holds and blocks",
    description:
      "Why Doorman held or blocked recent tool calls: which rule fired, on which tool, how it was resolved, and what to do next — one entry per call, newest first. Call this rather than retrying a blocked call.",
    inputSchema: {
      type: "object",
      properties: {
        session_id: {
          type: "string",
          description: "Only this agent session. Without it, Doorman uses the calling agent's session when it can tell, and says when entries come from other sessions.",
        },
        cwd: { type: "string", description: "Only calls made from this working directory." },
        limit: { type: "integer", minimum: 1, maximum: 20, description: "How many recent calls, 1–20 (default 3); a value outside that range is clamped." },
      },
    },
    annotations: READ_ONLY,
  },
  {
    name: "doorman_session_spend",
    title: "Doorman token usage",
    description:
      "What Doorman has metered so far: model calls and their input/output token counts by model, plus how many calls carried no token counts. Token counts only — no dollar figures. Filter by session id or working directory; defaults to the last 24 hours across every agent on this computer.",
    inputSchema: {
      type: "object",
      properties: {
        session_id: { type: "string", description: "Only this agent session (the time window does not apply)." },
        cwd: { type: "string", description: "Only turns from this working directory." },
        since_hours: {
          type: "number",
          minimum: 0.1,
          maximum: 24 * 90,
          description: "Window in hours, 0.1–2160 (default 24); a value outside that range is clamped.",
        },
      },
    },
    annotations: READ_ONLY,
  },
  {
    name: "doorman_status",
    title: "Doorman status",
    description:
      "Whether Doorman's guard is installed, whether the Doorman app or `doorman watch` is running to answer holds, which rules currently hold or block a call, and which agent hosts the guard knows.",
    inputSchema: { type: "object", properties: {} },
    annotations: READ_ONLY,
  },
  {
    name: "doorman_propose_rule",
    title: "Suggest a Doorman rule",
    description:
      "Suggest a new custom rule to the person who runs Doorman — for example when they ask you to make Doorman hold or block a kind of command, or you notice a risky pattern their rules do not cover. The rule is only saved as a suggestion: the person reviews it in Doorman (Guardrails → Your rules) or with `doorman custom-rules accept <id>`, may edit it, and nothing applies until they save it. A suggestion can only ADD a rule: it cannot change, switch off or replace a rule they already have, so use an id that is not taken. Every clause is a case-insensitive regular expression. Call doorman_status first if you need to know which rules exist.",
    inputSchema: {
      type: "object",
      properties: {
        rule: {
          type: "object",
          description:
            'The rule, in Doorman\'s custom rule format. Example: { "id": "kubectl_apply_prod", "label": "kubectl apply against prod", "severity": "high", "mode": "ask", "when": { "command": "\\\\bkubectl\\\\b[^|;]*\\\\bapply\\\\b[^|;]*--context[= ]\\\\S*prod" } }.',
          properties: {
            id: { type: "string", description: "1–48 lowercase letters, digits, - or _; must not be an id already in use." },
            label: { type: "string", description: "A short name the person will read, up to 80 characters." },
            blurb: { type: "string", description: "Optional: one sentence on what it catches." },
            severity: { type: "string", enum: ["critical", "high", "medium", "low"] },
            mode: { type: "string", enum: ["observe", "warn", "ask", "block"], description: "observe records, warn tells the agent, ask holds the call for the person, block refuses it." },
            when: {
              type: "object",
              description: "What the call is; every clause given must match. At least one clause.",
              properties: {
                tool: { type: "string", description: "Regex over the tool name (^Bash$, ^mcp__slack__send)." },
                command: { type: "string", description: "Regex over a shell call's command." },
                server: { type: "string", description: "Regex over the MCP server of mcp__<server>__<tool>." },
                target: { type: "string", description: "Regex over the call's target: a program name or a file path." },
                arg: { type: "object", description: "Argument field (dotted paths reach nested fields) → regex over its value.", additionalProperties: { type: "string" } },
              },
            },
            after: {
              type: "object",
              description: "Optional: only after this kind of data entered the session.",
              properties: { taint: { type: "string", enum: ["secret", "injection", "untrusted_fetch", "private_data", "sql_result"] } },
            },
            scope: { type: "object", description: "Optional: only under this directory.", properties: { cwd_prefix: { type: "string" } } },
          },
          required: ["id", "label", "severity", "mode", "when"],
        },
        reason: { type: "string", description: "One line for the person: why this rule is worth having (up to 300 characters)." },
        cwd: { type: "string", description: "Optional: the working directory you are in, shown to the person with the suggestion." },
      },
      required: ["rule", "reason"],
    },
    annotations: PROPOSES,
  },
] as const;

export const SERVER_INSTRUCTIONS =
  "Doorman guards tool calls on this computer. Before a shell command that reads credentials or sends data over the network, and before writing a file that may hold a secret, call doorman_check_tool_call and follow its answer. If a tool call was blocked or held, call doorman_explain_last_block rather than retrying or working around it; the person decides in Doorman.";

type ToolResult = { text: string; isError?: boolean };

function obj(value: unknown): Record<string, unknown> | undefined {
  return value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : undefined;
}
function str(value: unknown): string | undefined {
  return typeof value === "string" && value !== "" ? value : undefined;
}

/** Text from the spool or the ledger, flattened for an agent to read: no
 * control or invisible format characters, no line breaks, capped. A tool name
 * or label with a newline and "SYSTEM: …" behind it is a prompt injection. */
function oneLine(text: string, max: number): string {
  const flat = text.replace(/[\p{Cc}\p{Cf}\u2028\u2029]+/gu, " ").replace(/\s+/g, " ").trim();
  return flat.length > max ? `${flat.slice(0, max - 1)}…` : flat;
}

/** An identifier (tool name, unknown host id) kept to identifier characters. */
function safeName(name: string | undefined, fallback: string): string {
  if (!name) return fallback;
  const safe = name.replace(/[^A-Za-z0-9_.:@/+-]/g, "_");
  return safe.length > 80 ? `${safe.slice(0, 79)}…` : safe;
}

/** A host's label; a source this build doesn't know is shown as an identifier. */
function safeHostLabel(source: string | undefined): string {
  const label = hostLabel(source);
  return label === source ? safeName(source, "agent") : label;
}

/** The argument types a tool takes; a wrong type is the agent's error to fix. */
type ArgKind = "string" | "object" | "number";

function argProblem(args: Record<string, unknown>, spec: Readonly<Record<string, ArgKind>>): string | undefined {
  for (const [key, kind] of Object.entries(spec)) {
    const value = args[key];
    if (value === undefined) continue;
    const ok =
      kind === "object" ? obj(value) !== undefined : kind === "number" ? typeof value === "number" && Number.isFinite(value) : typeof value === "string";
    if (!ok) return `\`${key}\` must be ${kind === "object" ? "an object" : `a ${kind}`}.`;
  }
  return undefined;
}

/** The policy the guard reads, and whether the file there could not be read
 * — the guard then runs on its built-in defaults, which the person should know. */
function readPolicy(paths: McpPaths, io: McpReadIo): { policy: GuardPolicy; unreadable: boolean } {
  const text = io.readText(join(paths.guardDir, "policy.json"));
  let unreadable = false;
  if (text !== undefined) {
    try {
      const parsed: unknown = JSON.parse(text.replace(/^\uFEFF/, ""));
      unreadable = obj(parsed) === undefined;
    } catch {
      unreadable = true;
    }
  }
  return { policy: parsePolicy(text), unreadable };
}

const POLICY_UNREADABLE =
  "Doorman's policy file on this computer could not be read, so the guard is applying its built-in rules; the person can fix it by changing any setting in Doorman.";

/** A custom rule from a pack the app hides (rule-scope.ts) is never named. */
function hiddenCustomRules(policy: GuardPolicy): Set<string> {
  return new Set((policy.custom_rules ?? []).filter((r) => r.pack !== undefined && !rulePackShown(r.pack)).map((r) => customDetectorId(r.id)));
}

function labelOf(id: string, labels?: Record<string, string>): string {
  return labels?.[id] ?? (DETECTOR_LABELS as Record<string, string>)[id] ?? id;
}

const PROPOSE_ARGS: Readonly<Record<string, ArgKind>> = { rule: "object", reason: "string", cwd: "string" };

/**
 * Save a suggested rule for the person's review. The ids it must not reuse are
 * every rule the guard runs — the policy's `custom_rules` already carries the
 * enabled packs' rules under their `<pack>--<rule>` ids next to the person's
 * own — plus any other pending suggestion's (saveProposal reads those).
 */
export function proposeRule(args: Record<string, unknown>, paths: McpPaths, io: McpReadIo, session: McpSession): ToolResult {
  const problem = argProblem(args, PROPOSE_ARGS);
  if (problem) return { text: problem, isError: true };
  const reason = str(args.reason);
  if (obj(args.rule) === undefined || reason === undefined) return { text: "`rule` (an object) and `reason` (a string) are both required.", isError: true };
  const cwd = str(args.cwd);
  const result = saveProposal(paths.guardDir, parseCustomRules(readPolicy(paths, io).policy.custom_rules).map((r) => r.id), {
    rule: args.rule,
    reason,
    from: proposerLabel(session.clientName),
    ...(cwd === undefined ? {} : { cwd }),
    now: new Date(io.now()),
  });
  if (!result.ok) {
    return {
      text: ["Doorman did not save this suggestion:", ...result.problems.map((p) => `- ${p.field}: ${oneLine(p.message, 200)}`)].join("\n"),
      isError: true,
    };
  }
  const { proposal } = result;
  return {
    text: [
      `Saved for the person's review as suggestion ${proposal.id}: "${oneLine(proposal.rule.label, 80)}" (${proposal.rule.mode}). ${oneLine(describeRule(proposal.rule), 600)}`,
      `Nothing applies until they save it — in Doorman → Guardrails → Your rules, or with \`doorman custom-rules accept ${proposal.id}\`. Tell them it is waiting for their review.`,
    ].join("\n"),
  };
}

const CHECK_ARGS: Readonly<Record<string, ArgKind>> = { tool_name: "string", tool_input: "object", command: "string", cwd: "string", session_id: "string" };

export function checkToolCall(args: Record<string, unknown>, paths: McpPaths, io: McpReadIo): ToolResult {
  const problem = argProblem(args, CHECK_ARGS);
  if (problem) return { text: problem, isError: true };
  const command = str(args.command);
  if (command !== undefined && args.tool_input !== undefined) {
    return { text: "Give either `command` or `tool_input`, not both.", isError: true };
  }
  const toolName = str(args.tool_name) ?? (command ? "Bash" : undefined);
  const toolInput = obj(args.tool_input) ?? (command ? { command } : undefined);
  if (!toolName || !toolInput) {
    return { text: "Give either `command` (a shell command) or `tool_name` + `tool_input`.", isError: true };
  }
  const input: GuardHookInput = {
    tool_name: toolName,
    tool_input: toolInput,
    ...(str(args.cwd) ? { cwd: str(args.cwd) } : {}),
    ...(str(args.session_id) ? { session_id: str(args.session_id) } : {}),
  };
  const { policy, unreadable } = readPolicy(paths, io);
  const guardOff = io.guardHosts().length === 0;
  const result = evaluateToolCall(input, policy);
  const decision = result.decision;
  const labels = customDetectorLabels(policy.custom_rules ?? []);
  const hidden = hiddenCustomRules(policy);
  // Only rules the app shows are named to the agent (guard/rule-scope.ts): a
  // hidden rule's finding is recorded by the guard, not reported.
  const shown = (id: string) => ruleShown(id) && !hidden.has(id);
  const warned: string[] = decision.warned.filter(shown);
  const fired = [...new Set(result.findings.map((f) => f.detector as string))].filter(
    (id) => shown(id) && !warned.includes(id) && !decision.detectors.includes(id),
  );
  const notes = unreadable ? [POLICY_UNREADABLE] : [];
  if (decision.decision === "allow") {
    const lines = ["Decision: allow — no Doorman rule that is on holds or blocks this call."];
    if (fired.length > 0) lines.push(`Recorded, not held: ${fired.map((id) => labelOf(id, labels)).join(", ")}.`);
    if (warned.length > 0) lines.push(`Heads-up rules that would fire: ${warned.map((id) => labelOf(id, labels)).join(", ")}.`);
    // Not a clearance: the shown rules are about sensitive information only.
    lines.push(
      "Doorman's rules look for sensitive information: credentials, secrets, wallet keys and personal data. An allow is not a safety review of anything else the call does.",
    );
    if (guardOff) lines.push("Doorman's guard is not installed in any agent on this computer, so it holds or blocks nothing.");
    return { text: [...lines, ...notes].join("\n") };
  }
  const deny = decision.decision === "deny";
  const verb = guardOff
    ? `${deny ? "deny — Doorman's rules would block this call" : "ask — Doorman's rules would hold this call for the person to approve"}, but its guard is not installed in any agent on this computer, so nothing will ${deny ? "block" : "hold"} it`
    : deny
      ? "deny — the guard would block this call"
      : "ask — the guard would hold this call for the person to approve";
  const next = deny
    ? "Do not make this call or work around it; ask the user how to proceed."
    : guardOff
      ? "Ask the user before making this call; do not work around the rule."
      : "If you make this call, the user is asked first; do not work around the hold.";
  return {
    text: [
      `Decision: ${verb}.`,
      `Rules: ${decision.detectors.filter(shown).map((id) => labelOf(id, labels)).join(", ") || "a rule"}.`,
      `What to do: ${remedyFor(decision.detectors)} ${next}`,
      ...notes,
    ].join("\n"),
  };
}

/** One spool line, every field type-checked: a row a newer or broken writer
 * produced must not take the whole answer down. */
interface SpoolRow {
  atMs: number;
  session_id?: string;
  source?: string;
  tool_name?: string;
  cwd?: string;
  decision?: string;
  resolution?: HoldResolution;
  held?: boolean;
  /** When the hold began — only on a hold's resolution line (hold.ts HoldTelemetry). */
  heldAtMs?: number;
  decided_via?: string;
  detectors: string[];
  labels: Record<string, string>;
}

const HOLD_RESOLUTIONS: readonly string[] = ["allowed", "denied", "timeout", "unattended", "unavailable"];

function spoolRow(value: unknown): SpoolRow | undefined {
  const r = obj(value);
  if (!r) return undefined;
  const findings = Array.isArray(r.findings) ? r.findings : [];
  const detectors = [...new Set(findings.map((f) => obj(f)?.detector).filter((d): d is string => typeof d === "string"))];
  const labels: Record<string, string> = {};
  for (const [id, label] of Object.entries(obj(r.detector_labels) ?? {})) if (typeof label === "string") labels[id] = label;
  const heldAtMs = str(r.held_at) ? Date.parse(r.held_at as string) : NaN;
  const resolution = str(r.resolution);
  return {
    atMs: str(r.at) ? Date.parse(r.at as string) : NaN,
    session_id: str(r.session_id),
    source: str(r.source),
    tool_name: str(r.tool_name),
    cwd: str(r.cwd),
    decision: str(r.decision),
    ...(resolution !== undefined && HOLD_RESOLUTIONS.includes(resolution) ? { resolution: resolution as HoldResolution } : {}),
    ...(typeof r.held === "boolean" ? { held: r.held } : {}),
    ...(Number.isFinite(heldAtMs) ? { heldAtMs } : {}),
    ...(str(r.decided_via) ? { decided_via: str(r.decided_via) } : {}),
    detectors,
    labels,
  };
}

/** One held or blocked call: the guard writes a detection line and, for a
 * hold, a resolution line when it ends (guard.ts spool). */
interface SpooledCall {
  first: SpoolRow;
  last: SpoolRow;
}

/** How far a resolution line's `held_at` may trail its detection line's `at`
 * (the two are written by the same guard process, milliseconds apart). */
const FOLD_WINDOW_MS = 10_000;

/**
 * Detection and resolution lines → one entry per call. A resolution line
 * carries `held_at`, the moment its hold began; its detection line is the
 * latest still-open hold of the same (session, host, tool, cwd) written at or
 * just before then — so two parallel holds in one session pair up correctly.
 */
function foldCalls(rows: readonly SpoolRow[]): SpooledCall[] {
  const calls: SpooledCall[] = [];
  let open: SpooledCall[] = [];
  for (const row of rows) {
    if (row.heldAtMs !== undefined) {
      const heldAt = row.heldAtMs;
      // A hold lasts at most HOLD_SECONDS_MAX; anything older is never resolved now.
      if (Number.isFinite(row.atMs)) open = open.filter((c) => !(row.atMs - c.first.atMs > 400_000));
      let best: SpooledCall | undefined;
      for (const candidate of open) {
        const d = candidate.first;
        if (d.session_id !== row.session_id || d.source !== row.source || d.tool_name !== row.tool_name || d.cwd !== row.cwd) continue;
        if (!(d.atMs <= heldAt + 1000 && heldAt - d.atMs <= FOLD_WINDOW_MS)) continue;
        if (!best || d.atMs > best.first.atMs) best = candidate;
      }
      if (best) {
        best.last = row;
        open = open.filter((c) => c !== best);
        continue;
      }
    }
    const call = { first: row, last: row };
    calls.push(call);
    if (row.decision === "ask" && row.held !== false && row.resolution === undefined) open.push(call);
  }
  return calls;
}

/** A cwd as a comparable key: no trailing separator, symlinks resolved, and
 * macOS's /private/tmp, /private/var, /private/etc read as /tmp, /var, /etc
 * (a deleted directory no longer resolves, so that fold is lexical too). */
function pathKey(path: string, io: McpReadIo, cache: Map<string, string>): string {
  const cached = cache.get(path);
  if (cached !== undefined) return cached;
  const trimmed = path.length > 1 ? path.replace(/[\\/]+$/, "") || path.slice(0, 1) : path;
  const key = io.realpath(trimmed).replace(/^\/private(?=\/(?:tmp|var|etc)(?:\/|$))/, "");
  cache.set(path, key);
  return key;
}

function outcomeOf(r: SpoolRow, stale: boolean): string {
  const deny = r.decision === "deny";
  switch (r.resolution) {
    case "allowed":
      return "the person allowed it";
    case "denied":
      return "the person denied it";
    case "timeout":
      return deny ? "nobody answered in time, so it did not run" : "nobody answered in time; handed to the agent's own permission prompt";
    case "unattended":
      return "Doorman stopped listening before anyone answered; handed to the agent's own permission prompt";
    case "unavailable":
      return "not run: nobody could be asked";
    default:
      if (deny) return "blocked by policy";
      if (r.held === false) return "not held; handed to the agent's own permission prompt";
      return stale ? "held for approval; no answer was recorded" : "held for approval, waiting for the person's answer";
  }
}

const EXPLAIN_ARGS: Readonly<Record<string, ArgKind>> = { session_id: "string", cwd: "string", limit: "number" };

export function explainLastBlock(args: Record<string, unknown>, paths: McpPaths, io: McpReadIo): ToolResult {
  const problem = argProblem(args, EXPLAIN_ARGS);
  if (problem) return { text: problem, isError: true };
  const sessionId = str(args.session_id);
  const cwd = str(args.cwd);
  const limit = typeof args.limit === "number" ? Math.min(20, Math.max(1, Math.floor(args.limit))) : 3;
  const rows: SpoolRow[] = [];
  for (const line of (io.readText(join(paths.guardDir, "spool.jsonl")) ?? "").split("\n")) {
    if (line.trim() === "") continue;
    let row: SpoolRow | undefined;
    try {
      row = spoolRow(JSON.parse(line));
    } catch {
      continue; // a half-written line
    }
    if (row && (row.decision === "ask" || row.decision === "deny" || row.resolution !== undefined)) rows.push(row);
  }
  const cache = new Map<string, string>();
  const cwdKey = cwd === undefined ? undefined : pathKey(cwd, io, cache);
  const scoped = foldCalls(rows)
    .filter((c) => cwdKey === undefined || (c.first.cwd !== undefined && pathKey(c.first.cwd, io, cache) === cwdKey))
    .filter((c) => sessionId === undefined || c.first.session_id === sessionId)
    .sort((a, b) => (Number.isFinite(a.last.atMs) ? a.last.atMs : 0) - (Number.isFinite(b.last.atMs) ? b.last.atMs : 0));
  // Without a session id, the calling agent's own session when we can tell —
  // and when it has nothing, the others, said to be the others.
  const current = sessionId === undefined ? io.currentSession(paths.guardDir) : undefined;
  let picked = scoped;
  let header: string | undefined;
  if (current) {
    const mine = scoped.filter((c) => c.first.session_id === current.session_id);
    if (mine.length > 0) picked = mine;
    else if (scoped.length > 0) header = "Nothing was held or blocked in this session. These calls are from other agent sessions on this computer:";
  }
  const recent = picked.slice(-limit).reverse();
  if (recent.length === 0) {
    return {
      text: sessionId || cwd
        ? "Doorman has held or blocked nothing for that session or directory. If a call failed, the cause was not the guard."
        : "Doorman has held or blocked nothing recently on this computer.",
    };
  }
  if (!current && !sessionId && new Set(recent.map((c) => c.first.session_id ?? "")).size > 1) {
    header = "These calls come from more than one agent session on this computer; pass session_id to see one session only.";
  }
  const { policy } = readPolicy(paths, io);
  const staleAfterMs = (policy.confirm.hold_seconds + HOOK_TIMEOUT_SLACK_SECONDS) * 1000;
  const out = recent.map(({ first, last }) => {
    const labels = { ...first.labels, ...last.labels };
    const detectors = [...new Set([...first.detectors, ...last.detectors])].filter(ruleShown);
    const named = detectors.map((id) => oneLine(labelOf(id, labels), 80));
    const decision = last.decision === "deny" ? "deny" : "ask";
    const pending = last.resolution === undefined && decision === "ask" && last.held !== false;
    const stale = pending && !(io.now() - last.atMs <= staleAfterMs);
    const reason = `Doorman flagged this tool call: ${named.join(", ") || "a rule"}.`;
    const text = stale
      ? `${reason} ${remedyFor(detectors)} Doorman has no record of how this hold ended. Do not retry it or work around it; ask the user whether it should run.`
      : agentFacingReason({
          decision,
          reason,
          detectors,
          ...(last.resolution === undefined ? {} : { resolution: last.resolution }),
          policy,
          ...(last.held === undefined ? {} : { held: last.held }),
          ...(last.decided_via === undefined ? {} : { decidedVia: last.decided_via }),
          holdingOff: !policy.confirm.interactive,
        });
    const at = Number.isFinite(first.atMs) ? new Date(first.atMs).toISOString() : "?";
    return `${at} · ${safeName(first.tool_name, "tool")} on ${safeHostLabel(first.source)} — ${outcomeOf(last, stale)}.\n${text}`;
  });
  return { text: [...(header ? [header] : []), ...out].join("\n\n") };
}

interface StoredTurn {
  role?: string;
  at?: string;
  session_id?: string;
  source?: string;
  cwd?: string;
  model?: string;
  usage?: { input_tokens?: unknown; output_tokens?: unknown };
}

const SPEND_ARGS: Readonly<Record<string, ArgKind>> = { session_id: "string", cwd: "string", since_hours: "number" };

export function sessionSpend(args: Record<string, unknown>, paths: McpPaths, io: McpReadIo): ToolResult {
  const problem = argProblem(args, SPEND_ARGS);
  if (problem) return { text: problem, isError: true };
  const text = io.readText(join(paths.storeDir, "turns.jsonl"));
  const sessionId = str(args.session_id);
  const cwd = str(args.cwd);
  const hours = typeof args.since_hours === "number" ? Math.min(24 * 90, Math.max(0.1, args.since_hours)) : 24;
  const since = io.now() - hours * 3_600_000;
  const cache = new Map<string, string>();
  const cwdKey = cwd === undefined ? undefined : pathKey(cwd, io, cache);
  const byModel = new Map<string, { calls: number; input: number; output: number }>();
  const bySource = new Map<string, number>();
  let unmetered = 0;
  const sessions = new Set<string>();
  const count = (v: unknown) => (typeof v === "number" && Number.isFinite(v) && v > 0 ? v : 0);
  for (const line of (text ?? "").split("\n")) {
    if (line.trim() === "") continue;
    let turn: StoredTurn | undefined;
    try {
      turn = obj(JSON.parse(line)) as StoredTurn | undefined;
    } catch {
      continue;
    }
    if (!turn || turn.role !== "assistant") continue;
    if (sessionId && turn.session_id !== sessionId) continue;
    if (cwdKey !== undefined && (typeof turn.cwd !== "string" || pathKey(turn.cwd, io, cache) !== cwdKey)) continue;
    const at = typeof turn.at === "string" ? Date.parse(turn.at) : NaN;
    if (!sessionId && (!Number.isFinite(at) || at < since)) continue;
    if (typeof turn.session_id === "string") sessions.add(turn.session_id);
    // Tokens, never dollars: the on-device price is an estimate the app does
    // not stand behind, and an agent would repeat it as fact.
    const usage = obj(turn.usage);
    const input = count(usage?.input_tokens);
    const output = count(usage?.output_tokens);
    if (input + output > 0) {
      const key = typeof turn.model === "string" && turn.model !== "" ? oneLine(turn.model, 80) : "unknown model";
      const row = byModel.get(key) ?? { calls: 0, input: 0, output: 0 };
      row.calls += 1;
      row.input += input;
      row.output += output;
      byModel.set(key, row);
      const source = typeof turn.source === "string" ? turn.source : "?";
      bySource.set(source, (bySource.get(source) ?? 0) + input + output);
    } else {
      unmetered += 1;
    }
  }
  const scope = sessionId
    ? `session ${safeName(sessionId, "?")}`
    : cwd
      ? `${oneLine(cwd, 200)} (last ${hours}h)`
      : `every agent on this computer (last ${hours}h)`;
  if (byModel.size === 0 && unmetered === 0) return { text: `Doorman has metered nothing for ${scope}.` };
  const totalIn = [...byModel.values()].reduce((sum, r) => sum + r.input, 0);
  const totalOut = [...byModel.values()].reduce((sum, r) => sum + r.output, 0);
  const n = (v: number) => v.toLocaleString("en-US");
  const lines = [`Metered for ${scope}: ${n(totalIn + totalOut)} tokens (${n(totalIn)} in / ${n(totalOut)} out) across ${sessions.size} session(s).`];
  for (const [model, row] of [...byModel].sort((a, b) => b[1].input + b[1].output - (a[1].input + a[1].output))) {
    lines.push(`· ${model}: ${row.calls} call(s), ${n(row.input)} in / ${n(row.output)} out tokens`);
  }
  if (bySource.size > 1) {
    lines.push(`By agent: ${[...bySource].map(([s, tokens]) => `${safeHostLabel(s)} ${n(tokens)} tokens`).join(", ")}.`);
  }
  if (unmetered > 0) lines.push(`${unmetered} call(s) carried no token counts and are not in the total.`);
  lines.push("No dollar figure is given: Doorman reports measured tokens, not an estimated cost.");
  return { text: lines.join("\n") };
}

/** Whether the live heartbeat is `doorman watch`'s (cli/commands/watch.ts
 * writes `version: "cli-<version>"`) rather than the app's. */
function watchAnswers(heartbeat: string | undefined): boolean {
  try {
    const version = obj(JSON.parse(heartbeat ?? ""))?.version;
    return typeof version === "string" && version.startsWith("cli-");
  } catch {
    return false;
  }
}

export function status(paths: McpPaths, io: McpReadIo): ToolResult {
  const { policy, unreadable } = readPolicy(paths, io);
  const hold: string[] = [];
  const block: string[] = [];
  for (const [id, mode] of Object.entries(policy.modes)) {
    if (mode === "ask") hold.push(labelOf(id));
    else if (mode === "block") block.push(labelOf(id));
  }
  // The person's own rules and the enabled packs' (the app merges both into
  // `custom_rules`), minus any from a pack the app hides.
  for (const rule of policy.custom_rules ?? []) {
    if (rule.enabled === false || (rule.pack !== undefined && !rulePackShown(rule.pack))) continue;
    if (rule.mode === "ask") hold.push(oneLine(rule.label, 80));
    else if (rule.mode === "block") block.push(oneLine(rule.label, 80));
  }
  const guarded = io.guardHosts();
  const listening = io.appListening(paths.guardDir);
  return {
    text: [
      guarded.length > 0
        ? `Doorman's guard is installed in: ${guarded.join(", ")}.`
        : "Doorman's guard is not installed in any agent on this computer, so no tool call is held or blocked. The person can install it from the Doorman app or with `doorman guard install`.",
      ...(unreadable ? [POLICY_UNREADABLE] : []),
      listening
        ? watchAnswers(io.readText(heartbeatPath(paths.guardDir)))
          ? "`doorman watch` is running in a terminal: a held call waits for the person to answer there."
          : "The Doorman app is running: a held call waits for the person to answer there."
        : // Absent app = the unattended rule (confirm.unattended, review F1), not
          // the timeout one: a host with its own prompt is handed the question,
          // every other host gets a deny by default.
          `The Doorman app is not running: a call that needs approval is handed to the agent's own prompt where it has one, and otherwise ${policy.confirm.unattended === "deny" ? "denied (not run) until the app is open" : "warned about and continued"} rather than held.`,
      ...(policy.confirm.interactive ? [] : ["Holding is switched off: a call a rule would hold goes to the agent's own permission prompt."]),
      block.length > 0 ? `Rules that block: ${block.join(", ")}.` : "No rule blocks outright.",
      hold.length > 0 ? `Rules that hold for approval: ${hold.join(", ")}.` : "No rule holds a call.",
      `Hold window: ${policy.confirm.hold_seconds}s, then ${policy.confirm.on_timeout}.`,
      `When the app can't ask: ${policy.confirm.unattended === "deny" ? "deny" : "continue with a warning"}.`,
      `Guard hosts known: ${HOSTS.map((h) => h.label).join(", ")}.`,
    ].join("\n"),
  };
}

// ---- JSON-RPC ---------------------------------------------------------------

/** Per-connection state: the revision `initialize` settled on. */
export interface McpSession {
  protocolVersion?: string;
  /** `initialize` clientInfo.name — who a rule proposal says it came from. */
  clientName?: string;
}

/** A response line. `idJson` is the id as JSON TEXT, so an id beyond 2^53
 * goes back digit for digit. */
function reply(idJson: string, result: unknown): string {
  return `{"jsonrpc":"2.0","id":${idJson},"result":${JSON.stringify(result)}}`;
}
function error(idJson: string, code: number, message: string): string {
  return `{"jsonrpc":"2.0","id":${idJson},"error":${JSON.stringify({ code, message })}}`;
}

/**
 * The raw text of the numeric `id` member of the top-level object (index 0),
 * or of each object element of a top-level array (by element index). Only
 * read for an id `JSON.parse` could not hold exactly. Linear, string-aware.
 */
function rawNumericIds(raw: string): (string | undefined)[] {
  const out: (string | undefined)[] = [];
  const stack: string[] = [];
  let topArray = false;
  let element = 0;
  for (let i = 0; i < raw.length; i++) {
    const c = raw[i];
    if (c === '"') {
      let j = i + 1;
      while (j < raw.length && raw[j] !== '"') j += raw[j] === "\\" ? 2 : 1;
      const memberDepth = topArray ? 2 : 1;
      if (stack.length === memberDepth && stack[stack.length - 1] === "{") {
        let k = j + 1;
        while (k < raw.length && /\s/.test(raw[k]!)) k++;
        if (raw[k] === ":") {
          let key: unknown;
          try {
            key = JSON.parse(raw.slice(i, j + 1));
          } catch {
            key = undefined;
          }
          if (key === "id") {
            k++;
            while (k < raw.length && /\s/.test(raw[k]!)) k++;
            const number = /^-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?/.exec(raw.slice(k, k + 400));
            if (number) out[topArray ? element : 0] = number[0];
          }
        }
      }
      i = j;
    } else if (c === "{" || c === "[") {
      if (stack.length === 0 && c === "[") topArray = true;
      stack.push(c);
    } else if (c === "}" || c === "]") {
      stack.pop();
    } else if (c === "," && topArray && stack.length === 1) {
      element++;
    }
  }
  return out;
}

function unsafeNumericId(message: unknown): boolean {
  const id = obj(message)?.id;
  return typeof id === "number" && !Number.isSafeInteger(id);
}

/** One request object → zero or one response line. */
function handleOne(value: unknown, rawId: string | undefined, paths: McpPaths, io: McpReadIo, session: McpSession, inBatch: boolean): string | undefined {
  const message = obj(value);
  if (!message) return error("null", -32600, "Invalid Request");
  const hasId = Object.hasOwn(message, "id");
  const method = message.method;
  // A client's response to us (we never send requests): nothing to answer.
  if (method === undefined && (Object.hasOwn(message, "result") || Object.hasOwn(message, "error"))) return undefined;
  // A notification is never answered (JSON-RPC 2.0 §4.1), whatever its
  // method — and nothing here has an effect worth running unanswered.
  if (!hasId) return undefined;
  const id = message.id;
  const idValid = typeof id === "string" || (typeof id === "number" && Number.isFinite(id));
  const idJson = !idValid ? "null" : typeof id === "number" && !Number.isSafeInteger(id) && rawId !== undefined ? rawId : JSON.stringify(id);
  if (!idValid || message.jsonrpc !== "2.0" || typeof method !== "string" || method === "") return error(idJson, -32600, "Invalid Request");
  if (message.params !== undefined && !obj(message.params)) return error(idJson, -32602, "Invalid params: params must be an object");
  const params = obj(message.params) ?? {};

  switch (method) {
    case "initialize": {
      if (inBatch) return error(idJson, -32600, "Invalid Request: initialize cannot be part of a batch");
      const requested = str(params.protocolVersion);
      const version = requested !== undefined && SUPPORTED_PROTOCOL_VERSIONS.includes(requested) ? requested : LATEST_PROTOCOL_VERSION;
      session.protocolVersion = version;
      const clientName = str(obj(params.clientInfo)?.name);
      if (clientName !== undefined) session.clientName = clientName;
      return reply(idJson, {
        protocolVersion: version,
        capabilities: { tools: { listChanged: false } },
        serverInfo: { name: MCP_SERVER_NAME, title: "Doorman", version: MCP_SERVER_VERSION },
        instructions: SERVER_INSTRUCTIONS,
      });
    }
    case "ping":
      return reply(idJson, {});
    case "tools/list":
      return reply(idJson, { tools: TOOLS });
    case "tools/call": {
      const name = str(params.name);
      if (params.arguments !== undefined && !obj(params.arguments)) return error(idJson, -32602, "Invalid params: arguments must be an object");
      const args = obj(params.arguments) ?? {};
      let result: ToolResult;
      try {
        switch (name) {
          case "doorman_check_tool_call":
            result = checkToolCall(args, paths, io);
            break;
          case "doorman_explain_last_block":
            result = explainLastBlock(args, paths, io);
            break;
          case "doorman_session_spend":
            result = sessionSpend(args, paths, io);
            break;
          case "doorman_status":
            result = status(paths, io);
            break;
          case "doorman_propose_rule":
            result = proposeRule(args, paths, io, session);
            break;
          default:
            // The caller's own string is not echoed back.
            return error(idJson, -32602, `Unknown tool. Doorman's tools: ${TOOLS.map((t) => t.name).join(", ")}.`);
        }
      } catch (err) {
        result = { text: `Doorman could not answer: ${oneLine(String(err), 300)}`, isError: true };
      }
      return reply(idJson, {
        content: [{ type: "text", text: result.text }],
        ...(result.isError ? { isError: true } : {}),
      });
    }
    default:
      return error(idJson, -32601, "Method not found");
  }
}

/** One incoming line → zero or one outgoing line. Pure over `paths`/`io`,
 * apart from `session`, which `initialize` settles. */
export function handleMessage(raw: string, paths: McpPaths, io: McpReadIo, session: McpSession = {}): string | undefined {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return error("null", -32700, "Parse error");
  }
  if (!Array.isArray(parsed)) {
    return handleOne(parsed, unsafeNumericId(parsed) ? rawNumericIds(raw)[0] : undefined, paths, io, session, false);
  }
  // Batches exist only in 2025-03-26: added there, removed in 2025-06-18.
  if (session.protocolVersion !== BATCH_PROTOCOL_VERSION) {
    return error("null", -32600, `Invalid Request: batches are not supported${session.protocolVersion ? ` in protocol version ${session.protocolVersion}` : " before initialize"}`);
  }
  if (parsed.length === 0) return error("null", -32600, "Invalid Request");
  const rawIds = parsed.some(unsafeNumericId) ? rawNumericIds(raw) : [];
  const out = parsed.map((m, i) => handleOne(m, rawIds[i], paths, io, session, true)).filter((line): line is string => line !== undefined);
  return out.length > 0 ? `[${out.join(",")}]` : undefined;
}

// ---- process ----------------------------------------------------------------

function main(): void {
  const paths = defaultPaths(__dirname);
  const io = realIo();
  const session: McpSession = {};
  const stdout = process.stdout;
  // The reader is gone (EPIPE): nobody is left to answer.
  stdout.on("error", () => process.exit(0));
  const answer = (rawLine: string): void => {
    const line = rawLine.endsWith("\r") ? rawLine.slice(0, -1) : rawLine;
    if (line.trim() === "") return;
    let out: string | undefined;
    try {
      out = handleMessage(line, paths, io, session);
    } catch (err) {
      process.stderr.write(`[doorman mcp] ${String(err)}\n`);
      out = undefined;
    }
    if (out !== undefined) stdout.write(`${out}\n`);
  };
  const tooLarge = () => stdout.write(`${error("null", -32600, `Invalid Request: message longer than ${MAX_MESSAGE_CHARS} characters`)}\n`);
  // The partial line so far, as pieces: each chunk is scanned once from where
  // it starts, never the whole buffer again (that was quadratic).
  let pieces: string[] = [];
  let size = 0;
  let skipping = false;
  process.stdin.setEncoding("utf8");
  process.stdin.on("data", (chunk: string) => {
    let start = 0;
    let newline: number;
    while ((newline = chunk.indexOf("\n", start)) >= 0) {
      const tail = chunk.slice(start, newline);
      start = newline + 1;
      if (skipping) {
        skipping = false;
      } else if (size + tail.length > MAX_MESSAGE_CHARS) {
        tooLarge();
      } else {
        answer(pieces.length === 0 ? tail : pieces.join("") + tail);
      }
      pieces = [];
      size = 0;
    }
    if (start < chunk.length && !skipping) {
      const rest = chunk.slice(start);
      size += rest.length;
      if (size > MAX_MESSAGE_CHARS) {
        // Drop it now rather than hold it: the rest of this line is skipped.
        tooLarge();
        skipping = true;
        pieces = [];
        size = 0;
      } else {
        pieces.push(rest);
      }
    }
  });
  process.stdin.on("end", () => {
    // A last message without its newline is still a message.
    if (!skipping && pieces.length > 0) answer(pieces.join(""));
    // Exit once every queued response has reached the pipe: stdout is
    // asynchronous on a pipe, and exiting now dropped the queued answers.
    stdout.write("", () => process.exit(0));
  });
}

// Only run when invoked directly (not when imported by a test).
if (process.argv[1] && process.argv[1].endsWith("doorman-mcp.js")) {
  main();
}
