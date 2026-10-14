/**
 * Armed-session escalation — the enforceable half of the radar-only
 * `flow_injection_followed` rule.
 *
 * The guard is PreToolUse: it never sees tool OUTPUT, so it cannot know on its
 * own that an injected instruction arrived three calls ago. The app's capture
 * engine does — it tails the transcript, runs the flow rules, and writes the
 * sessions currently carrying a live injection taint into
 * `<guardDir>/armed.json` (lib/flow-rules.ts `armedInjectionTaints`,
 * enforcement.ts `writeArmedSessions`). This module is the guard-side reader:
 * given the current call, does it MATCH a sink an armed injection could be
 * steering? If so, the call escalates to `ask` with the arming evidence as the
 * reason — "an injection arrived" becomes "an injection is being obeyed, and
 * you're being asked first".
 *
 * Honest limits, stated where the code lives:
 *  - BEST EFFORT. The evidence travels transcript flush → watcher → armed.json;
 *    a sink fired inside that window (seconds) is not held. This narrows the
 *    race, it does not close it — the radar's post-hoc flow finding remains
 *    the complete record.
 *  - Injection taints ONLY. Secret-read taints escalating every later curl
 *    would interrupt ordinary development constantly; the injection→sink pair
 *    is the one chain severe enough (critical) and rare enough to hold.
 *
 * The sink vocabulary deliberately mirrors lib/flow-rules.ts' classifySinks —
 * duplicated (small, like guard.ts' toolTarget) rather than imported, because
 * this directory is copied verbatim to userData and may import nothing outside
 * itself. Staleness mirrors FLOW_MAX_GAP_MS; the call-count bound lives on the
 * engine side, which drops a session from armed.json as its taints go stale.
 *
 * Self-containment rule: nothing here may import from outside main/guard/.
 */

import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
  invokedCommands,
  networkInvocationIn,
  programOf,
  SECRET_PATH_PATTERNS,
  secretPathReadIn,
} from "./security-detect.js";
import {
  customDetectorId,
  customWhenMatches,
  type CustomDetectorId,
  type CustomRule,
  type CustomRuleInput,
} from "./custom-rules.js";

export const ARMED_FILE = "armed.json";

/** Mirrors lib/flow-rules.ts FLOW_MAX_GAP_MS — a taint older than this is a
 * different story, not a live injection. */
export const ARMED_MAX_AGE_MS = 30 * 60_000;

/** One live injection taint, as the engine recorded it. Everything here is
 * already masked/sanitized (the engine builds it from redacted text). */
export interface ArmedTaint {
  /** e.g. `injected instruction (injected_instruction (override))` */
  name: string;
  /** When the tainting output arrived (ISO). */
  at: string;
  /** Masked one-liner of the tainting output, for the approval card. */
  excerpt: string;
}

export interface ArmedSessionsFile {
  version: 1;
  sessions: Record<string, { taints: ArmedTaint[]; updated_at: string }>;
}

/** The injection taints currently live for a session — [] on any problem
 * (missing file, malformed JSON, stale entries): absence of arming must never
 * break a tool call. */
export function readArmedTaints(
  guardDir: string,
  sessionId: string | undefined,
  nowMs: number = Date.now(),
): ArmedTaint[] {
  if (!sessionId) return [];
  let raw: string;
  try {
    raw = readFileSync(join(guardDir, ARMED_FILE), "utf8");
  } catch {
    return [];
  }
  try {
    const parsed = JSON.parse(raw) as Partial<ArmedSessionsFile>;
    const entry = parsed?.sessions?.[sessionId];
    if (!entry || !Array.isArray(entry.taints)) return [];
    return entry.taints.filter((t): t is ArmedTaint => {
      if (!t || typeof t !== "object") return false;
      if (typeof t.name !== "string" || typeof t.at !== "string") return false;
      const atMs = Date.parse(t.at);
      return Number.isFinite(atMs) && nowMs - atMs <= ARMED_MAX_AGE_MS;
    });
  } catch {
    return [];
  }
}

// ── Sink classification — THE definition, shared with lib/flow-rules.ts ──────
//
// The guard bundle may import nothing outside this directory, but lib/ may
// import from here — so the sink vocabulary lives on this side and the flow
// engine reads it. It used to be mirrored by hand and drifted: the guard held
// `mcp__linear__create_comment` as a "send" the radar never reported.

/** Interpreting or executing something — tested against an invocation HEAD
 * (execInvocationIn), so `echo source me` and a commit message that says
 * "sh -c" are not executions. A bare shell (the tail of `echo … | base64 -d |
 * sh`) counts: the interpreter with no script argument is the "run what you
 * can't read" shape, not a no-op. */
export const EXEC_VERB_RE =
  /^(?:\S*\/)?(?:ba|z|k|d|fi)?sh(?:\s+\S|\s*$)|^(?:\S*\/)?(?:python[0-9.]*|node|deno|bun|ruby|perl|php|osascript)\s+\S|^(?:eval|source|\.)\s+\S|^(?:\S*\/)?chmod\s+\+x\s|^\S*\/[\w.-]+\.(?:sh|bash|zsh|py|js|mjs|cjs|ts|rb|pl|php|command)(?:\s|$)/;

/** The head that executes code, or undefined. The last alternative above is a
 * script run BY PATH (`./install.sh`, `/tmp/x.py`) — a path to a script file,
 * not any path, so `./node_modules/.bin/tsc` is not an exec sink. */
export function execInvocationIn(command: string): string | undefined {
  return invokedCommands(command).find((head) => EXEC_VERB_RE.test(head));
}

/** Web-fetch-shaped tools: an egress channel that carries no command line
 * (`WebFetch`, `fetch`, `mcp__fetch__get`, …). */
export const FETCH_TOOL_RE = /(?:^|[_-])(?:web)?fetch(?:$|[_-])/i;

/** Genuinely-outbound verbs on an MCP tool — the send half of read→send.
 * Deliberately EXCLUDES `create`/`add`/`comment`: reading a tracker item then
 * `create_comment` / `add_comment` is ordinary write-back, not exfiltration,
 * and it was the single biggest source of read→send noise for tracker-MCP
 * users. `send_message`, `forward`, `email`, `dm`, `share`, `upload`, `post`
 * (to a webhook) still fire, so the canonical inbox→outbound shape is
 * untouched. */
export const SEND_TOOL_RE =
  /(?:^|_)(?:send|post|reply|forward|share|upload|publish|invite|message|email|dm)(?:_|$)/i;

/** `mcp__<server>__<tool>` — group 1 is the server. */
export const MCP_SERVER_RE = /^mcp__([^_]+(?:_[^_]+)*?)__/;

/**
 * A command that MOVES FUNDS or broadcasts a signed transaction: node-wallet
 * sends, Foundry/Hardhat broadcasts to a non-local network, Solana / SPL
 * transfers, Sui / Aptos / NEAR / Cosmos-SDK transfers, a raw
 * `eth_sendRawTransaction`. The `spend` sink — infra_mutation for money.
 * A LOCAL or TESTNET target is not money: an `--rpc-url` at 127.0.0.1 /
 * localhost / anvil, chain id 31337, a named testnet, or Solana's -ul/-ud/-ut
 * is a developer's loop and is exempt — the same doctrine as the egress
 * detector's local-host exemption (2026-09-09, after the pack shipped at ask).
 * The crypto_operations rule pack (rule-packs.ts) carries the same shapes as
 * editable rules; this is the flow engine's and the armed escalation's copy,
 * so "an injection arrived, then a transfer ran" is held even when the pack is
 * off. Keep the two in step.
 */
export const SPEND_COMMAND_RE =
  /(?:^|\s)bitcoin-cli\b[^|;\n]*?\s(?:sendtoaddress|sendmany|send|sendall|walletprocesspsbt|signrawtransactionwithwallet)\b|(?:^|\s)electrum\b[^|;\n]*?\s(?:payto|paytomany|broadcast)\b|(?:^|\s)cast\s+(?:send|publish|mktx)\b(?![^|;\n]*(?:--rpc-url|-r|--fork-url)[= ]\S*(?:127\.0\.0\.1|localhost|anvil)\b)(?![^|;\n]*--chain(?:-id)?[= ](?:31337|anvil|localhost|sepolia|holesky|goerli)\b)|(?:^|\s)forge\s+script\b(?![^|;\n]*(?:--rpc-url|-r|--fork-url)[= ]\S*(?:127\.0\.0\.1|localhost|anvil)\b)(?![^|;\n]*--chain(?:-id)?[= ](?:31337|anvil|localhost|sepolia|holesky|goerli)\b)[^|;\n]*--broadcast\b|(?:^|\s)hardhat\s+(?:run|ignition\s+deploy)\b[^|;\n]*--network\s+(?!localhost\b|hardhat\b|anvil\b|sepolia\b|holesky\b|goerli\b)\S|(?:^|\s)solana\s+transfer(?![\w-])(?![^|;\n]*(?:-u\s*[ldt]\b|--url[= ]\S*(?:localhost|devnet|testnet|127\.0\.0\.1)\b|--url[= ][ldt]\b))|(?:^|\s)spl-token\s+(?:transfer|burn|close)\b(?![^|;\n]*(?:-u\s*[ldt]\b|--url[= ]\S*(?:localhost|devnet|testnet|127\.0\.0\.1)\b|--url[= ][ldt]\b))|(?:^|\s)sui\s+client\s+(?:transfer|transfer-sui|pay|pay-sui|pay-all-sui|call)\b|(?:^|\s)aptos\s+(?:account\s+transfer|move\s+run)\b|(?:^|\s)near\s+(?:send|send-near)\b|(?:^|\s)\w+d\s+tx\s+bank\s+send\b|(?<!(?:127\.0\.0\.1|localhost)[^|;\n]*)\beth_sendRawTransaction\b/i;

/**
 * The head that moves funds, or undefined. SPEND_COMMAND_RE's alternatives
 * each allow a leading space, so a head only counts when the match starts at
 * the program — `echo cast send` and a commit message are not transfers. The
 * one exception is a raw `eth_sendRawTransaction`, which lives inside a JSON
 * body by nature, and counts only when the head is an HTTP client or `cast`.
 */
export function spendInvocationIn(command: string): string | undefined {
  return invokedCommands(command).find((head) => {
    const match = SPEND_COMMAND_RE.exec(head);
    if (!match) return false;
    if (/eth_sendRawTransaction/.test(match[0])) {
      return /^(?:curl|wget|http|https|xh|cast)$/.test(programOf(head));
    }
    return match.index === 0 || head.slice(0, match.index).trim() === "";
  });
}

/**
 * Per-unit detectors whose subject is "text from outside told the agent to do
 * something" — what arms a session (here), taints a flow (lib/flow-rules.ts)
 * and arms a gateway connection (gateway/mcp-gateway.ts). One set, so the three
 * never disagree about what counts: an invisible-character payload or a
 * data-carrying link in fetched content is an injection channel whether or not
 * it also spelled out an instruction.
 */
export const INJECTION_MARKER_DETECTORS: ReadonlySet<string> = new Set([
  "injected_instruction",
  "invisible_unicode",
  "exfil_render_link",
]);

/** The command string out of a tool call's input — flow-rules' commandOf,
 * operating on the parsed object the guard already holds. */
function commandOf(toolName: string | undefined, input: unknown): string | undefined {
  if (!input || typeof input !== "object") return undefined;
  const record = input as Record<string, unknown>;
  for (const key of ["command", "cmd", "script", "commandLine"]) {
    const value = record[key];
    if (typeof value === "string" && value !== "") return value;
  }
  if (toolName && /shell|bash/i.test(toolName)) {
    const first = Object.values(record).find((v) => typeof v === "string" && v !== "");
    return typeof first === "string" ? first : undefined;
  }
  return undefined;
}

export interface ArmedSink {
  kind: "egress" | "exec" | "send" | "secret_read" | "spend";
  /** For the reason sentence: "reaches the network", "executes a script", … */
  does: string;
}

/** Does this call do something an armed injection could be steering? The five
 * sinks are exactly the injection rows of flow-rules' FLOW_RULES table. */
export function classifyArmedSink(
  toolName: string | undefined,
  toolInput: unknown,
  target: string | undefined,
): ArmedSink | undefined {
  const command = commandOf(toolName, toolInput);
  if (command !== undefined) {
    // Spend first: `cast send` reaches an RPC endpoint too, and "moves funds"
    // is the reason a person needs to read.
    if (spendInvocationIn(command) !== undefined) {
      return { kind: "spend", does: "moves funds or broadcasts a transaction" };
    }
    if (networkInvocationIn(command) !== undefined) {
      return { kind: "egress", does: "reaches the network" };
    }
    if (execInvocationIn(command) !== undefined) {
      return { kind: "exec", does: "executes code" };
    }
    const read = secretPathReadIn(command);
    if (read !== undefined) return { kind: "secret_read", does: `reads ${read.name}` };
    return undefined;
  }
  if (toolName) {
    if (FETCH_TOOL_RE.test(toolName)) return { kind: "egress", does: "reaches the network" };
    if (MCP_SERVER_RE.test(toolName) && SEND_TOOL_RE.test(toolName)) {
      return { kind: "send", does: "sends data out" };
    }
    if (target !== undefined) {
      for (const [name, pattern] of SECRET_PATH_PATTERNS) {
        if (pattern.test(target)) return { kind: "secret_read", does: `reads ${name}` };
      }
    }
  }
  return undefined;
}

export interface ArmedEscalation {
  /** Always the flow rule's id — the approval card and the spool both name it,
   * so the radar folds the held call into the same story the flow pass tells. */
  detector: "flow_injection_followed";
  reason: string;
  key_name: string;
  /** `<taint excerpt> ⇢ <sink>` — masked on both sides. */
  excerpt: string;
  taint: ArmedTaint;
  sink: ArmedSink;
}

/**
 * A person's own `when` + `after: injection` rule, armed the same way: the
 * session carries a live injection taint, and this call satisfies the rule's
 * `when`. Where the shipped sinks are the four flow-table rows, this lets a
 * rule say "after an injection, hold any call to my deploy tool". Same
 * best-effort caveat, same evidence shape; the detector is the rule's id.
 */
export interface CustomArmedEscalation {
  detector: CustomDetectorId;
  label: string;
  severity: "critical" | "high" | "medium" | "low";
  mode: "ask" | "block";
  reason: string;
  key_name: string;
  excerpt: string;
  taint: ArmedTaint;
}

export function customArmedEscalation(
  taints: readonly ArmedTaint[],
  rules: readonly CustomRule[] | undefined,
  input: CustomRuleInput,
): CustomArmedEscalation | undefined {
  if (taints.length === 0 || !rules || rules.length === 0) return undefined;
  const taint = taints[0]!;
  for (const rule of rules) {
    if (rule.enabled === false || !rule.when || rule.after?.taint !== "injection") continue;
    if (rule.mode !== "ask" && rule.mode !== "block") continue;
    if (!customWhenMatches(rule, input)) continue;
    const where = [input.tool_name, input.target].filter(Boolean).join(" ");
    return {
      detector: customDetectorId(rule.id),
      label: rule.label,
      severity: rule.severity,
      mode: rule.mode,
      reason:
        `Doorman flagged this tool call: earlier in this session a tool result carried an ` +
        `injected instruction (${taint.name}), and this call matches your rule "${rule.label}".`,
      key_name: `${taint.name} → ${rule.label}`,
      excerpt: `${taint.excerpt} ⇢ ${where || rule.label}`.slice(0, 240),
      taint,
    };
  }
  return undefined;
}

/** Escalate this call, or not. Pure over what the guard already holds. */
export function armedEscalation(
  taints: readonly ArmedTaint[],
  toolName: string | undefined,
  toolInput: unknown,
  target: string | undefined,
): ArmedEscalation | undefined {
  if (taints.length === 0) return undefined;
  const sink = classifyArmedSink(toolName, toolInput, target);
  if (!sink) return undefined;
  const taint = taints[0]!;
  const does = sink.does;
  return {
    detector: "flow_injection_followed",
    reason:
      `Doorman flagged this tool call: earlier in this session a tool result carried an ` +
      `injected instruction (${taint.name}), and this call ${does}.`,
    key_name: `${taint.name} → ${sink.kind}`,
    excerpt: `${taint.excerpt} ⇢ ${[toolName, target].filter(Boolean).join(" ") || sink.kind}`.slice(0, 240),
    taint,
    sink,
  };
}
