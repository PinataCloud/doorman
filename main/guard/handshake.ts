/**
 * The hold-and-confirm handshake between the PreToolUse guard and the app.
 *
 * The guard is a process Claude Code spawns for one tool call and throws away;
 * the app is a long-lived Electron process. To ask a human before a dangerous
 * call runs, the short-lived side has to block on the long-lived side — so this
 * file defines the rendezvous both use.
 *
 * FILES, not a socket. `<guardDir>/pending/<id>.json` is the question,
 * `<guardDir>/pending/<id>.reply.json` is the answer, `<guardDir>/app.json` is
 * the app's heartbeat. Reasons, in order of how much they mattered:
 *
 *  1. A unix socket path is capped near 104 bytes and the guard lives under
 *     "~/Library/Application Support/Doorman/doorman/guard/", which
 *     spends most of that budget before the filename — a long macOS username
 *     would break the channel, and it would break it as a *silent* fail-open.
 *  2. The rest of this app already rendezvouses through files (spool.jsonl,
 *     cursors.json), so there is one concurrency model to reason about.
 *  3. It is testable with a temp directory and no listener.
 *
 * Cost: the guard polls instead of being woken. At POLL_MS that is a handful of
 * stats per second while a human decides — invisible next to the model call the
 * session is already waiting on.
 *
 * Self-containment rule: this directory is copied verbatim into userData and run
 * with plain `node`, so nothing here may import from outside main/guard/.
 */

import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { SecurityDetectorId, SecuritySeverity } from "./security-detect.js";
// ApprovalRequest.detectors is string[] rather than SecurityDetectorId[]: an
// armed-session escalation (armed.ts) holds under `flow_injection_followed`,
// which is deliberately outside the guard's detector union. Consumers that
// write POLICY from a detectors list must still filter against ALL_DETECTORS.

/** How often the guard looks for its answer. */
export const POLL_MS = 200;
/** A heartbeat older than this means the app is gone (it writes every 15s). */
export const HEARTBEAT_STALE_MS = 45_000;
/** Redacted preview of the tool input carried on the request. */
export const PREVIEW_LIMIT = 700;

export function pendingDir(guardDir: string): string {
  return join(guardDir, "pending");
}

export function requestPath(guardDir: string, id: string): string {
  return join(pendingDir(guardDir), `${id}.json`);
}

export function replyPath(guardDir: string, id: string): string {
  return join(pendingDir(guardDir), `${id}.reply.json`);
}

export function heartbeatPath(guardDir: string): string {
  return join(guardDir, "app.json");
}

/**
 * Presence — the guard's side of "which agent process is which session".
 *
 * A transcript names a session; the process table names a pid; nothing on
 * disk joins the two. The guard hook is spawned BY the agent, so at the
 * moment it runs, its parent pid (or a shell wrapper's parent) is the agent
 * that owns the session id on stdin. Every evaluated tool call overwrites
 * one small file per session with that fact; the app reads the folder on
 * its live-sessions tick (lib/live-sessions.ts) and prunes files whose pid
 * is gone. Content is metadata only — no tool input, no text.
 */
export interface PresenceRecord {
  session_id: string;
  /** The host's `source` string — "claude-code", "codex", … */
  source: string;
  /** The guard process's parent: the agent, or a `sh -c` between them. */
  pid: number;
  cwd?: string;
  /** ISO instant of the tool call the record was written on. */
  at: string;
  /** Terminal identity inherited through the agent's environment — what the
   * terminal app itself set, so a window can be found without a tty lookup.
   * `program` is `$TERM_PROGRAM` (Apple_Terminal, iTerm.app, ghostty, vscode,
   * WarpTerminal, tmux); `session` is Terminal's `$TERM_SESSION_ID` or
   * iTerm's `$ITERM_SESSION_ID`. */
  term?: { program?: string; session?: string; tmux?: boolean };
}

export function presenceDir(guardDir: string): string {
  return join(guardDir, "presence");
}

/** One file per (source, session); a session id outside the safe alphabet
 * is not recorded at all rather than escaped. */
export function presencePath(guardDir: string, source: string, sessionId: string): string | undefined {
  if (!/^[A-Za-z0-9._-]{1,120}$/.test(sessionId) || !/^[a-z0-9-]{1,40}$/.test(source)) return undefined;
  return join(presenceDir(guardDir), `${source}--${sessionId}.json`);
}

/** Read the terminal identity out of an environment — the guard's own
 * `process.env`, inherited from the agent and the terminal above it. */
export function presenceTerm(env: Record<string, string | undefined>): PresenceRecord["term"] | undefined {
  const program = env.TERM_PROGRAM;
  const session = env.TERM_SESSION_ID ?? env.ITERM_SESSION_ID;
  const tmux = typeof env.TMUX === "string" && env.TMUX !== "";
  if (!program && !session && !tmux) return undefined;
  return {
    ...(program ? { program } : {}),
    ...(session ? { session } : {}),
    ...(tmux ? { tmux: true } : {}),
  };
}

/** Best-effort, never throws: a full disk must not block a tool call. */
export function writePresence(guardDir: string, record: PresenceRecord): void {
  const path = presencePath(guardDir, record.source, record.session_id);
  if (!path) return;
  try {
    mkdirSync(presenceDir(guardDir), { recursive: true });
    writeFileSync(path, JSON.stringify(record));
  } catch {
    // ignore
  }
}

export function parsePresence(json: string): PresenceRecord | undefined {
  try {
    const raw = JSON.parse(json) as Record<string, unknown>;
    if (!raw || typeof raw !== "object") return undefined;
    if (typeof raw.session_id !== "string" || typeof raw.source !== "string") return undefined;
    if (typeof raw.pid !== "number" || typeof raw.at !== "string") return undefined;
    const term = raw.term && typeof raw.term === "object" ? (raw.term as PresenceRecord["term"]) : undefined;
    return {
      session_id: raw.session_id,
      source: raw.source,
      pid: raw.pid,
      at: raw.at,
      ...(typeof raw.cwd === "string" ? { cwd: raw.cwd } : {}),
      ...(term ? { term } : {}),
    };
  } catch {
    return undefined;
  }
}

/** What the guard asks. Everything here is safe to display: the preview is
 * redacted before it is written, exactly like a finding's excerpt. */
/** Who is asking: a PreToolUse guard for one of the registered hosts (its
 * `source` string — hosts/index.ts), or the MCP gateway holding a `tools/call`
 * on a routed server (gateway/mcp-gateway.ts). The two host values are named
 * for autocompletion; the type accepts any host the registry grows. */
export type ApprovalSource = "claude-code" | "codex" | "mcp-gateway" | (string & {});

/** How the person answered — the telemetry the Analytics screen's "median time
 * to approve" and the per-surface split are built from. */
/** `editor` is a decision made inside VS Code, through the companion extension
 * (vscode-extension): the extension never writes a reply itself, so by
 * the time this value is set the app has applied it through the same path the
 * panel uses. */
export type ApprovalVia = "panel" | "window" | "notification" | "editor";

export interface ApprovalRequest {
  id: string;
  at: string;
  /** Agent whose tool call is waiting. Optional for requests written by older
   * guard bundles, which are Claude Code by construction. */
  source?: ApprovalSource;
  session_id?: string;
  tool_name?: string;
  target?: string;
  cwd?: string;
  detectors: string[];
  /** The (detector, key_name) pairs that drove the hold — what a scoped
   * "allow for this project" ignore rule is written from. The masked key
   * name only, never a value. */
  held_keys?: { detector: string; key_name?: string }[];
  /** Labels for any custom-rule detector ids in `detectors`, so the card can
   * name a person's own rule without the app having to look it up. */
  detector_labels?: Record<string, string>;
  /** MCP gateway holds only: the routed server and the tool's permission class. */
  server?: string;
  tool_class?: "read" | "write" | "act";
  max_severity?: SecuritySeverity;
  reason: string;
  preview: string;
  hold_seconds: number;
  on_timeout: "deny" | "ask";
  /** The waiting guard, so the app can drop a card whose process is already
   * dead (Claude Code killed the hook) instead of asking about nothing. */
  pid: number;
  /** App-computed, display-only: a one-line risk note about WHERE this call
   * goes (an egress destination's class, an MCP server's risk profile). The
   * guard never writes it — the app fills it in before showing the card, so a
   * Deny/Allow is an informed choice, not just a rule name. */
  context_note?: string;
}

export type ApprovalVerdict = "allow" | "deny";

export interface ApprovalReply {
  id: string;
  verdict: ApprovalVerdict;
  at: string;
  /** Detectors the person switched to observe on their way out ("allow and
   * stop asking"). Informational for the guard; the app owns the policy write. */
  silenced?: SecurityDetectorId[];
  /** Which surface answered. Absent on replies from older app builds. */
  via?: ApprovalVia;
  /** The person allowed it AND scoped an ignore rule to this project. The app
   * owns the policy write; the guard records it on the spool line. */
  allow_scope?: "project";
}

/** How a held call ended. Recorded on the finding so the Radar can say what
 * happened rather than just that something fired.
 *  · `unattended` — nobody could be asked and the call went on to the host's
 *    own fallback (a native ask, or a warning under `confirm.unattended:
 *    "continue"`);
 *  · `unavailable` — nobody could be asked and the guard returned the host's
 *    deny instead (`confirm.unattended: "deny"`, the default since
 *    2026-09-10). Not a human decision: the person was never reached. */
export type ApprovalResolution = "allowed" | "denied" | "timeout" | "unattended" | "unavailable";

export interface Heartbeat {
  at: string;
  pid: number;
  version?: string;
}

export function heartbeatFresh(json: string | undefined, nowMs: number): boolean {
  if (!json) return false;
  try {
    const raw = JSON.parse(json) as Partial<Heartbeat>;
    if (!raw || typeof raw.at !== "string") return false;
    const at = Date.parse(raw.at);
    if (!Number.isFinite(at)) return false;
    // A clock that jumped backwards must not read as "fresh forever", so the
    // window is absolute in both directions.
    return Math.abs(nowMs - at) <= HEARTBEAT_STALE_MS;
  } catch {
    return false;
  }
}

/** Is the app running and listening for approvals? */
export function appListening(guardDir: string, nowMs: number = Date.now()): boolean {
  let json: string | undefined;
  try {
    json = readFileSync(heartbeatPath(guardDir), "utf8");
  } catch {
    return false;
  }
  return heartbeatFresh(json, nowMs);
}

export function writeRequest(guardDir: string, request: ApprovalRequest): void {
  mkdirSync(pendingDir(guardDir), { recursive: true });
  writeFileSync(requestPath(guardDir, request.id), `${JSON.stringify(request, null, 2)}\n`);
}

export function parseRequest(json: string): ApprovalRequest | undefined {
  try {
    const raw = JSON.parse(json) as Partial<ApprovalRequest>;
    if (!raw || typeof raw !== "object") return undefined;
    if (typeof raw.id !== "string" || raw.id === "") return undefined;
    if (typeof raw.at !== "string" || !Number.isFinite(Date.parse(raw.at))) return undefined;
    const heldKeys = Array.isArray(raw.held_keys)
      ? raw.held_keys
          .filter((k): k is { detector: string; key_name?: string } => !!k && typeof k === "object" && typeof k.detector === "string")
          .map((k) => ({ detector: k.detector, ...(typeof k.key_name === "string" ? { key_name: k.key_name } : {}) }))
      : undefined;
    const labels =
      raw.detector_labels && typeof raw.detector_labels === "object"
        ? Object.fromEntries(
            Object.entries(raw.detector_labels).filter((e): e is [string, string] => typeof e[1] === "string"),
          )
        : undefined;
    return {
      id: raw.id,
      at: raw.at,
      // Any non-empty string: a request written by a guard bundle that knows a
      // host this app build does not must still be answerable.
      source: typeof raw.source === "string" && raw.source !== "" ? raw.source : undefined,
      session_id: typeof raw.session_id === "string" ? raw.session_id : undefined,
      tool_name: typeof raw.tool_name === "string" ? raw.tool_name : undefined,
      target: typeof raw.target === "string" ? raw.target : undefined,
      cwd: typeof raw.cwd === "string" ? raw.cwd : undefined,
      detectors: Array.isArray(raw.detectors)
        ? raw.detectors.filter((d): d is string => typeof d === "string")
        : [],
      ...(heldKeys && heldKeys.length > 0 ? { held_keys: heldKeys } : {}),
      ...(labels && Object.keys(labels).length > 0 ? { detector_labels: labels } : {}),
      ...(typeof raw.server === "string" ? { server: raw.server } : {}),
      ...(raw.tool_class === "read" || raw.tool_class === "write" || raw.tool_class === "act"
        ? { tool_class: raw.tool_class }
        : {}),
      max_severity: raw.max_severity,
      reason: typeof raw.reason === "string" ? raw.reason : "",
      preview: typeof raw.preview === "string" ? raw.preview : "",
      hold_seconds: typeof raw.hold_seconds === "number" ? raw.hold_seconds : 60,
      on_timeout: raw.on_timeout === "ask" ? "ask" : "deny",
      pid: typeof raw.pid === "number" ? raw.pid : 0,
    };
  } catch {
    return undefined;
  }
}

export function writeReply(guardDir: string, reply: ApprovalReply): void {
  mkdirSync(pendingDir(guardDir), { recursive: true });
  writeFileSync(replyPath(guardDir, reply.id), `${JSON.stringify(reply)}\n`);
}

/**
 * The app's answer to a hold, if one has landed. It cannot prove WHO wrote it:
 * the app and the agent run as the same user, and anything the request file
 * could carry (a nonce, a token) the agent can read too. So the reply is not
 * where approval is protected — the guard holds any call that would write into
 * this directory (decision.ts guardSelfWrite), which is what stops an agent
 * approving its own hold. A parallel call doing it is held in turn.
 */
export function readReply(guardDir: string, id: string): ApprovalReply | undefined {
  let json: string;
  try {
    json = readFileSync(replyPath(guardDir, id), "utf8");
  } catch {
    return undefined;
  }
  try {
    const raw = JSON.parse(json) as Partial<ApprovalReply>;
    if (!raw || raw.id !== id) return undefined;
    if (raw.verdict !== "allow" && raw.verdict !== "deny") return undefined;
    return {
      id,
      verdict: raw.verdict,
      at: typeof raw.at === "string" ? raw.at : new Date().toISOString(),
      silenced: Array.isArray(raw.silenced)
        ? raw.silenced.filter((d): d is SecurityDetectorId => typeof d === "string")
        : undefined,
      ...(raw.via === "panel" || raw.via === "window" || raw.via === "notification" || raw.via === "editor"
        ? { via: raw.via }
        : {}),
      ...(raw.allow_scope === "project" ? { allow_scope: "project" as const } : {}),
    };
  } catch {
    return undefined;
  }
}

/** Best-effort removal of both halves — a finished exchange leaves no litter. */
export function clearExchange(guardDir: string, id: string): void {
  for (const path of [requestPath(guardDir, id), replyPath(guardDir, id)]) {
    try {
      rmSync(path, { force: true });
    } catch {
      // the app's sweep will get it
    }
  }
}

/** Did the app answer this request, or is the request already gone? */
export function exchangeState(
  guardDir: string,
  id: string,
): { state: "answered"; reply: ApprovalReply } | { state: "pending" | "withdrawn" } {
  const reply = readReply(guardDir, id);
  if (reply) return { state: "answered", reply };
  // The app sweeps a request it decides is stale; treat that as withdrawn
  // rather than waiting out the whole window for a reply that won't come.
  if (!existsSync(requestPath(guardDir, id))) return { state: "withdrawn" };
  return { state: "pending" };
}

export type HoldOutcome =
  | { outcome: "answered"; reply: ApprovalReply }
  | { outcome: "timeout" }
  | { outcome: "app_gone" };

/**
 * NOT unref'd, deliberately — and this is the whole hold.
 *
 * The guard's stdin has already ended by the time it polls, so an unref'd timer
 * is the only thing left in the event loop: node would consider itself idle and
 * EXIT mid-wait, code 0, no output. Claude Code reads that as "the hook had
 * nothing to say" and runs the tool call. That is a silent fail-open on exactly
 * the calls this file exists to hold, and it looks identical to working.
 */
const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * Block until the app answers, the app disappears, or the window closes.
 *
 * The app-disappeared check is what keeps a quit mid-hold from becoming a
 * pointless wait followed by a deny: no app, no human, so the call falls through
 * to Claude Code's own permission prompt instead.
 */
export async function holdForVerdict(
  guardDir: string,
  id: string,
  holdSeconds: number,
  options: { pollMs?: number; now?: () => number } = {},
): Promise<HoldOutcome> {
  const pollMs = options.pollMs ?? POLL_MS;
  const now = options.now ?? Date.now;
  const deadline = now() + Math.max(0, holdSeconds) * 1000;
  for (;;) {
    const state = exchangeState(guardDir, id);
    if (state.state === "answered") return { outcome: "answered", reply: state.reply };
    if (state.state === "withdrawn") return { outcome: "app_gone" };
    if (now() >= deadline) return { outcome: "timeout" };
    if (!appListening(guardDir, now())) return { outcome: "app_gone" };
    await sleep(Math.min(pollMs, Math.max(1, deadline - now())));
  }
}
