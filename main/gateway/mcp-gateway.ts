/**
 * The MCP gateway — phase 2: a stdio proxy that wraps one MCP server, observes
 * what it advertises and returns, and can enforce per-server permissions on
 * what the agent asks it to do.
 *
 * An agent is configured to spawn THIS instead of the real server:
 *   command: node   args: ["<userData>/…/gateway/mcp-gateway.js",
 *                          "--server", "<name>", "--", "<real cmd>", "<args…>"]
 * We spawn the real command and relay the JSON-RPC stream in both directions,
 * line by line, each line forwarded byte-for-byte. Three things ride on top:
 *
 *  1. OBSERVE descriptions (phase 1): `tools/list` results append each tool's
 *     name/description/schema/annotations — masked, one line per version not
 *     seen before — to `observed.jsonl` next to this file; the app scans them
 *     for poisoning and notices a description that CHANGES after it was first
 *     seen (the rug pull).
 *  2. OBSERVE calls and results: every `tools/call` request is paired with its
 *     result by JSON-RPC id, the result text is masked and run through the
 *     guard bundle's injection + poisoning detectors, and a masked record is
 *     appended to `calls.jsonl`. A result that carried an injection ARMS this
 *     connection — the connection is one agent session's link to one server,
 *     so "the next call on this connection" is exactly "the next call in this
 *     session to this server", with no session id needed.
 *  3. ENFORCE: before a `tools/call` is forwarded, its permission class (read /
 *     write / act — from the server's own annotations, else the verb) is looked
 *     up in policy.json's `mcp_permissions[server]`. `allow` forwards it; `ask`
 *     holds it through the same pending/ handshake the PreToolUse guard uses
 *     (the app raises the panel); `block` answers the client with a JSON-RPC
 *     error naming the rule. An ARMED connection escalates the next call to
 *     `ask` (policy `mcp_armed_escalation`, default on). Every rule that drives
 *     this is in the hidden MCP family today (guard/rule-scope.ts), so in this
 *     build the gateway observes and records; the enforcement path stays
 *     correct for when the family comes back.
 *
 * Non-negotiables, in order:
 *  · BYTE-EXACT for everything we don't decide about. Input is split into
 *    lines as BYTES (a chunk can end inside a multi-byte character) and a line
 *    is forwarded as the bytes it arrived as; observation reads a decoded copy.
 *    Only a line we refuse is withheld, and then the client gets an error
 *    response for that id. Anything the gateway writes itself is written
 *    between whole lines, never into the middle of one.
 *  · FAIL to the real server, not to nothing. If we can't spawn the child the
 *    server is genuinely unavailable; we exit with the child's code. Every
 *    observation/enforcement error is swallowed and the line is forwarded.
 *    The gateway exits only once the server's output has been read to its end
 *    and handed to the client.
 *  · NO STDOUT OF OUR OWN except a refusal for a held/blocked call, and an
 *    error for a request the server died without answering. Anything else we
 *    printed would corrupt the stream. Diagnostics go to stderr.
 *  · DEFAULT ALLOW. With no permissions configured the gateway forwards
 *    everything, exactly as phase 1 did.
 *  · An `ask` NOBODY CAN ANSWER is refused, not forwarded (2026-09-10,
 *    docs/plans/desktop-integration-enforcement-review.md F2): no app
 *    listening, the app gone mid-hold, a hold that errored, or the timeout
 *    fallback `ask` — all resolve through `gatewayHoldOutcome` under the same
 *    `confirm.unattended` the PreToolUse guard reads (default `deny`; `continue`
 *    restores the phase-2 forward). A configured `ask` is an authorization
 *    rule; the gateway's own availability is not an approval. A held call the
 *    agent has stopped waiting for (cancelled, timed out, disconnected) is
 *    never forwarded, whatever the answer.
 *  · NO SPOOL HOLDS A SECRET. Everything written to observed.jsonl and
 *    calls.jsonl goes through the guard's masks first, and both files are
 *    owner-only (0600), like the store.
 *
 * Self-containment rule: copied verbatim to userData and run with plain `node`.
 * It may import from the sibling guard bundle (`../guard/*.js`, copied to the
 * neighbouring directory by the same installer) and from nothing else.
 */

import { spawn, type ChildProcessByStdio } from "node:child_process";
import type { Readable, Writable } from "node:stream";
import { appendFileSync, chmodSync, readFileSync } from "node:fs";
import { createHash, randomUUID } from "node:crypto";
import { homedir } from "node:os";
import { join } from "node:path";
import { redact } from "../guard/redact.js";
import { detectSecurityFindings, maskDetectedValues } from "../guard/security-detect.js";
import { scanMcpToolOutput } from "../guard/mcp-poison.js";
import { INJECTION_MARKER_DETECTORS } from "../guard/armed.js";
import { ruleShown } from "../guard/rule-scope.js";
import { parsePolicy, type GuardPolicy, type McpPermissionMode } from "../guard/policy.js";
import {
  appListening,
  cappedPreview,
  decidedAtMs,
  holdForVerdict,
  toolCallPreview,
  writeRequest,
  clearExchange,
  type ApprovalResolution,
  type HoldOutcome,
} from "../guard/handshake.js";
import { isPlainObject as isRecord } from "../guard/jsonc.js";
import {
  ByteLineBuffer,
  cancelledIdKey,
  classifyTool,
  errorResponse,
  parseRpc,
  refusalLine,
  rpcIdKey,
  toolCallOf,
  toolResultOf,
  toolsOf,
  type McpToolClass,
  type ObservedTool,
  type RpcLine,
  type ToolCallRequest,
} from "./framing.js";

export interface GatewayArgs {
  server: string;
  command: string;
  commandArgs: string[];
}

/** Parse `--server <name> -- <cmd> <args…>`. The flags are read left to right
 * up to the first `--` that is not a flag's value, so a server named `--` is a
 * name. Testable, so it lives apart from the process wiring below. */
export function parseGatewayArgs(argv: readonly string[]): GatewayArgs | undefined {
  let server = "";
  let i = 0;
  while (i < argv.length && argv[i] !== "--") {
    if (argv[i] === "--server") {
      server = argv[i + 1] ?? "";
      i += 2;
    } else {
      i += 1;
    }
  }
  if (argv[i] !== "--") return undefined;
  const [command, ...commandArgs] = argv.slice(i + 1);
  if (!command) return undefined;
  return { server, command, commandArgs };
}

/** A stable id for an observed tool, so re-listing the same tools doesn't grow
 * the spool without bound — the app dedups on this too. */
export function toolKey(server: string, tool: ObservedTool): string {
  // Annotations are part of the identity: a server that flips
  // `destructiveHint` off after approval has changed the tool as surely as one
  // that rewrote the description, and the rug-pull fold must see it.
  const annotations = tool.annotations === undefined ? "" : JSON.stringify(tool.annotations);
  return createHash("sha1")
    .update(`${server}\0${tool.name}\0${tool.description ?? ""}\0${tool.schema ?? ""}\0${annotations}`)
    .digest("hex")
    .slice(0, 16);
}

/** How long an injection keeps this connection armed. Mirrors the guard's
 * ARMED_MAX_AGE_MS — a taint older than this is a different story. */
export const GATEWAY_ARMED_MAX_AGE_MS = 30 * 60_000;

/** The longest description or schema observed.jsonl keeps per tool version. */
export const OBSERVED_TEXT_MAX_CHARS = 8_000;

/** Everything any guard rule would call secret, masked — the same two steps as
 * the app's lib/masking.ts maskText, which this bundle cannot import. Every
 * string a spool stores goes through it. */
export function maskForSpool(text: string): string {
  return text === "" ? text : maskDetectedValues(redact(text));
}

/** Masked, then capped; a cap that lands inside a token drops the partial
 * token, which the masks may not recognise once cut. */
function cappedMasked(text: string, max = OBSERVED_TEXT_MAX_CHARS): string {
  const masked = maskForSpool(text);
  if (masked.length <= max) return masked;
  return `${masked.slice(0, max).replace(/[A-Za-z0-9_+/=.-]+$/, "")}…`;
}

/** The injection / poisoning markers a result text carries, if any. Pure, so
 * the gateway test can hold it to the same answer the flow engine gives. */
export function injectionMarkersIn(text: string, toolName: string): string[] {
  const redacted = redact(text);
  const markers: string[] = [];
  // The marker set is guard/armed.ts' INJECTION_MARKER_DETECTORS — shared with
  // the transcript flow engine, so gateway arming and radar taints agree.
  // A marker arms the connection, and an armed connection HOLDS its next
  // sink call — so a marker may only come from a rule the app shows
  // (guard/rule-scope.ts); a hidden rule's evidence is recorded by
  // the transcript engine and never surfaces here.
  for (const f of detectSecurityFindings({ kind: "tool_output", text: redacted, tool_name: toolName })) {
    if (INJECTION_MARKER_DETECTORS.has(f.detector) && ruleShown(f.detector)) {
      markers.push(f.key_name ? `${f.detector} (${f.key_name})` : f.detector);
    }
  }
  if (ruleShown("mcp_tool_poisoning")) {
    for (const p of scanMcpToolOutput(redacted, toolName)) {
      markers.push(`mcp_tool_poisoning (${p.key_name.split(" · ", 1)[0]})`);
    }
  }
  return [...new Set(markers)];
}

export interface GatewayDecision {
  action: "forward" | "ask" | "block";
  cls: McpToolClass;
  reason?: string;
  /** The armed taint that escalated this call, if that is what happened. */
  armed?: { marker: string; at: string };
}

/**
 * What to do with one `tools/call` — pure over the policy, the tool's class
 * and the connection's armed state. Permissions first (an explicit `block`
 * outranks everything), then the armed escalation, then allow.
 *
 * Per-server permissions are the `mcp_permission` rule, and a HIDDEN rule
 * never holds or blocks (guard/rule-scope.ts) — with the MCP family
 * hidden there is no screen left to see or change them on, so they are not
 * applied. They stay in the policy untouched: bringing the family back brings
 * them back exactly as the person set them.
 */
export function decideToolCall(
  policy: GuardPolicy,
  server: string,
  tool: Pick<ObservedTool, "name" | "annotations">,
  armed: { marker: string; at: string } | undefined,
  nowMs: number = Date.now(),
  permissionsShown: boolean = ruleShown("mcp_permission"),
): GatewayDecision {
  const cls = classifyTool(tool);
  const configured: McpPermissionMode = permissionsShown ? (policy.mcp_permissions?.[server]?.[cls] ?? "allow") : "allow";
  if (configured === "block") {
    return { action: "block", cls, reason: `Doorman blocked this call: ${server} may not ${describeClass(cls)} (your gateway permissions).` };
  }
  if (configured === "ask") {
    return { action: "ask", cls, reason: `Doorman flagged this MCP call: ${server} · ${tool.name} would ${describeClass(cls)} — held for your confirmation.` };
  }
  if (armed && policy.mcp_armed_escalation !== false && nowMs - Date.parse(armed.at) <= GATEWAY_ARMED_MAX_AGE_MS) {
    return {
      action: "ask",
      cls,
      armed,
      reason:
        `Doorman flagged this MCP call: an earlier result from ${server} carried an injected instruction ` +
        `(${armed.marker}), and this call would ${describeClass(cls)}.`,
    };
  }
  return { action: "forward", cls };
}

/** How a held `tools/call` ends: forwarded or refused, with the resolution the
 * calls record carries and the sentence appended to the refusal. */
export interface GatewayHoldOutcome {
  forward: boolean;
  resolution: ApprovalResolution;
  /** Appended to the decision's reason on a refusal; absent when forwarding. */
  message?: string;
}

/**
 * Pure: what an `ask` the gateway raised becomes once the hold has ended — or
 * could not be attempted (`held` undefined: no app listening, or the hold
 * machinery itself failed). Mirrors the guard's `unattendedOutcome`: a human
 * answer is final either way; a timeout follows `on_timeout`; and every ending
 * with nobody reached — app absent, app gone, timeout falling back to `ask` —
 * is governed by `confirm.unattended`, `deny` refusing the call with
 * `resolution: "unavailable"` (never "denied": nobody decided) and `continue`
 * forwarding it as phase 2 did.
 */
export function gatewayHoldOutcome(policy: GuardPolicy, held: HoldOutcome | undefined, seconds = policy.confirm.hold_seconds): GatewayHoldOutcome {
  if (held?.outcome === "answered") {
    return held.reply.verdict === "allow"
      ? { forward: true, resolution: "allowed" }
      : { forward: false, resolution: "denied", message: "You denied it in Doorman." };
  }
  if (held?.outcome === "timeout") {
    if (policy.confirm.on_timeout === "deny" || policy.confirm.unattended === "deny") {
      return { forward: false, resolution: "timeout", message: `It was held for ${seconds}s and nobody approved it.` };
    }
    return { forward: true, resolution: "timeout" };
  }
  // No hold, or the app vanished mid-hold: nobody was reached.
  if (policy.confirm.unattended === "continue") return { forward: true, resolution: "unattended" };
  return {
    forward: false,
    resolution: "unavailable",
    message:
      "Doorman is not running to ask you, so the call was not forwarded. Open Doorman and retry it if it is intended.",
  };
}

function describeClass(cls: McpToolClass): string {
  return cls === "read" ? "read data" : cls === "write" ? "write or change data" : "act outward";
}

/**
 * Codex's own per-call timeout for `server`, from its config.toml
 * (`[mcp_servers.<server>] tool_timeout_sec`), else its documented 60s.
 * Codex abandons a call at that timeout WITHOUT sending
 * `notifications/cancelled` (openai/codex#26956), so it is the only way the
 * gateway can know when a held call stops being wanted. A minimal reader:
 * the one key under the one table, nothing else of TOML.
 */
export function codexToolTimeoutSeconds(configToml: string | undefined, server: string): number {
  const DEFAULT = 60;
  if (!configToml) return DEFAULT;
  const quoted = JSON.stringify(server);
  const bare = /^[A-Za-z0-9_-]+$/.test(server) ? server : undefined;
  let inTable = false;
  for (const line of configToml.split(/\r?\n/)) {
    const header = /^\s*\[([^\]]+)\]\s*(?:#.*)?$/.exec(line);
    if (header) {
      const name = header[1]!.trim();
      inTable = name === `mcp_servers.${quoted}` || (bare !== undefined && name === `mcp_servers.${bare}`);
      continue;
    }
    if (!inTable) continue;
    const value = /^\s*tool_timeout_sec\s*=\s*([0-9]+(?:\.[0-9]+)?)\s*(?:#.*)?$/.exec(line);
    if (value) return Number(value[1]);
  }
  return DEFAULT;
}

/** How a held call ended without a verdict being applied: the agent stopped
 * waiting for it, or the server it was for went away. */
type HoldDrop = "cancelled" | "client_timeout" | "client_gone" | "upstream_gone";

interface CallState {
  /** Ties every calls.jsonl record about this one call together. */
  call: string;
  request: ToolCallRequest;
  cls: McpToolClass;
  at: string;
  /** Set when the call was held first: its decision record is already written. */
  held?: boolean;
}

interface HoldState {
  exchangeId: string;
  idKey?: string;
  rawId?: string;
  dropped?: HoldDrop;
}

/** Ordered writes to one stream that never splice a whole line of our own
 * into the middle of a passed-through one. */
class LineWriter {
  private midLine = false;
  private queue: Buffer[] = [];

  constructor(private readonly sink: (bytes: Buffer) => void) {}

  /** Stream bytes in order; they may end mid-line. */
  passthrough(bytes: Buffer): void {
    if (bytes.length === 0) return;
    this.sink(bytes);
    this.midLine = bytes[bytes.length - 1] !== 0x0a;
    if (!this.midLine) this.release();
  }

  /** A complete line of our own (or one released from a hold): written now if
   * the stream is between lines, else as soon as the current line ends. */
  line(bytes: Buffer): void {
    if (this.midLine) this.queue.push(bytes);
    else this.sink(bytes);
  }

  /** The stream will send no more: end a torn last line so what we queued
   * still reads as lines, and release it. */
  finish(): void {
    if (this.midLine && this.queue.length > 0) {
      this.sink(Buffer.from("\n"));
      this.midLine = false;
    }
    this.release();
  }

  private release(): void {
    const queued = this.queue;
    this.queue = [];
    for (const bytes of queued) this.sink(bytes);
  }
}

/** A response's id from the first bytes of a line too large to parse — so the
 * request it answers is no longer counted in flight. Ids lead in every SDK's
 * serialization; one that doesn't is simply not matched. */
function leadingResponseIdKey(head: string): string | undefined {
  const m = /^\s*\{\s*(?:"jsonrpc"\s*:\s*"2\.0"\s*,\s*)?"id"\s*:\s*("(?:[^"\\]|\\.)*"|-?\d+)\s*,/.exec(head);
  if (!m) return undefined;
  try {
    return rpcIdKey({ msg: { id: JSON.parse(m[1]!) as unknown }, rawId: m[1]! });
  } catch {
    return undefined;
  }
}

export interface GatewayOptions {
  args: GatewayArgs;
  /** Where the spools live (this file's directory once installed). */
  gatewayDir: string;
  /** The sibling guard bundle: policy.json and the approval handshake. */
  guardDir: string;
  /** The agent's side of the pipe. */
  input: NodeJS.ReadableStream;
  output: NodeJS.WritableStream & { writableLength?: number };
  stderr?: (text: string) => void;
  env?: Record<string, string | undefined>;
  /** Test seam: apply per-server permissions although `mcp_permission` is a
   * hidden rule in this build (see decideToolCall). */
  permissionsShown?: boolean;
  /** How long a server gets to exit after SIGTERM before SIGKILL. Under a
   * host's own SIGTERM→SIGKILL grace (the MCP SDK's is 2s), so the server is
   * gone before the gateway can be killed out from under it. */
  killGraceMs?: number;
  /** The approval handshake's poll interval (tests shorten it). */
  pollMs?: number;
}

export interface GatewayRun {
  /** Settles once the server has exited and everything it said has been
   * handed to the client: the code / signal to exit with. */
  done: Promise<{ code: number; signal?: NodeJS.Signals }>;
  /** Stop the server: SIGTERM, then SIGKILL after the grace. */
  terminate(signal?: NodeJS.Signals): void;
}

export function runGateway(options: GatewayOptions): GatewayRun {
  const { args, gatewayDir, guardDir, input, output } = options;
  const stderr = options.stderr ?? ((text: string) => process.stderr.write(text));
  const env = options.env ?? process.env;
  const killGraceMs = options.killGraceMs ?? 1_000;
  const observedPath = join(gatewayDir, "observed.jsonl");
  const callsPath = join(gatewayDir, "calls.jsonl");
  let seenTools: Set<string> | undefined;
  const tools = new Map<string, ObservedTool>();
  /** Forwarded tool calls awaiting their result, by id key. */
  const pending = new Map<string, CallState>();
  /** Every request forwarded to the server and not yet answered: id key → raw id. */
  const inflight = new Map<string, string>();
  const holds = new Set<HoldState>();
  let armed: { marker: string; at: string } | undefined;
  /** Seconds the client waits for a call before giving up, when it is known
   * to give up silently (see codexToolTimeoutSeconds). */
  let clientTimeoutSeconds: number | undefined;
  const fromServer = new ByteLineBuffer();
  const fromClient = new ByteLineBuffer();
  let clientEnded = false;
  let clientGone = false;
  let serverClosed = false;
  let terminatedBy: NodeJS.Signals | undefined;
  let resolveDone!: (value: { code: number; signal?: NodeJS.Signals }) => void;
  const done = new Promise<{ code: number; signal?: NodeJS.Signals }>((resolve) => {
    resolveDone = resolve;
  });
  let finished = false;
  const finish = (value: { code: number; signal?: NodeJS.Signals }): void => {
    if (finished) return;
    finished = true;
    resolveDone(value);
  };

  const readPolicy = (): GuardPolicy => {
    try {
      return parsePolicy(readFileSync(join(guardDir, "policy.json"), "utf8"));
    } catch {
      return parsePolicy(undefined);
    }
  };

  const tightened = new Set<string>();
  const append = (path: string, record: Record<string, unknown>): void => {
    try {
      appendFileSync(path, `${JSON.stringify({ at: new Date().toISOString(), server: args.server, ...record })}\n`, { mode: 0o600 });
      if (!tightened.has(path)) {
        // A spool an older gateway created at the umask's 0644.
        tightened.add(path);
        chmodSync(path, 0o600);
      }
    } catch {
      // Observation must never affect the proxy.
    }
  };

  let child: ChildProcessByStdio<Writable, Readable, null>;
  try {
    child = spawn(args.command, args.commandArgs, { stdio: ["pipe", "pipe", "inherit"], env });
  } catch (err) {
    stderr(`[doorman gateway] couldn't start MCP server: ${String(err)}\n`);
    finish({ code: 2 });
    return { done, terminate: () => {} };
  }
  const server = child;

  // ── writes to the client: whole lines, backpressure to the server ─────────
  let outputBlocked = false;
  const toClient = new LineWriter((bytes) => {
    if (clientGone) return;
    try {
      if (!output.write(bytes) && !outputBlocked) {
        outputBlocked = true;
        server.stdout.pause();
        output.once("drain", () => {
          outputBlocked = false;
          server.stdout.resume();
        });
      }
    } catch {
      onClientGone();
    }
  });
  output.on("error", () => onClientGone());

  // ── writes to the server: whole lines, backpressure to the client ─────────
  let serverInGone = false;
  let inputBlocked = false;
  const toServer = new LineWriter((bytes) => {
    if (serverInGone || server.stdin.destroyed || !server.stdin.writable) return;
    if (!server.stdin.write(bytes) && !inputBlocked) {
      inputBlocked = true;
      input.pause();
      server.stdin.once("drain", () => {
        inputBlocked = false;
        input.resume();
      });
    }
  });
  // EPIPE from a server that exited or closed its stdin: its `close` drives
  // the exit; the write is simply lost, as it would be without us.
  server.stdin.on("error", () => {
    serverInGone = true;
  });

  const ownLine = (text: string): void => toClient.line(Buffer.from(text.endsWith("\n") ? text : `${text}\n`));

  const terminate = (signal: NodeJS.Signals = "SIGTERM"): void => {
    if (serverClosed) return;
    try {
      server.kill(signal);
    } catch {
      // already gone
    }
    const timer = setTimeout(() => {
      if (serverClosed) return;
      try {
        server.kill("SIGKILL");
      } catch {
        // already gone
      }
    }, killGraceMs);
    timer.unref?.();
  };

  function onClientGone(): void {
    if (clientGone) return;
    clientGone = true;
    dropHolds("client_gone");
    try {
      server.stdin.end();
    } catch {
      // already gone
    }
    terminate();
  }

  // ── server → client: forward every byte verbatim, observe a copy ──────────
  server.stdout.on("data", (chunk: Buffer) => {
    toClient.passthrough(chunk);
    try {
      for (const segment of fromServer.push(chunk)) {
        if (segment.kind === "line") {
          observeFromServer(segment.bytes.toString("utf8"));
          continue;
        }
        if (!segment.first) continue;
        // Too large to parse: the reply still answers its request.
        const key = leadingResponseIdKey(segment.bytes.subarray(0, 512).toString("utf8"));
        if (key === undefined) continue;
        inflight.delete(key);
        const call = pending.get(key);
        if (!call) continue;
        pending.delete(key);
        append(callsPath, { call: call.call, tool: call.request.name, cls: call.cls, called_at: call.at, oversized: true });
      }
    } catch {
      // never let observation touch the stream
    }
  });

  const recordTools = (listed: ObservedTool[]): void => {
    if (!seenTools) {
      // Versions any earlier session already recorded are not new: the spool
      // grows by what CHANGED, not by every session's full tool list.
      seenTools = new Set();
      try {
        for (const line of readFileSync(observedPath, "utf8").split("\n")) {
          if (!line.includes(`"server":${JSON.stringify(args.server)}`)) continue;
          try {
            const rec = JSON.parse(line) as { id?: unknown; server?: unknown };
            if (rec.server === args.server && typeof rec.id === "string") seenTools.add(rec.id);
          } catch {
            // a torn line
          }
        }
      } catch {
        // no spool yet
      }
    }
    for (const tool of listed) {
      tools.set(tool.name, tool);
      const id = toolKey(args.server, tool);
      if (seenTools.has(id)) continue;
      seenTools.add(id);
      append(observedPath, {
        id,
        name: tool.name,
        ...(tool.description === undefined ? {} : { description: cappedMasked(tool.description) }),
        ...(tool.schema === undefined ? {} : { schema: cappedMasked(tool.schema) }),
        ...(tool.annotations === undefined ? {} : { annotations: tool.annotations }),
      });
    }
  };

  const observeFromServer = (line: string): void => {
    const parsed = parseRpc(line);
    if (!parsed) return;
    for (const message of parsed.messages) {
      const key = "method" in message.msg ? undefined : rpcIdKey(message);
      if (key !== undefined) inflight.delete(key);
      const listed = toolsOf(message);
      if (listed) {
        recordTools(listed);
        continue;
      }
      const result = toolResultOf(message);
      if (!result) continue;
      const call = pending.get(result.idKey);
      if (!call) continue;
      pending.delete(result.idKey);
      const markers = result.text ? injectionMarkersIn(result.text, `mcp__${args.server}__${call.request.name}`) : [];
      if (markers.length > 0) armed = { marker: markers[0]!, at: new Date().toISOString() };
      append(callsPath, {
        call: call.call,
        tool: call.request.name,
        cls: call.cls,
        called_at: call.at,
        is_error: result.isError,
        result_chars: result.text.length,
        // Masked, windowed — a record of what came back, never the payload.
        excerpt: maskForSpool(result.text).replace(/\s+/g, " ").slice(0, 200),
        ...(markers.length > 0 ? { injection: markers } : {}),
      });
    }
  };

  // ── client → server: forward each line, unless it is a call we decide on ──
  input.on("data", (chunk: Buffer | string) => {
    const bytes = typeof chunk === "string" ? Buffer.from(chunk, "utf8") : chunk;
    for (const segment of fromClient.push(bytes)) {
      // A `raw` run is part of a line past the buffer's bound and is forwarded
      // verbatim, unparsed — never dropped. A `line` carries its own newline,
      // so the bytes the server sees are the bytes the client sent.
      if (segment.kind === "raw") toServer.passthrough(segment.bytes);
      else relayFromClient(segment.bytes);
    }
  });
  input.on("end", () => {
    // A last message the client ended with EOF instead of a newline is still a
    // message: decided on and forwarded like any other.
    for (const segment of fromClient.end()) {
      if (segment.kind === "raw") toServer.passthrough(segment.bytes);
      else relayFromClient(segment.bytes);
    }
    clientEnded = true;
    // Nobody is left to receive the answer to a held call.
    dropHolds("client_gone");
    toServer.finish();
    try {
      server.stdin.end();
    } catch {
      // already gone
    }
  });
  input.on("error", () => {
    // A broken stdin is a client that went away.
    onClientGone();
  });

  const startCall = (request: ToolCallRequest, cls: McpToolClass, held = false): CallState => ({
    call: randomUUID(),
    request,
    cls,
    at: new Date().toISOString(),
    ...(held ? { held } : {}),
  });

  const forwardLine = (bytes: Buffer, parsed: RpcLine | undefined, calls: CallState[], viaQueue: boolean): void => {
    for (const message of parsed?.messages ?? []) {
      if (typeof message.msg.method !== "string") continue;
      const key = rpcIdKey(message);
      if (key !== undefined && message.rawId !== undefined) inflight.set(key, message.rawId);
    }
    for (const call of calls) if (call.request.idKey !== undefined) pending.set(call.request.idKey, call);
    if (viaQueue) toServer.line(bytes);
    else toServer.passthrough(bytes);
  };

  const refuse = (rawId: string | undefined, message: string): void => {
    if (rawId !== undefined) ownLine(refusalLine(rawId, message));
  };

  const relayFromClient = (bytes: Buffer): void => {
    let parsed: RpcLine | undefined;
    const decided: { request: ToolCallRequest; decision: GatewayDecision }[] = [];
    try {
      parsed = parseRpc(bytes.toString("utf8"));
      if (parsed) {
        let policy: GuardPolicy | undefined;
        for (const message of parsed.messages) {
          if (message.msg.method === "initialize") noteClient(message.msg.params);
          const cancelled = cancelledIdKey(message);
          if (cancelled !== undefined) dropHolds("cancelled", cancelled);
          const request = toolCallOf(message);
          if (!request) continue;
          policy ??= readPolicy();
          const known = tools.get(request.name) ?? { name: request.name };
          decided.push({ request, decision: decideToolCall(policy, args.server, known, armed, Date.now(), options.permissionsShown) });
        }
      }
    } catch {
      parsed = undefined;
      decided.length = 0;
    }
    if (decided.every((d) => d.decision.action === "forward")) {
      forwardLine(bytes, parsed, decided.map((d) => startCall(d.request, d.decision.cls)), false);
      return;
    }
    if (parsed?.batch) {
      refuseBatch(parsed, decided);
      return;
    }
    const { request, decision } = decided[0]!;
    if (decision.action === "block") {
      append(callsPath, { call: randomUUID(), tool: request.name, cls: decision.cls, blocked: true, reason: decision.reason });
      refuse(request.rawId, decision.reason ?? "Blocked by Doorman.");
      return;
    }
    void holdCall(bytes, parsed!, request, decision);
  };

  /**
   * A batch (a JSON array of messages) that carries a call the gateway would
   * not simply forward. A hold can't pause one element of a batch, and
   * forwarding the rest would split what the client sent as a unit, so the
   * whole batch is answered — each request with an error, in one array — and
   * nothing of it reaches the server.
   */
  const refuseBatch = (parsed: RpcLine, decided: { request: ToolCallRequest; decision: GatewayDecision }[]): void => {
    const why = new Map<string, string>();
    for (const { request, decision } of decided) {
      if (decision.action === "forward") continue;
      const message =
        decision.action === "block"
          ? decision.reason ?? "Blocked by Doorman."
          : `${decision.reason ?? "Held by Doorman."} Doorman can't hold a call inside a JSON-RPC batch, so it was not forwarded; send it on its own.`;
      append(callsPath, {
        call: randomUUID(),
        tool: request.name,
        cls: decision.cls,
        ...(decision.action === "block" ? { blocked: true } : { batch_refused: true, forwarded: false }),
        reason: decision.reason,
      });
      if (request.rawId !== undefined) why.set(request.rawId, message);
    }
    const responses: string[] = [];
    for (const message of parsed.messages) {
      if (typeof message.msg.method !== "string" || message.rawId === undefined) continue;
      responses.push(
        errorResponse(
          message.rawId,
          why.get(message.rawId) ??
            "Doorman did not forward this batch: another call in it needs a decision first. Send the calls one at a time.",
        ),
      );
    }
    if (responses.length > 0) ownLine(`[${responses.join(",")}]`);
  };

  function noteClient(params: unknown): void {
    const info = isRecord(params) && isRecord(params.clientInfo) ? params.clientInfo : undefined;
    const name = typeof info?.name === "string" ? info.name : "";
    if (!/codex/i.test(name)) return;
    let toml: string | undefined;
    try {
      toml = readFileSync(join(env.CODEX_HOME || join(env.HOME || homedir(), ".codex"), "config.toml"), "utf8");
    } catch {
      toml = undefined;
    }
    clientTimeoutSeconds = codexToolTimeoutSeconds(toml, args.server);
  }

  /** Mark held calls as no longer wanted — all of them, or the one whose
   * request id is `idKey` — and withdraw their cards. Each hold then ends
   * without forwarding (holdCall checks `dropped`). */
  function dropHolds(why: HoldDrop, idKey?: string): void {
    for (const hold of holds) {
      if (idKey !== undefined && hold.idKey !== idKey) continue;
      if (hold.dropped) continue;
      hold.dropped = why;
      clearExchange(guardDir, hold.exchangeId);
    }
  }

  const holdCall = async (bytes: Buffer, parsed: RpcLine, request: ToolCallRequest, decision: GatewayDecision): Promise<void> => {
    const state = startCall(request, decision.cls, true);
    const refusal = (outcome: GatewayHoldOutcome): void =>
      refuse(request.rawId, `${decision.reason ?? "Held by Doorman."} ${outcome.message ?? ""}`.trim());
    // ask: hold through the app, exactly as the PreToolUse guard does. No app
    // listening → nobody to ask: `confirm.unattended` decides (gatewayHoldOutcome).
    const policy = readPolicy();
    if (clientEnded || clientGone) {
      append(callsPath, { call: state.call, tool: request.name, cls: decision.cls, held: true, resolution: "client_gone", forwarded: false, reason: decision.reason });
      return;
    }
    if (!appListening(guardDir)) {
      const outcome = gatewayHoldOutcome(policy, undefined);
      append(callsPath, {
        call: state.call,
        tool: request.name,
        cls: decision.cls,
        unattended: true,
        resolution: outcome.resolution,
        forwarded: outcome.forward,
        reason: decision.reason,
      });
      if (outcome.forward) forwardLine(bytes, parsed, [state], false);
      else refusal(outcome);
      return;
    }
    const hold: HoldState = {
      exchangeId: randomUUID(),
      ...(request.idKey === undefined ? {} : { idKey: request.idKey }),
      ...(request.rawId === undefined ? {} : { rawId: request.rawId }),
    };
    holds.add(hold);
    const heldAt = new Date().toISOString();
    const receivedMs = Date.parse(heldAt);
    // A client that abandons a call silently (Codex) is waiting this long; a
    // hold that outlasted it would approve a call nobody is waiting for, so
    // the hold ends — and refuses — just before the client gives up.
    const holdSeconds =
      clientTimeoutSeconds === undefined ? policy.confirm.hold_seconds : Math.max(1, Math.min(policy.confirm.hold_seconds, Math.floor(clientTimeoutSeconds) - 2));
    const preview = cappedPreview(toolCallPreview(`mcp__${args.server}__${request.name}`, redact(JSON.stringify(request.arguments ?? {}))).preview);
    let held: HoldOutcome | undefined;
    let holdError = false;
    try {
      writeRequest(guardDir, {
        id: hold.exchangeId,
        at: heldAt,
        source: "mcp-gateway",
        tool_name: `mcp__${args.server}__${request.name}`,
        target: request.name,
        server: args.server,
        tool_class: decision.cls,
        detectors: decision.armed ? ["flow_injection_followed"] : ["mcp_permission"],
        detector_labels: { mcp_permission: `MCP ${decision.cls} call on ${args.server}` },
        max_severity: decision.armed ? "critical" : "high",
        reason: decision.reason ?? "Held by Doorman.",
        ...preview,
        hold_seconds: holdSeconds,
        on_timeout: policy.confirm.on_timeout,
        pid: process.pid,
      });
      held = await holdForVerdict(guardDir, hold.exchangeId, holdSeconds, options.pollMs === undefined ? {} : { pollMs: options.pollMs });
    } catch {
      // The hold machinery itself failed (a full disk under pending/, an
      // unreadable reply): nobody was reached, so `confirm.unattended` decides
      // — the same rule as an absent app, never a silent forward.
      holdError = true;
    } finally {
      holds.delete(hold);
      clearExchange(guardDir, hold.exchangeId);
    }
    const nowMs = Date.now();
    if (!hold.dropped && clientTimeoutSeconds !== undefined && nowMs - receivedMs >= clientTimeoutSeconds * 1000) hold.dropped = "client_timeout";
    if (!hold.dropped && (clientGone || clientEnded)) hold.dropped = "client_gone";
    if (!hold.dropped && serverClosed) hold.dropped = "upstream_gone";
    if (hold.dropped) {
      // The agent stopped waiting (or the server is gone): whatever the
      // answer, forwarding now would run a call nobody will see the end of.
      append(callsPath, {
        call: state.call,
        tool: request.name,
        cls: decision.cls,
        held: true,
        resolution: hold.dropped,
        forwarded: false,
        held_at: heldAt,
        hold_ms: Math.max(0, nowMs - receivedMs),
        reason: decision.reason,
      });
      return;
    }
    const outcome = gatewayHoldOutcome(policy, holdError ? undefined : held, holdSeconds);
    if (holdError || !held) {
      append(callsPath, { call: state.call, tool: request.name, cls: decision.cls, hold_error: true, resolution: outcome.resolution, forwarded: outcome.forward, reason: decision.reason });
    } else {
      const decidedMs = decidedAtMs(held, receivedMs, nowMs);
      append(callsPath, {
        call: state.call,
        tool: request.name,
        cls: decision.cls,
        held: true,
        resolution: outcome.resolution,
        forwarded: outcome.forward,
        held_at: heldAt,
        decided_at: new Date(decidedMs).toISOString(),
        decided_via: held.outcome === "answered" ? held.reply.via ?? "window" : held.outcome === "timeout" ? "timeout" : "app-absent",
        hold_ms: Math.max(0, decidedMs - receivedMs),
        ...(held.outcome === "timeout" ? { hold_seconds: holdSeconds } : {}),
        ...(decision.armed ? { injection: [decision.armed.marker] } : {}),
        reason: decision.reason,
      });
    }
    // Released between whole lines: other traffic kept flowing while it was held.
    if (outcome.forward) forwardLine(bytes, parsed, [state], true);
    else refusal(outcome);
  };

  // ── the end: the server's output read to its end, then handed over ───────
  server.on("error", (err) => {
    stderr(`[doorman gateway] MCP server error: ${String(err)}\n`);
    if (server.pid === undefined) {
      // Never started (ENOENT, EACCES): there is no output to wait for.
      serverClosed = true;
      finish({ code: 2 });
    }
  });
  server.on("close", (code, signal) => {
    if (serverClosed) return;
    serverClosed = true;
    // Requests the server will now never answer get an error instead of a
    // hang; held calls can't be forwarded any more.
    const died = `The MCP server exited before answering${signal ? ` (${signal})` : code ? ` (exit code ${code})` : ""}.`;
    for (const [key, rawId] of inflight) {
      ownLine(errorResponse(rawId, died, -32000));
      const call = pending.get(key);
      if (call) {
        append(callsPath, { call: call.call, tool: call.request.name, cls: call.cls, called_at: call.at, is_error: true, result_chars: 0, excerpt: died });
      }
    }
    inflight.clear();
    pending.clear();
    // Held calls are answered here, while the client is still being written
    // to; the hold itself then ends as `upstream_gone` without a second answer.
    for (const hold of holds) if (hold.rawId !== undefined && !hold.dropped) refuse(hold.rawId, died);
    dropHolds("upstream_gone");
    toClient.finish();
    const exitWith = { code: code ?? (signal ? 1 : 0), ...((terminatedBy ?? signal) ? { signal: (terminatedBy ?? signal)! } : {}) };
    const drained = (): void => finish(exitWith);
    if (clientGone || !output.writableLength) {
      drained();
      return;
    }
    output.once("drain", drained);
    // A client that stopped reading must not keep the gateway alive forever.
    setTimeout(drained, 30_000).unref?.();
  });

  return {
    done,
    terminate(signal: NodeJS.Signals = "SIGTERM") {
      terminatedBy ??= signal;
      terminate(signal);
    },
  };
}

function main(): void {
  const gatewayDir = __dirname;
  const args = parseGatewayArgs(process.argv.slice(2));
  if (!args) {
    process.stderr.write("[doorman gateway] no wrapped command; nothing to proxy\n");
    process.exit(2);
    return;
  }
  // A client that closes its end mid-write is an EPIPE here: handled by the
  // run (it stops the server), never an unhandled crash.
  const run = runGateway({ args, gatewayDir, guardDir: join(gatewayDir, "..", "guard"), input: process.stdin, output: process.stdout });
  for (const sig of ["SIGTERM", "SIGINT", "SIGHUP"] as const) process.on(sig, () => run.terminate(sig));
  // Last resort: whatever ends this process takes the server with it — an
  // orphaned server that ignores EOF would otherwise outlive its agent.
  process.on("exit", () => run.terminate("SIGKILL"));
  void run.done.then(({ code, signal }) => {
    if (signal) {
      // Mirror the child's fate so the host sees the real server's outcome —
      // without our own handler swallowing the re-raised signal.
      process.removeAllListeners(signal);
      process.kill(process.pid, signal);
    } else {
      process.exit(code);
    }
  });
}

// Only run when invoked directly (not when imported by a test).
if (process.argv[1] && process.argv[1].endsWith("mcp-gateway.js")) {
  main();
}
