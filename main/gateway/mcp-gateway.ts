/**
 * The MCP gateway — phase 2: a stdio proxy that wraps one MCP server, observes
 * what it advertises and returns, and ENFORCES per-server permissions on what
 * the agent asks it to do.
 *
 * An agent is configured to spawn THIS instead of the real server:
 *   command: node   args: ["<userData>/…/gateway/mcp-gateway.js",
 *                          "--server", "<name>", "--", "<real cmd>", "<args…>"]
 * We spawn the real command and relay the JSON-RPC stream in both directions,
 * line by line, each line forwarded byte-for-byte. Three things ride on top:
 *
 *  1. OBSERVE descriptions (phase 1): `tools/list` results append each tool's
 *     name/description/schema/annotations to `observed.jsonl` next to this
 *     file; the app scans them for poisoning and notices a description that
 *     CHANGES after it was first seen (the rug pull).
 *  2. OBSERVE calls and results: every `tools/call` request is paired with its
 *     result by JSON-RPC id, the result text is redacted and run through the
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
 *     `ask` (policy `mcp_armed_escalation`, default on).
 *
 * Non-negotiables, in order:
 *  · BYTE-EXACT for everything we don't decide about. A line is forwarded as
 *    the bytes it arrived as; observation reads a copy. Only a line we refuse
 *    is withheld, and then the client gets an error response for that id.
 *  · FAIL to the real server, not to nothing. If we can't spawn the child the
 *    server is genuinely unavailable; we exit with the child's code. Every
 *    observation/enforcement error is swallowed and the line is forwarded.
 *  · NO STDOUT OF OUR OWN except a refusal for a held/blocked call. Anything
 *    else we printed would corrupt the stream. Diagnostics go to stderr.
 *  · DEFAULT ALLOW. With no permissions configured the gateway forwards
 *    everything, exactly as phase 1 did.
 *  · An `ask` NOBODY CAN ANSWER is refused, not forwarded (2026-09-10,
 *    docs/plans/desktop-integration-enforcement-review.md F2): no app
 *    listening, the app gone mid-hold, a hold that errored, or the timeout
 *    fallback `ask` — all resolve through `gatewayHoldOutcome` under the same
 *    `confirm.unattended` the PreToolUse guard reads (default `deny`; `continue`
 *    restores the phase-2 forward). A configured `ask` is an authorization
 *    rule; the gateway's own availability is not an approval.
 *
 * Self-containment rule: copied verbatim to userData and run with plain `node`.
 * It may import from the sibling guard bundle (`../guard/*.js`, copied to the
 * neighbouring directory by the same installer) and from nothing else.
 */

import { spawn } from "node:child_process";
import { appendFileSync, readFileSync } from "node:fs";
import { createHash, randomUUID } from "node:crypto";
import { join } from "node:path";
import { redact } from "../guard/redact.js";
import { detectSecurityFindings } from "../guard/security-detect.js";
import { scanMcpToolOutput } from "../guard/mcp-poison.js";
import { INJECTION_MARKER_DETECTORS } from "../guard/armed.js";
import { ruleShown } from "../guard/rule-scope.js";
import { parsePolicy, type GuardPolicy, type McpPermissionMode } from "../guard/policy.js";
import {
  appListening,
  decidedAtMs,
  holdForVerdict,
  toolCallPreview,
  writeRequest,
  clearExchange,
  type ApprovalResolution,
  type HoldOutcome,
} from "../guard/handshake.js";
import {
  LineBuffer,
  classifyTool,
  refusalLine,
  toolCallFromLine,
  toolResultTextFromLine,
  toolsFromLine,
  type McpToolClass,
  type ObservedTool,
  type ToolCallRequest,
} from "./framing.js";

interface Args {
  server: string;
  command: string;
  commandArgs: string[];
}

/** Parse `--server <name> -- <cmd> <args…>`. Testable, so it lives apart from
 * the process wiring below. */
export function parseGatewayArgs(argv: readonly string[]): Args | undefined {
  const dashDash = argv.indexOf("--");
  if (dashDash < 0 || dashDash === argv.length - 1) return undefined;
  const flags = argv.slice(0, dashDash);
  const rest = argv.slice(dashDash + 1);
  const serverIdx = flags.indexOf("--server");
  const server = serverIdx >= 0 ? flags[serverIdx + 1] ?? "" : "";
  const [command, ...commandArgs] = rest;
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
export function gatewayHoldOutcome(policy: GuardPolicy, held: HoldOutcome | undefined): GatewayHoldOutcome {
  if (held?.outcome === "answered") {
    return held.reply.verdict === "allow"
      ? { forward: true, resolution: "allowed" }
      : { forward: false, resolution: "denied", message: "You denied it in Doorman." };
  }
  const seconds = policy.confirm.hold_seconds;
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

function main(): void {
  const gatewayDir = __dirname;
  const guardDir = join(gatewayDir, "..", "guard");
  const args = parseGatewayArgs(process.argv.slice(2));
  if (!args) {
    process.stderr.write("[doorman gateway] no wrapped command; nothing to proxy\n");
    process.exit(2);
    return;
  }

  const observedPath = join(gatewayDir, "observed.jsonl");
  const callsPath = join(gatewayDir, "calls.jsonl");
  const seenTools = new Set<string>();
  const tools = new Map<string, ObservedTool>();
  const pending = new Map<string, ToolCallRequest & { at: string; cls: McpToolClass }>();
  let armed: { marker: string; at: string } | undefined;
  const fromServer = new LineBuffer();
  const fromClient = new LineBuffer();

  const readPolicy = (): GuardPolicy => {
    try {
      return parsePolicy(readFileSync(join(guardDir, "policy.json"), "utf8"));
    } catch {
      return parsePolicy(undefined);
    }
  };

  const append = (path: string, record: Record<string, unknown>): void => {
    try {
      appendFileSync(path, `${JSON.stringify({ at: new Date().toISOString(), server: args.server, ...record })}\n`);
    } catch {
      // Observation must never affect the proxy.
    }
  };

  let child;
  try {
    child = spawn(args.command, args.commandArgs, { stdio: ["pipe", "pipe", "inherit"] });
  } catch (err) {
    process.stderr.write(`[doorman gateway] couldn't start MCP server: ${String(err)}\n`);
    process.exit(2);
    return;
  }
  const server = child;

  // ── server → client: forward every line verbatim, observe a copy ──────────
  child.stdout.on("data", (chunk: Buffer) => {
    process.stdout.write(chunk);
    try {
      for (const line of fromServer.push(chunk.toString("utf8"))) observeFromServer(line);
    } catch {
      // never let observation touch the stream
    }
  });

  const observeFromServer = (line: string): void => {
    const listed = toolsFromLine(line);
    if (listed) {
      for (const tool of listed) {
        tools.set(tool.name, tool);
        const id = toolKey(args.server, tool);
        if (seenTools.has(id)) continue;
        seenTools.add(id);
        append(observedPath, { id, ...tool });
      }
      return;
    }
    const result = toolResultTextFromLine(line);
    if (!result) return;
    const call = pending.get(result.idKey);
    if (!call) return;
    pending.delete(result.idKey);
    const markers = result.text ? injectionMarkersIn(result.text, `mcp__${args.server}__${call.name}`) : [];
    if (markers.length > 0) armed = { marker: markers[0]!, at: new Date().toISOString() };
    append(callsPath, {
      tool: call.name,
      cls: call.cls,
      called_at: call.at,
      is_error: result.isError,
      result_chars: result.text.length,
      // Masked, windowed — a record of what came back, never the payload.
      excerpt: redact(result.text).replace(/\s+/g, " ").slice(0, 200),
      ...(markers.length > 0 ? { injection: markers } : {}),
    });
  };

  // ── client → server: forward each line, unless it is a call we decide on ──
  process.stdin.on("data", (chunk: Buffer) => {
    let segments: ReturnType<typeof fromClient.pushSegments>;
    try {
      segments = fromClient.pushSegments(chunk.toString("utf8"));
    } catch {
      server.stdin.write(chunk);
      return;
    }
    // In order: a `raw` run is part of a line past the buffer's bound (a
    // tools/call carrying a large inline payload) and is forwarded verbatim,
    // unobserved — never dropped, a dropped line here was a lost tool call. A
    // `line` is re-terminated with the newline the buffer split on, so the
    // bytes the server sees are the bytes the client sent; a chunk that doesn't
    // end a line has been buffered whole and is forwarded with the line it
    // completes.
    for (const segment of segments) {
      if (segment.kind === "raw") server.stdin.write(segment.text);
      else void relayFromClient(segment.text);
    }
  });
  process.stdin.on("end", () => {
    try {
      server.stdin.end();
    } catch {
      // already gone
    }
  });

  const relayFromClient = async (line: string): Promise<void> => {
    let call: ToolCallRequest | undefined;
    let decision: GatewayDecision | undefined;
    try {
      call = toolCallFromLine(line);
      if (call) {
        const policy = readPolicy();
        const known = tools.get(call.name) ?? { name: call.name };
        decision = decideToolCall(policy, args.server, known, armed);
      }
    } catch {
      decision = undefined;
    }
    if (!call || !decision || decision.action === "forward") {
      if (call && decision) pending.set(call.idKey, { ...call, at: new Date().toISOString(), cls: decision.cls });
      server.stdin.write(`${line}\n`);
      return;
    }
    const rpcId = idFromKey(call.idKey);
    if (decision.action === "block") {
      append(callsPath, { tool: call.name, cls: decision.cls, blocked: true, reason: decision.reason });
      process.stdout.write(refusalLine(rpcId, decision.reason ?? "Blocked by Doorman."));
      return;
    }
    // ask: hold through the app, exactly as the PreToolUse guard does. No app
    // listening → nobody to ask: `confirm.unattended` decides (gatewayHoldOutcome).
    const policy = readPolicy();
    if (!appListening(guardDir)) {
      const outcome = gatewayHoldOutcome(policy, undefined);
      append(callsPath, {
        tool: call.name,
        cls: decision.cls,
        unattended: true,
        resolution: outcome.resolution,
        forwarded: outcome.forward,
        reason: decision.reason,
      });
      if (outcome.forward) {
        pending.set(call.idKey, { ...call, at: new Date().toISOString(), cls: decision.cls });
        server.stdin.write(`${line}\n`);
      } else {
        process.stdout.write(refusalLine(rpcId, `${decision.reason ?? "Held by Doorman."} ${outcome.message ?? ""}`.trim()));
      }
      return;
    }
    const id = randomUUID();
    const heldAt = new Date().toISOString();
    const preview = toolCallPreview(`mcp__${args.server}__${call.name}`, redact(JSON.stringify(call.arguments ?? {}))).preview;
    // Set the moment the call has been forwarded or refused, so the catch below
    // can never answer a call twice.
    let settled = false;
    try {
      writeRequest(guardDir, {
        id,
        at: heldAt,
        source: "mcp-gateway",
        tool_name: `mcp__${args.server}__${call.name}`,
        target: call.name,
        server: args.server,
        tool_class: decision.cls,
        detectors: decision.armed ? ["flow_injection_followed"] : ["mcp_permission"],
        detector_labels: { mcp_permission: `MCP ${decision.cls} call on ${args.server}` },
        max_severity: decision.armed ? "critical" : "high",
        reason: decision.reason ?? "Held by Doorman.",
        preview,
        hold_seconds: policy.confirm.hold_seconds,
        on_timeout: policy.confirm.on_timeout,
        pid: process.pid,
      });
      const held = await holdForVerdict(guardDir, id, policy.confirm.hold_seconds);
      const outcome = gatewayHoldOutcome(policy, held);
      const decidedMs = decidedAtMs(held, Date.parse(heldAt), Date.now());
      append(callsPath, {
        tool: call.name,
        cls: decision.cls,
        held: true,
        resolution: outcome.resolution,
        forwarded: outcome.forward,
        held_at: heldAt,
        decided_at: new Date(decidedMs).toISOString(),
        decided_via: held.outcome === "answered" ? held.reply.via ?? "window" : held.outcome === "timeout" ? "timeout" : "app-absent",
        hold_ms: Math.max(0, decidedMs - Date.parse(heldAt)),
        ...(decision.armed ? { injection: [decision.armed.marker] } : {}),
        reason: decision.reason,
      });
      settled = true;
      if (outcome.forward) {
        pending.set(call.idKey, { ...call, at: new Date().toISOString(), cls: decision.cls });
        server.stdin.write(`${line}\n`);
      } else {
        process.stdout.write(refusalLine(rpcId, `${decision.reason ?? "Held by Doorman."} ${outcome.message ?? ""}`.trim()));
      }
    } catch {
      // The hold machinery itself failed (a full disk under pending/, an
      // unreadable reply): nobody was reached, so `confirm.unattended` decides
      // — the same rule as an absent app, never a silent forward.
      if (settled) return;
      const outcome = gatewayHoldOutcome(policy, undefined);
      append(callsPath, { tool: call.name, cls: decision.cls, hold_error: true, resolution: outcome.resolution, forwarded: outcome.forward, reason: decision.reason });
      if (outcome.forward) {
        pending.set(call.idKey, { ...call, at: new Date().toISOString(), cls: decision.cls });
        server.stdin.write(`${line}\n`);
      } else {
        process.stdout.write(refusalLine(rpcId, `${decision.reason ?? "Held by Doorman."} ${outcome.message ?? ""}`.trim()));
      }
    } finally {
      clearExchange(guardDir, id);
    }
  };

  const forwardSignal = (sig: NodeJS.Signals) => {
    try {
      child.kill(sig);
    } catch {
      // already gone
    }
  };
  process.on("SIGTERM", () => forwardSignal("SIGTERM"));
  process.on("SIGINT", () => forwardSignal("SIGINT"));

  child.on("error", (err) => {
    process.stderr.write(`[doorman gateway] MCP server error: ${String(err)}\n`);
    process.exit(2);
  });
  child.on("exit", (code, signal) => {
    // Mirror the child's fate so the host sees the real server's outcome.
    if (signal) process.kill(process.pid, signal);
    else process.exit(code ?? 0);
  });
}

/** Undo rpcIdKey for the refusal response. */
function idFromKey(key: string): string | number {
  return key.startsWith("n:") ? Number(key.slice(2)) : key.slice(2);
}

// Only run when invoked directly (not when imported by a test for parseGatewayArgs).
if (process.argv[1] && process.argv[1].endsWith("mcp-gateway.js")) {
  main();
}
