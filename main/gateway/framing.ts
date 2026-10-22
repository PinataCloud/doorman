/**
 * MCP stdio framing — the pure half of the gateway, split out so it is testable
 * without spawning a process.
 *
 * The MCP stdio transport is newline-delimited JSON-RPC: each `\n`-terminated
 * line is one complete message, no embedded newlines. Phase 1 only OBSERVED the
 * server→client stream for `tools/list` results; phase 2 reads both directions
 * — `tools/call` requests going out, their results coming back, paired by
 * JSON-RPC id — and classifies each tool as read / write / act so the gateway
 * can apply per-server permissions (mcp-gateway.ts). Nothing here touches the
 * forwarded bytes; a line the gateway decides to hold or refuse is a decision
 * mcp-gateway.ts makes with what this file parsed.
 *
 * Lines are split as BYTES (ByteLineBuffer): a pipe chunk can end in the middle
 * of a multi-byte character, and decoding chunks one at a time turns that
 * character into U+FFFD. A line is only decoded once it is complete, and the
 * bytes forwarded are the bytes that arrived.
 *
 * Self-containment rule: this directory is compiled and copied verbatim into
 * userData, where an agent spawns it with plain `node`. It may import from the
 * sibling guard bundle (`../guard/*.js`, copied alongside) and nothing else.
 */

import { isPlainObject as isRecord } from "../guard/jsonc.js";

/** One observed tool, as the app's poisoning scan wants it. */
export interface ObservedTool {
  name: string;
  description?: string;
  /** The input schema, stringified — poisoning also hides in parameter descriptions. */
  schema?: string;
  /** The MCP spec's tool annotations, when the server sends them — the honest
   * source for the permission class (readOnlyHint, destructiveHint, openWorldHint). */
  annotations?: { readOnlyHint?: boolean; destructiveHint?: boolean; openWorldHint?: boolean; idempotentHint?: boolean };
}

export type McpToolClass = "read" | "write" | "act";

/** `raw.first`: this run starts the oversized line (its first bytes hold the
 * message's opening, an id included). */
export type ByteSegment = { kind: "line"; bytes: Buffer } | { kind: "raw"; bytes: Buffer; first: boolean };

const NEWLINE = 0x0a;

/**
 * A byte-level line splitter. Feed it chunks; it yields complete lines (each
 * WITH its terminating `\n`, so writing them reproduces the input) and keeps
 * the partial tail for the next feed.
 *
 * Bounded: a partial line past `maxLineBytes` is handed back as `raw` bytes as
 * it arrives instead of being buffered — the caller forwards them verbatim and
 * gives up on parsing that one line. The bytes are never dropped: on the
 * client→server side a dropped line was a lost tool call. Writing every
 * segment in order reproduces the input byte for byte.
 */
export class ByteLineBuffer {
  private parts: Buffer[] = [];
  private size = 0;
  /** Inside an oversized line: everything up to its newline is `raw`. */
  private spilling = false;

  constructor(private readonly maxLineBytes = 4 * 1024 * 1024) {}

  push(chunk: Buffer): ByteSegment[] {
    const out: ByteSegment[] = [];
    let start = 0;
    while (start < chunk.length) {
      const nl = chunk.indexOf(NEWLINE, start);
      if (this.spilling) {
        if (nl < 0) {
          out.push({ kind: "raw", bytes: chunk.subarray(start), first: false });
          return out;
        }
        out.push({ kind: "raw", bytes: chunk.subarray(start, nl + 1), first: false });
        this.spilling = false;
        start = nl + 1;
        continue;
      }
      if (nl < 0) {
        const tail = chunk.subarray(start);
        if (this.size + tail.length > this.maxLineBytes) {
          out.push({ kind: "raw", bytes: this.take(tail), first: true });
          this.spilling = true;
        } else {
          this.parts.push(tail);
          this.size += tail.length;
        }
        return out;
      }
      out.push({ kind: "line", bytes: this.take(chunk.subarray(start, nl + 1)) });
      start = nl + 1;
    }
    return out;
  }

  /** At end of input: the unterminated last line, if any, as a `line` with no
   * newline (a client may end its final message with EOF instead of `\n`). */
  end(): ByteSegment[] {
    if (this.spilling || this.size === 0) {
      this.spilling = false;
      return [];
    }
    return [{ kind: "line", bytes: this.take(Buffer.alloc(0)) }];
  }

  /** True while a line has started but not ended. */
  get midLine(): boolean {
    return this.spilling || this.size > 0;
  }

  private take(last: Buffer): Buffer {
    const whole = this.size === 0 ? last : Buffer.concat([...this.parts, last]);
    this.parts = [];
    this.size = 0;
    return whole;
  }
}

/** One JSON-RPC message from a line, with its id exactly as it was spelled. */
export interface RpcMessage {
  msg: Record<string, unknown>;
  /** The id's JSON source text (`9007199254740993`, `"a"`, `null`, `{…}`);
   * undefined when the message has no id member at all. */
  rawId?: string;
}

/** A parsed line: one message, or a JSON-RPC batch of them. */
export interface RpcLine {
  batch: boolean;
  messages: RpcMessage[];
}

// A minimal skimmer over text JSON.parse has already accepted — enough to find
// member and element SPANS, which JSON.parse doesn't report. Only the id's
// source text is read this way: a large integer id loses digits as a number.

function skipWs(t: string, i: number): number {
  while (i < t.length && (t[i] === " " || t[i] === "\t" || t[i] === "\n" || t[i] === "\r")) i++;
  return i;
}

function skipString(t: string, i: number): number {
  for (i += 1; i < t.length; i++) {
    if (t[i] === "\\") i++;
    else if (t[i] === '"') return i + 1;
  }
  return i;
}

function skipValue(t: string, i: number): number {
  const c = t[i];
  if (c === '"') return skipString(t, i);
  if (c === "{" || c === "[") {
    let depth = 0;
    while (i < t.length) {
      const ch = t[i];
      if (ch === '"') {
        i = skipString(t, i);
        continue;
      }
      if (ch === "{" || ch === "[") depth++;
      else if (ch === "}" || ch === "]") {
        depth--;
        if (depth === 0) return i + 1;
      }
      i++;
    }
    return i;
  }
  while (i < t.length && !/[\s,\]}]/.test(t[i]!)) i++;
  return i;
}

/** The source text of the object at `start`'s `id` member (last one wins, as
 * in JSON.parse), or undefined when it has none. */
function rawIdAt(t: string, start: number): string | undefined {
  let found: string | undefined;
  let i = start + 1;
  for (;;) {
    i = skipWs(t, i);
    if (t[i] !== '"') return found;
    const keyEnd = skipString(t, i);
    const key = JSON.parse(t.slice(i, keyEnd)) as string;
    i = skipWs(t, keyEnd);
    if (t[i] !== ":") return found;
    i = skipWs(t, i + 1);
    const valueEnd = skipValue(t, i);
    if (key === "id") found = t.slice(i, valueEnd);
    i = skipWs(t, valueEnd);
    if (t[i] !== ",") return found;
    i += 1;
  }
}

/**
 * Parse one JSON-RPC line into its message(s): a single object, or a batch
 * array (JSON-RPC 2.0 §6). Undefined for anything that isn't JSON-RPC shaped.
 * Never throws.
 */
export function parseRpc(line: string): RpcLine | undefined {
  const t = line.trim();
  if (t === "" || (t[0] !== "{" && t[0] !== "[")) return undefined;
  let value: unknown;
  try {
    value = JSON.parse(t);
  } catch {
    return undefined;
  }
  try {
    if (isRecord(value)) return { batch: false, messages: [{ msg: value, ...optionalId(rawIdAt(t, 0)) }] };
    if (!Array.isArray(value)) return undefined;
    const messages: RpcMessage[] = [];
    let i = skipWs(t, 1);
    for (const element of value) {
      const end = skipValue(t, i);
      if (isRecord(element)) messages.push({ msg: element, ...optionalId(rawIdAt(t, i)) });
      i = skipWs(t, end);
      if (t[i] === ",") i = skipWs(t, i + 1);
    }
    return { batch: true, messages };
  } catch {
    return undefined;
  }
}

function optionalId(rawId: string | undefined): { rawId?: string } {
  return rawId === undefined ? {} : { rawId };
}

/**
 * A map key pairing a request with its response. Strings and safe integers
 * compare by value; anything else (an unsafe integer, `null`, an object id a
 * client shouldn't send but might) by its exact source text — so two ids that
 * differ only past 2^53 never share a key. Undefined when there is no id.
 */
export function rpcIdKey(message: RpcMessage): string | undefined {
  const { rawId } = message;
  if (rawId === undefined) return undefined;
  const id = message.msg.id;
  if (typeof id === "string") return `s:${id}`;
  if (typeof id === "number" && Number.isSafeInteger(id)) return `n:${id}`;
  return `x:${rawId}`;
}

function annotationsOf(rec: Record<string, unknown>): ObservedTool["annotations"] | undefined {
  const a = rec.annotations;
  if (!a || typeof a !== "object") return undefined;
  const r = a as Record<string, unknown>;
  const out: NonNullable<ObservedTool["annotations"]> = {};
  for (const key of ["readOnlyHint", "destructiveHint", "openWorldHint", "idempotentHint"] as const) {
    if (typeof r[key] === "boolean") out[key] = r[key] as boolean;
  }
  return Object.keys(out).length > 0 ? out : undefined;
}

/**
 * If this message is a `tools/list` RESULT, return its tools; else undefined. A
 * plain result-with-a-tools-array is the only shape we care about — matching by
 * shape rather than by tracking request ids keeps the observer stateless and
 * robust to a server that re-lists after `notifications/tools/list_changed`.
 * Descriptions come back whole; the caller caps what it stores.
 */
export function toolsOf(message: RpcMessage): ObservedTool[] | undefined {
  const result = message.msg.result;
  if (!isRecord(result)) return undefined;
  const tools = result.tools;
  if (!Array.isArray(tools)) return undefined;
  const out: ObservedTool[] = [];
  for (const t of tools) {
    if (!isRecord(t)) continue;
    if (typeof t.name !== "string") continue;
    const annotations = annotationsOf(t);
    out.push({
      name: t.name,
      ...(typeof t.description === "string" ? { description: t.description } : {}),
      ...(t.inputSchema && typeof t.inputSchema === "object" ? { schema: safeStringify(t.inputSchema) } : {}),
      ...(annotations ? { annotations } : {}),
    });
  }
  return out;
}

/** The tools of the first `tools/list` result on a line (batches included). */
export function toolsFromLine(line: string): ObservedTool[] | undefined {
  for (const message of parseRpc(line)?.messages ?? []) {
    const tools = toolsOf(message);
    if (tools) return tools;
  }
  return undefined;
}

/**
 * A `tools/call` REQUEST going client→server. Anything with that method is
 * one, whatever its id — a missing, `null`, object or boolean id doesn't stop a
 * server from running the tool, so it must not stop the gateway deciding on it.
 */
export interface ToolCallRequest {
  /** Pairs the call with its result; undefined for a notification (no id). */
  idKey?: string;
  /** The id's source text, echoed exactly in a refusal. */
  rawId?: string;
  /** The tool name, `""` when the request names none. */
  name: string;
  arguments: unknown;
}

export function toolCallOf(message: RpcMessage): ToolCallRequest | undefined {
  if (message.msg.method !== "tools/call") return undefined;
  const params = isRecord(message.msg.params) ? message.msg.params : {};
  const idKey = rpcIdKey(message);
  return {
    ...(idKey === undefined ? {} : { idKey }),
    ...optionalId(message.rawId),
    name: typeof params.name === "string" ? params.name : "",
    arguments: params.arguments,
  };
}

/** The `tools/call` requests on a line, batches included. */
export function toolCallsFromLine(line: string): ToolCallRequest[] {
  return (parseRpc(line)?.messages ?? []).flatMap((m) => toolCallOf(m) ?? []);
}

/** The ids a `notifications/cancelled` names (MCP: `params.requestId`), as keys. */
export function cancelledIdKey(message: RpcMessage): string | undefined {
  if (message.msg.method !== "notifications/cancelled") return undefined;
  const params = message.msg.params;
  if (!isRecord(params) || !("requestId" in params)) return undefined;
  const id = params.requestId;
  if (typeof id === "string") return `s:${id}`;
  if (typeof id === "number" && Number.isSafeInteger(id)) return `n:${id}`;
  // An unsafe integer here has lost its digits already; the safe-integer and
  // string ids every real client uses are what is matched.
  return undefined;
}

function stringLeaves(value: unknown, out: string[], depth = 0): void {
  if (depth > 8 || out.length > 2_000) return;
  if (typeof value === "string") {
    if (value.trim() !== "") out.push(value);
  } else if (Array.isArray(value)) {
    for (const v of value) stringLeaves(v, out, depth + 1);
  } else if (isRecord(value)) {
    for (const v of Object.values(value)) stringLeaves(v, out, depth + 1);
  }
}

/** The text a `tools/call` RESULT carries, flattened — content blocks of type
 * text plus any `structuredContent` they don't already say, for the injection
 * scan and the excerpt. */
export function toolResultOf(message: RpcMessage): { idKey: string; text: string; isError: boolean } | undefined {
  const idKey = rpcIdKey(message);
  if (idKey === undefined) return undefined;
  const { msg } = message;
  if (isRecord(msg.error)) {
    const text = msg.error.message;
    return { idKey, text: typeof text === "string" ? text : "", isError: true };
  }
  const r = msg.result;
  if (!isRecord(r)) return undefined;
  const parts: string[] = [];
  if (Array.isArray(r.content)) {
    for (const block of r.content) {
      if (!isRecord(block)) continue;
      if (block.type === "text" && typeof block.text === "string") parts.push(block.text);
      // Resource blocks carry fetched documents — exactly where an injection lives.
      const resource = block.resource;
      if (isRecord(resource) && typeof resource.text === "string") parts.push(resource.text);
    }
  }
  if (r.structuredContent !== undefined) {
    // The spec has a server repeat its structured result as text, so most
    // results say everything twice. Only structure that adds something — a
    // string the text blocks don't contain — is counted again.
    const said = parts.join("\n");
    const leaves: string[] = [];
    stringLeaves(r.structuredContent, leaves);
    const adds = parts.length === 0 || leaves.some((leaf) => !said.includes(leaf));
    const s = adds ? safeStringify(r.structuredContent) : undefined;
    if (s) parts.push(s);
  }
  if (parts.length === 0 && !("content" in r)) return undefined;
  return { idKey, text: parts.join("\n"), isError: r.isError === true };
}

/** Verb-shaped fallbacks for a server that sends no annotations. */
const READ_VERB_RE = /(?:^|[_-])(?:get|read|list|search|fetch|query|find|lookup|describe|show|view|count|check|browse|download|export|stat|head|cat|ls|info)(?:$|[_-])/i;
const ACT_VERB_RE = /(?:^|[_-])(?:send|post|reply|forward|share|publish|deploy|run|exec(?:ute)?|invoke|launch|start|stop|restart|kill|delete|remove|destroy|drop|truncate|purge|pay|charge|transfer|approve|merge|push|release|email|message|dm|notify|schedule|trigger|submit|grant|revoke|reset)(?:$|[_-])/i;

/**
 * The permission class of a tool: what the server SAYS (annotations) first,
 * the verb in its name second, `write` when neither speaks — the middle class
 * is the honest default for "does something we can't characterize". An
 * `openWorldHint` (the tool reaches beyond the server's own data) promotes a
 * write to act: outward is what the act class is for.
 */
export function classifyTool(tool: Pick<ObservedTool, "name" | "annotations">): McpToolClass {
  const a = tool.annotations;
  // Annotations are the SERVER's word about itself. They may raise a tool's
  // class freely, but a `readOnlyHint` can only LOWER it when the name does
  // not say otherwise: a server that labels `delete_repository` read-only is
  // lying, and the verb is the one thing it cannot rewrite without also
  // changing what the client calls.
  const actVerb = ACT_VERB_RE.test(tool.name);
  if (a) {
    if (a.destructiveHint === true) return "act";
    if (a.openWorldHint === true) return "act";
    if (a.readOnlyHint === true) return actVerb ? "act" : "read";
    if (a.readOnlyHint === false || a.destructiveHint === false) return actVerb ? "act" : "write";
  }
  if (actVerb) return "act";
  if (READ_VERB_RE.test(tool.name)) return "read";
  return "write";
}

/**
 * A JSON-RPC error response the gateway sends INSTEAD of forwarding a call it
 * refused — the client sees a failed tool call with a reason, never a hang.
 * `rawId` is the request's id as it was spelled, echoed byte for byte (an
 * integer past 2^53 would come back as a different number through JSON).
 */
export function refusalLine(rawId: string, message: string, code = -32001): string {
  return `${errorResponse(rawId, message, code)}\n`;
}

/** One error response object as text, with the id spliced in verbatim. */
export function errorResponse(rawId: string, message: string, code = -32001): string {
  return `{"jsonrpc":"2.0","id":${rawId},"error":${JSON.stringify({ code, message })}}`;
}

export function safeStringify(value: unknown): string | undefined {
  try {
    return JSON.stringify(value).slice(0, 8_000);
  } catch {
    return undefined;
  }
}
