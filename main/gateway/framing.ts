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
 * Self-containment rule: this directory is compiled and copied verbatim into
 * userData, where an agent spawns it with plain `node`. It may import from the
 * sibling guard bundle (`../guard/*.js`, copied alongside) and nothing else.
 */

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

/**
 * A line-buffered splitter. Feed it stdout chunks; it yields complete lines and
 * keeps any partial tail for the next feed. Bounded: a single line past
 * MAX_LINE_BYTES is dropped (an MCP message that large is not a tools/list we
 * need to parse, and buffering it unboundedly would be the observer leaking
 * memory the passthrough doesn't).
 */
export class LineBuffer {
  private buf = "";
  /** Bytes of the current line already handed back as an `overflow` chunk. */
  private spilled = 0;
  /**
   * @param maxLineBytes past this, a partial line is handed back as it arrives
   *   (`overflow`) instead of being buffered — the caller forwards the bytes
   *   verbatim and gives up on observing that one line. The bytes are never
   *   dropped: on the client→server side a dropped line was a lost tool call.
   */
  constructor(private readonly maxLineBytes = 4 * 1024 * 1024) {}

  push(chunk: string): string[] {
    return this.pushSegments(chunk)
      .filter((s): s is { kind: "line"; text: string } => s.kind === "line")
      .map((s) => s.text);
  }

  /**
   * The chunk as an ORDERED list of segments: complete `line`s (newline
   * stripped, to be parsed and re-terminated by the caller) and `raw` byte
   * runs belonging to an oversized line, to be forwarded verbatim and never
   * parsed. Once a line spills, the rest of it up to and including its newline
   * keeps arriving as `raw`, so a caller that writes segments in order
   * reproduces the input byte-for-byte; observation resumes with the next line.
   */
  pushSegments(chunk: string): LineSegment[] {
    const out: LineSegment[] = [];
    let rest = chunk;
    if (this.spilled > 0) {
      // Mid-spill: pass through up to the newline, then resume buffering.
      const nl = rest.indexOf("\n");
      if (nl < 0) {
        this.spilled += rest.length;
        return [{ kind: "raw", text: rest }];
      }
      out.push({ kind: "raw", text: rest.slice(0, nl + 1) });
      this.spilled = 0;
      rest = rest.slice(nl + 1);
    }
    this.buf += rest;
    if (this.buf.length > this.maxLineBytes && !this.buf.includes("\n")) {
      // A single oversized partial line: hand it back for passthrough and
      // remember that the rest of this line is not ours to parse.
      out.push({ kind: "raw", text: this.buf });
      this.spilled = this.buf.length;
      this.buf = "";
      return out;
    }
    let idx: number;
    while ((idx = this.buf.indexOf("\n")) >= 0) {
      out.push({ kind: "line", text: this.buf.slice(0, idx) });
      this.buf = this.buf.slice(idx + 1);
    }
    // The tail left after the last newline may itself already be oversized:
    // spill it now rather than holding it until the next chunk.
    if (this.buf.length > this.maxLineBytes) {
      out.push({ kind: "raw", text: this.buf });
      this.spilled = this.buf.length;
      this.buf = "";
    }
    return out;
  }
}

export type LineSegment = { kind: "line"; text: string } | { kind: "raw"; text: string };

/** Parse one JSON-RPC line; undefined for anything that isn't an object. */
export function parseRpcLine(line: string): Record<string, unknown> | undefined {
  const trimmed = line.trim();
  if (trimmed === "" || trimmed[0] !== "{") return undefined;
  try {
    const msg = JSON.parse(trimmed) as unknown;
    return msg && typeof msg === "object" && !Array.isArray(msg) ? (msg as Record<string, unknown>) : undefined;
  } catch {
    return undefined;
  }
}

/** JSON-RPC ids are strings or numbers; normalized to a map key. */
export function rpcIdKey(id: unknown): string | undefined {
  if (typeof id === "string") return `s:${id}`;
  if (typeof id === "number" && Number.isFinite(id)) return `n:${id}`;
  return undefined;
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
 * If this line is a `tools/list` RESULT, return its tools; else undefined. A
 * plain result-with-a-tools-array is the only shape we care about — matching by
 * shape rather than by tracking request ids keeps the observer stateless and
 * robust to a server that re-lists after `notifications/tools/list_changed`.
 * Never throws — a non-JSON or unexpected line simply isn't a tool list.
 */
export function toolsFromLine(line: string): ObservedTool[] | undefined {
  const msg = parseRpcLine(line);
  if (!msg) return undefined;
  const result = msg.result;
  if (!result || typeof result !== "object") return undefined;
  const tools = (result as Record<string, unknown>).tools;
  if (!Array.isArray(tools)) return undefined;
  const out: ObservedTool[] = [];
  for (const t of tools) {
    if (!t || typeof t !== "object") continue;
    const rec = t as Record<string, unknown>;
    if (typeof rec.name !== "string") continue;
    const annotations = annotationsOf(rec);
    out.push({
      name: rec.name,
      ...(typeof rec.description === "string" ? { description: rec.description } : {}),
      ...(rec.inputSchema && typeof rec.inputSchema === "object"
        ? { schema: safeStringify(rec.inputSchema) }
        : {}),
      ...(annotations ? { annotations } : {}),
    });
  }
  return out;
}

/** A `tools/call` REQUEST going client→server: the tool and its arguments. */
export interface ToolCallRequest {
  idKey: string;
  name: string;
  arguments: unknown;
}

export function toolCallFromLine(line: string): ToolCallRequest | undefined {
  const msg = parseRpcLine(line);
  if (!msg || msg.method !== "tools/call") return undefined;
  const idKey = rpcIdKey(msg.id);
  if (idKey === undefined) return undefined;
  const params = msg.params;
  if (!params || typeof params !== "object") return undefined;
  const name = (params as Record<string, unknown>).name;
  if (typeof name !== "string") return undefined;
  return { idKey, name, arguments: (params as Record<string, unknown>).arguments };
}

/** The text a `tools/call` RESULT carries, flattened — content blocks of type
 * text plus any `structuredContent`, for the injection scan. */
export function toolResultTextFromLine(line: string): { idKey: string; text: string; isError: boolean } | undefined {
  const msg = parseRpcLine(line);
  if (!msg) return undefined;
  const idKey = rpcIdKey(msg.id);
  if (idKey === undefined) return undefined;
  if (msg.error && typeof msg.error === "object") {
    const message = (msg.error as Record<string, unknown>).message;
    return { idKey, text: typeof message === "string" ? message : "", isError: true };
  }
  const result = msg.result;
  if (!result || typeof result !== "object") return undefined;
  const r = result as Record<string, unknown>;
  const parts: string[] = [];
  if (Array.isArray(r.content)) {
    for (const block of r.content) {
      if (!block || typeof block !== "object") continue;
      const b = block as Record<string, unknown>;
      if (b.type === "text" && typeof b.text === "string") parts.push(b.text);
      // Resource blocks carry fetched documents — exactly where an injection lives.
      const resource = b.resource as Record<string, unknown> | undefined;
      if (resource && typeof resource.text === "string") parts.push(resource.text);
    }
  }
  if (r.structuredContent !== undefined) {
    const s = safeStringify(r.structuredContent);
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

/** A JSON-RPC error response the gateway sends INSTEAD of forwarding a call it
 * refused — the client sees a failed tool call with a reason, never a hang. */
export function refusalLine(id: unknown, message: string): string {
  return `${JSON.stringify({ jsonrpc: "2.0", id, error: { code: -32001, message } })}\n`;
}

export function safeStringify(value: unknown): string | undefined {
  try {
    return JSON.stringify(value).slice(0, 8_000);
  } catch {
    return undefined;
  }
}
