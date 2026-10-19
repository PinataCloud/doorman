/**
 * JSON with comments — read it, and EDIT it without losing a byte the person
 * wrote.
 *
 * Several agents' own settings files are legally commented: Gemini CLI and
 * Qwen Code strip `//` and `/* *\/` before `JSON.parse`, Factory Droid reads
 * JSONC, OpenClaw falls back to JSON5. Their descriptors (hosts/gemini.ts,
 * hosts/claude-family.ts, hosts/openclaw.ts) keep their object-level merge and
 * hand the result here; `editJsonc` turns the difference between the document
 * and that object into minimal splices — a changed value is replaced in place,
 * a new property or element is inserted before the closing bracket in the
 * container's own indentation and comma style, a removed one is cut out with
 * its comma — so comments, formatting and key order stay byte-identical.
 *
 * Lives under main/guard/ because the descriptors run inside the copied guard
 * bundle (enforcement.ts GUARD_FILES), which imports nothing outside this
 * directory. The app side shares the same scanner: the setup doctor
 * (lib/doctor.ts `repairJsonText`) strips comments from `~/.claude/settings.json`
 * as DAMAGE — Claude Code's parser is strict — while the VS Code reader
 * (lib/vscode.ts) strips them to READ values from a file whose comments are
 * normal and never writes it back. `stripJsonc` only ever produces a string to
 * hand `JSON.parse` and a list of what it removed; what that means is the
 * caller's judgement.
 *
 * Pure: text in, text out. No dependencies.
 */

// ---------------------------------------------------------------------------
// The scanner — shared by the stripper, the parser and the editor
// ---------------------------------------------------------------------------

/** Index just past the string literal opening at `i`. Greater than
 * `text.length` when the literal is unterminated. */
function stringEnd(text: string, i: number, quote: string): number {
  let j = i + 1;
  while (j < text.length && text[j] !== quote) {
    if (text[j] === "\\") j++;
    j++;
  }
  return j + 1;
}

/** Index just past the comment opening at `i`, or -1 when none opens there. A
 * line comment ends AT its newline (the newline is not part of it); an
 * unterminated block comment returns `text.length + 1`. */
function commentEnd(text: string, i: number): number {
  if (text[i] !== "/") return -1;
  if (text[i + 1] === "/") {
    const end = text.indexOf("\n", i);
    return end === -1 ? text.length : end;
  }
  if (text[i + 1] === "*") {
    const end = text.indexOf("*/", i + 2);
    return end === -1 ? text.length + 1 : end + 2;
  }
  return -1;
}

const isJsonSpace = (ch: string | undefined): boolean => ch === " " || ch === "\t" || ch === "\n" || ch === "\r";
const isAnySpace = (ch: string | undefined): boolean => ch !== undefined && /\s/.test(ch);

export interface JsoncStrip {
  /** The text with comments, trailing commas and a BOM removed. */
  text: string;
  /** Human-readable list of what was removed, in discovery order. */
  changes: string[];
}

/**
 * Remove the three things that make an otherwise unambiguous document fail
 * `JSON.parse`: a byte-order mark, `//` and `/* *\/` comments, and a comma
 * whose next significant character closes its container.
 *
 * String-aware (a `//` inside a string literal survives) and total — it never
 * throws and never guesses at a truncated document; the result is simply
 * handed to `JSON.parse`, which is what decides whether the text was salvaged.
 */
export function stripJsonc(raw: string): JsoncStrip {
  const changes = new Set<string>();
  let text = raw;
  if (text.charCodeAt(0) === 0xfeff) {
    text = text.slice(1);
    changes.add("removed a byte-order mark");
  }
  let out = "";
  let i = 0;
  const n = text.length;
  while (i < n) {
    const ch = text[i]!;
    if (ch === '"') {
      const end = stringEnd(text, i, '"');
      out += text.slice(i, Math.min(end, n));
      i = end;
      continue;
    }
    const comment = commentEnd(text, i);
    if (comment !== -1) {
      i = Math.min(comment, n);
      changes.add("removed comments");
      continue;
    }
    if (ch === ",") {
      // Look past whitespace and comments for a closing bracket.
      let j = i + 1;
      for (;;) {
        while (j < n && isAnySpace(text[j])) j++;
        const end = commentEnd(text, j);
        if (end === -1) break;
        j = Math.min(end, n);
      }
      if (text[j] === "}" || text[j] === "]") {
        changes.add("removed trailing commas");
        i++;
        continue;
      }
    }
    out += ch;
    i++;
  }
  return { text: out, changes: [...changes] };
}

/**
 * Parse a JSONC document into an object, tolerating the editor dialect.
 * Undefined for anything that is not a JSON object at the top level — a
 * settings file that holds an array, a number or nothing readable is not a
 * settings file, and a caller reading keys out of it would be guessing.
 */
export function parseJsonc(text: string | undefined): Record<string, unknown> | undefined {
  if (text === undefined || text.trim() === "") return undefined;
  const attempt = (raw: string): Record<string, unknown> | undefined => {
    try {
      const value = JSON.parse(raw);
      return value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : undefined;
    } catch {
      return undefined;
    }
  };
  return attempt(text) ?? attempt(stripJsonc(text).text);
}

// ---------------------------------------------------------------------------
// The position-aware parser
// ---------------------------------------------------------------------------

/**
 * What a host's own parser accepts beyond strict JSON. Comments and a leading
 * byte-order mark are always accepted.
 */
export interface JsoncDialect {
  /** A comma before `}` / `]` is fine (Factory Droid, OpenClaw). Gemini CLI
   * and Qwen Code strip comments and then `JSON.parse`, so for them it is
   * fatal — and a document the host can't read is not one we edit. */
  trailingCommas: boolean;
  /** The host also reads JSON5 (OpenClaw). JSON5-only syntax — unquoted keys,
   * single quotes, hex numbers… — is still refused, but by name, so the person
   * learns why rather than being told their working config is broken. */
  json5?: boolean;
}

/** A document its dialect can't read. `json5` lists the JSON5-only syntax that
 * made it unreadable, when that is the only reason. */
export class JsoncSyntaxError extends Error {
  constructor(
    readonly reason: string,
    readonly line: number,
    readonly json5?: readonly string[],
  ) {
    super(`line ${line}: ${reason}`);
    this.name = "JsoncSyntaxError";
  }
}

interface Span {
  /** Offset of the first character. */
  start: number;
  /** Offset just past the last character. */
  end: number;
}

interface ScalarNode extends Span {
  kind: "scalar";
  value: unknown;
}

interface Member extends Span {
  /** For a property, `start` is the key's first character. */
  node: Node;
  /** Offset of the comma after this member, or -1. */
  comma: number;
}

interface Property extends Member {
  key: string;
  keyEnd: number;
}

interface ObjectNode extends Span {
  kind: "object";
  value: Record<string, unknown>;
  members: Property[];
  /** A comment sits BETWEEN members (not inside one). */
  comments: boolean;
}

interface ArrayNode extends Span {
  kind: "array";
  value: unknown[];
  members: Member[];
  comments: boolean;
}

type Node = ScalarNode | ObjectNode | ArrayNode;

const JSON_NUMBER = /^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?$/;
const JSON5_NUMBER = /^[+-]?(?:Infinity|NaN|0[xX][0-9a-fA-F]+|(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?)$/;
const WORD = /[^\s{}[\]:,"'/]+/y;
const IDENTIFIER = /[A-Za-z_$][\w$]*/y;

function lineOf(text: string, at: number): number {
  let line = 1;
  for (let k = 0; k < at && k < text.length; k++) if (text[k] === "\n") line++;
  return line;
}

/** Own-property assignment with `JSON.parse`'s semantics — a `__proto__` key
 * is a key, and a duplicate keeps its first position with the last value. */
function define(target: Record<string, unknown>, key: string, value: unknown): void {
  Object.defineProperty(target, key, { value, writable: true, enumerable: true, configurable: true });
}

/**
 * The document as a tree of spans. `json5` switches the parser into a
 * RECOGNISER for JSON5-only syntax (values are then meaningless; only
 * `features` is read).
 */
function parseTree(text: string, dialect: JsoncDialect, json5: boolean): { root: Node; features: Set<string> } {
  const n = text.length;
  const features = new Set<string>();
  let i = text.charCodeAt(0) === 0xfeff ? 1 : 0;
  const isSpace = json5 ? isAnySpace : isJsonSpace;

  const fail = (reason: string, at = i): never => {
    throw new JsoncSyntaxError(at >= n ? "unexpected end of document" : reason, lineOf(text, at));
  };
  /** Skip whitespace and comments; whether a comment was skipped. */
  const trivia = (): boolean => {
    let saw = false;
    for (;;) {
      while (i < n && isSpace(text[i])) i++;
      const end = commentEnd(text, i);
      if (end === -1) return saw;
      if (end > n) fail("unterminated comment");
      i = end;
      saw = true;
    }
  };
  const string = (): string => {
    const quote = text[i]!;
    const end = stringEnd(text, i, quote);
    if (end > n) fail("unterminated string");
    const raw = text.slice(i, end);
    const at = i;
    i = end;
    if (quote === "'") {
      features.add("single-quoted strings");
      return raw.slice(1, -1);
    }
    try {
      return JSON.parse(raw) as string;
    } catch {
      if (json5) {
        features.add("JSON5 string escapes");
        return raw.slice(1, -1);
      }
      return fail("invalid string", at);
    }
  };
  const value = (): Node => {
    const ch = text[i];
    if (ch === "{") return object();
    if (ch === "[") return array();
    const start = i;
    if (ch === '"' || (json5 && ch === "'")) {
      const literal = string();
      return { kind: "scalar", start, end: i, value: literal };
    }
    WORD.lastIndex = i;
    const word = WORD.exec(text)?.[0];
    if (!word) return fail(ch === "'" ? "single-quoted string" : `unexpected "${ch ?? ""}"`);
    i += word.length;
    if (word === "true" || word === "false" || word === "null") return { kind: "scalar", start, end: i, value: JSON.parse(word) };
    if (JSON_NUMBER.test(word)) return { kind: "scalar", start, end: i, value: Number(word) };
    if (json5 && JSON5_NUMBER.test(word)) {
      features.add("JSON5 numbers");
      return { kind: "scalar", start, end: i, value: 0 };
    }
    return fail(`unexpected "${word}"`, start);
  };
  const object = (): ObjectNode => {
    const node: ObjectNode = { kind: "object", start: i, end: i, value: {}, members: [], comments: false };
    i++;
    if (trivia()) node.comments = true;
    if (text[i] === "}") {
      i++;
      node.end = i;
      return node;
    }
    for (;;) {
      const keyStart = i;
      let key: string;
      if (text[i] === '"' || (json5 && text[i] === "'")) key = string();
      else {
        IDENTIFIER.lastIndex = i;
        const id = json5 ? IDENTIFIER.exec(text)?.[0] : undefined;
        if (id === undefined) return fail("expected a property name in double quotes");
        features.add("unquoted keys");
        key = id;
        i += id.length;
      }
      const keyEnd = i;
      trivia();
      if (text[i] !== ":") return fail("expected ':' after a property name");
      i++;
      trivia();
      const child = value();
      const member: Property = { key, keyEnd, start: keyStart, end: child.end, node: child, comma: -1 };
      node.members.push(member);
      define(node.value, key, child.value);
      if (trivia()) node.comments = true;
      if (text[i] === ",") {
        member.comma = i;
        i++;
        if (trivia()) node.comments = true;
        if (text[i] === "}") {
          if (!dialect.trailingCommas && !json5) fail("trailing comma", member.comma);
          i++;
          break;
        }
        continue;
      }
      if (text[i] === "}") {
        i++;
        break;
      }
      return fail("expected ',' or '}'");
    }
    node.end = i;
    return node;
  };
  const array = (): ArrayNode => {
    const node: ArrayNode = { kind: "array", start: i, end: i, value: [], members: [], comments: false };
    i++;
    if (trivia()) node.comments = true;
    if (text[i] === "]") {
      i++;
      node.end = i;
      return node;
    }
    for (;;) {
      const child = value();
      const member: Member = { start: child.start, end: child.end, node: child, comma: -1 };
      node.members.push(member);
      node.value.push(child.value);
      if (trivia()) node.comments = true;
      if (text[i] === ",") {
        member.comma = i;
        i++;
        if (trivia()) node.comments = true;
        if (text[i] === "]") {
          if (!dialect.trailingCommas && !json5) fail("trailing comma", member.comma);
          i++;
          break;
        }
        continue;
      }
      if (text[i] === "]") {
        i++;
        break;
      }
      return fail("expected ',' or ']'");
    }
    node.end = i;
    return node;
  };

  trivia();
  if (i >= n) fail("empty document");
  const root = value();
  trivia();
  if (i < n) fail("unexpected text after the document");
  return { root, features };
}

function parseDocument(text: string, dialect: JsoncDialect): Node {
  try {
    return parseTree(text, dialect, false).root;
  } catch (err) {
    if (dialect.json5 && err instanceof JsoncSyntaxError) {
      let features: Set<string> | undefined;
      try {
        features = parseTree(text, dialect, true).features;
      } catch {
        // not JSON5 either — the plain error stands
      }
      if (features && features.size > 0) throw new JsoncSyntaxError("JSON5 syntax", err.line, [...features]);
    }
    throw err;
  }
}

/** The value of a document in `dialect`. Throws JsoncSyntaxError. */
export function readJsonc(text: string, dialect: JsoncDialect): unknown {
  return parseDocument(text, dialect).value;
}

// ---------------------------------------------------------------------------
// The editor
// ---------------------------------------------------------------------------

interface Edit {
  start: number;
  end: number;
  text: string;
}

interface EditContext {
  text: string;
  edits: Edit[];
  eol: string;
  /** One level of indentation, as the document spells it. */
  unit: string;
}

/** Renders one new member at `indent`; `multiline` false = the compact form an
 * inline container already uses. */
type Item = (indent: string, multiline: boolean) => string;

const hasOwn = (o: object, k: string): boolean => Object.prototype.hasOwnProperty.call(o, k);

const isPlainObject = (v: unknown): v is Record<string, unknown> =>
  typeof v === "object" && v !== null && !Array.isArray(v);

function jsonEqual(a: unknown, b: unknown): boolean {
  if (a === b) return true;
  if (typeof a !== "object" || typeof b !== "object" || a === null || b === null) return false;
  if (Array.isArray(a) || Array.isArray(b)) {
    if (!Array.isArray(a) || !Array.isArray(b) || a.length !== b.length) return false;
    return a.every((v, k) => jsonEqual(v, b[k]));
  }
  const ka = Object.keys(a);
  const rb = b as Record<string, unknown>;
  if (ka.length !== Object.keys(rb).length) return false;
  return ka.every((k) => hasOwn(rb, k) && jsonEqual((a as Record<string, unknown>)[k], rb[k]));
}

function lineStart(text: string, pos: number): number {
  return text.lastIndexOf("\n", pos - 1) + 1;
}

function lineIndent(text: string, pos: number): string {
  const from = lineStart(text, pos);
  let to = from;
  while (text[to] === " " || text[to] === "\t") to++;
  return text.slice(from, to);
}

/** Nothing but indentation before `pos` on its line. */
function onOwnLine(text: string, pos: number): boolean {
  return /^[ \t]*$/.test(text.slice(lineStart(text, pos), pos));
}

function serialize(ctx: EditContext, value: unknown, indent: string): string {
  return JSON.stringify(value, null, ctx.unit).split("\n").join(`${ctx.eol}${indent}`);
}

function memberIndent(ctx: EditContext, node: ObjectNode | ArrayNode): string {
  const first = node.members.find((m) => onOwnLine(ctx.text, m.start));
  return first ? lineIndent(ctx.text, first.start) : `${lineIndent(ctx.text, node.start)}${ctx.unit}`;
}

function closeIndent(ctx: EditContext, node: ObjectNode | ArrayNode): string {
  const close = node.end - 1;
  return onOwnLine(ctx.text, close) ? lineIndent(ctx.text, close) : lineIndent(ctx.text, node.start);
}

function indentUnit(text: string, root: Node): string {
  if (root.kind === "scalar") return "  ";
  const first = root.members.find((m) => onOwnLine(text, m.start));
  if (!first) return "  ";
  const base = lineIndent(text, root.start);
  const own = lineIndent(text, first.start);
  return own.startsWith(base) && own.length > base.length ? own.slice(base.length) : "  ";
}

/** Where to append after the last kept member of a multi-line container: past
 * its comma and any comment that finishes its line, before the line break —
 * a trailing `// note` stays with the member it annotates. */
function lineTail(text: string, member: Member): number {
  let best = member.comma >= 0 ? member.comma + 1 : member.end;
  let i = best;
  for (;;) {
    while (text[i] === " " || text[i] === "\t") i++;
    const end = commentEnd(text, i);
    if (end === -1 || end > text.length) return best;
    if (text[i + 1] === "/") return text[end - 1] === "\r" ? end - 1 : end;
    if (text.slice(i, end).includes("\n")) return best;
    best = i = end;
  }
}

/** The range that cuts member `idx` out with its comma; a member alone on its
 * line takes the line with it. */
function cutRange(ctx: EditContext, node: ObjectNode | ArrayNode, idx: number, multiline: boolean, deleted: ReadonlySet<number>): [number, number] {
  const { text } = ctx;
  const m = node.members[idx]!;
  const s = m.start;
  const e = m.comma >= 0 ? m.comma + 1 : m.end;
  let t = e;
  while (text[t] === " " || text[t] === "\t") t++;
  if (multiline && onOwnLine(text, s)) {
    if (t >= text.length) return [lineStart(text, s), t];
    if (text[t] === "\n") return [lineStart(text, s), t + 1];
    if (text[t] === "\r" && text[t + 1] === "\n") return [lineStart(text, s), t + 2];
    return [s, t];
  }
  if (m.comma < 0 && idx > 0 && !deleted.has(idx - 1)) {
    // The final member, sharing its line with a kept predecessor: the spaces
    // before it go too (the predecessor's comma is taken out separately). A
    // deleted predecessor's own cut already took them.
    let b = s;
    while (b > node.start + 1 && (text[b - 1] === " " || text[b - 1] === "\t")) b--;
    return [b, e];
  }
  return [s, t];
}

/**
 * Cut the `deleted` members out of a container and add `inserts` (each before
 * old member `before`, or at the end when `before` is the member count), fixing
 * the commas so the result has exactly the commas it needs — plus a trailing
 * one when the container already wrote one.
 */
function splice(
  ctx: EditContext,
  node: ObjectNode | ArrayNode,
  deleted: ReadonlySet<number>,
  inserts: readonly { before: number; items: Item[] }[],
): void {
  const { text, eol, edits } = ctx;
  const members: readonly Member[] = node.members;
  const count = members.length;
  const inserted = inserts.reduce((sum, x) => sum + x.items.length, 0);
  if (deleted.size === 0 && inserted === 0) return;
  const multiline = count === 0 || text.slice(node.start, node.end).includes("\n");
  const kept = members.map((_, k) => k).filter((k) => !deleted.has(k));
  const trailing = count > 0 && members[count - 1]!.comma >= 0;
  const indent = memberIndent(ctx, node);
  const render = (items: readonly Item[]): string[] => items.map((f) => (multiline ? f(indent, true) : f("", false)));

  if (kept.length === 0 && !node.comments) {
    // Nothing of the old content survives, not even a comment: write the
    // inside afresh, the way JSON.stringify lays it out.
    const all = render([...inserts].sort((a, b) => a.before - b.before).flatMap((x) => x.items));
    const inner =
      all.length === 0 ? "" : multiline ? `${all.map((t) => `${eol}${indent}${t}`).join(",")}${eol}${closeIndent(ctx, node)}` : all.join(", ");
    edits.push({ start: node.start + 1, end: node.end - 1, text: inner });
    return;
  }

  for (const k of deleted) {
    const [start, end] = cutRange(ctx, node, k, multiline, deleted);
    edits.push({ start, end, text: "" });
  }

  const atEnd = inserts.filter((x) => x.before >= count).flatMap((x) => x.items);
  const last = kept.length > 0 ? members[kept[kept.length - 1]!]! : undefined;
  if (last) {
    if (atEnd.length > 0) {
      if (last.comma < 0) edits.push({ start: last.end, end: last.end, text: "," });
    } else if (last.comma >= 0 && !trailing) {
      // It was followed by something that is gone; JSON (unlike the dialects
      // that allow it) has no comma before a closing bracket.
      edits.push({ start: last.comma, end: last.comma + 1, text: "" });
    }
  }

  for (const x of inserts) {
    if (x.before >= count || x.items.length === 0) continue;
    const anchor = members[x.before]!;
    const own = multiline && onOwnLine(text, anchor.start);
    const at = own ? lineStart(text, anchor.start) : anchor.start;
    const body = render(x.items)
      .map((t) => (own ? `${indent}${t},${eol}` : `${t}, `))
      .join("");
    edits.push({ start: at, end: at, text: body });
  }

  if (atEnd.length > 0) {
    const at = last ? (multiline ? lineTail(text, last) : last.comma >= 0 ? last.comma + 1 : last.end) : node.start + 1;
    const body = render(atEnd)
      .map((t) => (multiline ? `${eol}${indent}${t}` : ` ${t}`))
      .join(",");
    edits.push({ start: at, end: at, text: `${body}${trailing ? "," : ""}` });
  }
}

function diffObject(ctx: EditContext, node: ObjectNode, want: Record<string, unknown>): void {
  const lastIndex = new Map<string, number>();
  node.members.forEach((m, k) => lastIndex.set(m.key, k));
  const deleted = new Set<number>();
  node.members.forEach((m, k) => {
    // Every copy of a removed key goes — an earlier duplicate would otherwise
    // come back to life. Of a kept key only the last (effective) copy is edited.
    if (!hasOwn(want, m.key)) deleted.add(k);
    else if (lastIndex.get(m.key) === k) diffNode(ctx, m.node, want[m.key]);
  });
  const first = node.members[0];
  const between = first ? ctx.text.slice(first.keyEnd, first.node.start) : "";
  const sep = /^[ \t]*:[ \t]*$/.test(between) ? between : ": ";
  const items: Item[] = Object.keys(want)
    .filter((k) => !lastIndex.has(k))
    .map((k) => (indent, multiline) =>
      `${JSON.stringify(k)}${sep}${multiline ? serialize(ctx, want[k], indent) : JSON.stringify(want[k])}`,
    );
  splice(ctx, node, deleted, [{ before: node.members.length, items }]);
}

function diffArray(ctx: EditContext, node: ArrayNode, want: unknown[]): void {
  const old = node.members.map((m) => m.node.value);
  const n = old.length;
  const m = want.length;
  // Longest common subsequence of equal elements; what lies between two
  // matches is edited pairwise in place, then deleted or inserted.
  const lcs: number[][] = Array.from({ length: n + 1 }, () => new Array<number>(m + 1).fill(0));
  for (let a = n - 1; a >= 0; a--) {
    for (let b = m - 1; b >= 0; b--) {
      lcs[a]![b] = jsonEqual(old[a], want[b]) ? lcs[a + 1]![b + 1]! + 1 : Math.max(lcs[a + 1]![b]!, lcs[a]![b + 1]!);
    }
  }
  const matches: [number, number][] = [];
  for (let a = 0, b = 0; a < n && b < m; ) {
    if (jsonEqual(old[a], want[b]) && lcs[a]![b] === lcs[a + 1]![b + 1]! + 1) {
      matches.push([a, b]);
      a++;
      b++;
    } else if (lcs[a + 1]![b]! >= lcs[a]![b + 1]!) a++;
    else b++;
  }
  matches.push([n, m]);
  const deleted = new Set<number>();
  const inserts: { before: number; items: Item[] }[] = [];
  let a = 0;
  let b = 0;
  for (const [ma, mb] of matches) {
    const paired = Math.min(ma - a, mb - b);
    for (let k = 0; k < paired; k++) diffNode(ctx, node.members[a + k]!.node, want[b + k]);
    for (let k = a + paired; k < ma; k++) deleted.add(k);
    const added = want.slice(b + paired, mb);
    if (added.length > 0) {
      inserts.push({
        before: ma,
        items: added.map((v) => (indent, multiline) => (multiline ? serialize(ctx, v, indent) : JSON.stringify(v))),
      });
    }
    a = ma + 1;
    b = mb + 1;
  }
  splice(ctx, node, deleted, inserts);
}

function diffNode(ctx: EditContext, node: Node, want: unknown): void {
  if (node.kind === "object" && isPlainObject(want)) return diffObject(ctx, node, want);
  if (node.kind === "array" && Array.isArray(want)) return diffArray(ctx, node, want);
  if (jsonEqual(node.value, want)) return;
  ctx.edits.push({ start: node.start, end: node.end, text: serialize(ctx, want, lineIndent(ctx.text, node.start)) });
}

function applyEdits(text: string, edits: readonly Edit[]): string {
  // At one offset, pure insertions go before a cut or replacement starting
  // there (they land in front of it); otherwise the order they were made in.
  const ordered = edits
    .map((e, k) => ({ ...e, k }))
    .sort((x, y) => x.start - y.start || Number(x.end > x.start) - Number(y.end > y.start) || x.k - y.k);
  let out = "";
  let at = 0;
  for (const e of ordered) {
    if (e.start < at) throw new Error("overlapping edits");
    out += text.slice(at, e.start) + e.text;
    at = e.end;
  }
  return out + text.slice(at);
}

/**
 * `text` rewritten so it reads as `next`, touching only what differs: every
 * byte outside a changed value — comments, blank lines, key order, the
 * person's own indentation — is kept. The same text when nothing differs.
 * Throws JsoncSyntaxError for a document `dialect` can't read, and a plain
 * Error in the (defensive) case where the edit would not read back as `next`.
 */
export function editJsonc(text: string, next: unknown, dialect: JsoncDialect): string {
  const root = parseDocument(text, dialect);
  // JSON's own view of the target: `undefined` members dropped, toJSON applied.
  const want: unknown = JSON.parse(JSON.stringify(next));
  const ctx: EditContext = {
    text,
    edits: [],
    eol: text.includes("\r\n") ? "\r\n" : "\n",
    unit: indentUnit(text, root),
  };
  diffNode(ctx, root, want);
  if (ctx.edits.length === 0) return text;
  const out = applyEdits(text, ctx.edits);
  let check: unknown;
  try {
    check = readJsonc(out, dialect);
  } catch {
    check = undefined;
  }
  if (!jsonEqual(check, want)) throw new Error("the edited document does not read back as intended");
  return out;
}

// ---------------------------------------------------------------------------
// Host documents
// ---------------------------------------------------------------------------

/** The refusal a host's merge throws for a document its dialect can't read. */
function refusal(label: string, err: unknown): Error {
  if (err instanceof JsoncSyntaxError && err.json5) {
    return new Error(`${label} uses JSON5 syntax (${err.json5.join(", ")}) the guard can't edit safely; not touching it`);
  }
  const where = err instanceof JsoncSyntaxError ? ` (${err.message})` : "";
  return new Error(`${label} is not valid JSON${where}; not touching it`);
}

/**
 * A host's hook document as a value. Strict JSON when `dialect` is absent;
 * otherwise strict JSON first (byte-for-byte today's reading of every
 * uncommented file), then the host's dialect. Throws a user-facing Error
 * naming `label` ("… not touching it") for a document the host itself can't
 * read. Callers handle the blank document before calling.
 */
export function readHostJson(docText: string, dialect: JsoncDialect | undefined, label: string): unknown {
  try {
    return JSON.parse(docText);
  } catch (err) {
    if (!dialect) throw refusal(label, err);
  }
  try {
    return readJsonc(docText, dialect);
  } catch (err) {
    throw refusal(label, err);
  }
}

/**
 * The text to write for a host document whose new value is `value`. A
 * missing, blank or strict-JSON document is written as canonical JSON (2-space,
 * trailing newline) exactly as before; a commented one is edited in place
 * (editJsonc) so every comment survives.
 */
export function writeHostJson(docText: string | undefined, value: unknown, dialect: JsoncDialect | undefined, label: string): string {
  const canonical = (): string => `${JSON.stringify(value, null, 2)}\n`;
  if (!dialect || docText === undefined || docText.trim() === "") return canonical();
  try {
    JSON.parse(docText);
    return canonical();
  } catch {
    // commented (or otherwise dialect-only): edit, don't rewrite
  }
  try {
    return editJsonc(docText, value, dialect);
  } catch (err) {
    if (err instanceof JsoncSyntaxError) throw refusal(label, err);
    throw new Error(`${label} couldn't be edited without disturbing its comments; not touching it`);
  }
}
