import { styles, visibleLength, type ColorDepth, type Styles } from "./output.js";

/**
 * The CLI's visual language: colour roles, status glyphs, section headings,
 * aligned key/value blocks, tables that fit the terminal, and the "next thing
 * to do" line. One `Ui` per output stream (stdout and stderr can differ).
 *
 * Three rules decide what a stream gets (`termInfo`):
 *
 * - Decoration (colour, glyphs, the art, card frames) only on a terminal,
 *   with `NO_COLOR` unset or empty and `TERM` not `dumb`. Anything else is
 *   plain text: the same words and the same columns, nothing that breaks
 *   `grep` or `awk`. Glyphs only ever repeat what the words say.
 * - ASCII instead of Unicode with `DOORMAN_ASCII=1` (any output, piped too),
 *   and on a terminal that may not render Unicode: the Linux console, a
 *   locale that isn't UTF-8, and Windows outside a terminal known to render
 *   it (Windows Terminal, VS Code, ConEmu, mintty / MSYS). `DOORMAN_ASCII=0`
 *   forces Unicode. ASCII means ASCII glyphs and frames, and every other
 *   character Doorman itself writes (· — … → and the like, `toAscii`) in its
 *   ASCII form; `--json` stays as it is. The art is ASCII always.
 * - Fitting (truncating table cells, wrapping long values) only on a
 *   terminal, to its width (`COLUMNS` when the terminal doesn't say), read
 *   afresh on every access so a resized window gets the new width. Piped
 *   output keeps every character, whatever a caller asks (`truncate` is then
 *   a no-op). In-place redraws (progress, the watch countdown) also need a
 *   terminal that isn't `dumb`.
 */

export interface TermInfo {
  color: ColorDepth;
  /** Colour, glyphs, frames and art. */
  decorate: boolean;
  /** Text goes out in ASCII (`toAscii`). */
  ascii: boolean;
  /** Unicode glyphs and frames (only with `decorate`, never with `ascii`). */
  unicode: boolean;
  /** Columns to fit to; undefined when the stream is not a terminal. Read
   * from the stream on every access, so it follows a resized window. */
  readonly width: number | undefined;
  /** Lines may be redrawn in place. */
  live: boolean;
}

export interface UiStream {
  isTTY?: boolean;
  columns?: number;
}

export function termInfo(stream: UiStream, env: NodeJS.ProcessEnv, platform: NodeJS.Platform): TermInfo {
  const tty = stream.isTTY === true;
  const dumb = env.TERM === "dumb";
  const decorate = tty && !dumb && (env.NO_COLOR === undefined || env.NO_COLOR === "");
  const envColumns = Number.parseInt(env.COLUMNS ?? "", 10);
  const forced = asciiSetting(env);
  const ascii = forced ?? (tty && asciiTerminal(env, platform));
  return {
    color: decorate ? colorDepth(env) : "none",
    decorate,
    ascii,
    unicode: decorate && !ascii,
    // A getter: Node updates a TTY stream's `columns` on SIGWINCH.
    get width() {
      if (!tty) return undefined;
      const columns = stream.columns !== undefined && stream.columns > 0 ? stream.columns : envColumns;
      return Number.isFinite(columns) && columns > 0 ? columns : 80;
    },
    live: tty && !dumb,
  };
}

/** `DOORMAN_ASCII`: true (1, true, yes), false (0, false, no), or unset. */
function asciiSetting(env: NodeJS.ProcessEnv): boolean | undefined {
  const value = env.DOORMAN_ASCII?.trim().toLowerCase();
  if (value === "1" || value === "true" || value === "yes") return true;
  if (value === "0" || value === "false" || value === "no") return false;
  return undefined;
}

/** A terminal that may not render Unicode: see the rules above. */
function asciiTerminal(env: NodeJS.ProcessEnv, platform: NodeJS.Platform): boolean {
  if (env.TERM === "dumb" || env.TERM === "linux") return true;
  if (platform === "win32") {
    const unicodeTerminal = !!env.WT_SESSION || !!env.TERM_PROGRAM || env.ConEmuANSI === "ON" || /xterm|cygwin|msys/i.test(env.TERM ?? "");
    return !unicodeTerminal;
  }
  const locale = env.LC_ALL || env.LC_CTYPE || env.LANG;
  return !!locale && !/utf-?8/i.test(locale);
}

/** The ASCII form of each non-ASCII character Doorman's own text uses
 * (its messages, the app's shared wording, the Unicode glyphs). */
const ASCII_FORMS: Record<string, string> = {
  "·": "|",
  "—": "-",
  "–": "-",
  "−": "-",
  "…": "...",
  "→": "->",
  "⇢": "->",
  "←": "<-",
  "×": "x",
  "≤": "<=",
  "≥": ">=",
  "±": "+/-",
  "⌘": "Cmd",
  "‘": "'",
  "’": "'",
  "“": '"',
  "”": '"',
  "✓": "+",
  "✗": "x",
  "•": "-",
  "○": "o",
  "◆": "*",
  "─": "-",
  "│": "|",
  "╭": "+",
  "╰": "+",
  "└": "+",
  "█": "#",
  "░": "-",
};

const NON_ASCII_FORMS = new RegExp(`[${Object.keys(ASCII_FORMS).join("")}\\u2800-\\u28ff]`, "g");

/** Text with every character in `ASCII_FORMS` (and the braille spinner)
 * replaced by its ASCII form. Anything else, like a non-ASCII name in a
 * transcript, is the person's own data and stays. */
export function toAscii(text: string): string {
  return text.replace(NON_ASCII_FORMS, (ch) => ASCII_FORMS[ch] ?? "-");
}

function colorDepth(env: NodeJS.ProcessEnv): ColorDepth {
  const colorterm = (env.COLORTERM ?? "").toLowerCase();
  if (colorterm === "truecolor" || colorterm === "24bit" || env.WT_SESSION) return "truecolor";
  if (/256/.test(env.TERM ?? "")) return "256";
  return "basic";
}

/** What a status glyph says. Words always say it too. */
export type Tone = "ok" | "warn" | "error" | "info" | "off" | "held";

interface GlyphSet {
  tone: Record<Tone, string>;
  next: string;
  sep: string;
  ellipsis: string;
  /** Card frame: top-left, side, bottom-left, horizontal. */
  frame: { top: string; side: string; bottom: string; line: string };
  bar: { full: string; empty: string };
  spinner: readonly string[];
}

const UNICODE: GlyphSet = {
  tone: { ok: "✓", warn: "!", error: "✗", info: "•", off: "○", held: "◆" },
  next: "→",
  sep: "·",
  ellipsis: "…",
  frame: { top: "╭", side: "│", bottom: "╰", line: "─" },
  bar: { full: "█", empty: "░" },
  spinner: ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"],
};

const ASCII: GlyphSet = {
  tone: { ok: "+", warn: "!", error: "x", info: "-", off: "o", held: "*" },
  next: ">",
  sep: "|",
  ellipsis: "...",
  frame: { top: "+", side: "|", bottom: "+", line: "-" },
  bar: { full: "#", empty: "-" },
  spinner: ["|", "/", "-", "\\"],
};

const SGR = /\u001b\[[0-9;]*m/y;

export type KvRow = readonly [key: string, value: string] | undefined | false;

export interface TableOptions {
  /** Spaces before every line. */
  indent?: number;
  /** Columns never cut: ids and names a command takes back, short counts.
   * A table that can't fit without cutting them prints as records. */
  keep?: readonly number[];
  /** Low-value columns (sightings, last seen), left out in this order
   * before any other is cut short; records leave them out too. */
  drop?: readonly number[];
}

/** No cut column is narrower than this (or its header): the table turns
 * into records instead. */
const MIN_CUT = 20;
/** Below this many columns a table that needs cutting prints as records. */
const NARROW = 70;

export class Ui {
  readonly style: Styles;
  readonly glyphs: GlyphSet;

  constructor(readonly term: TermInfo) {
    this.style = styles(term.color);
    this.glyphs = term.unicode ? UNICODE : ASCII;
  }

  static for(stream: UiStream, env: NodeJS.ProcessEnv, platform: NodeJS.Platform): Ui {
    return new Ui(termInfo(stream, env, platform));
  }

  get decorate(): boolean {
    return this.term.decorate;
  }

  /** The width to fit to; undefined = don't fit (piped output). */
  get width(): number | undefined {
    return this.term.width;
  }

  /** Text in its tone's colour. */
  paint(tone: Tone, text: string): string {
    const s = this.style;
    if (tone === "ok") return s.ok(text);
    if (tone === "warn" || tone === "held") return s.warn(text);
    if (tone === "error") return s.error(text);
    if (tone === "info") return s.cyan(text);
    return s.dim(text);
  }

  /** The tone's glyph, coloured, then the text; just the text when plain. */
  mark(tone: Tone, text: string): string {
    return this.decorate ? `${this.paint(tone, this.glyphs.tone[tone])} ${text}` : text;
  }

  /** A section heading. */
  section(title: string, aside?: string): string {
    const s = this.style;
    return `${s.bold(s.accent(title))}${aside ? `  ${s.dim(aside)}` : ""}`;
  }

  /** A command to type: coloured on a terminal, in backticks when plain. */
  code(command: string): string {
    return this.decorate ? this.style.accent(command) : `\`${command}\``;
  }

  /** Prose whose `backticked` commands are coloured on a terminal (the
   * backticks then go); unchanged when plain. */
  prose(text: string): string {
    return this.decorate ? text.replace(/`([^`\n]+)`/g, (_, c: string) => this.style.accent(c)) : text;
  }

  /** The one next thing to do. */
  next(text: string): string {
    return this.decorate ? `${this.style.accent(this.glyphs.next)} ${this.prose(text)}` : `Next: ${text}`;
  }

  /** Short facts on one line: a dim dot between them on a terminal (a bar
   * in ASCII), commas when plain. */
  list(items: readonly string[]): string {
    return items.join(this.decorate ? ` ${this.style.dim(this.glyphs.sep)} ` : ", ");
  }

  /**
   * Keys left (dim on a terminal, unless `plainKeys`: the caller styled
   * them), values aligned after the widest key (or `keyWidth`). On a
   * terminal a value too long for the line (`width`, default the
   * terminal's) wraps under itself rather than under the key; when the keys
   * leave it under 20 columns, it goes on the lines below its key instead.
   */
  kv(rows: readonly KvRow[], options: { indent?: number; plainKeys?: boolean; keyWidth?: number; width?: number } = {}): string[] {
    const shown = rows.filter((r): r is readonly [string, string] => !!r);
    const indent = " ".repeat(options.indent ?? 2);
    const keyWidth = Math.max(options.keyWidth ?? 0, ...shown.map(([k]) => visibleLength(k)));
    const width = this.width === undefined ? undefined : (options.width ?? this.width);
    const out: string[] = [];
    for (const [key, value] of shown) {
      const head = `${indent}${this.decorate && !options.plainKeys ? this.style.dim(key) : key}${" ".repeat(keyWidth - visibleLength(key))}  `;
      const room = width === undefined ? undefined : width - visibleLength(head);
      if (width !== undefined && room! < 20 && visibleLength(value) > room!) {
        const hang = `${indent}    `;
        out.push(...(head.trim() ? [head.trimEnd()] : []), ...this.wrap(value, Math.max(20, width - hang.length)).map((l) => `${hang}${l}`));
        continue;
      }
      const lines = room !== undefined ? this.wrap(value, room) : [value];
      out.push(`${head}${lines[0] ?? ""}`.trimEnd());
      for (const more of lines.slice(1)) out.push(`${" ".repeat(visibleLength(head))}${more}`);
    }
    return out;
  }

  /**
   * Columns padded to the widest cell (colour codes don't count), two spaces
   * apart, the header dim on a terminal. Piped, nothing is cut or left out.
   * On a terminal that is too narrow: the `drop` columns go first, in order
   * and only while the table doesn't fit; then the columns not
   * in `keep` are cut to one common width, the widest first, with an
   * ellipsis. When that would leave a cut column under 20 columns (or its
   * header), the terminal is under 70 columns, or the kept ones alone don't
   * fit, each row prints as a record
   * instead: its first and kept cells on one line (labelled by header), the
   * rest wrapped under it, nothing cut.
   */
  table(header: readonly string[], rows: readonly (readonly string[])[], options: TableOptions = {}): string[] {
    const indent = options.indent ?? 0;
    const natural = header.map((h, i) => Math.max(visibleLength(h), ...rows.map((r) => visibleLength(r[i] ?? ""))));
    const all = header.map((_, i) => i);
    const width = this.width;
    if (width === undefined) return this.grid(header, rows, all, natural, indent);
    const keep = new Set(options.keep ?? []);
    const drop = (options.drop ?? []).filter((i) => i >= 0 && i < header.length);
    // The width every cut column may take with these columns shown:
    // Infinity = nothing is cut, undefined = it doesn't fit as a table.
    const capFor = (shown: readonly number[]): number | undefined => {
      const cut = shown.filter((i) => !keep.has(i));
      const fixed = indent + 2 * (shown.length - 1) + shown.reduce((a, i) => a + (keep.has(i) ? natural[i]! : 0), 0);
      const total = (cap: number) => fixed + cut.reduce((a, i) => a + Math.min(natural[i]!, cap), 0);
      if (total(Infinity) <= width) return Infinity;
      let cap = Math.max(0, ...cut.map((i) => natural[i]!));
      while (cap > 0 && total(cap) > width) cap--;
      return cut.every((i) => natural[i]! <= cap || cap >= Math.max(MIN_CUT, visibleLength(header[i]!))) ? cap : undefined;
    };
    let shown = all;
    let cap = capFor(shown);
    for (const gone of drop) {
      if (cap === Infinity) break;
      shown = shown.filter((i) => i !== gone);
      cap = capFor(shown);
    }
    if (cap === undefined || (cap !== Infinity && width < NARROW)) return this.records(header, rows, all.filter((i) => !drop.includes(i)), keep, indent, width);
    const widths = natural.map((n, i) => (keep.has(i) ? n : Math.min(n, cap)));
    return this.grid(header, rows, shown, widths, indent);
  }

  /** The `shown` columns, each cell cut to its width. */
  private grid(header: readonly string[], rows: readonly (readonly string[])[], shown: readonly number[], widths: readonly number[], indent: number): string[] {
    const pad = " ".repeat(indent);
    const line = (cells: readonly string[]) =>
      pad +
      shown
        .map((i, k) => {
          const c = cells[i] ?? "";
          const cell = visibleLength(c) > widths[i]! ? this.truncate(c, widths[i]!) : c;
          return k === shown.length - 1 ? cell : cell + " ".repeat(Math.max(0, widths[i]! - visibleLength(cell)));
        })
        .join("  ")
        .trimEnd();
    const head = line(header);
    return [this.decorate ? this.style.dim(head) : head, ...rows.map(line)];
  }

  /** A table too wide for the terminal, a row at a time: the first and kept
   * cells on a line (the kept ones labelled by their header, broken between
   * cells), then the other cells in a list wrapped under it. */
  private records(header: readonly string[], rows: readonly (readonly string[])[], shown: readonly number[], keep: ReadonlySet<number>, indent: number, width: number): string[] {
    const pad = " ".repeat(indent);
    const [first, ...others] = shown;
    if (first === undefined) return [];
    const out: string[] = [];
    for (const row of rows) {
      const cell = (i: number) => row[i] ?? "";
      const labelled = (i: number) => (/[a-z]/i.test(header[i]!) ? `${this.style.dim(header[i]!.toLowerCase())} ${cell(i)}` : cell(i));
      const heads = [cell(first), ...others.filter((i) => keep.has(i) && visibleLength(cell(i)) > 0).map(labelled)];
      const lines: string[] = [];
      for (const item of heads) {
        const last = lines.length - 1;
        if (last >= 0 && visibleLength(lines[last]!) + 2 + visibleLength(item) <= width - indent - (last > 0 ? 4 : 0)) lines[last] += `  ${item}`;
        else lines.push(item);
      }
      out.push(...lines.map((l, k) => `${pad}${k > 0 ? "    " : ""}${l}`));
      const rest = others.filter((i) => !keep.has(i)).map(cell).filter((c) => visibleLength(c) > 0);
      if (rest.length > 0) out.push(...this.wrap(this.list(rest), Math.max(20, width - indent - 2)).map((l) => `${pad}  ${l}`));
    }
    return out;
  }

  /** Cut to `width` columns, ending in an ellipsis; colour codes kept and
   * closed. Unchanged when piped: piped output keeps every character. */
  truncate(text: string, width: number): string {
    if (this.width === undefined || visibleLength(text) <= width) return text;
    const ellipsis = this.glyphs.ellipsis;
    const room = Math.max(0, width - ellipsis.length);
    let out = "";
    let seen = 0;
    let coloured = false;
    for (let i = 0; i < text.length; ) {
      SGR.lastIndex = i;
      const esc = SGR.exec(text);
      if (esc) {
        out += esc[0];
        coloured = true;
        i += esc[0].length;
        continue;
      }
      const ch = String.fromCodePoint(text.codePointAt(i)!);
      if (seen >= room) break;
      out += ch;
      seen += 1;
      i += ch.length;
    }
    return `${out}${ellipsis}${coloured ? "\u001b[0m" : ""}`;
  }

  /** A line cut to the terminal's width; unchanged when piped. */
  fit(line: string): string {
    return this.width === undefined ? line : this.truncate(line, this.width);
  }

  /** Word-wrap to `width` columns (colour codes don't count). A word longer
   * than the line, like a path or URL, breaks only after a `/` or `\`; a
   * piece with no separator to break at stays whole and runs over. */
  wrap(text: string, width: number): string[] {
    if (visibleLength(text) <= width) return [text];
    const lines: string[] = [];
    let line = "";
    const put = (piece: string, glue: string) => {
      if (!line) line = piece;
      else if (visibleLength(line) + glue.length + visibleLength(piece) <= width) line += `${glue}${piece}`;
      else {
        lines.push(line);
        line = piece;
      }
    };
    for (const word of text.split(" ")) {
      if (visibleLength(word) <= width) put(word, " ");
      else word.split(/(?<=[/\\])/).forEach((piece, i) => put(piece, i === 0 ? " " : ""));
    }
    if (line) lines.push(line);
    return lines;
  }

  /** A filled bar `cells` wide for a fraction 0..1, coloured by tone. */
  bar(fraction: number, cells: number, tone: Tone = "ok"): string {
    const full = Math.round(Math.min(1, Math.max(0, fraction)) * cells);
    return `${this.paint(tone, this.glyphs.bar.full.repeat(full))}${this.style.dim(this.glyphs.bar.empty.repeat(cells - full))}`;
  }
}

/** `n thing` / `n things`. */
export function plural(n: number, word: string, many = `${word}s`): string {
  return `${n} ${n === 1 ? word : many}`;
}
