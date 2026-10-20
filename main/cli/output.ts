/** What a command hands back: `data` is printed as JSON under `--json`,
 * `text` (lines) otherwise. Commands stay printable and testable alike. */
export interface CommandResult {
  data: unknown;
  text: string[];
  /** Non-zero exit without an error message, e.g. "findings need review". */
  exitCode?: number;
  /** `text` is machine output (a JSON export): written byte for byte, even
   * in ASCII mode, like `--json`. */
  raw?: boolean;
}

/** A failure the person can act on: printed as one line, exit code 1 (or as given).
 * `hint` is the next thing to try, said under the message. */
export class CliError extends Error {
  constructor(
    message: string,
    readonly exitCode = 1,
    readonly hint?: string,
  ) {
    super(message);
  }
}

/** Colour roles: what a piece of text means, not which colour it is. The
 * brand hues (accent purple, pink, cyan) are for headings, commands, keys and
 * the art. */
export interface Styles {
  bold(s: string): string;
  dim(s: string): string;
  ok(s: string): string;
  warn(s: string): string;
  error(s: string): string;
  accent(s: string): string;
  pink(s: string): string;
  cyan(s: string): string;
}

/** How many colours the terminal takes: none (plain), the 16 basic ones, the
 * 256-colour palette, or 24-bit. */
export type ColorDepth = "none" | "basic" | "256" | "truecolor";

type Sgr = [open: string, close: string];

/** Brand hues per depth: Pinata purple #AE81ED, pink #FF3AB4, the mark's
 * cyan #29B8D4 (the dark-theme tokens, renderer/tokens.css). */
const BRAND: Record<"accent" | "pink" | "cyan", Record<Exclude<ColorDepth, "none">, string>> = {
  accent: { truecolor: "38;2;174;129;237", "256": "38;5;141", basic: "35" },
  pink: { truecolor: "38;2;255;58;180", "256": "38;5;205", basic: "95" },
  cyan: { truecolor: "38;2;41;184;212", "256": "38;5;38", basic: "36" },
};

/** ANSI styles at the given depth; every style is the identity at "none".
 * ok/warn/error stay the terminal's own green/yellow/red, so they follow its theme. */
export function styles(depth: ColorDepth): Styles {
  const sgr: Record<keyof Styles, Sgr> | undefined =
    depth === "none"
      ? undefined
      : {
          bold: ["1", "22"],
          dim: ["2", "22"],
          ok: ["32", "39"],
          warn: ["33", "39"],
          error: ["31", "39"],
          accent: [BRAND.accent[depth], "39"],
          pink: [BRAND.pink[depth], "39"],
          cyan: [BRAND.cyan[depth], "39"],
        };
  const wrap = (name: keyof Styles) => {
    const codes = sgr?.[name];
    return codes ? (s: string) => (s === "" ? s : `\u001b[${codes[0]}m${s}\u001b[${codes[1]}m`) : (s: string) => s;
  };
  return {
    bold: wrap("bold"),
    dim: wrap("dim"),
    ok: wrap("ok"),
    warn: wrap("warn"),
    error: wrap("error"),
    accent: wrap("accent"),
    pink: wrap("pink"),
    cyan: wrap("cyan"),
  };
}

const ANSI = /\u001b\[[0-9;]*m/g;

/** The text without its colour codes. */
export function stripAnsi(s: string): string {
  return s.replace(ANSI, "");
}

/** How many columns the text takes (colour codes take none). */
export function visibleLength(s: string): number {
  return [...stripAnsi(s)].length;
}

/** `12345` → `12.3k`, the app's compact token count. */
export function compactNumber(n: number): string {
  if (n >= 1e6) return `${(n / 1e6).toFixed(1)}M`;
  if (n >= 1e3) return `${(n / 1e3).toFixed(1)}k`;
  return String(n);
}

/** ISO time → "3m ago" / "2h ago" / "4d ago". */
export function ago(iso: string, nowMs: number): string {
  const s = Math.max(0, Math.round((nowMs - Date.parse(iso)) / 1000));
  if (!Number.isFinite(s)) return "";
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.round(s / 60)}m ago`;
  if (s < 86_400) return `${Math.round(s / 3600)}h ago`;
  return `${Math.round(s / 86_400)}d ago`;
}
