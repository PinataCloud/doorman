/** What a command hands back: `data` is printed as JSON under `--json`,
 * `text` (lines) otherwise. Commands stay printable and testable alike. */
export interface CommandResult {
  data: unknown;
  text: string[];
  /** Non-zero exit without an error message, e.g. "findings need review". */
  exitCode?: number;
}

/** A failure the person can act on: printed as one line, exit code 1 (or as given). */
export class CliError extends Error {
  constructor(
    message: string,
    readonly exitCode = 1,
  ) {
    super(message);
  }
}

export interface Styles {
  bold(s: string): string;
  dim(s: string): string;
  red(s: string): string;
  yellow(s: string): string;
  green(s: string): string;
  purple(s: string): string;
}

const SGR: Record<keyof Styles, [number, number]> = {
  bold: [1, 22],
  dim: [2, 22],
  red: [31, 39],
  yellow: [33, 39],
  green: [32, 39],
  purple: [35, 39],
};

/** ANSI styles when the stream is a terminal and NO_COLOR is unset; plain otherwise. */
export function styles(enabled: boolean): Styles {
  const wrap = (name: keyof Styles) => (s: string) => (enabled ? `\u001b[${SGR[name][0]}m${s}\u001b[${SGR[name][1]}m` : s);
  return {
    bold: wrap("bold"),
    dim: wrap("dim"),
    red: wrap("red"),
    yellow: wrap("yellow"),
    green: wrap("green"),
    purple: wrap("purple"),
  };
}

const ANSI = /\u001b\[[0-9;]*m/g;

/** Left-aligned columns padded to the widest cell (ANSI codes don't count). */
export function table(header: readonly string[], rows: readonly (readonly string[])[]): string[] {
  const width = header.map((h, i) => Math.max(h.length, ...rows.map((r) => (r[i] ?? "").replace(ANSI, "").length)));
  const line = (cells: readonly string[]) =>
    cells
      .map((c, i) => (i === cells.length - 1 ? c : c + " ".repeat(Math.max(0, width[i]! - c.replace(ANSI, "").length))))
      .join("  ")
      .trimEnd();
  return [line(header), ...rows.map(line)];
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
