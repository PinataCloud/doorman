// The quote-aware command splitter, on its own so the guard bundle carries it
// once — security-detect.ts is its consumer.

/**
 * Split a shell command line into its pipeline/sequence segments, respecting
 * single and double quotes. `a && b | c; d` yields four segments. This is NOT a
 * shell parser — it exists so callers can reason about each command in a
 * pipeline separately (e.g. "does one segment both read a credential and reach
 * the network").
 */
export function commandSegments(commandLine: string): string[] {
  const segments: string[] = [];
  let current = "";
  let quote: string | undefined;
  for (let i = 0; i < commandLine.length; i += 1) {
    const ch = commandLine[i]!;
    if (quote) {
      // Backslash escapes apply inside double quotes only — the shell's own rule.
      if (ch === "\\" && quote === '"' && i + 1 < commandLine.length) {
        current += ch + commandLine[i + 1];
        i += 1;
        continue;
      }
      if (ch === quote) quote = undefined;
      current += ch;
      continue;
    }
    if (ch === '"' || ch === "'") {
      quote = ch;
      current += ch;
      continue;
    }
    if (ch === "\n" || ch === ";") {
      segments.push(current);
      current = "";
      continue;
    }
    if (ch === "|" || ch === "&") {
      // A redirection operator spelled with `|`/`&` is part of THIS command, not
      // a separator: `>|` (clobber), `>&`/`<&` (to a file or an fd) and
      // `&>`/`&>>` (both streams). Splitting there cut the target off into a
      // "segment" of its own, where it read as a program name.
      const prev = commandLine[i - 1];
      const redirection =
        (ch === "|" && prev === ">") ||
        (ch === "&" && (prev === ">" || prev === "<" || (commandLine[i + 1] === ">" && prev !== "&")));
      if (redirection) {
        current += ch;
        continue;
      }
      // `&&`/`||` and a bare `|` all start a new command; a bare `&` backgrounds
      // the segment, which ends it just the same.
      if (commandLine[i + 1] === ch) i += 1;
      segments.push(current);
      current = "";
      continue;
    }
    current += ch;
  }
  segments.push(current);
  return segments;
}
