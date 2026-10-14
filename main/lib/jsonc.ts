/**
 * JSON with comments and trailing commas — the dialect every editor-owned
 * settings file is actually written in.
 *
 * Two callers, with opposite intents, share this one scanner:
 *  · the setup doctor (lib/doctor.ts `repairJsonText`) treats a comment in
 *    `~/.claude/settings.json` as DAMAGE — Claude Code's own parser is strict,
 *    so a commented document is one nothing can read, and the repair rewrites
 *    it as canonical JSON;
 *  · the VS Code reader (lib/vscode.ts) treats a comment as NORMAL — VS Code
 *    writes `// …` into `settings.json` itself and parses it back happily, so
 *    the comments are stripped to READ the values and the file is never
 *    rewritten from them.
 *
 * Hence the split: this module only ever produces a string to hand `JSON.parse`
 * and a list of what it removed. What that means is the caller's judgement.
 */

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
      let j = i + 1;
      while (j < n && text[j] !== '"') {
        if (text[j] === "\\") j++;
        j++;
      }
      out += text.slice(i, Math.min(j + 1, n));
      i = j + 1;
      continue;
    }
    if (ch === "/" && text[i + 1] === "/") {
      const end = text.indexOf("\n", i);
      i = end === -1 ? n : end;
      changes.add("removed comments");
      continue;
    }
    if (ch === "/" && text[i + 1] === "*") {
      const end = text.indexOf("*/", i + 2);
      i = end === -1 ? n : end + 2;
      changes.add("removed comments");
      continue;
    }
    if (ch === ",") {
      // Look past whitespace and comments for a closing bracket.
      let j = i + 1;
      for (;;) {
        while (j < n && /\s/.test(text[j]!)) j++;
        if (text[j] === "/" && text[j + 1] === "/") {
          const end = text.indexOf("\n", j);
          j = end === -1 ? n : end;
          continue;
        }
        if (text[j] === "/" && text[j + 1] === "*") {
          const end = text.indexOf("*/", j + 2);
          j = end === -1 ? n : end + 2;
          continue;
        }
        break;
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
