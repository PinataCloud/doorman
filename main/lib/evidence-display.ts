/**
 * A masked excerpt as the Radar's evidence strip shows it. MIRRORS
 * renderer/screens/radar.jsx `evidenceDisplayParts`, so the terminal prints
 * the line the card prints. The stored excerpt is never changed; only what is
 * shown differs. Pure.
 */

const MARK_SPLIT = /(\[redacted(?::[a-z0-9_]+)?\])/g;
const isMark = (p: string | undefined): boolean => p !== undefined && /^\[redacted/.test(p);

/**
 * What each part of the split excerpt shows (null = not shown):
 *  · A shell call's excerpt is its tool input, `{"command":"curl -H \"…`:
 *    when the window opens on a `command` string, show the command text,
 *    unescaped, and drop the JSON around it — unless a mark sits outside the
 *    string, which the rewrite would hide.
 *  · Redaction can mask one value twice (`[redacted] [redacted:github]`):
 *    an anonymous mark beside a named one shows as the named one alone.
 */
export function evidenceDisplayParts(parts: readonly string[]): (string | null)[] {
  const out: (string | null)[] = parts.slice();
  for (let i = 0; i + 2 < parts.length; i += 2) {
    if (!isMark(parts[i + 1]) || !isMark(parts[i + 3]) || !/^\s*$/.test(parts[i + 2]!)) continue;
    const a = parts[i + 1] === "[redacted]";
    const b = parts[i + 3] === "[redacted]";
    if (a && !b) {
      out[i + 1] = null;
      out[i + 2] = null;
    } else if (b && !a) {
      out[i + 2] = null;
      out[i + 3] = null;
    }
  }
  const head = /^(?:…|\.\.\.)?\s*\{\s*"command"\s*:\s*"/.exec(parts[0] ?? "");
  if (!head) return out;
  const cmd = out.slice();
  let escaped = false;
  for (let i = 0; i < parts.length; i++) {
    if (isMark(parts[i])) continue;
    const seg = i === 0 ? parts[0]!.slice(head[0].length) : parts[i]!;
    let text = "";
    let closed = false;
    for (let k = 0; k < seg.length; k++) {
      const c = seg[k]!;
      if (escaped) {
        escaped = false;
        if (c === "n") text += "\n";
        else if (c === "t") text += "\t";
        else if (c === "r") text += "";
        else if (c === "u" && /^[0-9a-fA-F]{4}$/.test(seg.slice(k + 1, k + 5))) {
          text += String.fromCharCode(parseInt(seg.slice(k + 1, k + 5), 16));
          k += 4;
        } else text += c;
      } else if (c === "\\") escaped = true;
      else if (c === '"') {
        closed = true;
        break;
      } else text += c;
    }
    if (cmd[i] != null) cmd[i] = text;
    if (closed) {
      if (parts.slice(i + 1).some(isMark)) return out;
      for (let j = i + 1; j < parts.length; j++) cmd[j] = null;
      break;
    }
  }
  return cmd;
}

/** The excerpt's displayed text: `evidenceDisplayParts` joined. */
export function evidenceDisplay(excerpt: string): string {
  return evidenceDisplayParts(excerpt.split(MARK_SPLIT))
    .filter((p): p is string => p !== null)
    .join("");
}
