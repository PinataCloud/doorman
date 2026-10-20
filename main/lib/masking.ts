/**
 * The one masking rule for text the app STORES in a record or WRITES OUT:
 * `redact()` for every credential family it knows, then the detectors' own
 * masks for what it doesn't (cards, IBANs, SSNs, wallet keys and
 * addresses, high-entropy tokens — guard/security-detect.ts maskDetectedValues).
 *
 * Both steps only ever REPLACE substrings with a placeholder, so a masked text
 * is still a pure replacement view of its raw twin, and reveal.ts
 * `alignRedactedValues(raw, masked)` recovers exactly the values it hid — the
 * reveal-in-place contract the ledger bubbles depend on.
 */

import { redact } from "../guard/redact.js";
import { maskDetectedValues } from "../guard/security-detect.js";
import type { ExposureAccount } from "./account.js";
import type { FindingRow } from "./findings.js";
import { TURN_TEXT_MAX_CHARS } from "./turns.js";

const PLACEHOLDER = "[redacted]";

/** The family of the cap's own mask over a cut final token (maskTurnText): a
 * precaution, not a detection — most cut tokens are ordinary words. Consumers
 * that list or count SECRETS (ledger-export fingerprints, the detectors on a
 * pasted placeholder) skip it. */
export const CUT_LABEL = "cut";
const CUT_PLACEHOLDER = `[redacted:${CUT_LABEL}]`;

/** Everything any rule here would call secret, masked. */
export function maskText(text: string): string {
  if (text === "") return text;
  return maskDetectedValues(redact(text));
}

const PLACEHOLDER_TOKEN_RE = /\[redacted(?::[a-z0-9_]+)?\]/g;

/**
 * A finding EXCERPT, masked — `maskText` over the literal text BETWEEN the
 * placeholders already in it, the placeholders kept verbatim. A detector
 * masks only ITS value in the window it quotes, so a card-number excerpt
 * still carried the SSN and IBAN beside it, and those reached the export and
 * Doorman AI. Masking the whole string would instead re-mask the detector's
 * own `KEY=[redacted:aws]` as `KEY=[redacted]`, losing the family and (since
 * the vault and Reveal key on the excerpt) changing the sighting's identity on
 * every pass. Segment-wise, it is idempotent: masking a masked excerpt is a
 * no-op, so the ledger, the vault and a re-detected excerpt all agree.
 */
export function maskExcerpt(text: string): string {
  if (text === "") return text;
  let out = "";
  let last = 0;
  PLACEHOLDER_TOKEN_RE.lastIndex = 0;
  let match: RegExpExecArray | null;
  while ((match = PLACEHOLDER_TOKEN_RE.exec(text)) !== null) {
    out += maskText(text.slice(last, match.index)) + match[0];
    last = match.index + match[0].length;
  }
  return out + maskText(text.slice(last));
}

/** `maskText`, or undefined for undefined — for optional record fields. */
function maskOptional(text: string | undefined): string | undefined {
  return typeof text === "string" ? maskText(text) : text;
}

/**
 * A stored turn's text, masked. The parsers cap turn text at
 * TURN_TEXT_MAX_CHARS BEFORE anything is redacted (lib/turns.ts), and a secret
 * the cap cut in half no longer matches its pattern — the private-key block
 * without its END line, the AWS secret cut to 25 characters. So a text that
 * reached the cap is treated as cut: an unterminated PEM block is masked to
 * the end, and so is the final token, which is by construction the one the cut
 * went through. That token is masked as `[redacted:cut]`, not `[redacted]`:
 * nothing matched it, and a ledger export listed eleven ordinary words cut at
 * the cap (1–8 characters each) among one session's secrets.
 */
export function maskTurnText(text: string): string {
  let masked = maskText(text);
  if (text.length < TURN_TEXT_MAX_CHARS) return masked;
  const begin = masked.lastIndexOf("-----BEGIN");
  if (begin >= 0 && begin > masked.lastIndexOf("-----END")) return `${masked.slice(0, begin)}${PLACEHOLDER}`;
  const tail = /\S+$/.exec(masked);
  if (tail && !/^\[redacted(?::[a-z0-9_]+)?\]$/.test(tail[0])) masked = `${masked.slice(0, tail.index)}${CUT_PLACEHOLDER}`;
  return masked;
}

const ACCOUNT_TEXT_FIELDS = [
  "source_ref",
  "name",
  "read_via",
  "sink_tool",
  "destination_host",
  "credential_family",
  "family_noun",
  "gap",
  "sentence",
  "title",
  "so",
  "next",
] as const satisfies readonly (keyof ExposureAccount)[];

export function maskAccount(account: ExposureAccount): ExposureAccount {
  const out: ExposureAccount = { ...account };
  for (const field of ACCOUNT_TEXT_FIELDS) {
    const value = out[field];
    if (typeof value === "string") out[field] = maskText(value);
  }
  return out;
}

/**
 * A finding row with every free-text field masked — the fields a detector
 * copies from the RAW call (a Bash target is the command's first word, so
 * `STRIPE_KEY=sk_live_… node` was a target) — and the excerpt, whose detector
 * masked only its own value (`maskExcerpt`). Reveal compares a re-detected
 * excerpt through the same function, so it still finds its unit.
 */
export function maskFindingRow<T extends FindingRow>(row: T): T {
  const out: T = { ...row };
  if (typeof row.excerpt === "string") out.excerpt = maskExcerpt(row.excerpt);
  const target = maskOptional(row.target);
  if (target !== undefined) out.target = target;
  const key = maskOptional(row.key_name);
  if (key !== undefined) out.key_name = key;
  const cwd = maskOptional(row.cwd);
  if (cwd !== undefined) out.cwd = cwd;
  if (row.account) out.account = maskAccount(row.account);
  if (row.exception?.note !== undefined) out.exception = { ...row.exception, note: maskText(row.exception.note) };
  return out;
}
