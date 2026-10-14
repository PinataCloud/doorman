/**
 * Raw-evidence reveal for the Security Radar — the "view it locally" half of
 * the masking story.
 *
 * A finding's stored excerpt is masked before it is written (the invariant in
 * guard/security-detect.ts: a finding never carries the secret), and nothing in
 * this app un-stores that. But the app is local-first and the transcript the
 * finding came from is the user's own file on their own disk — so on an
 * explicit click we re-read that file, re-run the detector against the same
 * unit of text, and hand the RAW window back over IPC for display. Since
 * the engine also keeps that window in the evidence vault
 * (lib/evidence-vault.ts), encrypted by the OS keychain, so Reveal survives the
 * transcript; it is never synced, exported or sent to Doorman AI.
 *
 * Pure over (finding, detect units): the transcript locating + reading lives in
 * capture.ts, so this half is testable without a filesystem.
 */

import { redact } from "../guard/redact.js";
import { detectSecurityFindings, type DetectOptions } from "../guard/security-detect.js";
import { maskExcerpt, maskText } from "./masking.js";
import type { DetectUnit } from "./cc-transcript.js";
import type { FindingRow } from "./findings.js";
import { evaluateFlowFindings, type FlowOptions } from "./flow-rules.js";
import { accountForFlow, accountForUnit, type ExposureAccount } from "./account.js";

export interface RawEvidence {
  raw: string;
  truncated: boolean;
  tool_name?: string;
  target?: string;
  at: string;
  /** Every value redaction removed from the matched unit, in placeholder
   * order with its family label — what lets the renderer reveal ONE
   * placeholder in place instead of swapping to the whole raw window. */
  secrets: RedactedSecret[];
  /** What happened, in quotable fields and a sentence (lib/account.ts,
   *) — computed here too so a row minted before accounts existed
   * gets one the moment its raw is read. */
  account?: ExposureAccount;
  /** Where this came from: the evidence vault (kept when the detection fired),
   * a fresh read of the transcript, or the config file. Set by the engine. */
  evidence_source?: "vault" | "transcript" | "config";
}

export interface RedactedSecret {
  /** The placeholder family: "aws", "credentials", "" for anonymous. */
  label: string;
  value: string;
  /** Set on the ONE value the card is about when the reveal could tell it
   * from the others in the same window (the excerpt's own region held it).
   * Absent, the renderer falls back to matching by label. */
  primary?: boolean;
}

const PLACEHOLDER_RE = /\[redacted(?::([a-z0-9_]+))?\]/g;

/**
 * Recover the values `redact()` removed from `raw`, in order.
 *
 * Redaction only ever REPLACES substrings, so the redacted text's
 * non-placeholder segments appear verbatim in the raw text, in order — walking
 * segment to segment, the gaps between them ARE the redacted values. Returns
 * [] when the alignment fails (it shouldn't, but a wrong secret shown in
 * place would be worse than falling back to the raw window).
 */
export function extractRedactedSecrets(raw: string): RedactedSecret[] {
  return alignRedactedValues(raw, redact(raw));
}

/** A recovered value with where it sits in the text it came from — the
 * reveal's own bookkeeping; the renderer gets label + value only. */
interface Span extends RedactedSecret {
  at: number;
}

/** `extractRedactedSecrets` keeping each value's position. */
function extractRedactedSpans(raw: string): Span[] {
  return alignRedactedSpans(raw, redact(raw));
}

/**
 * The alignment itself, over a raw text and its redacted twin. STRICT: each
 * literal segment must resume exactly where the previous value ended, and
 * the last one must be the raw text's own tail. The earlier walk let a segment
 * be found anywhere AFTER the current position, so when a short segment
 * repeated (line-number prefixes such as `5xx:` do) it anchored on the wrong
 * occurrence and reported the slack between as a "value" — `28:`, `40:` —
 * which the raw window then highlighted as a credential. Now any slack, an
 * empty value or two placeholders with nothing between them means the masked
 * text is not a pure replacement view of the raw one, and the answer is []:
 * no value shown is better than a wrong one.
 */
export function alignRedactedValues(raw: string, masked: string): RedactedSecret[] {
  return alignRedactedSpans(raw, masked).map(({ label, value }) => ({ label, value }));
}

function alignRedactedSpans(raw: string, masked: string): Span[] {
  PLACEHOLDER_RE.lastIndex = 0;
  const labels: string[] = [];
  const segments: string[] = [];
  let last = 0;
  let match: RegExpExecArray | null;
  while ((match = PLACEHOLDER_RE.exec(masked)) !== null) {
    segments.push(masked.slice(last, match.index));
    labels.push(match[1] ?? "");
    last = match.index + match[0].length;
  }
  if (labels.length === 0) return [];
  segments.push(masked.slice(last));

  const secrets: Span[] = [];
  let pos = 0;
  for (let i = 0; i < labels.length; i++) {
    const before = segments[i]!;
    if (!raw.startsWith(before, pos)) return [];
    const valueStart = pos + before.length;
    const after = segments[i + 1]!;
    let valueEnd: number;
    if (i === labels.length - 1) {
      // The final literal is the raw text's tail, or the alignment is off.
      if (!raw.endsWith(after) || raw.length - after.length < valueStart) return [];
      valueEnd = raw.length - after.length;
    } else if (after === "") {
      // Two placeholders back to back: nothing separates their values.
      return [];
    } else {
      valueEnd = raw.indexOf(after, valueStart);
      if (valueEnd === -1) return [];
    }
    if (valueEnd <= valueStart) return [];
    secrets.push({ label: labels[i]!, value: raw.slice(valueStart, valueEnd), at: valueStart });
    pos = valueEnd;
  }
  return secrets;
}

/** Cap on what crosses the bridge — a window, not the whole tool argument. */
export const RAW_EVIDENCE_MAX_CHARS = 1_600;

/**
 * Cut `raw` down to a window the strip can show. Centered on `focus` — the
 * recovered value the card is about — when the caller has one and it is in
 * the text; else on the finding's named key when that appears; else the head
 * of the unit. A credential-family key_name like "aws" or "github" names the
 * PATTERN, not a substring of the raw text, so before `focus` existed such a
 * card opened on the head of the unit with the credential a screen below it.
 */
export function rawWindow(
  raw: string,
  keyName: string | undefined,
  max = RAW_EVIDENCE_MAX_CHARS,
  focus?: string | number,
): { raw: string; truncated: boolean } {
  if (raw.length <= max) return { raw, truncated: false };
  // A number is a position already found (the excerpt's own region); a string
  // is a value to look for.
  let idx = typeof focus === "number" ? (focus >= 0 && focus < raw.length ? focus : -1) : focus && focus !== "" ? raw.indexOf(focus) : -1;
  if (idx < 0) idx = keyName ? raw.toLowerCase().indexOf(keyName.toLowerCase()) : -1;
  if (idx < 0) return { raw: `${raw.slice(0, max - 1)}…`, truncated: true };
  const start = Math.max(0, idx - Math.floor(max / 2));
  const end = Math.min(raw.length, start + max);
  return {
    raw: `${start > 0 ? "…" : ""}${raw.slice(start, end)}${end < raw.length ? "…" : ""}`,
    truncated: true,
  };
}


/**
 * The text the raw strip SHOWS for a unit. A tool call is stored as the JSON
 * of its arguments — `{"file_path":"…","content":"{\n  \"env\": …"}` — while
 * the detectors that raised on it read the arguments' STRINGS (the command,
 * the written payload), and so does the excerpt on the card. Shown as JSON,
 * the raw never matched the preview: every quote escaped, every line one
 * `\n`. So the strip shows the arguments the way the detector read them,
 * one `name: value` per field, a multi-line string on its own lines.
 * Everything else (a prompt, a tool's output) is shown as it is.
 */
export function unitDisplayText(unit: Pick<DetectUnit, "kind" | "raw">): string {
  if (unit.kind !== "tool_call") return unit.raw;
  let parsed: unknown;
  try {
    parsed = JSON.parse(unit.raw);
  } catch {
    return unit.raw;
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return unit.raw;
  const lines: string[] = [];
  for (const [key, value] of Object.entries(parsed as Record<string, unknown>)) {
    if (typeof value === "string") {
      lines.push(value.includes("\n") ? `${key}:\n${value}` : `${key}: ${value}`);
    } else {
      lines.push(`${key}: ${JSON.stringify(value)}`);
    }
  }
  return lines.length > 0 ? lines.join("\n") : unit.raw;
}

/** Where the card's excerpt sits in a text, and what its placeholders hid. */
export interface ExcerptAnchor {
  start: number;
  end: number;
  /** One per placeholder (or run of placeholders) that had literal text on
   * both sides, in order, each with its position in the text. */
  values: Array<RedactedSecret & { at: number }>;
}

/**
 * Find the stored excerpt's region in `text`. The excerpt is the detector's
 * ±70 characters of context around the match with the match masked and the
 * whitespace collapsed (guard/security-detect.ts maskedExcerpt), sometimes
 * from a JSON-escaped reading of the same text — so each literal segment is
 * matched with any whitespace run, `\n`/`\t` escapes included, standing for
 * any other, and a quote optionally escaped; each placeholder between two
 * literals becomes a capture, which IS the value it masked. That recovers a
 * value `redact()` never touched — an `unrecognized_secret` masks its own
 * match — and finds the region when the row's excerpt no longer re-detects
 * character for character. Undefined when the excerpt has too little literal
 * text to anchor, or isn't in the text.
 */
export function excerptAnchor(text: string, excerpt: string): ExcerptAnchor | undefined {
  if (text === "" || excerpt === "") return undefined;
  // The ellipses cut mid-token, a placeholder included: `[redacted…` at the
  // tail or `…ted]` at the head is a fragment of a mask, not text to find.
  const parts = excerpt
    .replace(/^…/, "")
    .replace(/…$/, "")
    .replace(/^[a-z0-9_:[]{0,20}\]/, "")
    .replace(/\[[a-z0-9_:]{0,20}$/, "")
    .split(/(\[redacted(?::[a-z0-9_]+)?\])/);
  // Any whitespace run — or none — where the excerpt has a space (its
  // builder pads the mask with spaces the text never had) or an escape.
  const WS = "(?:\\s|\\\\[ntr])*";
  const isMark = (part: string | undefined) => part !== undefined && /^\[redacted(?::[a-z0-9_]+)?\]$/.test(part);
  const literal = (part: string | undefined) =>
    (part ?? "")
      .replace(/\\"/g, '"')
      .replace(/\\[ntr]/g, " ")
      .replace(/\s+/g, " ")
      .trim();
  let pattern = "";
  const labels: string[] = [];
  let anchored = 0;
  for (let i = 0; i < parts.length; i++) {
    const part = parts[i]!;
    if (isMark(part)) {
      const label = /^\[redacted(?::([a-z0-9_]+))?\]$/.exec(part)?.[1] ?? "";
      const before = literal(parts[i - 1]);
      // A run of placeholders with only whitespace between them is one
      // value to the eye (`cp: [redacted] [redacted]/x` — one path); the run
      // is captured whole under the first one's label.
      while (isMark(parts[i + 2]) && literal(parts[i + 1]) === "") i += 2;
      const after = literal(parts[i + 1]);
      // Only a placeholder bracketed on both sides is a value worth naming:
      // one at an edge has nothing to say where it stops.
      // The value sits on its own line as often as not (a grep hit, a table
      // row), so the whitespace around the mask is matched here, not by the
      // capture: `.` stops at a newline, and the excerpt trimmed the space.
      if (before !== "" && after !== "") {
        pattern += `${WS}(.{1,400}?)${WS}`;
        labels.push(label);
      } else {
        pattern += `${WS}.{0,400}?${WS}`;
      }
      continue;
    }
    const lit = literal(part);
    if (lit === "") continue;
    anchored += lit.length;
    // A space stands for any whitespace run — or none: the excerpt builder
    // pads its mask with spaces the text never had. A quote may be escaped
    // in one reading and not the other, a backslash may not be there at all.
    pattern += lit
      .split(/( )/)
      .map((piece) =>
        piece === " "
          ? WS
          : piece
              .replace(/[.*+?^${}()|[\]\\]/g, "\\$&")
              .replace(/\\\\/g, "\\\\?")
              .replace(/"/g, '\\\\?"'),
      )
      .join("");
  }
  if (anchored < 8 || pattern === "") return undefined;
  let match: RegExpExecArray | null;
  try {
    match = new RegExp(pattern, "d").exec(text);
  } catch {
    return undefined;
  }
  if (!match) return undefined;
  const values: ExcerptAnchor["values"] = [];
  const indices = (match as RegExpExecArray & { indices?: Array<[number, number] | undefined> }).indices ?? [];
  for (let i = 0; i < labels.length; i++) {
    const value = match[i + 1];
    const span = indices[i + 1];
    if (typeof value !== "string" || value.trim() === "" || /\[redacted/.test(value) || !span) continue;
    const lead = value.length - value.trimStart().length;
    values.push({ label: labels[i]!, value: value.trim(), at: span[0] + lead });
  }
  return { start: match.index, end: match.index + match[0].length, values };
}

/**
 * Does this unit reproduce the finding? Same pipeline as capture's scan
 * (redact, then detect) with every detector ON — a rule the user has since
 * switched off or ignored must still be revealable, because the finding it
 * already raised is still on screen.
 */
export function unitMatchesFinding(unit: DetectUnit, row: FindingRow, detect: RevealDetectOptions = {}): boolean {
  return matchingFinding(unit, row, detect) !== undefined;
}

/**
 * What the reproduction needs from the capture's detect options. Only the
 * WALLET settings: a row about the person's own wallet is keyed `your "cold"
 * wallet (Ethereum) …`, which only a detector that knows their hashed
 * addresses can mint again. The switched-off and ignored rules are NOT passed
 * — a finding already on screen must stay revealable.
 */
export interface RevealDetectOptions {
  wallets?: DetectOptions["wallets"];
}

/** A re-detected key compared with a stored one. Stored keys are masked
 * (lib/masking.ts), so the fresh one is masked the same way first. */
function sameKey(fresh: string | undefined, stored: string | undefined): boolean {
  return maskText(fresh ?? "") === (stored ?? "") || (fresh ?? "") === (stored ?? "");
}

/** The finding this unit reproduces for the row, or undefined — the same
 *  test as `unitMatchesFinding`, keeping what it found so a caller can compare
 *  its excerpt with the card's. */
export function matchingFinding(unit: DetectUnit, row: FindingRow, detect: RevealDetectOptions = {}) {
  const found = detectSecurityFindings(
    {
      kind: unit.kind,
      text: redact(unit.raw),
      ...(unit.kind === "tool_call" ? { raw_text: unit.raw } : {}),
      tool_name: unit.tool_name,
      target: unit.target,
    },
    detect.wallets === undefined ? {} : { wallets: detect.wallets },
  );
  return found.find((f) => f.detector === row.detector && sameKey(f.key_name, row.key_name));
}

/** A re-detected excerpt compared with a stored one — stored excerpts are
 * masked (lib/masking.ts maskExcerpt), so the fresh one is masked the same way. */
function sameExcerpt(fresh: string | undefined, stored: string): boolean {
  return fresh !== undefined && (fresh === stored || maskExcerpt(fresh) === stored);
}

/** Raw evidence plus whether it is provably THE sighting the card shows. */
export interface ScoredEvidence {
  evidence: RawEvidence;
  /**
   * True when the unit re-detected with the card's very excerpt (a flow: the
   * pair re-evaluated with it). Only exact evidence may be KEPT in the vault
   * under the card's excerpt — a near match is displayed at most, never
   * stored as "what was reported".
   */
  exact: boolean;
}

/** `revealEvidenceForFinding`'s evidence alone — the historical API. */
export function rawEvidenceForFinding(
  row: FindingRow,
  units: readonly DetectUnit[],
  options: FlowOptions & { detect?: RevealDetectOptions } = {},
): RawEvidence | undefined {
  return revealEvidenceForFinding(row, units, options)?.evidence;
}

/**
 * The raw window behind a finding, out of the session's detect units. The
 * finding id doesn't encode a turn (identity is detector + session + key), so
 * every unit in the session that reproduces the same detector + key pair is
 * the same exposure — and a row that merged many sightings shows the NEWEST
 * one's excerpt (findings.ts mergeFinding; rows written before it kept the
 * FIRST one's turn). So the unit whose re-detected excerpt equals the card's
 * own comes first: that is the call the person is looking at. Then the
 * excerpt's context, then the row's turn, then a lone reproduction — never
 * one of several that nothing ties to the card. Only the first is `exact`,
 * the one grade a caller may keep in the vault. The window is centred on the
 * recovered value the card is about, so the credential is on screen when it
 * opens.
 */
export function revealEvidenceForFinding(
  row: FindingRow,
  units: readonly DetectUnit[],
  options: FlowOptions & { detect?: RevealDetectOptions } = {},
): ScoredEvidence | undefined {
  // Everything the session-flow evaluator emits reproduces through it — the
  // per-unit detectors below cannot emit a loop, an unapproved server or a
  // flow, so routing those there always ended at "couldn't reproduce". A
  // custom rule may be either shape (an `after` clause makes it a flow), so it
  // tries the flow path first and falls through to the per-unit scan.
  if (isFlowShaped(row.detector)) return scoredFlowEvidence(row, units, options);
  if (row.detector.startsWith("custom:")) {
    const asFlow = scoredFlowEvidence(row, units, options);
    if (asFlow) return asFlow;
  }
  // The unit the person is looking at: 3 = re-detects with the very excerpt
  // the card shows; 2 = the excerpt's context is in its text (the stored
  // excerpt has drifted from what the detector writes today, but this is
  // still the call); 1 = the row's own turn; 0 = any reproduction. A unit
  // from the same tool breaks a tie — a session's `unrecognized_secret` rows
  // all share one identity, so without it a Read's excerpt could open a
  // Bash call's output. Earliest unit wins what is left.
  let best: { unit: DetectUnit; display: string; anchor: ExcerptAnchor | undefined; score: number; base: number } | undefined;
  let reproductions = 0;
  for (const unit of units) {
    const found = matchingFinding(unit, row, options.detect);
    if (!found) continue;
    reproductions += 1;
    const display = unitDisplayText(unit);
    const anchor = excerptAnchor(display, row.excerpt);
    const base = sameExcerpt(found.excerpt, row.excerpt) ? 3 : anchor ? 2 : row.turn_id !== undefined && unit.turn_id === row.turn_id ? 1 : 0;
    const score = base * 2 + ((row.tool_name ?? "") === (unit.tool_name ?? "") ? 1 : 0);
    if (!best || score > best.score) best = { unit, display, anchor, score, base };
    if (score === 7) break;
  }
  if (!best) return undefined;
  // Nothing tied the pick to this card — not its excerpt, the excerpt's
  // context, nor its turn (which mergeFinding keeps on the NEWEST sighting,
  // the one the card shows). With ONE reproducing unit there is nothing else
  // it could be; with several, it may be another sighting holding a different
  // credential, and showing that under this card is worse than showing
  // nothing.
  if (best.base === 0 && reproductions > 1) return undefined;
  const { unit, display, anchor } = best;
  const spans = mergeSpans(extractRedactedSpans(display), anchor?.values ?? []);
  // The value the card is about: of those in the excerpt's region, the one
  // nearest its middle — the excerpt is the detector's context to either
  // side of ITS match, so the match is at the centre and a neighbour's
  // value on the line above is not. Then the row's label, then the first.
  // By POSITION, not by a search for the value: `"API key"` recurs in a
  // file, and its first occurrence is not the one the card is about.
  const label = row.key_name ?? "";
  const inRegion = anchor
    ? spans
        .filter((s) => s.at < anchor.end && s.at + s.value.length > anchor.start)
        .sort((a, b) => Math.abs(a.at + a.value.length / 2 - (anchor.start + anchor.end) / 2) - Math.abs(b.at + b.value.length / 2 - (anchor.start + anchor.end) / 2))
    : [];
  // With the excerpt found but no value inside it (a `.env` read names a
  // path, not a secret), the window opens on the excerpt, not on whatever
  // the redactor took out elsewhere in the same call.
  const own = inRegion.find((s) => s.label === label) ?? inRegion[0] ?? (anchor ? undefined : spans.find((s) => s.label === label) ?? spans[0]);
  const secrets: RedactedSecret[] = spans.map((s) => ({
    label: s.label,
    value: s.value,
    ...(s === own && spans.length > 1 ? { primary: true } : {}),
  }));
  const focus = own ? own.at : anchor ? Math.floor((anchor.start + anchor.end) / 2) : (spans.find((s) => s.label === label) ?? spans[0])?.at;
  const window = rawWindow(display, row.key_name, RAW_EVIDENCE_MAX_CHARS, focus);
  const account = accountForUnit(row, unit, secrets, row.cwd);
  return {
    evidence: {
      ...window,
      tool_name: unit.tool_name,
      target: unit.target,
      at: unit.at,
      secrets,
      ...(account === undefined ? {} : { account }),
    },
    exact: best.base === 3,
  };
}

/** The redactor's values first, then the excerpt's own that add a value —
 * one the redactor never saw, not a piece of one it did. */
function mergeSpans(redacted: Span[], fromExcerpt: Span[]): Span[] {
  const out = redacted.map((s) => ({ ...s }));
  for (const s of fromExcerpt) {
    if (out.some((o) => o.at < s.at + s.value.length && s.at < o.at + o.value.length)) continue;
    out.push({ ...s });
  }
  return out.sort((a, b) => a.at - b.at);
}

/**
 * A flow finding spans TWO tool calls, so its raw evidence is two windows: the
 * source (the read) and the sink (the egress), joined with the gap between
 * them named. Re-runs the flow evaluator over the session's units — same
 * "reproduce, don't trust the stored row" rule as the per-unit reveal — and
 * matches on key_name, the flow's identity.
 *
 * `secrets` is what the redactor took out of EITHER end, so the strip marks
 * the credential where it was read and again where it went out — the
 * highlight is a substring search over the shown text, so the stitched
 * string is no obstacle to it. (A one-window loop or server row has none.)
 */
export function rawEvidenceForFlowFinding(
  row: FindingRow,
  units: readonly DetectUnit[],
  options: FlowOptions = {},
): RawEvidence | undefined {
  return scoredFlowEvidence(row, units, options)?.evidence;
}

/** The flow reveal, with whether the re-evaluated pair carries the card's own
 * excerpt (a flow's excerpt names both ends, so equal excerpts = same pair). */
function scoredFlowEvidence(
  row: FindingRow,
  units: readonly DetectUnit[],
  options: FlowOptions = {},
): ScoredEvidence | undefined {
  const flows = evaluateFlowFindings(units, options);
  const flow = flows.find((f) => f.detector === row.detector && sameKey(f.key_name, row.key_name));
  if (!flow) return undefined;
  const evidence = flowEvidence(row, units, flow);
  return evidence === undefined ? undefined : { evidence, exact: sameExcerpt(flow.excerpt, row.excerpt) };
}

function flowEvidence(
  row: FindingRow,
  units: readonly DetectUnit[],
  flow: ReturnType<typeof evaluateFlowFindings>[number],
): RawEvidence | undefined {
  const sink = units.find((u) => u.turn_id === flow.sink_turn_id && u.kind === "tool_call");
  if (!sink) return undefined;
  // One call, not two: the unapproved-server row is a single tool call, and
  // so is a loop whose run collapsed to one unit — a lone window says so.
  if (flow.source_turn_id === flow.sink_turn_id) {
    const window = rawWindow(unitDisplayText(sink), undefined);
    return { ...window, tool_name: sink.tool_name, target: sink.target, at: sink.at, secrets: [] };
  }
  const half = Math.floor(RAW_EVIDENCE_MAX_CHARS / 2) - 40;
  const source = units.find((u) => u.turn_id === flow.source_turn_id && u.kind !== "prompt");
  if (!source) return undefined;
  const sourceDisplay = unitDisplayText(source);
  const sinkDisplay = unitDisplayText(sink);
  const sourceSecrets = extractRedactedSecrets(sourceDisplay);
  const sinkSecrets = extractRedactedSecrets(sinkDisplay);
  // Each window opens on the first value its end carries, so the read and
  // the send are both on screen with their credential.
  const sourceWindow = rawWindow(sourceDisplay, undefined, half, sourceSecrets[0]?.value);
  const sinkWindow = rawWindow(sinkDisplay, undefined, half, sinkSecrets[0]?.value);
  const gap = flowGapLabel(source.at, sink.at);
  const [head, tail] = flowEndLabels(row.detector);
  const seen = new Set<string>();
  const secrets: RedactedSecret[] = [];
  for (const s of [...sourceSecrets, ...sinkSecrets]) {
    if (seen.has(s.value)) continue;
    seen.add(s.value);
    secrets.push({ label: s.label, value: s.value });
  }
  // The account reads both ends; the source's recovered values name the family.
  const account = accountForFlow({ ...row, source_at: source.at, at: sink.at }, source, sink, sourceSecrets, row.cwd);
  return {
    raw: `— ${head} —\n${sourceWindow.raw}\n— ${tail}, ${gap} later —\n${sinkWindow.raw}`,
    truncated: sourceWindow.truncated || sinkWindow.truncated,
    tool_name: sink.tool_name,
    target: sink.target,
    at: sink.at,
    secrets,
    ...(account === undefined ? {} : { account }),
  };
}

/** The detector ids whose rows only the session-flow evaluator can reproduce. */
export function isFlowShaped(detector: string): boolean {
  return detector.startsWith("flow_") || detector === "agent_loop" || detector === "unknown_mcp_server";
}

/** "4s" / "3m" between a flow's two ends; "?" when a timestamp is unreadable. */
export function flowGapLabel(sourceAt: string, sinkAt: string): string {
  const gapMs = Date.parse(sinkAt) - Date.parse(sourceAt);
  if (!Number.isFinite(gapMs) || gapMs < 0) return "?";
  return gapMs < 60_000 ? `${Math.max(1, Math.round(gapMs / 1000))}s` : `${Math.round(gapMs / 60_000)}m`;
}

/**
 * What each end of a flow IS, by rule — the raw strip used to label every sink
 * "egress", which was wrong for an install, an exec and a query. The head is
 * the source's role, the tail the sink's.
 */
export function flowEndLabels(detector: string): [string, string] {
  switch (detector) {
    case "flow_secret_egress":
      return ["credential read", "egress"];
    case "flow_read_then_send":
      return ["private data read", "send"];
    case "flow_injection_followed":
      return ["injected instruction arrived", "the call that followed"];
    case "flow_fetch_then_exec":
      return ["fetched", "executed"];
    case "flow_fetch_then_install":
      return ["fetched content named a package", "installed"];
    case "flow_insecure_code_executed":
      return ["insecure code written", "executed"];
    case "flow_sql_second_order":
      return ["database result", "later query"];
    case "agent_loop":
      return ["first repeat", "last repeat"];
    default:
      return ["source", "sink"];
  }
}
