/**
 * FOCUS WINDOWS — how the doorman-1 injection model reads a tool output
 *. Stock Prompt Guard reads the first 2 × 512 tokens
 * (injection-classifier.ts `classifierWindows`); doorman-1 was trained and
 * calibrated on short crops CENTRED ON WHAT THE REGEX FLAGGED, so it must be
 * fed the same crops or its calibration (the 0.2 stand-down point) means
 * nothing. Used only when the selected model's manifest says
 * `windowing: "focus"` (model-assets.ts).
 *
 * A crop is the hit's line plus whole neighbouring lines, grown alternately
 * below then above while the token cost (tokenizer ids without special
 * tokens, +1 per line) stays within FOCUS_BUDGET. A line longer than
 * FOCUS_LINE_CHARS is cut to head + " … " + tail (the hit line's head starts
 * just before the hit), so one long quoted attack cannot crowd out the short
 * line next to it — where the cue that makes it live usually sits. One crop
 * per distinct hit region, at most FOCUS_MAX_CROPS; the row's score is the
 * max over crops, the production rule (most malicious window wins).
 *
 * A port of the training pipeline's reference cropper (`common.py` Cropper +
 * `text_and_offsets`), proven equal crop-for-crop on public benchmark rows
 * (test/injection-focus.test.ts). Line lengths and slices count CODE
 * POINTS, as the reference's Python strings do. The regex offsets are UTF-16
 * indices and are converted to code points here — the one deliberate
 * difference from the reference, which used them as code-point indices
 * unconverted and so drifted past the hit when an emoji preceded it.
 *
 * Pure: the token counter is injected, so tests never need the tokenizer.
 */

import { injectionHitOffsets } from "../guard/security-detect.js";

export const FOCUS_BUDGET = 256;
/** ~90 tokens: a longer line is cut to FOCUS_HEAD_CHARS + " … " + FOCUS_TAIL_CHARS. */
export const FOCUS_LINE_CHARS = 360;
export const FOCUS_HEAD_CHARS = 240;
export const FOCUS_TAIL_CHARS = 110;
/** How far before the hit the hit line's head starts. */
export const FOCUS_HIT_LEAD = 60;
export const FOCUS_MAX_CROPS = 4;

/**
 * What to crop and where: the regex's offsets index foldForMatching(raw), so
 * when folding changed the length (entities decoded, format characters
 * removed) the FOLDED text is cropped — the offsets only line up there.
 * Otherwise the raw text, exactly as the tool returned it.
 */
export function focusTarget(raw: string): { text: string; offsets: number[] } {
  const { folded, offsets } = injectionHitOffsets(raw);
  return { text: folded.length === raw.length ? raw : folded, offsets };
}

/** Code points in `s` — a well-formed surrogate pair counts once. */
function codePointLength(s: string): number {
  let n = s.length;
  for (let i = 0; i < s.length - 1; i++) {
    const c = s.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) {
      const d = s.charCodeAt(i + 1);
      if (d >= 0xdc00 && d <= 0xdfff) {
        n -= 1;
        i += 1;
      }
    }
  }
  return n;
}

/** `line`, cut to head + " … " + tail when it is longer than FOCUS_LINE_CHARS
 * code points. `at` is the hit's code-point column on the hit line. */
export function shortenLine(line: string, at?: number): string {
  if (line.length <= FOCUS_LINE_CHARS) return line; // UTF-16 length ≥ code points
  const cps = Array.from(line);
  if (cps.length <= FOCUS_LINE_CHARS) return line;
  const start = at === undefined ? 0 : Math.max(0, Math.min(at - FOCUS_HIT_LEAD, cps.length - FOCUS_LINE_CHARS));
  const head = cps.slice(start, start + FOCUS_HEAD_CHARS).join("");
  const tail = start + FOCUS_HEAD_CHARS < cps.length - FOCUS_TAIL_CHARS ? cps.slice(-FOCUS_TAIL_CHARS).join("") : "";
  return tail === "" ? head : `${head} … ${tail}`;
}

/**
 * The crops for `text` around `offsets` (UTF-16 indices into `text`, sorted —
 * focusTarget's). No offsets crops around the start. An offset whose line an
 * earlier crop already covers adds nothing.
 */
export function focusCrops(text: string, offsets: readonly number[], countTokens: (s: string) => number): string[] {
  if (text === "") return [""];
  const lines = text.split("\n");
  const lineLengths = lines.map(codePointLength);
  const textLength = lineLengths.reduce((a, b) => a + b, 0) + lines.length - 1;
  const spans: Array<[number, number]> = [];
  const out: string[] = [];
  for (const offset of offsets.length > 0 ? offsets : [0]) {
    const prefix = text.slice(0, Math.max(0, offset));
    let lineOfHit = 0;
    for (let i = prefix.indexOf("\n"); i !== -1; i = prefix.indexOf("\n", i + 1)) lineOfHit += 1;
    if (spans.some(([a, b]) => a <= lineOfHit && lineOfHit <= b)) continue;
    const at = Math.min(codePointLength(prefix), textLength - 1);
    const { crop, span } = cropAt(lines, lineLengths, at, countTokens);
    spans.push(span);
    out.push(crop);
    if (out.length >= FOCUS_MAX_CROPS) break;
  }
  return out;
}

/** One crop around code-point offset `at`. */
function cropAt(
  raw: readonly string[],
  lengths: readonly number[],
  at: number,
  countTokens: (s: string) => number,
): { crop: string; span: [number, number] } {
  let pos = 0;
  let li = raw.length - 1;
  for (let i = 0; i < raw.length; i++) {
    if (pos + lengths[i]! >= at) {
      li = i;
      break;
    }
    pos += lengths[i]! + 1;
  }
  const shown = new Map<number, string>([[li, shortenLine(raw[li]!, at - pos)]]);
  const cost = new Map<number, number>();
  const c = (i: number): number => {
    let line = shown.get(i);
    if (line === undefined) {
      line = shortenLine(raw[i]!);
      shown.set(i, line);
    }
    let n = cost.get(i);
    if (n === undefined) {
      n = countTokens(line) + 1;
      cost.set(i, n);
    }
    return n;
  };
  let lo = li;
  let hi = li;
  let used = c(li);
  let grew = true;
  while (grew) {
    grew = false;
    for (const next of [hi + 1, lo - 1]) {
      if (next >= 0 && next < raw.length && used + c(next) <= FOCUS_BUDGET) {
        used += c(next);
        lo = Math.min(lo, next);
        hi = Math.max(hi, next);
        grew = true;
      }
    }
  }
  const kept: string[] = [];
  for (let i = lo; i <= hi; i++) kept.push(shown.get(i)!);
  return { crop: kept.join("\n"), span: [lo, hi] };
}
