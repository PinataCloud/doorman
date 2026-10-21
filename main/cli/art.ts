import type { Styles } from "./output.js";
import type { Ui } from "./ui.js";

/**
 * The Doorman mark in ASCII: the piñata llama in its doorman's cap (plume,
 * cap and visor, eye, snout, collar and tie, buttons, tail, legs), and the
 * wordmark. Pure ASCII so it renders in every console and font; colour only
 * on a terminal that decorates (ui.ts). Each line has a paint line beside it:
 * one letter per character naming its hue.
 *
 *   c cyan (plume)  b bold (cap)  p pink (snout, legs)  u accent purple (tail)
 *   y warn yellow (buttons)  space: as is
 */

type Paint = "c" | "b" | "p" | "u" | "y" | " ";

const LLAMA: readonly (readonly [art: string, paint: string])[] = [
  ["           //", "           cc"],
  ["        __//__", "        bbccbb"],
  ["       [______]=-", "       bbbbbbbbbb"],
  ["        | o  (__)", "             pppp"],
  ["        |   ___/", ""],
  ["  @     |\\V/|", "  u"],
  ["   \\____| : |", "   u      y"],
  ["   |      : |", "          y"],
  ["   |________|", ""],
  ["    |_|  |_|", "    ppp  ppp"],
];

/** The three-line mark: plume, cap, face. */
const MARK: readonly (readonly [art: string, paint: string])[] = [
  ["    //", "    cc"],
  [" [____]=-", " bbbbbbbb"],
  ["  |o (__)", "     pppp"],
];

/** "doorman" in figlet's `small` font. */
const WORDMARK: readonly string[] = [
  "    _",
  " __| |___  ___ _ _ _ __  __ _ _ _",
  "/ _` / _ \\/ _ \\ '_| '  \\/ _` | ' \\",
  "\\__,_\\___/\\___/_| |_|_|_\\__,_|_||_|",
];

function painted(s: Styles, art: string, paint: string): string {
  const hue = (p: Paint, text: string): string => {
    if (p === "c") return s.cyan(text);
    if (p === "b") return s.bold(text);
    if (p === "p") return s.pink(text);
    if (p === "u") return s.accent(text);
    if (p === "y") return s.warn(text);
    return text;
  };
  let out = "";
  let run = "";
  let runPaint: Paint = " ";
  for (let i = 0; i < art.length; i++) {
    const p = (paint[i] ?? " ") as Paint;
    if (p !== runPaint) {
      out += hue(runPaint, run);
      run = "";
      runPaint = p;
    }
    run += art[i];
  }
  return out + hue(runPaint, run);
}

/** Art blocks side by side: `left` padded to its widest line, then `right`. */
function beside(left: readonly (readonly [string, string])[], right: readonly string[], s: Styles, gap: number, top = 0): string[] {
  const width = Math.max(...left.map(([a]) => a.length));
  const rows = Math.max(left.length, right.length + top);
  const out: string[] = [];
  for (let i = 0; i < rows; i++) {
    const [art, paint] = left[i] ?? ["", ""];
    const r = right[i - top];
    out.push(r === undefined || r === "" ? painted(s, art, paint).trimEnd() : `${painted(s, art, paint)}${" ".repeat(width - art.length + gap)}${r}`);
  }
  return out;
}

/**
 * The welcome banner for `doorman` and `doorman help`: the llama beside the
 * wordmark from 60 columns (the tagline beside it when it fits, else under
 * it), the small mark beside the name from 32, and just the name below that.
 * Plain: one line of text.
 */
export function homeBanner(ui: Ui, version: string, tagline: string): string[] {
  const s = ui.style;
  if (!ui.decorate) return [`doorman ${version}: ${tagline}.`];
  const width = ui.width ?? 80;
  const llamaWidth = Math.max(...LLAMA.map(([a]) => a.length));
  if (width >= 60) {
    const word = WORDMARK.map((l) => s.bold(s.accent(l)));
    const besideFits = llamaWidth + 4 + tagline.length <= width;
    const right = besideFits ? [...word, "", tagline, s.dim(`v${version}`)] : [...word, "", s.dim(`v${version}`)];
    return [...beside(LLAMA, right, s, 4, 2), ...(besideFits ? [] : ["", tagline])];
  }
  if (width >= 32) return [...beside(MARK, [s.bold(s.accent("doorman")), s.dim(`v${version}`)], s, 3, 1), "", ...ui.wrap(tagline, width)];
  return [`${s.bold(s.accent("doorman"))} ${s.dim(version)}`, ...ui.wrap(tagline, width)];
}

/** The small mark with a title and a subtitle beside it (the `doorman watch`
 * banner); nothing when plain or narrower than 40 columns. */
export function compactBanner(ui: Ui, title: string, subtitle: string): string[] {
  if (!ui.decorate || (ui.width ?? 80) < 40) return [];
  const s = ui.style;
  return beside(MARK, [s.bold(s.accent(title)), s.dim(subtitle)], s, 3, 1);
}

/** The small mark with `lines` beside it (the `doorman status` header, an
 * "All clear"), `top` lines down, each line fitted to the terminal; just
 * the lines, as given, when plain, and unmarked under `min` columns. */
export function markBeside(ui: Ui, lines: readonly string[], min: number, top = 0): string[] {
  if (!ui.decorate) return [...lines];
  const out = (ui.width ?? 80) < min ? lines : beside(MARK, lines, ui.style, 3, top);
  return out.map((l) => ui.fit(l));
}
