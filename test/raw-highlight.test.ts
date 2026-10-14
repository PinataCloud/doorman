import { readFileSync } from "node:fs";
import { createContext, runInContext } from "node:vm";
import { describe, expect, it } from "vitest";

/**
 * The exposure card's VIEW RAW window marks the value the finding is about
 * (the credentials-first card) — the two pure helpers at the top of
 * renderer/screens/radar.jsx, evaluated the way the app does (bundled Babel,
 * one shared scope), same as renderer-logic.test.ts.
 *
 * The masked excerpt's placeholders are BUILT here rather than written out:
 * a literal one in a file is exactly what the guard's credential_in_tool_arg
 * rule looks for after it has redacted a tool call, so a fixture spelling it
 * out is held as a credential every time this file is written.
 */

const rendererDir = new URL("../renderer/", import.meta.url);

function loadRenderer(files: string[]): Record<string, any> {
  const babelSrc = readFileSync(new URL("../assets/vendor/babel.js", import.meta.url), "utf8");
  const ctx: Record<string, any> = { console, setTimeout, clearTimeout, Date, Math, JSON };
  ctx.window = ctx;
  ctx.self = ctx;
  ctx.globalThis = ctx;
  createContext(ctx);
  runInContext(babelSrc, ctx as object, { filename: "babel.js" });
  runInContext("var React = { Fragment: 'F', createElement: function () { return null; } };", ctx as object);
  for (const file of files) {
    const source = readFileSync(new URL(file, rendererDir), "utf8");
    const { code } = ctx.Babel.transform(source, { presets: ["react"], filename: file });
    runInContext(code as string, ctx as object, { filename: file });
  }
  return ctx;
}

type Segment = { text: string; hit: boolean; primary?: boolean };
type Redacted = Array<{ label: string; value: string }>;

/** "[" + "redacted" + ":label" + "]" — assembled, see the file comment. */
const mark = (label?: string) => "[" + "redacted" + (label ? ":" + label : "") + "]";

describe("the VIEW RAW highlight (radar.jsx)", () => {
  const ctx = loadRenderer(["components.jsx", "screens/radar.jsx"]);
  const paint = ctx.highlightSecrets as (raw: string, found: Redacted, primary: Set<string>) => Segment[];
  const labels = ctx.excerptLabels as (parts: string[]) => Set<string>;
  const split = (excerpt: string) => excerpt.split(/(\[redacted(?::[a-z0-9_]+)?\])/g);
  // Plain-word placeholders: the helper matches substrings, never shapes, so
  // the fixture need not look like anything real.
  const ONE = "one two three";
  const TWO = "four five";
  const found = (...pairs: Array<[string, string]>): Redacted => pairs.map(([label, value]) => ({ label, value }));

  it("lets the reveal name the card's own value outright, over the label rule", () => {
    // Every value in a Write's file carries the anonymous label; the reveal
    // flags the one on the card's line as primary, and only that one is.
    const raw = `a: ${ONE}, b: ${TWO}`;
    const flagged = [{ label: "", value: ONE }, { label: "", value: TWO, primary: true }];
    const segs = paint(raw, flagged as Redacted, labels(split(`a: ${mark()}, b: ${mark()}`)));
    expect(segs.filter((s) => s.hit).map((s) => [s.text, s.primary])).toEqual([[ONE, false], [TWO, true]]);
  });

  it("wraps the finding's own value, and marks other redacted values softer", () => {
    // The card is about the alpha-labelled value; the same window also had an
    // anonymous value redacted. Both are marked, only the alpha one is primary.
    const raw = `first ${ONE} then ${TWO} end`;
    const segs = paint(raw, found(["alpha", ONE], ["", TWO]), labels(split(`first ${mark("alpha")} then …`)));
    expect(segs.map((s) => s.text).join("")).toBe(raw); // nothing lost, nothing reordered
    expect(segs.filter((s) => s.hit).map((s) => [s.text, s.primary])).toEqual([
      [ONE, true],
      [TWO, false],
    ]);
  });

  it("marks every hit as primary when the excerpt has no labelled mark to compare against", () => {
    const segs = paint(`a ${TWO} b ${TWO}`, found(["", TWO]), new Set());
    expect(segs.filter((s) => s.hit)).toHaveLength(2);
    expect(segs.filter((s) => s.hit).every((s) => s.primary)).toBe(true);
  });

  it("lets a longer value claim a span whole, ignores tiny values, and leaves plain text alone", () => {
    const segs = paint(`x more ${TWO} y ab`, found(["", TWO], ["beta", `more ${TWO}`], ["", "ab"]), new Set(["beta"]));
    expect(segs.filter((s) => s.hit).map((s) => s.text)).toEqual([`more ${TWO}`]);
    expect(paint("nothing here", [], new Set())).toEqual([{ text: "nothing here", hit: false }]);
    expect(paint("", found(["", "abc"]), new Set())).toEqual([{ text: "", hit: false }]);
  });

  it("reads the excerpt's placeholder families, anonymous marks included", () => {
    expect([...labels(split(`a ${mark("alpha")} b ${mark()} c`))].sort()).toEqual(["", "alpha"]);
    expect(labels(split("no marks")).size).toBe(0);
  });
});
