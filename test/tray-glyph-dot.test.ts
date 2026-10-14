/**
 * The menu-bar mark's status dot (lib/tray-glyph.ts `dot`): drawn in its own
 * colour in the bottom-right corner, with a clear ring knocked out of the mark
 * so it reads as a dot ON the mark rather than a smudge in it. No dot = the
 * template mark, black with alpha only, exactly as before.
 */
import { describe, expect, it } from "vitest";
import { inkCoverage, renderTrayGlyph } from "../main/lib/tray-glyph.js";

const px = (g: { bitmap: Buffer; width: number }, x: number, y: number) => {
  const i = (y * g.width + x) * 4;
  return { b: g.bitmap[i]!, g: g.bitmap[i + 1]!, r: g.bitmap[i + 2]!, a: g.bitmap[i + 3]! };
};

describe("renderTrayGlyph status dot", () => {
  it("stays black-with-alpha without options (the template image)", () => {
    const g = renderTrayGlyph(32);
    for (let i = 0; i < g.bitmap.length; i += 4) {
      expect(g.bitmap[i]).toBe(0);
      expect(g.bitmap[i + 1]).toBe(0);
      expect(g.bitmap[i + 2]).toBe(0);
    }
  });

  it("paints the dot in its colour at the bottom-right, ringed by clear pixels", () => {
    const g = renderTrayGlyph(64, { ink: [0, 0, 0], dot: [52, 168, 83] });
    // The dot's centre (12.9/16 of the box) in a 64px raster.
    const centre = px(g, Math.round((12.9 / 16) * 64), Math.round((12.9 / 16) * 64));
    expect(centre.a).toBe(255);
    expect(centre.g).toBeGreaterThan(centre.r);
    expect(centre.g).toBeGreaterThan(centre.b);
    // Just outside the dot, inside the ring, to its left — where the mark's
    // front leg is ink in the plain glyph: cleared, so the dot has an edge.
    const ringR = 3.1 + 0.5;
    const ringX = Math.round(((12.9 - ringR) / 16) * 64);
    const ringY = Math.round((12.9 / 16) * 64);
    expect(px(g, ringX, ringY).a).toBe(0);
    const plain = renderTrayGlyph(64);
    expect(px(plain, ringX, ringY).a).toBeGreaterThan(0);
  });

  it("draws the mark white when asked, for a dark menu bar", () => {
    const g = renderTrayGlyph(64, { ink: [255, 255, 255], dot: [52, 168, 83] });
    // The body, mid-left of centre, is ink in the plain mark.
    const p = px(g, 28, 38);
    expect(p.a).toBeGreaterThan(0);
    expect(p.r).toBe(p.a);
    expect(p.g).toBe(p.a);
    expect(p.b).toBe(p.a);
  });

  it("takes its shape from the brand mark: ink on the body, none in the corners", () => {
    expect(inkCoverage(7, 9.5)).toBeGreaterThan(0.9);
    for (const [x, y] of [[0.2, 0.2], [15.8, 0.2], [0.2, 15.8]]) expect(inkCoverage(x!, y!)).toBe(0);
  });
});
