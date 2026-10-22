import { describe, expect, it } from "vitest";
import { fitPanelBounds } from "../main/lib/panel-fit.js";

// A 1440×900 display whose work area starts under a 25px menu bar.
const work = { x: 0, y: 25, width: 1440, height: 875 };
const placed = { x: 964, y: 41, width: 460, height: 336 };

describe("the floating approval panel's window follows its card", () => {
  it("grows to a card taller than the first paint, keeping its place", () => {
    expect(fitPanelBounds(placed, 471.4, work, 16, 160)).toEqual({ x: 964, y: 41, width: 460, height: 472 });
  });

  it("shrinks to a short card, but not below the minimum", () => {
    expect(fitPanelBounds(placed, 240, work, 16, 160).height).toBe(240);
    expect(fitPanelBounds(placed, 40, work, 16, 160).height).toBe(160);
  });

  it("never grows past the work area: the card scrolls instead", () => {
    expect(fitPanelBounds(placed, 5000, work, 16, 160)).toEqual({ x: 964, y: 41, width: 460, height: 843 });
  });

  it("moves up rather than running off the bottom when dragged low", () => {
    const low = { ...placed, y: 700 };
    const fit = fitPanelBounds(low, 400, work, 16, 160);
    expect(fit.height).toBe(400);
    expect(fit.y + fit.height).toBe(work.y + work.height - 16);
  });
});
