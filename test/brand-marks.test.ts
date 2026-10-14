import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { SHADOW_AI_CATALOG } from "../main/lib/shadow-ai.js";
import { allSourceLabels } from "../main/lib/transcript-sources-registry.js";

/**
 * The brand-mark registry in the renderer (components.jsx): `RAIL_MARKS` holds
 * the drawable marks, `RAIL_BRAND` maps a ledger source to one, `TOOL_BRAND`
 * maps a coverage-card catalog id to one. Three things can silently rot: a
 * mapping to a brand nobody drew (the row renders nothing and no test notices),
 * a mapping keyed by an id that no longer exists (dead weight the next reader
 * trusts), and a host that ships without its mark (Hermes Agent and OpenClaw
 * did, for a day). Static over the source, because the renderer is classic
 * scripts sharing one global scope and these are plain object literals.
 */
const src = readFileSync(new URL("../renderer/components.jsx", import.meta.url), "utf8");

function block(name: string): string {
  const m = new RegExp(`const ${name} = \\{([\\s\\S]*?)\\n\\};`).exec(src);
  if (!m) throw new Error(`${name} not found in components.jsx`);
  return m[1]!;
}

/** Brands the registry can draw: every `key: { color: "#…"` row, plus the
 * Cursor cube, which RailMark/ToolMark draw inline as strokes. */
const drawable = new Set([
  ...[...block("RAIL_MARKS").matchAll(/^\s{2}([a-z0-9]+): \{ color: "#[0-9A-Fa-f]{6}"/gm)].map((m) => m[1]!),
  "cursor",
]);
const pairs = (name: string): Array<[string, string]> =>
  [...block(name).matchAll(/^\s{2}"?([\w-]+)"?: "([a-z0-9]+)",/gm)].map((m) => [m[1]!, m[2]!]);
const railBrand = pairs("RAIL_BRAND");
const toolBrand = pairs("TOOL_BRAND"); // own rows only — the `...RAIL_BRAND` spread is not a row

describe("the brand-mark registry", () => {
  it("draws every brand a rail or a tool is mapped to", () => {
    for (const [id, brand] of [...railBrand, ...toolBrand]) {
      expect(drawable.has(brand), `${id} → ${brand}: no such mark in RAIL_MARKS`).toBe(true);
    }
  });

  it("keys every rail mark by a source the ledger can hold", () => {
    const sources = new Set(allSourceLabels().map((s) => s.id as string));
    for (const [id] of railBrand) expect(sources.has(id), `RAIL_BRAND["${id}"] names no ledger source`).toBe(true);
  });

  it("keys every tool mark by a coverage-card catalog id", () => {
    const ids = new Set(SHADOW_AI_CATALOG.map((e) => e.id));
    for (const [id] of toolBrand) expect(ids.has(id), `TOOL_BRAND["${id}"] names no catalog entry`).toBe(true);
  });

  /**
   * The seven catalog rows that still wear no mark. Each publishes no vector
   * any permissively-licensed set carries — checked 2026-09-08 against
   * simple-icons, LobeHub's lobe-icons, thesvg and gilbarbara/logos — and the
   * card's rule is that a tool with no honest mark shows its name and its state
   * dot, never a monogram standing in for a logo. Pinned so a NEW catalog entry
   * has to arrive either with its mark or with a deliberate line here.
   */
  const UNMARKED = ["aider", "crush", "dia", "factory-droid", "jan", "msty", "superwhisper"];

  it("gives every tool on the coverage card its mark, or names why it has none", () => {
    const marked = new Set([...railBrand, ...toolBrand].map(([id]) => id));
    const bare = SHADOW_AI_CATALOG.map((e) => e.id)
      .filter((id) => !marked.has(id))
      .sort();
    expect(bare).toEqual(UNMARKED);
  });

  it("gives Hermes Agent and OpenClaw their makers' marks on both screens", () => {
    // Both ids are at once a TurnSource (the ledger's rail chip) and a catalog
    // id (the coverage row), so one RAIL_BRAND entry serves both — TOOL_BRAND
    // spreads it. Nous Research stands for Hermes Agent the way Alibaba Cloud
    // stands for Qwen Code: the maker's mark, not an invented one.
    const rail = Object.fromEntries(railBrand);
    expect(rail.hermes).toBe("nousresearch");
    expect(rail.openclaw).toBe("openclaw");
    // Both are even-odd drawings (rings that are holes), and the registry has
    // to say so or the nonzero default fills the lobster's eyes solid.
    expect(src).toMatch(/nousresearch: \{ color: "#0A0A0A", fillRule: "evenodd", path: "M5\.938 12\.835/);
    expect(src).toMatch(/openclaw: \{ color: "#CC3434", fillRule: "evenodd", path: "M9\.046 7\.104/);
    // ...and every registry-drawn <path> carries the flag through.
    expect(src.match(/<path d=\{mark\.path\} fillRule=\{mark\.fillRule\} \/>/g)).toHaveLength(3);
  });
});
