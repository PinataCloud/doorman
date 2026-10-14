import { readFileSync } from "node:fs";
import { createContext, runInContext } from "node:vm";
import { describe, expect, it } from "vitest";
import { HIDDEN_SURFACES, surfaceShown } from "../main/lib/surface-scope.js";

/**
 * Surfaces held back for now (lib/surface-scope.ts) and the MCP servers card,
 * which follows its rule family (guard/rule-scope.ts). Pinned at the
 * source: the renderer mirror, and that each card or row mounts behind its gate.
 */

const read = (rel: string) => readFileSync(new URL(`../${rel}`, import.meta.url), "utf8");

function loadComponents(): Record<string, any> {
  const babelSrc = readFileSync(new URL("../assets/vendor/babel.js", import.meta.url), "utf8");
  const ctx: Record<string, any> = { console, setTimeout, clearTimeout, Date, Math, JSON };
  ctx.window = ctx;
  ctx.self = ctx;
  ctx.globalThis = ctx;
  createContext(ctx);
  runInContext(babelSrc, ctx as object, { filename: "babel.js" });
  runInContext("var React = { Fragment: 'F', createElement: function () { return null; } };", ctx as object);
  const { code } = ctx.Babel.transform(read("renderer/components.jsx"), { presets: ["react"], filename: "components.jsx" });
  runInContext(code as string, ctx as object, { filename: "components.jsx" });
  return ctx;
}

describe("surface scope", () => {
  it("hides the editor card and the digests", () => {
    expect([...HIDDEN_SURFACES].sort()).toEqual(["digests", "editor_extension"]);
    expect(surfaceShown("digests")).toBe(false);
  });

  it("is mirrored exactly by the renderer (components.jsx HIDDEN_SURFACES)", () => {
    const mirror = runInContext("[...HIDDEN_SURFACES]", loadComponents() as object) as string[];
    expect([...mirror].sort()).toEqual([...HIDDEN_SURFACES].sort());
  });

  it("mounts each hidden card and row behind its gate", () => {
    const integrations = read("renderer/screens/integrations.jsx");
    expect(integrations).not.toContain("BrowserGuardCard");
    expect(integrations).toContain('{surfaceShown("editor_extension") ? <EditorExtensionCard');
    // The MCP servers card follows the MCP rule family, which is hidden.
    expect(integrations).toContain("{mcpFamilyShown() ? <McpInventoryCard");
    const settings = read("renderer/screens/settings.jsx");
    const gate = settings.indexOf('surfaceShown("digests")');
    expect(gate).toBeGreaterThan(-1);
    for (const row of ['title="Security digest"', 'title="Usage digest"', 'ariaLabel="Startup digest"']) {
      expect(settings.indexOf(row), `${row} sits under the digests gate`).toBeGreaterThan(gate);
    }
  });

  it("pauses the digests while they are hidden, and the notification facts say so", () => {
    const index = read("main/index.ts");
    expect(index).toContain("prefs: () => notificationPrefs(store.prefs())");
    expect(index).toContain("if (!notificationPrefs(store.prefs()).notify_startup_digest)");
    expect(index).toContain("const prefs = notificationPrefs(store.prefs());");
  });
});
