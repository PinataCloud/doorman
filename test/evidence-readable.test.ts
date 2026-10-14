import { readFileSync } from "node:fs";
import { createContext, runInContext } from "node:vm";
import { describe, expect, it } from "vitest";
import { callNeverRan, evidenceReadable } from "../main/lib/findings.js";

/**
 * Which rows have evidence to read: the one line the display
 * filter and the evidence judge draw between a row the app can back with a
 * document and a row it cannot — the latter is not shown.
 */

describe("evidence readable", () => {
  it("a refused or unanswered hold never ran; an allowed one, a warned one and an observed one did", () => {
    expect(callNeverRan({ enforced: "deny" })).toBe(true);
    expect(callNeverRan({ enforced: "ask" })).toBe(true);
    expect(callNeverRan({ enforced: "ask", resolution: "timeout" })).toBe(true);
    expect(callNeverRan({ enforced: "ask", resolution: "unavailable" })).toBe(true);
    expect(callNeverRan({ enforced: "ask", resolution: "allowed" })).toBe(false);
    expect(callNeverRan({ enforced: "ask", resolution: "unattended" })).toBe(false);
    expect(callNeverRan({ enforced: "warn" })).toBe(false);
    expect(callNeverRan({ enforced: "excepted" })).toBe(false);
    expect(callNeverRan({})).toBe(false);
  });

  it("only a session's transcript or a config file can be read; the rest of the rows are their own record", () => {
    expect(evidenceReadable({ origin: "guard", session_id: "s" })).toBe(true);
    expect(evidenceReadable({ origin: "transcript", session_id: "s" })).toBe(true);
    expect(evidenceReadable({ origin: "config", target: "/x/.claude.json" })).toBe(true);
    expect(evidenceReadable({ origin: "config" })).toBe(false);
    expect(evidenceReadable({ origin: "guard" })).toBe(false);
    expect(evidenceReadable({ origin: "gateway" })).toBe(false);
    expect(evidenceReadable({ origin: "integrity" })).toBe(false);
    expect(evidenceReadable({ origin: "guard", session_id: "s", enforced: "deny" })).toBe(false);
  });

  it("is mirrored exactly by the renderer (components.jsx callNeverRan)", () => {
    const babelSrc = readFileSync(new URL("../assets/vendor/babel.js", import.meta.url), "utf8");
    const ctx = createContext({ console }) as Record<string, unknown>;
    ctx.window = ctx;
    ctx.self = ctx;
    ctx.globalThis = ctx;
    runInContext(babelSrc, ctx as object, { filename: "babel.js" });
    runInContext("var React = { Fragment: 'F', createElement: function () { return null; } };", ctx as object);
    const src = readFileSync(new URL("../renderer/components.jsx", import.meta.url), "utf8");
    const { code } = (ctx.Babel as { transform: (s: string, o: object) => { code: string } }).transform(src, { presets: ["react"], filename: "components.jsx" });
    runInContext(code, ctx as object, { filename: "components.jsx" });
    const mirror = runInContext("callNeverRan", ctx as object) as (f: unknown) => boolean;
    for (const enforced of [undefined, "ask", "deny", "warn", "excepted"] as const) {
      for (const resolution of [undefined, "allowed", "denied", "timeout", "unattended", "unavailable"] as const) {
        const row = { enforced, resolution };
        expect(mirror(row), JSON.stringify(row)).toBe(callNeverRan(row));
      }
    }
  });
});
