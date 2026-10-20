import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

/**
 * THIS MAC — the whole-machine subject. A "How to fix this?" drawer opened
 * with no reference must still be framed from this machine: main resolves a
 * MISSING reference (and the machine kind) into `machineContext`, and the
 * drawer has starter questions for it. Static, because none of it is visible
 * to a test that doesn't mount the renderer.
 */
const read = (rel: string) => readFileSync(new URL(rel, import.meta.url), "utf8");

describe("the whole-machine subject", () => {
  it("main resolves the machine kind AND a missing reference into the machine context", () => {
    const main = read("../main/index.ts");
    expect(main).toMatch(/r\.kind === "machine" \|\| r\.kind === undefined/);
    expect(main).toContain("return machineContext({");
    expect(main).toContain("coverage: {");
    expect(main).toContain("platform: snapshot.platform,");
    expect(read("../main/ai-assistant.ts")).toContain("AI TOOLS ON THIS COMPUTER");
  });

  it("the drawer has starter questions for it", () => {
    const drawer = read("../renderer/ai.jsx");
    expect(drawer).toMatch(/^\s*machine: \[/m);
  });
});
