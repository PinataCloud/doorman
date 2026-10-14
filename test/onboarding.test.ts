/**
 * First-run setup — the pure decisions behind the flow.
 *
 * Same harness as renderer-logic.test.ts: the renderer is classic scripts with
 * no import/export, so the file is transpiled with the Babel it ships and
 * evaluated, then the top-level helpers are read off the context.
 *
 * What is worth testing here is exactly what the screen must not get wrong:
 * WHICH steps a given machine has (the location gate is conditional, and the
 * progress dots lie if it is counted when absent), WHAT the tools step lists
 * (installed only, covered first), and whether the last step's summary reads
 * the guard's real state rather than a local toggle.
 */

import { readFileSync } from "node:fs";
import { createContext, runInContext } from "node:vm";
import { beforeAll, describe, expect, it } from "vitest";
import { Store, defaultPrefs } from "../main/state.js";

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

let ctx: Record<string, any>;
beforeAll(() => {
  ctx = loadRenderer(["screens/onboarding.jsx"]);
});

/** A snapshot with only the slices the flow reads. */
function snapshot(over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    prefs: { guard_wanted: false },
    shadow_ai: { tools: [] },
    ...over,
  };
}

const tool = (over: Record<string, unknown> = {}) => ({
  id: "claude-code",
  name: "Claude Code",
  kind: "agent-cli",
  installed: true,
  captured: false,
  guarded: false,
  guardable: false,
  ...over,
});

describe("onboardingSteps", () => {
  it("is the four-step happy path on a machine with nothing to fix", () => {
    expect(ctx.onboardingSteps(snapshot())).toEqual(["welcome", "tools", "watching", "done"]);
  });

  it("prepends the location step when main says this copy is translocated", () => {
    const state = snapshot({ translocated: true });
    expect(ctx.onboardingSteps(state)[0]).toBe("place");
    expect(ctx.onboardingSteps(state)).toHaveLength(5);
  });

  it("does not gate on a translocated flag that is false", () => {
    expect(ctx.onboardingSteps(snapshot({ translocated: false }))[0]).toBe("welcome");
  });

  it("survives a snapshot that does not carry the flag", () => {
    // The first paint can beat the first snapshot; a missing flag is
    // "nothing to fix", never a crash.
    expect(ctx.onboardingSteps({})[0]).toBe("welcome");
  });

  it("reads main's own flag rather than re-deriving it", () => {
    expect(readFileSync(new URL("../main/state.ts", import.meta.url), "utf8")).toContain("translocated");
  });
});

describe("onboardingTools", () => {
  it("lists installed tools only", () => {
    const state = snapshot({
      shadow_ai: {
        tools: [tool(), tool({ id: "codex", name: "Codex", installed: false })],
      },
    });
    expect(ctx.onboardingTools(state).map((t: any) => t.id)).toEqual(["claude-code"]);
  });

  it("counts a captured rail and a guarded host alike as covered", () => {
    const state = snapshot({
      shadow_ai: {
        tools: [
          tool({ id: "cursor", name: "Cursor", captured: true }),
          tool({ id: "codex", name: "Codex", guarded: true }),
        ],
      },
    });
    expect(ctx.onboardingTools(state).every((t: any) => t.covered)).toBe(true);
  });

  it("orders covered first, then the ones the next step can cover, then the rest", () => {
    const state = snapshot({
      shadow_ai: {
        tools: [
          tool({ id: "ollama", name: "Ollama", kind: "local-model" }),
          tool({ id: "codex", name: "Codex", guardable: true }),
          tool({ id: "claude-code", name: "Claude Code", captured: true }),
        ],
      },
    });
    expect(ctx.onboardingTools(state).map((t: any) => t.id)).toEqual(["claude-code", "codex", "ollama"]);
  });


  it("never marks a covered tool as pending", () => {
    // `pending` is the call to action "turning warnings on wires this in".
    // A tool already covered has nothing to wait for, whatever guardable says.
    const state = snapshot({
      shadow_ai: { tools: [tool({ captured: true, guardable: true })] },
    });
    expect(ctx.onboardingTools(state)[0].pending).toBe(false);
  });

  it("is empty, not broken, when nothing is installed", () => {
    expect(ctx.onboardingTools(snapshot())).toEqual([]);
    expect(ctx.onboardingTools({})).toEqual([]);
  });
});

describe("onboardingSummary", () => {
  it("reports warnings from the guard pref, not from the screen's own answer", () => {
    // The switch calls installGuard, and installGuard is what sets
    // guard_wanted. Reading the pref back is what stops a failed install from
    // being reported as success on the final step.
    expect(ctx.onboardingSummary(snapshot()).warning).toBe(false);
    expect(ctx.onboardingSummary(snapshot({ prefs: { guard_wanted: true } })).warning).toBe(true);
  });

  it("counts only covered tools as watched", () => {
    const state = snapshot({
      shadow_ai: {
        tools: [tool({ captured: true }), tool({ id: "codex", name: "Codex", guardable: true })],
      },
    });
    const summary = ctx.onboardingSummary(state);
    expect(summary.found).toBe(2);
    expect(summary.watching).toBe(1);
  });
});

describe("the flow's contract with the rest of the app", () => {
  const source = readFileSync(new URL("screens/onboarding.jsx", rendererDir), "utf8");

  it("only calls channels the preload actually exposes", () => {
    const preload = readFileSync(new URL("../main/preload.ts", import.meta.url), "utf8");
    const called = [...source.matchAll(/window\.doorman\.([a-zA-Z]+)/g)].map((m) => m[1]!);
    expect(called.length).toBeGreaterThan(0);
    for (const name of new Set(called)) {
      expect(preload, `preload.ts exposes doorman.${name}`).toContain(`${name}:`);
    }
  });

  it("closes itself by clearing the pref main set, so re-opening stays one write", () => {
    expect(source).toContain("onboarding_open: false");
  });

  it("is registered in the renderer's load order before app.jsx uses it", () => {
    // The screens are one concatenated scope; a file missing from this list is
    // a blank window, and the packaged build reads the same list.
    const html = readFileSync(new URL("index.html", rendererDir), "utf8");
    const list = html.match(/var SCREENS = \[([^\]]*)\]/)?.[1] ?? "";
    const files = [...list.matchAll(/"([^"]+)"/g)].map((m) => m[1]!);
    expect(files).toContain("screens/onboarding.jsx");
    expect(files.indexOf("screens/onboarding.jsx")).toBeLessThan(files.indexOf("app.jsx"));
  });
});

/**
 * The main-side half: `onboarding_open` is TRI-STATE, and that is what stops
 * an upgrade from dropping someone back into setup on a machine that is
 * already reporting. `false` means "finished or skipped"; ABSENT means "this
 * install predates the flow" — and only `index.ts`'s first-boot branch (the
 * one place that can still tell a fresh install from an update) ever sets it.
 */
describe("the onboarding_open preference", () => {
  function store(persisted: Record<string, unknown> = {}) {
    return new Store({
      appVersion: "0.0.0-test",
      dataDir: "/tmp/nowhere",
      nodePlatform: "darwin",
      readPrefs: () => persisted as never,
      writePrefs: () => {},
      onChange: () => {},
    });
  }

  it("is absent by default, so no install is 'pending setup' merely for lacking it", () => {
    expect(defaultPrefs().onboarding_open).toBeUndefined();
    expect("onboarding_open" in defaultPrefs()).toBe(false);
  });

  it("stays absent when a prefs file carries no value for it", () => {
    // An existing install upgrading into this build: its prefs file has plenty
    // in it and nothing about onboarding. It must NOT read as "show setup".
    expect(store({ retention_days: 90, guard_wanted: true }).prefs().onboarding_open).toBeUndefined();
  });

  it("round-trips both booleans", () => {
    expect(store({ onboarding_open: true }).prefs().onboarding_open).toBe(true);
    expect(store({ onboarding_open: false }).prefs().onboarding_open).toBe(false);
  });

  it("ignores a non-boolean rather than treating it as truthy", () => {
    // A hand-edited or corrupted file must not open setup over a live install.
    expect(store({ onboarding_open: "yes" }).prefs().onboarding_open).toBeUndefined();
    expect(store({ onboarding_open: 1 }).prefs().onboarding_open).toBeUndefined();
  });

  it("is opened on a first boot only, and never on an update", () => {
    // The decision itself lives in index.ts's announceUpdateOutcome, which is
    // not importable here (it closes over Electron's app). Assert the shape of
    // the condition instead, so moving the branch keeps the two facts that
    // matter: it is gated on NO recorded version, and on the pref being unset.
    const index = readFileSync(new URL("../main/index.ts", import.meta.url), "utf8");
    const guard = index.match(/if \(previous === undefined && prefs\.onboarding_open === undefined\) \{\s*store\.setPrefs\(\{ onboarding_open: true \}\);/);
    expect(guard, "the first-boot branch that opens setup").not.toBeNull();
    // And it must be decided BEFORE last_run_version is recorded, or the very
    // first boot would already look like every later one.
    expect(index.indexOf("onboarding_open: true")).toBeLessThan(
      index.indexOf("store.setPrefs({ last_run_version: version"),
    );
  });
});

/**
 * Per-tool switches (the ones added on review). What is worth testing is not
 * the switch but the CONSEQUENCE: "off" has to stop the watching in all three
 * places, or the control is decoration. The engine's own scan is covered by
 * capture.test.ts; here we pin the contract each consumer relies on.
 */

