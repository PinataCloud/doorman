// The "Act on it" row under the "How to fix this?" prompt in the Mac app: the
// actions a question about this subject most often ends in, derived from the
// LIVE snapshot, each one existing IPC and
// still the person's click. What these pin: the per-subject sets, that an
// action already taken stops being offered, that a resolved hold offers
// nothing, that Deny precedes Allow, and that each `run` reaches the bridge
// with the arguments the screens themselves send.
//
// Harness: transpile the .jsx with the bundled Babel the app loads, evaluate it against a proxied global, and call
// the top-level helper directly.
import { readFileSync } from "node:fs";
import { createContext, runInContext } from "node:vm";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";

interface Action {
  id: string;
  label: string;
  done: string | null;
  run(): unknown;
}

const read = (rel: string) => readFileSync(new URL(rel, import.meta.url), "utf8");

let aiActionsFor: (kind: string, ref: unknown, state: unknown, nav?: unknown) => Action[];
const calls: Array<[string, ...unknown[]]> = [];

beforeAll(() => {
  const sandbox: Record<string, unknown> = { console, setTimeout, clearTimeout };
  sandbox.window = sandbox;
  sandbox.self = sandbox;
  sandbox.globalThis = sandbox;
  createContext(sandbox);
  runInContext(read("../assets/vendor/babel.js"), sandbox, { filename: "babel.js" });
  const Babel = sandbox.Babel as { transform(src: string, opts: unknown): { code: string } };
  const { code } = Babel.transform(read("../renderer/ai.jsx"), { presets: ["react"], filename: "ai.jsx" });

  const record = (name: string) => (...args: unknown[]) => {
    calls.push([name, ...args]);
    return Promise.resolve({ ok: true });
  };
  const known: Record<string, unknown> = {
    console,
    React: { createElement: () => null, Fragment: "Fragment" },
    doorman: {
      setFindingStatus: record("setFindingStatus"),
      setFindingStatusBulk: record("setFindingStatusBulk"),
      setDetectorMode: record("setDetectorMode"),
      resolveApproval: record("resolveApproval"),
      recognizeMcpServer: record("recognizeMcpServer"),
    },
    // The renderer's rule table (components.jsx): built-in rules the guard can
    // enforce, and radar-only flow rules that can't change mode.
    SEC_DETECTORS: {
      secret_egress: { label: "Secret egress" },
      injected_then_acted: { label: "Injection, then acted on", radarOnly: true },
    },
  };
  known.window = known;
  const StubComponent = function StubComponent() {
    return null;
  };
  const proxied = new Proxy(known, {
    has: () => true,
    get: (target, key) => {
      if (typeof key === "symbol") return undefined;
      const name = key as string;
      if (name in target) return target[name];
      if (name in globalThis) return (globalThis as Record<string, unknown>)[name];
      return StubComponent;
    },
  });
  runInContext(code, createContext(proxied as object), { filename: "ai.jsx" });
  aiActionsFor = known.aiActionsFor as typeof aiActionsFor;
  expect(typeof aiActionsFor).toBe("function");
});

beforeEach(() => {
  calls.length = 0;
});

const state = {
  radar: {
    findings: [
      { finding_id: "f1", detector: "secret_egress", status: "open", exposure_key: "e1" },
      { finding_id: "f2", detector: "secret_egress", status: "open", exposure_key: "e1" },
      { finding_id: "f3", detector: "secret_egress", status: "resolved", exposure_key: "e1" },
      { finding_id: "f4", detector: "injected_then_acted", status: "false_positive", exposure_key: "e2" },
      { finding_id: "f5", detector: "custom:mine", status: "open", exposure_key: "e3" },
    ],
  },
  prefs: { policy: { modes: { secret_egress: "observe" } } },
  approvals: [{ id: "a1" }],
  mcp: { servers: [{ name: "GitHub", recognized: false }, { name: "slack", recognized: true }, { name: "stale", recognized: true, recognized_stale: true }] },
};

describe("aiActionsFor", () => {
  it("offers nothing without a subject or a snapshot", () => {
    expect(aiActionsFor("finding", null, state)).toEqual([]);
    expect(aiActionsFor("finding", { finding_id: "f1" }, null)).toEqual([]);
    expect(aiActionsFor("finding", { finding_id: "nope" }, state)).toEqual([]);
    expect(aiActionsFor("spend", { days: 7 }, state)).toEqual([]);
    expect(aiActionsFor("machine", {}, state)).toEqual([]);
  });

  it("a finding: triage statuses it is NOT already in, plus holding an enforceable rule that only watches", async () => {
    const actions = aiActionsFor("finding", { finding_id: "f1" }, state);
    expect(actions.map((a) => a.label)).toEqual([
      "False positive",
      "Accept risk",
      "Resolved",
      "Set this rule to Ask",
    ]);
    await actions[0]!.run();
    await actions[3]!.run();
    expect(calls).toEqual([
      ["setFindingStatus", "f1", "false_positive"],
      ["setDetectorMode", "secret_egress", "ask"],
    ]);
  });

  it("an already-triaged finding offers Reopen instead of its own status, and a radar-only or custom rule offers no mode change", () => {
    const labels = (id: string) => aiActionsFor("finding", { finding_id: id }, state).map((a) => a.label);
    expect(labels("f4")).toEqual(["Accept risk", "Resolved", "Reopen"]);
    expect(labels("f5")).toEqual(["False positive", "Accept risk", "Resolved"]);
  });

  it("an exposure triages every open sighting under it in one bulk call — the same rows the Radar card acts on", async () => {
    const actions = aiActionsFor("exposure", { finding_id: "f1" }, state);
    expect(actions[0]!.label).toBe("False positive");
    expect(actions[0]!.done).toBe("Marked 2 sightings false positive");
    await actions[0]!.run();
    // f3 is already triaged — a different bucket, left alone.
    expect(calls).toEqual([["setFindingStatusBulk", ["f1", "f2"], "false_positive"]]);
  });

  it("a held call: Deny before Allow, both through the window's own path; nothing once it is answered", async () => {
    const actions = aiActionsFor("approval", { approval_id: "a1" }, state);
    expect(actions.map((a) => a.label)).toEqual(["Deny", "Allow once"]);
    await actions[0]!.run();
    await actions[1]!.run();
    expect(calls).toEqual([
      ["resolveApproval", "a1", "deny", { via: "window" }],
      ["resolveApproval", "a1", "allow", { via: "window" }],
    ]);
    expect(aiActionsFor("approval", { approval_id: "gone" }, state)).toEqual([]);
  });

  it("an MCP server: no recognize / un-recognize while the MCP-servers rules are hidden", () => {
    // Recognizing a server answers the unapproved-server rule; with that
    // family hidden (components.jsx HIDDEN_RULES) the review offers nothing,
    // whatever the server's standing. The routing action is a setting rather
    // than a verdict and is unaffected — none of these has a stdio config, so
    // none is offered here.
    for (const server of ["github", "slack", "stale"]) {
      expect(aiActionsFor("mcp_server", { server }, state).map((a) => a.label), server).toEqual([]);
    }
    expect(calls).toEqual([]);
  });

  it("a rule: the two modes it is not in; none for a rule the guard cannot enforce", async () => {
    const actions = aiActionsFor("rule", { detector: "secret_egress", days: 14 }, state);
    expect(actions.map((a) => a.label)).toEqual(["Hold and ask", "Block outright"]);
    await actions[1]!.run();
    expect(calls).toEqual([["setDetectorMode", "secret_egress", "block"]]);
    expect(aiActionsFor("rule", { detector: "injected_then_acted" }, state)).toEqual([]);
    expect(aiActionsFor("rule", { detector: "custom:mine" }, state)).toEqual([]);
  });

  it("a session: the one thing to do is open it, through the navigation the root hands in", async () => {
    const opened: string[] = [];
    const actions = aiActionsFor("session", { session_id: "s9" }, state, { openSession: (id: string) => opened.push(id) });
    expect(actions.map((a) => a.label)).toEqual(["Open in the Event Ledger"]);
    await actions[0]!.run();
    expect(opened).toEqual(["s9"]);
    expect(calls).toEqual([]);
    // No navigation available → no dead button.
    expect(aiActionsFor("session", { session_id: "s9" }, state)).toEqual([]);
  });
});
