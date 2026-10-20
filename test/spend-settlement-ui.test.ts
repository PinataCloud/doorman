// Subscription vs API credits on the Mac app's Usage screen and tray
// (2026-09-04; tokens since): the token tiles ADD UP (tokens = plan +
// beyond the plan + unattributed, each with its share), the unattributed part
// is a tile of its own rather than a remainder hiding inside the total, the
// lead sentence no longer claims "none of it API credits" about tokens it
// could not attribute, and no surface prints a dollar. The pure sentence runs
// through the Babel + vm harness; the tiles are pinned at source.
import { readFileSync } from "node:fs";
import { createContext, runInContext } from "node:vm";
import { beforeAll, describe, expect, it } from "vitest";

const read = (rel: string) => readFileSync(new URL(rel, import.meta.url), "utf8");
const graphs = read("../renderer/screens/graphs.jsx");
const tray = read("../main/tray.ts");

let spendHighlight: (g: unknown) => string | null;
let shareOf: (part: number, whole: number) => string;

const base = {
  by_task: [{ task: "coding", seconds: 7200, prev_seconds: 0 }],
  window_seconds: 10_800,
  window_tokens: 12_000,
  covered_tokens: 0,
  overage_tokens: 0,
  billed_tokens: 0,
  unknown_tokens: 0,
};

beforeAll(() => {
  const sandbox: Record<string, unknown> = { console, setTimeout, clearTimeout };
  sandbox.window = sandbox;
  sandbox.self = sandbox;
  sandbox.globalThis = sandbox;
  createContext(sandbox);
  runInContext(read("../assets/vendor/babel.js"), sandbox, { filename: "babel.js" });
  const Babel = sandbox.Babel as { transform(src: string, opts: unknown): { code: string } };
  const { code } = Babel.transform(graphs, { presets: ["react"], filename: "graphs.jsx" });
  const known: Record<string, unknown> = {
    console,
    Math,
    String,
    Number,
    JSON,
    Object,
    Array,
    Date,
    Symbol,
    Promise,
    navigator: {},
    React: { createElement: () => null, Fragment: "Fragment" },
    fmtTokens: (n: number) => (n >= 1000 ? (n / 1000).toFixed(1) + "k" : String(Math.round(n))),
    fmtDur: (s: number) => Math.round(s / 3600) + "h",
    taskLabel: (t: string) => t,
  };
  const scope = new Proxy(known, {
    has: () => true,
    get: (target, key) => (key in target ? target[key as string] : key === Symbol.unscopables ? undefined : () => null),
  });
  const ctx = createContext(scope);
  runInContext(code + "\n;__out = { spendHighlight, shareOf };", ctx, { filename: "graphs.jsx" });
  const out = known.__out as Record<string, unknown>;
  spendHighlight = out.spendHighlight as typeof spendHighlight;
  shareOf = out.shareOf as typeof shareOf;
});

describe("the lead sentence", () => {
  it("leads with the tokens that ran beyond the plan when API credits were observed", () => {
    expect(spendHighlight({ ...base, overage_tokens: 3000, covered_tokens: 9000 })).toContain("3.0k of the 12.0k tokens ran on API credits.");
  });
  it("names API-key billing apart from credits — they land on different bills", () => {
    expect(spendHighlight({ ...base, billed_tokens: 4000, covered_tokens: 8000 })).toContain("4.0k of the 12.0k tokens were billed to an API key.");
    expect(spendHighlight({ ...base, overage_tokens: 3000, billed_tokens: 4000, covered_tokens: 5000 })).toContain(
      "7.0k of the 12.0k tokens ran beyond the plan — 3.0k on API credits and 4.0k billed to an API key.",
    );
  });
  it("says all on the plan only when nothing is unattributed", () => {
    expect(spendHighlight({ ...base, covered_tokens: 12_000 })).toContain("4.0k per active hour, all of it on your plan.");
  });
  it("says only the part known to be on the plan, never claiming the unattributed rest", () => {
    const s = spendHighlight({ ...base, covered_tokens: 8000, unknown_tokens: 4000 }) || "";
    expect(s).toContain("4.0k per active hour; 8.0k of it on your plan.");
    expect(s).not.toContain("all of it");
    expect(s).not.toContain("none of it API credits");
    const none = spendHighlight({ ...base, unknown_tokens: 12_000 }) || "";
    expect(none).toContain("4.0k per active hour.");
    expect(none).not.toContain("plan");
    expect(none).not.toContain("credits");
  });
  it("never prints a dollar", () => {
    for (const g of [base, { ...base, overage_tokens: 3000, billed_tokens: 4000, covered_tokens: 5000 }]) {
      expect(spendHighlight(g)).not.toContain("$");
    }
  });
});

describe("shareOf", () => {
  it("rounds to whole percents and never shows real usage as 0%", () => {
    expect(shareOf(3, 12)).toBe("25%");
    expect(shareOf(0.01, 12)).toBe("<1%");
    expect(shareOf(0, 12)).toBe("0%");
    expect(shareOf(5, 0)).toBe("0%");
  });
});

describe("the token tiles", () => {
  it("are the window's tokens and today's — no settlement tiles, no settlement chart", () => {
    // The plan / API credits / unattributed split only carries information
    // when a host reports how a turn settled, and Claude Code's transcript
    // reports nothing — so it was three tiles restating "unattributed". It
    // stays only where it is silent when uninformative: the highlight
    // sentence, the ledger's per-session line and the tray's 7d row.
    const order = ['label="Tokens"', 'label="Today"'].map((k) => graphs.indexOf(k));
    expect(order.every((i) => i > 0)).toBe(true);
    expect([...order].sort((a, b) => a - b)).toEqual(order);
    for (const gone of ['label="Covered by plan"', 'label="Unattributed"', "On API credits", "settleSeries", 'hint="How each day settled', "shareOf(g.covered_tokens", "shareOf(g.unknown_tokens"]) {
      expect(graphs, gone).not.toContain(gone);
    }
    // The split still speaks in the sentence, the ledger and the tray.
    expect(graphs).toContain('text(" tokens ran on API credits.");');
    expect(read("../renderer/screens/ledger.jsx")).toContain('{ key: "a", label: "API key", value: summary.billed_tokens || 0, color: "var(--ink-3)" }');
    expect(tray).toContain("billed to an API key");
    // Today is its own tile, with its unit named, and the hero note keeps the rate.
    expect(graphs).toContain('num={fmtTokens(g.today_tokens) + " tokens"}');
    expect(graphs).toContain('" tokens per active hour"');
  });

  it("show no dollar anywhere on the screen", () => {
    // No dollar formatter exists in the renderer any more, and no screen
    // reaches for a *_cost field: the priced twins stay in the fold for the
    // engine, never on a tile.
    const components = read("../renderer/components.jsx");
    expect(components).not.toContain("fmtUsd");
    for (const file of ["graphs", "ledger", "analytics", "integrations"]) {
      const src = read(`../renderer/screens/${file}.jsx`);
      expect(src, file).not.toMatch(/fmtUsd|_cost\b|burned_usd|at API rates/);
    }
    expect(read("../renderer/ai.jsx")).not.toMatch(/aiUsd|\$0\.00/);
  });
});

describe("the tray", () => {
  it("says tokens, never dollars, and shows the split once anything is attributed", () => {
    expect(tray).toContain("tokens`,");
    expect(tray).not.toMatch(/formatTrayCost|formatUsd|at API rates|_cost\b/);
    expect(tray).toContain("state.graphs.covered_tokens > 0 || state.graphs.overage_tokens > 0");
    expect(tray).toContain("plan · ${formatTokens(state.graphs.overage_tokens)} API credits");
    expect(tray).toContain("on API credits`);");
  });
});
