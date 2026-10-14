import { describe, expect, it } from "vitest";
import { aggregateGraphs, utcDays } from "../main/lib/spend.js";
import type { LedgerTurn } from "../main/lib/turns.js";

/** Mid-day UTC so a day-boundary bug shows up. */
const NOW = new Date(Date.UTC(2026, 7, 20, 12, 0, 0));

const assistant = (over: Partial<LedgerTurn>): LedgerTurn => ({
  id: Math.random().toString(36).slice(2),
  source: "claude-code",
  session_id: "s1",
  role: "assistant",
  at: "2026-08-20T10:00:00.000Z",
  model: "m1",
  cost: 1,
  ...over,
});

/** input+output only; cache buckets deliberately noisy so a fold that counted
 * them would fail. */
const usage = (tokens: number): LedgerTurn["usage"] => ({
  input_tokens: tokens,
  output_tokens: 0,
  cache_read_tokens: 9999,
  cache_write_tokens: 9999,
  cache_write_1h_tokens: 0,
  web_search_requests: 0,
});

describe("utcDays", () => {
  it("yields UTC day keys oldest-first ending today", () => {
    expect(utcDays(NOW, 3)).toEqual(["2026-08-18", "2026-08-19", "2026-08-20"]);
  });
});

describe("aggregateGraphs", () => {
  it("splits window spend by task when a taskOf lookup is supplied", () => {
    const turns: LedgerTurn[] = [
      assistant({ session_id: "s1", cost: 3 }),
      assistant({ session_id: "s2", cost: 1 }),
    ];
    const taskOf = (id: string) => (id === "s1" ? "coding" : "research");
    const g = aggregateGraphs(turns, NOW, 7, taskOf);
    // Project only the split fields this test owns — by_task carries extra
    // time fields (seconds/…) owned by the active-time aggregation.
    expect(g.by_task.map((t) => ({ task: t.task, cost: t.cost, tokens: t.tokens, sessions: t.sessions }))).toEqual([
      { task: "coding", cost: 3, tokens: 0, sessions: 1 },
      { task: "research", cost: 1, tokens: 0, sessions: 1 },
    ]);
    // No lookup → no breakdown, existing callers unaffected.
    expect(aggregateGraphs(turns, NOW, 7).by_task).toEqual([]);
  });

  it("buckets by UTC day and consolidates past the top 5 into other, ranked by tokens", () => {
    const turns: LedgerTurn[] = [];
    for (let i = 0; i < 7; i += 1) {
      // m0 has the most TOKENS but the least cost: the rank — and so the
      // legend, the share table and the "other" fold — follows tokens, the
      // figure the screens show, never the priced twin.
      turns.push(assistant({ model: `m${i}`, cost: 1 + i, usage: usage((7 - i) * 100) }));
    }
    const g = aggregateGraphs(turns, NOW);
    expect(g.models).toEqual(["m0", "m1", "m2", "m3", "m4", "other"]);
    expect(g.model_rows.map((r) => r.model)).toEqual(["m0", "m1", "m2", "m3", "m4", "other"]);
    expect(g.model_rows[0]).toMatchObject({ model: "m0", tokens: 700, cost: 1 });
    const today = g.token_days[g.token_days.length - 1]!;
    expect(today.by_model.other).toBe(200 + 100); // m5 + m6
    expect(g.cost_days[g.cost_days.length - 1]!.by_model.other).toBeCloseTo(6 + 7);
    expect(g.window_tokens).toBe(2800);
    expect(g.today_tokens).toBe(g.window_tokens);
    expect(g.window_cost).toBeCloseTo(1 + 2 + 3 + 4 + 5 + 6 + 7);
    expect(g.today_cost).toBeCloseTo(g.window_cost);
  });

  it("keeps tokens to input+output and excludes prompts and out-of-window turns", () => {
    const g = aggregateGraphs(
      [
        assistant({
          usage: { input_tokens: 100, output_tokens: 50, cache_read_tokens: 9999, cache_write_tokens: 9999, cache_write_1h_tokens: 0, web_search_requests: 0 },
        }),
        assistant({ at: "2026-08-01T10:00:00.000Z", cost: 100 }), // before the window
        { ...assistant({}), role: "user" as const, cost: undefined },
      ],
      NOW,
    );
    expect(g.window_tokens).toBe(150);
    expect(g.window_cost).toBeCloseTo(1);
  });

  it("counts LOCAL-day today, including a late evening past the UTC boundary", () => {
    // Built from LOCAL date components so the assertion holds in any timezone:
    // in a negative-offset zone the 23:00 turn lands in UTC-tomorrow — outside
    // the chart window entirely — and must still be part of "today".
    const now = new Date(2026, 7, 20, 15, 0, 0);
    const at = (hour: number, day = 20) => new Date(2026, 7, day, hour, 0, 0).toISOString();
    const g = aggregateGraphs(
      [
        assistant({ at: at(9), cost: 1, usage: usage(10) }),
        assistant({ at: at(23), cost: 2, usage: usage(20) }),
        assistant({ at: at(20, 19), cost: 4, usage: usage(40) }), // yesterday, local
      ],
      now,
    );
    expect(g.today_cost).toBeCloseTo(3);
    expect(g.today_tokens).toBe(30);
  });

  it("splits settlement in both units and counts unpriced turns", () => {
    const g = aggregateGraphs(
      [
        assistant({ settlement: "subscription", cost: 3, usage: usage(300) }),
        assistant({ settlement: "credits", cost: 2, usage: usage(200) }),
        assistant({ settlement: "billed", cost: 5, usage: usage(500) }),
        assistant({ cost: 1, usage: usage(100) }),
        // Unpriced, not unmetered: its tokens still count, only the price is missing.
        assistant({ cost: undefined, cost_unknown: true, usage: usage(50) }),
      ],
      NOW,
    );
    expect(g.covered_cost).toBeCloseTo(3);
    expect(g.overage_cost).toBeCloseTo(2);
    // API-metered on the person's own key: beyond the plan, but not credits.
    expect(g.billed_cost).toBeCloseTo(5);
    expect(g.unknown_cost).toBeCloseTo(1);
    expect(g.unpriced_turns).toBe(1);
    // The token twin — what the tiles, the tray and the ledger show.
    expect(g.covered_tokens).toBe(300);
    expect(g.overage_tokens).toBe(200);
    expect(g.billed_tokens).toBe(500);
    expect(g.unknown_tokens).toBe(150);
    // The four buckets add up to the total in each unit — the tiles' invariant.
    expect(g.covered_cost + g.overage_cost + g.billed_cost + g.unknown_cost).toBeCloseTo(g.window_cost);
    expect(g.covered_tokens + g.overage_tokens + g.billed_tokens + g.unknown_tokens).toBe(g.window_tokens);
    const day = g.cost_days.find((d) => d.total > 0)!;
    expect(day.billed).toBeCloseTo(5);
    // token_days carries the same split in tokens, so the settlement chart
    // needs no dollar.
    const tokenDay = g.token_days.find((d) => d.total > 0)!;
    expect(tokenDay).toMatchObject({ covered: 300, overage: 200, billed: 500, unknown: 150, total: 1150 });
  });
});

describe("active time", () => {
  const at = (min: number, sec = 0) =>
    new Date(Date.UTC(2026, 7, 20, 10, min, sec)).toISOString();

  it("chains near turns whole, floors idle and final ones, counts prompts as presence", () => {
    const g = aggregateGraphs(
      [
        { ...assistant({}), role: "user" as const, at: at(0), cost: undefined },
        assistant({ at: at(2) }), // 120s gap → the whole gap is engaged
        assistant({ at: at(20) }), // 1080s gap → the 10:02 turn floors at 30s
        // …and the final turn always floors at 30s.
      ],
      NOW,
    );
    expect(g.window_seconds).toBe(120 + 30 + 30);
    // No taskOf lookup → no directory, and the chart folds under "other".
    expect(g.by_task).toEqual([]);
    expect(g.time_tasks).toEqual(["other"]);
  });

  it("splits time, sessions, cost and recency by use case, ranked by engaged time", () => {
    const taskOf = (id: string) => (id === "s1" ? "coding" : "docs");
    const g = aggregateGraphs(
      [
        assistant({ session_id: "s1", at: at(0), cost: 1 }),
        assistant({ session_id: "s1", at: at(4), cost: 1 }), // 240s + 30s tail
        assistant({ session_id: "s2", at: at(0), cost: 5 }), // isolated → 30s
      ],
      NOW,
      7,
      taskOf,
    );
    expect(g.by_task.map((t) => t.task)).toEqual(["coding", "docs"]); // time order, not cost
    const coding = g.by_task[0]!;
    expect(coding.seconds).toBe(270);
    expect(coding.sessions).toBe(1);
    expect(coding.cost).toBeCloseTo(2);
    expect(coding.last_at).toBe(at(4));
    expect(g.window_sessions).toBe(2);
    expect(g.time_tasks).toEqual(["coding", "docs"]);
    const today = g.time_days[g.time_days.length - 1]!;
    expect(today.by_task.coding).toBe(270);
    expect(today.total).toBe(300);
  });

  it("attributes prior-window time to prev_seconds for the trend badge", () => {
    const g = aggregateGraphs(
      [
        assistant({ at: "2026-08-10T10:00:00.000Z" }), // prior window
        assistant({ at: "2026-08-20T10:00:00.000Z" }),
      ],
      NOW,
      7,
      () => "coding",
    );
    expect(g.window_seconds).toBe(30);
    expect(g.prev_window_seconds).toBe(30);
    expect(g.by_task[0]!.prev_seconds).toBe(30);
  });

  it("counts LOCAL-day today seconds, same contract as today_cost", () => {
    const now = new Date(2026, 7, 20, 15, 0, 0);
    const mk = (hour: number, day = 20) => new Date(2026, 7, day, hour, 0, 0).toISOString();
    const g = aggregateGraphs(
      [assistant({ at: mk(20, 19) }), assistant({ at: mk(9) })],
      now,
    );
    expect(g.today_seconds).toBe(30);
  });

  it("splits the same seconds by rail, ranked by time", () => {
    const g = aggregateGraphs(
      [
        assistant({ session_id: "cc", source: "claude-code", at: at(0) }),
        assistant({ session_id: "cc", source: "claude-code", at: at(3) }), // 180s + 30s
        assistant({ session_id: "cx", source: "codex", at: at(0) }), // 30s
      ],
      NOW,
      7,
      () => "coding",
    );
    expect(g.time_rails).toEqual(["claude-code", "codex"]);
    const today = g.time_days[g.time_days.length - 1]!;
    expect(today.by_rail["claude-code"]).toBe(210);
    expect(today.by_rail.codex).toBe(30);
    // The two splits are the same seconds seen two ways — they must total the same.
    const railTotal = Object.values(today.by_rail).reduce((n, v) => n + v, 0);
    const taskTotal = Object.values(today.by_task).reduce((n, v) => n + v, 0);
    expect(railTotal).toBe(taskTotal);
    expect(railTotal).toBe(today.total);
  });

  it("folds use cases past the top five into other in the chart, never the directory", () => {
    const tasks = ["coding", "debugging", "testing", "refactor", "data", "docs", "research"];
    const turns: LedgerTurn[] = [];
    tasks.forEach((task, i) => {
      // Two turns per session, (7−i)·10 seconds apart → coding longest.
      turns.push(assistant({ session_id: task, at: at(0) }));
      turns.push(assistant({ session_id: task, at: at(0, (tasks.length - i) * 10) }));
    });
    const g = aggregateGraphs(turns, NOW, 7, (id) => id);
    expect(g.time_tasks).toEqual(["coding", "debugging", "testing", "refactor", "data", "other"]);
    expect(g.by_task).toHaveLength(7);
    const today = g.time_days[g.time_days.length - 1]!;
    expect(today.by_task.other).toBe(20 + 10 + 30 + 30); // docs + research, tails included
  });
});
