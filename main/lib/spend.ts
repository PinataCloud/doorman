/**
 * Graph aggregation: N days × top-5 models (+ "other"), computed locally from
 * the turn store. Day keys are UTC, so a day's fold never depends on the
 * machine's timezone.
 *
 * Shapes follow the Usage screen: a tokens-per-day-by-model chart, a
 * tokens-per-day covered-vs-overage chart, a model share table, and KPI cards
 * with a prior-window trend — plus the time-first views (engaged hours per day
 * by use-case, and the use-case directory) that lead the redesigned screen.
 *
 * Every figure the screens SHOW is a token count. The cost folds
 * are kept beside them — the pricing engine still runs per turn — but nothing
 * in the app renders a dollar: the
 * on-device estimate ignores what actually paid for a turn, lags the
 * provider's rates and prices unknown models as nothing, so a "$4.21" would
 * be read as an invoice the app cannot stand behind. Tokens are measured.
 */

import type { LedgerTurn, TurnSource } from "./turns.js";
import { sourceLabel as railLabel } from "./transcript-sources-registry.js";

export const WINDOW_DAYS = 7;
export const TOP_MODELS = 5;
/** Legend cap for the time-by-use-case chart — same house rule as models. */
export const TOP_TASKS = 5;
export const OTHER_KEY = "other";

/**
 * The active-time model (WakaTime-style, deterministic, no model): a turn is a
 * proof of presence. Consecutive turns in one session closer than
 * ACTIVE_GAP_MAX_SECONDS chain — the whole gap counts as engaged time. A turn
 * whose successor is further away (or that ends the session) contributes only
 * ACTIVE_TURN_FLOOR_SECONDS: the tail of attention, never the idle stare.
 * Engaged time is attributed to the day of the EARLIER turn, mirroring how a
 * turn's cost lands on its own timestamp.
 */
export const ACTIVE_GAP_MAX_SECONDS = 300;
export const ACTIVE_TURN_FLOOR_SECONDS = 30;

/** UTC day keys, oldest first, ending on `now`'s day. */
export function utcDays(now: Date, count: number): string[] {
  const days: string[] = [];
  const end = Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate());
  for (let i = count - 1; i >= 0; i -= 1) {
    days.push(new Date(end - i * 86_400_000).toISOString().slice(0, 10));
  }
  return days;
}

export interface GraphDay {
  date: string;
  total: number;
  by_model: Record<string, number>;
  /** Settlement split for the day, in the day's own unit (USD on `cost_days`,
   * tokens on `token_days`): plan-covered, API credits (paid overage),
   * API-key billed, unattributed. */
  covered: number;
  overage: number;
  billed: number;
  unknown: number;
}

export interface ModelRow {
  model: string;
  cost: number;
  tokens: number;
  /** "claude code" / "codex" / "mixed" — which rail(s) drove this model. */
  source: string;
}

export interface TaskSpend {
  task: string;
  cost: number;
  /** input+output tokens in the window — the figure the directory shows. */
  tokens: number;
  /** Distinct sessions of this task type in the window. */
  sessions: number;
  /** Engaged seconds in the window (the active-time model above). */
  seconds: number;
  /** Engaged seconds in the window immediately before, for the trend badge. */
  prev_seconds: number;
  /** Newest activity in the window (ISO instant). */
  last_at?: string;
}

/** One day of engaged time, split by session use-case (top-N + "other"). */
export interface TimeDay {
  date: string;
  /** Engaged seconds that day. */
  total: number;
  by_task: Record<string, number>;
  /** The same seconds split by capture rail (claude-code / codex) — the time
   * chart's second view, so "which agent am I actually in?" is one toggle
   * rather than a different screen. */
  by_rail: Record<string, number>;
}

export interface SpendGraphs {
  /** USD per day per model, with the day's settlement split in USD. Folded
   * but not rendered (see the module comment). */
  cost_days: GraphDay[];
  /** input+output tokens per day per model, with the day's settlement split
   * in tokens — cache traffic deliberately excluded: it dwarfs real volume
   * and is a billing story, not a usage one. */
  token_days: GraphDay[];
  /** Top models by window tokens, then "other" when anything was consolidated. */
  models: string[];
  /** Per-model totals for the share table, ranked by tokens. */
  model_rows: ModelRow[];
  /** The machine's LOCAL calendar day — the human "today" the tray and the
   * Today stat show. May exceed what the UTC-bucketed chart shows for the
   * last column; the buckets deliberately stay UTC. */
  today_cost: number;
  today_tokens: number;
  window_cost: number;
  window_tokens: number;
  /** The window immediately BEFORE this one, for the trend line. */
  prev_window_cost: number;
  prev_window_tokens: number;
  /** Cost-weighted settlement split over the window. */
  covered_cost: number;
  overage_cost: number;
  /** Metered on the person's own API key — money out, like `overage_cost`,
   * but an invoice from the provider rather than credits bought on top of a
   * plan. Only a host that reports BYOK can set it today. */
  billed_cost: number;
  unknown_cost: number;
  /** The same split, token-weighted — what the tiles, the tray and the ledger
   * show. The four add up to `window_tokens`. */
  covered_tokens: number;
  overage_tokens: number;
  billed_tokens: number;
  unknown_tokens: number;
  /** Turns that could not be priced (unknown models) count $0 in the cost
   * folds. Their tokens still count; nothing shown depends on this now. */
  unpriced_turns: number;
  /** Window spend + engaged time split by session use-case (lib/task-class.ts),
   * ranked by engaged time. Empty when no `taskOf` lookup was supplied. */
  by_task: TaskSpend[];
  /** Engaged seconds per day, split by use-case — the time twin of cost_days. */
  time_days: TimeDay[];
  /** Top use-cases by window engaged time (the time chart's series order),
   * then "other" when anything was consolidated. */
  time_tasks: string[];
  /** Rails with engaged time in the window, most first — the by-rail series. */
  time_rails: string[];
  /** Engaged seconds over the window / the window before it (trend). */
  window_seconds: number;
  prev_window_seconds: number;
  /** Engaged seconds on the machine's LOCAL calendar day — same contract as
   * today_cost. */
  today_seconds: number;
  /** Distinct sessions with any activity in the window. */
  window_sessions: number;
  /** Engaged seconds by LOCAL weekday × hour over the window: 7 rows (Monday
   * first) × 24 columns (local hour 0–23). A stretch lands whole on the local
   * hour its earlier turn falls in — the same attribution time_days uses — so
   * the cells sum to window_seconds. Window membership stays UTC-day, like
   * every other window figure; only the placement is local. */
  punchcard: number[][];
  days: number;
}

export function aggregateGraphs(
  turns: readonly LedgerTurn[],
  now: Date,
  count = WINDOW_DAYS,
  /** Session id → use-case, for the by_task split. Absent → no task breakdown. */
  taskOf?: (sessionId: string) => string | undefined,
): SpendGraphs {
  const days = utcDays(now, count);
  const first = days[0]!;
  const prevFirst = utcDays(now, count * 2)[0]!;
  const todayKey = days[days.length - 1]!;
  const dayIndex = new Map(days.map((d, i) => [d, i]));
  // "Today" is the machine's LOCAL calendar day, not the UTC bucket. The chart
  // days stay UTC (server parity), but the tray title and the Today tile answer
  // a human question — and for a negative-offset timezone an evening turn lands
  // in UTC-tomorrow, which the bucket guard below rightly drops from the chart
  // window but must NOT drop from "today", or the person watches their evening
  // session run while both surfaces claim nothing happened.
  const todayStartMs = new Date(now.getFullYear(), now.getMonth(), now.getDate()).getTime();
  const todayEndMs = todayStartMs + 86_400_000;

  const modelCost = new Map<string, number>();
  const modelTokens = new Map<string, number>();
  const modelSources = new Map<string, Set<string>>();
  const mkDay = (date: string): GraphDay => ({
    date,
    total: 0,
    by_model: {},
    covered: 0,
    overage: 0,
    billed: 0,
    unknown: 0,
  });
  const perDayCost: Map<string, number>[] = days.map(() => new Map());
  const perDayTokens: Map<string, number>[] = days.map(() => new Map());
  // The settlement split per day, once in each unit.
  const splitCostDays = days.map(mkDay);
  const splitTokenDays = days.map(mkDay);
  let todayCost = 0;
  let todayTokens = 0;
  let windowCost = 0;
  let windowTokens = 0;
  let prevCost = 0;
  let prevTokens = 0;
  let covered = 0;
  let overage = 0;
  let billed = 0;
  let unknown = 0;
  let coveredTokens = 0;
  let overageTokens = 0;
  let billedTokens = 0;
  let unknownTokens = 0;
  let unpriced = 0;
  const taskCost = new Map<string, number>();
  const taskTokens = new Map<string, number>();

  for (const turn of turns) {
    if (turn.role !== "assistant") continue;
    const cost = turn.cost ?? 0;
    const tokens = (turn.usage?.input_tokens ?? 0) + (turn.usage?.output_tokens ?? 0);
    // Local-day "today", judged BEFORE the UTC bucket guard — see above.
    const atMs = Date.parse(turn.at);
    if (atMs >= todayStartMs && atMs < todayEndMs) {
      todayCost += cost;
      todayTokens += tokens;
    }
    const day = turn.at.slice(0, 10);
    if (day < prevFirst || day > todayKey) continue;
    if (day < first) {
      prevCost += cost;
      prevTokens += tokens;
      continue;
    }
    const idx = dayIndex.get(day);
    if (idx === undefined) continue;
    const model = turn.model ?? "unknown";
    if (turn.cost_unknown) unpriced += 1;
    windowCost += cost;
    windowTokens += tokens;
    if (taskOf) {
      const task = taskOf(turn.session_id) ?? OTHER_KEY;
      taskCost.set(task, (taskCost.get(task) ?? 0) + cost);
      taskTokens.set(task, (taskTokens.get(task) ?? 0) + tokens);
    }
    modelCost.set(model, (modelCost.get(model) ?? 0) + cost);
    modelTokens.set(model, (modelTokens.get(model) ?? 0) + tokens);
    let sources = modelSources.get(model);
    if (!sources) {
      sources = new Set();
      modelSources.set(model, sources);
    }
    sources.add(turn.source);
    perDayCost[idx]!.set(model, (perDayCost[idx]!.get(model) ?? 0) + cost);
    perDayTokens[idx]!.set(model, (perDayTokens[idx]!.get(model) ?? 0) + tokens);
    const splitCost = splitCostDays[idx]!;
    const splitTokens = splitTokenDays[idx]!;
    switch (turn.settlement) {
      case "subscription":
        covered += cost;
        coveredTokens += tokens;
        splitCost.covered += cost;
        splitTokens.covered += tokens;
        break;
      case "credits":
        overage += cost;
        overageTokens += tokens;
        splitCost.overage += cost;
        splitTokens.overage += tokens;
        break;
      case "billed":
        billed += cost;
        billedTokens += tokens;
        splitCost.billed += cost;
        splitTokens.billed += tokens;
        break;
      default:
        unknown += cost;
        unknownTokens += tokens;
        splitCost.unknown += cost;
        splitTokens.unknown += tokens;
        break;
    }
  }

  // Models rank by TOKENS — the figure every screen shows — so the chart's
  // legend, the share table and the "other" fold agree with what is printed.
  const ranked = [...modelTokens.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
  const top = ranked.slice(0, TOP_MODELS).map(([model]) => model);
  const consolidated = ranked.length > TOP_MODELS;
  const models = consolidated ? [...top, OTHER_KEY] : top;
  const topSet = new Set(top);

  const sourceLabel = (set: Set<string> | undefined): string => {
    if (!set || set.size === 0) return "—";
    if (set.size > 1) return "mixed";
    const only = [...set][0]!;
    return railLabel(only as TurnSource);
  };

  const model_rows: ModelRow[] = top.map((model) => ({
    model,
    cost: modelCost.get(model) ?? 0,
    tokens: modelTokens.get(model) ?? 0,
    source: sourceLabel(modelSources.get(model)),
  }));
  if (consolidated) {
    let cost = 0;
    let tokens = 0;
    const sources = new Set<string>();
    for (const [model] of ranked.slice(TOP_MODELS)) {
      cost += modelCost.get(model) ?? 0;
      tokens += modelTokens.get(model) ?? 0;
      for (const s of modelSources.get(model) ?? []) sources.add(s);
    }
    model_rows.push({ model: OTHER_KEY, cost, tokens, source: sourceLabel(sources) });
  }

  const fold = (per: Map<string, number>[], split: GraphDay[]): GraphDay[] =>
    days.map((date, i) => {
      const day = mkDay(date);
      day.covered = split[i]!.covered;
      day.overage = split[i]!.overage;
      day.billed = split[i]!.billed;
      day.unknown = split[i]!.unknown;
      for (const [model, value] of per[i]!) {
        const key = topSet.has(model) ? model : OTHER_KEY;
        day.by_model[key] = (day.by_model[key] ?? 0) + value;
        day.total += value;
      }
      return day;
    });

  // ---- Engaged time — a second pass, per session in timestamp order, because
  // the active-time model chains CONSECUTIVE turns and the main loop sees turns
  // in store order. Prompts count here (a prompt is presence exactly as an
  // answer is) even though they never carry cost.
  const bySession = new Map<string, { at: number; iso: string; day: string; rail: string }[]>();
  for (const turn of turns) {
    const rec = { at: Date.parse(turn.at), iso: turn.at, day: turn.at.slice(0, 10), rail: turn.source };
    const list = bySession.get(turn.session_id);
    if (list) list.push(rec);
    else bySession.set(turn.session_id, [rec]);
  }
  const perDayTaskSeconds: Map<string, number>[] = days.map(() => new Map());
  const perDayRailSeconds: Map<string, number>[] = days.map(() => new Map());
  const railSeconds = new Map<string, number>();
  const taskSeconds = new Map<string, number>();
  const taskPrevSeconds = new Map<string, number>();
  const taskSessions = new Map<string, Set<string>>();
  const taskLast = new Map<string, string>();
  const windowSessions = new Set<string>();
  let windowSeconds = 0;
  let prevSeconds = 0;
  let todaySeconds = 0;
  const punchcard: number[][] = Array.from({ length: 7 }, () => new Array<number>(24).fill(0));

  for (const [sessionId, recs] of bySession) {
    recs.sort((a, b) => a.at - b.at || (a.iso < b.iso ? -1 : 1));
    const task = taskOf?.(sessionId) ?? OTHER_KEY;
    for (let i = 0; i < recs.length; i += 1) {
      const rec = recs[i]!;
      const next = recs[i + 1];
      const gapSec = next ? (next.at - rec.at) / 1000 : Infinity;
      const seconds = gapSec <= ACTIVE_GAP_MAX_SECONDS ? gapSec : ACTIVE_TURN_FLOOR_SECONDS;
      // Local-day "today" first, same contract as today_cost.
      if (rec.at >= todayStartMs && rec.at < todayEndMs) todaySeconds += seconds;
      if (rec.day < prevFirst || rec.day > todayKey) continue;
      if (rec.day < first) {
        prevSeconds += seconds;
        taskPrevSeconds.set(task, (taskPrevSeconds.get(task) ?? 0) + seconds);
        continue;
      }
      const idx = dayIndex.get(rec.day);
      if (idx === undefined) continue;
      windowSeconds += seconds;
      windowSessions.add(sessionId);
      // Local weekday, Monday first (getDay() is Sunday = 0).
      const local = new Date(rec.at);
      const weekday = punchcard[(local.getDay() + 6) % 7]!;
      weekday[local.getHours()] = (weekday[local.getHours()] ?? 0) + seconds;
      taskSeconds.set(task, (taskSeconds.get(task) ?? 0) + seconds);
      perDayTaskSeconds[idx]!.set(task, (perDayTaskSeconds[idx]!.get(task) ?? 0) + seconds);
      railSeconds.set(rec.rail, (railSeconds.get(rec.rail) ?? 0) + seconds);
      perDayRailSeconds[idx]!.set(rec.rail, (perDayRailSeconds[idx]!.get(rec.rail) ?? 0) + seconds);
      let sessions = taskSessions.get(task);
      if (!sessions) taskSessions.set(task, (sessions = new Set()));
      sessions.add(sessionId);
      const last = taskLast.get(task);
      if (!last || rec.iso > last) taskLast.set(task, rec.iso);
    }
  }

  // Chart series: top use-cases by window time, everything past the cap folded
  // into "other" — same consolidation rule as models.
  const rankedTasks = [...taskSeconds.entries()].sort(
    (a, b) => b[1] - a[1] || a[0].localeCompare(b[0]),
  );
  const topTasks = rankedTasks.slice(0, TOP_TASKS).map(([task]) => task);
  const topTaskSet = new Set(topTasks);
  const time_tasks = rankedTasks.length > TOP_TASKS ? [...topTasks, OTHER_KEY] : topTasks;
  const time_rails = [...railSeconds.entries()]
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .map(([rail]) => rail);
  const time_days: TimeDay[] = days.map((date, i) => {
    const day: TimeDay = { date, total: 0, by_task: {}, by_rail: {} };
    for (const [task, value] of perDayTaskSeconds[i]!) {
      const key = topTaskSet.has(task) ? task : OTHER_KEY;
      day.by_task[key] = (day.by_task[key] ?? 0) + value;
      day.total += value;
    }
    for (const [rail, value] of perDayRailSeconds[i]!) {
      day.by_rail[rail] = (day.by_rail[rail] ?? 0) + value;
    }
    return day;
  });

  // The use-case directory: every task with window activity (time OR tokens —
  // a read-only session with no metered turn still spent minutes), ranked by
  // engaged time.
  const by_task: TaskSpend[] = taskOf
    ? [...new Set([...taskSeconds.keys(), ...taskCost.keys(), ...taskTokens.keys()])]
        .map((task) => ({
          task,
          cost: taskCost.get(task) ?? 0,
          tokens: taskTokens.get(task) ?? 0,
          sessions: taskSessions.get(task)?.size ?? 0,
          seconds: taskSeconds.get(task) ?? 0,
          prev_seconds: taskPrevSeconds.get(task) ?? 0,
          ...(taskLast.has(task) ? { last_at: taskLast.get(task)! } : {}),
        }))
        .sort(
          (a, b) => b.seconds - a.seconds || b.tokens - a.tokens || a.task.localeCompare(b.task),
        )
    : [];

  return {
    cost_days: fold(perDayCost, splitCostDays),
    token_days: fold(perDayTokens, splitTokenDays),
    models,
    model_rows,
    today_cost: todayCost,
    today_tokens: todayTokens,
    window_cost: windowCost,
    window_tokens: windowTokens,
    prev_window_cost: prevCost,
    prev_window_tokens: prevTokens,
    covered_cost: covered,
    overage_cost: overage,
    billed_cost: billed,
    unknown_cost: unknown,
    covered_tokens: coveredTokens,
    overage_tokens: overageTokens,
    billed_tokens: billedTokens,
    unknown_tokens: unknownTokens,
    unpriced_turns: unpriced,
    by_task,
    time_days,
    time_tasks,
    time_rails,
    window_seconds: windowSeconds,
    prev_window_seconds: prevSeconds,
    today_seconds: todaySeconds,
    window_sessions: windowSessions.size,
    punchcard,
    days: count,
  };
}
