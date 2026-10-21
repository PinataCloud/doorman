import { alertsByTask, ruleStatsWindow, sessionTaskLookup } from "../../lib/app-views.js";
import { RULE_STATS_WINDOWS } from "../../lib/findings.js";
import { aggregateGraphs } from "../../lib/spend.js";
import { TASK_LABELS, type TaskClass } from "../../lib/task-class.js";
import type { CliCommand } from "../command.js";
import { ago, compactNumber } from "../output.js";
import { plural, type KvRow } from "../ui.js";
import { daysOption, delta, duration, paintSeverity, ruleLabels, withEngine } from "./data-shared.js";

export const usageCommand: CliCommand = {
  name: "usage",
  summary: "Tokens and time spent with AI agents, by use case",
  usage: "[--days 7|30] [--scan]",
  options: { days: { type: "string" }, scan: { type: "boolean", default: false } },
  flags: [
    ["--days 7|30", "the window (default 7)"],
    ["--scan", "read new transcripts first"],
  ],
  notes: [
    "Tokens (input + output; cache traffic left out, as on the screen), engaged time, sessions, use cases and models over the window, against the window before it. Tokens only: the app prices nothing it can't stand behind, so no dollar figures.",
  ],
  examples: [
    ["doorman usage --scan", "read new transcripts, then the last 7 days"],
    ["doorman usage --days 30", "the last 30 days"],
  ],
  async run(ctx, args) {
    const days = daysOption(args.values.days, [7, 30] as const, 7);
    return withEngine(ctx, args.values.scan === true, ({ engine }) => {
      const now = new Date(ctx.io.now());
      const sessions = engine.sessions();
      const taskOf = sessionTaskLookup(sessions);
      const g = aggregateGraphs([...engine.turns.values()], now, days, taskOf);
      const alerts = alertsByTask(engine.shownFindings(), taskOf);
      const alertsOf = new Map(alerts.map((a) => [a.task, a.alerts]));
      const activeDays = g.time_days.filter((d) => d.total > 0).length;
      const tokensPerHour = g.window_seconds > 0 ? Math.round(g.window_tokens / (g.window_seconds / 3600)) : 0;
      const plans = engine.planWindowList();
      const data = {
        days,
        tokens: g.window_tokens,
        prev_tokens: g.prev_window_tokens,
        today_tokens: g.today_tokens,
        seconds: g.window_seconds,
        prev_seconds: g.prev_window_seconds,
        today_seconds: g.today_seconds,
        sessions: g.window_sessions,
        active_days: activeDays,
        tokens_per_hour: tokensPerHour,
        settlement_tokens: { covered: g.covered_tokens, overage: g.overage_tokens, billed: g.billed_tokens, unknown: g.unknown_tokens },
        by_task: g.by_task.map((t) => ({
          task: t.task,
          label: TASK_LABELS[t.task as TaskClass] ?? t.task,
          tokens: t.tokens,
          sessions: t.sessions,
          seconds: t.seconds,
          prev_seconds: t.prev_seconds,
          ...(t.last_at ? { last_at: t.last_at } : {}),
          alerts: alertsOf.get(t.task) ?? 0,
        })),
        by_model: g.model_rows.map((m) => ({ model: m.model, tokens: m.tokens, source: m.source })),
        token_days: g.token_days.map((d) => ({ date: d.date, tokens: d.total })),
        time_days: g.time_days.map((d) => ({ date: d.date, seconds: d.total })),
        alerts_by_task: alerts,
        plan_windows: plans,
      };
      const s = ctx.style;
      const ui = ctx.ui;
      if (g.window_tokens === 0 && g.window_seconds === 0) {
        return {
          data,
          text: [
            ui.mark("off", `No activity in the last ${days} days.`),
            ui.next(args.values.scan === true ? "`doorman sessions` lists the sessions read so far." : "`doorman usage --scan` reads new transcripts first."),
          ],
        };
      }
      const noted = (v: string, note: string) => (note ? `${v}  ${s.dim(note)}` : v);
      // A heat cell a day (two in a week's window, so the dates fit under
      // it), shaded by the quarter of the busiest day; the max gives the scale.
      const per = Math.ceil(14 / days);
      const cells = g.time_days.length * per;
      // Only where the keys (15 columns), the strip and its dates fit unwrapped.
      const strip = ui.decorate && cells > 0 && (ui.width ?? 80) >= 15 + Math.max(cells, 13) + 2;
      const [from = "", to = ""] = strip
        ? [g.time_days[0]!.date, g.time_days[g.time_days.length - 1]!.date].map((date) =>
            new Date(`${date}T00:00:00Z`).toLocaleDateString("en-US", { month: "short", day: "numeric", timeZone: "UTC" }),
          )
        : [];
      const maxSeconds = Math.max(0, ...g.time_days.map((d) => d.total));
      const maxTokens = Math.max(0, ...g.token_days.map((d) => d.total));
      const text = [
        ui.section(`Usage, last ${days} days`),
        ...ui.kv([
          ["tokens", noted(compactNumber(g.window_tokens), delta(g.window_tokens, g.prev_window_tokens, `vs prior ${days}d`))],
          ["today", noted(compactNumber(g.today_tokens), g.today_seconds > 0 ? `${duration(g.today_seconds)} engaged today` : "nothing yet today")],
          ["time spent", noted(duration(g.window_seconds), delta(g.window_seconds, g.prev_window_seconds, `vs prior ${days}d`))],
          [
            "sessions",
            noted(String(g.window_sessions), ui.list([`${activeDays} of ${days} days had activity`, plural(g.by_task.length, "use case")])),
          ],
          tokensPerHour > 0 && ["tokens/hour", compactNumber(tokensPerHour)],
          strip && ["time/day", noted(ui.heat(g.time_days.flatMap((d) => Array<number>(per).fill(d.total))), maxSeconds > 0 ? `max ${duration(maxSeconds)}` : "")],
          strip && ["tokens/day", noted(ui.heat(g.token_days.flatMap((d) => Array<number>(per).fill(d.total))), maxTokens > 0 ? `max ${compactNumber(maxTokens)}` : "")],
          strip && ["", s.dim(`${from}${" ".repeat(Math.max(1, cells - from.length - to.length))}${to}`)],
        ]),
      ];
      if (g.by_task.length > 0) {
        text.push(
          "",
          ui.section("By use case"),
          ...ui.table(
            ["USE CASE", "TIME", "SHARE", "TOKENS", "SESSIONS", "SIGHTINGS"],
            g.by_task.map((t) => [
              TASK_LABELS[t.task as TaskClass] ?? t.task,
              duration(t.seconds),
              g.window_seconds > 0 ? `${Math.round((t.seconds / g.window_seconds) * 100)}%` : "",
              compactNumber(t.tokens),
              String(t.sessions),
              String(alertsOf.get(t.task) ?? 0),
            ]),
            { indent: 2, keep: [1, 2, 3, 4, 5] },
          ),
        );
      }
      if (g.model_rows.length > 0) {
        text.push(
          "",
          ui.section("By model"),
          ...ui.table(
            ["MODEL", "TOKENS", "SHARE", "AGENT"],
            g.model_rows.map((m) => [
              m.model,
              compactNumber(m.tokens),
              g.window_tokens > 0 ? `${Math.round((m.tokens / g.window_tokens) * 100)}%` : "",
              m.source,
            ]),
            { indent: 2, keep: [1, 2] },
          ),
        );
      }
      if (plans.length > 0) {
        text.push(
          "",
          ui.section("Plan allowance"),
          ...ui.kv(
            plans.map((p): KvRow => [
              `${p.source}${p.window_id ? ` (${p.window_id})` : ""}`,
              `${Math.round(p.used_percentage)}% used${p.resets_at ? `, resets ${p.resets_at}` : ""}  ${s.dim(p.label ?? ago(p.at, ctx.io.now()))}`,
            ]),
          ),
        );
      }
      return { data, text };
    });
  },
};

export const analyticsCommand: CliCommand = {
  name: "analytics",
  summary: "Security analytics: what each rule caught in the window, and how held calls were answered",
  usage: "[--days 7|14|30|90] [--scan]",
  options: { days: { type: "string" }, scan: { type: "boolean", default: false } },
  flags: [
    ["--days 7|14|30|90", "the window (default 14)"],
    ["--scan", "read new transcripts first"],
  ],
  notes: [
    "Exposures (a rule at a place), the distinct items exposed under them (secrets, files) and sightings in the window, how many of the sessions that ran had a sighting, how held calls were answered, and every rule that fired.",
  ],
  examples: [
    ["doorman analytics", "the last 14 days"],
    ["doorman analytics --days 90 --scan", "read new transcripts, then the last 90 days"],
  ],
  async run(ctx, args) {
    const days = daysOption(args.values.days, RULE_STATS_WINDOWS, 14);
    const labels = ruleLabels(ctx);
    return withEngine(ctx, args.values.scan === true, ({ engine }) => {
      const stats = ruleStatsWindow(engine.shownFindings(), engine.sessions(), days, new Date(ctx.io.now()), labels);
      // Tokens only: the dollar estimates stay folded, never shown.
      const { burned_usd: _usd, rules, ...rest } = stats;
      const data = { ...rest, rules: rules.map(({ burned_usd: _ruleUsd, ...r }) => r) };
      const s = ctx.style;
      const ui = ctx.ui;
      const rate = stats.window_sessions ? Math.round((stats.sessions / stats.window_sessions) * 100) : undefined;
      const noted = (v: string, note: string) => (note ? `${v}  ${s.dim(note)}` : v);
      const prevNew = stats.prev?.new_exposures;
      const humans = Object.entries(stats.decided_via)
        .filter(([, n]) => n > 0)
        .map(([via, n]) => `${via} ${n}`);
      const text = [
        ui.section(`Security analytics, last ${days} days`),
        ...ui.kv([
          ["exposures", noted(String(stats.exposures), `${stats.new_exposures} new${prevNew !== undefined ? ` (${prevNew} the ${days} days before)` : ""}`)],
          ["items", noted(String(stats.things), `${stats.new_things} new`)],
          ["sightings", String(stats.total)],
          [
            "sessions",
            noted(rate !== undefined ? `${rate}%` : String(stats.sessions), `${stats.sessions} of the ${stats.window_sessions ?? 0} sessions that ran had a sighting`),
          ],
          [
            "held calls",
            noted(
              String(stats.decisions),
              ui.list(
                [
                  stats.median_hold_ms !== undefined ? `median ${Math.round(stats.median_hold_ms / 1000)}s to decide` : "",
                  ...humans,
                  stats.scoped_allows > 0 ? `${stats.scoped_allows} allowed for a project` : "",
                ].filter(Boolean),
              ),
            ),
          ],
          typeof stats.burned_tokens === "number" && ["stuck loops", `${compactNumber(stats.burned_tokens)} tokens burned`],
        ]),
      ];
      if (stats.rules.length > 0) {
        text.push(
          "",
          ui.section(`Rules that fired (${stats.rules.length})`),
          ...ui.table(
            ["RULE", "WORST", "FIRED", "EXPOSURES", "SESSIONS", "BLOCKED", "HELD", "WARNED", "LAST"],
            stats.rules.map((r) => [
              r.label,
              r.worst ? paintSeverity(s, r.worst) : "",
              String(r.fired),
              String(r.exposures),
              String(r.sessions),
              String(r.blocked),
              String(r.held),
              String(r.warned),
              r.last_fired_at ? ago(r.last_fired_at, ctx.io.now()) : "",
            ]),
            { indent: 2, keep: [0, 1, 2, 3, 4, 5, 6, 7, 8], drop: [5, 6, 7, 4] },
          ),
        );
      } else {
        text.push("", ui.mark("ok", s.ok(`No rule fired in the last ${days} days.`)));
      }
      const notes = [
        stats.stood_down ? `${stats.stood_down} sighting${stats.stood_down === 1 ? " was" : "s were"} stood down by a model after the rule fired.` : "",
        stats.rejected ? `${stats.rejected} sighting${stats.rejected === 1 ? " was" : "s were"} marked false positive and counted nowhere above.` : "",
      ].filter(Boolean);
      if (notes.length > 0) text.push("", ...notes.map((n) => s.dim(n)));
      return { data, text };
    });
  },
};
