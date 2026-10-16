import { alertsByTask, ruleStatsWindow, sessionTaskLookup } from "../../lib/app-views.js";
import { RULE_STATS_WINDOWS } from "../../lib/findings.js";
import { aggregateGraphs } from "../../lib/spend.js";
import { TASK_LABELS, type TaskClass } from "../../lib/task-class.js";
import type { CliCommand } from "../command.js";
import { ago, compactNumber, table } from "../output.js";
import { daysOption, delta, duration, paintSeverity, ruleLabels, withEngine } from "./data-shared.js";

export const usageCommand: CliCommand = {
  name: "usage",
  summary: "Tokens and time spent with AI, like the Usage screen",
  usage: "[--days 7|30] [--scan]",
  options: { days: { type: "string" }, scan: { type: "boolean", default: false } },
  details: [
    "Tokens (input + output; cache traffic left out, as on the screen), engaged time, sessions,",
    "use cases and models over the window, against the window before it. Tokens only: the app",
    "prices nothing it can't stand behind, so no dollar figures.",
    "--days 7|30  the window (default 7)",
    "--scan       read new transcripts first",
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
      if (g.window_tokens === 0 && g.window_seconds === 0) {
        return { data, text: [s.dim(`No activity in the last ${days} days.`)] };
      }
      const line = (k: string, v: string, note = "") => `  ${s.dim(k.padEnd(13))}${v}${note ? `  ${s.dim(note)}` : ""}`;
      const text = [
        s.bold(`Usage, last ${days} days`),
        line("tokens", compactNumber(g.window_tokens), delta(g.window_tokens, g.prev_window_tokens, `vs prior ${days}d`)),
        line("today", compactNumber(g.today_tokens), g.today_seconds > 0 ? `${duration(g.today_seconds)} engaged today` : "nothing yet today"),
        line("time spent", duration(g.window_seconds), delta(g.window_seconds, g.prev_window_seconds, `vs prior ${days}d`)),
        line("sessions", String(g.window_sessions), `${activeDays} of ${days} days had activity · ${g.by_task.length} use case${g.by_task.length === 1 ? "" : "s"}`),
        ...(tokensPerHour > 0 ? [line("tokens/hour", compactNumber(tokensPerHour))] : []),
      ];
      if (g.by_task.length > 0) {
        text.push(
          "",
          s.bold("By use case"),
          ...table(
            ["USE CASE", "TIME", "SHARE", "TOKENS", "SESSIONS", "ALERTS"],
            g.by_task.map((t) => [
              TASK_LABELS[t.task as TaskClass] ?? t.task,
              duration(t.seconds),
              g.window_seconds > 0 ? `${Math.round((t.seconds / g.window_seconds) * 100)}%` : "",
              compactNumber(t.tokens),
              String(t.sessions),
              String(alertsOf.get(t.task) ?? 0),
            ]),
          ).map((l) => `  ${l}`),
        );
      }
      if (g.model_rows.length > 0) {
        text.push(
          "",
          s.bold("By model"),
          ...table(
            ["MODEL", "TOKENS", "SHARE", "AGENT"],
            g.model_rows.map((m) => [
              m.model,
              compactNumber(m.tokens),
              g.window_tokens > 0 ? `${Math.round((m.tokens / g.window_tokens) * 100)}%` : "",
              m.source,
            ]),
          ).map((l) => `  ${l}`),
        );
      }
      if (plans.length > 0) {
        text.push(
          "",
          s.bold("Plan allowance"),
          ...plans.map(
            (p) =>
              `  ${p.source}${p.window_id ? ` (${p.window_id})` : ""}  ${Math.round(p.used_percentage)}% used${p.resets_at ? `, resets ${p.resets_at}` : ""}  ${s.dim(p.label ?? ago(p.at, ctx.io.now()))}`,
          ),
        );
      }
      return { data, text };
    });
  },
};

export const analyticsCommand: CliCommand = {
  name: "analytics",
  summary: "Security analytics: what each rule found, like the Analytics screen",
  usage: "[--days 7|14|30|90] [--scan]",
  options: { days: { type: "string" }, scan: { type: "boolean", default: false } },
  details: [
    "Exposures (rule x place), things under them and sightings in the window, how many of the",
    "sessions that ran had a finding, how held calls were answered, and every rule that fired.",
    "--days 7|14|30|90  the window (default 14)",
    "--scan             read new transcripts first",
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
      const rate = stats.window_sessions ? Math.round((stats.sessions / stats.window_sessions) * 100) : undefined;
      const line = (k: string, v: string, note = "") => `  ${s.dim(k.padEnd(15))}${v}${note ? `  ${s.dim(note)}` : ""}`;
      const prevNew = stats.prev?.new_exposures;
      const humans = Object.entries(stats.decided_via)
        .filter(([, n]) => n > 0)
        .map(([via, n]) => `${via} ${n}`)
        .join(" · ");
      const text = [
        s.bold(`Security analytics, last ${days} days`),
        line("exposures", String(stats.exposures), `${stats.new_exposures} new${prevNew !== undefined ? ` (${prevNew} the ${days} days before)` : ""}`),
        line("things", String(stats.things), `${stats.new_things} new`),
        line("sightings", String(stats.total)),
        line(
          "sessions",
          rate !== undefined ? `${rate}%` : String(stats.sessions),
          `${stats.sessions} of the ${stats.window_sessions ?? 0} sessions that ran had a finding`,
        ),
        line(
          "held calls",
          String(stats.decisions),
          [stats.median_hold_ms !== undefined ? `median ${Math.round(stats.median_hold_ms / 1000)}s to decide` : "", humans, stats.scoped_allows > 0 ? `${stats.scoped_allows} allowed for a project` : ""]
            .filter(Boolean)
            .join(" · "),
        ),
        ...(typeof stats.burned_tokens === "number" ? [line("stuck loops", `${compactNumber(stats.burned_tokens)} tokens burned`)] : []),
      ];
      if (stats.rules.length > 0) {
        text.push(
          "",
          s.bold(`Rules that fired (${stats.rules.length})`),
          ...table(
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
          ).map((l) => `  ${l}`),
        );
      } else {
        text.push("", s.green(`No rule fired in the last ${days} days.`));
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
