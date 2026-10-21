/* Usage — redesigned time-first (ref: Harmonic's Usage Explorer, rendered
   with the house primitives and the gallery's card grammar).

   Shape of the argument, top to bottom: ONE hero number — how much TIME went
   into AI this window (engaged time from the person's own turn timestamps,
   gap-capped in main/lib/spend.ts) — with its trend, then the token tiles
   beside it (the window and today). Then the two time questions the redesign
   exists to answer: "when was I in it?" (hours per day, split by use case,
   then the weekday × hour punchcard)
   and "what was the time FOR?" (the use-case directory: every task class with
   its hours, trend badge, sessions and tokens). Only then the volume story:
   the cumulative climb, tokens by model and the model table.

   No settlement tiles (plan / API credits / unattributed) and no settlement
   chart: the split only carries information when a host reports how a turn
   settled (Codex plan windows, Copilot's quota, a BYOK flag), and Claude
   Code's transcript reports nothing — so for most people it was three tiles
   restating "unattributed". The split still speaks where it stays silent when
   uninformative: the highlight sentence, the ledger's per-session line and
   the tray's 7d row. Plan headroom answers the subscriber's real question.

   Deliberate calls:
   · TOKENS, never dollars. The app derives cost on-device from a
     bundled rate table, and that number is an estimate: it ignores what
     actually paid for a turn (plan, credits, BYOK), lags the provider's
     prices, prices unknown models as nothing and approximates cache tiers.
     A precise-looking "$4.21" invites the reader to treat it as an invoice.
     Token counts are measured straight from the transcripts — the one figure
     the app can report honestly — so every tile, chart, sentence and table
     here is in tokens until cost derivation is something we can stand behind.
   · Time leads, tokens follow — engaged time is the usage signal a local
     app can actually own, and tokens/active-hour joins the two stories.
   · Use cases come from lib/task-class.ts: deterministic tool-mix + keyword
     heuristics, NO model — "other" is an honest bucket, never a guess.
   · The range switcher stays REAL (7d/30d) in one row above everything it
     scopes. Still no 24h/custom: the fold is UTC-day grained.
   · Chart colors are positional by rank (house rule); the directory and the
     time chart sort by the same key (window seconds), so a use case wears
     one color everywhere it appears on this screen.
   · Every chart carries a table twin; nothing is hover-only. No projections. */

const SPEND_RANGES = [
  { days: 7, label: "7 days" },
  { days: 30, label: "30 days" },
];

/** The time chart's two splits: what the work WAS, or which agent did it. */
const TIME_SPLITS = [
  { key: "task", label: "By use case" },
  { key: "rail", label: "By agent" },
];

/**
 * The window's one-sentence read — Harmonic's "Key Highlight", personal
 * edition and template-only (no model): where the time went, which way that
 * kind of work is moving, and the one settlement fact worth leading with.
 *
 * Returned as TOKENS, not a string: `{ text }` for the connective prose and
 * `{ num }` for a figure, so the renderer can set the figures in the mono face
 * every other number on this screen wears instead of leaving four numbers
 * buried in a run of sans prose. Concatenating the tokens gives exactly the
 * old sentence, which is what spendHighlight() below still returns.
 */
function spendHighlightTokens(g) {
  if (!g || !g.by_task || g.by_task.length === 0 || !(g.window_seconds > 0)) return null;
  const top = g.by_task[0];
  const share = Math.round((top.seconds / g.window_seconds) * 100);
  const out = [];
  const text = (v) => out.push({ text: v });
  const num = (v) => out.push({ num: v });

  text("Most of this window — ");
  num(share + "%");
  text(" of ");
  num(fmtDur(g.window_seconds));
  text(" — went to " + taskLabel(top.task).toLowerCase() + ".");

  if (top.prev_seconds > 0) {
    const pct = Math.round(((top.seconds - top.prev_seconds) / top.prev_seconds) * 100);
    if (Math.abs(pct) >= 10) {
      text(" That is ");
      num(Math.abs(pct) + "%");
      text(" " + (pct > 0 ? "more" : "less") + " than the window before.");
    }
  }
  // The settlement sentence leads with whatever is actually true: tokens
  // that ran beyond the plan beat a plan-covered total, which beats an
  // unattributed one. Two kinds of beyond-the-plan are named apart — credits
  // bought on top of a plan, and turns metered to the person's own API key —
  // because they land on different bills. Everything is in TOKENS: the app
  // shows no dollar figure it cannot stand behind.
  const overage = g.overage_tokens || 0;
  const billed = g.billed_tokens || 0;
  const covered = g.covered_tokens || 0;
  const unknown = g.unknown_tokens || 0;
  if (overage > 0 || billed > 0) {
    text(" ");
    num(fmtTokens(overage + billed));
    text(" of the ");
    num(fmtTokens(g.window_tokens));
    if (overage > 0 && billed > 0) {
      text(" tokens ran beyond the plan — ");
      num(fmtTokens(overage));
      text(" on API credits and ");
      num(fmtTokens(billed));
      text(" billed to an API key.");
    } else if (billed > 0) {
      text(" tokens were billed to an API key.");
    } else {
      text(" tokens ran on API credits.");
    }
  } else if (g.window_tokens > 0) {
    // Nothing observed beyond the plan: say how much is known to be on the
    // plan, and nothing about the rest — a share without billing info is not
    // a fact the reader can act on.
    text(" ");
    num(fmtTokens(g.window_tokens));
    text(" tokens went through — ");
    num(fmtTokens(g.window_tokens / (g.window_seconds / 3600)));
    text(" per active hour");
    if (covered > 0 && unknown <= 0) {
      text(", all of it on your plan.");
    } else if (covered > 0) {
      text("; ");
      num(fmtTokens(covered));
      text(" of it on your plan.");
    } else {
      text(".");
    }
  }
  return out;
}

/**
 * The same read as one plain string — the tray, a tooltip and
 * test/renderer-logic.test.ts all want the phrasing, not the markup.
 * Pure and exported to the global scope; null when there is nothing honest
 * to say.
 */
function spendHighlight(g) {
  const tokens = spendHighlightTokens(g);
  return tokens === null ? null : tokens.map((t) => (t.num === undefined ? t.text : t.num)).join("");
}

/* Plan headroom — the question the token tiles above structurally cannot
   answer. Tokens keep climbing while the REQUESTS the plan includes run out,
   and the first sign is the agent stopping. Copilot states
   its monthly quota exactly (lib/copilot-quota.ts); a rail that states nothing
   has no row, rather than a zero that would read as "plenty left".

   Not a chart: one magnitude per rail against a known ceiling, which the form
   guide calls a meter. Status colours, thresholds matching the status string,
   and every number written out beside the bar. */
/* The reset instant is the PROVIDER'S boundary, so it is shown in the zone the
   provider stated it in. Copilot's `resetDate` is midnight UTC on the 1st;
   rendering that in a western local zone says "resets Sep 30", which
   contradicts what GitHub's own billing page tells the same person. */
function resetLabel(iso) {
  const ms = Date.parse(iso || "");
  if (!Number.isFinite(ms)) return null;
  return new Date(ms).toLocaleDateString(undefined, { month: "short", day: "numeric", timeZone: "UTC" });
}

/* The bucket in words. Copilot's own keys are machine-shaped
   (`premium_interactions`), and "premium interactions requests" is a doubled
   noun nobody says. An unknown bucket falls back to its own key rather than
   being dropped. */
const HEADROOM_BUCKETS = { chat: "chat requests", premium_interactions: "premium requests", completions: "completions" };

function PlanHeadroom({ state }) {
  const windows = (state && state.plan_windows) || [];
  if (windows.length === 0) return null;
  return (
    <Card
      title="Plan headroom"
      hint="What your subscription still includes — the plan's own unit, beside the token counts above."
    >
      <div className="headrooms">
        {windows.map((w) => {
          const reset = resetLabel(w.resets_at);
          const counts = w.used !== undefined && w.entitlement ? w.used + " of " + w.entitlement : null;
          const bucket = w.window_id ? HEADROOM_BUCKETS[w.window_id] || w.window_id.replace(/_/g, " ") : null;
          return (
            <div className="headroom-row" key={w.source + ":" + (w.window_id || "")}>
              <span className="headroom-rail">
                <RailMark source={w.source} size={14} />
                <span className="headroom-name">{SOURCE_NAMES[w.source] || w.source}</span>
              </span>
              <HeadroomBar used_percentage={w.used_percentage} />
              <span className="headroom-note muted">
                {[bucket, counts, reset ? "resets " + reset : null].filter(Boolean).join(" · ")}
              </span>
            </div>
          );
        })}
      </div>
    </Card>
  );
}

/** "42%" — a part's share of a whole, for the token tiles' notes. A share
 *  under half a percent says "<1%" rather than rounding real usage to 0%. */
function shareOf(part, whole) {
  if (!(whole > 0) || !(part > 0)) return "0%";
  const pct = (part / whole) * 100;
  return pct < 0.5 ? "<1%" : Math.round(pct) + "%";
}

/* Punchcard rows, Monday first — the order main/lib/spend.ts folds them in. */
const PUNCH_DAYS = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"];
/* Axis hours: every sixth, in the clock's own short form. */
const PUNCH_TICKS = [
  { h: 0, label: "12a" },
  { h: 6, label: "6a" },
  { h: 12, label: "12p" },
  { h: 18, label: "6p" },
];

/** "12am", "1pm" — a local clock hour (24 wraps to midnight). */
function punchHour(h) {
  const hh = h % 24;
  return (hh % 12 === 0 ? 12 : hh % 12) + (hh < 12 ? "am" : "pm");
}

/** "2pm–3pm" — the hour a punchcard cell covers. */
function punchSpan(h) {
  return punchHour(h) + "–" + punchHour(h + 1);
}

/**
 * When the engaged time happens: local weekday × hour of day, summed over the
 * window (`g.punchcard`, main/lib/spend.ts — each stretch at the hour it
 * began). Circle AREA is the cell's seconds against the busiest cell, so a
 * cell twice as long reads twice as big; an empty hour is a faint dot that
 * keeps the grid legible. Hover reads a cell; the table twin carries each
 * weekday's total and peak hour, so nothing is hover-only.
 */
function WorkPunchcard({ grid, total, days }) {
  const [ref, width] = useChartWidth();
  const [hover, setHover] = useState(null); // { d, h }
  const wrapRef = useRef(null);

  const LABEL_W = 40;
  const PAD_R = 6;
  const ROW_H = 24;
  const AXIS_H = 20;
  const innerW = Math.max(120, width - LABEL_W - PAD_R);
  const colW = innerW / 24;
  const height = ROW_H * 7 + AXIS_H;
  const rMax = Math.max(2, Math.min(colW, ROW_H) / 2 - 1.5);

  let peak = { d: 0, h: 0, v: 0 };
  grid.forEach((row, d) =>
    row.forEach((v, h) => {
      if (v > peak.v) peak = { d, h, v };
    }),
  );
  const radius = (v) => (v > 0 ? Math.max(1.5, Math.sqrt(v / peak.v) * rMax) : 1);
  const dayTotals = grid.map((row) => row.reduce((n, v) => n + v, 0));
  const hourTotals = Array.from({ length: 24 }, (_, h) => grid.reduce((n, row) => n + (row[h] || 0), 0));
  const busiestDay = dayTotals.indexOf(Math.max(...dayTotals));
  const busiestHour = hourTotals.indexOf(Math.max(...hourTotals));
  const aria =
    "Engaged time by weekday and local hour, summed over the last " + days + " days. Busiest hour: " +
    punchSpan(busiestHour) + ", " + fmtDur(hourTotals[busiestHour]) + ". Busiest day: " +
    PUNCH_DAYS[busiestDay] + ", " + fmtDur(dayTotals[busiestDay]) + ". Busiest single slot: " +
    PUNCH_DAYS[peak.d] + " " + punchSpan(peak.h) + ", " + fmtDur(peak.v) + ".";
  const cx = (h) => LABEL_W + colW * h + colW / 2;
  const cy = (d) => ROW_H * d + ROW_H / 2;

  return (
    <div className="chart punchcard" ref={ref}>
      <div className="chart-inner" ref={wrapRef}>
        <svg width={width} height={height} role="img" aria-label={aria} style={{ display: "block" }}>
          {PUNCH_DAYS.map((name, d) => (
            <text
              key={name}
              className={"ax" + (d === busiestDay ? " pc-top" : "")}
              x={0}
              y={cy(d) + 3}
            >
              {name.slice(0, 3)}
            </text>
          ))}
          {PUNCH_TICKS.map((t) => (
            <text key={t.h} className="ax x" x={cx(t.h)} y={height - 6} textAnchor="middle">
              {t.label}
            </text>
          ))}
          {grid.map((row, d) =>
            row.map((v, h) => {
              const on = hover && hover.d === d && hover.h === h;
              return (
                <g key={d + "-" + h} className={"pc-cell" + (v > 0 ? "" : " empty")}>
                  {on ? (
                    <rect x={LABEL_W + colW * h} y={ROW_H * d} width={colW} height={ROW_H} fill="var(--paper-2)" rx="3" />
                  ) : null}
                  <circle cx={cx(h)} cy={cy(d)} r={radius(v)} />
                  <rect
                    x={LABEL_W + colW * h}
                    y={ROW_H * d}
                    width={colW}
                    height={ROW_H}
                    fill="transparent"
                    onMouseEnter={() => setHover({ d, h })}
                    onMouseLeave={() => setHover(null)}
                  />
                </g>
              );
            }),
          )}
        </svg>
      </div>
      {hover ? (
        <ChartTip
          anchor={wrapRef.current}
          x={cx(hover.h)}
          y={ROW_H * (hover.d + 1) + 4}
          title={PUNCH_DAYS[hover.d] + " · " + punchSpan(hover.h)}
          rows={[{ key: "t", label: "Engaged", color: "var(--c1)", value: fmtDur(grid[hover.d][hover.h]) }]}
          note={
            grid[hover.d][hover.h] > 0
              ? shareOf(grid[hover.d][hover.h], total) + " of the window's engaged time"
              : "Nothing recorded in this hour."
          }
        />
      ) : null}
      <TableTwin
        label="the weekly rhythm"
        columns={[
          { key: "day", label: "Day" },
          { key: "total", label: "Engaged", right: true },
          { key: "peak", label: "Busiest hour", right: true },
        ]}
        rows={PUNCH_DAYS.flatMap((name, d) => {
          if (!(dayTotals[d] > 0)) return [];
          const row = grid[d];
          const top = row.indexOf(Math.max(...row));
          return [{ day: name, total: fmtDur(dayTotals[d]), peak: punchSpan(top) + " · " + fmtDur(row[top]) }];
        })}
      />
    </div>
  );
}

function GraphsScreen({ state, onOpenTask }) {
  const [range, setRange] = useState(7);
  const [split, setSplit] = useState("task");
  const g = range === 30 ? state.graphs30 : state.graphs;
  const scanning = state.capture.status === "scanning";
  const nothingYet = g.window_tokens === 0 && g.window_seconds === 0;

  const mSeries = modelSeries(g.models);
  const tSeries = taskSeries(g.time_tasks);
  /* The by-rail series. With five possible rails a per-host color is no longer
     a thing the reader can hold in their head, so these are POSITIONAL like
     every other categorical series in the app: the theme's fixed ramp, indexed
     by the rail's slot in the snapshot's source list, with anything past the
     ramp folded onto the reserved neutral. The series is labelled in text, so
     nothing here depends on color alone. */
  const railSeries = (g.time_rails || []).map((rail) => ({
    key: rail,
    label: SOURCE_NAMES[rail] || rail,
    color: railColor(state, rail),
    valueOf: (d) => (d.by_rail || {})[rail] || 0,
  }));
  const timeSeries = split === "rail" && railSeries.length > 0 ? railSeries : tSeries;
  const highlight = spendHighlightTokens(g);
  const exposuresByTask = (state.radar && state.radar.exposures_by_task) || [];
  const radarSummary = (state.radar && state.radar.summary) || {};
  /* The Radar's own total (what the sidebar badge prints): the by-use-case
     rows below can sum past it, since an exposure spanning use cases counts
     in each. */
  const openExposures =
    radarSummary.open_exposures != null
      ? radarSummary.open_exposures
      : exposuresByTask.reduce((n, a) => n + a.exposures, 0);
  const todayIso = new Date().toISOString().slice(0, 10);
  const activeDays = g.time_days.filter((d) => d.total > 0).length;
  const perDaySeconds = activeDays > 0 ? g.window_seconds / activeDays : 0;
  const tokensPerHour = g.window_seconds > 0 ? g.window_tokens / (g.window_seconds / 3600) : 0;
  /* A use case wears the color of its chart series — positional by rank, and
     anything folded past the top five wears the reserved "other" neutral. */
  const taskColor = (task) => {
    const i = g.time_tasks.indexOf(task);
    return i >= 0 ? taskSeriesColor(i, task) : "var(--c-other)";
  };
  // Absent on a snapshot from before the field existed.
  const punchTotal =
    Array.isArray(g.punchcard) && g.punchcard.length === 7
      ? g.punchcard.reduce((n, row) => n + row.reduce((a, v) => a + v, 0), 0)
      : 0;

  return (
    <div>
      <div className="screen-head">
        <h1>Usage</h1>
      </div>

      {/* One filter row, above everything it scopes. The range is a segmented
          control, not a pill pair: 7d and 30d are two views of one dataset. */}
      <div className="filterbar">
        <Segmented
          ariaLabel="Window"
          value={range}
          options={SPEND_RANGES.map((r) => ({ key: r.days, label: r.label }))}
          onPick={setRange}
        />
        <span className="spacer" />
        <span className="fb-note">
          {activeDays} of {g.days} days had activity
        </span>
      </div>

      {nothingYet ? (
        <Card>
          <Empty>
            {scanning
              ? "Scanning your transcripts — the last " + g.days + " days will fill in shortly."
              : "No activity in the last " + g.days + " days. Sessions from Claude Code and Codex appear here automatically."}
          </Empty>
        </Card>
      ) : (
        <React.Fragment>
          <div className="herorow">
            <Card className="herocard">
              <Hero
                value={fmtDur(g.window_seconds)}
                label={"Time spent with AI · last " + g.days + " days"}
                tip="Engaged time, not wall clock: turns close together chain into one stretch of work, and idle gaps never count."
                spark={g.time_days.map((d) => d.total)}
                delta={
                  <Delta
                    current={g.window_seconds}
                    prev={g.prev_window_seconds}
                    suffix={"vs prior " + g.days + "d"}
                  />
                }
                note={
                  "≈ " + fmtDur(perDaySeconds) + " per active day" +
                  (tokensPerHour > 0 ? " · " + fmtTokens(tokensPerHour) + " tokens per active hour" : "")
                }
              />
              {/* The hero's supporting stats (ref: Harmonic's hero panel):
                  how many sittings, how many kinds of work, how many days.
                  Today is a tile of its own beside them. */}
              <div className="herostats">
                <span className="hs">
                  <b>{g.window_sessions}</b> session{g.window_sessions === 1 ? "" : "s"}
                </span>
                <span className="hs">
                  <b>{g.by_task.length}</b> use case{g.by_task.length === 1 ? "" : "s"}
                </span>
                <span className="hs">
                  <b>{activeDays}</b> active day{activeDays === 1 ? "" : "s"}
                </span>
              </div>
            </Card>
            {/* Volume keeps its own numbers, as TILES beside the time hero:
                the window's tokens with their trend, and today's. Tokens,
                never dollars. */}
            <div className="statgrid">
              <Kpi
                num={fmtTokens(g.window_tokens)}
                label="Tokens"
                tip="Input and output tokens measured from your transcripts, whatever paid for them — the plan, API credits or an API key. Cache traffic is not counted. No dollar figure is shown: a cost derived on this computer from a rate table is an estimate the app cannot stand behind."
                note={<Delta current={g.window_tokens} prev={g.prev_window_tokens} suffix="vs prior" />}
              />
              <Kpi
                num={fmtTokens(g.today_tokens) + " tokens"}
                label="Today"
                tip="The machine's local calendar day, so far — evenings past the UTC boundary included, which the chart's UTC buckets leave out."
                note={g.today_seconds > 0 ? fmtDur(g.today_seconds) + " engaged today" : "nothing yet today"}
              />
            </div>
          </div>

          {/* Headroom sits directly under the token tiles: it is the same
              question asked in the plan's own unit rather than in tokens, and
              it is the one a person acts on before the month ends. */}
          <PlanHeadroom state={state} />

          {/* The window in one sentence, before any chart — Harmonic leads its
              explorer with a written read, and a person opening this screen
              wants the answer before the evidence. Template over the same
              aggregates the cards below draw; no model, nothing inferred. */}
          {highlight ? (
            <p className="highlight">
              {highlight.map((t, i) =>
                t.num === undefined ? t.text : <b key={i}>{t.num}</b>,
              )}
            </p>
          ) : null}

          <Card
            title="Time spent per day"
            hint="Engaged time — turns close together chain into work; idle gaps never count."
            right={
              <div className="cardctl">
                {railSeries.length > 1 ? (
                  <Segmented
                    ariaLabel="Split"
                    value={split}
                    options={TIME_SPLITS}
                    onPick={setSplit}
                  />
                ) : null}
                <Legend series={timeSeries} />
              </div>
            }
          >
            <ColumnChart
              days={g.time_days}
              series={timeSeries}
              format={fmtDurShort}
              todayIso={todayIso}
              height={224}
              tipNote={
                split === "task" && g.time_tasks.includes("other") && g.by_task.length > g.time_tasks.length
                  ? "Use cases beyond the top five fold into “other”."
                  : undefined
              }
            />
            <TableTwin
              label="the daily hours"
              columns={[
                { key: "day", label: "Day" },
                ...timeSeries.map((s) => ({ key: s.key, label: s.label, right: true })),
                { key: "total", label: "Total", right: true },
              ]}
              rows={g.time_days
                .filter((d) => d.total > 0)
                .map((d) => {
                  const row = { day: fullDayLabel(d.date), total: fmtDur(d.total) };
                  for (const s of timeSeries) row[s.key] = fmtDur(s.valueOf(d));
                  return row;
                })}
            />
          </Card>

          {/* The same engaged time, folded by the clock instead of the
              calendar: which hours of which weekdays the work happens in. */}
          {punchTotal > 0 ? (
            <Card
              title="When you work with AI"
              hint={"Engaged time by weekday and hour, your local time, summed over the last " + g.days + " days."}
            >
              <WorkPunchcard grid={g.punchcard} total={punchTotal} days={g.days} />
            </Card>
          ) : null}

          {/* The use-case directory (ref: Harmonic's Use Cases list): what the
              time was FOR. Hours lead, the trend badge says which way this
              kind of work is moving, sessions/tokens/recency ride the meta
              line, and the track under each row is its share of the window. */}
          {g.by_task.length > 0 ? (
            <Card
              title="Where the time went"
              hint="Every use case in the window, classified on this machine from each session's tools and prompts."
            >
              {/* Each row is a BUTTON into the Event Ledger, filtered to that
                  use case — the drill-down Harmonic puts in a drawer, done
                  with the screen we already have (which carries the search,
                  the turn timeline and the inline radar cards a drawer would
                  have had to reimplement). */}
              <div className="usecases">
                {g.by_task.map((t) => {
                  const exp = exposuresByTask.find((a) => a.task === t.task);
                  return (
                    <button
                      className="uc"
                      key={t.task}
                      onClick={() => onOpenTask(t.task)}
                      title={"Open the " + taskLabel(t.task).toLowerCase() + " sessions in the Event Ledger"}
                    >
                      <span className="uc-swatch" style={{ background: taskColor(t.task) }} />
                      <span className="uc-main">
                        <span className="uc-name">{taskLabel(t.task)}</span>
                        <span className="uc-meta">
                          {t.sessions} session{t.sessions === 1 ? "" : "s"} · {fmtTokens(t.tokens || 0)} tokens
                          {t.last_at ? " · last " + relTime(t.last_at) : ""}
                          {exp && exp.exposures > 0 ? (
                            <span className="uc-alerts">
                              {" · "}
                              {exp.exposures} open exposure{exp.exposures === 1 ? "" : "s"}
                            </span>
                          ) : null}
                        </span>
                        <span className="uc-track">
                          <span
                            style={{
                              width:
                                (g.window_seconds > 0
                                  ? Math.max(1, (t.seconds / g.window_seconds) * 100)
                                  : 0) + "%",
                              background: taskColor(t.task),
                            }}
                          />
                        </span>
                      </span>
                      <span className="uc-time">
                        <span className="uc-hrs">{fmtDur(t.seconds)}</span>
                        <Delta current={t.seconds} prev={t.prev_seconds} suffix="" />
                      </span>
                      <span className="uc-go" aria-hidden="true">
                        <Icon name="chevron" size={14} />
                      </span>
                    </button>
                  );
                })}
              </div>
              <div className="cardnote">
                Deterministic heuristic, not a label you set — a session that both refactors and
                tests lands in whichever signal was strongest. No model, nothing leaves {thisMachine(state.platform)}.
                Click a row to read those sessions in the Event Ledger.
              </div>
            </Card>
          ) : null}

          {/* Time up, exposure down — Harmonic's paired hero: adoption on its
              own is a vanity number, exposures on their own can't tell "more
              risk" from "more work". Two series at two scales must NOT share
              an axis, so this is two panels, each with its own label. The
              exposure side is all-time open, not windowed, and says so. */}
          {openExposures > 0 || g.window_seconds > 0 ? (
            <Card
              title="Adoption and exposure"
              hint={"Engaged time in the last " + g.days + " days, beside the exposures still open on the Radar."}
            >
              <div className="grid2 pairtrend">
                <div>
                  <Hero
                    value={fmtDur(g.window_seconds)}
                    label="Time spent"
                    spark={g.time_days.map((d) => d.total)}
                    delta={
                      <Delta
                        current={g.window_seconds}
                        prev={g.prev_window_seconds}
                        suffix={"vs prior " + g.days + "d"}
                      />
                    }
                  />
                </div>
                <div>
                  <Hero
                    value={String(openExposures)}
                    label={openExposures === 1 ? "Open exposure" : "Open exposures"}
                    tone={openExposures > 0 ? "bad" : undefined}
                    note={
                      exposuresByTask.length > 0
                        ? "most in " + taskLabel(exposuresByTask[0].task).toLowerCase()
                        : "nothing needs review"
                    }
                  />
                </div>
              </div>
              {exposuresByTask.length > 0 ? (
                <React.Fragment>
                  <div className="cardnote">
                    Open exposures by use case — an exposure seen in more than one use case counts in each.
                  </div>
                  <RankedBars
                    rows={exposuresByTask.slice(0, 6).map((a) => ({
                      key: a.task,
                      label: taskLabel(a.task),
                      value: a.exposures,
                      color: taskColor(a.task),
                      title:
                        plural(a.exposures, "open exposure") + " · " + plural(a.sessions, "session"),
                    }))}
                    format={(v) => String(v)}
                    onPick={onOpenTask}
                  />
                </React.Fragment>
              ) : null}
            </Card>
          ) : null}

          <Card title="Running token total">
            <CumulativeArea
              days={g.token_days}
              valueOf={(d) => d.total}
              format={fmtTokens}
              todayIso={todayIso}
              height={168}
            />
            <div className="cardnote">
              A straight climb is a steady stretch; a late kink is the day something ran away.
            </div>
          </Card>

          <Card
            title="Tokens per day by model"
            hint="Each day's tokens, split by model."
            right={<Legend series={mSeries} />}
          >
            <ColumnChart
              days={g.token_days}
              series={mSeries}
              format={fmtTokens}
              todayIso={todayIso}
              height={224}
              tipNote={g.models.length >= 5 ? "Models beyond the top five fold into “other”." : undefined}
            />
          </Card>

          <Card title="Model detail" hint="Every model in the window, by input and output tokens.">
            <table className="rows">
              <thead>
                <tr>
                  <th>Model</th>
                  <th>Source</th>
                  <th className="right">Tokens</th>
                  <th className="right">Share of tokens</th>
                </tr>
              </thead>
              <tbody>
                {g.model_rows.map((row, i) => (
                  <tr key={row.model}>
                    <td>
                      <span className="legend">
                        <span className="item">
                          <span className="swatch" style={{ background: seriesColor(i, row.model) }} />
                          {row.model}
                        </span>
                      </span>
                    </td>
                    <td className="muted">{row.source}</td>
                    <td className="num-cell">{fmtTokens(row.tokens)}</td>
                    <td className="right">
                      <ShareBar
                        share={g.window_tokens > 0 ? row.tokens / g.window_tokens : 0}
                        color={seriesColor(i, row.model)}
                      />
                    </td>
                  </tr>
                ))}
              </tbody>
              {/* A totals row, after the gallery's Records Table closing with
                  its aggregate. "Do these rows add up to the hero figure?" is
                  the first thing anyone checks on a usage table, and without a
                  footer they were checking it by adding six numbers by eye. */}
              <tfoot>
                <tr>
                  <td className="lab">
                    All models · {g.model_rows.length}
                  </td>
                  <td />
                  <td className="num-cell">{fmtTokens(g.window_tokens)}</td>
                  <td className="right lab">all tokens</td>
                </tr>
              </tfoot>
            </table>
          </Card>
        </React.Fragment>
      )}
    </div>
  );
}
