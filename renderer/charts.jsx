/* ============================================================
   Doorman — chart primitives.

   No dependencies, theme tokens only, built to the house dataviz specs:

     · marks are THIN — a column caps at 24px and never fills its slot; the
       leftover is air, not ink
     · a 2px SURFACE GAP separates every touching fill (stacked segments), and
       the data-end is rounded 4px while the baseline stays square, so a stack
       reads as one column of parts rather than a striped block
     · gridlines are solid hairlines one step off the surface — never dashed
       (dashing reads as "projection" when it is just a grid)
     · every mark has a hover readout listing EVERY series at that x, with a
       hit target the width of the whole slot (you aim at a day, not at a bar),
       and the same on keyboard focus
     · values are direct-labelled SELECTIVELY (the peak only) — a number on
       every column is chaos, and the axis plus the table twin carry the rest
     · every chart has a <TableTwin> underneath: no value is reachable only by
       hovering

   The series ramp is theme.css's validated brand palette (--c1…--c8, fixed
   order, adjacent slots crossing hue families). Colors come from tokens, so
   nothing here needs to know about light/dark.
   ============================================================ */

const CHART_GAP = 2; // the surface gap, in px, between stacked segments
/**
 * Column thickness cap. The house spec says 24px, and 24px is right for a dense
 * chart — but these are DAY buckets: a 7-day window across ~800px gives each
 * column a 114px slot, and a 24px mark in a 114px slot reads as an empty chart
 * with a few pins in it. The spec's cap exists to stop a mark becoming a fat
 * block, so the fix is to keep the proportional rule (55% of the slot) and lift
 * the ceiling: 44px at 7 days, ~31px at 14, ~15px at 30. Still air on both
 * sides of every column, never a filled slot.
 */
const CHART_BAR_MAX = 44;
const CHART_RADIUS = 4; // rounded data-end

/** Element width, live. Charts are laid out against the window, and this app's
    window resizes freely — a fixed viewBox would letterbox instead of reflow. */
function useChartWidth(initial = 560) {
  const ref = useRef(null);
  const [w, setW] = useState(initial);
  useEffect(() => {
    if (!ref.current) return;
    const ro = new ResizeObserver((entries) => {
      const cw = entries[0].contentRect.width;
      if (cw > 0) setW(cw);
    });
    ro.observe(ref.current);
    return () => ro.disconnect();
  }, []);
  return [ref, w];
}

/** Clean axis stops (0 / 2k / 4k), so the ticks carry the values no label does. */
function niceTicks(max, count) {
  if (!(max > 0)) return { ticks: [0], top: 1 };
  const raw = max / count;
  const mag = Math.pow(10, Math.floor(Math.log10(raw)));
  const norm = raw / mag;
  const step = (norm >= 5 ? 10 : norm >= 2 ? 5 : norm >= 1 ? 2 : 1) * mag;
  const top = Math.ceil(max / step) * step;
  const ticks = [];
  for (let v = 0; v <= top + 1e-9; v += step) ticks.push(v);
  return { ticks, top };
}

/** How many x labels fit without overprinting (~46px each at the tick size). */
function xLabelEvery(innerW, n) {
  const slots = Math.max(3, Math.min(8, Math.floor(innerW / 46)));
  return Math.max(1, Math.ceil(n / slots));
}

/**
 * Which x positions get a label: every `every`-th, plus ALWAYS the last one
 * (the axis has to state where the range ends) — and a regular tick is dropped
 * when it lands too close to that last one, so a 14-day window at step 2 does
 * not print "MON" and "TODAY" a few pixels apart. When every slot is labelled
 * there is room for all of them, so no gap applies.
 */
function xLabelVisible(i, n, every) {
  if (i === n - 1) return true;
  const gap = every === 1 ? 1 : Math.max(2, Math.ceil(every / 2));
  return i % every === 0 && n - 1 - i >= gap;
}

/** A rect with a rounded data-end and a square baseline. `up` = the rounded
    end is the top (columns grow up); `right` = it's the right edge (bars). */
function markPath(x, y, w, h, r, right) {
  const rad = Math.max(0, Math.min(r, w / 2, h));
  if (right) {
    return `M${x} ${y} H${x + w - rad} Q${x + w} ${y} ${x + w} ${y + rad} V${y + h - rad} Q${x + w} ${y + h} ${x + w - rad} ${y + h} H${x} Z`;
  }
  return `M${x} ${y + rad} Q${x} ${y} ${x + rad} ${y} H${x + w - rad} Q${x + w} ${y} ${x + w} ${y + rad} V${y + h} H${x} Z`;
}

/** Fixed-position tooltip portal'd to <body>, so a card's overflow can't clip
    it. Values lead, series names follow — the reader already has the series. */
function ChartTip({ anchor, x, y, title, rows, total, note }) {
  if (!anchor) return null;
  const r = anchor.getBoundingClientRect();
  const width = 232;
  const left = Math.max(8, Math.min(r.left + x - width / 2, window.innerWidth - width - 8));
  /* The vertical clamp the horizontal one always had: `top: r.top + y` alone
     ran a six-series tooltip off the bottom of the window whenever the hovered
     chart sat low on a long screen. The height is ESTIMATED from the row count
     rather than measured, because the box has not rendered yet and a second
     layout pass to find out would cost a flash at every pointer move — the
     estimate matches the CSS (5px padding, the mono title, ~18px per row) and
     over-estimating only parks the tooltip a few pixels higher. */
  const height = 10 + 16 + rows.length * 18 + (total ? 20 : 0) + (note ? 16 : 0);
  const top = Math.max(8, Math.min(r.top + y, window.innerHeight - height - 8));
  return ReactDOM.createPortal(
    <div className="charttip" style={{ left, top, width }}>
      <div className="tt-title">{title}</div>
      {rows.map((row) => (
        <div className="tt-row" key={row.key}>
          <span className="tt-key" style={{ background: row.color }} />
          <span className="tt-label">{row.label}</span>
          <span className="tt-val">{row.value}</span>
        </div>
      ))}
      {total ? (
        <div className="tt-row total">
          <span className="tt-label">{total.label}</span>
          <span className="tt-val">{total.value}</span>
        </div>
      ) : null}
      {note ? <div className="tt-note">{note}</div> : null}
    </div>,
    document.body,
  );
}

/** Legend — always present for two or more series, never for one (the card
    title already names a single series, and a lone swatch just restates it).

    Pass `days` and the legend stops being a colour key and becomes the chart's
    ranked table: each entry ends in that series' total over the window, so the
    reader gets the magnitudes without hovering a single column. `format` is the
    one the chart itself uses, so the two always agree. */
function Legend({ series, onlyIf = 2, days, format }) {
  if (series.length < onlyIf) return null;
  const fmt = format || ((v) => String(Math.round(v)));
  const totalOf = (s) => days.reduce((sum, d) => sum + (s.valueOf(d) || 0), 0);
  return (
    <div className="legend">
      {series.map((s) => (
        <span className="item" key={s.key}>
          <span className="swatch" style={{ background: s.color }} />
          {s.label}
          {days ? <b className="val">{fmt(totalOf(s))}</b> : null}
        </span>
      ))}
    </div>
  );
}

/**
 * Stacked columns over day buckets.
 *
 * `days` are the buckets ({ date }), `series` the ordered parts
 * ({ key, label, color, valueOf(day) }). One column = one day; the hit target
 * is the whole slot, so a 1px sliver of overage is still hoverable.
 */
function ColumnChart({ days, series, format, height = 208, todayIso, tipNote }) {
  const [ref, width] = useChartWidth();
  const [hover, setHover] = useState(null);
  const wrapRef = useRef(null);

  const PAD_L = 52;
  const PAD_R = 10;
  const PAD_T = 14;
  const AXIS_H = 26; // the x-label band lives INSIDE the box, never clipped
  const innerW = Math.max(80, width - PAD_L - PAD_R);
  const innerH = Math.max(60, height - PAD_T - AXIS_H);

  const totals = days.map((d) => series.reduce((sum, s) => sum + (s.valueOf(d) || 0), 0));
  const { ticks, top } = niceTicks(Math.max(...totals, 0), 3);
  const slot = innerW / Math.max(1, days.length);
  const barW = Math.min(slot * 0.55, CHART_BAR_MAX);
  const every = xLabelEvery(innerW, days.length);
  const peak = totals.indexOf(Math.max(...totals));

  const scale = (v) => (top > 0 ? (v / top) * innerH : 0);

  return (
    <div className="chart" ref={ref}>
      <div className="chart-inner" ref={wrapRef}>
        <svg width={width} height={height} role="img" style={{ display: "block" }}>
          {/* gridlines + y ticks: solid hairlines, one step off the surface */}
          {ticks.map((v) => {
            const y = PAD_T + innerH - scale(v);
            return (
              <g key={v}>
                <line
                  x1={PAD_L}
                  x2={width - PAD_R}
                  y1={y}
                  y2={y}
                  stroke={v === 0 ? "var(--tan-2)" : "var(--tan)"}
                  strokeWidth="1"
                  shapeRendering="crispEdges"
                />
                <text className="ax" x={PAD_L - 8} y={y + 3} textAnchor="end">
                  {format(v)}
                </text>
              </g>
            );
          })}

          {days.map((d, i) => {
            const x = PAD_L + slot * i + (slot - barW) / 2;
            const isToday = todayIso && d.date === todayIso;
            let cursor = PAD_T + innerH;
            const parts = [];
            const stack = series
              .map((s) => ({ s, v: s.valueOf(d) || 0 }))
              .filter((p) => p.v > 0);
            stack.forEach((p, idx) => {
              const raw = scale(p.v);
              const isTop = idx === stack.length - 1;
              // The 2px surface gap is taken off the TOP of each segment, so
              // the stack still totals to its true height at the baseline.
              const h = Math.max(1, raw - (isTop ? 0 : CHART_GAP));
              cursor -= raw;
              parts.push(
                <path
                  key={p.s.key}
                  d={markPath(x, cursor + (isTop ? 0 : CHART_GAP), barW, h, isTop ? CHART_RADIUS : 0)}
                  fill={p.s.color}
                  opacity={hover === null || hover === i ? 1 : 0.58}
                />,
              );
            });
            return (
              <g key={d.date}>
                {hover === i ? (
                  <rect
                    x={PAD_L + slot * i}
                    y={PAD_T}
                    width={slot}
                    height={innerH}
                    fill="var(--paper-2)"
                    rx="3"
                  />
                ) : null}
                {parts}
                {/* Selective direct label: the peak only. */}
                {i === peak && totals[i] > 0 ? (
                  <text className="peak" x={x + barW / 2} y={PAD_T + innerH - scale(totals[i]) - 7} textAnchor="middle">
                    {format(totals[i])}
                  </text>
                ) : null}
                <text
                  className={"ax x" + (isToday ? " today" : "")}
                  x={x + barW / 2}
                  y={height - 8}
                  textAnchor="middle"
                >
                  {isToday ? "TODAY" : xLabelVisible(i, days.length, every) ? dayLabel(d.date) : ""}
                </text>
                {/* Hit target: the whole slot, focusable, so hover and keyboard
                    reach the same readout. */}
                <rect
                  x={PAD_L + slot * i}
                  y={PAD_T}
                  width={slot}
                  height={innerH + AXIS_H}
                  fill="transparent"
                  tabIndex={0}
                  onMouseEnter={() => setHover(i)}
                  onFocus={() => setHover(i)}
                  onMouseLeave={() => setHover(null)}
                  onBlur={() => setHover(null)}
                />
              </g>
            );
          })}
        </svg>
      </div>
      {hover !== null && days[hover] ? (
        <ChartTip
          anchor={wrapRef.current}
          x={PAD_L + slot * hover + slot / 2}
          y={PAD_T}
          title={fullDayLabel(days[hover].date)}
          rows={series
            .map((s) => ({
              key: s.key,
              label: s.label,
              color: s.color,
              raw: s.valueOf(days[hover]) || 0,
            }))
            .filter((r) => r.raw > 0)
            .map((r) => ({ ...r, value: format(r.raw) }))}
          total={{ label: "Total", value: format(totals[hover]) }}
          note={totals[hover] === 0 ? "Nothing recorded this day." : tipNote}
        />
      ) : null}
    </div>
  );
}

/**
 * A cumulative area — where the window's spend actually went, in order. One
 * series, so no legend: 2px line, a 10% wash under it, and an end dot with a
 * 2px surface ring so it stays legible over the fill.
 */
function CumulativeArea({ days, valueOf, format, color = "var(--c1)", height = 150, todayIso }) {
  const [ref, width] = useChartWidth();
  const [hover, setHover] = useState(null);
  const wrapRef = useRef(null);

  const PAD_L = 52;
  const PAD_R = 10;
  const PAD_T = 12;
  const AXIS_H = 24;
  const innerW = Math.max(80, width - PAD_L - PAD_R);
  const innerH = Math.max(48, height - PAD_T - AXIS_H);

  let running = 0;
  const points = days.map((d) => {
    running += valueOf(d) || 0;
    return { date: d.date, value: running };
  });
  const { top } = niceTicks(running, 2);
  const stepX = innerW / Math.max(1, points.length - 1 || 1);
  const xy = points.map((p, i) => [
    PAD_L + stepX * i,
    PAD_T + innerH - (top > 0 ? (p.value / top) * innerH : 0),
  ]);
  const line = xy.map((p, i) => (i ? "L" : "M") + p[0].toFixed(1) + " " + p[1].toFixed(1)).join(" ");
  const area = `${line} L${xy.length ? xy[xy.length - 1][0].toFixed(1) : PAD_L} ${PAD_T + innerH} L${PAD_L} ${PAD_T + innerH} Z`;
  const gid = "cumfill";
  const last = xy[xy.length - 1];
  const every = xLabelEvery(innerW, points.length);

  return (
    <div className="chart" ref={ref}>
      <div className="chart-inner" ref={wrapRef}>
        <svg width={width} height={height} role="img" style={{ display: "block" }}>
          <defs>
            <linearGradient id={gid} x1="0" y1="0" x2="0" y2="1">
              <stop offset="0" stopColor={color} stopOpacity="0.16" />
              <stop offset="1" stopColor={color} stopOpacity="0.02" />
            </linearGradient>
          </defs>
          <line
            x1={PAD_L}
            x2={width - PAD_R}
            y1={PAD_T + innerH}
            y2={PAD_T + innerH}
            stroke="var(--tan-2)"
            strokeWidth="1"
            shapeRendering="crispEdges"
          />
          <text className="ax" x={PAD_L - 8} y={PAD_T + 4} textAnchor="end">
            {format(top)}
          </text>
          <path d={area} fill={`url(#${gid})`} />
          <path d={line} fill="none" stroke={color} strokeWidth="2" strokeLinejoin="round" strokeLinecap="round" />
          {hover !== null && xy[hover] ? (
            <g>
              <line
                x1={xy[hover][0]}
                x2={xy[hover][0]}
                y1={PAD_T}
                y2={PAD_T + innerH}
                stroke="var(--tan-3)"
                strokeWidth="1"
                shapeRendering="crispEdges"
              />
              <circle cx={xy[hover][0]} cy={xy[hover][1]} r="4.5" fill={color} stroke="var(--paper)" strokeWidth="2" />
            </g>
          ) : null}
          {last ? (
            <circle cx={last[0]} cy={last[1]} r="4.5" fill={color} stroke="var(--paper)" strokeWidth="2" />
          ) : null}
          {points.map((p, i) => (
            <g key={p.date}>
              <text
                className="ax x"
                x={PAD_L + stepX * i}
                y={height - 7}
                textAnchor={i === 0 ? "start" : i === points.length - 1 ? "end" : "middle"}
              >
                {todayIso && p.date === todayIso
                  ? "TODAY"
                  : xLabelVisible(i, points.length, every)
                    ? dayLabel(p.date)
                    : ""}
              </text>
              <rect
                x={PAD_L + stepX * i - stepX / 2}
                y={PAD_T}
                width={Math.max(12, stepX)}
                height={innerH + AXIS_H}
                fill="transparent"
                tabIndex={0}
                onMouseEnter={() => setHover(i)}
                onFocus={() => setHover(i)}
                onMouseLeave={() => setHover(null)}
                onBlur={() => setHover(null)}
              />
            </g>
          ))}
        </svg>
      </div>
      {hover !== null && points[hover] ? (
        <ChartTip
          anchor={wrapRef.current}
          x={PAD_L + stepX * hover}
          y={PAD_T}
          title={fullDayLabel(points[hover].date)}
          rows={[
            { key: "cum", label: "Running total", color, value: format(points[hover].value) },
            { key: "day", label: "That day", color: "var(--tan-3)", value: format(valueOf(days[hover]) || 0) },
          ]}
        />
      ) : null}
    </div>
  );
}

/**
 * Horizontal ranked bars — magnitude plus identity, which is what a "top
 * models" or "top rules" list actually is. Value rides the bar's tip (there is
 * a free end, so the label never sits inside the fill).
 */
function RankedBars({ rows, format, height = 22, maxRows = 8, onPick, activeKey }) {
  const shown = rows.slice(0, maxRows);
  const max = Math.max(...shown.map((r) => r.value), 1e-9);
  return (
    <div className="ranked">
      {shown.map((r) => (
        <div
          className={"rk" + (onPick ? " pick" : "") + (activeKey === r.key ? " on" : "")}
          key={r.key}
          onClick={onPick ? () => onPick(r.key) : undefined}
          role={onPick ? "button" : undefined}
          tabIndex={onPick ? 0 : undefined}
          onKeyDown={
            onPick
              ? (e) => {
                  if (e.key !== "Enter" && e.key !== " ") return;
                  e.preventDefault();
                  onPick(r.key);
                }
              : undefined
          }
          title={r.title || undefined}
        >
          <span className="rk-label">{r.label}</span>
          <span className="rk-track" style={{ height }}>
            <span
              className="rk-fill"
              style={{
                width: Math.max(2, (r.value / max) * 100) + "%",
                background: r.color || "var(--c1)",
              }}
            />
          </span>
          <span className="rk-val">{format(r.value)}</span>
          {r.suffix || null}
        </div>
      ))}
    </div>
  );
}

/**
 * The table twin. Every chart gets one: a tooltip may never be the only way to
 * read a value, and this is also the WCAG-clean path for anyone who can't use
 * the hover layer at all.
 */
function TableTwin({ label = "values", columns, rows }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="twin">
      <button className="twin-toggle" aria-expanded={open} onClick={() => setOpen(!open)}>
        {open ? "▾" : "▸"} {open ? "Hide" : "Show"} {label}
      </button>
      {open ? (
        <table className="rows twin-table">
          <thead>
            <tr>
              {columns.map((c) => (
                <th key={c.key} className={c.right ? "right" : ""}>
                  {c.label}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.map((row, i) => (
              <tr key={i}>
                {columns.map((c) => (
                  <td key={c.key} className={c.right ? "num-cell" : ""}>
                    {row[c.key]}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      ) : null}
    </div>
  );
}

/**
 * The hero figure — one per screen, the number the screen is about. Sans (never
 * a display face), proportional figures (tabular-nums makes a big number look
 * loose), with its delta and an optional 12-point sparkline beside it.
 */
function Hero({ value, label, note, delta, spark, sparkColor = "var(--c1)", sparkArea = true, tone, tip }) {
  return (
    <div className={"hero" + (tone ? " tone-" + tone : "")}>
      <div className="hero-lab">
        {tip ? (
          <span className="tipword" data-tip={tip} tabIndex={0}>
            {label}
          </span>
        ) : (
          label
        )}
      </div>
      <div className="hero-row">
        <div className="hero-num">{value}</div>
        {spark && spark.length > 1 ? <MicroSpark data={spark} color={sparkColor} area={sparkArea} /> : null}
      </div>
      <div className="hero-note">
        {delta || null}
        {delta && note ? <span className="dot-sep">·</span> : null}
        {note}
      </div>
    </div>
  );
}

/** A 12-point trend, de-emphasised: it says "shape", the hero says "how much".
    `area` (default on) washes under the line; off, the line stands alone —
    the wash closes flat along the SVG's bottom edge, which on a card whose
    only chart this is read as the chart being cut off. */
function MicroSpark({ data, color, width = 108, height = 34, area = true }) {
  const max = Math.max(...data, 1e-9);
  const span = Math.max(1, data.length - 1);
  const pts = data.map((v, i) => [
    (i / span) * width,
    height - 3 - (v / max) * (height - 8),
  ]);
  const line = pts.map((p, i) => (i ? "L" : "M") + p[0].toFixed(1) + " " + p[1].toFixed(1)).join(" ");
  const last = pts[pts.length - 1];
  return (
    <svg className="microspark" width={width} height={height} aria-hidden="true">
      {area ? <path d={`${line} L${width} ${height} L0 ${height} Z`} fill={color} fillOpacity="0.10" /> : null}
      <path d={line} fill="none" stroke={color} strokeWidth="2" strokeLinejoin="round" strokeLinecap="round" />
      <circle cx={last[0]} cy={last[1]} r="3.5" fill={color} stroke="var(--paper)" strokeWidth="2" />
    </svg>
  );
}

/** A one-row part-to-whole meter (covered / overage / unattributed and
    friends). The 2px surface gap does the separating here too. */
function MeterBar({ parts, height = 8, title }) {
  const total = parts.reduce((n, p) => n + p.value, 0);
  if (!(total > 0)) return null;
  return (
    <span className="meter" style={{ height }} title={title}>
      {parts
        .filter((p) => p.value > 0)
        .map((p) => (
          <span
            key={p.key}
            className="mp"
            style={{ width: (p.value / total) * 100 + "%", background: p.color }}
            title={p.label}
          />
        ))}
    </span>
  );
}
