/* Security Analytics — the WEEKLY screen: "is this working?"

   Where Radar answers "what needs me now" over the worst few findings, this
   reads the whole record over a window the person picks (7 / 14 / 30 / 90
   days). The unit everywhere is an EXPOSURE — one rule × one PLACE
   (main/lib/exposures.ts) — with THINGS (rule × exposed name) and SIGHTINGS
   (rows) shown under it: sixty-seven fixture secrets in one repo are one
   decision, and counting things made 146 sound like 146 problems when it
   was about 40.

   Layout, after beautifului.dev's insight cards and the presentation devices
   catalogued off Harmonic Security's usage explorer:

     · a GENERATED HEADLINE over the two figures that justify it — new
       exposures and how many the guard stopped — each with the delta sentence
       against the window before ("74% fewer than the 14 days before"), so the
       reader gets the conclusion and the evidence at once;
     · the supporting counts as a stat LEDGER rather than a comma run-on;
     · four tiles for the things the ledger can't say — a rate, a latency;
     · the per-day chart of NEW exposures (an exposure counts on the day it was
       first seen — a re-sighting is not news), its legend carrying each
       outcome's window total so the magnitudes read without a hover;
     · a THREE-QUESTION summary — what happened, why it matters, what to do
       next — read straight off the counters, with no model involved;
     · the rule list folded into its FAMILIES, each rule a name plus one meta
       line instead of eleven numeric columns, with the full grid still one
       click away under it;
     · the graduation view (plan A3) beneath.

   Every number comes off `state.radar.rule_stats` — per-rule counters main
   computes over EVERY stored finding for each window — because the snapshot's
   `findings` array is capped at the newest 200 and counting it here would
   print a total that didn't match the Radar hero. */

const ANALYTICS_WINDOWS = [7, 14, 30, 90];

/**
 * "74% fewer than the 14 days before" — the comparison stated as a sentence
 * rather than a signed percentage, because the reader has to know which
 * direction is the good one and "▼ 74%" doesn't say.
 *
 * `tone` is the JUDGEMENT, not the arithmetic, and this sentence is for a
 * measure where FEWER is better — exposures. The stopped figure deliberately
 * doesn't use it: on a count, "11% fewer stopped" would print in red directly
 * under "Enforcement is up.", because both statements are true of a window
 * where exposures fell faster than stops did. It states a share instead.
 *
 * Null when there is nothing to compare against — an unknown direction is not
 * a flat one.
 */
function windowDelta(now, before, days) {
  if (typeof before !== "number" || !Number.isFinite(now)) return null;
  const period = "the " + days + " days before";
  if (before === 0) {
    if (now === 0) return { arrow: "—", text: "none in " + period + " either.", tone: "flat" };
    return { arrow: "▲", text: "up from none in " + period + ".", tone: "worse" };
  }
  if (now === before) return { arrow: "—", text: "the same as " + period + ".", tone: "flat" };
  const down = now < before;
  const pct = Math.round((Math.abs(now - before) / before) * 100);
  return {
    arrow: down ? "▼" : "▲",
    text: pct + "% " + (down ? "fewer" : "more") + " than " + period + ".",
    tone: down ? "better" : "worse",
  };
}

/**
 * The headline, written from the two deltas underneath it.
 *
 * Enforcement is judged on the SHARE stopped, never the count: if exposures
 * halve, the stopped count halving with them is enforcement holding steady,
 * not enforcement failing. The 5-point band keeps a one-exposure wobble in a
 * quiet window from being reported as a trend.
 */
function windowHeadline(newExposures, prev, stopped, days) {
  if (newExposures === 0) {
    return prev && prev.new_exposures > 0 ? "Nothing new surfaced this window." : "Nothing has surfaced yet.";
  }
  if (!prev) return newExposures + " new exposure" + (newExposures === 1 ? "" : "s") + " in the last " + days + " days.";
  const first =
    prev.new_exposures === 0
      ? "Exposures are up."
      : newExposures < prev.new_exposures
        ? "Exposures are down."
        : newExposures > prev.new_exposures
          ? "Exposures are up."
          : "Exposures held steady.";
  // A share needs a denominator on both sides; without one the sentence stops
  // at the half it can stand behind.
  if (newExposures === 0 || prev.new_exposures === 0) return first;
  const share = stopped / newExposures;
  const prevShare = prev.stopped / prev.new_exposures;
  const second =
    share > prevShare + 0.05 ? "Enforcement is up." : share < prevShare - 0.05 ? "Enforcement is down." : "Enforcement held steady.";
  return first + " " + second;
}

/** The family a detector belongs to, for the grouped rule directory. Custom
    rules are their own family (they are yours, not ours); anything the tables
    don't know — a retired detector still sitting in old rows — lands in Other
    rather than vanishing. */
function ruleFamilyOf(detector) {
  if (typeof detector === "string" && detector.indexOf("custom:") === 0) {
    return { key: "custom", label: "Your rules" };
  }
  for (const fam of RULE_FAMILIES) if (fam.detectors.includes(detector)) return { key: fam.key, label: fam.label };
  return { key: "other", label: "Other" };
}

const plural = (n, word, suffix = "s") => n + " " + word + (n === 1 ? "" : suffix);
/** For the words whose plural isn't a trailing "s" — "1 family / 5 families". */
const pluralAs = (n, one, many) => n + " " + (n === 1 ? one : many);

function AnalyticsScreen({ state, onOpenRule, onGoRules }) {
  const [days, setDays] = useState(14);
  const [busyExport, setBusyExport] = useState(null);
  const [exported, setExported] = useState(null);
  const policy = state.prefs.policy || {};
  const modes = policy.modes || {};
  const statsByWindow = state.radar.rule_stats || {};
  const stats =
    statsByWindow[days] ||
    { days, total: 0, exposures: 0, new_exposures: 0, things: 0, new_things: 0, daily: [], sessions: 0, prev_sessions: 0, rules: [], decisions: 0, decided_via: {}, scoped_allows: 0 };
  /* Share of the sessions that RAN in the window which tripped at least one
     rule, and the same share one window earlier. Null rather than 0 when
     nothing ran: a rate over no sessions is unknown, not zero. */
  const pct = (n, of) => (of > 0 ? Math.round((n / of) * 100) : null);
  const sessionRate = pct(stats.sessions, stats.window_sessions || 0);
  const prevRate = pct(stats.prev_sessions || 0, stats.prev_window_sessions || 0);
  // Exposures (rule × place) are the unit; a snapshot from before the field
  // existed falls back to things so the screen never shows "undefined".
  const exposures = stats.exposures != null ? stats.exposures : stats.things;
  const newExposures = stats.new_exposures != null ? stats.new_exposures : stats.new_things;

  const enforceable = Object.keys(SEC_DETECTORS).filter((id) => !SEC_DETECTORS[id].radarOnly);
  const customRules = (policy.custom_rules || []).filter((r) => r.enabled !== false);
  const totalRules = Object.keys(SEC_DETECTORS).length + customRules.length;
  const firedIds = new Set(stats.rules.map((r) => r.detector));
  const neverFired =
    totalRules - [...firedIds].filter((id) => SEC_DETECTORS[id] || customRules.some((r) => "custom:" + r.id === id)).length;

  const trendSeries = [
    { key: "blocked", label: OUTCOME_META.blocked.label, color: OUTCOME_META.blocked.color, valueOf: (d) => d.blocked },
    { key: "held", label: OUTCOME_META.held.label, color: OUTCOME_META.held.color, valueOf: (d) => d.held },
    { key: "warned", label: OUTCOME_META.warned.label, color: OUTCOME_META.warned.color, valueOf: (d) => d.warned },
    { key: "observed", label: OUTCOME_META.observed.label, color: OUTCOME_META.observed.color, valueOf: (d) => d.observed },
  ];
  const daily = stats.daily || [];
  const stopped = daily.reduce((n, d) => n + d.blocked + d.held, 0);
  const warnedThings = daily.reduce((n, d) => n + d.warned, 0);
  const observedThings = daily.reduce((n, d) => n + d.observed, 0);

  // The window before this one, over the same two measures. Absent on a
  // snapshot written before main computed it — then the figures stand without
  // a direction rather than claiming one.
  const prev = stats.prev;
  const headline = windowHeadline(newExposures, prev, stopped, days);
  const exposureDelta = prev ? windowDelta(newExposures, prev.new_exposures, days) : null;
  /* The stopped figure states a SHARE, for the same reason the headline judges
     enforcement on one: 8 of 27 after 9 of 44 is enforcement gaining ground,
     and a delta on the counts would say "11% fewer" right beneath a headline
     that says it is up. Both would be true; together they read as a mistake. */
  const stoppedShare = pct(stopped, newExposures);
  const prevStoppedShare = prev ? pct(prev.stopped, prev.new_exposures) : null;
  const stoppedDelta =
    stoppedShare == null
      ? null
      : prevStoppedShare == null
        ? { arrow: "", text: stoppedShare + "% of them — blocked outright, or held for your call.", tone: "flat" }
        : stoppedShare === prevStoppedShare
          ? { arrow: "—", text: stoppedShare + "% of them, the same share as the " + days + " days before.", tone: "flat" }
          : {
              arrow: stoppedShare > prevStoppedShare ? "▲" : "▼",
              text:
                stoppedShare + "% of them, " + (stoppedShare > prevStoppedShare ? "up" : "down") + " from " +
                prevStoppedShare + "% the " + days + " days before.",
              tone: stoppedShare > prevStoppedShare ? "better" : "worse",
            };

  const modeOf = (detector) => {
    if (detector.indexOf("custom:") === 0) {
      const rule = customRules.find((r) => "custom:" + r.id === detector);
      return rule ? rule.mode : "observe";
    }
    return SEC_DETECTORS[detector] && SEC_DETECTORS[detector].radarOnly ? "radar" : modes[detector] || "observe";
  };
  const modeColor = (mode) =>
    mode === "block" ? "var(--bad)" : mode === "ask" ? "var(--warn)" : mode === "warn" ? "var(--gold)" : "var(--tan-3)";

  // Graduation candidates: enforceable, on observe, fired in the window — the
  // rules whose noise level is now a fact rather than a guess.
  const graduation = stats.rules
    .filter((r) => enforceable.includes(r.detector) && (modes[r.detector] || "observe") === "observe")
    .sort((a, b) => (b.exposures || b.things) - (a.exposures || a.things) || b.things - a.things);

  const exportReport = (format) => {
    setBusyExport(format);
    setExported(null);
    const run =
      format === "detections"
        ? window.doorman.exportDetections()
        : format === "ledger"
          ? window.doorman.exportLedger()
          : window.doorman.exportSecurityReport(format);
    run.then((res) => {
      setBusyExport(null);
      if (res && res.ok) setExported(res.path);
      else if (res && !res.canceled) setExported("error:" + (res.error || "failed"));
    });
  };

  const via = stats.decided_via || {};
  /* Every surface a PERSON answers through — the panel, the window, the
     notification, the editor (the VS Code companion) and the terminal
     (`doorman watch`). The other two values (`timeout`, `app-absent`) are the
     guard deciding alone, which is exactly what this figure is here to
     separate out. */
  const byHuman = (via.panel || 0) + (via.window || 0) + (via.notification || 0) + (via.editor || 0) + (via.terminal || 0);
  const peakDay = daily.reduce((best, d) => (d.total > (best ? best.total : 0) ? d : best), null);
  const topRule = stats.rules.length ? stats.rules[0] : null;

  /* The rule list, folded into families. Groups are ordered by how much of the
     window each one carries rather than by the fixed catalogue order: on a
     screen asking "is this working?", the family doing the most work goes
     first. */
  const groups = [];
  const groupIndex = new Map();
  for (const r of stats.rules) {
    const fam = ruleFamilyOf(r.detector);
    let group = groupIndex.get(fam.key);
    if (!group) {
      group = { key: fam.key, label: fam.label, rules: [], exposures: 0, things: 0 };
      groupIndex.set(fam.key, group);
      groups.push(group);
    }
    group.rules.push(r);
    group.exposures += r.exposures != null ? r.exposures : r.things;
    group.things += r.things;
  }
  groups.sort((a, b) => b.exposures - a.exposures || b.things - a.things || a.label.localeCompare(b.label));

  /* One rule's meta line — the dense sentence that replaces eight numeric
     columns. Only the parts that carry a number are printed: "0 warned" on
     every row is noise, and its absence is the same fact. */
  const ruleMeta = (r) => {
    const parts = [plural(r.things, "thing"), plural(r.fired, "sighting"), plural(r.sessions, "session")];
    const stoppedHere = r.blocked + r.denied;
    if (stoppedHere > 0) parts.push(stoppedHere + " stopped");
    if (r.warned > 0) parts.push(r.warned + " warned");
    if (r.allowed > 0) parts.push(r.allowed + " allowed");
    if (r.median_hold_ms != null) parts.push("median " + fmtHold(r.median_hold_ms) + " to decide");
    if (r.stood_down > 0) parts.push(r.stood_down + " stood down by a model");
    if (r.rejected > 0) parts.push(r.rejected + " rejected as false positive" + (r.rejected === 1 ? "" : "s"));
    if (typeof r.burned_tokens === "number") parts.push(fmtTokens(r.burned_tokens) + " tokens burned");
    if (r.last_fired_at) parts.push("last " + relTime(r.last_fired_at));
    return parts.join(" · ");
  };

  return (
    <div>
      {/* The title row is SecurityHeader's — see radar.jsx. */}
      <div className="filterbar">
        <Segmented
          ariaLabel="Window"
          value={days}
          options={ANALYTICS_WINDOWS.map((d) => ({ key: d, label: d + " days" }))}
          onPick={setDays}
        />
        <span className="spacer" />
        {/* Every export behind ONE control: the report for a person, and the
            two schema-valid JSON bundles (lib/detection-schema.ts,
            lib/ledger-export.ts) for a security team's tooling. All masked. */}
        <ActionMenu
          label="Export"
          trigger={busyExport ? "Exporting…" : "Export"}
          disabled={!!busyExport}
          items={[
            { id: "markdown", label: "Security report (Markdown)", onPick: () => exportReport("markdown"), hint: "The posture and the window's numbers, for a person to read." },
            { id: "json", label: "Security report (JSON)", onPick: () => exportReport("json") },
            { id: "detections", label: "Detections (JSON)", onPick: () => exportReport("detections"), hint: "Every detection on the Radar in the Doorman detection schema — redacted values as fingerprints only." },
            { id: "ledger", label: "Event Ledger (JSON)", onPick: () => exportReport("ledger"), hint: "Every session and its turns in the Doorman ledger schema — text redacted, values as fingerprints." },
          ]}
        />
      </div>
      {exported ? (
        <div className={"callout" + (exported.indexOf("error:") === 0 ? " bad" : " good")} style={{ marginBottom: "var(--s4)" }}>
          {exported.indexOf("error:") === 0 ? "Couldn't write the report: " + exported.slice(6) : "Saved to " + exported + " — masked excerpts only, nothing raw."}
        </div>
      ) : null}

      {/* The headline states the conclusion; the two figures under it are the
          evidence for each half of it, and the ledger is everything the
          sentence had to leave out. */}
      <Card className="pairwrap">
        <div className="pairhead">
          <h2>{headline}</h2>
          <p>New exposures and what the guard did with them, last {days} days.</p>
        </div>
        <div className="pairfigs">
          <div className="pf">
            <div className="pf-num">{newExposures}</div>
            <div className="pf-lab">New exposure{newExposures === 1 ? "" : "s"} surfaced</div>
            {exposureDelta ? (
              <div className={"pf-delta " + exposureDelta.tone}>
                {exposureDelta.arrow} {exposureDelta.text}
              </div>
            ) : (
              <div className="pf-delta flat">no earlier window to compare against.</div>
            )}
            {daily.length > 1 ? <MicroSpark data={daily.map((d) => d.total)} color="var(--c1)" width={240} height={46} /> : null}
          </div>
          <div className="pf">
            <div className="pf-num">{stopped}</div>
            <div className="pf-lab">Stopped by the guard</div>
            {stoppedDelta ? (
              <div className={"pf-delta " + stoppedDelta.tone}>
                {stoppedDelta.arrow} {stoppedDelta.text}
              </div>
            ) : (
              <div className="pf-delta flat">blocked outright, or held for your call.</div>
            )}
            {daily.length > 1 ? (
              <MicroSpark data={daily.map((d) => d.blocked + d.held)} color={OUTCOME_META.blocked.color} width={240} height={46} />
            ) : null}
          </div>
        </div>
        {/* The supporting counts as rows, not as a comma run-on inside the
            hero note — each one is a different unit and reads as one. */}
        <div className="herostats">
          <span className="hs">
            <b>{exposures}</b> exposure{exposures === 1 ? "" : "s"} needing review
          </span>
          <span className="hs">
            <b>{stats.things}</b> thing{stats.things === 1 ? "" : "s"} under them
          </span>
          <span className="hs">
            <b>{stats.total}</b> sighting{stats.total === 1 ? "" : "s"}
          </span>
          <span className="hs">
            <b>{stats.sessions}</b> session{stats.sessions === 1 ? "" : "s"}
          </span>
          {/* Usage, on a screen about whether the rules are working: what the
              window's stuck loops burned, in tokens. Absent when no loop row
              carried usage — "0" would say "free" when it means "unknown". */}
          {typeof stats.burned_tokens === "number" ? (
            <span className="hs">
              <b>{fmtTokens(stats.burned_tokens)}</b> tokens burned by stuck loops
            </span>
          ) : null}
        </div>
        {newExposures > 0 ? (
          <div className="hero-split">
            <MeterBar
              parts={[
                { key: "blocked", label: "blocked", value: daily.reduce((n, d) => n + d.blocked, 0), color: OUTCOME_META.blocked.color },
                { key: "held", label: "held for you", value: daily.reduce((n, d) => n + d.held, 0), color: OUTCOME_META.held.color },
                { key: "warned", label: "warned", value: warnedThings, color: OUTCOME_META.warned.color },
                { key: "observed", label: "observed", value: observedThings, color: OUTCOME_META.observed.color },
              ]}
              height={10}
              title="What the guard did with each new exposure"
            />
            <div className="sevkeys">
              <span className="sevkey"><span className="sw" style={{ background: OUTCOME_META.blocked.color }} />stopped <b>{stopped}</b></span>
              <span className="sevkey"><span className="sw" style={{ background: OUTCOME_META.warned.color }} />warned <b>{warnedThings}</b></span>
              <span className="sevkey"><span className="sw" style={{ background: OUTCOME_META.observed.color }} />observed <b>{observedThings}</b></span>
            </div>
          </div>
        ) : null}
      </Card>

      {/* The four tiles keep only what the ledger above cannot say: a rate, a
          latency, and the two counts about rules rather than exposures. */}
      <div className="statgrid wide">
        {/* A RATE, not a count: "17 sessions" cannot be managed, "a third
            of the sessions that ran" can — and the prior window says which
            way it is going. The denominator is sessions that RAN in the
            window (main fills it from the session store); with none, there is
            no rate to state and the count stands on its own. */}
        <Kpi
          num={sessionRate != null ? sessionRate + "%" : String(stats.sessions)}
          label="Sessions flagged"
          note={
            sessionRate == null
              ? "No sessions ran in the last " + days + " days, so there is no rate to give."
              : stats.sessions + " of the " + stats.window_sessions + " session" +
                (stats.window_sessions === 1 ? "" : "s") + " that ran in the last " + days + " days" +
                (prevRate == null
                  ? "."
                  : sessionRate === prevRate
                    ? " — the same share as the " + days + " days before."
                    : ", " + (sessionRate < prevRate ? "down" : "up") + " from " + prevRate + "% the " + days +
                      " days before.")
          }
        />
        <Kpi
          num={stats.median_hold_ms != null ? fmtHold(stats.median_hold_ms) : "—"}
          label="Median time to decide"
          note={
            stats.decisions > 0
              ? stats.decisions + " held call" + (stats.decisions === 1 ? "" : "s") + " · " + byHuman + " answered by you"
              : "no held calls decided yet"
          }
        />
        <Kpi
          num={neverFired + " / " + totalRules}
          label="Rules never triggered"
          note={neverFired === totalRules ? "no rule has fired in this window" : "quiet rules are not broken rules"}
        />
        <Kpi
          num={String(stats.rules.length)}
          label="Rules that fired"
          note={peakDay && peakDay.total > 0 ? "busiest day " + fullDayLabel(peakDay.date) + " · " + peakDay.total + " new" : "nothing fired"}
        />
      </div>

      <Card
        title={"New exposures per day · " + days + " days"}
        hint="counted on the day first seen."
        right={<Legend series={trendSeries} days={daily} />}
      >
        {newExposures === 0 ? (
          <Empty>Nothing new surfaced in this window.</Empty>
        ) : (
          <React.Fragment>
            <ColumnChart
              days={daily}
              series={trendSeries}
              format={(v) => String(Math.round(v))}
              todayIso={daily.length ? daily[daily.length - 1].date : undefined}
              height={186}
            />
            <TableTwin
              label="the daily counts"
              columns={[
                { key: "day", label: "Day" },
                { key: "blocked", label: "Blocked", right: true },
                { key: "held", label: "Held", right: true },
                { key: "warned", label: "Warned", right: true },
                { key: "observed", label: "Observed", right: true },
              ]}
              rows={daily
                .filter((d) => d.total > 0)
                .map((d) => ({ day: fullDayLabel(d.date), blocked: d.blocked, held: d.held, warned: d.warned, observed: d.observed }))}
            />
          </React.Fragment>
        )}
      </Card>

      {/* The three questions a person arrives with, in the order they ask them,
          answered off the counters above — no model involved, which is why the
          hint says so. */}
      <Card
        title="What this window says"
        hint="read off the counts on this screen — no model involved"
      >
        <div className="qa">
          <div className="qa-block">
            <h4>What happened</h4>
            {newExposures === 0 ? (
              <p>
                Nothing new surfaced in the last {days} days.
                {exposures > 0
                  ? " " + plural(exposures, "exposure") + " from before the window " + (exposures === 1 ? "is" : "are") + " still open."
                  : " No rule has anything open."}
              </p>
            ) : (
              <p>
                <b>{plural(newExposures, "new exposure")}</b> surfaced across{" "}
                <b>{plural(stats.rules.length, "rule")}</b> in the last {days} days
                {sessionRate != null
                  ? ", in " + stats.sessions + " of the " + plural(stats.window_sessions, "session") + " that ran"
                  : ""}
                .{" "}
                {peakDay && peakDay.total > 0
                  ? "The busiest day was " + fullDayLabel(peakDay.date) + ", with " + peakDay.total + "."
                  : ""}
              </p>
            )}
          </div>

          <div className="qa-block">
            <h4>Why it matters</h4>
            {newExposures === 0 ? (
              <p>
                A quiet window is the result you want, not a gap in coverage —{" "}
                {plural(totalRules - neverFired, "rule")} fired at some point, and{" "}
                {neverFired} {neverFired === 1 ? "has" : "have"} not needed to.
              </p>
            ) : (
              <p>
                <b>{stopped}</b> of them the guard stopped — blocked outright or held for your call —{" "}
                <b>{warnedThings}</b> warned, and <b>{observedThings}</b> only watched: those passed straight through to the
                model.{" "}
                {topRule
                  ? "The rule carrying the most is " +
                    topRule.label +
                    " (" +
                    plural(topRule.exposures != null ? topRule.exposures : topRule.things, "exposure") +
                    " across " +
                    plural(topRule.sessions, "session") +
                    ")."
                  : ""}
                {typeof stats.burned_tokens === "number"
                  ? " Stuck loops burned " + fmtTokens(stats.burned_tokens) + " tokens of model time in this window — usage that bought nothing."
                  : ""}
              </p>
            )}
          </div>

          <div className="qa-block">
            <h4>What to do next</h4>
            {graduation.length > 0 ? (
              <React.Fragment>
                <p>
                  Raise <b>{graduation[0].label}</b> to <b>ask</b>. It fired on{" "}
                  {plural(graduation[0].exposures != null ? graduation[0].exposures : graduation[0].things, "exposure")} across{" "}
                  {plural(graduation[0].sessions, "session")} here, so its noise level is a fact rather than a guess — and on
                  ask, the next call it flags waits for you instead of going through.
                </p>
                <button className="btn" onClick={() => window.doorman.setDetectorMode(graduation[0].detector, "ask")}>
                  Raise {graduation[0].label} to ask
                </button>
              </React.Fragment>
            ) : via.timeout > 0 ? (
              <p>
                {plural(via.timeout, "held call")} timed out and {via.timeout === 1 ? "was" : "were"} denied by default. If
                that is the wrong answer for the rule that held them, lower it to <b>warn</b> on{" "}
                <button className="linkbtn" onClick={onGoRules}>
                  Rules
                </button>
                .
              </p>
            ) : neverFired === totalRules ? (
              <p>
                Nothing has fired yet. Leave the rules where they are and come back after a week of real work — a posture
                set before the noise level is known is a guess.
              </p>
            ) : (
              <p>
                Nothing to change. Every rule that fired in this window is already enforcing, and the watch-only ones stayed
                quiet.
              </p>
            )}
          </div>
        </div>
      </Card>

      {/* The rule list as a DIRECTORY: families, then one row per rule carrying
          a name and a meta line. The eleven-column table it replaces is still
          here, one click down, for anyone who wants to compare a column. */}
      <Card
        title="Rule by rule"
        hint={
          stats.rules.length === 0
            ? "nothing fired in this window"
            : plural(stats.rules.length, "rule") + " of " + totalRules + " fired, in " + pluralAs(groups.length, "family", "families") +
              " — click a rule to open it on Radar"
        }
      >
        {stats.rules.length === 0 ? (
          <Empty>Nothing fired in this window.</Empty>
        ) : (
          <React.Fragment>
            <div className="ruledir">
              {groups.map((group) => (
                <div className="rulegroup" key={group.key}>
                  <div className="rg-head">
                    <span className="rg-name">{group.label}</span>
                    <span className="rg-tail">
                      <b>{group.exposures}</b> exposure{group.exposures === 1 ? "" : "s"} ·{" "}
                      <b>{group.rules.length}</b> rule{group.rules.length === 1 ? "" : "s"} firing
                    </span>
                  </div>
                  {group.rules.map((r) => {
                    const mode = modeOf(r.detector);
                    const count = r.exposures != null ? r.exposures : r.things;
                    return (
                      <div className="rr-row" key={r.detector}>
                        <div className="rr-main">
                          <button className="rule-name" title={r.label + " · " + r.detector} onClick={() => onOpenRule(r.detector)}>
                            <span className={"mode " + (mode === "radar" ? "observe" : mode)}>
                              {mode === "radar" ? "RADAR" : mode.toUpperCase()}
                            </span>
                            <span className="rule-label">{r.label}</span>
                            {r.worst ? <SeverityBadge severity={r.worst} /> : null}
                          </button>
                          <div className="rr-meta">{ruleMeta(r)}</div>
                        </div>
                        <MicroSpark
                          data={r.daily && r.daily.length > 1 ? r.daily : [0, 0]}
                          color={modeColor(mode)}
                          width={96}
                          height={26}
                        />
                        <div className="rr-fig">
                          <b>{count}</b>
                          <span>exposure{count === 1 ? "" : "s"}</span>
                        </div>
                      </div>
                    );
                  })}
                </div>
              ))}
            </div>
            <TableTwin
              label="every rule as columns"
              columns={[
                { key: "rule", label: "Rule" },
                { key: "mode", label: "Mode" },
                { key: "exposures", label: "Exposures", right: true },
                { key: "things", label: "Things", right: true },
                { key: "fired", label: "Seen", right: true },
                { key: "sessions", label: "Sessions", right: true },
                { key: "stopped", label: "Stopped", right: true },
                { key: "allowed", label: "Allowed", right: true },
                { key: "warned", label: "Warned", right: true },
                { key: "decide", label: "Decide", right: true },
              ]}
              rows={stats.rules.map((r) => ({
                rule: r.label,
                mode: modeOf(r.detector),
                exposures: r.exposures != null ? r.exposures : r.things,
                things: r.things,
                fired: r.fired,
                sessions: r.sessions,
                stopped: r.blocked + r.denied,
                allowed: r.allowed,
                warned: r.warned,
                decide: r.median_hold_ms != null ? fmtHold(r.median_hold_ms) : "—",
              }))}
            />
          </React.Fragment>
        )}
        <div className="cardnote">
          {stats.stood_down > 0
            ? stats.stood_down + " sighting" + (stats.stood_down === 1 ? " was" : "s were") + " stood down by a model after the rule fired — kept on the Radar at medium confidence, never announced. "
            : ""}
          {stats.rejected > 0
            ? stats.rejected + " sighting" + (stats.rejected === 1 ? " was" : "s were") + " marked false positive and " + (stats.rejected === 1 ? "is" : "are") + " counted nowhere above. "
            : ""}
          Stopped counts blocked and denied calls. The mode chip is the rule's posture — change it on{" "}
          <button className="linkbtn" onClick={onGoRules}>
            Guardrails →
          </button>
        </div>
      </Card>

      <Card
        title="Ready to enforce"
        hint={
          graduation.length === 0
            ? "no observe-mode rule has fired in this window"
            : graduation.length + " watch-only rule" + (graduation.length === 1 ? "" : "s") + " fired — their noise level is a fact now"
        }
      >
        <div className="cardnote" style={{ marginTop: 0 }}>
          A rule ships on watch until its real-world noise level is known. These have fired on this machine in the
          window; the counts say how many exposures and things, across how many sessions. Raising one to <b>ask</b>{" "}
          holds the next call it flags.
        </div>
        {graduation.length === 0 ? (
          <Empty>Nothing to graduate yet.</Empty>
        ) : (
          <table className="rows rulelist">
            <thead>
              <tr>
                <th>Rule</th>
                <th className="right">Exposures</th>
                <th className="right">Things</th>
                <th className="right" title="sightings — one row per session">Seen</th>
                <th className="right">Sessions</th>
                <th>Worst</th>
                <th>Last</th>
                <th style={{ width: 170 }}></th>
              </tr>
            </thead>
            <tbody>
              {graduation.map((r) => (
                <tr key={r.detector}>
                  <td className="rule-cell">
                    <span className="rule-name" title={r.detector}>
                      <span className="rule-label">{r.label}</span>
                      <span className="mono muted rule-id">{r.detector}</span>
                    </span>
                  </td>
                  <td className="num-cell"><b>{r.exposures != null ? r.exposures : r.things}</b></td>
                  <td className="num-cell muted">{r.things}</td>
                  <td className="num-cell muted">{r.fired}</td>
                  <td className="num-cell">{r.sessions}</td>
                  <td>{r.worst ? <SeverityBadge severity={r.worst} /> : "—"}</td>
                  <td className="muted">{r.last_fired_at ? relTime(r.last_fired_at) : "—"}</td>
                  <td>
                    <div className="row" style={{ gap: "var(--s2)", justifyContent: "flex-end" }}>
                      <button className="btn" onClick={() => window.doorman.setDetectorMode(r.detector, "ask")}>
                        Raise to ask
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>

      {stats.decisions > 0 ? (
        <Card title="How held calls were answered" hint={stats.scoped_allows > 0 ? stats.scoped_allows + " allowed for a whole project" : undefined}>
          <div className="rules-summary" role="note" aria-label="Decisions by surface">
            <span className={"mode-chip hold" + (via.panel ? "" : " zero")}><span className="dot" aria-hidden="true" />floating panel<b>{via.panel || 0}</b></span>
            <span className={"mode-chip hold" + (via.window ? "" : " zero")}><span className="dot" aria-hidden="true" />app window<b>{via.window || 0}</b></span>
            <span className={"mode-chip hold" + (via.notification ? "" : " zero")}><span className="dot" aria-hidden="true" />notification<b>{via.notification || 0}</b></span>
            <span className={"mode-chip block" + (via.timeout ? "" : " zero")}><span className="dot" aria-hidden="true" />timed out<b>{via.timeout || 0}</b></span>
            <span className={"mode-chip watch" + (via["app-absent"] ? "" : " zero")}><span className="dot" aria-hidden="true" />app closed<b>{via["app-absent"] || 0}</b></span>
          </div>
        </Card>
      ) : null}
    </div>
  );
}
