/* Security Analytics — the WEEKLY screen: "is this working?"

   Where Radar answers "what needs me now" over the worst few findings, this
   reads the whole record over a window the person picks (7 / 14 / 30 / 90
   days). The unit everywhere is an EXPOSURE — one rule × one PLACE
   (main/lib/exposures.ts) — with SIGHTINGS (rows) shown under it:
   sixty-seven fixture secrets in one repo are one decision.

   Layout, after beautifului.dev's insight cards and the presentation devices
   catalogued off Harmonic Security's usage explorer:
     · a GENERATED HEADLINE over the two figures that justify it — new
       exposures and how many the guard stopped (blocked, or held and
       denied) — each with the delta sentence against the window before
       ("74% fewer than the 14 days before"), so the reader gets the
       conclusion and the evidence at once;
     · the supporting counts as a stat LEDGER rather than a comma run-on;
     · tiles for what the ledger can't say — a rate, a latency, rule counts;
     · the per-day chart of NEW exposures (an exposure counts on the day it was
       first seen — a re-sighting is not news), its legend carrying each
       outcome's window total so the magnitudes read without a hover;
     · a NEXT STEP read straight off the counters — the rule carrying the
       most, and what to change — with no model involved;
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
 * quiet window from being reported as a trend. A window where nothing was
 * stopped says exactly that — 0% against 0% is not "held steady".
 */
function windowHeadline(newExposures, prev, stopped, allowed, days) {
  if (newExposures === 0) {
    return prev && prev.new_exposures > 0 ? "Nothing new surfaced this window." : "Nothing has surfaced yet.";
  }
  const none = "Nothing was stopped — every new exposure was " + (allowed > 0 ? "observed, warned or allowed." : "observed or warned.");
  if (!prev) {
    const counted = newExposures + " new exposure" + (newExposures === 1 ? "" : "s") + " in the last " + days + " days.";
    return stopped === 0 ? counted + " " + none : counted;
  }
  const first =
    prev.new_exposures === 0
      ? "Exposures are up."
      : newExposures < prev.new_exposures
        ? "Exposures are down."
        : newExposures > prev.new_exposures
          ? "Exposures are up."
          : "Exposures held steady.";
  if (stopped === 0) return first + " " + none;
  // A share needs a denominator on both sides; without one the sentence stops
  // at the half it can stand behind.
  if (prev.new_exposures === 0) return first;
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

/* What happened to each new exposure, worst outcome first — the day buckets
   main writes (lib/findings.ts StatsDay). Blocked and Denied are "stopped";
   Allowed is a hold you let through, so it ran. */
const ANALYTICS_OUTCOMES = [
  { key: "blocked", label: "Blocked", color: OUTCOME_META.blocked.color },
  { key: "denied", label: "Denied", color: OUTCOME_META.held.color },
  { key: "allowed", label: "Allowed", color: OUTCOME_META.excepted.color },
  { key: "warned", label: "Warned", color: OUTCOME_META.warned.color },
  { key: "observed", label: "Observed", color: OUTCOME_META.observed.color },
];

/** Sightings of one rule whose call never ran. `stopped` is main's count; a
    stat without it falls back to blocked + denied + timed out. */
const ruleStopped = (r) => (r.stopped != null ? r.stopped : r.blocked + r.denied + (r.timed_out || 0));

/** Rule modes as prose — the segment labels stay OBS/WARN/ASK/BLOCK. */
const ANALYTICS_MODE_WORDS = { observe: "Observe", warn: "Warn", ask: "Ask", block: "Block" };

const ANALYTICS_REDUCED_MOTION = window.matchMedia ? window.matchMedia("(prefers-reduced-motion: reduce)") : null;
const analyticsReducedMotion = () => !!(ANALYTICS_REDUCED_MOTION && ANALYTICS_REDUCED_MOTION.matches);

/**
 * A figure that counts up to its value over ~600ms — from 0 on first mount and
 * whenever `resetKey` (the window) changes, from the figure already shown when
 * only the value moved (a new snapshot). One rAF run per change, nothing
 * afterwards; under reduced motion the value is returned as is.
 */
function useCountUp(value, resetKey) {
  const [shown, setShown] = useState(0);
  const shownRef = useRef(0);
  const keyRef = useRef(resetKey);

  useEffect(() => {
    const settle = () => {
      shownRef.current = value;
      setShown(value);
    };
    const from = keyRef.current === resetKey ? shownRef.current : 0;
    keyRef.current = resetKey;
    if (!Number.isFinite(value) || analyticsReducedMotion() || from === value) {
      settle();
      return undefined;
    }
    const t0 = performance.now();
    let raf = requestAnimationFrame(function step(now) {
      const p = Math.min(1, (now - t0) / 600);
      const v = Math.round(from + (value - from) * (1 - Math.pow(1 - p, 3)));
      shownRef.current = v;
      setShown(v);
      if (p < 1) raf = requestAnimationFrame(step);
    });
    // Cut short (unmount, another change): the next run starts from where this stopped.
    return () => cancelAnimationFrame(raf);
  }, [value, resetKey]);

  if (analyticsReducedMotion() || !Number.isFinite(value)) return value;
  // The render that switches windows, before the effect restarts the count.
  return keyRef.current === resetKey ? shown : 0;
}

const STOPPED_MARKS_CAP = 20;

/** One ◆ per stopped exposure under the Stopped figure, in its outcome's colour
    (blocked first, then denied — the legend's order), capped with "+N".
    aria-hidden: the total is the figure above and the split is the legend. */
function StoppedMarks({ blocked, denied }) {
  const total = blocked + denied;
  if (total <= 0) return null;
  const shownBlocked = Math.min(blocked, STOPPED_MARKS_CAP);
  const shownDenied = Math.min(denied, STOPPED_MARKS_CAP - shownBlocked);
  const marks = [];
  for (let i = 0; i < shownBlocked; i++) marks.push(ANALYTICS_OUTCOMES[0].color);
  for (let i = 0; i < shownDenied; i++) marks.push(ANALYTICS_OUTCOMES[1].color);
  return (
    <div className="pf-marks" aria-hidden="true" title={blocked + " blocked · " + denied + " denied"}>
      {marks.map((color, i) => (
        <span key={i} className="pf-mark" style={{ color }}>◆</span>
      ))}
      {total > marks.length ? <span className="pf-more">+{total - marks.length}</span> : null}
    </div>
  );
}

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

  /* The rule count is the Guardrails count — shipped rules that can act on a
     call plus your own pre-call rules, the same set enforcingCount (app.jsx)
     totals for Settings and the header. Radar-only rules (session-flow
     analysis, your "after …" rules) fire too, but there is no mode to set on
     them, so they are counted on the side rather than inflating the total. */
  const enforceable = Object.keys(SEC_DETECTORS).filter((id) => !SEC_DETECTORS[id].radarOnly);
  const customRules = (policy.custom_rules || []).filter((r) => r.enabled !== false);
  const guardrailIds = new Set([...enforceable, ...customRules.filter((r) => !r.after).map((r) => "custom:" + r.id)]);
  const totalRules = guardrailIds.size;
  const firedGuardrails = stats.rules.filter((r) => guardrailIds.has(r.detector)).length;
  const firedRadarOnly = stats.rules.length - firedGuardrails;
  const neverFired = totalRules - firedGuardrails;

  const trendSeries = ANALYTICS_OUTCOMES.map((o) => ({ key: o.key, label: o.label, color: o.color, valueOf: (d) => d[o.key] || 0 }));
  const daily = stats.daily || [];
  const outcomeTotal = (key) => daily.reduce((n, d) => n + (d[key] || 0), 0);
  const outcomeParts = ANALYTICS_OUTCOMES.map((o) => ({ key: o.key, label: o.label, value: outcomeTotal(o.key), color: o.color }));
  const presentOutcomes = outcomeParts.filter((p) => p.value > 0);
  // Stopped = blocked + denied: a hold you allowed ran, so it is not stopped.
  const stopped = outcomeTotal("blocked") + outcomeTotal("denied");
  const allowedExposures = outcomeTotal("allowed");

  // The window before this one, over the same two measures. Absent on a
  // snapshot written before main computed it — then the figures stand without
  // a direction rather than claiming one.
  const prev = stats.prev;
  const headline = windowHeadline(newExposures, prev, stopped, allowedExposures, days);
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
        ? { arrow: "", text: stoppedShare + "% of them — blocked, or held and denied.", tone: "flat" }
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
      if (rule && rule.after) return "radar";
      return rule ? rule.mode : "observe";
    }
    return SEC_DETECTORS[detector] && SEC_DETECTORS[detector].radarOnly ? "radar" : modes[detector] || "observe";
  };
  const modeColor = (mode) =>
    mode === "block" ? "var(--bad)" : mode === "ask" ? "var(--warn)" : mode === "warn" ? "var(--gold)" : "var(--tan-3)";
  const byExposures = (a, b) => (b.exposures || b.things) - (a.exposures || a.things) || b.fired - a.fired;

  // Graduation candidates: enforceable, on observe, fired in the window — the
  // rules whose noise level is now a fact rather than a guess.
  const graduation = stats.rules
    .filter((r) => enforceable.includes(r.detector) && (modes[r.detector] || "observe") === "observe")
    .sort(byExposures);
  /* The next step's candidates: every Guardrails rule (shipped or yours) that
     fired while on Observe or Warn — on either, the call it flagged went
     through. Ask is the step up that makes the next one wait for you. */
  const raisable = stats.rules
    .filter((r) => guardrailIds.has(r.detector) && ["observe", "warn"].includes(modeOf(r.detector)))
    .sort(byExposures);
  // The reading the sidebar and the header use (app.jsx), so "off" means the same here.
  const protection = protectionState(state, enforcingCount(state));
  const guardOff = protection.kind === "off";

  // The hero figures and tile numbers count up per window (useCountUp).
  const shownNewExposures = useCountUp(newExposures, days);
  const shownStopped = useCountUp(stopped, days);
  const shownRate = useCountUp(sessionRate != null ? sessionRate : stats.sessions, days);
  const shownNeverFired = useCountUp(neverFired, days);
  const shownFired = useCountUp(stats.rules.length, days);

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
  const next = raisable.length ? raisable[0] : null;
  /* Sightings with no enforcement on them are observed whatever the rule's
     mode: they were read from transcripts after the call ran (before the guard
     was installed, while it was off, or from an agent it doesn't cover), so no
     mode was ever applied. Said beside a Warn rule so "Warn · 0 warned" isn't
     a contradiction. */
  const observedRows = (r) => Math.max(0, r.fired - r.warned - r.held - r.blocked);

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
    const parts = [plural(r.fired, "sighting"), plural(r.sessions, "session")];
    const stoppedHere = ruleStopped(r);
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
            <div className="pf-num">{shownNewExposures}</div>
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
            <div className="pf-num">{shownStopped}</div>
            <div className="pf-lab">Stopped by the guard</div>
            <StoppedMarks blocked={outcomeTotal("blocked")} denied={outcomeTotal("denied")} />
            {stoppedDelta ? (
              <div className={"pf-delta " + stoppedDelta.tone}>
                {stoppedDelta.arrow} {stoppedDelta.text}
              </div>
            ) : (
              <div className="pf-delta flat">blocked, or held and denied.</div>
            )}
            {daily.length > 1 ? (
              <MicroSpark data={daily.map((d) => (d.blocked || 0) + (d.denied || 0))} color={OUTCOME_META.blocked.color} width={240} height={46} />
            ) : null}
          </div>
        </div>
        {/* The supporting counts as rows, not as a comma run-on inside the
            hero note — each one is a different unit and reads as one. */}
        <div className="herostats">
          {/* Every exposure with a sighting in the window — including ones first
              seen earlier — so it is labelled by its window, never as the
              Radar's all-time open count. */}
          <span className="hs">
            <b>{exposures}</b> exposure{exposures === 1 ? "" : "s"} seen in the last {days} days
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
            {/* One outcome would paint a single-colour 100% bar; the key line
                below already says it. */}
            {presentOutcomes.length > 1 ? (
              <MeterBar parts={outcomeParts} height={10} title="What the guard did with each new exposure" />
            ) : null}
            <div className="sevkeys">
              {presentOutcomes.map((p) => (
                <span className="sevkey" key={p.key}>
                  <span className="sw" style={{ background: p.color }} />
                  {p.label} <b>{p.value}</b>
                </span>
              ))}
            </div>
          </div>
        ) : null}
      </Card>

      {/* The tiles keep only what the ledger above cannot say: a rate, a
          latency, and the two counts about rules rather than exposures. */}
      <div className="statgrid wide">
        {/* A RATE, not a count: "17 sessions" cannot be managed, "a third
            of the sessions that ran" can — and the prior window says which
            way it is going. The denominator is sessions that RAN in the
            window (main fills it from the session store); with none, there is
            no rate to state and the count stands on its own. */}
        <Kpi
          num={sessionRate != null ? shownRate + "%" : String(shownRate)}
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
        {/* No held call decided in the window means no latency to state; the
            tile goes and the grid reflows rather than printing a dash. */}
        {stats.decisions > 0 ? (
          <Kpi
            num={stats.median_hold_ms != null ? fmtHold(stats.median_hold_ms) : "—"}
            label="Median time to decide"
            note={plural(stats.decisions, "held call") + " · " + byHuman + " answered by you"}
          />
        ) : null}
        <Kpi
          num={shownNeverFired + " / " + totalRules}
          label="Rules never triggered"
          note={neverFired === totalRules ? "no rule on Guardrails fired in this window" : "quiet rules are not broken rules"}
        />
        <Kpi
          num={String(shownFired)}
          label="Rules that fired"
          note={
            (firedRadarOnly > 0 ? "incl. " + firedRadarOnly + " Radar-only · " : "") +
            (peakDay && peakDay.total > 0
              ? "busiest day " + fullDayLabel(peakDay.date) + " · " + peakDay.total + " new"
              : stats.rules.length > 0
                ? "nothing new surfaced"
                : "nothing fired")
          }
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
                { key: "denied", label: "Denied", right: true },
                { key: "allowed", label: "Allowed", right: true },
                { key: "warned", label: "Warned", right: true },
                { key: "observed", label: "Observed", right: true },
              ]}
              rows={daily
                .filter((d) => d.total > 0)
                .map((d) => ({
                  day: fullDayLabel(d.date),
                  blocked: d.blocked || 0,
                  denied: d.denied || 0,
                  allowed: d.allowed || 0,
                  warned: d.warned || 0,
                  observed: d.observed || 0,
                }))}
            />
          </React.Fragment>
        )}
      </Card>

      {/* Only what the counts above don't already say: which rule carries the
          window, and what to change. Read off the counters — no model
          involved, which is why the hint says so. */}
      <Card title="What to do next" hint="read off the counts on this screen — no model involved">
        <div className="qa">
          {topRule ? (
            <div className="qa-block">
              <h4>Carrying the most</h4>
              <p>
                <b>{topRule.label}</b> — {plural(topRule.exposures != null ? topRule.exposures : topRule.things, "exposure")}{" "}
                across {plural(topRule.sessions, "session")} in the last {days} days, on{" "}
                {modeOf(topRule.detector) === "radar" ? "the Radar only" : ANALYTICS_MODE_WORDS[modeOf(topRule.detector)] || "Observe"}.
              </p>
            </div>
          ) : null}

          <div className="qa-block">
            <h4>Next step</h4>
            {stats.rules.length === 0 ? (
              <p>
                Nothing has fired yet. Leave the rules where they are and come back after a week of real work — a posture
                set before the noise level is known is a guess.
              </p>
            ) : guardOff ? (
              <p>
                {protection.tampered
                  ? "The guard was changed outside this app, so no rule can act on a call — every rule only observes, whatever its mode. Repair it in "
                  : "Real-time protection is off, so every rule only observes, whatever its mode. Turn it on in "}
                <button className="linkbtn" onClick={onGoRules}>
                  Guardrails →
                </button>
              </p>
            ) : next ? (
              <React.Fragment>
                <p>
                  Set <b>{next.label}</b> to <b>Ask</b>. It is on {ANALYTICS_MODE_WORDS[modeOf(next.detector)]} and flagged{" "}
                  {plural(next.exposures != null ? next.exposures : next.things, "exposure")} across{" "}
                  {plural(next.sessions, "session")} here, each call let through — on Ask, the next one waits for you.
                  {observedRows(next) > 0 && modeOf(next.detector) === "warn"
                    ? " " + plural(observedRows(next), "sighting") + " read as observed, not warned: " +
                      (observedRows(next) === 1 ? "it was" : "they were") +
                      " found in transcripts after the call ran, where no mode applies."
                    : ""}
                  {raisable.length > 1
                    ? " " + pluralAs(raisable.length - 1, "other rule", "other rules") + " on Observe or Warn fired too."
                    : ""}
                </p>
                {next.detector.indexOf("custom:") === 0 ? (
                  <button className="btn" onClick={onGoRules}>
                    Guardrails →
                  </button>
                ) : (
                  <button className="btn" onClick={() => window.doorman.setDetectorMode(next.detector, "ask")}>
                    Set to Ask
                  </button>
                )}
              </React.Fragment>
            ) : via.timeout > 0 ? (
              <p>
                {plural(via.timeout, "held call")} timed out and {via.timeout === 1 ? "was" : "were"} denied by default. If
                that is the wrong answer for the rule that held them, lower it to <b>Warn</b> on{" "}
                <button className="linkbtn" onClick={onGoRules}>
                  Guardrails →
                </button>
              </p>
            ) : (
              <p>
                Nothing to change. Every rule that fired in this window and can act on a call is already on Ask or Block
                {firedRadarOnly > 0 ? "; Radar-only rules have no mode to raise." : "."}
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
            : firedGuardrails + " of " + plural(totalRules, "rule") + " fired" +
              (firedRadarOnly > 0 ? ", plus " + firedRadarOnly + " Radar-only" : "") +
              ", in " + pluralAs(groups.length, "family", "families") + " — click a rule to open it on Radar"
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
                    /* The whole row opens the rule on Radar. The name stays a
                       button so the row is reachable by keyboard; its click
                       bubbles up to the row's handler. */
                    return (
                      <div className="rr-row" key={r.detector} onClick={() => onOpenRule(r.detector)}>
                        <div className="rr-main">
                          <button className="rule-name" title={"Open " + r.label + " on Radar · " + r.detector}>
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
                        <span className="rr-go" aria-hidden="true">
                          <Icon name="chevron" size={14} />
                        </span>
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
                fired: r.fired,
                sessions: r.sessions,
                stopped: ruleStopped(r),
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
            ? "no Observe-mode rule has fired in this window"
            : graduation.length + " Observe-mode rule" + (graduation.length === 1 ? "" : "s") + " fired — their noise level is a fact now"
        }
      >
        <div className="cardnote lead">
          A rule ships on Observe until its real-world noise level is known. These have fired on this machine in the
          window; the counts say how many exposures, across how many sessions. Setting one to <b>Ask</b> holds the next
          call it flags.
        </div>
        {graduation.length === 0 ? (
          <Empty>Nothing to graduate yet.</Empty>
        ) : (
          <table className="rows rulelist">
            <thead>
              <tr>
                <th>Rule</th>
                <th className="right">Exposures</th>
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
                  <td className="num-cell muted">{r.fired}</td>
                  <td className="num-cell">{r.sessions}</td>
                  <td>{r.worst ? <SeverityBadge severity={r.worst} /> : "—"}</td>
                  <td className="muted">{r.last_fired_at ? relTime(r.last_fired_at) : "—"}</td>
                  <td>
                    <div className="row" style={{ gap: "var(--s2)", justifyContent: "flex-end" }}>
                      <button className="btn" onClick={() => window.doorman.setDetectorMode(r.detector, "ask")}>
                        Set to Ask
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
