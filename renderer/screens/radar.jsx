/* Security Radar — the TRIAGE screen: "is anything being STOPPED,
   and what needs me?"

   Reading order, top to bottom:
     1. anything happening RIGHT NOW (a held tool call), then what needs
        attention that is not an exposure — an unreviewed MCP server, an AI
        tool outside the guard. Both are quiet when there is nothing to say:
        the guard's own state is the header's 0/N ratio, and steady-state
        posture is not news.
     2. one hero (exposures needing review) split by what the guard did about
        each, the severity mix, and how far it spread.
     3. ONE filter row — search, severity, rule, rail, outcome, plus a triaged
        toggle that ADDS rows and therefore sits last. While anything narrows,
        the row says how much ("N of M") and offers one counted clear.
     4. the feed, capped at RADAR_PAGE groups behind a "show more": triage is
        read-decide-next over the worst few, not a scroll through everything —
        and the cap is what makes the cut honest, because the count above it
        says exactly how much sits below.

   What LEFT this screen, and where it went:
     · detections over time + "what fires most" → Analytics (the weekly
       "is this working" question, with a real window selector and per-rule
       counters); a rule picked there arrives here as the feed's rule filter
       (`ruleFilter`/`ruleNonce`, lifted into app.jsx).
     · per-rule modes → Rules (the rare, deliberate "what should this machine
       enforce" question) — the posture line links there. The guard toggle
       and hold behaviour stay in Settings.

   Statuses stay richer than the design's reviewed/unreviewed (false positive
   and accepted risk mean different things for tuning). Custom rules exist now
   (Rules → Your rules); a `custom:<id>` row is labelled by its rule. */


/* Groups on screen before "show more" — a page of decisions, not a scrollback.
   Worst-first ordering means what the cap hides is by construction the least
   urgent tail. */
const RADAR_PAGE = 8;

const RADAR_OUTCOMES = [
  { key: "all", label: "Any outcome", short: "Any outcome" },
  { key: "blocked", label: "Blocked", short: "Blocked", dot: "var(--bad)" },
  { key: "held", label: "Held for confirmation", short: "Held", dot: "var(--warn)" },
  { key: "warned", label: "Warned only", short: "Warned", dot: "var(--gold)" },
  { key: "observed", label: "Observed only", short: "Observed", dot: "var(--tan-3)" },
  { key: "excepted", label: "Allowed by an exception", short: "Excepted", dot: "var(--tan-2)" },
];

/** The THING a row is: one rule × one exposed name (main's `thingKey`). */
function thingKeyOf(row) {
  return row.detector + " " + (row.key_name || row.target || row.excerpt || "");
}

/**
 * The card is an EXPOSURE now (main/lib/exposures.ts): one rule in one PLACE —
 * the project a command ran in, the sink a flow ended in, the destination
 * host, the MCP server. Main stamps every snapshot row with `exposure_key`
 * and `place`; the renderer groups on that key and never re-derives it, so the
 * hero, the badge and this list can't disagree. Inside a card the rows fold a
 * second time into THINGS (rule × exposed name) — what there is to rotate —
 * and each thing holds its sightings.
 *
 * A row with no `exposure_key` (a fixture, an older snapshot) falls back to
 * its thing, which is what the card used to be. Open and triaged rows never
 * share a card, so a card dims as a whole or not at all; the group's FACE is
 * its worst row, so the input must already be sorted worst-first.
 */
function groupFindings(sorted) {
  const groups = new Map();
  for (const row of sorted) {
    const bucket = row.status === "open" ? "open" : "triaged";
    const key = (row.exposure_key || thingKeyOf(row)) + " " + bucket;
    let group = groups.get(key);
    if (!group) {
      group = {
        key,
        face: row,
        rows: [],
        occurrences: 0,
        sessions: new Set(),
        outcomes: new Set(),
        latest: row.last_seen_at,
        earliest: row.first_seen_at,
        place: row.place || null,
        place_kind: row.place_kind || null,
        things: new Map(),
      };
      groups.set(key, group);
    }
    group.rows.push(row);
    group.occurrences += Math.max(1, row.occurrences || 1);
    if (row.session_id) group.sessions.add(row.session_id);
    group.outcomes.add(findingOutcome(row));
    if (row.last_seen_at > group.latest) group.latest = row.last_seen_at;
    if (row.first_seen_at < group.earliest) group.earliest = row.first_seen_at;
    const tkey = thingKeyOf(row);
    let thing = group.things.get(tkey);
    if (!thing) {
      thing = { key: tkey, name: row.key_name || row.target || "", face: row, rows: [], latest: row.last_seen_at };
      group.things.set(tkey, thing);
    }
    thing.rows.push(row);
    if (row.last_seen_at > thing.latest) thing.latest = row.last_seen_at;
  }
  return [...groups.values()];
}

/**
 * WHERE the exposure is, in one word — the project the sightings ran in, or
 * whatever place main resolved when there is no directory (a destination
 * host, an MCP server, a sink).
 *
 * ONE derivation, read by both the closed row and the card's WHERE row, so
 * the two can never name different places for the same exposure.
 */
function exposurePlace(face, group) {
  return (face.cwd || group.place || "").split("/").filter(Boolean).pop() || "";
}

/** Things sorted most-sighted first, for the face line and the list. */
function rankedThings(group) {
  return [...group.things.values()].sort((a, b) => b.rows.length - a.rows.length || (a.latest < b.latest ? 1 : -1));
}


/** Worst first: severity band, then most recent. There is no scoring model
 * here, and inventing one to order a list would be a model nobody could
 * defend. */
function sortFindings(rows) {
  const rank = (s) => SEVERITY_ORDER.length - SEVERITY_ORDER.indexOf(s);
  return [...rows].sort((a, b) => {
    const d = rank(b.severity) - rank(a.severity);
    if (d !== 0) return d;
    return a.last_seen_at < b.last_seen_at ? 1 : a.last_seen_at > b.last_seen_at ? -1 : 0;
  });
}


function RadarScreen({
  state,
  onOpenSession,
  onGoRules,
  onGoIntegrations,
  onGoSettings,
  ruleFilter,
  ruleNonce,
  sessionFilter,
  focusFindingId,
  focusNonce,
  trace,
  onTraceClose,
  onTrace,
}) {
  const [status, setStatus] = useState("open"); // open | all
  /* False positives are hidden from the whole feed unless the person asked to
     see them (prefs.show_false_positives) — or arrived by deep link
     at one, in which case THIS visit shows them without touching the
     preference: a link to a hidden card would light nothing. */
  const [revealFp, setRevealFp] = useState(false);
  const showFp = (state.prefs && state.prefs.show_false_positives === true) || revealFp;
  /* Rows in a CONFIDENCE band that is not ticked are folded away the same
     way (prefs.confidence_bands, every band until some are unticked —
     the Confidence menu in the filter row) — in BOTH views, since a lead can
     be open. A deep link to one ticks its band for this visit without
     touching the preference. */
  const [revealBands, setRevealBands] = useState([]);
  /* The session the feed is narrowed to, when the Overview sent you here for
     one — its "Review these in the Radar" used to land on the whole feed,
     which is a link to nowhere in particular. Cleared like any other filter. */
  const [session, setSession] = useState(sessionFilter || null);
  /* One exposure lit up on arrival (the Overview's per-exposure link), then
     forgotten once the flash has run — a re-render must not flash it again. */
  const [focused, setFocused] = useState(focusFindingId || null);
  /* Which card is OPEN. `undefined` is "the first one" — whatever tops the
     feed under the current filters — so the default follows the sort rather
     than pinning a key that a filter might hide. `null` is "none": the person
     shut the open card. Anything else is a key they clicked. One at a time:
     full cards are tall, and the feed is for reading them one after another,
     not side by side. */
  const [expanded, setExpanded] = useState(undefined);
  const [sev, setSev] = useState("all");
  const [rule, setRule] = useState(ruleFilter || "all");
  const [rail, setRail] = useState("all");
  const [outcome, setOutcome] = useState("all");
  const [q, setQ] = useState("");
  // How many GROUPS the feed shows before "show more" — reset whenever any
  // filter changes, or a narrow view inherits the previous view's depth.
  const [shown, setShown] = useState(RADAR_PAGE);
  useEffect(() => {
    setShown(RADAR_PAGE);
  }, [status, sev, rule, rail, outcome, q, session]);
  // A rule picked on Analytics arrives as the feed's filter. The nonce makes a
  // repeat pick of the same rule distinct (see app.jsx).
  useEffect(() => {
    if (ruleNonce) setRule(ruleFilter || "all");
  }, [ruleNonce]);
  // A session (and maybe one exposure in it) picked on the Overview or the
  // Ledger, same shape. An exposure that has already been judged lives under
  // "All", so arriving for one widens the view — a deep link to a card the
  // current tab hides would light nothing.
  useEffect(() => {
    if (!focusNonce) return;
    setSession(sessionFilter || null);
    setFocused(focusFindingId || null);
    if (focusFindingId) {
      const target = state.radar.findings.find((f) => f.finding_id === focusFindingId);
      if (target && target.status !== "open") setStatus("all");
      if (target && target.status === "false_positive") setRevealFp(true);
      const band = confidenceBandOf(target);
      if (target) setRevealBands((r) => (r.indexOf(band) === -1 ? r.concat([band]) : r));
    }
  }, [focusNonce]);
  // Scroll the lit exposure into view once it is on the page, and let the
  // flash run its course exactly once. (The paging guard sits below, after
  // `groups` exists — a lit card behind "show more" is not on the page yet.)
  useEffect(() => {
    if (!focused) return undefined;
    const el = document.getElementById("exposure-focus");
    if (el && el.scrollIntoView) el.scrollIntoView({ block: "start", behavior: "smooth" });
    const t = setTimeout(() => setFocused(null), 2000);
    return () => clearTimeout(t);
  }, [focused, shown]);

  // Every row the feed, the menus and the counts read. Two passes, both
  // PREFERENCES rather than filters. First the confidence bands: a
  // row in a band that is not ticked is out of everything — not a card, not
  // a menu count, not the "of M" — in either view, since a lead can be open.
  // Then the false positives, over what is left: the verdict said
  // it was never a finding. The ticked set is the preference's plus any band
  // a deep link revealed for this visit; `hiddenBands` is the rest, main's
  // rule (components.jsx hiddenConfidenceBands).
  const shownBands = CONFIDENCE_BANDS.filter(
    (b) => confidenceBandsOf(state.prefs).indexOf(b) !== -1 || revealBands.indexOf(b) !== -1,
  );
  const hiddenBands = CONFIDENCE_BANDS.filter((b) => shownBands.indexOf(b) === -1);
  const inBand = state.radar.findings.filter((f) => confidenceShown(f, hiddenBands));
  const withoutFp = inBand.filter((f) => f.status !== "false_positive");
  const all = showFp ? inBand : withoutFp;
  // What an unticked band or a Show box holds back is counted as the CARDS it would
  // add, not as the rows on their own: a false positive shares its triaged
  // card with a resolved or accepted row of the same exposure, a
  // medium-confidence row can sit on a card a high-confidence sighting
  // already opened — so five hidden rows can be three more cards, and a
  // control that promised five and delivered three would read as broken.
  const cards = (rows) => groupFindings(sortFindings(rows)).length;
  // `hiddenFp` is how many EXPOSURES the false-positive pass keeps out of
  // "All", for the control that brings them back.
  const hiddenFp = showFp ? 0 : cards(inBand) - cards(withoutFp);
  // The rows the false-positive pass lets through, whatever their band —
  // what the Confidence menu's counts and the empty state measure against.
  const anyBand = state.radar.findings.filter((f) => showFp || f.status !== "false_positive");
  const inView = (f) => status === "all" || f.status === "open";
  // Every lead folded away in this view, counted once as cards — the empty
  // state's number.
  const hiddenLeads = hiddenBands.length === 0 ? 0 : cards(anyBand.filter(inView)) - cards(all.filter(inView));
  // The SHOW checkboxes (rendered under the filter row). One entry per kind of
  // row the feed folds away by default; each names what it is, whether it is
  // on, how many EXPOSURES it is holding back, and how to flip it. The
  // markup is the list. (The confidence bands are NOT here — three boxes
  // side by side read as three filters, so they are one menu in the filter
  // row, below.)
  const showOptions = [
    {
      key: "false_positives",
      label: "false positives",
      title: showFp
        ? "Exposures judged false positive are in the feed. Untick to leave them out."
        : "Exposures judged false positive are left out of the feed. Tick to see them, with their verdict.",
      on: showFp,
      hidden: hiddenFp,
      set: (on) => {
        setRevealFp(false);
        window.doorman.setPrefs({ show_false_positives: on });
      },
      // Only where one could appear: the queue never holds a judged card, and
      // a box that could change nothing is a box that lies about being off.
      applies: status === "all" && (hiddenFp > 0 || (showFp && all.some((f) => f.status === "false_positive"))),
    },
  ].filter((o) => o.applies);
  const policy = state.prefs.policy || {};
  const modes = policy.modes || {};
  const held = (state.approvals || []).length;

  const enforcing = Object.keys(SEC_DETECTORS).filter(
    (id) => modes[id] === "ask" || modes[id] === "block",
  );
  const holding = Object.keys(SEC_DETECTORS).filter((id) => modes[id] === "ask");

  const openRows = all.filter((f) => f.status === "open");

  // Filtering. Every count in the strip is computed against the OTHER filters,
  // so a menu never offers a choice that would empty the feed silently.
  const passesExcept = (f, except) => {
    if (except !== "status" && status !== "all" && (status === "open") !== (f.status === "open")) return false;
    if (except !== "session" && session && f.session_id !== session) return false;
    if (except !== "sev" && sev !== "all" && f.severity !== sev) return false;
    if (except !== "rule" && rule !== "all" && f.detector !== rule) return false;
    if (except !== "rail" && rail !== "all" && f.source !== rail) return false;
    if (except !== "outcome" && outcome !== "all" && findingOutcome(f) !== outcome) return false;
    if (except !== "q" && q.trim() !== "") {
      const needle = q.trim().toLowerCase();
      const hay = [f.detector, f.key_name, f.excerpt, f.tool_name, f.target, f.session_id]
        .filter(Boolean)
        .join(" ")
        .toLowerCase();
      if (!hay.includes(needle)) return false;
    }
    return true;
  };
  const rows = sortFindings(all.filter((f) => passesExcept(f, null)));
  const groups = groupFindings(rows);
  // A lit exposure that sits behind "show more" gets the page opened to it —
  // scrolling to a card that is not rendered would land on the button.
  useEffect(() => {
    if (!focused) return;
    const at = groups.findIndex((g) => g.rows.some((r) => r.finding_id === focused));
    if (at >= shown) setShown(at + 1);
    // …and open it: a deep link to a shut card would light a headline.
    if (at >= 0) setExpanded(groups[at].key);
  }, [focused, groups.length]);
  const openKey = expanded === undefined ? (groups[0] ? groups[0].key : null) : expanded;
  // Menu counts are GROUP counts: picking "high · 180" and landing on twelve
  // cards would make the strip a liar about what the choice costs you.
  const countBy = (except, pred) =>
    groupFindings(sortFindings(all.filter((f) => passesExcept(f, except) && pred(f)))).length;

  const sevOptions = [
    { key: "all", label: "Any severity", short: "Any severity", count: countBy("sev", () => true) },
    ...SEVERITY_ORDER.map((s) => ({
      key: s,
      label: s[0].toUpperCase() + s.slice(1),
      short: s[0].toUpperCase() + s.slice(1),
      dot: SEV_FILL[s],
      count: countBy("sev", (f) => f.severity === s),
    })).filter((o) => o.count > 0 || o.key === sev),
  ];
  const rulesPresent = [...new Set(all.map((f) => f.detector))];
  // A rule arriving from Analytics may have no row in the capped feed; it still
  // has to be an option, or the menu would show a filter it can't name.
  if (rule !== "all" && !rulesPresent.includes(rule)) rulesPresent.push(rule);
  const ruleOptions = [
    { key: "all", label: "All rules", short: "All rules", count: countBy("rule", () => true) },
    ...rulesPresent
      .map((d) => ({
        key: d,
        label: detectorMeta(d, policy, all.find((f) => f.detector === d)).label,
        short: detectorMeta(d, policy, all.find((f) => f.detector === d)).label,
        count: countBy("rule", (f) => f.detector === d),
      }))
      .sort((a, b) => b.count - a.count),
  ];
  // Every rail the snapshot knows (capture.sources, keyed by TurnSource) plus
  // any rail a stored finding names — a guard-only host has findings and no
  // ledger, and a host whose parser was removed still has its history. Options
  // with no rows are dropped, so the menu never offers an empty view.
  const railsPresent = [
    ...new Set([
      ...Object.keys((state.capture && state.capture.sources) || {}),
      ...all.map((f) => f.source),
    ]),
  ];
  const railOptions = [
    {
      key: "all",
      label: railsPresent.length === 2 ? "Both rails" : "All rails",
      short: railsPresent.length === 2 ? "Both rails" : "All rails",
      count: countBy("rail", () => true),
    },
    ...railsPresent
      .map((s) => ({
        key: s,
        label: SOURCE_LABELS[s] ? SOURCE_LABELS[s].toLowerCase() : s,
        short: SOURCE_LABELS[s] ? SOURCE_LABELS[s].toLowerCase() : s,
        count: countBy("rail", (f) => f.source === s),
      }))
      .filter((o) => o.count > 0 || o.key === rail),
  ];
  const outcomeOptions = RADAR_OUTCOMES.map((o) => ({
    ...o,
    count: o.key === "all" ? countBy("outcome", () => true) : countBy("outcome", (f) => findingOutcome(f) === o.key),
  }));

  // The CONFIDENCE menu: one tick box per band. Counted like the
  // other menus — against every other filter, as cards — per band, so each
  // box says what ticking it brings. Present only while some row sits
  // outside "high" or a band is unticked: a menu whose boxes could
  // change nothing is a menu that lies about having a choice. Never empties:
  // the last ticked band stays ticked, since a feed of nothing has no way
  // back but this menu.
  const bandCount = (b) => cards(anyBand.filter((r) => confidenceBandOf(r) === b && passesExcept(r, null)));
  const bandOptions = CONFIDENCE_BANDS.map((b) => ({
    key: b,
    label: b[0].toUpperCase() + b.slice(1),
    count: bandCount(b),
  }));
  const bandsApplies = hiddenBands.length > 0 || anyBand.some((f) => confidenceBandOf(f) !== "high");
  // The button names the DIMENSION as well as the set — "High only" on its
  // own says nothing about what is high; every reading here ends in the
  // word "confidence".
  const bandsSummary =
    shownBands.length === CONFIDENCE_BANDS.length
      ? "Any confidence"
      : shownBands.map((b, i) => (i === 0 ? b[0].toUpperCase() + b.slice(1) : b)).join(" + ") +
        " confidence" +
        (shownBands.length === 1 ? " only" : "");
  const pickBand = (key) => {
    const ticked = confidenceBandsOf(state.prefs);
    const next = ticked.indexOf(key) === -1 ? ticked.concat([key]) : ticked.filter((b) => b !== key);
    if (next.length === 0) return;
    setRevealBands([]);
    window.doorman.setPrefs({ confidence_bands: next });
  };

  // The five NARROWING controls. The triage segment is deliberately not one of
  // them: it picks which view you are reading (open / triaged / all), and a
  // "clear" that also flipped the view would un-answer a question you asked.
  const activeCount = [
    sev !== "all",
    rule !== "all",
    rail !== "all",
    outcome !== "all",
    q.trim() !== "",
    session !== null,
  ].filter(Boolean).length;
  const narrowed = activeCount > 0;
  const clearAll = () => {
    setSev("all");
    setRule("all");
    setRail("all");
    setOutcome("all");
    setQ("");
    setSession(null);
  };
  /* The narrowed session, by name — the id means nothing to a reader. */
  const sessionTitle = session
    ? ((state.sessions || []).find((x) => x.id === session) || {}).title || "one session"
    : null;
  // What the current triage view holds with no other filter — the "of M" that
  // stops three groups under a filter reading as a machine with three findings.
  // The denominator follows the triage segment (it is a view, not a narrow),
  // so "4 of 19" stays true when triaged rows are showing.
  const viewTotal = groupFindings(
    sortFindings(all.filter((f) => status === "all" || (status === "open") === (f.status === "open"))),
  ).length;

  // The severity mix and the affected-session count come off the SUMMARY, which
  // main computes over every stored finding and over the OPEN rows only — the
  // snapshot's `findings` array is capped at the newest 200 for the bridge, so
  // counting either here would print numbers that didn't add up to the hero
  // beside them. Both are exposure counts. (`by_severity` still exists for the
  // row-level question; nothing a person reads uses it.)

  // TRACE A SECRET (radar-trace.jsx): the Radar's question run backwards, as
  // its own sub page — opened from the bar under the hero, the menus, a
  // card's "trace everywhere" or the ledger's search box. The feed waits
  // behind it; the title row reads "Trace a secret" meanwhile (app.jsx).
  if (trace) {
    return (
      <TraceSecretView
        state={state}
        seed={trace.seed}
        seedNonce={trace.nonce}
        onBack={onTraceClose}
        onOpenSession={onOpenSession}
      />
    );
  }

  return (
    <div>
      {/* No title row here: SecurityHeader renders it (title, the ask beside
          it, the enforcing pill at the far end) for all three security
          screens. */}
      <HeldCallsLine held={held} />

      {/* No "Needs attention" box either. It reported the MACHINE —
          unreviewed MCP servers, tools outside the guard — above a list about
          the WORK, so the page opened on two subjects and the exposures came
          third. Those facts belong with the thing that fixes them: Integrations
          for the servers and the uncovered tools, Settings for the guard. */}

      {/* No hero boxes above the feed. The count, the severity
          split and the by-rule backlog were three summaries of the list
          directly beneath them — read on the way past, never acted on, and
          pushing the first actual exposure below the fold. What survives of
          them is where it belongs: the count is the scope tab's own number,
          the severities are a filter, and the Overview answers "how am I
          doing" for the whole section.

          Trace a secret moved up to the title row — a control, not a summary. */}
      {/* Trace a secret is on the title row (app.jsx SecurityHeader): the
          Radar's one action, level with its name rather than a row of its own. */}

      {/* HOW MANY ARE ACTIVE — the one summary above the feed, back by
          request: the open count as a figure, its 14-day shape, and its
          severity split. Not the outcome scoreboard (that is Analytics'
          subject, and its old tiles were wrong twice over) and not "Needs
          attention" (the machine, not the work). One number the badge, the
          menu bar and the scope tab all agree with, drawn large once. */}
      <ActiveExposures state={state} />

      {/* Detections over time and "what fires most" live on Analytics now — they were read on the way past here, never studied. */}

      {/* One filter row for the feed below it. Never wraps: the triage
          segment is pinned at the right, and the search box gives up width
          instead — a segment that fell under the row whenever its counts grew
          a digit flickered between two places as filters changed. */}
      <div className="filterbar radar-filters">
        <SearchBox
          placeholder="Search rule, key, target, excerpt…"
          value={q}
          onChange={(e) => setQ(e.target.value)}
        />
        {/* Narrowed to a session: the same active vocabulary as a picked
            menu, and clicking it is the clear — there is nothing else to
            pick, so a menu would be one item long. */}
        {session ? (
          <button className="fmenu on fsession" onClick={() => setSession(null)} title="Show every session">
            <span className="fsession-k">Session</span>
            <span className="fsession-t">{sessionTitle}</span>
            <span className="fsession-x" aria-hidden="true">×</span>
          </button>
        ) : null}
        <FilterMenu label="Severity" value={sev} options={sevOptions} onPick={setSev} />
        <FilterMenu label="Rule" value={rule} options={ruleOptions} onPick={setRule} />
        {railOptions.length > 2 ? (
          <FilterMenu label="Rail" value={rail} options={railOptions} onPick={setRail} />
        ) : null}
        {/* Outcome was a chip row, on the argument that the distribution IS
            the filter — as "Any outcome ⌄" you had to open a menu to learn
            that of 185 findings only three were ever blocked. The hero card
            now carries that distribution as pills a few rows up, so the
            argument is spent: what was left was a second, differently-counted
            copy of it (the pills partition the exposures; these counts are
            per-outcome and overlap on a mixed card) sitting in a row of
            dropdowns and looking like none of them. */}
        <FilterMenu label="Outcome" value={outcome} options={outcomeOptions} onPick={setOutcome} />
        {/* The confidence BANDS: tick boxes in one menu — the one
            control here that mostly ADDS rows, and a PREFERENCE, not a
            filter: it survives a relaunch, clear-filters leaves it alone, it
            does not count toward "N filters". At rest it reads "High only";
            any other set wears its bands the way a picked menu wears its
            value. Absent while every row is high-confidence. */}
        {bandsApplies ? (
          <FilterMenu
            label="Confidence"
            multi
            value={shownBands}
            summary={bandsSummary}
            narrowed={shownBands.length !== CONFIDENCE_BANDS.length}
            options={bandOptions}
            onPick={pickBand}
          />
        ) : null}
        <span className="spacer" />
        {/* Last: it is the only control that ADDS rows — everything left of it
            narrows. Two buckets, not three: a TRIAGED tab was a list of
            decisions already made, which is a thing you look at roughly never
            and a place a card could silently land in. What is left is the
            queue and the whole feed, and a judged card is still in "All",
            wearing its verdict — except a FALSE POSITIVE, which "All" leaves
            out until asked (the control under the count row): that
            verdict says there was nothing to see. Both views also leave out
            the rows in a CONFIDENCE band that is not ticked (the
            Confidence menu): a lead is not a thing to review. */}
        <Segmented
          ariaLabel="Triage"
          value={status}
          options={[
            { key: "open", label: "Needs review", count: countBy("status", (f) => f.status === "open") },
            { key: "all", label: "All", count: countBy("status", () => true) },
          ]}
          onPick={setStatus}
        />
      </div>

      {/* How much is in the feed, top-right above it: the total at rest, and
          "shown/total" the moment anything narrows — one number that answers
          both "how much is there" and "how much am I looking at". The reset
          rides on its left, appearing only while there is something to reset.
          It replaces a sentence ("30 exposures · 87 things · 153 sightings")
          that was three counts of three different units in the place the eye
          lands before the first card. */}
      <div className="feedcount-row">
        {narrowed ? (
          <button className="linkbtn" onClick={clearAll}>
            clear {activeCount === 1 ? "filter" : activeCount + " filters"}
          </button>
        ) : null}
        {/* The SHOW checkboxes: what the feed leaves out by default and can be
            asked for. One box — false positives, in the one view they could
            appear in; the confidence bands are one menu
            in the filter row instead of three boxes here. Each is a PREFERENCE, not
            a narrowing filter: it survives a relaunch, the clear-filters
            button leaves it alone (the way the triage segment is left alone),
            and it does not count toward "N filters" — every one of these ADDS
            rows. A box says how many it is holding back. Absent while nothing
            here applies. */}
        {showOptions.length > 0 ? (
          <span className="showchecks" role="group" aria-label="Show">
            <span className="showchecks-k">Show</span>
            {showOptions.map((o) => (
              <label key={o.key} title={o.title}>
                <input type="checkbox" checked={o.on} onChange={(e) => o.set(e.target.checked)} />
                {o.label}
                {o.hidden > 0 ? <span className="showchecks-n">({o.hidden})</span> : null}
              </label>
            ))}
          </span>
        ) : null}
        <span className="spacer" />
        <span className="feedcount" aria-live="polite" title={
          (narrowed ? groups.length + " of " + viewTotal + " exposures shown · " : viewTotal + " exposures · ") +
          rows.length + " sighting" + (rows.length === 1 ? "" : "s") +
          (all.length >= 200 ? " · newest 200 only, older ones stay in the local store" : "")
        }>
          {narrowed ? groups.length + "/" + viewTotal : String(viewTotal)}
          {/* The unit, once, in words — the digits alone left the reader to
              infer whether they counted cards, rules or sightings. Mono digits
              and a proportional word, so the number stays the thing that
              reads first. */}
          <span className="feedcount-unit">
            {" "}
            exposure{(narrowed ? groups.length : viewTotal) === 1 ? "" : "s"}
          </span>
        </span>
      </div>

      {rows.length === 0 ? (
        <Card>
          <Empty>
            {narrowed
              ? "Nothing matches these filters."
              : emptyFeedSentence(status, hiddenFp, hiddenLeads, state.platform)}
            {/* The way out lives in the dead end: the reset the reader needs is
                otherwise back up in a row of six controls, one of which did it. */}
            {narrowed ? (
              <div style={{ marginTop: "var(--s4)" }}>
                <button className="btn" onClick={clearAll}>
                  Clear {activeCount === 1 ? "the filter" : activeCount + " filters"}
                </button>
              </div>
            ) : null}
          </Empty>
        </Card>
      ) : (
        <div className="findings">
          {groups.slice(0, shown).map((g) => (
            <FindingGroup
              key={g.key}
              group={g}
              policy={policy}
              state={state}
              focused={!!focused && g.rows.some((r) => r.finding_id === focused)}
              expanded={g.key === openKey}
              onToggle={() => setExpanded(g.key === openKey ? null : g.key)}
              onGoSettings={onGoSettings}
              onOpenSession={onOpenSession}
              onTrace={onTrace}
              /* Reopening puts a card back into the queue, and the queue is
                 the first tab — so the scope follows it there, instead of the
                 card vanishing out from under the person who just pressed the
                 button on the tab they are on. */
              onReopened={() => setStatus("open")}
            />
          ))}
          {/* Worst-first ordering makes this an honest cut: everything behind
              the button ranks below everything above it, and the button says
              exactly how much that is. */}
          {groups.length > shown ? (
            <button className="btn loadmore" onClick={() => setShown(shown + RADAR_PAGE)}>
              Show {Math.min(RADAR_PAGE, groups.length - shown)} more · {groups.length - shown} below
            </button>
          ) : null}
        </div>
      )}
    </div>
  );
}

function HeldCallsLine({ held }) {
  if (!(held > 0)) return null;
  return (
    <div className="posture on hot">
      <span className="pdot" />
      <div className="ptext">
        <b>
          {held} tool call{held === 1 ? "" : "s"} held right now
        </b>{" "}
        — answer the prompt to let the session continue.
      </div>
    </div>
  );
}

/**
 * One group of alike findings: same rule, same exposed thing.
 *
 * Shut, it says everything a triage decision needs — worst severity, what the
 * rule is, what was exposed, how many times, across how many sessions, and what
 * enforcement did (or "mixed" when the sightings disagree, which is itself the
 * interesting case). Open, it lists the individual sightings.
 *
 * The group-level triage buttons are the point of grouping: with 600 findings on
 * a real machine, "mark reviewed" one row at a time isn't triage, it's data
 * entry. They act on every row in the group, in ONE call.
 */
/**
 * The empty feed's sentence, when no filter is narrowing it. An empty queue
 * with a band unticked says so — "nothing needs review" over a
 * menu holding three rows back would be the page contradicting its own
 * control — and "All" names both kinds of hidden row (false positives too,
 *), each as the number of CARDS its control would add. Pure, so a
 * test can ask it directly.
 */
function emptyFeedSentence(status, hiddenFp, hiddenLeads, platform) {
  const leads = hiddenLeads > 0 ? hiddenLeads + " exposure" + (hiddenLeads === 1 ? "" : "s") + " in an unticked confidence band" : null;
  if (status === "open") {
    return leads
      ? "Nothing needs review in the confidence bands ticked. " + leads + (hiddenLeads === 1 ? " is" : " are") + " folded away — tick the band under Confidence to read " + (hiddenLeads === 1 ? "it" : "them") + "."
      : "Nothing needs review. New findings appear here as sessions run, and as " + (PLATFORM_LABELS[platform] || "system") + " notifications.";
  }
  const fps = hiddenFp > 0 ? hiddenFp + " false positive" + (hiddenFp === 1 ? "" : "s") : null;
  const parts = [fps, leads].filter(Boolean);
  return parts.length > 0 ? "Nothing here but " + parts.join(" and ") + ", hidden." : "No findings here.";
}

/**
 * The figure above the feed: how many exposures are ACTIVE (open, needing
 * review), with the last fortnight's shape beside it and the severity split
 * under it.
 *
 * Every number here is main's. The count is `summary.open_exposures` — the
 * same field the sidebar badge, the menu bar and the "Needs review" tab
 * print, so the four can never disagree. The spark is `rule_stats[14].daily`,
 * new exposures per day, the same series Analytics draws for its 14-day
 * window. The split is `by_severity_exposures`, one bucket per exposure at
 * its worst severity, which is how each card ranks itself.
 *
 * Deliberately NOT here: what the guard did (Analytics' subject, and the
 * hero's old outcome tiles double-counted), and the machine's posture (lives
 * with the things that fix it). One question, answered once.
 */
function ActiveExposures({ state }) {
  const summary = (state.radar && state.radar.summary) || {};
  const open =
    summary.open_exposures != null ? summary.open_exposures : summary.open_groups != null ? summary.open_groups : 0;
  const bySev = summary.by_severity_exposures || summary.by_severity_groups || summary.by_severity || {};
  const stats = ((state.radar && state.radar.rule_stats) || {})[14];
  const daily = (stats && stats.daily) || [];
  const parts = SEVERITY_ORDER.map((sev) => ({ key: sev, label: sev, value: bySev[sev] || 0, color: SEV_FILL[sev] }));
  return (
    <Card className="activecard">
      <div className="active-row">
        <Hero
          value={String(open)}
          label={open === 1 ? "Exposure to review" : "Exposures to review"}
          tone={open > 0 ? "bad" : undefined}
          spark={daily.length > 1 ? daily.map((d) => d.total) : undefined}
          sparkColor="var(--bad)"
          sparkArea={false}
          note={daily.length > 1 ? "new per day · last 14 days" : undefined}
        />
        {open > 0 ? (
          <div className="active-split" role="note" aria-label="Exposures to review by severity">
            <MeterBar parts={parts} height={8} title="Exposures to review by severity" />
            {/* Every band named in text — meaning never rides on colour alone. */}
            <div className="active-key">
              {parts
                .filter((p) => p.value > 0)
                .map((p) => (
                  <span key={p.key} className="sevkey">
                    <span className="sw" aria-hidden="true" style={{ background: p.color }} />
                    <b className="mono">{p.value}</b> {p.label}
                  </span>
                ))}
            </div>
          </div>
        ) : null}
      </div>
    </Card>
  );
}

/* How many names the WHAT WE SAW list shows before it offers the rest. */
const THINGS_SHOWN = 6;

/**
 * One thing in the record: its row — name, how many times, what the guard did
 * to IT — and, open, its sightings and the masked line that fired.
 *
 * The per-thing outcome is where "which of these three actually got out?" is
 * answered; ACTION on the left can only say Mixed for the whole card. Inside,
 * the outcome repeats per sighting ONLY when the thing's sightings disagree:
 * then it is the per-row answer, and when they agree the row above already
 * said it once, and a column of the same word is a column of nothing.
 */
/** How many sightings a thing lists before the rest fold behind "Show N more". */
const SIGHTINGS_SHOWN = 5;

function ThingRecord({ thing: t, open, onToggle, onOpenSession, platform }) {
  const tOutcomes = [...new Set(t.rows.map(findingOutcome))];
  const tOutcome = tOutcomes.length === 1 ? tOutcomes[0] : "mixed";
  const [more, setMore] = useState(false);
  return (
    <div className={"thing" + (open ? " open" : "")}>
      {/* With a toggle the row is the disclosure (chevron and all); without
          one — the Radar card, where the step header does the selecting and
          the record shows one thing — it is a plain heading line. */}
      {onToggle ? (
        <button type="button" className="t-row" onClick={onToggle} aria-expanded={open}>
          <Icon className="t-chev" name="chevron" size={12} />
          <span className="t-name mono" title={t.name || t.face.excerpt}>
            {t.name || t.face.excerpt}
          </span>
          {t.rows.length > 1 ? <span className="t-n">×{t.rows.length}</span> : null}
          <span className={"t-act act-" + tOutcome}>{OUTCOME_WORDS[tOutcome] || tOutcome}</span>
        </button>
      ) : null}
      {/* Without a toggle there is no heading line at all: the step header
          already names the thing, and the card's Where row carries its
          counts — the record is the sightings and the masked line. */}
      {open ? (
        <div className="t-body">
          {/* Its sightings: when, (what happened, if that varies), and the way
              into that session — landing on the turn that fired. */}
          {(more ? t.rows : t.rows.slice(0, SIGHTINGS_SHOWN)).map((r) => {
            const o = findingOutcome(r);
            return (
              <div key={r.finding_id} className="t-sighting">
                <span className="fseen-when">{relTime(r.last_seen_at)}</span>
                {tOutcome === "mixed" ? <span className={"fseen-act act-" + o}>{OUTCOME_WORDS[o] || o}</span> : <span />}
                {r.session_id ? (
                  <button type="button" className="linkbtn" onClick={() => onOpenSession(r.session_id, r.finding_id)}>
                    session →
                  </button>
                ) : (
                  <span />
                )}
              </div>
            );
          })}
          {/* Past five sightings the rest fold behind a disclosure: the first
              five say when and how often; a long tail is a click, not a wall. */}
          {t.rows.length > SIGHTINGS_SHOWN ? (
            <button type="button" className="linkbtn t-more-s" aria-expanded={more} onClick={() => setMore(!more)}>
              {more ? "Show fewer" : "Show " + (t.rows.length - SIGHTINGS_SHOWN) + " more ▾"}
            </button>
          ) : null}
          {/* What fired, masked — the one thing the False Positive call needs
              to see. One click behind the name, never a wall beside the prose.
              The excerpt is a WINDOW (main keeps ~70 characters either side of
              the match, capped per detector), so VIEW RAW is offered here as
              on the Ledger: a deliberate click reads the transcript on this
              Mac and swaps the fuller window into the same box. */}
          <Evidence excerpt={t.face.excerpt} findingId={t.face.finding_id} row={t.face} raw platform={platform} />
        </div>
      ) : null}
    </div>
  );
}

/* The assistant's auto-written WHAT / MEANS / DO NEXT rows are gone: the card's three lines come from the exposure's own account,
   read off the transcript at scan time. "How to fix this?" still asks the
   assistant on demand through `ai:ask`; the summary channel it used to call
   on mount was removed with the rows. */

function FindingGroup({ group, policy, state, focused, expanded, onToggle, onGoSettings, onOpenSession, onTrace, onReopened }) {
  /* Rendered on its own (no `expanded`), the card is the whole card — a
     caller that does not manage the feed's open state gets everything. The
     feed passes a boolean and the toggle. */
  const open = expanded === undefined ? true : !!expanded;
  /* When a card in the feed is OPENED, bring it to the top of the view: the
     one that just shut above it may have been tall, and the reader's eye is
     on the header they clicked, not wherever the page landed. Not on first
     paint — the feed's opening card should not yank the page on load. */
  const cardRef = useRef(null);
  const wasOpen = useRef(open);
  useEffect(() => {
    if (open && !wasOpen.current && cardRef.current && typeof cardRef.current.scrollIntoView === "function") {
      cardRef.current.scrollIntoView({ block: "start", behavior: "smooth" });
    }
    wasOpen.current = open;
  }, [open]);
  const toggleKey = (e) => {
    if (!onToggle) return;
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      onToggle();
    }
  };
  const face = group.face;
  const meta = detectorMeta(face.detector, policy, face);
  const outcomes = [...group.outcomes];
  const outcome = outcomes.length === 1 ? outcomes[0] : "mixed";
  const many = group.rows.length > 1;
  const things = rankedThings(group);
  const manyThings = things.length > 1;
  /* Which thing is open to its sightings and what fired. The top-ranked one
     starts open — on a one-thing card that is the card's whole record, and on
     a many-thing card it is the worst thing's — and the rest are a click, so
     a five-sighting exposure never unrolls every thing at once. */
  /* `openThing` is the REVIEW SELECTION: the thing being reviewed,
     its sightings open on the right and What / Do next written for IT on the
     left. Every card starts on its worst thing — the record's top row — and
     the stepper (or a horizontal swipe on the body) walks the rest and wraps.
     The group account (the generalised story) titles the card; there is no
     "all" step to read it under. */
  const [openThing, setOpenThing] = useState(things[0] ? things[0].key : null);
  const [allThings, setAllThings] = useState(false);
  /* The header is THIS exposure's title when the row carries an account
     (main/lib/account.ts): "`.env` read, then sent to
     `api.example.com`" rather than "Secret read, then egress". It is derived
     from quoted fields at scan time, so it is as stable as the rule's name
     was — it never rewrites itself under a scrolling eye, which is what the
     assistant's late headline used to do and why that was retired. Rows
     minted before accounts existed keep the rule's name. */
  const account = groupAccount(face, group.rows, group.things.size);
  const headline = (account && account.title) || meta.label || face.detector;
  /* "How to fix this?" — on the step panel under Do next, where the reader
     has just been told what to do and may want to ask how. */
  const askButton = state ? (
    <AiAskButton
      contextRef={{ kind: "exposure", finding_id: face.finding_id }}
      question={
      manyThings
      ? "What is this exposure as a whole, which of these things actually matter, and how do I fix it?"
      : "How do I fix this, and is it a false positive?"
      }
      title={(meta.label || face.detector) + (group.place ? " · " + group.place : "")}
    />
  ) : null;
  /* What / Do next follow the selection: the selected thing's own account when
     one is being reviewed, else the group's. The TITLE is always the group's —
     it names the card, not the thing under review. */
  const selectedThing = openThing ? things.find((t) => t.key === openThing) || null : null;
  const storyAccount = selectedThing ? thingAccount(selectedThing) || account : account;
  const scope = manyThings && selectedThing ? { name: selectedThing.name, index: things.indexOf(selectedThing) + 1, total: things.length } : null;
  const stepTo = (key) => {
    setOpenThing(key);
    // A thing beyond the fold is brought into view when stepped to.
    if (key && things.findIndex((t) => t.key === key) >= THINGS_SHOWN) setAllThings(true);
  };
  const step = (dir) => stepTo(stepThing(things.map((t) => t.key), openThing, dir));
  const onSwipe = useSwipeStep(step);
  const setAll = (status) =>
    window.doorman.setFindingStatusBulk(group.rows.map((r) => r.finding_id), status);
  /* The reason the menu is showing, which is NOT yet the card's status:
     choosing one only fills this in, and "Mark reviewed" is what writes it —
     and stays disabled until there is one. Null means undecided, not
     "reviewed without a reason": that is not a state this card can write. */
  const [verdict, setVerdict] = useState(null);

  return (
    <div
      className={
        "finding" +
        (face.status !== "open" ? " triaged" : "") +
        (focused ? " just-focused" : "") +
        (open ? "" : " shut")
      }
      id={focused ? "exposure-focus" : undefined}
      ref={cardRef}
    >
      {/* The card is the LIST ITEM. Shut, it is its header alone: the same
          badge and written sentence it has open — never a second, smaller
          anatomy of rule/place/counts that summarised the answers one click
          away. The feed opens the first card and shuts the rest, so the page
          reads as a list of sentences with one of them expanded, and inside
          the open card the record column folds each thing's sightings behind
          a click of its own.

          The header: the rule's name and the same severity badge the rest of
          the app uses — stable from first paint. What happened here, in a
          sentence about THIS exposure, is the card's first row when the
          assistant has written it. */}
      {/* The header is the disclosure when the feed says so: the whole row
          toggles, so a shut card is one line — badge, sentence, chips — that
          opens where you click it. The ask inside it stops the click, since
          asking about a card is not opening it. */}
      <div
        className="fhead-row"
        {...(onToggle
          ? { role: "button", tabIndex: 0, "aria-expanded": open, onClick: onToggle, onKeyDown: toggleKey }
          : {})}
      >
        {/* Severity LEADS: it is the first thing to know about a sentence you
            have not read yet, and at the head of the line it makes the feed
            scannable down its left edge the way the old row was. */}
        <SeverityBadge severity={face.severity} />
        <span className="fhead">{codeSpans(headline)}</span>
        {/* How many things the card holds, on the header — while the card is
            SHUT. Open, the count hands over to the pager ("1 / 7") on the step
            header, so the number is said once, where it can be walked. */}
        {manyThings && !open ? (
          <span className="chip fhead-count" title={things.length + " things to review in this exposure"}>
            {things.length}
          </span>
        ) : null}
        {/* No PLACEHOLDER chip (2026-09-21): when the value looks like a
            fixture the card's What and Do next say so in words, which is
            where the reader is looking. */}
        {/* The few facts a written sentence cannot carry, and that nothing
            else on the card says: a rule the person WROTE, a row that came in
            through the gateway rather than a transcript, a model that stood
            the rule down, a rule that was unsure of itself, and which app's
            config a config-anchored row came from. Header, not row — there is
            no row any more. */}
        {meta.custom ? <span className="chip">YOURS</span> : null}
        {face.origin === "gateway" ? <span className="chip">GATEWAY</span> : null}
        {assistChip(face.assist) ? <span className="chip" title={assistPhrase(face.assist)}>{assistChip(face.assist)}</span> : null}
        {confidenceChip(face) ? <span className="chip" title={confidencePhrase(face)}>{confidenceChip(face)}</span> : null}
        {face.config_host ? <span className="chip" title={"Found in " + face.config_host + "'s MCP config"}>{face.config_host.toUpperCase()}</span> : null}
        {/* WHEN — the latest sighting, at the header's right, in the same
            relative form every row and card in the app uses ("2h ago"): the
            one fact about an exposure the sentence never carries, and the
            one that decides whether it is this morning's problem or last
            month's. The exact timestamp is the hover. */}
        <span className="fhead-when" title={group.latest}>{relTime(group.latest)}</span>
        {/* The ask ("How to fix this?") used to sit here at the header's far
            corner; it moved into the open card's decisions row (2026-09-21) so
            a shut card is one line — badge, title, when — and the question is
            asked from the card you are reading, not from the list. */}
        {onToggle ? <Icon className="fchev" name="chevron" size={15} /> : null}
      </div>
      {open ? (
      <div className="fbody">
          {/* The card in reading order: the headline above, then
              what it MEANS, where, what the guard DID, and what to do next.
              It used to lead with the rule that fired — the one thing the
              reader cannot act on — and never said what Guardrails did about
              it, which is the difference between "nothing to do" and "rotate
              this now". The per-rule blurb that used to sit here is gone: it
              said the same thing as MEANS one line lower, in the rule's
              words rather than this exposure's. */}
          {/* Prose LEFT, what we actually saw RIGHT (canvas artboard 2b).
              Under the prose the evidence had the full card width and still
              got ellipsised mid-URL — which hides the very part that decides
              whether it matters. Beside it, the column is narrow enough that
              wrapping is the obvious treatment, and the eye can check the
              sentence against the command without scrolling between them. */}
          {/* THE STEP HEADER, one row over both columns: on the
              left, what this step is about — the thing under review, named
              in mono — and at the far right the walk: ‹ 1 of 7 › in a fixed
              slot so the arrows never move, wrapping from the last thing to
              the first. What / Do next below-left and the record below-right are both
              answers about the SAME step, so they share this one heading and
              the rule under it. A horizontal swipe anywhere on the body steps
              the same way. */}
          {manyThings ? (
            <div className="freview">
              <span className="freview-title">
                <span className="freview-k">Reviewing</span> <span className="mono">{(selectedThing && selectedThing.name) || "one thing"}</span>
              </span>
            </div>
          ) : null}
          {/* THE STEP PANEL: everything about the thing under review on one
              soft ground — What / Action / Do next, the record beside them,
              and the review decisions beneath — so the step reads as one
              unit, distinct from the card's foot. */}
          <div className="fstep">
          <div className={"fsplit" + (manyThings ? " fsplit-step" : "")} onWheel={manyThings ? onSwipe : undefined}>
            <div className="fsplit-said">
            <ExposureStory face={face} group={group} state={state} account={storyAccount} stepRows={selectedThing ? selectedThing.rows : group.rows} ask={askButton} />
            {/* The "Details" disclosure that sat here (rule id, second look,
                confidence, chain, burned cost, place, where, seen-range) was
                removed 2026-09-21: the account's sentences and the
                facts line now carry what a person needs, and the rest was a
                spec sheet nobody opened. The row's fields are still on the
                finding; the Event Ledger shows them beside the turn. */}
            </div>
            <div className="fsplit-saw">
              {/* THE RECORD, in the data's own shape: exposure → things →
                  sightings. The left column is the judgment (what it means,
                  what to do); this is everything that happened, at both
                  grains — the things always, the top thing's sightings and
                  what fired open, the rest behind a click each. It used to be
                  two sections at two
                  grains — a names list here, a sightings table folded behind
                  SEEN on the left — sharing a name column and answering
                  "which key, how often, did it get out, show me yesterday's"
                  from opposite sides of the card. */}
              <div className="fsaw-head">
                <span className="fsaw-k">What we saw</span>
                {/* The noun follows the REMEDY (keys to rotate, files to clean),
                    then the size of the record. */}
                <span className="fsaw-n muted">
                  {/* No count here (2026-09-21): the thing's own row says "×2"
                      and lists each sighting with its session, so a summary
                      on the header said the same thing a line early. */}
                </span>
              </div>
              {/* The record follows the step header: the thing under review,
                  alone, open to its sightings. (A one-thing card has no
                  header and simply shows its thing.) */}
              <div className="things">
                {(selectedThing ? [selectedThing] : allThings ? things : things.slice(0, THINGS_SHOWN)).map((t) => (
                  <ThingRecord
                    key={t.key}
                    thing={t}
                    open={t.key === openThing}
                    onOpenSession={onOpenSession}
                    platform={state && state.platform}
                  />
                ))}
                {!selectedThing && things.length > THINGS_SHOWN ? (
                  <button type="button" className="linkbtn t-more" onClick={() => setAllThings(!allThings)}>
                    {allThings ? "Show fewer" : "Show all " + things.length}
                  </button>
                ) : null}
              </div>
            </div>
          </div>
          {/* THE WALK, at the panel's foot, right: the step's place in the
              exposure and the two arrows, under the record it moves. It sat
              in the step header until 2026-09-22 — read as a title control,
              a room away from the columns it changed. Wraps from the last
              thing to the first. */}
          {manyThings && scope ? (
            <div className="fstep-nav" role="group" aria-label="Step through the things in this exposure">
              <span className="fstep-count">
                {scope.index} <span className="fstep-of">of</span> {scope.total}
              </span>
              <button type="button" className="fstep-btn" aria-label="Previous thing" title="Previous (or swipe)" onClick={() => step(-1)}>
                <Icon name="chevron" size={14} className="fstep-prev" />
              </button>
              <button type="button" className="fstep-btn" aria-label="Next thing" title="Next (or swipe)" onClick={() => step(1)}>
                <Icon name="chevron" size={14} className="fstep-next" />
              </button>
            </div>
          ) : null}
          </div>
          {/* THE FOOT, full width under both columns: the facts line on the
              left (rule, place, tools, what the guard did) and Doorman AI on
              the right — a question ABOUT the card, asked once the evidence
              has been read, and kept off the decisions row above so it never
              reads as a third verdict. Optional — off renders a link to the
              setting. */}
          <div className="ffoot">
            <FactsLine face={face} group={group} />
            {/* THE DECISIONS, at the foot's right, inline with the facts:
                pick a reason, then Mark reviewed — one decision for every
                sighting the card holds. */}
          <div className="fdecide">
            <div className="row">
              {face.status === "open" ? (
                <React.Fragment>
                  {/* Pick the verdict, THEN commit it. The menu used to WRITE
                      on click, so a card left the queue the instant a menu item
                      was touched — a misclick with no moment in between, and
                      no way to see what you had chosen before it happened.
                      Now the left control only says what your conclusion was;
                      nothing is written until the button beside it. */}
                  <VerdictMenu value={verdict} onPick={setVerdict} />
                  {/* Disabled until a reason is picked: a review IS its reason
                      — "false positive" or "accepted risk" — and a bare
                      "reviewed" with neither is a card marked read, not a
                      decision anyone could act on later. The button never
                      counts the sightings either ("Mark all 5 reviewed"): the
                      card says "5 sightings in 3 sessions" two rows up, and
                      one decision covers the exposure either way. */}
                  <button
                    className="btn primary"
                    disabled={!verdict}
                    title={verdict ? undefined : "Pick a reason first"}
                    onClick={() => verdict && setAll(verdict)}
                  >
                    {manyThings ? "Mark all reviewed" : "Mark reviewed"}
                  </button>
                </React.Fragment>
              ) : (
                <React.Fragment>
                  {/* Decided. The SAME control, disabled, holding the choice
                      the person made — so the verdict reads back in the place
                      it was chosen rather than as a chip somewhere else on the
                      card that someone has to decode. A plain "Mark reviewed"
                      with no reason picked reads "Reviewed". */}
                  <VerdictMenu value={face.status} disabled />
                  <button
                    className="btn"
                    onClick={() => {
                      setAll("open");
                      setVerdict(null);
                      if (onReopened) onReopened();
                    }}
                  >
                    Reopen{many ? " all" : ""}
                  </button>
                </React.Fragment>
              )}
              {/* "Trace secret…" and "Open session" sat here until 2026-09-21. The way into a session is each sighting's own
                  "session →" link in the record, beside the moment it fired;
                  Trace a secret keeps its place at the top of the Radar. */}
            </div>
          </div>
          </div>


        {/* No sightings block down here: the SEEN row inside the card says
            how many there are and shows the list on the same line, so a
            second copy at the foot was the same table twice. */}
      </div>
      ) : null}
    </div>
  );
}

/** The placeholder families the masked excerpt names — "aws", "" for an
 *  anonymous [redacted] — i.e. which of the window's redacted values this
 *  card is ABOUT. Pure. */
function excerptLabels(parts) {
  const out = new Set();
  for (const p of Array.isArray(parts) ? parts : []) {
    const m = /^\[redacted(?::([a-z0-9_]+))?\]$/.exec(p);
    if (m) out.add(m[1] || "");
  }
  return out;
}

/**
 * The raw window cut around every value redaction removed from it, so the
 * eye lands on the exposed value instead of scanning a block of transcript
 * for it. `secrets` is the reveal's own list (main/lib/reveal.ts) — the exact
 * substrings `redact()` took out of this unit's text, so a plain indexOf is
 * the whole search; no regex is built from a value. A value whose label the
 * card's excerpt masks is `primary` (the finding's own); any other redacted
 * value in the same window is marked but one band softer. With no labelled
 * mark to compare against, every hit is primary.
 *
 * Returns [{ text, hit: false } | { text, hit: true, primary }] in order.
 * Longest value first, so a value that contains another claims the span
 * whole; spans never overlap. Pure; tested in renderer-logic.test.ts.
 */
function highlightSecrets(raw, secrets, primaryLabels) {
  const text = String(raw || "");
  const labels = primaryLabels instanceof Set ? primaryLabels : new Set();
  const values = [];
  const seen = new Set();
  // The reveal names the card's own value outright when it could tell it
  // from the rest (`primary` on one entry); only without that does the
  // label rule decide.
  const list = Array.isArray(secrets) ? secrets : [];
  const flagged = list.some((s) => s && s.primary === true);
  for (const s of list) {
    if (!s || typeof s.value !== "string" || s.value.length < 3 || seen.has(s.value)) continue;
    seen.add(s.value);
    values.push({ value: s.value, primary: flagged ? s.primary === true : labels.size === 0 || labels.has(s.label || "") });
  }
  if (text === "" || values.length === 0) return [{ text, hit: false }];
  values.sort((a, b) => b.value.length - a.value.length);
  const hits = [];
  for (const v of values) {
    let i = text.indexOf(v.value);
    while (i >= 0) {
      const end = i + v.value.length;
      if (!hits.some((h) => i < h.end && end > h.start)) hits.push({ start: i, end, primary: v.primary });
      i = text.indexOf(v.value, end);
    }
  }
  hits.sort((a, b) => a.start - b.start);
  const out = [];
  let last = 0;
  for (const h of hits) {
    if (h.start > last) out.push({ text: text.slice(last, h.start), hit: false });
    out.push({ text: text.slice(h.start, h.end), hit: true, primary: h.primary });
    last = h.end;
  }
  if (last < text.length) out.push({ text: text.slice(last), hit: false });
  return out;
}

function secretForMark(secrets, parts, markIndex) {
  const labelOf = (p) => {
    const m = /^\[redacted(?::([a-z0-9_]+))?\]$/.exec(p);
    return m ? m[1] || "" : null;
  };
  const label = labelOf(parts[markIndex]);
  if (label == null || !Array.isArray(secrets)) return null;
  // Indexed over EVERY same-label value, placeholders included: the nth mark
  // is the nth value. Filtering the literal placeholders out first shifted the
  // index, so a mark whose transcript held a pasted "[redacted]" revealed its
  // NEIGHBOUR's credential. A value that is itself a placeholder was already
  // masked when the agent wrote it — nothing behind it, so no value.
  const matching = secrets.filter((s) => s.label === label && s.value !== "");
  if (matching.length === 0) return null;
  let pick;
  if (matching.length === 1) pick = matching[0];
  else {
    let n = 0;
    for (let i = 0; i < markIndex; i++) if (labelOf(parts[i]) === label) n++;
    pick = matching[n];
  }
  return pick && !isPlaceholderText(pick.value) ? pick.value : null;
}

/** `[redacted]` / `[redacted:aws]` as LITERAL text in the transcript. */
function isPlaceholderText(value) {
  return /^\[redacted(?::[a-z0-9_]+)?\]$/.test(String(value || "").trim());
}

/**
 * The value behind a placeholder, recovered from the RAW window by the text
 * around it. The masked excerpt and the raw text share every character that is
 * not a placeholder, so the literal just before a mark and the literal just
 * after it bracket the value in the raw text. Deterministic, and it never
 * shows more than what sat between the brackets — the whole point, after the
 * fallback for an unmapped mark used to be "here is the entire raw window".
 *
 * Returns { value, partial } or null. `partial` means only one side anchored,
 * so the slice is bounded at a token boundary (or RAW_PEEK chars) rather than
 * known exactly. Pure; tested in test/renderer-logic.test.ts.
 */
const RAW_PEEK = 96;
const ANCHOR_MAX = 40;
const ANCHOR_MIN = 3;
function valueFromRaw(raw, parts, markIndex) {
  if (typeof raw !== "string" || raw === "" || !Array.isArray(parts)) return null;
  const trimEllipsis = (s) => String(s || "").replace(/^…/, "").replace(/…$/, "");
  const anchorBefore = (text) => trimEllipsis(text).slice(-ANCHOR_MAX).trimStart();
  const before = anchorBefore(parts[markIndex - 1]);
  const after = trimEllipsis(parts[markIndex + 1]).slice(0, ANCHOR_MAX).trimEnd();
  const occurrences = (hay, needle) => {
    const out = [];
    let i = hay.indexOf(needle);
    while (i >= 0) {
      out.push(i);
      i = hay.indexOf(needle, i + Math.max(1, needle.length));
    }
    return out;
  };
  // Marks sit at odd indices (split with a capture group). Earlier marks whose
  // preceding literal is the same anchor claim the earlier occurrences.
  let skip = 0;
  for (let i = markIndex - 2; i >= 1; i -= 2) if (anchorBefore(parts[i - 1]) === before) skip += 1;
  let start = -1;
  if (before.length >= ANCHOR_MIN) {
    const starts = occurrences(raw, before).map((i) => i + before.length);
    if (starts.length > 0) start = starts[Math.min(skip, starts.length - 1)];
  }
  if (start >= 0) {
    if (after.length >= ANCHOR_MIN) {
      const end = raw.indexOf(after, start);
      if (end >= start && end - start <= 400) return { value: raw.slice(start, end), partial: false };
    }
    const m = /^[^\s"'`,;)\]}]*/.exec(raw.slice(start, start + RAW_PEEK));
    const v = m && m[0] ? m[0] : raw.slice(start, start + RAW_PEEK);
    return v ? { value: v, partial: true } : null;
  }
  if (after.length >= ANCHOR_MIN) {
    const end = raw.indexOf(after);
    if (end > 0) {
      const head = raw.slice(Math.max(0, end - RAW_PEEK), end);
      const m = /[^\s"'`,;(\[{=:]*$/.exec(head);
      const v = m && m[0] ? m[0] : head;
      return v ? { value: v, partial: true } : null;
    }
  }
  return null;
}

/**
 * The masked evidence strip.
 *
 * `raw` opts the whole window in, and only the EVENT LEDGER asks for it. The
 * two surfaces want different things from the same bytes: the Radar card is a
 * verdict you are triaging, where a block of unmasked transcript nobody asked
 * to read sits under a headline promising the evidence is masked — so there
 * the strip shows the masked line and reveals ONE placeholder on a deliberate
 * click, and nothing else. The Ledger is the session itself, which is where
 * you go precisely to read what actually happened, next to the turn it
 * happened in and beside that turn's own REDACTED · VIEW RAW toggle.
 */
function Evidence({ excerpt, keyName, findingId, raw: rawAllowed, row, platform }) {
  const text = String(excerpt || "");
  // A call that never ran: the masked line the guard saw is the
  // whole record. It is shown as usual, but nothing behind it can be
  // opened, so VIEW RAW is not offered, the marks stay marks, and a line
  // under the box says why.
  const stopped = !!row && callNeverRan(row);
  const parts = text.split(/(\[redacted(?::[a-z0-9_]+)?\])/g);
  // null | {loading} | {text, truncated} | {error} — the VISIBLE raw window,
  // only ever reachable where `raw` was asked for.
  const [raw, setRaw] = useState(null);
  // The per-placeholder values from the reveal call (null until fetched), and
  // which marks are showing theirs: index → { value, partial, via }.
  const [secrets, setSecrets] = useState(null);
  const [shownMarks, setShownMarks] = useState({});
  // One line under the strip when a mark can't be isolated.
  const [note, setNote] = useState(null);
  // The reveal is one IPC round-trip that re-reads the transcript; every mark
  // and the raw window share it.
  const revealRef = useRef(null);

  const ensureReveal = () => {
    if (!revealRef.current) {
      revealRef.current = window.doorman.revealFinding(findingId).then((res) => {
        const list = res && res.ok && Array.isArray(res.secrets) ? res.secrets : [];
        setSecrets(list);
        return { res, list };
      });
    }
    return revealRef.current;
  };

  const toggleRaw = (event) => {
    event.stopPropagation();
    setNote(null);
    if (raw) {
      setRaw(null);
      return;
    }
    setRaw({ loading: true });
    ensureReveal().then(({ res, list }) => {
      if (res && res.ok) setRaw({ text: res.raw, truncated: !!res.truncated, secrets: list, from: res.evidence_source });
      else setRaw({ error: (res && res.error) || "Couldn't read the transcript." });
    });
  };

  /* Clicking the placeholder reveals THAT value in place; clicking the value
     masks it again. Resolution order: the per-label secret list the reveal
     returned; then the value bracketed by the mark's own surroundings in the
     raw text; then a one-line note — never the whole window, which is a
     separate, deliberate click where it exists at all. */
  const toggleMark = (index) => (event) => {
    event.stopPropagation();
    setNote(null);
    if (stopped) return;
    if (shownMarks[index]) {
      setShownMarks((s) => ({ ...s, [index]: null }));
      return;
    }
    ensureReveal().then(({ res, list }) => {
      const direct = secretForMark(list, parts, index);
      if (direct != null) {
        setShownMarks((s) => ({ ...s, [index]: { value: direct, partial: false, via: "secret" } }));
        return;
      }
      const bracketed = res && res.ok ? valueFromRaw(res.raw, parts, index) : null;
      if (bracketed && isPlaceholderText(bracketed.value)) {
        setNote("Nothing to reveal — this was already masked in the transcript itself (the agent wrote the placeholder, not a value).");
        return;
      }
      if (bracketed) {
        setShownMarks((s) => ({ ...s, [index]: { value: bracketed.value, partial: bracketed.partial, via: "raw" } }));
        return;
      }
      setNote(
        res && res.ok
          ? "Couldn't isolate this value — its surroundings differ from the stored excerpt." +
            (rawAllowed ? " VIEW RAW shows the whole window." : "")
          : (res && res.error) || "Couldn't read the transcript.",
      );
    });
  };

  const showingRaw = !!(raw && raw.text != null);
  // The window is 1,600 characters and the box shows a dozen lines: the
  // value the card is about is centred in the TEXT, which put it under the
  // box's fold as often as not. Scroll the box itself — never the page — so
  // the primary mark sits mid-box the moment the raw is shown.
  const rawRef = useRef(null);
  useEffect(() => {
    const box = rawRef.current;
    if (!showingRaw || !box) return;
    const hit = box.querySelector("mark.raw-hit:not(.other)") || box.querySelector("mark.raw-hit");
    if (!hit) return;
    box.scrollTop = Math.max(0, hit.offsetTop - box.offsetTop - box.clientHeight / 2 + hit.offsetHeight / 2);
  }, [showingRaw, raw && raw.text]);
  return (
    <div className="evidence-wrap">
      {/* One box, two contents. VIEW RAW swaps the masked line for the raw
          window IN PLACE — HIDE RAW swaps it back — rather than stacking the
          two, so the card never grows a second block of the same evidence. */}
      {showingRaw ? (
        <div
          className="evidence raw"
          ref={rawRef}
          title={
            (raw.truncated ? "A window of the raw text, centred on the match. " : "") +
            (raw.from === "vault"
              ? "Kept on " + thisMachine(platform) + " when the finding fired, encrypted by " + keyStoreName(platform) + ". Never synced or exported; the saved finding stays masked. "
              : "Read from the transcript on " + thisMachine(platform) + " just now. Never synced or exported; the saved finding stays masked. ") +
            "The value this finding is about is highlighted."
          }
        >
          {/* The exposed value is HIGHLIGHTED in the raw text, not left for the
              reader to find: the finding's own value in the strip's alarm
              colour, any other redacted value in the window one band softer. */}
          {highlightSecrets(raw.text, raw.secrets, excerptLabels(parts)).map((seg, i) =>
            seg.hit ? (
              <mark
                key={i}
                className={"raw-hit" + (seg.primary ? "" : " other")}
                title={seg.primary ? "The value this finding is about" : "Another value redaction removed from this window"}
              >
                {seg.text}
              </mark>
            ) : (
              <span key={i}>{seg.text}</span>
            ),
          )}
        </div>
      ) : (
        <div className="evidence">
          {keyName ? <span className="faint">{keyName}: </span> : null}
        {/* The placeholder itself is the natural click target for "so what WAS
            it?" — in place, one value at a time. Marks without a findingId
            (the approval panel) stay inert text. */}
        {parts.map((part, i) => {
          if (!/^\[redacted/.test(part)) return <span key={i}>{part}</span>;
          if (!findingId || stopped) return <mark key={i}>{part}</mark>;
          const shown = shownMarks[i] || null;
          return (
            <mark
              key={i}
              className={"reveal" + (shown ? " on" : "") + (shown && shown.partial ? " partial" : "")}
              role="button"
              tabIndex={0}
              title={
                shown
                  ? shown.partial
                    ? "Bounded by one side only — the value may continue. Click to mask it again"
                    : "Click to mask it again"
                  : "Reveal this value in place — read on this computer only, never sent"
              }
              onClick={toggleMark(i)}
              onKeyDown={(ev) => (ev.key === "Enter" || ev.key === " " ? toggleMark(i)(ev) : null)}
            >
              {shown ? shown.value + (shown.partial ? "…" : "") : part}
            </mark>
          );
        })}
        </div>
      )}
      <span className="evidence-actions">
        {rawAllowed && !stopped && findingId && text ? (
          <button
            className={"copybtn" + (raw && !raw.loading && !raw.error ? " done" : "")}
            onClick={toggleRaw}
            title="Show the original, unmasked text this finding was raised on — read on this computer only, never synced, exported or sent."
          >
            {raw ? (raw.loading ? "READING…" : "HIDE RAW") : "VIEW RAW"}
          </button>
        ) : null}
      </span>
      {stopped && rawAllowed ? <div className="evidence-note plain">{NEVER_RAN_NOTE}</div> : null}
      {note ? <div className="evidence-note err">{note}</div> : null}
      {raw && raw.error ? <div className="evidence-note err">{raw.error}</div> : null}
    </div>
  );
}

/** "4s", "1m 12s" — a hold's duration, for the outcome line and Analytics. */
function fmtHold(ms) {
  if (!Number.isFinite(ms) || ms < 0) return "—";
  const s = Math.round(ms / 1000);
  if (s < 60) return s + "s";
  const m = Math.floor(s / 60);
  return m + "m " + (s % 60) + "s";
}

/** Where a held call was decided. Mirrors DecidedVia in main/lib/findings.ts. */
const DECIDED_VIA_LABELS = {
  panel: "the floating panel",
  window: "the app window",
  notification: "a notification",
  timeout: "nobody — it timed out",
  "app-absent": "nobody — the app was closed",
};

/* The guard toggle and hold behaviour live in settings.jsx (RulesCard); the
   per-rule modes live in rules.jsx (RulesScreen). This screen only reports
   posture and links to both. */

/* ---- the exposure card's five questions ---------------------- */

/** What a judged card's verdict is CALLED. The store keeps four statuses and
 *  this is presentation over them — "resolved" is a thing you did, not a thing
 *  that happened, and "false_positive" is not a sentence. */
const VERDICT_LABELS = {
  resolved: "Reviewed",
  false_positive: "False Positive",
  accepted_risk: "Accept Risk",
  open: "Open",
};

/**
 * Whether the flagged call actually RAN, which is the hinge the whole card
 * turns on: a blocked call never happened, so there is nothing to rotate and
 * nothing to un-send, and the instruction under it has to change to match.
 *
 * Read from what the guard DID (`enforced`) and, for a held call, what was
 * decided (`resolution`) — never from severity, which says how bad it would
 * be, not whether it occurred.
 */
function exposureRan(f) {
  if (f.enforced === "deny") return false;
  if (f.enforced === "ask") return f.resolution === "allowed" || f.resolution === "continue";
  // warn, excepted, observed and anything unrecorded: the call went through.
  return true;
}

/**
 * The card's rows: WHAT happened (when the assistant wrote it), what it MEANS,
 * where, what the guard did, and what to do next. How often and when live in
 * the record column (WHAT WE SAW), under the things they happened to.
 *
 * `means` and `next` are Doorman AI's sentences about THIS exposure when the
 * assistant wrote them (`summary`), and the snapshot's per-rule
 * `detector_guidance` (lib/ai-guidance.ts) when it didn't. The fallback is one
 * table, shared with the assistant, so the card and the answer start from the
 * same position — and the card reads correctly with the assistant off, which
 * is how it ships.
 *
 * When the call was STOPPED, both are overridden whatever wrote them: advice
 * written for an exposure that happened, applied to one that didn't, is the
 * card inventing work.
 */
function ExposureStory({ face, group, state, account, stepRows, ask }) {
  const guidance = ((state && state.detector_guidance) || {})[face.detector] || {};
  /* WHERE is the size of this step's record — how many sightings, in how many
     sessions — for the thing under review (or the whole exposure on a
     one-thing card). The place and tools live on the facts line. */
  const rows = stepRows || group.rows;
  const sessions = new Set(rows.map((r) => r.session_id).filter(Boolean)).size;
  const where = rows.length + " sighting" + (rows.length === 1 ? "" : "s") + (sessions > 0 ? " · " + sessions + " session" + (sessions === 1 ? "" : "s") : "");
  /* The account is the SELECTION's: the group's (generalised over the rows
     where their fields differ, so a card holding three credentials never
     claims to be about one of them) or, while one thing is being reviewed,
     that thing's own — `scope` says which, and the caption names it. */
  /* Both read the whole GROUP, not its face. A card standing for five
     sightings whose guard outcomes disagree used to print the first row's
     outcome as if it were the exposure's — so three blocked calls and two
     that went through read "Blocked", and the instruction under it said
     there was nothing to do. If ANY of them ran, there is work. */
  const ran = group.rows.some(exposureRan);
  const outcomes = [...new Set(group.rows.map(findingOutcome))];
  const outcome = outcomes.length === 1 ? outcomes[0] : "mixed";
  /* Three lines, rule-specific, from the ACCOUNT (main/lib/account.ts) when the row has one — the story (what the transcript shows),
     the consequence, the next step — else the rule's own two sentences from
     lib/ai-guidance.ts. When the call was STOPPED the last two are
     overridden whatever wrote them: advice written for an exposure that
     happened, applied to one that didn't, is the card inventing work. */
  const story = account ? account.sentence : guidance.blurb || "";
  const so = !ran
    ? "Nothing left this computer — the call was stopped before it ran, so there is nothing to undo."
    : account
      ? account.so
      : "";
  const next = !ran
    ? "Nothing to clean up. Mark it reviewed — or loosen the rule in Guardrails if this should have been allowed."
    : account
      ? account.next
      : guidance.fix || "";
  return (
    <div className="fstory">
      {/* Two labelled rows. WHAT: the story — what the transcript shows, with
          the quoted parts in mono — and, on its own line under it, what that
          means. DO NEXT: the one step. Written for THIS rule, from the
          exposure's own account; the form's other answers ("Where", "Action")
          are one compact facts line underneath. */}
      {story || so ? (
        <div className="fqa-row">
          <span className="fqa-k">What</span>
          <span className="fqa-v fstory-what">
            {/* One paragraph: the story, then the consequence in the same
                breath — two sentences a person would say together, not two
                lines that read as two items. */}
            <p>
              {story ? codeSpans(story) : null}
              {story && so ? " " : null}
              {so ? <span className="fstory-so">{codeSpans(so)}</span> : null}
              {/* Provenance only when it is news: a sentence a LOCAL MODEL
                  read out of the transcript wears a chip so the reader can
                  weigh it. The deterministic extractor is every card's
                  normal state and says so by saying nothing. */}
              {account && account.by === "local_reader" ? (
                <span
                  className="chip fstory-src"
                  title="A local model on this computer read this out of the raw transcript. Every quoted part was checked against the text before it was shown; nothing here changes what the guard did."
                >
                  local model
                </span>
              ) : null}
            </p>
          </span>
        </div>
      ) : null}
      {/* ACTION: what the guard DID — one capitalized word on a pill, nothing
          after it. Read off the whole GROUP; if the rows disagree it says so.
          Sits under What, where the outcome bears on the story just told, and
          ahead of Do next, whose verbs it decides. */}
      <div className="fqa-row">
        <span className="fqa-k">Action</span>
        <span className="fqa-v">
          <span className={"fqa-outcome act-" + outcome}>{OUTCOME_WORDS[outcome] || outcome}</span>
        </span>
      </div>
      <div className="fqa-row">
        <span className="fqa-k">Where</span>
        <span className="fqa-v">
          <p>{where}</p>
        </span>
      </div>
      {next ? (
        <div className="fqa-row">
          <span className="fqa-k">Do next</span>
          <span className="fqa-v fstory-next">
            <p>{codeSpans(next)}</p>
          </span>
        </div>
      ) : null}
      {ask ? (
        <div className="fqa-row fstory-ask">
          <span className="fqa-k" aria-hidden="true"></span>
          <span className="fqa-v">{ask}</span>
        </div>
      ) : null}
    </div>
  );
}

/**
 * The facts a sentence doesn't carry, on one line at the card's foot: the
 * rule that fired (the header is the exposure now, so the rule moves here),
 * where, which tools, and what the guard DID — one capitalized word on a pill,
 * nothing after it. WHERE comes off the same helper the closed row prints, so
 * the two cannot disagree; every tool that saw it is named, not just the
 * face's — an exposure across Claude Code and Codex is one exposure in two
 * places. The outcome reads the whole GROUP: if the rows disagree it says so.
 */
function FactsLine({ face, group }) {
  const meta = detectorMeta(face.detector, null, face);
  const project = exposurePlace(face, group);
  const tools = [...new Set(group.rows.map((r) => SOURCE_NAMES[r.source] || r.source))].filter(Boolean);
  return (
    <div className="ffacts">
      <span className="ffact" title="The rule that fired">{meta.label || face.detector}</span>
      {project ? (
        <span className="ffact">
          in <span className="mono">{project}</span>
        </span>
      ) : null}
      {tools.length > 0 ? <span className="ffact">{tools.join(" · ")}</span> : null}
    </div>
  );
}

/**
 * "3 credentials" from ["AWS credential", "GitHub credential", "OpenAI
 * credential"] and a count of 3: the longest kind the nouns share — "credential",
 * or "API key" across "Grafana API key" and "Postman API key" — pluralised
 * behind how many things the card holds; nouns of different kinds become
 * "3 secrets". A title is not the place to list brands — the record column
 * names each thing — so the group phrase says how many, not which. Returns
 * { phrase, plural }. Pure.
 */
function joinFamilyNouns(nouns, count) {
  if (nouns.length <= 1) return { phrase: nouns[0] || "", plural: false };
  const n = Math.max(count || 0, nouns.length);
  const words = nouns.map((s) => s.split(" "));
  // The longest common trailing run of words, leaving every noun at least
  // one word of its own (the brand).
  const shared = [];
  for (let k = 1; k < Math.min(...words.map((w) => w.length)); k++) {
    const w = words[0][words[0].length - k];
    if (!words.every((ws) => ws[ws.length - k] === w)) break;
    shared.unshift(w);
  }
  return { phrase: n + " " + (shared.length > 0 ? shared.join(" ") : "secret") + "s", plural: true };
}

/**
 * ONE account for a card whose rows fold into several things. A
 * card is rule × place, so every row's account was rendered from the same
 * templates; only the FIELDS can differ — the family, the file, the host, the
 * secret-shaped name. Where the rows agree the face's account stands as is;
 * where they differ, the face's specific value is generalised in each line
 * ("AWS credential in a `Bash` call" → "AWS, GitHub and OpenAI credentials in
 * `Bash` calls"), the story says how many things there are and points at the
 * record, and the calm placeholder variant applies only if EVERY row looks
 * like a placeholder. Rows without an account (older snapshots) are skipped;
 * a card with none returns null and the rule's name stands. Pure; tested in
 * test/renderer-logic.test.ts.
 */
function groupAccount(face, rows, thingCount) {
  const ordered = [face].concat((rows || []).filter((r) => r !== face));
  const accounts = ordered.map((r) => r && r.account).filter((a) => a && a.title);
  if (accounts.length === 0) return null;
  const lead = accounts[0];
  const distinct = (k) => [...new Set(accounts.map((a) => a[k]).filter((v) => v != null && v !== ""))];
  const fams = distinct("family_noun");
  const files = distinct("source_ref");
  const hosts = distinct("destination_host");
  const names = distinct("name");
  const varies = fams.length > 1 || files.length > 1 || hosts.length > 1 || names.length > 1;
  const allPlaceholder = accounts.every((a) => a.placeholder_signals && a.placeholder_signals.length > 0);
  if (!varies) {
    return allPlaceholder || !(lead.placeholder_signals && lead.placeholder_signals.length) ? lead : { ...lead, placeholder_signals: [] };
  }
  // The family is generalised in ONE pass with its article, so "an AWS
  // credential" becomes "AWS, GitHub and OpenAI credentials" whole — never
  // "an AWS, GitHub and OpenAI credentials", and never substituted a second
  // time inside the phrase it just produced (which doubled the list when a
  // joined phrase still contained the lead's own words).
  const subs = [];
  let pluralFamily = false;
  let famRe = null;
  let famPhrase = "";
  const n = thingCount || accounts.length;
  if (fams.length > 1 && lead.family_noun) {
    const joined = joinFamilyNouns(fams, n);
    pluralFamily = joined.plural;
    famPhrase = joined.phrase;
    famRe = new RegExp("(\\b(?:An|A|an|a|The|the) )?" + lead.family_noun.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "g");
  }
  if (files.length > 1 && lead.source_ref) subs.push(["`" + lead.source_ref + "`", files.length + " files"]);
  if (hosts.length > 1 && lead.destination_host) subs.push(["`" + lead.destination_host + "`", hosts.length + " hosts"]);
  if (names.length > 1 && lead.name) subs.push(["`" + lead.name + "`", names.length + " names"]);
  const cap = (s) => s.charAt(0).toUpperCase() + s.slice(1);
  const generalise = (text) => {
    let out = String(text || "");
    if (famRe) {
      out = out.replace(famRe, (_m, article) => {
        if (!article) return famPhrase;
        const a = article.trim();
        // "Rotate the AWS credential" → "Rotate the credentials": "the 3
        // credentials" is not a phrase anyone says.
        if (a === "the") return "the " + famPhrase.replace(/^\d+ /, "");
        if (a === "The") return "The " + famPhrase.replace(/^\d+ /, "");
        return /^[A-Z]/.test(a) ? cap(famPhrase) : famPhrase;
      });
    }
    for (const [from, to] of subs) out = out.split(from).join(to);
    // "credentials was typed" → "credentials were typed": the one template
    // whose verb agrees with the family noun.
    if (pluralFamily) out = out.replace(/(credentials|tokens|keys|secrets|phrases) was /g, "$1 were ");
    // "in a `Bash` call" → "in `Bash` calls", "in a tool call" → "in tool
    // calls": several things, several calls.
    out = out
      .replace(/ in a (`[^`]+`) call\b/g, " in $1 calls")
      .replace(/ into a (`[^`]+`) call\b/g, " into $1 calls")
      .replace(/ in a tool call\b/g, " in tool calls")
      .replace(/ into a tool call\b/g, " into tool calls");
    return out;
  };
  // The story ends by pointing at the record. When the family phrase already
  // carries the count ("3 credentials"), saying "3 things in all" again is
  // the same number twice.
  const pointer = pluralFamily ? " See What we saw for each." : " " + n + " things in all — see What we saw.";
  return {
    ...lead,
    title: generalise(lead.title),
    sentence: generalise(lead.sentence) + pointer,
    so: generalise(lead.so),
    next: generalise(lead.next),
    placeholder_signals: allPlaceholder ? lead.placeholder_signals : [],
    grouped: true,
  };
}

/** The account a THING is reviewed with: its face row's, else the first of its
 *  rows that has one, else null (an older snapshot). Pure. */
function thingAccount(thing) {
  if (!thing) return null;
  const rows = [thing.face].concat((thing.rows || []).filter((r) => r !== thing.face));
  return rows.map((r) => r && r.account).find((a) => a && a.title) || null;
}

/**
 * The next selection on the review walk: the things in record order, and the
 * walk wraps, so stepping forward from the last thing is the first again. An
 * unknown `current` (or null) counts as "before the first". Pure; tested in
 * renderer-logic.test.ts.
 */
function stepThing(keys, current, dir) {
  if (keys.length === 0) return null;
  const at = current == null ? -1 : keys.indexOf(current);
  const n = keys.length;
  if (at < 0) return dir < 0 ? keys[n - 1] : keys[0];
  return keys[(at + (dir < 0 ? -1 : 1) + n) % n];
}

/**
 * A horizontal trackpad swipe as a step. Wheel events with a horizontal
 * majority accumulate; past the threshold they step once and lock briefly,
 * so one swipe is one step and a diagonal scroll is left to the page.
 */
function useSwipeStep(step) {
  const acc = useRef(0);
  const lockUntil = useRef(0);
  return (event) => {
    if (Math.abs(event.deltaX) <= Math.abs(event.deltaY)) return;
    const now = Date.now();
    if (now < lockUntil.current) return;
    acc.current += event.deltaX;
    if (Math.abs(acc.current) >= 60) {
      step(acc.current > 0 ? 1 : -1);
      acc.current = 0;
      lockUntil.current = now + 500;
    }
  };
}

/** An account sentence with its `quoted` fields set in mono — the text is
 *  plain (main never sends markup), so backticks are the one convention. Pure. */
function codeSpans(text) {
  const parts = String(text || "").split("`");
  return parts.map((part, i) => (i % 2 === 1 ? <span key={i} className="mono">{part}</span> : <React.Fragment key={i}>{part}</React.Fragment>));
}

/** The outcome as the card says it: one capitalized word on a pill. */
const OUTCOME_WORDS = {
  blocked: "Blocked",
  held: "Held",
  warned: "Warned",
  excepted: "Excepted",
  observed: "Observed",
  mixed: "Mixed",
};

/** The two QUALIFIERS on a review. Reviewed is not among them: reviewing is
 *  what the button does, and these are the two reasons that change what the
 *  review meant. */
const VERDICT_CHOICES = [
  { id: "false_positive", label: VERDICT_LABELS.false_positive },
  { id: "accepted_risk", label: VERDICT_LABELS.accepted_risk },
];

/** What the trigger says when nothing has been picked. A VERB phrase, and
 *  deliberately: a bare noun ("Reason") sitting directly above a list of two
 *  nouns reads as the first item in that list — as if it were a third thing
 *  you could pick. It is not; it is the empty state of the control, and while
 *  it shows, "Mark reviewed" beside it is disabled. */
const VERDICT_PLACEHOLDER = "Add reason";
const verdictLabel = (id) => VERDICT_LABELS[id] || VERDICT_PLACEHOLDER;

/**
 * WHY you reviewed it — a selector, not an action, and optional.
 *
 * Its trigger used to read "Dismiss", and picking an item WROTE that verdict
 * on the spot. Two problems in one control: "Dismiss" is a verb, so the thing
 * that was only supposed to qualify a decision looked like a second way to
 * make one; and a card could be triaged by a misclick in a menu, with no
 * moment between choosing and committing. Now the trigger shows what is
 * picked, the list marks it, and nothing is written until "Mark reviewed".
 *
 * `disabled` is the same control after the decision: no menu, no chevron
 * behaviour, just the choice the person made, which is why a judged card
 * shows its verdict in the place the verdict was chosen rather than as a chip
 * somewhere else on the card.
 */
function VerdictMenu({ value, onPick, disabled }) {
  const [open, setOpen] = useState(false);
  const ref = useRef(null);
  useEffect(() => {
    if (!open) return;
    const onDown = (e) => {
      if (ref.current && !ref.current.contains(e.target)) setOpen(false);
    };
    const onKey = (e) => (e.key === "Escape" ? setOpen(false) : null);
    const onScroll = (e) => {
      if (ref.current && ref.current.contains(e.target)) return;
      setOpen(false);
    };
    document.addEventListener("mousedown", onDown);
    document.addEventListener("keydown", onKey);
    document.addEventListener("scroll", onScroll, true);
    return () => {
      document.removeEventListener("mousedown", onDown);
      document.removeEventListener("keydown", onKey);
      document.removeEventListener("scroll", onScroll, true);
    };
  }, [open]);
  if (disabled) {
    return (
      <span className="verdict-wrap">
        <button className="btn" disabled>
          {verdictLabel(value)}
          <Icon name="chevron" size={12} />
        </button>
      </span>
    );
  }
  return (
    <span className="verdict-wrap" ref={ref}>
      <button
        className={"btn" + (value ? "" : " unset")}
        aria-haspopup="menu"
        aria-expanded={open}
        onClick={() => setOpen(!open)}
      >
        {verdictLabel(value)}
        <Icon name="chevron" size={12} />
      </button>
      {open ? (
        <div className="verdict-pop" role="menu">
          {VERDICT_CHOICES.map((c) => (
            <button
              key={c.id}
              type="button"
              role="menuitemradio"
              aria-checked={c.id === value}
              className={c.id === value ? "on" : undefined}
              onClick={() => {
                setOpen(false);
                onPick(c.id);
              }}
            >
              {c.label}
            </button>
          ))}
        </div>
      ) : null}
    </span>
  );
}

/** What the names under an exposure ARE, in the words of the fix: you rotate
 *  keys, you empty files, you review servers. Naming them "things" made the
 *  list a category rather than a to-do. */
function sawNoun(detector, n) {
  const d = String(detector || "");
  const noun =
    d.indexOf("wallet") === 0
      ? ["key to move", "keys to move"]
      : d === "dotenv_read" || d === "hardcoded_credential" || d === "env_dump"
        ? ["file to clean", "files to clean"]
        : d.indexOf("mcp") >= 0 || d === "unknown_mcp_server"
          ? ["server to review", "servers to review"]
          : d === "pii_exposure"
            ? ["record to remove", "records to remove"]
            : ["key to rotate", "keys to rotate"];
  return n + " " + (n === 1 ? noun[0] : noun[1]);
}
