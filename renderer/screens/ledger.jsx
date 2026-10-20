/* Event Ledger — master-detail: a day-grouped session list on the left, the
   selected session as a turn timeline on the right, with radar events INLINE
   at the turns they anchor to.

   THE CHANGE THAT MATTERS HERE: a session's timeline is mostly turns with no
   prose — an agent reading files, running a build, grepping. Rendered one
   bubble each they buried the turns a person actually wants to read (the
   prompts and the answers) under dozens of "(no text)" cards. Consecutive
   text-less turns now fold into ONE line — "12 events · show all", with the
   tools, tokens and cost of the run stated on it. Folding is not hiding: the line carries its
   own count and totals, and one click expands it in place.

   Search is one box over titles and turn text (the local FTS); a query
   grammar is deliberately not built. */

/* The rail chips are built from the snapshot's own source list
   (capture.sources, keyed by TurnSource and labelled by the transcript-source
   registry in main) rather than a list of hosts written down twice: registering
   a parser for Cursor puts Cursor in this control with no edit here. A rail with
   no sessions and no host on this machine is left out — the control offers
   choices, not a roadmap — and "All rails" only becomes a real word when there
   is more than one to choose between. */
function ledgerSources(state) {
  const map = (state.capture && state.capture.sources) || {};
  const rails = Object.keys(map)
    .map((id) => ({ key: id, label: map[id].label || id, present: !!map[id].present }))
    .filter((rail) => rail.present || (state.sessions || []).some((s) => s.source === rail.key));
  if (rails.length === 0) {
    rails.push({ key: "claude-code", label: "Claude Code" }, { key: "codex", label: "Codex" });
  }
  return [{ key: "all", label: rails.length === 2 ? "Both rails" : "All rails" }, ...rails];
}

/* A session's one usage figure: input+output tokens (tokens, never
   dollars). A session with turns but no token counts has not used 0 — its
   host simply recorded no usage, and "0 tokens" would read as idle. The hosts
   arriving through the transcript-source registry make this the common case
   rather than the odd one (VS Code's chat sessions carry no usage), so the
   ledger says so instead of showing a confident zero. */
function sessionTokens(s) {
  return (s.input_tokens || 0) + (s.output_tokens || 0);
}
function sessionTokensLabel(s) {
  const tokens = sessionTokens(s);
  return tokens > 0 ? fmtTokens(tokens) + " tokens" : "tokens not reported";
}

/* Use-case labels for the task filter (mirrors lib/task-class.ts). */
const LEDGER_TASK_LABELS = {
  coding: "Coding",
  debugging: "Debugging",
  testing: "Testing",
  refactor: "Refactoring",
  data: "Data & analysis",
  docs: "Docs & writing",
  infra: "Infra & ops",
  research: "Research",
  review: "Review",
  other: "Other",
};

/**
 * Fold a turn list into render rows: prose turns stay as themselves, runs of
 * text-less turns collapse into one `{ kind: "run" }` carrying the whole run.
 *
 * A run of ONE stays a turn — "1 event · show all" is more chrome than the
 * bubble it replaces. Pure, so test/ledger-view.test.ts can hold
 * it to that.
 */
function collapseTurnRuns(turns, minRun = 2) {
  const rows = [];
  let run = [];
  const flush = () => {
    if (run.length === 0) return;
    if (run.length < minRun) {
      for (const t of run) rows.push({ kind: "turn", turn: t });
    } else {
      const tools = [];
      let tokens = 0;
      for (const t of run) {
        for (const tool of t.tools || []) if (!tools.includes(tool)) tools.push(tool);
        if (t.usage) tokens += (t.usage.input_tokens || 0) + (t.usage.output_tokens || 0);
      }
      rows.push({
        kind: "run",
        id: "run-" + run[0].id,
        turns: run.slice(),
        tools,
        tokens,
        from: run[0].at,
        to: run[run.length - 1].at,
      });
    }
    run = [];
  };
  for (const t of turns) {
    const hasProse = typeof t.text === "string" && t.text.trim() !== "";
    if (hasProse) {
      flush();
      rows.push({ kind: "turn", turn: t });
    } else {
      run.push(t);
    }
  }
  flush();
  return rows;
}

function LedgerScreen({
  state,
  focusSessionId,
  onFocusHandled,
  focusFindingId,
  onFocusFindingHandled,
  focusNonce,
  focusTask,
  onFocusTaskHandled,
  onTraceSecret,
  onGoRadar,
}) {
  const [query, setQuery] = useState("");
  const [hitSessions, setHitSessions] = useState(null); // null = not searching
  const [selected, setSelected] = useState(null);
  const [source, setSource] = useState("all");
  const [task, setTask] = useState("all");
  const [alertsOnly, setAlertsOnly] = useState(false);
  const [exported, setExported] = useState(null); // a path, or "error:…"
  const [exporting, setExporting] = useState(false);
  const exportLedger = (sessionId) => {
    setExporting(true);
    setExported(null);
    window.doorman.exportLedger(sessionId).then((res) => {
      setExporting(false);
      if (res && res.ok) setExported(res.path);
      else if (res && !res.canceled) setExported("error:" + (res.error || "failed"));
    });
  };
  // The specific finding a Radar deep link wants scrolled-to-and-highlighted,
  // once its session is open. Separate from `focusFindingId` itself so it
  // survives past the one render where the incoming prop gets cleared.
  const [pendingFindingId, setPendingFindingId] = useState(null);
  // A session the Radar sent us to that is NOT in the capped `state.sessions`
  // snapshot (SNAPSHOT_SESSIONS = 100, and a machine can have far more). Its
  // turns still load fine over IPC by id, so the deep link must survive: this
  // pins the selection so the default-selection effect below can't overwrite
  // it with "the newest visible session", which is what used to happen — you
  // clicked a finding and landed on an unrelated session with no alerts.
  const [pinnedSessionId, setPinnedSessionId] = useState(null);
  const searchSeq = useRef(0);

  // The selected session stays IN VIEW in the list. A deep link (a Radar
  // card's `session →`, the Overview's Open session) selects a session that
  // may sit well below the fold of a hundred-row list, and the list used to
  // leave it there: the detail pane showed the session while the list showed
  // no selection at all until you scrolled to find it. `nearest` is a no-op
  // when the row is already visible — a click on a row never jolts the list.
  useEffect(() => {
    if (!selected) return;
    const row = document.querySelector(".list .sessrow.on");
    if (row && row.scrollIntoView) row.scrollIntoView({ block: "nearest" });
  }, [selected, hitSessions, source, task, alertsOnly]);

  // Radar → ledger deep link.
  useEffect(() => {
    if (focusSessionId) {
      setSelected(focusSessionId);
      setPinnedSessionId(focusSessionId);
      setQuery("");
      setHitSessions(null);
      setSource("all");
      setTask("all");
      setAlertsOnly(false);
      setPendingFindingId(focusFindingId || null);
      onFocusHandled();
      if (focusFindingId) onFocusFindingHandled();
    }
    // Keyed on the nonce as well as the id, so re-asking for the session that
    // is already open still re-runs (and re-scrolls to the new finding).
  }, [focusSessionId, focusNonce]);

  // Usage → ledger deep link: a use-case row opens the ledger filtered
  // to that class, which is the "use-case drawer" of the Harmonic pattern done
  // with the screen we already have.
  useEffect(() => {
    if (focusTask) {
      setTask(focusTask);
      setQuery("");
      setHitSessions(null);
      setSource("all");
      setAlertsOnly(false);
      setPinnedSessionId(null);
      setSelected(null);
      onFocusTaskHandled();
    }
  }, [focusTask]);

  useEffect(() => {
    const q = query.trim();
    if (q === "") {
      setHitSessions(null);
      return;
    }
    const seq = ++searchSeq.current;
    const handle = setTimeout(() => {
      window.doorman.searchTurns(q).then((res) => {
        if (searchSeq.current !== seq) return;
        // Fold turn hits into session ids; title matches join them.
        const bySession = new Map();
        for (const t of res.turns || []) {
          bySession.set(t.session_id, (bySession.get(t.session_id) || 0) + 1);
        }
        const lower = q.toLowerCase();
        for (const s of state.sessions) {
          if (s.title && s.title.toLowerCase().includes(lower) && !bySession.has(s.id)) {
            bySession.set(s.id, 0);
          }
        }
        setHitSessions(bySession);
      });
    }, 150);
    return () => clearTimeout(handle);
  }, [query, state.sessions]);

  // The "Now" group: agents running on this Mac this minute (main's
  // live-sessions fold), scoped by the rail filter only — search, task and
  // the flag toggle are questions about history, and a live row is shown
  // regardless of what it has written so far. Its sessions leave the
  // day-grouped list below so nothing appears twice.
  const liveRows = ((state.live && state.live.sessions) || []).filter(
    (r) => source === "all" || r.source === source,
  );
  const showLive = liveRows.length > 0 && hitSessions === null && task === "all" && !alertsOnly;
  const liveIds = new Set(showLive ? liveRows.map((r) => r.session_id).filter(Boolean) : []);
  // "quiet 4m" ages while nothing else changes — re-render on a slow clock
  // while anything is live.
  const [, setClock] = useState(0);
  useEffect(() => {
    if (!showLive) return undefined;
    const t = setInterval(() => setClock((n) => n + 1), 30000);
    return () => clearInterval(t);
  }, [showLive]);

  const visible = state.sessions.filter((s) => {
    if (liveIds.has(s.id)) return false;
    if (hitSessions !== null && !hitSessions.has(s.id)) return false;
    if (source !== "all" && s.source !== source) return false;
    if (task !== "all" && (s.task || "other") !== task) return false;
    if (alertsOnly && !(s.alerts > 0)) return false;
    return true;
  });
  // Task types actually present, with their session counts — the menu never
  // offers a choice that empties the pane.
  const taskCounts = {};
  for (const s of state.sessions) {
    const k = s.task || "other";
    taskCounts[k] = (taskCounts[k] || 0) + 1;
  }
  const railOptions = ledgerSources(state).map((s) => ({
    key: s.key,
    label: s.label,
    count: s.key === "all" ? state.sessions.length : state.sessions.filter((x) => x.source === s.key).length,
  }));
  const taskOptions = [
    { key: "all", label: "Any task", count: state.sessions.length },
    ...Object.keys(taskCounts)
      .map((k) => ({ key: k, label: LEDGER_TASK_LABELS[k] || k, count: taskCounts[k] }))
      .sort((a, b) => b.count - a.count),
  ];

  // Default selection: newest session that survives the filters. A pinned
  // deep-link target is exempt — it may legitimately sit outside the capped
  // snapshot list, and "not in the list" must not mean "silently show
  // something else".
  //
  // The FIRST guard is the deep link still in flight. On the mount that a
  // deep link causes, this effect and the deep-link effect above run in the
  // same commit, and this one's closure still holds `selected = null` and
  // `pinnedSessionId = null` — the pin has been requested, not applied. So it
  // used to queue its own setSelected(newest / live) AFTER the deep link's,
  // and the last write won: every "Open session" and "session →" landed on
  // whatever session happened to be newest (with an agent running, the live
  // one — this very session, reliably). The incoming PROP is the one thing
  // already true in this closure, so it is what this effect defers to.
  useEffect(() => {
    if (focusSessionId) return;
    const liveFirst = showLive ? liveRows.find((r) => r.session_id) : null;
    if (visible.length === 0 && !liveFirst) return;
    if (selected && selected === pinnedSessionId) return;
    if (selected && (liveIds.has(selected) || visible.some((s) => s.id === selected))) return;
    setSelected(liveFirst ? liveFirst.session_id : visible[0].id);
  }, [visible.length, liveIds.size, source, task, alertsOnly, hitSessions, pinnedSessionId, focusSessionId]);

  const summary = state.sessions.find((s) => s.id === selected);
  const maxTokens = visible.reduce((n, s) => Math.max(n, sessionTokens(s)), 0);
  const shownTokens = visible.reduce((n, s) => n + sessionTokens(s), 0);
  const shownAlerts = visible.reduce((n, s) => n + (s.alerts || 0), 0);
  const withAlerts = state.sessions.filter((s) => s.alerts > 0).length;
  const filtered = hitSessions !== null || source !== "all" || task !== "all" || alertsOnly;

  return (
    <div>
      <div className="screen-head">
        <h1>Event Ledger</h1>
      </div>

      {/* One filter row, above the pane it scopes. */}
      <div className="filterbar">
        <SearchBox
          placeholder="Search titles and turn text…"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
        />
        {/* A credential typed here is a different question — not "which
            sessions mention this" but "where has this been" — and the trace
            answers it over every transcript, not the capped store. */}
        {onTraceSecret && looksLikeSecret(query) ? (
          <button className="linkbtn trace-hint" onClick={() => onTraceSecret(query.trim())}>
            Looks like a credential — trace where it was exposed →
          </button>
        ) : null}
        {/* The rail is one exclusive view of the list; each option carries how
            many sessions it would leave, so picking "Codex" is never a jump
            into an empty pane. With two rails that is a three-way segmented
            control. Beyond two — the registry now brings Cursor, Gemini CLI,
            Copilot CLI, Claude Desktop — a row of six pills was a wall of tabs
            before the list, so it collapses to ONE menu button showing the
            selected rail, the same control Task uses beside it. The flag
            toggle stays a separate chip because it is a boolean ON TOP of
            whichever rail is selected, not another rail. */}
        {railOptions.length > 3 ? (
          <FilterMenu label="Rail" value={source} options={railOptions} onPick={setSource} />
        ) : (
          <Segmented ariaLabel="Rail" value={source} options={railOptions} onPick={setSource} />
        )}
        {/* Task type is up to ten values, so a dropdown (with counts) rather
            than a segmented control — same contract as the Radar's rule menu. */}
        {taskOptions.length > 2 ? (
          <FilterMenu label="Task" value={task} options={taskOptions} onPick={setTask} />
        ) : null}
        <DotChips
          ariaLabel="Flagged"
          value={alertsOnly ? "flagged" : null}
          options={[
            {
              key: "flagged",
              label: "Flagged only",
              count: withAlerts,
              dot: "var(--bad)",
              title: "Only sessions the Security Radar flagged",
            },
          ]}
          onPick={() => setAlertsOnly(!alertsOnly)}
        />
        <span className="spacer" />
        <span className="fb-note">
          {visible.length} shown · {fmtTokens(shownTokens)} tokens
          {shownAlerts > 0 ? " · " + shownAlerts + " alert" + (shownAlerts === 1 ? "" : "s") : ""}
        </span>
        {/* The ledger as JSON in the Doorman ledger schema — every session,
            or the one open on the right. Redacted text, fingerprints only. */}
        <ActionMenu
          label="Export"
          trigger={exporting ? "Exporting…" : "Export"}
          disabled={exporting}
          items={[
            { id: "all", label: "All sessions (JSON)", onPick: () => exportLedger() },
            ...(selected ? [{ id: "one", label: "This session (JSON)", onPick: () => exportLedger(selected) }] : []),
          ]}
        />
      </div>
      {exported ? (
        <div className={"callout" + (exported.indexOf("error:") === 0 ? " bad" : " good")} style={{ marginBottom: "var(--s4)" }}>
          {exported.indexOf("error:") === 0 ? "Couldn't write the export: " + exported.slice(6) : "Saved to " + exported + " — turn text redacted, nothing raw."}
        </div>
      ) : null}

      <div className="ledger">
        <div className="list">
          <div className="items">
            {showLive ? (
              <LiveGroup rows={liveRows} counts={state.live.counts} selected={selected} onSelect={setSelected} canFocus={state.platform === "macos"} />
            ) : null}
            {visible.length === 0 ? (
              showLive ? null : (
              <Empty>
                {filtered
                  ? "Nothing matches these filters."
                  : state.capture.status === "scanning"
                    ? "Backfilling from your transcripts…"
                    : "No sessions yet — use Claude Code or Codex and they appear within seconds."}
              </Empty>
              )
            ) : (
              (() => {
                const out = [];
                let lastGroup = null;
                for (const s of visible) {
                  const group = dayGroupLabel(s.ended_at);
                  if (group !== lastGroup) {
                    lastGroup = group;
                    out.push(
                      <div key={"g-" + group} className="daylabel">
                        {group}
                      </div>,
                    );
                  }
                  const hits = hitSessions !== null ? hitSessions.get(s.id) : 0;
                  out.push(
                    <button
                      key={s.source + s.id}
                      className={"sessrow" + (s.id === selected ? " on" : "")}
                      onClick={() => setSelected(s.id)}
                    >
                      {/* Two lines, not three: the rail's mark, the title and the
                          clock share the first; turns · cost · alerts take the
                          second. The mark says which agent without a word. */}
                      <span className="top">
                        <RailMark source={s.source} />
                        <span className="title">
                          {s.title || <span className="mono muted">{s.id.slice(0, 12)}…</span>}
                        </span>
                        <span className="when">{clockTime(s.ended_at)}</span>
                      </span>
                      <span className="meta">
                        {s.turns} turn{s.turns === 1 ? "" : "s"} · {sessionTokensLabel(s)}
                        {hits > 0 ? " · " + hits + " match" + (hits === 1 ? "" : "es") : ""}
                        {s.alerts > 0 ? (
                          <React.Fragment>
                            {" · "}
                            <span className="alert">
                              {s.alerts} alert{s.alerts === 1 ? "" : "s"}
                            </span>
                          </React.Fragment>
                        ) : null}
                      </span>
                      {/* Relative token volume within the visible set — the shape
                          of the list at a glance, without a column of numbers. */}
                      <span className="volbar">
                        <span
                          style={{ width: (maxTokens > 0 ? Math.max(1, (sessionTokens(s) / maxTokens) * 100) : 0) + "%" }}
                        />
                      </span>
                    </button>,
                  );
                }
                return out;
              })()
            )}
          </div>
        </div>

        <div className="detail">
          {selected ? (
            <SessionDetail
              key={selected}
              sessionId={selected}
              summary={summary}
              focusFindingId={pendingFindingId}
              onFocusFindingConsumed={() => setPendingFindingId(null)}
              state={state}
              onGoRadar={onGoRadar}
            />
          ) : (
            <Empty>Select a session.</Empty>
          )}
        </div>
      </div>
    </div>
  );
}

const TURN_PAGE = 50;
/**
 * How many extra pages a radar deep link will pull in trying to land its card
 * in the real turn timeline before it gives up and scrolls to wherever the
 * card already is.
 *
 * There has to be a bound. A LIVE session grows while you read it — every
 * reply raises `total` — so "keep paging until the anchoring turn is loaded"
 * is a race the reader loses: the scroll never fired at all on the session
 * that was still being written. Three pages (≈650 turns) covers any real
 * session; past that the finding still renders in the orphan list, so the
 * link takes you to the evidence either way.
 */
const FOCUS_MAX_PAGES = 3;

/**
 * Scroll a radar card into view inside the ledger's DETAIL column, and keep it
 * there while the timeline settles.
 *
 * Two reasons this isn't `el.scrollIntoView()`:
 *   · the ledger NESTS scrollports (the detail column inside the content
 *     pane), and scrollIntoView walks up and moves whichever ancestors it
 *     likes — it was parking the card off-screen;
 *   · the timeline is still growing as it runs (a page resolving, a folded run
 *     expanding), so a single measurement is a stale measurement: we were
 *     clamping to a scrollHeight that then got taller, leaving the card a few
 *     hundred pixels below the fold.
 *
 * So: measure the pane, jump (instantly — a smooth animation can't be
 * corrected mid-flight), and re-check a few times until the position stops
 * moving. Converges in one pass when nothing shifts.
 */
function placeInPane(el, tries = 6) {
  const pane = el.closest(".detail");
  if (!pane) {
    el.scrollIntoView({ block: "center" });
    return;
  }
  // Rect-delta, not el.offsetTop: offsetTop is measured from the nearest
  // POSITIONED ancestor, which the detail column isn't.
  const delta = el.getBoundingClientRect().top - pane.getBoundingClientRect().top;
  const want = pane.scrollTop + delta - pane.clientHeight / 3;
  const next = Math.max(0, Math.min(want, pane.scrollHeight - pane.clientHeight));
  const settled = Math.abs(next - pane.scrollTop) < 8;
  if (!settled) pane.scrollTop = next;
  if (!settled && tries > 0) setTimeout(() => placeInPane(el, tries - 1), 120);
}

function SessionDetail({ sessionId, summary, focusFindingId, onFocusFindingConsumed, state, onGoRadar }) {
  const [turns, setTurns] = useState([]);
  // Every finding main returned for the session, verdicts and all; what gets
  // inlined is the visible subset (visibleLedgerFindings) — a false positive
  // stays out of the timeline unless shown.
  const [allFindings, setFindings] = useState([]);
  const findings = useMemo(
    () => visibleLedgerFindings(allFindings, !!(state && state.prefs && state.prefs.show_false_positives), focusFindingId),
    [allFindings, state && state.prefs && state.prefs.show_false_positives, focusFindingId],
  );
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [openRuns, setOpenRuns] = useState({});
  // Monotonic request id. The deep-link effect below can fire a paging load
  // while the mount's own load(0) is still in flight, and IPC replies are not
  // ordered: a late offset-0 reply would REPLACE the turns a later page had
  // already appended, so the target turn never materialised and the scroll
  // silently never happened. Stale replies are dropped instead.
  const loadSeq = useRef(0);
  const inflight = useRef(new Set());
  // Pages already spent chasing a deep link's anchoring turn (FOCUS_MAX_PAGES).
  const focusPages = useRef(0);

  const load = useCallback(
    (offset, limit) => {
      // Never fire the same page twice — the focus effect re-runs on every
      // turns/findings change, and without this it re-requested the page it
      // was already waiting for.
      if (inflight.current.has(offset)) return;
      inflight.current.add(offset);
      const seq = ++loadSeq.current;
      setLoading(true);
      window.doorman.sessionTurns(sessionId, offset, limit || TURN_PAGE).then((res) => {
        inflight.current.delete(offset);
        // A reply older than a reset (new session) is discarded outright.
        if (seq < resetSeq.current) return;
        setTurns((prev) => {
          if (offset === 0) return res.turns;
          // Append only what we don't already hold, so an out-of-order reply
          // can't duplicate rows.
          const have = new Set(prev.map((t) => t.id));
          return prev.concat(res.turns.filter((t) => !have.has(t.id)));
        });
        setFindings(res.findings || []);
        setTotal(res.total);
        if (loadSeq.current === seq) setLoading(false);
      });
    },
    [sessionId],
  );
  const resetSeq = useRef(0);

  useEffect(() => {
    setTurns([]);
    setOpenRuns({});
    inflight.current.clear();
    resetSeq.current = loadSeq.current + 1;
    load(0);
  }, [sessionId]);

  const findingsByTurn = useMemo(() => {
    const map = new Map();
    for (const f of findings) {
      if (!f.turn_id) continue;
      if (!map.has(f.turn_id)) map.set(f.turn_id, []);
      map.get(f.turn_id).push(f);
    }
    return map;
  }, [findings]);

  // Session-flow rows have a second anchor: the turn the flow BEGAN on. The
  // full card sits at the sink (where the row lands); a marker sits here, so
  // reading the session top-down meets the read before the send.
  const sourcesByTurn = useMemo(() => {
    const map = new Map();
    for (const f of findings) {
      if (!f.source_turn_id || f.source_turn_id === f.turn_id) continue;
      if (!map.has(f.source_turn_id)) map.set(f.source_turn_id, []);
      map.get(f.source_turn_id).push(f);
    }
    return map;
  }, [findings]);
  /** Everything inlined under one turn: flow-source markers, then findings. */
  const cardsFor = (turnId) =>
    (sourcesByTurn.get(turnId) || [])
      .map((f) => <InlineRadarSource key={f.finding_id + "-source"} finding={f} />)
      .concat((findingsByTurn.get(turnId) || []).map((f) => <InlineRadar key={f.finding_id} finding={f} state={state} onGoRadar={onGoRadar} />));

  const rows = useMemo(() => collapseTurnRuns(turns), [turns]);
  const loadedIds = new Set(turns.map((t) => t.id));
  const orphanFindings = findings.filter((f) => !f.turn_id || !loadedIds.has(f.turn_id));

  const totalTokens = summary ? summary.input_tokens + summary.output_tokens : 0;
  const tokensByTurn = turns.map((t) => (t.usage ? (t.usage.input_tokens || 0) + (t.usage.output_tokens || 0) : 0));
  const folded = rows.filter((r) => r.kind === "run").reduce((n, r) => n + r.turns.length, 0);

  // Assistant turns are numbered across the WHOLE timeline, folded ones
  // included — a turn's number has to mean the same thing whether or not you
  // happened to expand the run it sits in.
  const ordinals = useMemo(() => {
    const map = new Map();
    let n = 0;
    for (const t of turns) {
      if (t.role === "assistant") {
        n += 1;
        map.set(t.id, n);
      }
    }
    return map;
  }, [turns]);

  // Radar → ledger deep link, resolved: page in more turns until the target
  // finding's turn is loaded (or the session is exhausted), auto-expand its
  // run if it's folded, then scroll to and briefly highlight the evidence
  // card itself — it renders at the right spot whether its run is open or
  // not, so this only has to make sure it's ON SCREEN and visibly the one
  // that was clicked.
  useEffect(() => {
    if (!focusFindingId) {
      focusPages.current = 0;
      return;
    }
    const finding = findings.find((f) => f.finding_id === focusFindingId);
    if (!finding) {
      if (total > 0 && turns.length >= total) onFocusFindingConsumed();
      return;
    }
    // Page in turns until the anchoring turn is loaded, so the card lands in
    // its real context — bounded (see FOCUS_MAX_PAGES: a live session's total
    // keeps growing, and chasing it meant never scrolling). When the budget is
    // spent, or every turn is loaded and the turn still isn't there (older than
    // the retention window), DON'T give up: the card still renders in the
    // orphan list, so fall through and scroll to it wherever it is.
    const anchored = !finding.turn_id || turns.some((t) => t.id === finding.turn_id);
    if (!anchored && turns.length < total && focusPages.current < FOCUS_MAX_PAGES) {
      focusPages.current += 1;
      load(turns.length, 200);
      return;
    }
    if (finding.turn_id) {
      const run = rows.find(
        (r) => r.kind === "run" && r.turns.some((t) => t.id === finding.turn_id),
      );
      if (run && !openRuns[run.id]) {
        setOpenRuns((o) => ({ ...o, [run.id]: true }));
        return;
      }
    }
    // Wait for the timeline to STOP GROWING before measuring it. Scrolling
    // while a page is still in flight put the card on screen and then pushed
    // it back off as the turns above it rendered — a scroll to a stale offset.
    // Every load resolution re-runs this effect, so this only defers.
    if (inflight.current.size > 0) return;
    const el = document.getElementById("finding-" + finding.finding_id);
    if (el) {
      placeInPane(el);
      el.classList.add("just-focused");
      setTimeout(() => el.classList.remove("just-focused"), 2200);
      onFocusFindingConsumed();
      return;
    }
    // The card isn't in the DOM yet (its run may have just been expanded this
    // render) — keep the request alive for the next pass instead of consuming
    // it, which used to drop the scroll silently. Only give up once every turn
    // is loaded and it still isn't there.
    if (total > 0 && turns.length >= total) onFocusFindingConsumed();
  }, [focusFindingId, findings, turns, total, rows, openRuns]);

  return (
    <div>
      <div className="detail-head">
        {/* The rail's mark at the title's left (name in the tip), where the
            "CLAUDE CODE" chip used to trail it. */}
        <div className="detail-title">
          {summary ? <RailMark source={summary.source} size={18} /> : null}
          <h2>{(summary && summary.title) || sessionId.slice(0, 12) + "…"}</h2>
        </div>
        <div className="meta">
          {summary ? (
            <React.Fragment>
              <span>
                {clockTime(summary.started_at)} → {clockTime(summary.ended_at)}
              </span>
              <span>{summary.turns} turns</span>
              <span>{fmtTokens(totalTokens)} tokens</span>
              {summary.alerts > 0 ? (
                <span className="alert">
                  {summary.alerts} radar alert{summary.alerts === 1 ? "" : "s"}
                </span>
              ) : null}
              {(summary.covered_tokens || 0) + (summary.overage_tokens || 0) + (summary.billed_tokens || 0) > 0 ? (
                <SettlementSplitLine summary={summary} />
              ) : null}
            </React.Fragment>
          ) : null}
        </div>
        <LiveHandoff
          row={((state.live && state.live.sessions) || []).find((r) => r.session_id === sessionId) || null}
          summary={summary}
          canFocus={state.platform === "macos"}
        />
      </div>

      {turns.length === 0 && !loading ? (
        <Empty>No turns stored for this session (it may be older than your retention window).</Empty>
      ) : (
        <div>
          {folded > 0 ? (
            <div className="foldnote">
              {folded} tool-only turn{folded === 1 ? "" : "s"} folded into event runs — expand any run
              to read it.
            </div>
          ) : null}
          {rows.map((row) => {
            if (row.kind === "run") {
              const open = !!openRuns[row.id];
              return (
                <React.Fragment key={row.id}>
                  <button
                    className={"eventrun" + (open ? " open" : "")}
                    aria-expanded={open}
                    onClick={() => setOpenRuns({ ...openRuns, [row.id]: !open })}
                  >
                    <span className="er-n">{row.turns.length} events</span>
                    {/* Tool names as chips (ref: the gallery's Tool Chips), not
                        a dot-joined string. Joined, one long MCP name ate the
                        line — `mcp__claude-in-chrome__na…` — and the four
                        ordinary tools after it were simply not rendered. Each
                        chip is whole or elided on its own, and the overflow is
                        counted rather than dropped. */}
                    <span className="er-chips">
                      {row.tools.length === 0 ? (
                        <span className="er-chip more">no tools recorded</span>
                      ) : (
                        // Four, not six: a run full of MCP tools has 30-character
                        // names, and six of those wrapped the run line to four
                        // rows — taller than the turn bubbles it is meant to be
                        // a compact stand-in for.
                        row.tools.slice(0, 4).map((tool) => (
                          <span key={tool} className="er-chip" title={tool}>
                            {tool}
                          </span>
                        ))
                      )}
                      {row.tools.length > 4 ? (
                        <span className="er-chip more">+{row.tools.length - 4}</span>
                      ) : null}
                    </span>
                    <span className="er-meta">
                      {clockTime(row.from)}
                      {row.to !== row.from ? "→" + clockTime(row.to) : ""}
                      {row.tokens > 0 ? " · " + fmtTokens(row.tokens) + " tok" : ""}
                    </span>
                    <span className="er-act">{open ? "hide" : "show all"}</span>
                  </button>
                  {open
                    ? row.turns.map((t) => (
                        <React.Fragment key={t.id}>
                          <TurnBubble turn={t} ordinal={ordinals.get(t.id)} inRun />
                          {cardsFor(t.id)}
                        </React.Fragment>
                      ))
                    : // A finding anchored inside a FOLDED run still shows — the
                      // whole point of the radar is that it isn't behind a click.
                      row.turns.flatMap((t) => cardsFor(t.id))}
                </React.Fragment>
              );
            }
            const t = row.turn;
            return (
              <React.Fragment key={t.id}>
                <TurnBubble turn={t} ordinal={ordinals.get(t.id)} />
                {cardsFor(t.id)}
              </React.Fragment>
            );
          })}
          {orphanFindings.map((f) => (
            <InlineRadar key={f.finding_id} finding={f} state={state} onGoRadar={onGoRadar} />
          ))}
          {turns.length < total ? (
            <button className="showall" disabled={loading} onClick={() => load(turns.length, 200)}>
              — {total - turns.length} more turn{total - turns.length === 1 ? "" : "s"} · <b>show more</b> —
            </button>
          ) : null}
        </div>
      )}
      {/* The session's footer, pinned to the pane's bottom: the cost-per-turn
          chart and the Doorman AI door, together — the two things you reach
          for after reading, not before. The subject of the question is the
          session summary plus every finding that fired in it
          (main/ai-assistant.ts sessionContext). */}
      {summary && tokensByTurn.filter((c) => c > 0).length > 2 ? (
        <div className="detail-foot">
          <span className="sparkwrap" title="Tokens per turn across this session">
            <MicroSpark data={tokensByTurn} color="var(--c1)" width={180} height={28} />
            <span className="sparklabel">tokens per turn</span>
          </span>
          <span className="spacer" />
        </div>
      ) : null}
    </div>
  );
}

function TurnBubble({ turn, ordinal, inRun }) {
  const t = turn;
  // Turn text arrives from main REDACTED (the store keeps the raw text, this
  // Mac only, but nothing renders a secret unasked). `text_redacted` flags the
  // turns where redaction changed something. Two reveals, both display-only
  // and reset when the bubble unmounts:
  //   · click ONE [redacted:…] mark — that value swaps in, in place. The
  //     bridge text is exactly redact(raw), so the nth placeholder is the nth
  //     recovered secret — no ambiguity;
  //   · VIEW RAW — the whole raw text, for when the shape of the full prompt
  //     is the question.
  const [raw, setRaw] = useState(null); // { text, secrets } once fetched
  const [showFull, setShowFull] = useState(false);
  const [shownMarks, setShownMarks] = useState({});
  const fetchRaw = () =>
    raw
      ? Promise.resolve(raw)
      : window.doorman.turnRaw(t.id).then((res) => {
          if (!res || !res.ok) return null;
          const next = { text: res.text, secrets: Array.isArray(res.secrets) ? res.secrets : [] };
          setRaw(next);
          return next;
        });
  const toggleFull = () => {
    if (showFull) {
      setShowFull(false);
      return;
    }
    fetchRaw().then((r) => {
      if (r) setShowFull(true);
    });
  };
  const toggleMark = (n) => (event) => {
    event.stopPropagation();
    if (shownMarks[n]) {
      setShownMarks((s) => ({ ...s, [n]: false }));
      return;
    }
    fetchRaw().then((r) => {
      if (r && r.secrets[n] && r.secrets[n].value !== "") {
        setShownMarks((s) => ({ ...s, [n]: true }));
      } else {
        // Can't map this one placeholder — show the whole raw text instead of
        // doing nothing.
        toggleFull();
      }
    });
  };
  const label =
    t.role === "user"
      ? "YOU · " + clockTime(t.at)
      : "TURN " +
        (ordinal || "–") +
        " · " +
        (t.model || "assistant").toUpperCase() +
        " · " +
        clockTime(t.at) +
        (t.usage ? " · " + fmtTokens(t.usage.input_tokens + t.usage.output_tokens) + " TOK" : "");

  let body = null;
  if (showFull && raw) {
    body = <div className="body">{raw.text}</div>;
  } else if (t.text && t.text_redacted) {
    // Placeholders render as clickable marks; `n` counts placeholders in
    // order, which is exactly their index into the recovered secrets.
    const parts = t.text.split(/(\[redacted(?::[a-z0-9_]+)?\])/g);
    let n = -1;
    body = (
      <div className="body">
        {parts.map((part, i) => {
          if (!/^\[redacted/.test(part)) return <span key={i}>{part}</span>;
          n += 1;
          const ord = n;
          const value = shownMarks[ord] && raw && raw.secrets[ord] ? raw.secrets[ord].value : null;
          return (
            <mark
              key={i}
              className={"redmark" + (value != null ? " on" : "")}
              role="button"
              tabIndex={0}
              title={
                value != null
                  ? "Click to mask it again"
                  : "Reveal this value in place — read from this computer just now, never stored"
              }
              onClick={toggleMark(ord)}
              onKeyDown={(ev) => (ev.key === "Enter" || ev.key === " " ? toggleMark(ord)(ev) : null)}
            >
              {value != null ? value : part}
            </mark>
          );
        })}
      </div>
    );
  } else if (t.text) {
    body = <div className="body">{t.text}</div>;
  } else {
    body = <span className="faint">no prose — tool calls only</span>;
  }

  return (
    <div className={"bubble " + t.role + (inRun ? " in-run" : "")}>
      <div className="turnlabel">
        {/* The model's own mark, where one is known — the label is a mono
            string, and the logo is the one part of it the eye finds without
            reading. */}
        {t.role === "user" ? null : <ModelMark model={t.model} />}
        {label}
        {t.text_redacted ? (
          <button
            className={"revealbtn" + (showFull ? " on" : "")}
            onClick={toggleFull}
            title="Secrets in this turn are redacted on screen — click a redaction to reveal just that value, or view the whole raw text. Read from this computer, shown here only."
          >
            {showFull ? "HIDE RAW" : "REDACTED · VIEW RAW"}
          </button>
        ) : null}
      </div>
      {body}
      {t.tools && t.tools.length > 0 ? (
        // Deduped chips with counts, same treatment as the event-run line —
        // dot-joined text repeated duplicates ("Bash, Bash") and let one long
        // MCP name push the rest off the line.
        <div className="tools">
          {(() => {
            const counts = new Map();
            for (const tool of t.tools) counts.set(tool, (counts.get(tool) || 0) + 1);
            return [...counts.entries()].map(([tool, n]) => (
              <span key={tool} className="er-chip" title={tool}>
                {tool}
                {n > 1 ? " ×" + n : ""}
              </span>
            ));
          })()}
        </div>
      ) : null}
    </div>
  );
}

function SettlementSplitLine({ summary }) {
  // Rendered only when part of the usage is actually attributed to the plan
  // or to API credits — a session that is 100% "unattributed" (the norm for a
  // local transcript with no billing signal) turned this into a solid
  // unlabeled bar that restated the total as a mystery stripe. When the
  // split IS informative, each part carries its own swatch + label + value
  // (tokens, never dollars): the hover title was the only place the
  // colors were named before.
  const parts = [
    { key: "p", label: "plan", value: summary.covered_tokens || 0, color: "var(--navy)" },
    { key: "c", label: "API credits", value: summary.overage_tokens || 0, color: "var(--bad)" },
    { key: "a", label: "API key", value: summary.billed_tokens || 0, color: "var(--ink-3)" },
    { key: "u", label: "unattributed", value: summary.unknown_tokens || 0, color: "var(--tan-3)" },
  ].filter((p) => p.value > 0);
  return (
    <span className="settle">
      <span className="metercap">
        <MeterBar parts={parts} height={6} />
      </span>
      {parts.map((p) => (
        <span key={p.key} className="s-item">
          <span className="swatch" style={{ background: p.color }} />
          {p.label} {fmtTokens(p.value)}
        </span>
      ))}
    </span>
  );
}

/**
 * The session's findings the timeline inlines. A row judged FALSE
 * POSITIVE is left out unless the person has asked to see them
 * (prefs.show_false_positives) — the verdict says there was nothing on that
 * turn — with one exception: the finding a deep link is aimed at, which is
 * kept whatever its verdict, because the Radar card that sent you here is
 * showing it and a link to nothing would scroll to nowhere. Pure, so a test
 * can ask it directly; the session detail cannot be driven to a loaded state
 * without the bridge.
 */
function visibleLedgerFindings(findings, showFalsePositives, focusFindingId) {
  if (showFalsePositives) return findings;
  return findings.filter((f) => f.status !== "false_positive" || f.finding_id === focusFindingId);
}

/**
 * A radar finding inlined at the ledger turn it anchors to.
 *
 * This card used to be one sentence and a rule id — the reader had to leave
 * for the Radar screen to learn WHAT was exposed. It now carries what the
 * Radar's own card carries: the severity, where it happened (tool → target),
 * and the masked evidence strip — with the same local click-to-reveal, since
 * the excerpt is exactly why someone stops at this card. `Evidence` is the
 * Radar screen's component (classic scripts, one global scope).
 */
/**
 * The OTHER end of a session flow, at the turn it began on: a marker, not a
 * second copy of the card. The card itself sits at the sink turn (where the
 * row anchors); this says "the read that fed it happened here" and points
 * down, so a top-down read of the session meets the flow in order.
 */
function InlineRadarSource({ finding }) {
  const meta = SEC_DETECTORS[finding.detector] || {};
  const ends = flowEnds(finding.detector);
  const span = flowSpan(finding);
  return (
    <div className="radar-inline source" id={"finding-" + finding.finding_id + "-source"}>
      <div className="head">
        <span className="tag soft">RADAR · FLOW BEGAN</span>
        <span className="meta">
          {finding.source_at ? clockTime(finding.source_at) + " · " : ""}
          {finding.detector}
        </span>
      </div>
      <div className="ri-what">
        {meta.label ? <strong>{meta.label}. </strong> : null}
        {"The " + ends[0] + " happened here; the " + ends[1] + " follows" + (span ? " " + span + " later" : "") + " ↓"}
      </div>
    </div>
  );
}

function InlineRadar({ finding, state, onGoRadar }) {
  const meta = SEC_DETECTORS[finding.detector] || {};
  const enforcedTag =
    finding.enforced === "deny"
      ? "RADAR · BLOCKED"
      : finding.enforced === "ask"
        ? "RADAR · ASKED"
        : finding.enforced === "warn"
          ? "RADAR · WARNED"
          : finding.enforced === "excepted"
            ? "RADAR · EXCEPTED"
            : "RADAR";
  const where =
    finding.tool_name || finding.target
      ? (finding.tool_name || "") + (finding.target ? " → " + finding.target : "")
      : "";
  return (
    <div className="radar-inline" id={"finding-" + finding.finding_id}>
      <div className="head">
        <span className={"tag" + (finding.enforced === "deny" ? "" : " soft")}>{enforcedTag}</span>
        <SeverityBadge severity={finding.severity} />
        {/* The same two chips the Radar card wears, for the same reasons: a
            model stood it down, or the rule itself was unsure. */}
        {assistChip(finding.assist) ? <span className="chip" title={assistPhrase(finding.assist)}>{assistChip(finding.assist)}</span> : null}
        {confidenceChip(finding) ? <span className="chip" title={confidencePhrase(finding)}>{confidenceChip(finding)}</span> : null}
        {finding.config_host ? <span className="chip">{finding.config_host.toUpperCase()}</span> : null}
        <span className="meta">
          {clockTime(finding.last_seen_at)} · {finding.detector}
          {finding.occurrences > 1 ? " · ×" + finding.occurrences : ""}
          {typeof finding.burned_tokens === "number" ? " · " + fmtTokens(finding.burned_tokens) + " tokens burned" : ""}
        </span>
      </div>
      <div className="ri-what">
        {meta.label ? <strong>{meta.label}. </strong> : null}
        {finding.resolution
          ? RESOLUTION_SENTENCE[finding.resolution]
          : finding.enforced === "deny"
            ? "The tool call was not executed."
            : finding.enforced === "ask"
              ? "Claude Code asked before running it."
              : finding.enforced === "warn"
                ? "The call ran — a coaching heads-up was raised."
                : finding.enforced === "excepted"
                  ? "The call ran — " + exceptionPhrase(finding) + "."
                  : "Observed — nothing was blocked."}
        {where ? <span className="mono muted"> · {where}</span> : null}
        {/* A flow landed here; it began at an earlier turn, where a marker sits. */}
        {flowSpan(finding) ? (
          <span className="muted">
            {" · " + flowEnds(finding.detector)[1] + " — the " + flowEnds(finding.detector)[0] + " was " + flowSpan(finding) + " earlier ↑"}
          </span>
        ) : null}
        {finding.assist ? <span className="muted"> · {assistPhrase(finding.assist)}</span> : null}
        {/* "How to fix this?", on the finding in its session context. Compact —
            the ledger is dense enough. */}
        <span className="ri-ask">
          <AiAskButton
            compact
            contextRef={{ kind: "finding", finding_id: finding.finding_id }}
            question="What does this finding mean in this session, and what should I do about it?"
            title={meta.label || finding.detector}
          />
        </span>
        {/* The way BACK: this card is one sighting of an exposure, and the
            decision about it is made on the Radar. Round trip, not one-way —
            the Radar's `session →` landed here, and a reader who followed it
            to check the context should not have to find the card again by
            scrolling the feed. Lands on the exposure, lit. */}
        {onGoRadar ? (
          <button type="button" className="linkbtn ri-go" onClick={() => onGoRadar({ finding_id: finding.finding_id })}>
            Review on Radar →
          </button>
        ) : null}
      </div>
      {/* `raw`: the Ledger is where you come to read what actually happened,
          so the whole unmasked window is one deliberate click away — beside
          the turn it fired on, which carries its own REDACTED · VIEW RAW.
          The Radar card asks for no such thing: there the strip is a masked
          line with one placeholder revealable at a time. */}
      {finding.excerpt ? (
        <Evidence excerpt={finding.excerpt} keyName={finding.key_name} findingId={finding.finding_id} row={finding} raw platform={state && state.platform} />
      ) : null}
    </div>
  );
}


/* ── Live sessions ("Now") ─────────────────────────────────────────────────
   The agents running on this Mac right now, joined to their ledger sessions
   by main (lib/live-sessions.ts): the guard's presence record pins a process
   to a session exactly; a process the guard has not seen yet joins by working
   directory; a session with a turn in the last two minutes but no visible
   process is shown too, and says so. One control per row — Open brings the
   agent's own terminal tab forward (the session cannot be attached to from
   here; that is the window it lives in). */

function liveAgo(iso) {
  const ms = Date.now() - Date.parse(iso);
  if (!(ms >= 0)) return "";
  const m = Math.floor(ms / 60000);
  if (m < 1) return "just now";
  if (m < 60) return m + "m";
  const h = Math.floor(m / 60);
  return h + "h" + (m % 60 ? " " + (m % 60) + "m" : "");
}

function liveStateLabel(row) {
  switch (row.state) {
    case "held":
      return "held — needs your answer";
    case "working":
      return "working";
    case "waiting":
      return "waiting for you · " + liveAgo(row.since);
    default:
      return "quiet " + liveAgo(row.since);
  }
}

function livePlace(row) {
  const parts = [];
  if (row.cwd) parts.push(row.cwd.split("/").filter(Boolean).pop() || row.cwd);
  if (row.git_branch) parts.push(row.git_branch);
  return parts.join(" · ");
}

function liveWhere(row) {
  if (row.headless) return "no terminal";
  if (row.tmux) return "tmux";
  if (row.terminal_app) return row.terminal_app;
  if (row.term_program) return row.term_program.replace(/^Apple_/, "").replace(/\.app$/, "");
  if (row.join === "recent") return "no local process seen";
  return "";
}

/* `canFocus`: bringing a live session's terminal forward goes through Apple
   Events (main/lib/terminal-handoff.ts) — macOS only, so elsewhere there is
   no Open button that could only ever fail. */
function LiveGroup({ rows, counts, selected, onSelect, canFocus }) {
  const line = counts
    ? [
        counts.held > 0 ? counts.held + " held" : null,
        counts.working > 0 ? counts.working + " working" : null,
        counts.waiting > 0 ? counts.waiting + " waiting for you" : null,
        counts.idle > 0 ? counts.idle + " quiet" : null,
      ]
        .filter(Boolean)
        .join(" · ")
    : "";
  return (
    <React.Fragment>
      <div className="daylabel live">Now{line ? " · " + line : ""}</div>
      {rows.map((row) => (
        <LiveRow
          key={"live-" + (row.pid || "") + "-" + (row.session_id || "")}
          row={row}
          selected={!!row.session_id && row.session_id === selected}
          onSelect={onSelect}
          canFocus={canFocus}
        />
      ))}
    </React.Fragment>
  );
}

function LiveRow({ row, selected, onSelect, canFocus }) {
  const [note, setNote] = useState(null);
  const canOpen = canFocus && !!row.pid && !row.headless;
  const open = (e) => {
    e.stopPropagation();
    setNote("…");
    window.doorman.liveOpen({ pid: row.pid, session_id: row.session_id }).then((res) => {
      setNote(res && res.ok ? res.note || null : (res && res.error) || "Couldn't open it.");
      if (res && res.ok && !res.note) setTimeout(() => setNote(null), 1500);
    });
  };
  const select = () => {
    if (row.session_id) onSelect(row.session_id);
  };
  const meta = [
    liveStateLabel(row),
    livePlace(row),
    liveWhere(row),
    row.turns > 0 ? row.turns + " turn" + (row.turns === 1 ? "" : "s") : row.session_id ? null : "no turns yet",
    row.tokens > 0 ? fmtTokens(row.tokens) + " tokens" : null,
  ].filter(Boolean);
  return (
    <div
      className={"sessrow live" + (selected ? " on" : "") + (row.session_id ? "" : " unjoined")}
      role="button"
      tabIndex={0}
      onClick={select}
      onKeyDown={(e) => {
        if (e.key === "Enter" || e.key === " ") select();
      }}
      title={row.cwd || undefined}
    >
      <span className={"livedot " + row.state} aria-hidden="true" />
      <span className="body">
        <span className="top">
          <RailMark source={row.source} />
          <span className="title">
            {row.title || (row.session_id ? <span className="mono muted">{row.session_id.slice(0, 12)}…</span> : "New session")}
          </span>
        </span>
        <span className="meta">
          {meta.join(" · ")}
          {row.alerts > 0 ? (
            <React.Fragment>
              {" · "}
              <span className="alert">
                {row.alerts} alert{row.alerts === 1 ? "" : "s"}
              </span>
            </React.Fragment>
          ) : null}
          {note ? <span className="live-note"> · {note}</span> : null}
        </span>
      </span>
      {canOpen ? (
        <button type="button" className="btn sm" onClick={open} title="Bring this session's terminal forward">
          Open
        </button>
      ) : null}
    </div>
  );
}

/* The detail head's one action: Open for a live session, Continue for an
   ended one whose host documents a resume command (main fills
   `resume_command` at snapshot time — no guess for hosts without one). The
   outcome is said in a line, with the command to paste when the app could
   not open a window itself (Automation denied, an unknown terminal). */
function LiveHandoff({ row, summary, canFocus }) {
  const [result, setResult] = useState(null);
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    setResult(null);
  }, [summary && summary.id]);
  if (!summary) return null;
  const live = row && row.pid;
  const resume = !live && summary.resume_command;
  if (!live && !resume) return null;
  const go = () => {
    setBusy(true);
    setResult(null);
    window.doorman.liveOpen({ session_id: summary.id, pid: row ? row.pid : undefined }).then((res) => {
      setBusy(false);
      setResult(res || { ok: false, error: "No answer from the app." });
    });
  };
  return (
    <div className="live-handoff">
      {live ? (
        <span className="livestate">
          <span className={"livedot " + row.state} aria-hidden="true" />
          {liveStateLabel(row)}
          {liveWhere(row) ? " · " + liveWhere(row) : ""}
        </span>
      ) : null}
      {live && canFocus && !row.headless ? (
        <button type="button" className="btn sm" onClick={go} disabled={busy} title="Bring this session's terminal forward">
          {busy ? "Opening…" : "Open terminal"}
        </button>
      ) : null}
      {resume ? (
        <button
          type="button"
          className="btn sm"
          onClick={go}
          disabled={busy}
          title={"Opens a new terminal window in " + (summary.cwd || "your home folder") + " running: " + summary.resume_command}
        >
          {busy ? "Opening…" : "Continue in Terminal"}
        </button>
      ) : null}
      {result ? (
        <span className={"live-note" + (result.ok ? "" : " bad")}>
          {result.ok
            ? result.how === "opened"
              ? "Opened a new window."
              : result.how === "focused"
                ? "Brought the tab forward."
                : "Brought the terminal forward."
            : result.error}
          {result.note ? " " + result.note : ""}
          {!result.ok && result.line ? (
            <React.Fragment>
              {" Paste this instead: "}
              <code className="mono">{result.line}</code>
            </React.Fragment>
          ) : null}
        </span>
      ) : null}
    </div>
  );
}
