/* Security Overview — the section's landing page (canvas artboards
   3 and 3b).

   Security opened on the Radar: a list that is either empty or overwhelming,
   with no route from "something happened in a session" to "here is the
   session". This screen is that route, and nothing else. It holds THREE
   things and deliberately no third — Trace a secret is the Radar's:

     1. the agents running RIGHT NOW, each with the exposures currently open
        against it — the Ledger's live rail, read for what it means rather
        than what it costs;
     2. recent sessions that had something flagged, each opening to its own
        exposures — plus a quiet line for the sessions that had nothing, which
        is the part that says the quiet is real rather than unmeasured.

   The canvas draws a third: a hero counting the backlog. Left out for now —
   that count is already on the sidebar badge and the menu bar, and a third
   copy is a third thing that can disagree with the other two.

   It owns NO list of its own. Everything it shows is a view onto the Radar's
   data, and every "review" route lands there: a second list of exposures,
   with its own filters and its own idea of what is open, is the thing this
   page exists to avoid. */

function OverviewScreen({ state, onGoRadar, onOpenSession }) {
  return (
    <div>
      {/* The title row is SecurityHeader's — see app.jsx — and carries the
          active-exposure count at its right, as the Radar's carries Trace a
          secret. It is `summary.open_exposures` — the very field the sidebar
          badge, the menu bar and the Radar's own hero print — so a fourth
          copy cannot disagree with the other three; it answers "is anything
          open?" before the reader scans a row, and a click lands on the Radar. */}

      <ActiveSessions state={state} onGoRadar={onGoRadar} onOpenSession={onOpenSession} />

      <FlaggedSessions state={state} onGoRadar={onGoRadar} onOpenSession={onOpenSession} />
    </div>
  );
}

/**
 * How many exposures are active — open, needing review — as one split pill:
 * the figure in a tinted block at the left, the words on paper at the right.
 *
 * Main's number, not a renderer-side count off the capped rows: the same
 * `open_exposures` the Radar's hero shows, so the landing page and the feed
 * it points at always agree. The block is red while anything is open, green
 * at zero; the figure is always printed, so the colour is the fast read and
 * never the only one. The whole pill is the route to the Radar, unfiltered —
 * the count is about everything, so the link is too.
 */
function ActiveCount({ state, onGoRadar }) {
  const summary = (state.radar && state.radar.summary) || {};
  const open =
    summary.open_exposures != null ? summary.open_exposures : summary.open_groups != null ? summary.open_groups : 0;
  return (
    <button
      type="button"
      className={"ovr-count " + (open > 0 ? "hot" : "live")}
      onClick={() => onGoRadar()}
      title="Open the Security Radar"
    >
      <b>{open}</b>
      <span className="ovr-count-lab">
        {open === 1 ? "exposure to review" : "exposures to review"}
        <span className="ovr-count-go" aria-hidden="true">
          →
        </span>
      </span>
    </button>
  );
}

/**
 * The agents running on this Mac right now, and what is open against each.
 *
 * The rows are main's live rail (lib/live-sessions.ts) — the same rows the
 * Ledger's "Now" group shows — joined here to the OPEN findings the renderer
 * holds, so a session that is working this minute and has a critical
 * exposure against it says so in one line, with the exposure a click from
 * its card on the Radar. The Ledger's row asks "what is it costing?"; this
 * one asks "is anything wrong with it?".
 */
const LIVE_EXPOSURES_SHOWN = 4;

function ActiveSessions({ state, onGoRadar, onOpenSession }) {
  const live = ((state.live && state.live.sessions) || []).filter((r) => r.state !== "idle" || r.session_id);
  const counts = (state.live && state.live.counts) || null;
  // Open rows in a band the person is seeing — the Radar's own
  // rule, so a session never reads "1 open" here beside a feed showing none.
  const findings = visibleConfidenceRows((state.radar && state.radar.findings) || [], state.prefs).filter(
    (f) => f.status === "open",
  );
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
    <Card title="Active sessions" hint={live.length > 0 && line ? line : undefined}>
      {live.length === 0 ? (
        <div className="cardnote" style={{ marginTop: 0 }}>
          No agent is running on this Mac right now. Sessions appear here the moment one starts, with anything the
          Radar has open against them.
        </div>
      ) : (
        <div className="ovr-live">
          {live.map((row) => {
            const open = row.session_id ? findings.filter((f) => f.session_id === row.session_id) : [];
            const ranked = [...open].sort(
              (a, b) =>
                SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity) ||
                (a.last_seen_at < b.last_seen_at ? 1 : -1),
            );
            return (
              <div key={"live-" + (row.pid || "") + "-" + (row.session_id || "")} className={"ovr-live-row " + row.state}>
                <span className={"livedot " + row.state} aria-hidden="true" />
                <div className="ovr-live-said">
                  <div className="ovr-live-top">
                    <span className="ovr-live-t">
                      {row.title || (row.session_id ? <span className="mono muted">{row.session_id.slice(0, 12)}…</span> : "New session")}
                    </span>
                    <span className="ovr-live-m muted">
                      {[SOURCE_NAMES[row.source] || row.source, liveStateLabel(row), livePlace(row)].filter(Boolean).join(" · ")}
                    </span>
                  </div>
                  {/* The exposures CURRENTLY open against this session — the
                      highlight. Each is a link to its card on the Radar,
                      lit; worst first. A running session with nothing open
                      says "No exposures to review" — a count, in the Radar's
                      own words, not a verdict on the session. */}
                  {ranked.length > 0 ? (
                    <div className="ovr-live-exps">
                      {ranked.slice(0, LIVE_EXPOSURES_SHOWN).map((f) => {
                        const meta = detectorMeta(f.detector, null, f);
                        return (
                          <button
                            key={f.finding_id}
                            type="button"
                            className={"ovr-exp sev-" + f.severity}
                            onClick={() => onGoRadar({ session_id: row.session_id, finding_id: f.finding_id })}
                            title="Review this exposure on the Radar"
                          >
                            <span className="ovr-exp-sev">{f.severity}</span>
                            {meta.label}
                            {f.key_name ? <span className="muted"> · {f.key_name}</span> : null}
                          </button>
                        );
                      })}
                      {ranked.length > LIVE_EXPOSURES_SHOWN ? (
                        <button type="button" className="linkbtn" onClick={() => onGoRadar({ session_id: row.session_id })}>
                          and {ranked.length - LIVE_EXPOSURES_SHOWN} more →
                        </button>
                      ) : null}
                    </div>
                  ) : (
                    <div className={"ovr-live-none" + (row.session_id ? " ok" : " muted")}>
                      {row.session_id ? <Icon name="check" size={13} strokeWidth={2.2} /> : null}
                      {row.session_id ? "No exposures to review" : "No turns yet"}
                    </div>
                  )}
                </div>
                {row.session_id ? (
                  <div className="ovr-live-act">
                    <button
                      type="button"
                      className="btn"
                      onClick={() => onOpenSession(row.session_id, ranked[0] ? ranked[0].finding_id : undefined)}
                    >
                      Open session
                    </button>
                  </div>
                ) : null}
              </div>
            );
          })}
        </div>
      )}
    </Card>
  );
}

/**
 * Recent sessions that had something flagged, newest first, each opening to
 * its own exposures.
 *
 * This is the route the section was missing: from "something happened" to the
 * session it happened in. The rows are built by joining the OPEN findings the
 * renderer holds against `state.sessions`, so a session with no findings never
 * appears and a finding whose session has aged out of the snapshot still does
 * — under its own id, rather than being dropped for want of a title.
 */
/* How many sessions the card lists before handing you to the Radar. This is a
   landing page, not the list — four is enough to see what is recent, and the
   rest are one click away in the place that can filter them. */
const SHOWN = 4;

function FlaggedSessions({ state, onGoRadar, onOpenSession }) {
  // Minus the confidence bands folded away: a session whose only
  // open row is a low-confidence lead is not "flagged" while the Radar and
  // the badge say there is nothing to review.
  const rows = visibleConfidenceRows((state.radar && state.radar.findings) || [], state.prefs);
  const sessions = state.sessions || [];
  const byId = {};
  for (const s of sessions) byId[s.id] = s;

  const groups = {};
  for (const f of rows) {
    if (f.status !== "open" || !f.session_id) continue;
    const g = (groups[f.session_id] = groups[f.session_id] || {
      id: f.session_id,
      findings: [],
      at: f.last_seen_at,
      source: f.source,
      cwd: f.cwd,
    });
    g.findings.push(f);
    if (f.last_seen_at > g.at) g.at = f.last_seen_at;
    if (!g.cwd && f.cwd) g.cwd = f.cwd;
  }
  const flagged = Object.values(groups).sort((a, b) => (a.at < b.at ? 1 : -1));
  /* Open rows with no session of their own — the machine-level findings. */
  const unsessioned = rows.filter((f) => f.status === "open" && !f.session_id).length;

  /* The sessions that had NOTHING. Counted against `sessions_total` (main's
     count of every session it holds) minus the flagged ones — not against the
     capped `sessions` array, which would shrink the reassurance as the app
     accumulated history. Only stated when the total is actually known and
     bigger, so it never reads "0 other sessions". */
  const total = typeof state.sessions_total === "number" ? state.sessions_total : sessions.length;
  const quiet = Math.max(0, total - flagged.length);

  return (
    <Card
      title="Recent sessions with something flagged"
      hint={
        /* Say what is ON SCREEN when the list is cut, not the total — a hint
           reading "31 with exposures" over eight rows is the card
           contradicting itself. The total is still named, after the "of". */
        flagged.length > SHOWN ? "showing " + SHOWN + " of " + flagged.length : flagged.length > 0 ? flagged.length + " with exposures" : undefined
      }
    >
      {flagged.length === 0 ? (
        /* Two different empty states, because they are two different facts and
           the badge beside them can only ever show one number. Not every
           exposure belongs to a session — a tampered guard, an unrecognized
           MCP server and a new egress destination are properties of the
           MACHINE — so "no session has anything" can be true while the badge
           reads 4. Saying only the first would read as a contradiction of the
           sidebar; this says which it is. */
        <div className="cardnote" style={{ marginTop: 0 }}>
          {unsessioned > 0
            ? unsessioned +
              (unsessioned === 1 ? " open exposure isn't" : " open exposures aren't") +
              " tied to a session — they are about this machine rather than one piece of work. Review them in the Security Radar."
            : "No session has anything open. Sessions are still being read and scored — anything found lands on the Security Radar."}
        </div>
      ) : (
        <div className="ovr-sessions">
          {flagged.slice(0, SHOWN).map((g) => (
            <FlaggedSession
              key={g.id}
              group={g}
              session={byId[g.id]}
              onGoRadar={onGoRadar}
              onOpenSession={onOpenSession}
            />
          ))}
        </div>
      )}
      {flagged.length > SHOWN ? (
        <div className="row" style={{ marginTop: "var(--s4)" }}>
          <button className="btn primary" onClick={() => onGoRadar()}>
            See the other {flagged.length - SHOWN} in the Security Radar →
          </button>
        </div>
      ) : null}
      {quiet > 0 ? (
        /* Good news drawn as good news: the check and the good colour, the
           same way a clean running session says so above. */
        <div className="cardnote ovr-quiet ok">
          <Icon name="check" size={13} strokeWidth={2.2} />
          {quiet} other session{quiet === 1 ? "" : "s"} had nothing flagged
        </div>
      ) : null}
    </Card>
  );
}

/** The exposure a session should open on: its worst, newest first within a
 *  band. Pure; SEVERITY_ORDER is worst-first. */
function worstOf(findings) {
  return [...findings].sort(
    (a, b) =>
      SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity) ||
      (a.last_seen_at < b.last_seen_at ? 1 : -1),
  )[0];
}

/** One session, opening to the exposures found in it. A native <details>, so
 *  its contents stay in the document when shut — the same reason Guardrails'
 *  Advanced uses one. */
function FlaggedSession({ group, session, onGoRadar, onOpenSession }) {
  const counts = {};
  for (const f of group.findings) counts[f.severity] = (counts[f.severity] || 0) + 1;
  const bands = SEVERITY_ORDER.filter((s) => counts[s] > 0);
  const title = (session && session.title) || "Untitled session";
  const project = (group.cwd || "").split("/").filter(Boolean).pop();
  const sourceName = SOURCE_NAMES[group.source] || group.source || "unknown";

  return (
    <details className="ovr-session">
      <summary>
        <span className="ovr-session-said">
          <span className="ovr-session-t">{title}</span>
          <span className="ovr-session-m muted">
            {sourceName} · {relTime(group.at)}
            {project ? " · " + project : ""}
          </span>
        </span>
        {bands.map((s) => (
          <span key={s} className={"sev sev-" + s}>
            {counts[s]} {s}
          </span>
        ))}
      </summary>
      <div className="ovr-session-body">
        {/* Each exposure is a LINK to its card on the Radar — narrowed to this
            session, scrolled to and lit. The list used to be inert text with
            one button under it for all of them, so "which of these three is
            the one I care about?" was a question the page could not take you
            to the answer of. */}
        {group.findings.slice(0, 6).map((f) => {
          const meta = detectorMeta(f.detector, null, f);
          const outcome = findingOutcome(f);
          return (
            <button
              key={f.finding_id}
              type="button"
              className="ovr-exposure"
              onClick={() => onGoRadar({ session_id: group.id, finding_id: f.finding_id })}
              title="Review this exposure on the Radar"
            >
              <span className={"sev sev-" + f.severity}>{f.severity}</span>
              <span className="ovr-exposure-t">
                {meta.label}
                {f.key_name ? <span className="muted"> · {f.key_name}</span> : null}
              </span>
              {/* What the guard DID, which is the difference between "nothing
                  to do" and "rotate this key now". */}
              <span className={"ovr-act act-" + outcome}>{outcome}</span>
              <span className="ovr-exposure-go" aria-hidden="true">→</span>
            </button>
          );
        })}
        {group.findings.length > 6 ? (
          <div className="cardnote" style={{ marginTop: 0 }}>
            and {group.findings.length - 6} more in this session
          </div>
        ) : null}
        <div className="row" style={{ marginTop: "var(--s4)" }}>
          {/* THIS session's exposures, not the whole feed: the Radar arrives
              narrowed to the session, with the filter chip to widen it. */}
          <button className="btn primary" onClick={() => onGoRadar({ session_id: group.id })}>
            Review these in the Radar →
          </button>
          {/* The session in the Ledger, opened AT its worst exposure's turn
              rather than at the top — the ledger scrolls to and lights the
              finding it is handed, and "open session" meant "show me where
              this happened", not "show me the session's first prompt". */}
          <button className="btn" onClick={() => onOpenSession(group.id, worstOf(group.findings).finding_id)}>
            Open session
          </button>
        </div>
      </div>
    </details>
  );
}
