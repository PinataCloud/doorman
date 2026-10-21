/* Security Overview — the section's landing page (canvas artboards
   3 and 3b).

   Security opened on the Radar: a list that is either empty or overwhelming,
   with no route from "something happened in a session" to "here is the
   session". This screen is that route. Trace a secret is the Radar's. Top to
   bottom it holds:

     1. a hero: protection as the sidebar reads it (protectionState), drawn
        as a ring filled to the security level around that level's shield;
        the agents running right now as dots; and, at its side, main's count
        of exposures still open — the number the sidebar badge and the menu
        bar carry, so the three cannot disagree;
     2. the agents running RIGHT NOW, each with the exposures currently open
        against it — the Ledger's live rail, read for what it means rather
        than what it costs;
     3. recent sessions that had something flagged, each opening to its own
        exposures — plus a quiet line for the sessions that had nothing, which
        is the part that says the quiet is real rather than unmeasured.

   It owns NO list of its own. Everything it shows is a view onto the Radar's
   data, and every "review" route lands there: a second list of exposures,
   with its own filters and its own idea of what is open, is the thing this
   page exists to avoid. */

function OverviewScreen({ state, onGoRadar, onOpenSession }) {
  const live = liveRows(state);
  return (
    <div>
      <OverviewHero state={state} live={live} onGoRadar={onGoRadar} onOpenSession={onOpenSession} />

      {live.length > 0 ? <ActiveSessions state={state} live={live} onGoRadar={onGoRadar} onOpenSession={onOpenSession} /> : null}

      <FlaggedSessions state={state} onGoRadar={onGoRadar} onOpenSession={onOpenSession} />
    </div>
  );
}

/** The live rail rows worth a line: anything not idle, or idle with a session. */
function liveRows(state) {
  return ((state.live && state.live.sessions) || []).filter((r) => r.state !== "idle" || r.session_id);
}

/**
 * The page's answer before any card: is protection on, at what level, who is
 * running, and how much is left to review. The words are the sidebar badge's
 * reading (protectionState, enforcingCount), so they cannot disagree.
 */
function OverviewHero({ state, live, onGoRadar, onOpenSession }) {
  const enforcing = enforcingCount(state);
  const p = protectionState(state, enforcing);
  const held = (state.approvals || []).length;
  // Off, the level is a setting nothing applies — the ring still shows it.
  const title = p.kind === "off" ? p.word : p.word + " · " + (p.level ? p.level.name : "Custom rules");
  const agents = plural(p.guarded, "agent") + " guarded";
  const sub =
    p.kind === "protected"
      ? agents + " · " + enforcing.acting + " of " + enforcing.total + " rules act before a call runs"
      : p.kind === "watch"
        ? agents + " · no rule is set to Ask or Block, so every rule only watches"
        : p.why;
  return (
    <Card className={"ovr-hero " + p.kind}>
      <div className="ovr-hero-row">
        <OvrRing protection={p} held={held} />
        <div className="ovr-hero-said">
          <h2 className="ovr-hero-t">{title}</h2>
          <div className="ovr-hero-sub">{sub}</div>
          <OvrLiveDots state={state} live={live} onOpenSession={onOpenSession} />
        </div>
        <OvrOpenCount state={state} onGoRadar={onGoRadar} />
      </div>
    </Card>
  );
}

/* The ring: one arc per security level, filled up to the one the rules are
   at, in the protection kind's colour, around that level's shield (the one
   Guardrails draws). Custom rules sit at no level, so the ring is drawn whole
   with a full shield and the caption says Custom. */
const OVR_RING_SIZE = 110;
const OVR_RING_R = 49;
const OVR_RING_C = 2 * Math.PI * OVR_RING_R;
const OVR_RING_GAP = 7;

function OvrRing({ protection, held }) {
  const p = protection;
  const n = SECURITY_LEVELS.length;
  const at = p.level ? SECURITY_LEVELS.indexOf(p.level) + 1 : null;
  const seg = OVR_RING_C / n;
  const mid = OVR_RING_SIZE / 2;
  const label =
    p.word +
    " — " +
    (at ? p.level.name + " level, " + at + " of " + n : "custom rules, at no level") +
    (held > 0 ? " — " + plural(held, "call") + " held for your answer" : "");
  return (
    <div className={"ovr-ring " + p.kind + (at ? "" : " custom")} role="img" aria-label={label}>
      <div className="ovr-ring-dial">
        <svg width={OVR_RING_SIZE} height={OVR_RING_SIZE} viewBox={"0 0 " + OVR_RING_SIZE + " " + OVR_RING_SIZE} aria-hidden="true">
          <g transform={"rotate(-90 " + mid + " " + mid + ")"}>
            {SECURITY_LEVELS.map((level, i) => (
              <circle
                key={level.id}
                className={"ovr-ring-seg" + (at == null || i < at ? " on" : "")}
                cx={mid}
                cy={mid}
                r={OVR_RING_R}
                strokeDasharray={seg - OVR_RING_GAP + " " + (OVR_RING_C - seg + OVR_RING_GAP)}
                strokeDashoffset={-(i * seg + OVR_RING_GAP / 2)}
              />
            ))}
          </g>
        </svg>
        <span className="ovr-ring-core">
          <LevelShield step={at ? at - 1 : n - 1} of={n - 1} />
          {held > 0 ? <span className="ovr-ring-held">{held}</span> : null}
        </span>
      </div>
      <span className="ovr-ring-cap">{at ? p.level.name + " · " + at + "/" + n : "Custom"}</span>
    </div>
  );
}

/**
 * One dot per agent running now — the live rail's rows, in the dot colours
 * the Ledger's rail uses. A held session counts down to its hold's deadline
 * (the approval panel's clock: `at` + `hold_seconds`), re-read once a second
 * only while something is held. Each dot opens its session; the held call
 * itself is already answered from the approval overlay.
 */
function OvrLiveDots({ state, live, onOpenSession }) {
  const approvals = state.approvals || [];
  const deadlineOf = (row) => {
    const a = row.state === "held" && row.approval_id ? approvals.find((x) => x.id === row.approval_id) : null;
    return a ? Date.parse(a.at) + (a.hold_seconds || 60) * 1000 : NaN;
  };
  const holding = live.some((row) => Number.isFinite(deadlineOf(row)));
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    if (!holding) return undefined;
    setNow(Date.now());
    const tick = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(tick);
  }, [holding]);

  if (live.length === 0) return <div className="ovr-dots-none muted">No agent running right now</div>;
  return (
    <ul className="ovr-dots" aria-label="Agents running now">
      {live.map((row) => {
        const name = SOURCE_NAMES[row.source] || row.source || "Agent";
        const deadline = deadlineOf(row);
        const word =
          row.state === "held"
            ? "held" + (Number.isFinite(deadline) ? " · " + Math.max(0, Math.round((deadline - now) / 1000)) + "s" : "")
            : row.state === "waiting"
              ? "waiting for you"
              : row.state === "idle"
                ? "quiet"
                : "working";
        const tip = row.title || livePlace(row) || undefined;
        const kids = [
          <span key="d" className={"livedot " + row.state} aria-hidden="true" />,
          <span key="n" className="ovr-dot-n">{name}</span>,
          <span key="s" className="ovr-dot-s">· {word}</span>,
        ];
        return (
          <li key={"dot-" + (row.pid || "") + "-" + (row.session_id || "")}>
            {row.session_id ? (
              <button
                type="button"
                className={"ovr-dot " + row.state}
                data-tip={tip}
                aria-label={name + " · " + word + (row.title ? " — " + row.title : "") + ". Open session"}
                onClick={() => onOpenSession(row.session_id)}
              >
                {kids}
              </button>
            ) : (
              <span className={"ovr-dot " + row.state} data-tip={tip}>
                {kids}
              </span>
            )}
          </li>
        );
      })}
    </ul>
  );
}

/** Main's count of exposures still open — over all time, the sidebar badge's
    number — as the hero's way to the Radar. */
function OvrOpenCount({ state, onGoRadar }) {
  const summary = (state.radar && state.radar.summary) || {};
  const open =
    summary.open_exposures != null ? summary.open_exposures : summary.open_groups != null ? summary.open_groups : 0;
  return (
    <button type="button" className={"ovr-count" + (open > 0 ? " hot" : " live")} onClick={() => onGoRadar({})}>
      <b>{open}</b>{" "}
      <span className="ovr-count-lab">
        {open === 1 ? "exposure" : "exposures"} open to review
        <span className="ovr-count-go" aria-hidden="true">→</span>
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

function ActiveSessions({ state, live, onGoRadar, onOpenSession }) {
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
    <Card title="Active sessions" hint={line || undefined}>
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
        <div className="cardnote lead">
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
            See the other {flagged.length - SHOWN} flagged session{flagged.length - SHOWN === 1 ? "" : "s"} on the Radar →
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
          <div className="cardnote lead">
            and {group.findings.length - 6} more in this session
          </div>
        ) : null}
        <div className="row" style={{ marginTop: "var(--s4)" }}>
          {/* THIS session's exposures, not the whole feed: the Radar arrives
              narrowed to the session, with the filter chip to widen it. */}
          <button className="btn" onClick={() => onGoRadar({ session_id: group.id })}>
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
