/* Integrations — the local rails as a health board: what feeds this app
   (transcript trees), and what enforces (the PreToolUse guard). Presence,
   freshness and totals all come from the capture engine. */

function IntegrationsScreen({ state, onGoRules }) {
  const cap = state.capture;

  return (
    <div>
      <div className="screen-head">
        <h1>Integrations</h1>
      </div>

      <SetupHealthCard doctor={state.doctor} />

      <CoverageCard state={state} onGoRules={onGoRules} />

      {surfaceShown("editor_extension") ? <EditorExtensionCard state={state} /> : null}

      {/* Hidden with its rule family: with the MCP rules out of
          scope the card had no action to offer and a green dot on every
          server nobody had reviewed. It comes back when the family does. */}
      {mcpFamilyShown() ? <McpInventoryCard mcp={state.mcp} state={state} /> : null}

      {/* Enforcement has NO card here: the guard's switches live once, in
          Guardrails → Protection, so there is one switch and one error path. */}
    </div>
  );
}

/**
 * Setup health — the setup doctor's report (main/lib/doctor.ts): is every
 * piece of wiring this app depends on — the guard's hook entries, its bundle,
 * the hook documents it writes into, the VS Code settings it relies on —
 * actually in a working state?
 *
 * The card answers in one line when everything is fine, and opens up the
 * moment anything isn't:
 * one row per check, grouped by host, each saying what is wrong and what
 * fixes it. Three kinds of right-hand side, and the distinction is the whole
 * UX: a **Fix** button for a lossless repair (the same repair the app applies
 * on its own at boot / on file change — offered here for when it stood down,
 * or when someone wants to see it happen); a two-click **Restore** for the ONE
 * lossy repair (replacing an unreadable JSON document with its backup — the
 * app never does that unasked); and plain text for what only a person can do
 * (a VS Code setting, an admin policy). "Repair all" is the lossless set
 * only.
 */
/* Every `DoctorHost` (main/lib/doctor.ts) must be listed: a row whose host is
   missing here is counted in the headline ("1 warning") and then filtered out
   of the body — which is how the VS Code rows went unseen from 2026-09-11 to
   2026-09-21. test/vscode.test.ts holds the list to the type. */
const DOCTOR_HOSTS = [
  ["vscode", "VS Code"],
  ["guard", "Guardrails"],
];

function doctorDot(status) {
  return status === "ok" ? "on" : status === "fail" ? "bad" : status === "warn" ? "warn" : "off";
}

function DoctorRow({ check, busy, paused }) {
  // The lossy restore earns the product's two-click inline confirm: the first
  // click says what it will do, the second does it.
  const [confirm, setConfirm] = useState(false);
  const lossy = check.fix === "restore-json";
  const fixable = !!check.fix && (check.auto || lossy || paused);
  return (
    <div className="setting">
      <div className="what">
        <div className="t">
          <span className={"dot " + doctorDot(check.status)} aria-hidden="true" /> {check.title}
        </div>
        <div className="d">
          {check.detail}
          {check.manual ? <span className="muted"> → {check.manual}</span> : null}
          {paused ? <span className="muted"> → Automatic repair paused (it kept being undone); press Fix to try again.</span> : null}
        </div>
      </div>
      {check.status === "ok" ? (
        <span className="chip good">ok</span>
      ) : check.status === "skip" ? (
        <span className="chip">—</span>
      ) : fixable ? (
        <button
          className={"btn" + (check.status === "fail" ? " primary" : "")}
          disabled={busy}
          onBlur={() => setConfirm(false)}
          onClick={() => {
            if (lossy && !confirm) {
              setConfirm(true);
              return;
            }
            setConfirm(false);
            window.doorman.doctorRepair(check.id);
          }}
        >
          {lossy ? (confirm ? "Really restore? The broken file is kept." : "Restore from backup") : "Fix"}
        </button>
      ) : (
        <span className={"chip" + (check.status === "fail" ? " bad" : "")}>
          {check.status === "fail" ? "needs you" : "warning"}
        </span>
      )}
    </div>
  );
}

/** A check that wants nothing from anyone — folded away while something else
    on the board does. `skip` counts as passing: it is "not applicable here". */
function passing(check) {
  return check.status === "ok" || check.status === "skip";
}

function SetupHealthCard({ doctor }) {
  // Tolerate a main process that predates the doctor (an unrebuilt build/main).
  const d = doctor || { status: "idle" };
  const report = d.report;
  const busy = d.status !== "idle";
  const paused = d.paused || [];
  const checks = report ? report.checks : [];
  const problems = checks.filter((c) => c.status === "fail" || c.status === "warn");
  const healthy = !!report && problems.length === 0;
  // What "Repair all" would do: every lossless fix still outstanding.
  const repairable = problems.filter((c) => c.fix && c.fix !== "restore-json");
  const hint = !report
    ? busy
      ? "Checking…"
      : "Not checked yet"
    : report.headline + (d.last_run_at ? " · checked " + relTime(d.last_run_at) : "");
  const lastRepairFailed = d.last_repair && d.last_repair.failed && d.last_repair.failed.length > 0;

  /* WHAT NEEDS ATTENTION, AND ONLY THAT (2026-09-06). The card used to offer a
     "Check now" button, a fold that listed every passing row, and a
     "N checks passed, including all of Codex" line — confirmed information
     nobody asked for, next to a button for a check that already runs at start,
     on every change to a hook file, and every 30 minutes. Now: healthy is one
     line; unhealthy is the failing rows, grouped by host, each saying what is
     wrong and what fixes it, with Repair all when the fixes are lossless. */
  return (
    <Card
      title="Setup health"
      hint={hint}
      right={
        repairable.length > 0 ? (
          <button className="btn primary" disabled={busy} onClick={() => window.doorman.doctorRepair()}>
            {d.status === "repairing" ? "Repairing…" : "Repair all"}
          </button>
        ) : null
      }
    >
      {!report ? (
        <div className="empty">{busy ? "Checking the guard wiring…" : "The setup doctor hasn't run yet."}</div>
      ) : healthy ? (
        <div className="setting">
          <div className="what">
            <div className="t">
              <span className="dot on" aria-hidden="true" />{" "}
              The guard and editor wiring all check out
            </div>
            <div className="d">
              Re-checked at start, on every change to a hook file, and every 30 minutes.
            </div>
          </div>
        </div>
      ) : (
        DOCTOR_HOSTS.map(([host, label]) => {
          const rows = checks.filter((c) => c.host === host && !passing(c));
          if (rows.length === 0) return null;
          return (
            <React.Fragment key={host}>
              <div className="health-host">{label}</div>
              {rows.map((c) => (
                <DoctorRow key={c.id} check={c} busy={busy} paused={paused.includes(c.id)} />
              ))}
            </React.Fragment>
          );
        })
      )}
      {/* A repair that did not take is news; one that did is not. */}
      {lastRepairFailed ? (
        <div className="faint health-log" style={{ marginTop: "var(--s3)", fontSize: "var(--t-2)" }}>
          {"Last repair " + relTime(d.last_repair.at) + "\n" +
            d.last_repair.applied.map((a) => "✓ " + a).concat(d.last_repair.failed.map((f) => "✗ " + f)).join("\n")}
        </div>
      ) : null}
    </Card>
  );
}

/**
 * AI on this Mac — the coverage map. One list of every AI tool found on this
 * machine, grouped by what Doorman does for it RIGHT NOW:
 *   Covered          captured (transcripts read), guarded (tool calls held
 *                    before they run), or both — the row says which;
 *   One switch away  the guard has an adapter for it and is not wired in —
 *                    the group label carries the ONE control that covers all
 *                    of them, never a button per tool;
 *   Not guarded      a disclosure, closed by default, with two subtitles:
 *                    Watch only (transcripts read, tool calls unchecked —
 *                    with the same Wire in as above) and Identified (found,
 *                    but Doorman has no way in — no guard adapter and
 *                    nothing readable on disk; nothing to accept or dismiss);
 *   Not detected     how many of the catalog were looked for and not found —
 *                    a count, because the catalog is long enough that listing
 *                    them would bury the real rows, expanding to the full list
 *                    with a search over it for "did it look for MY tool?".
 * The strip above the groups legends them (dot colour = group). Local
 * filesystem scan of each tool's own folders, no network. The captured rails'
 * numbers sit on their own rows; the turn store behind them has no row of its
 * own (its count and the manual rescan were removed from the display).
 */
const SHADOW_KIND_LABELS = {
  "agent-cli": "agent CLI",
  "desktop-app": "desktop app",
  editor: "editor",
  "local-model": "local model",
  browser: "browser",
  productivity: "productivity",
};

/** The same six kinds as a group heading — plural, because the heading names a
 * set. Kept beside the singular labels so a new kind cannot get one and not
 * the other (`test/renderer-screens.test.ts` fails if it does). */
const SHADOW_KIND_PLURALS = {
  "agent-cli": "agent CLIs",
  "desktop-app": "desktop apps",
  editor: "editors",
  "local-model": "local models",
  browser: "browsers",
  productivity: "productivity",
};

/** Heading order for the not-detected groups: the two kinds a developer is
 * most likely to be looking for first, then the rest. Fixed rather than
 * alphabetical or catalog order, so the list does not reshuffle as the
 * catalog grows. A kind missing from here sorts last, in catalog order. */
const SHADOW_KIND_ORDER = ["agent-cli", "editor", "desktop-app", "local-model", "browser", "productivity"];

/** The capture engine's per-source stat for a captured rail. The shadow-AI
 * catalog ids and the ledger's TurnSource ids are deliberately the SAME strings
 * (`claude-code`, `codex`, `cursor`, `gemini-cli`, `copilot-cli`), so this is a
 * direct lookup rather than a translation table that has to grow per host. A
 * catalog row whose id names no rail simply has no stat. */
/** The not-detected search, over a tool's NAME and its kind label — the two
 * things the row shows, so nothing matches invisibly. An empty query is not a
 * filter. `elsewhere` is the second answer the search has to give: a query
 * naming a tool that IS installed belongs in a sentence ("Cursor is on this
 * Mac — listed above"), not in an empty result that reads as "never looked". */
function searchCatalog(missing, installed, query) {
  const q = String(query || "").trim().toLowerCase();
  const hits = (t) =>
    !q ||
    String(t.name || "").toLowerCase().includes(q) ||
    String(SHADOW_KIND_LABELS[t.kind] || t.kind || "").toLowerCase().includes(q) ||
    String(SHADOW_KIND_PLURALS[t.kind] || "").toLowerCase().includes(q);
  return { shown: missing.filter(hits), elsewhere: q ? installed.filter(hits) : [] };
}

/**
 * The not-detected list, cut into its kind groups in `SHADOW_KIND_ORDER`.
 * Empty groups are dropped, so the headings describe what is actually below
 * them and a filtered list never shows a heading with nothing under it.
 */
function groupByKind(tools) {
  const byKind = new Map();
  for (const t of tools) {
    const kind = t.kind || "other";
    if (!byKind.has(kind)) byKind.set(kind, []);
    byKind.get(kind).push(t);
  }
  const rank = (k) => {
    const i = SHADOW_KIND_ORDER.indexOf(k);
    return i < 0 ? SHADOW_KIND_ORDER.length : i;
  };
  return [...byKind.entries()]
    .sort((a, b) => rank(a[0]) - rank(b[0]))
    .map(([kind, items]) => ({ kind, label: SHADOW_KIND_PLURALS[kind] || kind, items }));
}

/**
 * The kind chips over the not-detected list: `All 19 · agent CLIs 6 · …`,
 * counted over the SEARCHED set so the numbers move with the query rather
 * than describing a list nobody is looking at. `DotChips` disables a chip
 * whose count is 0, so a query narrows the strip instead of offering filters
 * that lead nowhere; no dots, because every tool here is in the same state
 * and a colour per kind would invent a meaning this card does not have.
 *
 * The selected kind is validated against the current counts rather than reset
 * by an effect: type past your own filter and the list falls back to All, and
 * clearing the query restores it, with no state to get out of step.
 */
function kindChips(shown) {
  const counts = new Map();
  for (const t of shown) counts.set(t.kind, (counts.get(t.kind) || 0) + 1);
  const options = [{ key: "all", label: "All", count: shown.length }];
  for (const kind of SHADOW_KIND_ORDER) {
    if (!counts.has(kind)) continue;
    options.push({ key: kind, label: SHADOW_KIND_PLURALS[kind] || kind, count: counts.get(kind) });
  }
  return { options, counts };
}

const captureStatFor = (capture, toolId) =>
  (capture && capture.sources ? capture.sources[toolId] : null) ||
  /* ...or an app whose sessions a RAIL carried rather than a rail of its
     own — ChatGPT Desktop's Codex mode, split out of the Codex totals
     under its catalog id so the same turns are never counted twice. */
  (capture && capture.apps ? capture.apps[toolId] : null) ||
  null;

function CoverageCard({ state, onGoRules }) {
  const cap = state.capture;
  const guardInstalled = !!state.radar.guard_installed;
  const [wiring, setWiring] = useState(false);
  // The same call the Settings switch makes: installs the guard into every
  // host on this Mac (idempotent, so one button covers the whole group).
  const wireIn = () => {
    setWiring(true);
    window.doorman.installGuard().finally(() => setWiring(false));
  };
  // Tolerate a main process that predates these fields: render an empty map,
  // never white-screen the page.
  const s = state.shadow_ai || {};
  const tools = s.tools || [];
  const installed = tools.filter((t) => t.installed);
  // Observation and prevention are two facts, shown apart (review F5):
  // `guarded` means tool calls are held before they run; `captured` means
  // transcripts are read. A metered rail with no hook is NOT "covered" here —
  // it is listed as metered only, with the same Wire in as any other gap.
  const guarded = installed.filter((t) => t.guarded);
  const meteredOnly = installed.filter((t) => !t.guarded && t.captured);
  const oneSwitch = installed.filter((t) => !t.guarded && !t.captured && t.guardable);
  const soon = installed.filter((t) => !t.guarded && !t.captured && !t.guardable);
  // Every unguarded row an adapter exists for — what the Wire in button reaches.
  const wireable = installed.filter((t) => !t.guarded && t.guardable);
  const missing = tools.filter((t) => !t.installed);
  // The not-detected list is a disclosure with its own search: the question is
  // "did it look for X?", and typing four letters answers it in one step,
  // whether or not X turns out to be installed.
  const [missingQuery, setMissingQuery] = useState("");
  const [missingKind, setMissingKind] = useState("all");
  const { shown: searchedMissing, elsewhere: foundInstead } = searchCatalog(missing, installed, missingQuery);
  // Chips count the SEARCHED set; the kind then narrows it. A kind the current
  // search has emptied is not honoured — see kindChips.
  const { options: kindOptions, counts: kindCounts } = kindChips(searchedMissing);
  const activeKind = missingKind !== "all" && kindCounts.get(missingKind) ? missingKind : "all";
  const shownMissing =
    activeKind === "all" ? searchedMissing : searchedMissing.filter((t) => t.kind === activeKind);
  const missingGroups = groupByKind(shownMissing);
  const hint =
    installed.length === 0
      ? "No AI tools detected"
      : guarded.length + " of " + installed.length + " detected tool" + (installed.length === 1 ? "" : "s") + " guarded" +
        (meteredOnly.length > 0 ? " · " + meteredOnly.length + " watch only" : "");

  const plural = (n, one) => n.toLocaleString("en-US") + " " + one + (n === 1 ? "" : "s");

  // One explanation per group: when every row of a group carries the same
  // note, it is said once under the group label and the rows keep only what
  // differs between them.
  const sharedNote = (list) =>
    list.length > 0 && list[0].note && list.every((t) => t.note === list[0].note) ? list[0].note : null;
  const guardedNote = sharedNote(guarded);

  const row = (t, dotClass, groupNote) => {
    const stat = t.captured ? captureStatFor(cap, t.id) : null;
    const parts = [];
    if (t.note && t.note !== groupNote) parts.push(t.note);
    if (stat && stat.turns > 0) {
      parts.push(
        plural(stat.sessions, "session") +
          " · " +
          plural(stat.turns, "turn") +
          " · " +
          /* A rail with turns but no tokens is UNMETERED, not idle —
             several of the hosts read through the transcript-source
             registry report no token counts at all, and "0 tokens"
             would read as "nothing ran" rather than "we don't know". */
          (stat.tokens > 0 ? fmtTokens(stat.tokens) + " tokens" : "tokens not reported"),
      );
    }
    if (stat && stat.last_at) parts.push("last activity " + relTime(stat.last_at));
    else if (t.last_active_at) parts.push("active " + relTime(t.last_active_at));
    return (
      <div className="setting" key={t.id}>
        <div className="what">
          <div className="t">
            <span className={"dot " + dotClass} aria-hidden="true" />
            {/* The tool's own mark, where one exists — a list of 40 names is
                scanned, and the logo is what the eye finds first. The state
                stays on the dot beside it, because a logo cannot say
                "covered". */}
            <ToolMark tool={t.id} /> {t.name}
            <span className="cover-meta" style={{ fontWeight: 400 }}> · {SHADOW_KIND_LABELS[t.kind] || t.kind}</span>
          </div>
          {parts.length > 0 ? <div className="d cover-meta">{parts.join(" · ")}</div> : null}
        </div>
        {/* No chip. The group label says Covered, the dot says it in colour and
            the note says how — a green "watching" pill on top was a fourth copy
            of one fact. */}
      </div>
    );
  };

  return (
    <Card
      title="AI on this computer"
      hint={hint}
      section="coverage"
    >
      <div className="cover-strip" role="list" aria-label="Coverage summary">
        <span className="mode-chip covered" role="listitem"><span className="dot" aria-hidden="true" /><b>{guarded.length}</b> guarded</span>
        {meteredOnly.length > 0 ? (
          <span className="mode-chip watch" role="listitem"><span className="dot" aria-hidden="true" /><b>{meteredOnly.length}</b> watch only</span>
        ) : null}
        {oneSwitch.length > 0 ? (
          <span className="mode-chip act" role="listitem"><span className="dot" aria-hidden="true" /><b>{oneSwitch.length}</b> one switch away</span>
        ) : null}
        {soon.length > 0 ? (
          <span className="mode-chip soon" role="listitem"><span className="dot" aria-hidden="true" /><b>{soon.length}</b> identified</span>
        ) : null}
      </div>
      <div className="cardnote lead">
        Every AI tool found on this computer and what Doorman does for it right now — guarded means risky
        tool calls are held before they run; metered means sessions and token usage are read. A local scan
        of each tool's own folders — nothing leaves this computer.
      </div>

      {guarded.length > 0 ? (
        <>
          <div className="cover-group"><span className="lab">Guarded</span></div>
          {guardedNote ? (
            <div className="cardnote" style={{ marginTop: "var(--s2)" }}>{guardedNote}</div>
          ) : null}
          {guarded.map((t) => row(t, "on", guardedNote))}
        </>
      ) : null}

      {oneSwitch.length > 0 ? (
        <>
          <div className="cover-group">
            <span className="lab">One switch away</span>
            {/* Two different asks. With the guard OFF, switching it on is a
                decision with consequences beyond this card (hold window,
                auto-deny, every agent on the Mac), so this is a LINK to the
                switch on Guardrails → Real-time protection, where those live —
                not a button that flips it from an inventory screen. With the
                guard ON but not in these hosts yet, "Wire in" is a repair:
                the decision was made, this just finishes it. */}
            {guardInstalled ? (
              <button
                className="btn primary"
                disabled={wiring}
                title={"Install the guard's hook into " + oneSwitch.map((t) => t.name).join(", ")}
                onClick={wireIn}
              >
                {wiring ? "Wiring in…" : "Wire in"}
              </button>
            ) : (
              <button
                className="linkbtn"
                title="The switch lives on Guardrails, with the hold window and what happens when nobody answers"
                onClick={() => onGoRules && onGoRules()}
              >
                Turn on real-time protection →
              </button>
            )}
          </div>
          <div className="cardnote" style={{ marginTop: "var(--s2)" }}>
            {guardInstalled
              ? "Guardrails are on but not wired into these yet."
              : "Guardrails are off. One switch wires them into every tool below — and into Claude Code and Codex."}
            {" Restart the tool afterwards so it loads the hook."}
          </div>
          {oneSwitch.map((t) => row(t, "act"))}
        </>
      ) : null}

      {meteredOnly.length + soon.length > 0 ? (
        // Everything installed that the guard does not hold, in one
        // disclosure, closed by default: the tools that are only watched
        // (transcripts read, tool calls unchecked) and the ones only
        // identified (found, no way in). Each keeps its own subtitle.
        <Advanced label={"Not guarded (" + (meteredOnly.length + soon.length) + ")"}>
          {meteredOnly.length > 0 ? (
            <>
              <div className="cover-group">
                <span className="lab">Watch only</span>
                {/* The same two asks as "One switch away" above, for the rails whose
                    transcripts are read but whose tool calls nothing holds. */}
                {wireable.some((t) => t.captured) ? (
                  guardInstalled ? (
                    <button
                      className="btn primary"
                      disabled={wiring}
                      title={"Install the guard's hook into " + wireable.filter((t) => t.captured).map((t) => t.name).join(", ")}
                      onClick={wireIn}
                    >
                      {wiring ? "Wiring in…" : "Wire in"}
                    </button>
                  ) : (
                    <button
                      className="linkbtn"
                      title="The switch lives on Guardrails"
                      onClick={() => onGoRules && onGoRules()}
                    >
                      Turn on real-time protection →
                    </button>
                  )
                ) : null}
              </div>
              <div className="cardnote" style={{ marginTop: "var(--s2)" }}>
                Sessions and token usage from these land in the ledger; their tool calls are not guarded.
              </div>
              {meteredOnly.map((t) => row(t, "watch"))}
            </>
          ) : null}
          {soon.length > 0 ? (
            <>
              <div className="cover-group"><span className="lab">Identified</span></div>
              <div className="cardnote" style={{ marginTop: "var(--s2)" }}>
                Doorman found these but has no way into them — the guard has no adapter and they write
                nothing it can read. They stay in the inventory so you know they are here; nothing to
                accept or dismiss.
              </div>
              {soon.map((t) => row(t, "soon"))}
            </>
          ) : null}
        </Advanced>
      ) : null}

      {missing.length > 0 ? (
        // The catalog is long enough that naming every absent tool would bury
        // the rows above it, so the count is the headline — but a count alone
        // cannot answer the question people actually bring here ("did it look
        // for MY tool?"), and the names were hover-only, which is unreachable
        // without a mouse. So: a disclosure holding the whole list, with a
        // search over it, because 30-odd names is a scan and one typed word
        // is not.
        <Advanced label={"Not detected (" + missing.length + ")"}>
          <div className="cardnote lead">
            Doorman looked for these AI tools but didn't find them on this computer.
          </div>
          <div className="cover-none-body">
            <div className="cover-none-tools">
              <SearchBox
                value={missingQuery}
                onChange={(e) => setMissingQuery(e.target.value)}
                placeholder="Search the catalog — Cline, Ollama, Raycast…"
              />
              {/* Two chips is a filter; one is a label of the obvious. */}
              {kindOptions.length > 2 ? (
                <DotChips
                  value={activeKind}
                  options={kindOptions}
                  onPick={setMissingKind}
                  ariaLabel="Filter the not-detected list by kind"
                />
              ) : null}
            </div>
            {/* A search that matches a tool which IS here answers the question
                rather than showing an empty list: the row is above, and saying
                so is cheaper than repeating it. */}
            {foundInstead.length > 0 ? (
              <div className="cardnote" style={{ marginTop: "var(--s3)" }}>
                {foundInstead.map((t) => t.name).join(", ")}
                {foundInstead.length === 1 ? " is" : " are"} on this computer — listed above.
              </div>
            ) : null}
            {/* Grouped by kind, so ~30 names read as six short lists instead of
                one long one — and the kind stops being a word repeated down
                every row to say what a heading says once. */}
            {missingGroups.length > 0 ? (
              <div className="cover-none-groups">
                {missingGroups.map((g) => (
                  <section key={g.kind} className="cover-none-group">
                    <div className="cover-group">
                      <span className="lab">{g.label}</span>
                      <span className="cover-meta">{g.items.length}</span>
                    </div>
                    <ul className="cover-none-list">
                      {g.items.map((t) => (
                        <li key={t.id}>
                          <span className="dot" aria-hidden="true" />
                          {/* The mark's slot is held open whether or not the
                              tool has one — seven of these have no honest logo,
                              and letting their names slide left would make the
                              column read as two ragged lists. */}
                          <span className="cover-none-mark">
                            <ToolMark tool={t.id} size={13} />
                          </span>
                          <span className="n">{t.name}</span>
                        </li>
                      ))}
                    </ul>
                  </section>
                ))}
              </div>
            ) : foundInstead.length === 0 ? (
              <div className="cardnote" style={{ marginTop: "var(--s3)" }}>
                Nothing in the catalog matches that. Doorman can only look for a tool it has a path
                for — an app bundle or the tool's own folder.
              </div>
            ) : null}
          </div>
        </Advanced>
      ) : null}

    </Card>
  );
}

/* The VS Code companion extension (main/vscode-ext-install.ts): one switch that
   installs Doorman into the editor through its own `code --install-extension`,
   so today's tokens, the guard's state and a held tool call show up where the
   person is already working — and the window's own report of whether the
   guard can run there. On by default. Lives HERE because it is the wiring of
   one more program into the app, not a preference about the app itself; the
   extension's README sends people to Integrations for it. The line under the
   switch names each build found and what it has —
   including a build whose command line is missing, which is the one case the
   app cannot fix for them. */
function EditorExtensionCard({ state }) {
  const prefs = state.prefs || {};
  const ext = state.editor_extension || { enabled: false, hosts: [] };
  const on = prefs.vscode_extension === true;
  const hosts = ext.hosts || [];
  const installed = hosts.filter((h) => h.installed).length;
  const drivable = hosts.filter((h) => !h.cliMissing).length;
  const setPref = (patch) => window.doorman.setPrefs(patch);
  const hostLine = (h) =>
    h.label + (h.cliMissing ? " — no `code` command line, install it from the Extensions view" : h.installed ? " — " + h.installed : " — not installed");
  return (
    <Card
      title="Doorman in VS Code"
      hint={on && drivable ? installed + " of " + drivable + " installed" : undefined}
      section="vscode"
    >
      {ext.error ? (
        <div className="callout bad" style={{ marginBottom: "var(--s4)" }}>
          Couldn't update the extension: {ext.error}
        </div>
      ) : null}
      <div className="setting">
        <div className="what">
          <div className="t">Show Doorman in the editor</div>
          <div className="d">
            Installs the Doorman extension into VS Code. Today's tokens and the Security Guard's
            state sit in the status bar, when the guard holds an agent's tool call you can answer it
            there instead of switching apps, and each open window tells this app whether the guard
            can run in it. It reads only this app's own files — nothing from your code, and nothing
            over the network.
          </div>
          {on && hosts.length ? <div className="d">{hosts.map(hostLine).join(" · ")}</div> : null}
          {on && !hosts.length ? <div className="d">No VS Code build found on this computer.</div> : null}
        </div>
        <Switch ariaLabel="Show Doorman in the editor" on={on} onChange={(v) => setPref({ vscode_extension: v })} />
      </div>
    </Card>
  );
}

/**
 * MCP server inventory — every MCP server this machine configures or has used,
 * with a shipped risk profile, the open poisoning findings against it, and a
 * personal "I recognize this" toggle that feeds the unknown-server radar rule.
 */
const MCP_PERMISSION_LABELS = { read: "read", write: "write", act: "act" };
const MCP_PERMISSION_HINTS = {
  read: "Tools the server marks read-only, or whose names read like a read (get, list, search…).",
  write: "Tools that change the server's own data — the default class for anything unmarked.",
  act: "Tools that reach outward or destroy (send, deploy, delete, pay…), or that the server marks destructive / open-world.",
};

/** The three-way permission control for one gatewayed server: read / write /
    act, each allow / ask / block. Allow is the default and the gateway forwards
    everything until a class is raised — so an untouched row means "unchanged". */
function McpPermissions({ row }) {
  const perms = row.permissions || {};
  return (
    <div className="mcp-perms" role="group" aria-label={"Gateway permissions for " + row.name}>
      {["read", "write", "act"].map((cls) => {
        const value = perms[cls] || "allow";
        return (
          <label key={cls} className="mcp-perm" title={MCP_PERMISSION_HINTS[cls]}>
            <span className="k">{MCP_PERMISSION_LABELS[cls]}</span>
            <select value={value} onChange={(e) => window.doorman.setMcpPermission(row.name, cls, e.target.value)}>
              <option value="allow">allow</option>
              <option value="ask">ask</option>
              <option value="block">block</option>
            </select>
          </label>
        );
      })}
    </div>
  );
}

/**
 * One MCP server, as a decision rather than a dashboard.
 *
 * The row is three things and nothing else: the dot (red = open poisoning,
 * amber = needs a look, green = trusted), one sentence under the name with the
 * worst fact first, and ONE control. A server that still needs a decision
 * offers "Recognize", and a local stdio server "Route through gateway". A
 * trusted server shows no control at all. What a
 * gatewayed server is allowed to do (read / write / act) stays inline, because
 * that IS a setting, not a fact.
 *
 * Deliberately absent: a per-row "Details" disclosure and "Recognize without
 * a review" — controls that would ask the person to understand the machinery
 * before the machinery had told them anything.
 */
function McpServerRow({ row }) {
  // The trust review — poisoning, "recognized by you", the unapproved-server
  // flag, a description that changed since — IS the MCP-servers rule family.
  // With that family hidden the row keeps the facts that are not a
  // rule's verdict: where the server lives, how much it is used, and what a
  // gatewayed one may do.
  const review = ruleShown("unknown_mcp_server") || ruleShown("mcp_tool_poisoning") || ruleShown("mcp_tool_changed");
  const trusted = row.recognized && !row.recognized_stale;
  const needsDecision = review && (row.poison_open > 0 || row.recognized_stale || !trusted);
  const risk = row.risk;
  const observed = row.observed_tools || [];
  const classes = observed.reduce((acc, t) => { acc[t.cls] = (acc[t.cls] || 0) + 1; return acc; }, {});
  const stdioConfig = (row.configs || []).find((c) => c.transport === "stdio");
  const plural = (n, one) => n.toLocaleString("en-US") + " " + one + (n === 1 ? "" : "s");

  const dot = !review ? "on" : row.poison_open > 0 ? "bad" : trusted ? "on" : "warn";
  // Worst fact first, then trust, then where it lives, then how much it is used.
  const facts = [];
  if (review && row.poison_open > 0) facts.push({ text: plural(row.poison_open, "open poisoning finding"), cls: "bad" });
  if (review && row.recognized_stale) facts.push({ text: "a tool description changed since you recognized it", cls: "bad" });
  if (review && row.changed_tools > 0) {
    facts.push({ text: plural(row.changed_tools, "tool description") + " changed after first sight" + (row.last_changed_at ? " (" + relTime(row.last_changed_at) + ")" : ""), cls: "bad" });
  }
  if (review) {
    if (trusted) facts.push({ text: "recognized by you" });
    else if (row.poison_open === 0 && !row.recognized_stale) facts.push({ text: "not reviewed yet" });
  }
  if (row.configs && row.configs.length > 0) {
    // Named by path, so "user stdio config" is a file you can open, not a category.
    facts.push({
      text: "in " + row.configs.map((c) => c.scope + " " + c.transport + " config" + (c.path ? " (" + shortPath(c.path) + ")" : "")).join(" and "),
    });
  } else if (row.observed_only) {
    facts.push({ text: "seen in transcripts only, not in any config" });
  }
  if (review && row.unknown_open > 0) facts.push({ text: "flagged by the unapproved-server rule" });
  if (row.gatewayed) {
    facts.push({
      text:
        observed.length > 0
          ? "routed through the gateway · " + observed.length + " tools seen live (" + ["read", "write", "act"].filter((c) => classes[c]).map((c) => classes[c] + " " + c).join(", ") + ")"
          : "routed through the gateway",
    });
  }
  facts.push({
    text:
      row.calls > 0
        ? plural(row.calls, "call") + " in " + plural(row.sessions, "session") + (row.last_used_at ? " · last " + relTime(row.last_used_at) : "")
        : "no calls captured",
    cls: "muted",
  });

  return (
    <div className="setting mcp-row">
      <div className="what">
        <div className="t">
          <span className={"dot " + dot} aria-hidden="true" />
          <span className="mono">{row.name}</span>
          {risk ? <span className="muted" style={{ fontWeight: 400 }}> · {risk.vendor} {risk.kind}</span> : null}
        </div>
        <div className="d">
          {risk ? risk.note : "No risk profile — nothing is known about this server yet."}
          {facts.map((f, i) => (
            <span key={i} className={f.cls || undefined}>{" · " + f.text}</span>
          ))}
        </div>
        {/* WHAT changed in a tool's description, tool by tool — the sentence
            the gateway wrote when it saw the new text. "3 descriptions changed"
            is a count; this is the evidence a re-recognition is judged on. */}
        {review && observed.some((t) => t.change_note) ? (
          <div className="d mcp-changes">
            {observed.filter((t) => t.change_note).slice(0, 3).map((t) => (
              <div key={t.name} className="mono">
                <span className="bad">{t.name}</span>
                <span className="muted">{" — " + t.change_note}</span>
              </div>
            ))}
            {observed.filter((t) => t.change_note).length > 3 ? (
              <div className="muted">+{observed.filter((t) => t.change_note).length - 3} more changed</div>
            ) : null}
          </div>
        ) : null}
        {/* What a gatewayed server may do — the one per-server SETTING, so it
            stays in the row rather than behind a review. */}
        {row.gatewayed ? <McpPermissions row={row} /> : null}
      </div>
      <div className="row mcp-actions" style={{ gap: "var(--s3)" }}>
        {needsDecision ? (
          <React.Fragment>
            {stdioConfig && !row.gatewayed ? (
              <button
                className="linkbtn"
                title="Route this server through the Doorman gateway to scan its live tool descriptions and hold or block its calls"
                onClick={() => window.doorman.routeMcpServer(row.name, stdioConfig.path, true)}
              >
                Route through gateway
              </button>
            ) : null}
              <button
                className="btn primary"
                title="Add this server to the approved list the unapproved-server rule reads"
                onClick={() => window.doorman.recognizeMcpServer(row.name, true)}
              >
                {row.recognized_stale ? "Recognize again" : "Recognize"}
              </button>
            </React.Fragment>
        ) : null}
      </div>
    </div>
  );
}

/** Whether any MCP-servers rule is in scope (guard/rule-scope.ts via the
 * renderer mirror) — what decides whether the MCP servers card exists. */
function mcpFamilyShown() {
  return ruleShown("unknown_mcp_server") || ruleShown("mcp_tool_poisoning") || ruleShown("mcp_tool_changed") || ruleShown("mcp_permission");
}

function McpInventoryCard({ mcp, state }) {
  const [showAll, setShowAll] = useState(false);
  // Same tolerance as ShadowAiCard: an unrebuilt main omits state.mcp.
  const servers = (mcp || {}).servers || [];
  const CAP = 6;
  const shown = showAll ? servers : servers.slice(0, CAP);
  const poisoned = servers.filter((s) => s.poison_open > 0).length;
  const stale = (mcp || {}).stale_recognitions || 0;
  const unreviewed = servers.filter((s) => !s.recognized && s.poison_open === 0).length;
  // With the MCP-servers rule family hidden there is no review to
  // summarize — the card counts servers and stops.
  const review = ruleShown("unknown_mcp_server") || ruleShown("mcp_tool_poisoning") || ruleShown("mcp_tool_changed");
  const hint =
    servers.length === 0
      ? "None configured or seen"
      : !review
        ? servers.length + " configured or seen"
      : poisoned > 0
        ? poisoned + " with open poisoning findings"
        : stale > 0
          ? stale + " changed since you recognized " + (stale === 1 ? "it" : "them")
          : unreviewed > 0
            ? unreviewed + " unreviewed"
            : "all reviewed";

  return (
    <Card title="MCP servers" hint={hint} section="mcp">
      <div className="cardnote lead">
        {review
          ? "Every MCP server this computer's agents can call — from their configs and from transcripts. Review one with " +
            "Doorman AI; recognizing it, or routing it through the gateway, is a click under the answer. A recognized " +
            "server stops raising the unapproved-server rule."
          : "Every MCP server this computer's agents can call — from their configs and from transcripts. Route a local " +
            "server through the gateway to scan its live tool descriptions and hold or block its calls."}
      </div>
      {servers.length === 0 ? (
        <div className="empty">No MCP servers found on this machine.</div>
      ) : (
        <React.Fragment>
          {shown.map((s) => (
            <McpServerRow key={s.name} row={s} />
          ))}
          {servers.length > CAP ? (
            <button className="btn loadmore" onClick={() => setShowAll(!showAll)}>
              {showAll ? "Show fewer" : "Show " + (servers.length - CAP) + " more"}
            </button>
          ) : null}
        </React.Fragment>
      )}
    </Card>
  );
}

