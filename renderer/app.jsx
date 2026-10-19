/* ============================================================
   Doorman — window-first root: sidebar navigation + content. Main
   destinations up top, Settings anchored at the bottom next to the radar
   status line. No context bar and no Workbench screen (search lives in the
   Ledger).

   State comes from the main process as one snapshot (`doorman.getState()` plus a
   `state:changed` push); heavier reads (search, session turns) go over
   dedicated invoke channels.
   ============================================================ */

/* SECURITY-FIRST ordering: the security section leads the sidebar (it is the
   section with something to DECIDE — the Radar badge counts open exposures),
   then the usage screens, then the configuration surfaces. The app also
   opens on the radar (INITIAL_SCREEN below) for the same reason: spend is a
   report, an open finding is a task.

   Security is THREE screens, because the one Radar screen answered
   three questions at three cadences: what needs me now (Radar, daily), is this
   working (Analytics, weekly), what should this machine enforce (Rules, rare
   and deliberate). Install-level guard behaviour stays in Settings. */
const NAV = [
  { id: "overview", label: "Overview", icon: "overview", section: "Security" },
  { id: "radar", label: "Security Radar", icon: "shield", section: "Security" },
  { id: "analytics", label: "Analytics", icon: "analytics", section: "Security" },
  { id: "rules", label: "Guardrails", icon: "rules", section: "Security" },
  { id: "spend", label: "Usage", icon: "overview", section: "Usage" },
  { id: "ledger", label: "Event Ledger", icon: "ledger", section: "Usage" },
  { id: "integrations", label: "Integrations", icon: "integrations", section: "Setup" },
  { id: "settings", label: "Settings", icon: "settings", section: "Setup" },
];
const SCREEN_IDS = NAV.map((n) => n.id);
const SECURITY_SCREENS = ["overview", "radar", "analytics", "rules"];
/* The security screens' own titles, which SecurityHeader renders — the header
   IS the title row on these screens, so the h1 lives here rather than in each
   screen file. Not the sidebar's labels: the nav says "Analytics" under a
   Security heading that supplies the other half of the name. */
const SECURITY_TITLES = {
  overview: "Security Overview",
  radar: "Security Radar",
  analytics: "Security Analytics",
  rules: "Guardrails",
};

/* Panel mode: the same bundle, loaded into the small always-on-top window, so
   the floating prompt and the in-window overlay can never drift apart. */
const PANEL_MODE = new URLSearchParams(location.search).get("panel") === "1";

const REQUESTED_SCREEN =
  new URLSearchParams(location.search).get("screen") || (location.hash || "").slice(1);
/* Security opens on the OVERVIEW now, not on the Radar. The Radar is
   a queue: it is either empty or overwhelming, and neither is an answer to
   "how am I doing?". The overview answers that in a sentence and hands you the
   queue when you want it. */
const INITIAL_SCREEN = SCREEN_IDS.includes(REQUESTED_SCREEN) ? REQUESTED_SCREEN : "overview";

function App() {
  const [state, setState] = useState(null);
  const [screen, setScreen] = useState(INITIAL_SCREEN);
  // Which Integrations section a cross-screen link asked for ("mcp",
  // "coverage"): the screen scrolls it into view once mounted, then clears it.
  // Without this the Radar's "MCP servers →" landed on the top of Integrations
  // and left the reader to find the section themselves.
  const [integrationsFocus, setIntegrationsFocus] = useState(null);
  const goIntegrations = (section) => {
    setIntegrationsFocus(section || null);
    setScreen("integrations");
  };
  // Radar → ledger deep link: which session the ledger should open on arrival,
  // and (when the click came from a specific finding, not just a group) which
  // finding to scroll to and highlight once it's loaded.
  const [focusSessionId, setFocusSessionId] = useState(null);
  const [focusFindingId, setFocusFindingId] = useState(null);
  // Usage → ledger: the use-case a directory row asked to read.
  const [focusTask, setFocusTask] = useState(null);
  // Bumped on every deep-link request — see openSession below.
  const [focusNonce, setFocusNonce] = useState(0);
  // Analytics → Radar: the rule the feed should be filtered to on arrival.
  // Lifted here because the two screens never mount together; the nonce makes
  // a repeat request for the same rule distinct.
  const [radarRule, setRadarRule] = useState(null);
  const [radarRuleNonce, setRadarRuleNonce] = useState(0);
  // Overview → Radar: the SESSION the feed should be narrowed to on arrival,
  // and (when the click was one exposure rather than the session's set) which
  // exposure to scroll to and light up. Same shape as the ledger deep link
  // above, for the same reason: "Review these in the Radar" that landed on
  // the whole feed was a link to nowhere in particular.
  const [radarSession, setRadarSession] = useState(null);
  const [radarFocusFinding, setRadarFocusFinding] = useState(null);
  const [radarFocusNonce, setRadarFocusNonce] = useState(0);
  // Trace a secret (screens/radar-trace.jsx): the Radar's sub page, opened
  // with a value in hand (a revealed finding, the ledger's search box) or
  // empty (the bar under the hero, the menus). Lifted here because every
  // screen can open it.
  const [trace, setTrace] = useState(null);
  const traceRef = useRef(null);
  /* The app menu's Check for Updates… — bumped to make the Updates card run
     the check with its own feedback. */
  const [updateCheck, setUpdateCheck] = useState(0);
  const openTrace = (seed) => {
    setTrace({ seed: seed || "", nonce: Date.now() });
    setScreen("radar");
  };
  traceRef.current = openTrace;

  useEffect(() => {
    let live = true;
    // Rail labels come from main's transcript-source registry, so they are
    // learned from the snapshot rather than written down a second time here.
    const take = (s) => {
      learnSourceLabels(s && s.capture);
      setState(s);
    };
    window.doorman.getState().then((s) => {
      if (live) take(s);
    });
    const off = window.doorman.onState(take);
    // The application menu (Settings…, ⌘,) and notifications navigate through
    // the main process.
    const offNav = window.doorman.onNav((target) => {
      // "trace" is the menus' Trace a Secret… (⌘⇧T).
      if (target === "trace") {
        if (traceRef.current) traceRef.current("");
        return;
      }
      if (target === "check-updates") {
        setScreen("settings");
        setUpdateCheck((n) => n + 1);
        return;
      }
      if (SCREEN_IDS.includes(target)) setScreen(target);
    });
    return () => {
      live = false;
      off();
      offNav();
    };
  }, []);

  if (!state) return PANEL_MODE ? null : <BootScreen />;
  // The floating panel is nothing but the prompt — no sidebar, no screens.
  if (PANEL_MODE) return <ApprovalPanel state={state} />;
  // First-run setup owns the whole window while it is open: there is
  // nothing to navigate to until the app is watching something. Main decides
  // when that is (prefs.onboarding_open — set on a fresh install's first boot
  // and by the menu's Set Up Doorman…), so this is one read, not a second
  // first-run heuristic that could disagree with it.
  if (state.prefs && state.prefs.onboarding_open) {
    return <OnboardingScreen state={state} onDone={(target) => setScreen(target)} />;
  }

  // The nonce makes every request distinct. Without it, asking for a session
  // that is ALREADY selected set the same state value, React saw no change,
  // and the ledger's effect never ran — so a second click on the same finding
  // (or another finding in the same session) scrolled nowhere.
  const openSession = (sessionId, findingId) => {
    setFocusSessionId(sessionId);
    setFocusFindingId(findingId || null);
    setFocusNonce((n) => n + 1);
    setScreen("ledger");
  };

  const openTask = (task) => {
    setFocusTask(task);
    setScreen("ledger");
  };

  const openRule = (rule) => {
    setRadarRule(rule || null);
    setRadarRuleNonce((n) => n + 1);
    setScreen("radar");
  };

  /** The Radar, narrowed to one session and/or scrolled to one exposure.
   *  `{}` (or nothing) is the whole feed. */
  const openRadar = (focus) => {
    setRadarSession((focus && focus.session_id) || null);
    setRadarFocusFinding((focus && focus.finding_id) || null);
    setRadarFocusNonce((n) => n + 1);
    setScreen("radar");
  };

  // The badge counts things to decide, not sightings — same unit as the Radar's
  // own hero, so the two can never disagree.
  // Exposures (rule × place) — the same number the Radar hero and the tray show.
  const radarOpen =
    state.radar.summary.open_exposures != null
      ? state.radar.summary.open_exposures
      : state.radar.summary.open_groups != null
        ? state.radar.summary.open_groups
        : state.radar.summary.open;
  const held = (state.approvals || []).length;
  const enforcing = enforcingCount(state);
  const protection = protectionState(state, enforcing);

  return (
    <div className="shell">
      {/* A held tool call outranks whatever screen you were on — a session is
          stopped until it's answered. */}
      <ApprovalOverlay state={state} />
      <div className="sidebar">
        {/* The brand carries what protection amounts to, on every screen: a
            badge on the mark (the menu-bar icon's status dot) and the line under
            the name, which is also the way to Settings — so not a link there. */}
        <div className="brand">
          <span className="brand-mark">
            <img src="_asset/doorman-mark-512.png" alt="" />
            <ProtectionMarkBadge protection={protection} />
          </span>
          <span className="brand-lock">
            <span className="brand-wordmark">Doorman</span>
            <ProtectionBadge
              state={state}
              enforcing={enforcing}
              onGoSettings={screen === "settings" ? undefined : () => setScreen("settings")}
            />
          </span>
        </div>
        <Nav screen={screen} onPick={setScreen} radarOpen={radarOpen} />
        <div className="foot">
          <div className="statusline">
            <span className={"dot" + (held > 0 ? " hot" : enforcing.acting > 0 ? "" : " off")} />
            {held > 0
              ? held === 1
                ? "1 CALL HELD"
                : held + " CALLS HELD"
              : enforcing.acting > 0
                ? "RADAR ENFORCING"
                : "RADAR OBSERVING"}
          </div>
          <div className="statusline">
            <span className="dot off" />
            NOTHING LEAVES THIS MAC
          </div>
          <div className="statusline credit">POWERED BY PINATA</div>
          {/* The update's one control, present only while there is one: the
              percentage while a download runs, a button once it has landed.
              Updates otherwise install on their own the moment the window is
              out of sight — this is for the person who is looking. The version
              itself is stated in Settings → Updates, not here. */}
          {state.updater && (state.updater.status === "downloaded" || state.updater.status === "installing") ? (
            <button type="button" className="statusline updatebtn" onClick={() => window.doorman.installUpdate()} title={state.updater.message || "Restart into the downloaded update"}>
              <span className="dot hot" />
              UPDATE NOW{state.updater.version ? " · v" + state.updater.version : ""}
            </button>
          ) : state.updater && state.updater.status === "downloading" ? (
            <div className="statusline" title={state.updater.message || ""}>
              <span className="dot" />
              UPDATING {Math.round((state.updater.progress && state.updater.progress.percent) || 0)}%
            </div>
          ) : null}
        </div>
      </div>

      <div className="content">
        <div className="drag-strip" />
        {/* The content pane's own right/bottom padding is dead cream space —
            same background, nothing ever renders there — but it wasn't
            draggable. Pinned to the window edges (not the scroll position),
            so it stays put across every screen. */}
        <div className="drag-edge drag-edge-r" />
        <div className="drag-edge drag-edge-b" />
        {SECURITY_SCREENS.includes(screen) ? (
          <SecurityHeader screen={screen} title={screen === "radar" && trace ? "Trace a secret" : undefined} />
        ) : null}
        {screen === "spend" ? <GraphsScreen state={state} onOpenTask={openTask} /> : null}
        {screen === "ledger" ? (
          <LedgerScreen
            state={state}
            focusSessionId={focusSessionId}
            onFocusHandled={() => setFocusSessionId(null)}
            focusFindingId={focusFindingId}
            onFocusFindingHandled={() => setFocusFindingId(null)}
            focusNonce={focusNonce}
            focusTask={focusTask}
            onFocusTaskHandled={() => setFocusTask(null)}
            onTraceSecret={openTrace}
            onGoRadar={openRadar}
          />
        ) : null}
        {screen === "overview" ? (
          <OverviewScreen
            state={state}
            onGoRadar={openRadar}
            onOpenSession={openSession}
            onTraceSecret={() => openTrace(null)}
          />
        ) : null}
        {screen === "radar" ? (
          <RadarScreen
            state={state}
            onOpenSession={openSession}
            onGoRules={() => setScreen("rules")}
            onGoIntegrations={goIntegrations}
            onGoSettings={() => setScreen("settings")}
            ruleFilter={radarRule}
            ruleNonce={radarRuleNonce}
            sessionFilter={radarSession}
            focusFindingId={radarFocusFinding}
            focusNonce={radarFocusNonce}
            trace={trace}
            onTraceClose={() => setTrace(null)}
            onTrace={openTrace}
          />
        ) : null}
        {screen === "analytics" ? <AnalyticsScreen state={state} onOpenRule={openRule} onGoRules={() => setScreen("rules")} /> : null}
        {screen === "rules" ? <RulesScreen state={state} onGoSettings={() => setScreen("settings")} /> : null}
        {screen === "integrations" ? (
          <IntegrationsScreen
            state={state}
            onGoSettings={() => setScreen("settings")}
            focus={integrationsFocus}
            onFocused={() => setIntegrationsFocus(null)}
          />
        ) : null}
        {screen === "settings" ? <SettingsScreen state={state} onGoRules={() => setScreen("rules")} checkNonce={updateCheck} /> : null}
      </div>

      <NoticeStack notices={state.notices || []} onNav={setScreen} state={state} onGoSettings={() => setScreen("settings")} />
      {/* Doorman AI — one drawer at the root, opened from wherever an issue
          is shown (finding cards, held calls). */}
      <AiDrawer state={state} onOpenSession={(sessionId) => openSession(sessionId)} />
    </div>
  );
}

/** How many rules act before a tool runs — the number the header pill and the
    Rules badge carry, counted once here so they can't disagree. Enforceable
    shipped detectors plus the person's own ask/block rules. */
function enforcingCount(state) {
  const policy = (state.prefs && state.prefs.policy) || {};
  const modes = policy.modes || {};
  const enforceable = Object.keys(SEC_DETECTORS).filter((id) => !SEC_DETECTORS[id].radarOnly);
  const shipped = enforceable.filter((id) => modes[id] === "ask" || modes[id] === "block").length;
  const holding = enforceable.filter((id) => modes[id] === "ask").length;
  const custom = (policy.custom_rules || []).filter((r) => r.enabled !== false && !r.after);
  const customOn = custom.filter((r) => r.mode === "ask" || r.mode === "block").length;
  const wanted = shipped + customOn;
  /* A guard changed outside the app is not holding anything either: the hook
     on disk is no longer what the app wrote, so the policy below it is
     decorative until it is restored. Same treatment as "not installed". */
  const tampered = !!(state.radar.integrity && state.radar.integrity.status === "tampered");
  return {
    /* WANTED: what the policy says, whatever is installed. Radar's posture
       line needs this — "installing it turns on N rules that hold a call" is a
       promise about the policy, and zeroing it would make the sentence read
       "turns on 0 rules". */
    enforcing: wanted,
    holding: holding + custom.filter((r) => r.mode === "ask").length,
    tampered,
    /* ACTING: what can actually run before a tool call. No guard installed —
       or a guard that is not the one the app wrote — means no rule of ours
       fires, so nothing acts however the policy reads. This is the number
       every "N of M enforcing" readout shows, so the pill, the sidebar badge
       and the coverage facts can't claim enforcement the machine isn't doing. */
    acting: state.radar.guard_installed && !tampered ? wanted : 0,
    total: enforceable.length + custom.length,
    shipped: enforceable.length,
    custom: custom.length,
  };
}

/**
 * The title row every Security screen shares: the screen's own name,
 * the whole-machine ask beside it, and — pushed to the far end — how many rules
 * enforce plus one link to change that. One band across the top, in flow: the
 * ask used to hang UNDER the enforcing pill in an out-of-flow corner stack,
 * which made the strip taller than the title and forced the row to reserve a
 * height it otherwise didn't need. Beside the title it costs no height at all,
 * and it reads where the question actually belongs — next to the name of the
 * screen it is asked about.
 *
 * The h1 is HERE rather than in each screen file, because a screen cannot put
 * something into a title row it renders itself.
 *
 * A guard changed outside the app is NOT stated here. It used to be, as a red
 * banner carrying its own reinstall button — while Radar's "Needs attention"
 * list said the same sentence in its first row. One statement now, in that
 * list, routing to Settings where every guard action lives; here the
 * consequence shows instead, the ratio dropping to 0/N because a guard the app
 * did not write is holding nothing.
 */
/**
 * The protection badge — one word, top right, in the same place on every
 * Security screen (canvas artboard 2c).
 *
 * It STATES; it does not act. The canvas draws the real-time-protection switch
 * inside this pill, and that reads well, but it would put a guard action in
 * the shared header — which deliberately emptied of them, on the
 * grounds that every guard action is install behaviour and belongs in one
 * place. So the badge keeps the canvas's shape, colours and proportions, drops
 * the switch, and carries `| Manage` to the place that DOES own it: Settings,
 * where the guard switch, the hold window, the timeout fallback, the
 * escalation and the integrity check all live. A word that reports a state
 * should be one click from the control that changes it.
 *
 * The three words are the canvas's, and they are chosen so that one of them is
 * always exactly true:
 *   · Protected  — the guard is on AND something is genuinely being stopped;
 *   · Watch only — the guard is on and nothing is: the state that exists so
 *     that "Protected" can never contradict a level that stops nothing;
 *   · Not protected — no guard;
 *   · Guard changed — a guard edited outside the app, which holds nothing
 *     until it is reinstalled (the action reads Repair).
 *
 * It replaces the `N/M guardrails enforcing` pill. That ratio is not lost —
 * it is the badge's tooltip, and on Guardrails the level card's own
 * "What's protected" row counts the same rules in full.
 *
 * "Protected" is only as true as `guard_installed`. The hook used to invoke a
 * bare `node`, which a Mac-app-only install may not have on its PATH — a
 * guard that never ran while this read Protected. It now starts Doorman's
 * launcher (main/lib/node-launcher.ts), which runs the guard on the app's own
 * runtime when there is no Node.js, so the word holds on macOS and Linux;
 * Windows still runs a bare `node`.
 *
 * It lives in the sidebar, under the brand, on every screen.
 */
/** What protection amounts to — one reading for the mark's badge and the
 * line under the name, so the two can never disagree. */
function protectionState(state, enforcing) {
  const installed = !!state.radar.guard_installed;
  // A guard changed outside the app holds nothing, so it cannot be called
  // protected however the policy reads.
  const acting = installed && !enforcing.tampered;
  const kind = !acting ? "off" : enforcing.acting > 0 ? "protected" : "watch";
  const word = kind === "protected" ? "Protected" : kind === "watch" ? "Watch only" : enforcing.tampered ? "Guard changed" : "Not protected";
  /* The level the rules are set to — read from the STORED modes, like the
     Guardrails card, so a guard that is off doesn't read as "Relaxed". */
  const modes = (state.prefs && state.prefs.policy && state.prefs.policy.modes) || {};
  const levelId = (state.prefs && state.prefs.security_level) || levelOfModes(modes, state.level_modes || {});
  const level = SECURITY_LEVELS.find((l) => l.id === levelId);
  const guarded = (state.radar.guard_hosts || []).filter((h) => h.present && h.installed).length;
  const why =
    kind === "protected"
      ? enforcing.acting + " of " + enforcing.total + " rules act before a tool call runs · " + guarded + (guarded === 1 ? " agent" : " agents") + " guarded"
      : kind === "watch"
        ? "Real time protection is on, but no rule is set to hold or block — every rule only watches"
        : enforcing.tampered
          ? "The guard was changed outside this app, so no rule can act until it is reinstalled — repair it in Settings"
          : "Real time protection is off, so no rule can act — turn it on in Settings";
  return { kind, word, why, level, guarded, acting, tampered: !!enforcing.tampered, action: kind === "off" ? (enforcing.tampered ? "Repair" : "Turn on") : "Manage" };
}

/**
 * The line under the wordmark: the state in one word, then the level in force.
 * When nothing can act there is no level to state — the line is the state and
 * an arrow, the way to the fix (its label and tip name it: Turn on, Repair).
 * The whole line is the way to Settings; on Settings itself it is just text.
 */
function ProtectionBadge({ state, enforcing, onGoSettings }) {
  const p = protectionState(state, enforcing);
  const kids = [
    <strong key="w">{p.word}</strong>,
    p.acting ? <span key="s" className="pb-sep" aria-hidden="true">·</span> : null,
    p.acting ? <span key="l" className="pb-level">{p.level ? p.level.name : "Custom"}</span> : null,
    onGoSettings ? <span key="a" className="pb-arrow" aria-hidden="true">›</span> : null,
  ];
  const className = "protbadge " + p.kind;
  return onGoSettings ? (
    <button
      className={className}
      data-tampered={p.tampered ? "" : undefined}
      data-action={p.action}
      data-tip={p.why}
      aria-label={p.word + " — " + p.why + ". " + p.action + " in Settings"}
      onClick={onGoSettings}
    >
      {kids}
    </button>
  ) : (
    <span className={className} data-tampered={p.tampered ? "" : undefined} data-tip={p.why} aria-label={p.word + " — " + p.why}>
      {kids}
    </span>
  );
}

/* The mark's corner badge, the menu-bar icon's status dot: a check when
   something is being stopped, an eye when everything only watches, a slash
   when nothing can act, an exclamation when the guard was changed. */
function ProtectionMarkBadge({ protection }) {
  const { kind, tampered } = protection;
  return (
    <span className={"brand-status " + (tampered ? "tampered" : kind)} aria-hidden="true">
      <svg viewBox="0 0 16 16" width="11" height="11" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        {kind === "protected" ? (
          <path d="M4 8.4l2.6 2.6L12 5.6" />
        ) : kind === "watch" ? (
          <g>
            <path d="M2.6 8s2-3.4 5.4-3.4S13.4 8 13.4 8s-2 3.4-5.4 3.4S2.6 8 2.6 8z" strokeWidth="1.6" />
            <circle cx="8" cy="8" r="1.4" fill="currentColor" stroke="none" />
          </g>
        ) : tampered ? (
          <g>
            <path d="M8 4v5" />
            <circle cx="8" cy="12" r="0.4" fill="currentColor" />
          </g>
        ) : (
          <path d="M4.5 4.5l7 7" />
        )}
      </svg>
    </span>
  );
}

function SecurityHeader({ screen, title }) {
  return (
    <div className="screen-head sechead">
      <h1>{title || SECURITY_TITLES[screen] || "Security"}</h1>
    </div>
  );
}

/** Labels for a notice's "open" action, per destination screen. */
const NOTICE_NAV_LABELS = {
  radar: "Open Security Radar",
  analytics: "Open Analytics",
  rules: "Open Guardrails",
  spend: "Open Usage",
  ledger: "Open Event Ledger",
  integrations: "Open Integrations",
  settings: "Open Settings",
  integrations: "Open Integrations",
};

/**
 * The in-window notice stack — the delivery rail of last resort. Main mirrors
 * every findings/digest banner here and posts the one-time "your notifications
 * are blocked" alert, so a message reaches the person even when the OS drops
 * the banner (permission never granted, Focus mode, unsigned dev build).
 *
 * Notices live in AppState, not local state: one raised while this window was
 * closed is still waiting when it reopens, and dismissing goes back over IPC so
 * the tray/panel snapshots can never disagree. Sticky notices (the blocked
 * alert) wait for the ✕; the rest retire themselves after a beat.
 */
/** How long a notice waits before retiring itself: what main asked for, else
 * long enough to reach a button, else long enough to read a line. */
function noticeTtl(n) {
  if (Number.isFinite(n.ttl_ms) && n.ttl_ms > 0) return n.ttl_ms;
  return n.nav || n.action ? 10_000 : 5_000;
}

function NoticeStack({ notices, onNav, state, onGoSettings }) {
  // The pointer being inside the stack HOLDS every retirement timer. A notice
  // that carries a button is something to act on, and ten seconds is not long
  // enough to read a sentence and reach for it — the card used to vanish from
  // under the cursor mid-reach. One with nothing to reach for is read in a
  // glance and only costs attention after that, so it goes at five; main can
  // ask for shorter still (ttl_ms) for a pure acknowledgement.
  const [held, setHeld] = useState(false);
  useEffect(() => {
    if (held) return;
    const timers = notices
      .filter((n) => !n.sticky)
      .map((n) => setTimeout(() => window.doorman.dismissNotice(n.id), noticeTtl(n)));
    return () => timers.forEach(clearTimeout);
  }, [notices.map((n) => n.id).join("|"), held]);
  if (notices.length === 0) return null;
  return (
    <div
      className="notices"
      role="status"
      aria-live="polite"
      onMouseEnter={() => setHeld(true)}
      onMouseLeave={() => setHeld(false)}
    >
      {notices.map((n) => (
        /* Clicking the card dismisses it — reading it IS the acknowledgement,
           and reaching for a 12px ✕ to say so is the wrong amount of work.
           The action row stops the event so its buttons keep their own
           meaning; the ✕ stays as the focusable control for the keyboard. */
        <div
          key={n.id}
          /* No body and no action = one line, so it is drawn as one line
             rather than a card with an empty second row. */
          className={
            "notice" +
            (n.kind === "warn" ? " warn" : "") +
            (n.body || n.nav || n.action ? "" : " compact")
          }
          title="Click to dismiss"
          onClick={() => window.doorman.dismissNotice(n.id)}
        >
          <div className="n-head">
            <span className="n-title">{n.title}</span>
            <button className="n-x" aria-label="Dismiss" onClick={() => window.doorman.dismissNotice(n.id)}>
              ✕
            </button>
          </div>
          {n.body ? <div className="n-body">{n.body}</div> : null}
          {n.nav || n.action ? (
            <div className="n-act" onClick={(e) => e.stopPropagation()}>
              {/* Blocked notifications: the FIX and the explanation of the
                  fix, side by side. Opening the OS pane is the whole answer
                  when permission was simply never granted; the ask covers
                  every case the app can't see from here (alert style None, a
                  Focus mode, an unsigned dev build) — which is why it carries
                  the `notifications` subject and not a generic question. */}
              {n.action === "open-notification-settings" ? (
                <React.Fragment>
                  <button className="btn primary" onClick={() => window.doorman.openNotificationSettings()}>
                    Open Notification settings
                  </button>
                  <AiAskButton
                    compact
                    contextRef={{ kind: "notifications" }}
                    question="This Mac isn't delivering Doorman's notifications. Walk me through turning them back on, and tell me what else could be silencing them."
                    title="Notifications"
                  />
                </React.Fragment>
              ) : null}
              {n.action === "install-update" ? (
                <button className="btn primary" onClick={() => window.doorman.installUpdate()} title="Restart into the downloaded update">
                  Update now
                </button>
              ) : null}
              {n.nav ? (
                <button
                  className="btn"
                  onClick={() => {
                    onNav(n.nav);
                    // Navigating IS reading it — a non-sticky notice is done.
                    if (!n.sticky) window.doorman.dismissNotice(n.id);
                  }}
                >
                  {NOTICE_NAV_LABELS[n.nav] || "Open"}
                </button>
              ) : null}
            </div>
          ) : null}
        </div>
      ))}
    </div>
  );
}

/**
 * The destination list, with beautifului.dev's gliding hover state: one pill
 * that travels to whichever item the pointer is over, instead of every item
 * lighting its own background independently.
 *
 * Why it is worth the state: with seven destinations in three sections, the
 * independent-:hover version makes the sidebar read as seven separate controls
 * you happen to have stacked. A single travelling highlight makes it read as
 * one control with seven stops — and the travel itself is the feedback that the
 * pointer moved, which matters in a window that is mostly still.
 *
 * The pill is hover ONLY. The active screen keeps its own tinted background and
 * gold edge marker, so nothing about which screen you are on depends on the
 * pointer being somewhere, and a keyboard user loses nothing.
 */
function Nav({ screen, onPick, radarOpen }) {
  const ref = useRef(null);
  const [pill, setPill] = useState(null);

  const track = (event) => {
    const host = ref.current;
    if (!host) return;
    const button = event.target.closest("button");
    if (!button || !host.contains(button)) return;
    setPill({ top: button.offsetTop, height: button.offsetHeight });
  };

  const rows = [];
  let lastSection = null;
  for (const item of NAV) {
    if (item.section !== lastSection) {
      lastSection = item.section;
      rows.push(
        <div key={"label-" + item.section} className="nav-label">
          {item.section}
        </div>,
      );
    }
    rows.push(
      <button
        key={item.id}
        className={screen === item.id ? "on" : ""}
        aria-current={screen === item.id ? "page" : undefined}
        onClick={() => onPick(item.id)}
      >
        <Icon name={item.icon} />
        <span>{item.label}</span>
        {/* Radar's badge is a QUEUE — a count of things waiting for you, which
            is what a sidebar badge means everywhere else in the app. Guardrails
            had an N/M ratio here, which is a configuration reading rather than
            a backlog: nothing about it needs attending to, and the protection
            badge on the screen itself already says what it amounts to. */}
        {item.id === "radar" && radarOpen > 0 ? <span className="badge">{radarOpen}</span> : null}
      </button>,
    );
  }

  return (
    <div
      className="nav"
      ref={ref}
      onMouseMove={track}
      onMouseLeave={() => setPill(null)}
    >
      <span
        className={"nav-glide" + (pill ? " on" : "")}
        style={pill ? { height: pill.height + "px", transform: "translateY(" + pill.top + "px)" } : undefined}
      />
      {rows}
    </div>
  );
}

function BootScreen() {
  return (
    <div className="boot">
      <div className="boot-mark">Doorman</div>
      <div className="boot-sub">Loading…</div>
    </div>
  );
}

ReactDOM.createRoot(document.getElementById("root")).render(<App />);
