/* ============================================================
   Doorman — first-run setup.

   The window's whole content while `prefs.onboarding_open` is true: no
   sidebar, no screens, one question per step. It ends with the app actually
   watching something, rather than dropping someone on an empty graph and
   leaving them to find Integrations.

   NOTHING HERE IS NEW MACHINERY. Every step is a call the app already has —
   `installGuard`, `rescan`, `moveToApplications` — over state the snapshot
   already carries (`shadow_ai`, `translocated`). This file is
   an ORDER and a presentation over those, which is why the steps are so thin:
   if a step needs new detection logic, that logic belongs in main/lib behind
   an injected probe, not in here.

   ORDER IS LOAD-BEARING. The app-location step comes first because it silently
   voids the guard install the warnings step would otherwise promise. Getting
   the order wrong produces steps that pass and then quietly un-pass.

   Every step is skippable and the flow can be abandoned at any point: it never
   installs anything except when a control is pressed, so leaving halfway
   leaves nothing half-done.
   ============================================================ */

/* The happy path. The app-location step is NOT in here — it is prepended by
   `onboardingSteps` only on a machine that needs it, so the step count and the
   progress dots tell the truth about how much is left. */
const ONBOARDING_STEPS = ["welcome", "tools", "watching", "done"];

/**
 * macOS launched this copy from somewhere a baked path won't survive, so a
 * guard installed now dies when the app quits. Main's word (the snapshot's
 * `translocated`), not probed again here.
 */
function onboardingNeedsMove(state) {
  return !!(state && state.translocated);
}

/** The steps this machine actually has, in order. */
function onboardingSteps(state) {
  return onboardingNeedsMove(state) ? ["place"].concat(ONBOARDING_STEPS) : ONBOARDING_STEPS.slice();
}

/**
 * The AI tools found on this Mac, as the tools step lists them.
 *
 * Installed only — an absent tool is not a decision anyone has to make — and
 * covered ones first, so the list opens on what is already working instead of
 * on what isn't. `covered` here is the snapshot's own join of the capture
 * rails and the guard host registry; this never recomputes coverage.
 */
function onboardingTools(state) {
  const rows = ((state && state.shadow_ai) || {}).tools || [];
  const installed = rows.filter((t) => t && t.installed);
  const covered = (t) => !!(t.captured || t.guarded);
  return installed
    .map((t) => ({
      id: t.id,
      name: t.name,
      kind: t.kind,
      covered: covered(t),
      /* Not covered, but the guard has an adapter for it: turning warnings on
         (the very next step) is what wires it in. That makes this row a reason
         to keep going, so the step says so rather than showing a bare name. */
      pending: !covered(t) && !!t.guardable,
    }))
    .sort((a, b) => {
      if (a.covered !== b.covered) return a.covered ? -1 : 1;
      if (a.pending !== b.pending) return a.pending ? -1 : 1;
      return a.name.localeCompare(b.name);
    });
}

/** Everything the last step reports, counted once. */
function onboardingSummary(state) {
  const tools = onboardingTools(state);
  const prefs = (state && state.prefs) || {};
  const watching = tools.filter((t) => t.covered).length;
  return {
    found: tools.length,
    watching,
    /* What the person chose in the warnings step, read back from the pref the
       guard install actually set — not from a local toggle, so a failed
       install can never be reported as success. */
    warning: prefs.guard_wanted === true,
  };
}

const ONBOARDING_KIND_LABELS = {
  "agent-cli": "Terminal",
  "desktop-app": "App",
  editor: "Editor",
  "local-model": "Local model",
  browser: "Browser",
};

/* ---------------------------------------------------------------- the screen */

function OnboardingScreen({ state, onDone }) {
  const steps = onboardingSteps(state);
  const [at, setAt] = useState(0);
  // A control is in flight (moving the app).
  const [busy, setBusy] = useState("");
  // The position the warnings switch is MOVING to, while the guard install
  // behind it runs — see Switch's `pending` in components.jsx. Installing
  // writes several hook documents and takes a beat, and a switch that holds
  // its old position for that beat gets pressed twice.
  const [guardPending, setGuardPending] = useState(null);
  const [moveError, setMoveError] = useState("");

  // A machine that needed moving and no longer does (the doctor re-ran after a
  // relaunch) must not be parked on a step about a problem it doesn't have.
  const step = steps[Math.min(at, steps.length - 1)] || "welcome";
  const first = at === 0;
  const last = at >= steps.length - 1;

  /**
   * Leave the flow. `go` is a screen to land on INSTEAD of the app's own
   * opening screen — the door on the last step, for someone who wants to see
   * what "risky" means now rather than find Guardrails later. Without it the
   * app opens where it always does (the Radar), which after the re-scan below
   * is the one screen showing what was found on THIS Mac.
   */
  const finish = (go) => {
    // The initial pass over transcripts already on disk, so the app is not
    // empty when it opens. Fire-and-forget: the ledger fills in as it lands.
    if (window.doorman.rescan) window.doorman.rescan();
    window.doorman.setPrefs({ onboarding_open: false });
    if (go && onDone) onDone(go);
  };
  const skip = () => window.doorman.setPrefs({ onboarding_open: false });
  const next = () => setAt((n) => Math.min(n + 1, steps.length - 1));
  const back = () => setAt((n) => Math.max(n - 1, 0));

  const moveNow = async () => {
    setBusy("place");
    setMoveError("");
    // On success macOS relaunches us and this never returns.
    const res = await window.doorman.moveToApplications();
    setBusy("");
    if (res && res.ok) return;
    setMoveError(
      res && res.conflict === "existsAndRunning"
        ? "A copy of Doorman is already open from your Applications folder. Quit that one and try again."
        : "Couldn't move it. Drag Doorman into Applications yourself, then reopen it.",
    );
  };

  const setWarnings = async (on) => {
    setGuardPending(on);
    // installGuard is what sets guard_wanted, so the switch follows the PREF
    // rather than a local copy of the answer: if the install fails, the switch
    // settles back on its own and never claims protection that isn't running.
    await (on ? window.doorman.installGuard() : window.doorman.uninstallGuard());
    setGuardPending(null);
  };

  return (
    <div className="onb">
      <div className="onb-body">
        {step === "place" ? <OnboardingPlace busy={busy === "place"} error={moveError} /> : null}
        {step === "welcome" ? <OnboardingWelcome /> : null}
        {step === "tools" ? <OnboardingTools state={state} /> : null}
        {step === "watching" ? (
          <OnboardingWatching state={state} pending={guardPending} onSet={setWarnings} />
        ) : null}
        {step === "done" ? <OnboardingDone state={state} /> : null}
      </div>

      <div className="onb-foot">
        <div className="onb-dots" role="presentation">
          {steps.map((id, i) => (
            <span key={id} className={"onb-dot" + (i === at ? " on" : "")} />
          ))}
        </div>
        <div className="onb-acts">
          {step === "welcome" ? (
            <button type="button" className="onb-skip" onClick={skip}>
              Skip setup
            </button>
          ) : null}
          {!first && !last ? (
            <button type="button" className="btn" onClick={back}>
              Back
            </button>
          ) : null}
          {/* A door, not a detour: the app still opens where it always does.
              Offered whether or not pausing was switched on — with it off the
              rules still flag things, so "what counts as risky" is the same
              question either way. */}
          {last ? (
            <button type="button" className="onb-skip" onClick={() => finish("rules")}>
              See what counts as risky
              <Icon name="chevron" size={13} />
            </button>
          ) : null}
          {/* The location step's own pair, primary rightmost. "Not now" only
              advances — declining the move never installs anything, and the
              steps after it say what that costs. */}
          {step === "place" ? (
            <button type="button" className="btn" onClick={next}>
              Not now
            </button>
          ) : null}
          {step === "place" ? (
            <button type="button" className="btn primary" disabled={busy === "place"} onClick={moveNow}>
              {busy === "place" ? "Moving…" : "Move and restart"}
            </button>
          ) : last ? (
            <button type="button" className="btn primary" onClick={() => finish()}>
              Open Doorman
            </button>
          ) : (
            <button type="button" className="btn primary" onClick={next}>
              {step === "welcome" ? "Get started" : "Continue"}
            </button>
          )}
        </div>
      </div>
    </div>
  );
}

/* ---------------------------------------------------------------- the steps */

/** Step: this copy is running from somewhere its own paths won't survive. */
function OnboardingPlace({ busy, error }) {
  return (
    <div className="onb-mid onb-center">
      <div className="onb-move">
        <span className="onb-tile is-temp">
          <img src="_asset/doorman-mark-512.png" alt="" />
        </span>
        <Icon name="chevron" size={22} />
        <span className="onb-tile">
          <img src="_asset/doorman-mark-512.png" alt="" />
        </span>
      </div>
      <div className="onb-said">
        <span className="chip warn">One thing first</span>
        <h1>Move Doorman to Applications</h1>
        <p>
          It&rsquo;s running from a temporary folder right now, so it won&rsquo;t keep working after
          you quit.
        </p>
        {error ? <p className="onb-err">{error}</p> : null}
        {busy ? <p className="onb-note">Moving…</p> : null}
      </div>
    </div>
  );
}

function OnboardingWelcome() {
  return (
    <div className="onb-mid onb-center">
      <span className="onb-hero-mark">
        <img src="_asset/doorman-mark-512.png" alt="" />
      </span>
      <div className="onb-said">
        <h1>Welcome to Doorman</h1>
        <p>Get a heads-up when your AI tools do something risky &mdash; and see how much they use.</p>
      </div>
    </div>
  );
}

/**
 * Step: what is on this Mac.
 *
 * Deliberately has NO per-tool switches. Capture is per rail and the guard
 * installs into every host it has an adapter for, so a switch here would be a
 * control that changes nothing — and a setup screen that lies about what it
 * can do is worse than one that shows less. It reports, and the next step is
 * where something actually turns on.
 */
function OnboardingTools({ state }) {
  const tools = onboardingTools(state);
  const watching = tools.filter((t) => t.covered).length;
  return (
    <div className="onb-mid">
      <div className="onb-said onb-said-left">
        <h1>
          {tools.length === 0
            ? "No AI tools found yet"
            : tools.length === 1
              ? "We found 1 AI tool on this Mac"
              : "We found " + tools.length + " AI tools on this Mac"}
        </h1>
        <p>
          {tools.length === 0
            ? "Install Claude Code, Codex or another agent and Doorman will pick it up on its own."
            : "This is what Doorman can see. Nothing to choose here."}
        </p>
      </div>
      {tools.length > 0 ? (
        <div className="onb-list">
          {tools.map((t) => (
            <div key={t.id} className="onb-row">
              <span className="onb-row-mark">
                <ToolMark tool={t.id} size={18} />
              </span>
              <span className="onb-row-said">
                <span className="onb-row-name">{t.name}</span>
                <span className="onb-row-kind">{ONBOARDING_KIND_LABELS[t.kind] || t.kind}</span>
              </span>
              {t.covered ? (
                <span className="chip good">Watching</span>
              ) : t.pending ? (
                <span className="chip">Next step</span>
              ) : (
                <span className="onb-row-kind">Not supported yet</span>
              )}
            </div>
          ))}
        </div>
      ) : null}
      {tools.length > 0 ? (
        <div className="onb-fact">
          <span className={"dot" + (watching > 0 ? "" : " off")} />
          {watching === tools.length
            ? "All of them are already being watched."
            : watching + " of " + tools.length + " already being watched."}
        </div>
      ) : null}
    </div>
  );
}

/** Step: what watching means, and the one thing to opt into. */
function OnboardingWatching({ state, pending, onSet }) {
  // The switch reads the PREF, not a local answer — see setWarnings.
  const on = !!(state.prefs && state.prefs.guard_wanted);
  const error = (state.radar && state.radar.guard_sync_error) || "";
  // While the install runs, the panel follows the position being MOVED to, so
  // the border and the sentence don't lag a beat behind the knob.
  const shown = pending == null ? on : !!pending;
  return (
    <div className="onb-mid">
      <div className="onb-headed">
        <span className="onb-glyph">
          <Icon name="eye" />
        </span>
        <div className="onb-said onb-said-left">
          <h1>Doorman will be watching</h1>
          <p>
            From now on it keeps a record of what your AI tools do and flags anything risky. It all stays on
            this Mac.
          </p>
        </div>
      </div>
      <div className={"onb-opt" + (shown ? " is-on" : "")}>
        <span className="onb-opt-said">
          <span className="onb-opt-name">Pause risky actions and ask me first</span>
          <span className="onb-opt-note">
            {shown
              ? "Enable the guard to pause risky actions and require your approval before they run."
              : "Enable the guard to pause risky actions and require your approval before they run."}
          </span>
        </span>
        <Switch
          on={on}
          pending={pending}
          ariaLabel="Pause risky actions and ask me first"
          onChange={onSet}
        />
      </div>
      {/* Why the switch went back. Installing writes into files this app does
          not own, so it can fail for reasons the person can act on — and a
          switch that settles back with no explanation reads as a bug in us
          rather than a locked file. The guard's own error, not a second
          opinion about it. */}
      {!on && pending == null && error ? <p className="onb-err">{error}</p> : null}
    </div>
  );
}

function OnboardingDone({ state }) {
  const s = onboardingSummary(state);
  return (
    <div className="onb-mid onb-center">
      <span className="onb-tick">
        <Icon name="check" />
      </span>
      <div className="onb-said">
        <h1>You&rsquo;re all set</h1>
        <p>
          {s.watching === 0
            ? "Doorman is running. It will pick your tools up as you use them."
            : "We’ll keep an eye on " +
              (s.watching === 1 ? "1 tool" : s.watching + " tools") +
              "."}
          {" Nothing leaves this Mac."}
        </p>
      </div>
      <div className="onb-fact">
        <span className={"dot" + (s.warning ? "" : " off")} />
        {s.warning
          ? "You’ll be asked before anything risky runs."
          : "Recording only — nothing will be paused."}
      </div>
    </div>
  );
}
