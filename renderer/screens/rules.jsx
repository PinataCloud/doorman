/* Rules — the CONFIGURATION screen: "what should this machine
   enforce?" Rare, deliberate, and now next to its own evidence instead of one
   section away from every screen that reports on it.

   TWO parts now, because the page used to open on thirty rules and
   answer neither question a person arrives with — am I protected, and what
   should this be set to?

     1. the SECURITY LEVEL: four stops (Relaxed · Watchful · Protective ·
        Locked down) that set every rule's rung on the guard's own ladder
        (observe → warn → ask → block). Under it, what you're protected
        against: kinds of risk on the left, and opening one lists its rules on
        the right, each rule's outcome a one-word control with a `?` carrying
        what the rule catches. A level is a PRESET over the same per-detector
        modes — the guard never learns it exists — so individual rules stay
        editable, and editing one drops the control to "Custom" rather than
        letting it claim a stop that is no longer true. Moving the level
        overwrites hand-edited rules, so it offers to keep them under a name
        first;

     2. ADVANCED, one card below, holding only what belongs to no category:
        saved rule sets (the other half of that overwrite), rule packs — new
        deterministic detections shipped as worked examples in the custom-rule
        format, switchable per machine (plan C2) — your own rules (a rule the
        person writes, as regexes over the tool, its arguments, the command,
        the server, an optional preceding taint and a directory scope, plan C1;
        the editor offers a dry run over the last 14 days first — advice, not a
        gate), exceptions (the ignore list, including the dated project-scoped
        allows the approval panel writes, plan A2), and the way back: restore
        every shipped rule to the mode Doorman ships it at.

   Radar-only rules are NOT on this page any more. They read whole transcripts
   after the fact, so there is no call to hold and no rung to set — a control
   that offered one was offering a choice that did nothing.

   Install-level guard behaviour (the toggle, the hold window, the timeout
   fallback, the injection escalation) stays in Settings, and the footer says so.

   With the guard NOT installed there is nothing to run before a call, so every
   mode on this screen is inert. The table then shows what is in force —
   observe, all of it — with the controls disabled and a banner saying where
   the choice went. The stored policy is never rewritten: those modes are what
   resumes the moment the guard goes on. */

const CUSTOM_SEVERITIES = ["critical", "high", "medium", "low"];
const CUSTOM_TAINTS = [
  { value: "", label: "No taint — any time" },
  { value: "injection", label: "after an injected instruction arrived" },
  { value: "secret", label: "after a credential was read" },
  { value: "untrusted_fetch", label: "after a download landed a file" },
  { value: "private_data", label: "after private data was read (mail, chat, docs)" },
  { value: "sql_result", label: "after a database query" },
];

function RulesScreen({ state, onGoSettings }) {
  const policy = state.prefs.policy || {};
  const modes = policy.modes || {};
  const enforceable = Object.keys(SEC_DETECTORS).filter((id) => !SEC_DETECTORS[id].radarOnly);
  const installed = state.radar.guard_installed;
  /* What is actually IN FORCE. No guard means nothing runs before a call, so
     every rule is observe whatever the policy says — and a control that offers
     BLOCK while nothing can block is a lie the screen tells about itself. The
     stored modes are deliberately NOT rewritten to observe: that would throw
     away the configuration the person gets back by installing the guard, so
     they are reported in the banner instead. */
  const frozen = !installed;
  // The saved choice, for the banner to promise back.
  const wanted = {
    blocking: enforceable.filter((id) => modes[id] === "block").length,
    asking: enforceable.filter((id) => modes[id] === "ask").length,
    warning: enforceable.filter((id) => modes[id] === "warn").length,
  };

  return (
    <div>
      {/* The title row is SecurityHeader's — see radar.jsx. */}
      {installed ? null : <GuardOffNotice wanted={wanted} onGoSettings={onGoSettings} />}

      {state.radar.guard_sync_error ? (
        <div className="callout bad" style={{ marginBottom: "var(--s4)" }}>
          The guard's hook entries couldn't be updated: {state.radar.guard_sync_error}. The modes below are what the
          app WANTS; wherever the update didn't land, the guard on disk may be running an older policy, or none.
        </div>
      ) : null}
      <LevelCard state={state} frozen={frozen} installed={installed} />

      {/* Everything that belongs to no kind of risk, behind one disclosure —
          the shape the canvas draws (artboard 1c).

          A NATIVE <details>, not a useState fold, and that is the load-bearing
          choice: its children stay in the tree when it is shut, so the browser
          hides them with CSS while the screen's tests still reach the packs,
          the person's own rules and the exceptions. A JS fold renders nothing
          until it is opened, and the renderer test harness cannot click. */}
      <details className="rules-adv">
        <summary>
          Advanced
          <span className="muted"> · saved sets, rule packs, your own rules, exceptions</span>
        </summary>

        <SavedRuleSetsCard state={state} frozen={frozen} />

        <RulePacksCard state={state} />

        {/* The guard being off reaches here, because a custom rule is as inert
            as a shipped one without it. */}
        <CustomRulesCard state={state} guardOff={!installed} />

        <ExceptionsCard state={state} />
      </details>

      {/* No "Restore Doorman defaults" box. Protective's mode map IS
          `DEFAULT_MODES` (asserted in test/policy.test.ts), so moving
          the level to Protective is that button, exactly — and the hand-edit
          notice's "Put Protective back" is it in one click from where the
          drift is reported. A second control doing the same write, with its
          own count of the same difference, could only ever agree or be a bug. */}

      <div className="cardnote" style={{ marginTop: "var(--s5)" }}>
        The guard itself — on or off, how long a held call waits, what happens when nobody answers, the injection
        escalation — lives in{" "}
        <button className="linkbtn" onClick={onGoSettings}>
          Settings →
        </button>
      </div>
    </div>
  );
}

/**
 * The security level — the whole Guardrails page's first decision.
 *
 * The page used to open on thirty rules, a detector id and an enforcement mode
 * each, and answered neither question a person actually arrives with: am I
 * protected, and what should this be set to? A four-stop level answers both,
 * because picking one stop is a decision a person can make and setting thirty
 * rungs is not.
 *
 * Nothing new is enforced. A level is a PRESET over the same per-detector
 * modes (`state.level_modes`, straight from guard/policy.ts) — the guard never
 * learns it exists, and the mode map remains what runs. So the rules stay
 * editable one at a time underneath, and editing one does not put the machine
 * into a state the guard cannot describe: it stops matching any stop, and the
 * control says so by reading "Custom" while leaving the dot where the person
 * last put it.
 */
function LevelCard({ state, frozen, installed }) {
  const policy = state.prefs.policy || {};
  const modes = policy.modes || {};
  const levelModes = state.level_modes || {};
  /* Which kind of risk is open, as a family key. `null` is the page's opening
     state: the list of kinds is the whole card and the rules panel does not
     exist yet, so you never see thirty rules before choosing to. */
  const [openCat, setOpenCat] = useState(null);
  /* The confirm sheet, while a level move is pending: { to, edited }. */
  const [pending, setPending] = useState(null);
  const cats = levelCategories(levelModes);

  /* What is actually IN FORCE, on the same rule as the table below: no guard
     means nothing runs before a call, so every rule reads observe whatever the
     policy says. The stored modes are not rewritten — they are what comes back
     the moment the guard goes on. */
  const effective = (id) => (installed ? modes[id] || "observe" : "observe");
  /* The level is read from the STORED modes, not the effective ones. With the
     guard off every rule reads observe, and a card that announced "Relaxed"
     because of it would be describing the guard's absence as a choice the
     person made. The banner above already says nothing can act. */
  const matched = levelOfModes(modes, levelModes);
  const chosen = state.prefs.security_level || matched || "protective";
  const at = levelIndex(chosen);
  const custom = matched === null;
  const edited = handEditedDetectors(modes, chosen, levelModes);

  /* Every shipped rule's rung at the level in force, for the tally and the
     per-category bars. Counted over the categories actually shown, so the four
     numbers add up to the rules on screen. */
  const shown = cats.flatMap((cat) => cat.detectors);
  const tally = [3, 2, 1, 0].map((rung) => ({
    ...RUNGS[rung],
    count: shown.filter((id) => RUNG_OF[effective(id)] === rung).length,
  }));

  const move = (to) => {
    if (frozen) return;
    // Nothing to overwrite and nothing to save: move without a sheet. The
    // confirm exists to protect hand edits, not to make every move a dialog.
    if (edited.length === 0) {
      window.doorman.setSecurityLevel(to);
      return;
    }
    setPending({ to, edited });
  };

  /* Where the HANDLE is, which is not always where the level is. Dragging
     moves the handle through the stops between; the level is written once, on
     release (or on the key going up), so a pull from Relaxed to Locked down is
     one decision and one write rather than three. When the write does not
     happen — the guard is frozen, or a confirm sheet opened instead — the
     handle goes back to the stop in force; the sheet's own Move brings it
     forward again through `at`. */
  const [pos, setPos] = useState(at);
  useEffect(() => {
    setPos(at);
  }, [at]);

  const commit = () => {
    if (pos === at) return;
    move(SECURITY_LEVELS[pos].id);
    if (frozen || edited.length > 0) setPos(at);
  };

  return (
    <Card title="Security level">
      {/* THE LEVER. One handle on a rail with four detents, and the names
          under them — a control you pull, not a row of four dots you pick
          from. The rail is inset 7% at each end, which is the centre of the
          first and last detent (each 14% wide under `space-between`); the
          range input that IS the handle is widened by half a grip on each
          side so its thumb's centre lands on 7% at the first stop and 93% at
          the last.

          The input is the accessible control (a slider: arrow keys, drag,
          click-to-jump, one name read aloud). The four detents are still
          buttons — a click on one is the obvious way to jump — but hidden
          from assistive tech, so a reader meets ONE control for one value.

          Capped and centred: at the full width of a real window the four
          stops drift far enough apart to stop reading as one lever. */}
      {/* `off`, NOT `frozen`. Two different reasons the handle won't move,
          and only one of them means the lever is inert: with no guard
          installed nothing runs before a call, so a navy handle would be
          drawing an enforcing machine while the banner above says nothing
          can act. */}
      <div className={"lvl-track-wrap" + (installed ? "" : " off")}>
        <div className="lvl-track">
          <div className="lvl-groove" aria-hidden="true" />
          <div
            className="lvl-rail-fill"
            aria-hidden="true"
            style={{ width: (pos / (SECURITY_LEVELS.length - 1)) * 86 + "%" }}
          />
          <div className="lvl-stops" aria-hidden="true">
            {SECURITY_LEVELS.map((level, i) => (
              <button
                key={level.id}
                type="button"
                tabIndex={-1}
                aria-checked={i === at}
                aria-label={level.name}
                disabled={frozen}
                className={"lvl-stop" + (i === pos ? " on" : "") + (i <= pos ? " passed" : "")}
                data-tip={level.blurb}
                onClick={() => {
                  setPos(i);
                  move(level.id);
                }}
              >
                <span className="lvl-dot" aria-hidden="true" />
              </button>
            ))}
          </div>
          <input
            type="range"
            className="lvl-lever"
            min={0}
            max={SECURITY_LEVELS.length - 1}
            step={1}
            value={pos}
            disabled={frozen}
            aria-label="Security level"
            aria-valuetext={SECURITY_LEVELS[pos].name + (SECURITY_LEVELS[pos].recommended ? " (recommended)" : "")}
            onChange={(e) => setPos(Number(e.target.value))}
            onPointerUp={commit}
            onKeyUp={commit}
            onBlur={commit}
          />
        </div>
        <div className="lvl-names" aria-hidden="true">
          {SECURITY_LEVELS.map((level, i) => (
            <span key={level.id} className={"lvl-name-stop" + (i === pos ? " on" : "")}>
              {level.name}
            </span>
          ))}
        </div>
      </div>

      {/* Everything the level MEANS, below the rule that closes the track —
          the name it goes by, what it costs you, and the four numbers. The
          name lives here rather than in the card's top-right corner (where it
          sat beside a heading that already said "Security level") because it
          is the track's answer, and belongs under the track. */}
      <div className="lvl-said">
        <div className="lvl-said-h">
          <span className="lvl-said-name">{custom ? "Custom" : SECURITY_LEVELS[at].name}</span>
          {!custom && SECURITY_LEVELS[at].recommended ? <span className="lvl-rec">Recommended</span> : null}
          {custom ? (
            <span className="lvl-said-of muted">a hand-edited {SECURITY_LEVELS[at].name}</span>
          ) : null}
        </div>

        {/* No prose line here. Each stop's sentence is still written — it is
            the `data-tip` on the stop itself (and on the dot you have not
            picked yet, which is where it actually helps you choose). Under the
            name it restated what the tally below already counts. */}

        {custom && !frozen ? (
          <HandEditNotice
            edited={edited.map((id) => ({
              id,
              label: (SEC_DETECTORS[id] || {}).label || id,
              now: RUNGS[RUNG_OF[effective(id)]].word,
            }))}
            onPick={(id) => setOpenCat(firstCategoryWith(cats, [id]))}
          />
        ) : null}

        {/* Directly under the notice that counts the edits, because it is
            about exactly those rules — at the foot of the card it sat below
            the rules panel, far from the sentence that had just told you what
            was at stake. */}
        {pending ? (
          <LevelConfirm
            to={pending.to}
            from={SECURITY_LEVELS[at]}
            edited={pending.edited}
            onCancel={() => setPending(null)}
            onMove={(saveAs) => {
              window.doorman.setSecurityLevel(pending.to, saveAs);
              setPending(null);
            }}
          />
        ) : null}

        {/* The whole level as four numbers, strongest first, under the
            question they answer. */}
        <div className="lvl-tally" role="note" aria-label="What's protected?">
          <span className="lvl-tally-h">What&#8217;s protected?</span>
          <span className="lvl-tally-gap" />
          {tally.map((t) => (
            <span key={t.mode} className={"lvl-tally-i mode-" + t.mode + (t.count ? "" : " zero")}>
              {/* No swatch: the count already wears the rung's colour, and the
                  word beside it names the rung — a dot was a third way of
                  saying the same thing. */}
              <b className="mono">{t.count}</b>
              <span data-tip={t.tip} aria-label={t.tip}>{t.word}</span>
            </span>
          ))}
        </div>
      </div>

      {/* Kinds of risk, one under the other; the open kind drops its rules
          out directly beneath its row. It used to open a panel to the RIGHT,
          which put a kind's rules in a different column from the kind, on a
          page that otherwise reads top to bottom — and on a narrow window the
          panel fell under the whole list anyway. A dropdown keeps the rules
          where the eye already is. */}
      <div className="lvl-cats" role="list">
        {cats.map((cat) => {
          /* The row: the kind's name and rule count, and the set-all segment.
             The accessible name carries how the kind's rules divide across
             the rungs, in words. */
          const split = [3, 2, 1, 0]
            .map((i) => ({ ...RUNGS[i], count: cat.detectors.filter((id) => RUNG_OF[effective(id)] === i).length }))
            .filter((part) => part.count > 0);
          const on = cat.key === openCat;
          /* What the whole kind is set to, when its rules agree — the value
             the set-all segment on the row shows. "" when they don't, which
             the segment draws as nothing lit and the count line says as
             "mixed". */
          const common = cat.detectors.every((id) => effective(id) === effective(cat.detectors[0]))
            ? effective(cat.detectors[0])
            : "";
          return (
            <div key={cat.key} role="listitem" className={"lvl-kind" + (on ? " on" : "")}>
              {/* The ROW is two controls side by side: the name is the toggle
                  that drops the rules out, and the segment beside it sets
                  every rule in the kind at once — it must not open the kind
                  it applies to, so it is a sibling, not a child. */}
              <div className={"lvl-cat-row" + (on ? " on" : "")}>
                <button
                  type="button"
                  aria-expanded={on}
                  className={"lvl-cat" + (on ? " on" : "")}
                  aria-label={
                    cat.label + ", " + cat.detectors.length + " rule" +
                    (cat.detectors.length === 1 ? "" : "s") + ": " +
                    split.map((part) => part.count + " " + part.word.toLowerCase()).join(", ")
                  }
                  onClick={() => setOpenCat(on ? null : cat.key)}
                >
                  <Icon className="lvl-cat-chev" name="chevron" size={13} />
                  <span className="lvl-cat-said">
                    <span className="lvl-cat-name">{cat.label}</span>
                    <span className="lvl-cat-n">
                      {cat.detectors.length} rule{cat.detectors.length === 1 ? "" : "s"}
                      {common === "" ? " · mixed" : ""}
                    </span>
                  </span>
                </button>
                {/* Set the whole kind at once. Lit at the mode every rule
                    shares; nothing lit when they differ, and the count line
                    says "mixed". The dropdown below still sets each rule on
                    its own. */}
                <ModeSeg
                  value={common}
                  disabled={frozen}
                  onChange={(mode) => cat.detectors.forEach((id) => window.doorman.setDetectorMode(id, mode))}
                />
              </div>
              {on ? (
                <KindRules
                  cat={cat}
                  effective={effective}
                  levelMode={(id) => (levelModes[chosen] || {})[id]}
                  frozen={frozen}
                  assist={state.model_assist || null}
                />
              ) : null}
            </div>
          );
        })}
      </div>

    </Card>
  );
}

/** The first category containing one of the hand-edited rules — where "Show
 *  them" opens to. */
function firstCategoryWith(cats, edited) {
  const found = cats.find((cat) => cat.detectors.some((id) => edited.includes(id)));
  return found ? found.key : null;
}

/**
 * The hand-edit notice. It exists because "Custom" on its own is a label, not
 * an explanation: it says the machine is off the ladder without saying what put
 * it there or how to get back.
 */
function HandEditNotice({ edited, onPick }) {
  return (
    /* A native <details> again — the list is in the document whether or not it
       is open, so the screen's tests can read it and a shut notice still says
       what it is hiding. Opening it shows the rules THEMSELVES rather than
       jumping the page to a category and leaving you to find them: what you
       asked was "which ones?", and this answers it in place. */
    <details className="lvl-edited">
      <summary>
        <b>
          {edited.length} rule{edited.length === 1 ? "" : "s"} changed by hand
        </b>
        <span className="lvl-edited-show">Show them</span>
        <span className="lvl-edited-hide">Hide</span>
      </summary>
      <ul className="lvl-edited-list">
        {edited.map((e) => (
          <li key={e.id}>
            <button type="button" className="linkbtn" onClick={() => onPick(e.id)}>
              {e.label}
            </button>
            {/* What the rule is set to, and nothing more. What the level
                would do instead is one click away on the rule itself, and
                spelling it out on every line turned a short list into three
                sentences that all ended the same way. */}
            <span className="muted">{e.now}</span>
          </li>
        ))}
      </ul>
    </details>
  );
}

/**
 * One kind of risk, opened: its rules, each with the one-word outcome as the
 * control and a `?` carrying what the rule actually catches.
 *
 * A word, not the four-button OBS/WARN/ASK/BLOCK strip: inside a level card the
 * strip asks you to re-decide the ladder on every row, which is the thing the
 * level exists to stop. The word is still the control — it opens the same four
 * choices — so nothing is less settable than it was.
 */
/**
 * A kind's rules, dropped out under its row. Each rule carries the mode
 * segment the app has always used for a rule's rung — OBS / WARN / ASK /
 * BLOCK, the same control the custom-rule editor and the exceptions use —
 * rather than a word that opened a list. One vocabulary for "what does this
 * rule do", wherever a rule is set.
 */
function KindRules({ cat, effective, levelMode, frozen, assist }) {
  return (
    <div className="lvl-rules">
      {cat.detectors.map((id) => {
        const meta = SEC_DETECTORS[id] || { label: id, blurb: "" };
        const mode = effective(id);
        const off = levelMode(id) !== undefined && levelMode(id) !== mode;
        return (
          <div key={id} className={"lvl-rule" + (off ? " edited" : "")}>
            <span className="lvl-rule-n">{meta.label}</span>
            {/* The "?" right after the name: what the rule catches, and what a
                model adds to it, one hover away from the words it explains. */}
            <span
              className="lvl-rule-q"
              data-tip={meta.blurb + (assist ? assistTip(id, assist) : "")}
              aria-label={meta.blurb}
            >
              ?
            </span>
            {/* Then, at the control's side, the tag for a rule set by hand —
                the same word the level control uses when the machine is off
                the ladder, so the two read as one fact. Beside the segment,
                because the segment is what made it Custom. */}
            {off ? (
              <span className="lvl-rule-tag" data-tip="Set by hand — the level would put this on a different rung.">
                Custom
              </span>
            ) : null}
            <ModeSeg value={mode} disabled={frozen} onChange={(next) => window.doorman.setDetectorMode(id, next)} />
          </div>
        );
      })}
    </div>
  );
}

/** What a model adds to this rule, folded into its `?` rather than given its
 *  own line — the list has no room for a paragraph per rule, and AssistNote's
 *  text is an elaboration of what the rule catches. */
function assistTip(id, assist) {
  const ic = assist.injection_classifier || {};
  const so = assist.second_opinion || {};
  if (id === "injected_instruction" && ic.enabled) {
    return " Every hit is re-read by " + ic.model + " on this Mac.";
  }
  if ((id === "hardcoded_credential" || id === "unrecognized_secret") && so.enabled) {
    return " Before a hold, " + (so.model || "a local model") + " on this Mac is asked whether the value is really a credential.";
  }
  return "";
}

/**
 * Moving the level overwrites every hand-edited rule — so it asks first, and
 * the ask is where the rules get kept.
 *
 * The name field is the whole point: "your rules will be overwritten, OK?" is a
 * warning you can only accept or refuse, and refusing leaves you unable to
 * change the level at all. Naming them makes the overwrite survivable, which is
 * what turns the warning into a choice.
 */
function LevelConfirm({ to, from, edited, onCancel, onMove }) {
  const target = SECURITY_LEVELS[levelIndex(to)];
  /* "My Rules": short, and yours to change. The field used to open on
     "My protective rules · 17 Sep", which named the level and the day for
     you and read as a system label rather than a name you would type. */
  const [name, setName] = useState("My Rules");
  const [save, setSave] = useState(true);
  const trimmed = name.trim();
  return (
    <div className="callout warn lvl-confirm" role="alertdialog" aria-label="Save your rules?">
      <b className="lvl-confirm-t">Save your rules?</b>
      {/* The count is NOT repeated: the notice immediately above already says
          how many were changed by hand. This says only what moving does to
          them, which is the part that is new. */}
      <div className="lvl-confirm-h">
        {target.name} sets every rule, so {edited.length === 1 ? "the one" : "the " + edited.length} you changed by
        hand {edited.length === 1 ? "is" : "are"} about to be overwritten.
      </div>
      <ul className="lvl-editlist">
        {edited.slice(0, 6).map((id) => (
          <li key={id}>{(SEC_DETECTORS[id] || {}).label || id}</li>
        ))}
        {edited.length > 6 ? <li className="muted">and {edited.length - 6} more</li> : null}
      </ul>
      <div className="lvl-savebar">
        <label>
          <input type="checkbox" checked={save} onChange={(e) => setSave(e.target.checked)} />
          Save them as
        </label>
        <input
          type="text"
          value={name}
          maxLength={60}
          disabled={!save}
          aria-label="Name for the saved rules"
          onChange={(e) => setName(e.target.value)}
        />
      </div>
      <div className="lvl-confirm-a">
        <button
          type="button"
          className="btn primary"
          disabled={save && trimmed === ""}
          onClick={() => onMove(save ? trimmed : "")}
        >
          {save ? "Save and move" : "Move anyway"}
        </button>
        <button type="button" className="btn" onClick={onCancel}>
          Cancel
        </button>
      </div>
      {/* Under the buttons, not beside them: it is a note about what happens
          AFTER you press one, so it reads last rather than competing with the
          two controls for the same line. */}
      <span className="lvl-confirm-note muted">
        Saved sets live under Advanced, and put these rules back in one click.
      </span>
    </div>
  );
}

/** A name that is already true of the set, so the field is a confirmation
 *  rather than a blank the person has to invent something for. */
/**
 * Saved rule sets — the other half of the overwrite. Sits in Advanced because
 * it is a record of past decisions, not one of the rules this machine runs.
 */
function SavedRuleSetsCard({ state, frozen }) {
  const sets = state.prefs.saved_rule_sets || [];
  const [naming, setNaming] = useState(false);
  const [name, setName] = useState("");
  const [confirm, setConfirm] = useState(null);
  /* The set being read, by id — a popup over the card, like the wizards. */
  const [viewing, setViewing] = useState(null);
  const viewed = viewing ? sets.find((set) => set.id === viewing) : null;
  return (
    <Card title="Saved rule sets" hint="rules you kept, by name">
      {viewed ? (
        <WizardPopup title={viewed.name} onClose={() => setViewing(null)}>
          <SavedRuleSetView
            set={viewed}
            state={state}
            frozen={frozen}
            onClose={() => setViewing(null)}
            onRestore={() => {
              // Back to the row, where the confirm step lives: reading a set
              // never writes, and restoring keeps its one moment of pause.
              setViewing(null);
              setConfirm(viewed.id);
            }}
          />
        </WizardPopup>
      ) : null}
      {sets.length === 0 ? (
        <div className="cardnote" style={{ marginTop: 0 }}>
          Nothing saved yet. Moving the security level offers to keep the rules it is about to overwrite — and you can
          save the rules as they stand at any time.
        </div>
      ) : (
        <table className="rows">
          <tbody>
            {sets.map((set) => (
              <tr key={set.id}>
                <td>
                  {set.name}
                  <div className="muted" style={{ fontSize: "var(--t-3)" }}>
                    {savedWhen(set.saved_at)}
                    {set.level ? " · saved on " + (SECURITY_LEVELS[levelIndex(set.level)] || {}).name : null}
                  </div>
                </td>
                <td style={{ textAlign: "right" }}>
                  {confirm === set.id ? (
                    <React.Fragment>
                      <span className="muted" style={{ fontSize: "var(--t-3)" }}>
                        Replaces every rule&#8217;s outcome and the packs.{" "}
                      </span>
                      <button
                        type="button"
                        className="linkbtn"
                        onClick={() => {
                          setConfirm(null);
                          window.doorman.restoreRuleSet(set.id);
                        }}
                      >
                        Restore it
                      </button>{" "}
                      <button type="button" className="linkbtn" onClick={() => setConfirm(null)}>
                        Keep
                      </button>
                    </React.Fragment>
                  ) : (
                    // One "⋯" per row instead of two spelled-out links: the
                    // row stays about its name, and Delete is no longer a
                    // pixel from Restore on every line. Restore still lands
                    // on the inline confirm above, in the trigger's place.
                    <ActionMenu
                      label={"Actions for " + set.name}
                      items={[
                        { id: "view", label: "View", onPick: () => setViewing(set.id) },
                        { id: "restore", label: "Restore", disabled: frozen, onPick: () => setConfirm(set.id) },
                        { id: "delete", label: "Delete", danger: true, onPick: () => window.doorman.deleteRuleSet(set.id) },
                      ]}
                    />
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {/* The control sits off the prose above it by the same --s4 every other
          card on this screen puts between what you read and what you press. */}
      <div className="row" style={{ marginTop: "var(--s4)" }}>
        {naming ? (
          <div className="lvl-savebar">
            <input
              type="text"
              autoFocus
              value={name}
              maxLength={60}
              placeholder="Name these rules"
              aria-label="Name these rules"
              onChange={(e) => setName(e.target.value)}
            />
            <button
              type="button"
              className="btn primary"
              disabled={name.trim() === ""}
              onClick={() => {
                window.doorman.saveRuleSet(name.trim());
                setName("");
                setNaming(false);
              }}
            >
              Save
            </button>
            <button type="button" className="btn" onClick={() => setNaming(false)}>
              Cancel
            </button>
          </div>
        ) : (
          // Primary, like every other button that starts something on this
          // screen — it is the card's one action, not an alternative to one.
          <button type="button" className="btn primary" disabled={frozen} onClick={() => setNaming(true)}>
            Save now
          </button>
        )}
      </div>
    </Card>
  );
}

/**
 * What a saved set would put back, read before restoring it — every rule with
 * the outcome the set holds, beside the outcome its level sets by default, so
 * the person can see which rules the set changes and which it merely keeps.
 *
 * The level it is read against is the one Restore would land on (the set's
 * own modes first, then the level it was saved on, then Protective), so the
 * "default" column is the level the machine would show after restoring, not
 * whatever it is on now. Rules that differ are marked Custom, the same word
 * the level control uses for a hand-edited rule. Nothing here writes: the
 * one action is the same Restore the row offers, via the same confirm.
 */
function SavedRuleSetView({ set, state, frozen, onClose, onRestore }) {
  const levelModes = state.level_modes || {};
  const levelId = levelOfModes(set.modes || {}, levelModes) || set.level || "protective";
  const level = SECURITY_LEVELS[levelIndex(levelId)];
  const defaults = levelModes[levelId] || {};
  const cats = levelCategories(levelModes);
  const savedMode = (id) => (set.modes || {})[id] || "observe";
  const rows = cats.map((cat) => ({
    ...cat,
    rules: cat.detectors.map((id) => {
      const saved = savedMode(id);
      const dflt = defaults[id];
      return { id, label: (SEC_DETECTORS[id] || {}).label || id, saved, dflt, differs: dflt !== undefined && dflt !== saved };
    }),
  }));
  const total = rows.reduce((n, cat) => n + cat.rules.length, 0);
  const changed = rows.reduce((n, cat) => n + cat.rules.filter((r) => r.differs).length, 0);
  const packs = state.rule_packs || [];
  const on = new Set(set.packs || []);
  const rung = (mode) =>
    mode === undefined ? (
      <span className="sset-rung none">—</span>
    ) : (
      <span className={"sset-rung mode-" + mode}>{RUNGS[RUNG_OF[mode] || 0].word}</span>
    );
  return (
    <div className="sset">
      <div className="rw-head">
        <div className="rw-eyebrow">
          Saved rule set · {savedWhen(set.saved_at)}
          {set.level ? " · saved on " + (SECURITY_LEVELS[levelIndex(set.level)] || {}).name : ""}
        </div>
        <h4 className="rw-title">{set.name}</h4>
        <p className="rw-lede">
          What restoring it sets, beside what {level.name} sets by default.{" "}
          {changed === 0
            ? "Every rule sits where " + level.name + " puts it."
            : (changed === 1 ? "One rule differs" : changed + " of " + total + " rules differ") + " from " + level.name + " — marked Custom."}
        </p>
      </div>
      <table className="rows sset-table">
        <thead>
          <tr>
            <th>Rule</th>
            <th>Saved</th>
            <th>{level.name} default</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((cat) => (
            <React.Fragment key={cat.key}>
              <tr className="sset-fam">
                <td colSpan={3}>{cat.label}</td>
              </tr>
              {cat.rules.map((r) => (
                <tr key={r.id} className={r.differs ? "differs" : undefined}>
                  <td>
                    {r.label}
                    {r.differs ? (
                      <span className="lvl-rule-tag" data-tip={"Set by hand — " + level.name + " would put this on a different rung."}>
                        Custom
                      </span>
                    ) : null}
                  </td>
                  <td>{rung(r.saved)}</td>
                  <td>{rung(r.dflt)}</td>
                </tr>
              ))}
            </React.Fragment>
          ))}
        </tbody>
      </table>
      {packs.length > 0 ? (
        <div className="sset-packs">
          <div className="sset-packs-h">Rule packs</div>
          {packs.map((p) => {
            const isOn = on.has(p.id);
            const differs = isOn !== !!p.default_on;
            return (
              <div key={p.id} className={"sset-pack" + (differs ? " differs" : "")}>
                <span className="sset-pack-n">{p.label}</span>
                <span className={"sset-rung " + (isOn ? "on" : "none")}>{isOn ? "On" : "Off"}</span>
                <span className="muted sset-pack-d">{differs ? (p.default_on ? "on by default" : "off by default") : "default"}</span>
              </div>
            );
          })}
        </div>
      ) : null}
      <div className="rw-foot">
        <button type="button" className="btn primary" disabled={frozen} onClick={onRestore}>
          Restore&#8230;
        </button>
        <button type="button" className="btn" onClick={onClose}>
          Close
        </button>
      </div>
    </div>
  );
}

/** When a set was saved, in the app's own short form. */
function savedWhen(iso) {
  const t = Date.parse(iso);
  if (!Number.isFinite(t)) return "";
  return new Date(t).toLocaleDateString("en-US", { month: "short", day: "numeric" });
}

/**
 * The guard is off, so nothing on this screen acts. Same banner shape and
 * words as Radar's posture line, because it is the same fact.
 *
 * It ROUTES to Settings rather than installing from here: switching the guard
 * on or off is install behaviour, which deliberately kept in Settings
 * (and a test pins Rules for not carrying it). Radar's posture line owns the
 * one-click install; this screen owns the policy the install then enforces.
 *
 * It names the saved modes on purpose: a table that silently switched to OBS
 * would read as "my configuration is gone".
 */
function GuardOffNotice({ wanted, onGoSettings }) {
  const kept = [
    wanted.blocking > 0 ? wanted.blocking + " block" : null,
    wanted.asking > 0 ? wanted.asking + " hold & ask" : null,
    wanted.warning > 0 ? wanted.warning + " warn" : null,
  ].filter(Boolean);
  return (
    <div className="posture off">
      <span className="pdot" />
      <div className="ptext">
        <b>None of these guardrails can act.</b> Real time protection is off, so every rule below is
        observe only: findings are still recorded from your transcripts, but no tool call is held or refused.
        {kept.length > 0
          ? " Your modes are saved and take effect the moment real time protection is on."
          : " Set the modes once real time protection is on."}
      </div>
      <button className="btn primary" onClick={onGoSettings}>
        Turn real time protection on →
      </button>
    </div>
  );
}
/** Shipped rule packs: switchable sets of custom-format rules. */
function RulePacksCard({ state }) {
  const packs = state.rule_packs || [];
  const enabled = new Set(state.prefs.rule_packs_enabled || []);
  if (packs.length === 0) return null;
  return (
    <Card title="Rule packs" hint={enabled.size + " of " + packs.length + " on"}>
      <div className="cardnote" style={{ marginTop: 0 }}>
        New detections shipped in the same format as your own rules — worked examples you can copy, and switch off
        per machine. A pack's rules show up in the feed under their own labels.
      </div>
      {packs.map((p) => (
        <div className="setting" key={p.id}>
          <div className="what">
            <div className="t">
              {p.label}
              <span className="muted" style={{ fontWeight: 400 }}> · {p.rules} rule{p.rules === 1 ? "" : "s"} · {p.default_mode}</span>
            </div>
            <div className="d">{p.blurb}</div>
          </div>
          <Switch ariaLabel={p.label} on={enabled.has(p.id)} onChange={(v) => window.doorman.setRulePack(p.id, v)} />
        </div>
      ))}
    </Card>
  );
}

/* ── Your rules: the wizard ────────────────────────────────────────────────
   A rule was one form of eleven fields under four labels — every regex box
   visible at once whether or not it applied, the mode beside the label, the
   dry run at the bottom. Nothing told a first-time author what a rule IS
   before asking for its shell-command regex.

   Now it is five steps, in the order a person thinks: what is it called,
   which calls does it match, only in which situations, what should the guard
   do, and check it against your history before it holds anything. Each step
   asks one question and gates on one thing (a name; at least one condition
   that compiles). A step rail says where you are and lets you go back; an
   existing rule (or a draft Doorman AI wrote) opens on Review with every
   step unlocked, because that reader wants to check, not to be walked.

   The shapes are the app's own craft layer: choice cards where a step is a
   pick from a handful (taint, severity), the mode segment where the rest of
   the screen uses it, a live "Fires when …" sentence so the regexes are read
   back in words, and the dry run as a task row with its elapsed clock. It is
   inline in the card — not a modal (the approval overlay is deliberately the
   only one) and not a box in a box: hairlines separate the rail, the body and
   the footer. */

const RULE_STEPS = [
  { key: "name", label: "Name", title: "What is this rule called?", lede: "The name is what a finding, a held call and the Analytics table will call it." },
  { key: "match", label: "Match", title: "Which calls does it match?", lede: "Regexes over what a call IS. Every condition you add must match — add fewer to catch more." },
  { key: "context", label: "Context", title: "Only in some situations?", lede: "Optional. Fire only after something happened earlier in the session, or only under one directory." },
  { key: "response", label: "Response", title: "What should the guard do?", lede: "How loud the finding is, and whether the call is let through, held or refused." },
  { key: "review", label: "Review", title: "Read it back, then check it against your history", lede: "A saved rule applies from the next tool call. The dry run is advice, not a gate." },
];

/* The conditions a rule can put on a call. One each of the first four; any
   number of argument fields. Order is the order a person usually knows them:
   the tool first, then what it was asked to do. */
const RULE_CLAUSE_KINDS = [
  { kind: "tool", label: "Tool name", hint: "The tool Claude Code or Codex called: Bash, Write, mcp__slack__send…", placeholder: "^mcp__slack__send|^Bash$" },
  { kind: "command", label: "Shell command", hint: "The Bash command line, redacted before matching — a rule can never probe for a value.", placeholder: "(?:^|\\s)kubectl\\s+apply\\b" },
  { kind: "server", label: "MCP server", hint: "The server segment of mcp__<server>__tool.", placeholder: "^(slack|gmail)$" },
  { kind: "target", label: "Target", hint: "The Bash program name, or the file path a tool writes or reads.", placeholder: "\\.tf$" },
  { kind: "arg", label: "Argument field", hint: "One named field of the tool's input. Dotted paths reach nested fields.", placeholder: "@(?!doorman\\.com$)", repeatable: true },
];

const CUSTOM_ID_RE = /^[a-z0-9_-]{1,48}$/;

const EMPTY_RULE = {
  id: "",
  id_touched: false,
  label: "",
  blurb: "",
  severity: "medium",
  mode: "warn",
  clauses: [],
  taint: "",
  cwd_prefix: "",
  enabled: true,
  pack: undefined,
  original_id: null,
};

function slugify(text) {
  return String(text || "")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "_")
    .replace(/^_+|_+$/g, "")
    .slice(0, 48);
}

let __clauseSeq = 0;
function newClause(kind, field, pattern) {
  return { key: "c" + ++__clauseSeq, kind, field: field || "", pattern: pattern || "" };
}

/** The wizard's form ↔ the policy's CustomRule shape. */
function formToRule(form) {
  const when = {};
  const arg = {};
  for (const c of form.clauses || []) {
    const pattern = String(c.pattern || "").trim();
    if (!pattern) continue;
    if (c.kind === "arg") {
      const field = String(c.field || "").trim();
      if (field) arg[field] = pattern;
    } else when[c.kind] = pattern;
  }
  if (Object.keys(arg).length > 0) when.arg = arg;
  const rule = {
    id: form.id.trim() || slugify(form.label),
    label: form.label.trim(),
    severity: form.severity,
    mode: form.mode,
  };
  if (form.blurb.trim()) rule.blurb = form.blurb.trim();
  if (Object.keys(when).length > 0) rule.when = when;
  if (form.taint) rule.after = { taint: form.taint };
  if (form.cwd_prefix.trim()) rule.scope = { cwd_prefix: form.cwd_prefix.trim() };
  if (form.enabled === false) rule.enabled = false;
  if (form.pack) rule.pack = form.pack;
  return rule;
}

function ruleToForm(rule) {
  const when = rule.when || {};
  const clauses = [];
  for (const k of RULE_CLAUSE_KINDS) {
    if (k.kind === "arg") continue;
    if (when[k.kind]) clauses.push(newClause(k.kind, "", when[k.kind]));
  }
  if (when.arg) for (const f of Object.keys(when.arg)) clauses.push(newClause("arg", f, when.arg[f]));
  return {
    ...EMPTY_RULE,
    id: rule.id,
    id_touched: true,
    original_id: rule.id,
    label: rule.label,
    blurb: rule.blurb || "",
    severity: rule.severity,
    mode: rule.mode,
    clauses,
    taint: rule.after ? rule.after.taint : "",
    cwd_prefix: (rule.scope && rule.scope.cwd_prefix) || "",
    enabled: rule.enabled !== false,
    pack: rule.pack,
  };
}

/** Client-side: does this pattern even parse? The guard's own validator is
    stricter (it refuses nested quantifiers and match-empty patterns), and its
    verdict arrives as a problem on Save — this is the instant version. */
function regexProblem(pattern) {
  if (!String(pattern || "").trim()) return null;
  try {
    new RegExp(pattern);
    return null;
  } catch (e) {
    return (e && e.message ? e.message.replace(/^Invalid regular expression: /, "") : "invalid pattern").replace(/^\/.*\/: /, "");
  }
}

/** What stops the person from leaving a step, in the words the footer says. */
function ruleStepBlocker(step, form) {
  const key = RULE_STEPS[step].key;
  if (key === "name") {
    if (!form.label.trim()) return "Give the rule a name";
    const id = form.id.trim() || slugify(form.label);
    if (!CUSTOM_ID_RE.test(id)) return "The id needs 1–48 lowercase letters, digits, - or _";
    return null;
  }
  if (key === "match") {
    const live = (form.clauses || []).filter((c) => String(c.pattern || "").trim());
    if (live.length === 0) return "Add at least one condition";
    for (const c of live) {
      if (c.kind === "arg" && !String(c.field || "").trim()) return "Name the argument field";
      if (regexProblem(c.pattern)) return "Fix the pattern that doesn't parse";
    }
    return null;
  }
  return null;
}

/** Which step a validator problem belongs to, so "fix it" lands there. */
function ruleStepForProblem(field) {
  const f = String(field || "");
  if (f === "id" || f === "label") return 0;
  if (f === "when" || f.startsWith("when.")) return 1;
  if (f === "after" || f.startsWith("after.") || f === "scope" || f.startsWith("scope.")) return 2;
  if (f === "severity" || f === "mode") return 3;
  return 4;
}

/**
 * The step rail: five numbered stops on one line. A done stop wears a tick, the
 * current one is filled, an unreached one is a ring you cannot click yet — a
 * reached one you can. A stop the validator complained about carries a red
 * dot so the reader sees where the problem lives from the Review step.
 */
function StepRail({ step, reached, flagged, onGo, steps }) {
  const stops = steps || RULE_STEPS;
  return (
    <ol className="rw-rail" aria-label="Steps">
      {stops.map((s, i) => {
        const state = i === step ? "current" : i < step ? "done" : i <= reached ? "reached" : "locked";
        return (
          <li key={s.key} className={"rw-stop " + state + (flagged && flagged.has(i) ? " flagged" : "")}>
            <button
              type="button"
              className="rw-stopbtn"
              disabled={state === "locked"}
              aria-current={i === step ? "step" : undefined}
              onClick={() => onGo(i)}
            >
              <span className="rw-num" aria-hidden="true">
                {state === "done" ? <Icon name="check" size={12} strokeWidth={2.4} /> : i + 1}
              </span>
              <span className="rw-stoplabel">{s.label}</span>
            </button>
            {i < stops.length - 1 ? <span className="rw-line" aria-hidden="true" /> : null}
          </li>
        );
      })}
    </ol>
  );
}

/** A pick from a handful, each option saying what it means (the approval
    card's option list, as a radio group). */
function ChoiceCards({ value, options, onPick, ariaLabel, columns }) {
  return (
    <div className="rw-choices" role="radiogroup" aria-label={ariaLabel} style={columns ? { gridTemplateColumns: "repeat(" + columns + ", minmax(0, 1fr))" } : undefined}>
      {options.map((o) => (
        <button
          type="button"
          key={String(o.value)}
          role="radio"
          aria-checked={value === o.value}
          className={"rw-choice" + (value === o.value ? " on" : "") + (o.tone ? " " + o.tone : "")}
          onClick={() => onPick(o.value)}
        >
          <span className="rw-choice-mark" aria-hidden="true">
            {o.dot ? <span className="dot" /> : null}
          </span>
          <span className="rw-choice-body">
            <span className="rw-choice-title">{o.label}</span>
            {o.note ? <span className="rw-choice-note">{o.note}</span> : null}
          </span>
        </button>
      ))}
    </div>
  );
}

/** One condition: its kind, its (optional) field, its pattern, its verdict. */
function ClauseRow({ clause, usedKinds, onChange, onRemove, onSubmit, autoFocus }) {
  const meta = RULE_CLAUSE_KINDS.find((k) => k.kind === clause.kind) || RULE_CLAUSE_KINDS[0];
  const bad = regexProblem(clause.pattern);
  const onKey = (e) => {
    if (e.key === "Enter") {
      e.preventDefault();
      onSubmit();
    }
  };
  return (
    <div className={"rw-clause" + (bad ? " bad" : "")}>
      <div className="rw-clause-row">
        <select
          aria-label="Condition"
          value={clause.kind}
          onChange={(e) => onChange({ ...clause, kind: e.target.value, field: e.target.value === "arg" ? clause.field : "" })}
        >
          {RULE_CLAUSE_KINDS.map((k) => (
            <option key={k.kind} value={k.kind} disabled={!k.repeatable && k.kind !== clause.kind && usedKinds.has(k.kind)}>
              {k.label}
            </option>
          ))}
        </select>
        {clause.kind === "arg" ? (
          <input
            type="text"
            className="mono rw-field"
            aria-label="Argument field"
            placeholder="to"
            value={clause.field}
            onKeyDown={onKey}
            onChange={(e) => onChange({ ...clause, field: e.target.value })}
          />
        ) : null}
        <span className="rw-op" aria-hidden="true">matches</span>
        <input
          type="text"
          className="mono rw-pattern"
          aria-label={meta.label + " pattern"}
          aria-invalid={bad ? true : undefined}
          placeholder={meta.placeholder}
          value={clause.pattern}
          autoFocus={autoFocus}
          onKeyDown={onKey}
          onChange={(e) => onChange({ ...clause, pattern: e.target.value })}
        />
        <button type="button" className="rw-x" aria-label={"Remove " + meta.label + " condition"} onClick={onRemove}>
          <Icon name="block" size={12} strokeWidth={2} />
        </button>
      </div>
      <div className={"rf-hint" + (bad ? " bad" : "")}>{bad ? "Doesn't parse: " + bad : meta.hint}</div>
    </div>
  );
}

/* ---- The wizard popup -------------------------------------------------------
   Both wizards open as a popup over the Rules screen rather than unfolding
   inside their card: a five-step form inline pushed the card's own list
   off-screen. One scrim, one dialog; Escape and the
   footer's Cancel both close it; the list behind stays where it was. The
   approval overlay keeps its own, sterner shape — it has no dismiss at all. */
function WizardPopup({ title, onClose, children }) {
  useEffect(() => {
    const onKey = (e) => {
      if (e.key === "Escape") {
        e.stopPropagation();
        onClose();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);
  return (
    <div className="wiz-scrim" onMouseDown={(e) => { if (e.target === e.currentTarget) onClose(); }}>
      <div className="wiz-modal" role="dialog" aria-modal="true" aria-label={title}>
        {children}
      </div>
    </div>
  );
}

/**
 * The wizard itself. `form` is the whole draft; `initialStep` is where it
 * opens (0 for a blank rule, Review for an existing one or an AI draft, when
 * every step is also unlocked); `problems` are the validator's verdicts from
 * the last Save, mapped onto steps.
 */
function RuleWizard({ form, setForm, initialStep, unlocked, problems, dry, saving, existing, guardOff, onDryRun, onSave, onCancel }) {
  const [step, setStep] = useState(initialStep || 0);
  const [reached, setReached] = useState(unlocked ? RULE_STEPS.length - 1 : initialStep || 0);
  const [focusKey, setFocusKey] = useState(null);
  const s = RULE_STEPS[step];
  const blocker = ruleStepBlocker(step, form);
  const last = step === RULE_STEPS.length - 1;
  const flagged = new Set((problems || []).map((p) => ruleStepForProblem(p.field)));
  const here = (problems || []).filter((p) => ruleStepForProblem(p.field) === step);

  const go = (i) => {
    if (i < 0 || i >= RULE_STEPS.length) return;
    setStep(i);
    setReached((r) => Math.max(r, i));
  };
  const next = () => {
    if (blocker || last) return;
    go(step + 1);
  };
  const onEnter = (e) => {
    if (e.key === "Enter" && !e.shiftKey && e.target.tagName !== "TEXTAREA") {
      e.preventDefault();
      next();
    }
  };
  const set = (patch) => setForm({ ...form, ...patch });

  const derivedId = form.id_touched ? form.id : slugify(form.label);
  const usedKinds = new Set((form.clauses || []).map((c) => c.kind));
  const addClause = (kind) => {
    const c = newClause(kind);
    setFocusKey(c.key);
    set({ clauses: [...(form.clauses || []), c] });
  };
  const preview = describeCustomRule(formToRule({ ...form, id: derivedId }));
  const flowOnly = !!form.taint && form.taint !== "injection";

  const modeWords = {
    observe: "Observe — record the finding and let the call through.",
    warn: "Warn — let the call through, but raise a heads-up banner.",
    ask: "Ask — hold the call open until you answer, on the approval panel.",
    block: "Block — refuse the call without asking.",
  };

  return (
    <div className="rw" onKeyDown={step < 4 ? onEnter : undefined}>
      <StepRail step={step} reached={reached} flagged={flagged} onGo={go} />

      <div className="rw-body" key={s.key}>
        <div className="rw-head">
          <div className="rw-eyebrow">Step {step + 1} of {RULE_STEPS.length}{existing ? " · editing " + (form.label || form.original_id) : ""}</div>
          <h4 className="rw-title">{s.title}</h4>
          <p className="rw-lede">{s.lede}</p>
        </div>

        {here.length > 0 ? (
          <div className="callout bad" role="alert">
            {here.map((p, i) => (
              <div key={i}><span className="mono">{p.field}</span>: {p.message}</div>
            ))}
          </div>
        ) : null}

        {s.key === "name" ? (
          <div className="rw-stack">
            <label className="rf-field">
              <span className="rf-label">Name</span>
              <input
                type="text"
                className="rw-big"
                autoFocus
                placeholder="Deploy to production"
                value={form.label}
                onChange={(e) => set({ label: e.target.value, ...(form.id_touched ? {} : { id: "" }) })}
              />
            </label>
            <label className="rf-field">
              <span className="rf-label">What it catches <span className="muted" style={{ textTransform: "none", letterSpacing: 0 }}>· optional</span></span>
              <input
                type="text"
                placeholder="A production deploy from an agent session."
                value={form.blurb}
                onChange={(e) => set({ blurb: e.target.value })}
              />
              <span className="rf-hint">Shown on the finding card, where the regexes would not help.</span>
            </label>
            <div className="rw-idline">
              <span className="rf-label">Id</span>
              <span className="chip mono">custom:{derivedId || "…"}</span>
              {form.id_touched ? (
                <input
                  type="text"
                  className="mono rw-id"
                  aria-label="Rule id"
                  autoFocus={!existing}
                  value={form.id}
                  onChange={(e) => set({ id: e.target.value })}
                />
              ) : (
                <button type="button" className="linkbtn" onClick={() => set({ id: derivedId, id_touched: true })}>
                  change
                </button>
              )}
              <span className="rf-hint">
                {existing ? "Renaming replaces this rule; its past findings keep the old name." : "Lowercase, digits, - and _. Follows the name unless you change it."}
              </span>
            </div>
          </div>
        ) : null}

        {s.key === "match" ? (
          <div className="rw-stack">
            {(form.clauses || []).length === 0 ? (
              <div className="rw-choices rw-kinds" role="group" aria-label="Add a condition">
                {RULE_CLAUSE_KINDS.map((k) => (
                  <button type="button" key={k.kind} className="rw-choice" onClick={() => addClause(k.kind)}>
                    <span className="rw-choice-mark plus" aria-hidden="true">+</span>
                    <span className="rw-choice-body">
                      <span className="rw-choice-title">{k.label}</span>
                      <span className="rw-choice-note">{k.hint}</span>
                    </span>
                  </button>
                ))}
              </div>
            ) : (
              <React.Fragment>
                <div className="rw-clauses">
                  {form.clauses.map((c) => (
                    <ClauseRow
                      key={c.key}
                      clause={c}
                      usedKinds={usedKinds}
                      autoFocus={c.key === focusKey}
                      onSubmit={next}
                      onChange={(nc) => set({ clauses: form.clauses.map((x) => (x.key === c.key ? nc : x)) })}
                      onRemove={() => set({ clauses: form.clauses.filter((x) => x.key !== c.key) })}
                    />
                  ))}
                </div>
                <div className="rw-addrow">
                  <span className="muted" style={{ fontSize: "var(--t-3)" }}>and</span>
                  {RULE_CLAUSE_KINDS.filter((k) => k.repeatable || !usedKinds.has(k.kind)).map((k) => (
                    <button type="button" key={k.kind} className="btn sm" onClick={() => addClause(k.kind)}>
                      + {k.label}
                    </button>
                  ))}
                </div>
                <div className="rw-preview">
                  <span className="rf-label">Reads as</span>
                  <span>{preview}</span>
                </div>
              </React.Fragment>
            )}
          </div>
        ) : null}

        {s.key === "context" ? (
          <div className="rw-stack">
            <div className="rf-field">
              <span className="rf-label">Only after</span>
              <ChoiceCards
                ariaLabel="Preceding taint"
                value={form.taint}
                onPick={(taint) => set({ taint })}
                columns={2}
                options={CUSTOM_TAINTS.map((t) => ({
                  value: t.value,
                  label: t.value === "" ? "Any time" : t.label.replace(/^after /, "After "),
                  note:
                    t.value === ""
                      ? "The call alone is enough."
                      : t.value === "injection"
                        ? "A flow rule the guard can also hold, through the escalation switch in Settings."
                        : "A flow rule — evidence only. The radar records it; the guard has no such taints to act on.",
                }))}
              />
            </div>
            <label className="rf-field">
              <span className="rf-label">Only under directory <span className="muted" style={{ textTransform: "none", letterSpacing: 0 }}>· optional</span></span>
              <input
                type="text"
                className="mono"
                placeholder="/Users/me/repos/acme"
                value={form.cwd_prefix}
                onChange={(e) => set({ cwd_prefix: e.target.value })}
              />
              <span className="rf-hint">Leave empty for every project.</span>
            </label>
          </div>
        ) : null}

        {s.key === "response" ? (
          <div className="rw-stack">
            <div className="rf-field">
              <span className="rf-label">Severity</span>
              <ChoiceCards
                ariaLabel="Severity"
                value={form.severity}
                onPick={(severity) => set({ severity })}
                columns={4}
                options={[
                  { value: "critical", label: "Critical", note: "Act now.", dot: true, tone: "sev-critical" },
                  { value: "high", label: "High", note: "Worth a hold.", dot: true, tone: "sev-high" },
                  { value: "medium", label: "Medium", note: "Look this week.", dot: true, tone: "sev-medium" },
                  { value: "low", label: "Low", note: "Good to know.", dot: true, tone: "sev-low" },
                ]}
              />
            </div>
            <div className="rf-field">
              <span className="rf-label">Guard</span>
              <div className="rw-moderow">
                {/* Not frozen when the guard is off: this is the mode being
                    WRITTEN, and saving observe over the person's choice would
                    lose it. The rule's row shows what is in force. */}
                <ModeSeg value={form.mode} onChange={(mode) => set({ mode })} />
                <span className="rw-modewords">{modeWords[form.mode]}</span>
              </div>
              {flowOnly ? (
                <div className="callout" style={{ marginTop: "var(--s4)" }}>
                  This rule fires only after a {form.taint.replace(/_/g, " ")} taint, which the guard cannot see — it is evidence on the radar,
                  and the mode is kept for the day it can act.
                </div>
              ) : guardOff ? (
                <div className="callout" style={{ marginTop: "var(--s4)" }}>
                  The guard is off, so nothing is held yet. The mode is saved and takes effect the moment the guard is on.
                </div>
              ) : null}
            </div>
          </div>
        ) : null}

        {s.key === "review" ? (
          <div className="rw-stack">
            <dl className="rw-review">
              <div className="rw-rrow">
                <dt>Name</dt>
                <dd>
                  <b>{form.label || "—"}</b> <span className="chip mono">custom:{derivedId}</span>
                  {form.blurb ? <div className="muted" style={{ fontSize: "var(--t-2)" }}>{form.blurb}</div> : null}
                </dd>
                <button type="button" className="linkbtn" onClick={() => go(0)}>Edit</button>
              </div>
              <div className="rw-rrow">
                <dt>Catches</dt>
                <dd>{preview}</dd>
                <button type="button" className="linkbtn" onClick={() => go(1)}>Edit</button>
              </div>
              <div className="rw-rrow">
                <dt>Context</dt>
                <dd>
                  {form.taint ? (CUSTOM_TAINTS.find((t) => t.value === form.taint) || {}).label : "any time"}
                  {form.cwd_prefix.trim() ? " · under " + form.cwd_prefix.trim() : " · every project"}
                </dd>
                <button type="button" className="linkbtn" onClick={() => go(2)}>Edit</button>
              </div>
              <div className="rw-rrow">
                <dt>Response</dt>
                <dd className="row" style={{ gap: "var(--s3)" }}>
                  <SeverityBadge severity={form.severity} />
                  <span className={"mode-chip " + (form.mode === "ask" ? "hold" : form.mode === "observe" ? "watch" : form.mode)}>
                    <span className="dot" aria-hidden="true" />
                    {form.mode === "ask" ? "hold & ask" : form.mode === "observe" ? "watch only" : form.mode}
                  </span>
                  {flowOnly ? <span className="muted" style={{ fontSize: "var(--t-3)" }}>radar only</span> : null}
                </dd>
                <button type="button" className="linkbtn" onClick={() => go(3)}>Edit</button>
              </div>
            </dl>

            {(problems || []).length > 0 ? (
              <div className="callout bad" role="alert">
                <b>Couldn't save.</b>
                {problems.map((p, i) => {
                  const at = ruleStepForProblem(p.field);
                  return (
                    <div key={i}>
                      <span className="mono">{p.field}</span>: {p.message}
                      {at < 4 ? (
                        <React.Fragment>
                          {" "}— <button type="button" className="linkbtn" onClick={() => go(at)}>fix in {RULE_STEPS[at].label}</button>
                        </React.Fragment>
                      ) : null}
                    </div>
                  );
                })}
              </div>
            ) : null}

            <div className={"rw-dry" + (dry && !dry.loading ? (dry.matches > 50 ? " hot" : dry.files === 0 ? "" : dry.matches > 0 ? " warm" : " good") : "")}>
              <div className="rw-dryhead">
                <span className={"rw-drydot" + (dry && dry.loading ? " running" : "")} aria-hidden="true" />
                <div className="rw-drytext">
                  <b>Dry run</b> <span className="muted">· the last 14 days of transcripts</span>
                  {dry && dry.loading ? (
                    <span className="muted"> · <Working active label="running" idle="" /></span>
                  ) : null}
                </div>
                <button type="button" className="btn sm" disabled={!!(dry && dry.loading) || !form.label.trim()} onClick={onDryRun}>
                  {dry && !dry.loading ? "Run again" : "Run it"}
                </button>
              </div>
              {dry && !dry.loading ? (
                <div className="rw-dryresult">
                  {dry.files === 0 ? (
                    <span><b>Nothing to check against:</b> no agent transcripts from the last {dry.days} days. The rule can still be saved — it just has no history to test on yet.</span>
                  ) : (
                    <span>
                      <b>{dry.matches} match{dry.matches === 1 ? "" : "es"}</b> across {dry.sessions} session{dry.sessions === 1 ? "" : "s"} ({dry.files} transcript files).
                      {dry.matches > 50 ? " That is a lot — narrow the pattern before this rule holds anything." : ""}
                      {dry.matches === 0 ? " Nothing like this happened recently — worth checking the pattern says what you meant." : ""}
                    </span>
                  )}
                  {dry.samples && dry.samples.length > 0 ? (
                    <div className="dry-samples">
                      {dry.samples.map((smp, i) => (
                        <div key={i} className="s-row">
                          <span className="s-when">{relTime(smp.at)}</span>
                          <span className="s-out mono">{smp.tool_name || "tool"}</span>
                          <span className="s-ex mono">{smp.excerpt}</span>
                        </div>
                      ))}
                    </div>
                  ) : null}
                </div>
              ) : (
                <div className="rw-dryresult muted">
                  Would this rule have fired on what your agents actually did? Advice, not a gate: a rule that would have fired
                  three hundred times is a rule to narrow first.
                </div>
              )}
            </div>
          </div>
        ) : null}
      </div>

      <div className="rw-foot">
        <button type="button" className="btn quiet" disabled={saving} onClick={onCancel}>Cancel</button>
        <span className="spacer" />
        {blocker && !last ? <span className="rw-blocker">{blocker}</span> : null}
        {step > 0 ? (
          <button type="button" className="btn" disabled={saving} onClick={() => go(step - 1)}>Back</button>
        ) : null}
        {last ? (
          <button type="button" className="btn primary" disabled={saving || !!ruleStepBlocker(0, form) || !!ruleStepBlocker(1, form)} onClick={onSave}>
            {saving ? "Saving…" : existing ? "Save changes" : "Save rule"}
          </button>
        ) : (
          <button type="button" className="btn primary" disabled={!!blocker} onClick={next}>
            Continue
          </button>
        )}
      </div>
    </div>
  );
}

/** Your rules — the list, and the wizard that writes one. */
function CustomRulesCard({ state, guardOff }) {
  const rules = (state.prefs.policy && state.prefs.policy.custom_rules) || [];
  // null | { form, at, unlocked, existing }
  const [editing, setEditing] = useState(null);
  const [problems, setProblems] = useState([]);
  const [dry, setDry] = useState(null); // null | {loading} | result
  const [saving, setSaving] = useState(false);

  const open = (form, opts) => {
    setEditing({ form, at: (opts && opts.at) || 0, unlocked: !!(opts && opts.unlocked), existing: !!(opts && opts.existing), nonce: Date.now() });
    setDry(null);
    setProblems([]);
  };
  const close = () => {
    setEditing(null);
    setDry(null);
    setProblems([]);
  };
  const setForm = (form) => setEditing((prev) => (prev ? { ...prev, form } : prev));

  const save = (next) => {
    setSaving(true);
    setProblems([]);
    return window.doorman.setCustomRules(next).then((res) => {
      setSaving(false);
      if (res && res.ok) {
        close();
        return true;
      }
      setProblems((res && res.problems) || [{ field: "rule", message: "couldn't save" }]);
      return false;
    });
  };

  const upsert = () => {
    const rule = formToRule(editing.form);
    // Replace by the NEW id and by the id the rule had when it was opened —
    // a renamed rule must not leave its old self behind.
    const others = rules.filter((r) => r.id !== rule.id && r.id !== editing.form.original_id);
    return save([...others, rule]);
  };
  const remove = (id) => save(rules.filter((r) => r.id !== id));
  const setMode = (rule, mode) => save(rules.map((r) => (r.id === rule.id ? { ...r, mode } : r)));
  const toggle = (rule, on) => save(rules.map((r) => (r.id === rule.id ? { ...r, enabled: on } : r)));

  const dryRun = () => {
    setDry({ loading: true });
    setProblems([]);
    window.doorman.dryRunCustomRule(formToRule(editing.form), 14).then((res) => {
      if (res && res.ok) setDry(res);
      else {
        setDry(null);
        setProblems((res && res.problems) || [{ field: "rule", message: "couldn't run" }]);
      }
    });
  };

  const hint = editing
    ? editing.existing
      ? "editing a rule"
      : "new rule"
    : rules.length === 0
      ? "none yet"
      : rules.length + " rule" + (rules.length === 1 ? "" : "s");

  return (
    <Card title="Your rules" hint={hint}>
      {editing ? (
        <WizardPopup title={editing.existing ? "Edit rule" : "New rule"} onClose={close}>
        <RuleWizard
          key={editing.nonce}
          form={editing.form}
          setForm={setForm}
          initialStep={editing.at}
          unlocked={editing.unlocked}
          existing={editing.existing}
          problems={problems}
          dry={dry}
          saving={saving}
          guardOff={guardOff}
          onDryRun={dryRun}
          onSave={upsert}
          onCancel={close}
        />
        </WizardPopup>
      ) : null}
      {/* The list stays put while the popup is up — the wizard used to replace it. */}
      <React.Fragment>
          <div className="cardnote" style={{ marginTop: 0 }}>
            A rule is regexes over what a call IS — the tool, its arguments, the shell command, the MCP server — and,
            optionally, what it FOLLOWS in the session. No code runs; unsafe patterns are refused. Custom ids can never
            shadow a shipped rule. A saved rule applies from the next
            tool call — dry run it first to see what it would have caught in your last 14 days.
          </div>

          {rules.length > 0 ? (
            <table className="rows">
              <thead>
                <tr>
                  <th>Rule</th>
                  <th>Fires when</th>
                  <th style={{ width: 250 }}>Mode</th>
                  <th style={{ width: 140 }}></th>
                </tr>
              </thead>
              <tbody>
                {rules.map((r) => (
                  <tr key={r.id} className={r.enabled === false ? "is-off" : ""}>
                    <td>
                      <span className="mono" style={{ fontSize: "var(--t-2)" }}>{r.id}</span>
                      <div className="muted" style={{ fontSize: "var(--t-3)" }}>
                        {r.label}
                        {r.pack ? " · from pack" : ""}
                        {r.after ? " · flow" : ""}
                      </div>
                    </td>
                    <td className="muted" style={{ fontSize: "var(--t-2)" }}>{r.blurb || describeCustomRule(r)}</td>
                    <td>
                      {r.after && r.after.taint !== "injection" ? (
                        <span className="muted" style={{ fontSize: "var(--t-3)" }} title="A flow rule with a non-injection taint is evidence only — the guard has no taints of its own.">
                          radar only
                        </span>
                      ) : (
                        <ModeSeg
                          value={guardOff ? "observe" : r.mode}
                          disabled={saving || guardOff}
                          onChange={(mode) => setMode(r, mode)}
                        />
                      )}
                    </td>
                    <td>
                      <div className="row" style={{ gap: "var(--s2)" }}>
                        <Switch ariaLabel={"Enable " + r.label} on={r.enabled !== false} disabled={saving} onChange={(v) => toggle(r, v)} />
                        <button className="linkbtn" onClick={() => open(ruleToForm(r), { at: RULE_STEPS.length - 1, unlocked: true, existing: true })}>edit</button>
                        <button className="linkbtn danger" onClick={() => remove(r.id)}>delete</button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : null}

          <div className="row" style={{ marginTop: "var(--s4)" }}>
            <button className="btn primary" onClick={() => open({ ...EMPTY_RULE, clauses: [] })}>
              New rule
            </button>
            {problems.length > 0 && !editing ? <span className="perr">{problems.map((p) => p.message).join("; ")}</span> : null}
          </div>
      </React.Fragment>
    </Card>
  );
}

/** The ignore list — the person's exceptions, including the project-scoped
    allows the approval panel writes. */
function ExceptionsCard({ state }) {
  const ignore = (state.prefs.policy && state.prefs.policy.ignore) || [];
  // null | { at, nonce } — the popup is up; `at` is the step it opens on.
  const [adding, setAdding] = useState(null);
  const [form, setForm] = useState(EMPTY_EXCEPTION);
  const [error, setError] = useState(null);
  const [saving, setSaving] = useState(false);
  const now = Date.now();

  const openWizard = (initial, at) => {
    setForm(initial || EMPTY_EXCEPTION);
    setError(null);
    setAdding({ at: at || 0, nonce: Date.now() });
  };
  const closeWizard = () => setAdding(null);

  const add = () => {
    setError(null);
    setSaving(true);
    window.doorman.addIgnoreRule(exceptionFormToRule(form)).then((res) => {
      setSaving(false);
      if (res && res.ok) {
        setAdding(null);
        setForm(EMPTY_EXCEPTION);
      } else setError((res && res.error) || "couldn't add");
    });
  };

  return (
    <Card title="Exceptions" hint={ignore.length === 0 ? "none" : ignore.length + " ignore rule" + (ignore.length === 1 ? "" : "s")}>
      <div className="cardnote" style={{ marginTop: 0 }}>
        A finding whose visible fields match an exception is not raised. "Allow for this project" on the approval panel
        writes one of these — scoped to the call's directory and dated to expire — so a false positive never has to be
        answered by switching a rule off everywhere.
      </div>
      {ignore.length > 0 ? (
        <table className="rows">
          <thead>
            <tr>
              <th>Rule</th>
              <th>Pattern</th>
              <th>Scope</th>
              <th>From</th>
              <th style={{ width: 80 }}></th>
            </tr>
          </thead>
          <tbody>
            {ignore.map((r, i) => {
              const expired = r.expires_at && Date.parse(r.expires_at) <= now;
              return (
                <tr key={i} className={expired ? "is-off" : ""}>
                  <td className="mono" style={{ fontSize: "var(--t-2)" }}>{r.detector || "any rule"}</td>
                  <td className="mono" style={{ fontSize: "var(--t-2)" }}>{r.pattern}</td>
                  <td className="muted" style={{ fontSize: "var(--t-2)" }}>
                    {r.cwd_prefix ? <span className="mono" title={r.cwd_prefix}>{shortPath(r.cwd_prefix)}</span> : "everywhere"}
                    {r.expires_at ? (expired ? " · expired" : " · until " + new Date(r.expires_at).toLocaleDateString("en-US", { month: "short", day: "numeric" })) : ""}
                  </td>
                  <td className="muted" style={{ fontSize: "var(--t-2)" }}>
                    {r.origin === "approval" ? "approval panel" : "you"}
                    {r.note ? <div style={{ fontSize: "var(--t-3)" }}>{r.note}</div> : null}
                  </td>
                  <td>
                    <button className="linkbtn danger" onClick={() => window.doorman.removeIgnoreRule(i)}>
                      remove
                    </button>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      ) : null}
      {adding ? (
        <WizardPopup title="New exception" onClose={closeWizard}>
          <ExceptionWizard
            key={adding.nonce}
            form={form}
            setForm={setForm}
            state={state}
            error={error}
            saving={saving}
            onSave={add}
            onCancel={closeWizard}
            initialStep={adding.at}
          />
        </WizardPopup>
      ) : null}
      <div className="row" style={{ marginTop: "var(--s4)" }}>
        <button className="btn primary" onClick={() => openWizard()}>New exception</button>
      </div>
    </Card>
  );
}

/* ---- The exception wizard ----------------------------------------------------
   Same shape as the rule wizard (rail, one question per step, read-back, the
   same footer), for the smaller decision: what NOT to raise. Four stops rather
   than five — an exception has no name and no response, it has a rule, a
   pattern, a scope and a lifetime. In place of the rule wizard's dry run over
   transcripts it previews live: which of the findings on the Radar right now
   this exception would have hidden, computed with the same haystack and the
   same directory rule the engine uses (securityIgnoreMatcher + cwdWithinPrefix),
   so the number is the truth and not an estimate. */

const EXCEPTION_STEPS = [
  { key: "rule", label: "Rule", title: "Which rule is this an exception to?", lede: "One rule keeps the exception narrow. \"Any rule\" hides every finding the pattern matches, whatever raised it." },
  { key: "match", label: "Match", title: "What should it ignore?", lede: "A case-insensitive regex over the finding's visible fields — rule id, key name, tool, target and the masked excerpt — never the raw value." },
  { key: "scope", label: "Where & how long", title: "Everywhere, or one project? Forever, or for a while?", lede: "A project-scoped, dated exception is how the approval panel writes them — a false positive in one repo never has to be answered by switching a rule off everywhere." },
  { key: "review", label: "Review", title: "Read it back", lede: "An exception applies from the next scan. Findings already on the Radar stay until you triage them; new sightings that match are not raised." },
];

const EXCEPTION_EXPIRY = [
  { value: "", label: "Doesn't expire", note: "Until you remove it." },
  { value: "30", label: "30 days", note: "The approval panel's default for a project allow." },
  { value: "90", label: "90 days", note: "A quarter — long enough to forget it is there." },
];

/* `rule_choice` is the first step's answer — "" until the person picks, so the
   wizard never defaults to the broad option while its own copy advises the
   narrow one. `detector` only counts when the choice is "one". */
const EMPTY_EXCEPTION = { rule_choice: "", detector: "", pattern: "", scoped: false, cwd_prefix: "", expires_days: "", note: "" };

function exceptionDetector(form) {
  return form.rule_choice === "one" && form.detector ? form.detector : "";
}

/** The wizard's form → what rules:ignore-add expects (parseIgnoreRule). */
function exceptionFormToRule(form) {
  const rule = { pattern: form.pattern.trim(), origin: "manual" };
  if (exceptionDetector(form)) rule.detector = exceptionDetector(form);
  if (form.scoped && form.cwd_prefix.trim()) rule.cwd_prefix = form.cwd_prefix.trim().replace(/\/+$/, "");
  if (form.expires_days) rule.expires_at = new Date(Date.now() + Number(form.expires_days) * 86400000).toISOString();
  if (form.note.trim()) rule.note = form.note.trim();
  return rule;
}

/** Why the pattern cannot be saved yet, in the footer's words — mirrors the
    engine's refusals (securityIgnoreMatcher skips a pattern that does not
    compile or that matches the empty string). */
function exceptionPatternProblem(pattern) {
  const p = (pattern || "").trim();
  if (!p) return "Write the pattern to continue.";
  const bad = regexProblem(p);
  if (bad) return bad;
  try {
    if (new RegExp(p, "i").test("")) return "This pattern matches everything — narrow it, or turn the rule off instead.";
  } catch (e) {
    return "That isn't a valid regex.";
  }
  return null;
}

function exceptionStepBlocker(step, form) {
  if (step === 0 && form.rule_choice !== "one" && form.rule_choice !== "any") return "Choose one rule, or any rule, to continue.";
  if (step === 0 && form.rule_choice === "one" && !form.detector) return "Pick the rule.";
  if (step === 1) return exceptionPatternProblem(form.pattern);
  if (step === 2 && form.scoped && !form.cwd_prefix.trim()) return "Name the directory, or choose Everywhere.";
  return null;
}

/** What the engine does with an ignore rule, done here over the findings the
    snapshot carries (the newest 200): the same haystack, the same directory
    rule. The number the Review step shows. */
function exceptionWouldHide(form, findings) {
  const problem = exceptionPatternProblem(form.pattern);
  if (problem) return { rows: [], total: 0 };
  let re;
  try {
    re = new RegExp(form.pattern.trim(), "i");
  } catch (e) {
    return { rows: [], total: 0 };
  }
  const prefix = form.scoped ? form.cwd_prefix.trim().replace(/\/+$/, "") : "";
  const detector = exceptionDetector(form);
  const rows = (findings || []).filter((f) => {
    if (detector && f.detector !== detector) return false;
    if (prefix && !(f.cwd && (f.cwd === prefix || f.cwd.indexOf(prefix + "/") === 0))) return false;
    const hay = [f.detector, f.key_name, f.tool_name, f.target, f.excerpt].filter((x) => typeof x === "string" && x !== "").join(" ");
    return re.test(hay);
  });
  return { rows: rows.slice(0, 5), total: rows.length };
}

function ExceptionWizard({ form, setForm, state, error, saving, onSave, onCancel, initialStep }) {
  const [step, setStep] = useState(initialStep || 0);
  const [reached, setReached] = useState(initialStep || 0);
  const s = EXCEPTION_STEPS[step];
  const last = step === EXCEPTION_STEPS.length - 1;
  const blocker = exceptionStepBlocker(step, form);
  const set = (patch) => setForm({ ...form, ...patch });
  const go = (i) => {
    if (i < 0 || i >= EXCEPTION_STEPS.length) return;
    setStep(i);
    setReached((r) => Math.max(r, i));
  };
  const next = () => {
    if (blocker || last) return;
    go(step + 1);
  };
  const onEnter = (e) => {
    if (e.key === "Enter" && !e.shiftKey && e.target.tagName !== "TEXTAREA") {
      e.preventDefault();
      next();
    }
  };

  const findings = (state.radar && state.radar.findings) || [];
  const policy = state.prefs.policy || {};
  const customRules = (policy.custom_rules || []).filter((r) => r.enabled !== false);
  // The rules that have actually fired on this Mac come first — an exception
  // is almost always written about a finding one has just seen.
  const firedCounts = {};
  findings.forEach((f) => {
    firedCounts[f.detector] = (firedCounts[f.detector] || 0) + 1;
  });
  const ruleOptions = Object.keys(SEC_DETECTORS)
    .map((id) => ({ id, label: SEC_DETECTORS[id].label, fired: firedCounts[id] || 0 }))
    .concat(customRules.map((r) => ({ id: "custom:" + r.id, label: r.label, fired: firedCounts["custom:" + r.id] || 0 })))
    .sort((a, b) => b.fired - a.fired || a.label.localeCompare(b.label));
  const ruleLabel = (id) => (SEC_DETECTORS[id] ? SEC_DETECTORS[id].label : (customRules.find((r) => "custom:" + r.id === id) || {}).label || id);
  // Directories the Radar has seen findings under — the likely scopes, one click each.
  const seenDirs = [];
  findings.forEach((f) => {
    if (f.cwd && seenDirs.indexOf(f.cwd) < 0) seenDirs.push(f.cwd);
  });
  const hide = exceptionWouldHide(form, findings);
  const patternProblem = form.pattern.trim() ? exceptionPatternProblem(form.pattern) : null;
  const expiryLabel = (EXCEPTION_EXPIRY.find((o) => o.value === form.expires_days) || EXCEPTION_EXPIRY[0]).label;

  return (
    <div className="rw" onKeyDown={!last ? onEnter : undefined}>
      <StepRail step={step} reached={reached} flagged={null} onGo={go} steps={EXCEPTION_STEPS} />

      <div className="rw-body" key={s.key}>
        <div className="rw-head">
          <div className="rw-eyebrow">Step {step + 1} of {EXCEPTION_STEPS.length} · new exception</div>
          <h4 className="rw-title">{s.title}</h4>
          <p className="rw-lede">{s.lede}</p>
        </div>

        {s.key === "rule" ? (
          <div className="rw-stack">
            <ChoiceCards
              ariaLabel="Which rule"
              value={form.rule_choice}
              columns={2}
              options={[
                { value: "one", label: "One rule", note: "Only findings this rule raises. The usual choice." },
                { value: "any", label: "Any rule", note: "Every finding the pattern matches, from any rule. Broad — use for a fixtures folder or a test domain." },
              ]}
              onPick={(v) => set({ rule_choice: v, detector: v === "one" ? form.detector || ruleOptions[0].id : form.detector })}
            />
            {form.rule_choice === "one" ? (
              <label className="rf-field">
                <span className="rf-label">Rule</span>
                <select autoFocus value={form.detector} onChange={(e) => set({ detector: e.target.value })}>
                  {ruleOptions.map((o) => (
                    <option key={o.id} value={o.id}>
                      {o.label + (o.fired ? " · " + o.fired + " on the Radar" : "")}
                    </option>
                  ))}
                </select>
                <span className="rf-hint mono">{form.detector}</span>
              </label>
            ) : null}
          </div>
        ) : null}

        {s.key === "match" ? (
          <div className="rw-stack">
            <label className="rf-field">
              <span className="rf-label">Pattern</span>
              <input
                type="text"
                className="rw-big mono"
                style={patternProblem ? { borderColor: "var(--bad)" } : undefined}
                autoFocus
                spellCheck={false}
                placeholder="fixtures/|\\.example$"
                value={form.pattern}
                onChange={(e) => set({ pattern: e.target.value })}
                aria-invalid={patternProblem ? "true" : undefined}
              />
              <span className="rf-hint" style={patternProblem ? { color: "var(--bad)" } : undefined}>
                {patternProblem || "Matched against \"rule key tool target excerpt\" joined by spaces, case-insensitive. Anchor to the excerpt with what you saw on the card."}
              </span>
            </label>
            <ExceptionHidePreview hide={hide} form={form} findings={findings} ruleLabel={ruleLabel} />
          </div>
        ) : null}

        {s.key === "scope" ? (
          <div className="rw-stack">
            <ChoiceCards
              ariaLabel="Where it applies"
              value={form.scoped ? "project" : "everywhere"}
              columns={2}
              options={[
                { value: "project", label: "Only under a directory", note: "The call's working directory must sit under this path. What the approval panel writes." },
                { value: "everywhere", label: "Everywhere", note: "Every project on this Mac." },
              ]}
              onPick={(v) => set({ scoped: v === "project", ...(v === "project" && !form.cwd_prefix && seenDirs.length === 1 ? { cwd_prefix: seenDirs[0] } : {}) })}
            />
            {form.scoped ? (
              <label className="rf-field">
                <span className="rf-label">Directory</span>
                <input
                  type="text"
                  className="mono"
                  autoFocus
                  spellCheck={false}
                  placeholder="/Users/me/repos/acme"
                  value={form.cwd_prefix}
                  onChange={(e) => set({ cwd_prefix: e.target.value })}
                />
                {seenDirs.length > 0 ? (
                  <span className="rf-hint">
                    Seen on the Radar:{" "}
                    {seenDirs.slice(0, 4).map((d) => (
                      <button key={d} type="button" className="linkbtn mono" style={{ marginRight: "var(--s3)" }} title={d} onClick={() => set({ cwd_prefix: d })}>
                        {shortPath(d)}
                      </button>
                    ))}
                  </span>
                ) : null}
              </label>
            ) : null}
            <div>
              <span className="rf-label">Expires</span>
              <ChoiceCards ariaLabel="Expiry" value={form.expires_days} columns={3} options={EXCEPTION_EXPIRY} onPick={(v) => set({ expires_days: v })} />
            </div>
            <label className="rf-field">
              <span className="rf-label">Note <span className="muted" style={{ textTransform: "none", letterSpacing: 0 }}>· optional</span></span>
              <input type="text" value={form.note} placeholder="Why this is fine here" maxLength={200} onChange={(e) => set({ note: e.target.value })} />
              <span className="rf-hint">Shown on the exceptions list, for whoever wonders later.</span>
            </label>
          </div>
        ) : null}

        {s.key === "review" ? (
          <div className="rw-stack">
            <dl className="rw-review">
              <div className="rw-rrow">
                <dt>Rule</dt>
                <dd>
                  {exceptionDetector(form) ? (
                    <React.Fragment>
                      <b>{ruleLabel(exceptionDetector(form))}</b> <span className="chip mono">{exceptionDetector(form)}</span>
                    </React.Fragment>
                  ) : (
                    <b>Any rule</b>
                  )}
                </dd>
                <button type="button" className="linkbtn" onClick={() => go(0)}>Edit</button>
              </div>
              <div className="rw-rrow">
                <dt>Ignores</dt>
                <dd><span className="mono">{form.pattern.trim()}</span></dd>
                <button type="button" className="linkbtn" onClick={() => go(1)}>Edit</button>
              </div>
              <div className="rw-rrow">
                <dt>Where</dt>
                <dd>
                  {form.scoped ? <span className="mono" title={form.cwd_prefix.trim()}>{shortPath(form.cwd_prefix.trim())}</span> : "Everywhere"}
                  {" · " + expiryLabel.toLowerCase()}
                  {form.note.trim() ? <div className="muted" style={{ fontSize: "var(--t-2)" }}>{form.note.trim()}</div> : null}
                </dd>
                <button type="button" className="linkbtn" onClick={() => go(2)}>Edit</button>
              </div>
            </dl>
            <ExceptionHidePreview hide={hide} form={form} findings={findings} ruleLabel={ruleLabel} review />
            {error ? <div className="callout bad" role="alert"><b>Couldn't save.</b> {error}</div> : null}
          </div>
        ) : null}
      </div>

      <div className="rw-foot">
        <button type="button" className="btn quiet" disabled={saving} onClick={onCancel}>Cancel</button>
        <span className="spacer" />
        {blocker && !last ? <span className="rw-blocker">{blocker}</span> : null}
        {step > 0 ? (
          <button type="button" className="btn" disabled={saving} onClick={() => go(step - 1)}>Back</button>
        ) : null}
        {last ? (
          <button type="button" className="btn primary" disabled={saving || !!exceptionStepBlocker(0, form) || !!exceptionStepBlocker(1, form) || !!exceptionStepBlocker(2, form)} onClick={onSave}>
            {saving ? "Saving…" : "Save exception"}
          </button>
        ) : (
          <button type="button" className="btn primary" disabled={!!blocker} onClick={next}>
            Continue
          </button>
        )}
      </div>
    </div>
  );
}

/** "This would hide N of the findings on the Radar", with the first few named
    — the exception wizard's stand-in for the rule wizard's dry run, live. */
function ExceptionHidePreview({ hide, form, findings, ruleLabel, review }) {
  const ready = !exceptionPatternProblem(form.pattern);
  const tone = !ready ? "" : hide.total === 0 ? "" : hide.total > 20 ? " hot" : " warm";
  return (
    <div className={"rw-dry" + tone}>
      <div className="rw-dryhead">
        <span className="rw-drydot" aria-hidden="true" />
        <div className="rw-drytext">
          <b>On the Radar now</b> <span className="muted">· the newest {Math.min(findings.length, 200)} findings</span>
        </div>
      </div>
      {!ready ? (
        <div className="rw-dryresult muted">Write the pattern and this says which current findings it would have hidden.</div>
      ) : (
        <div className="rw-dryresult">
          {hide.total === 0 ? (
            <span>
              <b>Hides nothing that is on the Radar now.</b>
              {findings.length === 0 ? " There are no findings yet to check against." : " Fine for a case you expect later — but if you wrote this about a finding you just saw, the pattern may not match its visible fields."}
            </span>
          ) : (
            <span>
              <b>Would hide {hide.total} of {findings.length} finding{findings.length === 1 ? "" : "s"}.</b>
              {hide.total > 20 ? " That is a lot for one exception — a narrower pattern, one rule or one directory keeps the Radar honest." : ""}
              {review ? " They stay listed until you triage them; new sightings like them are not raised." : ""}
            </span>
          )}
          {hide.rows.length > 0 ? (
            <div style={{ marginTop: "var(--s3)", display: "grid", gridTemplateColumns: "minmax(0, 11rem) minmax(0, 9rem) minmax(0, 1fr)", columnGap: "var(--s4)", rowGap: "var(--s2)", fontSize: "var(--t-2)" }}>
              {hide.rows.map((f) => (
                <React.Fragment key={f.finding_id}>
                  <span className="muted" style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={f.detector}>{ruleLabel(f.detector)}</span>
                  <span className="mono" style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={f.key_name || f.target || f.tool_name || ""}>{f.key_name || f.target || f.tool_name || "—"}</span>
                  <span className="mono muted" style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={f.excerpt}>{f.excerpt}</span>
                </React.Fragment>
              ))}
            </div>
          ) : null}
        </div>
      )}
    </div>
  );
}
