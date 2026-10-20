/* Settings — preferences about the app itself: agents asking Doorman over
   MCP, notifications, appearance, the menu bar, privacy & data, updates.

   Protection (Real-time protection, the hold behaviour, the AI re-read, the
   injection escalation) and My wallets live on Guardrails (rules.jsx), next
   to the rules they enforce. The "<os> notifications" row only speaks up when
   the app's own delivery check failed. */

const RETENTION_OPTIONS = [
  { value: 7, label: "7 days" },
  { value: 30, label: "30 days" },
  { value: 90, label: "90 days" },
  { value: 0, label: "Keep everything" },
];

const NOTIFY_OPTIONS = [
  { value: "off", label: "Never" },
  { value: "critical", label: "Critical only" },
  { value: "high", label: "High and up" },
  { value: "medium", label: "Medium and up" },
];

const DIGEST_PERIODS = [
  { key: "daily", label: "Daily" },
  { key: "weekly", label: "Weekly" },
];

/**
 * One digest: a switch, and — only while it is on — the period it lands on,
 * sitting at the switch's left the way the hold window sits beside the hold
 * switch (the inspector-row shape: the qualifying control right next to the
 * action it qualifies).
 *
 * The period is one segmented control rather than a second switch because it
 * is a property OF the digest, not a second setting: two switches for "daily"
 * and "weekly" let a person turn both on, which sent two banners about the
 * same facts. And it is hidden while the digest is off, because a Daily/Weekly
 * pair beside a dead switch is a control that changes nothing.
 *
 * `describe` takes the period and returns the row's sentence, so the copy says
 * when the banner actually arrives instead of a generic line that is wrong for
 * one of the two settings.
 */
function DigestSetting({ title, on, period, onToggle, onPeriod, describe }) {
  const p = period === "daily" ? "daily" : "weekly";
  return (
    <div className="setting digestrow">
      <div className="what">
        <div className="t">{title}</div>
        <div className="d">{describe(p)}</div>
      </div>
      <div className="row hold-controls digest-controls">
        {on ? <Segmented ariaLabel={title + " period"} value={p} options={DIGEST_PERIODS} onPick={onPeriod} /> : null}
        <Switch ariaLabel={title} on={on} onChange={onToggle} />
      </div>
    </div>
  );
}

/** "a", "a and b", "a, b and c". */
function listOf(labels) {
  if (labels.length <= 1) return labels[0] || "";
  return labels.slice(0, -1).join(", ") + " and " + labels[labels.length - 1];
}

/** Where a person turns notifications back on, per OS. Named because "check
 * your system settings" is the sentence that makes someone go looking. */
const NOTIFY_SETTINGS_LABELS = {
  macos: "Open Notification settings",
  windows: "Open Notification settings",
  linux: "Open Notification settings",
};

/* Doorman's own MCP server (main/mcp-install.ts): one switch that registers it
   with the MCP-capable agents on this Mac — Copilot in VS Code and the Copilot
   CLI to start — so an agent can ask the guard before it acts instead of being
   blocked after. Off by default because it writes into the hosts' shared MCP
   configs. The line under the switch names each present host and whether our
   entry is in its document; the host's own trust prompt still stands. */
function McpAnswersCard({ state }) {
  const prefs = state.prefs || {};
  const mcp = state.mcp_server || { enabled: false, hosts: [] };
  const on = prefs.mcp_answers === true;
  const hosts = (mcp.hosts || []).filter((h) => h.present);
  const connected = hosts.filter((h) => h.registered).length;
  const setPref = (patch) => window.doorman.setPrefs(patch);
  const hostLine = (h) =>
    h.label + (h.registered ? " — connected" : h.unreadable ? " — its MCP config could not be read" : " — not registered");
  return (
    <Card
      title="Agents can ask Doorman"
      hint={on && hosts.length ? connected + " of " + hosts.length + " agents connected" : undefined}
    >
      {mcp.error ? (
        <div className="callout bad" style={{ marginBottom: "var(--s4)" }}>
          Couldn't update an MCP config: {mcp.error}
        </div>
      ) : null}
      <div className="setting">
        <div className="what">
          <div className="t">Answer agents over MCP</div>
          <div className="d" title="The host still asks you before its agent uses a new server.">
            Registers Doorman as an MCP server for Copilot (VS Code and CLI): agents can check a call before it runs,
            ask why one was held, and read what {thisMachine(state.platform)} has metered. Read-only, local.
          </div>
          {on && hosts.length ? <div className="d">{hosts.map(hostLine).join(" · ")}</div> : null}
          {on && !hosts.length ? <div className="d">No MCP-capable agent found on {thisMachine(state.platform)} yet.</div> : null}
        </div>
        <Switch ariaLabel="Answer agents over MCP" on={on} onChange={(v) => setPref({ mcp_answers: v })} />
      </div>
    </Card>
  );
}

/* The VS Code companion's switch lives on Integrations (EditorExtensionCard in
   integrations.jsx) since 2026-09-21: it wires one more program into the app,
   like the browser guard beside it, rather than setting a preference about the
   app itself. */

function SettingsScreen({ state, checkNonce }) {
  const prefs = state.prefs;
  const os = PLATFORM_LABELS[state.platform] || "this computer";
  const setPref = (patch) => window.doorman.setPrefs(patch);

  return (
    <div>
      <div className="screen-head">
        <h1>Settings</h1>
      </div>

      <McpAnswersCard state={state} />

      <Card title="Notifications">
        <NotificationDeliveryProblem state={state} os={os} prefs={prefs} />
        <div className="setting">
          <div className="what">
            <div className="t">Held tool calls</div>
            <div className="d">
              Banner for a held call. The floating prompt appears either way. This only silences
              the duplicate in {notificationListName(state.platform)}.
            </div>
          </div>
          <Switch
            ariaLabel="Held tool call banners"
            on={prefs.notify_held !== false}
            onChange={(v) => setPref({ notify_held: v })}
          />
        </div>
        <div className="setting">
          <div className="what">
            <div className="t">Coaching heads-ups</div>
            <div className="d">
              For a rule set to <b>warn</b>: the call runs, and a quiet banner tells you what
              fired and why. Not severity-gated — warn is a choice you made per rule.
            </div>
          </div>
          <Switch
            ariaLabel="Coaching heads-up banners"
            on={prefs.notify_coaching !== false}
            onChange={(v) => setPref({ notify_coaching: v })}
          />
        </div>
        <div className="setting">
          <div className="what">
            <div className="t">Security findings</div>
            <div className="d">Notify when the Radar raises a finding at or above this severity.</div>
          </div>
          <select value={prefs.notify_findings} onChange={(e) => setPref({ notify_findings: e.target.value })}>
            {NOTIFY_OPTIONS.map((o) => (
              <option key={o.value} value={o.value}>{o.label}</option>
            ))}
          </select>
        </div>
        {/* Two digests, each ONE switch and ONE period. It used to be four
            switches — a security row that could only ever be weekly, and a
            daily and a weekly usage row that could both be on, which sent two
            banners about the same usage. The period only appears while the
            digest is on: a Daily/Weekly pair under a switch that is off is a
            control with nothing to control. */}
        {surfaceShown("digests") ? (
        <React.Fragment>
        <DigestSetting
          title="Security digest"
          on={prefs.notify_security_digest !== false}
          period={prefs.security_digest_period}
          onToggle={(v) => setPref({ notify_security_digest: v })}
          onPeriod={(v) => setPref({ security_digest_period: v })}
          describe={(p) =>
            (p === "daily" ? "09:00 every day" : "Mondays at 09:00") +
            " — held and denied calls, rules that fired for the first time, new MCP servers and new external " +
            "destinations over the " + (p === "daily" ? "day" : "week") + ". Quiet " +
            (p === "daily" ? "days" : "weeks") + " say so."
          }
        />
        <DigestSetting
          title="Usage digest"
          on={!!prefs.notify_spend_digest}
          period={prefs.spend_digest_period}
          onToggle={(v) => setPref({ notify_spend_digest: v })}
          onPeriod={(v) => setPref({ spend_digest_period: v })}
          describe={(p) =>
            p === "daily"
              ? "09:00 every day — yesterday's tokens and the 7-day total."
              : "Mondays at 09:00 — the last 7 days' tokens across your local sessions."
          }
        />
        <div className="setting">
          <div className="what">
            <div className="t">Startup digest</div>
            <div className="d">
              One quiet banner when the app starts — today's tokens, the week, open findings. Also
              how the app verifies {os} is delivering notifications at all. Fires on launch, so it has no period.
            </div>
          </div>
          <Switch
            ariaLabel="Startup digest"
            on={prefs.notify_startup_digest !== false}
            onChange={(v) => setPref({ notify_startup_digest: v })}
          />
        </div>
        </React.Fragment>
        ) : null}
      </Card>

      <Card title="Appearance">
        <div className="setting">
          <div className="what">
            <div className="t">Theme</div>
            <div className="d">Auto follows {os}'s light or dark setting and switches with it.</div>
          </div>
          {/* `|| "auto"` matches defaultPrefs: a prefs file from before this
              setting existed follows the OS. */}
          <Segmented
            ariaLabel="Theme"
            value={prefs.appearance || "auto"}
            options={[
              { key: "light", label: "Light" },
              { key: "dark", label: "Dark" },
              { key: "auto", label: "Auto" },
            ]}
            onPick={(v) => setPref({ appearance: v })}
          />
        </div>
      </Card>

      {/* The number beside the tray icon is Tray.setTitle, which only macOS
          draws: on Windows and Linux the setting would change nothing, so the
          card is not shown there. */}
      {state.platform === "macos" ? (
      <Card title="Menu bar">
        <div className="setting">
          <div className="what">
            <div className="t">Show beside the icon</div>
            <div className="d">
              Today's tokens, open security findings (hidden at zero), or the icon alone.
            </div>
          </div>
          {/* `|| "none"` matches defaultPrefs: the menu bar shows the glyph
              alone until someone asks for a number there. */}
          <select value={prefs.tray_display || "none"} onChange={(e) => setPref({ tray_display: e.target.value })}>
            <option value="spend">Today's tokens</option>
            <option value="alerts">Open security findings</option>
            <option value="none">Nothing</option>
          </select>
        </div>
      </Card>
      ) : null}

      <Card title="Privacy & data">
        <div className="setting">
          <div className="what">
            <div className="t">Local retention</div>
            <div className="d">Older turns are pruned from the local store. Transcripts on disk are never touched.</div>
          </div>
          <select
            value={String(prefs.retention_days)}
            onChange={(e) => setPref({ retention_days: Number(e.target.value) })}
          >
            {RETENTION_OPTIONS.map((o) => (
              <option key={o.value} value={String(o.value)}>{o.label}</option>
            ))}
          </select>
        </div>
        <div className="setting">
          <div className="what">
            <div className="t">Data folder</div>
            <div className="d mono">{state.dataDir}</div>
          </div>
          <button className="btn" onClick={() => window.doorman.openDataDir()}>
            {REVEAL_LABELS[state.platform] || "Open folder"}
          </button>
        </div>
        <div className="setting">
          <div className="what">
            <div className="t">What leaves this machine</div>
            <div className="d">
              Nothing. No account, no telemetry — the only network calls are the update check and the injection
              classifier's one-time model download.
            </div>
          </div>
          <span className="chip good">local only</span>
        </div>
      </Card>

      <UpdatesCard state={state} checkNonce={checkNonce} />
    </div>
  );
}

/** "Checking…" stays up at least this long: a check that answers in 80 ms
 * flashed and landed on the line that was already there, so a click looked
 * like it did nothing. */
const UPDATE_CHECK_MIN_MS = 700;
/** How long the answer to a click stays beside the button. */
const UPDATE_ANSWER_MS = 8000;

/** What a finished check found, as the card says it. */
function updateAnswer(u, appVersion) {
  if (u.status === "error") {
    return { kind: "bad", icon: "!", label: "Couldn't check", text: u.message || "The update server couldn't be reached." };
  }
  if (u.status === "unsupported") {
    return { kind: "muted", icon: "–", label: "Not available", text: u.message || "Updates aren't set up for this build." };
  }
  if (u.outdated || u.status === "available" || u.status === "downloading" || u.status === "downloaded" || u.status === "installing") {
    return {
      kind: "new",
      icon: "↓",
      label: u.version ? "v" + u.version + " found" : "Update found",
      text: (u.version ? "Doorman " + u.version : "A newer version") + " is available — downloading it now.",
    };
  }
  return { kind: "good", icon: "✓", label: "Up to date", text: "You're on the latest version, " + appVersion + "." };
}

/* Updates check themselves hourly and install themselves; this card is the
   only place the version is stated (the sidebar carries just the Update now
   control once a download has landed). A click — or the app menu's Check for
   Updates…, which lands here — always ends in an answer beside the button. */
function UpdatesCard({ state, checkNonce }) {
  const u = state.updater;
  const [phase, setPhase] = useState("idle"); // idle | checking | answered
  const [answer, setAnswer] = useState(null);
  const box = useRef(null);
  const timer = useRef(null);
  const run = async () => {
    if (phase === "checking") return;
    clearTimeout(timer.current);
    setPhase("checking");
    setAnswer(null);
    const started = Date.now();
    let after;
    try {
      after = await window.doorman.checkForUpdates();
    } catch (err) {
      after = { status: "error", message: String((err && err.message) || err) };
    }
    const rest = UPDATE_CHECK_MIN_MS - (Date.now() - started);
    if (rest > 0) await new Promise((resolve) => setTimeout(resolve, rest));
    setAnswer(updateAnswer(after || u, state.appVersion));
    setPhase("answered");
    timer.current = setTimeout(() => setPhase("idle"), UPDATE_ANSWER_MS);
  };
  useEffect(() => () => clearTimeout(timer.current), []);
  useEffect(() => {
    if (!checkNonce) return;
    if (box.current && box.current.scrollIntoView) box.current.scrollIntoView({ behavior: "smooth", block: "center" });
    run();
  }, [checkNonce]);

  const checking = phase === "checking" || u.status === "checking";
  const answered = phase === "answered" && answer;
  const percent = Math.round((u.progress && u.progress.percent) || 0);
  /* Outdated is a fact about THIS copy, not about what the updater is doing,
     so it is said in the description (in the warning colour) and stays there
     through a stalled download or a failed check. */
  const line = checking
    ? "Checking for a newer version…"
    : answered
      ? answer.text
      : u.outdated
        ? (u.version ? `v${u.version} is available. ` : "A newer version is available. ") + (u.message || "")
        : u.message || "Checked hourly for a newer version.";

  return (
    <Card title="Updates">
      {/* The scroll target for the app menu's Check for Updates… — inside the
          card, because a wrapper would break the `.card + .card` spacing. */}
      <span ref={box} aria-hidden="true" />
      <div className="setting">
        <div className="what">
          <div className="t">Version {state.appVersion}</div>
          <div className={"d" + (u.outdated && !answered ? " warn" : "")}>
            {line}
            {u.checked_at && !checking ? <span className="upd-when">{" · Last checked " + relTime(u.checked_at)}</span> : null}
          </div>
        </div>
        {u.status === "downloaded" || u.status === "installing" ? (
          <button className="btn primary" onClick={() => window.doorman.installUpdate()}>
            Update now
          </button>
        ) : (
          <div className="upd-actions">
            {answered ? (
              <span className={"upd-answer " + answer.kind} role="status" aria-live="polite">
                <span className="upd-ic" aria-hidden="true">{answer.icon}</span>
                {answer.label}
              </span>
            ) : null}
            <button className="btn" disabled={checking || u.status === "downloading"} aria-busy={checking} onClick={run}>
              {checking
                ? [<span key="s" className="spinner" aria-hidden="true" />, "Checking…"]
                : u.status === "downloading"
                  ? percent + "%"
                  : answered && answer.kind === "bad"
                    ? "Try again"
                    : "Check for updates"}
            </button>
          </div>
        )}
      </div>
      {/* Download progress: the same meter primitive the charts use, one
          segment wide. A finished download installs itself, so the bar's end
          state is the restart, not a button. */}
      {u.status === "downloading" || u.status === "downloaded" || u.status === "installing" ? (
        <div className="setting" style={{ paddingTop: 0 }}>
          <div className="what" style={{ width: "100%" }}>
            <div className="meter" style={{ height: 6 }} role="progressbar" aria-valuemin={0} aria-valuemax={100} aria-valuenow={percent}>
              <span className="mp" style={{ width: Math.max(2, percent) + "%", background: "var(--c1)", transition: "width 300ms ease" }} />
            </div>
            {u.progress && u.progress.total > 0 && u.status === "downloading" ? (
              <div className="d" style={{ marginTop: "var(--s2)" }}>
                {(u.progress.transferred / 1e6).toFixed(0)} of {(u.progress.total / 1e6).toFixed(0)} MB
                {u.progress.bytes_per_second > 0 ? " · " + (u.progress.bytes_per_second / 1e6).toFixed(1) + " MB/s" : ""}
              </div>
            ) : null}
          </div>
        </div>
      ) : null}
    </Card>
  );
}


/**
 * The app checks notification delivery itself — a silent probe or the startup
 * digest at every launch, plus every real banner's failed event — so on a
 * normal day Settings has nothing to say about it and says nothing. This row
 * exists for the two states worth a person's attention:
 *
 * - BLOCKED: macOS answered a banner with a refusal (no authorization, or it
 *   was revoked). Every banner switch below is then a promise the OS won't
 *   keep, so the row names which of them are on.
 * - UNDETERMINED: the last check got no answer (silence, or a platform with no
 *   notifications). Not a refusal — but not proof either, so it is stated
 *   quietly.
 *
 * What it cannot see: a banner macOS accepts and never shows — alert style set
 * to None, a Focus mode, Do Not Disturb. Electron only learns about refusals;
 * those states live in an undocumented bitfield the app does not read. That is
 * exactly the gap the "How to fix this?" ask exists to close: the fix depends
 * on WHICH refusal this is, and only the OS's own error string tells them
 * apart (main's `notificationsContext`).
 *
 * TWO buttons, and no "Check again": the app already
 * re-checks on its own — every launch probes delivery, and every real banner's
 * failed event lands here — so a button asking the person to do what runs on a
 * timer was work with no decision behind it. The row retires itself the moment
 * a check comes back healthy.
 */
function NotificationDeliveryProblem({ state, os, prefs }) {
  const check = state.notification_check || { status: "unknown" };
  const blocked = check.status === "blocked" || state.notifications_blocked;
  const undetermined = !blocked && check.status === "unknown" && !!check.error;
  if (!blocked && !undetermined) return null;
  // The banners this person has asked for — the ones the OS is now dropping.
  const wanted = [
    prefs.notify_held !== false ? "held tool calls" : null,
    prefs.notify_coaching !== false ? "coaching heads-ups" : null,
    prefs.notify_findings && prefs.notify_findings !== "off" ? "security findings" : null,
    prefs.notify_security_digest !== false ? "the " + (prefs.security_digest_period || "weekly") + " security digest" : null,
    prefs.notify_startup_digest !== false ? "the startup digest" : null,
    prefs.notify_spend_digest ? "the " + (prefs.spend_digest_period || "weekly") + " usage digest" : null,
  ].filter(Boolean);
  const detail = blocked
    ? `${os} is refusing Doorman's notifications — held calls still raise the floating prompt and findings appear in the app, but no banner reaches you while it is out of sight.` +
      (wanted.length ? ` On below but not arriving: ${wanted.join(", ")}.` : "")
    : `Couldn't confirm ${os} is delivering notifications — the last check got no answer${check.at ? " " + relTime(check.at) : ""}. The app re-checks at every launch and on the next banner it sends.`;
  return (
    <div className={"callout" + (blocked ? " bad" : "")} style={{ marginBottom: "var(--s4)" }}>
      <div className="setting" style={{ padding: 0, border: 0 }}>
        <div className="what">
          <div className="t">{blocked ? `${os} notifications are blocked` : `${os} notifications unconfirmed`}</div>
          {/* The OS's raw error is for diagnosis, not reading: a tooltip only. */}
          <div className="d" title={check.error ? "System error: " + check.error : undefined}>
            {detail}
          </div>
        </div>
        {/* The fix, and the explanation of the fix. `openNotificationSettings`
            lands on the pane; the ask covers everything the app cannot see
            from here (alert style None, a Focus mode, an unsigned build). */}
        <button className="btn primary" onClick={() => window.doorman.openNotificationSettings()}>
          {NOTIFY_SETTINGS_LABELS[state.platform] || "Open Notification settings"}
        </button>
        <AiAskButton
          compact
          contextRef={{ kind: "notifications" }}
          question={`${os} isn't delivering Doorman's notifications. Walk me through turning them back on, and tell me what else could be silencing them.`}
          title={`${os} notifications`}
        />
      </div>
    </div>
  );
}
