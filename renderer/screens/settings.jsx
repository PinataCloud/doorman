/* Settings — the guard itself (on/off, hold behaviour, the injection
   escalation, its integrity), retention, notifications, privacy, updates.

   Deliberately NOT here (2026-09-05): the injection classifier and the guard's
   credential second opinion. Both run on their defaults (classifier on, second
   opinion off) and are tuned from the environment only — see
   main/lib/policy-env.ts. Likewise the "<os> notifications" row: the app
   checks delivery itself at every launch, so Settings only speaks up when that
   check failed.

   The per-rule detector MODES moved to Security → Rules: they decide
   what gets blocked, and they belong next to the evidence they produce. What
   stays here is INSTALL-level behaviour — whether the guard is wired into the
   two agents at all, and what a held call does while nobody answers. */

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

const HOLD_OPTIONS = [
  { value: 30, label: "30 seconds" },
  { value: 60, label: "1 minute" },
  { value: 120, label: "2 minutes" },
  { value: 300, label: "5 minutes" },
];

/** What the guard's SWITCH is called: "Real time protection" — the Guardrails screen holds the rules, this switch is whether they act in real time — the product's name for
    it everywhere. The strip's dot and the sentence under it carry the STATE, so the
    name does not have to. */
function guardTitle() {
  return "Real time protection";
}

/** "a", "a and b", "a, b and c". */
function listOf(labels) {
  if (labels.length <= 1) return labels[0] || "";
  return labels.slice(0, -1).join(", ") + " and " + labels[labels.length - 1];
}

/**
 * The guard strip's one sentence: which agents it guards, whether any agent
 * on this Mac is left out, and — off — what turning it on would cover. Agents
 * that are not on this Mac are not mentioned at all: "Gemini CLI — not on this
 * Mac" is a fact about the catalog, not about this person's setup.
 */
function guardHostsSentence(hosts, installed) {
  const here = (hosts || []).filter((h) => h.present);
  if (here.length === 0) {
    return installed ? "On, but no supported agent is on this Mac." : "Off — and no supported agent is on this Mac to guard.";
  }
  const names = here.map((h) => h.label);
  if (!installed) {
    return "Off — the Radar's rules only watch. On, it holds or blocks what they catch in " + listOf(names) + " before the tool runs.";
  }
  const guarded = here.filter((h) => h.installed).map((h) => h.label);
  const missing = here.filter((h) => !h.installed).map((h) => h.label);
  let s = guarded.length > 0
    ? "Guarding " + listOf(guarded) + " — flagged tool calls are checked before they run."
    : "On, but not wired into any agent yet.";
  if (missing.length > 0) s += " " + listOf(missing) + (missing.length === 1 ? " is" : " are") + " on this Mac but not wired in yet.";
  if (guarded.includes("Codex")) s += " Restart Codex and trust the hook in /hooks after the first install.";
  return s;
}

/** "Claude Code asks natively; Codex warns and continues because native ask is
    unsupported" — which half a host lands in is its descriptor's
    supportsNativeAsk, not a hard-coded name. */
function fallbackSentence(hosts, confirm) {
  const list = hosts || [];
  const join = (labels, one, many) => labels.join(" and ") + " " + (labels.length === 1 ? one : many);
  const parts = [];
  const ask = list.filter((h) => h.native_ask).map((h) => h.label);
  const noAsk = list.filter((h) => !h.native_ask).map((h) => h.label);
  if (ask.length > 0) parts.push(join(ask, "asks natively", "ask natively"));
  if (noAsk.length > 0) {
    // What a host with no prompt of its own does is the row below this one.
    const strict = !confirm || confirm.unattended !== "continue";
    parts.push(
      strict
        ? join(noAsk, "is denied", "are denied") + " because native ask is unsupported"
        : join(noAsk, "warns and continues", "warn and continue") + " because native ask is unsupported",
    );
  }
  if (parts.length === 0) return "Off uses each agent's own fallback.";
  return "Off uses each agent's fallback: " + parts.join("; ") + ".";
}

/** The sentence under "Deny when Doorman can't ask": which installed hosts it
 * actually changes anything for (those without a native ask). */
function unattendedSentence(hosts, confirm) {
  const list = hosts || [];
  const noAsk = list.filter((h) => !h.native_ask).map((h) => h.label);
  const strict = !confirm || confirm.unattended !== "continue";
  const who = noAsk.length > 0 ? noAsk.join(", ") : "an agent without a prompt of its own";
  if (strict) {
    return (
      "If this app isn't running and the agent can't ask you itself, a held call is denied instead of running — " +
      who + ". Agents with a native prompt (Claude Code, Cursor, Copilot) ask on their own either way."
    );
  }
  return "Off: with this app closed, " + who + " warns and continues — the call runs.";
}

/** The sentence for "the guard has nowhere to live on this machine". */
function noHostSentence(hosts) {
  const labels = (hosts || []).map((h) => h.label);
  if (labels.length === 2) return "Neither " + labels[0] + " nor " + labels[1] + " was found on this machine.";
  if (labels.length === 1) return labels[0] + " was not found on this machine.";
  return "No supported agent (" + labels.join(", ") + ") was found on this machine.";
}

const PLATFORM_LABELS = { macos: "macOS", windows: "Windows", linux: "Linux" };
/** Where a person turns notifications back on, per OS. Named because "check
 * your system settings" is the sentence that makes someone go looking. */
const NOTIFY_SETTINGS_LABELS = {
  macos: "Open Notification settings",
  windows: "Open Notification settings",
  linux: "Open Notification settings",
};
const REVEAL_LABELS = { macos: "Reveal in Finder", windows: "Show in Explorer", linux: "Open folder" };

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
          <div className="d">
            Registers Doorman as an MCP server for Copilot in VS Code and the Copilot CLI. An agent
            can check a tool call before it runs, ask why one was held or blocked, and read what this
            Mac has metered. Read-only and local; the host still asks you before its agent uses a
            new server.
          </div>
          {on && hosts.length ? <div className="d">{hosts.map(hostLine).join(" · ")}</div> : null}
          {on && !hosts.length ? <div className="d">No MCP-capable agent found on this Mac yet.</div> : null}
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

function SettingsScreen({ state, onGoRules }) {
  const prefs = state.prefs;
  const os = PLATFORM_LABELS[state.platform] || "this computer";
  const setPref = (patch) => window.doorman.setPrefs(patch);

  return (
    <div>
      <div className="screen-head">
        <h1>Settings</h1>
      </div>

      <RulesCard state={state} onGoRules={onGoRules} />

      <WalletsCard state={state} />

      <McpAnswersCard state={state} />

      <Card title="Notifications">
        <NotificationDeliveryProblem state={state} os={os} prefs={prefs} />
        <div className="setting">
          <div className="what">
            <div className="t">Held tool calls</div>
            <div className="d">
              Banner for a held call. The floating prompt appears either way — this only silences
              the duplicate in Notification Center.
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

      {/* Updates check themselves hourly and install themselves; this card is
          the only place the version is stated (the sidebar carries just the
          Update now control once a download has landed). */}
      <Card title="Updates">
        <div className="setting">
          <div className="what">
            {/* Outdated is a fact about THIS copy, not about what the updater
                is doing, so it is said in the description (in the warning
                colour) and stays there through a stalled download or a failed
                check — the two cases where "Checking…" would otherwise be the
                whole story. The version line itself stays a plain title: a
                chip jammed against the number read as clutter, not as state. */}
            <div className="t">Version {state.appVersion}</div>
            <div className={"d" + (state.updater.outdated ? " warn" : "")}>
              {state.updater.outdated
                ? (state.updater.version ? `v${state.updater.version} is available. ` : "A newer version is available. ") +
                  (state.updater.message || "")
                : state.updater.message || "Checked hourly for a newer version."}
            </div>
          </div>
          {state.updater.status === "downloaded" || state.updater.status === "installing" ? (
            <button className="btn primary" onClick={() => window.doorman.installUpdate()}>
              Update now
            </button>
          ) : (
            <button
              className="btn"
              disabled={state.updater.status === "checking" || state.updater.status === "downloading"}
              onClick={() => window.doorman.checkForUpdates()}
            >
              {state.updater.status === "checking"
                ? "Checking…"
                : state.updater.status === "downloading"
                  ? Math.round((state.updater.progress && state.updater.progress.percent) || 0) + "%"
                  : "Check for updates"}
            </button>
          )}
        </div>
        {/* Download progress: the same meter primitive the charts use, one
            segment wide. A finished download installs itself, so the bar's end
            state is the restart, not a button. */}
        {state.updater.status === "downloading" || state.updater.status === "downloaded" || state.updater.status === "installing" ? (
          <div className="setting" style={{ paddingTop: 0 }}>
            <div className="what" style={{ width: "100%" }}>
              <div className="meter" style={{ height: 6 }} role="progressbar" aria-valuemin={0} aria-valuemax={100} aria-valuenow={Math.round((state.updater.progress && state.updater.progress.percent) || 0)}>
                <span
                  className="mp"
                  style={{
                    width: Math.max(2, Math.round((state.updater.progress && state.updater.progress.percent) || 0)) + "%",
                    background: "var(--c1)",
                    transition: "width 300ms ease",
                  }}
                />
              </div>
              {state.updater.progress && state.updater.progress.total > 0 && state.updater.status === "downloading" ? (
                <div className="d" style={{ marginTop: "var(--s2)" }}>
                  {(state.updater.progress.transferred / 1e6).toFixed(0)} of {(state.updater.progress.total / 1e6).toFixed(0)} MB
                  {state.updater.progress.bytes_per_second > 0 ? " · " + (state.updater.progress.bytes_per_second / 1e6).toFixed(1) + " MB/s" : ""}
                </div>
              ) : null}
            </div>
          </div>
        ) : null}
      </Card>
    </div>
  );
}

/**
 * The guard — installed or not, its hold behaviour, the injection escalation,
 * and whether it is still as the app left it.
 *
 * This card used to carry the per-rule mode table too. It moved to Security →
 * Rules: Settings is where you go for INSTALL concerns, and the
 * rules that decide what gets blocked belong next to every screen that reports
 * on them. The two halves link to each other, and a half-move would have left
 * an admin checking two places — so the distinction is stated here: install
 * behaviour lives here, per-rule detection policy lives there.
 */
function RulesCard({ state, onGoRules }) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  // The position the switch is TRAVELLING to, or null when it is at rest.
  // Separate from `busy` because they end at different moments: the IPC call
  // resolves when the hook documents are written, but `guard_installed` only
  // becomes true on the next broadcast state — holding the switch pending
  // until the app's own state agrees is what stops it snapping back to "off"
  // for a frame between the two.
  const [pendingGuard, setPendingGuard] = useState(null);
  const installed = state.radar.guard_installed;
  const policy = state.prefs.policy || {};
  const confirm = policy.confirm || { interactive: true, hold_seconds: 60, on_timeout: "deny", unattended: "deny" };
  const integrity = state.radar.integrity;
  const hosts = state.radar.guard_hosts || [];
  const e = enforcingCount(state);

  // The app's own state caught up with what was asked for — the switch is at
  // rest again. Also the release valve for a flip that FAILED: main leaves
  // `guard_installed` where it was, `pendingGuard` still points the other way,
  // and the error callout below says why, so the switch must return to the
  // truth rather than sit striped forever. (A failure clears it directly; this
  // covers the success path and any state change from elsewhere — the doctor
  // re-merging the guard, a second window.)
  useEffect(() => {
    if (pendingGuard != null && installed === pendingGuard) setPendingGuard(null);
  }, [installed, pendingGuard]);

  const toggleGuard = () => {
    // Fires ONCE: the switch is disabled while pending, and this guards the
    // keyboard/double-click path into the same handler.
    if (busy || pendingGuard != null) return;
    const target = !installed;
    setPendingGuard(target);
    setBusy(true);
    setError(null);
    const call = installed ? window.doorman.uninstallGuard() : window.doorman.installGuard();
    call.then((res) => {
      setBusy(false);
      if (res && res.ok === false) {
        setError(res.error || "failed");
        setPendingGuard(null);
      }
      // On success the switch stays pending until `guard_installed` agrees
      // (the effect above) — writing the hooks and the state broadcast that
      // reports them are two different moments.
    });
  };

  return (
    <Card
      title="Security Radar"
      /* No hint while the guard is off: the switch in this very card already
         says so, and the header's red 0/N ratio says it on every security
         screen. */
      hint={installed ? e.enforcing + " of " + e.total + " rules act before a tool runs" : undefined}
    >
      {error ? (
        <div className="callout bad" style={{ marginBottom: "var(--s4)" }}>
          Couldn't update the guard: {error}
        </div>
      ) : null}
      {/* A sync that can't reach the hook documents (usually a settings.json
          someone hand-broke) means the guard on disk is running an OLDER
          policy than the one shown below — the one state this card must
          never be quiet about. */}
      {state.radar.guard_sync_error ? (
        <div className="callout bad" style={{ marginBottom: "var(--s4)" }}>
          The guard's hook entries couldn't be updated: {state.radar.guard_sync_error}
        </div>
      ) : null}
      {/* The other state this card must never be quiet about: the guard's
          entry or bundle is not what the app left. A silent fail-open, made
          loud — with the one action that fixes it. */}
      {integrity && integrity.status === "tampered" ? (
        <div className="callout bad" style={{ marginBottom: "var(--s4)" }}>
          <b>The guard was changed outside this app.</b>{" "}
          {integrity.problems.indexOf("entry_missing") >= 0 ? "Its hook entry is gone. " : ""}
          {integrity.problems.indexOf("entry_altered") >= 0 ? "Its hook entry was rewritten. " : ""}
          {integrity.problems.indexOf("artifact_missing") >= 0 ? "Its plugin files are missing or changed, so the entry points at nothing. " : ""}
          {integrity.problems.indexOf("companion_missing") >= 0 ? "Its consent entry is gone, so the host skips the hook. " : ""}
          {integrity.bundle_modified.length > 0 || integrity.bundle_missing.length > 0
            ? (integrity.healed_bundle ? "Its files were modified and have been restored from the app. " : "Its files were modified. ")
            : ""}
          Nothing is being held until it is reinstalled.
          <div style={{ marginTop: "var(--s3)" }}>
            <button className="btn primary" disabled={busy} onClick={() => { setBusy(true); window.doorman.installGuard().then(() => setBusy(false)); }}>
              {busy ? "Reinstalling…" : "Reinstall the guard"}
            </button>
          </div>
        </div>
      ) : null}

      {/* The guard's state is the first thing this card has to answer — with it
          off, every control below is theatre. So it is a tinted strip, not a
          setting row: amber while the rules are decorative, green while they are
          law, with a switch that IS the state instead of an Install/Uninstall
          verb the reader has to invert ("which state am I in that this button
          would leave?"). Install/uninstall stays async underneath — the switch
          disables while the hooks are being written. */}
      <div className={"guardbar " + (installed ? "on" : "off")}>
        <span className="gdot" aria-hidden="true" />
        <div className="gtext">
          <div className="t">{guardTitle(hosts)}</div>
          {/* One sentence, built from the host registry (main: guard/hosts/
              index.ts) so a new adapter shows up without an edit — but as
              prose, not a ledger. "Claude Code — guarded · Codex — guarded ·
              Cursor — not installed · …" made five rows of the same word; what
              a person wants to know is WHICH agents are covered, and whether
              any that live on this Mac is not. Agents that are not on this Mac
              are simply not mentioned. */}
          <div className="d">{guardHostsSentence(hosts, installed)}</div>
        </div>
        {/* Named for what is happening, not "working…": installing writes
            three hook documents, and the wait is long enough that a person
            deserves to know which direction it is going. */}
        {pendingGuard != null ? (
          <span className="gbusy">{pendingGuard ? "turning on…" : "turning off…"}</span>
        ) : busy ? (
          <span className="gbusy">working…</span>
        ) : null}
        <Switch
          ariaLabel={guardTitle(hosts)}
          on={installed}
          pending={pendingGuard}
          disabled={busy}
          onChange={toggleGuard}
        />
      </div>

      {/* AI-delivered protection: the local model that re-reads what the rules
          catch (lib/injection-classifier.ts). One switch, default on, because
          the fact a reader needs is the privacy one: the model runs in this
          app's process and nothing it reads leaves the Mac. Beside it, WHICH
          model: Doorman's fine-tuned one (the default) or stock Prompt Guard 2.
          The row always names the model that actually RUNS — while the
          fine-tuned one has no download yet, that is stock, and it says so.
          The environment overrides (policy-env.ts) still win when set, and the
          row says so rather than showing a control that changes nothing. */}
      {(() => {
        const assist = state.model_assist || {};
        const ic = assist.injection_classifier || {};
        const envSet = !!assist.env;
        const choice = ic.model_choice || {};
        const modelNote = injectionModelNote(choice);
        const mb = (n) => Math.max(1, Math.round((n || 0) / 1048576));
        // The model's own line: what is on disk, against the build the app
        // pins. "Up to date" is exactly "every pinned file present" — a newer
        // app pins a newer build, the old files miss the pins, the download
        // starts on its own, and this line says so while it runs.
        let status;
        if (ic.downloading) {
          status = (ic.installed ? "Updating the model… " : "Installing the model… ") + mb(ic.downloading.bytes_done) + " of " + mb(ic.downloading.bytes_total) + " MB.";
        } else if (ic.download_error) {
          status = "The model download failed (" + ic.download_error + ") — it retries on its own.";
        } else if (!ic.runtime_present) {
          status = "The on-device runtime is missing from this build.";
        } else if (ic.installed) {
          status = "Model installed and up to date" + (ic.version ? " (build " + ic.version + ")" : "") + ".";
        } else {
          status = "Model not installed yet — it downloads on its own" + (ic.enabled === false ? " once this is on" : "") + ".";
        }
        return (
          <div className={"setting" + (envSet ? " is-off" : "")}>
            <div className="what">
              <div className="t">AI-delivered protection</div>
              <div className="d">
                Doorman's on-device threat model re-reads every tool result a rule flags for injected instructions, so
                plain text is stood down and real injections are held with more confidence. It runs inside this app on this
                Mac — nothing it reads leaves the machine. {status}
                {envSet ? " Set by the environment (DOORMAN_INJECTION_CLASSIFIER) — the switch is read-only." : ""}
              </div>
              {modelNote ? (
                <div className="d injection-model-note" style={{ marginTop: "var(--s2)" }}>
                  {modelNote}
                </div>
              ) : null}
              {/* No "Built with Llama" line here (2026-09-06). The Llama
                  license's attribution is carried where the model is actually
                  named — the Guardrails screen's classifier row — and shipped
                  in full as the LICENSE/NOTICE beside the model files. This row
                  never names it, so the credit read as a stray fragment under a
                  sentence about Doorman's own model. */}
              {/* The bar while it downloads: the same meter the app-update row
                  uses, so the two downloads in this app look like one thing.
                  Only while it runs — a full bar sitting under a finished
                  install is a control nobody needs. The sentence above already
                  carries the MB, so the bar is the shape, not the numbers. */}
              {ic.downloading && ic.downloading.bytes_total > 0 ? (
                <div
                  className="meter"
                  style={{ height: 6, marginTop: "var(--s3)", maxWidth: 360 }}
                  role="progressbar"
                  aria-label="Downloading the on-device threat model"
                  aria-valuemin={0}
                  aria-valuemax={100}
                  aria-valuenow={Math.round((ic.downloading.bytes_done / ic.downloading.bytes_total) * 100)}
                >
                  <span
                    className="mp"
                    style={{
                      width: Math.max(2, Math.round((ic.downloading.bytes_done / ic.downloading.bytes_total) * 100)) + "%",
                      background: "var(--c1)",
                      transition: "width 300ms ease",
                    }}
                  />
                </div>
              ) : null}
            </div>
            <div className="row hold-controls">
              <select
                aria-label="Injection model"
                title={choice.env ? "Set by DOORMAN_INJECTION_CLASSIFIER_MODEL" : "Which on-device model re-reads flagged tool results"}
                disabled={!!choice.env || ic.enabled === false}
                value={choice.selected || "doorman-1"}
                onChange={(e) => window.doorman.setInjectionClassifier({ model: e.target.value })}
              >
                {INJECTION_MODEL_OPTIONS.map((o) => (
                  <option key={o.value} value={o.value}>{o.label}</option>
                ))}
              </select>
              <Switch
                ariaLabel="AI-delivered protection"
                on={ic.enabled !== false}
                disabled={envSet}
                onChange={(v) => window.doorman.setInjectionClassifier({ enabled: v })}
              />
            </div>
          </div>
        );
      })()}

      {/* No Integrity row (2026-09-06). The check still runs at boot, on every
          change to a hook document and every minute for the bundle — but a
          row that reads "installed as the app left it" 99% of the time is a
          row nobody needs, and the 1% is the red banner above with its
          Reinstall button. Setup health on Integrations lists the same checks
          per host with a Fix, so "Check now" has a home there too. */}

      {/* The hold rows describe what the GUARD does with a flagged call, so
          with the guard off they are inert — dimmed and disabled, same as the
          two dependent rows already dim when holding itself is off. */}
      {/* Two rows where there were three (2026-09-06). The hold window is not a
          setting of its own — it is HOW LONG the hold row holds — so it sits in
          that row's control cluster, beside the switch (beautifului.dev's
          inspector rows: one label, the compact controls that qualify it at the
          right). And "if nobody answers" is a yes/no — deny, or fall through to
          the agent's own prompt — so it is a switch, with the agent-by-agent
          fallback sentence as its description while it is off. */}
      <div className={"setting" + (installed ? "" : " is-off")}>
        <div className="what">
          <div className="t">Hold the call and ask here</div>
          <div className="d">
            {installed
              ? "A flagged call waits for your answer in the floating prompt for up to the window on the right."
              : "Needs the guard above — nothing is held while it is off."}
          </div>
        </div>
        <div className="row hold-controls">
          <select
            aria-label="Hold window"
            title="How long the agent waits for your answer before the row below applies"
            disabled={!installed || !confirm.interactive}
            value={String(confirm.hold_seconds)}
            onChange={(e) => window.doorman.setConfirmPolicy({ hold_seconds: Number(e.target.value) })}
          >
            {HOLD_OPTIONS.map((o) => (
              <option key={o.value} value={String(o.value)}>{o.label}</option>
            ))}
          </select>
          <Switch
            ariaLabel="Hold the call and ask here"
            on={!!confirm.interactive}
            disabled={!installed}
            onChange={(v) => window.doorman.setConfirmPolicy({ interactive: v })}
          />
        </div>
      </div>
      <div className={"setting" + (installed && confirm.interactive ? "" : " is-off")}>
        <div className="what">
          <div className="t">Auto-deny if nobody answers</div>
          <div className="d">
            {confirm.on_timeout === "deny"
              ? "Past the hold window the call is denied — the safe answer when you walked away mid-session."
              : fallbackSentence(hosts, confirm)}
          </div>
        </div>
        <Switch
          ariaLabel="Auto-deny if nobody answers"
          on={confirm.on_timeout === "deny"}
          disabled={!installed || !confirm.interactive}
          onChange={(v) => window.doorman.setConfirmPolicy({ on_timeout: v ? "deny" : "ask" })}
        />
      </div>
      {/* An `ask`
          nobody can answer, on a host with no prompt of its own. Default deny
          since 2026-09-10 — "nobody could be asked" is not an approval. Off
          restores the visible warn-and-continue. Independent of the hold switch:
          it also governs holding-off and a mid-hold app quit. */}
      <div className={"setting" + (installed ? "" : " is-off")}>
        <div className="what">
          <div className="t">Deny when Doorman can't ask</div>
          <div className="d">{unattendedSentence(hosts, confirm)}</div>
        </div>
        <Switch
          ariaLabel="Deny when Doorman can't ask"
          on={confirm.unattended !== "continue"}
          disabled={!installed}
          onChange={(v) => window.doorman.setConfirmPolicy({ unattended: v ? "deny" : "continue" })}
        />
      </div>
      {/* The one flow rule the guard CAN act on before the fact: when a tool
          result earlier this session carried an injected instruction, hold the
          next call that could carry it out (network, exec, send, secret read).
          Best-effort — the evidence travels transcript → app → guard, so a call
          inside that window isn't caught; the radar's after-the-fact finding
          stays the complete record. On a gatewayed MCP server the same rule is
          exact: the gateway is in the stream. */}
      <div className={"setting" + (installed && confirm.interactive ? "" : " is-off")}>
        <div className="what">
          <div className="t">Hold the next risky call after an injection</div>
          <div className="d">
            When a tool result carried an injected instruction, hold the session's next
            network / exec / send / secret-read call. Best-effort, near-live — not a guarantee.
          </div>
        </div>
        <Switch
          ariaLabel="Hold the next risky call after an injection"
          on={(state.prefs.policy.armed_escalation ?? true) !== false}
          disabled={!installed || !confirm.interactive}
          onChange={(v) => window.doorman.setConfirmPolicy({ armed_escalation: v })}
        />
      </div>

      <div className="setting">
        <div className="what">
          <div className="t">Guardrails</div>
          <div className="d">
            Which of the {e.total} rules hold, block, warn or only watch — and your own rules, packs and exceptions —
            live on the Guardrails screen, next to the evidence they produce.
          </div>
        </div>
        <button className="btn" onClick={onGoRules}>
          Open detectors →
        </button>
      </div>
    </Card>
  );
}

/* ── My wallets ──────────────────────────────────────────────────────────────
   The custom half of the Crypto wallets & keys family. The person pastes an
   address ONCE; main classifies it, hashes it with a per-machine salt and
   stores the hash under the label they gave it — so prefs.json never lists
   anyone's wallets, and the Radar can still say "your cold storage address
   left in a prompt" by label. Chains and the unknown-address posture are the
   two settings; a web3 developer whose repo is full of contract addresses
   flips the second and keeps only the rows about their own wallets. */
const WALLET_CHAIN_NAMES = {
  btc: "Bitcoin", ltc: "Litecoin", doge: "Dogecoin", bch: "Bitcoin Cash", evm: "Ethereum / EVM", sol: "Solana",
  trx: "TRON", xrp: "XRP", ada: "Cardano", atom: "Cosmos", xlm: "Stellar", ton: "TON", xtz: "Tezos",
  dot: "Polkadot", algo: "Algorand", xmr: "Monero", sui: "Sui", apt: "Aptos",
};
/* Checksum-carrying chains first. Three shapes have no checksum to verify —
   Solana (recorded only when the text around it names it) and the 0x+64-hex
   Sui / Aptos form (every transaction hash looks the same; ships off). */
const WALLET_CHAIN_ORDER = ["btc", "evm", "sol", "ltc", "doge", "bch", "trx", "xrp", "ada", "atom", "xlm", "ton", "xtz", "dot", "algo", "xmr", "sui", "apt"];
const WALLET_SHAPE_ONLY = new Set(["sol", "sui", "apt"]);

function WalletsCard({ state }) {
  const policy = state.prefs.policy || {};
  const wallets = policy.wallets || { chains: WALLET_CHAIN_ORDER.filter((c) => c !== "sui" && c !== "apt"), unknown_address: "observe", own: [] };
  const own = wallets.own || [];
  const chains = new Set(wallets.chains || []);
  const [address, setAddress] = useState("");
  const [label, setLabel] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const [added, setAdded] = useState(null);
  const [removing, setRemoving] = useState(null);
  const [chainsOpen, setChainsOpen] = useState(false);

  const add = () => {
    if (address.trim() === "") return;
    setBusy(true);
    setError(null);
    setAdded(null);
    window.doorman.addWallet(address.trim(), label.trim()).then((res) => {
      setBusy(false);
      if (res && res.ok) {
        setAdded(res.chain_label);
        setAddress("");
        setLabel("");
      } else {
        setError((res && res.error) || "Couldn't add that wallet.");
      }
    });
  };
  const toggleChain = (c, on) => {
    const next = WALLET_CHAIN_ORDER.filter((id) => (id === c ? on : chains.has(id)));
    window.doorman.setWallets({ chains: next });
  };

  return (
    <Card
      title="My wallets"
      hint={own.length === 0 ? "None listed" : own.length + " listed · stored as hashes"}
    >
      <div className="cardnote" style={{ marginTop: 0 }}>
        Tell Doorman which wallet addresses are yours. An address is public by design, but one of yours leaving in a
        prompt or a network call is a different finding from a stranger's — it gets named by the label you give it,
        at high confidence. The address is hashed on this Mac and never stored, synced or shown again.
      </div>

      <div className="setting" style={{ alignItems: "flex-start" }}>
        <div className="what">
          <div className="t">Add a wallet</div>
          <div className="d">
            Bitcoin, Ethereum and other EVM chains, Solana, TRON, XRP, Cardano, Cosmos, Stellar, TON, Tezos, Polkadot,
            Algorand, Monero, Litecoin, Dogecoin, Bitcoin Cash. The chain is read from the address.
          </div>
        </div>
        <input
          type="text"
          placeholder="bc1q… / 0x… / …"
          value={address}
          aria-label="Wallet address"
          autoComplete="off"
          spellCheck={false}
          style={{ width: 260, fontFamily: "var(--mono)", fontSize: "var(--t-2)" }}
          disabled={busy}
          onChange={(e) => setAddress(e.target.value)}
          onKeyDown={(e) => { if (e.key === "Enter") add(); }}
        />
        <input
          type="text"
          placeholder="Label (cold storage)"
          value={label}
          aria-label="Wallet label"
          maxLength={40}
          style={{ width: 160 }}
          disabled={busy}
          onChange={(e) => setLabel(e.target.value)}
          onKeyDown={(e) => { if (e.key === "Enter") add(); }}
        />
        <button className="btn" disabled={busy || address.trim() === ""} onClick={add}>
          {busy ? "Adding…" : "Add"}
        </button>
      </div>
      {error ? <div className="callout bad" style={{ marginTop: "var(--s2)" }}>{error}</div> : null}
      {added ? <div className="callout" style={{ marginTop: "var(--s2)" }}>Added as a {added} wallet. The address itself was not kept.</div> : null}

      {own.map((w) => (
        <div className="setting" key={w.hash}>
          <div className="what">
            <div className="t">{w.label}</div>
            <div className="d">{WALLET_CHAIN_NAMES[w.chain] || w.chain} · hash {w.hash.slice(0, 8)}…</div>
          </div>
          {removing === w.hash ? (
            <React.Fragment>
              <button className="btn danger" onClick={() => { setRemoving(null); window.doorman.removeWallet(w.hash); }}>
                Remove {w.label}
              </button>
              <button className="btn" onClick={() => setRemoving(null)}>Keep</button>
            </React.Fragment>
          ) : (
            <button className="btn" aria-label={"Remove " + w.label} onClick={() => setRemoving(w.hash)}>Remove</button>
          )}
        </div>
      ))}

      <div className="setting">
        <div className="what">
          <div className="t">Addresses that aren't yours</div>
          <div className="d">
            {wallets.unknown_address === "ignore"
              ? "Ignored. Only the wallets listed above can raise a finding — the setting for a repo full of contract addresses."
              : "Recorded on the Radar at medium severity when they appear in a prompt, a tool argument or a network call. Never held."}
          </div>
        </div>
        <Switch
          ariaLabel="Record addresses that aren't yours"
          on={wallets.unknown_address !== "ignore"}
          onChange={(v) => window.doorman.setWallets({ unknown_address: v ? "observe" : "ignore" })}
        />
      </div>

      <div className="setting">
        <div className="what">
          <div className="t">Chains watched</div>
          <div className="d">
            {WALLET_CHAIN_ORDER.filter((c) => chains.has(c)).map((c) => WALLET_CHAIN_NAMES[c]).join(", ") || "None"}
            {". Solana keys carry no checksum and are recorded only when the surrounding text names them; the Sui / Aptos form is every transaction hash too, so it ships off."}
          </div>
        </div>
        <button className="btn" onClick={() => setChainsOpen(!chainsOpen)}>{chainsOpen ? "Done" : "Choose"}</button>
      </div>
      {chainsOpen ? (
        <div className="setting" style={{ flexWrap: "wrap", gap: "var(--s2)" }}>
          {WALLET_CHAIN_ORDER.map((c) => (
            <label key={c} className="chip" style={{ cursor: "pointer", display: "inline-flex", alignItems: "center", gap: 6 }}>
              <input type="checkbox" checked={chains.has(c)} onChange={(e) => toggleChain(c, e.target.checked)} aria-label={WALLET_CHAIN_NAMES[c]} />
              {WALLET_CHAIN_NAMES[c]}{WALLET_SHAPE_ONLY.has(c) ? " (shape only)" : ""}
            </label>
          ))}
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
    ? `${os} is refusing Doorman's notifications — held calls still raise the floating prompt and alerts appear in the app, but no banner reaches you while it is out of sight.` +
      (wanted.length ? ` On below but not arriving: ${wanted.join(", ")}.` : "")
    : `Couldn't confirm ${os} is delivering notifications — the last check got no answer${check.at ? " " + relTime(check.at) : ""}. The app re-checks at every launch and on the next banner it sends.`;
  return (
    <div className={"callout" + (blocked ? " bad" : "")} style={{ marginBottom: "var(--s4)" }}>
      <div className="setting" style={{ padding: 0, border: 0 }}>
        <div className="what">
          <div className="t">{blocked ? `${os} notifications are blocked` : `${os} notifications unconfirmed`}</div>
          <div className="d">
            {detail}
            {check.error ? <span className="mono"> ({check.error})</span> : null}
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
