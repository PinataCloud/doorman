/* The approval overlay — the one piece of this UI that interrupts.

   A tool call is held open in a Claude Code or Codex session RIGHT NOW (or a
   `tools/call` on a gatewayed MCP server); nothing in that session moves until
   this is answered. So it isn't a screen and it isn't a toast: it covers
   whatever you were doing, it cannot be dismissed by clicking away, and it
   counts down out loud, because the countdown ends in a denial.

   Four answers, in the order a person needs them:
     Deny                 — the guard prints deny and the agent drops the call.
     Allow once           — the guard prints NOTHING (see guard.ts rule 2), so
                            the agent's normal approval flow still applies. Said
                            plainly in the footnote rather than hidden, because
                            otherwise the second prompt reads like a bug.
     Allow for this project — same, plus a dated ignore rule scoped to the
                            call's directory (plan A2): the false-positive escape
                            hatch that doesn't switch a rule off everywhere.
     Allow, stop holding  — same, plus this rule drops to Observe for good
                            (asks for a second click).

   Every answer records WHICH surface gave it (`via`) — the floating panel or
   this window — so Analytics can say how fast decisions arrive and from where.

   Everything shown here arrived pre-redacted from the guard; `[redacted:…]`
   placeholders are highlighted the same way the Radar's evidence strip does it. */

/**
 * The floating-panel rendering of a held call: the same decision, sized for a
 * 460px always-on-top window. Buttons are REAL buttons here, which is the whole
 * reason the panel exists — macOS only shows a notification's actions inline
 * when the person has chosen "Alerts" as this app's notification style, and we
 * cannot set that for them.
 */
function ApprovalPanel({ state }) {
  const queue = state.approvals || [];
  const [busy, setBusy] = useState(null);
  if (queue.length === 0) return null;
  const request = queue[0];
  const answer = (verdict, options) => {
    setBusy(approvalBusyKey(verdict, options));
    window.doorman.resolveApproval(request.id, verdict, { ...(options || {}), via: "panel" }).then(() => setBusy(null));
  };
  return (
    <div className="panel">
      <div className="ap-head">
        <SeverityBadge severity={request.max_severity || "high"} outcome="held" />
        <span className="ap-title">{approvalTitle(request, state)}</span>
        <span className="spacer" />
        {queue.length > 1 ? <span className="chip">+{queue.length - 1}</span> : null}
        <ApprovalCountdown request={request} state={state} />
      </div>
      <div className="panel-where mono">
        {request.call_name || (request.tool_name || "tool") + (request.target ? " → " + request.target : "")}
      </div>
      {request.context_note ? <div className="ap-context">{request.context_note}</div> : null}
      {request.description ? <div className="ap-desc" title={request.description}>{request.description}</div> : null}
      <ApprovalPreview key={request.id} request={request} />
      <ApprovalActions key={"actions-" + request.id} request={request} state={state} busy={busy} answer={answer} />
      <div className="ap-foot">
        {approvalFootnote(request, state)}
      </div>
    </div>
  );
}

function ApprovalOverlay({ state }) {
  const queue = state.approvals || [];
  const [busy, setBusy] = useState(null);

  if (queue.length === 0) return null;
  const request = queue[0];

  const answer = (verdict, options) => {
    setBusy(approvalBusyKey(verdict, options));
    window.doorman.resolveApproval(request.id, verdict, { ...(options || {}), via: "window" }).then(() => setBusy(null));
  };
  const why = approvalWhy(request);
  const titleId = "ap-title-" + request.id;

  return (
    <div className="approval-scrim">
      <div className="approval" role="alertdialog" aria-modal="true" aria-labelledby={titleId}>
        <div className="ap-head">
          <SeverityBadge severity={request.max_severity || "high"} outcome="held" />
          <span className="ap-title" id={titleId}>{approvalTitle(request, state)}</span>
          <span className="spacer" />
          {queue.length > 1 ? <span className="chip">1 of {queue.length}</span> : null}
          <ApprovalCountdown request={request} state={state} />
        </div>

        {why ? <div className="ap-why">{why}</div> : null}
        {request.call_name ? <div className="ap-where mono">{request.call_name}</div> : null}

        <div className="fcols">
          <div className="fc">
            <div className="k">{request.source === "mcp-gateway" ? "MCP tool" : "Tool"}</div>
            <div className="v mono">{request.tool_name || "unknown"}</div>
          </div>
          {request.target ? (
            <div className="fc">
              <div className="k">Target</div>
              <div className="v mono">{breakPath(request.target)}</div>
            </div>
          ) : null}
          <div className="fc">
            <div className="k">{(request.detectors || []).length === 1 ? "Rule" : "Rules"}</div>
            <div className="v">{approvalRuleNames(request, state).join(", ") || "—"}</div>
          </div>
          {request.cwd ? (
            <div className="fc">
              <div className="k">Directory</div>
              <div className="v mono ellip" title={request.cwd}>{shortPath(request.cwd)}</div>
            </div>
          ) : null}
          {request.server ? (
            <div className="fc">
              <div className="k">Server</div>
              <div className="v mono">{breakPath(request.server)}{request.tool_class ? " · " + request.tool_class : ""}</div>
            </div>
          ) : null}
        </div>

        {request.context_note ? (
          <div className="ap-context">{request.context_note}</div>
        ) : null}

        <div className="ap-label">What the agent is about to run</div>
        {request.description ? <div className="ap-desc">{request.description}</div> : null}
        <ApprovalPreview key={request.id} request={request} />

        <ApprovalActions key={"actions-" + request.id} request={request} state={state} busy={busy} answer={answer} autoFocus />

        <div className="ap-foot">{approvalFootnote(request, state)}</div>
      </div>
    </div>
  );
}

/** The call as the guard previewed it. The guard cuts a long preview (and
    carries a longer copy); a card that showed the cut part as if it were the
    whole call would ask for an answer about a command nobody can see the end
    of — the egress at the tail of a long `&&` chain. So the cut is said, with
    how much is missing, and the longer copy is one click away. Keyed by the
    request id, so the next call starts cut again. */
function ApprovalPreview({ request }) {
  const [full, setFull] = useState(false);
  const preview = request.preview || "";
  const text = full && request.preview_full ? request.preview_full : preview;
  const omitted = Math.max(request.preview_chars || 0, text.length) - text.length;
  const expandable = !full && (request.preview_full || "").length > preview.length;
  return (
    <div className="ap-preview">
      <Evidence excerpt={text} />
      {omitted > 0 ? (
        <div className="ap-cut">
          {"… " + omitted + (omitted === 1 ? " more character " : " more characters ") + (full ? "the guard did not carry." : "not shown.")}
          {expandable ? (
            <button className="btn quiet" onClick={() => setFull(true)}>Show the full call</button>
          ) : null}
        </div>
      ) : null}
    </div>
  );
}

function approvalBusyKey(verdict, options) {
  return verdict + (options && options.silence ? "-silence" : options && options.scope ? "-project" : "");
}

const AP_MOD_KEY = /Mac/i.test(navigator.platform || "") ? "⌘" : "Ctrl+";

/**
 * The decision buttons, shared by the overlay and the floating panel so both
 * say exactly the same thing. Keyed by request id by the callers, so the
 * silence confirm never carries over to the next held call.
 *
 * "Stop holding" sets the rule to Observe for good — not a per-call answer —
 * so it takes a second click: the first turns the button into a danger
 * confirm for a few seconds, the second commits.
 *
 * Keys while it is shown: Esc denies, Cmd/Ctrl+Enter allows once.
 */
function ApprovalActions({ request, state, busy, answer, autoFocus }) {
  const [confirmSilence, setConfirmSilence] = useState(false);
  const denyRef = useRef(null);
  const rule = approvalTitle(request, state);

  useEffect(() => {
    if (autoFocus && denyRef.current) denyRef.current.focus();
  }, [autoFocus]);

  useEffect(() => {
    if (!confirmSilence) return undefined;
    const t = setTimeout(() => setConfirmSilence(false), 4000);
    return () => clearTimeout(t);
  }, [confirmSilence]);

  useEffect(() => {
    if (busy) return undefined;
    const onKey = (e) => {
      if (e.key === "Escape") {
        e.preventDefault();
        answer("deny");
      } else if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) {
        e.preventDefault();
        answer("allow");
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [busy, answer]);

  return (
    <div className="ap-actions">
      <button ref={denyRef} className="btn danger primary" disabled={!!busy} title="Deny (Esc)" onClick={() => answer("deny")}>
        {busy ? null : <HoldRing request={request} />}
        {busy === "deny" ? "Denying…" : "Deny"}
      </button>
      <button className="btn good" disabled={!!busy} title={"Allow once (" + AP_MOD_KEY + "Enter)"} onClick={() => answer("allow")}>
        {busy === "allow" ? "Allowing…" : "Allow once"}
      </button>
      {request.cwd && request.source !== "mcp-gateway" ? (
        <button
          className="btn quiet"
          disabled={!!busy}
          title={"Allow, and don't hold this rule for this exposure again under " + request.cwd + " for 30 days. Listed under Guardrails → Exceptions."}
          onClick={() => answer("allow", { scope: "project" })}
        >
          {busy === "allow-project" ? "Saving…" : "Allow for this project"}
        </button>
      ) : null}
      <span className="spacer" />
      {request.source !== "mcp-gateway" ? (
        <button
          className={"btn " + (confirmSilence ? "danger" : "quiet")}
          disabled={!!busy}
          title={"Allow this call and set " + rule + " to Observe: it stops holding calls everywhere until you change it in Guardrails."}
          onClick={() => (confirmSilence ? answer("allow", { silence: true }) : setConfirmSilence(true))}
        >
          {busy === "allow-silence" ? "Saving…" : confirmSilence ? "Confirm: stop holding " + rule : "Allow, stop holding " + rule}
        </button>
      ) : null}
      <span className="ap-keys muted" aria-hidden="true">
        <kbd>Esc</kbd> Deny · <kbd>{AP_MOD_KEY}↵</kbd> Allow once
      </span>
    </div>
  );
}

/** The request's reason minus the boilerplate that restates the title: the
    policy's "Doorman flagged this tool call: <rule names>." says nothing the
    head doesn't, but the armed rules' "…: earlier in this session …" does. */
function approvalWhy(request) {
  const reason = (request.reason || "").trim();
  const prefix = "Doorman flagged this tool call:";
  if (!reason.startsWith(prefix)) return reason;
  const rest = reason.slice(prefix.length).trim();
  if (!/^earlier\b/i.test(rest)) return "";
  return rest.charAt(0).toUpperCase() + rest.slice(1);
}

/** Each rule's human name — the detector label, never its id. A custom rule's
    label travels on the request itself. */
function approvalRuleNames(request, state) {
  const policy = state && state.prefs ? state.prefs.policy : undefined;
  const labels = request.detector_labels || {};
  return (request.detectors || []).map((d) => labels[d] || detectorMeta(d, policy).label || d);
}

/** "Destructive command" / "Secret egress + Destructive command". */
function approvalTitle(request, state) {
  const rules = approvalRuleNames(request, state);
  if (rules.length === 0) return "Tool call held for review";
  return rules.join(" + ");
}

/** The host row for a request's `source`, out of the registry the main process
    hands over on the snapshot (radar.guard_hosts). */
function approvalHost(request, state) {
  const hosts = (state && state.radar && state.radar.guard_hosts) || [];
  return hosts.find((h) => h.source === request.source);
}

function approvalAgent(request, state) {
  if (request.source === "mcp-gateway") return "the MCP client";
  const host = approvalHost(request, state);
  if (host) return host.label;
  // A request from a host this build doesn't know: its own id beats somebody
  // else's name.
  return request.source ? request.source : "Claude Code";
}

/** Does this host show its own prompt when we print `ask`? Unknown host →
    treat it as Claude Code's shape, which is what the guard falls back to. */
function hostAsks(request, state) {
  const host = approvalHost(request, state);
  return host ? host.native_ask !== false : request.source !== "codex";
}

/** What allowing means and what the countdown ends in, per source. */
function approvalFootnote(request, state) {
  if (request.source === "mcp-gateway") {
    return (
      "Allowing forwards the call to " + (request.server || "the server") + " exactly as the agent sent it; " +
      "denying answers the agent with an error naming this rule." +
      (request.on_timeout === "deny"
        ? " No answer within the hold window denies the call."
        : " No answer within the hold window forwards the call — there is no agent fallback for an MCP call.")
    );
  }
  // An agent running with its prompts bypassed runs the call the moment it is
  // allowed: saying it "still applies its approval flow" would promise a
  // second check that does not exist.
  if (request.permissions_bypassed) {
    return (
      "Allowing runs it now: " + approvalAgent(request, state) + " runs without its own prompts here." +
      (request.on_timeout === "deny"
        ? " No answer within the hold window denies the call."
        : hostAsks(request, state)
          ? " No answer within the hold window hands the question to " + approvalAgent(request, state) + "."
          : " No answer continues the call with a visible warning.")
    );
  }
  return (
    "Allowing here does not auto-approve the call — Doorman only ever adds a check, so " +
    approvalAgent(request, state) + " still applies its normal approval flow." +
    (request.on_timeout === "deny"
      ? " No answer within the hold window denies the call."
      : hostAsks(request, state)
        ? " No answer within the hold window hands the question to " + approvalAgent(request, state) + "."
        : " No answer continues the " + approvalAgent(request, state) +
          " call with a visible warning; " + approvalAgent(request, state) +
          " has no native PreToolUse ask.")
  );
}

/** The last two parts of a path, with the separator it was written with
    (a Windows path keeps its backslashes). */
function shortPath(path) {
  const text = String(path);
  const sep = text.includes("\\") && !text.includes("/") ? "\\" : "/";
  const parts = text.split(/[\\/]/).filter(Boolean);
  return parts.length <= 2 ? text : "…" + sep + parts.slice(-2).join(sep);
}

/** A long value (a path, a URL) with a line-break opportunity after every
    separator, so it wraps at a folder boundary inside its column instead of
    widening the card. */
function breakPath(text) {
  return String(text)
    .split(/(?<=[\\/])/)
    .flatMap((part, i) => (i === 0 ? [part] : [<wbr key={i} />, part]));
}

/** The hold window as a clock: milliseconds left before the guard gives up
    waiting, re-read once a second against the request's own deadline so a
    re-render or a slept laptop can't desynchronise it from what the guard will
    actually do. `epoch` bumps when ticks were missed (sleep, a throttled
    window) so a time-driven animation can restart at the true position. */
function useHoldClock(request) {
  const hold = (request.hold_seconds || 60) * 1000;
  const deadline = Date.parse(request.at) + hold;
  const [ms, setMs] = useState(() => Math.max(0, deadline - Date.now()));
  const [epoch, setEpoch] = useState(0);

  useEffect(() => {
    let last = Date.now();
    const tick = setInterval(() => {
      const now = Date.now();
      if (now - last > 2500) setEpoch((e) => e + 1);
      last = now;
      setMs(Math.max(0, deadline - now));
    }, 1000);
    return () => clearInterval(tick);
  }, [deadline]);

  return { hold, deadline, ms, epoch };
}

function ApprovalCountdown({ request, state }) {
  const { deadline, ms } = useHoldClock(request);
  const left = Math.round(ms / 1000);

  if (!Number.isFinite(deadline)) return null;
  return (
    <span className={"ap-clock" + (left <= 10 ? " urgent" : "")}>
      {left}s · {request.on_timeout === "deny"
        ? "then denied"
        : request.source === "mcp-gateway"
          ? "then forwarded"
          : hostAsks(request, state)
            ? "then " + approvalAgent(request, state) + " asks"
            : "then " + approvalAgent(request, state) + " warns + continues"}
    </span>
  );
}

/** The hold window drawn on the Deny button: a ring that empties as the
    countdown beside the title runs down (same deadline, same clock). The sweep
    is one linear CSS animation over the whole window, started part-way through
    by a negative delay fixed per epoch; under reduced motion the animation is
    off and the inline offset (re-read each tick) steps once a second instead.
    aria-hidden: the seconds are already read out by ApprovalCountdown. */
function HoldRing({ request }) {
  const { hold, deadline, ms, epoch } = useHoldClock(request);
  // Frozen per epoch: a changing delay would shift a running animation twice.
  const elapsed = useMemo(() => Math.max(0, hold - ms), [epoch, deadline]);
  if (!Number.isFinite(deadline) || hold <= 0) return null;
  return (
    <svg className="ap-ring" width="14" height="14" viewBox="0 0 16 16" aria-hidden="true">
      <circle className="ap-ring-track" cx="8" cy="8" r="6" />
      <circle
        key={epoch}
        className="ap-ring-sweep"
        cx="8"
        cy="8"
        r="6"
        pathLength="100"
        style={{
          strokeDashoffset: 100 * (1 - Math.min(1, ms / hold)),
          animationDuration: hold + "ms",
          animationDelay: -elapsed + "ms",
        }}
      />
    </svg>
  );
}
