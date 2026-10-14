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
     Allow + stop asking  — same, plus this rule drops to observe for good.

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
    setBusy(verdict + (options && options.silence ? "-s" : options && options.scope ? "-p" : ""));
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
        {request.tool_name || "tool"}
        {request.target ? " → " + request.target : ""}
      </div>
      {request.context_note ? <div className="ap-context">{request.context_note}</div> : null}
      <Evidence excerpt={request.preview} />
      <div className="ap-actions">
        <button className="btn danger primary" disabled={!!busy} onClick={() => answer("deny")}>
          {busy === "deny" ? "Denying…" : "Deny"}
        </button>
        <button className="btn good" disabled={!!busy} onClick={() => answer("allow")}>
          {busy === "allow" ? "Allowing…" : "Allow once"}
        </button>
        {request.cwd && request.source !== "mcp-gateway" ? (
          <button className="btn quiet" disabled={!!busy} title={"Allow, and don't hold this again under " + request.cwd + " for 30 days"} onClick={() => answer("allow", { scope: "project" })}>
            {busy === "allow-p" ? "Saving…" : "For this project"}
          </button>
        ) : null}
        <span className="spacer" />
        {request.source !== "mcp-gateway" ? (
          <button className="btn quiet" disabled={!!busy} onClick={() => answer("allow", { silence: true })}>
            {busy === "allow-s" ? "Saving…" : "Stop asking"}
          </button>
        ) : null}
      </div>
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
    setBusy(verdict + (options && options.silence ? "-silence" : options && options.scope ? "-project" : ""));
    window.doorman.resolveApproval(request.id, verdict, { ...(options || {}), via: "window" }).then(() => setBusy(null));
  };

  return (
    <div className="approval-scrim">
      <div className="approval" role="alertdialog" aria-modal="true">
        <div className="ap-head">
          <SeverityBadge severity={request.max_severity || "high"} outcome="held" />
          <span className="ap-title">{approvalTitle(request, state)}</span>
          <span className="spacer" />
          {queue.length > 1 ? <span className="chip">1 of {queue.length}</span> : null}
          <ApprovalCountdown request={request} state={state} />
        </div>

        <div className="ap-why">{request.reason}</div>

        <div className="fcols">
          <div className="fc">
            <div className="k">{request.source === "mcp-gateway" ? "MCP tool" : "Tool"}</div>
            <div className="v mono">{request.tool_name || "unknown"}</div>
          </div>
          {request.target ? (
            <div className="fc">
              <div className="k">Target</div>
              <div className="v mono">{request.target}</div>
            </div>
          ) : null}
          <div className="fc">
            <div className="k">Rules</div>
            <div className="v mono">{(request.detectors || []).join(", ") || "—"}</div>
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
              <div className="v mono">{request.server}{request.tool_class ? " · " + request.tool_class : ""}</div>
            </div>
          ) : null}
        </div>

        {request.context_note ? (
          <div className="ap-context">{request.context_note}</div>
        ) : null}

        <div className="ap-label">What the agent is about to run</div>
        <Evidence excerpt={request.preview} />

        <div className="ap-actions">
          <button
            className="btn danger primary"
            disabled={!!busy}
            onClick={() => answer("deny")}
          >
            {busy === "deny" ? "Denying…" : "Deny"}
          </button>
          <button className="btn good" disabled={!!busy} onClick={() => answer("allow")}>
            {busy === "allow" ? "Allowing…" : "Allow once"}
          </button>
          {request.cwd && request.source !== "mcp-gateway" ? (
            <button
              className="btn quiet"
              disabled={!!busy}
              title={"Allow, and don't hold this rule for this exposure again under " + request.cwd + " for 30 days. Listed under Rules → Exceptions."}
              onClick={() => answer("allow", { scope: "project" })}
            >
              {busy === "allow-project" ? "Saving…" : "Allow for this project"}
            </button>
          ) : null}
          <span className="spacer" />
          {request.source !== "mcp-gateway" ? (
            <button className="btn quiet" disabled={!!busy} onClick={() => answer("allow", { silence: true })}>
              {busy === "allow-silence" ? "Saving…" : "Allow and stop asking"}
            </button>
          ) : null}
        </div>

        <div className="ap-foot">{approvalFootnote(request, state)}</div>
      </div>
    </div>
  );
}

/** "Destructive command" / "2 rules" — the detector labels, never the values.
    A custom rule's label travels on the request itself. */
function approvalTitle(request, state) {
  const policy = state && state.prefs ? state.prefs.policy : undefined;
  const labels = request.detector_labels || {};
  const rules = (request.detectors || []).map((d) => labels[d] || detectorMeta(d, policy).label || d);
  if (rules.length === 0) return "Tool call held for review";
  if (rules.length === 1) return rules[0];
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

function shortPath(path) {
  const parts = String(path).split("/").filter(Boolean);
  return parts.length <= 2 ? path : "…/" + parts.slice(-2).join("/");
}

/** Ticks once a second against the request's own deadline, so a re-render or a
    slept laptop can't desynchronise it from what the guard will actually do. */
function ApprovalCountdown({ request, state }) {
  const deadline = Date.parse(request.at) + (request.hold_seconds || 60) * 1000;
  const [left, setLeft] = useState(Math.max(0, Math.round((deadline - Date.now()) / 1000)));

  useEffect(() => {
    const tick = setInterval(
      () => setLeft(Math.max(0, Math.round((deadline - Date.now()) / 1000))),
      1000,
    );
    return () => clearInterval(tick);
  }, [deadline]);

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
