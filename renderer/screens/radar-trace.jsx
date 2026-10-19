/* TRACE A SECRET — the Radar run backwards (main/lib/secret-trace.ts).

   The Radar starts from a rule and says "a credential was exposed here". This
   view starts from the CREDENTIAL you have in your hand — the key a provider
   just warned you about, the password you are about to rotate — and answers
   the inverse: everywhere an AI tool on this Mac has touched it, what happened
   to it in each place, and what to do first.

   Shape of the answer, worst fact first:
     1. the verdict — one sentence with the number ("Found in 7 places across
        3 sessions") or the honest negative ("Not found on this Mac"), and
        under it what that covers, so a zero is never mistaken for proof;
     2. the consequences — facts, each a dot and one sentence: which model
        providers it reached, which files an agent wrote it into, how many
        shell commands carried it, what Guardrails did, whether redaction
        recognizes its shape;
     3. act on it — rotate at the provider, copy the masked report;
     4. the sightings, grouped by the project they happened in, each one a
        click into the Event Ledger at that turn.

   The value: typed masked, sent to main once, and dropped the moment the
   answer arrives — what stays on screen is its last few characters. */

/* Something typed into a search box that is a credential, not a search: a
   known prefix, or a long single token mixing letters and digits. The ledger
   uses this to offer a trace instead of a text search. */
function looksLikeSecret(text) {
  const t = String(text || "").trim();
  if (t.length < 16 || /\s/.test(t)) return false;
  if (/^(sk-|AKIA|ASIA|gh[pousr]_|github_pat_|xox[abposr]-|xapp-|glpat-|whsec_|[sr]k_(live|test)_|pk_(live|test)_|eyJ[A-Za-z0-9_-]{10,}\.|AIza|hf_|npm_|pypi-|dop_v1_|SG\.|xai-|gsk_|pplx-|lin_api_)/.test(t)) return true;
  return t.length >= 24 && /[A-Za-z]/.test(t) && /[0-9]/.test(t) && /^[A-Za-z0-9_\-+/=.~]+$/.test(t) && !/^https?:/.test(t) && !t.includes("/") ;
}

const TRACE_OUTCOME = {
  blocked: { label: "blocked", color: "var(--bad)" },
  held_denied: { label: "held, denied", color: "var(--warn)" },
  held_allowed: { label: "held, allowed", color: "var(--warn)" },
  warned: { label: "warned", color: "var(--gold)" },
  observed: { label: "observed", color: "var(--tan-3)" },
};

const TRACE_KIND_DOT = {
  prompt: "var(--warn)",
  assistant: "var(--tan-3)",
  tool_call: "var(--bad)",
  tool_output: "var(--warn)",
};

function traceDay(iso) {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "";
  return d.toLocaleDateString("en-US", { month: "short", day: "numeric" });
}

function traceWhen(iso) {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "";
  return d.toLocaleString("en-US", { month: "short", day: "numeric", hour: "numeric", minute: "2-digit" });
}

const tracePlural = (n, one, many) => n + " " + (n === 1 ? one : many || one + "s");

function joinList(items) {
  if (items.length <= 1) return items.join("");
  if (items.length === 2) return items[0] + " and " + items[1];
  return items.slice(0, -1).join(", ") + ", and " + items[items.length - 1];
}

/** The headline and the line under it — the verdict, worst fact first. */
function traceVerdict(report) {
  const c = report.coverage;
  const covers =
    tracePlural(c.turns, "turn") +
    " and " +
    tracePlural(c.files_scanned, "transcript file") +
    (c.sources.length > 0 ? " from " + joinList(c.sources) : "") +
    (c.since ? ", back to " + traceDay(c.since) : "");
  if (report.total === 0) {
    return {
      tone: "ok",
      headline: "Not found on this Mac.",
      sub: "Nothing Doorman has read contains it — " + covers + ".",
    };
  }
  const span =
    report.first_at && report.last_at
      ? traceDay(report.first_at) === traceDay(report.last_at)
        ? "on " + traceDay(report.first_at)
        : "from " + traceDay(report.first_at) + " to " + traceDay(report.last_at)
      : "";
  return {
    tone: "bad",
    headline: "Found in " + tracePlural(report.total, "place") + " across " + tracePlural(report.sessions, "session") + ".",
    sub: (span ? "Seen " + span + " · " : "") + "searched " + covers + ".",
  };
}

/** The consequence facts under the verdict — each a dot and one sentence. */
function traceFacts(report) {
  const facts = [];
  const s = report.shape;
  if (report.total > 0) {
    if (report.providers.length > 0) {
      facts.push({
        tone: "bad",
        text:
          "Reached " +
          joinList(report.providers.map((p) => p.provider + " through " + p.label + " in " + tracePlural(p.sessions, "session"))) +
          ".",
      });
    }
    if (report.writes.length > 0) {
      const paths = [...new Set(report.writes.map((w) => w.path))];
      const shown = paths.slice(0, 3).map((p) => shortPathLabel(p));
      facts.push({
        tone: "bad",
        text:
          "Written to disk by an agent: " +
          shown.join(", ") +
          (paths.length > 3 ? " and " + (paths.length - 3) + " more" : "") +
          ".",
      });
    }
    if (report.commands > 0) {
      facts.push({ tone: "warn", text: "Ran inside " + tracePlural(report.commands, "shell command") + "." });
    }
    const o = report.outcomes;
    const acted = o.blocked + o.held_denied + o.held_allowed + o.warned;
    if (acted === 0) {
      facts.push({
        tone: "bad",
        text:
          "No guardrail acted on it — " +
          (report.total === 1 ? "the sighting was" : "all " + report.total + " sightings were") +
          " observed after the fact.",
      });
    } else {
      const parts = [];
      if (o.blocked) parts.push("blocked " + tracePlural(o.blocked, "call"));
      if (o.held_denied) parts.push("held " + tracePlural(o.held_denied, "call") + " you denied");
      if (o.held_allowed) parts.push("held " + tracePlural(o.held_allowed, "call") + " you allowed");
      if (o.warned) parts.push("warned on " + tracePlural(o.warned, "call"));
      facts.push({
        tone: o.observed > 0 ? "warn" : "ok",
        text: "Guardrails " + joinList(parts) + (o.observed > 0 ? "; " + tracePlural(o.observed, "sighting") + " only observed." : "."),
      });
    }
  }
  if (report.blocked_family > 0) {
    facts.push({
      tone: "ok",
      text:
        "Guardrails also blocked " +
        tracePlural(report.blocked_family, "call") +
        " carrying " +
        (s.family ? (/^[aeiou]/i.test(s.label) ? "an " : "a ") + s.label : "a credential") +
        " before it ran — a blocked call never reaches a transcript, so whether it was this one can't be said.",
    });
  }
  facts.push(
    s.recognized
      ? {
          tone: "ok",
          text:
            "Redaction recognizes this shape" +
            (s.family ? " (" + s.label + ")" : "") +
            " — a copied prompt or report carries a placeholder, never the value.",
        }
      : {
          tone: report.total > 0 ? "bad" : "warn",
          text:
            "Redaction does not recognize this shape" +
            " — a copied prompt or report would carry it verbatim."
        },
  );
  if (report.files.length > 0) {
    facts.push({
      tone: "warn",
      text: "Sits in plain text in " + tracePlural(report.files.length, "transcript file") + " on this Mac.",
    });
  }
  return facts;
}

/** "/Users/x/repos/a/b/.env" → "a/b/.env" — enough of a path to know the file. */
function shortPathLabel(path) {
  const parts = String(path || "").replace(/\/+$/, "").split("/").filter(Boolean);
  if (parts.length <= 3) return parts.join("/");
  return parts.slice(-3).join("/");
}

/* The door on the Radar: one row under the hero, shaped like the field it
   leads to. Any interaction opens the sub page, where the real input takes
   focus — the Radar itself stays a triage screen with nothing to type into. */
function TraceSecretBar({ onOpen, compact, pronounced }) {
  const short = compact || pronounced;
  return (
    <button
      type="button"
      className={"tracebar" + (compact ? " compact" : "") + (pronounced ? " pronounced" : "")}
      onClick={onOpen}
      title={short ? "Paste a key, token or password and see everywhere an AI tool on this Mac has touched it" : undefined}
    >
      {pronounced ? (
        <span className="tracebar-ic" aria-hidden="true">
          <Icon name="key" size={14} />
        </span>
      ) : (
        <Icon name="key" size={14} />
      )}
      <span className="tracebar-label">Trace a secret</span>
      {short ? null : (
        <span className="tracebar-hint">Paste a key, token or password and see everywhere an AI tool on this Mac has touched it</span>
      )}
      <Icon className="tracebar-go" name="chevron" size={13} strokeWidth={2} />
    </button>
  );
}

function TraceSecretView({ state, seed, seedNonce, onBack, onOpenSession }) {
  const [input, setInput] = useState("");
  // null | { done, total } while a trace runs.
  const [progress, setProgress] = useState(null);
  const [report, setReport] = useState(null);
  const [error, setError] = useState(null);
  const [copied, setCopied] = useState(false);
  const inputRef = useRef(null);
  const runningRef = useRef(false);

  useEffect(() => {
    // A progress event can land after the answer (the reply and the events
    // are separate messages), so only a trace still running takes one.
    const off = window.doorman.onTraceProgress
      ? window.doorman.onTraceProgress((p) => {
          if (runningRef.current) setProgress(p);
        })
      : () => {};
    return off;
  }, []);

  const run = (value) => {
    const v = String(value || "");
    if (runningRef.current || v.trim() === "") return;
    runningRef.current = true;
    setError(null);
    setReport(null);
    setProgress({ done: 0, total: 0 });
    window.doorman
      .traceSecret(v)
      .then((res) => {
        if (res && res.ok) {
          setReport(res.report);
          // The value is done with: nothing on screen holds it now.
          setInput("");
        } else {
          setError((res && res.error) || "Couldn't trace it.");
        }
      })
      .catch(() => setError("Couldn't trace it."))
      .finally(() => {
        runningRef.current = false;
        setProgress(null);
      });
  };

  // Opened with a value in hand (a finding's revealed secret, the ledger's
  // search box): trace it straight away; opened empty, the field takes focus.
  // The nonce makes a repeat distinct.
  useEffect(() => {
    if (seed) run(seed);
    else if (inputRef.current) inputRef.current.focus();
  }, [seedNonce]);

  useEffect(() => {
    if (!copied) return;
    const t = setTimeout(() => setCopied(false), 1400);
    return () => clearTimeout(t);
  }, [copied]);

  const submit = (e) => {
    e.preventDefault();
    run(input);
  };

  const reset = () => {
    setReport(null);
    setError(null);
    setInput("");
    setTimeout(() => inputRef.current && inputRef.current.focus(), 0);
  };

  const copy = () => {
    if (!report) return;
    Promise.resolve(navigator.clipboard.writeText(report.markdown))
      .then(() => setCopied(true))
      .catch(() => setCopied(false));
  };

  const running = progress !== null;
  const tooShort = input.trim().length > 0 && input.trim().length < 8;

  return (
    <div className="trace">
      <div className="trace-nav">
        <button className="linkbtn" onClick={onBack}>
          ← Security Radar
        </button>
      </div>

      {/* The ask. Once an answer is on screen the field gives way to the
          value's shape — the last characters and the family — and a way to
          trace another; the value itself is gone. */}
      {report ? (
        <div className="trace-shape">
          <span className="trace-fp mono" title={report.shape.length + " characters"}>
            <span className="trace-fp-mask">{"•".repeat(Math.max(4, Math.min(12, report.shape.length - report.shape.tail.length)))}</span>
            {report.shape.tail}
          </span>
          <span className="trace-shape-label">
            {report.shape.label[0].toUpperCase() + report.shape.label.slice(1)} · {report.shape.length} characters
          </span>
          <span className="spacer" />
          <button className="linkbtn" onClick={reset}>
            Trace another
          </button>
        </div>
      ) : (
        <form className="trace-form" onSubmit={submit}>
          <p className="trace-lead">
            Paste a key, token or password — or the last characters your provider's console shows — and see everywhere an AI tool on this Mac has touched it.
          </p>
          <div className="trace-row">
            <input
              ref={inputRef}
              className="trace-input mono"
              type="text"
              autoComplete="off"
              autoCorrect="off"
              autoCapitalize="off"
              spellCheck={false}
              placeholder="Paste the value, or 8+ characters of it"
              aria-label="Secret to trace"
              value={input}
              disabled={running}
              onChange={(e) => setInput(e.target.value)}
            />
            <button className="btn primary" type="submit" disabled={running || input.trim().length < 8}>
              Trace
            </button>
          </div>
          <p className="trace-privacy">
            Matched on this Mac against the transcripts your AI tools wrote and the local turn store. The value is never stored, logged or sent — Doorman AI sees only its shape and where it went.
          </p>
          {tooShort ? <p className="trace-note">At least 8 characters — a shorter fragment matches too much to say anything honest.</p> : null}
          {error ? <p className="evidence-note err">{error}</p> : null}
        </form>
      )}

      {running ? (
        <p className="trace-working" aria-live="polite">
          <Working
            active
            label={
              progress.total > 0
                ? "Reading transcripts… " + progress.done + " of " + progress.total
                : "Reading the turn store…"
            }
          />
        </p>
      ) : null}

      {report ? <TraceReportView report={report} state={state} onOpenSession={onOpenSession} onCopy={copy} copied={copied} /> : null}
    </div>
  );
}

function TraceReportView({ report, state, onOpenSession, onCopy, copied }) {
  const verdict = traceVerdict(report);
  const facts = traceFacts(report);
  /* Is there a VS Code on this Mac to open a transcript in? Presence is read at
     boot whether or not the companion extension is switched on, so this link
     appears for anyone with the editor, not only for people using it. */
  const hasEditor = ((state && state.editor_extension && state.editor_extension.hosts) || []).length > 0;
  return (
    <div className="trace-report">
      <div className={"trace-verdict tone-" + verdict.tone}>
        <div className="trace-headline">{verdict.headline}</div>
        <div className="trace-sub">{verdict.sub}</div>
        {report.total === 0 ? (
          <div className="trace-sub muted">
            That covers what your AI tools wrote to disk. A key pasted into a browser or a plain terminal leaves no transcript here.
          </div>
        ) : null}
      </div>

      <div className="facts trace-facts">
        {facts.map((f, i) => (
          <span className={"fact " + f.tone} key={i}>
            <span className="fdot" />
            {f.text}
          </span>
        ))}
      </div>

      {/* Act on it: rotate where the key lives, keep a copy. */}
      <div className="row trace-actions">
        {report.rotate ? (
          <button className="btn primary" onClick={() => window.doorman.openExternal(report.rotate.url)}>
            Rotate at {report.rotate.provider} ↗
          </button>
        ) : null}
        <button className="btn" onClick={onCopy}>
          {copied ? "Copied" : "Copy report"}
        </button>
      </div>

      {report.files.length > 0 ? (
        <div className="trace-files">
          <div className="s-head">Transcript files holding it</div>
          {report.files.map((f) => (
            <div className="trace-file" key={f.path}>
              <RailMark source={f.source} size={13} />
              <span className="mono trace-file-path" title={f.path}>
                {f.path.split("/").filter(Boolean).length > 3 ? "…/" : ""}
                {shortPathLabel(f.path)}
              </span>
              {/* A transcript is a document someone READS; Finder only points
                  at it. Offered only where there is an editor to open it in. */}
              {hasEditor ? (
                <button className="link" onClick={() => window.doorman.openTraceFileInEditor(f.path)}>
                  open in VS Code →
                </button>
              ) : null}
              <button className="link" onClick={() => window.doorman.showTraceFile(f.path)}>
                show in Finder →
              </button>
            </div>
          ))}
        </div>
      ) : null}

      {report.places.map((place) => (
        <div className="trace-place" key={place.key}>
          <div className="trace-place-head">
            <span className="trace-place-name">{place.label}</span>
            <span className="muted">{tracePlural(place.sightings.length, "sighting")}</span>
          </div>
          <div className="sightings trace-sightings">
            {place.sightings.map((s) => {
              const out = TRACE_OUTCOME[s.outcome] || TRACE_OUTCOME.observed;
              return (
                <button
                  type="button"
                  className="s-row trace-srow"
                  key={s.session_id + " " + s.kind + " " + s.turn_id}
                  title={traceWhen(s.at) + " · open this session in the Event Ledger"}
                  onClick={() => onOpenSession(s.session_id, s.finding_id)}
                >
                  <span className="s-dot" style={{ background: TRACE_KIND_DOT[s.kind] || "var(--tan-3)" }} />
                  <span className="s-when">{traceDay(s.at)}</span>
                  <RailMark source={s.source} size={13} />
                  <span className="s-ex trace-how">
                    {s.how}
                    {s.occurrences > 1 ? <span className="muted"> ×{s.occurrences}</span> : null}
                  </span>
                  <span className="s-out" style={{ color: out.color }}>
                    {out.label}
                  </span>
                </button>
              );
            })}
          </div>
        </div>
      ))}
    </div>
  );
}
