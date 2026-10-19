/**
 * The PreToolUse guard entry — what every registered host actually spawns.
 *
 * Hook input arrives as JSON on stdin ({ session_id, tool_name, tool_input, …}).
 * The command's optional `--host <id>` argument selects a registered host's
 * adapter (hosts/index.ts) — its input normalization and its output contract;
 * no argument means Claude Code, which preserves the installed command string
 * and the trust state keyed on it.
 *
 * On an `ask`-mode detector this process does not just answer — it HOLDS. It
 * writes an approval request next to itself, waits for the app to carry the
 * question to a human (handshake.ts), and only then answers. That is the
 * feature: the dangerous call has not run yet while you are deciding.
 *
 * Three rules this file lives by:
 *
 * 1. FAIL OPEN. Any internal error → exit 0 with no output, which lets the
 *    host's own permission system proceed untouched. A security add-on that can
 *    break someone's coding session gets uninstalled, and then protects nobody.
 * 2. NEVER print "allow". This guard adds a check on top of the native flow;
 *    it must not remove one. An approved call therefore prints NOTHING.
 * 3. NO HUMAN, NO HOLD. If the app isn't running there is nobody to ask. A host
 *    with a native ask (Claude Code) gets the question handed back to it. A
 *    host without one (Codex) used to get a visible warning and the call
 *    continued; since 2026-09-10 (`confirm.unattended`, default `deny`) it gets the
 *    host's valid DENY with `resolution: "unavailable"`: an `ask` rule is an
 *    authorization rule, and "nobody could be asked" is not an approval. The
 *    old warning is one setting away (`unattended: "continue"`). Rule 1 still
 *    stands above this: an internal ERROR is not an unattended ask.
 *
 * The app reads policy.json (written next to this file) for modes, and tails
 * spool.jsonl for findings/decisions. Both live in this directory because the
 * whole compiled guard dir is copied to userData at install time — a stable
 * path that survives app updates and relocations.
 */

import { appendFileSync, readFileSync, realpathSync } from "node:fs";
import { redact } from "./redact.js";
import { join } from "node:path";
import { armedEscalation, customArmedEscalation, readArmedTaints } from "./armed.js";
import { ruleShown } from "./rule-scope.js";
import { customDetectorLabels, isCustomDetectorId } from "./custom-rules.js";
import { evaluatePrompt, evaluateToolCall, guardSelfWrite, parsePolicy, type ExceptedFinding, type GuardHookInput } from "./decision.js";
import { decideEnforcement, type GuardFinding } from "./policy.js";
import { secondOpinion, secondOpinionRawText, type SecondOpinionTelemetry } from "./second-opinion.js";
import { MAX_COMMAND_CHARS, sanitizeExcerpt, scanWindow, type SecurityDetectorId } from "./security-detect.js";
import { appListening, presenceTerm, writePresence, type ApprovalResolution } from "./handshake.js";
import { holdForHuman, hostEmit, unattendedOutcome, type HoldTelemetry } from "./hold.js";
import { priorDecision, writeDedup } from "./dedup.js";
import { HOOK_TIMEOUT_SLACK_SECONDS } from "./policy.js";
import { hostForArgv, sourceForPayload } from "./hosts/index.js";
import type { GuardHostDescriptor } from "./hosts/types.js";
import { agentFacingReason, remedyFor, type HoldResolution } from "./remedy.js";

const MAX_STDIN_BYTES = 4 * 1024 * 1024;

/** The self-protection hold's id — not a rule (see decision.ts guardSelfWrite),
 * so it is outside SecurityDetectorId and every rule list. */
const GUARD_SELF_PROTECTION = "guard_self_protection";

/** Calls too large to inspect whole — not a rule either; see UNINSPECTABLE_REASON. */
const GUARD_UNINSPECTABLE = "guard_uninspectable";
const UNINSPECTABLE_REASON = "This call is too large for Doorman to inspect in full, so it was not allowed unseen.";

/** stdin, and whether it was cut at MAX_STDIN_BYTES. A cut payload no longer
 * parses; before, that meant silence — exit 0, which every host reads as allow. */
function readStdin(): Promise<{ text: string; truncated: boolean }> {
  return new Promise((resolve) => {
    const chunks: Buffer[] = [];
    let size = 0;
    process.stdin.on("data", (chunk: Buffer) => {
      size += chunk.length;
      if (size <= MAX_STDIN_BYTES) chunks.push(chunk);
    });
    process.stdin.on("end", () => resolve({ text: Buffer.concat(chunks).toString("utf8"), truncated: size > MAX_STDIN_BYTES }));
    process.stdin.on("error", () => resolve({ text: "", truncated: false }));
  });
}

/** Ask (or, where the host cannot ask, the unattended outcome) with nothing
 * inspected — for input the guard could not read whole. */
function emitUninspectable(guardDir: string, host: GuardHostDescriptor): void {
  let policyJson: string | undefined;
  try {
    policyJson = readFileSync(join(guardDir, "policy.json"), "utf8");
  } catch {
    policyJson = undefined;
  }
  const policy = parsePolicy(policyJson);
  const emitted = hostEmit(host, "ask", UNINSPECTABLE_REASON, policy.confirm.unattended);
  if (emitted.stdout) process.stdout.write(emitted.stdout);
  if (emitted.stderr) process.stderr.write(emitted.stderr);
  exitCode = emitted.exitCode;
}

/** A finding as the spool carries it: a shipped detector's or a custom rule's
 * (whose detector is outside SecurityDetectorId) or the armed escalation's. */
type SpooledFinding = Omit<GuardFinding, "detector"> & { detector: string };

/** One spool line per stage, so a guard killed mid-hold still leaves the
 * detection on record — the resolution line lands later and wins the fold. */
function spool(
  guardDir: string,
  record: {
    session_id?: string;
    /** The host's own `source` string (hosts/<host>.ts) — "claude-code",
     * "codex", and whatever the registry grows next. */
    source: string;
    tool_name?: string;
    cwd?: string;
    decision: string;
    max_severity?: string;
    findings: readonly SpooledFinding[];
    /** Warn-mode detectors that fired — the app raises the coaching banner. */
    warned?: string[];
    /** This call is being held for confirmation — the app owns the banner. */
    held?: boolean;
    resolution?: ApprovalResolution;
    /** Labels for any custom-rule ids in `findings`, so the app can name them
     * without reading the policy back. */
    detector_labels?: Record<string, string>;
    /** The local-model second opinion ran on this call (second-opinion.ts). */
    second_opinion?: SecondOpinionTelemetry;
    /** Findings a scoped exception (policy `ignore`, an approval-panel Allow,
     * a manual exception) dropped BEFORE the decision — recorded so the person can see
     * what their exception let through, never enforced. Each carries the rule
     * that applied. A record with only these has `decision: "allow"`. */
    excepted?: readonly ExceptedFinding[];
  } & Partial<HoldTelemetry>,
): void {
  try {
    appendFileSync(
      join(guardDir, "spool.jsonl"),
      `${JSON.stringify({ at: new Date().toISOString(), ...record })}\n`,
    );
  } catch {
    // Best-effort: a full disk must not block a tool call.
  }
}

/** The process's exit code. Stays 0 for every host whose non-zero exit is
 * ignored or, worse, read as a deny we did not decide — only a descriptor
 * whose emit() says otherwise can change it. */
let exitCode = 0;

async function main(): Promise<void> {
  const guardDir = __dirname;
  const host = hostForArgv(process.argv);
  const read = await readStdin();
  if (read.truncated) {
    emitUninspectable(guardDir, host);
    return;
  }
  const stdin = read.text;
  if (stdin.trim() === "") return;
  let raw: unknown;
  try {
    raw = JSON.parse(stdin);
  } catch {
    return;
  }
  if (!raw || typeof raw !== "object") return;
  // The product behind this payload: the host's own source, or a dialect's
  // (VS Code Copilot Chat calling through the Copilot CLI document).
  const source = sourceForPayload(host, raw);
  // A PROMPT, on a host that fires before the model sees one (Claude Code's
  // UserPromptSubmit): its own path — same redact → detect → fold,
  // `kind: "prompt"`, and a hold or block that stops the prompt itself.
  if (host.normalizePrompt && host.emitPrompt) {
    const prompt = host.normalizePrompt(raw);
    if (prompt) {
      await handlePrompt(guardDir, host, source, prompt);
      return;
    }
  }
  // Every host's payload becomes Claude Code's vocabulary here (hosts/types.ts
  // normalizeInput) — the detectors below key on nothing else.
  const input: GuardHookInput | undefined = host.normalizeInput(raw);
  // Not a tool call this host wants evaluated — silence, exit 0.
  if (!input) return;

  let policyJson: string | undefined;
  try {
    policyJson = readFileSync(join(guardDir, "policy.json"), "utf8");
  } catch {
    policyJson = undefined; // No policy yet — the built-in defaults apply.
  }
  const policy = parsePolicy(policyJson);

  // ONE CALL, ONE DECISION (dedup.ts). A host that fires several events for
  // the same call (Cursor) says so through callIdentity; a later event of a
  // call an earlier one already decided repeats that decision — and one an
  // earlier event is still HOLDING waits for it — instead of holding again.
  // Only across different events: the same call under the same event is a
  // repeat, evaluated afresh. No spool line: the first event's records it.
  const identity = host.callIdentity?.(raw, input);
  if (identity) {
    const prior = await priorDecision(guardDir, host.id, identity);
    if (prior) {
      const nativeAskNow = host.supportsNativeAskFor?.(raw) ?? host.supportsNativeAsk;
      const view: GuardHostDescriptor = nativeAskNow === host.supportsNativeAsk ? host : { ...host, supportsNativeAsk: nativeAskNow };
      const emitted = hostEmit(view, prior.decision, prior.reason, policy.confirm.unattended);
      if (emitted.stdout) process.stdout.write(emitted.stdout);
      if (emitted.stderr) process.stderr.write(emitted.stderr);
      exitCode = emitted.exitCode;
      return;
    }
    // Claim the call before deciding, so a concurrent second event waits.
    writeDedup(guardDir, host.id, identity, {
      event: identity.event,
      decision: "pending",
      at: new Date().toISOString(),
      pending_budget_ms: (policy.confirm.hold_seconds + HOOK_TIMEOUT_SLACK_SECONDS) * 1000,
    });
  }

  // Whether THIS payload's host can ask on its own: a static fact for most
  // hosts, a per-envelope one for OpenClaw (hosts/types.ts supportsNativeAskFor).
  const nativeAsk = host.supportsNativeAskFor?.(raw) ?? host.supportsNativeAsk;
  const hostView: GuardHostDescriptor = nativeAsk === host.supportsNativeAsk ? host : { ...host, supportsNativeAsk: nativeAsk };

  const cwd = typeof input.cwd === "string" ? input.cwd : undefined;
  const result = evaluateToolCall({ ...input, cwd }, policy);
  const { findings, excepted, target, redacted, command } = result;
  let decision = result.decision;
  const sessionId = typeof input.session_id === "string" ? input.session_id : undefined;
  const toolName = typeof input.tool_name === "string" ? input.tool_name : undefined;
  // Presence (handshake.ts): this hook was spawned by the agent whose session
  // id is on stdin, so our parent pid is that agent (or a shell between us).
  // One small file per session, overwritten per call — the app's live
  // sessions rail joins process to session on it.
  if (sessionId) {
    const term = presenceTerm(process.env);
    writePresence(guardDir, {
      session_id: sessionId,
      source,
      pid: process.ppid,
      ...(cwd === undefined ? {} : { cwd }),
      at: new Date().toISOString(),
      ...(term === undefined ? {} : { term }),
    });
  }
  const labels = customDetectorLabels(policy.custom_rules ?? []);

  // Self-protection (decision.ts guardSelfWrite): a call that would change this
  // directory — approve its own hold, rewrite policy.json, replace the guard —
  // is held whatever the policy says. Not a rule, so no hidden-rule, mode,
  // exception or second opinion can stand it down.
  let selfWrite: string | undefined;
  let selfFinding: SpooledFinding | undefined;
  try {
    let real: string | undefined;
    try {
      real = realpathSync(guardDir);
    } catch {
      real = undefined;
    }
    selfWrite = guardSelfWrite(toolName, input.tool_input, cwd, real === undefined ? [guardDir] : [guardDir, real]);
  } catch {
    selfWrite = undefined;
  }
  // A command longer than the detectors' command window (after collapsing
  // padding) had its middle skipped: hold it rather than allow it unseen.
  if (selfWrite === undefined && decision.decision === "allow" && command !== undefined && command.length > MAX_COMMAND_CHARS && scanWindow(command, MAX_COMMAND_CHARS).length > MAX_COMMAND_CHARS) {
    decision = { decision: "ask", reason: UNINSPECTABLE_REASON, max_severity: "high", detectors: [GUARD_UNINSPECTABLE], warned: decision.warned };
    labels[GUARD_UNINSPECTABLE] = "Too large to inspect";
  }
  if (selfWrite !== undefined) {
    decision = {
      decision: "ask",
      reason: `This call would change Doorman's own guard files (${selfWrite.slice(0, 120)}) — approvals, the policy and the guard live there.`,
      max_severity: "critical",
      detectors: [GUARD_SELF_PROTECTION],
      warned: decision.warned,
    };
    labels[GUARD_SELF_PROTECTION] = "Guard self-protection";
    selfFinding = {
      detector: GUARD_SELF_PROTECTION,
      severity: "critical",
      key_name: "writes to the guard directory",
      excerpt: sanitizeExcerpt(redact(selfWrite)).slice(0, 160),
      occurrences: 1,
      ...(toolName === undefined ? {} : { tool_name: toolName }),
      ...(target === undefined ? {} : { target }),
    };
  }

  // Armed-session escalation (armed.ts): the app's flow engine saw an injected
  // instruction arrive in this session, and this call matches a sink it could
  // be steering — escalate to ask. Only from allow: a call already held or
  // denied by a per-call rule doesn't need a second reason.
  const spooled: SpooledFinding[] = [...findings, ...(selfFinding === undefined ? [] : [selfFinding])];
  if (policy.armed_escalation !== false && decision.decision === "allow" && sessionId) {
    const taints = readArmedTaints(guardDir, sessionId);
    // The shipped escalation holds under `flow_injection_followed`. A hold is
    // the one thing a hidden rule (guard/rule-scope.ts) may never do,
    // so while that rule is out of scope the escalation stands down; a
    // person's own armed custom rule below is theirs and still fires.
    const escalated = ruleShown("flow_injection_followed") ? armedEscalation(taints, toolName, input.tool_input, target) : undefined;
    if (escalated) {
      decision = {
        decision: "ask",
        reason: escalated.reason,
        max_severity: "critical",
        // The flow id rides the detectors list so the approval card names the
        // rule; it can never be "silenced" into the policy (index.ts filters
        // silenced detectors against ALL_DETECTORS, which excludes it).
        detectors: [escalated.detector],
        warned: decision.warned,
      };
      spooled.push({
        detector: escalated.detector,
        severity: "critical",
        key_name: escalated.key_name,
        excerpt: escalated.excerpt,
        occurrences: 1,
        ...(toolName === undefined ? {} : { tool_name: toolName }),
        ...(target === undefined ? {} : { target }),
      });
    } else {
      // A person's own `when` + `after: injection` rule, armed the same way.
      const custom = customArmedEscalation(taints, policy.custom_rules, {
        tool_name: toolName,
        tool_input: input.tool_input,
        command,
        target,
        cwd,
        redacted,
      });
      if (custom) {
        decision = {
          decision: custom.mode === "block" ? "deny" : "ask",
          reason: custom.reason,
          max_severity: custom.severity,
          detectors: [custom.detector],
          warned: decision.warned,
        };
        labels[custom.detector] = custom.label;
        spooled.push({
          detector: custom.detector,
          severity: custom.severity,
          key_name: custom.key_name,
          excerpt: custom.excerpt,
          occurrences: 1,
          ...(toolName === undefined ? {} : { tool_name: toolName }),
          ...(target === undefined ? {} : { target }),
        });
      }
    }
  }

  // Second opinion (second-opinion.ts): about to interrupt on a shape guess,
  // and a local model is configured — ask it first. It can only lower a
  // finding's confidence, after which the same fold runs again; an armed
  // escalation is never among the eligible detectors, so a hold it raised is
  // untouched. Off, absent, slow or unsure → the decision above stands.
  let secondOpinionTelemetry: SecondOpinionTelemetry | undefined;
  if (decision.decision !== "allow" && selfWrite === undefined && policy.second_opinion?.enabled) {
    secondOpinionTelemetry = await secondOpinion(
      findings,
      decision.detectors,
      secondOpinionRawText(toolName, input.tool_input),
      policy.second_opinion,
      toolName,
    );
    if (secondOpinionTelemetry && secondOpinionTelemetry.downgraded.length > 0) {
      decision = decideEnforcement(findings, policy);
    }
  }

  // Whether this call is about to be HELD decides how the app treats the
  // detection line: a held call gets one approval banner, not a finding banner
  // a few milliseconds ahead of it. Deciding it HERE (rather than letting the
  // app infer it from whether the request file has landed yet) is what makes
  // that deterministic — the two writes race by design.
  const listening = appListening(guardDir);
  const willHold = decision.decision === "ask" && policy.confirm.interactive && listening;
  // An ask that will NOT be held (holding off, or nobody listening) on a host
  // that cannot ask on its own is resolved right here (hold.ts
  // unattendedOutcome): a deny under the default policy, the old warning
  // under `continue`. Deciding it before the spool write keeps the record's
  // decision the FINAL one — the Radar's blocked count is what happened.
  const preResolved = willHold ? undefined : unattendedOutcome(hostView, policy, decision.decision, undefined);

  // A call that only tripped warn-mode rules still runs — the record says WARN
  // so the app raises the coaching banner instead of a plain finding line.
  const spoolDecision =
    preResolved?.decision === "deny"
      ? "deny"
      : decision.decision === "allow" && decision.warned.length > 0
        ? "warn"
        : decision.decision;

  const usedLabels = Object.fromEntries(
    Object.entries(labels).filter(([id]) => spooled.some((f) => f.detector === id) || decision.detectors.includes(id)),
  );
  const common = {
    session_id: sessionId,
    source,
    tool_name: toolName,
    ...(cwd === undefined ? {} : { cwd }),
    max_severity: decision.max_severity,
    findings: spooled,
    ...(decision.warned.length > 0 ? { warned: decision.warned } : {}),
    ...(Object.keys(usedLabels).length > 0 ? { detector_labels: usedLabels } : {}),
    ...(secondOpinionTelemetry === undefined ? {} : { second_opinion: secondOpinionTelemetry }),
    ...(excepted.length > 0 ? { excepted } : {}),
  };

  // A call with nothing left to enforce but something an exception dropped is
  // still written down: silence here is exactly how a 30-day "allow for this
  // project" became invisible (the Copilot CLI rustup one-liner, 2026-09-08).
  if (spooled.length > 0 || excepted.length > 0) {
    spool(guardDir, {
      ...common,
      decision: spoolDecision,
      held: willHold,
      // An unattended deny names its resolution on the one line it writes, and
      // says the app was absent when that is why (holding off is not absence).
      ...(preResolved?.resolution === undefined ? {} : { resolution: preResolved.resolution }),
      ...(preResolved?.resolution !== undefined && !listening ? { decided_via: "app-absent" as const } : {}),
    });
  }

  let printed: "allow" | "ask" | "deny" = preResolved?.decision ?? decision.decision;
  let reason = decision.reason;
  let heldResolution: HoldResolution | undefined = preResolved?.resolution;

  if (willHold) {
    // The (detector, key) pairs behind the hold — what a scoped "allow for this
    // project" rule is written from. Masked key names only.
    const heldKeys = spooled
      .filter((f) => decision.detectors.includes(f.detector))
      .map((f) => ({ detector: f.detector, ...(f.key_name === undefined ? {} : { key_name: f.key_name }) }));
    const held = await holdForHuman(guardDir, policy, decision, {
      host: host.id,
      source,
      session_id: sessionId,
      tool_name: toolName,
      target,
      cwd,
      redacted,
      held_keys: heldKeys,
      detector_labels: usedLabels,
    }, {
      // A host whose hook cannot outlive the policy's window gets a shorter
      // hold, so OUR timeout answers before its kill. No host declares one
      // today (Hermes caps its own hook timeout at 600 s in hosts/hermes.ts,
      // above any hold the policy allows); the seam stays for one that will.
      ...(host.maxHoldSeconds === undefined ? {} : { holdSeconds: host.maxHoldSeconds }),
    });
    // A hold that ended in `ask` (the app vanished, or the timeout fallback is
    // ask) is the unattended case again — same rule as above.
    const strict = unattendedOutcome(hostView, policy, held.decision, held.resolution);
    printed = strict.decision;
    // The hold's own sentence ("You denied it in Doorman.") is written for the
    // approval card; the agent gets the same fact phrased for it below.
    reason = decision.reason;
    heldResolution = strict.resolution;
    if (spooled.length > 0) {
      spool(guardDir, {
        ...common,
        // The FINAL decision, so the Radar's blocked/asked counts reflect what
        // happened rather than what was proposed.
        decision: printed === "allow" ? "ask" : printed,
        resolution: heldResolution,
        ...held.telemetry,
      });
    }
  }

  // What the AGENT reads (remedy.ts): the human-facing reason plus what to do
  // instead and how the human weighs in. The spooled reason above stays the
  // short human line the approval card shows.
  const agentReason =
    printed === "allow"
      ? reason
      : agentFacingReason({
          decision: printed,
          reason,
          detectors: decision.detectors,
          resolution: heldResolution,
          policy,
          // An unheld ask with nobody listening must not tell the agent the
          // user is being asked in Doorman (remedy.ts).
          appListening: listening,
        });
  if (identity) {
    writeDedup(guardDir, host.id, identity, {
      event: identity.event,
      decision: printed,
      ...(printed === "allow" || agentReason === undefined ? {} : { reason: agentReason }),
      at: new Date().toISOString(),
    });
  }
  const emitted = hostEmit(hostView, printed, agentReason, policy.confirm.unattended);
  if (emitted.stdout) process.stdout.write(emitted.stdout);
  if (emitted.stderr) process.stderr.write(emitted.stderr);
  exitCode = emitted.exitCode;
}

/**
 * The prompt path. What differs from a tool call: there is no tool, no target
 * and no armed escalation (a prompt is the person's own words, never a sink);
 * `warn` reaches the AGENT as additionalContext (the remedy line) since there
 * is no banner channel on this event; and a hold that ends in deny or timeout
 * ERASES the prompt — which is the point, and why the default-ask rule here is
 * only `wallet_key_material` until the path's noise level is known.
 */
async function handlePrompt(
  guardDir: string,
  host: GuardHostDescriptor,
  source: string,
  prompt: { session_id?: string; cwd?: string; prompt: string },
): Promise<void> {
  let policyJson: string | undefined;
  try {
    policyJson = readFileSync(join(guardDir, "policy.json"), "utf8");
  } catch {
    policyJson = undefined;
  }
  const policy = parsePolicy(policyJson);
  const cwd = typeof prompt.cwd === "string" ? prompt.cwd : undefined;
  const sessionId = typeof prompt.session_id === "string" ? prompt.session_id : undefined;
  const result = evaluatePrompt({ ...prompt, cwd }, policy);
  const { findings, excepted, redacted } = result;
  const decision = result.decision;
  if (sessionId) {
    const term = presenceTerm(process.env);
    writePresence(guardDir, {
      session_id: sessionId,
      source,
      pid: process.ppid,
      ...(cwd === undefined ? {} : { cwd }),
      at: new Date().toISOString(),
      ...(term === undefined ? {} : { term }),
    });
  }
  const spooled: SpooledFinding[] = [...findings];
  const listening = appListening(guardDir);
  const willHold = decision.decision === "ask" && policy.confirm.interactive && listening;
  // No host has a native ask for a prompt, so an unheld `ask` here is the
  // unattended case on every host (hold.ts unattendedOutcome, `prompt: true`).
  const preResolved = willHold
    ? undefined
    : unattendedOutcome(host, policy, decision.decision, undefined, { prompt: true });
  const spoolDecision =
    preResolved?.decision === "deny"
      ? "deny"
      : decision.decision === "allow" && decision.warned.length > 0
        ? "warn"
        : decision.decision;
  const common = {
    session_id: sessionId,
    source,
    // The row's "tool": the event name, so the Radar and the approval card can
    // say what was held. `target` is the word `prompt` for the same reason.
    tool_name: PROMPT_TOOL_NAME,
    ...(cwd === undefined ? {} : { cwd }),
    max_severity: decision.max_severity,
    findings: spooled,
    ...(decision.warned.length > 0 ? { warned: decision.warned } : {}),
    ...(excepted.length > 0 ? { excepted } : {}),
  };
  if (spooled.length > 0 || excepted.length > 0) {
    spool(guardDir, {
      ...common,
      decision: spoolDecision,
      held: willHold,
      ...(preResolved?.resolution === undefined ? {} : { resolution: preResolved.resolution }),
      ...(preResolved?.resolution !== undefined && !listening ? { decided_via: "app-absent" as const } : {}),
    });
  }

  let printed: "allow" | "ask" | "deny" = preResolved?.decision ?? decision.decision;
  let reason = decision.reason;
  let heldResolution: HoldResolution | undefined = preResolved?.resolution;
  if (willHold) {
    const heldKeys = spooled
      .filter((f) => decision.detectors.includes(f.detector))
      .map((f) => ({ detector: f.detector, ...(f.key_name === undefined ? {} : { key_name: f.key_name }) }));
    const held = await holdForHuman(guardDir, policy, decision, {
      host: host.id,
      source,
      session_id: sessionId,
      tool_name: PROMPT_TOOL_NAME,
      target: "prompt",
      cwd,
      redacted,
      held_keys: heldKeys,
    }, {
      ...(host.maxHoldSeconds === undefined ? {} : { holdSeconds: host.maxHoldSeconds }),
    });
    const strict = unattendedOutcome(host, policy, held.decision, held.resolution, { prompt: true });
    printed = strict.decision;
    reason = decision.reason;
    heldResolution = strict.resolution;
    if (spooled.length > 0) {
      spool(guardDir, {
        ...common,
        decision: printed === "allow" ? "ask" : printed,
        resolution: heldResolution,
        ...held.telemetry,
      });
    }
  }

  // An `ask` still standing here is one `unattended: "continue"` let through:
  // a warn — the prompt goes through and the agent gets the note. Under the
  // default policy it has already become a deny above, and the prompt is erased.
  const outcome: "allow" | "warn" | "deny" =
    printed === "deny" ? "deny" : printed === "ask" || decision.warned.length > 0 ? "warn" : "allow";
  // Deny: the full agent-facing sentence (rule, remedy, the human's role).
  // Warn: just the remedy line, as a note beside the prompt the agent now reads.
  const agentReason =
    outcome === "deny"
      ? agentFacingReason({ decision: "deny", reason, detectors: decision.detectors, resolution: heldResolution, policy })
      : outcome === "warn"
        ? remedyFor(decision.detectors.length > 0 ? decision.detectors : decision.warned)
        : undefined;
  const emitted = host.emitPrompt!(outcome, reason, agentReason);
  if (emitted.stdout) process.stdout.write(emitted.stdout);
  if (emitted.stderr) process.stderr.write(emitted.stderr);
  exitCode = emitted.exitCode;
}

/** The pseudo tool name a prompt row carries (spool, approval card, Radar). */
export const PROMPT_TOOL_NAME = "UserPromptSubmit";

// Re-exported for the probe script and tests that want to label spool rows.
export { isCustomDetectorId };
export type { SecurityDetectorId };

main()
  // Rule 1: any internal error is an exit 0 with no output, whatever the host's
  // exit semantics are — we never turn our own bug into somebody's blocked call.
  .catch(() => {
    exitCode = 0;
  })
  .finally(() => process.exit(exitCode));
