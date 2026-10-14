/**
 * The hold itself: publish the question, wait, and turn what came back into the
 * decision the guard prints.
 *
 * Split out of guard.ts on purpose. guard.ts is an executable shell — it reads
 * stdin, writes stdout and calls process.exit — so importing it from a test
 * would run all three. This file is the part worth testing and none of the part
 * that would take the test runner down with it.
 *
 * Self-containment rule: copied verbatim into userData, so nothing here may
 * import from outside main/guard/.
 */

import { randomUUID } from "node:crypto";
import {
  PREVIEW_LIMIT,
  clearExchange,
  holdForVerdict,
  writeRequest,
  type ApprovalResolution,
  type ApprovalVia,
} from "./handshake.js";
import type { EnforcementDecision, GuardPolicy, UnattendedPolicy } from "./policy.js";
import { DEFAULT_HOST, hostById, hostForArgv } from "./hosts/index.js";
import type { GuardHostDescriptor, HostEmit } from "./hosts/types.js";

/** A registered host's id (hosts/index.ts). A string, not a closed union: the
 * registry is what decides which hosts exist, and it grows by one import. */
export type GuardHost = string;

/**
 * How a hold ended, for the spool: when it was raised, when it was decided,
 * through which surface, and how long that took. `decided_via` widens the
 * reply's surface set with the two non-human endings, so one field answers
 * "who decided" for every row.
 */
export interface HoldTelemetry {
  held_at: string;
  decided_at: string;
  decided_via: ApprovalVia | "timeout" | "app-absent";
  hold_ms: number;
  /** The person also scoped an ignore rule to the project on their way out. */
  allow_scope?: "project";
}

/** Keep the executable-shell argument parsing testable without importing
 * guard.ts (which reads stdin and exits as soon as it is loaded). A thin
 * wrapper over the registry's `hostForArgv`, kept because it is what the
 * guard's tests and older callers ask for. */
export function guardHostFromArgv(argv: readonly string[]): GuardHost {
  return hostForArgv(argv).id;
}

export interface HeldResult {
  /** What to print. `allow` means print NOTHING (guard.ts rule 2): an approval
   * here removes our check, never Claude Code's. */
  decision: "allow" | "ask" | "deny";
  reason?: string;
  resolution: ApprovalResolution;
  telemetry: HoldTelemetry;
}

export interface HoldContext {
  host: GuardHost;
  /** The payload's `source` when it differs from the host's own — a dialect
   * (hosts/types.ts HostDialect). Absent → the host's source. */
  source?: string;
  session_id?: string;
  tool_name?: string;
  target?: string;
  cwd?: string;
  /** Already redacted (decision.ts). An approval card is under the same rule as
   * a finding excerpt: it never carries the secret. */
  redacted: string;
  /** The (detector, key_name) pairs behind the hold — see ApprovalRequest. */
  held_keys?: { detector: string; key_name?: string }[];
  /** Labels for custom-rule detector ids named in the decision. */
  detector_labels?: Record<string, string>;
}

export async function holdForHuman(
  guardDir: string,
  policy: GuardPolicy,
  decision: EnforcementDecision,
  context: HoldContext,
  options: { id?: string; pollMs?: number; holdSeconds?: number } = {},
): Promise<HeldResult> {
  const id = options.id ?? randomUUID();
  const reason = decision.reason ?? "Flagged by Doorman.";
  // The window actually waited: the policy's, unless the host's hook cannot
  // survive that long (hosts/types.ts maxHoldSeconds) — guard.ts passes the
  // smaller of the two, and every record below says the window really used.
  const holdSeconds = Math.max(0, Math.min(policy.confirm.hold_seconds, options.holdSeconds ?? policy.confirm.hold_seconds));
  const heldAt = new Date().toISOString();
  const startedMs = Date.now();
  writeRequest(guardDir, {
    id,
    at: heldAt,
    session_id: context.session_id,
    source: context.source ?? (hostById(context.host) ?? DEFAULT_HOST).source,
    tool_name: context.tool_name,
    target: context.target,
    cwd: context.cwd,
    detectors: decision.detectors,
    ...(context.held_keys && context.held_keys.length > 0 ? { held_keys: context.held_keys } : {}),
    ...(context.detector_labels && Object.keys(context.detector_labels).length > 0
      ? { detector_labels: context.detector_labels }
      : {}),
    max_severity: decision.max_severity,
    reason,
    preview: context.redacted.slice(0, PREVIEW_LIMIT),
    hold_seconds: holdSeconds,
    on_timeout: policy.confirm.on_timeout,
    pid: process.pid,
  });
  const telemetry = (
    via: HoldTelemetry["decided_via"],
    allowScope?: "project",
  ): HoldTelemetry => ({
    held_at: heldAt,
    decided_at: new Date().toISOString(),
    decided_via: via,
    hold_ms: Math.max(0, Date.now() - startedMs),
    ...(allowScope === "project" ? { allow_scope: "project" as const } : {}),
  });
  try {
    const held = await holdForVerdict(guardDir, id, holdSeconds, {
      pollMs: options.pollMs,
    });
    if (held.outcome === "answered") {
      // A reply from an app build that predates `via` answered from the window.
      const via = held.reply.via ?? "window";
      if (held.reply.verdict === "allow") {
        return { decision: "allow", resolution: "allowed", telemetry: telemetry(via, held.reply.allow_scope) };
      }
      return {
        decision: "deny",
        reason: `${reason} You denied it in Doorman.`,
        resolution: "denied",
        telemetry: telemetry(via),
      };
    }
    // The app vanished mid-hold (quit, crash, or never there): there is nobody
    // to have walked away, so this is not the timeout case — hand the question
    // back to the host adapter rather than denying on a human's behalf.
    if (held.outcome === "app_gone") {
      return { decision: "ask", reason, resolution: "unattended", telemetry: telemetry("app-absent") };
    }
    if (policy.confirm.on_timeout === "ask") {
      return { decision: "ask", reason, resolution: "timeout", telemetry: telemetry("timeout") };
    }
    return {
      decision: "deny",
      reason: `${reason} It was held for ${holdSeconds}s and nobody approved it.`,
      resolution: "timeout",
      telemetry: telemetry("timeout"),
    };
  } finally {
    clearExchange(guardDir, id);
  }
}

/**
 * The strict rule, pure: an `ask` about to reach a host that cannot ask on its own is a question
 * nobody will answer. Under `confirm.unattended: "deny"` it becomes the host's
 * valid DENY — with `resolution: "unavailable"` when there was no hold at all
 * or the app vanished mid-hold, and the hold's own resolution (`timeout`) kept
 * when there was one. Under `"continue"` the decision passes through, and
 * `hostEmit` turns it into the host's visible warning as before.
 *
 * A host WITH a native ask is untouched: handing the question to its own
 * prompt is a real ask, not a fail-open. `prompt: true` says there is no such
 * thing for this event — no host has a native ask for a UserPromptSubmit — so
 * the rule applies whatever the host declares for tool calls.
 */
export function unattendedOutcome(
  host: Pick<GuardHostDescriptor, "supportsNativeAsk">,
  policy: Pick<GuardPolicy, "confirm">,
  decision: "allow" | "ask" | "deny",
  resolution: ApprovalResolution | undefined,
  options: { prompt?: boolean } = {},
): { decision: "allow" | "ask" | "deny"; resolution: ApprovalResolution | undefined } {
  if (decision !== "ask") return { decision, resolution };
  if (host.supportsNativeAsk && !options.prompt) return { decision, resolution };
  if (policy.confirm.unattended === "continue") return { decision, resolution };
  return {
    decision: "deny",
    resolution: resolution === undefined || resolution === "unattended" ? "unavailable" : resolution,
  };
}

/**
 * Translate the guard's host-neutral decision into the output contract the
 * host supports. Silence means our check passed and the agent's own approval
 * machinery remains untouched. A host with no native `ask` (Codex) takes the
 * warn path instead: when the app cannot mediate the question, say so visibly
 * and let the call continue.
 *
 * A compatibility wrapper over the registry — the descriptors' `emit`/`warn`
 * own the shapes now. Returns stdout only; `hostEmit` below carries the exit
 * code a fail-closed host will eventually need. `unattended` defaults to the
 * policy default (deny) — pass `"continue"` for the pre-2026-09-10 warning.
 */
export function hookOutputForHost(
  host: GuardHost,
  decision: "allow" | "ask" | "deny",
  reason?: string,
  unattended: UnattendedPolicy = "deny",
): string | undefined {
  return hostEmit(hostById(host) ?? DEFAULT_HOST, decision, reason, unattended).stdout;
}

/** What to print and how to exit, for one decision on one host. An `ask` on a
 * host without a native ask is the unattended case: `deny` (the default)
 * returns the host's deny, `continue` its warning (guard.ts normally resolves
 * this ahead of time through `unattendedOutcome`, so the deny reason it prints
 * names the resolution; this is the last line of defence). */
export function hostEmit(
  host: GuardHostDescriptor,
  decision: "allow" | "ask" | "deny",
  reason?: string,
  unattended: UnattendedPolicy = "deny",
): HostEmit {
  if (decision === "ask" && !host.supportsNativeAsk) {
    if (unattended === "continue") return host.warn(reason ?? "Doorman security policy");
    return host.emit("deny", reason ?? "Doorman security policy");
  }
  return host.emit(decision, reason);
}
