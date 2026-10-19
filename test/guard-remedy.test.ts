import { describe, expect, it } from "vitest";

import { AGENT_REMEDIES, agentFacingReason, remedyFor } from "../main/guard/remedy.js";
import { DEFAULT_MODES, DETECTOR_LABELS, decideEnforcement, defaultPolicy } from "../main/guard/policy.js";

/**
 * The deny/ask reason is the one lever a hook has over the model's next move,
 * so it has to say what to do INSTEAD — not just which rule fired. These pin
 * the shape of that text and that every rule which can hold a call has a
 * remedy of its own rather than the generic line.
 */
describe("agent-facing reason", () => {
  it("every detector that ships enforcing — ask, warn or block — has its own remedy", () => {
    for (const id of Object.keys(DEFAULT_MODES)) {
      expect(AGENT_REMEDIES[id], id).toBeTruthy();
    }
    // …and every remedy speaks to the agent: imperative, no Ledger the agent
    // cannot open, no asking the agent itself to rotate anything.
    for (const [id, text] of Object.entries(AGENT_REMEDIES)) {
      expect(text, id).toMatch(/^(Do not|A |An |Content|Ignore|Stop)/);
      expect(text, id).not.toMatch(/Ledger/);
      expect(text, id).not.toMatch(/(^|\. )Rotate/);
    }
  });

  it("names the rule, the remedy and the human's role, in that order", () => {
    const decision = decideEnforcement(
      [{ detector: "secret_egress", severity: "high", confidence: "high", excerpt: "", occurrences: 1 } as never],
      defaultPolicy(),
    );
    expect(decision.decision).toBe("ask");
    const text = agentFacingReason({ decision: "deny", reason: decision.reason, detectors: decision.detectors });
    expect(text.startsWith(`Doorman flagged this tool call: ${DETECTOR_LABELS.secret_egress}.`)).toBe(true);
    expect(text).toContain(AGENT_REMEDIES.secret_egress);
    expect(text.endsWith("The user can review and allow this call in Doorman (Security Radar) if it is intended.")).toBe(true);
  });

  it("phrases a human's denial and a silent timeout for the agent", () => {
    const denied = agentFacingReason({ decision: "deny", reason: "R.", detectors: ["destructive_command"], resolution: "denied" });
    expect(denied).toContain("The user denied this call in Doorman; ask them before trying an alternative.");
    const timedOut = agentFacingReason({
      decision: "deny",
      reason: "R.",
      detectors: ["destructive_command"],
      resolution: "timeout",
      policy: { confirm: { interactive: true, hold_seconds: 60, on_timeout: "deny", unattended: "deny" } },
    });
    expect(timedOut).toContain("Nobody approved it within 60s; ask the user to approve it in Doorman or choose another approach.");
    // Nobody was reached: the sentence must not claim a human decided, and
    // must name the one thing that unblocks the agent.
    const unavailable = agentFacingReason({ decision: "deny", reason: "R.", detectors: ["destructive_command"], resolution: "unavailable" });
    expect(unavailable).toContain("could not reach the user for approval");
    expect(unavailable).toContain("was not executed");
    expect(unavailable).toContain("open Doorman");
    expect(unavailable).not.toContain("denied this call");
    const asking = agentFacingReason({ decision: "ask", reason: "R.", detectors: ["infra_mutation"] });
    expect(asking).toContain("wait for their answer rather than working around it");
  });

  it("doesn't send the agent waiting on Doorman when nobody is there to ask", () => {
    // Found on Windows: with the app closed and no `doorman watch`, Claude Code
    // was handed the `ask` and the agent read "asking you in Doorman" — but the
    // only thing that could answer was Claude Code's own prompt.
    const base = { decision: "ask" as const, reason: "R.", detectors: ["infra_mutation"] };
    const attended = agentFacingReason({ ...base, appListening: true });
    expect(attended).toBe(agentFacingReason(base));
    expect(attended).toContain("The user is being asked in Doorman");
    for (const unattended of [
      agentFacingReason({ ...base, appListening: false }),
      // The app vanished mid-hold and the question went back to the host.
      agentFacingReason({ ...base, appListening: true, resolution: "unattended" }),
    ]) {
      expect(unattended).not.toContain("The user is being asked in Doorman");
      expect(unattended).toContain("Doorman is not running");
      expect(unattended).toContain("your own permission prompt");
    }
  });

  it("falls back to the generic line for a custom or unknown rule, and never throws", () => {
    expect(remedyFor(["custom:no-prod-deploys"])).toMatch(/^Do not retry the same call/);
    expect(remedyFor([])).toMatch(/^Do not retry the same call/);
    // The first detector with a remedy wins, in the order the decision listed them.
    expect(remedyFor(["custom:x", "unsafe_fetch_exec", "secret_egress"])).toBe(AGENT_REMEDIES.unsafe_fetch_exec);
    expect(agentFacingReason({ decision: "deny", detectors: [] })).toMatch(/^Doorman flagged this tool call\. Do not retry/);
  });
});
