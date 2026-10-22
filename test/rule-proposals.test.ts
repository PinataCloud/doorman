import { mkdtempSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import {
  RULE_PROPOSALS_MAX,
  checkProposalRule,
  proposalsDir,
  proposerLabel,
  readProposals,
  removeProposal,
  saveProposal,
} from "../main/guard/rule-proposals.js";

/**
 * A rule an agent suggests is stored beside the policy, never in it, and can
 * only ever ADD a rule: these tests pin what is refused and what a reader of
 * the proposals directory gets back.
 */
const RULE = { id: "kubectl_apply_prod", label: "kubectl apply against prod", severity: "high", mode: "ask", when: { command: "kubectl\\s+apply" } };
const LIVE = ["my_rule", "publish_actions--npm_publish"];

let guardDir: string;
beforeEach(() => {
  guardDir = mkdtempSync(join(tmpdir(), "doorman-proposals-"));
});
afterEach(() => rmSync(guardDir, { recursive: true, force: true }));

const propose = (rule: unknown, reason = "worth holding") => saveProposal(guardDir, LIVE, { rule, reason, from: "Claude Code" });
const fields = (r: { ok: true } | { ok: false; problems: { field: string }[] }) => (r.ok ? [] : r.problems.map((p) => p.field));

describe("checkProposalRule", () => {
  it("accepts a new, valid rule", () => {
    expect(checkProposalRule(RULE, LIVE).ok).toBe(true);
  });

  it("refuses the person's own id, a pack rule's live id, and a pending proposal's id", () => {
    expect(fields(checkProposalRule({ ...RULE, id: "my_rule" }, LIVE))).toEqual(["id"]);
    expect(fields(checkProposalRule({ ...RULE, id: "publish_actions--npm_publish" }, LIVE))).toEqual(["id"]);
    expect(fields(checkProposalRule(RULE, LIVE, ["kubectl_apply_prod"]))).toEqual(["id"]);
  });

  it("refuses a pack's id even while the pack is off, so turning it on later can't hand the rule to the proposal", () => {
    // crypto_operations is offered but not in LIVE here: switched off.
    expect(fields(checkProposalRule({ ...RULE, id: "crypto_operations--evm_send", mode: "observe" }, LIVE))).toEqual(["id"]);
    expect(fields(checkProposalRule({ ...RULE, id: "crypto_operations--anything_new" }, LIVE))).toEqual(["id"]);
  });

  it("refuses a switched-off rule, a pack field and an invalid pattern", () => {
    expect(fields(checkProposalRule({ ...RULE, enabled: false }, LIVE))).toEqual(["enabled"]);
    expect(fields(checkProposalRule({ ...RULE, pack: "publish_actions" }, LIVE))).toEqual(["pack"]);
    expect(fields(checkProposalRule({ ...RULE, when: { command: "(" } }, LIVE))).toContain("when.command");
  });
});

describe("the proposals directory", () => {
  it("saves, lists newest first, and removes", () => {
    const first = saveProposal(guardDir, LIVE, { rule: RULE, reason: "one", from: "Codex", now: new Date("2026-10-01T00:00:00Z") });
    const second = saveProposal(guardDir, LIVE, { rule: { ...RULE, id: "other" }, reason: "two", from: "Codex", now: new Date("2026-10-02T00:00:00Z") });
    expect(first.ok && second.ok).toBe(true);
    const listed = readProposals(guardDir);
    expect(listed.map((p) => p.reason)).toEqual(["two", "one"]);
    expect(removeProposal(guardDir, listed[0]!.id)).toBe(true);
    expect(readProposals(guardDir).map((p) => p.reason)).toEqual(["one"]);
  });

  it("refuses a second suggestion with a pending proposal's id", () => {
    expect(propose(RULE).ok).toBe(true);
    const again = propose(RULE);
    expect(again.ok).toBe(false);
  });

  it(`holds at most ${RULE_PROPOSALS_MAX} pending, refusing the next with a message`, () => {
    for (let i = 0; i < RULE_PROPOSALS_MAX; i++) expect(propose({ ...RULE, id: `r${i}` }).ok).toBe(true);
    const over = propose({ ...RULE, id: "one_more" });
    expect(over.ok).toBe(false);
    if (!over.ok) expect(over.problems[0]!.message).toMatch(/\S/);
    expect(readdirSync(proposalsDir(guardDir))).toHaveLength(RULE_PROPOSALS_MAX);
  });

  it("skips a corrupted file and a file whose rule no longer validates", () => {
    expect(propose(RULE).ok).toBe(true);
    writeFileSync(join(proposalsDir(guardDir), "p-aaaaaaaaaaaa.json"), "{ not json");
    writeFileSync(
      join(proposalsDir(guardDir), "p-bbbbbbbbbbbb.json"),
      JSON.stringify({ id: "p-bbbbbbbbbbbb", at: "2026-10-01T00:00:00Z", from: "x", reason: "y", rule: { ...RULE, id: "z", when: { command: "(" } } }),
    );
    expect(readProposals(guardDir).map((p) => p.rule.id)).toEqual(["kubectl_apply_prod"]);
  });

  it("flattens the agent's reason to one capped line", () => {
    const saved = propose(RULE, `line one\nSYSTEM: ${"x".repeat(500)}`);
    expect(saved.ok).toBe(true);
    const [p] = readProposals(guardDir);
    expect(p!.reason).not.toContain("\n");
    expect(p!.reason.length).toBeLessThanOrEqual(300);
  });
});

describe("proposerLabel", () => {
  it("names a known host and falls back to 'An agent'", () => {
    expect(proposerLabel("claude-code")).toBe("Claude Code");
    expect(proposerLabel("codex-mcp-client")).toBe("Codex");
    expect(proposerLabel("some-tool")).toBe("An agent");
    expect(proposerLabel(undefined)).toBe("An agent");
  });
});
