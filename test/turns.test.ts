import { describe, expect, it } from "vitest";
import {
  deriveAutoTitle,
  groupSessions,
  titleWriteApplies,
  type LedgerTurn,
  type SessionTitle,
} from "../main/lib/turns.js";

const turn = (over: Partial<LedgerTurn>): LedgerTurn => ({
  id: over.id ?? Math.random().toString(36).slice(2),
  source: "claude-code",
  session_id: "s1",
  role: "assistant",
  at: "2026-08-20T10:00:00.000Z",
  ...over,
});

describe("groupSessions", () => {
  it("classifies each session's use-case from its turns", () => {
    const sessions = groupSessions(
      [
        turn({ id: "p", role: "user", text: "deploy via terraform to prod", at: "2026-08-20T09:59:00Z" }),
        turn({ id: "a", tools: ["Bash"], cost: 1 }),
      ],
      new Map(),
    );
    expect(sessions[0]!.task).toBe("infra");
  });

  it("folds cost, tokens, models and the settlement split per session", () => {
    const turns: LedgerTurn[] = [
      turn({ id: "p1", role: "user", at: "2026-08-20T09:59:00.000Z" }),
      turn({
        id: "a1",
        model: "claude-opus-5",
        cost: 1.5,
        usage: { input_tokens: 10, output_tokens: 20, cache_read_tokens: 0, cache_write_tokens: 0, cache_write_1h_tokens: 0, web_search_requests: 0 },
      }),
      turn({ id: "a2", model: "claude-opus-5", cost: 0.5, settlement: "subscription" }),
      turn({ id: "a3", source: "codex", session_id: "s2", model: "gpt-5-codex", cost: 2, settlement: "credits", at: "2026-08-21T10:00:00.000Z" }),
    ];
    const titles = new Map<string, SessionTitle>([
      ["s1", { text: "Fix login", origin: "auto_prompt" }],
    ]);
    const sessions = groupSessions(turns, titles);
    expect(sessions.map((s) => s.id)).toEqual(["s2", "s1"]); // newest activity first
    const s1 = sessions[1]!;
    expect(s1.title).toBe("Fix login");
    expect(s1.cost).toBeCloseTo(2);
    expect(s1.turns).toBe(2);
    expect(s1.prompts).toBe(1);
    expect(s1.models).toEqual(["claude-opus-5"]);
    expect(s1.covered_cost).toBeCloseTo(0.5);
    expect(s1.unknown_cost).toBeCloseTo(1.5); // unattributed stays unknown, never assumed
    // The token twin of the split — what the ledger shows. a1 carried
    // usage and no settlement; a2 was plan-settled but carried no usage.
    expect(s1.unknown_tokens).toBe(30);
    expect(s1.covered_tokens).toBe(0);
    const s2 = sessions[0]!;
    expect(s2.overage_cost).toBeCloseTo(2);
    expect(s2.overage_tokens).toBe(0);
  });
});

describe("titleWriteApplies", () => {
  it("auto_summary outranks and self-replaces; auto_prompt never overwrites", () => {
    expect(titleWriteApplies("auto_prompt", undefined)).toBe(true);
    expect(titleWriteApplies("auto_prompt", "auto_prompt")).toBe(false);
    expect(titleWriteApplies("auto_prompt", "auto_summary")).toBe(false);
    expect(titleWriteApplies("auto_summary", "auto_prompt")).toBe(true);
    expect(titleWriteApplies("auto_summary", "auto_summary")).toBe(true);
  });
});

describe("deriveAutoTitle", () => {
  it("takes the first usable line", () => {
    expect(deriveAutoTitle("fix the login bug\nmore detail")).toBe("fix the login bug");
  });

  it("skips a leading declaration header block", () => {
    expect(deriveAutoTitle("feature: auth\nissue: ENG-1\nactual request")).toBe("actual request");
  });

  it("returns undefined for slash and shell commands so junk never sticks", () => {
    expect(deriveAutoTitle("/model opus")).toBeUndefined();
    expect(deriveAutoTitle("!ls -la")).toBeUndefined();
  });

  it("cuts at 80 chars on a word boundary with an ellipsis", () => {
    const long = "word ".repeat(40).trim();
    const title = deriveAutoTitle(long)!;
    expect(title.length).toBeLessThanOrEqual(81);
    expect(title.endsWith("…")).toBe(true);
    expect(title).not.toMatch(/wor…$/); // broke at a space, not mid-word
  });

  it("skips lines that are nothing but redactions", () => {
    expect(deriveAutoTitle("[redacted:aws]\nreal title")).toBe("real title");
  });
});
