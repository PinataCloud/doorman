import { describe, expect, it } from "vitest";
import { classifySession, TASK_LABELS } from "../main/lib/task-class.js";
import type { LedgerTurn } from "../main/lib/turns.js";

let seq = 0;
const user = (text: string): LedgerTurn => ({
  id: `u${seq++}`, source: "claude-code", session_id: "s", role: "user", at: "2026-09-01T10:00:00Z", text,
});
const asst = (tools: string[]): LedgerTurn => ({
  id: `a${seq++}`, source: "claude-code", session_id: "s", role: "assistant", at: "2026-09-01T10:00:01Z", tools,
});

describe("classifySession", () => {
  it("calls a write-heavy feature session coding", () => {
    expect(classifySession([user("implement the new export endpoint"), asst(["Read", "Edit", "Write"])])).toBe("coding");
  });

  it("recognizes testing, debugging and refactor from prompt keywords", () => {
    expect(classifySession([user("write unit tests for the export module with vitest"), asst(["Bash", "Write"])])).toBe("testing");
    expect(classifySession([user("debug this crash in the parser"), asst(["Read"])])).toBe("debugging");
    expect(classifySession([user("refactor and rename these helpers"), asst(["MultiEdit"])])).toBe("refactor");
  });

  it("routes infra, data and docs by their vocabulary", () => {
    expect(classifySession([user("deploy via terraform to the prod cluster"), asst(["Bash"])])).toBe("infra");
    expect(classifySession([user("analyze the csv and write a SQL query"), asst(["NotebookEdit"])])).toBe("data");
    expect(classifySession([user("update the README and changelog"), asst(["Write"])])).toBe("docs");
  });

  it("treats web-only and read-only sessions as research / review", () => {
    expect(classifySession([user("how do promises work"), asst(["WebSearch", "WebFetch"])])).toBe("research");
    expect(classifySession([user("look at this module"), asst(["Read", "Grep"])])).toBe("review");
  });

  it("falls back to other when nothing speaks, and every class has a label", () => {
    expect(classifySession([])).toBe("other");
    expect(classifySession([asst([])])).toBe("other");
    for (const key of Object.keys(TASK_LABELS)) expect(TASK_LABELS[key as keyof typeof TASK_LABELS]).toBeTruthy();
  });

  it("is deterministic — same turns, same class", () => {
    const turns = [user("fix the failing test"), asst(["Bash", "Edit"])];
    expect(classifySession(turns)).toBe(classifySession(turns));
  });
});
