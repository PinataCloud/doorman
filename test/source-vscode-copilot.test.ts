import { describe, expect, it } from "vitest";
import {
  parseCopilotChatSession,
  sessionIdFromPath,
  vscodeCopilotSource,
} from "../main/lib/vscode-copilot-transcript.js";
import type { SourceIo } from "../main/lib/transcript-sources.js";

/** Shape recorded from real chatSessions documents on 2026-09-06: `message` is
 * an object on newer builds and a bare string on older ones, `response` is an
 * array of value blocks, `modelId` appears only on newer builds — and there is
 * no token count anywhere, on either. */
const SESSION = JSON.stringify({
  version: 3,
  sessionId: "1891762e-b165-4d87-97d5-7fd055efc791",
  creationDate: 1751558100000,
  requests: [
    {
      timestamp: 1751558176633,
      message: { text: "how do the workers share types?" },
      response: [{ value: "Each subworker keeps shared types under src/common." }],
      agent: { id: "github.copilot.default" },
      modelId: "copilot/gpt-4.1",
      result: { timings: { totalElapsed: 13832 } },
    },
    {
      timestamp: 1751558200000,
      message: "and the middlewares?",
      response: [{ value: "Same directory: " }, { value: "src/common/middlewares." }],
      agent: { id: "github.copilot.default" },
    },
  ],
});

const ROOT = "/home/Library/Application Support/Code/User/workspaceStorage";
const PATH = `${ROOT}/2b3fc6ee/chatSessions/1891762e-b165-4d87-97d5-7fd055efc791.json`;

function io(files: Record<string, string>, dirs: Record<string, string[]>): SourceIo {
  return {
    readText: (p) => files[p],
    listDir: (p) => dirs[p] ?? [],
    stat: (p) =>
      files[p] !== undefined
        ? { size: files[p].length, mtimeMs: 1, isDirectory: false }
        : dirs[p] !== undefined
          ? { size: 0, mtimeMs: 1, isDirectory: true }
          : undefined,
    querySqlite: () => {
      throw new Error("not used");
    },
  };
}

describe("vs code copilot transcript source", () => {
  it("NEVER attaches usage or cost to a chatSessions document — it carries no token counts", () => {
    const { turns } = parseCopilotChatSession(SESSION, "s1");
    expect(turns.length).toBeGreaterThan(0);
    // A $0 here would be a lie about a real bill.
    for (const turn of turns) {
      expect(turn.usage).toBeUndefined();
      expect(turn.cost).toBeUndefined();
      expect(turn.cost_unknown).toBeUndefined();
    }
    // The RAIL is metered all the same: VS Code's SDK-hosted agent sessions are
    // priced by the Copilot CLI reader from the session-store usage table and
    // attributed to this source (copilot-transcript.ts, 2026-09-08).
    expect(vscodeCopilotSource.metered).toBe(true);
  });

  it("reads both the object and the bare-string message shapes", () => {
    const { turns } = parseCopilotChatSession(SESSION, "s1");
    const prompts = turns.filter((t) => t.role === "user");
    expect(prompts.map((t) => t.text)).toEqual([
      "how do the workers share types?",
      "and the middlewares?",
    ]);
  });

  it("joins the response blocks and keeps the model half of modelId", () => {
    const { turns } = parseCopilotChatSession(SESSION, "s1");
    const answers = turns.filter((t) => t.role === "assistant");
    expect(answers[0].model).toBe("gpt-4.1");
    expect(answers[1].text).toBe("Same directory: src/common/middlewares.");
    // Absent on older documents rather than guessed.
    expect(answers[1].model).toBeUndefined();
  });

  it("scans the assistant answer as model-authored text that landed here", () => {
    const { detect } = parseCopilotChatSession(SESSION, "s1");
    const outputs = detect.filter((u) => u.kind === "tool_output");
    expect(outputs).toHaveLength(2);
    expect(outputs[0].tool_name).toBe("copilot_chat");
    expect(detect.filter((u) => u.kind === "prompt")).toHaveLength(2);
  });

  it("is idempotent and stable on position, not on an absent requestId", () => {
    const a = parseCopilotChatSession(SESSION, "s1").turns.map((t) => t.id);
    const b = parseCopilotChatSession(SESSION, "s1").turns.map((t) => t.id);
    expect(a).toEqual(b);
    expect(new Set(a).size).toBe(a.length);
    expect(a).toContain("vscode-copilot:s1:p0");
    expect(a).toContain("vscode-copilot:s1:a1");
  });

  it("returns nothing for truncated JSON rather than throwing", () => {
    expect(parseCopilotChatSession('{"requests":[{"timesta', "s1").turns).toEqual([]);
    // A session VS Code has created but nobody has typed in yet.
    expect(parseCopilotChatSession('{"requests":[]}', "s1").turns).toEqual([]);
  });

  it("discovers chatSessions across workspace folders and skips those without one", () => {
    const dirs = {
      [ROOT]: ["2b3fc6ee", "0155a440"],
      [`${ROOT}/2b3fc6ee/chatSessions`]: [
        "1891762e-b165-4d87-97d5-7fd055efc791.json",
        "notes.txt",
      ],
    };
    expect(vscodeCopilotSource.discover(ROOT, io({ [PATH]: SESSION }, dirs))).toEqual([PATH]);
  });

  it("takes the session id from the file name, which is VS Code's own", () => {
    expect(sessionIdFromPath(PATH)).toBe("1891762e-b165-4d87-97d5-7fd055efc791");
    expect(sessionIdFromPath("/a/b")).toBeUndefined();
  });
});
