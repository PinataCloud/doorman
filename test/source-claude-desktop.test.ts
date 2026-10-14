import { describe, expect, it } from "vitest";
import {
  claudeDesktopSource,
  parseClaudeDesktopAudit,
  sessionIdFromPath,
} from "../main/lib/claude-desktop-transcript.js";
import type { SourceIo } from "../main/lib/transcript-sources.js";

/**
 * The fixture mirrors the shape recorded from a real Cowork session on
 * 2026-09-06: one assistant message split across three lines (thinking, text,
 * tool_use) that all REPEAT the same usage object, a tool_result carried on a
 * `user` line, and a closing `result` record with the session's real cost.
 * The numbers are the real session's, scaled down.
 */
const AUDIT = [
  {
    type: "user",
    message: { role: "user", content: "add a drag and drop upload to the chat" },
    _audit_timestamp: "2026-04-17T17:42:12.927Z",
  },
  {
    type: "system",
    subtype: "init",
    cwd: "/sessions/eloquent-serene-meitner",
    _audit_timestamp: "2026-04-17T17:42:13.000Z",
  },
  {
    type: "assistant",
    message: {
      id: "msg_01AAA",
      model: "claude-opus-4-7",
      content: [{ type: "thinking", thinking: "considering" }],
      usage: {
        input_tokens: 6,
        output_tokens: 8,
        cache_creation_input_tokens: 39936,
        cache_read_input_tokens: 0,
        cache_creation: { ephemeral_1h_input_tokens: 39936, ephemeral_5m_input_tokens: 0 },
      },
    },
    _audit_timestamp: "2026-04-17T17:42:20.000Z",
  },
  {
    type: "assistant",
    message: {
      id: "msg_01AAA",
      model: "claude-opus-4-7",
      content: [{ type: "text", text: "Looking at the chat component." }],
      usage: {
        input_tokens: 6,
        output_tokens: 8,
        cache_creation_input_tokens: 39936,
        cache_read_input_tokens: 0,
        cache_creation: { ephemeral_1h_input_tokens: 39936, ephemeral_5m_input_tokens: 0 },
      },
    },
    _audit_timestamp: "2026-04-17T17:42:21.000Z",
  },
  {
    type: "assistant",
    message: {
      id: "msg_01AAA",
      model: "claude-opus-4-7",
      content: [
        { type: "tool_use", id: "tu_1", name: "Bash", input: { command: "cat .env" } },
      ],
      usage: {
        input_tokens: 6,
        output_tokens: 8,
        cache_creation_input_tokens: 39936,
        cache_read_input_tokens: 0,
        cache_creation: { ephemeral_1h_input_tokens: 39936, ephemeral_5m_input_tokens: 0 },
      },
    },
    _audit_timestamp: "2026-04-17T17:42:22.000Z",
  },
  {
    type: "user",
    message: {
      role: "user",
      content: [{ type: "tool_result", tool_use_id: "tu_1", content: "AWS_SECRET=hunter2" }],
    },
    _audit_timestamp: "2026-04-17T17:42:23.000Z",
  },
  {
    type: "assistant",
    message: {
      id: "msg_01BBB",
      model: "claude-opus-4-7",
      content: [{ type: "text", text: "Done." }],
      usage: {
        input_tokens: 1,
        output_tokens: 53,
        cache_creation_input_tokens: 354,
        cache_read_input_tokens: 62455,
        cache_creation: { ephemeral_1h_input_tokens: 354, ephemeral_5m_input_tokens: 0 },
      },
    },
    _audit_timestamp: "2026-04-17T17:43:30.000Z",
  },
  {
    type: "result",
    subtype: "success",
    num_turns: 2,
    duration_ms: 79048,
    total_cost_usd: 1.100388,
    _audit_timestamp: "2026-04-17T17:43:34.063Z",
  },
]
  .map((r) => JSON.stringify(r))
  .join("\n");

const SIDECAR = JSON.stringify({
  sessionId: "local_275aa6e2",
  model: "claude-opus-4-7",
  title: "Implement drag-and-drop file upload",
  cwd: "/sessions/eloquent-serene-meitner",
  userSelectedFolders: ["/Users/dev/repos/agents-api"],
});

const ROOT = "/home/Library/Application Support/Claude/local-agent-mode-sessions";
const SESSION_DIR = `${ROOT}/acct/org/local_275aa6e2`;
const AUDIT_PATH = `${SESSION_DIR}/audit.jsonl`;

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

describe("claude desktop transcript source", () => {
  it("counts a message's usage ONCE however many lines it is split across", () => {
    const { turns } = parseClaudeDesktopAudit(AUDIT, "275aa6e2");
    const assistant = turns.filter((t) => t.role === "assistant");
    // Three lines for msg_01AAA, one for msg_01BBB → two turns, not four.
    expect(assistant).toHaveLength(2);
    expect(assistant[0].usage).toEqual({
      input_tokens: 6,
      output_tokens: 8,
      cache_read_tokens: 0,
      cache_write_tokens: 39936,
      cache_write_1h_tokens: 39936,
      web_search_requests: 0,
    });
    // Summing the three lines would have given 119808 cache-write tokens.
    const totalCacheWrite = assistant.reduce((s, t) => s + (t.usage?.cache_write_tokens ?? 0), 0);
    expect(totalCacheWrite).toBe(39936 + 354);
  });

  it("merges the content blocks of one message into a single turn", () => {
    const { turns } = parseClaudeDesktopAudit(AUDIT, "275aa6e2");
    const first = turns.find((t) => t.id.endsWith("msg_01AAA"));
    expect(first?.text).toBe("Looking at the chat component.");
    expect(first?.tools).toEqual(["Bash"]);
  });

  it("takes the session's cost from the result record and never derives one", () => {
    const { turns } = parseClaudeDesktopAudit(AUDIT, "275aa6e2");
    const assistant = turns.filter((t) => t.role === "assistant");
    // Exactly one turn carries cost, and the session totals to the host's figure.
    expect(assistant.filter((t) => t.cost !== undefined)).toHaveLength(1);
    expect(assistant.reduce((s, t) => s + (t.cost ?? 0), 0)).toBeCloseTo(1.100388, 6);
    // `cost_unknown` means "no price for this model" — a priced session must
    // not raise it just because most turns carry no cost of their own.
    expect(assistant.some((t) => t.cost_unknown)).toBe(false);
    expect(assistant.every((t) => t.settlement === "unknown")).toBe(true);
  });

  it("reads a human prompt but not a tool_result carried on a user line", () => {
    const { turns, detect } = parseClaudeDesktopAudit(AUDIT, "275aa6e2");
    const prompts = turns.filter((t) => t.role === "user");
    expect(prompts).toHaveLength(1);
    expect(prompts[0].text).toBe("add a drag and drop upload to the chat");
    // The tool result is still SCANNED — that is where a leaked secret shows up.
    const output = detect.find((u) => u.kind === "tool_output");
    expect(output?.raw).toContain("AWS_SECRET=hunter2");
    expect(output?.tool_name).toBe("Bash");
    const call = detect.find((u) => u.kind === "tool_call");
    expect(call?.tool_name).toBe("Bash");
    expect(call?.target).toBe("cat");
  });

  it("is idempotent: re-parsing mints the same turn ids", () => {
    const a = parseClaudeDesktopAudit(AUDIT, "275aa6e2").turns.map((t) => t.id);
    const b = parseClaudeDesktopAudit(AUDIT, "275aa6e2").turns.map((t) => t.id);
    expect(a).toEqual(b);
    expect(new Set(a).size).toBe(a.length);
  });

  it("tolerates a half-written final line without throwing", () => {
    const partial = `${AUDIT}\n{"type":"assistant","message":{"id":"msg_0`;
    expect(() => parseClaudeDesktopAudit(partial, "275aa6e2")).not.toThrow();
    expect(parseClaudeDesktopAudit(partial, "275aa6e2").turns).toHaveLength(3);
  });

  it("discovers audit logs under the account/org directories", () => {
    const dirs = {
      [ROOT]: ["acct"],
      [`${ROOT}/acct`]: ["org"],
      [`${ROOT}/acct/org`]: ["local_275aa6e2", "spaces.json"],
      [`${ROOT}/acct/org/local_275aa6e2`]: ["audit.jsonl"],
    };
    const files = { [AUDIT_PATH]: AUDIT, [`${SESSION_DIR}.json`]: SIDECAR };
    expect(claudeDesktopSource.discover(ROOT, io(files, dirs))).toEqual([AUDIT_PATH]);
  });

  it("takes title and the real project folder from the sidecar", () => {
    const dirs = {
      [ROOT]: ["acct"],
      [`${ROOT}/acct`]: ["org"],
      [`${ROOT}/acct/org`]: ["local_275aa6e2"],
      [`${ROOT}/acct/org/local_275aa6e2`]: ["audit.jsonl"],
    };
    const result = claudeDesktopSource.parse(
      AUDIT_PATH,
      io({ [AUDIT_PATH]: AUDIT, [`${SESSION_DIR}.json`]: SIDECAR }, dirs),
    );
    expect(result.titles).toEqual([
      {
        session_id: "275aa6e2",
        title: { text: "Implement drag-and-drop file upload", origin: "auto_summary" },
      },
    ]);
    // NOT the VM's /sessions/... path — the folder the person actually chose.
    expect(result.turns[0].cwd).toBe("/Users/dev/repos/agents-api");
  });

  it("derives the session id from the directory, not the file name", () => {
    expect(sessionIdFromPath(AUDIT_PATH)).toBe("275aa6e2");
    expect(claudeDesktopSource.sessionIdOf(AUDIT_PATH)).toBe("275aa6e2");
    expect(sessionIdFromPath("/tmp/audit.jsonl")).toBeUndefined();
  });

  it("is declared metered — it reports real tokens and a real cost", () => {
    expect(claudeDesktopSource.metered).toBe(true);
  });
});
