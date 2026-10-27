import { describe, expect, it } from "vitest";
import {
  parseClaudeTranscript,
  toolTarget,
} from "../main/lib/cc-transcript.js";

/**
 * The backfill's ground truth is the on-disk transcript, so the parser carries
 * two rules: usage collapses on message id (streamed
 * content-block lines repeat identical usage — anything else double-counts),
 * while text and tool_use blocks MERGE across those lines.
 */

const SESSION = "11111111-2222-3333-4444-555555555555";

function assistantLine(opts: {
  id: string;
  content: unknown[];
  ts?: string;
  usage?: Record<string, unknown>;
}): string {
  return JSON.stringify({
    type: "assistant",
    uuid: "u-" + opts.id + "-" + Math.abs(JSON.stringify(opts.content).length),
    timestamp: opts.ts ?? "2026-08-20T10:00:01.000Z",
    sessionId: SESSION,
    cwd: "/Users/dev/repo",
    gitBranch: "main",
    message: {
      id: opts.id,
      model: "claude-opus-5",
      role: "assistant",
      content: opts.content,
      usage: opts.usage ?? {
        input_tokens: 100,
        output_tokens: 50,
        cache_creation_input_tokens: 1000,
        cache_read_input_tokens: 4000,
        cache_creation: { ephemeral_1h_input_tokens: 1000, ephemeral_5m_input_tokens: 0 },
        server_tool_use: { web_search_requests: 0 },
      },
    },
  });
}

describe("parseClaudeTranscript", () => {
  it("collapses streamed lines by message id and merges their content", () => {
    const contents = [
      JSON.stringify({
        type: "user",
        uuid: "prompt-1",
        timestamp: "2026-08-20T10:00:00.000Z",
        sessionId: SESSION,
        message: { role: "user", content: "fix the login bug" },
      }),
      assistantLine({ id: "msg_1", content: [{ type: "text", text: "Looking." }] }),
      assistantLine({
        id: "msg_1",
        content: [{ type: "tool_use", name: "Bash", input: { command: "npm test" } }],
        ts: "2026-08-20T10:00:05.000Z",
      }),
    ].join("\n");

    const { turns, detect } = parseClaudeTranscript(contents, SESSION);
    const assistants = turns.filter((t) => t.role === "assistant");
    expect(assistants).toHaveLength(1);
    const turn = assistants[0]!;
    expect(turn.id).toBe("msg_1");
    expect(turn.usage).toEqual({
      input_tokens: 100,
      output_tokens: 50,
      cache_read_tokens: 4000,
      cache_write_tokens: 1000,
      cache_write_1h_tokens: 1000,
      web_search_requests: 0,
    });
    expect(turn.text).toBe("Looking.");
    expect(turn.tools).toEqual(["Bash"]);
    expect(turn.cwd).toBe("/Users/dev/repo");
    expect(turn.git_branch).toBe("main");

    // Cost from the claude-opus-5 row: in $5/M, out $25/M, read $0.5/M, 1h write $10/M.
    // 100 in + 50 out + 4000 read + 1000 write (all of it 1h).
    const expected = (100 * 5 + 50 * 25 + 4000 * 0.5 + 1000 * 10) / 1_000_000;
    expect(turn.cost).toBeCloseTo(expected, 12);
    expect(turn.cost_unknown).toBeUndefined();

    // Detection saw the prompt AND the tool call, each anchored to its turn.
    expect(detect.map((u) => u.kind).sort()).toEqual(["prompt", "tool_call"]);
    const tool = detect.find((u) => u.kind === "tool_call")!;
    expect(tool.turn_id).toBe("msg_1");
    expect(tool.tool_name).toBe("Bash");
    expect(tool.target).toBe("npm");
  });

  it("skips sidechain prompts, command wrappers and tool_result users", () => {
    const contents = [
      JSON.stringify({
        type: "user",
        uuid: "side-1",
        isSidechain: true,
        timestamp: "2026-08-20T10:00:00.000Z",
        sessionId: SESSION,
        message: { role: "user", content: "subagent prompt" },
      }),
      JSON.stringify({
        type: "user",
        uuid: "cmd-1",
        timestamp: "2026-08-20T10:00:01.000Z",
        sessionId: SESSION,
        message: { role: "user", content: "<command-name>/model</command-name>" },
      }),
      JSON.stringify({
        type: "user",
        uuid: "tool-res",
        timestamp: "2026-08-20T10:00:02.000Z",
        sessionId: SESSION,
        message: { role: "user", content: [{ type: "tool_result", content: "ok" }] },
      }),
    ].join("\n");
    const { turns } = parseClaudeTranscript(contents, SESSION);
    expect(turns).toHaveLength(0);
  });

  it("keeps user prompts that begin with markup", () => {
    const prompts = [
      '<div class="card">Fix the accessibility issue</div>',
      "<configuration>\n  <cache enabled=\"true\" />\n</configuration>",
    ];
    const contents = prompts
      .map((content, index) =>
        JSON.stringify({
          type: "user",
          uuid: `markup-${index}`,
          timestamp: `2026-08-20T10:00:0${index}.000Z`,
          sessionId: SESSION,
          message: { role: "user", content },
        }),
      )
      .join("\n");

    const { turns, detect } = parseClaudeTranscript(contents, SESSION);
    expect(turns.map((turn) => turn.text)).toEqual(prompts);
    expect(detect.map((unit) => unit.raw)).toEqual(prompts);
  });

  it("captures tool_result blocks as tool_output units, named by their tool_use id", () => {
    const contents = [
      assistantLine({
        id: "msg_1",
        content: [
          { type: "tool_use", id: "toolu_01", name: "Read", input: { file_path: "notes.md" } },
        ],
      }),
      JSON.stringify({
        type: "user",
        uuid: "tool-res-1",
        timestamp: "2026-08-20T10:00:06.000Z",
        sessionId: SESSION,
        message: {
          role: "user",
          content: [
            { type: "tool_result", tool_use_id: "toolu_01", content: "fetched page body" },
            // Text-block content shape, and an unmatched id (no name known).
            { type: "tool_result", tool_use_id: "toolu_99", content: [{ type: "text", text: "second output" }] },
          ],
        },
      }),
    ].join("\n");

    const { turns, detect } = parseClaudeTranscript(contents, SESSION);
    // Outputs are scan units, never ledger turns.
    expect(turns.filter((t) => t.role === "user")).toHaveLength(0);
    const outputs = detect.filter((u) => u.kind === "tool_output");
    expect(outputs).toHaveLength(2);
    expect(outputs[0]).toMatchObject({
      raw: "fetched page body",
      tool_name: "Read",
      target: "notes.md",
      turn_id: "tool-res-1",
      // The ledger turn to file a finding under: the assistant that called Read.
      anchor_turn_id: "msg_1",
      session_id: SESSION,
    });
    expect(outputs[1]!.raw).toBe("second output");
    expect(outputs[1]!.tool_name).toBeUndefined();
    expect(outputs[1]!.anchor_turn_id).toBeUndefined();
  });

  it("lifts ai-title records as auto_summary, last one winning", () => {
    const contents = [
      JSON.stringify({ type: "ai-title", aiTitle: "First title", sessionId: SESSION }),
      JSON.stringify({ type: "ai-title", aiTitle: "Better title", sessionId: SESSION }),
    ].join("\n");
    const { titles } = parseClaudeTranscript(contents, SESSION);
    expect(titles).toEqual([
      { session_id: SESSION, title: { text: "Better title", origin: "auto_summary" } },
    ]);
  });

  it("prices unknown models as cost_unknown, never $0-silently", () => {
    const contents = assistantLine({
      id: "msg_x",
      content: [],
      usage: { input_tokens: 10, output_tokens: 10, cache_creation_input_tokens: 0, cache_read_input_tokens: 0 },
    }).replace('"claude-opus-5"', '"claude-brand-new"');
    const { turns } = parseClaudeTranscript(contents, SESSION);
    expect(turns[0]!.cost).toBeUndefined();
    expect(turns[0]!.cost_unknown).toBe(true);
  });

  it("tolerates malformed lines", () => {
    const contents = ["not json", "{\"type\":42}", ""].join("\n");
    expect(parseClaudeTranscript(contents, SESSION).turns).toHaveLength(0);
  });
});

describe("toolTarget", () => {
  it("extracts the Bash program and file-tool paths", () => {
    expect(toolTarget("Bash", { command: "  git push --force" })).toBe("git");
    expect(toolTarget("Write", { file_path: "/tmp/x.ts" })).toBe("/tmp/x.ts");
    expect(toolTarget("Read", {})).toBeUndefined();
  });
});
