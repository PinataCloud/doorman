import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  geminiSource,
  parseGeminiSession,
} from "../main/lib/gemini-transcript.js";
import type { SourceIo } from "../main/lib/transcript-sources.js";

const FIXTURES = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  "fixtures/transcripts/gemini",
);
/** The fixture tree stands in for `~/.gemini`, so its `tmp/` is a root. */
const ROOT = path.join(FIXTURES, "tmp");
const CHATS = path.join(ROOT, "doorman-loop", "chats");
const MAIN_SESSION = path.join(CHATS, "session-2026-09-05T14-32-9f3c1a2b.jsonl");
const LEGACY_SESSION = path.join(CHATS, "session-2026-09-05T09-10-4b8e77c0.json");
const TRUNCATED_SESSION = path.join(CHATS, "session-2026-09-05T15-00-c0ffee11.jsonl");
const SUBAGENT_SESSION = path.join(
  CHATS,
  "9f3c1a2b-4d5e-4f60-9a1b-2c3d4e5f6071",
  "7a1b2c3d-4e5f-4061-8a2b-3c4d5e6f7081.jsonl",
);
const SESSION_ID = "9f3c1a2b-4d5e-4f60-9a1b-2c3d4e5f6071";
const PROJECT_ROOT = "/Users/dev/projects/doorman-loop";

/**
 * A `SourceIo` over the real fixture files — the descriptor never touches fs
 * itself, so every read here is one this fake serves. `querySqlite` throws:
 * a Gemini descriptor that reached for a database would be a bug.
 */
function fakeIo(overrides: Partial<SourceIo> = {}): SourceIo {
  return {
    readText: (p) => {
      try {
        return fs.readFileSync(p, "utf8");
      } catch {
        return undefined;
      }
    },
    listDir: (p) => {
      try {
        return fs.readdirSync(p);
      } catch {
        return [];
      }
    },
    stat: (p) => {
      try {
        const s = fs.statSync(p);
        return { size: s.size, mtimeMs: s.mtimeMs, isDirectory: s.isDirectory() };
      } catch {
        return undefined;
      }
    },
    querySqlite: () => {
      throw new Error("the Gemini CLI reader must never open a database");
    },
    ...overrides,
  };
}

describe("geminiSource identity + roots", () => {
  it("declares the ledger id and presence path the registry expects", () => {
    expect(geminiSource.id).toBe("gemini-cli");
    expect(geminiSource.label).toBe("Gemini CLI");
    expect(geminiSource.presencePaths).toEqual([".gemini"]);
    // Gemini CLI records tokens per message, so its sessions are spend.
    expect(geminiSource.metered).toBe(true);
  });

  it("roots at ~/.gemini/tmp, and GEMINI_CLI_HOME adds the relocated dir first", () => {
    const home = path.join("/Users/dev", ".gemini", "tmp");
    expect(geminiSource.roots("/Users/dev", {})).toEqual([home]);
    expect(
      geminiSource.roots("/Users/dev", { GEMINI_CLI_HOME: "/data/gem" } as NodeJS.ProcessEnv),
    ).toEqual([path.join("/data/gem", ".gemini", "tmp"), home]);
    // The override pointing back at home must not yield the same root twice.
    expect(
      geminiSource.roots("/Users/dev", { GEMINI_CLI_HOME: "/Users/dev" } as NodeJS.ProcessEnv),
    ).toEqual([home]);
  });
});

describe("geminiSource.discover", () => {
  it("finds every session document and nothing else", () => {
    const found = geminiSource.discover(ROOT, fakeIo());
    expect(found).toEqual([
      path.join(CHATS, "session-2026-09-05T09-10-4b8e77c0.json"),
      MAIN_SESSION,
      TRUNCATED_SESSION,
      SUBAGENT_SESSION,
    ]);
  });

  it("skips Antigravity, the writer's scratch files and non-session files", () => {
    const found = geminiSource.discover(ROOT, fakeIo());
    expect(found.some((p) => p.includes("antigravity"))).toBe(false);
    expect(found.some((p) => p.endsWith(".tmp-4242"))).toBe(false);
    expect(found.some((p) => p.endsWith("notes.txt"))).toBe(false);
  });

  it("returns nothing for a root that does not exist", () => {
    expect(geminiSource.discover("/no/such/root", fakeIo())).toEqual([]);
  });
});

describe("geminiSource.sessionIdOf", () => {
  it("reads the full id off a subagent file", () => {
    expect(geminiSource.sessionIdOf(SUBAGENT_SESSION)).toBe(
      "7a1b2c3d-4e5f-4061-8a2b-3c4d5e6f7081",
    );
  });

  it("is undefined for a main session file, whose name holds only 8 characters of the id", () => {
    // `session-<ts>-9f3c1a2b.jsonl` — returning "9f3c1a2b" would be a session
    // id that never matches the one inside the file.
    expect(geminiSource.sessionIdOf(MAIN_SESSION)).toBeUndefined();
  });
});

describe("geminiSource.parse — the append log", () => {
  const result = geminiSource.parse(MAIN_SESSION, fakeIo());

  it("emits one turn per surviving user and gemini message", () => {
    expect(result.turns.map((t) => t.id)).toEqual([
      `gemini:${SESSION_ID}:m-0002`,
      `gemini:${SESSION_ID}:m-0003`,
      `gemini:${SESSION_ID}:m-0004`,
      `gemini:${SESSION_ID}:m-0008`,
      `gemini:${SESSION_ID}:m-0009`,
    ]);
    expect(result.turns.every((t) => t.source === "gemini-cli")).toBe(true);
    expect(result.turns.every((t) => t.session_id === SESSION_ID)).toBe(true);
  });

  it("drops slash commands and the CLI's own info banners", () => {
    // m-0001 is "/memory show"; m-0005 is an info message.
    const ids = result.turns.map((t) => t.id);
    expect(ids).not.toContain(`gemini:${SESSION_ID}:m-0001`);
    expect(ids).not.toContain(`gemini:${SESSION_ID}:m-0005`);
  });

  it("honours $rewindTo by dropping the rewound message and everything after it", () => {
    const ids = result.turns.map((t) => t.id);
    expect(ids).not.toContain(`gemini:${SESSION_ID}:m-0006`);
    expect(ids).not.toContain(`gemini:${SESSION_ID}:m-0007`);
  });

  it("takes the session title from the $set summary", () => {
    expect(result.titles).toEqual([
      {
        session_id: SESSION_ID,
        title: { text: "Cap the fetch retry backoff", origin: "auto_summary" },
      },
    ]);
  });

  it("reads cwd from the project's .project_root marker", () => {
    expect(result.turns.every((t) => t.cwd === PROJECT_ROOT)).toBe(true);
  });

  it("maps TokensSummary onto the ledger's usage and prices a known model", () => {
    const turn = result.turns.find((t) => t.id === `gemini:${SESSION_ID}:m-0004`)!;
    expect(turn.role).toBe("assistant");
    expect(turn.model).toBe("gemini-2.5-pro");
    expect(turn.usage).toEqual({
      // input(12000) − cached(8000) + tool(60)
      input_tokens: 4060,
      // output(240) + thoughts(180): thoughts are a SEPARATE bucket upstream,
      // billed at the output rate — unlike Codex's reasoning_output_tokens.
      output_tokens: 420,
      cache_read_tokens: 8000,
      cache_write_tokens: 0,
      cache_write_1h_tokens: 0,
      web_search_requests: 0,
    });
    // gemini-2.5-pro: in $1.25/M, out $10/M, cache read 0.1x input = $0.125/M.
    expect(turn.cost).toBeCloseTo((4060 * 1.25 + 420 * 10 + 8000 * 0.125) / 1_000_000, 12);
    expect(turn.cost_unknown).toBeUndefined();
    // No plan/credits signal exists in the record — never guessed.
    expect(turn.settlement).toBeUndefined();
  });

  it("marks an unpriced model cost_unknown rather than $0", () => {
    const turn = result.turns.find((t) => t.id === `gemini:${SESSION_ID}:m-0009`)!;
    expect(turn.model).toBe("gemini-3-pro-preview"); // not in the pricing table
    expect(turn.usage?.input_tokens).toBe(950);
    expect(turn.cost).toBeUndefined();
    expect(turn.cost_unknown).toBe(true);
  });

  it("keeps the assistant's answer as text but not its thinking stream", () => {
    const turn = result.turns.find((t) => t.id === `gemini:${SESSION_ID}:m-0004`)!;
    expect(turn.text).toBe("Capped the backoff at 30s and re-ran the suite.");
    expect(turn.text).not.toContain("Planning the change");
  });

  it("names the tools a turn called, in call order", () => {
    const withTools = result.turns.find((t) => t.id === `gemini:${SESSION_ID}:m-0003`)!;
    expect(withTools.tools).toEqual(["read_file"]);
    expect(result.turns.find((t) => t.id === `gemini:${SESSION_ID}:m-0004`)!.tools).toEqual([
      "run_shell_command",
    ]);
  });

  it("carries a tool-call-only message with no cost verdict at all", () => {
    // Its tokens land on the NEXT message; calling it cost_unknown would
    // inflate the session's unknown count.
    const turn = result.turns.find((t) => t.id === `gemini:${SESSION_ID}:m-0003`)!;
    expect(turn.usage).toBeUndefined();
    expect(turn.cost).toBeUndefined();
    expect(turn.cost_unknown).toBeUndefined();
  });

  it("produces prompt, tool_call and tool_output detect units with targets", () => {
    expect(result.detect.map((u) => `${u.kind}:${u.tool_name ?? ""}`)).toEqual([
      "prompt:",
      "tool_call:read_file",
      "tool_output:read_file",
      "tool_call:run_shell_command",
      "tool_output:run_shell_command",
      "prompt:",
    ]);
    const read = result.detect.find((u) => u.kind === "tool_call" && u.tool_name === "read_file")!;
    expect(read.target).toBe(`${PROJECT_ROOT}/src/lib/fetch.ts`);
    expect(read.raw).toContain("fetch.ts");
    expect(read.at).toBe("2026-09-05T14:32:19.000Z");
    // A shell target is the program, not the whole command line.
    const shell = result.detect.find(
      (u) => u.kind === "tool_call" && u.tool_name === "run_shell_command",
    )!;
    expect(shell.target).toBe("npm");
    const output = result.detect.find((u) => u.kind === "tool_output" && u.tool_name === "run_shell_command")!;
    expect(output.raw).toBe("3 passed, 0 failed");
    expect(output.turn_id).toBe(`gemini:${SESSION_ID}:m-0004`);
  });

  it("anchors every detect unit to the turn and session it came from", () => {
    for (const unit of result.detect) {
      expect(unit.session_id).toBe(SESSION_ID);
      expect(unit.turn_id.startsWith(`gemini:${SESSION_ID}:`)).toBe(true);
      expect(unit.cwd).toBe(PROJECT_ROOT);
    }
  });

  it("is idempotent — a re-parse mints exactly the same ids", () => {
    const again = geminiSource.parse(MAIN_SESSION, fakeIo());
    expect(again.turns.map((t) => t.id)).toEqual(result.turns.map((t) => t.id));
    expect(again.detect.map((u) => u.turn_id)).toEqual(result.detect.map((u) => u.turn_id));
  });

  it("keeps the same ids when the log grows and a message is rewritten in place", () => {
    // The CLI upserts a message by id when its tokens arrive later; the turn
    // that already existed must converge, not duplicate.
    const grown =
      fs.readFileSync(MAIN_SESSION, "utf8") +
      JSON.stringify({
        id: "m-0003",
        timestamp: "2026-09-05T14:32:18.000Z",
        type: "gemini",
        content: "Read the helper.",
        model: "gemini-2.5-pro",
        tokens: { input: 500, output: 20, cached: 0, thoughts: 0, tool: 0, total: 520 },
      }) +
      "\n";
    const reparsed = parseGeminiSession(grown, "unused", PROJECT_ROOT);
    expect(reparsed.turns.map((t) => t.id)).toEqual(result.turns.map((t) => t.id));
    const rewritten = reparsed.turns.find((t) => t.id === `gemini:${SESSION_ID}:m-0003`)!;
    expect(rewritten.usage?.input_tokens).toBe(500);
    expect(rewritten.text).toBe("Read the helper.");
  });
});

describe("geminiSource.parse — the legacy whole-file record", () => {
  const result = geminiSource.parse(LEGACY_SESSION, fakeIo());

  it("reads a `.json` ConversationRecord the same way as the append log", () => {
    expect(result.turns.map((t) => t.id)).toEqual([
      "gemini:4b8e77c0-1d2e-4f30-8a4b-5c6d7e8f9012:n-0001",
      "gemini:4b8e77c0-1d2e-4f30-8a4b-5c6d7e8f9012:n-0002",
    ]);
    expect(result.titles[0]?.title.text).toBe("Rename the digest scheduler flag");
    const assistant = result.turns[1]!;
    expect(assistant.model).toBe("gemini-2.5-flash");
    // gemini-2.5-flash: in $0.30/M, out $2.50/M.
    expect(assistant.cost).toBeCloseTo((4200 * 0.3 + 130 * 2.5) / 1_000_000, 12);
    expect(assistant.tools).toEqual(["write_file"]);
    expect(assistant.cwd).toBe(PROJECT_ROOT);
  });
});

describe("geminiSource.parse — subagent documents", () => {
  it("parses a nested subagent session under its own id", () => {
    const result = geminiSource.parse(SUBAGENT_SESSION, fakeIo());
    expect(result.turns.map((t) => t.session_id)).toEqual([
      "7a1b2c3d-4e5f-4061-8a2b-3c4d5e6f7081",
      "7a1b2c3d-4e5f-4061-8a2b-3c4d5e6f7081",
    ]);
    const assistant = result.turns[1]!;
    expect(assistant.model).toBe("gemini-3.1-flash-lite");
    expect(assistant.usage).toEqual({
      input_tokens: 2000,
      output_tokens: 90,
      cache_read_tokens: 600,
      cache_write_tokens: 0,
      cache_write_1h_tokens: 0,
      web_search_requests: 0,
    });
    // The marker file is two levels up from a nested document.
    expect(assistant.cwd).toBe(PROJECT_ROOT);
  });
});

describe("geminiSource.parse — totality", () => {
  it("yields what it can from a half-written trailing line and never throws", () => {
    const result = geminiSource.parse(TRUNCATED_SESSION, fakeIo());
    expect(result.turns).toHaveLength(1);
    expect(result.turns[0]!.role).toBe("user");
    expect(result.turns[0]!.text).toBe("summarise the migration lineage");
  });

  it("returns an empty result for a missing or empty document", () => {
    const empty = { turns: [], titles: [], detect: [] };
    expect(geminiSource.parse("/no/such/session.jsonl", fakeIo())).toEqual(empty);
    expect(
      geminiSource.parse(MAIN_SESSION, fakeIo({ readText: () => "" })),
    ).toEqual(empty);
  });

  it("survives a document that is valid JSON but not a conversation at all", () => {
    expect(parseGeminiSession('{"unexpected":true}', "fallback")).toEqual({
      turns: [],
      titles: [],
      detect: [],
    });
    expect(parseGeminiSession("not json at all\n\n", "fallback")).toEqual({
      turns: [],
      titles: [],
      detect: [],
    });
  });

  it("falls back to the caller's session id when no metadata line has landed yet", () => {
    const contents = `${JSON.stringify({
      id: "x-1",
      timestamp: "2026-09-05T16:00:00.000Z",
      type: "user",
      content: "first prompt, metadata still buffered",
    })}\n`;
    const { turns } = parseGeminiSession(contents, "/tmp/session-x.jsonl");
    expect(turns[0]!.session_id).toBe("/tmp/session-x.jsonl");
    expect(turns[0]!.id).toBe("gemini:/tmp/session-x.jsonl:x-1");
  });

  it("clears the conversation when $rewindTo names an id it has not seen", () => {
    const contents = [
      JSON.stringify({ sessionId: "s1", projectHash: "p" }),
      JSON.stringify({ id: "a", timestamp: "2026-09-05T16:00:00.000Z", type: "user", content: "one" }),
      JSON.stringify({ $rewindTo: "never-written" }),
    ].join("\n");
    expect(parseGeminiSession(contents, "s1").turns).toEqual([]);
  });

  it("lets a $set replace the whole message list", () => {
    const contents = [
      JSON.stringify({ sessionId: "s2", projectHash: "p" }),
      JSON.stringify({ id: "a", timestamp: "2026-09-05T16:00:00.000Z", type: "user", content: "one" }),
      JSON.stringify({
        $set: {
          messages: [
            { id: "b", timestamp: "2026-09-05T16:01:00.000Z", type: "user", content: "two" },
          ],
        },
      }),
    ].join("\n");
    const { turns } = parseGeminiSession(contents, "s2");
    expect(turns.map((t) => t.id)).toEqual(["gemini:s2:b"]);
  });

  it("skips a message with no timestamp and a gemini message with nothing on it", () => {
    const contents = [
      JSON.stringify({ sessionId: "s3", projectHash: "p" }),
      JSON.stringify({ id: "a", type: "user", content: "no instant, unchartable" }),
      JSON.stringify({ id: "b", timestamp: "2026-09-05T16:02:00.000Z", type: "gemini", content: "" }),
    ].join("\n");
    expect(parseGeminiSession(contents, "s3").turns).toEqual([]);
  });

  it("drops the ambient wrappers Gemini CLI injects as user messages", () => {
    const contents = [
      JSON.stringify({ sessionId: "s4", projectHash: "p" }),
      JSON.stringify({
        id: "a",
        timestamp: "2026-09-05T16:03:00.000Z",
        type: "user",
        content: "<session_context>cwd=/w</session_context>",
      }),
      JSON.stringify({
        id: "b",
        timestamp: "2026-09-05T16:03:01.000Z",
        type: "user",
        content: "<hook_context>pre-tool</hook_context>",
      }),
      JSON.stringify({
        id: "c",
        timestamp: "2026-09-05T16:03:02.000Z",
        type: "user",
        content: "?",
      }),
    ].join("\n");
    expect(parseGeminiSession(contents, "s4").turns).toEqual([]);
  });
});

describe("geminiSource.parse — caps", () => {
  const long = (n: number) => "x".repeat(n);

  it("caps stored turn text, the tools list and a scanned tool output", () => {
    const toolCalls = Array.from({ length: 40 }, (_, i) => ({
      id: `tc-${i}`,
      name: `tool_${i}`,
      args: {},
      status: "success",
      timestamp: "2026-09-05T17:00:00.000Z",
    }));
    const contents = [
      JSON.stringify({ sessionId: "s5", projectHash: "p" }),
      JSON.stringify({
        id: "u",
        timestamp: "2026-09-05T17:00:00.000Z",
        type: "user",
        content: long(9_000),
      }),
      JSON.stringify({
        id: "g",
        timestamp: "2026-09-05T17:00:01.000Z",
        type: "gemini",
        content: long(9_000),
        model: "gemini-2.5-flash",
        tokens: { input: 10, output: 5, cached: 0, thoughts: 0, tool: 0, total: 15 },
        toolCalls: [
          ...toolCalls,
          {
            id: "tc-big",
            name: "run_shell_command",
            args: { command: "cat huge.log" },
            status: "success",
            timestamp: "2026-09-05T17:00:02.000Z",
            result: [
              {
                functionResponse: {
                  id: "tc-big",
                  name: "run_shell_command",
                  response: { output: long(200_000) },
                },
              },
            ],
          },
        ],
      }),
    ].join("\n");
    const { turns, detect } = parseGeminiSession(contents, "s5");
    expect(turns[0]!.text).toHaveLength(4_000); // TURN_TEXT_MAX_CHARS
    expect(turns[1]!.text).toHaveLength(4_000);
    expect(turns[1]!.tools).toHaveLength(32); // TURN_TOOLS_MAX
    const output = detect.find((u) => u.kind === "tool_output")!;
    expect(output.raw).toHaveLength(64_000); // TOOL_OUTPUT_MAX_CHARS
    // The prompt unit is scanned in FULL — the cap is on what is stored.
    expect(detect.find((u) => u.kind === "prompt")!.raw).toHaveLength(9_000);
  });
});
