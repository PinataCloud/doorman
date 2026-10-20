import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { openclawSource, parseOpenclawSession } from "../main/lib/openclaw-transcript.js";
import type { SourceIo } from "../main/lib/transcript-sources.js";

const FIXTURES = path.join(path.dirname(fileURLToPath(import.meta.url)), "fixtures/transcripts/openclaw");
/** The fixture tree stands in for `~/.openclaw`, so its `agents/` is the root. */
const ROOT = path.join(FIXTURES, "agents");
const MAIN_SESSIONS = path.join(ROOT, "main", "sessions");
const MAIN_ID = "3f7a9c12-5b4e-4d8a-9c1e-7b2d4f6a8e01";
const MAIN_FILE = path.join(MAIN_SESSIONS, `2026-09-06T10-00-00-000Z_${MAIN_ID}.jsonl`);
const LEGACY_FILE = path.join(MAIN_SESSIONS, "legacy-flat.jsonl");
const WORK_ID = "9a8b7c6d-5e4f-4a3b-2c1d-0e9f8a7b6c5d";
const WORK_FILE = path.join(ROOT, "work", "sessions", `${WORK_ID}.jsonl`);
/** The one real recording (see _provenance.md): OpenClaw 2026.3.8, 2026-09-08. */
const LIVE_ID = "doorman-e2e-1";
const LIVE_FILE = path.join(MAIN_SESSIONS, `${LIVE_ID}.jsonl`);

/** A `SourceIo` over the fixture files; `querySqlite` throws — OpenClaw's
 * transcripts are JSONL and a reader that opened a database would be a bug. */
function fakeIo(): SourceIo {
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
      throw new Error("the OpenClaw reader must never open a database");
    },
  };
}

describe("the descriptor", () => {
  it("names itself and its footprint", () => {
    expect(openclawSource.id).toBe("openclaw");
    expect(openclawSource.label).toBe("OpenClaw");
    expect(openclawSource.presencePaths).toEqual([".openclaw"]);
    expect(openclawSource.metered).toBe(true);
  });

  it("roots at <state>/agents, honouring OPENCLAW_STATE_DIR", () => {
    expect(openclawSource.roots("/Users/dev", {})).toEqual([path.join("/Users/dev", ".openclaw", "agents")]);
    expect(openclawSource.roots("/Users/dev", { OPENCLAW_STATE_DIR: "/srv/claw" })).toEqual([path.join("/srv/claw", "agents")]);
  });

  it("discovers every agent's session files and skips the index", () => {
    const found = openclawSource.discover(ROOT, fakeIo());
    expect(found).toEqual([MAIN_FILE, LIVE_FILE, LEGACY_FILE, WORK_FILE]);
    expect(found.some((f) => f.endsWith("sessions.json"))).toBe(false);
    expect(openclawSource.discover("/nowhere", fakeIo())).toEqual([]);
  });

  it("reads the session id off both file-name shapes", () => {
    expect(openclawSource.sessionIdOf(MAIN_FILE)).toBe(MAIN_ID);
    expect(openclawSource.sessionIdOf(WORK_FILE)).toBe(WORK_ID);
    expect(openclawSource.sessionIdOf(LEGACY_FILE)).toBeUndefined();
  });
});

describe("parsing a v3 session", () => {
  const result = openclawSource.parse(MAIN_FILE, fakeIo());

  it("takes the session id and cwd from the header and the title from session_info", () => {
    expect(result.titles).toEqual([
      { session_id: MAIN_ID, title: { text: "Rotate the staging credentials", origin: "auto_summary" } },
    ]);
    for (const turn of result.turns) {
      expect(turn.session_id).toBe(MAIN_ID);
      expect(turn.cwd).toBe("/Users/dev/projects/api");
      expect(turn.source).toBe("openclaw");
    }
  });

  it("mints stable ids from the entry ids and skips the errored empty reply", () => {
    expect(result.turns.map((t) => t.id)).toEqual([
      `openclaw:${MAIN_ID}:c3d4e5f6`,
      `openclaw:${MAIN_ID}:d4e5f6a7`,
      `openclaw:${MAIN_ID}:f6a7b8c9`,
    ]);
    // Re-parsing converges: same ids, same order.
    expect(openclawSource.parse(MAIN_FILE, fakeIo()).turns.map((t) => t.id)).toEqual(result.turns.map((t) => t.id));
  });

  it("honours the host's own cost when it priced the call, and prices the rest itself", () => {
    const [, first, second] = result.turns;
    expect(first!.role).toBe("assistant");
    expect(first!.model).toBe("claude-sonnet-4-5");
    expect(first!.usage).toEqual({
      input_tokens: 1200,
      output_tokens: 85,
      cache_read_tokens: 4000,
      cache_write_tokens: 600,
      cache_write_1h_tokens: 0,
      web_search_requests: 0,
    });
    expect(first!.cost).toBe(0.008325);
    expect(first!.cost_unknown).toBeUndefined();
    // The thinking block is not text; the answer is.
    expect(first!.text).toBe("Reading the current secrets file first.");
    expect(first!.tools).toEqual(["read"]);

    // OpenRouter `vendor/model` with a zero host cost: priced from the table.
    expect(second!.model).toBe("anthropic/claude-sonnet-4-5");
    expect(second!.usage?.input_tokens).toBe(38506);
    expect(second!.cost).toBeGreaterThan(0);
    expect(second!.cost_unknown).toBeUndefined();
    expect(second!.tools).toEqual(["exec"]);
    expect(second!.text).toBeUndefined();
  });

  it("emits prompt, tool_call and tool_output units, anchoring the result to the calling turn", () => {
    const prompt = result.detect.find((u) => u.kind === "prompt");
    expect(prompt?.raw).toContain("Rotate the staging DB password");
    const calls = result.detect.filter((u) => u.kind === "tool_call");
    expect(calls.map((u) => [u.tool_name, u.target])).toEqual([
      ["read", "deploy/secrets.yaml"],
      ["exec", "aws"],
    ]);
    const output = result.detect.find((u) => u.kind === "tool_output");
    expect(output?.tool_name).toBe("read");
    expect(output?.raw).toContain("wJalrXUtnFEMI/S5FRSUZ/tQjWbrCYPZPAKTFWYN");
    expect(output?.anchor_turn_id).toBe(`openclaw:${MAIN_ID}:d4e5f6a7`);
    expect(output?.turn_id).toBe(`openclaw:${MAIN_ID}:e5f6a7b8`);
    expect(output?.cwd).toBe("/Users/dev/projects/api");
  });
});

describe("the live recording (OpenClaw 2026.3.8, 2026-09-08)", () => {
  const result = openclawSource.parse(LIVE_FILE, fakeIo());
  const assistants = result.turns.filter((t) => t.role === "assistant");

  it("reads the session and both prompts off a file the CLI kept appending to", () => {
    // `openclaw agent --session-id doorman-e2e-1` named the file after that
    // id, which is not a UUID — so the NAME yields nothing (the gateway's own
    // sessions are UUIDs) and the header's `id` carries the session instead.
    expect(openclawSource.sessionIdOf(LIVE_FILE)).toBeUndefined();
    const prompts = result.turns.filter((t) => t.role === "user");
    expect(prompts.map((t) => t.id)).toEqual([`openclaw:${LIVE_ID}:48804c98`, `openclaw:${LIVE_ID}:67f3ec1b`]);
    expect(prompts[0]?.text).toContain("echo DOORMAN_DENY_ME");
    expect(prompts[0]?.cwd).toBe("/Users/dev/.openclaw/workspace");
    for (const t of result.turns) expect(t.session_id).toBe(LIVE_ID);
  });

  it("meters every assistant message with pi-ai's usage and honours the host's own cost", () => {
    expect(assistants).toHaveLength(7);
    for (const t of assistants) expect(t.model).toBe("claude-opus-4-6");
    const first = assistants[0]!;
    expect(first.id).toBe(`openclaw:${LIVE_ID}:b44d2037`);
    expect(first.usage).toMatchObject({ input_tokens: 3, output_tokens: 104, cache_read_tokens: 0, cache_write_tokens: 11692 });
    expect(first.cost).toBeCloseTo(0.07569, 6);
    // Two parallel tool calls on one assistant message.
    expect(first.tools).toEqual(["exec", "exec"]);
    // A thinking part alongside text and a tool call is read, not tripped over.
    const thinking = assistants.find((t) => t.id === `openclaw:${LIVE_ID}:89005650`);
    expect(thinking?.tools).toEqual(["write"]);
    expect(thinking?.cost).toBeCloseTo(0.01016125, 8);
    const total = assistants.reduce((sum, t) => sum + (t.cost ?? 0), 0);
    expect(total).toBeCloseTo(0.13117, 4);
  });

  it("surfaces the four file/shell calls and the tool results, including how a guard deny looks on this host", () => {
    const calls = result.detect.filter((u) => u.kind === "tool_call");
    expect(calls.map((u) => u.tool_name)).toEqual(["exec", "exec", "write", "read", "edit", "exec"]);
    const outputs = result.detect.filter((u) => u.kind === "tool_output");
    // pi records a blocked call as a completed tool result whose text is the
    // runner's error — `isError: false` — carrying our reason verbatim.
    const denied = outputs.filter((u) => u.raw.includes("Doorman flagged this tool call: E2E deny marker."));
    expect(denied).toHaveLength(2);
    expect(denied[0]?.tool_name).toBe("exec");
    expect(denied[0]?.anchor_turn_id).toBe(`openclaw:${LIVE_ID}:b44d2037`);
    expect(outputs.some((u) => u.tool_name === "exec" && u.raw.includes("DOORMAN_ALLOW_ME"))).toBe(true);
  });
});

describe("edge shapes", () => {
  it("marks an unpriceable custom-provider model cost_unknown and survives a half-written last line", () => {
    const result = openclawSource.parse(WORK_FILE, fakeIo());
    expect(result.turns).toHaveLength(1);
    const turn = result.turns[0]!;
    expect(turn.session_id).toBe(WORK_ID);
    expect(turn.model).toBe("deepseek/deepseek-v3.2");
    expect(turn.usage?.input_tokens).toBe(900);
    expect(turn.cost).toBeUndefined();
    expect(turn.cost_unknown).toBe(true);
    expect(turn.cwd).toBe("/Users/dev/notes");
  });

  it("reads v1 flat lines, minting ids from the line number and instants from epoch ms", () => {
    const result = openclawSource.parse(LEGACY_FILE, fakeIo());
    expect(result.turns.map((t) => [t.id, t.role, t.at])).toEqual([
      [`openclaw:${LEGACY_FILE}:line0`, "user", "2026-02-06T05:32:50.000Z"],
      [`openclaw:${LEGACY_FILE}:line1`, "assistant", "2026-02-06T05:32:58.327Z"],
    ]);
    const reply = result.turns[1]!;
    expect(reply.model).toBe("MiniMax-M2.1-lightning");
    expect(reply.usage?.input_tokens).toBe(12);
    // No host cost and no table price: honest unknown, never $0.
    expect(reply.cost_unknown).toBe(true);
    expect(reply.cwd).toBeUndefined();
  });

  it("returns nothing for a missing or empty document, and never throws on garbage", () => {
    expect(openclawSource.parse("/nowhere.jsonl", fakeIo())).toEqual({ turns: [], titles: [], detect: [] });
    expect(parseOpenclawSession("", "s")).toEqual({ turns: [], titles: [], detect: [] });
    expect(parseOpenclawSession("not json\n{\n[]\n{\"type\":\"message\"}\n", "s").turns).toEqual([]);
  });

  it("keeps heartbeat-shaped turns: background spend is still spend", () => {
    const lines = [
      JSON.stringify({ type: "session", version: 3, id: "h1", timestamp: "2026-09-06T12:00:00.000Z" }),
      JSON.stringify({
        type: "message",
        id: "aaaa1111",
        parentId: null,
        timestamp: "2026-09-06T12:00:00.500Z",
        message: { role: "user", content: [{ type: "text", text: "HEARTBEAT" }], timestamp: 1 },
      }),
      JSON.stringify({
        type: "message",
        id: "bbbb2222",
        parentId: "aaaa1111",
        timestamp: "2026-09-06T12:00:02.000Z",
        message: {
          role: "assistant",
          content: [{ type: "text", text: "HEARTBEAT_OK" }],
          provider: "openai",
          model: "gpt-5",
          usage: { input: 3000, output: 4, cacheRead: 0, cacheWrite: 0, totalTokens: 3004, cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 } },
          stopReason: "stop",
          timestamp: 2,
        },
      }),
    ].join("\n");
    const result = parseOpenclawSession(lines, "fallback");
    expect(result.turns).toHaveLength(2);
    expect(result.turns[1]!.cost).toBeGreaterThan(0);
  });
});
