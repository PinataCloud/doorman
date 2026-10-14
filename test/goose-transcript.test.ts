/**
 * The Goose transcript source — a SQLite `sessions.db` reader.
 *
 * The io is a fake over in-memory rows whose `querySqlite` understands exactly
 * the two statements the descriptor issues: a parser that widened its SELECT
 * would fail here rather than quietly read a whole chat database. Rows are
 * shaped from block/goose `session_manager.rs` + `message.rs` (fetched
 * 2026-09-06), NOT from a live database — see the source header.
 */
import { describe, expect, it } from "vitest";
import { gooseSource, parseGooseSessionsDb } from "../main/lib/goose-transcript.js";
import type { SourceIo } from "../main/lib/transcript-sources.js";

const HOME = "/Users/dev";
const ROOT = `${HOME}/Library/Application Support/Block.block.goose/sessions`;
const DB = `${ROOT}/sessions.db`;

const SESSIONS_SQL =
  "SELECT id, name, description, user_set_name, working_dir, created_at, provider_name, model_config_json, " +
  "accumulated_input_tokens, accumulated_output_tokens, accumulated_cache_read_tokens, " +
  "accumulated_cache_write_tokens, accumulated_cost FROM sessions";
const MESSAGES_SQL =
  "SELECT id, role, content_json, created_timestamp, metadata_json FROM messages WHERE session_id = ? " +
  "ORDER BY created_timestamp, id";

interface FakeDb {
  sessions: Record<string, unknown>[];
  messages: Record<string, unknown>[];
}

function makeIo(db: FakeDb | undefined, dirs: Record<string, string[]> = {}): SourceIo {
  return {
    readText: () => undefined,
    listDir: (path) => dirs[path] ?? [],
    stat: (path) =>
      db && path === DB
        ? { size: 4096, mtimeMs: 1788000000000, isDirectory: false }
        : dirs[path]
          ? { size: 0, mtimeMs: 1788000000000, isDirectory: true }
          : undefined,
    querySqlite: (path, sql, params) => {
      if (!db || path !== DB) throw new Error(`no such database: ${path}`);
      if (sql === SESSIONS_SQL) return db.sessions;
      if (sql === MESSAGES_SQL) {
        const [sessionId] = params ?? [];
        return db.messages
          .filter((m) => m.session_id === sessionId)
          .sort((a, b) => Number(a.created_timestamp) - Number(b.created_timestamp) || Number(a.id) - Number(b.id));
      }
      throw new Error(`unexpected sql: ${sql}`);
    },
  };
}

const json = (value: unknown): string => JSON.stringify(value);
/** 2026-09-06T10:15:00Z as unix seconds — Goose's `created_timestamp` unit. */
const T0 = Date.UTC(2026, 8, 6, 10, 15, 0) / 1000;

/** A modern session: per-message usage with Goose's own cost on one turn. */
function modernDb(): FakeDb {
  const S = "20260906_101500";
  return {
    sessions: [
      {
        id: S,
        name: "",
        description: "Rotate the staging credentials",
        user_set_name: 0,
        working_dir: "/Users/dev/projects/api",
        created_at: "2026-09-06 10:15:00",
        provider_name: "anthropic",
        model_config_json: json({ model_name: "goose-test-model", context_limit: 200000 }),
        accumulated_input_tokens: 9999,
        accumulated_output_tokens: 9999,
        accumulated_cache_read_tokens: 0,
        accumulated_cache_write_tokens: 0,
        accumulated_cost: 9.99,
      },
    ],
    messages: [
      {
        id: 1,
        session_id: S,
        role: "user",
        content_json: json([{ type: "text", text: "Rotate the staging credentials and restart the API." }]),
        created_timestamp: T0,
        metadata_json: json({ userVisible: true, agentVisible: true }),
      },
      {
        id: 2,
        session_id: S,
        role: "assistant",
        content_json: json([
          { type: "thinking", thinking: "plan", signature: "" },
          { type: "text", text: "Rotating now." },
          {
            type: "toolRequest",
            id: "call_1",
            toolCall: {
              status: "success",
              value: { name: "developer__shell", arguments: { command: "aws secretsmanager rotate-secret --secret-id staging/api" } },
            },
          },
        ]),
        created_timestamp: T0 + 12,
        metadata_json: json({
          userVisible: true,
          agentVisible: true,
          inference: { provider: "anthropic", requestedModel: "goose-test-model", resolvedModel: "goose-test-model-2026" },
          usage: { inputTokens: 1200, outputTokens: 80, totalTokens: 1280, cacheReadTokens: 900, cacheWriteTokens: 100, cost: 0.0123, costSource: "provider" },
        }),
      },
      {
        // The tool RESULT travels in a user-role message.
        id: 3,
        session_id: S,
        role: "user",
        content_json: json([
          {
            type: "toolResponse",
            id: "call_1",
            toolResult: { status: "success", value: { content: [{ type: "text", text: "Secret rotated. AWS_SECRET_ACCESS_KEY=abc123" }], isError: false } },
          },
        ]),
        created_timestamp: T0 + 20,
        metadata_json: json({ userVisible: true, agentVisible: true }),
      },
      {
        // Compaction summary: agent-only, never a person's prompt.
        id: 4,
        session_id: S,
        role: "user",
        content_json: json([{ type: "text", text: "Summary of the conversation so far…" }]),
        created_timestamp: T0 + 25,
        metadata_json: json({ userVisible: false, agentVisible: true }),
      },
      {
        // Usage without a host cost and a model the pricing table does not know.
        id: 5,
        session_id: S,
        role: "assistant",
        content_json: json([{ type: "text", text: "Done — the API is back up." }]),
        created_timestamp: (T0 + 30) * 1000, // milliseconds, as Goose guards for
        metadata_json: json({
          userVisible: true,
          agentVisible: true,
          usage: { inputTokens: 1500, outputTokens: 40, totalTokens: 1540 },
        }),
      },
      {
        // A placeholder with nothing on it is not a turn.
        id: 6,
        session_id: S,
        role: "assistant",
        content_json: json([]),
        created_timestamp: T0 + 31,
        metadata_json: json({ userVisible: true, agentVisible: true }),
      },
    ],
  };
}

describe("parseGooseSessionsDb", () => {
  it("reads prompts, assistant turns, per-message usage and Goose's own cost", () => {
    const result = parseGooseSessionsDb(DB, makeIo(modernDb()));
    const ids = result.turns.map((t) => t.id);
    expect(ids).toEqual([
      "goose:20260906_101500:1",
      "goose:20260906_101500:2",
      "goose:20260906_101500:5",
    ]);
    const [prompt, first, last] = result.turns;
    expect(prompt).toMatchObject({
      source: "goose",
      role: "user",
      at: "2026-09-06T10:15:00.000Z",
      cwd: "/Users/dev/projects/api",
      text: "Rotate the staging credentials and restart the API.",
    });
    // Per-message usage, the resolved model, and the host's own cost win.
    expect(first).toMatchObject({
      role: "assistant",
      model: "goose-test-model-2026",
      usage: { input_tokens: 1200, output_tokens: 80, cache_read_tokens: 900, cache_write_tokens: 100 },
      cost: 0.0123,
      tools: ["developer__shell"],
      text: "Rotating now.",
    });
    expect(first!.cost_unknown).toBeUndefined();
    // No host cost + a model without a public price = honest unknown, never $0.
    expect(last).toMatchObject({
      model: "goose-test-model",
      usage: { input_tokens: 1500, output_tokens: 40 },
      cost_unknown: true,
      at: "2026-09-06T10:15:30.000Z",
    });
    expect(last!.cost).toBeUndefined();
    // The session's accumulated totals are NOT layered on top when the
    // messages carry their own numbers.
    expect(result.turns.some((t) => t.usage?.input_tokens === 9999)).toBe(false);
  });

  it("emits the tool call and its result as detect units, the result anchored to the calling turn", () => {
    const result = parseGooseSessionsDb(DB, makeIo(modernDb()));
    const call = result.detect.find((u) => u.kind === "tool_call");
    expect(call).toMatchObject({
      tool_name: "developer__shell",
      target: "aws",
      turn_id: "goose:20260906_101500:2",
      cwd: "/Users/dev/projects/api",
    });
    expect(call!.raw).toContain("rotate-secret");
    const output = result.detect.find((u) => u.kind === "tool_output");
    expect(output).toMatchObject({
      tool_name: "developer__shell",
      turn_id: "goose:20260906_101500:3",
      anchor_turn_id: "goose:20260906_101500:2",
    });
    expect(output!.raw).toContain("AWS_SECRET_ACCESS_KEY=abc123");
    // The compaction summary is neither a prompt nor a turn.
    expect(result.detect.filter((u) => u.kind === "prompt")).toHaveLength(1);
    expect(result.detect.some((u) => u.raw.includes("Summary of the conversation"))).toBe(false);
  });

  it("titles the session from Goose's own description", () => {
    const result = parseGooseSessionsDb(DB, makeIo(modernDb()));
    expect(result.titles).toEqual([
      { session_id: "20260906_101500", title: { text: "Rotate the staging credentials", origin: "auto_summary" } },
    ]);
  });

  it("falls back to the session's accumulated totals on the last assistant turn for an older database", () => {
    const db = modernDb();
    for (const m of db.messages) {
      const meta = JSON.parse(String(m.metadata_json)) as Record<string, unknown>;
      delete meta.usage;
      delete meta.inference;
      m.metadata_json = json(meta);
    }
    db.sessions[0]!.accumulated_input_tokens = 4200;
    db.sessions[0]!.accumulated_output_tokens = 310;
    db.sessions[0]!.accumulated_cache_read_tokens = 2000;
    db.sessions[0]!.accumulated_cache_write_tokens = 0;
    db.sessions[0]!.accumulated_cost = 0.42;
    const result = parseGooseSessionsDb(DB, makeIo(db));
    const assistant = result.turns.filter((t) => t.role === "assistant");
    expect(assistant).toHaveLength(2);
    expect(assistant[0]!.usage).toBeUndefined();
    expect(assistant[1]).toMatchObject({
      id: "goose:20260906_101500:5",
      model: "goose-test-model",
      usage: { input_tokens: 4200, output_tokens: 310, cache_read_tokens: 2000, cache_write_tokens: 0 },
      cost: 0.42,
    });
    // Nothing recorded at all: no usage is invented.
    db.sessions[0]!.accumulated_input_tokens = null;
    db.sessions[0]!.accumulated_output_tokens = null;
    db.sessions[0]!.accumulated_cache_read_tokens = null;
    db.sessions[0]!.accumulated_cost = null;
    const bare = parseGooseSessionsDb(DB, makeIo(db));
    expect(bare.turns.every((t) => t.usage === undefined)).toBe(true);
  });

  it("is idempotent, and total over a database it cannot read", () => {
    const io = makeIo(modernDb());
    expect(parseGooseSessionsDb(DB, io)).toEqual(parseGooseSessionsDb(DB, io));
    expect(parseGooseSessionsDb(DB, makeIo(undefined))).toEqual({ turns: [], titles: [], detect: [] });
    const broken = modernDb();
    broken.messages[1]!.content_json = "{ not json";
    broken.messages[1]!.metadata_json = "nope";
    expect(() => parseGooseSessionsDb(DB, makeIo(broken))).not.toThrow();
  });
});

describe("gooseSource", () => {
  it("names every data directory Goose has used, GOOSE_PATH_ROOT first", () => {
    const roots = gooseSource.roots(HOME, {});
    expect(roots[0]).toBe(ROOT);
    expect(roots).toContain(`${HOME}/.local/share/goose/sessions`);
    expect(roots).toContain(`${HOME}/Library/Application Support/Block/goose/sessions`);
    const overridden = gooseSource.roots(HOME, { GOOSE_PATH_ROOT: "/opt/goose-root" });
    expect(overridden[0]).toBe("/opt/goose-root/data/sessions");
    // A relative override is ignored, exactly as Goose ignores it.
    expect(gooseSource.roots(HOME, { GOOSE_PATH_ROOT: "relative/dir" })).toEqual(roots);
  });

  it("discovers the one database under a sessions directory, and nothing where there is none", () => {
    expect(gooseSource.discover(ROOT, makeIo(modernDb()))).toEqual([DB]);
    expect(gooseSource.discover(ROOT, makeIo(undefined))).toEqual([]);
    expect(gooseSource.sessionIdOf(DB)).toBeUndefined();
    expect(gooseSource.id).toBe("goose");
    expect(gooseSource.metered).toBe(true);
  });
});
