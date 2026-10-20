/**
 * The Hermes Agent transcript source: one SQLite database, every session in
 * it. Two suites — a fake io that answers exactly the statements the parser
 * issues (so a wider query fails loudly), and a real `node:sqlite` database
 * built with the documented schema and read through the engine's own
 * SourceIo, WAL snapshot and all.
 */

import { mkdirSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { join, normalize } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { hermesSource, parseHermesDatabase } from "../main/lib/hermes-transcript.js";
import { createSourceIo } from "../main/lib/source-io.js";
import type { SourceIo } from "../main/lib/transcript-sources.js";

const HOME = "/Users/dev";
const DB = `${HOME}/.hermes/state.db`;

const T0 = 1_788_000_000; // epoch seconds, 2026-08-30T00:00:00Z-ish
const iso = (seconds: number): string => new Date(seconds * 1000).toISOString();

const SESSION_COLS = [
  "id", "source", "model", "title", "started_at", "ended_at", "input_tokens", "output_tokens",
  "cache_read_tokens", "cache_write_tokens", "reasoning_tokens", "estimated_cost_usd", "actual_cost_usd",
  "billing_mode", "cwd", "git_branch",
];
const MESSAGE_COLS = ["id", "session_id", "role", "content", "tool_calls", "tool_call_id", "tool_name", "timestamp"];

interface FakeDb {
  sessions: Record<string, unknown>[];
  messages: Record<string, unknown>[];
  /** Columns the fake claims each table has (an older schema drops some). */
  sessionCols?: string[];
  messageCols?: string[];
}

function makeIo(databases: Record<string, FakeDb>): SourceIo {
  return {
    readText: () => undefined,
    listDir: () => [],
    stat: (path) => (databases[path] ? { size: 4096, mtimeMs: T0 * 1000, isDirectory: false } : undefined),
    querySqlite: (path, sql) => {
      const db = databases[path];
      if (!db) throw new Error(`no such database: ${path}`);
      const sessionCols = db.sessionCols ?? SESSION_COLS;
      const messageCols = db.messageCols ?? MESSAGE_COLS;
      if (sql === "SELECT name FROM pragma_table_info('sessions')") return sessionCols.map((name) => ({ name }));
      if (sql === "SELECT name FROM pragma_table_info('messages')") return messageCols.map((name) => ({ name }));
      const pick = (row: Record<string, unknown>, cols: string[]): Record<string, unknown> =>
        Object.fromEntries(cols.map((c) => [c, row[c] ?? null]));
      if (sql === `SELECT ${sessionCols.join(", ")} FROM sessions`) return db.sessions.map((r) => pick(r, sessionCols));
      if (sql === `SELECT ${messageCols.join(", ")} FROM messages ORDER BY session_id, id`) {
        return [...db.messages]
          .sort((a, b) =>
            String(a.session_id) < String(b.session_id) ? -1 : String(a.session_id) > String(b.session_id) ? 1 : Number(a.id) - Number(b.id),
          )
          .map((r) => pick(r, messageCols));
      }
      throw new Error(`unexpected sql: ${sql}`);
    },
  };
}

const toolCalls = (calls: Array<{ id: string; name: string; args: unknown }>): string =>
  JSON.stringify(calls.map((c) => ({ id: c.id, type: "function", function: { name: c.name, arguments: JSON.stringify(c.args) } })));

/** A CLI session with a terminal call and its result, priced by Hermes. */
function cliSession(): FakeDb {
  return {
    sessions: [
      {
        id: "sess_cli_1",
        source: "cli",
        model: "anthropic/claude-sonnet-4",
        title: "Rotate the staging keys",
        started_at: T0,
        ended_at: T0 + 90,
        input_tokens: 12_000,
        output_tokens: 800,
        cache_read_tokens: 9_000,
        cache_write_tokens: 1_500,
        reasoning_tokens: 300,
        estimated_cost_usd: 0.0421,
        actual_cost_usd: null,
        billing_mode: "api_key",
        cwd: "/Users/dev/projects/api",
        git_branch: "main",
      },
    ],
    messages: [
      { id: 1, session_id: "sess_cli_1", role: "system", content: "You are Hermes.", timestamp: T0 },
      { id: 2, session_id: "sess_cli_1", role: "user", content: "rotate the staging keys", timestamp: T0 + 1 },
      {
        id: 3,
        session_id: "sess_cli_1",
        role: "assistant",
        content: "Looking at the current keys first.",
        tool_calls: toolCalls([{ id: "call_1", name: "terminal", args: { command: "aws iam list-access-keys" } }]),
        timestamp: T0 + 5,
      },
      { id: 4, session_id: "sess_cli_1", role: "tool", content: "AKIAMQHGCTEF5EUSLEJR active", tool_call_id: "call_1", tool_name: "terminal", timestamp: T0 + 6 },
      {
        id: 5,
        session_id: "sess_cli_1",
        role: "assistant",
        content: "Rotated. The old key is now inactive.",
        tool_calls: toolCalls([
          { id: "call_2", name: "write_file", args: { path: "/Users/dev/projects/api/.env", content: "X" } },
          { id: "call_3", name: "web_extract", args: { urls: ["https://docs.aws.amazon.com/iam"] } },
        ]),
        timestamp: T0 + 40,
      },
      { id: 6, session_id: "sess_cli_1", role: "tool", content: "written", tool_call_id: "call_2", tool_name: "write_file", timestamp: T0 + 41 },
    ],
  };
}

describe("the Hermes descriptor", () => {
  it("is shaped for the registry", () => {
    expect(hermesSource.id).toBe("hermes");
    expect(hermesSource.label).toBe("Hermes Agent");
    expect(hermesSource.presencePaths).toEqual([".hermes"]);
    expect(hermesSource.metered).toBe(true);
    expect(hermesSource.sessionIdOf("/x/state.db")).toBeUndefined();
  });

  it("roots at ~/.hermes, and at $HERMES_HOME first when set", () => {
    expect(hermesSource.roots(HOME, {})).toEqual([`${HOME}/.hermes`]);
    expect(hermesSource.roots(HOME, { HERMES_HOME: "/srv/hermes" })).toEqual(["/srv/hermes", `${HOME}/.hermes`]);
    expect(hermesSource.roots(HOME, { HERMES_HOME: `${HOME}/.hermes` })).toEqual([`${HOME}/.hermes`]);
  });

  it("discovers the database when it exists and nothing when it doesn't", () => {
    const io = makeIo({ [DB]: cliSession() });
    expect(hermesSource.discover(`${HOME}/.hermes`, io)).toEqual([DB]);
    expect(hermesSource.discover("/nowhere", io)).toEqual([]);
  });
});

describe("parse", () => {
  it("turns a session's rows into user/assistant turns, and its numbers land once, on the last assistant turn", () => {
    const { turns, titles, detect } = hermesSource.parse(DB, makeIo({ [DB]: cliSession() }));
    expect(turns.map((t) => [t.id, t.role])).toEqual([
      ["hermes:sess_cli_1:2", "user"],
      ["hermes:sess_cli_1:3", "assistant"],
      ["hermes:sess_cli_1:5", "assistant"],
    ]);
    const [user, first, last] = turns;
    expect(user).toMatchObject({
      source: "hermes",
      session_id: "sess_cli_1",
      at: iso(T0 + 1),
      text: "rotate the staging keys",
      cwd: "/Users/dev/projects/api",
      git_branch: "main",
    });
    expect(first).toMatchObject({ model: "anthropic/claude-sonnet-4", tools: ["terminal"], text: "Looking at the current keys first." });
    expect(first?.usage).toBeUndefined();
    expect(first?.cost).toBeUndefined();
    expect(last).toMatchObject({
      tools: ["write_file", "web_extract"],
      usage: {
        input_tokens: 12_000,
        output_tokens: 800,
        cache_read_tokens: 9_000,
        cache_write_tokens: 1_500,
        cache_write_1h_tokens: 0,
        web_search_requests: 0,
      },
      // Hermes's own estimate, not ours; settlement stays unknown.
      cost: 0.0421,
    });
    expect(last?.cost_unknown).toBeUndefined();
    expect(last?.settlement).toBeUndefined();
    expect(titles).toEqual([{ session_id: "sess_cli_1", title: { text: "Rotate the staging keys", origin: "auto_summary" } }]);

    // Detection: the prompt, three tool calls with targets, two tool outputs
    // anchored to the assistant turns that made the calls.
    expect(detect.filter((d) => d.kind === "prompt")).toHaveLength(1);
    const calls = detect.filter((d) => d.kind === "tool_call");
    expect(calls.map((d) => [d.tool_name, d.target, d.turn_id])).toEqual([
      ["terminal", "aws", "hermes:sess_cli_1:3"],
      ["write_file", "/Users/dev/projects/api/.env", "hermes:sess_cli_1:5"],
      ["web_extract", "https://docs.aws.amazon.com/iam", "hermes:sess_cli_1:5"],
    ]);
    const outputs = detect.filter((d) => d.kind === "tool_output");
    expect(outputs.map((d) => [d.raw, d.turn_id, d.anchor_turn_id])).toEqual([
      ["AKIAMQHGCTEF5EUSLEJR active", "hermes:sess_cli_1:4", "hermes:sess_cli_1:3"],
      ["written", "hermes:sess_cli_1:6", "hermes:sess_cli_1:5"],
    ]);
    for (const unit of detect) expect(unit.cwd).toBe("/Users/dev/projects/api");
  });

  it("prefers the billed cost, then the estimate, then its own pricing, then admits it doesn't know", () => {
    const base = cliSession();
    const s = base.sessions[0]!;
    const cost = (over: Record<string, unknown>): { cost?: number; cost_unknown?: boolean } => {
      const db = { ...base, sessions: [{ ...s, ...over }] };
      const last = hermesSource.parse(DB, makeIo({ [DB]: db })).turns.at(-1)!;
      return { cost: last.cost, cost_unknown: last.cost_unknown };
    };
    expect(cost({ actual_cost_usd: 0.05 })).toEqual({ cost: 0.05, cost_unknown: undefined });
    expect(cost({ actual_cost_usd: 0, estimated_cost_usd: 0.0421 })).toEqual({ cost: 0.0421, cost_unknown: undefined });
    // Neither recorded: a model our table prices is derived locally…
    const derived = cost({ actual_cost_usd: null, estimated_cost_usd: null, model: "claude-sonnet-4" });
    expect(derived.cost_unknown).toBeUndefined();
    expect(derived.cost).toBeGreaterThan(0);
    // …and one it doesn't is unknown, never $0.
    expect(cost({ actual_cost_usd: null, estimated_cost_usd: null, model: "nous/hermes-4-405b" })).toEqual({
      cost: undefined,
      cost_unknown: true,
    });
    expect(cost({ actual_cost_usd: null, estimated_cost_usd: null, model: null })).toEqual({ cost: undefined, cost_unknown: true });
  });

  it("emits no usage for a zero-token (ACP) session — activity, not spend", () => {
    const db = cliSession();
    Object.assign(db.sessions[0]!, {
      input_tokens: 0, output_tokens: 0, cache_read_tokens: 0, cache_write_tokens: 0, estimated_cost_usd: 0,
    });
    const last = hermesSource.parse(DB, makeIo({ [DB]: db })).turns.at(-1)!;
    expect(last.usage).toBeUndefined();
    expect(last.cost).toBeUndefined();
    expect(last.cost_unknown).toBeUndefined();
  });

  it("marks a subscription-billed session as covered, and nothing else", () => {
    const db = cliSession();
    db.sessions[0]!.billing_mode = "subscription";
    expect(hermesSource.parse(DB, makeIo({ [DB]: db })).turns.at(-1)?.settlement).toBe("subscription");
  });

  it("reads an older schema that lacks the newer columns without throwing", () => {
    const db = cliSession();
    db.sessionCols = ["id", "source", "model", "started_at", "input_tokens", "output_tokens"];
    db.messageCols = ["id", "session_id", "role", "content", "tool_calls", "timestamp"];
    const { turns, titles, detect } = hermesSource.parse(DB, makeIo({ [DB]: db }));
    expect(turns).toHaveLength(3);
    expect(titles).toEqual([]);
    expect(turns.at(-1)?.usage).toMatchObject({ input_tokens: 12_000, output_tokens: 800, cache_read_tokens: 0 });
    // No cwd column → unscoped units; tool outputs still land, unanchored.
    expect(detect.every((d) => d.cwd === undefined)).toBe(true);
    expect(detect.filter((d) => d.kind === "tool_output").every((d) => d.anchor_turn_id === undefined)).toBe(true);
  });

  it("gives a row without a timestamp the previous row's instant, then the session's start", () => {
    const db = cliSession();
    db.messages = [
      { id: 10, session_id: "sess_cli_1", role: "user", content: "hi", timestamp: null },
      { id: 11, session_id: "sess_cli_1", role: "assistant", content: "hello", timestamp: T0 + 7 },
      { id: 12, session_id: "sess_cli_1", role: "user", content: "again", timestamp: null },
    ];
    const { turns } = hermesSource.parse(DB, makeIo({ [DB]: db }));
    expect(turns.map((t) => [t.id, t.at])).toEqual([
      ["hermes:sess_cli_1:10", iso(T0)],
      ["hermes:sess_cli_1:11", iso(T0 + 7)],
      ["hermes:sess_cli_1:12", iso(T0 + 7)],
    ]);
  });

  it("keeps sessions apart, mints the same ids on a re-parse, and survives a half-written database", () => {
    const db = cliSession();
    db.sessions.push({ id: "sess_tg_2", source: "telegram", model: "gpt-5", started_at: T0 + 1000, input_tokens: 10, output_tokens: 5 });
    db.messages.push(
      { id: 7, session_id: "sess_tg_2", role: "user", content: "ping", timestamp: T0 + 1001 },
      { id: 8, session_id: "sess_tg_2", role: "assistant", content: "pong", tool_calls: "{not json", timestamp: T0 + 1002 },
      { id: 9, session_id: "sess_tg_2", role: "assistant", content: null, tool_calls: null, timestamp: T0 + 1003 },
    );
    const io = makeIo({ [DB]: db });
    const once = hermesSource.parse(DB, io);
    const twice = hermesSource.parse(DB, io);
    expect(twice).toEqual(once);
    const tg = once.turns.filter((t) => t.session_id === "sess_tg_2");
    expect(tg.map((t) => t.id)).toEqual(["hermes:sess_tg_2:7", "hermes:sess_tg_2:8"]); // 9 is an empty placeholder
    expect(tg[1]?.tools).toBeUndefined();
    expect(tg[1]?.usage?.input_tokens).toBe(10);
    // A database that is not there at all is an empty answer, not a throw.
    expect(hermesSource.parse("/gone/state.db", io)).toEqual({ turns: [], titles: [], detect: [] });
    expect(parseHermesDatabase("/gone/state.db", io)).toEqual({ turns: [], titles: [], detect: [] });
  });
});

describe("against a real state.db", () => {
  let root: string;
  beforeEach(() => {
    root = mkdtempSync(join(tmpdir(), "hermes-src-"));
  });
  afterEach(() => {
    rmSync(root, { recursive: true, force: true });
  });

  it("reads the rows Hermes 0.21.1 really wrote during the guard's live test (fixtures/transcripts/hermes/state-rows.json)", () => {
    // Every column of both tables, values verbatim (paths sanitised) — see the
    // fixture's _provenance. Rebuilt into a real database so the reader's
    // column discovery runs against the genuine, much wider schema.
    const { DatabaseSync } = createRequire(join(process.cwd(), "index.js"))("node:sqlite") as typeof import("node:sqlite");
    const fixture = JSON.parse(
      readFileSync(join(fileURLToPath(new URL(".", import.meta.url)), "fixtures/transcripts/hermes/state-rows.json"), "utf8"),
    ) as { sessions: Record<string, unknown>[]; messages: Record<string, unknown>[] };
    const home = join(root, "home");
    const dbPath = join(home, ".hermes", "state.db");
    mkdirSync(join(home, ".hermes"), { recursive: true });
    const live = new DatabaseSync(dbPath);
    const create = (table: string, rows: Record<string, unknown>[]): void => {
      const cols = Object.keys(rows[0]!);
      live.exec(`CREATE TABLE ${table} (${cols.map((c) => (c === "id" && table === "messages" ? "id INTEGER PRIMARY KEY" : c)).join(", ")})`);
      const stmt = live.prepare(`INSERT INTO ${table} (${cols.join(", ")}) VALUES (${cols.map(() => "?").join(", ")})`);
      for (const row of rows) stmt.run(...cols.map((c) => (row[c] === undefined ? null : (row[c] as null | string | number))));
    };
    create("sessions", fixture.sessions);
    create("messages", fixture.messages);
    live.close();

    const io = createSourceIo({ snapshotDir: join(root, "snapshots") });
    const { turns, titles, detect } = hermesSource.parse(dbPath, io);
    const first = "20260908_144631_0cdc75";
    const second = "20260908_144708_bc03e9";
    expect(titles.map((t) => [t.session_id, t.title.text])).toEqual([
      [first, "Run terminal commands and report output"],
      [second, "Execute four file operations in sequence"],
    ]);
    // The session's numbers land once, on its last assistant turn; the host's
    // estimate is the cost (actual_cost_usd is NULL on this build).
    const firstTurns = turns.filter((t) => t.session_id === first);
    expect(firstTurns.map((t) => [t.id, t.role])).toEqual([
      [`hermes:${first}:1`, "user"],
      [`hermes:${first}:2`, "assistant"],
      [`hermes:${first}:5`, "assistant"],
    ]);
    expect(firstTurns[1]).toMatchObject({ model: "anthropic/claude-haiku-4.5", tools: ["terminal", "terminal"], cwd: "/Users/dev" });
    expect(firstTurns[1]?.usage).toBeUndefined();
    expect(firstTurns[2]?.usage).toMatchObject({ input_tokens: 17, output_tokens: 238, cache_read_tokens: 10156, cache_write_tokens: 11159 });
    expect(firstTurns[2]?.cost).toBeCloseTo(0.01617135, 8);
    const secondTurns = turns.filter((t) => t.session_id === second);
    expect(secondTurns.filter((t) => t.role === "assistant").flatMap((t) => t.tools ?? [])).toEqual([
      "write_file",
      "read_file",
      "patch",
      "terminal",
    ]);
    expect(secondTurns.at(-1)?.usage).toMatchObject({ input_tokens: 30, output_tokens: 554 });
    // A guard deny is a `tool` row whose content is `{"error": "…our reason"}`.
    const denied = detect.filter((d) => d.kind === "tool_output" && d.raw.includes("Doorman flagged this tool call: E2E deny marker."));
    expect(denied).toHaveLength(2);
    expect(denied[0]).toMatchObject({ tool_name: "terminal", anchor_turn_id: `hermes:${first}:2` });
    expect(detect.filter((d) => d.kind === "tool_call").map((d) => [d.tool_name, d.target])).toEqual([
      ["terminal", "echo"],
      ["terminal", "echo"],
      ["write_file", "notes/e2e.txt"],
      ["read_file", "notes/e2e.txt"],
      ["patch", "notes/e2e.txt"],
      ["terminal", "cat"],
    ]);
  });

  it("reads the documented schema through the engine's io, WAL rows included, without writing", () => {
    const { DatabaseSync } = createRequire(join(process.cwd(), "index.js"))("node:sqlite") as typeof import("node:sqlite");
    const home = join(root, "home");
    const dbPath = join(home, ".hermes", "state.db");
    const io = createSourceIo({ snapshotDir: join(root, "snapshots") });
    // Build the directory the way Hermes would, then the tables per the docs.
    mkdirSync(join(home, ".hermes"), { recursive: true });
    const live = new DatabaseSync(dbPath);
    live.exec("PRAGMA journal_mode = WAL");
    live.exec(`CREATE TABLE sessions (
      id TEXT PRIMARY KEY, source TEXT, user_id TEXT, model TEXT, model_config TEXT, system_prompt TEXT,
      parent_session_id TEXT, started_at REAL, ended_at REAL, end_reason TEXT, title TEXT,
      input_tokens INTEGER, output_tokens INTEGER, cache_read_tokens INTEGER, cache_write_tokens INTEGER,
      reasoning_tokens INTEGER, billing_provider TEXT, billing_base_url TEXT, billing_mode TEXT,
      estimated_cost_usd REAL, actual_cost_usd REAL, cost_status TEXT, cost_source TEXT, pricing_version TEXT,
      message_count INTEGER, tool_call_count INTEGER, api_call_count INTEGER, cwd TEXT, git_branch TEXT, git_repo_root TEXT)`);
    live.exec(`CREATE TABLE messages (
      id INTEGER PRIMARY KEY AUTOINCREMENT, session_id TEXT NOT NULL, role TEXT NOT NULL, content TEXT,
      tool_call_id TEXT, tool_name TEXT, tool_calls TEXT, timestamp REAL, token_count INTEGER, finish_reason TEXT)`);
    live
      .prepare(
        `INSERT INTO sessions (id, source, model, title, started_at, input_tokens, output_tokens, cache_read_tokens, cache_write_tokens, estimated_cost_usd, cwd)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run("s1", "cli", "anthropic/claude-sonnet-4", "Real db", T0, 100, 20, 0, 0, 0.001, "/Users/dev/p");
    const insert = live.prepare(
      "INSERT INTO messages (session_id, role, content, tool_calls, tool_call_id, tool_name, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?)",
    );
    insert.run("s1", "user", "do it", null, null, null, T0 + 1);
    insert.run("s1", "assistant", "on it", toolCalls([{ id: "c1", name: "terminal", args: { command: "ls -la" } }]), null, null, T0 + 2);
    // Left uncheckpointed in the WAL, the way a running gateway keeps it.
    insert.run("s1", "tool", "total 0", null, "c1", "terminal", T0 + 3);

    // The descriptor joins with `/` (as Cursor's and Goose's do), which on
    // Windows makes `C:\…\.hermes/state.db`: the same file, spelled mixed.
    expect(hermesSource.discover(join(home, ".hermes"), io).map((p) => normalize(p))).toEqual([dbPath]);
    const { turns, titles, detect } = hermesSource.parse(dbPath, io);
    expect(turns.map((t) => [t.id, t.role])).toEqual([
      ["hermes:s1:1", "user"],
      ["hermes:s1:2", "assistant"],
    ]);
    expect(turns[1]).toMatchObject({ model: "anthropic/claude-sonnet-4", tools: ["terminal"], cost: 0.001, cwd: "/Users/dev/p" });
    expect(turns[1]?.usage).toMatchObject({ input_tokens: 100, output_tokens: 20 });
    expect(titles[0]?.title.text).toBe("Real db");
    expect(detect.find((d) => d.kind === "tool_output")).toMatchObject({ raw: "total 0", anchor_turn_id: "hermes:s1:2" });
    expect(detect.find((d) => d.kind === "tool_call")).toMatchObject({ tool_name: "terminal", target: "ls" });
    live.close();
  });
});
