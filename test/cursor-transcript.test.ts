import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { cursorSource } from "../main/lib/cursor-transcript.js";
import type { SourceIo } from "../main/lib/transcript-sources.js";
import { TURN_TEXT_MAX_CHARS, TURN_TOOLS_MAX } from "../main/lib/turns.js";
import { TOOL_OUTPUT_MAX_CHARS } from "../main/lib/turns.js";

const FIXTURES = join(fileURLToPath(new URL(".", import.meta.url)), "fixtures/transcripts/cursor");
const fixture = (name: string): Record<string, unknown> =>
  JSON.parse(readFileSync(join(FIXTURES, `${name}.json`), "utf8")) as Record<string, unknown>;

const HOME = "/Users/dev";
const GLOBAL_DIR = `${HOME}/Library/Application Support/Cursor/User/globalStorage`;
const WORKSPACE_DIR = `${HOME}/Library/Application Support/Cursor/User/workspaceStorage`;
const DB = `${GLOBAL_DIR}/state.vscdb`;

interface FakeDb {
  /** key → the JSON blob Cursor stored. An object here is stringified the way
   * SQLite would hold it; a raw string is passed through verbatim, which is how
   * a half-written record is expressed. */
  cursorDiskKV?: Record<string, unknown>;
  composerHeaders?: Record<string, unknown>[];
  ItemTable?: Record<string, unknown>;
}

const blob = (value: unknown): string => (typeof value === "string" ? value : JSON.stringify(value));

/**
 * A SourceIo over in-memory documents. `querySqlite` understands exactly the
 * three statements the descriptor issues — anything else throws, so a parser
 * that started issuing a wide `SELECT *` would fail this suite rather than
 * quietly reading the whole database.
 */
function makeIo(options: {
  databases?: Record<string, FakeDb>;
  files?: Record<string, string>;
  dirs?: Record<string, string[]>;
}): SourceIo {
  const databases = options.databases ?? {};
  const files = options.files ?? {};
  const dirs = options.dirs ?? {};
  return {
    readText: (path) => files[path],
    listDir: (path) => dirs[path] ?? [],
    stat: (path) =>
      databases[path] || files[path] !== undefined
        ? { size: 1024, mtimeMs: 1788000000000, isDirectory: false }
        : dirs[path]
          ? { size: 0, mtimeMs: 1788000000000, isDirectory: true }
          : undefined,
    querySqlite: (path, sql, params) => {
      const db = databases[path];
      if (!db) throw new Error(`no such database: ${path}`);
      const like = (params?.[0] as string | undefined) ?? "";
      if (sql === "SELECT key, value FROM cursorDiskKV WHERE key LIKE ?") {
        const prefix = like.replace(/%$/, "");
        return Object.entries(db.cursorDiskKV ?? {})
          .filter(([key]) => key.startsWith(prefix))
          .map(([key, value]) => ({ key, value: blob(value) }));
      }
      if (sql === "SELECT composerId, workspaceId FROM composerHeaders") {
        if (!db.composerHeaders) throw new Error("no such table: composerHeaders");
        return db.composerHeaders.map((row) => ({
          composerId: row.composerId,
          workspaceId: row.workspaceId,
        }));
      }
      if (sql === "SELECT value FROM ItemTable WHERE key = ?") {
        const value = (db.ItemTable ?? {})[like];
        return value === undefined ? [] : [{ value: blob(value) }];
      }
      throw new Error(`unexpected sql: ${sql}`);
    },
  };
}

/** The fixture documents, wired up as the Cursor profile they stand in for. */
function fixtureIo(): SourceIo {
  const global = fixture("global-state");
  const workspaces = fixture("workspaces").workspaces as Record<string, Record<string, unknown>>;
  const databases: Record<string, FakeDb> = {
    [DB]: {
      cursorDiskKV: global.cursorDiskKV as Record<string, unknown>,
      composerHeaders: global.composerHeaders as Record<string, unknown>[],
    },
  };
  const files: Record<string, string> = {};
  for (const [dir, ws] of Object.entries(workspaces)) {
    if (ws["workspace.json"]) {
      files[`${WORKSPACE_DIR}/${dir}/workspace.json`] = JSON.stringify(ws["workspace.json"]);
    }
    databases[`${WORKSPACE_DIR}/${dir}/state.vscdb`] = {
      ItemTable: (ws.ItemTable ?? {}) as Record<string, unknown>,
    };
  }
  return makeIo({
    databases,
    files,
    dirs: { [GLOBAL_DIR]: ["state.vscdb"], [WORKSPACE_DIR]: Object.keys(workspaces) },
  });
}

const SESSION_1 = "11111111-1111-4111-8111-111111111111";
const SESSION_2 = "22222222-2222-4222-8222-222222222222";
const SESSION_3 = "33333333-3333-4333-8333-333333333333";

describe("the fixtures", () => {
  it("all parse and all say they are synthetic", () => {
    const files = readdirSync(FIXTURES).filter((f) => f.endsWith(".json"));
    expect(files.length).toBeGreaterThan(0);
    for (const file of files) {
      const parsed = JSON.parse(readFileSync(join(FIXTURES, file), "utf8")) as Record<string, unknown>;
      // A shape nobody recorded must SAY so, or the next reader will trust it
      // as ground truth.
      expect(String(parsed._provenance), file).toContain("SYNTHETIC");
      expect(String(parsed._provenance), file).toContain("Cursor 3.15.19");
    }
  });
});

describe("cursorSource descriptor", () => {
  it("names the host the way the ledger does", () => {
    expect(cursorSource.id).toBe("cursor");
    expect(cursorSource.label).toBe("Cursor");
    expect(cursorSource.presencePaths).toEqual(["/Applications/Cursor.app", ".cursor"]);
    // Cursor writes inputTokens/outputTokens per assistant turn — partially,
    // but really.
    expect(cursorSource.metered).toBe(true);
  });

  it("roots at globalStorage only — workspaceStorage is a lookup, not a session store", () => {
    expect(cursorSource.roots(HOME, {})).toEqual([GLOBAL_DIR]);
  });

  it("discovers the one state database, and nothing when the profile is absent", () => {
    const io = fixtureIo();
    expect(cursorSource.discover(GLOBAL_DIR, io)).toEqual([DB]);
    expect(cursorSource.discover("/nowhere", io)).toEqual([]);
  });

  it("cannot name a session from the path — one database holds them all", () => {
    expect(cursorSource.sessionIdOf(DB)).toBeUndefined();
  });
});

describe("parse", () => {
  it("turns a composer into prompt + tool + assistant turns with the workspace as cwd", () => {
    const { turns, titles } = cursorSource.parse(DB, fixtureIo());
    const session = turns.filter((t) => t.session_id === SESSION_1);
    expect(session).toHaveLength(2); // the two tool bubbles are not turns

    const prompt = session[0]!;
    expect(prompt.id).toBe(`cursor:${SESSION_1}:aaaa0001-0000-4000-8000-000000000001`);
    expect(prompt.role).toBe("user");
    expect(prompt.source).toBe("cursor");
    expect(prompt.text).toBe("add a retry to the fetch helper in src/net.ts");
    expect(prompt.cwd).toBe("/Users/dev/projects/acme-api");
    // No instant of its own anywhere — inherits the composer's start.
    expect(prompt.at).toBe("2026-08-29T10:40:00.000Z");

    const answer = session[1]!;
    expect(answer.id).toBe(`cursor:${SESSION_1}:aaaa0004-0000-4000-8000-000000000004`);
    expect(answer.role).toBe("assistant");
    expect(answer.at).toBe("2026-08-29T10:40:30.000Z");
    expect(answer.model).toBe("gpt-5");
    expect(answer.usage).toEqual({
      input_tokens: 14581,
      output_tokens: 632,
      cache_read_tokens: 0,
      cache_write_tokens: 0,
      cache_write_1h_tokens: 0,
      web_search_requests: 0,
    });
    // gpt-5: in $1.25/M, out $10/M. Cursor reports no cache split at all.
    expect(answer.cost).toBeCloseTo((14581 * 1.25 + 632 * 10) / 1_000_000, 12);
    expect(answer.cost_unknown).toBeUndefined();
    // Cursor records nothing about plan vs. usage-based billing.
    expect(answer.settlement).toBe("unknown");
    // Both tool bubbles between the prompt and the answer settle onto it.
    expect(answer.tools).toEqual(["read_file", "run_terminal_cmd"]);

    expect(titles).toContainEqual({
      session_id: SESSION_1,
      title: { text: "Retry the fetch helper", origin: "auto_summary" },
    });
  });

  it("emits a tool_call and a tool_output per tool bubble, anchored to the settling turn", () => {
    const { detect } = cursorSource.parse(DB, fixtureIo());
    const units = detect.filter((u) => u.session_id === SESSION_1);
    expect(units.map((u) => u.kind)).toEqual([
      "prompt",
      "tool_call",
      "tool_output",
      "tool_call",
      "tool_output",
    ]);

    const answerId = `cursor:${SESSION_1}:aaaa0004-0000-4000-8000-000000000004`;
    const read = units[1]!;
    expect(read.tool_name).toBe("read_file");
    expect(read.target).toBe("src/net.ts");
    expect(read.turn_id).toBe(answerId);
    expect(read.cwd).toBe("/Users/dev/projects/acme-api");
    // The MODEL's own arguments are what a rule is judged against.
    expect(read.raw).toContain("should_read_entire_file");

    expect(units[2]!.raw).toContain("export async function fetchJson");
    expect(units[2]!.tool_name).toBe("read_file");

    const shell = units[3]!;
    expect(shell.tool_name).toBe("run_terminal_cmd");
    // A shell target is the program, like every other reader.
    expect(shell.target).toBe("npm");
    expect(shell.turn_id).toBe(answerId);
    expect(units[4]!.raw).toContain("12 passed");

    // The prompt is a detect unit in its own right.
    expect(units[0]!.turn_id).toBe(`cursor:${SESSION_1}:aaaa0001-0000-4000-8000-000000000001`);
  });

  it("is honest when Cursor recorded no tokens: no usage, cost unknown, never zero", () => {
    const { turns } = cursorSource.parse(DB, fixtureIo());
    const answer = turns.find(
      (t) => t.session_id === SESSION_2 && t.role === "assistant",
    )!;
    expect(answer.usage).toBeUndefined();
    expect(answer.cost).toBeUndefined();
    expect(answer.cost_unknown).toBe(true);
    expect(answer.settlement).toBe("unknown");
    // The session-level model stands in when the message didn't record one —
    // and `composer-*` has no public per-token price, so it stays unknown.
    expect(answer.model).toBe("composer-2.5");
    expect(answer.at).toBe("2026-08-29T11:30:04.000Z");
    // cwd via composerHeaders.workspaceId → workspace.json, percent-decoded.
    expect(answer.cwd).toBe("/Users/dev/projects/beta service");
  });

  it("yields what it can from a half-written session instead of throwing", () => {
    const { turns, detect, titles } = cursorSource.parse(DB, fixtureIo());
    const session = turns.filter((t) => t.session_id === SESSION_3);
    // An unparseable bubble blob and a header pointing at a bubble that was
    // never written are both simply absent; the prompt still lands.
    expect(session).toHaveLength(1);
    expect(session[0]!.role).toBe("user");
    expect(session[0]!.text).toBe("grep for the old feature flag");

    const units = detect.filter((u) => u.session_id === SESSION_3);
    expect(units.map((u) => u.kind)).toEqual(["prompt", "tool_call", "tool_output"]);
    // Nothing settled these tool calls, so they anchor to a session-stable tail.
    expect(units[1]!.turn_id).toBe(`cursor:${SESSION_3}:tail`);
    expect(units[1]!.target).toBe("ENABLE_LEGACY_UPLOAD");
    // A failed tool's error is still output worth scanning.
    expect(units[2]!.raw).toContain("ripgrep exited");
    expect(units[2]!.turn_id).toBe(`cursor:${SESSION_3}:tail`);

    expect(titles.map((t) => t.session_id)).toEqual([SESSION_1, SESSION_2, SESSION_3]);
  });

  it("skips a composer whose own record is unreadable, and one with no messages", () => {
    const { turns } = cursorSource.parse(DB, fixtureIo());
    const sessions = new Set(turns.map((t) => t.session_id));
    expect([...sessions]).toEqual([SESSION_1, SESSION_2, SESSION_3]);
    expect(turns).toHaveLength(5);
  });

  it("mints the same ids on a re-parse", () => {
    const first = cursorSource.parse(DB, fixtureIo());
    const second = cursorSource.parse(DB, fixtureIo());
    expect(second.turns.map((t) => t.id)).toEqual(first.turns.map((t) => t.id));
    expect(second.turns).toEqual(first.turns);
    expect(second.detect.map((u) => `${u.kind}:${u.turn_id}`)).toEqual(
      first.detect.map((u) => `${u.kind}:${u.turn_id}`),
    );
    expect(second.titles).toEqual(first.titles);
  });

  it("reads nothing out of an empty profile", () => {
    const empty = fixture("empty-state");
    const io = makeIo({
      databases: {
        [DB]: {
          cursorDiskKV: empty.cursorDiskKV as Record<string, unknown>,
          composerHeaders: empty.composerHeaders as Record<string, unknown>[],
        },
      },
      dirs: { [GLOBAL_DIR]: ["state.vscdb"], [WORKSPACE_DIR]: [] },
    });
    expect(cursorSource.parse(DB, io)).toEqual({ turns: [], titles: [], detect: [] });
  });

  it("returns empty rather than throwing when the database itself is gone", () => {
    const io = makeIo({ databases: {}, dirs: {} });
    expect(() => cursorSource.parse(DB, io)).not.toThrow();
    expect(cursorSource.parse(DB, io)).toEqual({ turns: [], titles: [], detect: [] });
  });

  it("survives a database with no composerHeaders table (older Cursor)", () => {
    const global = fixture("global-state");
    const io = makeIo({
      databases: { [DB]: { cursorDiskKV: global.cursorDiskKV as Record<string, unknown> } },
      dirs: { [GLOBAL_DIR]: ["state.vscdb"], [WORKSPACE_DIR]: [] },
    });
    const { turns } = cursorSource.parse(DB, io);
    expect(turns.length).toBe(5);
    // Without the header table (and without workspaces) no cwd is knowable —
    // and none is invented.
    expect(turns.every((t) => t.cwd === undefined)).toBe(true);
  });
});

describe("caps", () => {
  const long = (n: number, seed: string): string => seed.repeat(Math.ceil(n / seed.length)).slice(0, n);

  function cappedIo(): SourceIo {
    const cid = "99999999-9999-4999-8999-999999999999";
    const tools = Array.from({ length: TURN_TOOLS_MAX + 8 }, (_, i) => ({
      bubbleId: `tool${String(i).padStart(4, "0")}`,
      type: 2,
    }));
    const kv: Record<string, unknown> = {
      [`composerData:${cid}`]: {
        composerId: cid,
        name: "Capped",
        createdAt: 1788000000000,
        fullConversationHeadersOnly: [
          { bubbleId: "prompt01", type: 1 },
          ...tools,
          { bubbleId: "answer01", type: 2 },
        ],
      },
      [`bubbleId:${cid}:prompt01`]: {
        type: 1,
        text: long(TURN_TEXT_MAX_CHARS + 500, "prompt "),
        tokenCount: { inputTokens: 0, outputTokens: 0 },
      },
      [`bubbleId:${cid}:answer01`]: {
        type: 2,
        text: long(TURN_TEXT_MAX_CHARS + 500, "answer "),
        tokenCount: { inputTokens: 100, outputTokens: 20 },
        modelInfo: { modelName: "gpt-5" },
      },
    };
    for (const [i, tool] of tools.entries()) {
      kv[`bubbleId:${cid}:${tool.bubbleId}`] = {
        type: 2,
        text: "",
        toolFormerData: {
          name: `read_file`,
          tool: 5,
          status: "completed",
          rawArgs: JSON.stringify({ target_file: `src/file-${i}.ts` }),
          result: long(TOOL_OUTPUT_MAX_CHARS + 1_000, "output "),
        },
      };
    }
    return makeIo({
      databases: { [DB]: { cursorDiskKV: kv, composerHeaders: [] } },
      dirs: { [GLOBAL_DIR]: ["state.vscdb"], [WORKSPACE_DIR]: [] },
    });
  }

  it("caps stored text, the tool chip list and a scanned tool output", () => {
    const { turns, detect } = cursorSource.parse(DB, cappedIo());
    expect(turns).toHaveLength(2);
    expect(turns[0]!.text).toHaveLength(TURN_TEXT_MAX_CHARS);
    expect(turns[1]!.text).toHaveLength(TURN_TEXT_MAX_CHARS);
    expect(turns[1]!.tools).toHaveLength(TURN_TOOLS_MAX);

    // The detect unit keeps the FULL prompt — detection scans before the cap.
    const prompt = detect.find((u) => u.kind === "prompt")!;
    expect(prompt.raw.length).toBe(TURN_TEXT_MAX_CHARS + 500);
    // Every tool call is still scanned, even past the chip cap.
    expect(detect.filter((u) => u.kind === "tool_call")).toHaveLength(TURN_TOOLS_MAX + 8);
    for (const unit of detect.filter((u) => u.kind === "tool_output")) {
      expect(unit.raw).toHaveLength(TOOL_OUTPUT_MAX_CHARS);
    }
  });
});
