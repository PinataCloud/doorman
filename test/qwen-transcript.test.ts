/**
 * The Qwen Code transcript source. Qwen Code forked Gemini CLI but records
 * chats in its OWN shape (a `uuid`/`parentUuid` tree of `ChatRecord`s, not the
 * `$set`/`$rewindTo` append log) — this suite pins that shape from the
 * upstream source (QwenLM/qwen-code, 2026-09-06). The fixture is derived from
 * that source, not a live recording, and says so on its first line.
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { parseQwenSession, qwenSource } from "../main/lib/qwen-transcript.js";
import type { SourceIo } from "../main/lib/transcript-sources.js";

const FIXTURES = join(fileURLToPath(new URL(".", import.meta.url)), "fixtures/transcripts/qwen");
const SESSION = "3f9c2a1b-7d4e-4c0a-9b1e-2c8d4a6e7f01";
const FILE = join(FIXTURES, `${SESSION}.jsonl`);
const contents = readFileSync(FILE, "utf8");

const HOME = "/Users/dev";
const ROOT = `${HOME}/.qwen/projects`;
const CHATS = `${ROOT}/-Users-dev-projects-api/chats`;
const DOC = `${CHATS}/${SESSION}.jsonl`;

function makeIo(): SourceIo {
  const files: Record<string, string> = { [DOC]: contents };
  const dirs: Record<string, string[]> = {
    [ROOT]: ["-Users-dev-projects-api", "stray-file.txt"],
    [`${ROOT}/-Users-dev-projects-api`]: ["chats", "plans"],
    [CHATS]: [`${SESSION}.jsonl`, "notes.md", "half.jsonl"],
  };
  files[`${CHATS}/half.jsonl`] = "";
  return {
    readText: (path) => files[path],
    listDir: (path) => dirs[path] ?? [],
    stat: (path) =>
      files[path] !== undefined
        ? { size: files[path]!.length, mtimeMs: 1, isDirectory: false }
        : dirs[path]
          ? { size: 0, mtimeMs: 1, isDirectory: true }
          : undefined,
    querySqlite: () => {
      throw new Error("no sqlite here");
    },
  };
}

describe("the fixture", () => {
  it("says where it came from and ends in a half-written line", () => {
    const first = JSON.parse(contents.split("\n")[0]!) as Record<string, unknown>;
    expect(String(first._provenance)).toContain("not a live recording");
    expect(contents.trimEnd().endsWith('"type":"assist')).toBe(true);
  });
});

describe("parseQwenSession", () => {
  const result = parseQwenSession(contents, SESSION);

  it("reads the prompt, the two assistant turns, and skips slash commands, system records and the torn line", () => {
    expect(result.turns.map((t) => t.id)).toEqual([`qwen:${SESSION}:u-1`, `qwen:${SESSION}:u-2`, `qwen:${SESSION}:u-4`]);
    expect(result.turns[0]).toMatchObject({
      source: "qwen-code",
      role: "user",
      session_id: SESSION,
      at: "2026-09-06T09:00:01.000Z",
      cwd: "/Users/dev/projects/api",
      git_branch: "main",
      text: "Delete the old backups in the prod bucket.",
    });
  });

  it("does Gemini's usage maths and refuses to price a model the table does not know", () => {
    const first = result.turns[1]!;
    // input = prompt − cached + tool = 12000 − 9000 + 500; output = candidates + thoughts.
    expect(first).toMatchObject({
      role: "assistant",
      model: "qwen3-coder-plus",
      usage: { input_tokens: 3500, output_tokens: 100, cache_read_tokens: 9000, cache_write_tokens: 0 },
      cost_unknown: true,
      tools: ["run_shell_command"],
      text: "Listing first.",
    });
    expect(first.cost).toBeUndefined();
    expect(first.text).not.toContain("thinking about it");
    const second = result.turns[2]!;
    expect(second.usage).toEqual({
      input_tokens: 500,
      output_tokens: 15,
      cache_read_tokens: 12500,
      cache_write_tokens: 0,
      cache_write_1h_tokens: 0,
      web_search_requests: 0,
    });
    expect(second.settlement).toBeUndefined();
  });

  it("emits the tool call and its result, the result anchored to the calling turn", () => {
    const call = result.detect.find((u) => u.kind === "tool_call");
    expect(call).toMatchObject({
      tool_name: "run_shell_command",
      target: "aws",
      turn_id: `qwen:${SESSION}:u-2`,
      cwd: "/Users/dev/projects/api",
    });
    expect(call!.raw).toContain("s3://prod-backups");
    const output = result.detect.find((u) => u.kind === "tool_output");
    expect(output).toMatchObject({
      tool_name: "run_shell_command",
      turn_id: `qwen:${SESSION}:u-3`,
      anchor_turn_id: `qwen:${SESSION}:u-2`,
    });
    // The full functionResponse output is scanned, not the trimmed display.
    expect(output!.raw).toContain("AWS_SECRET_ACCESS_KEY=");
    expect(result.detect.filter((u) => u.kind === "prompt")).toHaveLength(1);
  });

  it("takes the session's own title, and is idempotent", () => {
    expect(result.titles).toEqual([{ session_id: SESSION, title: { text: "Prod backup cleanup", origin: "auto_summary" } }]);
    expect(parseQwenSession(contents, SESSION)).toEqual(result);
    expect(parseQwenSession("", "x")).toEqual({ turns: [], titles: [], detect: [] });
  });
});

describe("qwenSource", () => {
  it("walks ~/.qwen/projects and the older tmp layout, QWEN_HOME first", () => {
    expect(qwenSource.roots(HOME, {})).toEqual([`${HOME}/.qwen/projects`, `${HOME}/.qwen/tmp`]);
    const roots = qwenSource.roots(HOME, { QWEN_HOME: "/Volumes/work/.qwen" });
    expect(roots[0]).toBe("/Volumes/work/.qwen/projects");
    expect(roots).toContain(`${HOME}/.qwen/projects`);
  });

  it("discovers <project>/chats/*.jsonl only, and parses through the io", () => {
    const io = makeIo();
    expect(qwenSource.discover(ROOT, io)).toEqual([DOC, `${CHATS}/half.jsonl`]);
    expect(qwenSource.sessionIdOf(DOC)).toBe(SESSION);
    expect(qwenSource.sessionIdOf(`${CHATS}/notes.md`)).toBeUndefined();
    const parsed = qwenSource.parse(DOC, io);
    expect(parsed.turns).toHaveLength(3);
    expect(qwenSource.parse(`${CHATS}/half.jsonl`, io)).toEqual({ turns: [], titles: [], detect: [] });
    expect(qwenSource.id).toBe("qwen-code");
    expect(qwenSource.metered).toBe(true);
  });
});
