import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { parseGrokSession, grokSource } from "../main/lib/grok-transcript.js";
import type { SourceIo } from "../main/lib/transcript-sources.js";

const fixture = readFileSync(new URL("./fixtures/transcripts/grok/updates.jsonl", import.meta.url), "utf8");
const summary = JSON.stringify({ info: { cwd: "/private/project" }, generated_title: "Deployment review" });
const parse = (text = fixture, session = "grok-session") => parseGrokSession(text, session, summary);

describe("Grok completed-turn capture", () => {
  it("reads durable bills once, splits models, and subtracts cache without adding reasoning twice", () => {
    const result = parse();
    const billed = result.turns.filter(t => t.usage);
    expect(billed).toHaveLength(3);
    expect(billed[0]).toMatchObject({ model: "grok-build-0.1", cost: 0.3, reported_cost: 0.3,
      usage: { input_tokens: 800, output_tokens: 100, cache_read_tokens: 9000, cache_write_tokens: 200 },
      text: "PRIVATE ANSWER", cwd: "/private/project", tools: ["run_terminal_command"] });
    expect(billed[1]).toMatchObject({ model: "grok-4.6", cost: 0.05 });
    expect(billed[1]?.text).toBeUndefined();
    expect(result.turns.filter(t => t.role === "user")).toHaveLength(2);
    expect(result.titles[0]?.title.text).toBe("Deployment review");
    expect(billed.reduce((n, t) => n + (t.cost ?? 0), 0)).toBeCloseTo(0.35);
  });

  it("keeps partial/incomplete costs unknown even when upstream includes a number", () => {
    const partial = parse().turns.filter(t => t.usage).at(-1)!;
    expect(partial).toMatchObject({ cost_unknown: true, usage_incomplete: true });
    expect(partial.cost).toBeUndefined();
    expect(partial.reported_cost).toBeUndefined();
    expect(partial.settlement).toBeUndefined();
  });

  it("does not fabricate usage for old or in-flight records and ignores torn lines", () => {
    expect(parse(fixture.split('\n').filter(l => !l.includes('turn_completed')).join('\n')).turns.every(t => !t.usage)).toBe(true);
    expect(parseGrokSession("{broken", "s")).toEqual({ turns: [], titles: [], detect: [] });
    const old = JSON.stringify({ timestamp: 1788692411, params: { update: { sessionUpdate: "turn_completed", prompt_id: "old" } } });
    const turn = parse(old).turns[0]!;
    expect(turn.usage).toBeUndefined();
    expect(turn.cost).toBeUndefined();
  });

  it("keeps spend IDs stable across re-reads, resumed appends and fork replay", () => {
    const first = parse().turns.filter(t => t.usage);
    const fork = parse(fixture, "fork-session").turns.filter(t => t.usage);
    expect(fork.map(t => t.id)).toEqual(first.map(t => t.id));
    const duplicate = parse(fixture + '\n' + fixture).turns.filter(t => t.usage);
    expect(duplicate.map(t => t.id)).toEqual(first.map(t => t.id));
  });

  it("anchors tool findings to the settled turn", () => {
    const result = parse();
    const assistant = result.turns.find(t => t.reported_cost)!;
    expect(result.detect.find(d => d.kind === "tool_call")).toMatchObject({ tool_name: "Bash", target: "git", turn_id: assistant.id });
    expect(result.detect.find(d => d.kind === "tool_output")).toMatchObject({ raw: "PRIVATE TOOL OUTPUT", anchor_turn_id: assistant.id });
  });
});

describe("Grok discovery", () => {
  it("discovers only session update files and honors a relocated home", () => {
    const root = "/custom/grok/sessions";
    const path = root + "/project/session/updates.jsonl";
    const dirs: Record<string, string[]> = { [root]: ["project"], [root + "/project"]: ["session"] };
    const io: SourceIo = {
      readText: p => p === path ? fixture : p.endsWith("summary.json") ? summary : undefined,
      listDir: p => dirs[p] ?? [],
      stat: p => p === path ? { size: 1, mtimeMs: 1, isDirectory: false } : dirs[p] ? { size: 0, mtimeMs: 1, isDirectory: true } : undefined,
      querySqlite: () => { throw new Error("not sqlite"); },
    };
    expect(grokSource.roots("/home/dev", { GROK_HOME: "/custom/grok" })[0]).toBe(root);
    expect(grokSource.discover(root, io)).toEqual([path]);
    expect(grokSource.sessionIdOf(path)).toBe("session");
    expect(grokSource.parse(path, io).turns.filter(t => t.usage)).toHaveLength(3);
  });
});
