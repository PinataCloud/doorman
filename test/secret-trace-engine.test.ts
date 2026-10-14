import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { CaptureEngine } from "../main/capture.js";
import { defaultPolicy } from "../main/guard/policy.js";

/**
 * The trace end to end: real transcript files in a temp tree, the engine's
 * own backfill, then `traceSecret` — the literal search over every document
 * plus the turn store, folded into the report the screen shows.
 */

const SESSION = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
const OTHER = "bbbbbbbb-bbbb-cccc-dddd-eeeeeeeeeeee";
const KEY = "sk-ant-api03-RrQkSgZuGnEbLbBvCuVpVtDsRp5889763378xxndppahgp";
const CWD = "/Users/dev/repos/acme/api";

function exposedTranscript(): string {
  return [
    JSON.stringify({
      type: "user",
      uuid: "prompt-1",
      timestamp: "2026-08-20T10:00:00.000Z",
      sessionId: SESSION,
      cwd: CWD,
      message: { role: "user", content: `use ${KEY} for the deploy and put it in .env` },
    }),
    JSON.stringify({
      type: "assistant",
      timestamp: "2026-08-20T10:00:05.000Z",
      sessionId: SESSION,
      cwd: CWD,
      message: {
        id: "msg_1",
        model: "claude-opus-5",
        role: "assistant",
        content: [
          { type: "tool_use", id: "toolu_1", name: "Write", input: { file_path: `${CWD}/.env`, content: `ANTHROPIC_API_KEY=${KEY}\n` } },
        ],
        usage: { input_tokens: 10, output_tokens: 5, cache_creation_input_tokens: 0, cache_read_input_tokens: 0 },
      },
    }),
    JSON.stringify({
      type: "user",
      uuid: "tool-res-1",
      timestamp: "2026-08-20T10:00:06.000Z",
      sessionId: SESSION,
      message: { role: "user", content: [{ type: "tool_result", tool_use_id: "toolu_1", content: `wrote ANTHROPIC_API_KEY=${KEY}` }] },
    }),
    JSON.stringify({
      type: "assistant",
      timestamp: "2026-08-20T10:00:09.000Z",
      sessionId: SESSION,
      cwd: CWD,
      message: {
        id: "msg_2",
        model: "claude-opus-5",
        role: "assistant",
        content: [{ type: "text", text: "Done — the key is in .env." }],
        usage: { input_tokens: 10, output_tokens: 5, cache_creation_input_tokens: 0, cache_read_input_tokens: 0 },
      },
    }),
  ].join("\n");
}

function cleanTranscript(): string {
  return [
    JSON.stringify({
      type: "user",
      uuid: "prompt-2",
      timestamp: "2026-08-21T10:00:00.000Z",
      sessionId: OTHER,
      cwd: "/Users/dev/repos/other",
      message: { role: "user", content: "rename the readme" },
    }),
  ].join("\n");
}

describe("CaptureEngine.traceSecret", () => {
  let root: string;
  let deps: ConstructorParameters<typeof CaptureEngine>[0];

  beforeEach(() => {
    root = mkdtempSync(join(tmpdir(), "doorman-trace-"));
    mkdirSync(join(root, "claude", "projects", "-Users-dev-repos-acme-api"), { recursive: true });
    mkdirSync(join(root, "claude", "projects", "-Users-dev-repos-other"), { recursive: true });
    mkdirSync(join(root, "codex", "sessions"), { recursive: true });
    writeFileSync(join(root, "claude", "projects", "-Users-dev-repos-acme-api", `${SESSION}.jsonl`), exposedTranscript());
    writeFileSync(join(root, "claude", "projects", "-Users-dev-repos-other", `${OTHER}.jsonl`), cleanTranscript());
    deps = {
      storeDir: join(root, "store"),
      claudeProjectsDir: join(root, "claude", "projects"),
      codexSessionsDir: join(root, "codex", "sessions"),
      home: root,
      policy: () => defaultPolicy(),
      retentionDays: () => 0,
      onUpdate: () => {},
      onNewFindings: () => {},
      log: () => {},
    };
  });

  afterEach(() => {
    rmSync(root, { recursive: true, force: true });
  });

  it("finds every place the value appears, says where, and what the Radar made of it", async () => {
    const engine = new CaptureEngine(deps);
    await engine.start();
    const progress: Array<{ done: number; total: number }> = [];
    const report = await engine.traceSecret(KEY, (p) => progress.push(p));

    // Prompt, the Write call, its result — one sighting each, one session.
    expect(report.total).toBe(3);
    expect(report.sessions).toBe(1);
    expect(report.places).toHaveLength(1);
    expect(report.places[0]!.label).toBe("acme/api");
    const hows = report.places[0]!.sightings.map((s) => s.how).sort();
    expect(hows).toEqual(["In your prompt", "Echoed back after writing acme/api/.env", "Written to acme/api/.env"].sort());
    expect(report.writes.map((w) => w.path)).toEqual([`${CWD}/.env`]);
    expect(report.providers).toEqual([{ source: "claude-code", label: "Claude Code", provider: "Anthropic", sessions: 1 }]);

    // The prompt's sighting is tied to the Radar row the backfill minted for it.
    const prompt = report.places[0]!.sightings.find((s) => s.kind === "prompt");
    expect(prompt?.finding_id).toBeDefined();
    expect(engine.ledger.get(prompt!.finding_id!)?.detector).toBe("credential_in_prompt");
    expect(prompt?.outcome).toBe("observed");

    // The transcript that holds it, and the coverage a zero would be judged by.
    expect(report.files).toEqual([{ path: join(deps.claudeProjectsDir, "-Users-dev-repos-acme-api", `${SESSION}.jsonl`), source: "claude-code" }]);
    expect(report.coverage.files_scanned).toBe(2);
    expect(report.coverage.turns).toBeGreaterThanOrEqual(3);
    expect(report.coverage.since).toBe("2026-08-20T10:00:00.000Z");
    expect(report.shape).toMatchObject({ family: "anthropic", recognized: true, tail: KEY.slice(-4) });
    expect(progress.length).toBeGreaterThan(0);
    expect(progress[progress.length - 1]).toEqual({ done: 2, total: 2 });

    // What comes back never carries the value.
    expect(JSON.stringify(report)).not.toContain(KEY);
  });

  it("a fragment finds the same places; an absent value finds none and says what that covers", async () => {
    const engine = new CaptureEngine(deps);
    await engine.start();
    const fragment = await engine.traceSecret(KEY.slice(-12));
    expect(fragment.total).toBe(3);
    expect(fragment.shape.family).toBeUndefined();

    const none = await engine.traceSecret("sk-ant-api03-NotInAnyTranscriptAtAll000000000000");
    expect(none.total).toBe(0);
    expect(none.files).toEqual([]);
    expect(none.coverage.files_scanned).toBe(2);
    expect(none.coverage.sources).toContain("Claude Code");
  });
});
