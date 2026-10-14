import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  clientNameOf,
  copilotSessionIdFromPath,
  copilotSource,
  copilotSourceFor,
  copilotUsageDbPath,
  parseCopilotSession,
  USAGE_ROWS_SQL,
  type CopilotUsageRow,
} from "../main/lib/copilot-transcript.js";
import type { SourceIo } from "../main/lib/transcript-sources.js";
import { TURN_TEXT_MAX_CHARS, TURN_TOOLS_MAX } from "../main/lib/turns.js";

const FIXTURES = join(
  dirname(fileURLToPath(import.meta.url)),
  "fixtures",
  "transcripts",
  "copilot",
);

const PRICED_SESSION = "9f2a6c14-8f31-4b7e-9d2a-3c5e17a08b41";
const UNMETERED_SESSION = "7c9d0e5b-2a44-4f18-8c31-6b0d9e7f1a20";

function fixture(name: string): string {
  return readFileSync(join(FIXTURES, name, "events.jsonl"), "utf8");
}

/** A fake SourceIo over a plain path → contents map. Directories are declared
 * by listing their entries. `sqlite` answers `querySqlite` for the paths it
 * names (the session-store usage table); any other database throws, which the
 * descriptor must survive. */
function fakeIo(
  files: Record<string, string>,
  dirs: Record<string, string[]> = {},
  sqlite: Record<string, (sql: string, params: readonly unknown[]) => Record<string, unknown>[]> = {},
): SourceIo {
  return {
    readText: (path) => files[path],
    listDir: (path) => dirs[path] ?? [],
    stat: (path) => {
      if (path in dirs) return { size: 0, mtimeMs: 1, isDirectory: true };
      if (path in files) return { size: files[path]!.length, mtimeMs: 1, isDirectory: false };
      if (path in sqlite) return { size: 4096, mtimeMs: 1, isDirectory: false };
      return undefined;
    },
    querySqlite: (path, sql, params = []) => {
      const answer = sqlite[path];
      if (!answer) throw new Error(`no sqlite fixture at ${path}`);
      return answer(sql, params);
    },
  };
}

const event = (type: string, data: unknown, id: string, timestamp = "2026-09-05T10:00:00.000Z") =>
  JSON.stringify({ id, timestamp, parentId: null, type, data });

describe("copilotSource descriptor", () => {
  it("declares the shipped identity the ledger keys off", () => {
    expect(copilotSource.id).toBe("copilot-cli");
    expect(copilotSource.label).toBe("Copilot CLI");
    expect(copilotSource.presencePaths).toEqual([".copilot/session-state"]);
    // Copilot records its own token counts (assistant.usage per model call,
    // modelMetrics at session.shutdown) — this rail is metered, not just seen.
    expect(copilotSource.metered).toBe(true);
  });

  it("roots at ~/.copilot/session-state, and follows COPILOT_HOME when set", () => {
    expect(copilotSource.roots("/Users/dev", {})).toEqual([
      "/Users/dev/.copilot/session-state",
    ]);
    expect(
      copilotSource.roots("/Users/dev", { COPILOT_HOME: "/opt/copilot-home" }),
    ).toEqual(["/opt/copilot-home/session-state"]);
    // An empty override is not an override.
    expect(copilotSource.roots("/Users/dev", { COPILOT_HOME: "" })).toEqual([
      "/Users/dev/.copilot/session-state",
    ]);
  });

  it("discovers one events.jsonl per session directory, sorted", () => {
    const root = "/home/.copilot/session-state";
    const io = fakeIo(
      {
        [`${root}/bbb/events.jsonl`]: "",
        [`${root}/aaa/events.jsonl`]: "",
        // A flat document (older layout) is accepted too.
        [`${root}/ccc.jsonl`]: "",
        // Anything else in a session directory is not a document.
        [`${root}/aaa/workspace.yaml`]: "id: aaa",
        [`${root}/notes.txt`]: "",
      },
      {
        [root]: ["bbb", "aaa", "ccc.jsonl", "notes.txt", ".DS_Store", "empty"],
        [`${root}/bbb`]: ["events.jsonl"],
        [`${root}/aaa`]: ["events.jsonl", "workspace.yaml"],
        // A session directory that has not been written yet yields nothing.
        [`${root}/empty`]: [],
      },
    );
    expect(copilotSource.discover(root, io)).toEqual([
      `${root}/aaa/events.jsonl`,
      `${root}/bbb/events.jsonl`,
      `${root}/ccc.jsonl`,
    ]);
  });

  it("reads the session id out of a document path", () => {
    expect(
      copilotSource.sessionIdOf("/home/.copilot/session-state/abc-123/events.jsonl"),
    ).toBe("abc-123");
    expect(copilotSessionIdFromPath("/home/.copilot/session-state/abc-123.jsonl")).toBe(
      "abc-123",
    );
    expect(copilotSessionIdFromPath("/home/.copilot/session-state/abc-123")).toBeUndefined();
  });

  it("parses through the io, and a missing document is empty, not a throw", () => {
    const path = `/home/.copilot/session-state/${PRICED_SESSION}/events.jsonl`;
    const io = fakeIo({ [path]: fixture("priced-session") });
    const result = copilotSource.parse(path, io);
    expect(result.turns.length).toBeGreaterThan(0);
    expect(result.turns.every((t) => t.session_id === PRICED_SESSION)).toBe(true);
    expect(copilotSource.parse("/nope/events.jsonl", io)).toEqual({
      turns: [],
      titles: [],
      detect: [],
    });
  });
});

describe("parseCopilotSession", () => {
  it("turns assistant.usage into priced turns with the message event's stable id", () => {
    const { turns, titles } = parseCopilotSession(fixture("priced-session"), "from-path");

    expect(turns.map((t) => t.role)).toEqual(["user", "assistant", "assistant"]);
    // session.start's own sessionId wins over the directory name.
    expect(turns.every((t) => t.session_id === PRICED_SESSION)).toBe(true);

    const prompt = turns[0]!;
    expect(prompt.id).toBe(`copilot:${PRICED_SESSION}:11111111-0000-4000-8000-000000000002`);
    expect(prompt.text).toBe("add a retry budget to the payments client");
    expect(prompt.cwd).toBe("/Users/dev/acme-api");
    expect(prompt.git_branch).toBe("feat/retry-budget");
    expect(prompt.usage).toBeUndefined();

    const first = turns[1]!;
    // The id comes from the assistant.message, not the usage event, so a
    // re-parse after the call settles updates this row instead of adding one.
    expect(first.id).toBe(`copilot:${PRICED_SESSION}:11111111-0000-4000-8000-000000000004`);
    expect(first.at).toBe("2026-09-05T10:00:31.000Z");
    expect(first.model).toBe("claude-sonnet-4.5");
    // inputTokens is the TOTAL prompt side: the cache buckets come out of it.
    expect(first.usage).toEqual({
      input_tokens: 24000 - 18000 - 2000,
      output_tokens: 900,
      cache_read_tokens: 18000,
      cache_write_tokens: 2000,
      cache_write_1h_tokens: 0,
      web_search_requests: 0,
    });
    // claude-sonnet-4.5 → anthropic/claude-sonnet-4-5: in $3/M, out $15/M,
    // cache read $0.30/M, cache write $3.75/M.
    expect(first.cost).toBeCloseTo(
      (4000 * 3 + 900 * 15 + 18000 * 0.3 + 2000 * 3.75) / 1_000_000,
      12,
    );
    expect(first.cost_unknown).toBeUndefined();
    // Quota still available on the snapshot riding this call.
    expect(first.settlement).toBe("subscription");
    expect(first.text).toBe("Looking at the payments client first.");
    // Copilot's own tool names, mapped to the names the detectors key on.
    expect(first.tools).toEqual(["Read", "Bash"]);

    const second = turns[2]!;
    expect(second.id).toBe(`copilot:${PRICED_SESSION}:11111111-0000-4000-8000-00000000000b`);
    expect(second.model).toBe("gpt-5");
    expect(second.usage?.input_tokens).toBe(31000 - 25000);
    expect(second.cost).toBeCloseTo(
      (6000 * 1.25 + 1400 * 10 + 25000 * 0.125) / 1_000_000,
      12,
    );
    // Quota exhausted with overage allowed and used → paid overage.
    expect(second.settlement).toBe("credits");
    expect(second.tools).toEqual(["Edit"]);

    // Per-call usage was present, so the session.shutdown fallback stays off.
    expect(turns.some((t) => t.id.includes(":shutdown:"))).toBe(false);

    // The CLI's own generated title outranks a first-prompt title.
    expect(titles).toEqual([
      {
        session_id: PRICED_SESSION,
        title: { text: "Retry budget for the payments client", origin: "auto_summary" },
      },
    ]);
  });

  it("scans prompts, tool calls and tool output, including non-human prompts", () => {
    const { detect } = parseCopilotSession(fixture("priced-session"), "from-path");
    expect(detect.map((u) => u.kind)).toEqual([
      "prompt",
      "tool_call",
      "tool_output",
      "prompt",
    ]);

    const call = detect[1]!;
    expect(call.tool_name).toBe("Bash");
    expect(call.target).toBe("rg");
    expect(call.raw).toContain("rg -n 'retry' src/payments");
    expect(call.cwd).toBe("/Users/dev/acme-api");
    // Units raised before the call settled are anchored to its turn.
    expect(call.turn_id).toBe(
      `copilot:${PRICED_SESSION}:11111111-0000-4000-8000-000000000004`,
    );

    const output = detect[2]!;
    expect(output.tool_name).toBe("Bash");
    expect(output.raw).toContain("no retry policy yet");

    // A skill-injected message is NOT a prompt turn, but it is still scanned.
    const injected = detect[3]!;
    expect(injected.raw).toContain("summarize the attached invoice pdf");
    const turnIds = new Set(
      parseCopilotSession(fixture("priced-session"), "x").turns.map((t) => t.id),
    );
    expect(turnIds.has(injected.turn_id)).toBe(false);
  });

  it("keeps the assistant turn id stable as the document grows", () => {
    const full = fixture("priced-session").split("\n").filter((l) => l.trim() !== "");
    // The document as it looked before the call settled (no usage line yet).
    const beforeUsage = full.slice(0, 6).join("\n");
    const early = parseCopilotSession(beforeUsage, "from-path");
    const settled = parseCopilotSession(full.join("\n"), "from-path");

    const earlyAssistant = early.turns.find((t) => t.role === "assistant")!;
    const settledAssistant = settled.turns.find((t) => t.role === "assistant")!;
    expect(earlyAssistant.id).toBe(settledAssistant.id);
    // Unsettled: seen, honestly unpriced. Settled: real tokens.
    expect(earlyAssistant.usage).toBeUndefined();
    expect(earlyAssistant.cost_unknown).toBe(true);
    expect(settledAssistant.usage).toBeDefined();

    // And a re-parse of the same bytes is byte-identical.
    expect(parseCopilotSession(full.join("\n"), "from-path")).toEqual(settled);
  });

  it("falls back to the session's own shutdown totals when no usage was persisted", () => {
    const { turns } = parseCopilotSession(fixture("unmetered-session"), "from-path");
    const assistant = turns.filter((t) => t.role === "assistant");
    expect(assistant).toHaveLength(2);

    // The responses themselves: seen, unpriced, never invented.
    const seen = assistant[0]!;
    expect(seen.usage).toBeUndefined();
    expect(seen.cost).toBeUndefined();
    expect(seen.cost_unknown).toBe(true);
    expect(seen.text).toContain("Comparing the two bundle reports");
    expect(seen.text).toContain("every moment.js locale");

    // session.shutdown's per-model accounting is the only token record here.
    const settled = assistant[1]!;
    expect(settled.id).toBe(`copilot:${UNMETERED_SESSION}:shutdown:gpt-5`);
    expect(settled.at).toBe("2026-09-05T14:01:05.000Z");
    expect(settled.model).toBe("gpt-5");
    expect(settled.usage).toEqual({
      input_tokens: 40000 - 30000 - 1000,
      output_tokens: 2200,
      cache_read_tokens: 30000,
      cache_write_tokens: 1000,
      cache_write_1h_tokens: 0,
      web_search_requests: 0,
    });
    expect(settled.cost).toBeCloseTo(
      // gpt-5 publishes no cache-write premium: writes price at the input rate.
      (9000 * 1.25 + 2200 * 10 + 30000 * 0.125 + 1000 * 1.25) / 1_000_000,
      12,
    );
    // No quota snapshot was ever seen, so settlement stays honestly unknown.
    expect(settled.settlement).toBe("unknown");
  });

  it("tolerates half-written, truncated and unknown records", () => {
    const { turns, detect } = parseCopilotSession(fixture("malformed-session"), "from-path");
    // The truncated trailing assistant.usage line is skipped, not thrown on;
    // the prompt and the unsettled response still land.
    expect(turns.map((t) => t.role)).toEqual(["user", "assistant"]);
    expect(turns[0]!.text).toBe("ship it");
    const assistant = turns[1]!;
    expect(assistant.usage).toBeUndefined();
    expect(assistant.cost_unknown).toBe(true);
    // An MCP tool is named the way the mcp__ detectors expect.
    expect(assistant.tools).toEqual(["mcp__releases__promote"]);

    // A tool call raised before any assistant turn is anchored to the first
    // one rather than dropped, and a JSON-STRING `arguments` still parses.
    const call = detect.find((u) => u.kind === "tool_call")!;
    expect(call.tool_name).toBe("Bash");
    expect(call.target).toBe("curl");
    expect(call.turn_id).toBe(assistant.id);
    // A user.message with no timestamp cannot be placed, so it is skipped.
    expect(turns.some((t) => t.text === "no timestamp on this one")).toBe(false);
  });

  it("reads settlement off the quota snapshot, and bills a BYOK call to the API key", () => {
    const usage = (data: Record<string, unknown>, id: string) =>
      [
        event("assistant.message", { messageId: id, content: "ok" }, `m-${id}`),
        event("assistant.usage", { model: "gpt-5", inputTokens: 10, outputTokens: 5, ...data }, id),
      ].join("\n");

    const unlimited = parseCopilotSession(
      usage({ quotaSnapshots: { premium: { isUnlimitedEntitlement: true } } }, "u1"),
      "s",
    );
    expect(unlimited.turns[0]!.settlement).toBe("subscription");

    const exhausted = parseCopilotSession(
      usage(
        {
          quotaSnapshots: {
            premium: { hasQuota: false, remainingPercentage: 0, overage: 3 },
          },
        },
        "u2",
      ),
      "s",
    );
    expect(exhausted.turns[0]!.settlement).toBe("credits");

    // Bring-your-own-key is metered on the person's own provider account: the
    // one funding mode the host states outright. It is never plan-covered,
    // whatever the (irrelevant) Copilot quota beside it says.
    const byok = parseCopilotSession(
      usage({ isByok: true, quotaSnapshots: { premium: { hasQuota: true } } }, "u3"),
      "s",
    );
    expect(byok.turns[0]!.settlement).toBe("billed");

    const silent = parseCopilotSession(usage({}, "u4"), "s");
    expect(silent.turns[0]!.settlement).toBe("unknown");
  });

  it("lets a later reading replace the session's verdict instead of only ever upgrading it", () => {
    // The sticky bug: a BYOK turn (or an exhausted quota with no overage) after
    // an included one produced a verdict the carry-forward rule discarded as
    // "no news", so the whole rest of the session kept reading as plan-covered.
    const usage = (data: Record<string, unknown>, id: string) =>
      [
        event("assistant.message", { messageId: id, content: "ok" }, `m-${id}`),
        event("assistant.usage", { model: "gpt-5", inputTokens: 10, outputTokens: 5, ...data }, id),
      ].join("\n");
    const doc = [
      usage({ quotaSnapshots: { premium: { hasQuota: true, remainingPercentage: 40 } } }, "u1"),
      // The developer switches to their own key mid-session.
      usage({ isByok: true }, "u2"),
      // No snapshot and no BYOK flag at all: nothing observed, last verdict holds.
      usage({}, "u3"),
      // Back on the plan, but the quota is gone and overage is not allowed.
      usage({ quotaSnapshots: { premium: { hasQuota: false, remainingPercentage: 0 } } }, "u4"),
      usage({}, "u5"),
    ].join("\n");
    const { turns } = parseCopilotSession(doc, "s");
    expect(turns.map((t) => t.settlement)).toEqual([
      "subscription",
      "billed",
      "billed",
      "unknown",
      "unknown",
    ]);
  });

  it("prices only what it can name, and never silently zeroes an unknown model", () => {
    const doc = [
      event("assistant.message", { messageId: "a", content: "hi" }, "m1"),
      event(
        "assistant.usage",
        { model: "custom-inhouse-model", inputTokens: 1000, outputTokens: 100 },
        "u1",
      ),
    ].join("\n");
    const { turns } = parseCopilotSession(doc, "s");
    expect(turns[0]!.model).toBe("custom-inhouse-model");
    expect(turns[0]!.usage?.input_tokens).toBe(1000);
    expect(turns[0]!.cost).toBeUndefined();
    expect(turns[0]!.cost_unknown).toBe(true);
  });

  it("caps stored text and tool chips, and scans the full text before the cap", () => {
    const long = "x".repeat(TURN_TEXT_MAX_CHARS + 500);
    const requests = Array.from({ length: TURN_TOOLS_MAX + 8 }, (_, i) => ({
      toolCallId: `c${i}`,
      name: "bash",
      arguments: { command: "ls" },
    }));
    const doc = [
      event("session.start", { sessionId: "s1" }, "e1"),
      event("user.message", { content: long }, "e2"),
      event("assistant.message", { messageId: "a", content: long, toolRequests: requests }, "e3"),
      event(
        "assistant.usage",
        { model: "gpt-5", inputTokens: 100, outputTokens: 10 },
        "e4",
      ),
    ].join("\n");
    const { turns, detect } = parseCopilotSession(doc, "s1");
    expect(turns[0]!.text).toHaveLength(TURN_TEXT_MAX_CHARS);
    expect(turns[1]!.text).toHaveLength(TURN_TEXT_MAX_CHARS);
    expect(turns[1]!.tools).toHaveLength(TURN_TOOLS_MAX);
    // Detection sees the whole prompt, cap or no cap.
    expect(detect[0]!.raw).toHaveLength(long.length);
  });

  it("keeps sub-agent calls on their own settlement, not the main conversation's", () => {
    const doc = [
      event("session.start", { sessionId: "s1", selectedModel: "gpt-5" }, "e1"),
      event("assistant.message", { messageId: "main-1", content: "main answer" }, "e2"),
      JSON.stringify({
        id: "e3",
        timestamp: "2026-09-05T10:00:02.000Z",
        parentId: null,
        agentId: "agent-7",
        type: "assistant.message",
        data: { messageId: "sub-1", content: "sub answer" },
      }),
      JSON.stringify({
        id: "e4",
        timestamp: "2026-09-05T10:00:03.000Z",
        parentId: null,
        agentId: "agent-7",
        type: "assistant.usage",
        data: { model: "gpt-5", inputTokens: 500, outputTokens: 50 },
      }),
      event("assistant.usage", { model: "gpt-5", inputTokens: 200, outputTokens: 20 }, "e5"),
    ].join("\n");
    const { turns } = parseCopilotSession(doc, "s1");
    const byId = new Map(turns.map((t) => [t.id, t]));
    // Each agent's text settled against its OWN usage event.
    expect(byId.get("copilot:s1:e3")!.text).toBe("sub answer");
    expect(byId.get("copilot:s1:e3")!.usage?.output_tokens).toBe(50);
    expect(byId.get("copilot:s1:e2")!.text).toBe("main answer");
    expect(byId.get("copilot:s1:e2")!.usage?.output_tokens).toBe(20);
  });
});

/**
 * METERING, SECOND SOURCE: CLI 1.0.83 never persists `assistant.usage`, but
 * `~/.copilot/session-store.db`'s `assistant_usage_events` holds the exact
 * per-call record. The parser pairs an agent's k-th row with its k-th
 * `assistant.message`; the descriptor fetches the rows through io.querySqlite.
 */
describe("session-store usage rows", () => {
  const SID = "3e6f1a2b-4c5d-4e7f-8a9b-0c1d2e3f4a5b";
  const HOME = "/Users/dev/.copilot";
  const EVENTS = `${HOME}/session-state/${SID}/events.jsonl`;
  const DB = `${HOME}/session-store.db`;

  /** A log with two model calls on the main agent and one on a sub-agent, no
   * assistant.usage anywhere, and a shutdown whose totals would otherwise be
   * the fallback. */
  const unsettledLog = (): string =>
    [
      event("session.start", { sessionId: SID, selectedModel: "claude-sonnet-4.5", context: { cwd: "/Users/dev/acme-api", branch: "main" } }, "e-start", "2026-09-08T16:57:44.000Z"),
      event("user.message", { content: "add a retry budget" }, "e-prompt", "2026-09-08T16:57:45.000Z"),
      event("assistant.message", { content: "Reading the client first.", toolRequests: [{ toolCallId: "c1", name: "view", arguments: {} }] }, "e-msg-1", "2026-09-08T16:57:49.000Z"),
      event("tool.execution_start", { toolCallId: "c1", toolName: "view", arguments: { path: "/Users/dev/acme-api/src/client.ts" } }, "e-tool-1", "2026-09-08T16:57:49.500Z"),
      JSON.stringify({ id: "e-sub-1", timestamp: "2026-09-08T16:57:50.000Z", parentId: null, agentId: "explorer", type: "assistant.message", data: { content: "Sub-agent summary." } }),
      event("assistant.message", { content: "Done — retries now 3." }, "e-msg-2", "2026-09-08T16:57:51.000Z"),
      event("session.shutdown", { modelMetrics: { "claude-sonnet-4.5": { usage: { inputTokens: 999999, outputTokens: 1, cacheReadTokens: 0, cacheWriteTokens: 0 } } } }, "e-shutdown", "2026-09-08T16:58:00.000Z"),
    ].join("\n") + "\n";

  const row = (id: number, over: Partial<CopilotUsageRow> = {}): CopilotUsageRow => ({
    id,
    turn_index: 0,
    agent_id: null,
    model: "claude-sonnet-4.5",
    input_tokens: 24000,
    output_tokens: 900,
    cache_read_tokens: 18000,
    cache_write_tokens: 2000,
    created_at: `2026-09-08T16:57:${String(48 + id).padStart(2, "0")}.000Z`,
    ...over,
  });

  it("pairs each agent's rows with its assistant.message events, in order", () => {
    const rows = [row(1), row(2, { agent_id: "explorer", model: "gpt-5", input_tokens: 31000, output_tokens: 1400, cache_read_tokens: 25000, cache_write_tokens: 0 }), row(3, { output_tokens: 40 })];
    const { turns } = parseCopilotSession(unsettledLog(), SID, { usageRows: rows });
    const assistant = turns.filter((t) => t.role === "assistant");
    expect(assistant.map((t) => t.id)).toEqual([`copilot:${SID}:e-msg-1`, `copilot:${SID}:e-sub-1`, `copilot:${SID}:e-msg-2`]);
    // Main's first call ← row 1; the sub-agent's call ← row 2; main's second ← row 3.
    expect(assistant[0]!.usage).toEqual({ input_tokens: 4000, output_tokens: 900, cache_read_tokens: 18000, cache_write_tokens: 2000, cache_write_1h_tokens: 0, web_search_requests: 0 });
    expect(assistant[0]!.cost).toBeCloseTo((4000 * 3 + 900 * 15 + 18000 * 0.3 + 2000 * 3.75) / 1_000_000, 12);
    expect(assistant[0]!.text).toBe("Reading the client first.");
    expect(assistant[0]!.tools).toEqual(["Read"]);
    expect(assistant[1]!.model).toBe("gpt-5");
    expect(assistant[1]!.usage?.input_tokens).toBe(6000);
    expect(assistant[2]!.usage?.output_tokens).toBe(40);
    // Priced from the table, so the shutdown fallback stays off.
    expect(turns.some((t) => t.id.includes(":shutdown:"))).toBe(false);
    // The tool call anchors to the turn whose message requested it.
    const { detect } = parseCopilotSession(unsettledLog(), SID, { usageRows: rows });
    expect(detect.find((u) => u.kind === "tool_call")?.turn_id).toBe(`copilot:${SID}:e-msg-1`);
  });

  it("a row with no message becomes its own priced settlement turn; a message with no row stays unpriced", () => {
    const { turns } = parseCopilotSession(unsettledLog(), SID, { usageRows: [row(1), row(7, { created_at: "2026-09-08T16:57:59.000Z" }), row(9)] });
    const assistant = turns.filter((t) => t.role === "assistant");
    // Three main-agent rows, two main-agent messages: the third row is a tail.
    const tail = assistant.find((t) => t.id === `copilot:${SID}:usage:9`)!;
    expect(tail.usage?.output_tokens).toBe(900);
    expect(tail.cost).toBeGreaterThan(0);
    expect(tail.text).toBeUndefined();
    // The sub-agent's message had no row of its own: a turn, unpriced, never $0.
    const sub = assistant.find((t) => t.id === `copilot:${SID}:e-sub-1`)!;
    expect(sub.usage).toBeUndefined();
    expect(sub.cost).toBeUndefined();
    expect(sub.cost_unknown).toBe(true);
  });

  it("without rows the old behaviour stands: unpriced turns, then the shutdown fallback", () => {
    const { turns } = parseCopilotSession(unsettledLog(), SID);
    expect(turns.filter((t) => t.id.includes(":shutdown:"))).toHaveLength(1);
    expect(turns.filter((t) => t.id.includes(":usage:"))).toHaveLength(0);
  });

  it("persisted assistant.usage events win over the table — nothing counts twice", () => {
    const withRows = parseCopilotSession(fixture("priced-session"), "from-path", { usageRows: [row(1), row(2), row(3)] });
    const without = parseCopilotSession(fixture("priced-session"), "from-path");
    expect(withRows.turns).toEqual(without.turns);
  });

  it("attributes the session to the rail the caller names", () => {
    const { turns } = parseCopilotSession(unsettledLog(), SID, { source: "vscode-copilot", usageRows: [row(1)] });
    expect(turns.length).toBeGreaterThan(0);
    expect(turns.every((t) => t.source === "vscode-copilot")).toBe(true);
  });

  it("locates the database and reads the host out of workspace.yaml", () => {
    expect(copilotUsageDbPath(EVENTS)).toBe(DB);
    expect(copilotUsageDbPath("/x/session-state/abc.jsonl")).toBeUndefined();
    expect(clientNameOf("id: abc\ncwd: /w\nclient_name: github/cli\nname: x\n")).toBe("github/cli");
    expect(clientNameOf("client_name: \"vscode\"\n")).toBe("vscode");
    expect(clientNameOf(undefined)).toBeUndefined();
    expect(copilotSourceFor("github/cli")).toBe("copilot-cli");
    expect(copilotSourceFor("vscode")).toBe("vscode-copilot");
    expect(copilotSourceFor("vscode-insiders")).toBe("vscode-copilot");
    expect(copilotSourceFor(undefined)).toBe("copilot-cli");
  });

  it("the descriptor prices a VS Code-hosted session from the table, under the VS Code rail", () => {
    const seen: { sql: string; params: readonly unknown[] }[] = [];
    const io = fakeIo(
      { [EVENTS]: unsettledLog(), [`${HOME}/session-state/${SID}/workspace.yaml`]: `id: ${SID}\ncwd: /Users/dev/acme-api\nclient_name: vscode\n` },
      {},
      {
        [DB]: (sql, params) => {
          seen.push({ sql, params });
          return [row(1), row(3)] as unknown as Record<string, unknown>[];
        },
      },
    );
    const { turns } = copilotSource.parse(EVENTS, io);
    expect(seen).toEqual([{ sql: USAGE_ROWS_SQL, params: [SID] }]);
    expect(turns.every((t) => t.source === "vscode-copilot")).toBe(true);
    expect(turns.filter((t) => t.usage !== undefined)).toHaveLength(2);
  });

  it("a CLI session stays on its rail, and a missing or failing database means unpriced, never a throw", () => {
    const cli = copilotSource.parse(EVENTS, fakeIo({ [EVENTS]: unsettledLog(), [`${HOME}/session-state/${SID}/workspace.yaml`]: "client_name: github/cli\n" }));
    expect(cli.turns.every((t) => t.source === "copilot-cli")).toBe(true);
    expect(cli.turns.filter((t) => t.usage !== undefined).map((t) => t.id)).toEqual([`copilot:${SID}:shutdown:claude-sonnet-4.5`]);
    const failing = copilotSource.parse(
      EVENTS,
      fakeIo({ [EVENTS]: unsettledLog() }, {}, { [DB]: () => { throw new Error("database is locked"); } }),
    );
    expect(failing.turns.length).toBe(cli.turns.length);
  });
});
