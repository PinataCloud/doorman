import { describe, expect, it } from "vitest";
import {
  parseCodexRollout,
  rolloutSessionId,
  shadowAiIdForOriginator,
} from "../main/lib/codex-rollout.js";

const SESSION = "019fa430-8a06-7211-a2a1-d53c8c7327a1";

const line = (type: string, payload: unknown, ts = "2026-08-20T12:00:00.000Z") =>
  JSON.stringify({ timestamp: ts, type, payload });

describe("parseCodexRollout", () => {
  it("turns token_count events into priced assistant turns with stable ids", () => {
    const contents = [
      line("session_meta", { session_id: SESSION, cwd: "/Users/dev/repo" }),
      line("turn_context", { model: "gpt-5-codex" }),
      line("event_msg", { type: "user_message", message: "add a retry to the fetch" }),
      line("event_msg", { type: "agent_message", message: "On it." }),
      line("event_msg", {
        type: "token_count",
        info: {
          total_token_usage: { total_tokens: 15261 },
          last_token_usage: {
            input_tokens: 15137,
            cached_input_tokens: 11008,
            cache_write_input_tokens: 0,
            output_tokens: 124,
            reasoning_output_tokens: 12,
          },
        },
        rate_limits: { primary: { used_percent: 42.5 } },
      }),
    ].join("\n");

    const { turns } = parseCodexRollout(contents, "fallback");
    expect(turns).toHaveLength(2);

    const prompt = turns[0]!;
    expect(prompt.role).toBe("user");
    expect(prompt.session_id).toBe(SESSION);
    expect(prompt.text).toBe("add a retry to the fetch");

    const turn = turns[1]!;
    expect(turn.id).toBe(`codex:${SESSION}:15261`);
    expect(turn.model).toBe("gpt-5-codex");
    expect(turn.usage).toEqual({
      input_tokens: 15137 - 11008,
      output_tokens: 124,
      cache_read_tokens: 11008,
      cache_write_tokens: 0,
      cache_write_1h_tokens: 0,
      web_search_requests: 0,
    });
    // gpt-5-codex: in $1.25/M, out $10/M, cached $0.125/M.
    const expected = ((15137 - 11008) * 1.25 + 124 * 10 + 11008 * 0.125) / 1_000_000;
    expect(turn.cost).toBeCloseTo(expected, 12);
    // primary < 100% is OBSERVED subscription coverage.
    expect(turn.settlement).toBe("subscription");
    expect(turn.text).toBe("On it.");
  });

  const tokenCount = (total: number, rateLimits: unknown) =>
    line("event_msg", {
      type: "token_count",
      info: {
        total_token_usage: { total_tokens: total },
        last_token_usage: { input_tokens: 10, cached_input_tokens: 0, output_tokens: 5 },
      },
      rate_limits: rateLimits,
    });

  it("infers credits at 100% primary with credits available, unknown otherwise", () => {
    const contents = [
      line("session_meta", { session_id: SESSION }),
      tokenCount(100, { primary: { used_percent: 100 }, credits: { has_credits: true } }),
      tokenCount(200, undefined),
      tokenCount(300, { primary: {} }),
    ].join("\n");
    const { turns } = parseCodexRollout(contents, SESSION);
    expect(turns.map((t) => t.settlement)).toEqual([
      "credits",
      // NO rate_limits block at all → no observation, so the last verdict
      // carries forward. This is most records.
      "credits",
      // The provider DID report and the reading supports no funding claim, so
      // it retracts the previous one instead of inheriting it.
      "unknown",
    ]);
  });

  it("stops claiming coverage once a reading says the allowance is gone", () => {
    // The bug this closes: an explicitly exhausted reading with no credits
    // returned the same "unknown" as a record carrying no reading at all, and
    // the carry-forward rule could not tell them apart — so a session that ran
    // past its allowance kept reporting "Subscription" for every later turn.
    const contents = [
      line("session_meta", { session_id: SESSION }),
      tokenCount(100, { primary: { used_percent: 50 }, credits: { has_credits: false } }),
      tokenCount(200, { primary: { used_percent: 100 }, credits: { has_credits: false } }),
      tokenCount(300, undefined),
    ].join("\n");
    const { turns } = parseCodexRollout(contents, SESSION);
    expect(turns.map((t) => t.settlement)).toEqual([
      "subscription",
      "unknown",
      // Still nothing new to say — the retraction stands.
      "unknown",
    ]);
  });

  it("retracts credits once they read as depleted", () => {
    const contents = [
      line("session_meta", { session_id: SESSION }),
      tokenCount(100, { primary: { used_percent: 100 }, credits: { has_credits: true } }),
      tokenCount(200, {
        primary: { used_percent: 100 },
        credits: { has_credits: false, unlimited: false },
        rate_limit_reached_type: "workspace_member_credits_depleted",
      }),
    ].join("\n");
    const { turns } = parseCodexRollout(contents, SESSION);
    expect(turns.map((t) => t.settlement)).toEqual(["credits", "unknown"]);
  });

  it("refuses to interpret a utilization outside 0-100", () => {
    // Accepting any finite number would let a negative percentage read as
    // coverage and >100 read as credits. Malformed input settles the
    // conservative way.
    const negative = [
      line("session_meta", { session_id: SESSION }),
      tokenCount(100, { primary: { used_percent: -5 } }),
    ].join("\n");
    expect(parseCodexRollout(negative, SESSION).turns[0]!.settlement).toBe("unknown");
    const over = [
      line("session_meta", { session_id: SESSION }),
      tokenCount(100, { primary: { used_percent: 118 }, credits: { has_credits: true } }),
    ].join("\n");
    expect(parseCodexRollout(over, SESSION).turns[0]!.settlement).toBe("unknown");
  });

  it("leaves turns before any snapshot honestly unattributed", () => {
    const contents = [
      line("session_meta", { session_id: SESSION }),
      line("event_msg", {
        type: "token_count",
        info: {
          total_token_usage: { total_tokens: 50 },
          last_token_usage: { input_tokens: 10, cached_input_tokens: 0, output_tokens: 5 },
        },
      }),
    ].join("\n");
    const { turns } = parseCodexRollout(contents, SESSION);
    expect(turns[0]!.settlement).toBe("unknown");
  });

  it("skips ambient <wrapped> user messages and captures the first real prompt", () => {
    const contents = [
      line("event_msg", { type: "user_message", message: "<environment_context>…</environment_context>" }),
      line("event_msg", { type: "user_message", message: "real prompt" }),
    ].join("\n");
    const parsed = parseCodexRollout(contents, SESSION);
    expect(parsed.first_prompt).toBe("real prompt");
    expect(parsed.turns).toHaveLength(1);
  });

  it("collects tool calls as detect units anchored to the settling turn", () => {
    const contents = [
      line("session_meta", { session_id: SESSION }),
      line("response_item", {
        type: "function_call",
        name: "shell",
        arguments: JSON.stringify({ command: "printenv" }),
      }),
      line("event_msg", {
        type: "token_count",
        info: {
          total_token_usage: { total_tokens: 99 },
          last_token_usage: { input_tokens: 10, cached_input_tokens: 0, output_tokens: 5 },
        },
      }),
    ].join("\n");
    const { detect, turns } = parseCodexRollout(contents, SESSION);
    const tool = detect.find((u) => u.kind === "tool_call")!;
    expect(tool.turn_id).toBe(turns.find((t) => t.role === "assistant")!.id);
    expect(tool.target).toBe("printenv");
    expect(turns.find((t) => t.role === "assistant")!.tools).toEqual(["shell"]);
  });

  it("captures *_call_output as tool_output units, named via call_id, never as tool chips", () => {
    const contents = [
      line("session_meta", { session_id: SESSION }),
      line("response_item", {
        type: "function_call",
        name: "shell",
        call_id: "call_1",
        arguments: JSON.stringify({ command: "cat notes.md" }),
      }),
      line("response_item", {
        type: "function_call_output",
        call_id: "call_1",
        // The JSON-envelope shape some Codex versions write.
        output: JSON.stringify({ output: "the file contents", metadata: { exit_code: 0 } }),
      }),
      line("response_item", {
        type: "custom_tool_call_output",
        call_id: "call_unknown",
        output: "plain string output",
      }),
      line("event_msg", {
        type: "token_count",
        info: {
          total_token_usage: { total_tokens: 99 },
          last_token_usage: { input_tokens: 10, cached_input_tokens: 0, output_tokens: 5 },
        },
      }),
    ].join("\n");
    const { detect, turns } = parseCodexRollout(contents, SESSION);
    const outputs = detect.filter((u) => u.kind === "tool_output");
    expect(outputs).toHaveLength(2);
    expect(outputs[0]).toMatchObject({ raw: "the file contents", tool_name: "shell" });
    expect(outputs[1]!.raw).toBe("plain string output");
    expect(outputs[1]!.tool_name).toBeUndefined();
    // Outputs settle to the same turn as the calls, but never name tool chips.
    const assistant = turns.find((t) => t.role === "assistant")!;
    expect(outputs[0]!.turn_id).toBe(assistant.id);
    expect(assistant.tools).toEqual(["shell"]);
  });
});

describe("rolloutSessionId", () => {
  it("reads the conversation id from the filename", () => {
    expect(
      rolloutSessionId(`/x/2026/07/27/rollout-2026-07-27T12-27-52-${SESSION}.jsonl`),
    ).toBe(SESSION);
    expect(rolloutSessionId("/x/other.jsonl")).toBeUndefined();
  });
});

describe("originator → which app ran Codex", () => {
  const rollout = (originator?: string) =>
    [
      JSON.stringify({
        type: "session_meta",
        timestamp: "2026-08-24T19:55:47Z",
        payload: {
          id: "01a035fc",
          session_id: "01a035fc",
          cwd: "/Users/dev/notes",
          ...(originator === undefined ? {} : { originator }),
          source: "vscode",
        },
      }),
    ].join("\n");

  it("reads the surface off session_meta, verbatim", () => {
    expect(parseCodexRollout(rollout("Codex Desktop"), "f").originator).toBe("Codex Desktop");
    expect(parseCodexRollout(rollout("codex-tui"), "f").originator).toBe("codex-tui");
    // Rollouts written before Codex stamped it.
    expect(parseCodexRollout(rollout(), "f").originator).toBeUndefined();
  });

  it("maps ONLY the desktop surfaces to the ChatGPT Desktop row", () => {
    expect(shadowAiIdForOriginator("Codex Desktop")).toBe("chatgpt-desktop");
    expect(shadowAiIdForOriginator("codex_desktop")).toBe("chatgpt-desktop");
    expect(shadowAiIdForOriginator("  CODEX DESKTOP ")).toBe("chatgpt-desktop");
    // The terminal's own surfaces are the rail itself, not a separate app —
    // and a surface we have never seen must not be guessed into a row.
    for (const other of ["codex-tui", "codex_exec", "codex_vscode", "codex-desktop-next", ""]) {
      expect(shadowAiIdForOriginator(other)).toBeUndefined();
    }
    expect(shadowAiIdForOriginator(undefined)).toBeUndefined();
  });
});
