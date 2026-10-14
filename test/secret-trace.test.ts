import { describe, expect, it } from "vitest";
import type { FindingRow } from "../main/lib/findings.js";
import {
  attachFinding,
  buildTraceReport,
  countOccurrences,
  describeSighting,
  literalForms,
  normalizeTraceInput,
  outcomeOfRow,
  traceShape,
  type RawSighting,
  type TraceCoverage,
} from "../main/lib/secret-trace.js";
import { traceContext } from "../main/ai-assistant.js";

/** A live-looking Anthropic key — the shape redact.ts names `anthropic`. */
const KEY = "sk-ant-api03-RrQkSgZuGnEbLbBvCuVpVtDsRp5889763378xxndppahgp";
const AWS_KEY = "AKIARFQRSLZCGAEHLNBH";

const coverage: TraceCoverage = {
  turns: 4_120,
  files_scanned: 212,
  sources: ["Claude Code", "Codex"],
  since: "2026-06-03T09:00:00.000Z",
  scanned_at: "2026-09-07T12:00:00.000Z",
};

const sighting = (over: Partial<RawSighting> = {}): RawSighting => ({
  session_id: "sess-1",
  turn_id: "turn-1",
  at: "2026-09-01T10:00:00.000Z",
  source: "claude-code",
  kind: "prompt",
  cwd: "/Users/dev/repos/acme/api",
  occurrences: 1,
  ...over,
});

const row = (over: Partial<FindingRow> = {}): FindingRow => ({
  finding_id: "f1",
  detector: "credential_in_prompt",
  severity: "critical",
  key_name: "anthropic",
  excerpt: "use [redacted:anthropic] for the deploy",
  occurrences: 1,
  source: "claude-code",
  origin: "transcript",
  session_id: "sess-1",
  turn_id: "turn-1",
  status: "open",
  first_seen_at: "2026-09-01T10:00:00.000Z",
  last_seen_at: "2026-09-01T10:00:00.000Z",
  ...over,
});

const labelOf = (source: string) => (source === "claude-code" ? "Claude Code" : source === "codex" ? "Codex" : source);

describe("normalizeTraceInput — down to the value people actually paste", () => {
  it("strips the wrappers a copied line carries", () => {
    expect(normalizeTraceInput(`export ANTHROPIC_API_KEY="${KEY}"`)).toEqual({ ok: true, value: KEY });
    expect(normalizeTraceInput(`ANTHROPIC_API_KEY=${KEY};`)).toEqual({ ok: true, value: KEY });
    expect(normalizeTraceInput(`Authorization: Bearer ${KEY}`)).toEqual({ ok: true, value: KEY });
    expect(normalizeTraceInput(`  '${KEY}'  `)).toEqual({ ok: true, value: KEY });
    expect(normalizeTraceInput(`"api_key": "${KEY}",`)).toEqual({ ok: true, value: KEY });
  });

  it("leaves a bare value alone, `=` tails included", () => {
    expect(normalizeTraceInput("dGhpcyBpcyBiYXNlNjQ=")).toEqual({ ok: true, value: "dGhpcyBpcyBiYXNlNjQ=" });
  });

  it("refuses what it cannot search for honestly", () => {
    expect(normalizeTraceInput("")).toMatchObject({ ok: false });
    expect(normalizeTraceInput("abc1234")).toMatchObject({ ok: false, error: expect.stringContaining("8 characters") });
    expect(normalizeTraceInput("two words here")).toMatchObject({ ok: false, error: expect.stringContaining("no spaces") });
    expect(normalizeTraceInput("-----BEGIN PRIVATE KEY-----\nMIIE")).toMatchObject({ ok: false });
  });
});

describe("traceShape — what the value is, without keeping it", () => {
  it("names a recognized family and keeps only the tail", () => {
    const shape = traceShape(KEY);
    expect(shape).toMatchObject({ family: "anthropic", label: "Anthropic API key", recognized: true, length: KEY.length });
    expect(shape.tail).toBe(KEY.slice(-4));
    expect(JSON.stringify(shape)).not.toContain(KEY.slice(0, 20));
    expect(traceShape(AWS_KEY)).toMatchObject({ family: "aws", label: "AWS access key" });
  });

  it("a fragment matches no family and shows two characters", () => {
    const fragment = KEY.slice(-12);
    const shape = traceShape(fragment);
    expect(shape.family).toBeUndefined();
    expect(shape.recognized).toBe(false);
    expect(shape.tail).toBe(fragment.slice(-2));
    expect(shape.label).toContain("doesn't recognize");
  });
});

describe("describeSighting — the sentence for where it was", () => {
  it("says what happened in the person's words", () => {
    const home = "/Users/dev";
    expect(describeSighting({ kind: "prompt" })).toBe("In your prompt");
    expect(describeSighting({ kind: "assistant" })).toBe("In the assistant's reply");
    expect(describeSighting({ kind: "tool_call", tool_name: "Write", target: "/Users/dev/repos/acme/api/.env" }, home)).toBe("Written to acme/api/.env");
    expect(describeSighting({ kind: "tool_call", tool_name: "Bash", target: "curl" })).toBe("In a curl command");
    expect(describeSighting({ kind: "tool_call", tool_name: "Bash" })).toBe("In a shell command");
    expect(describeSighting({ kind: "tool_call", tool_name: "mcp__github__create_issue" })).toBe("Sent to MCP server github (create_issue)");
    expect(describeSighting({ kind: "tool_output", tool_name: "Read", target: "/Users/dev/.aws/credentials" }, home)).toBe("Returned by reading ~/.aws/credentials");
    expect(describeSighting({ kind: "tool_output", tool_name: "Bash", target: "cat" })).toBe("Returned by a cat command");
    expect(describeSighting({ kind: "tool_output", tool_name: "mcp__vault__read" })).toBe("Returned by MCP server vault");
    expect(describeSighting({ kind: "tool_output" })).toBe("Returned by a tool");
    expect(describeSighting({ kind: "tool_output", tool_name: "Write", target: "/Users/dev/repos/acme/api/.env" }, home)).toBe("Echoed back after writing acme/api/.env");
  });
});

describe("attachFinding — what the guard did about the same call", () => {
  it("prefers the row anchored to the sighting's turn, and reads its outcome", () => {
    const rows = [row({ enforced: "ask", resolution: "allowed", finding_id: "held" }), row({ turn_id: "other", finding_id: "other" })];
    expect(attachFinding(sighting(), rows, "anthropic")).toEqual({ finding_id: "held", outcome: "held_allowed" });
  });

  it("falls back to a same-family row held within two minutes — a guard row has no turn id", () => {
    const rows = [
      row({ turn_id: undefined, origin: "guard", enforced: "deny", finding_id: "g1", held_at: "2026-09-01T10:01:30.000Z" }),
      row({ turn_id: undefined, origin: "guard", enforced: "deny", finding_id: "far", held_at: "2026-09-01T11:00:00.000Z" }),
      row({ turn_id: undefined, origin: "guard", enforced: "deny", finding_id: "aws", key_name: "aws", held_at: "2026-09-01T10:00:10.000Z" }),
    ];
    expect(attachFinding(sighting(), rows, "anthropic")).toEqual({ finding_id: "g1", outcome: "blocked" });
  });

  it("is observed when nothing saw it, and ranks the strongest outcome first", () => {
    expect(attachFinding(sighting(), [], "anthropic")).toEqual({ outcome: "observed" });
    expect(outcomeOfRow({ enforced: "warn" })).toBe("warned");
    expect(outcomeOfRow({ enforced: "ask", resolution: "timeout" })).toBe("held_denied");
    expect(outcomeOfRow({})).toBe("observed");
    const rows = [row({ finding_id: "obs" }), row({ finding_id: "blk", enforced: "deny" })];
    expect(attachFinding(sighting(), rows, "anthropic").finding_id).toBe("blk");
  });
});

describe("buildTraceReport — the answer, worst fact first", () => {
  const sightings: RawSighting[] = [
    sighting(),
    sighting({ turn_id: "turn-2", at: "2026-09-01T10:00:20.000Z", kind: "tool_call", tool_name: "Write", target: "/Users/dev/repos/acme/api/.env", occurrences: 2 }),
    sighting({ turn_id: "turn-3", at: "2026-09-01T10:00:40.000Z", kind: "tool_call", tool_name: "Bash", target: "curl" }),
    sighting({ session_id: "sess-2", turn_id: "turn-9", at: "2026-08-20T08:00:00.000Z", source: "codex", kind: "tool_output", tool_name: "shell", target: "cat", cwd: "/Users/dev/repos/other" }),
    // A duplicate of the first (the turn store and the transcript both saw it).
    sighting(),
  ];

  const report = buildTraceReport({
    shape: traceShape(KEY),
    sightings,
    findings: [row({ enforced: "ask", resolution: "allowed" }), row({ finding_id: "g", origin: "guard", enforced: "deny", session_id: "sess-3", turn_id: undefined, first_seen_at: "2026-08-01T00:00:00.000Z" })],
    files: [{ path: "/Users/dev/.claude/projects/-Users-dev-repos-acme-api/sess-1.jsonl", source: "claude-code" }],
    coverage,
    labelOf,
    home: "/Users/dev",
  });

  it("counts distinct sightings, sessions and the span", () => {
    expect(report.total).toBe(4);
    expect(report.occurrences).toBe(5);
    expect(report.sessions).toBe(2);
    expect(report.first_at).toBe("2026-08-20T08:00:00.000Z");
    expect(report.last_at).toBe("2026-09-01T10:00:40.000Z");
  });

  it("names the provider each rail reached, what was written and what ran", () => {
    expect(report.providers).toEqual([
      { source: "claude-code", label: "Claude Code", provider: "Anthropic", sessions: 1 },
      { source: "codex", label: "Codex", provider: "OpenAI", sessions: 1 },
    ]);
    expect(report.writes).toEqual([{ path: "/Users/dev/repos/acme/api/.env", tool: "Write", at: "2026-09-01T10:00:20.000Z", session_id: "sess-1", turn_id: "turn-2" }]);
    expect(report.commands).toBe(1);
    expect(report.rotate).toEqual({ provider: "Anthropic", url: "https://console.anthropic.com/settings/keys" });
  });

  it("tallies what the guard did, per sighting and for the family", () => {
    expect(report.outcomes).toEqual({ blocked: 0, held_denied: 0, held_allowed: 1, warned: 0, observed: 3 });
    expect(report.blocked_family).toBe(1);
    const prompt = report.places.flatMap((p) => p.sightings).find((s) => s.kind === "prompt");
    expect(prompt).toMatchObject({ how: "In your prompt", outcome: "held_allowed", finding_id: "f1" });
  });

  it("groups by the project a call ran in, newest place first", () => {
    expect(report.places.map((p) => p.label)).toEqual(["acme/api", "repos/other"]);
    expect(report.places[0]!.sightings.map((s) => s.how)).toEqual(["In a curl command", "Written to acme/api/.env", "In your prompt"]);
  });

  it("never carries the value — not in the report, not on the clipboard, not to the assistant", () => {
    const serialized = JSON.stringify(report);
    expect(serialized).not.toContain(KEY);
    expect(serialized).not.toContain(KEY.slice(0, 24));
    expect(report.markdown).toContain(KEY.slice(-4));
    expect(report.markdown).toContain("Found in 4 places across 2 sessions");
    expect(report.markdown).toContain("Written to disk by an agent: acme/api/.env");
    expect(report.markdown).toContain("Rotate at Anthropic");
    const context = traceContext(report);
    expect(context.kind).toBe("trace");
    expect(context.text).not.toContain(KEY);
    expect(context.text).toContain("Anthropic via Claude Code");
    expect(context.text).toContain("Written to disk: /Users/dev/repos/acme/api/.env");
    expect(traceContext(undefined).text).toContain("No secret has been traced");
  });

  it("says what a zero covers", () => {
    const none = buildTraceReport({ shape: traceShape(KEY.slice(-12)), sightings: [], findings: [], files: [], coverage, labelOf });
    expect(none.total).toBe(0);
    expect(none.places).toEqual([]);
    expect(none.rotate).toBeUndefined();
    expect(none.markdown).toContain("Not found in anything Doorman has read: 4120 turns and 212 transcript files from Claude Code, Codex, back to 2026-06-03");
    expect(none.markdown).toContain("Redaction does not recognize this shape");
  });
});

describe("literal search helpers", () => {
  it("counts non-overlapping occurrences", () => {
    expect(countOccurrences(`${KEY} and ${KEY}`, KEY)).toBe(2);
    expect(countOccurrences("aaaa", "aa")).toBe(2);
    expect(countOccurrences("abc", "")).toBe(0);
  });

  it("knows the JSON-escaped forms a transcript line can hold", () => {
    expect(literalForms(KEY)).toEqual([KEY]);
    expect(literalForms('a"b/c')).toEqual(['a"b/c', 'a\\"b/c', 'a\\"b\\/c']);
  });
});
