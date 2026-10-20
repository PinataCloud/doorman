import { describe, expect, it } from "vitest";
import {
  annotateExposure,
  createPlaceResolver,
  exposureKey,
  flowSink,
  mcpServerOf,
  shortPath,
} from "../main/lib/exposures.js";
import { countExposures, summarizeFindings, summarizeRuleStats, type FindingRow } from "../main/lib/findings.js";
import { exposureGroups, radarFeedRows, radarRows } from "../main/lib/app-views.js";

/**
 * Exposures — the layer above things. What these pin: the place each family of
 * rule folds to, the project-root folding, the fallback chain for rows with no
 * cwd, and that the headline counts (summary, rule stats) are exposures while
 * things and sightings survive underneath.
 */

const NOW = new Date("2026-09-02T12:00:00.000Z");
const at = (daysAgo: number) => new Date(NOW.getTime() - daysAgo * 86_400_000).toISOString();

const row = (over: Partial<FindingRow>): FindingRow => ({
  finding_id: Math.random().toString(36).slice(2),
  detector: "hardcoded_credential",
  severity: "high",
  excerpt: "const KEY = [redacted]",
  occurrences: 1,
  source: "claude-code",
  origin: "transcript",
  status: "open",
  first_seen_at: at(1),
  last_seen_at: at(1),
  ...over,
});

describe("places", () => {
  it("folds a command's cwd to the outermost known project root", () => {
    const rows = [
      row({ cwd: "/Users/x/repos/acme", key_name: "AWS_SECRET", target: "/Users/x/repos/acme/a.ts" }),
      row({ cwd: "/Users/x/repos/acme/desktop", key_name: "OPENAI_API_KEY", target: "/Users/x/repos/acme/desktop/b.ts" }),
      row({ cwd: "/Users/x/repos/other", key_name: "TOKEN" }),
    ];
    const places = createPlaceResolver(rows, { home: "/Users/x" });
    expect(places.placeOf(rows[0]!)).toEqual({ kind: "project", label: "repos/acme", key: "project:/Users/x/repos/acme" });
    // The subdirectory is the SAME project.
    expect(places.placeOf(rows[1]!).key).toBe("project:/Users/x/repos/acme");
    expect(places.placeOf(rows[2]!).label).toBe("repos/other");
    // Sixty-seven names in one repo: two exposures here, not three things.
    expect(countExposures(rows, rows).count).toBe(2);
  });

  it("projects a cwd-less file write onto a known root, else its directory", () => {
    const known = row({ cwd: "/Users/x/repos/acme" });
    const places = createPlaceResolver([known]);
    expect(places.placeOf(row({ target: "/Users/x/repos/acme/src/deep/file.ts" })).key).toBe("project:/Users/x/repos/acme");
    expect(places.placeOf(row({ target: "/private/tmp/scratch/leak.cjs" })).key).toBe("project:/private/tmp/scratch");
    expect(places.placeOf(row({ target: "grep" })).kind).toBe("unknown");
  });

  it("uses the sink for flow rules, the host for egress, the server for MCP, the tool for injection", () => {
    const places = createPlaceResolver([]);
    expect(places.placeOf(row({ detector: "flow_secret_egress", key_name: ".env file → curl", tool_name: "Bash" }))).toEqual({
      kind: "sink",
      label: "→ curl",
      key: "sink:curl",
    });
    expect(places.placeOf(row({ detector: "flow_secret_egress", key_name: "aws credential in tool output → curl" })).key).toBe("sink:curl");
    expect(places.placeOf(row({ detector: "egress_new_destination", key_name: "Pastebin.com" }))).toEqual({
      kind: "destination",
      label: "pastebin.com",
      key: "destination:pastebin.com",
    });
    expect(places.placeOf(row({ detector: "mcp_tool_poisoning", key_name: "hidden instruction · github" })).label).toBe("github");
    // A config row from another app carries the app as a THIRD part; the
    // server is still the second — the card used to say "server Cursor".
    expect(places.placeOf(row({ detector: "mcp_tool_poisoning", key_name: "hidden instruction · facts · Cursor" })).label).toBe("facts");
    expect(places.placeOf(row({ detector: "mcp_tool_changed", key_name: "slack/send_message · v2" })).label).toBe("slack");
    expect(places.placeOf(row({ detector: "unknown_mcp_server", key_name: "weird" })).key).toBe("server:weird");
    expect(places.placeOf(row({ detector: "injected_instruction", tool_name: "WebFetch", key_name: "instruction override" }))).toEqual({
      kind: "channel",
      label: "via WebFetch",
      key: "channel:webfetch",
    });
    // The escalation flow is a channel too (where the injection came in), not a sink.
    expect(places.placeOf(row({ detector: "flow_injection_followed", tool_name: "Bash", key_name: "injected → shell execution" })).kind).toBe("channel");
  });

  it("has small pure helpers with honest edges", () => {
    expect(shortPath("/Users/x/repos/a/b", "/Users/x")).toBe("a/b");
    expect(shortPath("/Users/x", "/Users/x")).toBe("~");
    expect(shortPath("/srv")).toBe("srv");
    expect(flowSink("a → b → curl", "Bash")).toBe("curl");
    expect(flowSink("no arrow", "Bash")).toBe("Bash");
    expect(flowSink(undefined, undefined)).toBe("unknown sink");
    expect(mcpServerOf({ detector: "mcp_permission" as never, target: "slack" })).toBe("slack");
    expect(exposureKey("x", { kind: "project", label: "l", key: "project:/p" })).toContain("project:/p");
  });

  it("annotates a row without touching what it had", () => {
    const r = row({ cwd: "/Users/x/repos/acme", key_name: "K" });
    const a = annotateExposure(r, createPlaceResolver([r], { home: "/Users/x" }));
    expect(a.place).toBe("repos/acme");
    expect(a.place_kind).toBe("project");
    expect(a.exposure_key).toBe(exposureKey("hardcoded_credential", { kind: "project", label: "repos/acme", key: "project:/Users/x/repos/acme" }));
    expect(a.finding_id).toBe(r.finding_id);
  });
});

describe("exposure counts on the headline surfaces", () => {
  const rows = [
    row({ cwd: "/r/a", key_name: "A", session_id: "s1" }),
    row({ cwd: "/r/a", key_name: "B", session_id: "s2", severity: "critical" }),
    row({ cwd: "/r/a", key_name: "B", session_id: "s3" }),
    row({ cwd: "/r/b", key_name: "A", session_id: "s1", severity: "medium" }),
    row({ detector: "flow_secret_egress", key_name: ".env file → curl", tool_name: "Bash", session_id: "s2" }),
    row({ detector: "flow_secret_egress", key_name: "aws credential in tool output → curl", tool_name: "Bash", session_id: "s3" }),
    row({ cwd: "/r/a", key_name: "C", status: "resolved" }),
  ];

  it("summarizes open exposures at their worst severity, keeping things and rows beneath", () => {
    const s = summarizeFindings(rows);
    expect(s.open).toBe(6);
    // Things know no place: A (in both projects), B, two flow names → 4.
    expect(s.open_groups).toBe(4);
    // Exposures: hardcoded@/r/a, hardcoded@/r/b, flow→curl → 3.
    expect(s.open_exposures).toBe(3);
    expect(s.by_severity_exposures).toEqual({ critical: 1, high: 1, medium: 1, low: 0 });
  });

  it("leaves the confidence bands the Radar folds away out of every open count", () => {
    const leads = [
      ...rows,
      // A lead on a place of its own — a whole exposure that only the band holds.
      row({ cwd: "/r/c", key_name: "L", session_id: "s7", confidence: "low", severity: "critical" }),
      // And one on a place a sure row already opened — hidden, it changes no
      // exposure count, only the row count beneath.
      row({ cwd: "/r/a", key_name: "M", session_id: "s8", confidence: "medium" }),
    ];
    const every = summarizeFindings(leads);
    expect(every.open).toBe(8);
    expect(every.open_exposures).toBe(4);
    expect(every.by_severity_exposures).toEqual({ critical: 2, high: 1, medium: 1, low: 0 });
    expect(every.affected_sessions).toBe(5);
    const folded = summarizeFindings(leads, { hide_confidence: ["medium", "low"] });
    expect(folded.open).toBe(6);
    expect(folded.open_exposures).toBe(3);
    expect(folded.by_severity_exposures).toEqual({ critical: 1, high: 1, medium: 1, low: 0 });
    expect(folded.affected_sessions).toBe(3);
    expect(folded.open_groups).toBe(summarizeFindings(rows).open_groups);
    // One band at a time, and an empty list is no floor at all.
    expect(summarizeFindings(leads, { hide_confidence: ["low"] }).open_exposures).toBe(3);
    expect(summarizeFindings(leads, { hide_confidence: ["medium"] }).open_exposures).toBe(4);
    expect(summarizeFindings(leads, { hide_confidence: [] })).toEqual(every);
    // Absent means high: never folded.
    expect(summarizeFindings(rows, { hide_confidence: ["medium", "low"] })).toEqual(summarizeFindings(rows));
  });

  it("counts the exposures the Radar's cards show, with places learned from every row", () => {
    // Two open rows in subdirectories, and a reviewed and a hidden-band row
    // at the project root: the Radar (radarRows over every row) folds both
    // subdirectories into the root, one card per rule. The hero and
    // `doorman status` (summarizeFindings) used to resolve places over the
    // open, shown rows only and count two.
    const sightings = [
      row({ cwd: "/r/app/web", key_name: "A" }),
      row({ cwd: "/r/app/api", key_name: "B" }),
      row({ cwd: "/r/app", key_name: "C", status: "resolved" }),
      row({ detector: "env_dump", cwd: "/r/app/web", key_name: "environment" }),
      row({ detector: "env_dump", cwd: "/r/app/api", key_name: "environment" }),
      row({ detector: "env_dump", cwd: "/r/app", key_name: "environment", confidence: "low" }),
    ];
    const hide = ["low", "medium"] as const;
    const cards = exposureGroups(radarFeedRows(radarRows(sightings, "/home/x"), { hiddenBands: hide, showFalsePositives: false })).filter(
      (g) => g.bucket === "open",
    );
    expect(cards).toHaveLength(2);
    const summary = summarizeFindings(sightings, { hide_confidence: hide });
    expect(summary.open_exposures).toBe(cards.length);
    expect(summary.by_severity_exposures.high).toBe(2);
  });

  it("windows rule stats in exposures first, things and sightings after", () => {
    const stats = summarizeRuleStats(rows, 14, NOW);
    expect(stats.total).toBe(7);
    expect(stats.exposures).toBe(3);
    expect(stats.new_exposures).toBe(3);
    expect(stats.things).toBe(5); // A, B, C (resolved rows count in a window) + two flow names
    const hc = stats.rules.find((r) => r.detector === "hardcoded_credential")!;
    expect(hc).toMatchObject({ exposures: 2, things: 3, fired: 5, sessions: 3 });
    expect(hc.daily.reduce((n, v) => n + v, 0)).toBe(2);
    const flow = stats.rules.find((r) => r.detector === "flow_secret_egress")!;
    expect(flow).toMatchObject({ exposures: 1, things: 2, fired: 2 });
    // The day chart is exposures: one lit day, three new exposures, all observed.
    const lit = stats.daily.filter((d) => d.total > 0);
    expect(lit).toHaveLength(1);
    expect(lit[0]).toMatchObject({ observed: 3, total: 3 });
    // Most exposures first.
    expect(stats.rules[0]!.detector).toBe("hardcoded_credential");
  });
});
