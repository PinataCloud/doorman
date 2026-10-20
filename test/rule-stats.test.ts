import { describe, expect, it } from "vitest";
import {
  localDetectorLabel,
  mergeFinding,
  mintFindingRow,
  summarizeRuleStats,
  type FindingRow,
} from "../main/lib/findings.js";
import { applicableIgnoreRules, cwdWithinPrefix, parseIgnoreRule, parsePolicy } from "../main/guard/policy.js";
import { scopedIgnoreRulesFor } from "../main/lib/approvals.js";
import { buildSecurityReport, renderSecurityReportMarkdown } from "../main/lib/report.js";
import { securityDigestBody } from "../main/notifications.js";
import { defaultPolicy } from "../main/guard/policy.js";

/**
 * Decision telemetry (plan A1), scoped allows (A2), the per-rule counters the
 * Analytics screen reads (A3), the report (E2) and the digest wording (E1).
 */

const NOW = new Date("2026-09-02T12:00:00.000Z");
const at = (daysAgo: number) => new Date(NOW.getTime() - daysAgo * 86_400_000).toISOString();

const row = (over: Partial<FindingRow>): FindingRow => ({
  finding_id: Math.random().toString(36).slice(2),
  detector: "destructive_command",
  severity: "high",
  excerpt: "rm -rf",
  occurrences: 1,
  source: "claude-code",
  origin: "guard",
  status: "open",
  first_seen_at: at(1),
  last_seen_at: at(1),
  ...over,
});

describe("decision telemetry on the ledger", () => {
  it("rides the resolution line onto the row and survives a later plain re-observation", () => {
    const detected = mintFindingRow(
      { detector: "destructive_command", severity: "high", excerpt: "rm -rf", occurrences: 1 },
      { source: "claude-code", origin: "guard", session_id: "s", at: at(1), enforced: "ask", cwd: "/Users/x/repo" },
    );
    const resolved = mintFindingRow(
      { detector: "destructive_command", severity: "high", excerpt: "rm -rf", occurrences: 1 },
      {
        source: "claude-code",
        origin: "guard",
        session_id: "s",
        at: at(1),
        enforced: "ask",
        resolution: "allowed",
        held_at: at(1),
        decided_at: at(1),
        decided_via: "panel",
        hold_ms: 4200,
        allow_scope: "project",
      },
    );
    const merged = mergeFinding(detected, resolved);
    expect(merged).toMatchObject({ decided_via: "panel", hold_ms: 4200, allow_scope: "project", resolution: "allowed", cwd: "/Users/x/repo" });
    const again = mergeFinding(merged, { ...detected, enforced: undefined });
    expect(again.decided_via).toBe("panel");
    expect(again.hold_ms).toBe(4200);
  });
});

describe("summarizeRuleStats", () => {
  const rows = [
    row({ detector: "destructive_command", session_id: "a", enforced: "ask", resolution: "allowed", hold_ms: 3000, decided_via: "panel" }),
    row({ detector: "destructive_command", session_id: "b", enforced: "ask", resolution: "denied", hold_ms: 9000, decided_via: "window" }),
    row({ detector: "destructive_command", session_id: "b", enforced: "deny" }),
    row({ detector: "env_dump", session_id: "a", enforced: "warn", severity: "medium" }),
    row({ detector: "env_dump", session_id: "c" }),
    row({ detector: "custom:deploy", detector_label: "Production deploy", session_id: "c", resolution: "timeout", enforced: "deny", hold_ms: 60000, decided_via: "timeout" }),
    row({ detector: "dotenv_read", session_id: "old", last_seen_at: at(40), first_seen_at: at(40) }),
  ];

  it("counts rows per rule inside the window with what enforcement did, most-fired first", () => {
    const stats = summarizeRuleStats(rows, 30, NOW);
    expect(stats.total).toBe(6);
    expect(stats.sessions).toBe(3);
    expect(stats.rules.map((r) => r.detector)).toEqual(["destructive_command", "env_dump", "custom:deploy"]);
    const dc = stats.rules[0]!;
    expect(dc).toMatchObject({ fired: 3, sessions: 2, blocked: 1, held: 2, allowed: 1, denied: 1, worst: "high", median_hold_ms: 6000 });
    // THINGS: the three destructive rows share one excerpt and no key → one
    // thing; its daily trend has one bucket lit (all first seen a day ago).
    expect(dc.things).toBe(1);
    expect(dc.daily).toHaveLength(30);
    expect(dc.daily.reduce((n, v) => n + v, 0)).toBe(1);
    expect(stats.rules[1]).toMatchObject({ fired: 2, warned: 1, things: 1, exposures: 1 });
    expect(stats.things).toBe(3);
    expect(stats.new_things).toBe(3);
    // No cwd anywhere → one "unknown" place per rule, so exposures = rules here.
    expect(stats.exposures).toBe(3);
    expect(stats.new_exposures).toBe(3);
    expect(dc.exposures).toBe(1);
    // The day chart is drawn in things by worst outcome: the destructive thing
    // had a blocked row, so it counts as blocked, not three times; the custom
    // rule's hold ran out with no answer, so it counts as denied.
    const lit = stats.daily.filter((d) => d.total > 0);
    expect(lit).toHaveLength(1);
    expect(lit[0]).toMatchObject({ blocked: 1, denied: 1, allowed: 0, warned: 1, observed: 0, total: 3 });
    expect(lit[0]).not.toHaveProperty("held");
    // A custom rule reads its recorded label, even with no policy in hand.
    expect(stats.rules[2]!.label).toBe("Production deploy");
    // Decisions: three held rows carried a duration; the median is the middle one.
    expect(stats.decisions).toBe(3);
    expect(stats.median_hold_ms).toBe(9000);
    expect(stats.decided_via).toMatchObject({ panel: 1, window: 1, timeout: 1, notification: 0, "app-absent": 0 });
    // The 90-day window reaches the old row; the 7-day one is the same as 30 here.
    expect(summarizeRuleStats(rows, 90, NOW).total).toBe(7);
    expect(summarizeRuleStats(rows, 7, NOW).total).toBe(6);
  });

  it("counts the window BEFORE this one over the same two measures, so a delta has two halves", () => {
    // The 30-day window's predecessor is [60d, 30d). Only the dotenv row lives
    // there, and nothing enforced it — so one new exposure, none stopped.
    const stats = summarizeRuleStats(rows, 30, NOW);
    expect(stats.prev).toEqual({ new_exposures: 1, stopped: 0 });
    // Its own window sees it as current business, and the window before THAT
    // is empty — a count of zero, never undefined, so the screen can say "none
    // in the 90 days before" rather than going silent.
    expect(summarizeRuleStats(rows, 90, NOW).prev).toEqual({ new_exposures: 0, stopped: 0 });
  });

  it("counts a blocked exposure in the previous window as stopped", () => {
    const earlier = [
      row({ detector: "secret_egress", session_id: "p", first_seen_at: at(20), last_seen_at: at(20), enforced: "deny" }),
      row({ detector: "env_dump", session_id: "q", first_seen_at: at(20), last_seen_at: at(20) }),
    ];
    // A 14-day window: both rows sit in [28d, 14d), the window before it.
    const stats = summarizeRuleStats(earlier, 14, NOW);
    expect(stats.new_exposures).toBe(0);
    expect(stats.prev).toEqual({ new_exposures: 2, stopped: 1 });
  });

  it("counts the rows a model stood down, per rule and overall — they stay inside Seen", () => {
    const assisted = [
      row({ finding_id: "i1", detector: "injected_instruction", session_id: "s9", last_seen_at: NOW.toISOString(), first_seen_at: NOW.toISOString(), confidence: "medium", assist: { by: "injection_classifier", model: "Llama Prompt Guard 2", verdict: "stood_down", score: 0.04 } }),
      row({ finding_id: "i2", detector: "injected_instruction", session_id: "s9", last_seen_at: NOW.toISOString(), first_seen_at: NOW.toISOString(), assist: { by: "injection_classifier", model: "Llama Prompt Guard 2", verdict: "confirmed", score: 0.97 } }),
      row({ finding_id: "i3", detector: "injected_instruction", session_id: "s9", last_seen_at: NOW.toISOString(), first_seen_at: NOW.toISOString() }),
    ];
    const stats = summarizeRuleStats(assisted, 7, NOW);
    const inj = stats.rules.find((r) => r.detector === "injected_instruction")!;
    expect(inj.fired).toBe(3);
    expect(inj.stood_down).toBe(1);
    expect(stats.stood_down).toBe(1);
    // A window with no model verdicts says zero, not undefined.
    expect(summarizeRuleStats(rows, 30, NOW).stood_down).toBe(0);
    expect(summarizeRuleStats(rows, 30, NOW).rules[0]!.stood_down).toBe(0);
  });

  it("leaves a false positive out of every count and says how many were rejected", () => {
    const judged = [
      ...rows,
      // Same rule, same session as a real row: must not add a sighting, a thing,
      // an exposure or a day — only a rejection under the rule.
      row({ detector: "destructive_command", session_id: "b", status: "false_positive" }),
      // A rule that ONLY fired wrongly in the window: no row in the table at
      // all, but it still counts in the overall rejection number.
      row({ detector: "pii_exposure", session_id: "fp-only", status: "false_positive" }),
    ];
    const stats = summarizeRuleStats(judged, 30, NOW);
    const clean = summarizeRuleStats(rows, 30, NOW);
    expect(stats.total).toBe(clean.total);
    expect(stats.sessions).toBe(clean.sessions);
    expect(stats.things).toBe(clean.things);
    expect(stats.exposures).toBe(clean.exposures);
    expect(stats.new_exposures).toBe(clean.new_exposures);
    expect(stats.daily).toEqual(clean.daily);
    expect(stats.rules.map((r) => r.detector)).toEqual(clean.rules.map((r) => r.detector));
    expect(stats.rules[0]).toMatchObject({ detector: "destructive_command", fired: 3, rejected: 1 });
    expect(stats.rules[1]!.rejected).toBe(0);
    expect(stats.rejected).toBe(2);
    // A window with no verdicts says zero, not undefined.
    expect(clean.rejected).toBe(0);
    // Out of the window, out of the count.
    const old = [row({ detector: "env_dump", status: "false_positive", first_seen_at: at(40), last_seen_at: at(40) })];
    expect(summarizeRuleStats([...rows, ...old], 30, NOW).rejected).toBe(0);
    expect(summarizeRuleStats([...rows, ...old], 90, NOW).rejected).toBe(1);
  });

  it("labels every id, custom or shipped or unknown", () => {
    expect(localDetectorLabel("secret_egress")).toBe("Secret egress over the network");
    expect(localDetectorLabel("guard_tampered")).toBe("Guard entry or bundle altered");
    expect(localDetectorLabel("custom:x", { "custom:x": "X" })).toBe("X");
    expect(localDetectorLabel("custom:x")).toBe("Your rule: x");
    expect(localDetectorLabel("whatever")).toBe("whatever");
  });
});

describe("scoped ignore rules", () => {
  it("apply only under their prefix and before their expiry", () => {
    expect(cwdWithinPrefix("/Users/x/repo/src", "/Users/x/repo")).toBe(true);
    expect(cwdWithinPrefix("/Users/x/repo", "/Users/x/repo/")).toBe(true);
    expect(cwdWithinPrefix("/Users/x/repo-old", "/Users/x/repo")).toBe(false);
    expect(cwdWithinPrefix(undefined, "/Users/x/repo")).toBe(false);
    expect(cwdWithinPrefix(undefined, undefined)).toBe(true);
    const rules = [
      { pattern: "everywhere" },
      { pattern: "here", cwd_prefix: "/Users/x/repo" },
      { pattern: "gone", cwd_prefix: "/Users/x/repo", expires_at: at(1) },
      { pattern: "later", expires_at: at(-1) },
    ];
    expect(applicableIgnoreRules(rules, "/Users/x/repo/pkg", NOW.getTime()).map((r) => r.pattern)).toEqual(["everywhere", "here", "later"]);
    expect(applicableIgnoreRules(rules, "/elsewhere", NOW.getTime()).map((r) => r.pattern)).toEqual(["everywhere", "later"]);
    expect(applicableIgnoreRules(rules, undefined, NOW.getTime()).map((r) => r.pattern)).toEqual(["everywhere", "later"]);
  });

  it("parse with their scope fields and round-trip through policy.json", () => {
    expect(parseIgnoreRule({ pattern: "x", detector: "env_dump", cwd_prefix: " /r ", expires_at: at(-1), origin: "approval", note: "n" })).toEqual({
      pattern: "x",
      detector: "env_dump",
      cwd_prefix: "/r",
      expires_at: at(-1),
      origin: "approval",
      note: "n",
    });
    // An unknown scope drops the RULE, never the scope: widening "ignore x for
    // nope" into "ignore x everywhere" is the one edit an ignore rule must not make.
    expect(parseIgnoreRule({ pattern: "x", detector: "nope", expires_at: "whenever" })).toBeUndefined();
    // Radar-only ids are legitimate scopes even though the guard never raises them.
    expect(parseIgnoreRule({ pattern: "npm", detector: "flow_secret_egress" })).toEqual({ pattern: "npm", detector: "flow_secret_egress" });
    // A hidden rule is not a scope the app knows — the rule drops.
    expect(parseIgnoreRule({ pattern: "npm", detector: "agent_loop" })).toBeUndefined();
    expect(parseIgnoreRule({ pattern: "x", detector: "custom:deploy" })).toEqual({ pattern: "x", detector: "custom:deploy" });
    expect(parseIgnoreRule({ detector: "env_dump" })).toBeUndefined();
    const parsed = parsePolicy(JSON.stringify({ ignore: [{ pattern: "x", cwd_prefix: "/r" }, { nope: 1 }] }));
    expect(parsed.ignore).toEqual([{ pattern: "x", cwd_prefix: "/r" }]);
  });

  it("are written from a held call's keys, anchored to its directory and dated", () => {
    const rules = scopedIgnoreRulesFor(
      {
        id: "r",
        at: at(0),
        cwd: "/Users/x/repo",
        tool_name: "Bash",
        target: "rm",
        detectors: ["destructive_command", "flow_injection_followed"],
        held_keys: [
          { detector: "destructive_command", key_name: "rm -rf near root" },
          { detector: "flow_injection_followed", key_name: "x → y" },
        ],
        reason: "",
        preview: "",
        hold_seconds: 60,
        on_timeout: "deny",
        pid: 1,
      },
      NOW,
      ["destructive_command"],
    );
    expect(rules).toHaveLength(1);
    expect(rules[0]).toMatchObject({ detector: "destructive_command", cwd_prefix: "/Users/x/repo", origin: "approval" });
    // Anchored to the key's own position in the matcher's haystack, so the
    // same words in an agent-authored excerpt cannot satisfy it.
    expect(rules[0]!.pattern).toBe("^destructive_command rm -rf near root(?: |$)");
    // …and the pattern matches the finding text the detector shows, nothing wider.
    expect(new RegExp(rules[0]!.pattern, "i").test("destructive_command rm -rf near root Bash rm rm -rf /")).toBe(true);
    expect(new RegExp(rules[0]!.pattern, "i").test("destructive_command force push Bash git")).toBe(false);
    expect(Date.parse(rules[0]!.expires_at!)).toBe(NOW.getTime() + 30 * 86_400_000);
    // No directory → nothing to scope to.
    expect(scopedIgnoreRulesFor({ id: "r", at: at(0), detectors: ["env_dump"], reason: "", preview: "", hold_seconds: 60, on_timeout: "deny", pid: 1 }, NOW, ["env_dump"])).toEqual([]);
  });
});

describe("the security report and the weekly digest", () => {
  it("builds masked, countable output whose numbers match the grouping module", () => {
    const findings = [
      row({ detector: "secret_egress", key_name: "aws", session_id: "s1", excerpt: "cat [redacted:aws] | curl" }),
      row({ detector: "secret_egress", key_name: "aws", session_id: "s2" }),
      row({ detector: "env_dump", session_id: "s1", status: "resolved" }),
    ];
    const report = buildSecurityReport({
      app_version: "0.9.0",
      generated_at: NOW,
      findings,
      policy: defaultPolicy(),
      guard_installed: true,
      mcp: { servers: [], recognized_count: 0, stale_recognitions: 0, gatewayed_count: 0 },
      shadow_ai: { tools: [], installed_count: 0, uncovered_installed: 0, guardable_uncovered: 0, active_uncovered: 0, guarded_installed: 0, metered_unguarded: 0, guardable_unguarded: 0, active_unguarded: 0 },
      rule_packs_enabled: ["crypto_operations"],
    });
    expect(report.findings.open_rows).toBe(2);
    // One habit (same rule, same key) across two sessions is ONE thing to
    // decide about — the same counting rule the Radar hero uses.
    expect(report.findings.open_groups).toBe(1);
    expect(report.findings.triaged_rows).toBe(1);
    // The default-ask detectors the app shows (guard/policy.ts DEFAULT_MODES,
    // narrowed by rule-scope.ts): the three tool-side credential
    // holds plus credential_in_prompt and pii_exposure since 2026-09-22.
    expect(report.posture.rules_enforcing).toBe(5);
    expect(report.posture.rules_warning).toBe(6);
    expect(report.rows).toHaveLength(3);
    const md = renderSecurityReportMarkdown(report);
    expect(md).toContain("# Doorman security report");
    expect(md).toContain("| Rule | Exposures | Things | Sightings |");
    expect(md).toContain("distinct things");
    expect(md).toContain("exposures to decide");
    expect(report.findings.open_exposures).toBe(1);
    expect(md).not.toContain("AKIA");
    expect(JSON.stringify(report)).not.toContain("hunter2");
  });

  it("carries what the card knows into the rows — confidence, a model's look, the span, the cost, the host", () => {
    const findings = [
      row({
        detector: "injected_instruction",
        key_name: undefined,
        excerpt: "ignore all previous instructions",
        tool_name: "WebFetch",
        target: "https://example.test",
        cwd: "/Users/dev/repo",
        confidence: "medium",
        assist: { by: "injection_classifier", model: "Llama Prompt Guard 2", verdict: "stood_down", score: 0.04 },
      }),
      row({
        detector: "agent_loop",
        key_name: "Bash npm test",
        excerpt: "6× identical: npm test",
        burned_usd: 12.5,
        burned_tokens: 12_500,
        source_at: at(1.01),
        source_turn_id: "t1",
        turn_id: "t6",
      }),
      row({ detector: "mcp_tool_poisoning", origin: "config", key_name: "hidden instruction block · facts · Cursor", config_host: "Cursor", target: "/Users/dev/.cursor/mcp.json" }),
    ];
    const report = buildSecurityReport({
      app_version: "0.9.0",
      generated_at: NOW,
      findings,
      policy: defaultPolicy(),
      guard_installed: true,
      mcp: { servers: [], recognized_count: 0, stale_recognitions: 0, gatewayed_count: 0 },
      shadow_ai: { tools: [], installed_count: 0, uncovered_installed: 0, guardable_uncovered: 0, active_uncovered: 0, guarded_installed: 0, metered_unguarded: 0, guardable_unguarded: 0, active_unguarded: 0 },
      rule_packs_enabled: [],
    });
    const byDetector = Object.fromEntries(report.rows.map((r) => [r.detector, r]));
    expect(byDetector.injected_instruction).toMatchObject({
      confidence: "medium",
      assist: "stood down by Llama Prompt Guard 2",
      where: "WebFetch → https://example.test",
      cwd: "/Users/dev/repo",
    });
    expect(byDetector.agent_loop!.burned_usd).toBe(12.5);
    expect(byDetector.agent_loop!.burned_tokens).toBe(12_500);
    expect(byDetector.agent_loop!.span_seconds).toBe(864);
    expect(byDetector.mcp_tool_poisoning!.config_host).toBe("Cursor");
    // The window totals the loops' burn in both units, so the report can state
    // it once — and the Markdown prints the TOKENS, never the dollar.
    const w30 = report.windows.find((w) => w.days === 30)!;
    expect(w30.burned_usd).toBe(12.5);
    expect(w30.burned_tokens).toBe(12_500);
    expect(w30.rules.find((r) => r.detector === "agent_loop")!.burned_tokens).toBe(12_500);
    expect(w30.rules.find((r) => r.detector === "injected_instruction")!.burned_tokens).toBeUndefined();
    const md = renderSecurityReportMarkdown(report);
    expect(md).toContain("stuck loops burned 12,500 tokens");
    expect(md).toContain("| Where | Excerpt | Notes |");
    expect(md).toContain("medium confidence; stood down by Llama Prompt Guard 2");
    expect(md).toContain("spans 864s; burned 12,500 tokens");
    expect(md).toContain("Cursor config");
    expect(md).not.toContain("$12.50");
  });

  it("says nothing about a burn when no loop row carried one", () => {
    const stats = summarizeRuleStats([row({ detector: "agent_loop", key_name: "Bash x", excerpt: "4× identical: x" })], 30, NOW);
    expect(stats.burned_usd).toBeUndefined();
    expect(stats.burned_tokens).toBeUndefined();
    expect(stats.rules[0]!.burned_usd).toBeUndefined();
    expect(stats.rules[0]!.burned_tokens).toBeUndefined();
  });

  it("says only what happened, and says when nothing did", () => {
    expect(securityDigestBody({ held: 0, denied: 0, blocked: 0, new_rules_fired: [], new_mcp_servers: 0, new_egress_destinations: 0, open_groups: 0, guard_healthy: true })).toBe(
      "A quiet week: nothing held, nothing new.",
    );
    const busy = securityDigestBody({
      held: 3,
      denied: 1,
      blocked: 0,
      new_rules_fired: ["Secret egress", "Deploy"],
      new_mcp_servers: 1,
      new_egress_destinations: 2,
      open_groups: 4,
      guard_healthy: false,
    });
    expect(busy).toContain("3 calls held for you");
    expect(busy).toContain("1 denied");
    expect(busy).not.toContain("blocked");
    expect(busy).toContain("2 rules fired for the first time (Secret egress, Deploy)");
    expect(busy).toContain("1 new MCP server");
    expect(busy).toContain("2 new external destinations");
    expect(busy).toContain("4 exposures still need review");
    expect(busy).toContain("not installed as the app left it");
  });

  it("says a quiet DAY when the digest is the daily one", () => {
    // The security digest can now land daily as well as Monday, and the two
    // are different claims: "a quiet week" on a digest covering one day is a
    // digest that has stopped being true. `days` is what tells them apart, and
    // an absent one still reads as the week for a caller written before it.
    const quiet = { held: 0, denied: 0, blocked: 0, new_rules_fired: [], new_mcp_servers: 0, new_egress_destinations: 0, open_groups: 0, guard_healthy: true };
    expect(securityDigestBody({ ...quiet, days: 1 })).toBe("A quiet day: nothing held, nothing new.");
    expect(securityDigestBody({ ...quiet, days: 7 })).toBe("A quiet week: nothing held, nothing new.");
    expect(securityDigestBody(quiet)).toBe("A quiet week: nothing held, nothing new.");
    // The period only colours the QUIET sentence — the facts read the same
    // either way, so a busy day is not reworded into a busy week.
    const busyDay = securityDigestBody({ ...quiet, days: 1, held: 2 });
    expect(busyDay).toContain("2 calls held for you");
    expect(busyDay).not.toContain("quiet");
  });
});
