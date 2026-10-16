/**
 * The local security report — what a developer hands their security team when
 * asked "what does that Mac app actually do, and what has it seen?".
 *
 * Masked excerpts only (they arrive masked from the ledger; nothing here reads
 * a transcript), no consumer identities beyond this machine's, and the counts
 * come from the same grouping module the screen uses, so a number in the
 * report is the number on the Radar. Two renderings of one structure: JSON for
 * a tool, Markdown for a person. Pure — the caller picks the file.
 */

import { RULE_STATS_WINDOWS, countExposures, localDetectorLabel, summarizeRuleStats, type FindingRow } from "./findings.js";
import { countSecurityGroups } from "./security-grouping.js";
import type { GuardIntegrityReport } from "./guard-integrity.js";
import type { McpInventoryState } from "./mcp-inventory.js";
import type { ShadowAiState } from "./shadow-ai.js";
import type { GuardPolicy } from "../guard/policy.js";
import { ALL_DETECTORS } from "../guard/policy.js";
import { customDetectorLabels } from "../guard/custom-rules.js";

export interface ReportInputs {
  app_version: string;
  /** What produced the report, as the reader should see it. Default: the desktop app. */
  generator?: string;
  generated_at: Date;
  findings: readonly FindingRow[];
  policy: GuardPolicy;
  guard_installed: boolean;
  integrity?: GuardIntegrityReport;
  mcp: McpInventoryState;
  shadow_ai: ShadowAiState;
  rule_packs_enabled: readonly string[];
  /** Cap on rows listed in full. */
  max_rows?: number;
}

export interface SecurityReport {
  generated_at: string;
  app_version: string;
  /** "Doorman for Mac", or "the Doorman CLI" when the CLI wrote it. */
  generator: string;
  posture: {
    guard_installed: boolean;
    integrity: GuardIntegrityReport["status"] | "unchecked";
    rules_total: number;
    rules_enforcing: number;
    rules_holding: number;
    rules_blocking: number;
    rules_warning: number;
    custom_rules: number;
    rule_packs: string[];
    hold_seconds: number;
    on_timeout: "deny" | "ask";
    /** What an ask nobody can answer becomes on a host with no native ask. */
    unattended: "deny" | "continue";
    armed_escalation: boolean;
  };
  findings: {
    open_rows: number;
    open_groups: number;
    by_severity_groups: Record<string, number>;
    /** Rule × place (lib/exposures.ts) — the headline unit. */
    open_exposures: number;
    by_severity_exposures: Record<string, number>;
    triaged_rows: number;
  };
  windows: ReturnType<typeof summarizeRuleStats>[];
  mcp: {
    servers: number;
    recognized: number;
    stale_recognitions: number;
    gatewayed: number;
    with_open_poisoning: number;
    changed_descriptions: number;
  };
  shadow_ai: {
    installed: number;
    /** Installed and NOT guarded — metered-only rails included (review F5). */
    outside_guard: number;
    active_outside_guard: number;
    guarded: number;
    metered_only: number;
    tools: string[];
  };
  rows: Array<{
    detector: string;
    label: string;
    severity: string;
    status: string;
    key_name?: string;
    excerpt: string;
    occurrences: number;
    source: string;
    origin: string;
    /** The app whose config file this is, for config-anchored rows. */
    config_host?: string;
    /** tool → target, when the row recorded where it fired. */
    where?: string;
    cwd?: string;
    first_seen_at: string;
    last_seen_at: string;
    enforced?: string;
    resolution?: string;
    /** Absent means high — see FindingRow.confidence. */
    confidence?: string;
    /** A model's second look, as one line: "<verdict> by <model>". */
    assist?: string;
    /** Seconds between a flow's two ends (source → sink). */
    span_seconds?: number;
    /** agent_loop: what the run's turns cost (priced twin, for the record). */
    burned_usd?: number;
    /** agent_loop: input+output tokens the run's turns burned — the figure
     * the Markdown prints. */
    burned_tokens?: number;
  }>;
  rows_omitted: number;
}

export function buildSecurityReport(inputs: ReportInputs): SecurityReport {
  const { policy } = inputs;
  const modes = policy.modes;
  const rules = ALL_DETECTORS;
  const count = (mode: string) => rules.filter((d) => (modes[d] ?? "observe") === mode).length;
  const open = inputs.findings.filter((f) => f.status === "open");
  const grouped = countSecurityGroups(open);
  const exposures = countExposures(open);
  const labels = customDetectorLabels(policy.custom_rules ?? []);
  const max = inputs.max_rows ?? 500;
  const sorted = [...inputs.findings].sort((a, b) => (a.last_seen_at < b.last_seen_at ? 1 : -1));
  return {
    generated_at: inputs.generated_at.toISOString(),
    app_version: inputs.app_version,
    generator: inputs.generator ?? "Doorman for Mac",
    posture: {
      guard_installed: inputs.guard_installed,
      integrity: inputs.integrity?.status ?? "unchecked",
      rules_total: rules.length,
      rules_enforcing: count("ask") + count("block"),
      rules_holding: count("ask"),
      rules_blocking: count("block"),
      rules_warning: count("warn"),
      custom_rules: (policy.custom_rules ?? []).length,
      rule_packs: [...inputs.rule_packs_enabled],
      hold_seconds: policy.confirm.hold_seconds,
      on_timeout: policy.confirm.on_timeout,
      unattended: policy.confirm.unattended,
      armed_escalation: policy.armed_escalation !== false,
    },
    findings: {
      open_rows: open.length,
      open_groups: grouped.groups,
      by_severity_groups: grouped.by_severity,
      open_exposures: exposures.count,
      by_severity_exposures: exposures.by_severity,
      triaged_rows: inputs.findings.length - open.length,
    },
    windows: RULE_STATS_WINDOWS.map((days) => summarizeRuleStats(inputs.findings, days, inputs.generated_at, labels)),
    mcp: {
      servers: inputs.mcp.servers.length,
      recognized: inputs.mcp.recognized_count,
      stale_recognitions: inputs.mcp.stale_recognitions,
      gatewayed: inputs.mcp.gatewayed_count,
      with_open_poisoning: inputs.mcp.servers.filter((s) => s.poison_open > 0).length,
      changed_descriptions: inputs.mcp.servers.reduce((n, s) => n + s.changed_tools, 0),
    },
    shadow_ai: {
      installed: inputs.shadow_ai.installed_count,
      outside_guard: inputs.shadow_ai.installed_count - inputs.shadow_ai.guarded_installed,
      active_outside_guard: inputs.shadow_ai.active_unguarded,
      guarded: inputs.shadow_ai.guarded_installed,
      metered_only: inputs.shadow_ai.metered_unguarded,
      // Say which of the two it is — "covered" hid a metered rail with the
      // guard off behind the same word as a guarded one.
      tools: inputs.shadow_ai.tools
        .filter((t) => t.installed)
        .map((t) => `${t.name}${t.guarded ? (t.captured ? " (metered, guarded)" : " (guarded)") : t.captured ? " (metered only)" : ""}`),
    },
    rows: sorted.slice(0, max).map((f) => ({
      detector: f.detector,
      label: f.detector_label ?? localDetectorLabel(f.detector, labels),
      severity: f.severity,
      status: f.status,
      ...(f.key_name === undefined ? {} : { key_name: f.key_name }),
      excerpt: f.excerpt,
      occurrences: f.occurrences,
      source: f.source,
      origin: f.origin,
      ...(f.config_host === undefined ? {} : { config_host: f.config_host }),
      ...(f.tool_name || f.target ? { where: [f.tool_name, f.target].filter(Boolean).join(" → ") } : {}),
      ...(f.cwd === undefined ? {} : { cwd: f.cwd }),
      first_seen_at: f.first_seen_at,
      last_seen_at: f.last_seen_at,
      ...(f.enforced === undefined ? {} : { enforced: f.enforced }),
      ...(f.resolution === undefined ? {} : { resolution: f.resolution }),
      ...(f.confidence === undefined ? {} : { confidence: f.confidence }),
      ...(f.assist === undefined ? {} : { assist: `${f.assist.verdict.replace("_", " ")} by ${f.assist.model}` }),
      ...(spanSeconds(f) === undefined ? {} : { span_seconds: spanSeconds(f) }),
      ...(typeof f.burned_usd === "number" ? { burned_usd: f.burned_usd } : {}),
      ...(typeof f.burned_tokens === "number" ? { burned_tokens: f.burned_tokens } : {}),
    })),
    rows_omitted: Math.max(0, sorted.length - max),
  };
}

/** Whole seconds between a flow row's two ends; undefined for per-unit rows. */
function spanSeconds(f: FindingRow): number | undefined {
  if (!f.source_at) return undefined;
  const gap = Date.parse(f.last_seen_at) - Date.parse(f.source_at);
  return Number.isFinite(gap) && gap >= 0 ? Math.round(gap / 1000) : undefined;
}

/** Token counts in full, thousands-separated — a report is read, not glanced. */
function tokens(value: number): string {
  return `${Math.round(value).toLocaleString("en-US")} tokens`;
}

function ms(value: number | undefined): string {
  if (value === undefined) return "—";
  if (value < 1000) return `${value} ms`;
  return `${(value / 1000).toFixed(1)} s`;
}

export function renderSecurityReportMarkdown(report: SecurityReport): string {
  const p = report.posture;
  const w30 = report.windows.find((w) => w.days === 30) ?? report.windows[0];
  const lines: string[] = [];
  lines.push(`# Doorman security report`);
  lines.push("");
  lines.push(`Generated ${report.generated_at} by ${report.generator} ${report.app_version}. Every excerpt below was masked on this machine before it was stored; no raw transcript text and no credential value appears in this file.`);
  lines.push("");
  lines.push("## Posture");
  lines.push("");
  lines.push(`- Guard installed: **${p.guard_installed ? "yes" : "no"}** · integrity: **${p.integrity}**`);
  lines.push(`- Rules: ${p.rules_enforcing} of ${p.rules_total} enforce before a tool runs (${p.rules_holding} hold and ask, ${p.rules_blocking} block, ${p.rules_warning} warn)`);
  lines.push(`- Custom rules: ${p.custom_rules} · packs on: ${p.rule_packs.length > 0 ? p.rule_packs.join(", ") : "none"}`);
  lines.push(
    `- Hold window ${p.hold_seconds}s, then ${p.on_timeout === "deny" ? "deny" : "agent fallback"} · app closed → ${p.unattended === "deny" ? "deny" : "agent fallback"} · injection escalation ${p.armed_escalation ? "on" : "off"}`,
  );
  lines.push("");
  lines.push("## Findings");
  lines.push("");
  lines.push(
    `- Open: **${report.findings.open_exposures}** exposures to decide (${report.findings.open_groups} distinct things, ${report.findings.open_rows} rows) · triaged rows: ${report.findings.triaged_rows}`,
  );
  lines.push(
    `- Open exposures by severity: ${Object.entries(report.findings.by_severity_exposures)
      .map(([k, v]) => `${k} ${v}`)
      .join(" · ")}`,
  );
  if (w30) {
    lines.push("");
    lines.push(`## Last ${w30.days} days`);
    lines.push("");
    lines.push(
      `- ${w30.exposures} exposures (${w30.new_exposures} new) over ${w30.things} distinct things and ${w30.total} sightings across ${w30.sessions} sessions · ${w30.decisions} held calls decided · median time to decide ${ms(w30.median_hold_ms)}${
        typeof w30.burned_tokens === "number" ? ` · stuck loops burned ${tokens(w30.burned_tokens)}` : ""
      }${typeof w30.stood_down === "number" && w30.stood_down > 0 ? ` · ${w30.stood_down} rows stood down by a model` : ""}`,
    );
    lines.push(
      `- Decided via: panel ${w30.decided_via.panel} · window ${w30.decided_via.window} · notification ${w30.decided_via.notification} · editor ${w30.decided_via.editor} · terminal ${w30.decided_via.terminal} · timed out ${w30.decided_via.timeout} · app absent ${w30.decided_via["app-absent"]}`,
    );
    lines.push("");
    lines.push("| Rule | Exposures | Things | Sightings | Sessions | Blocked | Held | Allowed | Denied | Warned |");
    lines.push("| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |");
    for (const r of w30.rules) {
      lines.push(`| ${r.label} (\`${r.detector}\`) | ${r.exposures} | ${r.things} | ${r.fired} | ${r.sessions} | ${r.blocked} | ${r.held} | ${r.allowed} | ${r.denied} | ${r.warned} |`);
    }
  }
  lines.push("");
  lines.push("## MCP servers");
  lines.push("");
  lines.push(
    `- ${report.mcp.servers} servers · ${report.mcp.recognized} recognized (${report.mcp.stale_recognitions} stale) · ${report.mcp.gatewayed} routed through the gateway · ${report.mcp.with_open_poisoning} with open poisoning findings · ${report.mcp.changed_descriptions} tool descriptions changed after first sight`,
  );
  lines.push("");
  lines.push("## Other AI on this Mac");
  lines.push("");
  lines.push(
    `- ${report.shadow_ai.installed} installed · ${report.shadow_ai.guarded} guarded · ${report.shadow_ai.metered_only} metered only · ${report.shadow_ai.outside_guard} outside the guard (${report.shadow_ai.active_outside_guard} active)`,
  );
  if (report.shadow_ai.tools.length > 0) lines.push(`- ${report.shadow_ai.tools.join(", ")}`);
  lines.push("");
  lines.push(`## Rows (${report.rows.length}${report.rows_omitted > 0 ? `, ${report.rows_omitted} older omitted` : ""})`);
  lines.push("");
  lines.push("| Last seen | Severity | Rule | Status | Outcome | Key | Where | Excerpt | Notes |");
  lines.push("| --- | --- | --- | --- | --- | --- | --- | --- | --- |");
  const cell = (s: string | undefined) => (s ?? "").replace(/\|/g, "\\|").replace(/\n/g, " ");
  for (const r of report.rows) {
    const outcome = r.resolution ?? r.enforced ?? "observed";
    // What the card knows and the table used to drop: the confidence band, a
    // model's second look, the flow's span, a loop's burn, the config's app.
    const notes = [
      r.confidence && r.confidence !== "high" ? `${r.confidence} confidence` : undefined,
      r.assist,
      r.span_seconds !== undefined ? `spans ${r.span_seconds}s` : undefined,
      r.burned_tokens !== undefined ? `burned ${tokens(r.burned_tokens)}` : undefined,
      r.config_host ? `${r.config_host} config` : undefined,
    ].filter(Boolean);
    lines.push(
      `| ${r.last_seen_at.slice(0, 16).replace("T", " ")} | ${r.severity} | ${cell(r.label)} | ${r.status} | ${outcome} | ${cell(r.key_name)} | ${cell(r.where)} | ${cell(r.excerpt)} | ${cell(notes.join("; "))} |`,
    );
  }
  lines.push("");
  return lines.join("\n");
}
