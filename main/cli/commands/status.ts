import { guardHostStates } from "../../enforcement.js";
import { ALL_DETECTORS, defaultInjectionClassifierConfig, levelOfModes } from "../../guard/policy.js";
import { radarFeedRows, radarRows } from "../../lib/app-views.js";
import { runtimePresent } from "../../lib/injection-classifier.js";
import { summarizeFindings, summarizeRuleStats, type WindowStats } from "../../lib/findings.js";
import { injectionModelManifest, modelStatus } from "../../lib/model-assets.js";
import { hiddenConfidenceBands } from "../../state.js";
import { markBeside } from "../art.js";
import { modelPlan, modelsRoot, runtimeDir } from "../classifier.js";
import type { CliCommand } from "../command.js";
import { dockerSandbox, processLabel, sandboxWatchCommand } from "../docker-sandbox.js";
import { plural, type Tone, type Ui } from "../ui.js";
import { SEVERITIES, severityLine, type Severity } from "./data-shared.js";
import { runningModel } from "./model.js";
import { LEVEL_NAMES, tilde } from "./policy.js";
import { cachedUpdateStatus } from "../update-check.js";

/** The worst-first shade and colour of each severity in the stacked bar:
 * the shades keep critical and high apart where the colour is the same. */
const SEVERITY_SHADE: Record<Severity, readonly [shade: number, tone: Tone]> = {
  critical: [4, "error"],
  high: [3, "error"],
  medium: [2, "warn"],
  low: [1, "off"],
};

/** One bar `cells` wide split by severity, worst first: every severity with
 * an exposure gets a cell, the rest go by share (largest remainder). */
function severityBar(ui: Ui, counts: Record<Severity, number>, cells: number): string {
  const present = SEVERITIES.filter((k) => counts[k] > 0);
  const total = present.reduce((a, k) => a + counts[k], 0);
  const spare = cells - present.length;
  const exact = present.map((k) => (counts[k] / total) * spare);
  const width = exact.map((e) => 1 + Math.floor(e));
  let left = cells - width.reduce((a, w) => a + w, 0);
  for (const i of present.map((_, i) => i).sort((a, b) => (exact[b]! % 1) - (exact[a]! % 1))) {
    if (left-- <= 0) break;
    width[i] = width[i]! + 1;
  }
  return present.map((k, i) => ui.paint(SEVERITY_SHADE[k][1], ui.glyphs.heat[SEVERITY_SHADE[k][0]]!.repeat(width[i]!))).join("");
}

export const statusCommand: CliCommand = {
  name: "status",
  summary: "The dashboard: guard, agents, model, what needs review, and what to do next",
  options: { scan: { type: "boolean", default: false } },
  flags: [["--scan", "read new transcripts first (otherwise the store as last saved)"]],
  examples: [
    ["doorman status", "where things stand"],
    ["doorman status --scan", "read new transcripts, then show it"],
    ["doorman status --json", "the same as JSON, for scripts"],
  ],
  async run(ctx, args) {
    const prefs = ctx.prefs();
    const policy = ctx.policy();
    const running = ctx.running();
    const hosts = guardHostStates(ctx.io.env).filter((h) => h.present);
    const guarded = [...new Set(hosts.filter((h) => h.installed).map((h) => h.host.label))];
    const unguarded = [...new Set(hosts.filter((h) => !h.installed).map((h) => h.host.label))].filter((l) => !guarded.includes(l));
    const plan = modelPlan(ctx.dataDir, policy, ctx.io.env);
    const model = modelStatus(modelsRoot(ctx.dataDir), injectionModelManifest(plan.effective));
    const enabled = (policy.injection_classifier ?? defaultInjectionClassifierConfig()).enabled;
    const ui = ctx.ui;
    const s = ctx.style;
    const runtime = runtimePresent(runtimeDir());
    const runs = runningModel(ctx, plan, enabled, runtime, s);
    const handle = await ctx.openEngine({ scan: args.values.scan === true });
    let summary;
    // Text only: the Radar's 14-day spark (rule_stats[14].daily) and the
    // count behind its Reviewed tab.
    let recent: WindowStats | undefined;
    let reviewed = 0;
    try {
      const rows = handle.engine.shownFindings();
      const hiddenBands = hiddenConfidenceBands(prefs);
      summary = summarizeFindings(rows, { hide_confidence: hiddenBands });
      if (ui.decorate && !ctx.json) {
        recent = summarizeRuleStats(rows, 14, new Date(ctx.io.now()));
        if (summary.open_exposures === 0) {
          const feed = radarFeedRows(radarRows(rows, ctx.io.home), { hiddenBands, showFalsePositives: prefs.show_false_positives === true });
          reviewed = new Set(feed.filter((r) => r.status !== "open").map((r) => r.exposure_key)).size;
        }
      }
    } finally {
      handle.close();
    }
    const level = levelOfModes(policy.modes) ?? "custom";
    const levelName = level === "custom" ? "custom" : LEVEL_NAMES[level];
    // From the last daily check; status itself never waits on the network.
    const update = cachedUpdateStatus(ctx, ctx.io.packageName ?? "@pinata/doorman", ctx.io.version);
    const sandbox = dockerSandbox(ctx.io.env);
    const data = {
      cli: { version: ctx.io.version, ...(update.latest !== undefined ? { latest: update.latest } : {}), update_available: update.update_available },
      data_dir: ctx.dataDir,
      running: running ?? null,
      guard: { wanted: prefs.guard_wanted, installed: guarded, not_installed: unguarded },
      security_level: level,
      injection_model: {
        selected: plan.selected,
        effective: plan.effective,
        installed: model.present,
        active: runs.active,
        downloading: runs.download.status === "running",
        ...(plan.fallback ? { fallback: plan.fallback } : {}),
      },
      exposures: { open: summary.open_exposures, by_severity: summary.by_severity_exposures },
      ...(sandbox ? { sandbox: { name: sandbox.name, answer_command: sandboxWatchCommand(sandbox) } } : {}),
    };

    const sev = summary.by_severity_exposures;
    const answerer = running
      ? running.stdio && sandbox
        ? "doorman sbx watch on your computer"
        : `${running.version?.startsWith("cli-") ? "doorman watch running" : "running"}${processLabel(ctx.io.env, running.pid)}`
      : undefined;
    const agents = [...guarded, ...unguarded];
    const guardWord =
      guarded.length === 0
        ? ui.mark("warn", s.warn(agents.length === 0 ? "no supported agent here" : "off"))
        : unguarded.length > 0
          ? ui.mark("warn", s.warn(`on in ${guarded.length} of ${agents.length} agents`))
          : ui.mark("ok", s.ok("on"));
    // Every agent here; the ones without the hook say so once some have it.
    const agentWords = agents.map((label) =>
      guarded.includes(label) ? ui.mark("ok", label) : ui.mark("warn", guarded.length > 0 ? `${label} ${s.dim("(hook missing)")}` : label),
    );
    const severities = SEVERITIES.map((k) => {
      const words = `${k} ${sev[k]}`;
      if (sev[k] === 0) return s.dim(words);
      return k === "critical" || k === "high" ? s.error(words) : k === "medium" ? s.warn(words) : words;
    });
    const open = summary.open_exposures;
    const exposures =
      open === 0
        ? ui.mark("ok", s.ok("none to review"))
        : ui.mark(sev.critical + sev.high > 0 ? "error" : "warn", ui.decorate ? `${open} to review` : `${open} to review  ${severityLine(sev)}`);
    const cli = update.update_available
      ? ui.mark("warn", `${ctx.io.version}${s.warn(`  (${update.latest} available: doorman update)`)}`)
      : ctx.io.version;

    const title = ui.section("Doorman", [ui.decorate ? ctx.io.version : ctx.dataDir, sandbox ? `in Docker Sandbox ${sandbox.name}` : ""].filter(Boolean).join("  "));
    const dot = ui.glyphs.dot;
    // The app's protection badge (renderer protectionState): off without a
    // hook, watch only while no rule asks or blocks (tray enforcingGlance).
    const acting =
      ALL_DETECTORS.some((id) => policy.modes[id] === "ask" || policy.modes[id] === "block") ||
      (policy.custom_rules ?? []).some((r) => r.enabled !== false && !r.after && (r.mode === "ask" || r.mode === "block"));
    const [badgeTone, badge]: [Tone, string] =
      guarded.length === 0
        ? ["warn", `${dot.off} GUARD OFF`]
        : !acting
          ? ["info", `${dot.on} WATCH ONLY`]
          : unguarded.length > 0
            ? ["warn", `${dot.on} PARTLY PROTECTED`]
            : ["ok", `${dot.on} PROTECTED`];
    const header = ui.decorate
      ? markBeside(
          ui,
          [
            title,
            ui.list([s.bold(ui.paint(badgeTone, badge)), level === "custom" ? "custom rules" : `${levelName} level`]),
            agents.length > 0
              ? agents.map((label) => (guarded.includes(label) ? `${ui.paint("ok", dot.on)} ${label}` : `${ui.paint("warn", dot.off)} ${label}`)).join("  ")
              : s.dim("no supported agent here"),
          ],
          60,
        )
      : [title];
    // Nothing open: the mark and what was reviewed, in place of the count.
    const allClear = ui.decorate && open === 0;

    // One key column for the whole dashboard.
    const keyWidth = "exposures".length;
    const text = [
      ...header,
      "",
      ui.section("Guard"),
      ...ui.kv(
        [
          ["guard", guardWord],
          agents.length > 0 && ["agents", ui.list(agentWords)],
          sandbox
            ? ["answers", answerer ? ui.mark("ok", s.ok(answerer)) : ui.mark("warn", ui.prose(`nobody: on the host, run \`${sandboxWatchCommand(sandbox)}\``))]
            : ["app", answerer ? ui.mark("ok", s.ok(answerer)) : s.dim("not running")],
          ["level", levelName],
        ],
        { keyWidth },
      ),
      "",
      ui.section("Review"),
      ...(allClear
        ? markBeside(ui, [ui.mark("ok", s.bold(s.ok("All clear"))), s.dim(ui.list(["none to review", ...(reviewed > 0 ? [`${plural(reviewed, "exposure")} reviewed`] : [])]))], 40, 1).map(
            (l) => `  ${l}`,
          )
        : []),
      ...ui.kv(
        [
          !allClear && ["exposures", exposures],
          ui.decorate && open > 0 && ["severity", `${severityBar(ui, sev, 12)}  ${ui.list(severities)}`],
          recent !== undefined && ["14 days", `${ui.spark(recent.daily.map((d) => d.total), "error")}  ${s.dim(plural(recent.new_exposures, "new exposure"))}`],
          ["model", ui.mark(runs.active ? "ok" : "warn", runs.text)],
        ],
        { keyWidth },
      ),
      "",
      ui.section("CLI"),
      ...ui.kv(
        [
          ["cli", cli],
          ["data", ui.decorate ? tilde(ctx.dataDir, ctx.io.home) : ctx.dataDir],
        ],
        { keyWidth },
      ),
    ];

    // The one next thing to do, most important first.
    const answerHint = sandbox ? `on your computer, run \`${sandboxWatchCommand(sandbox)}\`` : "open Doorman or run `doorman watch`";
    let next: string | undefined;
    if (hosts.length === 0) next = "No supported agent found here. `doorman guard --all` lists the ones Doorman supports.";
    else if (guarded.length === 0) next = "Turn the guard on: `doorman guard install`.";
    else if (summary.open_exposures > 0) next = `Review ${plural(summary.open_exposures, "exposure")}: \`doorman findings\`.`;
    else if (unguarded.length > 0) next = `Guard ${unguarded.join(", ")} too: \`doorman guard install\`.`;
    else if (!running && policy.confirm.interactive) next = `To answer held calls, ${answerHint}.`;
    else if (enabled && runtime && !runs.active && runs.download.status !== "running") next = "Fetch the injection classifier: `doorman model download`.";
    else if (update.update_available) next = `Update the CLI to ${update.latest}: \`doorman update\`.`;
    text.push("", next ? ui.next(next) : ui.mark("ok", `All set. ${ui.prose("`doorman scan` reads new transcripts.")}`));
    return { data, text };
  },
};
