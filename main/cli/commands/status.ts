import { guardHostStates } from "../../enforcement.js";
import { defaultInjectionClassifierConfig, levelOfModes } from "../../guard/policy.js";
import { runtimePresent } from "../../lib/injection-classifier.js";
import { summarizeFindings } from "../../lib/findings.js";
import { injectionModelManifest, modelStatus } from "../../lib/model-assets.js";
import { hiddenConfidenceBands } from "../../state.js";
import { modelPlan, modelsRoot, runtimeDir } from "../classifier.js";
import type { CliCommand } from "../command.js";
import { runningModel } from "./model.js";
import { cachedUpdateStatus } from "../update-check.js";

export const statusCommand: CliCommand = {
  name: "status",
  summary: "Where Doorman keeps its data, what it guards, and what needs review",
  options: { scan: { type: "boolean", default: false } },
  details: ["--scan  read new transcripts first (otherwise the store as last saved)"],
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
    const s = ctx.style;
    const runs = runningModel(ctx, plan, enabled, runtimePresent(runtimeDir()), s);
    const handle = await ctx.openEngine({ scan: args.values.scan === true });
    let summary;
    try {
      summary = summarizeFindings(handle.engine.shownFindings(), { hide_confidence: hiddenConfidenceBands(prefs) });
    } finally {
      handle.close();
    }
    const level = levelOfModes(policy.modes) ?? "custom";
    // From the last daily check; status itself never waits on the network.
    const update = cachedUpdateStatus(ctx, ctx.io.packageName ?? "@pinata/doorman", ctx.io.version);
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
    };
    const sev = summary.by_severity_exposures;
    const text = [
      `${s.bold("Doorman")}  ${s.dim(ctx.dataDir)}`,
      `  app        ${running ? s.green(`${running.version?.startsWith("cli-") ? "doorman watch running" : "running"}${running.pid !== undefined ? ` (pid ${running.pid})` : ""}`) : s.dim("not running")}`,
      `  cli        ${ctx.io.version}${update.update_available ? s.yellow(`  (${update.latest} available: doorman update)`) : ""}`,
      `  guard      ${guarded.length > 0 ? s.green(guarded.join(", ")) : s.yellow("not installed")}${unguarded.length > 0 ? s.dim(`  · not guarded: ${unguarded.join(", ")}`) : ""}`,
      `  level      ${level}`,
      `  model      ${runs.text}`,
      `  exposures  ${summary.open_exposures === 0 ? s.green("none to review") : `${summary.open_exposures} to review  ${s.dim(`critical ${sev.critical} · high ${sev.high} · medium ${sev.medium} · low ${sev.low}`)}`}`,
    ];
    return { data, text };
  },
};
