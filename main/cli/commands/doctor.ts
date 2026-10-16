import { DoctorRunner, attentionChecks } from "../../doctor.js";
import type { DoctorCheck } from "../../lib/doctor.js";
import type { CliCommand } from "../command.js";
import type { CliContext } from "../context.js";
import { CliError } from "../output.js";

function statusText(ctx: CliContext, check: DoctorCheck): string {
  const s = ctx.style;
  if (check.status === "fail") return s.red("fail");
  if (check.status === "warn") return s.yellow("warn");
  if (check.status === "skip") return s.dim("skip");
  return s.green("ok  ");
}

/** What to do about a check that isn't ok: the person's step, or the repair
 * that clears it (automatic ones with `--repair auto`, the rest by name). */
function remedy(check: DoctorCheck): string | undefined {
  if (check.manual) return check.manual;
  if (!check.fix) return undefined;
  return check.auto ? "fix: doorman doctor --repair auto" : `fix: doorman doctor --repair all --only ${check.id}`;
}

export const doctorCommand: CliCommand = {
  name: "doctor",
  summary: "Check that the guard, MCP server and editor wiring work, and repair what doesn't",
  usage: "[--repair auto|all] [--only <check>]",
  options: { repair: { type: "string" }, only: { type: "string" } },
  details: [
    "The setup doctor from the app's Integrations screen, run once.",
    "--repair auto  apply the lossless repairs (what the app does on its own)",
    "--repair all   also the ones automatic repair skips; with --only, everything that check offers,",
    "               including replacing an unreadable document with its backup",
    "--only <check> report (and repair) one check by id",
    "",
    "Exit code 1 when any check still warns or fails after the run (something needs attention).",
  ],
  async run(ctx, args) {
    const repairArg = args.values.repair;
    if (repairArg !== undefined && repairArg !== "auto" && repairArg !== "all") throw new CliError("--repair takes auto or all.", 2);
    const repair = repairArg ?? "none";
    const only = typeof args.values.only === "string" ? args.values.only : undefined;
    if (repair !== "none") ctx.requireWritable("Repair the setup");
    const runner = new DoctorRunner({
      userDataDir: ctx.dataDir,
      guardWanted: () => ctx.prefs().guard_wanted,
      mcpWanted: () => ctx.prefs().mcp_answers === true,
      editorExtensionWanted: () => ctx.prefs().vscode_extension === true,
      appVersion: ctx.io.version,
      policy: () => ctx.policy(),
      onState: () => {},
      log: (line) => ctx.log(`doctor: ${line}`),
      now: () => ctx.io.now(),
    });
    // A manual run: fresh probes, and through even where the app's automatic
    // repair would stand down. One repair can uncover the next (a document
    // made readable, then the guard entry it lacked); the app catches that on
    // the file change, a one-shot run goes round again, a few times at most.
    const applied: string[] = [];
    const failed: string[] = [];
    let state = await runner.run({ reason: "cli", repair, only, refresh: true, force: repair !== "none" });
    let repaired = state.last_repair;
    for (let pass = 1; repaired !== undefined; pass += 1) {
      applied.push(...repaired.applied);
      failed.push(...repaired.failed);
      const open = state.report?.checks.some((c) => c.status === "warn" || c.status === "fail") ?? false;
      if (repaired.applied.length === 0 || repaired.failed.length > 0 || !open || pass >= 3) break;
      state = await runner.run({ reason: "cli", repair, only, refresh: true, force: true });
      // The state keeps the last outcome; a pass that repaired nothing leaves it as it was.
      repaired = state.last_repair === repaired ? undefined : state.last_repair;
    }
    const report = state.report;
    if (!report) throw new CliError("The doctor couldn't finish; run with --verbose to see why.");
    const checks = report.checks.filter((c) => only === undefined || c.id === only);
    if (only !== undefined && !report.checks.some((c) => c.id === only)) {
      throw new CliError(`No check "${only}". Checks: ${report.checks.map((c) => c.id).join(", ")}`);
    }
    const s = ctx.style;
    const text = [s.bold(report.headline), ""];
    for (const check of checks) {
      text.push(`  ${statusText(ctx, check)}  ${check.title}  ${s.dim(`[${check.id}]`)}`);
      if (check.status === "warn" || check.status === "fail" || (check.status === "skip" && check.detail !== "")) {
        text.push(`        ${check.detail}`);
        const step = remedy(check);
        if (step) text.push(`        ${s.dim(step)}`);
      }
    }
    if (applied.length + failed.length > 0) {
      text.push("");
      for (const line of applied) text.push(`  ${s.green("repaired")}  ${line}`);
      for (const line of failed) text.push(`  ${s.red("failed")}    ${line}`);
    }
    const needsAttention = checks.some((c) => c.status === "warn" || c.status === "fail");
    return {
      data: {
        report: { ...report, checks },
        attention: attentionChecks(report, state.paused).map((c) => c.id),
        repairs: { applied, failed },
      },
      text,
      exitCode: needsAttention ? 1 : 0,
    };
  },
};
