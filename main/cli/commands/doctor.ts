import { DoctorRunner } from "../../doctor.js";
import type { DoctorCheck } from "../../lib/doctor.js";
import type { CliCommand } from "../command.js";
import type { CliContext } from "../context.js";
import { dockerSandbox, sandboxWatchCommand } from "../docker-sandbox.js";
import { CliError } from "../output.js";
import { plural } from "../ui.js";

/**
 * A check as a CLI user acts on it. The shared doctor speaks to the app:
 * its skipped guard checks point at a Settings screen, and the editor
 * companion — on by default — fails until installed and is installed by the
 * automatic repair. From a terminal, that install is asked for by name
 * (`doorman editor install`), so it reads as a warning with that step.
 */
function forCli(check: DoctorCheck): DoctorCheck {
  if ((check.id === "guard.off" || check.id === "vscode.guard_off") && check.status === "skip") {
    return { ...check, detail: "The guard is off: rules only watch; nothing is held or blocked. `doorman guard install` turns it on." };
  }
  if (check.id === "vscode.extension" && check.fix === "install-vscode-extension") {
    const { fix: _fix, auto: _auto, ...rest } = check;
    return {
      ...rest,
      status: "warn",
      manual: "`doorman editor install` installs it; `doorman config set vscode_extension false` stops asking.",
    };
  }
  return check;
}

/** The check's status word, marked: ok / warn / fail / skip, padded to one width. */
function statusText(ctx: CliContext, check: DoctorCheck): string {
  const s = ctx.style;
  if (check.status === "fail") return ctx.ui.mark("error", s.error("fail"));
  if (check.status === "warn") return ctx.ui.mark("warn", s.warn("warn"));
  if (check.status === "skip") return ctx.ui.mark("off", s.dim("skip"));
  return ctx.ui.mark("ok", s.ok("ok  "));
}

/** The repair that clears a check: automatic ones with `--repair auto`, the rest by name. */
function repairCommand(check: DoctorCheck): string | undefined {
  if (!check.fix) return undefined;
  return check.auto ? "doorman doctor --repair auto" : `doorman doctor --repair all --only ${check.id}`;
}

/** What to do about a check that isn't ok: the person's step, or the repair. */
function remedy(ctx: CliContext, check: DoctorCheck): string | undefined {
  if (check.manual) return ctx.style.dim(ctx.ui.prose(check.manual));
  const command = repairCommand(check);
  return command === undefined ? undefined : `${ctx.style.dim("fix:")} ${ctx.ui.code(command)}`;
}

export const doctorCommand: CliCommand = {
  name: "doctor",
  summary: "Check that the guard, MCP server and editor wiring work, and repair what doesn't",
  usage: "[--repair auto|all] [--only <check>]",
  options: { repair: { type: "string" }, only: { type: "string" } },
  flags: [
    ["--repair auto", "apply the lossless repairs (what the app does on its own)"],
    ["--repair all", "also the ones automatic repair skips; with --only, all that check offers, even restoring a backup"],
    ["--only <check>", "report (and repair) one check by id"],
  ],
  notes: [
    "The setup doctor (the app runs the same checks on its own), run once.",
    "The VS Code companion is installed only when asked: `doorman editor install`, or `--repair all --only vscode.extension`.",
    "Exit code 1 when any check still warns or fails after the run (something needs attention).",
  ],
  examples: [
    ["doorman doctor", "check the setup, change nothing"],
    ["doorman doctor --repair auto", "apply the lossless repairs"],
    ["doorman doctor --repair all --only guard.hooks", "every repair one check offers"],
  ],
  async run(ctx, args) {
    const repairArg = args.values.repair;
    if (repairArg !== undefined && repairArg !== "auto" && repairArg !== "all") {
      throw new CliError(`--repair takes auto or all, not "${String(repairArg)}".`, 2, "`doorman doctor --repair auto` applies the lossless repairs.");
    }
    const repair = repairArg ?? "none";
    const only = typeof args.values.only === "string" ? args.values.only : undefined;
    if (repair !== "none") ctx.requireWritable("Repair the setup");
    const sandbox = dockerSandbox(ctx.io.env);
    // The companion is installed by the repair only when that check is named.
    let probeExtension = repair === "none" || only === "vscode.extension";
    const runner = new DoctorRunner({
      userDataDir: ctx.dataDir,
      guardWanted: () => ctx.prefs().guard_wanted,
      mcpWanted: () => ctx.prefs().mcp_answers === true,
      editorExtensionWanted: () => probeExtension && ctx.prefs().vscode_extension === true,
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
    if (!probeExtension) {
      // Repairs done without the companion: report it as it stands, unrepaired.
      probeExtension = true;
      state = await runner.run({ reason: "cli", repair: "none", only, refresh: true });
    }
    if (!state.report) throw new CliError("The doctor couldn't finish.", 1, "`doorman doctor --verbose` shows why.");
    const all = state.report.checks.map(forCli);
    const checks = all.filter((c) => only === undefined || c.id === only);
    const ok = all.filter((c) => c.status === "ok").length;
    const warn = all.filter((c) => c.status === "warn").length;
    const fail = all.filter((c) => c.status === "fail").length;
    const issues = [fail > 0 ? plural(fail, "issue") : "", warn > 0 ? plural(warn, "warning") : ""].filter(Boolean).join(", ");
    const report = { ...state.report, checks: all, ok, warn, fail, headline: issues || "Everything is wired" };
    if (only !== undefined && !report.checks.some((c) => c.id === only)) {
      throw new CliError(`No check "${only}".`, 1, `Checks: ${report.checks.map((c) => c.id).join(", ")}`);
    }
    const s = ctx.style;
    const ui = ctx.ui;
    // Detail lines sit under the title: past the status word, and its glyph when there is one.
    const under = " ".repeat(ui.decorate ? 10 : 8);
    const text = [ui.section(report.headline), ""];
    if (sandbox) {
      text.push(`  ${ui.mark("info", `Docker Sandbox ${s.bold(sandbox.name)}: the app can't run here; held calls are answered from the host with ${ui.code(sandboxWatchCommand(sandbox))}.`)}`, "");
    }
    for (const check of checks) {
      text.push(`  ${statusText(ctx, check)}  ${check.title}  ${s.dim(`[${check.id}]`)}`);
      if (check.status === "warn" || check.status === "fail" || (check.status === "skip" && check.detail !== "")) {
        const width = ui.width === undefined ? undefined : ui.width - under.length;
        for (const line of width === undefined || width < 20 ? [check.detail] : ui.wrap(check.detail, width)) text.push(`${under}${ui.prose(line)}`);
        const step = remedy(ctx, check);
        if (step) text.push(`${under}${step}`);
      }
    }
    if (applied.length + failed.length > 0) {
      text.push("");
      for (const line of applied) text.push(`  ${ui.mark("ok", s.ok("repaired"))}  ${line}`);
      for (const line of failed) text.push(`  ${ui.mark("error", s.error("failed"))}    ${line}`);
    }
    const open = checks.filter((c) => c.status === "warn" || c.status === "fail");
    const needsAttention = open.length > 0;
    const count = (status: DoctorCheck["status"]) => checks.filter((c) => c.status === status).length;
    const tally = [
      count("ok") > 0 ? s.ok(`${count("ok")} ok`) : "",
      count("warn") > 0 ? s.warn(`${count("warn")} warn`) : "",
      count("fail") > 0 ? s.error(`${count("fail")} fail`) : "",
      count("skip") > 0 ? s.dim(`${count("skip")} skipped`) : "",
    ].filter((p) => p !== "");
    const tone = count("fail") > 0 ? "error" : count("warn") > 0 ? "warn" : "ok";
    text.push("", ui.mark(tone, `${plural(checks.length, "check")}: ${tally.join(", ")}.${needsAttention ? ` ${plural(open.length, "needs", "need")} attention.` : ""}`));
    if (needsAttention) {
      // One next step: the automatic repair if it would help, else one check's own repair, else the person's steps.
      const auto = repair === "none" ? open.find((c) => c.fix && c.auto) : undefined;
      const named = open.find((c) => c.fix && !(c.auto && repair !== "none"));
      const command = auto ? repairCommand(auto) : named ? repairCommand(named) : undefined;
      text.push(ui.next(command ? `\`${command}\` repairs what it can.` : "Follow the steps above, then run `doorman doctor` again."));
    }
    return {
      data: {
        report: { ...report, checks },
        // The checks the text counts as needing attention: every warn or fail still open.
        attention: open.map((c) => c.id),
        repairs: { applied, failed },
        ...(sandbox ? { sandbox: { name: sandbox.name, answer_command: sandboxWatchCommand(sandbox) } } : {}),
      },
      text,
      exitCode: needsAttention ? 1 : 0,
    };
  },
};
