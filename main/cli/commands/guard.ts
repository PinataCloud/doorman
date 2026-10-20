import { existsSync } from "node:fs";
import { join } from "node:path";
import { checkGuardIntegrity, checkGuardRuntime, guardHostStates, installGuard, uninstallGuard } from "../../enforcement.js";
import type { UnattendedPolicy } from "../../guard/policy.js";
import { describeIntegrity } from "../../lib/guard-integrity.js";
import type { CliCommand } from "../command.js";
import type { CliContext } from "../context.js";
import { dockerSandbox, processLabel, sandboxWatchCommand, type DockerSandbox } from "../docker-sandbox.js";
import { CliError, type CommandResult } from "../output.js";
import { customRulesCommands } from "./custom-rules.js";
import { exceptionsCommands } from "./exceptions.js";
import { confirmSentence, policyCommands, tilde } from "./policy.js";
import { rulesCommands } from "./rules.js";
import { watchCommand } from "./watch.js";

/** Where the guard is wired, whether it is intact, and who answers its holds. */
/** `advise`: end with the next step when something needs doing. */
function guardReport(ctx: CliContext, all: boolean, advise = true): CommandResult {
  const prefs = ctx.prefs();
  const policy = ctx.policy();
  const states = guardHostStates(ctx.io.env);
  const hosts = states.map((st) => ({
    id: st.host.id,
    label: st.host.label,
    doc_path: st.docPath,
    present: st.present,
    installed: st.installed,
    // With nobody to answer, such an agent falls back to its own permission
    // prompt instead of a deny (guard/hold.ts unattendedOutcome).
    native_ask: st.host.supportsNativeAsk,
  }));
  // A read: report a drifted bundle, don't re-copy it (install does that).
  const integrity = checkGuardIntegrity(ctx.dataDir, prefs.guard_wanted, { heal: false });
  // Wired is not working: run the launcher once the way an agent starts the
  // hook, and each runtime it may use. A read, so nothing is rewritten.
  const installed = hosts.some((h) => h.installed);
  const runtime = installed ? checkGuardRuntime(ctx.dataDir, { fresh: true, persist: false }) : undefined;
  const broken = runtime !== undefined && !runtime.working;
  const running = ctx.running();
  const answering = running
    ? { by: running.version?.startsWith("cli-") ? "doorman watch" : "Doorman", ...(running.pid !== undefined ? { pid: running.pid } : {}) }
    : null;
  const data = {
    wanted: prefs.guard_wanted,
    guard_dir: ctx.guardDir,
    policy_file: existsSync(join(ctx.guardDir, "policy.json")),
    hosts,
    integrity,
    runtime: runtime ?? null,
    answering,
    confirm: policy.confirm,
  };
  const ui = ctx.ui;
  const s = ctx.style;
  const shown = all ? hosts : hosts.filter((h) => h.present);
  const absent = new Set(hosts.filter((h) => !h.present).map((h) => h.label)).size;
  const sandbox = dockerSandbox(ctx.io.env);
  const switchedOff = prefs.guard_wanted ? "" : s.dim("  (switched off)");
  const state = broken
    ? ui.mark("error", `${s.error("not working")}${switchedOff}`)
    : integrity.status === "healthy"
      ? ui.mark("ok", s.ok("installed"))
      : integrity.status === "tampered"
        ? ui.mark("error", `${s.error("altered")}${switchedOff}`)
        : integrity.status === "not_installed"
          ? prefs.guard_wanted
            ? ui.mark("warn", s.warn("not installed"))
            : ui.mark("off", s.dim("switched off"))
          : ui.mark("warn", `${s.warn("no agent found")}${switchedOff}`);
  const hook = (h: (typeof hosts)[number]) =>
    h.installed ? ui.mark("ok", s.ok("installed")) : h.present ? ui.mark("warn", s.warn("not installed")) : ui.mark("off", s.dim("not on this machine"));
  // The one thing to do next, if anything needs doing.
  const next = !advise
    ? undefined
    : !prefs.guard_wanted
      ? "`doorman guard install` turns it on."
      : broken
        ? runtime.ok
          ? "`doorman guard install` switches it to a runtime that works."
          : "Install Node.js or reinstall Doorman, then run `doorman guard install`."
      : integrity.status === "tampered"
        ? "`doorman guard install` restores it."
        : integrity.status === "unknown" && !all
          ? "`doorman guard status --all` lists the agents Doorman supports."
          : installed && !answering
            ? sandbox
              ? `On your computer, run \`${sandboxWatchCommand(sandbox)}\` to answer held calls.`
              : "Open Doorman, or run `doorman watch` to answer held calls in this terminal."
            : undefined;
  const text = [
    `${ui.section("Guard")}  ${state}`,
    ...(shown.length > 0
      ? ui.table(
          ["Agent", "Hook", "File"],
          shown.map((h) => [h.label, hook(h), tilde(h.doc_path, ctx.io.home)]),
          { indent: 2, keep: [0, 1] },
        )
      : ["  No supported agent found on this machine."]),
    ...(!all && absent > 0 ? [s.dim(`  ${absent} other agent${absent === 1 ? "" : "s"} not on this machine (--all lists them)`)] : []),
    ...(integrity.status === "tampered" || (installed && integrity.status !== "healthy") ? [`  ${ui.mark("error", s.error(describeIntegrity(integrity)))}`] : []),
    ...(broken && runtime.problem ? [`  ${ui.mark("error", s.error(runtime.problem))}`] : []),
    "",
    ...ui.kv([
      ["bundle", `${tilde(ctx.guardDir, ctx.io.home)}${data.policy_file ? "" : s.warn("  (no policy.json yet)")}`],
      ["holds", confirmSentence(policy.confirm)],
      ["answers", answering ? s.ok(`${answering.by}${processLabel(ctx.io.env, answering.pid)}`) : nobodyAnswers(hosts, policy.confirm.unattended, sandbox)],
    ]),
    ...(next ? ["", ui.next(next)] : []),
  ];
  return { data, text, ...(broken ? { exitCode: 1 } : {}) };
}

/** What a held call does while neither the app nor `doorman watch` answers:
 * agents with their own permission prompt ask there, the rest follow
 * `confirm.unattended` (guard/hold.ts unattendedOutcome). In a Docker Sandbox
 * the app can't run, so the way to answer is `doorman watch` from the host. */
function nobodyAnswers(
  hosts: readonly { label: string; installed: boolean; native_ask: boolean }[],
  unattended: UnattendedPolicy,
  sandbox: DockerSandbox | undefined,
): string {
  const guarded = hosts.filter((h) => h.installed);
  const ownPrompt = [...new Set(guarded.filter((h) => h.native_ask).map((h) => h.label))];
  const others = [...new Set(guarded.filter((h) => !h.native_ask).map((h) => h.label))].filter((l) => !ownPrompt.includes(l));
  const fallback = unattended === "deny" ? "denied" : "let through with a warning";
  const parts: string[] = [];
  if (ownPrompt.length > 0) parts.push(`${ownPrompt.join(", ")} ${ownPrompt.length === 1 ? "asks in its" : "ask in their"} own prompt`);
  if (others.length > 0) parts.push(`${others.join(", ")}: held calls are ${fallback}`);
  if (parts.length === 0) parts.push(`held calls are ${fallback}`);
  return `nobody right now: ${parts.join("; ")} (${sandbox ? `run on your computer: ${sandboxWatchCommand(sandbox)}` : "open Doorman or run doorman watch"})`;
}

const statusOptions = { all: { type: "boolean", default: false } } as const;

const guardStatus: CliCommand = {
  name: "guard status",
  summary: "Where the guard hook is installed, whether it is intact, who answers held calls",
  flags: [["--all", "list every supported agent, not only the ones on this machine"]],
  examples: [
    ["doorman guard status", "the agents on this machine and who answers held calls"],
    ["doorman guard status --all", "every agent Doorman supports"],
  ],
  options: statusOptions,
  async run(ctx, args) {
    return guardReport(ctx, args.values.all === true);
  },
};

const guardBare: CliCommand = {
  ...guardStatus,
  name: "guard",
  summary: "Same as `doorman guard status`",
  examples: [
    ["doorman guard --all", "every agent Doorman supports, wired or not"],
    ["doorman guard install", "turn the guard on in every agent here"],
    ["doorman guard uninstall", "take the hook out again"],
  ],
};

const guardInstall: CliCommand = {
  name: "guard install",
  summary: "Turn the guard on: install its hook into every agent on this machine",
  notes: [
    "Only agents found on this machine are wired; run it again after you install another one. It also puts back a hook or bundle that was altered.",
  ],
  async run(ctx) {
    // setGuardWanted(true): install, and only then record the intent.
    ctx.requireWritable("Turn the guard on");
    // Fresh probes: an explicit install re-checks every runtime it may use.
    const outcome = installGuard(ctx.dataDir, ctx.policy(), { fresh: true });
    if (!outcome.ok) {
      throw new CliError(outcome.error, 1, outcome.no_agents ? "Run `doorman guard status --all` to see the agents Doorman supports." : undefined);
    }
    ctx.setPrefs({ guard_wanted: true });
    const report = guardReport(ctx, false);
    const { ui, style: s } = ctx;
    const notes = outcome.codex_restart_required ? [ui.mark("warn", s.warn("Restart running Codex sessions so they load the new hook."))] : [];
    // Every agent the install could take was wired; these keep what they had.
    for (const failure of outcome.failures) notes.push(ui.mark("warn", s.warn(`Not installed in ${failure.label}: ${failure.error}`)));
    return {
      data: {
        ...(report.data as object),
        codex_restart_required: outcome.codex_restart_required,
        failed_hosts: outcome.failures,
      },
      // Wired but unable to start is not "on": the report below says why.
      text: [report.exitCode ? ui.mark("error", s.error("Guard wired, but it can't start.")) : ui.mark("ok", s.ok("Guard on.")), ...notes, "", ...report.text],
      ...(report.exitCode ? { exitCode: report.exitCode } : {}),
    };
  },
};

const guardUninstall: CliCommand = {
  name: "guard uninstall",
  summary: "Turn the guard off: remove its hook from every agent",
  notes: ["Your policy, rules and exceptions are kept; `doorman guard install` turns it back on."],
  async run(ctx) {
    // setGuardWanted(false): intent first, so the integrity check reads the
    // removal as the person's own act rather than tampering.
    ctx.requireWritable("Turn the guard off");
    ctx.setPrefs({ guard_wanted: false });
    const outcome = uninstallGuard();
    if (!outcome.ok) throw new CliError(outcome.error);
    const report = guardReport(ctx, false, false);
    return { data: report.data, text: [ctx.ui.mark("off", "Guard off. Tool calls are no longer checked."), "", ...report.text] };
  },
};

export const guardCommands: CliCommand[] = [
  guardBare,
  guardStatus,
  guardInstall,
  guardUninstall,
  watchCommand,
  ...policyCommands,
  ...rulesCommands,
  ...exceptionsCommands,
  ...customRulesCommands,
];
