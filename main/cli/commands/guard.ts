import { existsSync } from "node:fs";
import { join } from "node:path";
import { checkGuardIntegrity, guardHostStates, installGuard, uninstallGuard } from "../../enforcement.js";
import type { UnattendedPolicy } from "../../guard/policy.js";
import { describeIntegrity } from "../../lib/guard-integrity.js";
import type { CliCommand } from "../command.js";
import type { CliContext } from "../context.js";
import { dockerSandbox, sandboxWatchCommand, type DockerSandbox } from "../docker-sandbox.js";
import { CliError, table, type CommandResult } from "../output.js";
import { customRulesCommands } from "./custom-rules.js";
import { exceptionsCommands } from "./exceptions.js";
import { confirmSentence, policyCommands, tilde } from "./policy.js";
import { rulesCommands } from "./rules.js";
import { watchCommand } from "./watch.js";

/** Where the guard is wired, whether it is intact, and who answers its holds. */
function guardReport(ctx: CliContext, all: boolean): CommandResult {
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
    answering,
    confirm: policy.confirm,
  };
  const s = ctx.style;
  const shown = all ? hosts : hosts.filter((h) => h.present);
  const absent = new Set(hosts.filter((h) => !h.present).map((h) => h.label)).size;
  const installed = hosts.some((h) => h.installed);
  const statusWord =
    integrity.status === "healthy"
      ? s.green("installed")
      : integrity.status === "tampered"
        ? s.red("altered")
        : integrity.status === "not_installed"
          ? s.yellow("not installed")
          : s.yellow(integrity.status);
  const text = [
    `${s.bold("Guard")}  ${statusWord}${prefs.guard_wanted ? "" : s.dim("  (switched off)")}`,
    ...(shown.length > 0
      ? table(
          ["Agent", "Hook", "File"],
          shown.map((h) => [h.label, h.installed ? s.green("installed") : h.present ? s.yellow("not installed") : s.dim("not on this machine"), tilde(h.doc_path, ctx.io.home)]),
        ).map((l) => `  ${l}`)
      : ["  No supported agent found on this machine."]),
    ...(!all && absent > 0 ? [s.dim(`  ${absent} other agent${absent === 1 ? "" : "s"} not on this machine (--all lists them)`)] : []),
    ...(integrity.status === "tampered" || (installed && integrity.status !== "healthy") ? [`  ${s.red(describeIntegrity(integrity))}`] : []),
    `  bundle   ${tilde(ctx.guardDir, ctx.io.home)}${data.policy_file ? "" : s.yellow("  (no policy.json yet)")}`,
    `  holds    ${confirmSentence(policy.confirm)}`,
    `  answers  ${answering ? s.green(`${answering.by}${answering.pid !== undefined ? ` (pid ${answering.pid})` : ""}`) : nobodyAnswers(hosts, policy.confirm.unattended, dockerSandbox(ctx.io.env))}`,
  ];
  return { data, text };
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
  details: ["--all  list every supported agent, not only the ones on this machine"],
  options: statusOptions,
  async run(ctx, args) {
    return guardReport(ctx, args.values.all === true);
  },
};

const guardBare: CliCommand = { ...guardStatus, name: "guard", summary: "Same as `doorman guard status`" };

const guardInstall: CliCommand = {
  name: "guard install",
  summary: "Turn the guard on: install its hook into every agent on this machine",
  async run(ctx) {
    // setGuardWanted(true): install, and only then record the intent.
    ctx.requireWritable("Turn the guard on");
    const outcome = installGuard(ctx.dataDir, ctx.policy());
    if (!outcome.ok) {
      throw new CliError(outcome.no_agents ? `${outcome.error}\nRun \`doorman guard status --all\` to see the agents Doorman supports.` : outcome.error);
    }
    ctx.setPrefs({ guard_wanted: true });
    const report = guardReport(ctx, false);
    const notes = outcome.codex_restart_required ? [ctx.style.yellow("Restart running Codex sessions so they load the new hook.")] : [];
    // Every agent the install could take was wired; these keep what they had.
    for (const failure of outcome.failures) notes.push(ctx.style.yellow(`Not installed in ${failure.label}: ${failure.error}`));
    return {
      data: {
        ...(report.data as object),
        codex_restart_required: outcome.codex_restart_required,
        failed_hosts: outcome.failures,
      },
      text: ["Guard on.", ...notes, "", ...report.text],
    };
  },
};

const guardUninstall: CliCommand = {
  name: "guard uninstall",
  summary: "Turn the guard off: remove its hook from every agent",
  async run(ctx) {
    // setGuardWanted(false): intent first, so the integrity check reads the
    // removal as the person's own act rather than tampering.
    ctx.requireWritable("Turn the guard off");
    ctx.setPrefs({ guard_wanted: false });
    const outcome = uninstallGuard();
    if (!outcome.ok) throw new CliError(outcome.error);
    const report = guardReport(ctx, false);
    return { data: report.data, text: ["Guard off. Tool calls are no longer checked.", "", ...report.text] };
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
