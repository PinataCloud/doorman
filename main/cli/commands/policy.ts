import { syncGuard } from "../../enforcement.js";
import {
  ALL_DETECTORS,
  HOLD_SECONDS_MAX,
  HOLD_SECONDS_MIN,
  SECURITY_LEVELS,
  handEditedDetectors,
  levelOfModes,
  normalizeConfirm,
  policyWithLevel,
  type ConfirmPolicy,
  type GuardPolicy,
  type SecurityLevel,
} from "../../guard/policy.js";
import { RULE_PACKS } from "../../guard/rule-packs.js";
import { ruleModeOf } from "../../lib/findings.js";
import type { Prefs } from "../../state.js";
import type { CliCommand } from "../command.js";
import type { CliContext } from "../context.js";
import { CliError } from "../output.js";

/**
 * Write a policy/prefs change the way the app's handlers do: refuse while
 * another Doorman owns the data, store the prefs, then push the live policy to
 * the guard (`applyGuardSync`). A failed sync does not undo the change (the
 * app keeps it too and shows the error); it is returned for the caller to say.
 */
export function savePrefs(ctx: CliContext, action: string, patch: (prefs: Prefs) => Partial<Prefs>): { prefs: Prefs; syncError?: string } {
  ctx.requireWritable(action);
  const prefs = ctx.setPrefs(patch(ctx.prefs()));
  const outcome = syncGuard(ctx.dataDir, ctx.policy());
  return outcome.ok ? { prefs } : { prefs, syncError: outcome.error };
}

/** The line that says a saved change did not reach the guard, if it didn't. */
export function syncNote(ctx: CliContext, syncError: string | undefined): string[] {
  return syncError ? [ctx.style.yellow(`Saved, but the guard was not updated: ${syncError}`)] : [];
}

/** `/Users/me/x` → `~/x`. */
export function tilde(path: string, home: string): string {
  return home && (path === home || path.startsWith(`${home}/`)) ? `~${path.slice(home.length)}` : path;
}

/** The level the app shows: the stored one, else what the modes are. */
export function currentLevel(prefs: Prefs): SecurityLevel {
  return prefs.security_level ?? levelOfModes(prefs.policy.modes) ?? "protective";
}

/** What a held call turns into when nobody answers in time, in words. */
export function confirmSentence(confirm: ConfirmPolicy): string {
  if (!confirm.interactive) return "off: ask rules go straight to the agent's own prompt";
  const timeout = confirm.on_timeout === "deny" ? "then denied" : "then the agent asks";
  const unattended = confirm.unattended === "deny" ? "denied" : "continue with a warning";
  return `held up to ${confirm.hold_seconds}s, ${timeout} · with nobody to ask, agents without their own prompt: ${unattended}`;
}

function modeCounts(policy: GuardPolicy): Record<string, number> {
  const counts: Record<string, number> = { block: 0, ask: 0, warn: 0, observe: 0, off: 0 };
  for (const id of ALL_DETECTORS) {
    const mode = ruleModeOf(id, policy) ?? "observe";
    counts[mode] = (counts[mode] ?? 0) + 1;
  }
  return counts;
}

const policyShow: CliCommand = {
  name: "policy",
  summary: "The policy the guard enforces: level, rule modes, holds, packs, custom rules, exceptions",
  async run(ctx) {
    const prefs = ctx.prefs();
    const policy = ctx.policy();
    const level = currentLevel(prefs);
    const edited = handEditedDetectors(prefs.policy.modes, level);
    const counts = modeCounts(policy);
    const nowMs = ctx.io.now();
    const ignore = prefs.policy.ignore;
    const expired = ignore.filter((r) => r.expires_at !== undefined && Date.parse(r.expires_at) <= nowMs).length;
    const packs = prefs.rule_packs_enabled.filter((id) => RULE_PACKS.some((p) => p.id === id));
    const own = prefs.policy.custom_rules ?? [];
    const data = {
      level,
      hand_edited: edited,
      modes: Object.fromEntries(ALL_DETECTORS.map((id) => [id, ruleModeOf(id, policy) ?? "observe"])),
      disabled: policy.disabled,
      confirm: policy.confirm,
      armed_escalation: policy.armed_escalation !== false,
      packs_enabled: packs,
      custom_rules: own.length,
      exceptions: { total: ignore.length, expired },
    };
    const s = ctx.style;
    const modeLine = (["block", "ask", "warn", "observe", "off"] as const)
      .filter((m) => (counts[m] ?? 0) > 0)
      .map((m) => `${counts[m]} ${m}`)
      .join(" · ");
    const text = [
      s.bold("Policy"),
      `  level         ${level}${edited.length > 0 ? s.yellow(`  ${edited.length} rule${edited.length === 1 ? "" : "s"} changed by hand`) : ""}`,
      `  rules         ${modeLine}  ${s.dim("doorman rules")}`,
      `  holds         ${confirmSentence(policy.confirm)}`,
      `  packs         ${packs.length === 0 ? "none" : packs.join(", ")}  ${s.dim(`${packs.length} of ${RULE_PACKS.length} · doorman packs`)}`,
      `  custom rules  ${own.length}  ${s.dim("doorman custom-rules")}`,
      `  exceptions    ${ignore.length}${expired > 0 ? s.dim(` (${expired} expired)`) : ""}  ${s.dim("doorman exceptions")}`,
    ];
    return { data, text };
  },
};

const policyLevel: CliCommand = {
  name: "policy level",
  summary: "Move the security level (resets every rule's mode to the level's)",
  usage: `<${SECURITY_LEVELS.join("|")}>`,
  details: [
    "A level rewrites the mode of every rule, like the level control in the app.",
    "Custom rules, packs, exceptions and hold settings are kept.",
  ],
  positionals: { min: 1, max: 1 },
  async run(ctx, args) {
    const level = args.positionals[0] as SecurityLevel;
    if (!SECURITY_LEVELS.includes(level)) throw new CliError(`Unknown level "${level}". Pick one of: ${SECURITY_LEVELS.join(", ")}.`, 2);
    let overwritten = 0;
    const { syncError } = savePrefs(ctx, "Change the security level", (prefs) => {
      // Counted before the write, against the level being left (radar:security-level).
      overwritten = handEditedDetectors(prefs.policy.modes, currentLevel(prefs)).length;
      return { policy: policyWithLevel(prefs.policy, level), security_level: level };
    });
    return {
      data: { level, overwritten, ...(syncError ? { sync_error: syncError } : {}) },
      text: [
        `Level: ${level}.${overwritten > 0 ? ` ${overwritten} rule${overwritten === 1 ? "" : "s"} changed by hand went back to the level's mode.` : ""}`,
        ...syncNote(ctx, syncError),
      ],
    };
  },
};

const policyConfirm: CliCommand = {
  name: "policy confirm",
  summary: "How held calls wait for an answer (hold window, timeout, nobody to ask)",
  usage: "[--hold <s>] [--on-timeout deny|ask] [--unattended deny|continue] [--interactive on|off] [--armed-escalation on|off]",
  details: [
    `--hold <s>               how long a call waits for you (${HOLD_SECONDS_MIN}-${HOLD_SECONDS_MAX} seconds)`,
    "--on-timeout deny|ask    what an unanswered hold becomes: denied, or the agent's own prompt",
    "--unattended deny|continue  with nobody to ask (no app, no `doorman watch`), for agents without their own prompt: deny, or continue with a warning",
    "--interactive on|off     hold ask-mode calls at all",
    "--armed-escalation on|off  hold the next risky call after an injected instruction arrived in the session",
    "Without options it prints the current settings.",
  ],
  options: {
    hold: { type: "string" },
    "on-timeout": { type: "string" },
    unattended: { type: "string" },
    interactive: { type: "string" },
    "armed-escalation": { type: "string" },
  },
  async run(ctx, args) {
    const v = args.values;
    const patch: Record<string, unknown> = {};
    if (typeof v.hold === "string") {
      const n = Number(v.hold);
      if (!Number.isInteger(n) || n < HOLD_SECONDS_MIN || n > HOLD_SECONDS_MAX) {
        throw new CliError(`--hold takes whole seconds from ${HOLD_SECONDS_MIN} to ${HOLD_SECONDS_MAX}.`, 2);
      }
      patch.hold_seconds = n;
    }
    const choice = (flag: string, allowed: readonly string[]): string | undefined => {
      const value = v[flag];
      if (value === undefined) return undefined;
      if (typeof value !== "string" || !allowed.includes(value)) throw new CliError(`--${flag} takes ${allowed.join(" or ")}.`, 2);
      return value;
    };
    const onTimeout = choice("on-timeout", ["deny", "ask"]);
    if (onTimeout) patch.on_timeout = onTimeout;
    const unattended = choice("unattended", ["deny", "continue"]);
    if (unattended) patch.unattended = unattended;
    const interactive = choice("interactive", ["on", "off"]);
    if (interactive) patch.interactive = interactive === "on";
    const armed = choice("armed-escalation", ["on", "off"]);
    let syncError: string | undefined;
    if (Object.keys(patch).length > 0 || armed !== undefined) {
      // radar:confirm-policy: the hold window is also the hook's timeout, so
      // the sync re-merges the hook documents, not just policy.json.
      ({ syncError } = savePrefs(ctx, "Change how held calls wait", (prefs) => {
        const policy: GuardPolicy = { ...prefs.policy, confirm: normalizeConfirm({ ...prefs.policy.confirm, ...patch }) };
        if (armed !== undefined) policy.armed_escalation = armed === "on";
        return { policy };
      }));
    }
    const policy = ctx.policy();
    const confirm = policy.confirm;
    const s = ctx.style;
    return {
      data: { confirm, armed_escalation: policy.armed_escalation !== false, ...(syncError ? { sync_error: syncError } : {}) },
      text: [
        s.bold("Holds"),
        `  interactive        ${confirm.interactive ? "on" : "off"}`,
        `  hold window        ${confirm.hold_seconds}s`,
        `  on timeout         ${confirm.on_timeout === "deny" ? "deny" : "ask (the agent's own prompt)"}`,
        `  nobody to ask      ${confirm.unattended === "deny" ? "deny" : "continue with a warning"}`,
        `  armed escalation   ${policy.armed_escalation !== false ? "on" : "off"}`,
        ...syncNote(ctx, syncError),
      ],
    };
  },
};

export const policyCommands: CliCommand[] = [policyShow, policyLevel, policyConfirm];
