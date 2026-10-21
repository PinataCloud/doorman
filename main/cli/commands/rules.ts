import { ALL_DETECTORS, levelModes, type EnforcementMode } from "../../guard/policy.js";
import { RULE_PACKS, RULE_PACK_IDS } from "../../guard/rule-packs.js";
import { ruleShown } from "../../guard/rule-scope.js";
import type { SecurityDetectorId } from "../../guard/security-detect.js";
import { DETECTOR_GUIDANCE } from "../../lib/ai-guidance.js";
import { localDetectorLabel, ruleModeOf } from "../../lib/findings.js";
import type { CliCommand } from "../command.js";
import { CliError } from "../output.js";
import { LEVEL_NAMES, currentLevel, savePrefs, syncNote } from "./policy.js";

const MODES: readonly EnforcementMode[] = ["observe", "warn", "ask", "block"];

/** A detector id the guard enforces and the app shows, or a usage error naming the catalog. */
function detectorArg(raw: string | undefined): SecurityDetectorId {
  if (raw && ruleShown(raw) && (ALL_DETECTORS as readonly string[]).includes(raw)) return raw as SecurityDetectorId;
  throw new CliError(`Unknown rule "${raw ?? ""}".`, 2, "`doorman rules` lists them.");
}

const rulesList: CliCommand = {
  name: "rules",
  summary: "The rule catalog and what each rule does now (observe, warn, ask, block, off)",
  notes: [
    "  observe  record only",
    "  warn     let it run and warn",
    "  ask      hold it for you",
    "  block    deny it",
    "  off      disabled",
    "A * marks a mode changed by hand from the level's.",
  ],
  examples: [
    ["doorman rules", "every rule and its mode"],
    ["doorman rules set secret_egress block", "deny instead of asking"],
  ],
  async run(ctx) {
    const prefs = ctx.prefs();
    const policy = ctx.policy();
    const level = currentLevel(prefs);
    const atLevel = levelModes(level);
    const rows = ALL_DETECTORS.filter((id) => ruleShown(id)).map((id) => {
      const mode = ruleModeOf(id, policy) ?? "observe";
      const levelMode = atLevel[id] ?? "observe";
      return {
        id,
        label: localDetectorLabel(id),
        mode,
        level_mode: levelMode,
        hand_edited: mode !== "off" && mode !== levelMode,
        ...(DETECTOR_GUIDANCE[id] ? { blurb: DETECTOR_GUIDANCE[id]!.blurb } : {}),
      };
    });
    const s = ctx.style;
    const paint = (mode: string) =>
      mode === "block" ? s.error(mode) : mode === "ask" ? s.warn(mode) : mode === "observe" || mode === "off" ? s.dim(mode) : mode;
    const own = policy.custom_rules?.length ?? 0;
    return {
      data: { level, rules: rows },
      text: [
        ctx.ui.section("Rules", `level ${LEVEL_NAMES[level]}`),
        ...ctx.ui.table(
          ["Rule", "Mode", "What it catches"],
          rows.map((r) => [r.id, `${paint(r.mode)}${r.hand_edited ? "*" : ""}`, r.label]),
          { indent: 2, keep: [0, 1] },
        ),
        ...(own > 0 ? ["", s.dim(`Plus ${own} custom and pack rule${own === 1 ? "" : "s"}: doorman custom-rules, doorman packs`)] : []),
      ],
    };
  },
};

const rulesSet: CliCommand = {
  name: "rules set",
  summary: "Set one rule's mode",
  usage: "<rule> <observe|warn|ask|block>",
  notes: ["Rule ids are in `doorman rules`. `doorman policy level` puts every rule back to the level's mode."],
  examples: [
    ["doorman rules set secret_egress block", "deny instead of asking"],
    ["doorman rules set secret_egress ask", "hold it for you"],
  ],
  positionals: { min: 2, max: 2 },
  async run(ctx, args) {
    const id = detectorArg(args.positionals[0]);
    const mode = args.positionals[1] as EnforcementMode;
    if (!MODES.includes(mode)) throw new CliError(`Unknown mode "${mode}". Mode must be one of: ${MODES.join(", ")}.`, 2);
    // radar:detector-mode: every mode is written out, observe included (an
    // absent entry means the built-in default).
    const { syncError } = savePrefs(ctx, "Change a rule's mode", (prefs) => ({
      policy: { ...prefs.policy, modes: { ...prefs.policy.modes, [id]: mode } },
    }));
    const disabled = ctx.policy().disabled.includes(id);
    return {
      data: { rule: id, mode, disabled, ...(syncError ? { sync_error: syncError } : {}) },
      text: [
        ctx.ui.mark("ok", `${localDetectorLabel(id)} (${id}): ${mode}.`),
        ...(disabled ? [ctx.ui.mark("off", ctx.style.warn("It is disabled, so it stays off.")), ctx.ui.next(`\`doorman rules enable ${id}\` turns it back on.`)] : []),
        ...syncNote(ctx, syncError),
      ],
    };
  },
};

function toggleRule(enable: boolean): CliCommand {
  return {
    name: enable ? "rules enable" : "rules disable",
    summary: enable ? "Turn a disabled rule back on" : "Turn a rule off entirely (not even recorded)",
    usage: "<rule>",
    examples: [[`doorman rules ${enable ? "enable" : "disable"} secret_egress`, enable ? "back to its mode" : "stop checking for it"]],
    positionals: { min: 1, max: 1 },
    async run(ctx, args) {
      const id = detectorArg(args.positionals[0]);
      const { syncError } = savePrefs(ctx, enable ? "Enable a rule" : "Disable a rule", (prefs) => {
        const rest = prefs.policy.disabled.filter((d) => d !== id);
        return { policy: { ...prefs.policy, disabled: enable ? rest : [...rest, id] } };
      });
      const mode = ruleModeOf(id, ctx.policy()) ?? "observe";
      return {
        data: { rule: id, mode, ...(syncError ? { sync_error: syncError } : {}) },
        text: [ctx.ui.mark(enable ? "ok" : "off", `${localDetectorLabel(id)} (${id}): ${enable ? `on, ${mode}` : "off"}.`), ...syncNote(ctx, syncError)],
      };
    },
  };
}

const packsList: CliCommand = {
  name: "packs",
  summary: "Shipped rule packs and which are on",
  examples: [["doorman packs enable crypto_operations", "turn one pack on"]],
  async run(ctx) {
    const enabled = new Set(ctx.prefs().rule_packs_enabled);
    const rows = RULE_PACKS.map((p) => ({ id: p.id, label: p.label, blurb: p.blurb, enabled: enabled.has(p.id), rules: p.rules.length }));
    const s = ctx.style;
    return {
      data: { packs: rows },
      text: [
        ctx.ui.section("Rule packs"),
        ...ctx.ui.table(
          ["Pack", "State", "Rules", "What it covers"],
          rows.map((r) => [r.id, r.enabled ? ctx.ui.mark("ok", s.ok("on")) : ctx.ui.mark("off", s.dim("off")), String(r.rules), r.label]),
          { indent: 2, keep: [0, 1, 2] },
        ),
      ],
    };
  },
};

function togglePack(enable: boolean): CliCommand {
  return {
    name: enable ? "packs enable" : "packs disable",
    summary: enable ? "Turn a rule pack on" : "Turn a rule pack off",
    usage: "<pack>",
    notes: ["Pack ids are in `doorman packs`."],
    examples: [[`doorman packs ${enable ? "enable" : "disable"} crypto_operations`, enable ? "add its rules" : "drop its rules"]],
    positionals: { min: 1, max: 1 },
    async run(ctx, args) {
      const id = args.positionals[0]!;
      if (!RULE_PACK_IDS.includes(id)) throw new CliError(`Unknown pack "${id}".`, 2, "`doorman packs` lists them.");
      // rules:pack
      const { prefs, syncError } = savePrefs(ctx, enable ? "Turn a rule pack on" : "Turn a rule pack off", (current) => {
        const list = current.rule_packs_enabled ?? [];
        return { rule_packs_enabled: enable ? [...new Set([...list, id])] : list.filter((p) => p !== id) };
      });
      const label = RULE_PACKS.find((p) => p.id === id)!.label;
      return {
        data: { pack: id, enabled: enable, rule_packs_enabled: prefs.rule_packs_enabled, ...(syncError ? { sync_error: syncError } : {}) },
        text: [ctx.ui.mark(enable ? "ok" : "off", `${label} (${id}): ${enable ? "on" : "off"}.`), ...syncNote(ctx, syncError)],
      };
    },
  };
}

export const rulesCommands: CliCommand[] = [rulesList, rulesSet, toggleRule(true), toggleRule(false), packsList, togglePack(true), togglePack(false)];
