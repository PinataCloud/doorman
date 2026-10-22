import { existsSync, readFileSync } from "node:fs";
import { parseCustomRules, validateCustomRule, validateCustomRuleList, type CustomRule, type CustomRuleProblem } from "../../guard/custom-rules.js";
import type { GuardPolicy } from "../../guard/policy.js";
import { checkAcceptedProposal, describeRule, readProposal, readProposals, removeProposal } from "../../guard/rule-proposals.js";
import type { CliCommand } from "../command.js";
import type { CliContext } from "../context.js";
import { CliError } from "../output.js";
import { savePrefs, syncNote } from "./policy.js";

function readJson(path: string): unknown {
  let text: string;
  try {
    text = readFileSync(path, "utf8");
  } catch (err) {
    throw new CliError(`Can't read ${path}: ${err instanceof Error ? err.message : String(err)}`);
  }
  try {
    return JSON.parse(text);
  } catch (err) {
    throw new CliError(`${path} is not JSON: ${err instanceof Error ? err.message : String(err)}`);
  }
}

function problemsError(problems: readonly CustomRuleProblem[]): CliError {
  const lines = problems.map((p) => `  ${p.id ? `${p.id}: ` : ""}${p.field}: ${p.message}`);
  return new CliError(`The rule can't be saved:\n${lines.join("\n")}`, 2);
}

/** Save the person's own rules whole, like rules:custom-set (validated as a
 * list, an empty list removes the field). */
function saveRules(ctx: CliContext, action: string, next: (own: CustomRule[]) => unknown[]) {
  return savePrefs(ctx, action, (prefs) => {
    const result = validateCustomRuleList(next(prefs.policy.custom_rules ?? []));
    if (!result.ok) throw problemsError(result.problems);
    const policy: GuardPolicy = { ...prefs.policy };
    if (result.rules.length > 0) policy.custom_rules = parseCustomRules(result.rules);
    else delete policy.custom_rules;
    return { policy };
  });
}

/** The guide to rules, packs and writing your own, with every field and examples. */
const RULES_GUIDE_URL = "https://github.com/PinataCloud/doorman/blob/main/docs/rules.md#your-own-rules";

const customList: CliCommand = {
  name: "custom-rules",
  summary: "Your own rules (and the ones enabled packs add)",
  notes: [`How to write one, with examples: ${RULES_GUIDE_URL}`],
  examples: [
    ["doorman custom-rules dry-run rule.json", "what a rule would have caught, before saving it"],
    ["doorman custom-rules add rule.json", "save it"],
    ["doorman custom-rules accept <suggestion-id>", "save a rule an agent suggested"],
  ],
  async run(ctx) {
    const own = ctx.prefs().policy.custom_rules ?? [];
    const fromPacks = (ctx.policy().custom_rules ?? []).filter((r) => r.pack !== undefined && !own.some((o) => o.id === r.id));
    const s = ctx.style;
    const ui = ctx.ui;
    const row = (r: CustomRule) => [r.id, r.enabled === false ? ui.mark("off", s.dim("off")) : r.mode, r.severity, r.label];
    const rulesTable = (rules: readonly CustomRule[]) => ui.table(["Id", "Mode", "Severity", "Label"], rules.map(row), { indent: 2, keep: [0, 1, 2] });
    const text =
      own.length === 0
        ? ["No custom rules.", ui.next("`doorman custom-rules add <file.json>` adds one.")]
        : [ui.section("Custom rules"), ...rulesTable(own)];
    if (fromPacks.length > 0) text.push("", ui.section("From packs"), ...rulesTable(fromPacks));
    // Rules an agent suggested over Doorman's MCP server: shown apart, since
    // none of them is live until the person accepts it.
    const suggested = readProposals(ctx.guardDir);
    if (suggested.length > 0) {
      text.push("", ui.section("Suggested by your agents"));
      for (const p of suggested) {
        text.push(`  ${p.id}  ${p.rule.mode}  ${p.rule.label}  ${s.dim(`from ${p.from}`)}`, `    ${s.dim(describeRule(p.rule))}`, `    ${s.dim(p.reason)}`);
      }
      text.push(ui.next("`doorman custom-rules accept <id>` saves one; `doorman custom-rules dismiss <id>` drops it."));
    }
    return { data: { custom_rules: own, pack_rules: fromPacks, suggested }, text };
  },
};

const customAdd: CliCommand = {
  name: "custom-rules add",
  summary: "Add custom rules from a JSON file (one rule or a list)",
  usage: "<file.json> [--replace]",
  notes: [
    "A rule is a JSON object with these fields (? = optional):",
    '  {"id", "label", "severity", "mode",',
    '   "when": {"tool" | "command" | "server" | "target" | "arg"},',
    '   "after"?, "scope"?}',
    "Try it first with `doorman custom-rules dry-run <file.json>`.",
    `Every field, with examples: ${RULES_GUIDE_URL}`,
  ],
  flags: [["--replace", "replace a rule with the same id instead of refusing"]],
  examples: [
    ["doorman custom-rules add rule.json", "add the rule (or list of rules) in the file"],
    ["doorman custom-rules add rule.json --replace", "update rules you already have"],
  ],
  options: { replace: { type: "boolean", default: false } },
  positionals: { min: 1, max: 1 },
  async run(ctx, args) {
    const raw = readJson(args.positionals[0]!);
    const incoming = Array.isArray(raw) ? raw : [raw];
    const checked = validateCustomRuleList(incoming);
    if (!checked.ok) throw problemsError(checked.problems);
    const ids = checked.rules.map((r) => r.id);
    const replace = args.values.replace === true;
    const { prefs, syncError } = saveRules(ctx, "Add a custom rule", (own) => {
      const clash = own.filter((r) => ids.includes(r.id)).map((r) => r.id);
      if (clash.length > 0 && !replace) throw new CliError(`Already have ${clash.join(", ")}.`, 2, "Pass --replace to overwrite.");
      return [...own.filter((r) => !ids.includes(r.id)), ...checked.rules];
    });
    return {
      data: { added: ids, custom_rules: prefs.policy.custom_rules ?? [], ...(syncError ? { sync_error: syncError } : {}) },
      text: [ctx.ui.mark("ok", `Saved ${ids.join(", ")}.`), ...syncNote(ctx, syncError)],
    };
  },
};

const customRemove: CliCommand = {
  name: "custom-rules remove",
  summary: "Remove one of your custom rules",
  usage: "<id>",
  notes: ["Pack rules go with their pack: `doorman packs disable <pack>`."],
  examples: [["doorman custom-rules remove no-prod", "remove the rule with id no-prod"]],
  positionals: { min: 1, max: 1 },
  async run(ctx, args) {
    const id = args.positionals[0]!;
    if (!(ctx.prefs().policy.custom_rules ?? []).some((r) => r.id === id)) {
      throw new CliError(`No custom rule "${id}".`, 2, "`doorman custom-rules` lists them (pack rules go with `doorman packs disable`).");
    }
    const { syncError } = saveRules(ctx, "Remove a custom rule", (own) => own.filter((r) => r.id !== id));
    return { data: { removed: id, ...(syncError ? { sync_error: syncError } : {}) }, text: [ctx.ui.mark("off", `Removed ${id}.`), ...syncNote(ctx, syncError)] };
  },
};

const customDryRun: CliCommand = {
  name: "custom-rules dry-run",
  summary: "What a rule would have caught in your recent transcripts",
  usage: "<file.json|id> [--days 14]",
  flags: [["--days <n>", "how far back to look (1-90, default 14)"]],
  notes: ["Takes a rule file, or the id of a rule in `doorman custom-rules` (pack rules too). It only reads transcripts; nothing is saved."],
  examples: [
    ["doorman custom-rules dry-run rule.json", "try a rule file before adding it"],
    ["doorman custom-rules dry-run no-prod --days 30", "a saved rule over the last 30 days"],
  ],
  options: { days: { type: "string", default: "14" } },
  positionals: { min: 1, max: 1 },
  async run(ctx, args) {
    const arg = args.positionals[0]!;
    let raw: unknown;
    if (existsSync(arg)) raw = readJson(arg);
    else {
      raw = (ctx.policy().custom_rules ?? []).find((r) => r.id === arg);
      if (!raw) throw new CliError(`"${arg}" is neither a file nor a custom rule id.`, 2);
    }
    const result = validateCustomRule(raw);
    if (!result.ok) throw problemsError(result.problems);
    const n = Number(args.values.days);
    if (!Number.isFinite(n) || n <= 0) throw new CliError("--days takes a positive number.", 2);
    // rules:custom-dry-run
    const days = Math.min(90, Math.floor(n));
    const handle = await ctx.openEngine({ scan: false });
    let run;
    try {
      run = await handle.engine.dryRunCustomRule(result.rule, days);
    } finally {
      handle.close();
    }
    const s = ctx.style;
    return {
      data: { rule: result.rule.id, ...run },
      text: [
        `${result.rule.label} (${result.rule.id}): ${run.matches} match${run.matches === 1 ? "" : "es"} in ${run.sessions} session${run.sessions === 1 ? "" : "s"}  ${s.dim(`${run.files} transcript files, last ${run.days} days`)}`,
        ...run.samples.map((m) => `  ${s.dim(m.at.slice(0, 16).replace("T", " "))}  ${m.tool_name ?? ""}  ${m.excerpt.replace(/\s+/g, " ")}`),
      ],
    };
  },
};

const customAccept: CliCommand = {
  name: "custom-rules accept",
  summary: "Save a rule an agent suggested",
  usage: "<suggestion-id>",
  notes: [
    "Agents suggest rules with Doorman's MCP tool doorman_propose_rule; `doorman custom-rules` lists them.",
    "A suggestion only ever adds a new rule: one whose id is already taken is refused.",
  ],
  examples: [["doorman custom-rules accept p-1a2b3c4d5e6f", "add the suggested rule to your own"]],
  positionals: { min: 1, max: 1 },
  async run(ctx, args) {
    const id = args.positionals[0]!;
    const proposal = readProposal(ctx.guardDir, id);
    if (!proposal) throw new CliError(`No suggested rule "${id}".`, 2, "`doorman custom-rules` lists them.");
    const { syncError } = saveRules(ctx, "Accept a suggested rule", (own) => {
      // Checked inside the save, against the live set as it is now.
      const checked = checkAcceptedProposal(ctx.guardDir, id, proposal.rule, (ctx.policy().custom_rules ?? []).map((r) => r.id));
      if (!checked.ok) throw problemsError(checked.problems);
      return [...own, checked.rule];
    });
    removeProposal(ctx.guardDir, id);
    return {
      data: { accepted: id, rule: proposal.rule.id, ...(syncError ? { sync_error: syncError } : {}) },
      text: [ctx.ui.mark("ok", `Saved ${proposal.rule.id} (${proposal.rule.label}).`), ...syncNote(ctx, syncError)],
    };
  },
};

const customDismiss: CliCommand = {
  name: "custom-rules dismiss",
  summary: "Drop a rule an agent suggested",
  usage: "<suggestion-id>",
  examples: [["doorman custom-rules dismiss p-1a2b3c4d5e6f", "drop the suggestion; nothing was ever applied"]],
  positionals: { min: 1, max: 1 },
  async run(ctx, args) {
    const id = args.positionals[0]!;
    ctx.requireWritable("Dismiss a suggested rule");
    if (!removeProposal(ctx.guardDir, id)) throw new CliError(`No suggested rule "${id}".`, 2, "`doorman custom-rules` lists them.");
    return { data: { dismissed: id }, text: [ctx.ui.mark("off", `Dismissed ${id}.`)] };
  },
};

export const customRulesCommands: CliCommand[] = [customList, customAdd, customRemove, customDryRun, customAccept, customDismiss];
