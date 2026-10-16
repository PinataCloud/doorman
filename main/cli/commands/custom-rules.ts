import { existsSync, readFileSync } from "node:fs";
import { parseCustomRules, validateCustomRule, validateCustomRuleList, type CustomRule, type CustomRuleProblem } from "../../guard/custom-rules.js";
import type { GuardPolicy } from "../../guard/policy.js";
import type { CliCommand } from "../command.js";
import type { CliContext } from "../context.js";
import { CliError, table } from "../output.js";
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

const customList: CliCommand = {
  name: "custom-rules",
  summary: "Your own rules (and the ones enabled packs add)",
  async run(ctx) {
    const own = ctx.prefs().policy.custom_rules ?? [];
    const fromPacks = (ctx.policy().custom_rules ?? []).filter((r) => r.pack !== undefined && !own.some((o) => o.id === r.id));
    const s = ctx.style;
    const row = (r: CustomRule) => [r.id, r.enabled === false ? s.dim("off") : r.mode, r.severity, r.label];
    const text =
      own.length === 0
        ? ["No custom rules. Add one with `doorman custom-rules add <file.json>`."]
        : [s.bold("Custom rules"), ...table(["Id", "Mode", "Severity", "Label"], own.map(row)).map((l) => `  ${l}`)];
    if (fromPacks.length > 0) {
      text.push("", s.bold("From packs"), ...table(["Id", "Mode", "Severity", "Label"], fromPacks.map(row)).map((l) => `  ${l}`));
    }
    return { data: { custom_rules: own, pack_rules: fromPacks }, text };
  },
};

const customAdd: CliCommand = {
  name: "custom-rules add",
  summary: "Add custom rules from a JSON file (one rule or a list)",
  usage: "<file.json> [--replace]",
  details: [
    'A rule: {"id","label","severity","mode","when":{"tool"|"command"|"server"|"target"|"arg"},"after"?,"scope"?}',
    "Try it first with `doorman custom-rules dry-run <file.json>`.",
    "--replace  replace a rule with the same id instead of refusing",
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
      if (clash.length > 0 && !replace) throw new CliError(`Already have ${clash.join(", ")}. Pass --replace to overwrite.`, 2);
      return [...own.filter((r) => !ids.includes(r.id)), ...checked.rules];
    });
    return {
      data: { added: ids, custom_rules: prefs.policy.custom_rules ?? [], ...(syncError ? { sync_error: syncError } : {}) },
      text: [`Saved ${ids.join(", ")}.`, ...syncNote(ctx, syncError)],
    };
  },
};

const customRemove: CliCommand = {
  name: "custom-rules remove",
  summary: "Remove one of your custom rules",
  usage: "<id>",
  positionals: { min: 1, max: 1 },
  async run(ctx, args) {
    const id = args.positionals[0]!;
    if (!(ctx.prefs().policy.custom_rules ?? []).some((r) => r.id === id)) {
      throw new CliError(`No custom rule "${id}". \`doorman custom-rules\` lists them (pack rules go with \`doorman packs disable\`).`, 2);
    }
    const { syncError } = saveRules(ctx, "Remove a custom rule", (own) => own.filter((r) => r.id !== id));
    return { data: { removed: id, ...(syncError ? { sync_error: syncError } : {}) }, text: [`Removed ${id}.`, ...syncNote(ctx, syncError)] };
  },
};

const customDryRun: CliCommand = {
  name: "custom-rules dry-run",
  summary: "What a rule would have caught in your recent transcripts",
  usage: "<file.json|id> [--days 14]",
  details: ["--days <n>  how far back to look (1-90, default 14)"],
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

export const customRulesCommands: CliCommand[] = [customList, customAdd, customRemove, customDryRun];
