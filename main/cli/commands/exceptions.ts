import { resolve } from "node:path";
import { KNOWN_IGNORE_SCOPES, parseIgnoreRule, type ScopedIgnoreRule } from "../../guard/policy.js";
import { isPathologicalPattern } from "../../guard/security-detect.js";
import { localDetectorLabel } from "../../lib/findings.js";
import type { CliCommand } from "../command.js";
import { CliError } from "../output.js";
import { savePrefs, syncNote, tilde } from "./policy.js";

/** Why an exception pattern can't be saved: the engine skips a pattern that
 * doesn't compile, matches the empty string or has a pathological shape, so
 * saving one would be an exception that silently never applies. */
function patternProblem(pattern: string): string | undefined {
  let re: RegExp;
  try {
    re = new RegExp(pattern, "i");
  } catch (err) {
    return `That isn't a valid regex: ${err instanceof Error ? err.message.replace(/^Invalid regular expression: /, "") : String(err)}`;
  }
  if (re.test("")) return "This pattern matches everything. Narrow it, or turn the rule off instead.";
  if (isPathologicalPattern(pattern)) return "This pattern nests repeats (like (a+)+), which Doorman refuses to run.";
  return undefined;
}

function describeScope(rule: ScopedIgnoreRule, nowMs: number, home: string): string {
  const where = rule.cwd_prefix ? tilde(rule.cwd_prefix, home) : "everywhere";
  if (!rule.expires_at) return where;
  const at = Date.parse(rule.expires_at);
  return at <= nowMs ? `${where} · expired` : `${where} · until ${rule.expires_at.slice(0, 10)}`;
}

const exceptionsList: CliCommand = {
  name: "exceptions",
  summary: "Exceptions: sightings matching one of these are not raised",
  notes: ["Numbers in the first column are what `doorman exceptions remove` takes."],
  examples: [
    ["doorman exceptions", "every exception, numbered"],
    ["doorman exceptions remove 2", "drop the second one"],
  ],
  async run(ctx) {
    const ignore = ctx.prefs().policy.ignore;
    const nowMs = ctx.io.now();
    const s = ctx.style;
    const data = {
      exceptions: ignore.map((rule, i) => ({
        number: i + 1,
        ...rule,
        expired: rule.expires_at !== undefined && Date.parse(rule.expires_at) <= nowMs,
      })),
    };
    if (ignore.length === 0) return { data, text: ["No exceptions.", ctx.ui.next("`doorman exceptions add <rule|any> <pattern>` adds one.")] };
    return {
      data,
      text: [
        ctx.ui.section("Exceptions"),
        ...ctx.ui.table(
          ["#", "Rule", "Pattern", "Scope", "From"],
          ignore.map((rule, i) => {
            const scope = describeScope(rule, nowMs, ctx.io.home);
            return [
              String(i + 1),
              rule.detector ?? "any rule",
              rule.pattern,
              scope.endsWith("expired") ? s.dim(scope) : scope,
              `${rule.origin === "approval" ? "approval" : "you"}${rule.note ? s.dim(` · ${rule.note}`) : ""}`,
            ];
          }),
          { indent: 2, keep: [0, 1] },
        ),
      ],
    };
  },
};

const exceptionsAdd: CliCommand = {
  name: "exceptions add",
  summary: "Add an exception for one rule (or any rule), everywhere or in one project",
  usage: "<rule|any> <pattern> [--project <dir>] [--days <n>] [--note <text>]",
  notes: [
    "<pattern> is a case-insensitive regex over the sighting's visible fields: rule id, key name, tool, target and the masked excerpt. Never the raw value.",
  ],
  flags: [
    ["--project <dir>", "only for tool calls under this directory (default: everywhere)"],
    ["--days <n>", "expire after n days (the approval panel uses 30; default: never)"],
    ["--note <text>", "why, shown in the list"],
  ],
  examples: [
    ["doorman exceptions add secret_egress 'api\\.internal' --project .", "one rule, this project only"],
    ["doorman exceptions add any npm --days 30 --note 'registry token'", "every rule, for 30 days"],
  ],
  options: { project: { type: "string" }, days: { type: "string" }, note: { type: "string" } },
  positionals: { min: 2, max: 2 },
  async run(ctx, args) {
    const [ruleArg, rawPattern] = args.positionals as [string, string];
    const pattern = rawPattern.trim();
    const problem = pattern === "" ? "Write the pattern." : patternProblem(pattern);
    if (problem) throw new CliError(problem, 2);
    const raw: Record<string, unknown> = { pattern, origin: "manual" };
    if (ruleArg !== "any") {
      if (!KNOWN_IGNORE_SCOPES.has(ruleArg) && !ruleArg.startsWith("custom:")) {
        throw new CliError(`Unknown rule "${ruleArg}".`, 2, 'Use a rule id from `doorman rules`, a custom:<id>, or "any".');
      }
      raw.detector = ruleArg;
    }
    const project = args.values.project;
    if (typeof project === "string") {
      if (project.trim() === "") throw new CliError("--project needs a directory.", 2);
      raw.cwd_prefix = resolve(project.trim()).replace(/\/+$/, "") || "/";
    }
    const days = args.values.days;
    if (typeof days === "string") {
      const n = Number(days);
      if (!Number.isInteger(n) || n <= 0) throw new CliError("--days takes a whole number of days.", 2);
      raw.expires_at = new Date(ctx.io.now() + n * 86_400_000).toISOString();
    }
    if (typeof args.values.note === "string" && args.values.note.trim() !== "") raw.note = args.values.note.trim();
    const rule = parseIgnoreRule(raw);
    if (!rule) throw new CliError("That exception can't be saved.", 2);
    // rules:ignore-add
    const { prefs, syncError } = savePrefs(ctx, "Add an exception", (current) => ({
      policy: { ...current.policy, ignore: [...current.policy.ignore, { ...rule, origin: rule.origin ?? ("manual" as const) }] },
    }));
    const number = prefs.policy.ignore.length;
    return {
      data: { number, exception: prefs.policy.ignore[number - 1], ...(syncError ? { sync_error: syncError } : {}) },
      text: [
        ctx.ui.mark("ok", `Exception ${number}: ${rule.detector ? localDetectorLabel(rule.detector) : "any rule"} matching /${rule.pattern}/i, ${describeScope(rule, ctx.io.now(), ctx.io.home)}.`),
        ctx.style.dim("It applies from the next scan and the next tool call. Sightings already raised stay until you review them."),
        ...syncNote(ctx, syncError),
      ],
    };
  },
};

const exceptionsRemove: CliCommand = {
  name: "exceptions remove",
  summary: "Remove an exception by its number in `doorman exceptions`",
  usage: "<number>",
  examples: [["doorman exceptions remove 1", "the first one in `doorman exceptions`"]],
  positionals: { min: 1, max: 1 },
  async run(ctx, args) {
    const n = Number(args.positionals[0]);
    const count = ctx.prefs().policy.ignore.length;
    if (!Number.isInteger(n) || n < 1 || n > count) {
      throw new CliError(
        count === 0 ? "There are no exceptions." : `No exception ${args.positionals[0]}. Pick a number from 1 to ${count}.`,
        2,
        count === 0 ? undefined : "`doorman exceptions` lists them.",
      );
    }
    let removed: ScopedIgnoreRule | undefined;
    // rules:ignore-remove
    const { syncError } = savePrefs(ctx, "Remove an exception", (current) => {
      removed = current.policy.ignore[n - 1];
      return { policy: { ...current.policy, ignore: current.policy.ignore.filter((_, i) => i !== n - 1) } };
    });
    return {
      data: { removed, ...(syncError ? { sync_error: syncError } : {}) },
      text: [ctx.ui.mark("off", `Removed exception ${n}: ${removed?.detector ?? "any rule"} /${removed?.pattern ?? ""}/i.`), ...syncNote(ctx, syncError)],
    };
  },
};

export const exceptionsCommands: CliCommand[] = [exceptionsList, exceptionsAdd, exceptionsRemove];
