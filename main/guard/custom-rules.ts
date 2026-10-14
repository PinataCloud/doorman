/**
 * Custom rules — the one Invariant Guardrails idea this product had never
 * taken: a rule the PERSON writes. Invariant's policy language is Python
 * (`raise "…" if: (call: ToolCall) -> (call2: ToolCall); call is tool:x({to:
 * ".*@(?!ours)"})`), and executing user Python inside a PreToolUse hook is
 * exactly the reason its engine was rejected. This keeps the SHAPE —
 * tool name, per-field argument patterns, a command pattern, an optional
 * preceding taint, a scope — and none of the execution: every clause is a
 * regular expression, compiled once, size-capped, with pathological shapes
 * refused before they ever see input.
 *
 * Two halves, one format:
 *  · `when` — evaluated HERE, at PreToolUse, by the guard: what the call is.
 *  · `after` — evaluated by the app's flow engine (lib/flow-rules.ts) over the
 *    session's ordered calls: what the call FOLLOWS. Radar-only by default,
 *    like every other flow rule; the injection taint is the one that can also
 *    arm the guard's next-call escalation (armed.ts), so a `when` + `after:
 *    injection` rule is enforceable in the same best-effort way.
 *
 * Custom ids live in the `custom:` namespace so they can never shadow a
 * shipped detector.
 *
 * Self-containment rule: this directory is copied verbatim to userData and run
 * with plain `node`; nothing here may import from outside main/guard/.
 */

import type { EnforcementMode } from "./policy.js";
import { redact } from "./redact.js";
import { isPathologicalPattern, sanitizeExcerpt, type SecuritySeverity } from "./security-detect.js";

export const CUSTOM_ID_PREFIX = "custom:";
export type CustomDetectorId = `custom:${string}`;

/** The taint vocabulary a rule's `after` may name — lib/flow-rules.ts' kinds. */
export type CustomTaintKind = "secret" | "injection" | "untrusted_fetch" | "private_data" | "sql_result";
export const CUSTOM_TAINT_KINDS: readonly CustomTaintKind[] = [
  "secret",
  "injection",
  "untrusted_fetch",
  "private_data",
  "sql_result",
];

export interface CustomRuleWhen {
  /** Regex over the tool name (`^mcp__slack__send`, `^Bash$`). */
  tool?: string;
  /** Regex over the command string of a shell call. */
  command?: string;
  /** Regex over the MCP server segment of `mcp__<server>__<tool>`. */
  server?: string;
  /** Regex over the call's target (a Bash program name or a file path). */
  target?: string;
  /** Field → regex over that argument's string value. Dotted paths reach
   * nested fields (`params.to`). Every listed field must match. */
  arg?: Record<string, string>;
}

export interface CustomRule {
  /** `[a-z0-9][a-z0-9_-]{0,47}` — becomes `custom:<id>`. */
  id: string;
  label: string;
  blurb?: string;
  severity: SecuritySeverity;
  mode: EnforcementMode;
  /** Absent = enabled. */
  enabled?: boolean;
  when?: CustomRuleWhen;
  after?: { taint: CustomTaintKind };
  /** Only applies to calls whose working directory starts with this prefix. */
  scope?: { cwd_prefix?: string };
  /** Set on rules copied in from a shipped pack (rule-packs.ts). */
  pack?: string;
}

/** What a `when` match produces — the same shape a detector finding has, plus
 * the mode the rule asked for (a custom finding carries its own posture; the
 * per-detector `modes` map never knows it). */
export interface CustomRuleFinding {
  detector: CustomDetectorId;
  label: string;
  severity: SecuritySeverity;
  mode: EnforcementMode;
  key_name: string;
  excerpt: string;
  occurrences: number;
  tool_name?: string;
  target?: string;
}

export const CUSTOM_RULES_MAX = 64;
export const CUSTOM_PATTERN_MAX_CHARS = 400;
const CUSTOM_ID_RE = /^[a-z0-9][a-z0-9_-]{0,47}$/;
const LABEL_MAX = 80;
const BLURB_MAX = 240;
/** Cap on any single string a custom pattern is tested against. */
const MATCH_INPUT_MAX = 64_000;
const EXCERPT_MAX = 200;

export function customDetectorId(id: string): CustomDetectorId {
  return `${CUSTOM_ID_PREFIX}${id}`;
}

export function isCustomDetectorId(id: string): id is CustomDetectorId {
  return id.startsWith(CUSTOM_ID_PREFIX);
}

/** The pathological-shape refusal now lives in the shared detector module, so
 * the ignore-rule matcher and this engine apply the identical test. */
export { isPathologicalPattern } from "./security-detect.js";

/** Compile one clause, or undefined when it is unsafe or invalid. */
export function compileClause(pattern: unknown): RegExp | undefined {
  if (typeof pattern !== "string" || pattern === "" || pattern.length > CUSTOM_PATTERN_MAX_CHARS) return undefined;
  if (isPathologicalPattern(pattern)) return undefined;
  try {
    const re = new RegExp(pattern, "i");
    // A clause that matches the empty string matches everything — a typo, not
    // a rule, and as a `when` it would hold every tool call on the machine.
    if (re.test("")) return undefined;
    return re;
  } catch {
    return undefined;
  }
}

/** Why a rule was rejected, for the editor to say. */
export interface CustomRuleProblem {
  id?: string;
  field: string;
  message: string;
}

/**
 * Validate one raw rule object. Returns the normalized rule or the problems —
 * never throws, never keeps a clause it could not compile (a rule with a bad
 * clause is dropped whole rather than silently widened).
 */
export function validateCustomRule(raw: unknown): { ok: true; rule: CustomRule } | { ok: false; problems: CustomRuleProblem[] } {
  const problems: CustomRuleProblem[] = [];
  if (!raw || typeof raw !== "object") return { ok: false, problems: [{ field: "rule", message: "not an object" }] };
  const r = raw as Record<string, unknown>;
  const id = typeof r.id === "string" ? r.id.trim() : "";
  if (!CUSTOM_ID_RE.test(id)) problems.push({ id, field: "id", message: "id must be 1–48 lowercase letters, digits, - or _" });
  const label = typeof r.label === "string" ? r.label.trim().slice(0, LABEL_MAX) : "";
  if (label === "") problems.push({ id, field: "label", message: "a label is required" });
  const severity = r.severity;
  if (severity !== "critical" && severity !== "high" && severity !== "medium" && severity !== "low") {
    problems.push({ id, field: "severity", message: "severity must be critical, high, medium or low" });
  }
  const mode = r.mode;
  if (mode !== "observe" && mode !== "warn" && mode !== "ask" && mode !== "block") {
    problems.push({ id, field: "mode", message: "mode must be observe, warn, ask or block" });
  }

  let when: CustomRuleWhen | undefined;
  if (r.when !== undefined) {
    if (!r.when || typeof r.when !== "object") {
      problems.push({ id, field: "when", message: "when must be an object" });
    } else {
      const w = r.when as Record<string, unknown>;
      when = {};
      for (const key of ["tool", "command", "server", "target"] as const) {
        if (w[key] === undefined || w[key] === "") continue;
        if (!compileClause(w[key])) problems.push({ id, field: `when.${key}`, message: "not a safe, valid pattern" });
        else when[key] = w[key] as string;
      }
      if (w.arg !== undefined) {
        if (!w.arg || typeof w.arg !== "object" || Array.isArray(w.arg)) {
          problems.push({ id, field: "when.arg", message: "arg must map field names to patterns" });
        } else {
          const arg: Record<string, string> = {};
          for (const [field, pattern] of Object.entries(w.arg as Record<string, unknown>)) {
            if (field.trim() === "" || field.length > 80) continue;
            if (!compileClause(pattern)) problems.push({ id, field: `when.arg.${field}`, message: "not a safe, valid pattern" });
            else arg[field] = pattern as string;
          }
          if (Object.keys(arg).length > 0) when.arg = arg;
        }
      }
      if (Object.keys(when).length === 0) problems.push({ id, field: "when", message: "when needs at least one clause" });
    }
  }

  let after: CustomRule["after"];
  if (r.after !== undefined) {
    const taint = (r.after as { taint?: unknown } | null)?.taint;
    if ((CUSTOM_TAINT_KINDS as readonly unknown[]).includes(taint)) after = { taint: taint as CustomTaintKind };
    else problems.push({ id, field: "after.taint", message: `taint must be one of ${CUSTOM_TAINT_KINDS.join(", ")}` });
  }
  if (when === undefined) {
    // An `after` alone would make every later call a finding — the taint says
    // what happened before, the `when` says what THIS call is; a rule needs both
    // halves to describe a flow, and at least the `when` to describe a call.
    problems.push({
      id,
      field: "when",
      message: after === undefined ? "a rule needs a when clause" : "an after clause needs a when clause naming the later call",
    });
  }

  let scope: CustomRule["scope"];
  if (r.scope && typeof r.scope === "object") {
    const prefix = (r.scope as { cwd_prefix?: unknown }).cwd_prefix;
    if (typeof prefix === "string" && prefix.trim() !== "") scope = { cwd_prefix: prefix.trim() };
  }

  if (problems.length > 0) return { ok: false, problems };
  const rule: CustomRule = {
    id,
    label,
    severity: severity as SecuritySeverity,
    mode: mode as EnforcementMode,
    ...(typeof r.blurb === "string" && r.blurb.trim() !== "" ? { blurb: r.blurb.trim().slice(0, BLURB_MAX) } : {}),
    ...(r.enabled === false ? { enabled: false } : {}),
    ...(when === undefined ? {} : { when }),
    ...(after === undefined ? {} : { after }),
    ...(scope === undefined ? {} : { scope }),
    ...(typeof r.pack === "string" && r.pack !== "" ? { pack: r.pack } : {}),
  };
  return { ok: true, rule };
}

/** Parse an untrusted array off disk: invalid rules are dropped, ids de-duped
 * (first wins), the list capped. Never throws. */
export function parseCustomRules(raw: unknown): CustomRule[] {
  if (!Array.isArray(raw)) return [];
  const out: CustomRule[] = [];
  const seen = new Set<string>();
  for (const item of raw) {
    if (out.length >= CUSTOM_RULES_MAX) break;
    const result = validateCustomRule(item);
    if (!result.ok || seen.has(result.rule.id)) continue;
    seen.add(result.rule.id);
    out.push(result.rule);
  }
  return out;
}

/** What the guard knows about one call, shaped for matching. */
export interface CustomRuleInput {
  tool_name?: string;
  tool_input?: unknown;
  /** The command string, if this is a shell call (already extracted by the caller). */
  command?: string;
  target?: string;
  cwd?: string;
  /** The redacted text an excerpt may be built from. */
  redacted: string;
}

interface Compiled {
  rule: CustomRule;
  tool?: RegExp;
  command?: RegExp;
  server?: RegExp;
  target?: RegExp;
  arg?: Array<[string, RegExp]>;
}

const MCP_SERVER_RE = /^mcp__([^_]+(?:_[^_]+)*?)__/;

function compile(rule: CustomRule): Compiled | undefined {
  if (!rule.when) return undefined;
  const c: Compiled = { rule };
  for (const key of ["tool", "command", "server", "target"] as const) {
    const pattern = rule.when[key];
    if (pattern === undefined) continue;
    const re = compileClause(pattern);
    if (!re) return undefined;
    c[key] = re;
  }
  if (rule.when.arg) {
    c.arg = [];
    for (const [field, pattern] of Object.entries(rule.when.arg)) {
      const re = compileClause(pattern);
      if (!re) return undefined;
      c.arg.push([field, re]);
    }
  }
  return c;
}

/** A dotted-path read into the tool input; arrays are joined for matching. */
function argValue(input: unknown, path: string): string | undefined {
  let node: unknown = input;
  for (const part of path.split(".")) {
    if (!node || typeof node !== "object") return undefined;
    node = (node as Record<string, unknown>)[part];
  }
  if (node === undefined || node === null) return undefined;
  if (typeof node === "string") return node;
  if (typeof node === "number" || typeof node === "boolean") return String(node);
  if (Array.isArray(node)) return node.map((v) => (typeof v === "string" ? v : JSON.stringify(v))).join("\n");
  try {
    return JSON.stringify(node);
  } catch {
    return undefined;
  }
}

const cap = (s: string): string => (s.length > MATCH_INPUT_MAX ? s.slice(0, MATCH_INPUT_MAX) : s);

export function ruleAppliesToCwd(rule: Pick<CustomRule, "scope">, cwd: string | undefined): boolean {
  const prefix = rule.scope?.cwd_prefix;
  if (!prefix) return true;
  if (!cwd) return false;
  return cwd === prefix || cwd.startsWith(prefix.endsWith("/") ? prefix : `${prefix}/`);
}

/**
 * Evaluate the `when` half of every enabled rule against one call. Rules with
 * only an `after` clause are the flow engine's; rules whose `when` fails to
 * compile are skipped (validateCustomRule already refused them, this is the
 * second lock). Pure.
 */
export function matchCustomRules(rules: readonly CustomRule[], input: CustomRuleInput): CustomRuleFinding[] {
  const out: CustomRuleFinding[] = [];
  const tool = input.tool_name ?? "";
  const server = MCP_SERVER_RE.exec(tool)?.[1];
  for (const rule of rules) {
    if (rule.enabled === false || !rule.when) continue;
    if (!ruleAppliesToCwd(rule, input.cwd)) continue;
    const c = compile(rule);
    if (!c) continue;
    let evidence: string | undefined;
    if (c.tool) {
      if (!c.tool.test(tool)) continue;
      evidence = tool;
    }
    if (c.server) {
      if (server === undefined || !c.server.test(server)) continue;
      evidence = evidence ?? tool;
    }
    if (c.target) {
      if (input.target === undefined || !c.target.test(cap(input.target))) continue;
      evidence = input.target;
    }
    if (c.command) {
      if (input.command === undefined) continue;
      const m = c.command.exec(cap(input.command));
      if (!m) continue;
      evidence = input.command;
    }
    if (c.arg) {
      let all = true;
      for (const [field, re] of c.arg) {
        const value = argValue(input.tool_input, field);
        if (value === undefined || !re.test(cap(value))) {
          all = false;
          break;
        }
        evidence = `${field}=${value}`;
      }
      if (!all) continue;
    }
    // A `when` + `after` rule needs the taint too — the guard has no taints of
    // its own; guard.ts pairs these with armed.ts for the injection case and
    // the flow engine does the rest. Reported here only when no `after`.
    if (rule.after) continue;
    out.push({
      detector: customDetectorId(rule.id),
      label: rule.label,
      severity: rule.severity,
      mode: rule.mode,
      key_name: rule.label,
      // Evidence may be a raw target or argument value (only `command` and
      // `redacted` arrive pre-redacted), and an excerpt is stored — the spool,
      // the approval preview, the Radar — so it is redacted here, at the one
      // place every custom and pack finding is built.
      excerpt: sanitizeExcerpt(collapse(redact(evidence ?? input.redacted))).slice(0, EXCERPT_MAX),
      occurrences: 1,
      ...(input.tool_name === undefined ? {} : { tool_name: input.tool_name }),
      ...(input.target === undefined ? {} : { target: input.target }),
    });
  }
  return out;
}

/**
 * Does this call satisfy a rule's `when` at all (ignoring `after`)? The flow
 * engine and the armed escalation both ask this about a candidate SINK.
 */
export function customWhenMatches(rule: CustomRule, input: CustomRuleInput): boolean {
  if (!rule.when) return false;
  const probe: CustomRule = { ...rule, after: undefined };
  delete (probe as { after?: unknown }).after;
  return matchCustomRules([probe], input).length > 0;
}

function collapse(text: string): string {
  return text.replace(/\s+/g, " ").trim();
}

/** Labels for every custom detector id in a rule set — what the approval card,
 * the radar and the notifications read instead of DETECTOR_LABELS. */
export function customDetectorLabels(rules: readonly CustomRule[]): Record<string, string> {
  const out: Record<string, string> = {};
  for (const rule of rules) out[customDetectorId(rule.id)] = rule.label;
  return out;
}
