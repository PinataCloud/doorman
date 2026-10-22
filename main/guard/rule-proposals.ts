/**
 * Rule proposals — a custom rule an AGENT suggests, over Doorman's own MCP
 * server (mcp/doorman-mcp.ts doorman_propose_rule), that nothing applies until
 * the person saves it: in the app (Guardrails → Your rules → Suggested by your
 * agents) or with `doorman custom-rules accept <id>`.
 *
 * Why a separate file per proposal instead of a list in policy.json: the
 * guard's policy is the person's, and an agent must never be able to reach it
 * — not even "temporarily, until reviewed". A proposal sits beside the policy
 * in `<guardDir>/proposals/<id>.json`, read by nothing that enforces.
 *
 * A proposal may only ADD a rule. It can never change, switch off or replace
 * one the person has: an id that collides with a live rule (their own, or a
 * pack rule's `<pack>--<rule>` id) or with another pending proposal is refused,
 * as is any id in a pack's `<pack>--` namespace even while that pack is off
 * (turned on later, the saved proposal would replace the shipped rule), and
 * so are `enabled: false` (a switched-off rule proposes nothing but a shadow)
 * and a `pack` field (only shipped packs set it). The checks run when the
 * agent proposes AND again when the person accepts — the live set may have
 * moved in between, and the accepted rule may have been edited.
 *
 * Self-containment rule: this directory is copied verbatim to userData and run
 * with plain `node`; nothing here may import from outside main/guard/.
 */

import { randomBytes } from "node:crypto";
import { existsSync, mkdirSync, readdirSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { validateCustomRule, type CustomRule, type CustomRuleProblem } from "./custom-rules.js";
import { hostLabel } from "./hosts/index.js";
import { RULE_PACK_IDS } from "./rule-packs.js";

export interface RuleProposal {
  id: string;
  /** ISO time the agent proposed it. */
  at: string;
  /** Who proposed it: a host's label ("Claude Code") or "An agent". */
  from: string;
  /** The working directory the agent said it was in, if any. */
  cwd?: string;
  /** Why, in the agent's words — one line, sanitized, capped. */
  reason: string;
  rule: CustomRule;
}

/** More pending than this and the agent is told to wait for the person: a
 * review queue nobody reads is not a review. */
export const RULE_PROPOSALS_MAX = 20;
export const PROPOSAL_REASON_MAX = 300;
const PROPOSAL_ID_RE = /^p-[a-z0-9]{6,32}$/;
const FROM_FALLBACK = "An agent";

export function proposalsDir(guardDir: string): string {
  return join(guardDir, "proposals");
}

/** Agent text the app and the CLI will print: no control or invisible format
 * characters, one line, capped. */
export function proposalLine(text: string, max: number): string {
  const flat = text.replace(/[\p{Cc}\p{Cf}\u2028\u2029]+/gu, " ").replace(/\s+/g, " ").trim();
  return flat.length > max ? `${flat.slice(0, max - 1)}…` : flat;
}

/**
 * MCP clients name themselves in `initialize` clientInfo — `claude-code`,
 * `codex-mcp-client`, `Visual Studio Code`, `cursor-vscode`… A name that maps
 * to a host Doorman knows gets that host's label; anything else is "An agent"
 * (the client's own string is not trusted to be a name worth showing).
 */
const CLIENT_ALIASES: ReadonlyArray<[RegExp, string]> = [
  [/^claude[-_ ]?(?:code|ai)?$/i, "claude-code"],
  [/^codex(?:[-_ ]mcp[-_ ]client)?$/i, "codex"],
  [/^(?:visual studio code|vscode|vs code)(?:[-_ ]insiders)?$/i, "vscode-copilot"],
  [/^(?:github[-_ ])?copilot(?:[-_ ]cli)?$/i, "copilot-cli"],
  [/^cursor(?:[-_ ]vscode)?$/i, "cursor"],
  [/^gemini(?:[-_ ]cli)?(?:[-_ ]mcp[-_ ]client)?$/i, "gemini-cli"],
  [/^qwen(?:[-_ ]code)?(?:[-_ ]mcp[-_ ]client)?$/i, "qwen-code"],
  [/^kimi(?:[-_ ]code)?$/i, "kimi-code"],
  [/^kiro(?:[-_ ]cli)?$/i, "kiro"],
  [/^(?:factory[-_ ])?droid$/i, "droid"],
  [/^goose$/i, "goose"],
  [/^opencode$/i, "opencode"],
  [/^crush$/i, "crush"],
  [/^hermes(?:[-_ ]agent)?$/i, "hermes"],
  [/^openclaw$/i, "openclaw"],
  [/^grok(?:[-_ ]build)?$/i, "grok-build"],
];

export function proposerLabel(clientName: string | undefined): string {
  const name = clientName?.trim();
  if (!name) return FROM_FALLBACK;
  for (const [re, source] of CLIENT_ALIASES) {
    if (re.test(name)) {
      const label = hostLabel(source);
      return label === source ? FROM_FALLBACK : label;
    }
  }
  return FROM_FALLBACK;
}

/**
 * Validate a proposed rule and refuse anything that would touch what the
 * person already has. `liveIds` is every rule id the guard runs (their own and
 * the enabled packs'); `pendingIds` the ids other proposals already claim.
 */
export function checkProposalRule(
  raw: unknown,
  liveIds: Iterable<string>,
  pendingIds: Iterable<string> = [],
): { ok: true; rule: CustomRule } | { ok: false; problems: CustomRuleProblem[] } {
  const result = validateCustomRule(raw);
  const r = raw && typeof raw === "object" ? (raw as Record<string, unknown>) : {};
  const problems: CustomRuleProblem[] = result.ok ? [] : [...result.problems];
  const id = typeof r.id === "string" ? r.id.trim() : "";
  if (id !== "") {
    if (new Set(liveIds).has(id)) {
      problems.push({ id, field: "id", message: "a rule with this id already exists; a proposal can only add a new rule, so pick another id" });
    } else if (new Set(pendingIds).has(id)) {
      problems.push({ id, field: "id", message: "another suggested rule already uses this id; pick another id" });
    } else if (RULE_PACK_IDS.some((pack) => id.startsWith(`${pack}--`))) {
      problems.push({ id, field: "id", message: "ids starting with a rule pack's name and -- belong to that pack; pick another id" });
    }
  }
  if (r.enabled === false) problems.push({ id, field: "enabled", message: "a proposed rule must be switched on (leave enabled out)" });
  if (r.pack !== undefined) problems.push({ id, field: "pack", message: "pack is set only on shipped rules; leave it out" });
  if (problems.length > 0 || !result.ok) return { ok: false, problems };
  return { ok: true, rule: result.rule };
}

/** One proposal off disk, or undefined for anything malformed. The rule is
 * validated again: the file is outside the policy, but its rule is what the
 * person will be shown and may save. */
function parseProposal(raw: unknown, fileId: string): RuleProposal | undefined {
  if (!raw || typeof raw !== "object") return undefined;
  const p = raw as Record<string, unknown>;
  if (p.id !== fileId || typeof p.at !== "string" || Number.isNaN(Date.parse(p.at))) return undefined;
  const rule = validateCustomRule(p.rule);
  if (!rule.ok || rule.rule.enabled === false || rule.rule.pack !== undefined) return undefined;
  return {
    id: fileId,
    at: p.at,
    from: typeof p.from === "string" && p.from.trim() !== "" ? proposalLine(p.from, 60) : FROM_FALLBACK,
    ...(typeof p.cwd === "string" && p.cwd !== "" ? { cwd: proposalLine(p.cwd, 400) } : {}),
    reason: typeof p.reason === "string" ? proposalLine(p.reason, PROPOSAL_REASON_MAX) : "",
    rule: rule.rule,
  };
}

/** Every readable proposal, newest first. Never throws. */
export function readProposals(guardDir: string): RuleProposal[] {
  let names: string[];
  try {
    names = readdirSync(proposalsDir(guardDir));
  } catch {
    return [];
  }
  const out: RuleProposal[] = [];
  for (const name of names) {
    if (!name.endsWith(".json")) continue;
    const id = name.slice(0, -".json".length);
    if (!PROPOSAL_ID_RE.test(id)) continue;
    try {
      const proposal = parseProposal(JSON.parse(readFileSync(join(proposalsDir(guardDir), name), "utf8")), id);
      if (proposal) out.push(proposal);
    } catch {
      // unreadable or half-written: skipped, never fatal
    }
  }
  return out.sort((a, b) => (a.at < b.at ? 1 : a.at > b.at ? -1 : a.id < b.id ? 1 : -1));
}

export function readProposal(guardDir: string, id: string): RuleProposal | undefined {
  if (!PROPOSAL_ID_RE.test(id)) return undefined;
  return readProposals(guardDir).find((p) => p.id === id);
}

export interface ProposeInput {
  rule: unknown;
  reason: string;
  from: string;
  cwd?: string;
  now?: Date;
}

/**
 * Check and store one proposal. Written to a temp file and renamed into
 * place, 0600, so a reader never sees half a proposal.
 */
export function saveProposal(
  guardDir: string,
  liveIds: Iterable<string>,
  input: ProposeInput,
): { ok: true; proposal: RuleProposal } | { ok: false; problems: CustomRuleProblem[] } {
  const reason = proposalLine(input.reason, PROPOSAL_REASON_MAX);
  if (reason === "") return { ok: false, problems: [{ field: "reason", message: "say in one line why this rule is worth having" }] };
  const pending = readProposals(guardDir);
  if (pending.length >= RULE_PROPOSALS_MAX) {
    return {
      ok: false,
      problems: [
        {
          field: "proposals",
          message: `${RULE_PROPOSALS_MAX} suggested rules are already waiting for the person's review; nothing more can be suggested until they save or dismiss some`,
        },
      ],
    };
  }
  const checked = checkProposalRule(input.rule, liveIds, pending.map((p) => p.rule.id));
  if (!checked.ok) return checked;
  const proposal: RuleProposal = {
    id: `p-${randomBytes(6).toString("hex")}`,
    at: (input.now ?? new Date()).toISOString(),
    from: proposalLine(input.from, 60) || FROM_FALLBACK,
    ...(input.cwd ? { cwd: proposalLine(input.cwd, 400) } : {}),
    reason,
    rule: checked.rule,
  };
  const dir = proposalsDir(guardDir);
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const path = join(dir, `${proposal.id}.json`);
  const tmp = `${path}.${process.pid}.tmp`;
  writeFileSync(tmp, `${JSON.stringify(proposal, null, 2)}\n`, { mode: 0o600 });
  renameSync(tmp, path);
  return { ok: true, proposal };
}

/**
 * The checks again, at the moment the person accepts: the rule as it is now
 * (perhaps edited in the wizard) against the live ids as they are now, and
 * against every OTHER pending proposal. The app and the CLI both call this,
 * then add the rule the way they add any rule of the person's own.
 */
export function checkAcceptedProposal(
  guardDir: string,
  proposalId: string,
  raw: unknown,
  liveIds: Iterable<string>,
): { ok: true; rule: CustomRule } | { ok: false; problems: CustomRuleProblem[] } {
  const pending = readProposals(guardDir);
  if (!pending.some((p) => p.id === proposalId)) return { ok: false, problems: [{ field: "proposal", message: "this suggestion is no longer waiting (saved or dismissed already)" }] };
  return checkProposalRule(raw, liveIds, pending.filter((p) => p.id !== proposalId).map((p) => p.rule.id));
}

/** Remove one proposal (accepted or dismissed). True when it was there. */
export function removeProposal(guardDir: string, id: string): boolean {
  if (!PROPOSAL_ID_RE.test(id)) return false;
  const path = join(proposalsDir(guardDir), `${id}.json`);
  if (!existsSync(path)) return false;
  rmSync(path, { force: true });
  return true;
}

/** What a rule fires on, in words — for the agent's confirmation and the CLI.
 * The renderer has its own (components.jsx describeCustomRule) in the same
 * words. */
export function describeRule(rule: CustomRule): string {
  const parts: string[] = [];
  const w = rule.when ?? {};
  if (w.tool) parts.push(`tool matches /${w.tool}/`);
  if (w.server) parts.push(`server matches /${w.server}/`);
  if (w.command) parts.push(`command matches /${w.command}/`);
  if (w.target) parts.push(`target matches /${w.target}/`);
  for (const [k, v] of Object.entries(w.arg ?? {})) parts.push(`${k} matches /${v}/`);
  const when = parts.length > 0 ? parts.join(", ") : "any call";
  const after = rule.after ? `, after a ${rule.after.taint.replace(/_/g, " ")} taint in the same session` : "";
  const scope = rule.scope?.cwd_prefix ? `, under ${rule.scope.cwd_prefix}` : "";
  return `Fires when ${when}${after}${scope}.`;
}
