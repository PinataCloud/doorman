/**
 * Which shipped rules the app SHOWS.
 *
 * The app is narrowed to one job — sensitive-information exposure —
 * so the UX of that one thing can be got right before anything is added
 * back. Every rule outside it is hidden rather than deleted: the detectors
 * still run and their findings still land in the local ledger
 * (capture.ts `ledger`, findings.jsonl), but nothing a person or a connected
 * agent can reach names them — not the Guardrails list, not a count, not a
 * banner, not a hold, not the report, not the MCP tool's answers.
 *
 * This file is the ONE place that decision lives. The two choke points that
 * consume it are `ALL_DETECTORS` (guard/policy.ts — the rule catalog every
 * "which rules exist" surface reads) and `CaptureEngine.shownFindings()`
 * (capture.ts — the findings every "what was found" surface reads). The
 * renderer carries a mirror of `HIDDEN_RULES` in components.jsx because it is
 * a separate no-import bundle; test/rule-scope.test.ts pins the two
 * lists equal.
 *
 * Kept (the "sensitive info" families):
 *   · credentials & secrets   · crypto wallets & keys   · personal data
 *   (The guard's own integrity alert, `guard_tampered`, was kept at first and
 *   then hidden with its family on 2026-09-21 — the Settings integrity row
 *   still reports the guard's state; it is the Radar card that goes.)
 *
 * Hidden (feature-flagged out, per the proposal):
 *   · infrastructure & destructive   · code & agent config
 *   · exfiltration & hidden content  · MCP servers   · licensing
 *
 * Bringing a family back is a matter of deleting its ids from this set; no
 * other file needs to know.
 */

export const HIDDEN_RULES: ReadonlySet<string> = new Set([
  // Infrastructure & destructive
  "destructive_command",
  "infra_mutation",
  "unsafe_fetch_exec",
  "security_control_disabled",
  "flow_fetch_then_exec",
  "flow_fetch_then_install",
  "flow_sql_second_order",
  "agent_loop",
  // Code & agent config
  "insecure_code_written",
  "guard_tampered",
  "flow_insecure_code_executed",
  "agent_config_tamper",
  // Exfiltration & hidden content
  "exfil_render_link",
  "invisible_unicode",
  "injected_instruction",
  "flow_injection_followed",
  "flow_read_then_send",
  "egress_new_destination",
  // MCP servers
  "mcp_tool_poisoning",
  "mcp_tool_changed",
  "unknown_mcp_server",
  "mcp_permission",
  // Licensing
  "license_contamination",
]);

/**
 * The shipped rule PACKS the app hides — the same decision along the packs'
 * own axis. A pack is a bundle of custom-format rules, so its rules never sat
 * in a detector family; the ones outside sensitive-information exposure are
 * hidden here instead. Read by guard/rule-packs.ts, which narrows RULE_PACKS
 * at its definition: a hidden pack is not offered, not enabled and contributes
 * no rule to the policy, so it "does not exist except in code".
 *
 * Kept: `crypto_operations` (fund transfers, wallet key exports, exchange
 * API keys — the wallets family's pack).
 */
export const HIDDEN_RULE_PACKS: ReadonlySet<string> = new Set([
  "publish_actions", // Publish & outward pushes
  "external_recipients", // Messages to external recipients
  "container_privilege", // Privileged containers
  "privilege_escalation", // Privilege escalation
]);

/** Whether a shipped rule pack is one the app shows. */
export function rulePackShown(packId: string): boolean {
  return !HIDDEN_RULE_PACKS.has(packId);
}

/** Whether a rule id is one the app shows. A person's own `custom:` rules are
 * always theirs to see. */
export function ruleShown(id: string): boolean {
  return !HIDDEN_RULES.has(id);
}

/** A detector list with the hidden ids dropped, order kept. */
export function shownRules<T extends string>(ids: readonly T[]): T[] {
  return ids.filter((id) => ruleShown(id));
}

/** A per-detector record with the hidden keys dropped. */
export function shownRecord<K extends string, V>(record: Readonly<Partial<Record<K, V>>>): Partial<Record<K, V>> {
  const out: Partial<Record<K, V>> = {};
  for (const [id, value] of Object.entries(record) as [K, V][]) if (ruleShown(id)) out[id] = value;
  return out;
}
