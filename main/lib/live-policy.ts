import type { GuardPolicy } from "../guard/policy.js";
import { packRules } from "../guard/rule-packs.js";
import type { Prefs } from "../state.js";
import { applyPolicyEnv } from "./policy-env.js";

/**
 * The policy the guard actually enforces, folded from the person's prefs —
 * shared by the app and the CLI so both write the same `policy.json`.
 *
 * - The model-assisted rules (injection classifier, credential second opinion)
 *   left Settings on 2026-09-05; the environment is their only knob now, laid
 *   over whatever the prefs file still says (lib/policy-env.ts).
 * - The shipped packs the person has on, with their own rules layered over (an
 *   edited copy of a pack rule — same id — replaces the shipped one). One list
 *   reaches the guard; the split is a prefs concern, not a policy one.
 * - The person's own recognized MCP servers are unioned into the approved list,
 *   so `unknown_mcp_server` has a local opinion. A case-insensitive de-dupe
 *   keeps `GitHub`/`github` one.
 */
export function livePolicy(
  prefs: Pick<Prefs, "policy" | "rule_packs_enabled" | "mcp_recognized">,
  env: NodeJS.ProcessEnv = process.env,
): GuardPolicy {
  const { custom_rules: _shipped, ...policy } = applyPolicyEnv(prefs.policy, env);
  const own = prefs.policy.custom_rules ?? [];
  const ownIds = new Set(own.map((r) => r.id));
  const fromPacks = packRules(prefs.rule_packs_enabled ?? []).filter((r) => !ownIds.has(r.id));
  const customRules = [...fromPacks, ...own];
  const withRules: GuardPolicy = customRules.length > 0 ? { ...policy, custom_rules: customRules } : policy;
  const recognized = prefs.mcp_recognized ?? [];
  if (recognized.length === 0) return withRules;
  const seen = new Set((withRules.approved_mcp_servers ?? []).map((s) => s.toLowerCase()));
  const merged = [...(withRules.approved_mcp_servers ?? [])];
  for (const server of recognized) {
    if (!seen.has(server.toLowerCase())) {
      seen.add(server.toLowerCase());
      merged.push(server);
    }
  }
  return { ...withRules, approved_mcp_servers: merged };
}
