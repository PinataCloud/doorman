/**
 * Pure helpers for the hold-and-confirm flow — the wording of a held call, the
 * notification de-duplication and what an answer does to the policy. They
 * live in lib/ (no electron import) so the app and `doorman watch` answer a
 * held call the same way, and so they are testable from the repo root: what a
 * banner says about a blocked session is behaviour, not decoration.
 */

import type { ApprovalRequest, ApprovalVerdict } from "../guard/handshake.js";
import { ALL_DETECTORS, type GuardPolicy, type ScopedIgnoreRule } from "../guard/policy.js";
import type { SecurityDetectorId } from "../guard/security-detect.js";
import { classifyDestination, extractHosts } from "./egress-intel.js";
import { localDetectorLabel } from "./findings.js";
import type { FindingRow } from "./findings.js";
import { riskProfileFor } from "./mcp-inventory.js";

/** Labels over the WIDE id set: a hold raised by the armed-session escalation
 * names `flow_injection_followed`, which DETECTOR_LABELS doesn't know, and a
 * custom rule's label travels on the request itself. */
const label = (request: ApprovalRequest, d: string): string => localDetectorLabel(d, request.detector_labels);

/** Just the rules, for a notification subtitle: "Infrastructure mutation". */
export function approvalRules(request: ApprovalRequest): string {
  const rules = request.detectors.map((d) => label(request, d));
  return rules.length > 0 ? rules.join(", ") : "Security policy";
}

/** What the held call is: its risky part when the guard named one
 * (`curl → webhook.site`), else the tool and its target (`Bash → rm`). */
export function approvalWhere(request: ApprovalRequest): string {
  return request.call_name ?? [request.tool_name, request.target].filter(Boolean).join(" → ");
}

/** One line describing what is being held: "Destructive command · Bash → rm". */
export function approvalSummary(request: ApprovalRequest): string {
  const rules = request.detectors.map((d) => label(request, d));
  const what = rules.length > 0 ? rules.join(", ") : "Security policy";
  const where = approvalWhere(request);
  return where ? `${what} · ${where}` : what;
}

/**
 * Drop the findings that a pending approval is already banner-ing about. The
 * guard records the detection BEFORE it holds, so without this a held call
 * arrives as two notifications a fraction of a second apart — one asking for a
 * decision, one announcing the thing the decision is about.
 */
export function suppressHeldFindings(
  rows: readonly FindingRow[],
  pending: readonly ApprovalRequest[],
): FindingRow[] {
  if (pending.length === 0) return [...rows];
  return rows.filter(
    (row) =>
      !pending.some(
        (request) =>
          // Widened compare: a row's detector may be radar-only (flow_*),
          // which a guard hold can never name — the include is simply false.
          request.session_id === row.session_id &&
          (request.detectors as readonly string[]).includes(row.detector),
      ),
  );
}

/** Regex-escape a masked key name for an ignore pattern. */
function escapeRegex(text: string): string {
  return text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/** How long a project-scoped allow lives before it has to be re-earned. */
export const SCOPED_ALLOW_DAYS = 30;

/**
 * The ignore rules an "Allow for this project" answer writes: one per
 * (detector, key) pair behind the hold, anchored to the call's working
 * directory and dated to expire. Nothing here carries a value — the pattern is
 * the masked key name the detector already exposed on the card. Empty when the
 * request has no directory to scope to, or names only ids the policy can't
 * carry (a flow rule, a custom rule — those have their own controls).
 */
export function scopedIgnoreRulesFor(
  request: ApprovalRequest,
  now: Date = new Date(),
  allowedDetectors: readonly string[],
): ScopedIgnoreRule[] {
  const cwd = request.cwd?.trim();
  if (!cwd) return [];
  const expires = new Date(now.getTime() + SCOPED_ALLOW_DAYS * 86_400_000).toISOString();
  const keys: { detector: string; key_name?: string }[] =
    request.held_keys && request.held_keys.length > 0
      ? request.held_keys
      : request.detectors.map((detector) => ({ detector }));
  const out: ScopedIgnoreRule[] = [];
  const seen = new Set<string>();
  for (const key of keys) {
    if (!allowedDetectors.includes(key.detector)) continue;
    const name = key.key_name?.trim();
    // Anchored on the KEY NAME'S OWN POSITION. The shared matcher tests one
    // haystack, `detector key_name tool target excerpt`, so `^detector key ` can
    // only be satisfied by the finding's key — never by the same words showing
    // up in the agent-authored excerpt or target (a `# .env file → host`
    // comment on a different exfiltration). With no key the rule covers the
    // detector for this directory outright (still dated, still scoped) —
    // `[\s\S]` matches any finding text while never matching the empty string
    // the shared matcher refuses.
    const pattern = name ? `^${escapeRegex(key.detector)} ${escapeRegex(name)}(?: |$)` : "[\\s\\S]";
    const id = `${key.detector}|${pattern}`;
    if (seen.has(id)) continue;
    seen.add(id);
    out.push({
      detector: key.detector as ScopedIgnoreRule["detector"],
      pattern,
      cwd_prefix: cwd,
      expires_at: expires,
      origin: "approval",
      note: `Allowed from the approval panel · ${request.tool_name ?? "tool"}${request.target ? ` → ${request.target}` : ""}`,
    });
  }
  return out;
}

/**
 * What answering a held call does to the policy, computed before the verdict
 * is written. Policy first, verdict second: "allow and stop asking" and "allow
 * for this project" must not race the next tool call in the same session back
 * into a hold. `silence` drops the request's detectors to observe; a project
 * allow adds the dated ignore rules of scopedIgnoreRulesFor. `policy` is the
 * input object itself when nothing changes (and always when the request is
 * gone), so the caller writes and syncs only on a real change.
 */
export function approvalPolicyChange(
  policy: GuardPolicy,
  request: ApprovalRequest | undefined,
  verdict: ApprovalVerdict,
  options: { silence: boolean; scope: "project" | undefined },
  now: Date = new Date(),
): { policy: GuardPolicy; silenced: SecurityDetectorId[]; scoped: number } {
  if (!request) return { policy, silenced: [], scoped: 0 };
  const silenced = options.silence
    ? request.detectors.filter((d): d is SecurityDetectorId => (ALL_DETECTORS as readonly string[]).includes(d))
    : [];
  let next = policy;
  if (silenced.length > 0) {
    const modes = { ...next.modes };
    for (const detector of silenced) modes[detector] = "observe";
    next = { ...next, modes };
  }
  let scoped = 0;
  if (verdict === "allow" && options.scope === "project") {
    const rules = scopedIgnoreRulesFor(request, now, ALL_DETECTORS as readonly string[]);
    if (rules.length > 0) {
      next = { ...next, ignore: [...next.ignore, ...rules] };
      scoped = rules.length;
    }
  }
  return { policy: next, silenced, scoped };
}

/** A one-line "where does this go?" note for a held call — the egress
 * destination's class, or an MCP server's risk profile — so the approval card
 * can be an informed decision (idea #9). Display-only, computed from the
 * already-redacted request. Undefined when nothing notable applies. */
export function approvalContextNote(request: ApprovalRequest): string | undefined {
  const mcp = /^mcp__([^_]+(?:_[^_]+)*?)__/.exec(request.tool_name ?? "");
  const server = request.server ?? mcp?.[1];
  if (server) {
    const risk = riskProfileFor(server);
    const cls = request.tool_class ? ` · ${request.tool_class} call` : "";
    if (risk) return `MCP · ${risk.vendor} ${risk.kind}${cls} — ${risk.note}`;
    if (request.source === "mcp-gateway") return `MCP · ${server}${cls} — no risk profile for this server.`;
  }
  // The longer copy when the guard cut the preview: the destination is often
  // the tail of a long chain.
  const hosts = extractHosts(`${request.target ?? ""}\n${request.preview_full ?? request.preview ?? ""}`);
  if (hosts.length > 0) {
    const p = classifyDestination(hosts[0]!);
    return `Destination: ${hosts[0]} — ${p.label}. ${p.note}`;
  }
  return undefined;
}

export function withApprovalContext(requests: readonly ApprovalRequest[]): ApprovalRequest[] {
  return requests.map((r) => {
    const note = approvalContextNote(r);
    return note ? { ...r, context_note: note } : r;
  });
}
