/**
 * Enforcement policy: what the PreToolUse guard does per detector, and the
 * Claude Code/Codex hook-document surgery that installs/uninstalls the guard.
 *
 * Both agents expose synchronous PreToolUse hooks, so the same detector and
 * hold-and-confirm path protects both. Claude Code can fall back to its native
 * `ask` response when the app is unavailable; Codex cannot, so its host adapter
 * warns and continues instead. Direct block and an in-app allow/deny are
 * supported on both rails.
 *
 * The first-run default is NOT observe-everything: the five detectors that catch
 * a call you would want stopped before it runs (DEFAULT_MODES) ship on `ask`, so
 * installing the guard actually protects you rather than narrating. `ask` means
 * the guard HOLDS the call and the app asks — see handshake.ts and guard.ts.
 * Everything quieter, and everything that fires on prompts rather than tool
 * calls, stays observe.
 */

import type { SecurityDetectorId, SecuritySeverity, SecurityFinding } from "./security-detect.js";
import { DEFAULT_WALLET_CHAINS, WALLET_CHAINS, type WalletChain } from "./wallet-codec.js";
import { parseCustomRules, type CustomRule, type CustomRuleFinding } from "./custom-rules.js";
import { shownRecord, shownRules } from "./rule-scope.js";

/**
 * `warn` is the coaching rung between observe and ask: the call goes through
 * untouched (the guard prints nothing, same as allow), but the finding is
 * spooled as a WARN so the app raises a heads-up banner naming the rule and
 * the masked evidence. It exists because the jump from invisible (`observe`)
 * to a blocking countdown panel (`ask`) is the cliff that gets guards turned
 * off — warn is the posture you can leave on.
 */
export type EnforcementMode = "observe" | "warn" | "ask" | "block";

/** Severity ordering, canonical for both the guard's decision fold and the
 * app's notification threshold. Lives here (not lib/) because the guard
 * directory must stay self-contained — it is copied verbatim to userData. */
export const SEVERITY_RANK: Record<SecuritySeverity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
};

/**
 * What `ask` mode does. `interactive` is the whole point of the feature: the
 * guard holds the tool call open and Doorman asks, instead of handing the
 * question straight to the host's fallback (`ask` in Claude Code, a visible
 * fail-open warning in Codex) when `interactive: false` or the app is absent.
 *
 * `on_timeout` only applies while the app IS running and nobody answers —
 * that is a walked-away keyboard, so the default is `deny`. An app that isn't
 * running can't have been walked away from; that case falls through to the
 * host: a host with a native ask (Claude Code, Cursor, Copilot, …) gets the
 * question handed to it, and a host WITHOUT one is governed by `unattended`.
 *
 * `unattended` (2026-09-10) is what an `ask` becomes when NOBODY can answer it and the host cannot
 * ask on its own: the app is not running, vanished mid-hold, holding is off,
 * or the timeout fallback is `ask`. `deny` — the default — returns the host's
 * valid deny ("approval unavailable; not run") and tells the agent to ask the
 * person to open Doorman. `continue` is the pre-2026-09-10 behaviour: a
 * visible warning through the host's `warn()`, and the call runs. A prompt
 * hold (UserPromptSubmit) follows the same rule on every host, since no host
 * has a native ask for a prompt.
 */
export type UnattendedPolicy = "deny" | "continue";

export interface ConfirmPolicy {
  interactive: boolean;
  hold_seconds: number;
  on_timeout: "deny" | "ask";
  unattended: UnattendedPolicy;
}

/**
 * An ignore rule, optionally SCOPED. The shared detector module knows only
 * `{detector?, pattern}`; the two extra fields are this app's, and are applied
 * BEFORE the rules reach the detector (applicableIgnoreRules):
 *  · `cwd_prefix` — only calls whose working directory starts here. This is
 *    the "allow, and don't hold this again for THIS project" escape hatch
 *    from the approval panel, and the reason a false positive no longer has
 *    to be answered by switching a rule to observe everywhere.
 *  · `expires_at` — an ISO instant after which the rule is dead. A scoped
 *    allow is a decision about today's work, not a permanent exemption.
 * `origin` records how the rule came to exist, so the Rules screen can say
 * "from the approval panel" rather than presenting every rule as hand-written.
 */
export interface ScopedIgnoreRule {
  /** A guard detector, a radar-only id (KNOWN_IGNORE_SCOPES) or a `custom:` id. */
  detector?: SecurityDetectorId | string;
  pattern: string;
  cwd_prefix?: string;
  expires_at?: string;
  note?: string;
  origin?: "approval" | "manual";
}

/** What the MCP gateway may do with a class of tool on a server. `allow` is
 * the default everywhere — the gateway changes nothing until asked to. */
export type McpPermissionMode = "allow" | "ask" | "block";
export type McpToolClass = "read" | "write" | "act";
export const MCP_TOOL_CLASSES: readonly McpToolClass[] = ["read", "write", "act"];
export type McpPermissionSet = Partial<Record<McpToolClass, McpPermissionMode>>;

export interface GuardPolicy {
  version: 1;
  modes: Partial<Record<SecurityDetectorId, EnforcementMode>>;
  disabled: SecurityDetectorId[];
  ignore: ScopedIgnoreRule[];
  confirm: ConfirmPolicy;
  /**
   * The person's own rules (guard/custom-rules.ts), plus the rules of every
   * enabled shipped pack (guard/rule-packs.ts) — the app merges the two before
   * writing policy.json, so the guard reads one list.
   */
  custom_rules?: CustomRule[];
  /**
   * Per-server, per-class permissions the MCP GATEWAY enforces on `tools/call`
   * (gateway/mcp-gateway.ts) — read / write / act, each allow / ask / block.
   * Absent server or class = allow. The PreToolUse guard ignores this field
   * entirely; it rides the policy file so the gateway reads the same document.
   */
  mcp_permissions?: Record<string, McpPermissionSet>;
  /**
   * Gateway-side armed escalation (default ON): after a tool RESULT on a
   * gatewayed connection carried an injection, the next `tools/call` on that
   * same connection is held for confirmation. Exact rather than best-effort —
   * the gateway is in the stream — but MCP-only; Bash sinks stay with armed.ts.
   */
  mcp_armed_escalation?: boolean;
  /**
   * MCP servers the person has recognized. The GUARD ignores this entirely
   * — it rides the policy file only so the app's engine (which raises
   * `unknown_mcp_server`, a radar-only check over whole sessions) reads the
   * same document every other rule comes from. Absent or empty = no opinion.
   * The app writes the person's recognized servers into this list when it
   * writes policy.json (index.ts livePolicy).
   */
  approved_mcp_servers?: string[];
  /**
   * Armed-session escalation (default ON): when the app's flow engine has seen
   * an injected instruction arrive in this session's tool output (armed.json,
   * written next to this policy), the guard escalates the session's next
   * matching sink call (egress / exec / send / secret read) to `ask` — the
   * enforceable half of the radar-only `flow_injection_followed` rule. Best
   * effort by construction: the arming evidence travels transcript → engine →
   * armed.json, so a sink fired inside that latency window is not held.
   */
  armed_escalation?: boolean;
  /**
   * The local-model SECOND OPINION (guard/second-opinion.ts), default OFF. When
   * a hold or block is about to happen on one of the guessing detectors
   * (SECOND_OPINION_DETECTORS), the guard asks a small model on a LOOPBACK
   * endpoint whether the flagged value really is a credential. The answer can
   * only lower a finding's confidence — never raise one, never add one — so
   * with the model absent, slow or wrong the guard behaves exactly as without
   * it. Raw tool content goes to that endpoint and nowhere else, which is why a
   * non-loopback URL disables the feature rather than being honoured.
   */
  second_opinion?: SecondOpinionPolicy;
  /**
   * The injection CLASSIFIER (lib/injection-classifier.ts), default ON — but
   * inert until the person downloads the model (the ~82 MB fetch stays a
   * deliberate act in Settings). Absent-safe by construction, so "on with no
   * model" is exactly today's behaviour and costs nothing. Runs in
   * the app process over the transcript scan, never in this guard: a small
   * local model re-judges `injected_instruction` regex hits, and a hit it is
   * confidently benign about stops arming the next-call escalation and drops
   * to medium confidence on the Radar. Adjust-only — it can never raise a
   * finding — and the other two marker detectors (a zero-width character, a
   * rendered exfil link) are facts about the bytes it gets no vote on. Rides
   * the policy file so the app's engine and Settings read one document.
   */
  injection_classifier?: InjectionClassifierConfig;
  /**
   * The person's WALLETS: which
   * chains the address detector watches, what to do with an address that is
   * not theirs, and the addresses that ARE theirs — stored as salted hashes,
   * because this file sits in userData in plain text and a document listing
   * someone's wallets is itself the leak. Absent = the defaults
   * (defaultWallets()).
   */
  wallets?: WalletsPolicy;
}

// ── Wallets ──────────────────────────────────────────────────────────────────

export type WalletUnknownAddress = "observe" | "ignore";

export interface OwnWallet {
  /** walletAddressHash(salt, chain, address) — never the address. */
  hash: string;
  /** What the person called it ("cold storage"); the Radar shows this. */
  label: string;
  chain: WalletChain;
}

export interface WalletsPolicy {
  /** Chains whose addresses may raise `wallet_address_exposed` at all. */
  chains: WalletChain[];
  /** `ignore`: only the person's own addresses raise; anything else is quiet.
   * The setting a web3 developer flips — a Hardhat repo is full of addresses. */
  unknown_address: WalletUnknownAddress;
  own: OwnWallet[];
  /** Hex salt minted by the app when the first wallet is added; "" until then. */
  salt: string;
}

export const OWN_WALLETS_MAX = 64;
const WALLET_LABEL_MAX = 40;
const WALLET_HASH_RE = /^[0-9a-f]{64}$/;
const WALLET_SALT_RE = /^[0-9a-f]{16,64}$/;

export function defaultWallets(): WalletsPolicy {
  return { chains: [...DEFAULT_WALLET_CHAINS], unknown_address: "observe", own: [], salt: "" };
}

/** Never throws; unknown chains, malformed hashes and over-long labels are dropped. */
export function normalizeWallets(raw: unknown): WalletsPolicy {
  const base = defaultWallets();
  if (!raw || typeof raw !== "object") return base;
  const r = raw as Record<string, unknown>;
  if (Array.isArray(r.chains)) {
    const chains = r.chains.filter((c): c is WalletChain => (WALLET_CHAINS as readonly string[]).includes(c as string));
    base.chains = [...new Set(chains)];
  }
  if (r.unknown_address === "ignore" || r.unknown_address === "observe") base.unknown_address = r.unknown_address;
  if (typeof r.salt === "string" && WALLET_SALT_RE.test(r.salt)) base.salt = r.salt;
  if (Array.isArray(r.own)) {
    const seen = new Set<string>();
    for (const item of r.own) {
      if (base.own.length >= OWN_WALLETS_MAX) break;
      if (!item || typeof item !== "object") continue;
      const w = item as Record<string, unknown>;
      if (typeof w.hash !== "string" || !WALLET_HASH_RE.test(w.hash) || seen.has(w.hash)) continue;
      if (!(WALLET_CHAINS as readonly string[]).includes(w.chain as string)) continue;
      const label = typeof w.label === "string" ? w.label.trim().slice(0, WALLET_LABEL_MAX) : "";
      seen.add(w.hash);
      base.own.push({ hash: w.hash, label: label === "" ? "wallet" : label, chain: w.chain as WalletChain });
    }
  }
  // An own list without a salt cannot be matched against anything: drop it
  // rather than carry hashes nothing will ever equal.
  if (base.salt === "" && base.own.length > 0) base.own = [];
  return base;
}

export interface InjectionClassifierConfig {
  enabled: boolean;
  /**
   * The regex marker keeps standing UNLESS the model's malicious probability
   * is at or below this. Low by construction: the model overrules the detector
   * only when it is confidently benign, never on a coin toss.
   */
  suppress_below: number;
}

export const INJECTION_SUPPRESS_BELOW_DEFAULT = 0.2;
export const INJECTION_SUPPRESS_BELOW_MIN = 0.01;
/** Above this the model would overrule the detector on genuine ambiguity. */
export const INJECTION_SUPPRESS_BELOW_MAX = 0.5;

export function defaultInjectionClassifierConfig(): InjectionClassifierConfig {
  return { enabled: true, suppress_below: INJECTION_SUPPRESS_BELOW_DEFAULT };
}

export function normalizeInjectionClassifierConfig(raw: unknown): InjectionClassifierConfig {
  const cfg = defaultInjectionClassifierConfig();
  if (!raw || typeof raw !== "object") return cfg;
  const obj = raw as Record<string, unknown>;
  // An explicit boolean is honoured either way; an absent key keeps the default
  // (on), so a prefs file written before this field existed turns it on too.
  if (typeof obj.enabled === "boolean") cfg.enabled = obj.enabled;
  if (typeof obj.suppress_below === "number" && Number.isFinite(obj.suppress_below)) {
    cfg.suppress_below = Math.min(INJECTION_SUPPRESS_BELOW_MAX, Math.max(INJECTION_SUPPRESS_BELOW_MIN, obj.suppress_below));
  }
  return cfg;
}

export interface SecondOpinionPolicy {
  enabled: boolean;
  /** OpenAI-compatible chat completions URL. Loopback only. */
  endpoint: string;
  /** The model id the endpoint serves (an Ollama tag, an LM Studio id, …). */
  model: string;
  /** Wall-clock budget for one question; a miss is `unsure` and changes nothing. */
  timeout_ms: number;
}

export const SECOND_OPINION_DEFAULT_ENDPOINT = "http://127.0.0.1:11434/v1/chat/completions";
export const SECOND_OPINION_DEFAULT_MODEL = "qwen2.5:1.5b";
export const SECOND_OPINION_TIMEOUT_MIN_MS = 500;
/** Under the fast hook timeout (10s) with the detectors' own time left over. */
export const SECOND_OPINION_TIMEOUT_MAX_MS = 6_000;
export const SECOND_OPINION_DEFAULT_TIMEOUT_MS = 3_000;

export function defaultSecondOpinion(): SecondOpinionPolicy {
  return {
    enabled: false,
    endpoint: SECOND_OPINION_DEFAULT_ENDPOINT,
    model: SECOND_OPINION_DEFAULT_MODEL,
    timeout_ms: SECOND_OPINION_DEFAULT_TIMEOUT_MS,
  };
}

/**
 * Only an address that resolves to this machine may receive raw tool content.
 * `localhost.evil.example` fails on purpose: the host must BE loopback, not
 * start with it.
 */
export function isLoopbackEndpoint(endpoint: string): boolean {
  let url: URL;
  try {
    url = new URL(endpoint);
  } catch {
    return false;
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") return false;
  const host = url.hostname.toLowerCase();
  if (host === "localhost" || host === "[::1]" || host === "::1") return true;
  return /^127(?:\.\d{1,3}){3}$/.test(host);
}

export function normalizeSecondOpinion(raw: unknown): SecondOpinionPolicy {
  const policy = defaultSecondOpinion();
  if (!raw || typeof raw !== "object") return policy;
  const obj = raw as Record<string, unknown>;
  if (typeof obj.endpoint === "string" && obj.endpoint.trim() !== "") policy.endpoint = obj.endpoint.trim();
  if (typeof obj.model === "string" && /^[\w./:@-]{1,120}$/.test(obj.model.trim())) policy.model = obj.model.trim();
  if (typeof obj.timeout_ms === "number" && Number.isFinite(obj.timeout_ms)) {
    policy.timeout_ms = Math.min(SECOND_OPINION_TIMEOUT_MAX_MS, Math.max(SECOND_OPINION_TIMEOUT_MIN_MS, Math.round(obj.timeout_ms)));
  }
  // A non-loopback endpoint is not an error to report from a hook — it is a
  // configuration the guard refuses to act on. Off, with the URL kept so the
  // Settings screen can say why.
  policy.enabled = obj.enabled === true && isLoopbackEndpoint(policy.endpoint);
  return policy;
}

export const HOLD_SECONDS_MIN = 10;
export const HOLD_SECONDS_MAX = 300;
export const HOLD_SECONDS_CHOICES = [30, 60, 120, 300] as const;

/** Slack over the hold window, so OUR timeout fires before the host kills
 * the hook — a killed hook is a fail-open, which would silently defeat the
 * `deny on no answer` choice. */
export const HOOK_TIMEOUT_SLACK_SECONDS = 15;
/** The timeout for a non-interactive guard: it only ever reads and decides. */
export const HOOK_TIMEOUT_FAST_SECONDS = 10;

export function hookTimeoutSeconds(policy: GuardPolicy): number {
  if (!policy.confirm.interactive) return HOOK_TIMEOUT_FAST_SECONDS;
  return policy.confirm.hold_seconds + HOOK_TIMEOUT_SLACK_SECONDS;
}

/**
 * Every detector the guard can enforce — the full shipped set, BEFORE the
 * scope is applied. Private on purpose: nothing outside this file
 * should be able to list a rule the app does not show. `ALL_DETECTORS` below
 * is what everything reads.
 */
const SHIPPED_DETECTORS: readonly SecurityDetectorId[] = [
  "credential_in_prompt",
  "credential_in_tool_arg",
  "secret_egress",
  "env_dump",
  "dotenv_read",
  "hardcoded_credential",
  "unsafe_fetch_exec",
  "destructive_command",
  "infra_mutation",
  "unrecognized_secret",
  "invisible_unicode",
  "exfil_render_link",
  "secret_manager_read",
  "agent_config_tamper",
  "insecure_code_written",
  "pii_exposure",
  "license_contamination",
  "security_control_disabled",
  "wallet_key_material",
  "wallet_address_exposed",
  // `injected_instruction` is deliberately ABSENT: it scans tool OUTPUT, and
  // the guard is PreToolUse — it never sees output, so it could never act on
  // one. Listing it would offer an ask/block mode that silently does nothing.
];

/**
 * The rule catalog: every enforceable detector the app SHOWS. This is the one
 * list every "which rules exist" surface reads — the Guardrails level modes and
 * defaults, the tray's "N of M enforcing", the report's
 * rule table, the set-mode IPC's validation, ignore-scope parsing. Narrowed
 * through guard/rule-scope.ts, so a hidden rule has no mode written
 * for it and `decideEnforcement` reads it as observe: it records, and never
 * holds, warns or blocks.
 */
export const ALL_DETECTORS: readonly SecurityDetectorId[] = shownRules(SHIPPED_DETECTORS);

/**
 * Every detector id an ignore rule may be SCOPED to: the guard's own, plus the
 * radar-only ids the app mints (flow rules, loops, MCP, egress, integrity).
 * `parseIgnoreRule` drops a rule naming anything else rather than widening it.
 */
export const KNOWN_IGNORE_SCOPES: ReadonlySet<string> = new Set(shownRules([
  ...ALL_DETECTORS,
  "injected_instruction",
  "flow_secret_egress",
  "flow_injection_followed",
  "flow_fetch_then_exec",
  "flow_fetch_then_install",
  "flow_insecure_code_executed",
  "flow_read_then_send",
  "flow_sql_second_order",
  "agent_loop",
  "unknown_mcp_server",
  "mcp_tool_poisoning",
  "mcp_tool_changed",
  "mcp_permission",
  "egress_new_destination",
  "guard_tampered",
  "wallet_address_tampered",
]));

/** Human labels for reasons and the Radar UI (the finding itself carries no title). */
export const DETECTOR_LABELS: Record<SecurityDetectorId, string> = {
  credential_in_prompt: "Credential in prompt",
  credential_in_tool_arg: "Credential in tool argument",
  secret_egress: "Secret egress over the network",
  env_dump: "Environment dump",
  dotenv_read: "Credential file read",
  hardcoded_credential: "Hardcoded credential",
  unsafe_fetch_exec: "Download piped into interpreter",
  destructive_command: "Destructive command",
  infra_mutation: "Infrastructure mutation",
  unrecognized_secret: "Unrecognized secret",
  invisible_unicode: "Invisible characters",
  exfil_render_link: "Data-carrying link",
  secret_manager_read: "Secret manager read",
  agent_config_tamper: "Agent configuration write",
  injected_instruction: "Injected instruction in tool output",
  insecure_code_written: "Insecure code written",
  pii_exposure: "Personal data exposed",
  license_contamination: "License contamination",
  security_control_disabled: "Security control switched off",
  wallet_key_material: "Wallet key material",
  wallet_address_exposed: "Wallet address exposed",
};

/**
 * What ships enforcing — the Protective column of `LEVEL_LADDER`, and by the
 * test's anchoring, exactly that column.
 *
 * Five hold (`ask`): the credential rules whose damage is done the moment the
 * call runs — an exfiltration, a credential handed to a tool, a seed phrase in
 * an argument — plus `credential_in_prompt` and `pii_exposure`, which on Claude
 * Code the guard now reaches on UserPromptSubmit, so a hold DOES stop the
 * prompt before it is sent. Holding them costs a keystroke; not holding them
 * costs the incident.
 *
 * The quieter credential rules ship `warn` (2026-09-22; they shipped observe
 * before): `env_dump` / `dotenv_read` / `secret_manager_read` are routine in
 * normal development and `hardcoded_credential` / `unrecognized_secret` fire on
 * writes that are trivially reversible, so none of them earns a hold on a
 * fresh install — but each is the step before a leak, and a heads-up naming
 * the rule is how a person learns the guard is watching without being stopped.
 * `wallet_address_exposed` warns for the same reason: an address is public by
 * design and a web3 repo is full of them, so it is never held at any level.
 *
 * Nothing ships `block`: an install must never dead-end a session before the
 * person has had a chance to answer.
 *
 * The rules the app hides (guard/rule-scope.ts) carry no entry —
 * `shownRecord` strips them — and so are observed whatever they would be on.
 */
export const DEFAULT_MODES: Readonly<Partial<Record<SecurityDetectorId, EnforcementMode>>> = shownRecord({
  credential_in_prompt: "ask",
  credential_in_tool_arg: "ask",
  secret_egress: "ask",
  unsafe_fetch_exec: "ask",
  destructive_command: "ask",
  infra_mutation: "ask",
  env_dump: "warn",
  dotenv_read: "warn",
  hardcoded_credential: "warn",
  unrecognized_secret: "warn",
  secret_manager_read: "warn",
  pii_exposure: "ask",
  // A seed phrase or signer key in a tool argument is the one credential with
  // no rotation — the finding IS the loss. Held like credential_in_tool_arg;
  // the xpub shape rides at medium confidence and so never actually holds.
  wallet_key_material: "ask",
  wallet_address_exposed: "warn",
} satisfies Partial<Record<SecurityDetectorId, EnforcementMode>>);

export function defaultConfirm(): ConfirmPolicy {
  return { interactive: true, hold_seconds: 60, on_timeout: "deny", unattended: "deny" };
}

export function defaultPolicy(): GuardPolicy {
  return {
    version: 1,
    modes: { ...DEFAULT_MODES },
    disabled: [],
    ignore: [],
    confirm: defaultConfirm(),
  };
}

/**
 * The policy a "restore the shipped defaults" writes: every shipped detector
 * back on `DEFAULT_MODES`, and nothing else touched — custom rules, packs,
 * exceptions, the hold behaviour and the approved-server list are the person's
 * own and survive.
 *
 * The map is written WHOLE rather than cleared, and that is the whole trick:
 * an absent entry means "take the built-in default" to both `parsePolicy` and
 * the prefs sanitizer, but an explicit `observe` is deliberately kept (it is
 * how someone opts out of a default of ask). Clearing the map would therefore
 * leave a silenced ask rule silenced for ever.
 */
export function policyWithDefaultModes(policy: GuardPolicy): GuardPolicy {
  return { ...policy, modes: { ...DEFAULT_MODES } };
}

/**
 * Which detectors are NOT on the mode Doorman ships them at — what a restore
 * would change, and the only honest count to put next to the button that does
 * it. Pass `ids` to ask about a subset (the Rules screen asks about the rules
 * its table shows); the default is every shipped detector.
 */
export function driftedDetectors(
  modes: Partial<Record<SecurityDetectorId, EnforcementMode>> | undefined,
  ids: readonly SecurityDetectorId[] = ALL_DETECTORS,
): SecurityDetectorId[] {
  const map = modes ?? {};
  return ids.filter((id) => {
    const saved = map[id];
    // An ABSENT entry is not drift: absence means "take the built-in default"
    // to `parsePolicy` and the prefs sanitizer alike, so only an explicit
    // disagreement counts. Reading absence as `observe` instead would report
    // every rule that ships on ask or warn as drifted on any policy that
    // simply hasn't written them yet — and a restore would then "change" nothing.
    return saved !== undefined && saved !== (DEFAULT_MODES[id] ?? "observe");
  });
}

/* ---- Security levels ----------------------------------------- */

/**
 * The four stops of the security level: one decision a person can actually
 * make, in place of thirty rungs they cannot.
 *
 * A level is nothing but a PRESET over `modes` — it introduces no enforcement
 * concept the guard does not already have, and `livePolicy`, the hook document
 * and the guard itself never learn it exists. That is deliberate: the level is
 * a way of WRITING the mode map, not a second thing to consult when a call
 * arrives. If the two ever disagreed, the map is what runs.
 */
export type SecurityLevel = "relaxed" | "watchful" | "protective" | "locked_down";

export const SECURITY_LEVELS: readonly SecurityLevel[] = [
  "relaxed",
  "watchful",
  "protective",
  "locked_down",
];

/** The level Doorman ships on — and, by construction below, the one whose
 * mode map IS `DEFAULT_MODES`, so a fresh install reads "Protective" rather
 * than "Custom" on the day it is installed. */
export const DEFAULT_SECURITY_LEVEL: SecurityLevel = "protective";

/**
 * The ladder, as a table rather than as rules about a table.
 *
 * Read a row left to right and it never goes DOWN: moving the level up may
 * only ever make a rule louder. `assertLevelsMonotonic` (and a test) pins
 * that, because a level that quietened something while claiming to tighten is
 * the one failure this control cannot survive.
 *
 * **`protective` is `DEFAULT_MODES`.** Not approximately — the test asserts
 * the two maps are equal. That anchoring is what lets an install that has
 * never touched a rule read as a named level, and it is why a change to this
 * column IS a change to what ships (the 2026-09-22 revision below moved the
 * quieter credential rules to warn and `credential_in_prompt` / `pii_exposure`
 * to a hold, on purpose, for a fresh install too).
 *
 * An omitted detector is `observe` at every level.
 */
const LEVEL_LADDER: Readonly<
  Partial<Record<SecurityDetectorId, readonly [EnforcementMode, EnforcementMode, EnforcementMode, EnforcementMode]>>
> = {
  // The rules whose damage is done the moment the call runs. Relaxed silences
  // them, Watchful coaches, Protective holds (the shipped default), Locked
  // down refuses outright — except infra_mutation, which stays a hold even at
  // the top: `terraform apply` is the ordinary working shape of a platform
  // repo, and a level that refuses it is a level nobody leaves on.
  credential_in_prompt: ["observe", "warn", "ask", "block"],
  credential_in_tool_arg: ["observe", "warn", "ask", "block"],
  secret_egress: ["observe", "warn", "ask", "block"],
  destructive_command: ["observe", "warn", "ask", "block"],
  unsafe_fetch_exec: ["observe", "warn", "ask", "block"],
  wallet_key_material: ["observe", "warn", "ask", "block"],
  infra_mutation: ["observe", "warn", "ask", "ask"],

  // The quieter credential rules: silent through Watchful, a heads-up at
  // Protective (each is the step before a leak, not the leak), and a hold at
  // Locked down — never a refusal, because reading .env, dumping env and
  // writing a key you will rotate are all routine in real development.
  env_dump: ["observe", "observe", "warn", "ask"],
  dotenv_read: ["observe", "observe", "warn", "ask"],
  hardcoded_credential: ["observe", "observe", "warn", "ask"],
  unrecognized_secret: ["observe", "observe", "warn", "ask"],
  secret_manager_read: ["observe", "observe", "warn", "ask"],

  // Personal data leaving in a prompt or an argument: coached from Watchful,
  // held from Protective up. Not refused even at the top — a record in a test
  // fixture is the common case, and a hold lets the person say so.
  pii_exposure: ["observe", "warn", "ask", "ask"],

  // A wallet ADDRESS is public by design and a web3 repo is full of them, so
  // it is only ever a heads-up — from Protective up — and never held.
  wallet_address_exposed: ["observe", "observe", "warn", "warn"],

  // Hidden for now but kept on the ladder so the
  // guard's own view of a level is whole. Observe until Locked down, where
  // they earn `warn` — still of unknown noisiness (the invisible-character and
  // link pair) or reversible (an insecure line written).
  invisible_unicode: ["observe", "observe", "observe", "warn"],
  exfil_render_link: ["observe", "observe", "observe", "warn"],
  insecure_code_written: ["observe", "observe", "observe", "warn"],

  // The two that DO hold at the top. A write to a hooks file grants code
  // execution on every future session; switching off Gatekeeper, SIP or the
  // firewall disarms the machine itself. Both are routine-shaped enough that
  // holding them by default teaches people to switch the guard off — which is
  // exactly what a level you opt into is for.
  agent_config_tamper: ["observe", "observe", "observe", "ask"],
  security_control_disabled: ["observe", "observe", "observe", "ask"],

  // Deliberately observe at every stop, Locked down included: a licensing
  // hygiene finding, not a call you would want held; holding it stops work
  // over a text match.
  license_contamination: ["observe", "observe", "observe", "observe"],
};

/** Every shipped detector's mode at one level — the map a level WRITES. */
export function levelModes(level: SecurityLevel): Partial<Record<SecurityDetectorId, EnforcementMode>> {
  const at = SECURITY_LEVELS.indexOf(level);
  const i = at < 0 ? SECURITY_LEVELS.indexOf(DEFAULT_SECURITY_LEVEL) : at;
  const out: Partial<Record<SecurityDetectorId, EnforcementMode>> = {};
  for (const id of ALL_DETECTORS) {
    const row = LEVEL_LADDER[id];
    out[id] = row ? row[i] : "observe";
  }
  return out;
}

/**
 * The policy a level change writes: the whole mode map replaced, and NOTHING
 * else touched — custom rules, packs, exceptions, the hold behaviour and the
 * approved-server list are the person's own and survive a level move, exactly
 * as they survive a restore-the-defaults.
 *
 * The map is written WHOLE, for the same reason `policyWithDefaultModes`
 * writes it whole: an absent entry means "take the built-in default" to both
 * `parsePolicy` and the prefs sanitizer, so a level that CLEARED entries would
 * leave the rules that ship on ask or warn enforcing at Relaxed.
 */
export function policyWithLevel(policy: GuardPolicy, level: SecurityLevel): GuardPolicy {
  return { ...policy, modes: levelModes(level) };
}

/**
 * Which level these modes ARE, or `null` for a hand-edited map that is no
 * level at all — what the control renders as "Custom".
 *
 * Absence is resolved the way the rest of the app resolves it (built-in
 * default), so a policy whose `modes` map has never been written reads as
 * `protective`, not as Custom.
 */
export function levelOfModes(
  modes: Partial<Record<SecurityDetectorId, EnforcementMode>> | undefined,
): SecurityLevel | null {
  const map = modes ?? {};
  const effective = (id: SecurityDetectorId): EnforcementMode => map[id] ?? DEFAULT_MODES[id] ?? "observe";
  for (const level of SECURITY_LEVELS) {
    const want = levelModes(level);
    if (ALL_DETECTORS.every((id) => effective(id) === (want[id] ?? "observe"))) return level;
  }
  return null;
}

/**
 * Which detectors this map holds at a rung the level does not — what a level
 * move would OVERWRITE, and the only honest count to put in front of someone
 * before it does.
 *
 * Measured against the level the person is ON (the stored one), not against
 * the one they are moving to: the question the confirm asks is "what have you
 * changed by hand?", and a rule that merely differs from the destination is
 * not a hand edit, it is the point of moving.
 */
export function handEditedDetectors(
  modes: Partial<Record<SecurityDetectorId, EnforcementMode>> | undefined,
  level: SecurityLevel,
): SecurityDetectorId[] {
  const map = modes ?? {};
  const want = levelModes(level);
  return ALL_DETECTORS.filter((id) => {
    const saved = map[id] ?? DEFAULT_MODES[id] ?? "observe";
    return saved !== (want[id] ?? "observe");
  });
}

export function normalizeMode(value: unknown): EnforcementMode {
  return value === "warn" || value === "ask" || value === "block" ? value : "observe";
}

export function normalizeMcpPermission(value: unknown): McpPermissionMode {
  return value === "ask" || value === "block" ? value : "allow";
}

/** Does a working directory fall under a scope prefix? A prefix matches itself
 * and its descendants, never a sibling that merely shares a spelling
 * (`/repo` does not cover `/repo-old`). */
export function cwdWithinPrefix(cwd: string | undefined, prefix: string | undefined): boolean {
  if (!prefix) return true;
  if (!cwd) return false;
  const p = prefix.endsWith("/") ? prefix.slice(0, -1) : prefix;
  return cwd === p || cwd.startsWith(`${p}/`);
}

/**
 * The ignore rules that apply to THIS call: unscoped ones always, cwd-scoped
 * ones only under their prefix, expired ones never. What comes out is what the
 * shared detector's matcher is handed.
 */
export function applicableIgnoreRules(
  rules: readonly ScopedIgnoreRule[] | undefined,
  cwd: string | undefined,
  nowMs: number = Date.now(),
): ScopedIgnoreRule[] {
  if (!rules || rules.length === 0) return [];
  return rules.filter((rule) => {
    if (rule.expires_at !== undefined) {
      const at = Date.parse(rule.expires_at);
      if (Number.isFinite(at) && at <= nowMs) return false;
    }
    return cwdWithinPrefix(cwd, rule.cwd_prefix);
  });
}

/** Read an ignore rule off disk: the pattern is required, the scope fields are
 * kept only when they are the right shape. */
export function parseIgnoreRule(raw: unknown): ScopedIgnoreRule | undefined {
  if (!raw || typeof raw !== "object") return undefined;
  const r = raw as Record<string, unknown>;
  if (typeof r.pattern !== "string" || r.pattern === "") return undefined;
  const rule: ScopedIgnoreRule = { pattern: r.pattern };
  if (typeof r.detector === "string" && r.detector !== "") {
    // A scoped rule stays scoped or is dropped whole. Silently removing an
    // unknown detector used to turn "ignore npm for agent_loop" into "ignore
    // npm for EVERY detector" — the one edit an ignore rule must never make
    // on its own. Radar-only ids (flow rules, MCP, loops) are legitimate
    // scopes even though the guard itself never raises them.
    if (!KNOWN_IGNORE_SCOPES.has(r.detector) && !r.detector.startsWith("custom:")) return undefined;
    rule.detector = r.detector;
  }
  if (typeof r.cwd_prefix === "string" && r.cwd_prefix.trim() !== "") rule.cwd_prefix = r.cwd_prefix.trim();
  // An expiry that is present but unreadable fails CLOSED: keeping the rule
  // without it would turn a 30-day exception into a permanent one.
  if (r.expires_at !== undefined) {
    if (typeof r.expires_at !== "string" || !Number.isFinite(Date.parse(r.expires_at))) return undefined;
    rule.expires_at = r.expires_at;
  }
  if (typeof r.note === "string" && r.note.trim() !== "") rule.note = r.note.trim().slice(0, 200);
  if (r.origin === "approval" || r.origin === "manual") rule.origin = r.origin;
  return rule;
}

export function parseMcpPermissions(raw: unknown): Record<string, McpPermissionSet> | undefined {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return undefined;
  const out: Record<string, McpPermissionSet> = {};
  for (const [server, value] of Object.entries(raw as Record<string, unknown>)) {
    if (server.trim() === "" || !value || typeof value !== "object") continue;
    const set: McpPermissionSet = {};
    for (const cls of MCP_TOOL_CLASSES) {
      const mode = (value as Record<string, unknown>)[cls];
      if (mode === "ask" || mode === "block") set[cls] = mode;
    }
    if (Object.keys(set).length > 0) out[server] = set;
  }
  return Object.keys(out).length > 0 ? out : undefined;
}

/** Clamp a hold window to something a human can answer and a hook can survive. */
export function normalizeHoldSeconds(value: unknown): number {
  if (typeof value !== "number" || !Number.isFinite(value)) return defaultConfirm().hold_seconds;
  return Math.min(HOLD_SECONDS_MAX, Math.max(HOLD_SECONDS_MIN, Math.round(value)));
}

export function normalizeConfirm(raw: unknown): ConfirmPolicy {
  const confirm = defaultConfirm();
  if (!raw || typeof raw !== "object") return confirm;
  const obj = raw as Record<string, unknown>;
  if (typeof obj.interactive === "boolean") confirm.interactive = obj.interactive;
  if (obj.hold_seconds !== undefined) confirm.hold_seconds = normalizeHoldSeconds(obj.hold_seconds);
  if (obj.on_timeout === "ask" || obj.on_timeout === "deny") confirm.on_timeout = obj.on_timeout;
  if (obj.unattended === "deny" || obj.unattended === "continue") confirm.unattended = obj.unattended;
  return confirm;
}

export function parsePolicy(json: string | undefined): GuardPolicy {
  if (!json) return defaultPolicy();
  try {
    const raw = JSON.parse(json) as Record<string, unknown>;
    if (!raw || typeof raw !== "object") return defaultPolicy();
    const policy = defaultPolicy();
    const modes = raw.modes as Record<string, unknown> | undefined;
    if (modes && typeof modes === "object") {
      for (const detector of ALL_DETECTORS) {
        const mode = modes[detector];
        // "observe" is stored explicitly rather than left absent, because absent
        // now means "take the default" — and one of the defaults is ask. An
        // opt-out has to be able to say so out loud.
        if (mode === "warn" || mode === "ask" || mode === "block" || mode === "observe") {
          policy.modes[detector] = mode;
        }
      }
    }
    policy.confirm = normalizeConfirm(raw.confirm);
    if (Array.isArray(raw.disabled)) {
      policy.disabled = raw.disabled.filter((d): d is SecurityDetectorId =>
        (ALL_DETECTORS as readonly string[]).includes(d as string),
      );
    }
    if (typeof raw.armed_escalation === "boolean") policy.armed_escalation = raw.armed_escalation;
    if (raw.second_opinion && typeof raw.second_opinion === "object") {
      policy.second_opinion = normalizeSecondOpinion(raw.second_opinion);
    }
    if (raw.injection_classifier && typeof raw.injection_classifier === "object") {
      policy.injection_classifier = normalizeInjectionClassifierConfig(raw.injection_classifier);
    }
    if (Array.isArray(raw.approved_mcp_servers)) {
      const servers = raw.approved_mcp_servers.filter(
        (v: unknown): v is string => typeof v === "string" && v.trim() !== "",
      );
      if (servers.length > 0) policy.approved_mcp_servers = servers;
    }
    if (Array.isArray(raw.ignore)) {
      for (const rule of raw.ignore) {
        const parsed = parseIgnoreRule(rule);
        if (parsed) policy.ignore.push(parsed);
      }
    }
    const customRules = parseCustomRules(raw.custom_rules);
    if (customRules.length > 0) policy.custom_rules = customRules;
    const mcpPermissions = parseMcpPermissions(raw.mcp_permissions);
    if (mcpPermissions) policy.mcp_permissions = mcpPermissions;
    if (typeof raw.mcp_armed_escalation === "boolean") policy.mcp_armed_escalation = raw.mcp_armed_escalation;
    if (raw.wallets && typeof raw.wallets === "object") policy.wallets = normalizeWallets(raw.wallets);
    return policy;
  } catch {
    return defaultPolicy();
  }
}

export interface EnforcementDecision {
  decision: "allow" | "ask" | "deny";
  reason?: string;
  /** The severity band that drove the decision, for the spool record. */
  max_severity?: SecuritySeverity;
  /** The detectors that actually drove it (not the observed ones) — the
   * approval card names these, so it can't say "credential" when what fired
   * was a force-push. Typed string[] because the armed escalation (armed.ts)
   * holds under the flow rule's id, which is deliberately not a
   * SecurityDetectorId; decideEnforcement itself only ever emits real ones. */
  detectors: string[];
  /** Warn-mode detectors that fired at interrupt-grade confidence. They never
   * change `decision` — the call runs — but the guard spools them as WARN so
   * the app can raise the coaching banner. Typed as the detector union for the
   * shipped rules; a custom rule's `custom:<id>` rides the same list (the
   * consumers only ever compare and label). */
  warned: SecurityDetectorId[];
}

/**
 * Fold findings against the policy: any block-mode detector firing wins over
 * ask, which wins over observe. The reason names detectors, never values —
 * the same no-secrets rule as the excerpts themselves.
 */
/** A per-unit detector finding, or a custom rule's — the fold treats them alike
 * except for where the MODE and the LABEL come from. */
export type GuardFinding = SecurityFinding | CustomRuleFinding;

export function isCustomFinding(finding: GuardFinding): finding is CustomRuleFinding {
  return "mode" in finding && typeof (finding as CustomRuleFinding).mode === "string";
}

export function decideEnforcement(
  findings: readonly GuardFinding[],
  policy: GuardPolicy,
): EnforcementDecision {
  let decision: "allow" | "ask" | "deny" = "allow";
  let maxSeverity: SecuritySeverity | undefined;
  const named: string[] = [];
  const detectors: string[] = [];
  const warned: SecurityDetectorId[] = [];
  for (const finding of findings) {
    if (!maxSeverity || SEVERITY_RANK[finding.severity] > SEVERITY_RANK[maxSeverity]) {
      maxSeverity = finding.severity;
    }
    // A custom rule carries its own posture; a detector's comes from the map.
    const custom = isCustomFinding(finding);
    const mode = custom ? finding.mode : policy.modes[finding.detector] ?? "observe";
    if (mode === "observe") continue;
    // A finding below high confidence never interrupts, whatever the mode says:
    // holding someone's tool call on a guess (a generic `secret_…` prefix, an
    // entropy candidate, an SSN-shaped number) is how a guard gets switched
    // off. It is still recorded and spooled — observe, not silence. The same
    // bar gates warn: a coaching banner about a guess is spam, not coaching.
    if (!custom && (finding.confidence === "medium" || finding.confidence === "low")) continue;
    // `warn` mode, OR an advisory finding under ask/block, coaches rather than
    // holds: the call runs and the app raises the heads-up banner. Advisory is
    // the detector saying "this shape is routine — record it, don't interrupt"
    // (a terraform apply), while its destructive siblings stay holdable.
    if (mode === "warn" || (!custom && finding.advisory)) {
      // Custom warn-mode rules ride `warned` too: the spool marks them WARN and
      // the app's coaching banner names the rule by its label.
      if (!warned.includes(finding.detector as SecurityDetectorId)) warned.push(finding.detector as SecurityDetectorId);
      continue;
    }
    named.push(custom ? finding.label : DETECTOR_LABELS[finding.detector] ?? finding.detector);
    if (!detectors.includes(finding.detector)) detectors.push(finding.detector);
    if (mode === "block") decision = "deny";
    else if (decision === "allow") decision = "ask";
  }
  if (decision === "allow") return { decision, max_severity: maxSeverity, detectors, warned };
  const unique = [...new Set(named)];
  return {
    decision,
    max_severity: maxSeverity,
    detectors,
    warned,
    reason: `Doorman flagged this tool call: ${unique.join(", ")}.`,
  };
}

// --- hook-document surgery ------------------------------------------------

/** Substring that identifies OUR current hook entry, whatever path it was installed at. */
export const GUARD_COMMAND_MARKER = "doorman/guard";

export function isGuardCommand(command: unknown): command is string {
  return (
    typeof command === "string" &&
    command.includes(GUARD_COMMAND_MARKER)
  );
}

interface HookHandler {
  type?: string;
  command?: string;
  timeout?: number;
  statusMessage?: string;
}

interface HookEntry {
  matcher?: string;
  hooks?: HookHandler[];
}

/**
 * Every PreToolUse handler command in a hook document that carries OUR marker.
 * `undefined` when the document doesn't parse (which is not the same as "no
 * entry" — the caller has to be able to tell those apart). Shared by the host
 * descriptors' `installed()` and lib/guard-integrity.ts.
 */
export function hookDocumentCommands(docText: string | undefined, event = "PreToolUse"): string[] | undefined {
  if (docText === undefined) return [];
  let parsed: unknown;
  try {
    parsed = JSON.parse(docText);
  } catch {
    return undefined;
  }
  if (!parsed || typeof parsed !== "object") return [];
  const hooks = (parsed as Record<string, unknown>).hooks;
  if (!hooks || typeof hooks !== "object" || Array.isArray(hooks)) return [];
  const pre = (hooks as Record<string, unknown>)[event];
  if (!Array.isArray(pre)) return [];
  const out: string[] = [];
  for (const group of pre) {
    const handlers = (group as { hooks?: unknown } | null)?.hooks;
    if (!Array.isArray(handlers)) continue;
    for (const handler of handlers as HookHandler[]) {
      if (isOurCommand(handler)) out.push(handler.command as string);
    }
  }
  return out;
}

function isOurCommand(handler: HookHandler | null | undefined): boolean {
  return !!handler && isGuardCommand(handler.command);
}

/**
 * Claude Code's prompt event. The same guard command is installed
 * under it — Claude Code passes `hook_event_name`, so one process serves both
 * — which makes "a seed phrase pasted into the prompt" something the guard
 * can STOP (exit 2 erases the prompt) rather than record. No matcher: the
 * event has none. Only descriptors that ask for it get the entry
 * (hosts/claude.ts); every other document keeps its PreToolUse-only shape.
 */
export const PROMPT_HOOK_EVENT = "UserPromptSubmit";

/**
 * Add (or update, idempotently) the guard's PreToolUse entry in a
 * supported host hook document, preserving everything else verbatim.
 * Returns the new JSON text — or the INPUT text, byte-identical, when the
 * document already says exactly this, so callers can skip the write (and
 * Codex's per-definition trust survives untouched).
 *
 * Two rules of surgery, both learned the hard way:
 *  - Update IN PLACE, never remove-and-append. Codex trusts a handler by its
 *    (group index, handler index) as well as its definition, so reordering
 *    groups — ours or anybody else's — silently un-trusts hooks that did not
 *    change, and an untrusted hook does not run.
 *  - Operate on HANDLERS, never whole groups. A group can carry someone
 *    else's handler next to ours (a hand-merge, another tool appending into
 *    an existing group), and that handler is not ours to delete.
 *
 * `timeoutSeconds` must exceed the hold window (hookTimeoutSeconds does that
 * arithmetic): the host kills a hook that overruns its timeout, and a killed
 * hook produces no verdict at all — so a too-short timeout here would quietly
 * turn "deny when nobody answers" into "allow when nobody answers".
 */
function mergeHookDocument(
  settingsJson: string | undefined,
  command: string,
  timeoutSeconds: number,
  invalidDocument: string,
  statusMessage?: string,
  matcher?: string,
  promptEvent = false,
): string {
  let settings: Record<string, unknown> = {};
  if (settingsJson && settingsJson.trim() !== "") {
    try {
      const parsed = JSON.parse(settingsJson);
      if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
        settings = parsed as Record<string, unknown>;
      }
    } catch {
      // A malformed settings.json must not be destroyed by us — refuse instead.
      throw new Error(`${invalidDocument} is not valid JSON; not touching it`);
    }
  }
  // Canonical form BEFORE any mutation, to detect the no-op below.
  const before = JSON.stringify(settings);
  // `hooks: []` (an array) is valid JSON the host ignores — and a named event
  // set on an array disappears at JSON.stringify time, so the old code
  // reported success while wiring nothing. An inert shape is replaced.
  const hooks =
    settings.hooks && typeof settings.hooks === "object" && !Array.isArray(settings.hooks)
      ? (settings.hooks as Record<string, unknown>)
      : {};
  const desired: HookHandler = {
    type: "command",
    command,
    timeout: Math.max(1, Math.round(timeoutSeconds)),
    ...(statusMessage ? { statusMessage } : {}),
  };
  hooks.PreToolUse = upsertOurHandler(
    Array.isArray(hooks.PreToolUse) ? (hooks.PreToolUse as HookEntry[]) : [],
    desired,
    matcher,
  );
  if (promptEvent) {
    hooks[PROMPT_HOOK_EVENT] = upsertOurHandler(
      Array.isArray(hooks[PROMPT_HOOK_EVENT]) ? (hooks[PROMPT_HOOK_EVENT] as HookEntry[]) : [],
      desired,
      undefined,
    );
  }
  settings.hooks = hooks;
  if (settingsJson !== undefined && JSON.stringify(settings) === before) return settingsJson;
  return `${JSON.stringify(settings, null, 2)}\n`;
}

/** The in-place, handler-level upsert described above, for ONE event's groups. */
function upsertOurHandler(pre: HookEntry[], desired: HookHandler, matcher: string | undefined): HookEntry[] {
  const matchesDesired = (h: HookHandler): boolean =>
    h.type === desired.type &&
    h.command === desired.command &&
    h.timeout === desired.timeout &&
    h.statusMessage === desired.statusMessage &&
    Object.keys(h).length === Object.keys(desired).length;
  let placed = false;
  const next: HookEntry[] = [];
  for (const entry of pre) {
    if (!entry || typeof entry !== "object" || !Array.isArray(entry.hooks)) {
      next.push(entry);
      continue;
    }
    const kept: HookHandler[] = [];
    let touched = false;
    for (const handler of entry.hooks) {
      if (!isOurCommand(handler)) {
        kept.push(handler);
        continue;
      }
      if (placed) {
        // A stray extra copy of ours — dropped, handler by handler.
        touched = true;
        continue;
      }
      placed = true;
      if (matchesDesired(handler)) {
        kept.push(handler);
      } else {
        kept.push(desired);
        touched = true;
      }
    }
    if (kept.length === 0) continue; // the group held only stray copies of ours
    const soloOurs = kept.length === 1 && isOurCommand(kept[0]);
    if (soloOurs) {
      // Our own group: keep the canonical matcher (a narrowed matcher on a
      // security hook is a partial bypass, not a preference to preserve).
      const group: HookEntry = { ...entry, hooks: kept };
      if (matcher !== undefined) group.matcher = matcher;
      else delete group.matcher;
      next.push(group);
    } else {
      // A shared group is somebody else's structure — leave its shape alone.
      next.push(touched ? { ...entry, hooks: kept } : entry);
    }
  }
  if (!placed) {
    next.push({ ...(matcher !== undefined ? { matcher } : {}), hooks: [desired] });
  }
  return next;
}

export function mergeGuardHook(
  settingsJson: string | undefined,
  command: string,
  timeoutSeconds: number = HOOK_TIMEOUT_FAST_SECONDS,
  options: { promptEvent?: boolean } = {},
): string {
  return mergeHookDocument(
    settingsJson,
    command,
    timeoutSeconds,
    "~/.claude/settings.json",
    undefined,
    "*",
    options.promptEvent === true,
  );
}

/** Codex uses the same three-level hook shape in ~/.codex/hooks.json. Keep a
 * separate entry point so error messages and future host-specific fields stay
 * honest rather than pretending the two files are interchangeable. No
 * `matcher` here: Codex has never documented the field. */
export function mergeCodexGuardHook(
  hooksJson: string | undefined,
  command: string,
  timeoutSeconds: number = HOOK_TIMEOUT_FAST_SECONDS,
): string {
  return mergeHookDocument(
    hooksJson,
    command,
    timeoutSeconds,
    "$CODEX_HOME/hooks.json",
    "Checking Doorman security policy",
  );
}

/** Remove the guard's handlers — never a whole group, which can carry someone
 * else's handler next to ours. Returns the new JSON text, or undefined when
 * there was nothing of ours to remove. */
export function removeGuardHook(settingsJson: string | undefined): string | undefined {
  if (!settingsJson || settingsJson.trim() === "") return undefined;
  let settings: Record<string, unknown>;
  try {
    const parsed = JSON.parse(settingsJson);
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return undefined;
    settings = parsed as Record<string, unknown>;
  } catch {
    return undefined;
  }
  const hooks = settings.hooks as Record<string, unknown> | undefined;
  if (!hooks || typeof hooks !== "object" || Array.isArray(hooks)) return undefined;
  let removed = false;
  // Both events: the tool-call entry and, where a descriptor asked for it, the
  // prompt entry (PROMPT_HOOK_EVENT). Same handler-level rule for each.
  for (const event of ["PreToolUse", PROMPT_HOOK_EVENT]) {
    if (!Array.isArray(hooks[event])) continue;
    const next: HookEntry[] = [];
    for (const entry of hooks[event] as HookEntry[]) {
      if (!entry || typeof entry !== "object" || !Array.isArray(entry.hooks)) {
        next.push(entry);
        continue;
      }
      const kept = entry.hooks.filter((h) => !isOurCommand(h));
      if (kept.length !== entry.hooks.length) removed = true;
      if (kept.length > 0) {
        next.push(kept.length === entry.hooks.length ? entry : { ...entry, hooks: kept });
      }
    }
    if (next.length > 0) hooks[event] = next;
    else delete hooks[event];
  }
  if (!removed) return undefined;
  if (Object.keys(hooks).length === 0) delete settings.hooks;
  return `${JSON.stringify(settings, null, 2)}\n`;
}

export const removeCodexGuardHook = removeGuardHook;
