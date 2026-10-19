/**
 * The guard host contract — one descriptor per agent host the PreToolUse
 * guard can be installed into (Claude Code, Codex, Cursor, Gemini CLI,
 * Copilot CLI, …).
 *
 * A descriptor is PURE: config surgery over document text, stdin JSON →
 * GuardHookInput, decision → stdout/exit code. No fs, no process, no imports
 * outside this directory's siblings (the whole guard dir is copied to
 * userData and run with plain `node`, so it must stay self-contained).
 *
 * The registry (hosts/index.ts) is the only place that knows every host; the
 * guard entry, the installer, the doctor, the integrity watcher and the
 * coverage card all iterate it instead of naming hosts.
 *
 * This file is the seam three adapters are built against in parallel — extend
 * it ADDITIVELY (optional fields) and say so in your report; do not rename or
 * remove anything here.
 */

import type { GuardHookInput, GuardPromptInput } from "../decision.js";

/** Where a host reads a hook document from. `user` is the one the app
 * installs into; `project` documents live under a project root the caller
 * supplies; `system` is read for the doctor, never written. */
export type HostDocumentLevel = "user" | "project" | "system";

export interface HostDocument {
  /** Absolute for `user`/`system`; relative to the project root for `project`. */
  path: string;
  level: HostDocumentLevel;
}

/** What the guard process prints and how it exits for one decision. `stdout`
 * undefined means print nothing. */
export interface HostEmit {
  stdout?: string;
  /** Printed to stderr — the channel Kiro CLI (exit 2) reads a rejection
   * reason from. ADDITIVE (2026-09-06); undefined means print nothing. */
  stderr?: string;
  exitCode: number;
}

/**
 * The text format of a host's hook document. Every consumer that reads a
 * document (installer, doctor, integrity watcher, hook health) has parsed it
 * as JSON; a host declaring anything else tells them to ask the descriptor
 * instead (hosts/index.ts `documentReadable`). Absent means `json`. ADDITIVE
 * (2026-09-06): Hermes's `config.yaml` and Kimi Code's `config.toml` are the
 * first non-JSON documents. ADDITIVE (2026-10-19): `jsonc` — JSON the host
 * reads with comments (Gemini CLI, Qwen Code, Factory Droid) — and `json5` —
 * JSON the host falls back to reading as JSON5 (OpenClaw). Their descriptors
 * edit a commented document in place (guard/jsonc.ts), and the doctor never
 * "repairs" one into plain JSON: there, a comment is not damage.
 */
export type HostDocumentFormat = "json" | "jsonc" | "json5" | "yaml" | "toml";

/**
 * A file the installer writes BESIDES the hook document, for a host whose
 * only pre-tool seam is a plugin it loads from disk (OpenClaw). The content
 * is machine-independent — the guard command travels in the hook document,
 * never in the artefact — so the same bytes are written on every machine and
 * a drifted artefact is simply rewritten on the next install/sync. Paths are
 * absolute. ADDITIVE (2026-09-06).
 */
export interface HostArtifact {
  path: string;
  content: string;
}

/**
 * A second document a host needs written for our entry to take effect, with
 * its own surgery: Hermes persists first-use CONSENT per (event, command) in
 * `~/.hermes/shell-hooks-allowlist.json`, and a non-TTY run silently skips an
 * unconsented hook. The installer merges every companion in the same pass as
 * the hook document and removes them on uninstall; the doctor and the
 * integrity watcher do not read them. ADDITIVE (2026-09-06).
 */
export interface HostCompanion {
  /** Absolute path, resolved like documents(). */
  path(home: string, env: NodeJS.ProcessEnv): string;
  /** Add/refresh our entry; same contract as GuardHostDescriptor.merge. */
  merge(docText: string | undefined, command: string): string;
  /** Remove our entry — never anyone else's; undefined when nothing of ours. */
  remove(docText: string | undefined): string | undefined;
}

export type HostDecision = "allow" | "ask" | "deny";

/**
 * One tool call's identity across the SEVERAL hook events a host may fire for
 * it (Cursor: `beforeShellExecution` and `preToolUse` for one shell command).
 * `key` must be the same for every event of one call and different for two
 * calls — a host-issued call id where the wire carries one, else the host's
 * best stable join (conversation + generation + the call's primary argument).
 * `event` is the host's event name; the guard de-duplicates ONLY across
 * different events (guard/dedup.ts), so an identical call fired twice under
 * the same event is evaluated twice — a repeat is never a grant. ADDITIVE
 * (2026-09-10).
 */
export interface CallIdentity {
  key: string;
  event: string;
}

/**
 * A second PRODUCT that reads this host's hook document and delivers its own
 * payload shape to the same installed command. VS Code's Copilot Chat loads
 * `~/.copilot/hooks/*.json` exactly as the Copilot CLI does (verified against
 * VS Code 1.136.2, 2026-09-08) — so one document guards both, and a second
 * document would make every call fire twice on both. The descriptor's
 * `normalizeInput`/`emit` must understand the dialect; this record only says
 * which `source` a payload belongs to, so findings and approvals name the
 * product that actually made the call. ADDITIVE (2026-09-08).
 */
export interface HostDialect {
  /** The `source` for spool rows, findings and approval requests. */
  source: string;
  /** Human label ("VS Code + Copilot"). */
  label: string;
  /** Whether this raw stdin payload came from the dialect's product. Pure. */
  claims(raw: unknown): boolean;
}

/**
 * What a non-zero exit means to the host:
 *  - `fail-open`: the host ignores it and proceeds (Claude Code, Cursor default);
 *  - `fail-closed`: the host DENIES the call (Copilot CLI) — emit() must never
 *    return a non-zero code for a decision we did not make;
 *  - `exit-is-verdict`: the exit code IS the answer (Amp: 0 allow / 1 ask / 2 reject).
 */
export type HostExitSemantics = "fail-open" | "fail-closed" | "exit-is-verdict";

export interface GuardHostDescriptor {
  /** Stable id; also the `--host <id>` argument the installed command carries. */
  id: string;
  /** Human label ("Cursor"). */
  label: string;
  /** The `source` written to spool rows and findings for this host. Claude
   * Code's is "claude-code", Codex's "codex" — existing values must not change. */
  source: string;

  /** The hook documents for this host. `home` is the user's home directory,
   * already resolved; `env` is the process environment (for CODEX_HOME-style
   * overrides). Pure. */
  documents(home: string, env: NodeJS.ProcessEnv): HostDocument[];

  /** Add or refresh our hook entry in the document text. Preserve everything
   * unrelated byte-for-byte where the format allows; refuse malformed input by
   * throwing. `command` is the full guard command line for this host;
   * `holdSeconds` is the hold window the per-hook timeout must exceed (see
   * hookTimeoutSeconds in policy.ts) where the host has such a field.
   * `timeoutSeconds` is ADDITIVE and optional (A0): the exact per-hook timeout
   * the installer computed for this policy — `hookTimeoutSeconds(policy)`,
   * which is the hold window plus slack while holding is on and a short fixed
   * value while it is off. A descriptor that derives its own timeout from
   * `holdSeconds` may ignore it; Claude Code and Codex use it so the byte
   * written into their documents is unchanged from before the registry.
   * Returns the new document text (the same text when nothing changed). */
  merge(
    docText: string | undefined,
    command: string,
    holdSeconds: number,
    timeoutSeconds?: number,
  ): string;

  /** Remove our entry — never anyone else's. Returns undefined when there was
   * nothing of ours to remove. */
  remove(docText: string | undefined): string | undefined;

  /** Whether the document carries our entry for exactly this command. */
  installed(docText: string | undefined, command: string): boolean;

  /**
   * Translate the host's stdin payload into the guard's vocabulary. Tool names
   * and inputs are normalized to Claude Code's, which every detector keys on:
   *   Bash  { command }            shell execution
   *   Write { file_path, content } whole-file write
   *   Edit  { file_path, old_string, new_string }
   *   Read  { file_path }
   *   WebFetch { url }
   *   mcp__<server>__<tool> { …the tool's own arguments }
   * `session_id` is the host's own conversation/session identifier (armed
   * taints key on it); `cwd` scopes ignore rules and custom rules.
   * Return undefined for an event that is not a tool call we evaluate.
   */
  normalizeInput(raw: unknown): GuardHookInput | undefined;

  /**
   * ADDITIVE (2026-09-08). A host whose hook document can ALSO fire on
   * the PROMPT before the model sees it (Claude Code's `UserPromptSubmit`).
   * `normalizePrompt` returns the prompt payload in the guard's vocabulary, or
   * undefined for any other event; `emitPrompt` is the output contract for a
   * prompt decision — `deny` must stop the prompt (Claude Code: stderr + exit
   * 2 erases it), `warn` may hand the agent a note (`additionalContext`),
   * `allow` prints nothing. Both absent = the guard evaluates tool calls only,
   * exactly as before. A descriptor that sets one must set both.
   */
  normalizePrompt?(raw: unknown): GuardPromptInput | undefined;
  emitPrompt?(decision: "allow" | "warn" | "deny", reason?: string, context?: string): HostEmit;

  /** The host's output contract for a decision. `allow` prints NOTHING and
   * exits 0 (rule 2 in guard.ts: we add a check, never remove one) unless the
   * host's exit semantics make silence impossible. */
  emit(decision: HostDecision, reason?: string): HostEmit;

  /** What to print when the guard wanted to ask but nobody can answer (the app
   * is absent, or the host has no native ask): a visible warning that lets the
   * call continue. Hosts with native ask may return emit("ask", reason). */
  warn(reason: string): HostEmit;

  /** The host can show its own confirmation prompt when we print `ask`. */
  supportsNativeAsk: boolean;

  /**
   * ADDITIVE (2026-09-10). Per-PAYLOAD native ask, for a host whose ability
   * to ask depends on the runtime the payload came from (OpenClaw: the plugin
   * that built the envelope knows whether this build honours
   * `requireApproval` and whether `approvals.plugin` is routed, and says so in
   * the envelope). Wins over `supportsNativeAsk` when defined; the guard uses
   * it for the unattended rule (hold.ts unattendedOutcome) and for what it
   * prints. Pure. Absent = `supportsNativeAsk`.
   */
  supportsNativeAskFor?(raw: unknown): boolean;

  /**
   * ADDITIVE (2026-09-10). The longest hold this host's hook can survive, in
   * seconds — for a host whose per-hook timeout has a CEILING the installer
   * cannot raise (Hermes: `timeout` max 300). The guard caps its hold at this
   * so its own timeout fires (a deny under `on_timeout: "deny"`) before the
   * host kills the hook, which on a fail-open host is a silent allow. Absent =
   * the policy's hold window as configured.
   */
  maxHoldSeconds?: number;

  exitSemantics: HostExitSemantics;

  /**
   * The host's default per-hook timeout in seconds when merge() cannot set
   * one. The hold window must stay under it (a killed hook fails OPEN on most
   * hosts). Omit when merge() writes the timeout itself.
   */
  fixedTimeoutSeconds?: number;

  /** Home-relative paths whose presence means the host is installed on this
   * machine (the installer's "is there anything to install into" check and
   * the coverage card). */
  presencePaths: string[];
  /** Optional resolved footprints for hosts with a relocated home directory. */
  presencePathsFor?(home: string, env: NodeJS.ProcessEnv): string[];

  /** The hook document's text format; absent = `json`. See HostDocumentFormat. */
  documentFormat?: HostDocumentFormat;

  /**
   * Files written alongside the hook document — a plugin directory the host
   * loads (OpenClaw). Absent for hosts whose document alone carries the hook.
   * Pure: paths from `home`/`env`, content a constant. See HostArtifact.
   */
  artifacts?(home: string, env: NodeJS.ProcessEnv): HostArtifact[];

  /** Companion documents with their own surgery (Hermes's consent allowlist). */
  companions?: HostCompanion[];

  /** Other products that read this host's document and speak their own payload
   * dialect (VS Code Copilot Chat over the Copilot CLI document). See HostDialect. */
  dialects?: HostDialect[];

  /**
   * The call this payload belongs to, for a host that fires more than one
   * event per call (see CallIdentity). `normalized` is this payload's own
   * normalizeInput result. Pure. Absent = every event is its own call.
   */
  callIdentity?(raw: unknown, normalized: GuardHookInput): CallIdentity | undefined;
}
