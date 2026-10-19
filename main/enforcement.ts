/**
 * Enforcement plumbing: installing the PreToolUse guard into every registered
 * host (guard/hosts/index.ts — Claude Code and Codex today), keeping the
 * guard's on-disk bundle and policy
 * fresh, ingesting the spool it writes, and — the live half — answering the
 * calls it holds open (GuardHeartbeat + ApprovalWatcher, over the file
 * rendezvous defined in guard/handshake.ts).
 *
 * The guard is COPIED to <userData>/doorman/guard/ rather than run from
 * the app bundle: the settings.json entry must survive app updates and the
 * .app being moved, and userData is the one path that does. The directory name
 * doubles as the marker (`doorman/guard`) that identifies our hook entry
 * in settings.json, whatever the machine's userData root looks like.
 *
 * Every host runs the same copied bundle; the command carries `--host <id>`
 * so the guard picks that host's adapter (input normalization + output
 * contract) at runtime. Claude Code's command is deliberately BARE — its
 * settings entry, and the trust keyed on the exact string, predate the flag.
 */

import {
  copyFileSync,
  existsSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  renameSync,
  rmSync,
  statSync,
  type FSWatcher,
  watch,
  writeFileSync,
} from "node:fs";
import { hookWritesAllowed, SANDBOX_READ_ONLY } from "./lib/sandbox.js";
import { createHash } from "node:crypto";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { GUARD_COMMAND_MARKER, hookTimeoutSeconds, isGuardCommand, type GuardPolicy } from "./guard/policy.js";
import { DEFAULT_HOST, HOSTS, documentReadable } from "./guard/hosts/index.js";
import { hermesHome, hermesHost, withoutLegacyAllowlistEntries } from "./guard/hosts/hermes.js";
import type { GuardHostDescriptor, HostArtifact } from "./guard/hosts/types.js";
import { buildInfo } from "./lib/build-info.js";
import { assessGuardIntegrity, type GuardIntegrityReport } from "./lib/guard-integrity.js";
import {
  heartbeatPath,
  parseRequest,
  pendingDir,
  requestPath,
  writeReply,
  type ApprovalRequest,
  type ApprovalVerdict,
  type ApprovalVia,
} from "./guard/handshake.js";
import type { SecurityDetectorId } from "./guard/security-detect.js";
import { parseEditorAnswer, type EditorAnswer } from "./lib/vscode-ext.js";

/**
 * The compiled modules that make up the self-contained guard bundle.
 *
 * Exported because forgetting to add a file here is a silent failure of the
 * worst kind: the copied guard throws MODULE_NOT_FOUND in someone's session,
 * Claude Code treats the hook as errored, and the guard fails OPEN while the app
 * still says "enforcing". Keep this list in step with the guard's own
 * modules under main/guard/.
 */
export const GUARD_FILES = [
  "armed.js",
  "custom-rules.js",
  // One call, one decision across a host's several events (Cursor) — 2026-09-10.
  "dedup.js",
  "guard.js",
  "decision.js",
  "handshake.js",
  "hold.js",
  // Comment-preserving JSONC reader/editor for Gemini/Qwen/Droid/OpenClaw documents.
  "jsonc.js",
  // The host registry travels with the bundle — the guard resolves its host
  // (and that host's output contract) at runtime, inside the copy.
  "hosts/claude-family.js",
  "hosts/claude.js",
  "hosts/codex.js",
  "hosts/copilot.js",
  "hosts/crush.js",
  "hosts/cursor.js",
  "hosts/droid.js",
  "hosts/gemini.js",
  "hosts/goose.js",
  "hosts/grok.js",
  "hosts/hermes.js",
  "hosts/index.js",
  "hosts/kimi.js",
  "hosts/kiro.js",
  "hosts/openclaw.js",
  "hosts/opencode.js",
  "hosts/qwen.js",
  "hosts/types.js",
  "mcp-poison.js",
  "policy.js",
  "redact.js",
  "remedy.js",
  "rule-packs.js",
  // Which rules the app shows — policy.js narrows ALL_DETECTORS
  // through it, so the copied guard needs it too.
  "rule-scope.js",
  "second-opinion.js",
  "security-detect.js",
  "segments.js",
  "wallet-codec.js",
] as const;

export function guardDir(userDataDir: string): string {
  return join(userDataDir, "doorman", "guard");
}

/**
 * The command line installed for one host. The DEFAULT host's command is bare:
 * Claude Code's settings entry (and the trust keyed on the exact string) has
 * carried no argument since the first release, and rewriting it would re-ask
 * for trust on every machine. Every other host names itself.
 */
/**
 * Write a hook document in one step: the bytes land in a sibling temp file and
 * are renamed into place, so a host that reads the document at that very
 * moment (Copilot CLI re-reads `~/.copilot/hooks/*.json` at every session
 * start) sees the old text or the new text, never a half-written one. The
 * CLI's log carried exactly that on 2026-09-08 — "Invalid hook configuration
 * in …/doorman.json: hooks must be an object" — on a file whose content was
 * valid seconds later. A rename within one directory is atomic on APFS.
 */
export function writeDocumentAtomically(path: string, text: string): void {
  const temp = `${path}.doorman.tmp`;
  writeFileSync(temp, text);
  renameSync(temp, path);
}

export function guardCommand(userDataDir: string, host: string = DEFAULT_HOST.id): string {
  const base = `node "${join(guardDir(userDataDir), "guard.js")}"`;
  return host === DEFAULT_HOST.id ? base : `${base} --host ${host}`;
}

/** The user-level hook document(s) of one host, resolved against this machine. */
function hostUserDocuments(
  host: GuardHostDescriptor,
  env: NodeJS.ProcessEnv = process.env,
): string[] {
  return host
    .documents(homedir(), env)
    .filter((d) => d.level === "user")
    .map((d) => d.path);
}

/** Every user-level hook document the guard writes into, registry order. */
export function guardDocumentPaths(env: NodeJS.ProcessEnv = process.env): string[] {
  return HOSTS.flatMap((host) => hostUserDocuments(host, env));
}

/**
 * Every file the guard depends on BESIDE the hook documents, registry order:
 * each host's plugin artefacts (OpenClaw's three plugin files) and companion
 * documents (Hermes's consent allowlist). Deleting one of these leaves the
 * document's entry intact and the host silently unguarded, so the integrity
 * watcher watches them exactly like the documents.
 */
export function guardAuxiliaryPaths(env: NodeJS.ProcessEnv = process.env): string[] {
  const home = homedir();
  return HOSTS.flatMap((host) => [
    ...(host.artifacts?.(home, env) ?? []).map((artifact) => artifact.path),
    ...(host.companions ?? []).map((companion) => companion.path(home, env)),
  ]);
}

export function claudeSettingsPath(): string {
  return join(homedir(), ".claude", "settings.json");
}

export function codexHooksPath(env: NodeJS.ProcessEnv = process.env): string {
  const configured = env.CODEX_HOME?.trim();
  return join(configured || join(homedir(), ".codex"), "hooks.json");
}

function readDocument(path: string): string | undefined {
  try {
    return readFileSync(path, "utf8");
  } catch {
    return undefined;
  }
}

/**
 * The plugin artefacts a host needs on disk besides its hook document
 * (hosts/types.ts HostArtifact — OpenClaw's plugin directory today), resolved
 * against this machine. Empty for every host whose document alone carries the
 * hook. Exported for the doctor and the tests.
 */
export function hostArtifacts(
  host: GuardHostDescriptor,
  env: NodeJS.ProcessEnv = process.env,
): HostArtifact[] {
  return host.artifacts?.(homedir(), env) ?? [];
}

/** Write an artefact only when its bytes differ — this runs on every boot and
 * policy sync, and a no-op rewrite churns the host's file watchers. */
function writeArtifact(artifact: HostArtifact): void {
  if (readDocument(artifact.path) === artifact.content) return;
  mkdirSync(dirname(artifact.path), { recursive: true });
  writeFileSync(artifact.path, artifact.content);
}

/** Remove our artefacts, and the directory they lived in once it is empty —
 * the directory is ours (`…/extensions/doorman-guard/`), but a foreign file
 * that somehow landed in it is not, so an emptiness check stands in for
 * `rm -rf`. */
function removeArtifacts(artifacts: HostArtifact[]): void {
  const dirs = new Set<string>();
  for (const artifact of artifacts) {
    try {
      rmSync(artifact.path, { force: true });
    } catch {
      // best effort — a leftover artefact is inert without its config entry
    }
    dirs.add(dirname(artifact.path));
  }
  for (const dir of dirs) {
    try {
      if (readdirSync(dir).length === 0) rmSync(dir, { recursive: true, force: true });
    } catch {
      // already gone, or not ours to read
    }
  }
}

/** One host as this machine has it: its document, whether the host is here at
 * all, and whether our entry is in it. `present` is the host's own directory
 * (or an existing document) — writing unconditionally would CREATE ~/.codex on
 * a Claude-only Mac. */
export interface HostState {
  host: GuardHostDescriptor;
  docPath: string;
  doc: string | undefined;
  present: boolean;
  installed: boolean;
}

export function guardHostStates(env: NodeJS.ProcessEnv = process.env): HostState[] {
  const out: HostState[] = [];
  const home = homedir();
  for (const host of HOSTS) {
    // The host's own footprint decides presence — not the hook file's parent
    // directory, which for a host like Copilot CLI (`~/.copilot/hooks/`) does
    // not exist until WE create it, so keying on it would make the host
    // invisible to the install forever.
    const hostPresent = (host.presencePathsFor?.(home, env) ?? host.presencePaths)
      .some((p) => existsSync(p.startsWith("/") ? p : join(home, p)));
    for (const docPath of hostUserDocuments(host, env)) {
      const doc = readDocument(docPath);
      out.push({
        host,
        docPath,
        doc,
        present: doc !== undefined || hostPresent || existsSync(dirname(docPath)),
        installed: isGuardCommand(doc),
      });
    }
  }
  return out;
}

export function isGuardInstalled(): boolean {
  return guardHostStates().some((s) => s.installed);
}

/**
 * The hosts the guard is actually wired into — what the coverage card
 * (lib/shadow-ai.ts) computes `covered` from. BOTH keys per host, its `id` and
 * its `source`, because a catalog entry may be named after either.
 */
export function installedGuardHostIds(): string[] {
  const keys = new Set<string>();
  for (const state of guardHostStates()) {
    if (!state.installed) continue;
    keys.add(state.host.id);
    keys.add(state.host.source);
  }
  return [...keys];
}

/** One row per registered host for the renderer: is this host on the machine,
 * and is the guard in it? The Settings guard card renders from this instead of
 * naming Claude Code and Codex. */
export interface GuardHostSummary {
  id: string;
  label: string;
  source: string;
  doc_path: string;
  present: boolean;
  installed: boolean;
  /** The host can show its own confirmation prompt when we print `ask` — what
   * the Settings card's "if nobody answers" copy is written from. */
  native_ask: boolean;
}

export function guardHostSummaries(): GuardHostSummary[] {
  return guardHostStates().map((state) => ({
    id: state.host.id,
    label: state.host.label,
    source: state.host.source,
    doc_path: state.docPath,
    present: state.present,
    installed: state.installed,
    native_ask: state.host.supportsNativeAsk,
  }));
}

/**
 * Which Doorman build copied the guard bundle in, and what each file's hash was
 * then: `<guard dir>/bundle.json`. The app and the CLI are separate builds that
 * share this one bundle, and either may be the newer; the stamp is how each
 * recognises the other's bundle as a Doorman one — not tampering — and how an
 * older build knows not to replace a newer build's guard with its own.
 *
 * A bundle file edited after it was copied matches neither this build's
 * shipped files nor the stamp, so it is reported as before. (Like the rest of
 * the guard's files, the stamp sits in a user-writable folder: it guards
 * against a guard that drifted, not against someone rewriting both.)
 */
export interface GuardBundleStamp {
  writer: "app" | "cli";
  /** The writer's build revision (lib/build-info.ts): its commit time. */
  revision: number;
  commit?: string;
  files: Record<string, string>;
}

const BUNDLE_STAMP = "bundle.json";

export function readGuardBundleStamp(userDataDir: string): GuardBundleStamp | undefined {
  try {
    const raw: unknown = JSON.parse(readFileSync(join(guardDir(userDataDir), BUNDLE_STAMP), "utf8"));
    if (!raw || typeof raw !== "object") return undefined;
    const r = raw as Partial<GuardBundleStamp>;
    if ((r.writer !== "app" && r.writer !== "cli") || typeof r.revision !== "number" || !r.files || typeof r.files !== "object") return undefined;
    const files: Record<string, string> = {};
    for (const [name, hash] of Object.entries(r.files)) if (typeof hash === "string") files[name] = hash;
    return { writer: r.writer, revision: r.revision, ...(typeof r.commit === "string" ? { commit: r.commit } : {}), files };
  } catch {
    return undefined;
  }
}

/** The stamp's files are all on disk exactly as stamped. */
function stampIntact(userDataDir: string, stamp: GuardBundleStamp): boolean {
  const target = guardDir(userDataDir);
  const names = Object.keys(stamp.files);
  return names.length > 0 && names.every((name) => fileHash(join(target, name)) === stamp.files[name]);
}

/** What this process is, for the stamp: the Electron app, or the CLI under node. */
function bundleWriter(): GuardBundleStamp["writer"] {
  return process.versions.electron ? "app" : "cli";
}

/**
 * Copy the compiled guard bundle into userData (idempotent, cheap) — unless a
 * NEWER Doorman build's bundle is there intact: that one stays, so the app and
 * the CLI never downgrade each other's guard. Returns whether it copied.
 */
export function refreshGuardBundle(userDataDir: string): boolean {
  const target = guardDir(userDataDir);
  mkdirSync(target, { recursive: true });
  const own = buildInfo();
  const stamp = readGuardBundleStamp(userDataDir);
  if (stamp && stamp.revision > own.revision && stampIntact(userDataDir, stamp)) return false;
  // __dirname is build/main (or its packaged equivalent); the compiled guard
  // sits right next to this module.
  const from = join(__dirname, "guard");
  for (const file of GUARD_FILES) {
    const destination = join(target, file);
    // `hosts/…` — the registry ships as a subdirectory of the copied bundle.
    mkdirSync(dirname(destination), { recursive: true });
    // Temp + rename, like the policy: a guard spawned mid-copy would load a
    // half-written module, crash, and fail open on every host.
    const temp = `${destination}.doorman.tmp`;
    copyFileSync(join(from, file), temp);
    renameSync(temp, destination);
  }
  const files: Record<string, string> = {};
  for (const file of GUARD_FILES) {
    const hash = fileHash(join(target, file));
    if (hash !== undefined) files[file] = hash;
  }
  const next: GuardBundleStamp = { writer: bundleWriter(), revision: own.revision, ...(own.commit ? { commit: own.commit } : {}), files };
  const stampTemp = join(target, `${BUNDLE_STAMP}.doorman.tmp`);
  writeFileSync(stampTemp, `${JSON.stringify(next, null, 2)}\n`);
  renameSync(stampTemp, join(target, BUNDLE_STAMP));
  return true;
}

export function writeGuardPolicy(userDataDir: string, policy: GuardPolicy): void {
  const target = guardDir(userDataDir);
  mkdirSync(target, { recursive: true });
  // Atomic: a guard reading a torn policy.json falls back to the built-in
  // defaults for that call — a Locked-down policy, custom block rules and
  // exceptions all lost at once.
  writeDocumentAtomically(join(target, "policy.json"), `${JSON.stringify(policy, null, 2)}\n`);
}

/**
 * Publish the sessions currently carrying a live injection taint to the guard
 * (guard/armed.ts reads this before every tool call). Written whole on every
 * change — the file is a handful of sessions at most, and whole-write keeps the
 * guard's read atomic-enough (a torn read parses as not-JSON and arms nothing,
 * which is the fail-open direction everything else here already has).
 */
/**
 * Read back what is currently armed.
 *
 * The capture engine holds this map in memory and publishes it WHOLE on every
 * change, so a relaunch that starts empty silently disarms every session whose
 * transcript has not changed since — the agent is sitting at its next tool
 * call, so nothing re-parses it — the moment any other session publishes. The
 * next-call escalation for a still-poisoned session simply disappears, and
 * nobody is asked. Staleness is not this function's job: the guard re-checks
 * ARMED_MAX_AGE_MS at read time and the engine prunes by wall clock.
 */
export function readArmedSessions(
  userDataDir: string,
): Record<string, { taints: { name: string; at: string; excerpt: string }[]; updated_at: string }> {
  try {
    const raw = JSON.parse(readFileSync(join(guardDir(userDataDir), "armed.json"), "utf8")) as {
      sessions?: unknown;
    };
    const sessions = raw?.sessions;
    if (!sessions || typeof sessions !== "object" || Array.isArray(sessions)) return {};
    const out: Record<string, { taints: { name: string; at: string; excerpt: string }[]; updated_at: string }> = {};
    for (const [sessionId, value] of Object.entries(sessions as Record<string, unknown>)) {
      if (!value || typeof value !== "object") continue;
      const entry = value as { taints?: unknown; updated_at?: unknown };
      if (!Array.isArray(entry.taints)) continue;
      const taints = entry.taints.filter(
        (t): t is { name: string; at: string; excerpt: string } =>
          !!t &&
          typeof t === "object" &&
          typeof (t as { name?: unknown }).name === "string" &&
          typeof (t as { at?: unknown }).at === "string",
      );
      if (taints.length === 0) continue;
      out[sessionId] = {
        taints,
        updated_at: typeof entry.updated_at === "string" ? entry.updated_at : taints[0]!.at,
      };
    }
    return out;
  } catch {
    return {};
  }
}

export function writeArmedSessions(
  userDataDir: string,
  sessions: Record<string, { taints: { name: string; at: string; excerpt: string }[]; updated_at: string }>,
): void {
  const target = guardDir(userDataDir);
  mkdirSync(target, { recursive: true });
  writeDocumentAtomically(join(target, "armed.json"), `${JSON.stringify({ version: 1, sessions }, null, 2)}\n`);
}

/** The "there is nothing here to guard" sentence, built from the registry so a
 * new host joins it without an edit. With Claude Code and Codex registered it
 * reads exactly as it always has. */
function nothingToInstallInto(): string {
  const labels = HOSTS.map((h) => h.label);
  const where = HOSTS.flatMap((h) => h.presencePaths).map((p) => (p.startsWith("/") ? p : `~/${p}`));
  const who =
    labels.length === 2 ? `Neither ${labels[0]} nor ${labels[1]}` : `None of ${labels.join(", ")}`;
  const paths = where.length === 2 ? `${where[0]} or ${where[1]}` : where.join(", ");
  return `${who} was found on this machine (no ${paths}), so there is nothing to install the guard into.`;
}

/** A host the install (or removal) could not reach, and the host's own reason
 * — its merge's refusal ("~/.hermes/config.yaml is … ; not touching it") or
 * the write that failed. */
export interface GuardHostFailure {
  id: string;
  label: string;
  error: string;
}

/**
 * What installGuard did. `ok` means the guard is enforcing in at least one
 * agent; `failures` lists every present host it could not reach — those keep
 * whatever they had before (an older entry, or none), untouched.
 */
export type GuardInstallOutcome =
  | { ok: true; codex_restart_required: boolean; failures: GuardHostFailure[] }
  | { ok: false; error: string; failures?: GuardHostFailure[] };

/** One sentence per failing host, named — what `guard_sync_error` carries.
 * No closing period, so whoever shows it can end the sentence. */
export function describeGuardFailures(failures: readonly GuardHostFailure[]): string {
  return failures.map((f) => `${f.label}: ${f.error.replace(/\.+$/, "")}`).join(". ");
}

/** The problem to show for an install outcome, or undefined when every present
 * host took the guard. A partial install is a problem too: an agent the guard
 * couldn't reach runs an older policy, or none. */
export function guardInstallProblem(outcome: GuardInstallOutcome): string | undefined {
  if (!outcome.ok) return outcome.error;
  return outcome.failures.length > 0 ? describeGuardFailures(outcome.failures) : undefined;
}

const errorText = (err: unknown): string => (err instanceof Error ? err.message : String(err));

export function installGuard(userDataDir: string, policy: GuardPolicy): GuardInstallOutcome {
  try {
    // The effective per-hook timeout: it must EXCEED the hold window, or the
    // host kills the guard mid-hold and a killed hook fails open (which would
    // quietly turn "deny when nobody answers" into "allow when nobody
    // answers"). hookTimeoutSeconds owns that arithmetic; a descriptor's
    // merge() only has to write it wherever its document keeps a timeout.
    const timeout = hookTimeoutSeconds(policy);
    // A host is only wired when it exists on this machine: its own directory,
    // or our marker already in its hook file. Writing unconditionally used to
    // CREATE ~/.codex (and, symmetrically, ~/.claude on a Codex-only Mac),
    // making the tool look installed where it is not.
    const states = guardHostStates();
    const present = states.filter((s) => s.present);
    if (present.length === 0) {
      // Nothing to guard — say so rather than flip a switch that enforces
      // nowhere while the UI reads "enforcing".
      return { ok: false, error: nothingToInstallInto() };
    }
    // Plan each host on its own: its hook document(s), its companion documents
    // (a consent allowlist) and its plugin artefacts, all parsed and built
    // before anything of that host is written. A host whose plan refuses —
    // a hook document or companion its merge can't follow — is skipped whole
    // and reported, so it is never left half-on (a companion entry with no
    // hook, a hook pointing at a plugin that isn't there). It no longer takes
    // the other hosts down with it: one Hermes config the YAML reader can't
    // follow used to leave Claude, Codex and every other agent unguarded.
    const home = homedir();
    const failures: GuardHostFailure[] = [];
    type PlannedDocument = { path: string; doc: string | undefined; next: string };
    const plans: {
      host: GuardHostDescriptor;
      hooks: PlannedDocument[];
      companions: PlannedDocument[];
      artifacts: HostArtifact[];
    }[] = [];
    for (const host of [...new Set(present.map((s) => s.host))]) {
      try {
        const command = guardCommand(userDataDir, host.id);
        const hooks = present
          .filter((s) => s.host === host)
          .map((s) => ({
            path: s.docPath,
            doc: s.doc,
            next: host.merge(s.doc, command, policy.confirm.hold_seconds, timeout),
          }));
        const companions = (host.companions ?? []).map((companion) => {
          const path = companion.path(home, process.env);
          const doc = readDocument(path);
          return { path, doc, next: companion.merge(doc, command) };
        });
        plans.push({ host, hooks, companions, artifacts: hostArtifacts(host) });
      } catch (err) {
        failures.push({ id: host.id, label: host.label, error: errorText(err) });
      }
    }
    // No host could take the guard: write nothing (not even the policy, as
    // before) and keep the switch off rather than read "enforcing".
    if (plans.length === 0) return { ok: false, error: describeGuardFailures(failures), failures };
    refreshGuardBundle(userDataDir);
    writeGuardPolicy(userDataDir, policy);
    // Write only what changed: this runs on every boot and policy sync, and a
    // no-op rewrite still reformats the file and churns its mtime — plus, on
    // the Codex side, a rewrite is what invites the trust system to re-ask.
    // A sandboxed run stops here: bundle + policy live inside the sandbox and
    // were just refreshed; the hook documents live in the real home.
    if (!hookWritesAllowed()) return { ok: false, error: SANDBOX_READ_ONLY };
    let codexChanged = false;
    let installed = 0;
    const writeChanged = ({ path, doc, next }: PlannedDocument): boolean => {
      if (next === doc) return false;
      mkdirSync(dirname(path), { recursive: true });
      writeDocumentAtomically(path, next);
      return true;
    };
    for (const plan of plans) {
      try {
        // What the entry points at (plugin files, consent) first, the hook
        // entry last: a write that fails midway leaves inert files behind,
        // never an entry pointing at nothing.
        for (const artifact of plan.artifacts) writeArtifact(artifact);
        for (const companion of plan.companions) writeChanged(companion);
        for (const hook of plan.hooks) {
          if (writeChanged(hook) && plan.host.id === "codex") codexChanged = true;
        }
        installed += 1;
      } catch (err) {
        failures.push({ id: plan.host.id, label: plan.host.label, error: errorText(err) });
        continue;
      }
      // One-time upgrade hygiene (2026-09-10): the Hermes shell-hook install
      // left a consent entry for a command that is no longer configured; the
      // plugin path needs none. Best-effort, our entries only.
      if (plan.host.id === hermesHost.id) {
        try {
          const allowlist = `${hermesHome(home, process.env)}/shell-hooks-allowlist.json`;
          const cleaned = withoutLegacyAllowlistEntries(readDocument(allowlist));
          if (cleaned !== undefined) writeDocumentAtomically(allowlist, cleaned);
        } catch {
          // a stale consent entry for a command nobody runs is inert
        }
      }
    }
    if (installed === 0) return { ok: false, error: describeGuardFailures(failures), failures };
    return { ok: true, codex_restart_required: codexChanged, failures };
  } catch (err) {
    return { ok: false, error: errorText(err) };
  }
}

/**
 * Push a policy change out to wherever it has to land. The hold window is
 * encoded in the hook's `timeout` as well as policy.json, so changing it has to
 * re-merge settings.json — otherwise a 300s hold would be killed at 75s and
 * fail open, which is the one outcome the policy said not to have.
 *
 * Returns the failure instead of swallowing it: a settings.json the merge
 * refuses to touch (malformed JSON) means the guard on disk is now drifting
 * from the policy the app displays, and the caller has to be able to say so.
 * A host the re-merge couldn't reach is that failure too, named, even while
 * the others took the new policy.
 */
export function syncGuard(
  userDataDir: string,
  policy: GuardPolicy,
): { ok: true } | { ok: false; error: string } {
  try {
    if (isGuardInstalled()) {
      const outcome = installGuard(userDataDir, policy);
      const problem = guardInstallProblem(outcome);
      return problem === undefined ? { ok: true } : { ok: false, error: problem };
    }
    writeGuardPolicy(userDataDir, policy);
    return { ok: true };
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : String(err) };
  }
}

/**
 * Take our entry out of every host, each on its own: a host whose document
 * can't be rewritten is reported and the rest are still removed. Within one
 * host the hook document goes first; its companions and plugin artefacts are
 * only removed once it has, so a failure never strands an entry pointing at
 * nothing. Not ok while any host still carries the guard.
 */
export function uninstallGuard(): { ok: true } | { ok: false; error: string } {
  try {
    if (!hookWritesAllowed()) return { ok: false, error: SANDBOX_READ_ONLY };
    const home = homedir();
    const states = guardHostStates();
    const failures: GuardHostFailure[] = [];
    for (const host of HOSTS) {
      try {
        for (const state of states.filter((s) => s.host === host)) {
          const next = host.remove(state.doc);
          if (next !== undefined) writeDocumentAtomically(state.docPath, next);
        }
        for (const companion of host.companions ?? []) {
          const path = companion.path(home, process.env);
          const next = companion.remove(readDocument(path));
          if (next !== undefined) writeDocumentAtomically(path, next);
        }
        removeArtifacts(hostArtifacts(host));
      } catch (err) {
        failures.push({ id: host.id, label: host.label, error: errorText(err) });
      }
    }
    return failures.length === 0 ? { ok: true } : { ok: false, error: describeGuardFailures(failures) };
  } catch (err) {
    return { ok: false, error: errorText(err) };
  }
}

/**
 * The app's "I am here" file. The guard reads it to decide whether holding a
 * tool call could ever be answered — no heartbeat, no hold (guard.ts rule 3).
 * Written on a short interval and REMOVED on quit, so a crash degrades to a
 * stale timestamp rather than a permanent lie.
 */
export class GuardHeartbeat {
  private timer: NodeJS.Timeout | undefined;

  constructor(
    private readonly deps: { userDataDir: string; version: string; log(message: string): void },
  ) {}

  private path(): string {
    return heartbeatPath(guardDir(this.deps.userDataDir));
  }

  start(intervalMs = 15_000): void {
    this.stop();
    this.beat();
    this.timer = setInterval(() => this.beat(), intervalMs);
    this.timer.unref?.();
  }

  stop(): void {
    if (this.timer) clearInterval(this.timer);
    this.timer = undefined;
  }

  /** Called on quit: a guard spawned after this must not wait for us. */
  clear(): void {
    this.stop();
    try {
      rmSync(this.path(), { force: true });
    } catch {
      // a stale beat expires on its own
    }
  }

  private beat(): void {
    const now = new Date();
    const payload = `${JSON.stringify({
      at: now.toISOString(),
      pid: process.pid,
      version: this.deps.version,
    })}\n`;
    try {
      mkdirSync(guardDir(this.deps.userDataDir), { recursive: true });
      writeFileSync(this.path(), payload);
    } catch (err) {
      this.deps.log(`couldn't write the guard heartbeat: ${String(err)}`);
    }
  }
}

function pidAlive(pid: number): boolean {
  if (!pid) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    // EPERM means it exists and isn't ours to signal — still alive.
    return (err as { code?: string }).code === "EPERM";
  }
}

/** Grace beyond a request's own hold window before we sweep it: the guard is
 * the one that times out, and it should get there first. */
const SWEEP_GRACE_MS = 20_000;

/**
 * Watch the pending-approval directory: surface each held tool call, write the
 * verdict back, and sweep the ones nobody can answer any more.
 *
 * Polling (not just fs.watch) because the whole feature is a person waiting: a
 * missed watch event would look like the app ignoring a blocked session. The
 * directory holds a handful of files at most, so the poll is free.
 */
export class ApprovalWatcher {
  private watcher: FSWatcher | undefined;
  private timer: NodeJS.Timeout | undefined;
  private pending = new Map<string, ApprovalRequest>();

  constructor(
    private readonly deps: {
      userDataDir: string;
      /** The visible queue changed (new, answered, swept). */
      onChange(pending: ApprovalRequest[]): void;
      /** A request nobody has seen yet — notify, raise the window. */
      onNew(request: ApprovalRequest): void;
      /**
       * Someone answered in the EDITOR. The VS Code extension writes
       * `<id>.answer.json` here rather than the `<id>.reply.json` the guard is
       * waiting on, so the app still owns everything that goes with a verdict:
       * the policy write behind "stop asking", the finding's resolution, the
       * spool line. The handler is expected to call the same resolve path the
       * app's own window does.
       */
      onAnswer?(answer: EditorAnswer): void;
      log(message: string): void;
    },
  ) {}

  private dir(): string {
    return pendingDir(guardDir(this.deps.userDataDir));
  }

  start(intervalMs = 300): void {
    try {
      mkdirSync(this.dir(), { recursive: true });
      this.watcher = watch(this.dir(), () => this.poll());
      this.watcher.on("error", (err) => this.deps.log(`approval watch error: ${String(err)}`));
    } catch (err) {
      this.deps.log(`couldn't watch pending approvals: ${String(err)}`);
    }
    this.poll();
    this.timer = setInterval(() => this.poll(), intervalMs);
    this.timer.unref?.();
  }

  stop(): void {
    this.watcher?.close();
    this.watcher = undefined;
    if (this.timer) clearInterval(this.timer);
    this.timer = undefined;
  }

  list(): ApprovalRequest[] {
    return [...this.pending.values()].sort((a, b) => (a.at < b.at ? -1 : a.at > b.at ? 1 : 0));
  }

  /** Answer a held call. Returns false when it's already gone (the guard timed
   * out, or Claude Code killed it) — the UI then just drops the card. The
   * options ride the reply so the guard's spool line records how (and from
   * which surface) the person decided. */
  resolve(
    id: string,
    verdict: ApprovalVerdict,
    options: SecurityDetectorId[] | { silenced?: SecurityDetectorId[]; via?: ApprovalVia; allow_scope?: "project" } = {},
  ): boolean {
    const request = this.pending.get(id);
    if (!request) return false;
    const opts = Array.isArray(options) ? { silenced: options } : options;
    try {
      writeReply(guardDir(this.deps.userDataDir), {
        id,
        verdict,
        at: new Date().toISOString(),
        silenced: opts.silenced,
        ...(opts.via === undefined ? {} : { via: opts.via }),
        ...(opts.allow_scope === undefined ? {} : { allow_scope: opts.allow_scope }),
      });
    } catch (err) {
      this.deps.log(`couldn't write approval reply: ${String(err)}`);
      return false;
    }
    // Drop it from the queue immediately: the guard deletes both files as it
    // exits, and the card must not linger while that happens.
    this.pending.delete(id);
    this.deps.onChange(this.list());
    return true;
  }

  poll(): void {
    let entries: string[];
    try {
      entries = readdirSync(this.dir());
    } catch {
      return; // no pending dir yet
    }
    const seen = new Set<string>();
    const fresh: ApprovalRequest[] = [];
    const answers: string[] = [];
    let changed = false;
    const nowMs = Date.now();
    for (const entry of entries) {
      // An editor answer lives beside the exchange and is NOT a request. It has
      // to be excluded by name: it carries an `id` and an `at`, so parseRequest
      // would happily read it as a second, phantom held call.
      if (entry.endsWith(".answer.json")) {
        answers.push(entry);
        continue;
      }
      if (!entry.endsWith(".json") || entry.endsWith(".reply.json")) continue;
      const id = entry.slice(0, -".json".length);
      const path = join(this.dir(), entry);
      let request = this.pending.get(id);
      if (!request) {
        let json: string;
        try {
          json = readFileSync(path, "utf8");
        } catch {
          continue; // being written right now; next poll picks it up
        }
        const parsed = parseRequest(json);
        if (!parsed) continue;
        request = parsed;
      }
      // Expired or orphaned: the guard has already answered on its own (or been
      // killed), so asking now would collect a verdict nothing is waiting for.
      const expiresAt = Date.parse(request.at) + request.hold_seconds * 1000 + SWEEP_GRACE_MS;
      if (nowMs > expiresAt || !pidAlive(request.pid)) {
        try {
          rmSync(path, { force: true });
        } catch {
          // it'll come round again
        }
        if (this.pending.delete(id)) changed = true;
        continue;
      }
      seen.add(id);
      if (!this.pending.has(id)) {
        this.pending.set(id, request);
        fresh.push(request);
        changed = true;
      }
    }
    for (const id of [...this.pending.keys()]) {
      if (!seen.has(id)) {
        this.pending.delete(id);
        changed = true;
      }
    }
    if (changed) this.deps.onChange(this.list());
    for (const request of fresh) this.deps.onNew(request);
    this.drainAnswers(answers);
  }

  /**
   * Apply what the editor answered. Every answer is CONSUMED (deleted) whether
   * or not it is acted on, so a file the app cannot use — malformed, or about a
   * call that has since timed out — can never be replayed on the next poll.
   *
   * The id comes from the FILE NAME, not from the document: a hand-written
   * answer must not be able to decide a different call than the one it is
   * named for.
   */
  private drainAnswers(entries: string[]): void {
    for (const entry of entries) {
      const path = join(this.dir(), entry);
      const id = entry.slice(0, -".answer.json".length);
      let answer: EditorAnswer | undefined;
      try {
        answer = parseEditorAnswer(readFileSync(path, "utf8"));
      } catch {
        answer = undefined;
      }
      try {
        rmSync(path, { force: true });
      } catch {
        // An answer we cannot delete would be applied again every poll, which
        // is worse than dropping it; the sweep will get the file.
        continue;
      }
      if (!answer || answer.id !== id) continue;
      if (!this.pending.has(id)) continue; // already answered, or long gone
      this.deps.onAnswer?.(answer);
    }
  }

  /** Does a request file still exist? (Used by tests and diagnostics.) */
  has(id: string): boolean {
    return existsSync(requestPath(guardDir(this.deps.userDataDir), id));
  }
}

/** sha256 of a file, or undefined when it can't be read. */
function fileHash(path: string): string | undefined {
  try {
    return createHash("sha256").update(readFileSync(path)).digest("hex");
  } catch {
    return undefined;
  }
}

/** The hashes the copied bundle (userData) should have, and the ones it has —
 * what the integrity check compares. Expected is this build's own shipped
 * guard/, or — when another Doorman build (the app, the CLI) copied its bundle
 * in and it is intact as that build stamped it — that build's: then nothing
 * drifted, it is just the other build's guard. */
export function guardBundleHashes(userDataDir: string): {
  shipped: Record<string, string>;
  copied: Record<string, string | undefined>;
} {
  const source = join(__dirname, "guard");
  const target = guardDir(userDataDir);
  // Another build's: a different revision. A stamp claiming THIS revision
  // must match this build's own files, so it falls through to them.
  const stamp = readGuardBundleStamp(userDataDir);
  if (stamp && stamp.revision !== buildInfo().revision && stampIntact(userDataDir, stamp)) {
    return { shipped: { ...stamp.files }, copied: Object.fromEntries(Object.keys(stamp.files).map((f) => [f, fileHash(join(target, f))])) };
  }
  const shipped: Record<string, string> = {};
  const copied: Record<string, string | undefined> = {};
  for (const file of GUARD_FILES) {
    const hash = fileHash(join(source, file));
    // A shipped file the app itself can't read is a build problem, not a
    // tampering report — leave it out rather than flag every user.
    if (hash === undefined) continue;
    shipped[file] = hash;
    copied[file] = fileHash(join(target, file));
  }
  return { shipped, copied };
}

/**
 * Is the guard still where the app put it, and still what the app shipped?
 * One read of both hook documents plus a hash of the copied bundle; the pure
 * verdict lives in lib/guard-integrity.ts. `heal` re-copies a drifted bundle
 * from the app (the entry is NOT re-added — that is the person's decision,
 * offered through the notification's action).
 */
export function checkGuardIntegrity(
  userDataDir: string,
  wanted: boolean,
  options: { heal?: boolean } = {},
): GuardIntegrityReport {
  const hashes = guardBundleHashes(userDataDir);
  let report = assessGuardIntegrity({
    wanted,
    hosts: guardHostStates().map((state) => {
      const expected = guardCommand(userDataDir, state.host.id);
      // Ask the host's own descriptor whether its document carries our entry
      // exactly — each host keeps the hook in its own shape, and the generic
      // PreToolUse walk read a correct Cursor / Gemini / Copilot entry as
      // missing (a "tampered" banner that Reinstall could never clear).
      // Readable in the host's OWN format: a YAML or TOML document (Hermes,
      // Kimi Code) is not malformed for failing JSON.parse.
      const unreadable = !documentReadable(state.host, state.doc);
      return {
        host: state.host.source,
        label: state.host.label,
        doc_path: state.docPath,
        present: state.present,
        doc: state.doc,
        expected_command: expected,
        unreadable,
        entry_present: state.installed,
        entry_exact: !unreadable && state.installed && state.host.installed(state.doc, expected),
        // The two halves the marker cannot see: a plugin host's files beside
        // the document, and a companion document's consent entry. Compared
        // against exactly what installGuard would write, so "would a
        // reinstall change anything" is the whole question.
        artifacts_missing: hostArtifacts(state.host)
          .filter((artifact) => readDocument(artifact.path) !== artifact.content)
          .map((artifact) => artifact.path),
        companions_missing: (state.host.companions ?? [])
          .map((companion) => companion.path(homedir(), process.env))
          .filter((path, index) => {
            const doc = readDocument(path);
            try {
              return state.host.companions![index]!.merge(doc, expected) !== doc;
            } catch {
              return true; // unparseable: the host cannot read its consent either
            }
          }),
      };
    }),
    shipped: hashes.shipped,
    copied: hashes.copied,
    policy_readable: existsSync(join(guardDir(userDataDir), "policy.json")),
  });
  const bundleDrifted = report.bundle_missing.length > 0 || report.bundle_modified.length > 0;
  if (options.heal !== false && bundleDrifted && (wanted || report.status === "tampered")) {
    // A modified bundle is a modified detector: restore the shipped one. The
    // report still says it happened — healing is not the same as nothing.
    try {
      refreshGuardBundle(userDataDir);
      report = { ...report, healed_bundle: true };
    } catch {
      // unwritable userData: the report stands as-is
    }
  }
  return report;
}

/**
 * Watch every registered host's hook document and the copied bundle for anything that is not
 * this app changing them. fs.watch where the file exists, a slow interval
 * everywhere, a size+mtime cursor so an untouched file costs a stat — the
 * mcp-watch.ts shape. Reports every check; the caller decides what a change
 * in status means (notify, mint a radar row, offer reinstall).
 */
export class GuardIntegrityWatcher {
  private watchers = new Map<string, FSWatcher>();
  private timer: NodeJS.Timeout | undefined;
  private debounce: NodeJS.Timeout | undefined;
  private cursors = new Map<string, { size: number; mtimeMs: number }>();
  private last: GuardIntegrityReport | undefined;

  constructor(
    private readonly deps: {
      userDataDir: string;
      wanted(): boolean;
      onReport(report: GuardIntegrityReport, previous: GuardIntegrityReport | undefined): void;
      log(message: string): void;
    },
  ) {}

  private paths(): string[] {
    return [...guardDocumentPaths(), ...guardAuxiliaryPaths()];
  }

  start(intervalMs = 60_000): void {
    this.sweep(true);
    this.timer = setInterval(() => this.sweep(false), intervalMs);
    this.timer.unref?.();
  }

  stop(): void {
    for (const watcher of this.watchers.values()) watcher.close();
    this.watchers.clear();
    if (this.timer) clearInterval(this.timer);
    if (this.debounce) clearTimeout(this.debounce);
    this.timer = undefined;
  }

  latest(): GuardIntegrityReport | undefined {
    return this.last;
  }

  /** Run the check now (after an install/uninstall the app itself made, so
   * the report reflects the new intent immediately). */
  check(): GuardIntegrityReport {
    const report = checkGuardIntegrity(this.deps.userDataDir, this.deps.wanted());
    const previous = this.last;
    this.last = report;
    this.deps.onReport(report, previous);
    return report;
  }

  private sweep(force: boolean): void {
    let changed = force;
    for (const path of this.paths()) {
      this.ensureWatch(path);
      let size = -1;
      let mtimeMs = -1;
      try {
        const stat = statSync(path);
        size = stat.size;
        mtimeMs = stat.mtimeMs;
      } catch {
        // absent — a cursor of -1/-1 records that too
      }
      const cursor = this.cursors.get(path);
      if (!cursor || cursor.size !== size || cursor.mtimeMs !== mtimeMs) {
        this.cursors.set(path, { size, mtimeMs });
        changed = true;
      }
    }
    // The bundle is hashed on every sweep regardless — a rewritten guard file
    // leaves the hook documents untouched.
    if (!changed && this.last && this.last.bundle_modified.length === 0 && this.last.bundle_missing.length === 0) {
      const hashes = guardBundleHashes(this.deps.userDataDir);
      changed = Object.entries(hashes.shipped).some(([file, hash]) => hashes.copied[file] !== hash);
    }
    if (changed) this.check();
  }

  private ensureWatch(path: string): void {
    if (this.watchers.has(path)) return;
    try {
      const watcher = watch(path, () => {
        if (this.debounce) clearTimeout(this.debounce);
        this.debounce = setTimeout(() => this.sweep(false), 500);
      });
      watcher.on("error", () => {
        this.watchers.get(path)?.close();
        this.watchers.delete(path);
      });
      this.watchers.set(path, watcher);
    } catch {
      // doesn't exist yet — the interval sweep re-arms it
    }
  }
}

/**
 * Tail the guard's spool.jsonl. The offset persists in the store dir so
 * findings raised while the app was closed are ingested on next launch —
 * that's the point of spooling instead of any live channel.
 */
export class SpoolWatcher {
  private watcher: FSWatcher | undefined;
  private timer: NodeJS.Timeout | undefined;
  private offset = 0;

  constructor(
    private readonly deps: {
      userDataDir: string;
      storeDir: string;
      onLines(lines: string[]): void;
      log(message: string): void;
    },
  ) {}

  private spoolPath(): string {
    return join(guardDir(this.deps.userDataDir), "spool.jsonl");
  }

  private offsetPath(): string {
    return join(this.deps.storeDir, "spool-offset.json");
  }

  start(): void {
    try {
      const raw = JSON.parse(readFileSync(this.offsetPath(), "utf8")) as { offset?: number };
      if (typeof raw.offset === "number" && raw.offset >= 0) this.offset = raw.offset;
    } catch {
      this.offset = 0;
    }
    this.drain();
    const dir = guardDir(this.deps.userDataDir);
    if (existsSync(dir)) {
      try {
        this.watcher = watch(dir, () => this.drain());
        this.watcher.on("error", (err) => this.deps.log(`spool watch error: ${String(err)}`));
      } catch (err) {
        this.deps.log(`couldn't watch spool: ${String(err)}`);
      }
    }
    this.timer = setInterval(() => this.drain(), 15_000);
    this.timer.unref?.();
  }

  stop(): void {
    this.watcher?.close();
    this.watcher = undefined;
    if (this.timer) clearInterval(this.timer);
    this.timer = undefined;
  }

  drain(): void {
    const path = this.spoolPath();
    let size: number;
    try {
      size = statSync(path).size;
    } catch {
      return; // no spool yet
    }
    if (size < this.offset) this.offset = 0; // spool was reset
    if (size === this.offset) return;
    let contents: Buffer;
    try {
      contents = readFileSync(path);
    } catch (err) {
      this.deps.log(`couldn't read spool: ${String(err)}`);
      return;
    }
    // The offset is in BYTES (that's what statSync reports), so all slicing
    // happens on the buffer — excerpts can carry multibyte characters.
    const chunk = contents.subarray(this.offset);
    // Only consume complete lines; a partially-written tail stays for next time.
    const lastNewline = chunk.lastIndexOf(0x0a);
    if (lastNewline < 0) return;
    const lines = chunk.subarray(0, lastNewline).toString("utf8").split("\n");
    // Hand the lines over BEFORE advancing the durable cursor. The other order
    // consumed them first: if the engine threw, the offset had already moved
    // past findings that were never ingested, and the guard writes this file
    // precisely so its findings survive a closed app. A throw now leaves the
    // cursor where it was and the next poll re-reads the same lines, which the
    // engine already merges idempotently.
    if (lines.length > 0) {
      try {
        this.deps.onLines(lines);
      } catch (err) {
        this.deps.log(`couldn't ingest spool lines, leaving them for the next poll: ${String(err)}`);
        return;
      }
    }
    this.offset += lastNewline + 1;
    try {
      writeFileSync(this.offsetPath(), `${JSON.stringify({ offset: this.offset })}\n`);
    } catch (err) {
      this.deps.log(`couldn't persist spool offset: ${String(err)}`);
    }
  }
}
