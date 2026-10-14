/**
 * Guard self-integrity — is the guard still where the app put it, and is it
 * still what the app shipped?
 *
 * The guard is a PreToolUse entry in two hook documents plus a directory of
 * compiled files copied to userData. Either half can be altered by something
 * that is not this app: an agent that "tidied" settings.json (the
 * `agent_config_tamper` detector sees the write but ships observe), another
 * installer rewriting the hooks block, a person hand-editing, a stray `rm`.
 * Every one of those is a SILENT fail-open — the hook simply stops running and
 * the app keeps saying "enforcing" — which is the one failure a guard must not
 * have quietly.
 *
 * Pure: the caller (enforcement.ts GuardIntegrityWatcher) reads the documents
 * and hashes the files; this decides what they mean. `wanted` is the person's
 * intent (prefs.guard_wanted) — a missing entry is tampering only when the
 * guard is supposed to be there, so switching it off in Settings is never
 * reported as an attack on itself.
 */

import { hookDocumentCommands } from "../guard/policy.js";

export type IntegrityProblem =
  | "entry_missing"
  | "entry_altered"
  /** A host's plugin artefact (OpenClaw's `extensions/doorman-guard/*`) is
   * gone or no longer the bytes the app wrote — the entry in the document
   * still points at it, so the marker check alone reads "installed" while the
   * host loads nothing. */
  | "artifact_missing"
  /** A host's companion document (Hermes's consent allowlist) no longer
   * carries our entry — the hook is declared but the host skips it. */
  | "companion_missing"
  | "bundle_missing"
  | "bundle_modified"
  | "policy_unreadable";

export interface HostIntegrity {
  /** The host's `source` string (guard/hosts/<host>.ts) — "claude-code",
   * "codex", and whatever the registry grows next. */
  host: string;
  /** The host's human label, for the sentence describeIntegrity writes. */
  label?: string;
  doc_path: string;
  /** The host exists on this machine (its home directory or hook file does). */
  present: boolean;
  /** Our marker appears in the document at all. */
  entry_present: boolean;
  /** The entry's command is exactly the one the app would write. */
  entry_exact: boolean;
  /** The document could not be parsed (so nothing above is knowable). */
  unreadable?: boolean;
  /** Plugin artefact paths that are absent or differ from what the app writes. */
  artifacts_missing?: string[];
  /** Companion document paths whose merge would change them (our entry is
   * gone) or that no longer parse. */
  companions_missing?: string[];
}

export interface GuardIntegrityReport {
  checked_at: string;
  /** The person wants the guard installed (prefs.guard_wanted). */
  wanted: boolean;
  status: "healthy" | "tampered" | "not_installed" | "unknown";
  problems: IntegrityProblem[];
  hosts: HostIntegrity[];
  /** Bundle files whose hash differs from the shipped copy, or are missing. */
  bundle_modified: string[];
  bundle_missing: string[];
  /** The bundle was re-copied from the app on this check (self-heal). */
  healed_bundle?: boolean;
}

export interface IntegrityInputs {
  wanted: boolean;
  hosts: Array<{
    host: string;
    label?: string;
    doc_path: string;
    present: boolean;
    /** The document text, or undefined when absent. */
    doc?: string;
    /** The command the app would install for this host (enforcement.ts guardCommand). */
    expected_command: string;
    /**
     * What the host's OWN descriptor says about the document (guard/hosts/
     * <host>.ts `installed()` + the marker), supplied by the caller. Every host
     * keeps its hook in a different shape — Claude Code and Codex under
     * `hooks.PreToolUse[].hooks[].command`, Cursor under three event arrays,
     * Gemini under `hooks.BeforeTool`, Copilot under `preToolUse[].bash` — so
     * the generic PreToolUse walk below only ever understood the first two, and
     * read a perfectly installed Cursor / Gemini / Copilot entry as MISSING:
     * "changed outside the app", Reinstall wrote the same correct file, and the
     * banner came straight back. When these are given they are the verdict;
     * the walk stays as the fallback for callers that don't know the host.
     */
    entry_present?: boolean;
    entry_exact?: boolean;
    unreadable?: boolean;
    /** Artefact paths the host needs beside its document that are absent or
     * altered (enforcement.ts compares bytes against `artifacts()`). A host
     * whose hook lives in the document alone passes none. */
    artifacts_missing?: string[];
    /** Companion documents whose `merge()` would change them — our consent
     * entry is gone — or that fail to parse. */
    companions_missing?: string[];
  }>;
  /** file → sha256 of the SHIPPED module (inside the app). */
  shipped: Record<string, string>;
  /** file → sha256 of the COPIED module in userData; undefined = missing. */
  copied: Record<string, string | undefined>;
  policy_readable: boolean;
  now?: Date;
}

/** Every handler command in the document's PreToolUse groups that carries our
 * marker. Tolerates any shape; a malformed document yields `undefined`. The
 * hook-document walk itself lives in guard/policy.ts, next to the surgery that
 * writes those entries (and inside the copied bundle, where the host
 * descriptors' `installed()` needs it too). */
export const guardCommandsIn = hookDocumentCommands;

export function assessGuardIntegrity(inputs: IntegrityInputs): GuardIntegrityReport {
  const now = inputs.now ?? new Date();
  const problems = new Set<IntegrityProblem>();
  const hosts: HostIntegrity[] = [];
  let anyEntry = false;
  for (const host of inputs.hosts) {
    const label = host.label === undefined ? {} : { label: host.label };
    if (host.unreadable) {
      hosts.push({ host: host.host, ...label, doc_path: host.doc_path, present: host.present, entry_present: false, entry_exact: false, unreadable: true });
      continue;
    }
    // The host's own verdict when the caller has one; the PreToolUse walk
    // (Claude Code / Codex shape) only as the fallback.
    const commands = host.entry_present === undefined ? guardCommandsIn(host.doc) : [];
    if (host.entry_present === undefined && commands === undefined) {
      hosts.push({ host: host.host, ...label, doc_path: host.doc_path, present: host.present, entry_present: false, entry_exact: false, unreadable: true });
      continue;
    }
    const entryPresent = host.entry_present ?? (commands as string[]).length > 0;
    const entryExact = host.entry_exact ?? (commands as string[]).some((c) => c === host.expected_command);
    if (entryPresent) anyEntry = true;
    const artifactsMissing = host.artifacts_missing ?? [];
    const companionsMissing = host.companions_missing ?? [];
    hosts.push({
      host: host.host,
      ...label,
      doc_path: host.doc_path,
      present: host.present,
      entry_present: entryPresent,
      entry_exact: entryExact,
      ...(artifactsMissing.length > 0 ? { artifacts_missing: artifactsMissing } : {}),
      ...(companionsMissing.length > 0 ? { companions_missing: companionsMissing } : {}),
    });
    if (inputs.wanted && host.present) {
      if (!entryPresent) problems.add("entry_missing");
      else if (!entryExact) problems.add("entry_altered");
      // Only meaningful once the entry is there: a missing entry already says
      // the host is unguarded, and the same reinstall writes both.
      if (entryPresent && artifactsMissing.length > 0) problems.add("artifact_missing");
      if (entryPresent && companionsMissing.length > 0) problems.add("companion_missing");
    }
  }
  const bundleMissing: string[] = [];
  const bundleModified: string[] = [];
  for (const [file, shippedHash] of Object.entries(inputs.shipped)) {
    const copied = inputs.copied[file];
    if (copied === undefined) bundleMissing.push(file);
    else if (copied !== shippedHash) bundleModified.push(file);
  }
  if (inputs.wanted || anyEntry) {
    if (bundleMissing.length > 0) problems.add("bundle_missing");
    if (bundleModified.length > 0) problems.add("bundle_modified");
    if (!inputs.policy_readable) problems.add("policy_unreadable");
  }
  const anyHostPresent = inputs.hosts.some((h) => h.present);
  let status: GuardIntegrityReport["status"];
  if (!inputs.wanted && !anyEntry) status = "not_installed";
  else if (!anyHostPresent) status = "unknown";
  else status = problems.size > 0 ? "tampered" : "healthy";
  return {
    checked_at: now.toISOString(),
    wanted: inputs.wanted,
    status,
    problems: [...problems],
    hosts,
    bundle_modified: bundleModified,
    bundle_missing: bundleMissing,
  };
}

/** One sentence for a notification or the radar row. */
export function describeIntegrity(report: GuardIntegrityReport): string {
  const parts: string[] = [];
  const name = (h: HostIntegrity): string => h.label ?? h.host;
  const missing = report.hosts.filter((h) => h.present && !h.entry_present && !h.unreadable).map(name);
  const altered = report.hosts.filter((h) => h.present && h.entry_present && !h.entry_exact).map(name);
  const unreadable = report.hosts.filter((h) => h.unreadable).map(name);
  if (missing.length > 0) parts.push(`the guard's hook entry is gone from ${missing.join(" and ")}`);
  if (altered.length > 0) parts.push(`the guard's hook entry was rewritten in ${altered.join(" and ")}`);
  if (unreadable.length > 0) parts.push(`the ${unreadable.join(" and ")} hook file no longer parses`);
  const artifacts = report.hosts.filter((h) => h.present && h.entry_present && (h.artifacts_missing?.length ?? 0) > 0).map(name);
  const companions = report.hosts.filter((h) => h.present && h.entry_present && (h.companions_missing?.length ?? 0) > 0).map(name);
  if (artifacts.length > 0) parts.push(`the guard's plugin files for ${artifacts.join(" and ")} are missing or changed, so the entry points at nothing`);
  if (companions.length > 0) parts.push(`the guard's consent entry for ${companions.join(" and ")} is gone, so the hook is skipped`);
  if (report.bundle_missing.length > 0) parts.push(`${report.bundle_missing.length} guard file(s) are missing`);
  if (report.bundle_modified.length > 0) parts.push(`${report.bundle_modified.length} guard file(s) were modified`);
  if (report.problems.includes("policy_unreadable")) parts.push("the policy file is unreadable");
  if (parts.length === 0) return "The guard is installed as the app left it.";
  const sentence = parts.join("; ");
  return `${sentence.charAt(0).toUpperCase()}${sentence.slice(1)}.`;
}
