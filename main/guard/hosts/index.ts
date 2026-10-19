/**
 * The guard host REGISTRY — the only place that knows which agent hosts the
 * PreToolUse guard can be installed into.
 *
 * The guard entry (guard.ts), the installer (enforcement.ts), the setup doctor
 * (lib/doctor.ts), the integrity watcher (lib/guard-integrity.ts) and the
 * coverage card (lib/shadow-ai.ts) all iterate `HOSTS` instead of naming
 * hosts, so adding one is an import here plus a descriptor file — never a
 * third `if`.
 *
 * Pure, like every descriptor: this module is copied to userData with the rest
 * of the guard and run with plain `node`, so it may import only its siblings.
 */

import { claudeHost } from "./claude.js";
import { codexHost } from "./codex.js";
import type { GuardHostDescriptor } from "./types.js";

// ---- registered hosts -------------------------------------------------------
// TO ADD A HOST: write `hosts/<id>.ts` exporting one descriptor (copy the
// shape in claude.ts / codex.ts), import it here, and append it to HOSTS.
// Nothing else in the app has to change.
//
// The three adapters being written against this contract land as:
import { cursorHost } from "./cursor.js";
import { geminiHost } from "./gemini.js";
import { copilotHost } from "./copilot.js";
// …and are appended to the array below, after codexHost.
// 2026-09-06: Hermes Agent — a
// shell hook in config.yaml (the first YAML document) plus its consent
// allowlist as a companion.
import { hermesHost } from "./hermes.js";
// The Claude-shaped family, one factory (claude-family.ts) and six specs.
import { qwenHost } from "./qwen.js";
import { droidHost } from "./droid.js";
import { crushHost } from "./crush.js";
import { gooseHost } from "./goose.js";
import { kimiHost } from "./kimi.js";
import { kiroHost } from "./kiro.js";
// OpenClaw — the first PLUGIN host: the document only enables and configures
// a plugin directory the installer writes (types.ts artifacts()).
import { openclawHost } from "./openclaw.js";
import { grokHost } from "./grok.js";
// OpenCode — the second plugin host (2026-09-10): a sidecar JSON document
// beside its plugins directory, one plugin file as the artefact.
import { opencodeHost } from "./opencode.js";
// ---- end registered hosts ---------------------------------------------------

export const HOSTS: readonly GuardHostDescriptor[] = [
  claudeHost,
  codexHost,
  cursorHost,
  geminiHost,
  copilotHost,
  hermesHost,
  qwenHost,
  droidHost,
  crushHost,
  gooseHost,
  kimiHost,
  kiroHost,
  openclawHost,
  grokHost,
  opencodeHost,
];

/** The host every unknown/absent `--host` falls back to. Fail-open: a guard
 * that refuses to run because it can't identify its host protects nobody. */
export const DEFAULT_HOST: GuardHostDescriptor = claudeHost;

export function hostById(id: string | undefined): GuardHostDescriptor | undefined {
  if (!id) return undefined;
  return HOSTS.find((h) => h.id === id);
}

/** The descriptor for a `source` string as it appears on spool rows, findings
 * and approval requests ("claude-code", "codex", …). */
export function hostBySource(source: string | undefined): GuardHostDescriptor | undefined {
  if (!source) return undefined;
  return HOSTS.find((h) => h.source === source || h.dialects?.some((d) => d.source === source));
}

/**
 * The `source` a raw stdin payload belongs to: the host's own, unless one of
 * its dialects (types.ts HostDialect) claims the payload — VS Code Copilot
 * Chat delivering to the Copilot CLI document. Pure.
 */
export function sourceForPayload(host: GuardHostDescriptor, raw: unknown): string {
  const dialect = host.dialects?.find((d) => d.claims(raw));
  return dialect?.source ?? host.source;
}

/**
 * `--host <id>` out of the installed command line. Absent or unknown → the
 * default host, never an error: Claude Code's entry carries no argument at all
 * (its trust state is keyed on the exact command string), so "no flag" is the
 * normal case rather than a broken one.
 */
export function hostForArgv(argv: readonly string[]): GuardHostDescriptor {
  const index = argv.indexOf("--host");
  if (index < 0) return DEFAULT_HOST;
  return hostById(argv[index + 1]) ?? DEFAULT_HOST;
}

/** A `source` string → the host's human label. An unknown source is returned
 * as-is: a row from a host this build doesn't know is still a row, and showing
 * its raw id beats showing somebody else's name. */
export function hostLabel(source: string | undefined): string {
  if (!source) return DEFAULT_HOST.label;
  const host = hostBySource(source);
  if (!host) return source;
  if (host.source === source) return host.label;
  return host.dialects?.find((d) => d.source === source)?.label ?? source;
}

/** Every host's label, registry order — "Claude Code + Codex" and whatever
 * comes after it, for the sentences that used to hard-code two names. */
export function hostLabels(): string[] {
  return HOSTS.map((h) => h.label);
}

/**
 * Can this document be read in the host's own format? The installer, the
 * doctor and the integrity watcher used to `JSON.parse` every hook document;
 * a host whose document is YAML, TOML or commented JSON (documentFormat
 * `yaml`/`toml`/`jsonc`/`json5`) answers through its own merge() instead — the
 * descriptor refuses a document its host can't read by throwing, which is the
 * same signal. An absent document is readable (there is nothing to misread);
 * a strict JSON document is readable when JSON.parse says so.
 */
export function documentReadable(host: GuardHostDescriptor, docText: string | undefined): boolean {
  if (docText === undefined) return true;
  if ((host.documentFormat ?? "json") === "json") {
    try {
      JSON.parse(docText);
      return true;
    } catch {
      return false;
    }
  }
  try {
    host.merge(docText, `probe ${GUARD_PROBE_MARKER}`, 60);
    return true;
  } catch {
    return false;
  }
}

/** A command that is never installed — only handed to merge() as a probe. */
const GUARD_PROBE_MARKER = "doorman/guard/probe";

export type { GuardHostDescriptor };
