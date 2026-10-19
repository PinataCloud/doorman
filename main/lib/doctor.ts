/**
 * Setup doctor — is this machine's enforcement wiring in a WORKING state, and
 * if not, what exactly is wrong and what would fix it?
 *
 * The guard writes into hook documents it does not own — `~/.claude/settings.json`,
 * `${CODEX_HOME:-~/.codex}/hooks.json` and every other registered host's — and
 * so do their owners (Claude Code rewrites settings.json on a model switch) and
 * the person themselves. Any of those can leave the wiring partially there or
 * simply not parseable, and every one of those states looks identical from the
 * outside: nothing is held, and nothing says why.
 *
 * This module is the diagnosis and the repair PLAN, kept pure (no Electron, no
 * filesystem — everything comes in through `DoctorInput`) so each corruption
 * class maps to exactly one check and one fix under test. `main/doctor.ts` is
 * the side that reads files and applies the plan.
 *
 * Repair policy, in one sentence: a fix that is lossless AND idempotent is
 * applied without asking (`auto: true`) — re-merging the guard entry, removing
 * comments/trailing commas from a JSON document; a fix that could lose
 * someone's settings (restoring a JSON document from a backup, or starting it
 * empty) is offered with one click and says what it would lose; and what only
 * a person can do is stated as an instruction, never guessed at.
 */


import { nodeCommandPrefix } from "./node-launcher.js";
import { dirname, join } from "node:path";
import { DEFAULT_HOST, HOSTS, documentReadable } from "../guard/hosts/index.js";
import type { GuardHostDescriptor } from "../guard/hosts/types.js";
import { stripJsonc } from "../guard/jsonc.js";
import {
  COPILOT_HOOKS_LOCATION,
  VSCODE_VARIANTS,
  profiles,
  readSettings,
  readWorkspaceTrust,
  variantPresent,
  type WorkspaceTrustReading,
} from "./vscode.js";
import type { EditorWindowReport } from "./vscode-ext.js";

export type DoctorHost = "guard" | "vscode";
export type DoctorStatus = "ok" | "warn" | "fail" | "skip";

export type DoctorFix =
  /** Install/refresh the VS Code companion extension through the editor's CLI. */
  | "install-vscode-extension"
  /** Lossless: strip comments / trailing commas / a BOM and write canonical JSON. */
  | "repair-json"
  /** LOSSY: replace an unreadable JSON document with its `.bak` (or `{}`). */
  | "restore-json"
  /** Re-merge the guard's PreToolUse entry and refresh its bundle. */
  | "install-guard";

export interface DoctorCheck {
  id: string;
  host: DoctorHost;
  title: string;
  status: DoctorStatus;
  detail: string;
  fix?: DoctorFix;
  /** Lossless + idempotent — applied without asking. */
  auto?: boolean;
  /** What a person has to do; set when no fix the app can apply exists. */
  manual?: string;
  /** The file a `repair-json` / `restore-json` / `salvage-toml` fix acts on. */
  file?: string;
}

export interface DoctorReport {
  at: string;
  checks: DoctorCheck[];
  ok: number;
  warn: number;
  fail: number;
  /** One line for the card hint / notice title. */
  headline: string;
}

export interface DoctorFs {
  exists(path: string): boolean;
  /** File text, or undefined when it doesn't exist / can't be read. */
  read(path: string): string | undefined;
  /** Entry names of a directory; [] when missing. Optional because only the
   * VS Code checks need to enumerate anything (editor profiles) — a test that
   * doesn't care leaves it out and simply sees no profiles. */
  listDir?(path: string): string[];
  /**
   * Rows of a read-only SQLite query. Optional because only the VS Code
   * workspace-trust check needs a database (the editor's `state.vscdb`); a
   * test that leaves it out sees trust as unknown, never as a verdict. May
   * throw on a missing or corrupt file — the check treats that as unknown.
   */
  querySqlite?(path: string, sql: string, params: readonly unknown[]): Record<string, unknown>[];
}

export interface DoctorInput {
  home: string;
  /** `$CODEX_HOME`, when set. */
  codexHome?: string | undefined;
  grokHome?: string | undefined;
  /** Whether the person has the guard switched on (Settings). */
  guardWanted: boolean;
  /** `prefs.mcp_answers` — our MCP server is meant to be registered. Absent =
   * off, which skips the one VS Code setting that can silently unload it. */
  mcpWanted?: boolean | undefined;
  /** `prefs.vscode_extension` — the editor companion is meant to be installed,
   * plus what is installed and what this build ships. Absent = off (skipped). */
  vscodeExtension?:
    | {
        wanted: boolean;
        /** Version the editor reports (`code --list-extensions --show-versions`). */
        installed?: string | undefined;
        /** Version this app ships in its resources. */
        bundled?: string | undefined;
        /** No VS Code CLI could be resolved — nothing can be installed or read. */
        cliMissing?: boolean | undefined;
      }
    | undefined;
  /**
   * What each OPEN VS Code window reports about itself through the companion
   * extension (`editor/windows/<id>.json`, lib/vscode-ext.ts): Restricted Mode
   * and the effective hook settings after policy. Live reports only — the
   * caller drops stale ones. Absent or empty = no window is telling us, and the
   * checks fall back to inference from settings files and the trust database.
   */
  vscodeWindows?: readonly EditorWindowReport[] | undefined;
  /** `<userData>/doorman/guard` — where the guard bundle lives. */
  guardDir: string;
  /** The compiled guard modules that must exist in `guardDir`. */
  guardFiles: readonly string[];
  /** The substring that identifies our guard entry in a hook document. */
  guardCommandMarker: string;
  /** The command line the installer writes for one host (enforcement.ts
   * guardCommand), used to verify a host's companion document carries our
   * exact consent entry. Defaults to the same rule derived from `guardDir`. */
  guardCommandFor?: ((hostId: string) => string) | undefined;
  /** The process environment the registry resolves host homes against
   * (`HERMES_HOME`, `OPENCLAW_STATE_DIR`, …); `codexHome`/`grokHome` above
   * take precedence. Without it the doctor sees only the default locations
   * while the installer honours the overrides — and the two disagree. */
  env?: NodeJS.ProcessEnv | undefined;
  fs: DoctorFs;
  now?: () => Date;
}


// ---- paths -------------------------------------------------------------------------

/** The two hook documents the app watches for edits, so a rewrite by their
 * owner (or by hand) is re-checked within seconds rather than at relaunch. */
export function doctorPaths(home: string, codexHome?: string | undefined) {
  const codex = codexHome?.trim() || join(home, ".codex");
  return {
    claudeSettings: join(home, ".claude", "settings.json"),
    codexHooks: join(codex, "hooks.json"),
  };
}

// ---- JSON: lenient parse → lossless repair -----------------------------------------

export interface JsonRepair {
  /** Canonical JSON text (2-space, trailing newline) of the repaired document. */
  text: string;
  value: Record<string, unknown>;
  /** Human-readable list of what was removed. */
  changes: string[];
}

/**
 * Parse a JSON document that a person (or a tool) left with comments, trailing
 * commas or a byte-order mark — the three ways a hand-edited settings file
 * stops being JSON while still being unambiguous. Returns null when the text
 * already parses (nothing to repair) or when it cannot be made to parse
 * without guessing (truncated, unbalanced) — that second case is the LOSSY
 * path, which never runs unasked.
 */
export function repairJsonText(raw: string): JsonRepair | null {
  try {
    const parsed = JSON.parse(raw);
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) return null;
  } catch {
    // fall through to the repair
  }
  // The scanner lives in guard/jsonc.ts because the VS Code reader and the
  // commented-JSON hosts (Gemini CLI, Qwen Code, Droid, OpenClaw) need the same
  // one for the OPPOSITE reason — there a comment is normal, and stripping it
  // is how the values are read rather than a defect to be written back.
  const { text: out, changes } = stripJsonc(raw);
  try {
    const value = JSON.parse(out);
    if (!value || typeof value !== "object" || Array.isArray(value)) return null;
    if (changes.length === 0) return null;
    return {
      text: `${JSON.stringify(value, null, 2)}\n`,
      value: value as Record<string, unknown>,
      changes,
    };
  } catch {
    return null;
  }
}


function isObject(v: unknown): v is Record<string, unknown> {
  return !!v && typeof v === "object" && !Array.isArray(v);
}


// ---- the diagnosis -----------------------------------------------------------------

type ParsedDoc =
  | { kind: "ok"; value: Record<string, unknown> }
  | { kind: "missing" }
  | { kind: "repairable"; repair: JsonRepair }
  | { kind: "broken"; error: string };

function parseDoc(text: string | undefined): ParsedDoc {
  if (text === undefined) return { kind: "missing" };
  try {
    const value = JSON.parse(text);
    if (isObject(value)) return { kind: "ok", value };
    return { kind: "broken", error: "the document is not a JSON object" };
  } catch (err) {
    const repair = repairJsonText(text);
    if (repair) return { kind: "repairable", repair };
    return { kind: "broken", error: err instanceof Error ? err.message : String(err) };
  }
}

function short(path: string, home: string): string {
  return path.startsWith(home) ? `~${path.slice(home.length)}` : path;
}

/** Assess every command of ours in a document: the worst runtime/script
 * problem wins, expressed as a check status + detail.
 *
 * Problem ranks: 3 fails the check, 2 warns, and BOTH offer the reinstall that
 * fixes them. Rank 1 warns and offers nothing automatic — it is for the one
 * thing a reinstall must not be pointed at on a guess (see the PATH note
 * below), which arrives as a `manual` instruction instead.
 */

/**
 * An unreadable JSON hook document: nothing — the guard's merge, the tool that
 * owns it — can read it. Repairable without loss when only comments, trailing
 * commas or a BOM broke it; otherwise the lossy restore is offered by hand.
 */
function unreadableDocCheck(id: string, host: DoctorHost, file: string, doc: ParsedDoc, input: DoctorInput): DoctorCheck | undefined {
  const name = short(file, input.home);
  if (doc.kind === "repairable") {
    return {
      id,
      host,
      title: name,
      status: "fail",
      detail: `Not valid JSON, but repairable without losing anything: ${doc.repair.changes.join(", ")}.`,
      fix: "repair-json",
      auto: true,
      file,
    };
  }
  if (doc.kind !== "broken") return undefined;
  const bak = input.fs.read(`${file}.bak`);
  let bakNote: string;
  if (bak !== undefined) {
    try {
      bakNote = isObject(JSON.parse(bak))
        ? ` A readable backup (${name}.bak) exists and would be restored.`
        : ` The backup (${name}.bak) is not readable either, so the file would start empty.`;
    } catch {
      bakNote = ` The backup (${name}.bak) is not readable either, so the file would start empty.`;
    }
  } else {
    bakNote = " There is no backup, so the file would start empty and the guard be re-wired into it.";
  }
  return {
    id,
    host,
    title: name,
    status: "fail",
    detail: `Not valid JSON (${doc.error}). Nothing can read it — including the tool that owns it.${bakNote} The broken file is kept as ${name}.corrupt-<time>.`,
    fix: "restore-json",
    auto: false,
    file,
  };
}

function guardChecks(input: DoctorInput): DoctorCheck[] {
  const { fs } = input;
  const host: DoctorHost = "guard";
  if (!input.guardWanted) {
    return [{ id: "guard.off", host, title: "Guardrails", status: "skip", detail: "Off in Settings → Real time protection. Rules only watch; nothing is held or blocked." }];
  }
  const out: DoctorCheck[] = [];
  // One row per REGISTERED host (guard/hosts/index.ts), not two hard-coded
  // ones: a host is here when its own directory is, and it is guarded when its
  // user-level document carries our marker.
  const env: NodeJS.ProcessEnv = { ...input.env };
  if (input.codexHome !== undefined) env.CODEX_HOME = input.codexHome;
  if (input.grokHome !== undefined) env.GROK_HOME = input.grokHome;
  const hosts: { host: GuardHostDescriptor; name: string; path: string; present: boolean; doc: string | undefined }[] = HOSTS.flatMap(
    (host) =>
      host
        .documents(input.home, env)
        .filter((doc) => doc.level === "user")
        .map((doc) => ({
          host,
          name: host.label,
          path: doc.path,
          // The host's own footprint, not the hook file's parent directory —
          // Copilot's `~/.copilot/hooks/` exists only once we have written it.
          present:
            (host.presencePathsFor?.(input.home, env) ?? host.presencePaths)
              .some((p) => fs.exists(p.startsWith("/") ? p : join(input.home, p))) ||
            fs.exists(dirname(doc.path)),
          doc: fs.read(doc.path),
        })),
  );
  const missing: string[] = [];
  const unreadable: string[] = [];
  const docChecks: DoctorCheck[] = [];
  for (const h of hosts) {
    if (!h.present) continue;
    if (h.doc === undefined) {
      missing.push(h.name);
      continue;
    }
    // In the host's OWN format — Hermes's config.yaml, Kimi Code's
    // config.toml, and the commented JSON Gemini CLI, Qwen Code, Droid and
    // OpenClaw read (`jsonc`/`json5`) are not malformed for failing
    // JSON.parse. Only a strict-JSON host's document is offered the JSON
    // repair: in the other dialects a comment is legitimate, and rewriting the
    // file as plain JSON would delete it.
    if (!documentReadable(h.host, h.doc)) {
      unreadable.push(h.name);
      if ((h.host.documentFormat ?? "json") === "json") {
        const check = unreadableDocCheck(`guard.document:${h.host.id}`, host, h.path, parseDoc(h.doc), input);
        if (check) docChecks.push(check);
      }
      continue;
    }
    if (!h.doc.includes(input.guardCommandMarker)) missing.push(h.name);
  }
  out.push(...docChecks);
  if (unreadable.length > 0) {
    out.push({ id: "guard.hooks", host, title: "Guard hook entries", status: "skip", detail: `Checked once ${unreadable.join(" and ")} hook file${unreadable.length > 1 ? "s are" : " is"} readable.` });
  } else if (missing.length > 0) {
    out.push({ id: "guard.hooks", host, title: "Guard hook entries", status: "fail", detail: `The guard is on but its PreToolUse entry is missing from ${missing.join(" and ")} — nothing is held or blocked there.`, fix: "install-guard", auto: true });
  } else {
    out.push({ id: "guard.hooks", host, title: "Guard hook entries", status: "ok", detail: "Wired into every agent on this machine." });
  }
  // Beyond the document: a plugin host's artefacts (OpenClaw's three plugin
  // files) and a host's companion document (Hermes's consent allowlist). The
  // marker check above reads "installed" while the plugin directory is gone
  // or the consent entry revoked — and the host then loads or skips the hook
  // in silence. Checked only where the entry itself is present; a missing
  // entry is already the row above, and the same reinstall writes all three.
  const commandFor =
    input.guardCommandFor ??
    ((hostId: string) => {
      const base = `${nodeCommandPrefix(input.guardDir)} "${join(input.guardDir, "guard.js")}"`;
      return hostId === DEFAULT_HOST.id ? base : `${base} --host ${hostId}`;
    });
  const brokenArtifacts: string[] = [];
  const brokenCompanions: string[] = [];
  let auxiliaryHosts = 0;
  for (const h of hosts) {
    if (!h.present || h.doc === undefined || !documentReadable(h.host, h.doc) || !h.doc.includes(input.guardCommandMarker)) continue;
    const artifacts = h.host.artifacts?.(input.home, env) ?? [];
    const companions = h.host.companions ?? [];
    if (artifacts.length === 0 && companions.length === 0) continue;
    auxiliaryHosts++;
    if (artifacts.some((a) => fs.read(a.path) !== a.content)) brokenArtifacts.push(h.name);
    for (const companion of companions) {
      const path = companion.path(input.home, env);
      const doc = fs.read(path);
      let intact = false;
      try {
        intact = companion.merge(doc, commandFor(h.host.id)) === doc;
      } catch {
        intact = false; // unparseable — the host cannot read its consent either
      }
      if (!intact) {
        brokenCompanions.push(h.name);
        break;
      }
    }
  }
  if (auxiliaryHosts > 0) {
    const problems: string[] = [];
    if (brokenArtifacts.length > 0) problems.push(`${brokenArtifacts.join(" and ")}'s plugin files are missing or changed (the entry points at nothing)`);
    if (brokenCompanions.length > 0) problems.push(`${brokenCompanions.join(" and ")}'s consent entry is gone (the hook is declared but skipped)`);
    out.push(
      problems.length === 0
        ? { id: "guard.artifacts", host, title: "Guard plugin files and consent", status: "ok", detail: "Every plugin file and consent entry the guard depends on is in place." }
        : { id: "guard.artifacts", host, title: "Guard plugin files and consent", status: "fail", detail: `${problems.join("; ")} — nothing is held or blocked there.`, fix: "install-guard", auto: true },
    );
  }
  const missingFiles = input.guardFiles.filter((f) => !fs.exists(join(input.guardDir, f)));
  out.push(
    missingFiles.length === 0
      ? { id: "guard.bundle", host, title: "Guard bundle", status: "ok", detail: `All ${input.guardFiles.length} guard modules present.` }
      : { id: "guard.bundle", host, title: "Guard bundle", status: "fail", detail: `${missingFiles.length} guard module(s) missing (${missingFiles.slice(0, 3).join(", ")}) — the hook errors and fails open.`, fix: "install-guard", auto: true },
  );
  return out;
}

/**
 * VS Code — the host whose coverage is decided by SETTINGS rather than by a
 * file we wrote.
 *
 * Every other host in this report fails because something of OURS is missing.
 * VS Code fails because of a switch in someone else's document: `chat.useHooks`
 * off, or `~/.copilot/hooks` disabled in `chat.hookFilesLocations`, and our
 * guard hook is never loaded while `~/.copilot/hooks/doorman.json` sits there
 * looking perfectly installed. That state was invisible until this check
 * existed, and it is the same class of silence as the 2026-09-05 outage.
 *
 * Nothing here is repaired automatically. These are the person's own editor
 * preferences, in a JSONC document they hand-edit with comments; rewriting it
 * would be the lossy kind of fix (the comments do not survive a canonical
 * re-serialization), and flipping someone's preview flag back on behind their
 * back is not a repair. Every row therefore carries a `manual` instruction
 * naming the exact setting — except the extension, which is ours.
 */
/** `/Users/x/repos/app` → `~/repos/app`, so a folder list reads at a glance. */
function homeRelative(home: string): (path: string) => string {
  const base = home.replace(/\/+$/, "");
  return (path) => (path === base ? "~" : path.startsWith(`${base}/`) ? `~${path.slice(base.length)}` : path);
}

/**
 * The trust half of the healthy hooks row. When every build's list was read,
 * it says so in terms of the folders checked; when Workspace Trust is off, it
 * says that; when nothing could be read (an older build, no reader), it keeps
 * the standing caveat — a person should still hear what Restricted Mode does.
 */
function trustSentence(readings: readonly WorkspaceTrustReading[]): string {
  if (readings.length > 0 && readings.every((r) => r.kind === "disabled")) {
    return "Workspace Trust is switched off in VS Code, so no folder opens in Restricted Mode and hooks run everywhere.";
  }
  const read = readings.filter((r) => r.kind === "read");
  if (read.length > 0 && read.length + readings.filter((r) => r.kind === "disabled").length === readings.length) {
    const checked = read.reduce((n, r) => n + r.checked, 0);
    const untrusted = read.reduce((n, r) => n + r.untrusted.length, 0);
    if (checked === 0) return "No recently opened folder to check for Restricted Mode yet.";
    if (untrusted === 0) {
      return `Your ${checked} most recent folder${checked === 1 ? " is" : "s are all"} trusted, so the guard runs in each.`;
    }
    return "VS Code skips every hook in a folder opened in Restricted Mode — see the Restricted Mode row.";
  }
  return "VS Code skips every hook in a workspace opened in Restricted Mode — trust the folder for the guard to run there.";
}

/** Which build a window's `vscode.env.appName` belongs to. */
function variantIdForAppName(appName: string): (typeof VSCODE_VARIANTS)[number]["id"] {
  if (/insiders/i.test(appName)) return "vscode-insiders";
  if (/vscodium/i.test(appName)) return "vscodium";
  return "vscode";
}

/** The build these windows belong to — "VS Code Insiders", or "editor" for a mix. */
function buildLabel(windows: readonly EditorWindowReport[]): string {
  const labels = [...new Set(windows.map((w) => VSCODE_VARIANTS.find((v) => v.id === variantIdForAppName(w.app_name))?.label ?? "VS Code"))];
  return labels.length === 1 ? labels[0]! : "editor";
}

/** "1 open VS Code window" / "2 open VS Code Insiders windows" / "3 open editor windows". */
function windowLabel(windows: readonly EditorWindowReport[]): string {
  return `${windows.length} open ${buildLabel(windows)} window${windows.length === 1 ? "" : "s"}`;
}

function vscodeChecks(input: DoctorInput): DoctorCheck[] {
  const { fs } = input;
  const host: DoctorHost = "vscode";
  // Live reports from open windows (companion extension). The caller already
  // dropped stale files; a window with no folders still counts for the hook
  // settings, just not for Restricted Mode.
  const windows = input.vscodeWindows ?? [];
  const io = { exists: (p: string) => fs.exists(p), listDir: (p: string) => fs.listDir?.(p) ?? [] };
  const present = VSCODE_VARIANTS.filter((v) => variantPresent(v, input.home, io.exists));
  if (present.length === 0) {
    return [{ id: "vscode.present", host, title: "VS Code", status: "skip", detail: "Not found on this machine." }];
  }
  const out: DoctorCheck[] = [];
  // One reading per PROFILE, not per build: a profile keeps its own
  // settings.json, so someone working in a profile with hooks off is unguarded
  // no matter what the default profile says.
  const readings = present.flatMap((variant) =>
    profiles(variant, input.home, io).map((profile) => ({
      variant,
      profile,
      facts: readSettings(fs.read(join(profile.dir, "settings.json"))),
    })),
  );
  const name = (r: (typeof readings)[number]): string =>
    r.profile.default ? r.variant.label : `${r.variant.label} (profile ${r.profile.id})`;
  const list = (rs: typeof readings): string => [...new Set(rs.map(name))].join(" and ");

  if (!input.guardWanted) {
    out.push({
      id: "vscode.guard_off",
      host,
      title: "Agent hooks",
      status: "skip",
      detail: "Off in Settings → Real time protection. Rules only watch; nothing is held or blocked.",
    });
  } else {
    const hooksOff = readings.filter((r) => !r.facts.hooksEnabled);
    const locationOff = readings.filter((r) => r.facts.hooksEnabled && !r.facts.copilotHooksLocationEnabled);
    if (hooksOff.length > 0) {
      out.push({
        id: "vscode.hooks",
        host,
        title: "Agent hooks",
        status: "fail",
        detail: `chat.useHooks is off in ${list(hooksOff)} — VS Code loads no hooks at all there, so the guard never sees an agent-mode tool call. The hook file is installed and inert.`,
        manual:
          "Set chat.useHooks to true in VS Code's settings. If it keeps reverting, an organization policy (ChatHooks) is forcing it off — that is an admin setting, and Doorman won't fight it.",
      });
    } else if (locationOff.length > 0) {
      out.push({
        id: "vscode.hooks",
        host,
        title: "Agent hooks",
        status: "fail",
        detail: `chat.hookFilesLocations disables ${COPILOT_HOOKS_LOCATION} in ${list(locationOff)} — that is the directory our guard hook lives in, so VS Code never loads it.`,
        manual: `Set "${COPILOT_HOOKS_LOCATION}": true under chat.hookFilesLocations in VS Code's settings.`,
      });
    } else if (windows.some((w) => !w.hooks_enabled)) {
      // The settings files say hooks are on, but an open window says they are
      // not: that is an enterprise policy (ChatHooks) in force, which only the
      // editor's own configuration service can see.
      out.push({
        id: "vscode.hooks",
        host,
        title: "Agent hooks",
        status: "fail",
        detail: `${windowLabel(windows.filter((w) => !w.hooks_enabled))} report${windows.filter((w) => !w.hooks_enabled).length === 1 ? "s" : ""} chat.useHooks OFF even though the settings files say on — an organization policy (ChatHooks) is forcing it. VS Code loads no hooks there; the hook file is installed and inert.`,
        manual: "That is an admin setting, and Doorman won't fight it. Ask whoever manages your VS Code policy to allow chat hooks.",
      });
    } else if (windows.some((w) => !w.copilot_hooks_location_enabled)) {
      out.push({
        id: "vscode.hooks",
        host,
        title: "Agent hooks",
        status: "fail",
        detail: `${windowLabel(windows.filter((w) => !w.copilot_hooks_location_enabled))} report${windows.filter((w) => !w.copilot_hooks_location_enabled).length === 1 ? "s" : ""} ${COPILOT_HOOKS_LOCATION} disabled under chat.hookFilesLocations — that is the directory our guard hook lives in, so VS Code never loads it there.`,
        manual: `Set "${COPILOT_HOOKS_LOCATION}": true under chat.hookFilesLocations in VS Code's settings.`,
      });
    } else {
      // Hooks are wired; the one thing that still switches them off per window
      // is Restricted Mode. Two sources, best first:
      //   · an OPEN window's own report (`workspace.isTrusted`, via the
      //     companion extension) — the truth about that window;
      //   · for builds with no window reporting, the trusted-folder list
      //     against the recently opened folders — a verdict about the folders
      //     in use, not a standing caveat. One reading per BUILD (trust is
      //     application-wide, not per profile), from the default profile.
      const reporting = new Set(windows.map((w) => variantIdForAppName(w.app_name)));
      const trust = present
        .filter((variant) => !reporting.has(variant.id))
        .map((variant) => ({
          variant,
          reading: readWorkspaceTrust(
            variant,
            input.home,
            readings.find((r) => r.variant === variant && r.profile.default)?.facts ?? readSettings(undefined),
            {
              exists: io.exists,
              readText: (p) => fs.read(p),
              ...(fs.querySqlite ? { querySqlite: (p, sql, params) => fs.querySqlite!(p, sql, params) } : {}),
            },
          ),
        }));
      // An untrusted EMPTY window has nothing for an agent to run in.
      const restrictedWindows = windows.filter((w) => !w.trusted && w.folders.length > 0);
      const restricted = trust.filter((t) => t.reading.untrusted.length > 0);
      const sentences: string[] = [];
      if (windows.length > 0) {
        sentences.push(
          restrictedWindows.length > 0
            ? "VS Code skips every hook in a folder opened in Restricted Mode — see the Restricted Mode row."
            : `${windows.length === 1 ? `The open ${buildLabel(windows)} window is` : `All ${windows.length} open ${buildLabel(windows)} windows are`} trusted, so the guard runs there.`,
        );
      }
      if (trust.length > 0) sentences.push(trustSentence(trust.map((t) => t.reading)));
      out.push({
        id: "vscode.hooks",
        host,
        title: "Agent hooks",
        status: "ok",
        detail: `Hooks are on and ${COPILOT_HOOKS_LOCATION} is enabled. ${sentences.join(" ")}`,
      });
      const rel = homeRelative(input.home);
      const manual =
        "Trust the folder in VS Code (Manage Workspace Trust in the gear menu), or trust its parent directory once to cover every project under it.";
      if (restrictedWindows.length > 0) {
        // A window open RIGHT NOW with the agent unguarded is a live defect,
        // not a heads-up about folders someone might open.
        const folders = [...new Set(restrictedWindows.flatMap((w) => w.folders))];
        const shown = folders.slice(0, 3).map(rel).join(", ");
        const more = folders.length > 3 ? ` and ${folders.length - 3} more` : "";
        out.push({
          id: "vscode.restricted_mode",
          host,
          title: "Restricted Mode",
          status: "fail",
          detail: `${windowLabel(restrictedWindows)} ${restrictedWindows.length === 1 ? "is" : "are"} in Restricted Mode right now — VS Code runs the agent there with no hooks at all, ours included: ${shown}${more}.`,
          manual,
        });
      } else if (restricted.length > 0) {
        const folders = restricted.flatMap((t) => t.reading.untrusted);
        const shown = folders.slice(0, 3).map(rel).join(", ");
        const more = folders.length > 3 ? ` and ${folders.length - 3} more` : "";
        const where = restricted.length === present.length ? "" : ` in ${restricted.map((t) => t.variant.label).join(" and ")}`;
        out.push({
          id: "vscode.restricted_mode",
          host,
          title: "Restricted Mode",
          status: "warn",
          detail: `${folders.length} of your ${restricted.reduce((n, t) => n + t.reading.checked, 0)} most recent folders open in Restricted Mode${where} — VS Code runs the agent there with no hooks at all, ours included: ${shown}${more}.`,
          manual,
        });
      }
    }
  }

  // VS Code's OWN confirmations. Our hold is unaffected — but "the editor
  // stopped asking" is exactly the state someone wants told.
  const yolo = readings.filter((r) => r.facts.globalAutoApprove);
  const terminal = readings.filter((r) => r.facts.terminalAutoApproveAllows > 0);
  if (yolo.length > 0 || terminal.length > 0) {
    out.push({
      id: "vscode.auto_approve",
      host,
      title: "Editor confirmations",
      status: "warn",
      detail:
        yolo.length > 0
          ? `chat.tools.global.autoApprove is on in ${list(yolo)} — VS Code runs every agent tool call without asking. Doorman's own hold still applies; VS Code's does not.`
          : `${list(terminal)} auto-approves ${terminal[0]!.facts.terminalAutoApproveAllows} terminal command pattern(s) without asking.`,
      manual:
        "Review chat.tools.global.autoApprove / chat.tools.terminal.autoApprove in VS Code's settings if that isn't deliberate.",
    });
  }

  if (input.mcpWanted) {
    const blocked = readings.filter((r) => r.facts.mcpAccess === "none");
    if (blocked.length > 0) {
      out.push({
        id: "vscode.mcp_access",
        host,
        title: "MCP access",
        status: "warn",
        detail: `chat.mcp.access is "none" in ${list(blocked)} — no MCP server loads there, Doorman's included.`,
        manual: 'Set chat.mcp.access back to "all" in VS Code\'s settings to let MCP servers load.',
      });
    }
  }

  const ext = input.vscodeExtension;
  if (ext?.wanted) {
    if (ext.cliMissing) {
      out.push({
        id: "vscode.extension",
        host,
        title: "Editor companion",
        status: "warn",
        detail: "VS Code is installed but its `code` command line couldn't be found, so the companion extension can't be installed from here.",
        manual: "Install Doorman from the Extensions view in VS Code, or reinstall VS Code so its bundled `code` command is present.",
      });
    } else if (!ext.installed) {
      out.push({
        id: "vscode.extension",
        host,
        title: "Editor companion",
        status: "fail",
        detail: "The Doorman extension is switched on but not installed in VS Code — spend, guard state and held calls don't show in the editor.",
        fix: "install-vscode-extension",
        auto: true,
      });
    } else if (ext.bundled && ext.installed !== ext.bundled) {
      out.push({
        id: "vscode.extension",
        host,
        title: "Editor companion",
        status: "warn",
        detail: `VS Code has the Doorman extension ${ext.installed}; this app ships ${ext.bundled}.`,
        fix: "install-vscode-extension",
        auto: true,
      });
    } else {
      out.push({
        id: "vscode.extension",
        host,
        title: "Editor companion",
        status: "ok",
        detail: `Doorman ${ext.installed} is installed in VS Code.`,
      });
    }
  }
  return out;
}

export function diagnose(input: DoctorInput): DoctorReport {
  const checks = [...vscodeChecks(input), ...guardChecks(input)];
  const ok = checks.filter((c) => c.status === "ok").length;
  const warn = checks.filter((c) => c.status === "warn").length;
  const fail = checks.filter((c) => c.status === "fail").length;
  const headline =
    fail > 0
      ? `${fail} issue${fail === 1 ? "" : "s"}${warn > 0 ? `, ${warn} warning${warn === 1 ? "" : "s"}` : ""}`
      : warn > 0
        ? `${warn} warning${warn === 1 ? "" : "s"}`
        : "Everything is wired";
  return { at: (input.now ?? (() => new Date()))().toISOString(), checks, ok, warn, fail, headline };
}

// ---- the repair plan ---------------------------------------------------------------

export interface PlannedRepair {
  fix: DoctorFix;
  file?: string;
  /** The checks this repair is expected to clear. */
  checks: string[];
}

const FIX_ORDER: DoctorFix[] = [
  "repair-json",
  "restore-json",
  "install-guard",
  "install-vscode-extension",
];

/**
 * Turn a report into an ordered, de-duplicated list of repairs. Documents are
 * made readable first (nothing else can merge into a broken file), then the
 * guard. `mode: "auto"` takes only lossless repairs; `"all"` includes the
 * lossy restore.
 */
export function planRepairs(
  report: DoctorReport,
  mode: "auto" | "all",
  opts: { only?: string | undefined } = {},
): PlannedRepair[] {
  const byKey = new Map<string, PlannedRepair>();
  for (const check of report.checks) {
    if (!check.fix) continue;
    if (opts.only !== undefined && check.id !== opts.only) continue;
    if (mode === "auto" && !check.auto) continue;
    const key = `${check.fix}|${check.file ?? ""}`;
    const existing = byKey.get(key);
    if (existing) existing.checks.push(check.id);
    else byKey.set(key, { fix: check.fix, ...(check.file ? { file: check.file } : {}), checks: [check.id] });
  }
  return [...byKey.values()].sort((a, b) => FIX_ORDER.indexOf(a.fix) - FIX_ORDER.indexOf(b.fix));
}

/**
 * The flip-flop breaker: a repair that keeps being re-applied is fighting
 * something (a terminal installer on a loop, a tool that rewrites its file
 * back, a Codex trust re-ask on every write). After `limit` applications of
 * the same repair inside `windowMs`, automatic repair stands down and the
 * check says so; an explicit click still goes through.
 */
export class RepairLedger {
  private readonly applied = new Map<string, number[]>();

  constructor(
    private readonly now: () => number = Date.now,
    private readonly limit = 3,
    private readonly windowMs = 60 * 60_000,
  ) {}

  private key(repair: PlannedRepair): string {
    return `${repair.fix}|${repair.file ?? ""}`;
  }

  record(repair: PlannedRepair): void {
    const key = this.key(repair);
    const at = this.now();
    const list = (this.applied.get(key) ?? []).filter((t) => at - t < this.windowMs);
    list.push(at);
    this.applied.set(key, list);
  }

  /** True when this repair has hit the limit inside the window. */
  exhausted(repair: PlannedRepair): boolean {
    const at = this.now();
    const list = (this.applied.get(this.key(repair)) ?? []).filter((t) => at - t < this.windowMs);
    return list.length >= this.limit;
  }
}

// ---- what crosses to the renderer -----------------------------------------------

export interface DoctorRepairOutcome {
  at: string;
  /** Repairs that ran and finished — as one-line human sentences. */
  applied: string[];
  /** Repairs that ran and did NOT take (installer exit code, unwritable file). */
  failed: string[];
}

export interface DoctorState {
  status: "idle" | "checking" | "repairing";
  report?: DoctorReport;
  last_run_at?: string;
  /** Why the last run happened ("boot", "focus", "file-change", "manual", …). */
  last_reason?: string;
  last_repair?: DoctorRepairOutcome;
  /** Check ids whose automatic repair stood down (see RepairLedger) — the
   * card offers them as an explicit click instead. */
  paused?: string[];
}

/** One line per repair, for the outcome list and the in-window notice. */
export function describeRepair(repair: PlannedRepair, home: string): string {
  const file = repair.file ? (repair.file.startsWith(home) ? `~${repair.file.slice(home.length)}` : repair.file) : "";
  switch (repair.fix) {
    case "repair-json":
      return `Repaired ${file} (removed what made it invalid JSON; a copy of the original is kept beside it)`;
    case "restore-json":
      return `Restored ${file} from its backup (the unreadable file is kept beside it)`;
    case "install-guard":
      return "Re-wired the guard's PreToolUse entry";
    case "install-vscode-extension":
      return "Installed the Doorman extension in VS Code";
  }
}
