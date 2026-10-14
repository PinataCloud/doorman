/**
 * Installing the Doorman VS Code extension, and keeping the two files it
 * lives on up to date. The Electron side of lib/vscode-ext.ts.
 *
 * HOW IT INSTALLS. Through the editor's own command line —
 * `<VS Code.app>/Contents/Resources/app/bin/code --install-extension
 * <path>.vsix --force` — not by unzipping into `~/.vscode/extensions`
 * ourselves. The CLI owns that directory's `extensions.json` index, and a
 * hand-placed folder is either ignored or corrupts it. Verified end to end
 * against VS Code 1.136.2: install exits 0 with the extension listed by
 * `--list-extensions --show-versions`, a re-install of the same version is a
 * no-op under `--force`, and `--uninstall-extension` removes it cleanly. A
 * running editor picks the new version up on its next window reload; nothing
 * here restarts or interrupts one.
 *
 * The `code` the app finds is the one INSIDE the application bundle, never
 * whatever is on the PATH: a GUI-launched Mac app inherits launchd's minimal
 * PATH (the same reason the doctor's Node probe has to ask a login shell), so
 * a PATH lookup would report "VS Code has no CLI" on a machine that plainly
 * has one. Each build in the family (lib/vscode.ts) carries its own.
 *
 * Sandboxed runs write nothing, same rule as every other installer here.
 */

import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, rmSync, watch, type FSWatcher } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { writeDocumentAtomically } from "./enforcement.js";
import { hookWritesAllowed, SANDBOX_READ_ONLY } from "./lib/sandbox.js";
import {
  EXTENSION_ID,
  VSIX_BASENAME,
  editorDir,
  installArgs,
  installedVersion,
  listArgs,
  needsInstall,
  openIntentPath,
  parseEditorOpenIntent,
  statusPath,
  uninstallArgs,
  type EditorOpenScreen,
  type EditorStatus,
} from "./lib/vscode-ext.js";
import { VSCODE_VARIANTS, cliCandidates, variantPresent, type VscodeVariant } from "./lib/vscode.js";

/** The editor CLI is a local process we spawn and wait for; an editor that
 * hangs must not hang the app's boot. */
const CLI_TIMEOUT_MS = 60_000;

export interface EditorTarget {
  variant: VscodeVariant;
  /** Absolute path of that build's `code` binary. */
  cli: string;
}

/**
 * Every VS Code-family build on this Mac that we can drive, in family order.
 * A build that is present but whose CLI is missing (a damaged bundle, or a
 * distribution that strips it) is deliberately NOT returned — the caller
 * reports "installed, but no command line" rather than silently doing nothing.
 */
export function editorTargets(home: string = homedir()): EditorTarget[] {
  const out: EditorTarget[] = [];
  for (const variant of VSCODE_VARIANTS) {
    if (!variantPresent(variant, home, existsSync)) continue;
    const cli = cliCandidates(variant).find((path) => existsSync(path));
    if (cli) out.push({ variant, cli });
  }
  return out;
}

/** Builds that are here but offer no command line — the warn case. */
export function editorsWithoutCli(home: string = homedir()): VscodeVariant[] {
  return VSCODE_VARIANTS.filter(
    (variant) => variantPresent(variant, home, existsSync) && !cliCandidates(variant).some((path) => existsSync(path)),
  );
}

/** The packaged extension: `Resources/vscode/` in a built app, `build/vscode/`
 * in a dev run (scripts/build-vsix.mjs writes both). */
export function vsixPath(): string {
  const packaged = join(process.resourcesPath ?? "", "vscode", VSIX_BASENAME);
  if (existsSync(packaged)) return packaged;
  return join(__dirname, "..", "vscode", VSIX_BASENAME);
}

function run(cli: string, args: string[]): { ok: boolean; stdout: string; error?: string } {
  try {
    const stdout = execFileSync(cli, args, {
      encoding: "utf8",
      timeout: CLI_TIMEOUT_MS,
      // The CLI writes Node deprecation warnings to stderr on the current
      // build; they are not failures and parseExtensionList drops them anyway.
      stdio: ["ignore", "pipe", "ignore"],
    });
    return { ok: true, stdout };
  } catch (err) {
    return { ok: false, stdout: "", error: err instanceof Error ? err.message : String(err) };
  }
}

export interface EditorExtensionStatus {
  variant: string;
  label: string;
  /** The build is here and drivable. */
  present: boolean;
  /** No `code` command line inside the bundle. */
  cliMissing?: boolean;
  /** Version the editor reports, when our extension is installed there. */
  installed?: string;
}

/**
 * Which builds are here, WITHOUT spawning anything. Used when the companion is
 * switched off — the app still wants to know whether to offer "open in VS
 * Code", and paying a subprocess per build at every boot for a feature nobody
 * turned on is not worth the second.
 */
export function editorPresence(home: string = homedir()): EditorExtensionStatus[] {
  return [
    ...editorsWithoutCli(home).map((variant) => ({ variant: variant.id, label: variant.label, present: true, cliMissing: true })),
    ...editorTargets(home).map(({ variant }) => ({ variant: variant.id, label: variant.label, present: true })),
  ];
}

/** What each build currently has. One CLI call per present build. */
export function extensionStatus(home: string = homedir()): EditorExtensionStatus[] {
  const out: EditorExtensionStatus[] = [];
  for (const variant of editorsWithoutCli(home)) {
    out.push({ variant: variant.id, label: variant.label, present: true, cliMissing: true });
  }
  for (const { variant, cli } of editorTargets(home)) {
    const result = run(cli, listArgs());
    const installed = result.ok ? installedVersion(result.stdout) : undefined;
    out.push({ variant: variant.id, label: variant.label, present: true, ...(installed ? { installed } : {}) });
  }
  return out;
}

export interface EditorInstallOutcome {
  ok: boolean;
  error?: string;
  /** Builds the extension is now installed in. */
  installed: string[];
  hosts: EditorExtensionStatus[];
}

/**
 * Install (or refresh) the extension in every drivable build. Idempotent: a
 * build already carrying this exact version is skipped without spawning
 * anything, so this is safe on every boot.
 */
export function installEditorExtension(version: string, home: string = homedir()): EditorInstallOutcome {
  if (!hookWritesAllowed()) return { ok: false, error: SANDBOX_READ_ONLY, installed: [], hosts: extensionStatus(home) };
  const vsix = vsixPath();
  if (!existsSync(vsix)) {
    return { ok: false, error: `the packaged extension is missing (${vsix})`, installed: [], hosts: extensionStatus(home) };
  }
  const errors: string[] = [];
  const installed: string[] = [];
  for (const { variant, cli } of editorTargets(home)) {
    const listed = run(cli, listArgs());
    const current = listed.ok ? installedVersion(listed.stdout) : undefined;
    if (!needsInstall(current, version)) {
      installed.push(variant.id);
      continue;
    }
    const result = run(cli, installArgs(vsix));
    if (result.ok) installed.push(variant.id);
    else errors.push(`${variant.label}: ${result.error ?? "the editor's CLI refused the install"}`);
  }
  return {
    ok: errors.length === 0,
    ...(errors.length > 0 ? { error: errors.join("; ") } : {}),
    installed,
    hosts: extensionStatus(home),
  };
}

/** Remove it from every build that has it. */
export function uninstallEditorExtension(home: string = homedir()): EditorInstallOutcome {
  if (!hookWritesAllowed()) return { ok: false, error: SANDBOX_READ_ONLY, installed: [], hosts: extensionStatus(home) };
  const errors: string[] = [];
  for (const { variant, cli } of editorTargets(home)) {
    const listed = run(cli, listArgs());
    if (listed.ok && installedVersion(listed.stdout) === undefined) continue;
    const result = run(cli, uninstallArgs());
    if (!result.ok) errors.push(`${variant.label}: ${result.error ?? `couldn't remove ${EXTENSION_ID}`}`);
  }
  return {
    ok: errors.length === 0,
    ...(errors.length > 0 ? { error: errors.join("; ") } : {}),
    installed: [],
    hosts: extensionStatus(home),
  };
}

// ---- the two files the extension lives on -------------------------------------

/**
 * Publish what the editor shows. Atomic, because the extension polls this file
 * and a half-written one would flicker the status bar back to "not running".
 * Best effort: a status file we cannot write costs a display surface, never a
 * capture or a decision, so it never throws into a caller.
 */
export function publishEditorStatus(userDataDir: string, status: EditorStatus): void {
  if (!hookWritesAllowed()) return;
  try {
    mkdirSync(editorDir(userDataDir), { recursive: true });
    writeDocumentAtomically(statusPath(userDataDir), `${JSON.stringify(status, null, 2)}\n`);
  } catch {
    // ignore
  }
}

/** Remove the status file — on quit, and when the person turns the extension
 * off — so a stopped app never leaves a number behind that reads as live. */
export function clearEditorStatus(userDataDir: string): void {
  try {
    rmSync(statusPath(userDataDir), { force: true });
  } catch {
    // ignore
  }
}

// The other direction — draining `<id>.answer.json` — lives in the
// ApprovalWatcher (enforcement.ts `drainAnswers`), because it already scans
// that directory 3× a second and a second watcher would race it.

/**
 * The editor asking the app to come to the screen: the status-bar
 * click writes `editor/open.json`; this watches for it, hands the screen to
 * the caller (who shows the window and navigates) and deletes the file so the
 * request is honoured once. A directory watch is the fast path — the click
 * should feel instant — and a one-second poll is the floor, because macOS
 * coalesces watch events and a directory that does not exist yet cannot be
 * watched at all. Nothing here runs in a sandboxed profile's read-only mode
 * differently: reading and deleting our own file is not a hook write.
 */
export function watchEditorIntents(
  userDataDir: string,
  onOpen: (screen: EditorOpenScreen) => void,
  log: (line: string) => void = () => {},
): { stop(): void } {
  const file = openIntentPath(userDataDir);
  const drain = (): void => {
    if (!existsSync(file)) return;
    let text: string;
    try {
      text = readFileSync(file, "utf8");
    } catch {
      return; // half-written; the next tick reads it whole
    }
    try {
      rmSync(file, { force: true });
    } catch {
      // a file we cannot remove would re-fire every second; say so once
      log(`couldn't remove ${file}`);
    }
    const intent = parseEditorOpenIntent(text);
    if (intent) onOpen(intent.screen);
  };
  let watcher: FSWatcher | undefined;
  const attach = (): void => {
    if (watcher) return;
    try {
      watcher = watch(editorDir(userDataDir), () => drain());
      watcher.on("error", () => {
        watcher?.close();
        watcher = undefined;
      });
    } catch {
      watcher = undefined; // the directory appears with the first status write
    }
  };
  attach();
  const timer = setInterval(() => {
    attach();
    drain();
  }, 1_000);
  drain();
  return {
    stop() {
      clearInterval(timer);
      watcher?.close();
      watcher = undefined;
    },
  };
}
