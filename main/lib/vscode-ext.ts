/**
 * The Doorman VS Code extension — what it is, where its files are, and the
 * two-file contract between it and this app.
 *
 * WHY AN EXTENSION AT ALL. Three things the hook rail structurally cannot do,
 * because a PreToolUse hook is a process VS Code spawns and throws away:
 *   · ask the person IN THE EDITOR. Today a held call raises a native window
 *     over whatever they were doing; the extension puts the same question in
 *     the window their hands are already in.
 *   · show state continuously — today's spend, whether the guard is armed, how
 *     many agents are running — without them switching apps to find out.
 *   · open things. A finding names a file; only something inside the editor can
 *     put the cursor on it.
 *
 * HOW IT TALKS TO THE APP: files, for the same reasons the guard handshake uses
 * them (guard/handshake.ts) — no socket path length limit, one concurrency
 * model, testable with a temp directory. Three files, both directions:
 *
 *   app → extension   `editor/status.json` — written on every state change,
 *                                      read and watched by the extension's
 *                                      status bar; carries `app_path` so the
 *                                      editor knows what "Open the app" opens.
 *   extension → app   `<id>.answer.json` in the GUARD's `pending/` directory —
 *                                      the person's verdict on a held call.
 *   extension → app   `editor/windows/<sessionId>.json` — what only the editor
 *                                      knows about an open window: Restricted
 *                                      Mode and the effective hook settings
 *                                      after policy (see below).
 *
 * The extension deliberately does NOT write `<id>.reply.json` itself, even
 * though the guard would honour it: the app owns what happens around a verdict
 * (the policy write behind "allow and stop asking", the finding's resolution
 * and hold_ms, the spool line). An answer file is a REQUEST to decide, which
 * the app validates and then answers through its one existing path — so a
 * decision made in the editor is recorded exactly like one made in the panel,
 * and an extension that is out of date can never invent a state the app
 * doesn't understand.
 *
 * Pure: paths from a userData string, parsing from text. The runner lives in
 * main/vscode-ext-install.ts.
 */

/** Publisher + name from vscode-extension/package.json. The CLI identifies an
 * extension by exactly this string, so it is the one place it is spelled. */
export const EXTENSION_ID = "pinata.doorman";

/** Basename of the packaged extension inside the app's resources. */
export const VSIX_BASENAME = "doorman.vsix";

export function editorDir(userDataDir: string): string {
  return `${userDataDir.replace(/\/+$/, "")}/doorman/editor`;
}

export function statusPath(userDataDir: string): string {
  return `${editorDir(userDataDir)}/status.json`;
}

/** The extension's answer to a held call, beside the guard's own exchange. */
export function answerPath(guardDir: string, id: string): string {
  return `${guardDir.replace(/\/+$/, "")}/pending/${id}.answer.json`;
}

// ---- what each open editor window reports about itself -------------------------

/**
 * `editor/windows/<sessionId>.json` — one per open VS Code window.
 *
 * The third file of the contract, and the only one where information flows
 * editor → app about the EDITOR rather than about a decision. It exists
 * because two facts decide whether the guard runs in a window and neither is
 * readable from outside it:
 *   · `workspace.isTrusted` — Restricted Mode, per window. The doctor infers
 *     this from the trusted-folder list and the recently opened list
 *     (lib/vscode.ts), which is a good guess about recent folders and no
 *     statement at all about the windows open right now.
 *   · the EFFECTIVE `chat.useHooks` — settings.json can say `true` while an
 *     enterprise policy (`ChatHooks`) forces it off; only the editor's own
 *     configuration service knows the value that actually applies.
 *
 * Written on activation and on every change to trust, folders or the chat
 * settings; refreshed as a heartbeat on the status poll; removed on
 * deactivate. A report older than WINDOW_STALE_MS is a closed window whose
 * extension host died before deactivate ran, and is ignored.
 */
export function windowsDir(userDataDir: string): string {
  return `${editorDir(userDataDir)}/windows`;
}

/** Same tolerance as the status heartbeat: the extension rewrites every 10 s. */
export const WINDOW_STALE_MS = 60_000;

export interface EditorWindowReport {
  /** `vscode.env.sessionId` — unique per window, and the file's basename. */
  id: string;
  /** When the extension wrote this. */
  at: string;
  /** `vscode.env.appName` — "Visual Studio Code", "… - Insiders", "VSCodium". */
  app_name: string;
  /** `vscode.version`. */
  version?: string | undefined;
  /** `workspace.isTrusted` — false is Restricted Mode: no hook runs here. */
  trusted: boolean;
  /** The window's workspace folders (`uri.fsPath`); [] for an empty window. */
  folders: string[];
  /** EFFECTIVE values, after policy — what the editor will actually do. */
  hooks_enabled: boolean;
  copilot_hooks_location_enabled: boolean;
  mcp_access?: string | undefined;
}

export function parseEditorWindowReport(json: string): EditorWindowReport | undefined {
  try {
    const raw = JSON.parse(json) as Partial<EditorWindowReport> & { folders?: unknown };
    if (!raw || typeof raw !== "object") return undefined;
    if (typeof raw.id !== "string" || raw.id === "") return undefined;
    if (typeof raw.at !== "string" || typeof raw.trusted !== "boolean") return undefined;
    const folders = Array.isArray(raw.folders) ? raw.folders.filter((f): f is string => typeof f === "string") : [];
    return {
      id: raw.id,
      at: raw.at,
      app_name: typeof raw.app_name === "string" ? raw.app_name : "VS Code",
      ...(typeof raw.version === "string" ? { version: raw.version } : {}),
      trusted: raw.trusted,
      folders,
      // Absent means the extension predates the field; VS Code's defaults are
      // ON, and an unreported value must never read as "switched off".
      hooks_enabled: raw.hooks_enabled !== false,
      copilot_hooks_location_enabled: raw.copilot_hooks_location_enabled !== false,
      ...(typeof raw.mcp_access === "string" ? { mcp_access: raw.mcp_access } : {}),
    };
  } catch {
    return undefined;
  }
}

/** A report is live when its heartbeat is recent — closed windows leave
 * files behind whenever the extension host is killed before deactivate. */
export function windowReportLive(report: EditorWindowReport, now: number = Date.now()): boolean {
  const at = Date.parse(report.at);
  return Number.isFinite(at) && now - at <= WINDOW_STALE_MS;
}

/**
 * What the editor shows. Deliberately small and already-formatted: the
 * extension is a display surface, not a second implementation of the app's
 * arithmetic, so it never has to agree with us about what "today" means or how
 * a cost rounds.
 */
export interface EditorStatus {
  /** When the app wrote this. The extension greys out a stale file rather than
   * showing yesterday's number as if it were live. */
  at: string;
  /** Guardrails on, and how many hosts carry the hook. */
  guard: { armed: boolean; hosts: number };
  /** Today's input+output tokens, pre-formatted ("12.4k"), and absent when
   * unknown — never "0", which would read as "nothing ran" rather than "not
   * known". Tokens, not dollars. */
  tokens_today?: string;
  /** Agents running right now (lib/live-sessions.ts). */
  live_sessions: number;
  /** Open findings on the Security Radar. */
  open_findings: number;
  /** App version, so the extension can say when the two are out of step. */
  app_version: string;
  /**
   * What "Open the app" should open: the `.app` bundle on macOS, the
   * executable elsewhere. Written by a packaged app only — a dev run's
   * execPath is Electron's, and opening that would be a lie. Absent lets the
   * extension fall back to its per-platform default.
   */
  app_path?: string;
}

export type EditorAnswerVerdict = "allow" | "deny";

/** The extension's verdict file. `silence` is the "allow and stop asking"
 * checkbox; the app decides what policy that writes — the extension only
 * reports which box was ticked. */
export interface EditorAnswer {
  id: string;
  verdict: EditorAnswerVerdict;
  at: string;
  silence?: boolean;
  scope?: "project";
}

export function parseEditorAnswer(json: string): EditorAnswer | undefined {
  try {
    const raw = JSON.parse(json) as Partial<EditorAnswer>;
    if (!raw || typeof raw !== "object") return undefined;
    if (typeof raw.id !== "string" || raw.id === "") return undefined;
    if (raw.verdict !== "allow" && raw.verdict !== "deny") return undefined;
    return {
      id: raw.id,
      verdict: raw.verdict,
      at: typeof raw.at === "string" ? raw.at : new Date().toISOString(),
      ...(raw.silence === true ? { silence: true } : {}),
      ...(raw.scope === "project" ? { scope: "project" as const } : {}),
    };
  } catch {
    return undefined;
  }
}

// ---- "bring the app to the screen", asked from the editor -----------------------

/**
 * `editor/open.json` — the fourth file of the contract: the editor
 * asking the app to come to the front on a given screen. Written by the
 * status-bar click when nothing is held in the editor itself; the app watches
 * for it, shows its window, navigates, and deletes the file. An intent older
 * than OPEN_INTENT_MAX_AGE_MS was written for a click nobody is waiting on any
 * more (the app was not running) and is dropped rather than honoured minutes
 * later as a window that jumps to the front unasked.
 */
export function openIntentPath(userDataDir: string): string {
  return `${editorDir(userDataDir)}/open.json`;
}

export const OPEN_INTENT_MAX_AGE_MS = 30_000;

/** The screens the editor may ask for — the renderer's NAV ids, plus `ai`
 * (the assistant drawer) and `trace` that main already routes. Anything else
 * lands on the Overview rather than being trusted as a route. */
export const EDITOR_OPEN_SCREENS = ["overview", "radar", "analytics", "rules", "spend", "ledger", "integrations", "settings", "ai"] as const;
export type EditorOpenScreen = (typeof EDITOR_OPEN_SCREENS)[number];

export interface EditorOpenIntent {
  screen: EditorOpenScreen;
  at: string;
}

export function parseEditorOpenIntent(json: string, now: number = Date.now()): EditorOpenIntent | undefined {
  try {
    const raw = JSON.parse(json) as Partial<EditorOpenIntent> | null;
    if (!raw || typeof raw !== "object" || typeof raw.at !== "string") return undefined;
    const at = Date.parse(raw.at);
    if (!Number.isFinite(at) || now - at > OPEN_INTENT_MAX_AGE_MS) return undefined;
    const screen = (EDITOR_OPEN_SCREENS as readonly string[]).includes(String(raw.screen)) ? (raw.screen as EditorOpenScreen) : "overview";
    return { screen, at: raw.at };
  } catch {
    return undefined;
  }
}

/**
 * What "Open the app" should open, from this process's executable: the `.app`
 * bundle on macOS (`…/Doorman.app/Contents/MacOS/Doorman` → `…/Doorman.app`,
 * which is what Finder and `open` take), the executable itself elsewhere.
 */
export function appBundlePath(execPath: string): string {
  const m = /^(.*?\.app)\/Contents\/MacOS\/[^/]+$/.exec(execPath);
  return m ? m[1]! : execPath;
}

// ---- driving the editor's CLI --------------------------------------------------

/**
 * `code --list-extensions --show-versions` → a map of id → version.
 *
 * The CLI prints one `publisher.name@version` per line, but it also prints
 * whatever Electron felt like warning about (a `DeprecationWarning` on the
 * current build) to the same stream, so anything that isn't shaped like an
 * extension line is dropped rather than parsed optimistically.
 */
export function parseExtensionList(stdout: string): Map<string, string> {
  const out = new Map<string, string>();
  for (const line of stdout.split("\n")) {
    const m = /^([A-Za-z0-9][\w.-]*\.[\w.-]+)@(\d+\.\d+\.\d+(?:[-+][\w.-]+)?)\s*$/.exec(line.trim());
    if (m) out.set(m[1]!.toLowerCase(), m[2]!);
  }
  return out;
}

/** The installed version of our extension, or undefined. */
export function installedVersion(stdout: string): string | undefined {
  return parseExtensionList(stdout).get(EXTENSION_ID.toLowerCase());
}

export function installArgs(vsixPath: string): string[] {
  // `--force` makes a re-install of the same version a no-op success instead of
  // an "already installed" non-zero exit, which is what makes this idempotent
  // enough to run on every boot.
  return ["--install-extension", vsixPath, "--force"];
}

export function uninstallArgs(): string[] {
  return ["--uninstall-extension", EXTENSION_ID];
}

export function listArgs(): string[] {
  return ["--list-extensions", "--show-versions"];
}

/**
 * Does the installed version need replacing? Same version = nothing to do; a
 * different one either way (older OR newer) is replaced, because the extension
 * is shipped BY this app and the app's copy is the one that matches its file
 * contract — a newer extension left behind by a newer app the person rolled
 * back would talk a protocol this build doesn't write.
 */
export function needsInstall(installed: string | undefined, bundled: string): boolean {
  return installed !== bundled;
}
