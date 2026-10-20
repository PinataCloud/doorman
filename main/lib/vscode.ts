/**
 * VS Code, as this app has to see it — the FAMILY, its profiles, and the
 * handful of settings that decide whether the guard runs there at all.
 *
 * Until this module existed, "VS Code" meant exactly one directory,
 * `~/Library/Application Support/Code/User`, hard-coded in three places
 * (lib/mcp-register.ts, lib/mcp-inventory.ts, lib/vscode-copilot-transcript.ts).
 * Two things were therefore invisible:
 *
 *  1. EVERY OTHER BUILD. Insiders and VSCodium keep their own user-data
 *     directory, their own extensions directory and their own URL scheme. A
 *     person on Insiders got a clean bill of health for a machine we had not
 *     looked at. (Cursor and Windsurf are VS Code forks too, but they are
 *     already first-class hosts of their own here — guard/hosts/cursor.ts,
 *     the shadow-AI catalog — so they are deliberately NOT in this family.)
 *  2. PROFILES. A non-default profile has its own `settings.json` AND its own
 *     `mcp.json` under `User/profiles/<id>/`; VS Code resolves them through
 *     `useDefaultFlags` per resource (verified in 1.136.2's
 *     workbench.desktop.main.js: `mcpResource: … ? r.mcpResource : join(e,
 *     "mcp.json")`). A profile that does not inherit the default picks up
 *     neither our MCP registration nor the default profile's settings.
 *
 * WHAT MAKES THE GUARD RUN IN VS CODE (all verified against the shipped
 * VS Code 1.136.2 bundle and re-verified unchanged against 1.138.0 on
 * 2026-09-21, not documentation — see test/vscode.test.ts):
 *
 *  · `chat.useHooks` — default TRUE, tagged preview, `restricted: true`, and
 *    backed by the `ChatHooks` enterprise policy (`minimumVersion: 1.109`,
 *    forced off when `chat_preview_features_enabled === false`). False here and
 *    NO hook runs in VS Code — ours included, silently.
 *  · `chat.hookFilesLocations` — an enable map over the five hook sources VS
 *    Code knows, defaulting all true:
 *        .github/hooks, .claude/settings.local.json, .claude/settings.json,
 *        ~/.copilot/hooks, ~/.claude/settings.json
 *    `~/.copilot/hooks` is the one OUR document lives in (guard/hosts/copilot.ts
 *    writes `doorman.json` there, and VS Code reads the Copilot CLI's
 *    directory). Setting it false disables our guard while `chat.useHooks`
 *    still reads as on. (1.138.0 adds an `agentsWindow` default for the map
 *    that switches the three `.claude` sources off in the Agents window;
 *    `~/.copilot/hooks` stays on there too.)
 *  · `chat.useClaudeHooks` — default FALSE. The two `.claude` sources above are
 *    gated behind it, so our Claude Code hooks do NOT fire in VS Code unless
 *    someone turned this on. Worth reporting, never worth changing for them.
 *  · WORKSPACE TRUST. `computeHooks` bails with `skipReason:
 *    "workspace-untrusted"` unless `workspaceTrustService.isWorkspaceTrusted()`.
 *    A repo opened in Restricted Mode runs its agent with no hooks at all.
 *    Which folders are trusted IS readable — see *Workspace trust* below — so
 *    the setup check names the recent folders that open restricted instead of
 *    repeating a standing caveat.
 *  · `chat.mcp.access` — `none` stops our MCP server from loading.
 *  · `chat.tools.global.autoApprove` (default false) and
 *    `chat.tools.terminal.autoApprove` — VS Code's OWN confirmations, not
 *    ours. Reported because "the editor stops asking" is exactly the state
 *    someone wants to know about; the guard's own hold is unaffected.
 *
 * WORKSPACE TRUST, as 1.138.0 persists and computes it (read out of
 * workbench.desktop.main.js + main.js, and confirmed against the databases on
 * a real Mac):
 *
 *  · The trusted-folder list is `content.trust.model.key` in the
 *    APPLICATION-SHARED storage scope (`StorageScope` -2, new in this era of
 *    VS Code) — `<home>/<product.json sharedDataFolderName>/sharedStorage/
 *    state.vscdb`, an `ItemTable(key, value)` SQLite database the editor holds
 *    open in WAL mode. Stable's `sharedDataFolderName` is `.vscode-shared`;
 *    Code - OSS's (so VSCodium's) is `.vscode-oss-shared`; Insiders' is not
 *    verified here, so it is read out of the installed bundle's product.json
 *    at runtime rather than guessed. Builds from before the shared scope kept
 *    the same key in `User/globalStorage/state.vscdb` (scope -1), which is the
 *    fallback when no shared database exists — the shared one carries a
 *    `__$__migratedStorageMarker` once the move has happened.
 *  · The value is `{uriTrustInfo: [{uri: {scheme, path, fsPath, …},
 *    trusted}]}`; `loadTrustInfo` drops every entry that is not `trusted`, so
 *    the list is effectively the trusted set.
 *  · A folder is trusted when the LONGEST entry that equals it or is one of its
 *    parents is trusted (`isEqualOrParent`, longest `fsPath` wins) — so
 *    trusting `~/repos` once trusts every repo under it. Path casing is
 *    ignored for `file` URIs on macOS, as VS Code's `extUri` does.
 *  · `security.workspace.trust.enabled` false (an APPLICATION-scoped setting,
 *    so only the default profile's settings.json can carry it) or the
 *    `--disable-workspace-trust` flag makes every folder trusted.
 *  · Which folders matter is `history.recentlyOpenedPathsList` in the same
 *    database — `{entries: [{folderUri}, {fileUri, label?}, {workspace}]}`,
 *    most recent first.
 *
 * Pure: paths are built from a home string, and the filesystem questions
 * (does it exist, what is in it, what does this database row hold) arrive as
 * callbacks.
 */

import { join, posix, win32 } from "node:path";
import { parseJsonc } from "../guard/jsonc.js";

export interface VscodeVariant {
  /** Stable id; `vscode` is the shadow-AI/coverage id already in use. */
  id: "vscode" | "vscode-insiders" | "vscodium";
  label: string;
  /** Home-relative user-data directory (the one holding `User/`), for the
   * platform the list was built for (`vscodeVariants`). */
  supportRel: string;
  /** Home-relative extensions directory the CLI installs into. */
  extensionsRel: string;
  /** Absolute application bundles that mean this build is installed. */
  appPaths: string[];
  /** URL scheme for `…://file/…` deep links and `…://extension/…`. */
  scheme: string;
  /** The build's own command-line name: `code`, `code-insiders`, `codium`. */
  cliName: string;
  /** The folder the Windows installers create, under `%LOCALAPPDATA%\Programs`
   * (the per-user installer) or `%ProgramFiles%` (the system one). */
  windowsInstallDir: string;
  /**
   * Home-relative application-shared data folder (`product.json`'s
   * `sharedDataFolderName`), where 1.138-era builds keep the trusted-folder
   * list. Only set where it was read out of a real product.json; the installed
   * bundle's own product.json wins over it at runtime (`sharedDataFolder`).
   */
  sharedDataRel?: string;
}

/** Bundle-relative path of the `code` CLI inside every VS Code-derived app. */
export const VSCODE_CLI_REL = "Contents/Resources/app/bin";

/**
 * Home-relative folder Electron apps keep per-user data in: the default of
 * `app.getPath("appData")` on each platform. VS Code and Claude Desktop both
 * live under it (`<appData>/Code`, `<appData>/Claude`). A relocated
 * `%APPDATA%` or `$XDG_CONFIG_HOME` is not followed: every path built from
 * this is home-relative.
 */
export function appDataRel(platform: NodeJS.Platform = process.platform): string {
  if (platform === "darwin") return "Library/Application Support";
  if (platform === "win32") return "AppData/Roaming";
  return ".config";
}

/** The family, with each build's user-data folder NAME (`product.json`'s
 * `nameLong`-derived data folder, the same on every platform). */
const FAMILY: ReadonlyArray<Omit<VscodeVariant, "supportRel"> & { dataFolder: string }> = [
  {
    id: "vscode",
    label: "VS Code",
    dataFolder: "Code",
    extensionsRel: ".vscode",
    appPaths: ["/Applications/Visual Studio Code.app"],
    scheme: "vscode",
    cliName: "code",
    windowsInstallDir: "Microsoft VS Code",
    // 1.138.0's product.json, read 2026-09-21.
    sharedDataRel: ".vscode-shared",
  },
  {
    id: "vscode-insiders",
    label: "VS Code Insiders",
    dataFolder: "Code - Insiders",
    extensionsRel: ".vscode-insiders",
    appPaths: ["/Applications/Visual Studio Code - Insiders.app"],
    scheme: "vscode-insiders",
    cliName: "code-insiders",
    windowsInstallDir: "Microsoft VS Code Insiders",
  },
  {
    id: "vscodium",
    label: "VSCodium",
    dataFolder: "VSCodium",
    extensionsRel: ".vscode-oss",
    appPaths: ["/Applications/VSCodium.app"],
    scheme: "vscodium",
    cliName: "codium",
    windowsInstallDir: "VSCodium",
    // Code - OSS's product.json on microsoft/vscode main, read 2026-09-21;
    // VSCodium inherits it (its own overrides set dataFolderName only).
    sharedDataRel: ".vscode-oss-shared",
  },
];

/** The family as one platform lays it out: `~/Library/Application Support/Code`
 * on macOS, `%APPDATA%\Code` on Windows, `~/.config/Code` on Linux. */
export function vscodeVariants(platform: NodeJS.Platform = process.platform): readonly VscodeVariant[] {
  return FAMILY.map(({ dataFolder, ...variant }) => ({ ...variant, supportRel: `${appDataRel(platform)}/${dataFolder}` }));
}

export const VSCODE_VARIANTS: readonly VscodeVariant[] = vscodeVariants();

export const DEFAULT_VARIANT = VSCODE_VARIANTS[0]!;

function trimSlash(path: string): string {
  return path.replace(/\/+$/, "");
}

/** `<home>/<supportRel>/User` — the default profile's directory. */
export function userDir(variant: VscodeVariant, home: string): string {
  return join(home, variant.supportRel, "User");
}

/** Where a CLI lookup runs: the platform, the home, and the environment it
 * reads (`PATH`; on Windows `%LOCALAPPDATA%` and `%ProgramFiles%`). */
export interface CliPlace {
  platform: NodeJS.Platform;
  home: string;
  env: NodeJS.ProcessEnv;
}

/** The absolute directories on `PATH`, in order. A relative entry would
 * resolve against whatever directory the app runs in, so it is skipped. */
function pathDirs(place: CliPlace): string[] {
  const windows = place.platform === "win32";
  const raw = (windows ? (place.env.PATH ?? place.env.Path) : place.env.PATH) ?? "";
  const p = windows ? win32 : posix;
  return raw
    .split(windows ? ";" : ":")
    .map((dir) => dir.trim().replace(/^"(.*)"$/, "$1"))
    .filter((dir) => dir !== "" && p.isAbsolute(dir));
}

/**
 * Every place this build's `code` command line may be, most specific first;
 * the caller takes the first that exists.
 *
 * macOS: only INSIDE the application bundle, never the PATH — a GUI-launched
 * Mac app inherits launchd's minimal PATH, which has no `code`. The name
 * differs per build, so every candidate in the bin directory is offered.
 *
 * Windows: `bin\<name>.cmd` under the per-user install
 * (`%LOCALAPPDATA%\Programs\<dir>`), then the system one
 * (`%ProgramFiles%\<dir>`), then each `PATH` directory. Linux: the .deb/.rpm
 * (`/usr/bin`, `/usr/share/<name>/bin`), the snap, `~/.local/bin`, then
 * `PATH`. Off macOS only the build's own name is looked for: a bare `code`
 * on PATH is stable VS Code, not Insiders.
 */
export function cliCandidates(variant: VscodeVariant, place: CliPlace): string[] {
  if (place.platform === "darwin") {
    const names = variant.id === "vscode-insiders" ? ["code-insiders", "code"] : variant.id === "vscodium" ? ["codium", "code"] : ["code"];
    return variant.appPaths.flatMap((app) => names.map((name) => `${trimSlash(app)}/${VSCODE_CLI_REL}/${name}`));
  }
  const name = variant.cliName;
  let out: string[];
  if (place.platform === "win32") {
    const local = place.env.LOCALAPPDATA?.trim() || win32.join(place.home, "AppData", "Local");
    const programFiles = place.env.ProgramFiles?.trim() || "C:\\Program Files";
    const cmd = `${name}.cmd`;
    out = [
      win32.join(local, "Programs", variant.windowsInstallDir, "bin", cmd),
      win32.join(programFiles, variant.windowsInstallDir, "bin", cmd),
      ...pathDirs(place).map((dir) => win32.join(dir, cmd)),
    ];
  } else {
    out = [
      `/usr/bin/${name}`,
      `/usr/share/${name}/bin/${name}`,
      `/snap/bin/${name}`,
      ...(place.home ? [posix.join(place.home, ".local", "bin", name)] : []),
      ...pathDirs(place).map((dir) => posix.join(dir, name)),
    ];
  }
  return [...new Set(out)];
}

/**
 * How to spawn a found CLI. On Windows the CLI is a `.cmd` script, which Node
 * refuses to run directly (CVE-2024-27980), so it goes through `cmd.exe /d /s
 * /c` with every part quoted. cmd expands `%NAME%` even inside quotes and has
 * no escape for `"`, so a part holding either is refused (undefined) rather
 * than handed to the shell.
 */
export function cliInvocation(
  cli: string,
  args: readonly string[],
  platform: NodeJS.Platform = process.platform,
): { file: string; args: string[]; windowsVerbatimArguments?: true } | undefined {
  if (platform !== "win32" || !/\.(cmd|bat)$/i.test(cli)) return { file: cli, args: [...args] };
  const parts = [cli, ...args];
  if (parts.some((part) => /["%]/.test(part))) return undefined;
  return { file: "cmd.exe", args: ["/d", "/s", "/c", `"${parts.map((part) => `"${part}"`).join(" ")}"`], windowsVerbatimArguments: true };
}

/** This build is installed here (its bundle, or a user directory it wrote). */
export function variantPresent(variant: VscodeVariant, home: string, exists: (path: string) => boolean): boolean {
  return variant.appPaths.some(exists) || exists(userDir(variant, home));
}

export interface VscodeProfile {
  /** VS Code's own profile id; "" for the default profile. */
  id: string;
  /** Directory holding this profile's settings.json / mcp.json. */
  dir: string;
  default: boolean;
}

/**
 * Every profile directory of one build: the default `User/`, then each
 * `User/profiles/<id>/`. Profiles are listed even when empty — a profile that
 * inherits the default for a resource simply has no file there, and the caller
 * decides whether an absent file means "inherited" (fine) or "unregistered".
 */
export function profiles(
  variant: VscodeVariant,
  home: string,
  io: { exists(path: string): boolean; listDir(path: string): string[] },
): VscodeProfile[] {
  const base = userDir(variant, home);
  if (!io.exists(base)) return [];
  const out: VscodeProfile[] = [{ id: "", dir: base, default: true }];
  const root = join(base, "profiles");
  if (io.exists(root)) {
    for (const name of io.listDir(root).sort()) {
      const dir = join(root, name);
      if (io.exists(dir)) out.push({ id: name, dir, default: false });
    }
  }
  return out;
}

// ---- the settings that decide whether we are running there -------------------

/** The hook source our guard document lives in — `guard/hosts/copilot.ts`
 * writes `~/.copilot/hooks/doorman.json`, and VS Code globs that directory.
 * Spelled exactly as VS Code keys it in `chat.hookFilesLocations`. */
export const COPILOT_HOOKS_LOCATION = "~/.copilot/hooks";

/** VS Code 1.136.2's five hook sources, in the order it registers them. */
export const HOOK_LOCATIONS: readonly string[] = [
  ".github/hooks",
  ".claude/settings.local.json",
  ".claude/settings.json",
  COPILOT_HOOKS_LOCATION,
  "~/.claude/settings.json",
];

export interface VscodeSettingsFacts {
  /** `chat.useHooks` — absent means VS Code's default, which is ON. */
  hooksEnabled: boolean;
  /** `chat.useHooks` was explicitly written (someone chose this, either way). */
  hooksExplicit: boolean;
  /** `chat.hookFilesLocations["~/.copilot/hooks"]` — absent means default ON. */
  copilotHooksLocationEnabled: boolean;
  /** Hook locations someone switched off, as written. */
  disabledHookLocations: string[];
  /** `chat.useClaudeHooks` — default OFF; on means our Claude Code hooks fire here too. */
  claudeHooksEnabled: boolean;
  /** `chat.mcp.access`; undefined = default (MCP allowed). */
  mcpAccess?: string;
  /** `chat.tools.global.autoApprove` — default OFF. VS Code's own confirmations. */
  globalAutoApprove: boolean;
  /** Number of allow-entries in `chat.tools.terminal.autoApprove`. */
  terminalAutoApproveAllows: number;
  /** `chat.disableAIFeatures` — the whole chat surface is off. */
  aiDisabled: boolean;
  /**
   * `security.workspace.trust.enabled` — default ON. Off means no folder ever
   * opens in Restricted Mode, so hooks run everywhere. APPLICATION-scoped:
   * VS Code honours it from the default profile's settings.json only.
   */
  workspaceTrustEnabled: boolean;
}

function bool(value: unknown): boolean | undefined {
  return typeof value === "boolean" ? value : undefined;
}

/** Read the coverage-relevant settings out of a parsed settings document.
 * Every default here is VS Code's own, so an EMPTY document assesses as the
 * healthy state rather than as a pile of unknowns. */
export function assessSettings(settings: Record<string, unknown> | undefined): VscodeSettingsFacts {
  const doc = settings ?? {};
  const useHooks = bool(doc["chat.useHooks"]);
  const locations = doc["chat.hookFilesLocations"];
  const locationMap =
    locations && typeof locations === "object" && !Array.isArray(locations) ? (locations as Record<string, unknown>) : {};
  const disabled = Object.entries(locationMap)
    .filter(([, v]) => v === false)
    .map(([k]) => k);
  const terminal = doc["chat.tools.terminal.autoApprove"];
  const terminalMap =
    terminal && typeof terminal === "object" && !Array.isArray(terminal) ? (terminal as Record<string, unknown>) : {};
  const mcpAccess = doc["chat.mcp.access"];
  return {
    hooksEnabled: useHooks !== false,
    hooksExplicit: useHooks !== undefined,
    copilotHooksLocationEnabled: locationMap[COPILOT_HOOKS_LOCATION] !== false,
    disabledHookLocations: disabled,
    claudeHooksEnabled: bool(doc["chat.useClaudeHooks"]) === true,
    ...(typeof mcpAccess === "string" ? { mcpAccess } : {}),
    globalAutoApprove: bool(doc["chat.tools.global.autoApprove"]) === true,
    terminalAutoApproveAllows: Object.values(terminalMap).filter((v) => v === true).length,
    aiDisabled: bool(doc["chat.disableAIFeatures"]) === true,
    workspaceTrustEnabled: bool(doc["security.workspace.trust.enabled"]) !== false,
  };
}

/** Read + assess in one step. A settings file VS Code itself can read (JSONC)
 * is read; anything else assesses as the defaults, because an unreadable file
 * is not evidence that someone turned something off. */
export function readSettings(text: string | undefined): VscodeSettingsFacts {
  return assessSettings(parseJsonc(text));
}

// ---- workspace trust -------------------------------------------------------------

/** Bundle-relative path of the product manifest every VS Code build ships. */
export const VSCODE_PRODUCT_JSON_REL = "Contents/Resources/app/product.json";

/** The storage row holding `{uriTrustInfo: [...]}`. */
export const TRUST_STORAGE_KEY = "content.trust.model.key";
/** The storage row holding `{entries: [{folderUri} | {fileUri} | {workspace}]}`. */
export const RECENT_STORAGE_KEY = "history.recentlyOpenedPathsList";
/** The one statement issued against a VS Code storage database. */
export const STORAGE_ITEM_SQL = "SELECT value FROM ItemTable WHERE key = ?";
/** How many of the most recently opened folders the trust verdict covers. */
export const RECENT_FOLDER_LIMIT = 10;

/**
 * `sharedDataFolderName` of an installed build, read out of its own
 * product.json — the only source that is right for every build, Insiders
 * included. Falls back to the value recorded on the variant, and to undefined
 * when neither is known (an Insiders user directory with no bundle).
 */
export function sharedDataFolder(variant: VscodeVariant, readText: (path: string) => string | undefined): string | undefined {
  for (const app of variant.appPaths) {
    const text = readText(`${trimSlash(app)}/${VSCODE_PRODUCT_JSON_REL}`);
    if (!text) continue;
    try {
      const name = (JSON.parse(text) as { sharedDataFolderName?: unknown }).sharedDataFolderName;
      if (typeof name === "string" && name.length > 0) return name;
    } catch {
      // an unreadable manifest is not evidence of anything; fall through
    }
  }
  return variant.sharedDataRel;
}

/**
 * The storage databases that can hold the trusted-folder list, most
 * authoritative first: the application-shared one (1.138-era builds), then the
 * application/global one older builds wrote to. The caller takes the FIRST
 * that exists — once the shared database exists the older row is a migrated
 * copy that stops being updated.
 */
export function trustDatabases(variant: VscodeVariant, home: string, sharedFolder: string | undefined): string[] {
  const out: string[] = [];
  if (sharedFolder) out.push(join(home, sharedFolder, "sharedStorage", "state.vscdb"));
  out.push(join(userDir(variant, home), "globalStorage", "state.vscdb"));
  return out;
}

export interface TrustedUri {
  /** Absolute filesystem path of a `file` URI. */
  path: string;
  trusted: boolean;
}

function filePath(uri: unknown): string | undefined {
  if (typeof uri === "string") {
    if (!uri.startsWith("file://")) return undefined;
    // `file:///abs/path` (empty authority) is what VS Code writes; a host
    // authority, should one appear, is dropped so only the path remains.
    let rest = uri.slice("file://".length);
    if (!rest.startsWith("/")) {
      const slash = rest.indexOf("/");
      if (slash < 0) return undefined;
      rest = rest.slice(slash);
    }
    try {
      return decodeURIComponent(rest);
    } catch {
      return undefined;
    }
  }
  if (uri && typeof uri === "object") {
    const u = uri as { scheme?: unknown; fsPath?: unknown; path?: unknown };
    if (u.scheme !== undefined && u.scheme !== "file") return undefined;
    const p = typeof u.fsPath === "string" ? u.fsPath : typeof u.path === "string" ? u.path : undefined;
    return p && p.startsWith("/") ? p : undefined;
  }
  return undefined;
}

/**
 * `content.trust.model.key`'s value → the `file` entries, as VS Code's own
 * `loadTrustInfo` reads them. Undefined when the text is not that document at
 * all (so a corrupt row reads as "unknown", never as "nothing is trusted");
 * an absent row is the caller's `[]`, which IS "nothing is trusted".
 */
export function parseTrustInfo(text: string | undefined): TrustedUri[] | undefined {
  if (text === undefined) return undefined;
  let doc: unknown;
  try {
    doc = JSON.parse(text);
  } catch {
    return undefined;
  }
  if (!doc || typeof doc !== "object" || Array.isArray(doc)) return undefined;
  const info = (doc as { uriTrustInfo?: unknown }).uriTrustInfo;
  // VS Code's own reader: a document with no `uriTrustInfo` IS an empty list.
  if (info === undefined || info === null) return [];
  if (!Array.isArray(info)) return undefined;
  const out: TrustedUri[] = [];
  for (const entry of info) {
    if (!entry || typeof entry !== "object") continue;
    const path = filePath((entry as { uri?: unknown }).uri);
    if (path) out.push({ path: trimSlash(path) || "/", trusted: (entry as { trusted?: unknown }).trusted === true });
  }
  return out;
}

/**
 * `history.recentlyOpenedPathsList`'s value → the folders, most recent first.
 * Files and `.code-workspace` entries are skipped: a file opened on its own
 * is an empty window, and a multi-root workspace's trust is its own question.
 */
export function parseRecentFolders(text: string | undefined): string[] {
  if (text === undefined) return [];
  let doc: unknown;
  try {
    doc = JSON.parse(text);
  } catch {
    return [];
  }
  const entries = (doc as { entries?: unknown } | null)?.entries;
  if (!Array.isArray(entries)) return [];
  const out: string[] = [];
  for (const entry of entries) {
    const path = filePath((entry as { folderUri?: unknown } | null)?.folderUri);
    if (path) out.push(trimSlash(path) || "/");
  }
  return out;
}

/** VS Code's `isEqualOrParent` for two `file` paths on macOS: casing ignored. */
function isEqualOrParent(path: string, parent: string): boolean {
  const a = path.toLowerCase();
  const b = trimSlash(parent).toLowerCase() || "/";
  return a === b || a.startsWith(b === "/" ? "/" : `${b}/`);
}

/**
 * Is this folder trusted, given the persisted list? VS Code's own rule
 * (`doGetUriTrustInfo`): the LONGEST entry equal to the folder or one of its
 * parents decides; no entry at all means untrusted.
 */
export function folderTrusted(folder: string, entries: readonly TrustedUri[]): boolean {
  let best = -1;
  let trusted = false;
  for (const entry of entries) {
    if (!isEqualOrParent(folder, entry.path) || entry.path.length <= best) continue;
    best = entry.path.length;
    trusted = entry.trusted;
  }
  return trusted;
}

export interface WorkspaceTrustReading {
  /**
   * `disabled` — Workspace Trust is off, every folder is trusted;
   * `unknown` — no readable storage database (older build without the
   *             row, no sqlite reader, a locked or corrupt file);
   * `read` — the list was read and `untrusted` is the verdict.
   */
  kind: "disabled" | "unknown" | "read";
  /** How many recent folders were checked (`read` only). */
  checked: number;
  /** Recent folders that open in Restricted Mode, most recent first. */
  untrusted: string[];
  /** The database the verdict came from (`read` only). */
  database?: string;
}

export interface TrustIo {
  exists(path: string): boolean;
  readText(path: string): string | undefined;
  /** Rows of a read-only query; may be absent (no sqlite reader) or throw. */
  querySqlite?(path: string, sql: string, params: readonly unknown[]): Record<string, unknown>[];
}

/**
 * The trust verdict for one build: which of its most recently opened folders
 * would open in Restricted Mode today. `defaultSettings` are the DEFAULT
 * profile's facts — the only place `security.workspace.trust.enabled` counts.
 * Folders that no longer exist are not reported; nobody opens those.
 */
export function readWorkspaceTrust(
  variant: VscodeVariant,
  home: string,
  defaultSettings: VscodeSettingsFacts,
  io: TrustIo,
  limit: number = RECENT_FOLDER_LIMIT,
): WorkspaceTrustReading {
  if (!defaultSettings.workspaceTrustEnabled) return { kind: "disabled", checked: 0, untrusted: [] };
  if (!io.querySqlite) return { kind: "unknown", checked: 0, untrusted: [] };
  const database = trustDatabases(variant, home, sharedDataFolder(variant, io.readText)).find((p) => io.exists(p));
  if (!database) return { kind: "unknown", checked: 0, untrusted: [] };
  let trustRow: string | undefined;
  let recentRow: string | undefined;
  try {
    const value = (key: string): string | undefined => {
      const rows = io.querySqlite!(database, STORAGE_ITEM_SQL, [key]);
      const v = rows[0]?.["value"];
      return typeof v === "string" ? v : undefined;
    };
    trustRow = value(TRUST_STORAGE_KEY);
    recentRow = value(RECENT_STORAGE_KEY);
  } catch {
    return { kind: "unknown", checked: 0, untrusted: [] };
  }
  // No row yet is a real answer — nothing has ever been trusted in this build.
  const entries = trustRow === undefined ? [] : parseTrustInfo(trustRow);
  if (entries === undefined) return { kind: "unknown", checked: 0, untrusted: [] };
  const recent = parseRecentFolders(recentRow)
    .filter((folder) => io.exists(folder))
    .slice(0, limit);
  return {
    kind: "read",
    checked: recent.length,
    untrusted: recent.filter((folder) => !folderTrusted(folder, entries)),
    database,
  };
}

// ---- deep links ---------------------------------------------------------------

/**
 * `vscode://file/<abs path>[:line[:col]]` — the URL scheme every VS Code build
 * registers for "open this file here".
 *
 * The path is NOT percent-encoded as a whole: VS Code splits the authority
 * itself and expects a real path after `file`, so only the characters that
 * would end the URL or be read as part of the `:line:col` suffix are escaped.
 * A relative path returns undefined rather than being resolved against a guess
 * at the working directory.
 */
export function fileLink(path: string, line?: number, column?: number, scheme: string = DEFAULT_VARIANT.scheme): string | undefined {
  if (!path.startsWith("/")) return undefined;
  const encoded = path
    .split("/")
    .map((segment) => encodeURIComponent(segment))
    .join("/");
  const at = line !== undefined && Number.isFinite(line) && line > 0 ? `:${Math.floor(line)}${column !== undefined && Number.isFinite(column) && column > 0 ? `:${Math.floor(column)}` : ""}` : "";
  return `${scheme}://file${encoded}${at}`;
}

/** `vscode://<publisher>.<name>` install link for the Marketplace page. Only
 * used to send someone to the extension when the CLI install is unavailable. */
export function extensionLink(extensionId: string, scheme: string = DEFAULT_VARIANT.scheme): string {
  return `${scheme}:extension/${extensionId}`;
}
