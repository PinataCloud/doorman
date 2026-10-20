/**
 * Desktop integration for the Linux AppImage: the launcher entry and icon a
 * desktop shell needs to show the running window as "Doorman" with its icon.
 *
 * WHY. GNOME (and KDE, on Wayland) links a window to an app ONLY through a
 * `.desktop` file: its basename, or its `StartupWMClass`, must equal the
 * window's Wayland app_id / X11 WM_CLASS, and its `Icon=` must resolve in the
 * icon theme. Electron sets both to `desktopName` in package.json minus
 * `.desktop` — `cloud.pinata.doorman`. A distro package installs that entry; a
 * downloaded AppImage that is simply run installs nothing, so the shell falls
 * back to a window-backed app: a generic icon, labelled with the raw app_id.
 * This module writes the entry (and the icon) the AppImage lacks, under the
 * user's own data directory:
 *
 *   $XDG_DATA_HOME/applications/cloud.pinata.doorman.desktop
 *   $XDG_DATA_HOME/icons/hicolor/<n>x<n>/apps/cloud.pinata.doorman.png
 *
 * OURS VS SOMEONE ELSE'S. The entry carries `X-Doorman-AppImage=true`. One
 * with the marker is ours and is rewritten whenever it differs from what this
 * build would write (the AppImage moved, or a new version runs). One without
 * it was written by the person or another tool and is never touched. If some
 * other entry already launches this exact AppImage (AppImageLauncher, Gear
 * Lever, appimaged), the AppImage is integrated already and nothing is
 * written: a second "Doorman" in the app grid would be the only effect.
 *
 * REMOVAL. `TryExec` names the AppImage, so once it is deleted the shell hides
 * the entry by itself; deleting the two paths above removes the rest.
 *
 * Pure apart from the filesystem writes under the data directory: the icon
 * rendering (Electron's nativeImage) is passed in, so this file imports no
 * `electron` and is unit-tested against a temp directory.
 */

import { existsSync, mkdirSync, readdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname, isAbsolute, join } from "node:path";

/** package.json `desktopName` without `.desktop`: the app_id / WM_CLASS
 * Electron gives every window, and so the name the entry must carry. */
export const DESKTOP_ID = "cloud.pinata.doorman";

/** The marker key that makes an entry ours to update. */
export const MARKER_KEY = "X-Doorman-AppImage";

/** hicolor sizes written, from the 1024 px brand PNG. The theme's own size
 * list stops at 512; launchers and docks pick from these. */
export const ICON_SIZES = [512, 256, 128, 64, 48, 32] as const;

const COMMENT = "Local-first AI spend graphs, Security Guard and event ledger";
const CATEGORIES = "Development;Utility;";

export interface DesktopPaths {
  dataHome: string;
  applicationsDir: string;
  desktopFile: string;
  hicolorDir: string;
  iconFile: (size: number) => string;
}

/** `$XDG_DATA_HOME`, else `~/.local/share`. The spec says a relative value is
 * invalid and must be ignored. */
export function dataHome(env: NodeJS.ProcessEnv, home: string): string {
  const configured = env.XDG_DATA_HOME;
  return configured && isAbsolute(configured) ? configured : join(home, ".local", "share");
}

export function desktopPaths(env: NodeJS.ProcessEnv, home: string): DesktopPaths {
  const root = dataHome(env, home);
  const applicationsDir = join(root, "applications");
  const hicolorDir = join(root, "icons", "hicolor");
  return {
    dataHome: root,
    applicationsDir,
    desktopFile: join(applicationsDir, `${DESKTOP_ID}.desktop`),
    hicolorDir,
    iconFile: (size) => join(hicolorDir, `${size}x${size}`, "apps", `${DESKTOP_ID}.png`),
  };
}

/** A desktop-entry string value: `\` and the control characters a value can
 * carry are escaped (the spec's `\\`, `\n`, `\t`, `\r`). */
function escapeValue(value: string): string {
  return value.replace(/\\/g, "\\\\").replace(/\n/g, "\\n").replace(/\t/g, "\\t").replace(/\r/g, "\\r");
}

/** One argument of an `Exec` line: double-quoted, with the four characters the
 * spec reserves inside quotes backslashed and `%` doubled so it is never read
 * as a field code. escapeValue then applies the string-level escaping on top,
 * which is why a literal backslash ends up as four in the file. */
export function quoteExecArg(arg: string): string {
  return `"${arg.replace(/(["`$\\])/g, "\\$1").replace(/%/g, "%%")}"`;
}

/** The entry for an AppImage at `appImage`. */
export function desktopEntry(appImage: string, version: string): string {
  return [
    "[Desktop Entry]",
    "Type=Application",
    "Name=Doorman",
    `Comment=${COMMENT}`,
    `Exec=${escapeValue(`${quoteExecArg(appImage)} %U`)}`,
    `TryExec=${escapeValue(appImage)}`,
    `Icon=${DESKTOP_ID}`,
    "Terminal=false",
    `Categories=${CATEGORIES}`,
    `StartupWMClass=${DESKTOP_ID}`,
    `X-AppImage-Version=${version}`,
    `${MARKER_KEY}=true`,
    "",
  ].join("\n");
}

export type IntegrationStatus =
  /** Entry and every icon were already what this build writes. */
  | "current"
  /** No entry of ours existed; written now. */
  | "installed"
  /** Ours existed for another path or version, or an icon was missing. */
  | "updated"
  /** An entry with our name exists that we did not write: left alone. */
  | "foreign"
  /** Another entry already launches this AppImage: nothing written. */
  | "integrated-elsewhere"
  /** The AppImage path can't be written into an entry (relative, or a line break). */
  | "invalid-path";

export interface IntegrationResult {
  status: IntegrationStatus;
  /** Files written by this call (entry and/or icons). */
  written: string[];
}

export interface IntegrateOptions {
  /** `$APPIMAGE`: the absolute path of the running .AppImage file. */
  appImage: string;
  version: string;
  paths: DesktopPaths;
  /** The brand icon as a PNG of `size`×`size`, or null if it can't be made. */
  renderIcon: (size: number) => Buffer | null;
}

function writeAtomic(path: string, data: string | Buffer): void {
  const tmp = `${path}.${process.pid}.tmp`;
  writeFileSync(tmp, data);
  renameSync(tmp, path);
}

function readText(path: string): string | null {
  try {
    return readFileSync(path, "utf8");
  } catch {
    return null;
  }
}

/** Another `.desktop` in the applications directory whose Exec runs this
 * exact AppImage — the sign that a launcher tool integrated it already. */
function integratedElsewhere(applicationsDir: string, ownFile: string, appImage: string): boolean {
  let names: string[];
  try {
    names = readdirSync(applicationsDir);
  } catch {
    return false;
  }
  for (const name of names) {
    if (!name.endsWith(".desktop")) continue;
    const path = join(applicationsDir, name);
    if (path === ownFile) continue;
    const text = readText(path);
    if (text && text.split("\n").some((line) => line.startsWith("Exec=") && line.includes(appImage))) return true;
  }
  return false;
}

/**
 * Make sure the running AppImage has its launcher entry and icon. Cheap when
 * everything is current: one read and a stat per icon size; icons are only
 * rendered when the entry changes or one of them is missing.
 */
export function integrateAppImage(opts: IntegrateOptions): IntegrationResult {
  const { paths } = opts;
  if (!isAbsolute(opts.appImage) || /[\r\n]/.test(opts.appImage)) return { status: "invalid-path", written: [] };

  const existing = readText(paths.desktopFile);
  if (existing !== null && !new RegExp(`^${MARKER_KEY}=true$`, "m").test(existing)) return { status: "foreign", written: [] };
  if (existing === null && integratedElsewhere(paths.applicationsDir, paths.desktopFile, opts.appImage)) {
    return { status: "integrated-elsewhere", written: [] };
  }

  const wanted = desktopEntry(opts.appImage, opts.version);
  const entryChanged = existing !== wanted;
  const written: string[] = [];

  // Icons before the entry, so a shell that reads the new entry the moment it
  // lands already finds the icon it names.
  for (const size of ICON_SIZES) {
    const file = paths.iconFile(size);
    if (!entryChanged && existsSync(file)) continue;
    const png = opts.renderIcon(size);
    if (!png || png.length === 0) continue;
    mkdirSync(dirname(file), { recursive: true });
    writeAtomic(file, png);
    written.push(file);
  }

  if (entryChanged) {
    mkdirSync(paths.applicationsDir, { recursive: true });
    writeAtomic(paths.desktopFile, wanted);
    written.push(paths.desktopFile);
  }

  if (written.length === 0) return { status: "current", written };
  return { status: existing === null ? "installed" : "updated", written };
}

/** Runs a tool; `done` gets the spawn or exit error (`code` "ENOENT" when the
 * tool isn't installed), null on success. */
export type RunTool = (cmd: string, args: string[], done: (err: { code?: string | number | null } | null) => void) => void;

/**
 * Best-effort cache refreshes after the entry or an icon was written; a
 * desktop without these tools notices the new files by itself. Errors are
 * ignored. The icon cache is refreshed, never created: a hicolor directory
 * without one is simply scanned. KDE Plasma reads launcher entries from its
 * own KService cache (sycoca), so it is rebuilt too: kbuildsycoca6, or
 * kbuildsycoca5 where only Plasma 5 is installed.
 */
export function refreshDesktopCaches(paths: DesktopPaths, run: RunTool): void {
  run("update-desktop-database", ["-q", paths.applicationsDir], () => {});
  if (existsSync(join(paths.hicolorDir, "icon-theme.cache"))) {
    run("gtk-update-icon-cache", ["-q", "-t", "-f", paths.hicolorDir], () => {});
  }
  run("kbuildsycoca6", [], (err) => {
    if (err?.code === "ENOENT") run("kbuildsycoca5", [], () => {});
  });
}
