/**
 * The application menu. Electron's default menu says "Electron" and offers
 * nothing of ours; this one carries the app identity (About/Settings/Updates)
 * plus the standard Edit/Window roles — without an Edit menu, ⌘C/⌘V don't
 * work in any input on macOS.
 *
 * The APP NAME in the menu bar comes from the running bundle's `CFBundleName`,
 * not from `app.setName()` — packaged builds get it from electron-builder, and
 * dev runs from scripts/brand-dev-shell.mjs, which relabels the prebuilt
 * Electron.app in node_modules. Everything inside the menus is ours regardless.
 */

import { Menu, app } from "electron";

export interface MenuCallbacks {
  onSettings(): void;
  /** Re-open the first-run setup flow. The only way back to it for someone who
   * skipped it, or who arrived by upgrade and never saw it. */
  onRunSetup(): void;
  onCheckUpdates(): void;
  onOpenDataDir(): void;
  /** Go to a screen by its renderer id ("radar", "ledger", …). */
  onGo(screen: string): void;
  /** The Guardrails switch — the same one Settings and the tray carry. */
  onToggleGuard(on: boolean): void;
}

/** The state the menu shows: it is rebuilt (installAppMenu again) whenever
 * one of these flips, which is rare — a menu is cheap to build and the
 * checkbox has to be right when it opens. */
export interface MenuView {
  guardOn: boolean;
  /** The checkbox's label — tray.ts protectionLabel(state), so the count in
   * the menu bar's menu and the application menu is one string. */
  label?: string;
}

/** The screens, in the sidebar's order, with ⌘1…⌘6. Settings keeps ⌘, (the
 * Mac convention) and lives in the app menu. */
export const GO_SCREENS: ReadonlyArray<{ id: string; label: string }> = [
  { id: "radar", label: "Security Radar" },
  { id: "analytics", label: "Analytics" },
  { id: "rules", label: "Guardrails" },
  { id: "spend", label: "Usage" },
  { id: "ledger", label: "Event Ledger" },
  { id: "integrations", label: "Integrations" },
];

/** The File menu's reveal item, named for the platform's file browser. */
export function revealDataFolderLabel(platform: NodeJS.Platform = process.platform): string {
  if (platform === "darwin") return "Reveal Data Folder in Finder";
  if (platform === "win32") return "Show Data Folder in Explorer";
  return "Open Data Folder";
}

export function installAppMenu(callbacks: MenuCallbacks, view: MenuView = { guardOn: false }): void {
  // hide/hideOthers/unhide/zoom/front are macOS roles: on Windows and Linux
  // (the Alt menu bar) they were rows that did nothing when clicked.
  const mac = process.platform === "darwin";
  const template: Electron.MenuItemConstructorOptions[] = [
    {
      label: app.getName(),
      submenu: [
        { role: "about", label: "About Doorman" },
        { label: "Check for Updates…", click: () => callbacks.onCheckUpdates() },
        { type: "separator" },
        // The guard's switch, reachable without the window: what the tray
        // menu offers, the app menu offers too.
        {
          label: view.label ?? "Real time protection",
          type: "checkbox",
          checked: view.guardOn,
          click: () => callbacks.onToggleGuard(!view.guardOn),
        },
        {
          label: "Trace a Secret…",
          accelerator: "CmdOrCtrl+Shift+T",
          click: () => callbacks.onGo("trace"),
        },
        { type: "separator" },
        {
          label: "Set Up Doorman…",
          click: () => callbacks.onRunSetup(),
        },
        {
          label: "Settings…",
          accelerator: "CmdOrCtrl+,",
          click: () => callbacks.onSettings(),
        },
        { type: "separator" },
        ...(mac
          ? ([
              { role: "hide", label: "Hide Doorman" },
              { role: "hideOthers" },
              { role: "unhide" },
              { type: "separator" },
            ] as Electron.MenuItemConstructorOptions[])
          : []),
        { role: "quit", label: "Quit Doorman" },
      ],
    },
    {
      label: "File",
      submenu: [
        { label: revealDataFolderLabel(), click: () => callbacks.onOpenDataDir() },
        { type: "separator" },
        { role: "close" },
      ],
    },
    {
      label: "Edit",
      submenu: [
        { role: "undo" },
        { role: "redo" },
        { type: "separator" },
        { role: "cut" },
        { role: "copy" },
        { role: "paste" },
        { role: "selectAll" },
      ],
    },
    {
      label: "View",
      submenu: [
        { role: "reload" },
        ...(app.isPackaged
          ? []
          : ([{ role: "toggleDevTools" }] as Electron.MenuItemConstructorOptions[])),
        { type: "separator" },
        { role: "resetZoom" },
        { role: "zoomIn" },
        { role: "zoomOut" },
        { type: "separator" },
        { role: "togglefullscreen" },
      ],
    },
    {
      label: "Go",
      submenu: [
        ...GO_SCREENS.map((s, i) => ({
          label: s.label,
          accelerator: `CmdOrCtrl+${i + 1}`,
          click: () => callbacks.onGo(s.id),
        })),
        { type: "separator" },
        { label: "Settings", accelerator: "CmdOrCtrl+7", click: () => callbacks.onSettings() },
      ],
    },
    {
      label: "Window",
      submenu: mac ? [{ role: "minimize" }, { role: "zoom" }, { type: "separator" }, { role: "front" }] : [{ role: "minimize" }],
    },
  ];
  Menu.setApplicationMenu(Menu.buildFromTemplate(template));
}
