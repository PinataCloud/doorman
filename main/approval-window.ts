/**
 * The floating approval panel — a small always-on-top window that appears in the
 * corner while a tool call is held, carrying the Deny / Allow buttons.
 *
 * WHY THIS EXISTS, given we already post a notification: on macOS the action
 * buttons on a notification are only visible INLINE when the person has set this
 * app's notification style to "Alerts". Under the default "Banners" style macOS
 * hides them behind an `Options ⌄` chevron that appears on hover, and the banner
 * slides away after a few seconds — so the buttons read as missing. An app cannot
 * set that style; only System Settings can. And a build with no notification
 * authorization at all gets nothing.
 *
 * A window we own has none of those dependencies: it is always visible, the
 * buttons are always buttons, and it works with notifications off entirely. The
 * notification stays as the background-friendly path (it can be answered from
 * Notification Center without raising anything), and this is the one you can't
 * miss.
 *
 * Deliberately NOT focus-stealing: `showInactive` means your keystrokes keep
 * going to the terminal you were typing in. It floats above full-screen spaces
 * (that is where the agent is running) and it is never given a taskbar/dock
 * entry of its own.
 */

import { BrowserWindow, screen } from "electron";
import { join } from "node:path";
import { fitPanelBounds } from "./lib/panel-fit.js";

const PANEL_WIDTH = 460;
/** The first paint's height, until the card reports its own (fitApprovalPanel). */
const PANEL_HEIGHT = 336;
const PANEL_MIN_HEIGHT = 160;
const MARGIN = 16;

/** The height the card last asked for, so a re-shown panel opens at it. */
let contentHeight = PANEL_HEIGHT;

let panel: BrowserWindow | null = null;

export interface PanelDeps {
  preload: string;
  /** doorman:// URL of the renderer, minus the query. */
  url: string;
}

function place(win: BrowserWindow): void {
  // Top-right of the display the pointer is on, inside the work area so it
  // never lands under the menu bar or a notch.
  const cursor = screen.getCursorScreenPoint();
  const display = screen.getDisplayNearestPoint(cursor);
  const { x, y, width } = display.workArea;
  win.setBounds(
    fitPanelBounds(
      { x: Math.round(x + width - PANEL_WIDTH - MARGIN), y: Math.round(y + MARGIN), width: PANEL_WIDTH, height: PANEL_HEIGHT },
      contentHeight,
      display.workArea,
      MARGIN,
      PANEL_MIN_HEIGHT,
    ),
  );
}

export function showApprovalPanel(deps: PanelDeps): void {
  if (panel && !panel.isDestroyed()) {
    place(panel);
    if (!panel.isVisible()) panel.showInactive();
    return;
  }
  panel = new BrowserWindow({
    width: PANEL_WIDTH,
    height: PANEL_HEIGHT,
    show: false,
    frame: false,
    transparent: true,
    backgroundColor: "#00000000",
    resizable: false,
    minimizable: false,
    maximizable: false,
    fullscreenable: false,
    skipTaskbar: true,
    // A security prompt that hides behind the editor is a security prompt nobody
    // answers, so it sits at the screen-saver level and follows you across
    // spaces — including over a full-screen terminal, which is exactly where the
    // agent that triggered it is running.
    alwaysOnTop: true,
    webPreferences: {
      preload: deps.preload,
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: false,
    },
  });
  panel.setAlwaysOnTop(true, "screen-saver");
  panel.setVisibleOnAllWorkspaces(true, { visibleOnFullScreen: true });
  panel.on("closed", () => {
    panel = null;
  });
  panel.once("ready-to-show", () => {
    if (!panel || panel.isDestroyed()) return;
    place(panel);
    panel.showInactive();
  });
  void panel.loadURL(`${deps.url}?panel=1`);
}

export function hideApprovalPanel(): void {
  if (panel && !panel.isDestroyed() && panel.isVisible()) panel.hide();
}

/**
 * The card's natural height, reported by the panel's renderer whenever it
 * changes: the window follows it (lib/panel-fit.ts), in place. Only the panel's
 * own page may resize it.
 */
export function fitApprovalPanel(senderId: number, height: unknown): void {
  if (!panel || panel.isDestroyed() || panel.webContents.id !== senderId) return;
  if (typeof height !== "number" || !Number.isFinite(height) || height <= 0) return;
  contentHeight = height;
  const bounds = panel.getBounds();
  const next = fitPanelBounds(bounds, height, screen.getDisplayMatching(bounds).workArea, MARGIN, PANEL_MIN_HEIGHT);
  if (next.height !== bounds.height || next.y !== bounds.y) panel.setBounds(next);
}

export function destroyApprovalPanel(): void {
  if (panel && !panel.isDestroyed()) panel.destroy();
  panel = null;
}

/** Push a state snapshot at the panel, same channel the main window listens on. */
export function updateApprovalPanel(state: unknown): void {
  if (panel && !panel.isDestroyed()) panel.webContents.send("state:changed", state);
}

export function approvalPanelPreload(dirname: string): string {
  return join(dirname, "preload.js");
}
