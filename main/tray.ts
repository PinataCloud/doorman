/**
 * The tray companion. The window is primary; the tray is the glanceable
 * "today: 12.4k tok" — kept because it costs nothing. The glyph is drawn as
 * pixels (lib/tray-glyph.ts) because nativeImage cannot decode SVG; it fails
 * by returning an EMPTY image.
 */

import { Menu, Tray, nativeImage, nativeTheme, systemPreferences, type MenuItemConstructorOptions, type NativeImage } from "electron";
import { liveSummaryLine } from "./lib/live-sessions.js";
import { ALL_DETECTORS } from "./guard/policy.js";
import { formatTokens } from "./lib/format.js";
import { TRAY_GLYPH_SIZE, renderTrayGlyph, type Rgb } from "./lib/tray-glyph.js";
import type { AppState } from "./state.js";

export interface TrayCallbacks {
  onOpen(): void;
  onRescan(): void;
  onQuit(): void;
  /** The Guardrails switch, the same one Settings carries. */
  onToggleGuard(on: boolean): void;
  /** Open the window on Doorman AI with this Mac as the subject. */
  onAsk(): void;
  /** Open the window on Security Radar's Trace a secret section. */
  onTrace(): void;
}

/** What the menu-bar mark says about the guard, derived in ONE place so the
 * icon, the tray menu's checkbox and the application menu never disagree. */
export type GuardGlance = "off" | "on" | "tampered";
export function guardGlance(state: AppState): GuardGlance {
  const wanted = state.prefs.guard_wanted !== false;
  if (!wanted || !state.radar.guard_installed) return "off";
  return state.radar.integrity?.status === "tampered" ? "tampered" : "on";
}

const DOT_ON: Rgb = [52, 168, 83];
const DOT_OFF: Rgb = [222, 160, 44];
const DOT_TAMPERED: Rgb = [214, 69, 65];

/** How many guardrails can act right now, of how many there are — the same
 * arithmetic as the renderer's enforcingCount (app.jsx), so the menu's number
 * is the header's number. ACTING is zero while the guard is not installed or
 * was tampered with: the policy may say eleven, but nothing runs. */
export function enforcingGlance(state: AppState): { acting: number; total: number } {
  // A snapshot from before prefs were read (tests, the first boot tick) has no
  // policy yet; the count is then "0 of the shipped detectors".
  const policy: Partial<NonNullable<AppState["prefs"]["policy"]>> = state.prefs.policy ?? {};
  const modes = (policy.modes ?? {}) as Record<string, string | undefined>;
  const enforceable = ALL_DETECTORS as readonly string[];
  const custom = (policy.custom_rules ?? []).filter((r) => r.enabled !== false && !r.after);
  const wanted =
    enforceable.filter((id) => modes[id] === "ask" || modes[id] === "block").length +
    custom.filter((r) => r.mode === "ask" || r.mode === "block").length;
  const glance = guardGlance(state);
  return { acting: glance === "on" ? wanted : 0, total: enforceable.length + custom.length };
}

/** The one label the tray checkbox and the application menu's share:
 * "Real time protection · 11/18 guardrails enforcing". */
export function protectionLabel(state: AppState): string {
  const { acting, total } = enforcingGlance(state);
  return `Real time protection · ${acting}/${total} guardrails enforcing`;
}

/**
 * The menu-bar image: the mark with a status dot in its corner — green while
 * real time protection is on, amber while it is off, red when the guard was
 * tampered with — so the bar answers "is it on?" without a click. Colour
 * means the image cannot be a template (macOS would flatten it to one tint),
 * so the mark itself is drawn black or white to match the bar's appearance
 * and re-drawn when that flips.
 */
function trayIcon(glance: GuardGlance, dark: boolean): NativeImage {
  const image = nativeImage.createEmpty();
  const dot = glance === "tampered" ? DOT_TAMPERED : glance === "on" ? DOT_ON : DOT_OFF;
  const options = { ink: (dark ? [255, 255, 255] : [0, 0, 0]) as Rgb, dot };
  for (const scaleFactor of [1, 2]) {
    const glyph = renderTrayGlyph(TRAY_GLYPH_SIZE * scaleFactor, options);
    image.addRepresentation({
      scaleFactor,
      width: glyph.width,
      height: glyph.height,
      buffer: glyph.bitmap,
    });
  }
  image.setTemplateImage(false);
  return image;
}

/**
 * Whether the bar the icon sits in is dark. That is the SYSTEM's appearance,
 * not this app's: Settings → Appearance recolours the window (through
 * nativeTheme.themeSource, which is all `shouldUseDarkColors` then reports),
 * while the macOS menu bar keeps following the system — so a person who picks
 * Light on a dark Mac got a black mark on a black bar. macOS keeps the system
 * choice in the AppleInterfaceStyle default ("Dark", or unset for light, and
 * Auto flips it); Windows has its own taskbar setting.
 */
export function menuBarIsDark(platform: NodeJS.Platform = process.platform): boolean {
  if (platform === "darwin" && typeof systemPreferences?.getUserDefault === "function") {
    try {
      return systemPreferences.getUserDefault("AppleInterfaceStyle", "string") === "Dark";
    } catch {
      // fall through to the app's theme
    }
  }
  if (platform === "win32" && nativeTheme) return !!nativeTheme.shouldUseDarkColorsForSystemIntegratedUI;
  return !!(nativeTheme && nativeTheme.shouldUseDarkColors);
}

export class TrayController {
  private tray: Tray | undefined;
  /** The newest snapshot, for the right-click menu. The handler used to close
   * over `create(state)`'s argument, so the menu served the BOOT snapshot —
   * "Today 0 · 7d 0 tokens" — forever, while the re-rendered title beside it
   * showed the real number. */
  private latest: AppState | undefined;
  /** The icon variant currently shown, so a snapshot every few seconds does
   * not rebuild an identical image. */
  private iconKey = "";
  /** Linux: the content of the menu last handed to setContextMenu, so a
   * snapshot every few seconds does not re-export an identical dbusmenu (which
   * would close it under the pointer). */
  private menuKey = "";

  constructor(
    private readonly callbacks: TrayCallbacks,
    private readonly platform: NodeJS.Platform = process.platform,
  ) {}

  create(state: AppState): void {
    this.latest = state;
    this.tray = new Tray(this.icon(state));
    this.tray.setIgnoreDoubleClickEvents(true);
    // A coloured (non-template) mark is drawn for one bar appearance; when the
    // system flips light/dark, draw it again for the other.
    nativeTheme?.on?.("updated", () => { if (this.latest) this.render(this.latest); });
    // …and that flip is the SYSTEM's, which with Appearance set to Light or
    // Dark no longer reaches nativeTheme: hear it from macOS directly.
    if (process.platform === "darwin" && typeof systemPreferences?.subscribeNotification === "function") {
      systemPreferences.subscribeNotification("AppleInterfaceThemeChangedNotification", () => {
        if (this.latest) this.render(this.latest);
      });
    }
    // macOS: BOTH buttons open the menu, which is what every other menu-bar
    // app on this Mac does. Left-click used to jump straight to the window, so
    // the glanceable numbers and Rescan were reachable only by right-clicking —
    // a menu most people never discovered was there. "Open Doorman" is the
    // menu's first action, so the window is still one click further.
    //
    // Windows: left-click opens the window, right-click the menu. Electron
    // fires "click" on the button PRESS; for an icon in the taskbar's
    // overflow flyout (where Windows 11 puts every new tray icon) the flyout
    // closes on the RELEASE and takes the just-popped menu with it, so a
    // left-click menu showed nothing there. The window opens either way.
    //
    // Linux has no popUpContextMenu (a silent no-op there) and no right-click
    // event: the StatusNotifierItem host draws the menu itself from the one
    // set with setContextMenu (render keeps it current). Without it the item
    // exported an EMPTY dbusmenu and no click did anything. "click" there is
    // the SNI Activate call — a double click in GNOME's AppIndicator
    // extension, a left click on KDE — so it opens the window.
    if (this.platform === "darwin") {
      this.tray.on("click", () => this.showMenu());
      this.tray.on("right-click", () => this.showMenu());
    } else {
      this.tray.on("click", () => this.callbacks.onOpen());
      if (this.platform === "win32") this.tray.on("right-click", () => this.showMenu());
    }
    this.render(state);
  }

  /** Pop the menu, built from the NEWEST snapshot at click time. */
  private showMenu(): void {
    if (this.tray && this.latest) this.tray.popUpContextMenu(Menu.buildFromTemplate(this.template(this.latest)));
  }

  /** Linux: hand the host a menu built from this snapshot, when it says
   * something different from the last one. The rows' click handlers close
   * over the state they were built from, and that state (the guard switch) is
   * part of what is compared, so a kept menu never acts on a stale reading. */
  private syncContextMenu(state: AppState): void {
    if (!this.tray) return;
    const template = this.template(state);
    // JSON drops the click functions: the key is what the menu shows.
    const key = JSON.stringify(template);
    if (key === this.menuKey) return;
    this.menuKey = key;
    this.tray.setContextMenu(Menu.buildFromTemplate(template));
  }

  private template(state: AppState): MenuItemConstructorOptions[] {
    // Exposures, matching the sidebar badge and the tray title — see
    // lib/exposures.ts: one rule in one place is one thing to decide.
    const open =
      state.radar.summary.open_exposures != null ? state.radar.summary.open_exposures : state.radar.summary.open;
    // The ACTION leads, because the menu is now what a plain click opens and
    // the first row is where the pointer already is. The local-only promise
    // moved down beside the version, where it reads as a standing fact rather
    // than as the thing between you and the window.
    // No "Rescan transcripts" here. The engine watches both transcript roots
    // (fs.watch, debounced) and rescans on a 60s interval as a backstop, so a
    // manual scan changes nothing a person can perceive — it was a chore the
    // app already does, sitting in the second row, which is exactly where a
    // pointer aiming at "Open Doorman" lands on a mis-click. The button
    // survives on Integrations, where it is a DIAGNOSTIC rather than a chore:
    // it sits beside "N turns from M files · last scan 2m ago", so pressing it
    // answers "is this stuck, or is there genuinely nothing new?".
    const glance = guardGlance(state);
    return [
      { label: "Open Doorman", click: () => this.callbacks.onOpen() },
      { label: "Ask Doorman AI…", click: () => this.callbacks.onAsk() },
      { label: "Trace a Secret…", click: () => this.callbacks.onTrace() },
      { type: "separator" },
      // The guard's switch, where the eye already is when the dot on the icon
      // raised the question. Checked = enforcing; the tampered state keeps the
      // check (the person wants it on) and says so under it.
      {
        label: protectionLabel(state),
        type: "checkbox",
        checked: glance !== "off",
        click: () => this.callbacks.onToggleGuard(glance === "off"),
      },
      ...(glance === "tampered"
        ? [{ label: "Changed outside the app — reinstall in Settings", enabled: false }]
        : []),
      { type: "separator" },
      // Token counts, never dollars: input+output tokens measured
      // from the transcripts. The row under them says how the week actually
      // settled — plan, API credits, API key — shown only once something
      // attributed, so a Max-plan user can see the week was inside the plan.
      {
        label: `Today ${formatTokens(state.graphs.today_tokens)} · 7d ${formatTokens(state.graphs.window_tokens)} tokens`,
        enabled: false,
      },
      ...(state.graphs.covered_tokens > 0 || state.graphs.overage_tokens > 0 || state.graphs.billed_tokens > 0
        ? [
            {
              label: `7d: ${formatTokens(state.graphs.covered_tokens)} plan · ${formatTokens(state.graphs.overage_tokens)} API credits${state.graphs.billed_tokens > 0 ? ` · ${formatTokens(state.graphs.billed_tokens)} API key` : ""}${state.graphs.unknown_tokens > 0 ? ` · ${formatTokens(state.graphs.unknown_tokens)} unattributed` : ""}`,
              enabled: false,
            },
          ]
        : []),
      {
        label: open === 0 ? "Radar: all clear" : `Radar: ${open} exposure${open === 1 ? "" : "s"} to review`,
        enabled: false,
      },
      { type: "separator" },
      { label: "Local-only — nothing leaves this machine", enabled: false },
      { label: `Version ${state.appVersion}`, enabled: false },
      // An update in flight is the one moment the version line is about to be
      // wrong — say what is happening under it, in the words the Settings row
      // uses, so the menu never contradicts the window.
      ...(state.updater.status === "downloading" || state.updater.status === "downloaded" || state.updater.status === "installing"
        ? [{ label: state.updater.message ?? "Updating…", enabled: false }]
        : []),
      { role: "quit", label: "Quit Doorman", click: () => this.callbacks.onQuit() },
    ];
  }

  render(state: AppState): void {
    this.latest = state;
    if (!this.tray) return;
    const glance = guardGlance(state);
    const dark = menuBarIsDark();
    const key = glance + (dark ? ":dark" : ":light");
    if (key !== this.iconKey) {
      this.iconKey = key;
      this.tray.setImage(trayIcon(glance, dark));
    }
    this.tray.setTitle(this.title(state), { fontType: "monospacedDigit" });
    this.tray.setToolTip(this.tooltip(state));
    if (this.platform === "linux") this.syncContextMenu(state);
  }

  private icon(state: AppState): NativeImage {
    const glance = guardGlance(state);
    const dark = menuBarIsDark();
    this.iconKey = glance + (dark ? ":dark" : ":light");
    return trayIcon(glance, dark);
  }

  /** What sits beside the glyph, per the Settings → Menu bar preference:
   * today's tokens (local calendar day, "12.4k tok" — the unit rides along so
   * the number is never mistaken for the alerts count), open exposures to
   * review (silent at zero — a permanent "0" is noise wearing a number), or
   * nothing. */
  private title(state: AppState): string {
    const display = state.prefs.tray_display;
    if (display === "none") return "";
    if (display === "alerts") {
      const open =
        state.radar.summary.open_exposures != null
          ? state.radar.summary.open_exposures
          : state.radar.summary.open;
      return open > 0 ? String(open) : "";
    }
    if (state.capture.status === "starting") return "…";
    return `${formatTokens(state.graphs.today_tokens)} tok`;
  }

  private tooltip(state: AppState): string {
    const lines = [
      `Today ${formatTokens(state.graphs.today_tokens)} tokens`,
      `7 days ${formatTokens(state.graphs.window_tokens)} tokens`,
    ];
    if (state.graphs.overage_tokens > 0) lines.push(`${formatTokens(state.graphs.overage_tokens)} on API credits`);
    if (state.graphs.billed_tokens > 0) lines.push(`${formatTokens(state.graphs.billed_tokens)} billed to an API key`);
    const live = state.live ? liveSummaryLine(state.live.counts) : "";
    if (live) lines.push(`Agents now: ${live}`);
    const open = state.radar.summary.open;
    if (open > 0) lines.push(`${open} open security finding${open === 1 ? "" : "s"}`);
    const glance = guardGlance(state);
    lines.push(glance === "on" ? "Real time protection on" : glance === "tampered" ? "Real time protection changed outside the app" : "Real time protection off");
    return `Doorman — ${lines.join(" · ")}`;
  }

  destroy(): void {
    this.tray?.destroy();
    this.tray = undefined;
  }
}
