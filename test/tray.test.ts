/**
 * The menu-bar companion: which click opens the menu, and what the menu says.
 *
 * Both buttons open it. Left-click used to open the WINDOW, which left the
 * glanceable numbers and Rescan behind a right-click most people never tried —
 * so the menu, and everything only it can say, was effectively hidden.
 */

import { beforeEach, describe, expect, it, vi } from "vitest";

type Item = {
  label?: string;
  enabled?: boolean;
  type?: string;
  role?: string;
  click?: () => void;
};

const mocked = vi.hoisted(() => {
  const built: Item[][] = [];
  const popped: unknown[] = [];
  class FakeTray {
    static instances: FakeTray[] = [];
    handlers = new Map<string, () => void>();
    title = "";
    tooltip = "";
    ignoreDoubleClick = false;
    constructor() {
      FakeTray.instances.push(this);
    }
    setIgnoreDoubleClickEvents(v: boolean): void {
      this.ignoreDoubleClick = v;
    }
    on(event: string, cb: () => void): this {
      this.handlers.set(event, cb);
      return this;
    }
    setTitle(t: string): void {
      this.title = t;
    }
    image: unknown = null;
    setImage(i: unknown): void {
      this.image = i;
    }
    setToolTip(t: string): void {
      this.tooltip = t;
    }
    popUpContextMenu(menu: unknown): void {
      popped.push(menu);
    }
    click(event: string): void {
      this.handlers.get(event)?.();
    }
  }
  const Menu = {
    buildFromTemplate(items: Item[]): { items: Item[] } {
      built.push(items);
      return { items };
    },
  };
  const images: Array<{ template: boolean | undefined }> = [];
  const nativeImage = {
    createEmpty: () => {
      const img = { template: undefined as boolean | undefined, addRepresentation: () => {}, setTemplateImage(v: boolean) { img.template = v; } };
      images.push(img);
      return img;
    },
  };
  const nativeTheme = { shouldUseDarkColors: false, on: () => {} };
  return { FakeTray, Menu, nativeImage, nativeTheme, built, popped, images };
});

// The desktop tree carries its own node_modules, so from main/* the
// specifier "electron" resolves THERE (same reason as notices.test.ts).
vi.mock("../node_modules/electron/index.js", () => ({
  Tray: mocked.FakeTray,
  Menu: mocked.Menu,
  nativeImage: mocked.nativeImage,
  nativeTheme: mocked.nativeTheme,
}));

import { TrayController } from "../main/tray.js";
import { Store } from "../main/state.js";

const { FakeTray, built, popped } = mocked;

function snapshot(over: Record<string, unknown> = {}) {
  const store = new Store({
    appVersion: "9.9.9",
    dataDir: "/tmp/nowhere",
    nodePlatform: "darwin",
    readPrefs: () => ({}),
    writePrefs: () => {},
    onChange: () => {},
  });
  store.set(over as never);
  return store.snapshot();
}

function controller() {
  const calls: string[] = [];
  const c = new TrayController({
    onOpen: () => calls.push("open"),
    onRescan: () => calls.push("rescan"),
    onQuit: () => calls.push("quit"),
    onToggleGuard: (on) => calls.push(on ? "guard:on" : "guard:off"),
    onAsk: () => calls.push("ask"),
    onTrace: () => calls.push("trace"),
  });
  return { c, calls };
}

beforeEach(() => {
  FakeTray.instances.length = 0;
  built.length = 0;
  popped.length = 0;
});

describe("TrayController clicks", () => {
  it("opens the menu on BOTH buttons, and never on a double click", () => {
    const { c, calls } = controller();
    c.create(snapshot());
    const tray = FakeTray.instances[0]!;
    expect(tray.ignoreDoubleClick).toBe(true);
    tray.click("click");
    expect(popped).toHaveLength(1);
    tray.click("right-click");
    expect(popped).toHaveLength(2);
    // A plain click no longer jumps to the window behind the menu's back.
    expect(calls).toEqual([]);
  });

  it("builds the menu from the NEWEST snapshot, not the one it was created with", () => {
    // The handler used to close over create()'s argument, so the menu served
    // the boot snapshot — "Today 0 · 7d 0 tokens" — forever.
    const { c } = controller();
    c.create(snapshot({ graphs: { ...snapshot().graphs, today_tokens: 0 } }));
    c.render(snapshot({ graphs: { ...snapshot().graphs, today_tokens: 12_400, window_tokens: 30_000 } }));
    FakeTray.instances[0]!.click("click");
    const labels = built[built.length - 1]!.map((i) => i.label ?? i.type ?? "");
    expect(labels.some((l) => l.includes("Today 12.4k · 7d 30.0k tokens"))).toBe(true);
    // Tokens, never dollars.
    expect(labels.some((l) => l.includes("$"))).toBe(false);
  });

  it("shows an update in flight under the version line, in the Settings row's words", () => {
    const { c } = controller();
    c.create(snapshot());
    c.render(snapshot({ updater: { status: "downloading", version: "1.2.3", message: "Downloading update 1.2.3… 42%", progress: { percent: 42, transferred: 1, total: 2, bytes_per_second: 1 } } }));
    FakeTray.instances[0]!.click("click");
    const labels = built[built.length - 1]!.map((i) => i.label ?? "");
    const version = labels.findIndex((l) => l.startsWith("Version "));
    expect(labels[version + 1]).toBe("Downloading update 1.2.3… 42%");
    expect(labels[labels.length - 1]).toBe("Quit Doorman");
    // Idle: no such row.
    c.render(snapshot({ updater: { status: "idle" } }));
    FakeTray.instances[0]!.click("click");
    expect(built[built.length - 1]!.map((i) => i.label ?? "").some((l) => l.startsWith("Downloading"))).toBe(false);
  });

  it("leads with Open Doorman and keeps the promise beside the version", () => {
    // The first row is where the pointer already is when a click opens the
    // menu, so the action goes there and the branding line moves to the foot.
    const { c, calls } = controller();
    c.create(snapshot());
    FakeTray.instances[0]!.click("click");
    const items = built[built.length - 1]!;
    expect(items[0]!.label).toBe("Open Doorman");
    items[0]!.click?.();
    expect(calls).toEqual(["open"]);
    const labels = items.map((i) => i.label ?? "");
    const promise = labels.findIndex((l) => l.startsWith("Local-only"));
    const version = labels.findIndex((l) => l.startsWith("Version "));
    expect(promise).toBeGreaterThan(0);
    expect(version).toBe(promise + 1);
    expect(items[promise]!.enabled).toBe(false);
    expect(labels[labels.length - 1]).toBe("Quit Doorman");
  });

  it("counts exposures, matching the sidebar badge, and says all clear at zero", () => {
    const { c } = controller();
    const base = snapshot();
    c.create(base);
    c.render(snapshot({ radar: { ...base.radar, summary: { ...base.radar.summary, open_exposures: 3, open: 41 } } }));
    FakeTray.instances[0]!.click("click");
    let labels = built[built.length - 1]!.map((i) => i.label ?? "");
    expect(labels).toContain("Radar: 3 exposures to review");
    c.render(snapshot({ radar: { ...base.radar, summary: { ...base.radar.summary, open_exposures: 0 } } }));
    FakeTray.instances[0]!.click("click");
    labels = built[built.length - 1]!.map((i) => i.label ?? "");
    expect(labels).toContain("Radar: all clear");
  });

  it("offers no manual rescan — the engine watches and rescans on its own", () => {
    // fs.watch on both transcript roots plus a 60s backstop interval means a
    // manual scan changes nothing observable; as the menu's second row it was
    // a chore sitting where a mis-aimed "Open Doorman" click lands. The
    // Integrations card keeps the button, where it reads as a diagnostic.
    const { c } = controller();
    const base = snapshot();
    c.create(base);
    c.render(snapshot({ capture: { ...base.capture, status: "scanning" } }));
    FakeTray.instances[0]!.click("click");
    const labels = built[built.length - 1]!.map((i) => i.label ?? "");
    expect(labels.some((l) => l.startsWith("Rescan") || l.startsWith("Scanning"))).toBe(false);
    expect(labels[0]).toBe("Open Doorman");
  });
});


describe("the guard on the menu-bar mark", () => {
  const guardState = (over: Record<string, unknown>) =>
    snapshot({
      prefs: { guard_wanted: true },
      radar: { ...snapshot().radar, guard_installed: true, ...over },
    } as never);

  it("always wears a status dot — amber off, green on — so the image is never a template", () => {
    const { c } = controller();
    c.create(snapshot());
    expect(mocked.images.at(-1)?.template).toBe(false);
    expect(FakeTray.instances[0]!.tooltip).toContain("Real time protection off");
    const before = mocked.images.length;
    c.render(guardState({}));
    // A different state is a different image.
    expect(mocked.images.length).toBe(before + 1);
    expect(FakeTray.instances[0]!.image).toBe(mocked.images.at(-1));
    expect(FakeTray.instances[0]!.tooltip).toContain("Real time protection on");
  });

  it("does not rebuild an identical image on every snapshot", () => {
    const { c } = controller();
    c.create(guardState({}));
    const drawn = mocked.images.length;
    c.render(guardState({}));
    c.render(guardState({}));
    expect(mocked.images.length).toBe(drawn);
  });

  it("carries Real time protection as a checkbox with the guardrails count, flipping the state", () => {
    const { c, calls } = controller();
    c.create(snapshot());
    FakeTray.instances[0]!.click("click");
    const find = () => built.at(-1)!.find((i) => (i.label ?? "").startsWith("Real time protection")) as Item & { checked?: boolean };
    const off = find();
    expect(off.type).toBe("checkbox");
    expect(off.checked).toBe(false);
    // Off: nothing acts, whatever the policy says.
    expect(off.label).toMatch(/^Real time protection · 0\/\d+ guardrails enforcing$/);
    off.click?.();
    expect(calls).toContain("guard:on");
    c.render(guardState({}));
    FakeTray.instances[0]!.click("click");
    const on = find();
    expect(on.checked).toBe(true);
    expect(on.label).toMatch(/^Real time protection · \d+\/\d+ guardrails enforcing$/);
    on.click?.();
    expect(calls).toContain("guard:off");
  });

  it("offers Ask Doorman AI beside Open", () => {
    const { c, calls } = controller();
    c.create(snapshot());
    FakeTray.instances[0]!.click("click");
    const items = built.at(-1)!;
    expect(items[0]!.label).toBe("Open Doorman");
    expect(items[1]!.label).toBe("Ask Doorman AI…");
    items[1]!.click?.();
    expect(calls).toContain("ask");
  });
});
