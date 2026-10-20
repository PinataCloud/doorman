import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  DESKTOP_ID,
  ICON_SIZES,
  dataHome,
  desktopEntry,
  desktopPaths,
  integrateAppImage,
  quoteExecArg,
  type DesktopPaths,
} from "../main/lib/linux-desktop-entry.js";

let root: string;
let paths: DesktopPaths;
let rendered: number[];
const APPIMAGE = "/home/wubu/Applications/Doorman-0.5.3-arm64.AppImage";

// A stand-in PNG per size, so the test can tell which render landed where.
const renderIcon = (size: number): Buffer => {
  rendered.push(size);
  return Buffer.from(`png-${size}`);
};

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), "doorman-desktop-"));
  paths = desktopPaths({ XDG_DATA_HOME: join(root, "data") }, join(root, "home"));
  rendered = [];
});

afterEach(() => rmSync(root, { recursive: true, force: true }));

describe("desktop paths", () => {
  it("is named after package.json desktopName, which is Electron's app_id", () => {
    const pkg = JSON.parse(readFileSync(join(__dirname, "..", "package.json"), "utf8")) as { desktopName: string };
    expect(`${DESKTOP_ID}.desktop`).toBe(pkg.desktopName);
  });

  it("uses an absolute XDG_DATA_HOME, else ~/.local/share", () => {
    expect(dataHome({ XDG_DATA_HOME: "/x/share" }, "/home/u")).toBe("/x/share");
    expect(dataHome({}, "/home/u")).toBe("/home/u/.local/share");
    // The spec: a relative value is invalid and is ignored.
    expect(dataHome({ XDG_DATA_HOME: "rel/share" }, "/home/u")).toBe("/home/u/.local/share");
    expect(dataHome({ XDG_DATA_HOME: "" }, "/home/u")).toBe("/home/u/.local/share");
  });

  it("puts the entry in applications/ and the icons in hicolor/<n>x<n>/apps", () => {
    const p = desktopPaths({}, "/home/u");
    expect(p.desktopFile).toBe("/home/u/.local/share/applications/cloud.pinata.doorman.desktop");
    expect(p.iconFile(512)).toBe("/home/u/.local/share/icons/hicolor/512x512/apps/cloud.pinata.doorman.png");
    expect(p.hicolorDir).toBe("/home/u/.local/share/icons/hicolor");
  });
});

describe("desktopEntry", () => {
  it("links the window by app_id and launches the AppImage", () => {
    expect(desktopEntry(APPIMAGE, "0.5.3")).toBe(
      [
        "[Desktop Entry]",
        "Type=Application",
        "Name=Doorman",
        "Comment=Local-first AI spend graphs, Security Guard and event ledger",
        `Exec="${APPIMAGE}" %U`,
        `TryExec=${APPIMAGE}`,
        "Icon=cloud.pinata.doorman",
        "Terminal=false",
        "Categories=Development;Utility;",
        "StartupWMClass=cloud.pinata.doorman",
        "X-AppImage-Version=0.5.3",
        "X-Doorman-AppImage=true",
        "",
      ].join("\n"),
    );
  });

  it("escapes the characters the Exec quoting and the string level reserve", () => {
    expect(quoteExecArg('/a b/$x"`y%z\\w')).toBe('"/a b/\\$x\\"\\`y%%z\\\\w"');
    const entry = desktopEntry("/opt/My Apps/a\\b.AppImage", "1.0.0");
    // Exec: the quote-level `\\` doubled again by the string level.
    expect(entry).toContain('Exec="/opt/My Apps/a\\\\\\\\b.AppImage" %U\n');
    expect(entry).toContain("TryExec=/opt/My Apps/a\\\\b.AppImage\n");
  });
});

describe("integrateAppImage", () => {
  const run = (appImage = APPIMAGE, version = "0.5.3") => integrateAppImage({ appImage, version, paths, renderIcon });

  it("installs the entry and every icon size on the first run", () => {
    const out = run();
    expect(out.status).toBe("installed");
    expect(readFileSync(paths.desktopFile, "utf8")).toBe(desktopEntry(APPIMAGE, "0.5.3"));
    for (const size of ICON_SIZES) expect(readFileSync(paths.iconFile(size), "utf8")).toBe(`png-${size}`);
    expect(out.written).toEqual([...ICON_SIZES.map((s) => paths.iconFile(s)), paths.desktopFile]);
    // Written under XDG_DATA_HOME, never the home it was given.
    expect(existsSync(join(root, "home"))).toBe(false);
  });

  it("writes nothing and renders nothing once current", () => {
    run();
    const before = statSync(paths.desktopFile).mtimeMs;
    rendered = [];
    expect(run()).toEqual({ status: "current", written: [] });
    expect(rendered).toEqual([]);
    expect(statSync(paths.desktopFile).mtimeMs).toBe(before);
  });

  it("follows the AppImage when it moves, and a new version", () => {
    run();
    const moved = "/home/wubu/Downloads/Doorman-0.5.3-arm64.AppImage";
    expect(run(moved).status).toBe("updated");
    const entry = readFileSync(paths.desktopFile, "utf8");
    expect(entry).toContain(`Exec="${moved}" %U`);
    expect(entry).toContain(`TryExec=${moved}`);
    expect(run(moved, "0.6.0").status).toBe("updated");
    expect(readFileSync(paths.desktopFile, "utf8")).toContain("X-AppImage-Version=0.6.0");
    // An update re-renders the icons too, so a rebranded build replaces them.
    expect(rendered.length).toBe(ICON_SIZES.length * 3);
  });

  it("puts back a deleted icon without touching the entry", () => {
    run();
    rmSync(paths.iconFile(48));
    rendered = [];
    const out = run();
    expect(out).toEqual({ status: "updated", written: [paths.iconFile(48)] });
    expect(rendered).toEqual([48]);
  });

  it("leaves an entry of the same name that it didn't write alone", () => {
    mkdirSync(paths.applicationsDir, { recursive: true });
    const mine = "[Desktop Entry]\nType=Application\nName=My Doorman\nExec=/opt/doorman/doorman\n";
    writeFileSync(paths.desktopFile, mine);
    expect(run()).toEqual({ status: "foreign", written: [] });
    expect(readFileSync(paths.desktopFile, "utf8")).toBe(mine);
    expect(existsSync(paths.iconFile(512))).toBe(false);
  });

  it("writes nothing when another launcher entry already runs this AppImage", () => {
    mkdirSync(paths.applicationsDir, { recursive: true });
    writeFileSync(
      join(paths.applicationsDir, "appimagekit_0123abcd-Doorman.desktop"),
      `[Desktop Entry]\nName=Doorman\nExec=${APPIMAGE} %U\nStartupWMClass=cloud.pinata.doorman\n`,
    );
    expect(run()).toEqual({ status: "integrated-elsewhere", written: [] });
    expect(existsSync(paths.desktopFile)).toBe(false);
    // An entry for some OTHER AppImage is no reason to hold back.
    expect(run("/elsewhere/Doorman.AppImage").status).toBe("installed");
  });

  it("refuses a path an entry can't carry", () => {
    expect(run("Doorman.AppImage").status).toBe("invalid-path");
    expect(run("/tmp/a\nExec=evil").status).toBe("invalid-path");
    expect(existsSync(paths.desktopFile)).toBe(false);
  });

  it("still writes the entry when the icon can't be rendered", () => {
    const out = integrateAppImage({ appImage: APPIMAGE, version: "0.5.3", paths, renderIcon: () => null });
    expect(out).toEqual({ status: "installed", written: [paths.desktopFile] });
    expect(existsSync(paths.iconFile(512))).toBe(false);
  });
});
