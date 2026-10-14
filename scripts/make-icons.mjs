#!/usr/bin/env node
// Builds the app icons from the product's own mark: `icon.png` for Linux AND
// Windows (every platform can write it) and `icon.icns` for macOS (macOS only).
//
// There is no .ico half. electron-builder converts `icon.png` to a multi-size
// .ico itself when it packages the Windows target, so writing one here would be
// a second implementation of a conversion it already does — and one that would
// need an image library this script deliberately doesn't have.
//
// DERIVED, not committed: the source of truth is `assets/doorman-app-icon.png`
// (itself generated from the brand master by scripts/make-brand.py), so the app
// icon cannot drift from the mark the app renders. Regenerated on every
// `npm run build`; both outputs are gitignored.
//
// The .icns half is macOS-only by construction (`sips` + `iconutil`) and
// NO-OPS off macOS rather than dying. It used to be reachable only from
// `npm run build`, which was a Mac-only target; `compile` chains it too, and a
// CI gate may run `npm run compile` on a Linux runner where neither tool
// exists. A hard failure there
// gates every PR on a Mac icon that the Linux job would throw away — so skip,
// and let the packaging targets (each of which runs `icons` again itself) be
// the thing that must succeed. The .png half runs EVERYWHERE, because the
// AppImage build happens on Linux and needs it there.

import { execFileSync } from "node:child_process";
import { copyFileSync, mkdirSync, rmSync, existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { padToIconGrid } from "./pad-png.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const desktopRoot = join(here, "..");
const source = join(desktopRoot, "assets", "doorman-app-icon.png");
const outDir = join(desktopRoot, "build-resources");
const iconset = join(outDir, "icon.iconset");
const icns = join(outDir, "icon.icns");
const png = join(outDir, "icon.png");
const paddedMaster = join(outDir, "icon-master.png");

if (!existsSync(source)) {
  console.error(`! brand mark not found at ${source}`);
  process.exit(1);
}

mkdirSync(outDir, { recursive: true });

// Linux and Windows first, because it is the half that must work on every
// platform. UNPADDED, deliberately: freedesktop icons are drawn full-bleed at
// their nominal size, and a Windows taskbar icon nearly so — the ~80% Apple
// grid the .icns needs would render the mark visibly small next to every other
// icon in a GNOME/KDE launcher or on the taskbar. The 1024 master is above
// electron-builder's 512 minimum for a single-file Linux icon.
copyFileSync(source, png);
console.log(`✓ wrote ${png} (full-bleed, for Linux and Windows)`);

if (process.platform !== "darwin") {
  console.log("• skipping the .icns build — sips/iconutil are macOS-only.");
  process.exit(0);
}

// The mark is FULL-BLEED; a macOS icon draws inside Apple's grid (~80% of the
// canvas, transparent margins). Pad the master once, slice from the result —
// otherwise the dock icon reads oversized and blocky next to native icons.
writeFileSync(paddedMaster, padToIconGrid(readFileSync(source)));

// The slices macOS asks for. iconutil is strict about these names.
const SLICES = [
  ["icon_16x16.png", 16],
  ["icon_16x16@2x.png", 32],
  ["icon_32x32.png", 32],
  ["icon_32x32@2x.png", 64],
  ["icon_128x128.png", 128],
  ["icon_128x128@2x.png", 256],
  ["icon_256x256.png", 256],
  ["icon_256x256@2x.png", 512],
  ["icon_512x512.png", 512],
  ["icon_512x512@2x.png", 1024],
];

rmSync(iconset, { recursive: true, force: true });
mkdirSync(iconset, { recursive: true });
for (const [name, size] of SLICES) {
  execFileSync("sips", ["-s", "format", "png", "-z", String(size), String(size), paddedMaster, "--out", join(iconset, name)], {
    stdio: "ignore",
  });
}
execFileSync("iconutil", ["-c", "icns", iconset, "-o", icns]);
rmSync(iconset, { recursive: true, force: true });
console.log(`✓ wrote ${icns} (padded to the icon grid)`);
