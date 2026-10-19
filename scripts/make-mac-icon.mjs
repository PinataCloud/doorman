#!/usr/bin/env node
// Compiles the macOS 26+ app icon, assets/mac/Doorman.icon (an Icon Composer
// document written by scripts/make-brand.py), into assets/mac/Assets.car.
//
// COMMITTED, not built per release, for the same reason make-brand.py's
// outputs are: the compiler is Xcode 26+'s `actool`, and the release runner
// (macos-14) doesn't have it. electron-builder ships the .car beside the legacy
// icon.icns and points CFBundleIconName at it (electron-builder.yml): macOS 26+
// draws the catalog's icon, with its Dark variant; older macOS reads the .icns.
// scripts/brand-dev-shell.mjs puts the same pair into the dev shell.
//
// Re-run after `make-brand.py` changes the mark:
//
//     npm run icons:mac

import { execFileSync } from "node:child_process";
import { copyFileSync, existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const source = join(root, "assets", "mac", "Doorman.icon");
const target = join(root, "assets", "mac", "Assets.car");
/** The catalog's app-icon name; CFBundleIconName must say the same. */
const ICON_NAME = "Doorman";

if (process.platform !== "darwin") {
  console.error("! make-mac-icon needs macOS (Xcode's actool).");
  process.exit(1);
}
if (!existsSync(source)) {
  console.error(`! ${source} is missing — run scripts/make-brand.py first.`);
  process.exit(1);
}

/** The selected developer dir's actool, else Xcode.app's: the Command Line
 * Tools alone don't carry it. */
function actoolEnv() {
  for (const dir of [process.env.DEVELOPER_DIR, undefined, "/Applications/Xcode.app/Contents/Developer"]) {
    const env = { ...process.env, ...(dir ? { DEVELOPER_DIR: dir } : {}) };
    try {
      const out = execFileSync("xcrun", ["actool", "--version"], { env, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] });
      const version = /<key>short-bundle-version<\/key>\s*<string>([\d.]+)<\/string>/.exec(out)?.[1];
      if (version && Number(version.split(".")[0]) >= 26) return env;
    } catch {
      // not here — try the next
    }
  }
  return null;
}

const env = actoolEnv();
if (!env) {
  console.error("! make-mac-icon needs Xcode 26 or later (its actool compiles Icon Composer documents).");
  process.exit(1);
}

const out = mkdtempSync(join(tmpdir(), "doorman-mac-icon-"));
try {
  execFileSync(
    "xcrun",
    [
      "actool",
      source,
      "--compile",
      out,
      "--output-format",
      "human-readable-text",
      "--warnings",
      "--errors",
      "--output-partial-info-plist",
      join(out, "partial.plist"),
      "--app-icon",
      ICON_NAME,
      "--include-all-app-icons",
      "--target-device",
      "mac",
      "--minimum-deployment-target",
      "11.0",
      "--platform",
      "macosx",
    ],
    { env, stdio: ["ignore", "ignore", "inherit"] },
  );
  copyFileSync(join(out, "Assets.car"), target);
  console.log(`✓ wrote ${target}`);
} finally {
  rmSync(out, { recursive: true, force: true });
}
