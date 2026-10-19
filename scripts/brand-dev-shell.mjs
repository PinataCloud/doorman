/**
 * Give the DEV run the product's identity: "Doorman" in the macOS menu
 * bar and the brand mark in the Dock, instead of "Electron" and Electron's
 * atom logo.
 *
 * WHY A SCRIPT AND NOT AN API CALL. `app.setName()` (main/index.ts) already
 * fixes everything Electron owns — the About panel, notification titles, the
 * userData path, every "…Doorman" label inside our menus. It cannot fix
 * the two things macOS reads from the BUNDLE before our JavaScript exists:
 *   · the bold app-menu title, which is `CFBundleName`
 *   · the Dock icon at launch, which is `CFBundleIconFile` — and on macOS 26+
 *     `CFBundleIconName`, the asset catalog's icon with its Dark variant
 * Unpackaged, the bundle is `node_modules/electron/dist/Electron.app`, so those
 * two say Electron. A packaged build has always been correct (electron-builder
 * writes productName + icon.icns from electron-builder.yml) — this only closes
 * the gap for `npm run dev`.
 *
 * WHY EDITING THE BUNDLE IS SAFE HERE. Electron's prebuilt .app is signed
 * ad-hoc AND linker-signed — `Sealed Resources=none`, `Info.plist=not bound` —
 * so the signature covers the Mach-O and nothing else. Rewriting Info.plist and
 * dropping in a resource therefore changes nothing macOS checks at launch. The
 * script confirms that line before it writes, and leaves the bundle alone if a
 * future Electron starts sealing the plist.
 *
 * Idempotent, `npm i`-proof (chained into `compile`, and node_modules is not
 * committed), and a no-op off macOS or when Electron isn't installed — so it
 * can sit in the build chain without becoming a platform requirement.
 */

import { execFileSync, spawnSync } from "node:child_process";
import { copyFileSync, existsSync, lstatSync, readFileSync, renameSync, unlinkSync, utimesSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const APP_NAME = "Doorman";
/**
 * The dev shell needs its OWN bundle identifier, and this is the key that
 * actually fixes the Dock.
 *
 * LaunchServices resolves an app's displayed name per bundle IDENTIFIER, not
 * per path, and every prebuilt Electron.app ships `com.github.Electron`. A
 * machine with several of them registered (other checkouts, a global npm
 * package, worktrees) gets the menu bar fixed by renaming CFBundleName here —
 * it reads the running bundle directly — while the Dock tile keeps saying
 * "Electron", because LS answers for the identifier from one of the other
 * copies. No amount of `lsregister -f`/`-u` on this path changes that.
 *
 * Safe to change: Electron derives `userData` from `app.getName()`, not the
 * identifier, so the local store, the single-instance lock and the guard
 * directory all stay where they are. The one real consequence is that macOS
 * treats the dev app as a distinct notification client, so its permission is
 * granted separately from the packaged app's — which is the behaviour you want
 * anyway: a dev run should not inherit the shipped app's authorization.
 */
const APP_ID = "cloud.pinata.doorman.dev";
/** Our icns lands beside Electron's rather than replacing it — a clobbered
    electron.icns would be silently restored by the next `npm i` and the
    mismatch would be invisible. */
const ICON_STEM = "doorman";

const bundle = join(root, "node_modules", "electron", "dist", "Electron.app");
const plist = join(bundle, "Contents", "Info.plist");
const icns = join(root, "build-resources", "icon.icns");
/** The macOS 26+ icon (scripts/make-mac-icon.mjs) — committed, so always here. */
const car = join(root, "assets", "mac", "Assets.car");
const ICON_NAME = "Doorman";

if (process.platform !== "darwin") {
  process.exit(0);
}
if (!existsSync(plist)) {
  // Electron not installed (CI type-check, a fresh clone before `npm i`).
  process.exit(0);
}
if (!existsSync(icns)) {
  console.error("[brand-dev-shell] build-resources/icon.icns missing — run `npm run icons` first.");
  process.exit(0);
}

const sameBytes = (a, b) => existsSync(b) && readFileSync(a).equals(readFileSync(b));

const plutil = (...args) => execFileSync("plutil", args, { encoding: "utf8" });
const read = (key) => {
  try {
    // A key that isn't there yet is an answer (null), not an error to print.
    return execFileSync("plutil", ["-extract", key, "raw", "-o", "-", plist], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim();
  } catch {
    return null;
  }
};
/** `-replace` fails on a key that doesn't exist yet; `-insert` fails on one
    that does. Try replace, fall back to insert. */
const write = (key, value) => {
  try {
    plutil("-replace", key, "-string", value, plist);
  } catch {
    plutil("-insert", key, "-string", value, plist);
  }
};

/**
 * Is it safe to rewrite this bundle's Info.plist?
 *
 * Checked as a PRECONDITION, not by re-verifying afterwards. Electron's
 * prebuilt shell is linker-signed with `Sealed Resources=none`, so
 * `codesign --verify` reports "code has no resources but signature indicates
 * they must be present" whether or not anyone has touched it — a post-hoc
 * verify would fail identically on a pristine bundle and tell us nothing. What
 * actually matters is the one line that says whether the plist is inside the
 * seal.
 */
function plistIsUnsealed() {
  // `codesign -d` writes its whole description to STDERR and still exits 0, so
  // this has to be spawnSync reading .stderr — execFileSync's return value is
  // stdout, which is empty here, and the check silently answered "sealed".
  const res = spawnSync("codesign", ["-dvv", bundle], { encoding: "utf8" });
  const out = (res.stdout || "") + (res.stderr || "");
  return /Info\.plist=not bound/.test(out);
}

if (!plistIsUnsealed()) {
  console.error(
    "[brand-dev-shell] this Electron build seals Info.plist into its signature, so the\n" +
      '  dev shell cannot be re-labelled — the run will show "Electron" in the menu bar.\n' +
      "  A packaged build is unaffected; electron-builder writes the real bundle.",
  );
  process.exit(0);
}

/**
 * Undo the executable rename an earlier cut of this script performed — see the
 * note further down for why it was a mistake. Without this, a checkout that ran
 * the bad version stays broken (every asset 404s) until someone reinstalls
 * node_modules, and the failure gives no hint that the shell is the cause.
 */
(function repairRenamedExecutable() {
  const macos = join(bundle, "Contents", "MacOS");
  const renamed = join(macos, APP_NAME);
  const original = join(macos, "Electron");
  if (!existsSync(renamed)) return;
  if (existsSync(original) && lstatSync(original).isSymbolicLink()) unlinkSync(original);
  if (!existsSync(original)) renameSync(renamed, original);
  write("CFBundleExecutable", "Electron");
  console.log("[brand-dev-shell] restored Contents/MacOS/Electron (a rename there breaks isPackaged).");
})();

const already =
  read("CFBundleName") === APP_NAME &&
  read("CFBundleDisplayName") === APP_NAME &&
  read("CFBundleIdentifier") === APP_ID &&
  read("CFBundleIconFile") === ICON_STEM &&
  existsSync(join(bundle, "Contents", "Resources", `${ICON_STEM}.icns`)) &&
  (!existsSync(car) ||
    (read("CFBundleIconName") === ICON_NAME && sameBytes(car, join(bundle, "Contents", "Resources", "Assets.car"))));

if (already) {
  process.exit(0);
}

copyFileSync(icns, join(bundle, "Contents", "Resources", `${ICON_STEM}.icns`));
if (existsSync(car)) {
  copyFileSync(car, join(bundle, "Contents", "Resources", "Assets.car"));
  write("CFBundleIconName", ICON_NAME);
}
write("CFBundleName", APP_NAME);
write("CFBundleDisplayName", APP_NAME);
write("CFBundleIdentifier", APP_ID);
write("CFBundleIconFile", ICON_STEM);

/**
 * DO NOT rename Contents/MacOS/Electron. It is tempting — `ps` and Activity
 * Monitor read the binary's filename, so a rename is the only way to get the
 * product's name there — and it breaks the app outright.
 *
 * Electron computes `app.isPackaged` as "is my executable NOT called
 * `electron`?". Renaming the binary therefore makes an unpackaged dev run
 * believe it is packaged, and everything hanging off that flag inverts at once:
 * `assetRoot()` resolves to `process.resourcesPath/doorman`, which does not
 * exist in node_modules, so every font, React, React-DOM and Babel 404s and the
 * renderer dies with "Babel is not defined"; and the `if (!app.isPackaged)`
 * block that sets the Dock icon and the About panel stops running, so the
 * rename defeats the very thing it was added for. A symlink at the old name
 * does not help — the exec'd path is what Electron inspects.
 *
 * The process-list label is not worth any of that. Leave the binary alone.
 */

// macOS caches bundle name + icon per path in LaunchServices; without a bump
// the rename lands but the Dock keeps drawing the atom until a logout.
const now = new Date();
try {
  utimesSync(bundle, now, now);
  execFileSync(
    "/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister",
    ["-f", bundle],
    { stdio: "ignore" },
  );
} catch {
  // Best effort: the rename is already written, only the cache bump failed.
}

console.log(`[brand-dev-shell] dev shell labelled "${APP_NAME}" with the brand icon.`);
