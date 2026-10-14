// electron-builder `afterPack` hook: give the packed .app a valid AD-HOC
// signature.
//
// Why this exists, precisely — because "unsigned" is not what was wrong:
//
// Apple requires arm64 code to carry a signature, so the linker stamps every
// arm64 Mach-O with an ad-hoc one at link time (`flags=0x20002 adhoc,
// linker-signed`, `Identifier=Electron`). electron-builder then renames the
// binary and rewrites the bundle around it, which leaves that signature
// covering a bundle it no longer describes: no `_CodeSignature/CodeResources`,
// so `codesign --verify` reports "code has no resources but signature indicates
// they must be present". macOS reports an INVALID signature as
//
//     "Doorman.app is damaged and can't be opened. You should move it to the
//      Trash."
//
// — a dead end with no override in the UI. The x64 build of the same commit
// opened fine, because x86_64 has no signing requirement, so it was cleanly
// UNSIGNED and got the ordinary "unidentified developer" path with an Open
// Anyway button. Same app, same release: one arch bricked, one arch fine.
//
// Re-signing the whole bundle ad-hoc produces a valid signature
// (`Identifier=cloud.pinata.doorman`, "satisfies its Designated Requirement"),
// which puts arm64 back on that same ordinary path. It does NOT make the app
// notarized — Gatekeeper still stops a quarantined download, and the user still
// has to allow it once in System Settings → Privacy & Security. That is the
// intended preview experience; "damaged" never was.
//
// This is the fallback for a build with no Developer ID available — CI, or a
// contributor's machine. When a Developer ID Application certificate IS in the
// keychain, electron-builder signs the bundle properly and this hook steps
// aside.
//
// Note the ORDER, which is not what the hook name suggests: `afterPack` runs
// BEFORE electron-builder's own signing step, so "has this already been signed
// for distribution?" cannot be answered by inspecting the bundle — at this point
// nothing has. The question that CAN be answered is whether a Developer ID
// identity exists to sign with, so that is what this checks.

import { execFileSync } from "node:child_process";
import { join } from "node:path";

/** `codesign`, with output captured so a failure reports what it said. */
function codesign(args) {
  return execFileSync("codesign", args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
}

export default async function adhocSign(context) {
  if (context.electronPlatformName !== "darwin") return;

  const appPath = join(
    context.appOutDir,
    `${context.packager.appInfo.productFilename}.app`,
  );

  // A Developer ID in the keychain means electron-builder's signing step, which
  // runs after this hook, will sign the bundle properly. Doing an ad-hoc pass
  // first would only be thrown away — and if the ordering ever changes, it would
  // DOWNGRADE a distribution signature to one Gatekeeper trusts less.
  try {
    const identities = execFileSync("security", ["find-identity", "-v", "-p", "codesigning"], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    });
    if (String(identities).includes("Developer ID Application")) {
      console.log("  • adhoc-sign: a Developer ID is available — leaving signing to electron-builder");
      return;
    }
  } catch {
    // No keychain, or `security` unavailable. Fall through and ad-hoc sign:
    // shipping an invalid signature is the failure this hook exists to prevent.
  }

  console.log(`  • adhoc-sign: signing ${appPath}`);
  try {
    // --deep is deprecated for DISTRIBUTION signing, where each nested component
    // needs its own identity and entitlements. For ad-hoc it is the right tool:
    // one identity, no entitlements, every nested helper and framework covered.
    codesign(["--force", "--deep", "--sign", "-", appPath]);
  } catch (err) {
    const detail = err?.stderr || err?.message || err;
    throw new Error(`ad-hoc signing failed: ${detail}`);
  }

  // Verify rather than assume. A build that ships an invalid signature is
  // exactly the failure this hook exists to prevent, and it is invisible until
  // someone downloads it — so fail the build here instead.
  try {
    codesign(["--verify", "--deep", "--strict", appPath]);
  } catch (err) {
    const detail = err?.stderr || err?.message || err;
    throw new Error(`ad-hoc signature did not verify: ${detail}`);
  }
  console.log("  • adhoc-sign: valid on disk");
}
