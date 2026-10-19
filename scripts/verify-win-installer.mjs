#!/usr/bin/env node
/**
 * Prove a Windows installer will actually install Doorman, before it ships.
 *
 *   node scripts/verify-win-installer.mjs dist/Doorman-Setup-<v>.exe
 *
 * The NSIS installer carries one 7z payload per architecture
 * ($PLUGINSDIR/app-64.7z, app-arm64.7z) and unpacks it with the Nsis7z plugin.
 * 7-Zip 23.01+ compresses ARM64 executables with its ARM64 filter, which that
 * plugin cannot decode: it skips those entries without an error and the
 * installer still reports success, leaving no Doorman.exe and no DLLs
 * (electron-builder#9983; Doorman 0.4.0 shipped this way on Windows on ARM).
 * The release build sets ELECTRON_BUILDER_7Z_FILTER=BCJ to avoid it; this
 * check fails the build if any payload still uses a coder Nsis7z can't read,
 * or lacks the app's executable.
 *
 * Needs a 7-Zip binary on PATH (`7z` on GitHub's Windows runners, `7zz` from
 * Homebrew on a Mac).
 */
import { execFileSync } from "node:child_process";
import { mkdtempSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

/** Coders the installer's Nsis7z plugin decodes. */
const SUPPORTED = new Set(["LZMA", "LZMA2", "BCJ", "BCJ2", "Copy", "PPMD"]);
const EXECUTABLE = "Doorman.exe";

const installer = process.argv[2];
if (!installer) {
  console.error("usage: node scripts/verify-win-installer.mjs <Doorman-Setup.exe>");
  process.exit(2);
}

function sevenZip() {
  for (const bin of ["7z", "7zz", "7za"]) {
    try {
      execFileSync(bin, ["i"], { stdio: "ignore" });
      return bin;
    } catch {
      // try the next name
    }
  }
  console.error("verify-win-installer: no 7-Zip binary (7z, 7zz or 7za) on PATH");
  process.exit(2);
}

const z = sevenZip();
const work = mkdtempSync(join(tmpdir(), "doorman-installer-"));
let failures = 0;
try {
  execFileSync(z, ["x", "-y", `-o${work}`, installer, "$PLUGINSDIR/app-*.7z"], { stdio: "ignore" });
  const dir = join(work, "$PLUGINSDIR");
  const payloads = readdirSync(dir).filter((f) => /^app-.+\.7z$/.test(f));
  if (payloads.length === 0) {
    console.error(`verify-win-installer: ${installer} holds no app-*.7z payload`);
    process.exit(1);
  }
  for (const payload of payloads) {
    const listing = execFileSync(z, ["l", "-slt", join(dir, payload)], { encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
    // `-slt` prints the archive's own block first, then one block per entry
    // after a line of dashes; folders carry an empty Method.
    const entries = [];
    let path;
    let inEntries = false;
    for (const line of listing.split(/\r?\n/)) {
      if (/^-{5,}$/.test(line)) inEntries = true;
      else if (!inEntries) continue;
      else if (line.startsWith("Path = ")) path = line.slice(7);
      else if (line.startsWith("Method = ") && path !== undefined && line.length > 9) entries.push({ path, coders: line.slice(9).split(" ").map((c) => c.split(":")[0]) });
    }
    const bad = entries.filter((e) => e.coders.some((c) => !SUPPORTED.has(c)));
    const hasExe = entries.some((e) => e.path === EXECUTABLE);
    if (bad.length > 0) {
      failures++;
      console.error(`✗ ${payload}: ${bad.length} entr${bad.length === 1 ? "y uses a coder" : "ies use coders"} the installer can't decode (${[...new Set(bad.flatMap((e) => e.coders.filter((c) => !SUPPORTED.has(c))))].join(", ")}), e.g. ${bad.slice(0, 3).map((e) => e.path).join(", ")}`);
    }
    if (!hasExe) {
      failures++;
      console.error(`✗ ${payload}: no ${EXECUTABLE}`);
    }
    if (bad.length === 0 && hasExe) console.log(`✓ ${payload}: ${entries.length} entries, all decodable, ${EXECUTABLE} present`);
  }
} finally {
  rmSync(work, { recursive: true, force: true });
}
process.exit(failures > 0 ? 1 : 0);
