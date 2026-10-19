#!/usr/bin/env node
/**
 * Stamp `build/main/build-info.json` with the commit the build was made from:
 * its hash and its commit time. The desktop app and the CLI are built from
 * this one tree but released and updated separately, so on one machine they
 * can be different builds sharing one data directory; the commit time is how
 * each tells which of their guard bundles is the newer one (enforcement.ts
 * refreshGuardBundle never replaces a newer build's bundle with an older one).
 *
 * Run by `npm run compile` after tsc. Outside a git checkout it writes
 * revision 0, the oldest possible.
 */
import { execFileSync } from "node:child_process";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const git = (...args) => execFileSync("git", args, { cwd: root, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim();

let info = { revision: 0 };
try {
  info = { revision: Number(git("log", "-1", "--format=%ct")), commit: git("rev-parse", "--short=12", "HEAD") };
} catch {
  // not a git checkout (or no git): the oldest revision
}
const out = join(root, "build", "main", "build-info.json");
mkdirSync(dirname(out), { recursive: true });
writeFileSync(out, `${JSON.stringify(info)}\n`);
