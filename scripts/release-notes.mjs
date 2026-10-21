#!/usr/bin/env node
/**
 * Print one release's notes from CHANGELOG.md: the body of its
 * `## App <version> — <date>` or `## CLI <version> — <date>` section.
 *
 *   node scripts/release-notes.mjs app 0.7.0
 *   node scripts/release-notes.mjs cli cli-v0.6.0   # a tag works too
 *
 * Exits 1 when the section is missing or empty, so the release workflows stop
 * before building a release nobody wrote notes for. The CLI's `doorman
 * changelog` (main/cli/commands/changelog.ts) reads the same headings.
 */
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const HEADING = /^## (App|CLI) (\S+) [—–-] (\d{4}-\d{2}-\d{2})\s*$/;

const fail = (message, code = 1) => {
  console.error(`release-notes: ${message}`);
  process.exit(code);
};

const [product, tag, ...extra] = process.argv.slice(2);
if ((product !== "app" && product !== "cli") || !tag || extra.length > 0) fail("usage: release-notes.mjs <app|cli> <version>", 2);
const version = tag.replace(/^(cli-)?v/, "");
const name = product === "app" ? "App" : "CLI";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const lines = readFileSync(join(root, "CHANGELOG.md"), "utf8").split(/\r?\n/);
const start = lines.findIndex((line) => {
  const m = HEADING.exec(line);
  return m !== null && m[1] === name && m[2] === version;
});
if (start === -1) fail(`CHANGELOG.md has no "## ${name} ${version} — <YYYY-MM-DD>" section; write one before releasing`);
const rest = lines.slice(start + 1);
const end = rest.findIndex((line) => line.startsWith("## "));
const body = (end === -1 ? rest : rest.slice(0, end)).join("\n").trim();
if (!body) fail(`the "## ${name} ${version}" section in CHANGELOG.md is empty`);
console.log(body);
