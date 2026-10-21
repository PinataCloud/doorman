import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { CliCommand } from "../command.js";
import type { CliContext } from "../context.js";
import { CliError } from "../output.js";
import type { Ui } from "../ui.js";
import { compareVersions } from "../update-check.js";

/** Where every release's notes are published, for when the bundled ones can't be read. */
export const RELEASES_URL = "https://github.com/PinataCloud/doorman/releases";

/** One CLI release in CHANGELOG.md: `--json`'s shape, and what `doorman update` shows. */
export interface ChangelogRelease {
  version: string;
  /** YYYY-MM-DD. */
  date: string;
  /** The section's Markdown, heading left out. */
  body: string;
}

/** `## CLI 0.6.0 — 2026-10-21` (or `## App …`): the heading scheme CHANGELOG.md
 * describes at its top; scripts/release-notes.mjs reads the same. */
const HEADING = /^## (App|CLI) (\S+) [—–-] (\d{4}-\d{2}-\d{2})\s*$/;

/** The package directory this CLI runs from (three levels above build/main/cli):
 * the npm package's root, or the repo's. Both hold CHANGELOG.md. */
export function cliPackageDir(): string {
  return join(__dirname, "..", "..", "..", "..");
}

/** The CLI's releases in a CHANGELOG.md, in file order (newest first). */
export function parseChangelog(text: string): ChangelogRelease[] {
  const releases: ChangelogRelease[] = [];
  let current: { version: string; date: string; lines: string[] } | undefined;
  const close = () => {
    if (current) releases.push({ version: current.version, date: current.date, body: current.lines.join("\n").trim() });
    current = undefined;
  };
  for (const line of text.split(/\r?\n/)) {
    if (!line.startsWith("## ")) {
      current?.lines.push(line);
      continue;
    }
    close();
    const m = HEADING.exec(line);
    if (m?.[1] === "CLI") current = { version: m[2]!, date: m[3]!, lines: [] };
  }
  close();
  return releases;
}

/** Releases as text: a heading per release, its `###` groups, and bullets
 * wrapped under themselves (as written when piped). */
export function releaseLines(ui: Ui, releases: readonly ChangelogRelease[]): string[] {
  const s = ui.style;
  const bullet = ui.decorate ? s.dim(ui.glyphs.tone.info) : "-";
  const out: string[] = [];
  for (const release of releases) {
    if (out.length > 0) out.push("");
    out.push(ui.section(`Doorman CLI ${release.version}`, release.date));
    // A bullet's continuation lines (indented in the file) join it.
    const items: string[] = [];
    for (const raw of release.body.split("\n")) {
      const line = raw.trim();
      if (!line) continue;
      if (/^[-*] /.test(line) || line.startsWith("#") || items.length === 0) items.push(line);
      else items[items.length - 1] += ` ${line}`;
    }
    for (const item of items) {
      const group = /^#+\s+(.*)$/.exec(item);
      if (group) {
        out.push(`  ${s.bold(group[1]!)}`);
        continue;
      }
      const listed = /^[-*] /.test(item);
      const text = ui.prose(listed ? item.slice(2) : item);
      const lead = listed ? `  ${bullet} ` : "  ";
      const lines = ui.width === undefined ? [text] : ui.wrap(text, Math.max(20, ui.width - 4));
      out.push(...lines.map((l, i) => `${i === 0 ? lead : "    "}${l}`));
    }
  }
  return out;
}

export const changelogCommand: CliCommand = {
  name: "changelog",
  summary: "What changed in each release of the Doorman CLI",
  usage: "[--since <version>] [--all]",
  options: { since: { type: "string" }, all: { type: "boolean", default: false } },
  flags: [
    ["--since <version>", "every release after that version, newest first"],
    ["--all", "every release"],
  ],
  notes: [`Read from the CHANGELOG.md this copy shipped with; the app's releases are at ${RELEASES_URL}.`],
  examples: [
    ["doorman changelog", "what's new in the version you run"],
    ["doorman changelog --since 0.5.0", "everything after 0.5.0"],
  ],
  async run(ctx: CliContext, args) {
    const sinceArg = args.values.since;
    const all = args.values.all === true;
    if (typeof sinceArg === "string" && all) throw new CliError("--since and --all don't go together.", 2, "`doorman changelog --all` lists every release.");
    // "0.5.0", "v0.5.0" or a tag, "cli-v0.5.0".
    const given = typeof sinceArg === "string" ? sinceArg.trim().replace(/^(cli-)?v/, "") : undefined;
    const since = given !== undefined && /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(given) ? given : undefined;
    if (typeof sinceArg === "string" && since === undefined) throw new CliError(`"${sinceArg}" isn't a version.`, 2, "Give one like `doorman changelog --since 0.5.0`.");

    let releases: ChangelogRelease[];
    try {
      releases = parseChangelog(readFileSync(join(ctx.io.packageDir ?? cliPackageDir(), "CHANGELOG.md"), "utf8"));
    } catch {
      throw new CliError("This copy of Doorman has no CHANGELOG.md to read.", 1, `Every release's notes are at ${RELEASES_URL}.`);
    }
    const current = ctx.io.version;
    const shown = all ? releases : since !== undefined ? releases.filter((r) => compareVersions(r.version, since) > 0) : releases.filter((r) => r.version === current);
    if (shown.length === 0 && since === undefined) {
      throw new CliError(`The changelog has no entry for Doorman CLI ${current}.`, 1, `\`doorman changelog --all\` lists every release; ${RELEASES_URL} has them too.`);
    }
    const ui = ctx.ui;
    return {
      data: { versions: shown },
      text: shown.length > 0 ? releaseLines(ui, shown) : [ui.mark("ok", `Nothing new since ${since}.`)],
    };
  },
};
