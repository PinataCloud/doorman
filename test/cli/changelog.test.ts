import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PassThrough, Readable } from "node:stream";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { parseChangelog } from "../../main/cli/commands/changelog.js";
import type { CliEnvironment } from "../../main/cli/context.js";
import { main } from "../../main/cli/index.js";
import { compareVersions } from "../../main/cli/update-check.js";

/**
 * CHANGELOG.md, the release notes the workflows publish from it
 * (scripts/release-notes.mjs), and `doorman changelog`, which reads the copy
 * the CLI package ships.
 */

const repo = join(__dirname, "..", "..");
const changelog = readFileSync(join(repo, "CHANGELOG.md"), "utf8");

describe("CHANGELOG.md", () => {
  it("has a section for the CLI version in cli/package.json, newest first, none empty", () => {
    const releases = parseChangelog(changelog);
    const manifest: unknown = JSON.parse(readFileSync(join(repo, "cli", "package.json"), "utf8"));
    expect(manifest).toMatchObject({ version: releases[0]?.version });
    for (const [i, r] of releases.entries()) {
      expect(r.body, r.version).not.toBe("");
      if (i > 0) expect(compareVersions(releases[i - 1]!.version, r.version), r.version).toBeGreaterThan(0);
    }
  });

  it("gives the release workflows one section's notes, and fails a release without one", () => {
    const notes = (...args: string[]) => spawnSync(process.execPath, [join(repo, "scripts", "release-notes.mjs"), ...args], { encoding: "utf8" });
    const app = notes("app", "v0.7.0");
    expect(app.status).toBe(0);
    expect(app.stdout).toMatch(/^### New\n- /);
    expect(app.stdout).not.toMatch(/^## /m);
    const cli = notes("cli", "cli-v0.6.0");
    expect(cli.status).toBe(0);
    expect(cli.stdout).toContain("`doorman policy level balanced`");
    const missing = notes("cli", "0.0.1");
    expect(missing.status).toBe(1);
    expect(missing.stderr).toContain("no \"## CLI 0.0.1 — <YYYY-MM-DD>\" section");
  });
});

describe("doorman changelog", () => {
  let root: string;

  beforeEach(() => {
    root = mkdtempSync(join(tmpdir(), "doorman-changelog-"));
    writeFileSync(
      join(root, "CHANGELOG.md"),
      [
        "# Changelog",
        "",
        "## App 0.9.0 — 2026-10-22",
        "### New",
        "- an app thing",
        "",
        "## CLI 0.3.0 — 2026-10-21",
        "### New",
        "- `doorman changelog` shows what changed, in a bullet long enough",
        "  to carry on onto a second line in the file.",
        "### Fixed",
        "- a fix",
        "",
        "## CLI 0.2.0 — 2026-10-01",
        "### Changed",
        "- something older",
        "",
        "## Earlier releases",
        "",
        "See the GitHub releases.",
      ].join("\n"),
    );
  });

  afterEach(() => rmSync(root, { recursive: true, force: true }));

  async function run(argv: string[], packageDir = root) {
    const stdout = new PassThrough();
    const stderr = new PassThrough();
    let out = "";
    let err = "";
    stdout.on("data", (c: Buffer) => (out += c.toString()));
    stderr.on("data", (c: Buffer) => (err += c.toString()));
    const home = join(root, "home");
    mkdirSync(home, { recursive: true });
    const io: CliEnvironment = {
      env: { HOME: home, DOORMAN_APPDATA_DIR: join(root, "appdata"), NO_COLOR: "1", DOORMAN_NO_UPDATE_CHECK: "1" },
      home,
      platform: process.platform,
      version: "0.3.0",
      packageName: "@pinata/doorman",
      packageDir,
      stdout,
      stderr,
      stdin: Readable.from([""]),
      now: () => Date.now(),
      verbose: false,
    };
    const code = await main(argv, io);
    return { code, out, err };
  }

  it("prints the running version's CLI section, continuation lines joined", async () => {
    const r = await run(["changelog"]);
    expect(r.code).toBe(0);
    expect(r.out).toBe(
      [
        "Doorman CLI 0.3.0  2026-10-21",
        "  New",
        "  - `doorman changelog` shows what changed, in a bullet long enough to carry on onto a second line in the file.",
        "  Fixed",
        "  - a fix",
        "",
      ].join("\n"),
    );
  });

  it("--since lists every newer CLI release (a tag works too), --all every one, --json the same", async () => {
    const since = await run(["changelog", "--since", "cli-v0.1.0", "--json"]);
    expect(since.code).toBe(0);
    const data: unknown = JSON.parse(since.out);
    expect(data).toEqual({
      versions: [expect.objectContaining({ version: "0.3.0", date: "2026-10-21" }), { version: "0.2.0", date: "2026-10-01", body: "### Changed\n- something older" }],
    });
    expect((await run(["changelog", "--since", "0.2.0"])).out).not.toContain("something older");
    expect((await run(["changelog", "--since", "0.3.0"])).out).toBe("Nothing new since 0.3.0.\n");
    const all = await run(["changelog", "--all"]);
    expect(all.out).toContain("Doorman CLI 0.2.0  2026-10-01");
    expect(all.out).not.toContain("an app thing");
  });

  it("says what's wrong: a bad version, both flags, no entry, no file", async () => {
    expect((await run(["changelog", "--since", "soon"])).code).toBe(2);
    expect((await run(["changelog", "--since", "0.1.0", "--all"])).code).toBe(2);
    const missingDir = join(root, "nothing");
    mkdirSync(missingDir);
    const noFile = await run(["changelog"], missingDir);
    expect(noFile.code).toBe(1);
    expect(noFile.err).toContain("https://github.com/PinataCloud/doorman/releases");
    writeFileSync(join(missingDir, "CHANGELOG.md"), "## CLI 0.2.0 — 2026-10-01\n- older\n");
    const noEntry = await run(["changelog"], missingDir);
    expect(noEntry.code).toBe(1);
    expect(noEntry.err).toContain("no entry for Doorman CLI 0.3.0");
  });
});
