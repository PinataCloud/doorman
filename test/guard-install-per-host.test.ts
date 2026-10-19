import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

/**
 * The install is per host: one agent whose config the merge refuses is
 * skipped and named, and every other present agent still gets the guard.
 * Driven through the compiled tree, because the install copies the guard
 * bundle that sits beside build/main.
 */

/* eslint-disable @typescript-eslint/no-require-imports */
const build = join(__dirname, "..", "build", "main");
const enforcement = require(join(build, "enforcement.js")) as typeof import("../main/enforcement.js");
const { defaultPolicy } = require(join(build, "guard", "policy.js")) as typeof import("../main/guard/policy.js");
const { hermesHost } = require(join(build, "guard", "hosts", "hermes.js")) as typeof import("../main/guard/hosts/hermes.js");

const ENV_KEYS = ["HOME", "DOORMAN_APPDATA_DIR", "HERMES_HOME"] as const;
let root: string;
let home: string;
let dataDir: string;
let saved: Partial<Record<(typeof ENV_KEYS)[number], string>>;

/** A flow-style mapping: valid YAML, but nothing Hermes's line editor will follow. */
const REFUSED_HERMES = "{model: claude-opus-5, plugins: {}}\n";

const claudeSettings = () => join(home, ".claude", "settings.json");
const hermesConfig = () => join(home, ".hermes", "config.yaml");

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), "doorman-per-host-"));
  home = join(root, "home");
  dataDir = join(root, "data");
  saved = Object.fromEntries(ENV_KEYS.map((k) => [k, process.env[k]]));
  process.env.HOME = home;
  delete process.env.DOORMAN_APPDATA_DIR;
  delete process.env.HERMES_HOME;
  mkdirSync(join(home, ".claude"), { recursive: true });
  mkdirSync(join(home, ".hermes"), { recursive: true });
  mkdirSync(dataDir, { recursive: true });
});

afterEach(() => {
  for (const key of ENV_KEYS) {
    const value = saved[key];
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
  rmSync(root, { recursive: true, force: true });
});

describe("one agent's config the merge refuses", () => {
  it("doesn't keep the guard out of the others, and is named with its reason", () => {
    writeFileSync(claudeSettings(), "{}\n");
    writeFileSync(hermesConfig(), REFUSED_HERMES);

    const outcome = enforcement.installGuard(dataDir, defaultPolicy());

    expect(outcome, JSON.stringify(outcome)).toMatchObject({ ok: true });
    if (!outcome.ok) return;
    expect(outcome.failures).toEqual([
      { id: "hermes", label: "Hermes Agent", error: expect.stringContaining("~/.hermes/config.yaml") },
    ]);
    expect(outcome.failures[0]!.error).toMatch(/not touching it/);
    // Claude got our entry…
    expect(enforcement.guardHostStates().find((s) => s.host.id === "claude")?.installed).toBe(true);
    expect(readFileSync(claudeSettings(), "utf8")).toContain("PreToolUse");
    // …and nothing of Hermes was written: not its config, not its plugin files.
    expect(readFileSync(hermesConfig(), "utf8")).toBe(REFUSED_HERMES);
    for (const artifact of hermesHost.artifacts!(home, process.env)) expect(existsSync(artifact.path), artifact.path).toBe(false);
    // What the Settings and Rules callouts show: the agent, then its reason.
    const problem = enforcement.guardInstallProblem(outcome);
    expect(problem).toMatch(/^Hermes Agent: ~\/\.hermes\/config\.yaml .*not touching it$/);
    // A later policy sync reports the same agent, while Claude takes the policy.
    // The screens list that per agent, from the same failures.
    expect(enforcement.syncGuard(dataDir, defaultPolicy())).toEqual({ ok: false, error: problem, failures: outcome.failures });
  });

  it("is not ok when no present agent could take the guard, and writes nothing", () => {
    writeFileSync(claudeSettings(), "{ not json");
    writeFileSync(hermesConfig(), REFUSED_HERMES);

    const outcome = enforcement.installGuard(dataDir, defaultPolicy());

    expect(outcome.ok).toBe(false);
    if (outcome.ok) return;
    expect(outcome.error).toMatch(/^Claude Code: .+\. Hermes Agent: .+not touching it$/);
    expect(outcome.failures?.map((f) => f.id)).toEqual(["claude", "hermes"]);
    expect(readFileSync(claudeSettings(), "utf8")).toBe("{ not json");
    expect(readFileSync(hermesConfig(), "utf8")).toBe(REFUSED_HERMES);
    expect(existsSync(enforcement.guardDir(dataDir))).toBe(false);
  });
});

describe("no supported agent on this machine", () => {
  it("is an empty state, not a problem: one short sentence, flagged no_agents, nothing written", () => {
    rmSync(join(home, ".claude"), { recursive: true, force: true });
    rmSync(join(home, ".hermes"), { recursive: true, force: true });

    const outcome = enforcement.installGuard(dataDir, defaultPolicy());

    expect(outcome).toEqual({ ok: false, error: enforcement.NO_AGENTS_FOUND, no_agents: true });
    // It used to name all fifteen agents and every folder each is looked for in.
    expect(enforcement.NO_AGENTS_FOUND.length).toBeLessThan(120);
    // Nothing is out of date, so Settings and Rules show no red callout for it.
    expect(enforcement.guardProblem(outcome)).toBeUndefined();
    expect(existsSync(enforcement.guardDir(dataDir))).toBe(false);
  });
});
