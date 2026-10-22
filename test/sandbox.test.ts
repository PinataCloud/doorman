import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, realpathSync, rmSync, symlinkSync } from "node:fs";
import { homedir, tmpdir, userInfo } from "node:os";
import { join } from "node:path";
import { appHome } from "../main/lib/home.js";
import { installMcpServer, uninstallMcpServer } from "../main/mcp-install.js";
import { hookWritesAllowed, homeIsRedirected, SANDBOX_READ_ONLY } from "../main/lib/sandbox.js";

/**
 * The one predicate every write into a foreign document is checked against
 * (main/lib/sandbox.ts). It has to hold two lines at once: never touch
 * the real account's hook documents from a scratch run, and still let a fully
 * redirected fixture install the guard — without which no rule can ever hold a
 * call, and enforcement cannot be tested anywhere but a real machine.
 */
describe("the sandbox's write predicate", () => {
  const real = userInfo().homedir;

  it("allows everything in a normal run", () => {
    expect(hookWritesAllowed({ HOME: real })).toBe(true);
    // No HOME at all is still a normal run: the sandbox flag is what gates.
    expect(hookWritesAllowed({})).toBe(true);
    // An EMPTY value is not a sandbox — the variable has to name a directory.
    expect(hookWritesAllowed({ DOORMAN_APPDATA_DIR: "" })).toBe(true);
  });

  it("says why, in the message every refusal carries", () => {
    expect(SANDBOX_READ_ONLY).toMatch(/read-only/);
  });

  it("refuses a sandboxed run pointed at the REAL home", () => {
    // The 2026-09-06 incident exactly: a scratch profile, the real home, and a
    // boot re-merge that rewrote five hook documents to point into /tmp.
    expect(hookWritesAllowed({ DOORMAN_APPDATA_DIR: "/tmp/box", HOME: real })).toBe(false);
    // …and with HOME absent, which resolves to the real home too.
    expect(hookWritesAllowed({ DOORMAN_APPDATA_DIR: "/tmp/box" })).toBe(false);
  });

  it("allows a sandboxed run whose HOME is redirected too", () => {
    // Every hook path is resolved from homedir(), so under a redirected home
    // they all land inside the fixture — there is no foreign document to
    // damage, and the guard becomes installable and therefore testable.
    expect(hookWritesAllowed({ DOORMAN_APPDATA_DIR: "/tmp/box", HOME: "/tmp/box/home" })).toBe(true);
  });

  it("does not mistake a trailing slash for a different home", () => {
    expect(homeIsRedirected({ HOME: real + "/" })).toBe(false);
    expect(hookWritesAllowed({ DOORMAN_APPDATA_DIR: "/tmp/box", HOME: real + "/" })).toBe(false);
  });

  it("treats an unreadable home as NOT redirected — the end that writes nothing", () => {
    expect(homeIsRedirected({})).toBe(false);
    expect(homeIsRedirected({ HOME: "" })).toBe(false);
  });
});

/**
 * A redirected HOME says where paths should resolve, not where a write lands:
 * the app once took its home from Electron (which on macOS ignores $HOME) and
 * wrote MCP registrations into the real ~/.copilot while the predicate,
 * reading $HOME alone, said yes. With the target in hand it can't.
 */
describe("the sandbox's write predicate, given the actual target", () => {
  let root: string;
  let home: string;
  const real = userInfo().homedir;

  beforeEach(() => {
    root = realpathSync(mkdtempSync(join(tmpdir(), "doorman-sandbox-target-")));
    home = join(root, "home");
    mkdirSync(home, { recursive: true });
  });

  afterEach(() => rmSync(root, { recursive: true, force: true }));

  const sandbox = () => ({ DOORMAN_APPDATA_DIR: join(root, "appdata"), HOME: home });

  it("allows a target inside the fake HOME, existing or not yet", () => {
    expect(hookWritesAllowed(sandbox(), join(home, ".copilot", "mcp-config.json"))).toBe(true);
    expect(hookWritesAllowed(sandbox(), home)).toBe(true);
  });

  it("refuses a target outside the fake HOME — the real home above all", () => {
    expect(hookWritesAllowed(sandbox(), join(real, ".copilot", "mcp-config.json"))).toBe(false);
    expect(hookWritesAllowed(sandbox(), join(real, "Library", "Application Support", "Code", "User", "mcp.json"))).toBe(false);
    expect(hookWritesAllowed(sandbox(), real)).toBe(false);
    expect(hookWritesAllowed(sandbox(), join(root, "elsewhere", "settings.json"))).toBe(false);
    // A sibling whose name merely starts with the home's is not inside it.
    expect(hookWritesAllowed(sandbox(), `${home}-other/x.json`)).toBe(false);
    expect(hookWritesAllowed(sandbox(), join(home, "..", "x.json"))).toBe(false);
  });

  it("follows a symlink out of the fixture: a linked real directory is not the fixture's", () => {
    const outside = join(root, "real-cursor");
    mkdirSync(outside);
    symlinkSync(outside, join(home, ".cursor"));
    expect(hookWritesAllowed(sandbox(), join(home, ".cursor", "hooks.json"))).toBe(false);
  });

  it("still refuses everything when HOME is not redirected, and checks nothing in a normal run", () => {
    expect(hookWritesAllowed({ DOORMAN_APPDATA_DIR: join(root, "appdata"), HOME: real }, join(real, ".claude.json"))).toBe(false);
    expect(hookWritesAllowed({ HOME: home }, join(real, ".claude.json"))).toBe(true);
  });

  it("refuses MCP registration into any home but the redirected one — the app's 2026-10-21 write into the real ~/.copilot", () => {
    // The app passed Electron's home (the account's) while HOME pointed at
    // the fixture. A stand-in for that other home, so a regression writes
    // into the scratch directory and never the real one.
    const electronHome = join(root, "account-home");
    mkdirSync(join(electronHome, ".copilot"), { recursive: true });
    const userData = join(root, "appdata", "Doorman");
    for (const outcome of [installMcpServer(userData, electronHome, sandbox()), uninstallMcpServer(userData, electronHome, sandbox())]) {
      expect(outcome.ok).toBe(false);
      expect(outcome.error).toContain(SANDBOX_READ_ONLY);
    }
    expect(readdirSync(join(electronHome, ".copilot"))).toEqual([]);
  });
});

/** The app's one home (lib/home.ts): $HOME, as the guard and the CLI go by,
 * never Electron's own answer, which on macOS is the account's home. */
describe("the app's home", () => {
  const electron = () => "/Users/the-real-account";

  it("honours a redirected HOME over Electron's home", () => {
    expect(appHome(electron, { HOME: "/tmp/fixture/home" }, "darwin")).toBe("/tmp/fixture/home");
    expect(appHome(electron, { HOME: "/tmp/fixture/home" }, "linux")).toBe("/tmp/fixture/home");
  });

  it("is what os.homedir() says — the home the guard install and the MCP watcher use", () => {
    expect(appHome(electron)).toBe(homedir());
    expect(appHome(electron, {}, "darwin")).toBe(homedir());
  });

  it("is the only home the app main process resolves agent configs from", () => {
    const main = readFileSync(join(__dirname, "..", "main", "index.ts"), "utf8");
    // Electron's home on macOS ignores $HOME; os.homedir() calls scattered
    // beside it were the second answer. One function, one answer.
    expect(main.match(/getPath\(\s*["']home["']\s*\)/g)).toHaveLength(1);
    expect(main).toMatch(/appHome\(\(\) => app\.getPath\("home"\)\)/);
    expect(main).not.toMatch(/\bhomedir\(\)/);
  });
});
