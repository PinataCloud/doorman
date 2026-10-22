/**
 * Registering Doorman's MCP server against a scratch HOME: what the files on
 * disk look like before and after, byte for byte. Runs the COMPILED module
 * (build/main, compiled by vitest's global setup) because install copies the
 * compiled server and guard bundles that sit beside it.
 */
import { chmodSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

/* eslint-disable @typescript-eslint/no-require-imports */
const build = join(__dirname, "..", "build", "main");
type Outcome = { ok: boolean; error?: string; errors?: string[]; hosts: { host: string; label: string; path: string; registered: boolean; key?: string; unreadable?: boolean; problem?: string }[] };
const install = require(join(build, "mcp-install.js")) as {
  installMcpServer(dataDir: string, home: string, env: NodeJS.ProcessEnv): Outcome;
  uninstallMcpServer(dataDir: string, home: string, env: NodeJS.ProcessEnv): Outcome;
  mcpServerStatus(dataDir: string, home: string, env: NodeJS.ProcessEnv): Outcome["hosts"];
  switchMcpAnswers(
    enabled: boolean,
    dataDir: string,
    home: string,
    prefs: { get(): { mcp_recognized?: string[]; mcp_recognized_at?: Record<string, string> }; set(p: { mcp_recognized: string[]; mcp_recognized_at: Record<string, string> }): void },
    env: NodeJS.ProcessEnv,
  ): Outcome;
};
const { VSCODE_VARIANTS, userDir } = require(join(build, "lib", "vscode.js")) as {
  VSCODE_VARIANTS: unknown[];
  userDir(variant: unknown, home: string): string;
};

let root: string;
let home: string;
let dataDir: string;
let env: NodeJS.ProcessEnv;
const root0 = process.getuid?.() === 0;

const copilotConfig = () => join(home, ".copilot", "mcp-config.json");
const vscodeConfig = (variant = 0) => join(userDir(VSCODE_VARIANTS[variant], home), "mcp.json");
const read = (path: string) => readFileSync(path, "utf8");
const mode = (path: string) => statSync(path).mode & 0o777;
const script = () => join(dataDir, "doorman", "mcp", "doorman-mcp.js");

beforeEach(() => {
  root = realpathSync(mkdtempSync(join(tmpdir(), "doorman-mcp-install-")));
  home = join(root, "home");
  dataDir = join(root, "appdata", "Doorman");
  mkdirSync(home, { recursive: true });
  mkdirSync(dataDir, { recursive: true });
  // A sandboxed run with HOME redirected: writes are allowed, and only here.
  env = { HOME: home, DOORMAN_APPDATA_DIR: join(root, "appdata") };
});

afterEach(() => {
  for (const path of [copilotConfig(), vscodeConfig()]) {
    try {
      chmodSync(path, 0o644);
    } catch {
      // not there
    }
  }
  rmSync(root, { recursive: true, force: true });
});

describe("refusing what must not be replaced", () => {
  it.skipIf(root0)("refuses a config it can't read instead of treating it as absent", () => {
    mkdirSync(join(home, ".copilot"));
    const original = `{"mcpServers":{"precious":{"command":"keep-me"}}}`;
    writeFileSync(copilotConfig(), original);
    chmodSync(copilotConfig(), 0o000);

    expect(install.mcpServerStatus(dataDir, home, env)).toEqual([expect.objectContaining({ host: "copilot-cli", registered: false, unreadable: true })]);
    const outcome = install.installMcpServer(dataDir, home, env);
    expect(outcome.ok).toBe(false);
    expect(outcome.error).toMatch(/Copilot CLI's MCP config \(.*mcp-config\.json\) can't be read: permission denied; not touching it/);
    expect(mode(copilotConfig())).toBe(0o000);
    chmodSync(copilotConfig(), 0o600);
    expect(read(copilotConfig())).toBe(original);
    expect(existsSync(`${copilotConfig()}.doorman.bak`)).toBe(false);
  });

  it("never overwrites the person's own server named doorman, and still registers with the other hosts", () => {
    mkdirSync(join(home, ".copilot"));
    mkdirSync(userDir(VSCODE_VARIANTS[0], home), { recursive: true });
    const theirs = `{"mcpServers":{"doorman":{"command":"python","args":["-m","my_doorman_tool"]}}}\n`;
    writeFileSync(copilotConfig(), theirs);

    const on = install.installMcpServer(dataDir, home, env);
    expect(on.ok).toBe(false);
    expect(on.errors).toEqual([expect.stringMatching(/Copilot CLI's MCP config already has a server named "doorman" that isn't Doorman's.*Rename that server/)]);
    expect(read(copilotConfig())).toBe(theirs);
    expect(on.hosts.find((h) => h.host === "vscode-copilot")?.registered).toBe(true);

    const off = install.uninstallMcpServer(dataDir, home, env);
    expect(off.ok).toBe(true);
    expect(read(copilotConfig())).toBe(theirs);
    expect(existsSync(`${copilotConfig()}.doorman.bak`)).toBe(false);
  });

  it("refuses a server container that isn't an object", () => {
    mkdirSync(join(home, ".copilot"));
    const list = `{"mcpServers":[{"name":"x","command":"y"}],"other":1}`;
    writeFileSync(copilotConfig(), list);
    const outcome = install.installMcpServer(dataDir, home, env);
    expect(outcome.error).toMatch(/"mcpServers" as a list, not an object of servers; not touching it/);
    expect(read(copilotConfig())).toBe(list);
    expect(install.uninstallMcpServer(dataDir, home, env).ok).toBe(true);
    expect(read(copilotConfig())).toBe(list);
    expect(install.mcpServerStatus(dataDir, home, env)[0]).toEqual(expect.objectContaining({ unreadable: true }));
  });

  it.skipIf(root0)("refuses a read-only config rather than replacing it", () => {
    mkdirSync(join(home, ".copilot"));
    const original = `{"mcpServers":{}}`;
    writeFileSync(copilotConfig(), original);
    chmodSync(copilotConfig(), 0o444);
    const outcome = install.installMcpServer(dataDir, home, env);
    expect(outcome.error).toMatch(/is read-only; not touching it/);
    expect(read(copilotConfig())).toBe(original);
    expect(mode(copilotConfig())).toBe(0o444);
    expect(existsSync(`${copilotConfig()}.doorman.tmp`)).toBe(false);
  });
});

describe("giving the original back", () => {
  it("keeps the FIRST backup, with the original's mode, and uninstall restores the original bytes", () => {
    mkdirSync(join(home, ".copilot"));
    const original = `{\n    "mcpServers": {\n        "precious": { "command": "keep-me", "env": { "TOKEN": "s3cret" } }\n    }\n}`;
    writeFileSync(copilotConfig(), original, { mode: 0o600 });
    chmodSync(copilotConfig(), 0o600);

    expect(install.installMcpServer(dataDir, home, env).ok).toBe(true);
    const bak = `${copilotConfig()}.doorman.bak`;
    expect(read(bak)).toBe(original);
    expect(mode(bak)).toBe(0o600);
    expect(mode(copilotConfig())).toBe(0o600);
    expect(read(copilotConfig())).toContain(`        "precious": { "command": "keep-me", "env": { "TOKEN": "s3cret" } }`);

    // A second write (the app moved, so the entry is re-pointed) must not
    // replace the original with Doorman's own text.
    const moved = join(root, "moved", "Doorman");
    mkdirSync(moved, { recursive: true });
    expect(install.installMcpServer(moved, home, env).ok).toBe(true);
    expect(read(bak)).toBe(original);

    expect(install.uninstallMcpServer(moved, home, env).ok).toBe(true);
    expect(read(copilotConfig())).toBe(original);
    expect(mode(copilotConfig())).toBe(0o600);
    expect(existsSync(bak)).toBe(false);
  });

  it("removes a file Doorman created and gives an empty file back empty", () => {
    mkdirSync(join(home, ".copilot"));
    install.installMcpServer(dataDir, home, env);
    expect(JSON.parse(read(copilotConfig())).mcpServers.doorman.args).toEqual([script()]);
    install.uninstallMcpServer(dataDir, home, env);
    expect(existsSync(copilotConfig())).toBe(false);

    writeFileSync(copilotConfig(), "\n");
    install.installMcpServer(dataDir, home, env);
    install.uninstallMcpServer(dataDir, home, env);
    expect(read(copilotConfig())).toBe("\n");
  });

  it("keeps the person's later edits when uninstalling, touching only our entry", () => {
    mkdirSync(join(home, ".copilot"));
    writeFileSync(copilotConfig(), `{"mcpServers":{"a":{"command":"x"}}}`);
    install.installMcpServer(dataDir, home, env);
    const edited = read(copilotConfig()).replace(`"a":{"command":"x"}`, `"a":{"command":"x2"}`);
    writeFileSync(copilotConfig(), edited);
    install.uninstallMcpServer(dataDir, home, env);
    expect(read(copilotConfig())).toBe(`{"mcpServers":{"a":{"command":"x2"}}}`);
  });
});

describe("the files people actually have", () => {
  it("accepts VS Code's JSONC mcp.json and gives back the same bytes", () => {
    mkdirSync(userDir(VSCODE_VARIANTS[0], home), { recursive: true });
    const original = `\uFEFF{\n\t// my servers\n\t"servers": {\n\t\t"fetch": { "command": "uvx", "args": ["mcp-server-fetch"] }, // web\n\t},\n\t"inputs": [],\n}\n`;
    writeFileSync(vscodeConfig(), original);
    const on = install.installMcpServer(dataDir, home, env);
    expect(on.ok).toBe(true);
    const during = read(vscodeConfig());
    expect(during).toContain("// my servers");
    expect(during).toContain("// web");
    expect(on.hosts).toEqual([expect.objectContaining({ label: "VS Code", registered: true })]);
    expect(install.uninstallMcpServer(dataDir, home, env).ok).toBe(true);
    expect(read(vscodeConfig())).toBe(original);
  });

  it("writes through a symlinked config, so the dotfiles target is the one updated", () => {
    mkdirSync(join(home, ".copilot"));
    // Inside HOME: a sandboxed run writes nowhere else (lib/sandbox.ts).
    const dotfiles = join(home, "dotfiles");
    mkdirSync(dotfiles);
    const target = join(dotfiles, "mcp-config.json");
    writeFileSync(target, `{"mcpServers":{}}`);
    symlinkSync(target, copilotConfig());
    expect(install.installMcpServer(dataDir, home, env).ok).toBe(true);
    expect(lstatSync(copilotConfig()).isSymbolicLink()).toBe(true);
    expect(JSON.parse(read(target)).mcpServers.doorman).toBeDefined();
    install.uninstallMcpServer(dataDir, home, env);
    expect(lstatSync(copilotConfig()).isSymbolicLink()).toBe(true);
    expect(read(target)).toBe(`{"mcpServers":{}}`);
  });

  it("ignores a .DS_Store in VS Code's profiles folder", () => {
    const profiles = join(userDir(VSCODE_VARIANTS[0], home), "profiles");
    mkdirSync(join(profiles, "work"), { recursive: true });
    writeFileSync(join(profiles, ".DS_Store"), "");
    const outcome = install.installMcpServer(dataDir, home, env);
    expect(outcome.ok).toBe(true);
    expect(outcome.hosts.map((h) => h.label)).toEqual(["VS Code", "VS Code · work"]);
  });

  it("with only Insiders installed, doesn't create stable VS Code's config", () => {
    mkdirSync(userDir(VSCODE_VARIANTS[1], home), { recursive: true });
    const outcome = install.installMcpServer(dataDir, home, env);
    expect(outcome.hosts.map((h) => h.label)).toEqual(["VS Code Insiders"]);
    expect(existsSync(vscodeConfig(0))).toBe(false);
    expect(existsSync(userDir(VSCODE_VARIANTS[0], home))).toBe(false);
    expect(existsSync(vscodeConfig(1))).toBe(true);
  });

  it("finds Copilot CLI under $COPILOT_HOME", () => {
    const copilotHome = join(home, "copilot-home");
    mkdirSync(copilotHome);
    const outcome = install.installMcpServer(dataDir, home, { ...env, COPILOT_HOME: `${copilotHome}/` });
    expect(outcome.ok).toBe(true);
    expect(outcome.hosts).toEqual([expect.objectContaining({ host: "copilot-cli", path: join(copilotHome, "mcp-config.json"), registered: true })]);
    expect(existsSync(join(home, ".copilot"))).toBe(false);
  });
});

describe("the mcp_answers switch", () => {
  it("recognizes doorman when it landed in some host even though another failed", () => {
    mkdirSync(join(home, ".copilot"));
    mkdirSync(userDir(VSCODE_VARIANTS[0], home), { recursive: true });
    writeFileSync(copilotConfig(), "{ broken");
    let prefs: { mcp_recognized?: string[]; mcp_recognized_at?: Record<string, string> } = {};
    const outcome = install.switchMcpAnswers(true, dataDir, home, { get: () => prefs, set: (p) => (prefs = { ...prefs, ...p }) }, env);
    expect(outcome.ok).toBe(false);
    expect(prefs.mcp_recognized).toEqual(["doorman"]);
  });
});
