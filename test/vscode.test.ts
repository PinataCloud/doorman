import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join, sep } from "node:path";
import { describe, expect, it } from "vitest";

import {
  COPILOT_HOOKS_LOCATION,
  DEFAULT_VARIANT,
  HOOK_LOCATIONS,
  RECENT_STORAGE_KEY,
  STORAGE_ITEM_SQL,
  TRUST_STORAGE_KEY,
  VSCODE_PRODUCT_JSON_REL,
  VSCODE_VARIANTS,
  assessSettings,
  cliCandidates,
  cliInvocation,
  extensionLink,
  fileLink,
  folderTrusted,
  parseRecentFolders,
  parseTrustInfo,
  profiles,
  readSettings,
  readWorkspaceTrust,
  sharedDataFolder,
  trustDatabases,
  userDir,
  variantPresent,
  vscodeVariants,
} from "../main/lib/vscode.js";
import { createSourceIo } from "../main/lib/source-io.js";
import { parseJsonc, stripJsonc } from "../main/guard/jsonc.js";
import { diagnose, type DoctorInput } from "../main/lib/doctor.js";
import { resolveRegistrationDocuments } from "../main/lib/mcp-register.js";
import { mcpConfigPaths } from "../main/lib/mcp-inventory.js";
import {
  EXTENSION_ID,
  OPEN_INTENT_MAX_AGE_MS,
  WINDOW_STALE_MS,
  appBundlePath,
  openIntentPath,
  parseEditorOpenIntent,
  installArgs,
  installedVersion,
  needsInstall,
  parseEditorAnswer,
  parseEditorWindowReport,
  parseExtensionList,
  statusPath,
  uninstallArgs,
  windowReportLive,
  windowsDir,
  type EditorWindowReport,
} from "../main/lib/vscode-ext.js";

const HOME = "/Users/tester";

/** A DoctorInput with nothing on the machine, which every case below adds to. */
function input(over: Partial<DoctorInput> & { files?: Record<string, string>; dirs?: string[] } = {}): DoctorInput {
  const files = over.files ?? {};
  const dirs = new Set(over.dirs ?? []);
  return {
    home: HOME,
    guardWanted: true,
    guardDir: "/ud/guard",
    guardFiles: [],
    guardCommandMarker: "doorman/guard/guard.js",
    fs: {
      exists: (p) => p in files || dirs.has(p),
      read: (p) => files[p],
      listDir: (p) => [...dirs].filter((d) => d.startsWith(`${p}${sep}`)).map((d) => d.slice(p.length + 1).split(sep)[0]!),
    },
    ...over,
  };
}

const check = (report: ReturnType<typeof diagnose>, id: string) => report.checks.find((c) => c.id === id);

describe("the VS Code family", () => {
  it("is the three builds that are NOT already hosts of their own", () => {
    expect(VSCODE_VARIANTS.map((v) => v.id)).toEqual(["vscode", "vscode-insiders", "vscodium"]);
    // Cursor and Windsurf are VS Code forks too, but each is a first-class
    // guard host here; putting them in the family would double-count them.
    expect(VSCODE_VARIANTS.some((v) => /cursor|windsurf/i.test(v.label))).toBe(false);
    expect(DEFAULT_VARIANT.id).toBe("vscode");
  });

  it("gives each build its own user directory, extensions directory and URL scheme", () => {
    expect(userDir(VSCODE_VARIANTS[0]!, HOME)).toBe(join(HOME, VSCODE_VARIANTS[0]!.supportRel, "User"));
    expect(new Set(VSCODE_VARIANTS.map((v) => v.supportRel)).size).toBe(3);
    expect(new Set(VSCODE_VARIANTS.map((v) => v.extensionsRel)).size).toBe(3);
    expect(new Set(VSCODE_VARIANTS.map((v) => v.scheme)).size).toBe(3);
  });

  it("keeps each build's user data where that platform's VS Code does", () => {
    const rels = (platform: NodeJS.Platform) => vscodeVariants(platform).map((v) => v.supportRel);
    expect(rels("darwin")).toEqual(["Library/Application Support/Code", "Library/Application Support/Code - Insiders", "Library/Application Support/VSCodium"]);
    // %APPDATA%, at its default under the profile.
    expect(rels("win32")).toEqual(["AppData/Roaming/Code", "AppData/Roaming/Code - Insiders", "AppData/Roaming/VSCodium"]);
    expect(rels("linux")).toEqual([".config/Code", ".config/Code - Insiders", ".config/VSCodium"]);
    expect(userDir(vscodeVariants("win32")[0]!, HOME)).toBe(join(HOME, "AppData", "Roaming", "Code", "User"));
    expect(userDir(vscodeVariants("linux")[2]!, HOME)).toBe(join(HOME, ".config", "VSCodium", "User"));
    // Only the user-data folder moves; ids, schemes and shared-data names do not.
    expect(vscodeVariants("win32").map((v) => [v.id, v.scheme, v.sharedDataRel])).toEqual(vscodeVariants("darwin").map((v) => [v.id, v.scheme, v.sharedDataRel]));
  });

  it("looks for the CLI inside the app bundle on macOS, never on the PATH", () => {
    // A GUI-launched Mac app inherits launchd's PATH, which has no `code`.
    const mac = { platform: "darwin" as const, home: HOME, env: { PATH: "/usr/local/bin:/opt/homebrew/bin" } };
    for (const candidate of cliCandidates(DEFAULT_VARIANT, mac)) {
      expect(candidate.startsWith("/Applications/")).toBe(true);
      expect(candidate).toContain("Contents/Resources/app/bin/");
    }
    expect(cliCandidates(VSCODE_VARIANTS[1]!, mac).some((c) => c.endsWith("/code-insiders"))).toBe(true);
  });

  it("looks for code.cmd where the Windows installers put it, then on the PATH", () => {
    const [stable, insiders, codium] = vscodeVariants("win32");
    const env = {
      LOCALAPPDATA: "C:\\Users\\dev\\AppData\\Local",
      ProgramFiles: "D:\\Apps",
      // A quoted entry is unwrapped; a relative one would follow the app's cwd and is skipped.
      Path: 'C:\\Windows\\system32;"C:\\Tools\\VS Code\\bin";.\\bin;;',
    };
    const win = { platform: "win32" as const, home: "C:\\Users\\dev", env };
    expect(cliCandidates(stable!, win)).toEqual([
      "C:\\Users\\dev\\AppData\\Local\\Programs\\Microsoft VS Code\\bin\\code.cmd",
      "D:\\Apps\\Microsoft VS Code\\bin\\code.cmd",
      "C:\\Windows\\system32\\code.cmd",
      "C:\\Tools\\VS Code\\bin\\code.cmd",
    ]);
    expect(cliCandidates(insiders!, win).slice(0, 2)).toEqual([
      "C:\\Users\\dev\\AppData\\Local\\Programs\\Microsoft VS Code Insiders\\bin\\code-insiders.cmd",
      "D:\\Apps\\Microsoft VS Code Insiders\\bin\\code-insiders.cmd",
    ]);
    expect(cliCandidates(codium!, win)[0]).toBe("C:\\Users\\dev\\AppData\\Local\\Programs\\VSCodium\\bin\\codium.cmd");
    // No environment at all: the defaults under the profile and C:\Program Files.
    expect(cliCandidates(stable!, { platform: "win32", home: "C:\\Users\\dev", env: {} })).toEqual([
      "C:\\Users\\dev\\AppData\\Local\\Programs\\Microsoft VS Code\\bin\\code.cmd",
      "C:\\Program Files\\Microsoft VS Code\\bin\\code.cmd",
    ]);
    // Insiders never settles for stable's `code` on the PATH.
    expect(cliCandidates(insiders!, win).some((c) => c.endsWith("\\code.cmd"))).toBe(false);
  });

  it("looks for the CLI where the Linux packages put it, then ~/.local/bin and the PATH", () => {
    const [stable, insiders, codium] = vscodeVariants("linux");
    const linux = { platform: "linux" as const, home: "/home/dev", env: { PATH: "/usr/local/bin:/usr/bin:bin" } };
    expect(cliCandidates(stable!, linux)).toEqual([
      "/usr/bin/code",
      "/usr/share/code/bin/code",
      "/snap/bin/code",
      "/home/dev/.local/bin/code",
      "/usr/local/bin/code",
    ]);
    expect(cliCandidates(insiders!, linux)).toContain("/usr/share/code-insiders/bin/code-insiders");
    expect(cliCandidates(insiders!, linux).some((c) => c.endsWith("/code"))).toBe(false);
    expect(cliCandidates(codium!, linux)).toContain("/snap/bin/codium");
  });

  it("runs a Windows .cmd through cmd.exe with every part quoted, and refuses what cmd would rewrite", () => {
    expect(cliInvocation("/usr/bin/code", ["--list-extensions"], "linux")).toEqual({ file: "/usr/bin/code", args: ["--list-extensions"] });
    expect(cliInvocation("/Applications/Visual Studio Code.app/Contents/Resources/app/bin/code", ["-v"], "darwin")).toEqual({
      file: "/Applications/Visual Studio Code.app/Contents/Resources/app/bin/code",
      args: ["-v"],
    });
    const cmd = "C:\\Program Files\\Microsoft VS Code\\bin\\code.cmd";
    expect(cliInvocation(cmd, ["--install-extension", "C:\\a b\\doorman.vsix", "--force"], "win32")).toEqual({
      file: "cmd.exe",
      args: ["/d", "/s", "/c", `""${cmd}" "--install-extension" "C:\\a b\\doorman.vsix" "--force""`],
      windowsVerbatimArguments: true,
    });
    expect(cliInvocation(cmd, ["--install-extension", "C:\\%TEMP%\\x.vsix"], "win32")).toBeUndefined();
    expect(cliInvocation(cmd, ['say "hi"'], "win32")).toBeUndefined();
  });

  it.runIf(process.platform === "win32")("passes paths with spaces through cmd.exe intact", () => {
    const dir = mkdtempSync(join(tmpdir(), "doorman code cli "));
    const script = join(dir, "code.cmd");
    writeFileSync(script, "@echo off\r\necho [%~1] [%~2]\r\n");
    const call = cliInvocation(script, ["--install-extension", join(dir, "doorman ext.vsix")])!;
    const out = spawnSync(call.file, call.args, { encoding: "utf8", windowsVerbatimArguments: call.windowsVerbatimArguments });
    expect(out.status).toBe(0);
    expect(out.stdout.trim()).toBe(`[--install-extension] [${join(dir, "doorman ext.vsix")}]`);
  });

  it("counts a build as present from its bundle OR its user directory", () => {
    const bundleOnly = (p: string) => p === "/Applications/Visual Studio Code.app";
    expect(variantPresent(DEFAULT_VARIANT, HOME, bundleOnly)).toBe(true);
    const dataOnly = (p: string) => p === userDir(DEFAULT_VARIANT, HOME);
    expect(variantPresent(DEFAULT_VARIANT, HOME, dataOnly)).toBe(true);
    expect(variantPresent(DEFAULT_VARIANT, HOME, () => false)).toBe(false);
  });

  it("enumerates the default profile plus every named one", () => {
    const base = userDir(DEFAULT_VARIANT, HOME);
    const io = {
      exists: (p: string) => p === base || p === join(base, "profiles") || p.startsWith(join(base, "profiles", "")),
      listDir: (p: string) => (p === join(base, "profiles") ? ["-ab12", "work"] : []),
    };
    expect(profiles(DEFAULT_VARIANT, HOME, io)).toEqual([
      { id: "", dir: base, default: true },
      { id: "-ab12", dir: join(base, "profiles", "-ab12"), default: false },
      { id: "work", dir: join(base, "profiles", "work"), default: false },
    ]);
    // A build that isn't here has no profiles at all, not one empty default.
    expect(profiles(DEFAULT_VARIANT, HOME, { exists: () => false, listDir: () => [] })).toEqual([]);
  });
});

/**
 * These five settings decide whether the guard runs in VS Code at all. The
 * defaults asserted here are VS Code 1.136.2's own, read out of its shipped
 * bundle and re-verified unchanged against 1.138.0 — so an EMPTY settings
 * document has to assess as the healthy state, not as a pile of unknowns.
 */
describe("the settings that decide coverage", () => {
  it("reads an empty document as the healthy default", () => {
    const facts = assessSettings({});
    expect(facts.hooksEnabled).toBe(true);
    expect(facts.hooksExplicit).toBe(false);
    expect(facts.copilotHooksLocationEnabled).toBe(true);
    expect(facts.claudeHooksEnabled).toBe(false);
    expect(facts.globalAutoApprove).toBe(false);
    expect(facts.terminalAutoApproveAllows).toBe(0);
    expect(facts.mcpAccess).toBeUndefined();
  });

  it("names our own hook directory as one of VS Code's five sources", () => {
    expect(HOOK_LOCATIONS).toContain(COPILOT_HOOKS_LOCATION);
    expect(COPILOT_HOOKS_LOCATION).toBe("~/.copilot/hooks");
  });

  it("sees each way the guard can be switched off", () => {
    expect(assessSettings({ "chat.useHooks": false }).hooksEnabled).toBe(false);
    const located = assessSettings({ "chat.hookFilesLocations": { "~/.copilot/hooks": false } });
    expect(located.copilotHooksLocationEnabled).toBe(false);
    expect(located.disabledHookLocations).toEqual(["~/.copilot/hooks"]);
    expect(assessSettings({ "chat.tools.global.autoApprove": true }).globalAutoApprove).toBe(true);
    expect(assessSettings({ "chat.mcp.access": "none" }).mcpAccess).toBe("none");
    expect(assessSettings({ "chat.tools.terminal.autoApprove": { rm: true, ls: false } }).terminalAutoApproveAllows).toBe(1);
  });

  it("reads settings.json as the JSONC VS Code actually writes", () => {
    const text = `{
      // turned this off while debugging
      "chat.useHooks": false,
      /* block */
      "editor.fontSize": 12,
    }`;
    expect(readSettings(text).hooksEnabled).toBe(false);
    expect(parseJsonc(text)?.["editor.fontSize"]).toBe(12);
    // A comment in a VS Code settings file is normal, not damage: the scanner
    // reports what it removed and the caller decides what that means.
    expect(stripJsonc(text).changes).toContain("removed comments");
  });

  it("treats an unreadable settings file as the defaults, never as 'switched off'", () => {
    expect(readSettings("this is not json at all {{{").hooksEnabled).toBe(true);
    expect(readSettings(undefined).hooksEnabled).toBe(true);
  });
});

/**
 * Workspace trust as VS Code 1.138.0 persists it: `content.trust.model.key` in
 * the application-SHARED storage database under `~/<sharedDataFolderName>/`,
 * a `$mid`-tagged URI per entry, longest-parent-wins resolution. The shapes
 * below are copied from a real Mac's database, not from documentation.
 */
describe("workspace trust", () => {
  const TRUST_ROW = JSON.stringify({
    uriTrustInfo: [
      { uri: { $mid: 1, fsPath: "/Users/tester/repos", path: "/Users/tester/repos", scheme: "file" }, trusted: true },
      {
        uri: {
          $mid: 1,
          fsPath: "/Users/tester/Downloads/cert (2)",
          external: "file:///Users/tester/Downloads/cert%20%282%29",
          path: "/Users/tester/Downloads/cert (2)",
          scheme: "file",
        },
        trusted: true,
      },
      { uri: { $mid: 1, path: "/remote", scheme: "vscode-remote", authority: "ssh-remote+box" }, trusted: true },
    ],
  });
  const RECENT_ROW = JSON.stringify({
    entries: [
      { folderUri: "file:///Users/tester/repos/app" },
      { fileUri: "file:///Users/tester/notes.md", label: "notes" },
      { folderUri: "file:///Users/tester/Downloads/cert%20%282%29" },
      { workspace: { id: "abc", configPath: "file:///Users/tester/multi.code-workspace" } },
      { folderUri: "file:///Users/tester/scratch" },
    ],
  });

  it("reads the trusted set out of the stored document, file URIs only", () => {
    expect(parseTrustInfo(TRUST_ROW)).toEqual([
      { path: "/Users/tester/repos", trusted: true },
      { path: "/Users/tester/Downloads/cert (2)", trusted: true },
    ]);
    // A corrupt row is UNKNOWN, never "nothing is trusted" — that verdict
    // would put a Restricted Mode warning on every folder someone has.
    expect(parseTrustInfo("{not json")).toBeUndefined();
    expect(parseTrustInfo(JSON.stringify({ uriTrustInfo: "nope" }))).toBeUndefined();
    expect(parseTrustInfo(undefined)).toBeUndefined();
    // …but a document without the list is what VS Code's loadTrustInfo reads
    // as an empty list, so it is one here too.
    expect(parseTrustInfo("{}")).toEqual([]);
  });

  it("lists recently opened FOLDERS, decoded, most recent first — not files or workspaces", () => {
    expect(parseRecentFolders(RECENT_ROW)).toEqual([
      "/Users/tester/repos/app",
      "/Users/tester/Downloads/cert (2)",
      "/Users/tester/scratch",
    ]);
    expect(parseRecentFolders(undefined)).toEqual([]);
    expect(parseRecentFolders("garbage")).toEqual([]);
  });

  it("resolves a folder by its LONGEST trusted parent, as VS Code does", () => {
    const entries = parseTrustInfo(TRUST_ROW)!;
    expect(folderTrusted("/Users/tester/repos/app", entries)).toBe(true);
    expect(folderTrusted("/Users/tester/repos", entries)).toBe(true);
    // A prefix that is not a path boundary is not a parent.
    expect(folderTrusted("/Users/tester/repos-old", entries)).toBe(false);
    expect(folderTrusted("/Users/tester/scratch", entries)).toBe(false);
    expect(folderTrusted("/anything", [])).toBe(false);
    // macOS file URIs compare case-insensitively (VS Code's extUri does).
    expect(folderTrusted("/users/Tester/Repos/app", entries)).toBe(true);
    // The nearest entry decides: an untrusted child under a trusted parent.
    const nested = [
      { path: "/Users/tester/repos", trusted: true },
      { path: "/Users/tester/repos/vendor", trusted: false },
    ];
    expect(folderTrusted("/Users/tester/repos/vendor/x", nested)).toBe(false);
    expect(folderTrusted("/Users/tester/repos/mine", nested)).toBe(true);
  });

  it("takes the shared-data folder from the installed build's own product.json, then the recorded name", () => {
    const manifest = `${DEFAULT_VARIANT.appPaths[0]}/${VSCODE_PRODUCT_JSON_REL}`;
    expect(sharedDataFolder(DEFAULT_VARIANT, (p) => (p === manifest ? '{"sharedDataFolderName":".vscode-x"}' : undefined))).toBe(".vscode-x");
    expect(sharedDataFolder(DEFAULT_VARIANT, () => undefined)).toBe(".vscode-shared");
    expect(sharedDataFolder(DEFAULT_VARIANT, () => "not json")).toBe(".vscode-shared");
    // Insiders' name was never read out of a real manifest, so without the
    // bundle it is unknown rather than guessed.
    expect(sharedDataFolder(VSCODE_VARIANTS[1]!, () => undefined)).toBeUndefined();
    expect(trustDatabases(DEFAULT_VARIANT, HOME, ".vscode-shared")).toEqual([
      join(HOME, ".vscode-shared", "sharedStorage", "state.vscdb"),
      join(userDir(DEFAULT_VARIANT, HOME), "globalStorage", "state.vscdb"),
    ]);
    expect(trustDatabases(VSCODE_VARIANTS[1]!, HOME, undefined)).toEqual([
      join(userDir(VSCODE_VARIANTS[1]!, HOME), "globalStorage", "state.vscdb"),
    ]);
  });

  describe("the verdict for one build", () => {
    const shared = join(HOME, ".vscode-shared", "sharedStorage", "state.vscdb");
    const global = join(userDir(DEFAULT_VARIANT, HOME), "globalStorage", "state.vscdb");
    const folders = ["/Users/tester/repos/app", "/Users/tester/Downloads/cert (2)", "/Users/tester/scratch"];
    const db = (rows: Record<string, string | undefined>, at = shared) => ({
      exists: (p: string) => p === at || folders.includes(p),
      readText: () => undefined,
      querySqlite: (p: string, sql: string, params: readonly unknown[]) => {
        expect(p).toBe(at);
        expect(sql).toBe(STORAGE_ITEM_SQL);
        const value = rows[String(params[0])];
        return value === undefined ? [] : [{ value }];
      },
    });
    const facts = assessSettings({});

    it("names the recent folders that open in Restricted Mode", () => {
      const reading = readWorkspaceTrust(DEFAULT_VARIANT, HOME, facts, db({ [TRUST_STORAGE_KEY]: TRUST_ROW, [RECENT_STORAGE_KEY]: RECENT_ROW }));
      expect(reading).toEqual({ kind: "read", checked: 3, untrusted: ["/Users/tester/scratch"], database: shared });
    });

    it("treats a missing trust row as 'nothing trusted yet' and a corrupt one as unknown", () => {
      const none = readWorkspaceTrust(DEFAULT_VARIANT, HOME, facts, db({ [RECENT_STORAGE_KEY]: RECENT_ROW }));
      expect(none.kind).toBe("read");
      expect(none.untrusted).toEqual(folders);
      expect(readWorkspaceTrust(DEFAULT_VARIANT, HOME, facts, db({ [TRUST_STORAGE_KEY]: "{{", [RECENT_STORAGE_KEY]: RECENT_ROW })).kind).toBe("unknown");
    });

    it("falls back to the older global database when no shared one exists", () => {
      const reading = readWorkspaceTrust(DEFAULT_VARIANT, HOME, facts, db({ [TRUST_STORAGE_KEY]: TRUST_ROW, [RECENT_STORAGE_KEY]: RECENT_ROW }, global));
      expect(reading.kind).toBe("read");
      expect(reading.database).toBe(global);
    });

    it("skips folders that are gone, and caps at the most recent few", () => {
      const io = db({ [TRUST_STORAGE_KEY]: "{}", [RECENT_STORAGE_KEY]: RECENT_ROW });
      const gone = { ...io, exists: (p: string) => p === shared || p === "/Users/tester/scratch" };
      expect(readWorkspaceTrust(DEFAULT_VARIANT, HOME, facts, gone).untrusted).toEqual(["/Users/tester/scratch"]);
      expect(readWorkspaceTrust(DEFAULT_VARIANT, HOME, facts, io, 1).checked).toBe(1);
    });

    it("is unknown without a reader, without a database, or when the read throws", () => {
      const { querySqlite: _q, ...noReader } = db({});
      expect(readWorkspaceTrust(DEFAULT_VARIANT, HOME, facts, noReader).kind).toBe("unknown");
      expect(readWorkspaceTrust(DEFAULT_VARIANT, HOME, facts, { ...db({}), exists: () => false }).kind).toBe("unknown");
      const throwing = {
        ...db({}),
        querySqlite: () => {
          throw new Error("database is locked");
        },
      };
      expect(readWorkspaceTrust(DEFAULT_VARIANT, HOME, facts, throwing).kind).toBe("unknown");
    });

    it("never opens the database when Workspace Trust itself is off", () => {
      const off = assessSettings({ "security.workspace.trust.enabled": false });
      expect(off.workspaceTrustEnabled).toBe(false);
      const io = { ...db({}), querySqlite: () => { throw new Error("should not be called"); } };
      expect(readWorkspaceTrust(DEFAULT_VARIANT, HOME, off, io)).toEqual({ kind: "disabled", checked: 0, untrusted: [] });
    });
  });
});

describe("the setup check for VS Code", () => {
  // The doctor reads each profile's settings.json with path.join.
  const settingsFile = join(userDir(DEFAULT_VARIANT, HOME), "settings.json");
  const withCode = (settings: Record<string, unknown>, over: Partial<DoctorInput> = {}) =>
    diagnose(
      input({
        dirs: [userDir(DEFAULT_VARIANT, HOME)],
        files: { [settingsFile]: JSON.stringify(settings) },
        ...over,
      }),
    );

  it("skips a machine with no VS Code", () => {
    expect(check(diagnose(input()), "vscode.present")?.status).toBe("skip");
  });

  it("passes a default install, and — with no way to read trust — says what Restricted Mode does", () => {
    const row = check(withCode({}), "vscode.hooks");
    expect(row?.status).toBe("ok");
    expect(row?.detail).toMatch(/Restricted Mode/);
    expect(check(withCode({}), "vscode.restricted_mode")).toBeUndefined();
  });

  describe("with the trusted-folder list readable", () => {
    const shared = join(HOME, ".vscode-shared", "sharedStorage", "state.vscdb");
    const trustRow = JSON.stringify({ uriTrustInfo: [{ uri: { $mid: 1, fsPath: `${HOME}/repos`, path: `${HOME}/repos`, scheme: "file" }, trusted: true }] });
    const recentRow = (...folders: string[]) => JSON.stringify({ entries: folders.map((f) => ({ folderUri: `file://${f}` })) });
    const withTrust = (rows: Record<string, string>, folders: string[], settings: Record<string, unknown> = {}) => {
      const base = input({ dirs: [userDir(DEFAULT_VARIANT, HOME), shared, ...folders], files: { [settingsFile]: JSON.stringify(settings) } });
      base.fs.querySqlite = (p, _sql, params) => {
        expect(p).toBe(shared);
        const value = rows[String(params[0])];
        return value === undefined ? [] : [{ value }];
      };
      return diagnose(base);
    };

    it("WARNS with the recent folders that open in Restricted Mode, and drops the caveat from the healthy row", () => {
      const report = withTrust(
        { [TRUST_STORAGE_KEY]: trustRow, [RECENT_STORAGE_KEY]: recentRow(`${HOME}/repos/app`, `${HOME}/scratch`, `${HOME}/Downloads/x`) },
        [`${HOME}/repos/app`, `${HOME}/scratch`, `${HOME}/Downloads/x`],
      );
      const row = check(report, "vscode.restricted_mode");
      expect(row?.status).toBe("warn");
      expect(row?.detail).toContain("2 of your 3 most recent folders");
      expect(row?.detail).toContain("~/scratch, ~/Downloads/x");
      expect(row?.detail).toMatch(/no hooks at all/);
      // Their trust decision, never ours to make: no fix, a manual step.
      expect(row?.fix).toBeUndefined();
      expect(row?.manual).toMatch(/Manage Workspace Trust/);
      expect(check(report, "vscode.hooks")?.detail).toMatch(/see the Restricted Mode row/);
    });

    it("passes cleanly when every recent folder is trusted, saying how many were checked", () => {
      const report = withTrust(
        { [TRUST_STORAGE_KEY]: trustRow, [RECENT_STORAGE_KEY]: recentRow(`${HOME}/repos/app`, `${HOME}/repos/lib`) },
        [`${HOME}/repos/app`, `${HOME}/repos/lib`],
      );
      expect(check(report, "vscode.restricted_mode")).toBeUndefined();
      const row = check(report, "vscode.hooks");
      expect(row?.status).toBe("ok");
      expect(row?.detail).toContain("2 most recent folders are all trusted");
      expect(row?.detail).not.toMatch(/Restricted Mode/);
    });

    it("says Workspace Trust is off instead of reading anything", () => {
      const report = withTrust({}, [`${HOME}/scratch`], { "security.workspace.trust.enabled": false });
      expect(check(report, "vscode.restricted_mode")).toBeUndefined();
      expect(check(report, "vscode.hooks")?.detail).toMatch(/Workspace Trust is switched off/);
    });

    it("is silent about trust when the guard is not wanted or hooks are already off", () => {
      const rows = { [TRUST_STORAGE_KEY]: "{}", [RECENT_STORAGE_KEY]: recentRow(`${HOME}/scratch`) };
      expect(check(withTrust(rows, [`${HOME}/scratch`], { "chat.useHooks": false }), "vscode.restricted_mode")).toBeUndefined();
    });
  });

  it("FAILS when chat.useHooks is off — the hook file is there and inert", () => {
    const row = check(withCode({ "chat.useHooks": false }), "vscode.hooks");
    expect(row?.status).toBe("fail");
    expect(row?.detail).toMatch(/installed and inert/);
    // Never repaired for them: it is their editor preference, in a document
    // they hand-edit with comments.
    expect(row?.fix).toBeUndefined();
    expect(row?.manual).toMatch(/chat\.useHooks/);
  });

  it("FAILS when only our hook directory is disabled, which chat.useHooks hides", () => {
    const row = check(withCode({ "chat.hookFilesLocations": { "~/.copilot/hooks": false } }), "vscode.hooks");
    expect(row?.status).toBe("fail");
    expect(row?.detail).toContain(COPILOT_HOOKS_LOCATION);
  });

  it("reads the worst profile, not just the default one", () => {
    const base = userDir(DEFAULT_VARIANT, HOME);
    const report = diagnose(
      input({
        dirs: [base, join(base, "profiles"), join(base, "profiles", "work")],
        files: {
          [join(base, "settings.json")]: "{}",
          [join(base, "profiles", "work", "settings.json")]: JSON.stringify({ "chat.useHooks": false }),
        },
      }),
    );
    const row = check(report, "vscode.hooks");
    expect(row?.status).toBe("fail");
    expect(row?.detail).toContain("profile work");
  });

  it("warns about VS Code's own auto-approve without claiming ours is affected", () => {
    const row = check(withCode({ "chat.tools.global.autoApprove": true }), "vscode.auto_approve");
    expect(row?.status).toBe("warn");
    expect(row?.detail).toMatch(/Doorman's own hold still applies/);
  });

  it("says nothing about the guard when guardrails are off", () => {
    expect(check(withCode({ "chat.useHooks": false }, { guardWanted: false }), "vscode.hooks")).toBeUndefined();
    expect(check(withCode({}, { guardWanted: false }), "vscode.guard_off")?.status).toBe("skip");
  });

  it("mentions chat.mcp.access only when our MCP server is meant to be there", () => {
    expect(check(withCode({ "chat.mcp.access": "none" }), "vscode.mcp_access")).toBeUndefined();
    const row = check(withCode({ "chat.mcp.access": "none" }, { mcpWanted: true }), "vscode.mcp_access");
    expect(row?.status).toBe("warn");
  });

  it("offers to install the companion extension, and only when it is switched on", () => {
    expect(check(withCode({}), "vscode.extension")).toBeUndefined();
    const missing = check(withCode({}, { vscodeExtension: { wanted: true, bundled: "1.2.3" } }), "vscode.extension");
    expect(missing?.status).toBe("fail");
    expect(missing?.fix).toBe("install-vscode-extension");
    expect(missing?.auto).toBe(true);
    const stale = check(
      withCode({}, { vscodeExtension: { wanted: true, installed: "1.2.2", bundled: "1.2.3" } }),
      "vscode.extension",
    );
    expect(stale?.status).toBe("warn");
    const current = check(
      withCode({}, { vscodeExtension: { wanted: true, installed: "1.2.3", bundled: "1.2.3" } }),
      "vscode.extension",
    );
    expect(current?.status).toBe("ok");
    const noCli = check(withCode({}, { vscodeExtension: { wanted: true, cliMissing: true } }), "vscode.extension");
    expect(noCli?.status).toBe("warn");
    expect(noCli?.fix).toBeUndefined();
  });
});

/**
 * What an OPEN window reports through the companion extension outranks any
 * inference: it knows its own trust and the settings after policy.
 */
describe("the setup check with open windows reporting", () => {
  const settingsFile = join(userDir(DEFAULT_VARIANT, HOME), "settings.json");
  const shared = join(HOME, ".vscode-shared", "sharedStorage", "state.vscdb");
  const window = (over: Partial<EditorWindowReport>): EditorWindowReport => ({
    id: "w1",
    at: new Date().toISOString(),
    app_name: "Visual Studio Code",
    trusted: true,
    folders: [`${HOME}/repos/app`],
    hooks_enabled: true,
    copilot_hooks_location_enabled: true,
    ...over,
  });
  const withWindows = (windows: EditorWindowReport[], settings: Record<string, unknown> = {}) => {
    const base = input({
      dirs: [userDir(DEFAULT_VARIANT, HOME), shared, `${HOME}/scratch`],
      files: { [settingsFile]: JSON.stringify(settings) },
      vscodeWindows: windows,
    });
    // The database says ~/scratch (recently opened) is untrusted — the
    // inference the live report must outrank for the build that is reporting.
    base.fs.querySqlite = (_p, _sql, params) =>
      String(params[0]) === RECENT_STORAGE_KEY ? [{ value: JSON.stringify({ entries: [{ folderUri: `file://${HOME}/scratch` }] }) }] : [];
    return diagnose(base);
  };

  it("FAILS on a window in Restricted Mode right now, naming its folder", () => {
    const report = withWindows([window({ trusted: false, folders: [`${HOME}/repos/app`] })]);
    const row = check(report, "vscode.restricted_mode");
    expect(row?.status).toBe("fail");
    expect(row?.detail).toContain("1 open VS Code window is in Restricted Mode right now");
    expect(row?.detail).toContain("~/repos/app");
    expect(row?.manual).toMatch(/Manage Workspace Trust/);
  });

  it("passes on trusted windows and does NOT fall back to the recent-folder inference for that build", () => {
    const report = withWindows([window({}), window({ id: "w2", folders: [`${HOME}/repos/lib`] })]);
    expect(check(report, "vscode.restricted_mode")).toBeUndefined();
    const row = check(report, "vscode.hooks");
    expect(row?.status).toBe("ok");
    expect(row?.detail).toContain("All 2 open VS Code windows are trusted");
    expect(row?.detail).not.toContain("most recent folders");
  });

  it("does not call an untrusted EMPTY window restricted — nothing runs there", () => {
    expect(check(withWindows([window({ trusted: false, folders: [] })]), "vscode.restricted_mode")).toBeUndefined();
  });

  it("FAILS when a window reports chat.useHooks off while the settings file says on — a policy is forcing it", () => {
    const row = check(withWindows([window({ hooks_enabled: false })]), "vscode.hooks");
    expect(row?.status).toBe("fail");
    expect(row?.detail).toMatch(/organization policy \(ChatHooks\)/);
    expect(row?.manual).toMatch(/admin/);
  });

  it("FAILS when a window reports our hook directory disabled", () => {
    const row = check(withWindows([window({ copilot_hooks_location_enabled: false })]), "vscode.hooks");
    expect(row?.status).toBe("fail");
    expect(row?.detail).toContain(COPILOT_HOOKS_LOCATION);
  });

  it("still infers for a build with no window reporting, alongside the live verdict for the one that is", () => {
    // The Insiders window reports; stable VS Code (present via its user dir) does not.
    const base = input({
      dirs: [userDir(DEFAULT_VARIANT, HOME), userDir(VSCODE_VARIANTS[1]!, HOME), shared, `${HOME}/scratch`],
      files: { [settingsFile]: "{}" },
      vscodeWindows: [window({ app_name: "Visual Studio Code - Insiders" })],
    });
    base.fs.querySqlite = (_p, _sql, params) =>
      String(params[0]) === RECENT_STORAGE_KEY ? [{ value: JSON.stringify({ entries: [{ folderUri: `file://${HOME}/scratch` }] }) }] : [];
    const report = diagnose(base);
    expect(check(report, "vscode.hooks")?.detail).toContain("The open VS Code Insiders window is trusted");
    const restricted = check(report, "vscode.restricted_mode");
    expect(restricted?.status).toBe("warn");
    expect(restricted?.detail).toContain("in VS Code");
    expect(restricted?.detail).toContain("~/scratch");
  });
});

/**
 * The Setup health card groups rows by host from its own list. A host missing
 * there is counted in the headline and then filtered out of the body — the
 * VS Code rows were invisible that way for ten days. Hold the list to the type.
 */
describe("the Setup health card", () => {
  it("lists every DoctorHost, VS Code included", () => {
    const union = /export type DoctorHost = ([^;]+);/.exec(readFileSync("main/lib/doctor.ts", "utf8"))![1]!;
    const hosts = [...union.matchAll(/"([^"]+)"/g)].map((m) => m[1]);
    expect(hosts).toContain("vscode");
    const card = readFileSync("renderer/screens/integrations.jsx", "utf8");
    const list = /const DOCTOR_HOSTS = \[([\s\S]*?)\];/.exec(card)![1]!;
    const listed = [...list.matchAll(/\["([^"]+)",/g)].map((m) => m[1]);
    for (const host of hosts) expect(listed, `DOCTOR_HOSTS is missing "${host}"`).toContain(host);
  });
});

describe("MCP documents across builds and profiles", () => {
  it("registers in every build present and every named profile, once each", () => {
    const stable = userDir(VSCODE_VARIANTS[0]!, HOME);
    const insiders = userDir(VSCODE_VARIANTS[1]!, HOME);
    const dirs = new Set([stable, insiders, join(stable, "profiles"), join(stable, "profiles", "work")]);
    const io = {
      exists: (p: string) => dirs.has(p),
      listDir: (p: string) => (p === join(stable, "profiles") ? ["work"] : []),
    };
    const paths = resolveRegistrationDocuments(HOME, {}, io).map((d) => d.path);
    // Grouped by build — all of stable's documents, then Insiders' — because
    // that is the order the Settings card lists them in.
    expect(paths).toEqual([
      join(stable, "mcp.json"),
      join(stable, "profiles", "work", "mcp.json"),
      join(insiders, "mcp.json"),
    ]);
    expect(new Set(paths).size).toBe(paths.length);
  });

  it("writes nothing for a build that is not installed", () => {
    const stable = userDir(VSCODE_VARIANTS[0]!, HOME);
    const io = { exists: (p: string) => p === stable, listDir: () => [] };
    const paths = resolveRegistrationDocuments(HOME, {}, io).map((d) => d.path);
    expect(paths).toEqual([join(stable, "mcp.json")]);
  });

  it("still reaches a document when the host is gone, so uninstall is total", () => {
    const io = { exists: () => false, listDir: () => [] };
    expect(resolveRegistrationDocuments(HOME, {}, io)).toEqual([]);
    const all = resolveRegistrationDocuments(HOME, {}, io, undefined, { requirePresence: false });
    expect(all.map((d) => d.path)).toContain(join(userDir(VSCODE_VARIANTS[0]!, HOME), "mcp.json"));
  });

  it("on a machine with only Insiders, writes Insiders' mcp.json and never creates stable VS Code's", () => {
    const insiders = userDir(VSCODE_VARIANTS[1]!, HOME);
    const io = { exists: (p: string) => p === insiders, listDir: () => [] };
    const paths = resolveRegistrationDocuments(HOME, {}, io).map((d) => d.path);
    expect(paths).toEqual([join(insiders, "mcp.json")]);
  });

  it("takes only folders in profiles/ as profiles — never Finder's .DS_Store or a stray file", () => {
    const stable = userDir(VSCODE_VARIANTS[0]!, HOME);
    const profilesDir = join(stable, "profiles");
    const entries = [".DS_Store", "notes.txt", "work"];
    const io = {
      exists: (p: string) => p === stable || p === profilesDir || entries.some((e) => p === join(profilesDir, e)),
      listDir: (p: string) => (p === profilesDir ? entries : []),
      isDir: (p: string) => p === stable || p === profilesDir || p === join(profilesDir, "work"),
    };
    expect(resolveRegistrationDocuments(HOME, {}, io).map((d) => d.label)).toEqual(["VS Code", "VS Code · work"]);
    // Without isDir (a caller that can't tell), the dot-file is still skipped.
    const { isDir: _isDir, ...noIsDir } = io;
    expect(resolveRegistrationDocuments(HOME, {}, noIsDir).map((d) => d.label)).not.toContain("VS Code · .DS_Store");
  });

  it("finds Copilot CLI under $COPILOT_HOME, for registration and for the inventory", () => {
    const io = { exists: (p: string) => p === "/elsewhere/copilot", listDir: () => [] };
    const env = { COPILOT_HOME: "/elsewhere/copilot/" };
    expect(resolveRegistrationDocuments(HOME, env, io).map((d) => d.path)).toEqual([join("/elsewhere/copilot", "mcp-config.json")]);
    const paths = mcpConfigPaths(HOME, io, process.platform, env);
    expect(paths).toContain(join("/elsewhere/copilot", "mcp-config.json"));
    expect(paths).not.toContain(join(HOME, ".copilot", "mcp-config.json"));
  });

  it("scans every build's mcp.json and every profile's for poisoning", () => {
    const stable = userDir(VSCODE_VARIANTS[0]!, HOME);
    const io = {
      exists: (p: string) => p === stable || p === join(stable, "profiles") || p === join(stable, "profiles", "work"),
      listDir: (p: string) => (p === join(stable, "profiles") ? ["work"] : []),
    };
    const paths = mcpConfigPaths(HOME, io);
    for (const variant of VSCODE_VARIANTS) expect(paths).toContain(join(userDir(variant, HOME), "mcp.json"));
    expect(paths).toContain(join(stable, "profiles", "work", "mcp.json"));
  });

  it("finds the user-level MCP configs where Windows and Linux keep them", () => {
    const none = { exists: () => false, listDir: () => [] };
    const win = mcpConfigPaths(HOME, none, "win32");
    expect(win).toContain(join(HOME, "AppData", "Roaming", "Claude", "claude_desktop_config.json"));
    expect(win).toContain(join(HOME, "AppData", "Roaming", "Code", "User", "mcp.json"));
    expect(win).toContain(join(HOME, "AppData", "Roaming", "Code - Insiders", "User", "mcp.json"));
    expect(win).toContain(join(HOME, "AppData", "Roaming", "VSCodium", "User", "mcp.json"));
    const linux = mcpConfigPaths(HOME, none, "linux");
    expect(linux).toContain(join(HOME, ".config", "Code", "User", "mcp.json"));
    expect(linux).toContain(join(HOME, ".config", "VSCodium", "User", "mcp.json"));
    expect(linux).toContain(join(HOME, ".config", "Claude", "claude_desktop_config.json"));
    // macOS is where it was.
    const mac = mcpConfigPaths(HOME, none, "darwin");
    expect(mac).toContain(join(HOME, "Library", "Application Support", "Claude", "claude_desktop_config.json"));
    expect(mac).toContain(join(HOME, "Library", "Application Support", "Code", "User", "mcp.json"));
    for (const paths of [win, linux]) expect(paths.some((p) => p.includes("Library"))).toBe(false);
    // A Windows profile is found under its own build, too.
    const stable = userDir(vscodeVariants("win32")[0]!, HOME);
    const io = {
      exists: (p: string) => p === stable || p === join(stable, "profiles") || p === join(stable, "profiles", "work"),
      listDir: (p: string) => (p === join(stable, "profiles") ? ["work"] : []),
    };
    expect(mcpConfigPaths(HOME, io, "win32")).toContain(join(stable, "profiles", "work", "mcp.json"));
  });
});

describe("deep links", () => {
  it("builds the file link VS Code registers, with the line and column suffix", () => {
    expect(fileLink("/Users/x/a.ts")).toBe("vscode://file/Users/x/a.ts");
    expect(fileLink("/Users/x/a.ts", 12)).toBe("vscode://file/Users/x/a.ts:12");
    expect(fileLink("/Users/x/a.ts", 12, 4)).toBe("vscode://file/Users/x/a.ts:12:4");
    expect(fileLink("/Users/x/a b.ts")).toBe("vscode://file/Users/x/a%20b.ts");
    // The suffix is only a suffix when it is real — a 0 line would send the
    // cursor nowhere and reads as "we know where", which we don't.
    expect(fileLink("/Users/x/a.ts", 0)).toBe("vscode://file/Users/x/a.ts");
    expect(fileLink("relative/a.ts")).toBeUndefined();
    expect(fileLink("/Users/x/a.ts", 1, 1, "vscode-insiders")).toBe("vscode-insiders://file/Users/x/a.ts:1:1");
  });

  it("builds an extension link for the case where the CLI can't be used", () => {
    expect(extensionLink(EXTENSION_ID)).toBe("vscode:extension/pinata.doorman");
  });
});

describe("driving the editor's CLI", () => {
  it("reads `--list-extensions --show-versions`, ignoring the noise it prints", () => {
    const stdout = [
      "(node:1) [DEP0169] DeprecationWarning: url.parse() is bad",
      "anthropic.claude-code@2.1.263",
      "pinata.doorman@0.57.0",
      "(Use `Code --trace-deprecation ...` to show where the warning was created)",
    ].join("\n");
    expect(parseExtensionList(stdout).size).toBe(2);
    expect(installedVersion(stdout)).toBe("0.57.0");
    expect(installedVersion("nothing of ours here\n")).toBeUndefined();
  });

  it("replaces any version that isn't the one this app ships, in either direction", () => {
    expect(needsInstall(undefined, "1.0.0")).toBe(true);
    expect(needsInstall("1.0.0", "1.0.0")).toBe(false);
    expect(needsInstall("0.9.0", "1.0.0")).toBe(true);
    // A NEWER extension left by a newer app the person rolled back speaks a
    // protocol this build doesn't write, so it is replaced too.
    expect(needsInstall("2.0.0", "1.0.0")).toBe(true);
  });

  it("installs with --force so a re-run is a no-op instead of an error", () => {
    expect(installArgs("/tmp/doorman.vsix")).toEqual(["--install-extension", "/tmp/doorman.vsix", "--force"]);
    expect(uninstallArgs()).toEqual(["--uninstall-extension", EXTENSION_ID]);
  });
});

describe("the extension's side of the contract", () => {
  it("puts the status file where the extension looks for it", () => {
    expect(statusPath("/ud")).toBe("/ud/doorman/editor/status.json");
  });

  it("accepts only a well-formed verdict", () => {
    expect(parseEditorAnswer('{"id":"a","verdict":"allow","at":"2026-09-11T00:00:00Z"}')).toEqual({
      id: "a",
      verdict: "allow",
      at: "2026-09-11T00:00:00Z",
    });
    expect(parseEditorAnswer('{"id":"a","verdict":"maybe"}')).toBeUndefined();
    expect(parseEditorAnswer('{"verdict":"allow"}')).toBeUndefined();
    expect(parseEditorAnswer("not json")).toBeUndefined();
  });

  it("reads a window's report, with VS Code's ON defaults for anything an older extension left out", () => {
    expect(windowsDir("/ud")).toBe("/ud/doorman/editor/windows");
    const full = parseEditorWindowReport(
      JSON.stringify({
        id: "s1",
        at: "2026-09-21T12:00:00Z",
        app_name: "Visual Studio Code - Insiders",
        version: "1.138.0",
        trusted: false,
        folders: ["/Users/t/repos/app", 7],
        hooks_enabled: false,
        copilot_hooks_location_enabled: true,
        mcp_access: "none",
      }),
    );
    expect(full).toEqual({
      id: "s1",
      at: "2026-09-21T12:00:00Z",
      app_name: "Visual Studio Code - Insiders",
      version: "1.138.0",
      trusted: false,
      folders: ["/Users/t/repos/app"],
      hooks_enabled: false,
      copilot_hooks_location_enabled: true,
      mcp_access: "none",
    });
    const minimal = parseEditorWindowReport('{"id":"s2","at":"2026-09-21T12:00:00Z","trusted":true}');
    expect(minimal).toMatchObject({ folders: [], hooks_enabled: true, copilot_hooks_location_enabled: true, app_name: "VS Code" });
    // Not a report at all: no id, no trust verdict, or not JSON.
    expect(parseEditorWindowReport('{"at":"x","trusted":true}')).toBeUndefined();
    expect(parseEditorWindowReport('{"id":"s","at":"x"}')).toBeUndefined();
    expect(parseEditorWindowReport("{{")).toBeUndefined();
  });

  it("drops a report whose heartbeat stopped — a window that closed without deactivate", () => {
    const now = Date.parse("2026-09-21T12:00:00Z");
    const report = (at: string): EditorWindowReport => ({ id: "s", at, app_name: "VS Code", trusted: true, folders: [], hooks_enabled: true, copilot_hooks_location_enabled: true });
    expect(windowReportLive(report("2026-09-21T11:59:30Z"), now)).toBe(true);
    expect(windowReportLive(report(new Date(now - WINDOW_STALE_MS - 1).toISOString()), now)).toBe(false);
    expect(windowReportLive(report("garbage"), now)).toBe(false);
  });

  it("tells the extension what to open: the .app bundle on macOS, the executable elsewhere", () => {
    expect(appBundlePath("/Applications/Doorman.app/Contents/MacOS/Doorman")).toBe("/Applications/Doorman.app");
    expect(appBundlePath("/Users/x/Applications/Doorman.app/Contents/MacOS/Doorman")).toBe("/Users/x/Applications/Doorman.app");
    expect(appBundlePath("C:\\Users\\x\\AppData\\Local\\Programs\\Doorman\\Doorman.exe")).toBe("C:\\Users\\x\\AppData\\Local\\Programs\\Doorman\\Doorman.exe");
    expect(appBundlePath("/opt/Doorman/doorman")).toBe("/opt/Doorman/doorman");
  });

  it("reads the editor's 'bring the app to the screen' request, allow-listed and fresh only", () => {
    expect(openIntentPath("/ud")).toBe("/ud/doorman/editor/open.json");
    const now = Date.parse("2026-09-21T12:00:00Z");
    const fresh = new Date(now - 5_000).toISOString();
    expect(parseEditorOpenIntent(JSON.stringify({ screen: "radar", at: fresh }), now)).toEqual({ screen: "radar", at: fresh });
    // A screen we don't route lands on the Overview rather than being trusted.
    expect(parseEditorOpenIntent(JSON.stringify({ screen: "../etc", at: fresh }), now)?.screen).toBe("overview");
    // A click nobody is waiting on any more is dropped, never honoured late.
    expect(parseEditorOpenIntent(JSON.stringify({ screen: "radar", at: new Date(now - OPEN_INTENT_MAX_AGE_MS - 1).toISOString() }), now)).toBeUndefined();
    expect(parseEditorOpenIntent('{"screen":"radar"}', now)).toBeUndefined();
    expect(parseEditorOpenIntent("{{", now)).toBeUndefined();
  });
});

/**
 * The shipped VS Code on THIS machine, when there is one. Everything above is
 * fixtures; this is the alarm for the day a VS Code release moves a file or
 * renames a setting — the failure mode these checks exist to catch is exactly
 * the one a fixture cannot see.
 */
describe.skipIf(!existsSync(`${homedir()}/Library/Application Support/Code/User`))("against the installed VS Code", () => {
  const home = homedir();

  it("finds the real user directory and its settings file parses", () => {
    expect(variantPresent(DEFAULT_VARIANT, home, existsSync)).toBe(true);
    const found = profiles(DEFAULT_VARIANT, home, {
      exists: existsSync,
      listDir: (p) => {
        try {
          return readdirSync(p);
        } catch {
          return [];
        }
      },
    });
    expect(found[0]?.default).toBe(true);
    const settings = `${found[0]!.dir}/settings.json`;
    if (existsSync(settings)) expect(parseJsonc(readFileSync(settings, "utf8"))).toBeTypeOf("object");
  });

  it("still ships the `code` CLI at the path the installer drives", () => {
    if (!existsSync(DEFAULT_VARIANT.appPaths[0]!)) return;
    expect(cliCandidates(DEFAULT_VARIANT, { platform: process.platform, home: homedir(), env: process.env }).some((c) => existsSync(c))).toBe(true);
  });

  it("still names the shared-data folder we recorded, in its own product.json", () => {
    if (!existsSync(DEFAULT_VARIANT.appPaths[0]!)) return;
    const read = (p: string) => (existsSync(p) ? readFileSync(p, "utf8") : undefined);
    expect(sharedDataFolder(DEFAULT_VARIANT, read)).toBe(DEFAULT_VARIANT.sharedDataRel);
  });

  it("reads the real trusted-folder list through the same read-only reader the app uses", () => {
    const read = (p: string) => (existsSync(p) ? readFileSync(p, "utf8") : undefined);
    const database = trustDatabases(DEFAULT_VARIANT, home, sharedDataFolder(DEFAULT_VARIANT, read)).find((p) => existsSync(p));
    if (!database) return;
    const io = createSourceIo({ snapshotDir: mkdtempSync(join(tmpdir(), "doorman-vscode-trust-")) });
    const reading = readWorkspaceTrust(DEFAULT_VARIANT, home, readSettings(read(`${userDir(DEFAULT_VARIANT, home)}/settings.json`)), {
      exists: existsSync,
      readText: read,
      querySqlite: (p, sql, params) => io.querySqlite(p, sql, params),
    });
    // A readable database always yields a verdict — "unknown" here means the
    // row's shape moved under us, which is exactly what this alarm is for.
    expect(["read", "disabled"]).toContain(reading.kind);
    if (reading.kind === "read") expect(reading.database).toBe(database);
  });
});
