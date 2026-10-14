import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { runInNewContext } from "node:vm";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const here = dirname(fileURLToPath(import.meta.url));
const EXT_DIR = join(here, "..", "vscode-extension");
const EXT_JS = join(EXT_DIR, "extension.js");

/**
 * The extension is plain CommonJS that `require("vscode")` — a module that only
 * exists inside the editor. So it is loaded here in a vm with a `require` that
 * answers "vscode" with a stub and everything else with the real builtin.
 *
 * That is the whole point of this file: the extension ships as source (no
 * bundler, see scripts/build-vsix.mjs), so nothing else would ever catch a
 * typo in it — the first sign would be a status bar that silently never
 * appears on someone's machine.
 */
type Stub = ReturnType<typeof makeVscodeStub>;

interface StubItem {
  text: string;
  tooltip: unknown;
  color: unknown;
  command: string;
  backgroundColor: unknown;
  shown: boolean;
  show(): void;
  hide(): void;
  dispose(): void;
}

/** `config` is keyed `<section>.<key>` the way settings.json spells it, so a
 * `getConfiguration("chat").get("useHooks")` reads `chat.useHooks`. */
function makeVscodeStub(config: Record<string, unknown>, env: { trusted?: boolean; folders?: string[]; appName?: string } = {}) {
  const calls = {
    warnings: [] as { message: string; options: Record<string, unknown> | undefined; items: string[] }[],
    infos: [] as string[],
    errors: [] as string[],
    opened: [] as string[],
    executed: [] as string[],
  };
  let nextInfoChoice: string | undefined;
  const items: StubItem[] = [];
  const makeItem = (): StubItem => ({
    text: "",
    tooltip: undefined,
    color: undefined,
    command: "",
    backgroundColor: undefined,
    shown: false,
    show() {
      this.shown = true;
    },
    hide() {
      this.shown = false;
    },
    dispose() {},
  });
  const commands = new Map<string, (...args: unknown[]) => unknown>();
  let nextChoice: string | undefined;
  const lookup = (section: string | undefined) => ({
    get: (key: string) => config[section ? `${section}.${key}` : key],
  });
  const vscode = {
    version: "1.138.0",
    StatusBarAlignment: { Left: 1, Right: 2 },
    ThemeColor: class {
      constructor(public id: string) {}
    },
    MarkdownString: class {
      constructor(public value: string) {}
    },
    Uri: { file: (p: string) => ({ fsPath: p, toString: () => `file://${p}` }) },
    env: {
      sessionId: "session-abc/123",
      appName: env.appName ?? "Visual Studio Code",
      openExternal: async (uri: { fsPath: string }) => {
        calls.opened.push(uri.fsPath);
        return true;
      },
    },
    window: {
      createStatusBarItem: () => {
        const item = makeItem();
        items.push(item);
        return item;
      },
      createOutputChannel: () => ({ appendLine() {}, dispose() {} }),
      showWarningMessage: async (message: string, ...rest: unknown[]) => {
        const options = rest[0] && typeof rest[0] === "object" ? (rest[0] as Record<string, unknown>) : undefined;
        const items = rest.filter((r): r is string => typeof r === "string");
        calls.warnings.push({ message, options, items });
        return nextChoice;
      },
      showInformationMessage: async (message: string, ...items: string[]) => {
        calls.infos.push(message);
        return items.includes(String(nextInfoChoice)) ? nextInfoChoice : undefined;
      },
      showErrorMessage: async (message: string) => {
        calls.errors.push(message);
        return undefined;
      },
      showQuickPick: async (picks: unknown[]) => picks[0],
      showTextDocument: async () => ({}),
    },
    workspace: {
      isTrusted: env.trusted ?? true,
      workspaceFolders: (env.folders ?? []).map((p) => ({ uri: { fsPath: p } })),
      getConfiguration: (section?: string) => lookup(section),
      onDidChangeConfiguration: () => ({ dispose() {} }),
      onDidGrantWorkspaceTrust: () => ({ dispose() {} }),
      onDidChangeWorkspaceFolders: () => ({ dispose() {} }),
      openTextDocument: async (opts: unknown) => opts,
    },
    commands: {
      registerCommand: (name: string, fn: (...args: unknown[]) => unknown) => {
        commands.set(name, fn);
        return { dispose() {} };
      },
      executeCommand: async (name: string) => {
        calls.executed.push(name);
      },
    },
  };
  return {
    vscode,
    items,
    /** The main status item — the first one the extension creates. */
    get item() {
      return items[0]!;
    },
    /** The hold badge — the second. */
    get badge() {
      return items[1]!;
    },
    calls,
    commands,
    choose(choice: string | undefined) {
      nextChoice = choice;
    },
    chooseInfo(choice: string | undefined) {
      nextInfoChoice = choice;
    },
  };
}

/** A `process` the extension sees — platform and env are what it reads. */
function fakeProcess(over: { platform?: string; env?: Record<string, string> } = {}) {
  return { platform: over.platform ?? process.platform, env: over.env ?? process.env, pid: process.pid };
}

function loadExtension(stub: Stub, proc: ReturnType<typeof fakeProcess> = fakeProcess()) {
  const realRequire = createRequire(EXT_JS);
  const module = { exports: {} as Record<string, unknown> };
  runInNewContext(
    readFileSync(EXT_JS, "utf8"),
    {
      require: (name: string) => (name === "vscode" ? stub.vscode : realRequire(name)),
      module,
      exports: module.exports,
      console,
      process: proc,
      setInterval: () => 0,
      clearInterval: () => {},
      setTimeout: () => 0,
      clearTimeout: () => {},
      Date,
      JSON,
      Promise,
      String,
      Number,
      Boolean,
      Object,
      Array,
      Set,
      Map,
      Error,
      __dirname: EXT_DIR,
      __filename: EXT_JS,
    },
    { filename: EXT_JS },
  );
  return module.exports as { activate(ctx: { subscriptions: { dispose?(): void }[] }): void; deactivate(): void };
}

let dir: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "doorman-vscode-ext-"));
  mkdirSync(join(dir, "doorman", "editor"), { recursive: true });
  mkdirSync(join(dir, "doorman", "guard", "pending"), { recursive: true });
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

const writeStatus = (status: Record<string, unknown>) =>
  writeFileSync(join(dir, "doorman", "editor", "status.json"), JSON.stringify(status));

const writeRequest = (request: Record<string, unknown>) =>
  writeFileSync(join(dir, "doorman", "guard", "pending", `${request.id}.json`), JSON.stringify(request));

const pendingFiles = () => readdirSync(join(dir, "doorman", "guard", "pending"));
const windowsDir = () => join(dir, "doorman", "editor", "windows");
const windowReports = () => (existsSync(windowsDir()) ? readdirSync(windowsDir()) : []);
const readWindowReport = () => JSON.parse(readFileSync(join(windowsDir(), windowReports()[0]!), "utf8")) as Record<string, unknown>;

function activate(config: Record<string, unknown> = {}, env: Parameters<typeof makeVscodeStub>[1] = {}) {
  const stub = makeVscodeStub({ "doorman.userDataPath": dir, ...config }, env);
  const ext = loadExtension(stub);
  const ctx = { subscriptions: [] as { dispose?(): void }[] };
  ext.activate(ctx);
  return { ...stub, item: stub.item, badge: stub.badge, dispose: () => ctx.subscriptions.forEach((s) => s.dispose?.()) };
}

describe("the status bar", () => {
  it("shows today's tokens and the armed guard", () => {
    writeStatus({
      at: new Date().toISOString(),
      guard: { armed: true, hosts: 3 },
      tokens_today: "12.3k",
      live_sessions: 2,
      open_findings: 1,
      app_version: "0.57.0",
    });
    const stub = activate();
    expect(stub.item.shown).toBe(true);
    // The mark and the count of open detections — the app's own "things to
    // decide" number — in the bar; usage and the guard's state in the tooltip.
    expect(stub.item.text).toBe("$(doorman-mark) 1");
    const tip = String((stub.item.tooltip as { value: string }).value);
    expect(tip).toContain("1 open detection to review");
    expect(tip).toContain("armed across 3 agents");
    expect(tip).toContain("Today: 12.3k tokens");
    // Tokens, never dollars.
    expect(tip).not.toMatch(/\$\d/);
    expect(stub.item.color).toBeUndefined();
  });

  it("shows the mark alone when there is nothing to decide", () => {
    writeStatus({ at: new Date().toISOString(), guard: { armed: true, hosts: 1 }, live_sessions: 0, open_findings: 0, app_version: "1" });
    expect(activate().item.text).toBe("$(doorman-mark)");
  });

  it("says the app isn't running rather than showing a stale number as live", () => {
    writeStatus({
      at: new Date(Date.now() - 10 * 60_000).toISOString(),
      guard: { armed: true, hosts: 1 },
      tokens_today: "9.9k",
      live_sessions: 0,
      open_findings: 7,
      app_version: "0.57.0",
    });
    const stub = activate();
    expect(stub.item.text).toBe("$(doorman-mark)"); // no stale count as if live
    expect((stub.item.color as { id: string }).id).toBe("disabledForeground");
    expect(String((stub.item.tooltip as { value: string }).value)).toContain("isn't running");
  });

  it("marks an unarmed guard, and hides itself when turned off or when there is no file", () => {
    writeStatus({ at: new Date().toISOString(), guard: { armed: false, hosts: 0 }, live_sessions: 0, open_findings: 0, app_version: "0" });
    expect(activate().item.backgroundColor).toBeDefined();
    expect(activate({ "doorman.statusBar": false }).item.shown).toBe(false);
    rmSync(join(dir, "doorman", "editor", "status.json"));
    expect(activate().item.shown).toBe(false);
  });

  it("nudges for a window reload once the app — and so the installed extension — is a newer version", async () => {
    const own = JSON.parse(readFileSync(join(EXT_DIR, "package.json"), "utf8")).version as string;
    const status = { at: new Date().toISOString(), guard: { armed: true, hosts: 1 }, live_sessions: 0, open_findings: 0 };
    // Same version: nothing to say.
    writeStatus({ ...status, app_version: own });
    expect(activate().calls.infos).toEqual([]);
    // A newer app wrote the file: the running code is the old copy.
    writeStatus({ ...status, app_version: "99.0.0" });
    const stub = makeVscodeStub({ "doorman.userDataPath": dir });
    stub.chooseInfo("Reload Window");
    loadExtension(stub).activate({ subscriptions: [] });
    await new Promise((r) => setTimeout(r, 0));
    expect(stub.calls.infos.at(-1)).toMatch(/updated to 99\.0\.0.*Reload/);
    expect(stub.calls.executed).toEqual(["workbench.action.reloadWindow"]);
    // A stale file is a stopped app, not an update.
    writeStatus({ ...status, at: new Date(Date.now() - 10 * 60_000).toISOString(), app_version: "99.0.0" });
    expect(activate().calls.infos).toEqual([]);
  });
});

describe("finding the app's data on each platform", () => {
  const status = { at: new Date().toISOString(), guard: { armed: true, hosts: 1 }, tokens_today: "1.0k", live_sessions: 0, open_findings: 0, app_version: "1" };

  /** No `doorman.userDataPath`: the extension must find `<platform default>/Doorman`. */
  const activateOn = (platform: string, env: Record<string, string>) => {
    const stub = makeVscodeStub({});
    loadExtension(stub, fakeProcess({ platform, env })).activate({ subscriptions: [] });
    return stub;
  };

  it("reads %APPDATA%\\Doorman on Windows and $XDG_CONFIG_HOME/Doorman on Linux", () => {
    // Make the temp dir BE the platform's config root, holding an Doorman/.
    const root = mkdtempSync(join(tmpdir(), "doorman-platform-"));
    mkdirSync(join(root, "Doorman", "doorman", "editor"), { recursive: true });
    writeFileSync(join(root, "Doorman", "doorman", "editor", "status.json"), JSON.stringify(status));
    try {
      const tip = (stub: Stub) => String((stub.item.tooltip as { value: string }).value);
      expect(tip(activateOn("win32", { APPDATA: root }))).toContain("1.0k tokens");
      expect(tip(activateOn("linux", { XDG_CONFIG_HOME: root }))).toContain("1.0k tokens");
      // And an unrelated root finds nothing, rather than someone else's file.
      expect(activateOn("linux", { XDG_CONFIG_HOME: dir }).item.shown).toBe(false);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("opens the app where the app said it is, and only guesses a location on macOS", async () => {
    writeStatus({ ...status, app_path: "/opt/Doorman/doorman" });
    const told = activate();
    await told.commands.get("doorman.open")!();
    expect(told.calls.opened).toEqual(["/opt/Doorman/doorman"]);

    writeStatus(status);
    const mac = makeVscodeStub({ "doorman.userDataPath": dir });
    loadExtension(mac, fakeProcess({ platform: "darwin" })).activate({ subscriptions: [] });
    await mac.commands.get("doorman.open")!();
    expect(mac.calls.opened).toEqual(["/Applications/Doorman.app"]);

    const linux = makeVscodeStub({ "doorman.userDataPath": dir });
    loadExtension(linux, fakeProcess({ platform: "linux" })).activate({ subscriptions: [] });
    await linux.commands.get("doorman.open")!();
    expect(linux.calls.opened).toEqual([]);
    expect(linux.calls.warnings.at(-1)?.message).toMatch(/Couldn't find Doorman/);
  });
});

describe("answering a held tool call", () => {
  const request = (over: Record<string, unknown> = {}) => ({
    id: "hold-1",
    at: new Date().toISOString(),
    source: "claude-code",
    tool_name: "Bash",
    target: "curl example.com",
    reason: "a credential was about to leave this machine",
    preview: "curl -H 'authorization: ***'",
    detectors: ["credentials"],
    hold_seconds: 60,
    on_timeout: "deny",
    pid: process.pid,
    ...over,
  });

  it("writes an answer file — never the reply the guard is waiting on", async () => {
    writeRequest(request());
    const stub = activate();
    stub.choose("Allow");
    await stub.commands.get("doorman.pending")!();
    const files = pendingFiles();
    expect(files).toContain("hold-1.answer.json");
    // The app owns the verdict's consequences (policy, finding, spool line),
    // so the extension must NOT short-circuit to a reply.
    expect(files).not.toContain("hold-1.reply.json");
    const answer = JSON.parse(readFileSync(join(dir, "doorman", "guard", "pending", "hold-1.answer.json"), "utf8"));
    expect(answer).toMatchObject({ id: "hold-1", verdict: "allow" });
  });

  it("records a deny the same way", async () => {
    writeRequest(request());
    const stub = activate();
    stub.choose("Deny");
    await stub.commands.get("doorman.pending")!();
    const answer = JSON.parse(readFileSync(join(dir, "doorman", "guard", "pending", "hold-1.answer.json"), "utf8"));
    expect(answer.verdict).toBe("deny");
  });

  it("writes nothing when the notification is dismissed", async () => {
    writeRequest(request());
    const stub = activate();
    stub.choose(undefined);
    await stub.commands.get("doorman.pending")!();
    expect(pendingFiles()).toEqual(["hold-1.json"]);
  });

  it("names the tool and the reason, so the question is answerable without switching apps", async () => {
    writeRequest(request());
    const stub = activate();
    stub.choose(undefined);
    await stub.commands.get("doorman.pending")!();
    expect(stub.calls.warnings[0]!.message).toContain("Bash");
    expect(stub.calls.warnings[0]!.message).toContain("a credential was about to leave");
    expect(stub.calls.warnings[0]!.items).toEqual(["Allow", "Deny", "Details"]);
  });

  it("asks the moment it activates with a hold pending, and lights a badge that outlives the toast", () => {
    writeRequest(request());
    const stub = activate();
    // Asked once at activation — not only when someone runs the command.
    expect(stub.calls.warnings).toHaveLength(1);
    expect(stub.calls.warnings[0]!.options?.modal).toBeFalsy();
    expect(stub.badge.shown).toBe(true);
    expect(stub.badge.text).toContain("1 held");
    expect(stub.badge.command).toBe("doorman.pending");
    expect((stub.badge.backgroundColor as { id: string }).id).toBe("statusBarItem.errorBackground");
  });

  it("is modal for a critical hold — the one case worth interrupting for", () => {
    writeRequest(request({ max_severity: "critical" }));
    const stub = activate();
    expect(stub.calls.warnings[0]!.options).toEqual({ modal: true });
  });

  it("re-asks on demand after the activation toast was dismissed", async () => {
    writeRequest(request());
    const stub = activate();
    stub.choose(undefined);
    // Review held tool calls is an explicit request: it prompts even for a call
    // whose toast the person already dismissed.
    await stub.commands.get("doorman.pending")!();
    expect(stub.calls.warnings).toHaveLength(2); // activation + the explicit command
    expect(pendingFiles()).toEqual(["hold-1.json"]);
  });

  it("shows no badge and asks nothing when nothing is held", () => {
    const stub = activate();
    expect(stub.badge.shown).toBe(false);
    expect(stub.calls.warnings).toEqual([]);
  });

  it("ignores a call that has already been answered or withdrawn", async () => {
    writeRequest(request());
    writeFileSync(join(dir, "doorman", "guard", "pending", "hold-1.reply.json"), "{}");
    const stub = activate();
    stub.choose("Allow");
    await stub.commands.get("doorman.pending")!();
    expect(stub.calls.infos.join(" ")).toContain("Nothing is being held");
    expect(stub.badge.shown).toBe(false);
  });

  it("says nothing at all when asking in the editor is switched off — but still shows the badge", () => {
    writeRequest(request());
    const stub = activate({ "doorman.askInEditor": false });
    expect(stub.calls.warnings).toEqual([]);
    expect(stub.badge.shown).toBe(true);
  });
});

/**
 * A click on the status bar brings something to the screen: the
 * held calls here, or the app itself on the screen that matters.
 */
describe("clicking the status bar", () => {
  const status = (open: number) => ({ at: new Date().toISOString(), guard: { armed: true, hosts: 1 }, live_sessions: 0, open_findings: open, app_version: "1", app_path: "/Applications/Doorman.app" });
  const intent = () => JSON.parse(readFileSync(join(dir, "doorman", "editor", "open.json"), "utf8")) as { screen: string; at: string };

  it("is what the status item runs", () => {
    writeStatus(status(0));
    expect(activate().item.command).toBe("doorman.review");
  });

  it("asks the app to come to the front on the Radar when there are detections, and opens the app", async () => {
    writeStatus(status(3));
    const stub = activate();
    await stub.commands.get("doorman.review")!();
    expect(intent().screen).toBe("radar");
    expect(Date.parse(intent().at)).toBeGreaterThan(Date.now() - 5_000);
    expect(stub.calls.opened).toEqual(["/Applications/Doorman.app"]);
    expect(stub.calls.executed).toEqual([]); // nothing held → no picker
  });

  it("lands on the Overview when there is nothing to review", async () => {
    writeStatus(status(0));
    const stub = activate();
    await stub.commands.get("doorman.review")!();
    expect(intent().screen).toBe("overview");
  });

  it("reviews the held calls here instead, when there are any", async () => {
    writeStatus(status(3));
    writeRequest({ id: "hold-2", at: new Date().toISOString(), tool_name: "Bash", reason: "r", pid: process.pid });
    const stub = activate();
    await stub.commands.get("doorman.review")!();
    expect(stub.calls.executed).toEqual(["doorman.pending"]);
    expect(existsSync(join(dir, "doorman", "editor", "open.json"))).toBe(false);
    expect(stub.calls.opened).toEqual([]);
  });
});

/**
 * The third file of the contract: what only the editor knows about
 * this window, written for the app's setup doctor.
 */
describe("reporting this window to the app", () => {
  it("writes trust, folders and the EFFECTIVE chat settings under its session id", () => {
    const stub = activate({ "chat.useHooks": false, "chat.hookFilesLocations": { "~/.copilot/hooks": false }, "chat.mcp.access": "none" }, {
      trusted: false,
      folders: ["/Users/t/repos/app"],
      appName: "Visual Studio Code - Insiders",
    });
    expect(windowReports()).toEqual(["session-abc_123.json"]); // the id, made filename-safe
    const report = readWindowReport();
    expect(report).toMatchObject({
      id: "session-abc/123",
      app_name: "Visual Studio Code - Insiders",
      version: "1.138.0",
      trusted: false,
      folders: ["/Users/t/repos/app"],
      hooks_enabled: false,
      copilot_hooks_location_enabled: false,
      mcp_access: "none",
    });
    expect(Date.parse(String(report["at"]))).toBeGreaterThan(Date.now() - 5_000);
    // The status command tells the person too — this window is unguarded.
    writeStatus({ at: new Date().toISOString(), guard: { armed: true, hosts: 1 }, live_sessions: 0, open_findings: 0, app_version: "1" });
    stub.commands.get("doorman.status")!();
    expect(stub.calls.infos.at(-1)).toMatch(/Restricted Mode/);
  });

  it("reads VS Code's defaults as ON when nothing is configured", () => {
    activate();
    expect(readWindowReport()).toMatchObject({ trusted: true, folders: [], hooks_enabled: true, copilot_hooks_location_enabled: true });
  });

  it("removes its report on deactivate, so a closed window never reads as open", () => {
    const stub = activate();
    expect(windowReports()).toHaveLength(1);
    stub.dispose();
    expect(windowReports()).toEqual([]);
  });

  it("copes with an app that has never run — no directory, nothing to report to", () => {
    rmSync(join(dir, "doorman"), { recursive: true, force: true });
    // Creates the directory rather than failing: the app reads it on its first
    // run and the report is already there.
    expect(() => activate()).not.toThrow();
    expect(windowReports()).toHaveLength(1);
  });
});

/**
 * The packaged artefact, built and driven through the REAL editor CLI. The
 * .vsix is hand-rolled (scripts/build-vsix.mjs) rather than produced by `vsce`,
 * so "does VS Code actually accept it" is a question only an install can
 * answer — and it is the question the whole Tier-3 surface rests on.
 */
const CODE_CLI = "/Applications/Visual Studio Code.app/Contents/Resources/app/bin/code";
const DESKTOP = join(here, "..");
describe.skipIf(!existsSync(CODE_CLI))("the packaged .vsix, against the installed VS Code", () => {
  it("builds, installs, lists and uninstalls", () => {
    execFileSync("node", [join(DESKTOP, "scripts", "build-vsix.mjs")], { cwd: DESKTOP, stdio: "ignore" });
    const vsix = join(DESKTOP, "build", "vscode", "doorman.vsix");
    expect(existsSync(vsix)).toBe(true);
    // Six members, the icon among them — the mark is what the Extensions view
    // shows, and a `.vsix` without it renders a grey placeholder.
    const listing = execFileSync("unzip", ["-Z1", vsix], { encoding: "utf8" }).trim().split("\n").sort();
    expect(listing).toEqual(
      ["[Content_Types].xml", "extension.vsixmanifest", "extension/README.md", "extension/extension.js", "extension/icon.png", "extension/doorman-icons.woff", "extension/package.json"].sort(),
    );
    const version = JSON.parse(readFileSync(join(DESKTOP, "package.json"), "utf8")).version as string;
    // An isolated extensions directory, so this test never touches the
    // extensions the person actually has installed.
    const extDir = mkdtempSync(join(tmpdir(), "doorman-vsix-"));
    const run = (args: string[]) =>
      execFileSync(CODE_CLI, [...args, "--extensions-dir", extDir], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] });
    try {
      run(["--install-extension", vsix, "--force"]);
      expect(run(["--list-extensions", "--show-versions"])).toContain(`pinata.doorman@${version}`);
      run(["--uninstall-extension", "pinata.doorman"]);
      expect(run(["--list-extensions"])).not.toContain("pinata.doorman");
    } finally {
      rmSync(extDir, { recursive: true, force: true });
    }
  }, 180_000);
});
