/**
 * Doorman for VS Code — a display surface for the Doorman app, a second
 * place to answer it, and the one witness to what this window will actually do.
 *
 * Everything this extension knows, it reads from files the app writes under
 * its own data directory (`~/Library/Application Support/Doorman/doorman/`
 * on macOS, `%APPDATA%\Doorman\…` on Windows, `~/.config/Doorman/…` on
 * Linux). It opens no socket, makes no network request, and reads nothing
 * from the workspace — so it works in an untrusted window and there is
 * nothing to configure.
 *
 * Three jobs:
 *
 *  1. STATUS. `editor/status.json` (written by the app on every state change)
 *     becomes one status-bar item: today's spend and whether the guard is
 *     armed. A file older than STALE_MS means the app is not running, and the
 *     item says so instead of showing a stale number as if it were live.
 *
 *  2. ASKING. When the guard holds an agent's tool call it writes
 *     `guard/pending/<id>.json` and blocks. The app raises its own window; this
 *     extension raises the same question here, where the person's hands already
 *     are — as a notification, AND as a second status-bar item that stays lit
 *     until the call is decided, because VS Code hides a notification after a
 *     few seconds while the guard waits a minute. A dismissed notification is
 *     asked again while the request is still pending; a critical hold is modal.
 *     A choice writes `guard/pending/<id>.answer.json` — NOT the
 *     `<id>.reply.json` the guard is waiting on, which is deliberately still
 *     the app's to write (see main/lib/vscode-ext.ts): the app owns the policy
 *     write, the finding's resolution and the spool line that go with a
 *     verdict, so a decision made here is recorded exactly like one made there.
 *
 *  3. REPORTING THIS WINDOW. `editor/windows/<sessionId>.json` — whether this
 *     window is trusted (Restricted Mode runs the agent with NO hooks, ours
 *     included), its folders, and the EFFECTIVE values of the chat settings
 *     that decide whether hooks load, after any enterprise policy. The app's
 *     setup doctor can infer the first from the trusted-folder list and cannot
 *     see the second at all; this file is the truth for an open window.
 *     Rewritten on every change and every 10 s as a heartbeat; removed on
 *     deactivate; the app ignores one that has gone quiet.
 *
 * The pending directory is polled once a second AND watched: `fs.watch` on
 * macOS coalesces a burst of creates and deletes into something unreliable, so
 * the watch is the fast path and the poll is the floor. Against a directory
 * that is almost always empty, a `readdir` a second is cheaper than being wrong.
 *
 * Written as plain CommonJS with no dependencies: it is packaged by
 * scripts/build-vsix.mjs, which copies this file verbatim. There is
 * no build step to go stale.
 */

const vscode = require("vscode");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

/** A status file older than this means the app isn't running. The app writes
 * its guard heartbeat every 15s; this is the same tolerance. */
const STALE_MS = 45_000;
const STATUS_POLL_MS = 10_000;
const PENDING_POLL_MS = 1_000;
/** A request older than this was written before this window was even open —
 * the guard has long since timed out, and asking about it would be noise. */
const REQUEST_MAX_AGE_MS = 5 * 60_000;
/** A dismissed notification comes back after this while the hold is pending. */
const REASK_MS = 15_000;
/** Debounce for the pending-directory watch: a hold is a create plus, a moment
 * later, the app's own files beside it. */
const WATCH_DEBOUNCE_MS = 50;

/** The exact key VS Code uses for our hook directory in `chat.hookFilesLocations`. */
const COPILOT_HOOKS_LOCATION = "~/.copilot/hooks";

/**
 * Where the app keeps its data, per platform — Electron's `userData` for a
 * product named Doorman. The setting overrides this; an unset one on an
 * unknown platform simply finds no files.
 */
function defaultUserData() {
  const home = os.homedir();
  switch (process.platform) {
    case "darwin":
      return path.join(home, "Library", "Application Support", "Doorman");
    case "win32":
      return path.join(process.env.APPDATA || path.join(home, "AppData", "Roaming"), "Doorman");
    default:
      return path.join(process.env.XDG_CONFIG_HOME || path.join(home, ".config"), "Doorman");
  }
}

function userDataDir() {
  const configured = vscode.workspace.getConfiguration("doorman").get("userDataPath");
  const trimmed = typeof configured === "string" ? configured.trim() : "";
  return trimmed !== "" ? trimmed.replace(/^~(?=\/|$)/, os.homedir()) : defaultUserData();
}

const appDir = () => path.join(userDataDir(), "doorman");
const statusFile = () => path.join(appDir(), "editor", "status.json");
const windowsDir = () => path.join(appDir(), "editor", "windows");
const pendingDir = () => path.join(appDir(), "guard", "pending");

function readJson(file) {
  try {
    return JSON.parse(fs.readFileSync(file, "utf8"));
  } catch {
    // Missing, half-written, or not ours. Every caller treats undefined as
    // "nothing to show", which is the honest reading of all three.
    return undefined;
  }
}

function freshness(at) {
  const ms = Date.parse(at || "");
  return Number.isFinite(ms) ? Date.now() - ms : Number.POSITIVE_INFINITY;
}

/** Where "Open the app" goes: what the app said about itself, else the
 * platform's usual place. Only macOS has a usual place worth guessing. */
function appLocation(status) {
  if (status && typeof status.app_path === "string" && status.app_path !== "") return status.app_path;
  return process.platform === "darwin" ? "/Applications/Doorman.app" : undefined;
}

// ---- status bar ---------------------------------------------------------------

class StatusBar {
  constructor() {
    this.item = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
    // A click brings something to the screen: the held calls here if any are
    // waiting, otherwise the app itself on the screen that matters.
    this.item.command = "doorman.review";
    // The hold badge sits LEFT of the status item and stays lit while a call
    // is pending: a notification can be dismissed or missed, this cannot.
    this.holdItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 101);
    this.holdItem.command = "doorman.pending";
    this.holdItem.backgroundColor = new vscode.ThemeColor("statusBarItem.errorBackground");
    this.status = undefined;
  }

  refresh() {
    const show = vscode.workspace.getConfiguration("doorman").get("statusBar") !== false;
    const status = readJson(statusFile());
    this.status = status;
    if (!show || !status) {
      this.item.hide();
      return;
    }
    const stale = freshness(status.at) > STALE_MS;
    const armed = status.guard && status.guard.armed;
    // The Doorman mark (a glyph this extension contributes — package.json
    // `contributes.icons`, drawn by scripts/make-icon-font.py) and the
    // number of open detections beside it: the same "things to decide" count
    // the app's Radar badge and menu bar carry, so the editor never disagrees
    // with the app. Nothing to decide → the mark alone. Spend, guard state and
    // running agents live in the tooltip.
    const open = Number(status.open_findings) || 0;
    const tokens = status.tokens_today;
    this.item.text = stale || open === 0 ? "$(doorman-mark)" : `$(doorman-mark) ${open}`;
    const lines = stale
      ? ["Doorman isn't running — this is the last state it wrote."]
      : [
          `${open} open detection${open === 1 ? "" : "s"} to review.`,
          armed ? `Security Guard armed across ${status.guard.hosts} agent${status.guard.hosts === 1 ? "" : "s"}.` : "Security Guard is off — rules only watch.",
          tokens ? `Today: ${tokens} tokens` : "Today's usage isn't known yet.",
          `${status.live_sessions || 0} agent${status.live_sessions === 1 ? "" : "s"} running`,
        ];
    const tip = new vscode.MarkdownString(lines.join("\n\n"));
    this.item.tooltip = tip;
    // Greyed when the app isn't running; the warning background is still the
    // one visual for "the guard is off", which is the state worth a glance.
    this.item.color = stale ? new vscode.ThemeColor("disabledForeground") : undefined;
    this.item.backgroundColor = stale || armed ? undefined : new vscode.ThemeColor("statusBarItem.warningBackground");
    this.item.show();
  }

  /** How many calls are waiting right now; 0 hides the badge. */
  setHeld(count) {
    if (count <= 0) {
      this.holdItem.hide();
      return;
    }
    this.holdItem.text = `$(bell-dot) ${count} held`;
    this.holdItem.tooltip = `Doorman is holding ${count} agent tool call${count === 1 ? "" : "s"} for your decision — click to review.`;
    this.holdItem.show();
  }

  dispose() {
    this.item.dispose();
    this.holdItem.dispose();
  }
}

// ---- held tool calls ----------------------------------------------------------

/**
 * One notification per held call at a time. `asked` remembers when each id
 * was last put on screen: a request whose file is still there after the
 * person dismissed the notification comes back after REASK_MS — not every
 * second, and not never.
 */
class Holds {
  constructor(log, onCount) {
    this.asked = new Map();
    this.log = log;
    this.onCount = onCount;
  }

  /** Requests waiting for an answer right now. */
  list() {
    const dir = pendingDir();
    let names;
    try {
      names = fs.readdirSync(dir);
    } catch {
      return [];
    }
    const out = [];
    for (const name of names) {
      if (!name.endsWith(".json") || name.endsWith(".reply.json") || name.endsWith(".answer.json")) continue;
      const request = readJson(path.join(dir, name));
      if (!request || typeof request.id !== "string") continue;
      // Already decided (by the app's window, or by us a moment ago).
      if (fs.existsSync(path.join(dir, `${request.id}.reply.json`))) continue;
      if (fs.existsSync(path.join(dir, `${request.id}.answer.json`))) continue;
      out.push(request);
    }
    return out;
  }

  answer(request, verdict) {
    const file = path.join(pendingDir(), `${request.id}.answer.json`);
    const body = { id: request.id, verdict, at: new Date().toISOString() };
    try {
      fs.writeFileSync(file, `${JSON.stringify(body)}\n`);
    } catch (err) {
      // The guard is still blocked and the app's own window is still up, so a
      // failure here costs nothing but this surface.
      this.log(`could not write the answer for ${request.id}: ${String(err)}`);
      void vscode.window.showErrorMessage("Doorman couldn't record that decision here — answer it in the app's window.");
    }
  }

  describe(request) {
    const what = request.tool_name ? `${request.tool_name}` : "a tool call";
    const where = request.target ? ` on ${request.target}` : "";
    return `Doorman held ${what}${where}: ${request.reason || "a rule matched."}`;
  }

  /** Ask about anything new or dismissed-and-still-pending; keep the badge
   * current. Fresh requests only — an old file is one the guard stopped
   * waiting on long ago. */
  tick() {
    const waiting = this.list().filter((request) => freshness(request.at) <= REQUEST_MAX_AGE_MS);
    this.onCount(waiting.length);
    const live = new Set(waiting.map((r) => r.id));
    for (const id of [...this.asked.keys()]) if (!live.has(id)) this.asked.delete(id);
    if (vscode.workspace.getConfiguration("doorman").get("askInEditor") === false) return;
    const now = Date.now();
    for (const request of waiting) {
      const last = this.asked.get(request.id);
      if (last !== undefined && (last === Number.POSITIVE_INFINITY || now - last < REASK_MS)) continue;
      void this.prompt(request);
    }
  }

  async prompt(request) {
    // On screen: never re-ask while the notification is still up.
    this.asked.set(request.id, Number.POSITIVE_INFINITY);
    const critical = request.max_severity === "critical";
    const choice = await vscode.window.showWarningMessage(this.describe(request), { modal: critical }, "Allow", "Deny", "Details");
    if (choice === "Allow" || choice === "Deny") {
      this.answer(request, choice === "Allow" ? "allow" : "deny");
      return;
    }
    // Dismissed, or Details: eligible again after REASK_MS while still pending.
    // Details opens the document first — asking again after it is on screen is
    // the point of opening it.
    this.asked.set(request.id, Date.now() - (choice === "Details" ? REASK_MS : 0));
    if (choice === "Details") {
      const doc = await vscode.workspace.openTextDocument({
        language: "markdown",
        content: detailsMarkdown(request),
      });
      await vscode.window.showTextDocument(doc, { preview: true });
    }
  }
}

function detailsMarkdown(request) {
  const rows = [
    ["Agent", request.source],
    ["Tool", request.tool_name],
    ["Target", request.target],
    ["Working directory", request.cwd],
    ["Rules", Array.isArray(request.detectors) ? request.detectors.join(", ") : undefined],
    ["Severity", request.max_severity],
    ["Held at", request.at],
  ].filter(([, v]) => v !== undefined && v !== "");
  return [
    `# Held tool call`,
    "",
    request.reason || "",
    "",
    ...rows.map(([k, v]) => `- **${k}:** ${v}`),
    "",
    "## What the agent was about to do",
    "",
    "```",
    // The preview is redacted by the guard before it is written — the same
    // masking a finding's excerpt gets — so it is safe to put in a document.
    String(request.preview || "").slice(0, 2000),
    "```",
    "",
    "_Answer with the notification, or in the Doorman app._",
  ].join("\n");
}

// ---- keeping this window's copy current ----------------------------------------

/**
 * The app re-installs this extension into every VS Code build at every boot,
 * so an app update carries the editor's copy with it — but VS Code keeps
 * running the OLD code in every window that was open until that window
 * reloads. The status file carries the app's version, and the app's version IS
 * the extension's (build-vsix.mjs stamps it), so a mismatch between the two
 * means "a newer copy of me is installed, this window hasn't picked it up".
 * One nudge per app version, with the reload a click away.
 */
class UpdateNudge {
  constructor(ownVersion) {
    this.ownVersion = ownVersion;
    this.nudgedFor = undefined;
  }

  check(status) {
    if (!status || !this.ownVersion) return;
    if (freshness(status.at) > STALE_MS) return; // an old file says nothing about what is installed now
    const appVersion = status.app_version;
    if (typeof appVersion !== "string" || appVersion === "" || appVersion === this.ownVersion) return;
    if (this.nudgedFor === appVersion) return;
    this.nudgedFor = appVersion;
    void vscode.window
      .showInformationMessage(
        `Doorman updated to ${appVersion} — this window still runs its extension ${this.ownVersion}. Reload to finish the update.`,
        "Reload Window",
      )
      .then((choice) => {
        if (choice === "Reload Window") return vscode.commands.executeCommand("workbench.action.reloadWindow");
        return undefined;
      });
  }
}

/** This extension's own version: what the extension host loaded, which after
 * an app update is the OLD one until the window reloads. */
function ownVersion(context) {
  const fromHost = context && context.extension && context.extension.packageJSON && context.extension.packageJSON.version;
  if (typeof fromHost === "string") return fromHost;
  try {
    return require("./package.json").version;
  } catch {
    return undefined;
  }
}

// ---- this window, reported to the app ------------------------------------------

/**
 * What only the editor knows about this window. The values are the EFFECTIVE
 * ones — `getConfiguration().get()` after defaults, user, workspace and any
 * enterprise policy — which is the point: settings.json can say hooks are on
 * while a policy has them off, and nothing outside this process can tell.
 */
class WindowReport {
  constructor(log) {
    this.log = log;
    this.file = path.join(windowsDir(), `${sanitize(vscode.env.sessionId)}.json`);
  }

  body() {
    const chat = vscode.workspace.getConfiguration("chat");
    const locations = chat.get("hookFilesLocations");
    const folders = (vscode.workspace.workspaceFolders || []).map((f) => f.uri.fsPath);
    return {
      id: vscode.env.sessionId,
      at: new Date().toISOString(),
      app_name: vscode.env.appName,
      version: vscode.version,
      trusted: vscode.workspace.isTrusted,
      folders,
      hooks_enabled: chat.get("useHooks") !== false,
      copilot_hooks_location_enabled: !(locations && typeof locations === "object" && locations[COPILOT_HOOKS_LOCATION] === false),
      mcp_access: chat.get("mcp.access"),
    };
  }

  write() {
    try {
      fs.mkdirSync(path.dirname(this.file), { recursive: true });
      // Write-then-rename so the app never reads a half-written report.
      const tmp = `${this.file}.${process.pid}.tmp`;
      fs.writeFileSync(tmp, `${JSON.stringify(this.body())}\n`);
      fs.renameSync(tmp, this.file);
    } catch (err) {
      // The app's directory may not exist yet (never launched): nothing to
      // report to, and nothing lost — the next write retries.
      this.log(`could not write the window report: ${String(err)}`);
    }
  }

  dispose() {
    try {
      fs.rmSync(this.file, { force: true });
    } catch {
      // best effort; the app ignores a report that has gone quiet anyway
    }
  }
}

/** A session id is opaque; keep the file name to what every filesystem takes. */
function sanitize(id) {
  return String(id || "window").replace(/[^A-Za-z0-9._-]/g, "_").slice(0, 120);
}

// ---- activation ---------------------------------------------------------------

function activate(context) {
  const channel = vscode.window.createOutputChannel("Doorman");
  const log = (line) => channel.appendLine(`${new Date().toISOString()} ${line}`);

  const bar = new StatusBar();
  const holds = new Holds(log, (count) => bar.setHeld(count));
  const report = new WindowReport(log);
  const nudge = new UpdateNudge(ownVersion(context));
  // Every status read also asks "is a newer copy of me installed?".
  const refresh = () => {
    bar.refresh();
    nudge.check(bar.status);
  };
  refresh();
  holds.tick();
  report.write();

  const statusTimer = setInterval(() => {
    refresh();
    // The heartbeat: a report that stops refreshing is a window that closed
    // without deactivate running, and the app drops it after a minute.
    report.write();
  }, STATUS_POLL_MS);
  const pendingTimer = setInterval(() => holds.tick(), PENDING_POLL_MS);

  // A watch on the status file's directory turns the 10s poll into "within a
  // moment" while the app is running; the poll stays as the floor, because a
  // directory that doesn't exist yet cannot be watched at all.
  let statusWatcher;
  try {
    statusWatcher = fs.watch(path.dirname(statusFile()), () => refresh());
  } catch {
    statusWatcher = undefined;
  }

  // Same for the pending directory — the fast path for a hold. It is created
  // by the guard's first hold, so the watch is (re)attempted on every tick
  // until it takes; the one-second poll covers the gap.
  let pendingWatcher;
  let pendingDebounce;
  const watchPending = () => {
    if (pendingWatcher) return;
    try {
      pendingWatcher = fs.watch(pendingDir(), () => {
        clearTimeout(pendingDebounce);
        pendingDebounce = setTimeout(() => holds.tick(), WATCH_DEBOUNCE_MS);
      });
      pendingWatcher.on("error", () => {
        pendingWatcher.close();
        pendingWatcher = undefined;
      });
    } catch {
      pendingWatcher = undefined;
    }
  };
  watchPending();
  const watchTimer = setInterval(watchPending, PENDING_POLL_MS);

  context.subscriptions.push(
    bar,
    channel,
    report,
    { dispose: () => clearInterval(statusTimer) },
    { dispose: () => clearInterval(pendingTimer) },
    { dispose: () => clearInterval(watchTimer) },
    { dispose: () => clearTimeout(pendingDebounce) },
    { dispose: () => statusWatcher && statusWatcher.close() },
    { dispose: () => pendingWatcher && pendingWatcher.close() },
    vscode.workspace.onDidChangeConfiguration((e) => {
      if (e.affectsConfiguration("doorman")) refresh();
      if (e.affectsConfiguration("chat")) report.write();
    }),
    vscode.workspace.onDidGrantWorkspaceTrust(() => report.write()),
    vscode.workspace.onDidChangeWorkspaceFolders(() => report.write()),
    vscode.commands.registerCommand("doorman.open", async () => {
      // The app registers no URL scheme, so it is opened the way anything else
      // is: by the bundle or executable it told us about, or the usual place on
      // macOS. A machine without it gets the honest error, not a silent no-op.
      const location = appLocation(readJson(statusFile()));
      const opened = location ? await vscode.env.openExternal(vscode.Uri.file(location)) : false;
      if (!opened) {
        void vscode.window.showWarningMessage(
          location ? `Couldn't open Doorman at ${location}.` : "Couldn't find Doorman — start the app once, or set doorman.userDataPath.",
        );
      }
    }),
    vscode.commands.registerCommand("doorman.status", () => {
      const status = readJson(statusFile());
      if (!status) {
        void vscode.window.showInformationMessage("Doorman hasn't written any state here yet. Is the app running?");
        return;
      }
      const stale = freshness(status.at) > STALE_MS;
      const armed = status.guard && status.guard.armed;
      void vscode.window.showInformationMessage(
        [
          stale ? "Doorman isn't running." : armed ? "Security Guard is armed." : "Security Guard is off.",
          status.tokens_today ? `Today: ${status.tokens_today} tokens.` : null,
          `${status.live_sessions || 0} running, ${status.open_findings || 0} open findings.`,
          vscode.workspace.isTrusted ? null : "This window is in Restricted Mode — VS Code runs no hooks here, so the guard is not watching it.",
        ]
          .filter(Boolean)
          .join(" "),
      );
    }),
    vscode.commands.registerCommand("doorman.review", async () => {
      // Something to decide HERE wins: the held calls, answerable in place.
      if (holds.list().length > 0) {
        await vscode.commands.executeCommand("doorman.pending");
        return;
      }
      // Otherwise the app: on the Radar when there are detections to review,
      // on the Overview when there are not. The request is a file the app
      // watches (main/vscode-ext-install.ts watchEditorIntents) — it has no URL
      // scheme, and `open` alone only raises whatever screen it was on.
      const status = readJson(statusFile());
      const open = status ? Number(status.open_findings) || 0 : 0;
      const screen = open > 0 ? "radar" : "overview";
      try {
        fs.mkdirSync(path.dirname(statusFile()), { recursive: true });
        fs.writeFileSync(path.join(path.dirname(statusFile()), "open.json"), `${JSON.stringify({ screen, at: new Date().toISOString() })}\n`);
      } catch (err) {
        log(`could not write the open request: ${String(err)}`);
      }
      const running = status && freshness(status.at) <= STALE_MS;
      const location = appLocation(status);
      // A running app answers the file; a stopped one is launched and reads it
      // at boot. Either way the bundle is asked to come forward.
      const opened = location ? await vscode.env.openExternal(vscode.Uri.file(location)) : false;
      if (!opened && !running) {
        void vscode.window.showWarningMessage(
          location ? `Couldn't open Doorman at ${location}.` : "Couldn't find Doorman — start the app once, or set doorman.userDataPath.",
        );
      }
    }),
    vscode.commands.registerCommand("doorman.pending", async () => {
      const waiting = holds.list();
      if (waiting.length === 0) {
        void vscode.window.showInformationMessage("Nothing is being held right now.");
        return;
      }
      const picked = await vscode.window.showQuickPick(
        waiting.map((request) => ({ label: holds.describe(request), description: request.source || "", request })),
        { placeHolder: "Held tool calls waiting for a decision" },
      );
      if (picked) await holds.prompt(picked.request);
    }),
  );

  log(`watching ${appDir()} · reporting ${report.file}`);
}

function deactivate() {}

module.exports = { activate, deactivate };
