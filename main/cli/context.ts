import { spawn } from "node:child_process";
import { cpSync, existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import { CaptureEngine } from "../capture.js";
import { guardDir, readArmedSessions, writeArmedSessions } from "../enforcement.js";
import { heartbeatFresh, heartbeatPath, pidAlive } from "../guard/handshake.js";
import type { GuardPolicy } from "../guard/policy.js";
import { codexHomeDir } from "../lib/codex-rollout.js";
import { appOwner, liveLock, releaseLock, takeLock } from "../lib/data-owner.js";
import { drainImports, type ImportOutcome } from "../lib/sandbox-import.js";
import { doormanDataDir } from "../lib/data-dir.js";
import type { FindingRow } from "../lib/findings.js";
import type { InjectionClassifier } from "../lib/injection-classifier.js";
import { livePolicy } from "../lib/live-policy.js";
import type { FetchLike } from "../lib/model-assets.js";
import { readPrefsFile, writePrefsFile } from "../lib/prefs-file.js";
import { Store, type Prefs } from "../state.js";
import { loadClassifier, modelPlan } from "./classifier.js";
import { processLabel } from "./docker-sandbox.js";
import { CliError, type Styles } from "./output.js";
import { startProgress, withPolledProgress } from "./progress.js";
import { Ui, plural } from "./ui.js";
import type { NpmRunner } from "./commands/update.js";

export interface CliEnvironment {
  env: NodeJS.ProcessEnv;
  home: string;
  platform: NodeJS.Platform;
  /** The CLI package's version, reported as `appVersion` in what it writes. */
  version: string;
  stdout: NodeJS.WritableStream & { isTTY?: boolean; columns?: number };
  stderr: NodeJS.WritableStream & { isTTY?: boolean; columns?: number };
  stdin: NodeJS.ReadableStream & { isTTY?: boolean };
  now(): number;
  verbose: boolean;
  /** Start `doorman <args>` detached from this process, returning its pid
   * (the background model download). Absent = never start one: tests. */
  spawnDetached?(args: readonly string[]): number | undefined;
  /** What model downloads and the update check fetch with; absent = the global fetch. */
  fetch?: FetchLike;
  /** The npm package this CLI is (its update check asks the registry about
   * it); absent = `@pinata/doorman`. */
  packageName?: string;
  /** The directory the package is installed in; absent = beside build/main. */
  packageDir?: string;
  /** Runs npm for `doorman update`; absent = the real npm. */
  runNpm?: NpmRunner;
}

/** Whoever answers held calls right now: the desktop app, or `doorman watch`
 * (`stdio`: a `doorman watch --stdio`, answering for `doorman sbx watch` on the host). */
export interface RunningDoorman {
  pid?: number;
  version?: string;
  stdio?: true;
}

/** What a change touches, so that it waits only for whoever owns that.
 *  · `data` — the store and everything else (the default): refused while any
 *    other Doorman owns the data — the app, starting or running, or
 *    `doorman watch`.
 *  · `settings` — prefs, the guard's policy and agent configs, never the
 *    store: refused while the app owns the data (it holds the prefs in memory
 *    and would write over them), allowed while a `doorman watch` runs, which
 *    takes the writer lock around each of its own prefs writes and reads the
 *    file afresh under it (`underWriterLock`).
 *  · `config` — agent config files and the build-stamped bundles they point
 *    at, nothing the app keeps in memory: allowed whoever runs (the app's MCP
 *    config watcher follows the file). Still one CLI writer at a time. */
export type WriteScope = "data" | "settings" | "config";

const SCOPE_RANK: Record<WriteScope, number> = { config: 0, settings: 1, data: 2 };

/** How long `doorman watch` waits for a settings command to finish before it
 * writes its own answer anyway — such a command holds the lock for
 * milliseconds, and an answer must never be lost to it. */
const WATCH_LOCK_WAIT_MS = 5_000;

function sleepSync(ms: number): void {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

/** A heartbeat written by `doorman watch` (its version is `cli-<version>`), not the app. */
function isCliWatch(owner: RunningDoorman): boolean {
  return owner.version?.startsWith("cli-") === true;
}

export interface EngineHandle {
  engine: CaptureEngine;
  /** True when another Doorman (the app, `watch`, or another command) owned the
   * data, so the engine works on a copy of the store. */
  snapshot: boolean;
  /** Rows minted by this command's scan (empty with `scan: false`). */
  newFindings: FindingRow[];
  /** What this open took in from the sandbox drop folder (`doorman sbx
   * pull`, lib/sandbox-import.ts): ingested into the store, or — on a copy —
   * into the copy only, the files left for the owner. */
  imported: ImportOutcome[];
  close(): void;
}

/**
 * Everything a command reads and writes, resolved once per invocation.
 *
 * The CLI shares the desktop app's data directory — one store, one prefs file,
 * one guard bundle and policy — so the two never disagree about what was found
 * or what is enforced. They must not both WRITE at once: whoever holds the
 * guard heartbeat (the app, or `doorman watch`) owns the store, and so does
 * an app that is still starting (lib/data-owner.ts). While it runs, read
 * commands work on a temporary copy of the store and commands that change
 * what it owns refuse (`requireWritable`, by WriteScope: the app owns prefs
 * too, a `doorman watch` only the store).
 *
 * A command that writes first takes the CLI writer lock and only then checks
 * for the app — the app marks itself first and then waits for that lock — so
 * the two never write at once, whichever starts first. Two CLI commands don't
 * either: the second works on a copy, or refuses a change, until the first ends.
 * `doorman watch` owns the store through its own lock (`requireWatch`), which
 * the app waits for too, and takes the writer lock only around its writes.
 */
export class CliContext {
  readonly dataDir: string;
  /** How stdout is drawn (ui.ts): decorated on a terminal, plain when piped. */
  readonly ui: Ui;
  /** The same for stderr, where prompts, progress and errors go. */
  readonly errUi: Ui;
  /** stdout's styles (`ui.style`). */
  readonly style: Styles;
  /** The command being run, for the writer lock's record. */
  commandName = "";
  /** `--json`: stdout is machine output, and nothing draws on stderr either. */
  json = false;
  /** `--quiet`: no progress or notices on stderr; output, warnings and errors only. */
  quiet = false;
  private storeInstance: Store | undefined;
  /** The scope this command holds the CLI writer lock for (taken by its first write). */
  private held: WriteScope | undefined;
  /** `doorman watch`: owns the store for its whole run (the `watch` lock). */
  private watching = false;

  constructor(readonly io: CliEnvironment) {
    this.dataDir = doormanDataDir(io.env, io.platform, io.home);
    this.ui = Ui.for(io.stdout, io.env, io.platform);
    this.errUi = Ui.for(io.stderr, io.env, io.platform);
    this.style = this.ui.style;
  }

  get guardDir(): string {
    return guardDir(this.dataDir);
  }

  log(message: string): void {
    if (this.io.verbose) this.io.stderr.write(`${this.errUi.style.dim(message)}\n`);
  }

  /** The transcript scan, its progress on stderr: redrawn on a terminal, a
   * line every few seconds otherwise, none under --json or --verbose (whose
   * log lines it would cut into). */
  async scan(engine: CaptureEngine): Promise<void> {
    if (this.json || this.quiet || this.io.verbose) return engine.scan();
    const progress = startProgress(this.errUi, this.io.stderr, { label: "Scanning transcripts", format: (n) => plural(n, "file") + " read" });
    await withPolledProgress(progress, () => engine.filesSeen, () => engine.scan());
  }

  /** Who owns the data besides this process: the heartbeat's writer when it
   * is fresh, or an app that is still starting. */
  running(): RunningDoorman | undefined {
    return this.heartbeatOwner() ?? this.startingApp();
  }

  private startingApp(): RunningDoorman | undefined {
    const owner = appOwner(this.dataDir, this.io.now());
    return owner ? { pid: owner.pid } : undefined;
  }

  private heartbeatOwner(): RunningDoorman | undefined {
    let json: string;
    try {
      json = readFileSync(heartbeatPath(this.guardDir), "utf8");
    } catch {
      return undefined;
    }
    if (!heartbeatFresh(json, this.io.now())) return undefined;
    try {
      const raw: unknown = JSON.parse(json);
      if (!raw || typeof raw !== "object") return {};
      const pid = "pid" in raw && typeof raw.pid === "number" ? raw.pid : undefined;
      // Our own, or one a crashed app left behind (fresh for up to 45s more).
      if (pid === process.pid || (pid !== undefined && !pidAlive(pid))) return undefined;
      const version = "version" in raw && typeof raw.version === "string" ? raw.version : undefined;
      const stdio = "stdio" in raw && raw.stdio === true;
      return { ...(pid !== undefined ? { pid } : {}), ...(version !== undefined ? { version } : {}), ...(stdio ? { stdio: true as const } : {}) };
    } catch {
      return {};
    }
  }

  /** The desktop app, running or starting — not a `doorman watch`. A
   * heartbeat that can't be read counts as the app: the safe reading. */
  private appRunning(): RunningDoorman | undefined {
    const beat = this.heartbeatOwner();
    if (beat && !isCliWatch(beat)) return beat;
    return this.startingApp();
  }

  /** Whoever owns the store besides this process: `running()`, or a
   * `doorman watch` that has claimed it and not yet written its heartbeat. */
  private storeOwner(): RunningDoorman | undefined {
    const other = this.running();
    if (other) return other;
    const watch = liveLock(this.dataDir, "watch", this.io.now());
    return watch && watch.pid !== process.pid ? { pid: watch.pid, version: "cli-" } : undefined;
  }

  /**
   * Claim the data for this command's writes in `scope`: the CLI writer lock
   * first, then the check that nobody owning what the scope touches is
   * running. Held until the command ends (`releaseWrite`), so an app starting
   * meanwhile waits for it. A wider scope asked later is checked again; a
   * refusal then keeps the narrower claim.
   */
  private claimWrite(scope: WriteScope): { ok: true } | { ok: false; app?: RunningDoorman; cli?: { pid: number; command?: string } } {
    if (this.watching) return { ok: true };
    const fresh = this.held === undefined;
    if (!fresh && SCOPE_RANK[this.held!] >= SCOPE_RANK[scope]) return { ok: true };
    if (fresh && !takeLock(this.dataDir, "cli-writer", { pid: process.pid, by: "cli", command: this.commandName }, this.io.now())) {
      const holder = liveLock(this.dataDir, "cli-writer", this.io.now());
      return { ok: false, cli: { pid: holder?.pid ?? 0, ...(holder?.command ? { command: holder.command } : {}) } };
    }
    const other = scope === "data" ? this.storeOwner() : scope === "settings" ? this.appRunning() : undefined;
    if (other) {
      if (fresh) releaseLock(this.dataDir, "cli-writer", process.pid);
      return { ok: false, app: other };
    }
    // A change starts from the prefs file as it is now that nobody else may
    // write it, not as this command first read it.
    if (fresh) this.storeInstance = undefined;
    this.held = scope;
    return { ok: true };
  }

  /** Let go of the writer lock and of a watch's claim on the store (the
   * dispatcher calls this when the command ends; watch, the moment it stops). */
  releaseWrite(): void {
    if (this.watching) {
      this.watching = false;
      releaseLock(this.dataDir, "watch", process.pid);
    }
    if (this.held === undefined) return;
    this.held = undefined;
    releaseLock(this.dataDir, "cli-writer", process.pid);
  }

  /**
   * Refuse a change while another Doorman owns what it touches (WriteScope).
   * `inApp: false` — the app has no control for this change — so the
   * refusal says to quit it rather than point at a screen that isn't there.
   */
  requireWritable(action: string, options: { scope?: WriteScope; inApp?: boolean } = {}): void {
    const claim = this.claimWrite(options.scope ?? "data");
    if (claim.ok) return;
    if (claim.cli) {
      const what = claim.cli.command ? `\`doorman ${claim.cli.command}\`` : "Another doorman command";
      throw new CliError(`${what}${processLabel(this.io.env, claim.cli.pid)} is changing this data right now. Run this again when it finishes.`);
    }
    const owner = claim.app ?? {};
    const who = processLabel(this.io.env, owner.pid);
    if (isCliWatch(owner)) {
      throw new CliError(`\`doorman watch\`${who} owns this data while it answers held calls. Stop it and run this again.`);
    }
    throw new CliError(
      options.inApp === false
        ? `Doorman is running${who}, so it owns this data. Quit the app and run this again.`
        : `Doorman is running${who}, so it owns this data. ${action} in the app, or quit it and run this again.`,
    );
  }

  /**
   * `doorman watch`: own the store for as long as it runs — it ingests the
   * guard's spool and answers held calls — through the `watch` lock, which
   * the app waits for at start like the writer lock. The writer lock itself
   * is let go at once, so settings and config changes still work while it
   * runs; its own prefs writes go through `underWriterLock`.
   */
  requireWatch(action: string): void {
    this.requireWritable(action);
    if (!takeLock(this.dataDir, "watch", { pid: process.pid, by: "cli", command: this.commandName }, this.io.now())) {
      // Unreachable while the data claim above holds (it checks this lock),
      // but a claim that can't be had is never assumed.
      this.releaseWrite();
      throw new CliError("Another `doorman watch` is taking over this data right now. Run this again when it settles.");
    }
    this.watching = true;
    this.held = undefined;
    releaseLock(this.dataDir, "cli-writer", process.pid);
  }

  /**
   * Run a read-modify-write of prefs and the guard's policy as the only
   * writer. A `doorman watch` takes the writer lock for just this (waiting
   * out a settings command, which holds it for milliseconds) and reads the
   * prefs afresh, so a change another command made meanwhile is kept, not
   * written over. Any other command already holds the lock it claimed.
   */
  underWriterLock<T>(fn: () => T): T {
    if (!this.watching) return fn();
    const started = Date.now();
    let locked = takeLock(this.dataDir, "cli-writer", { pid: process.pid, by: "cli", command: this.commandName });
    while (!locked && Date.now() - started < WATCH_LOCK_WAIT_MS) {
      sleepSync(20);
      locked = takeLock(this.dataDir, "cli-writer", { pid: process.pid, by: "cli", command: this.commandName });
    }
    if (!locked) this.log(`the writer lock is still held after ${WATCH_LOCK_WAIT_MS / 1000}s; writing anyway`);
    this.storeInstance = undefined;
    try {
      return fn();
    } finally {
      if (locked) releaseLock(this.dataDir, "cli-writer", process.pid);
    }
  }

  private store(): Store {
    this.storeInstance ??= new Store({
      appVersion: this.io.version,
      dataDir: this.dataDir,
      nodePlatform: this.io.platform,
      readPrefs: () => readPrefsFile(this.dataDir),
      writePrefs: (prefs) => writePrefsFile(this.dataDir, prefs),
      onChange: () => {},
    });
    return this.storeInstance;
  }

  prefs(): Prefs {
    return this.store().prefs();
  }

  /** Write prefs (sanitized, atomically). Callers check `requireWritable` first
   * with a sentence naming what they change. */
  setPrefs(patch: Partial<Prefs>): Prefs {
    return this.store().setPrefs(patch);
  }

  policy(): GuardPolicy {
    return livePolicy(this.prefs(), this.io.env);
  }

  /**
   * The capture engine over the shared store. `scan` brings it up to date with
   * the transcripts first (the app's own scan, classifier included). While
   * another Doorman runs, it opens a temporary copy of the store instead, so
   * nothing is written under the owner's feet; `close()` removes the copy.
   * There is no evidence vault: that lives in the app's Keychain item.
   */
  async openEngine(options: { scan: boolean }): Promise<EngineHandle> {
    const snapshot = !this.claimWrite("data").ok;
    const realStore = join(this.dataDir, "store");
    let storeDir = realStore;
    let temp: string | undefined;
    if (snapshot) {
      temp = mkdtempSync(join(tmpdir(), "doorman-cli-"));
      storeDir = join(temp, "store");
      if (existsSync(realStore)) {
        cpSync(realStore, storeDir, {
          recursive: true,
          filter: (src) => !/evidence-vault|sqlite-snapshots/.test(src),
        });
      }
    }
    const newFindings: FindingRow[] = [];
    const env = this.io.env;
    let classifier: Promise<InjectionClassifier | null> | undefined;
    const engine = new CaptureEngine({
      storeDir,
      appVersion: this.io.version,
      claudeProjectsDir: join(this.io.home, ".claude", "projects"),
      codexSessionsDir: join(codexHomeDir(env, this.io.home), "sessions"),
      home: this.io.home,
      env,
      policy: () => this.policy(),
      retentionDays: () => this.prefs().retention_days,
      classifyInjection: async (text) => {
        classifier ??= loadClassifier(this.dataDir, this.policy(), env, (m) => this.log(m)).then((r) => r.classifier);
        return (await classifier)?.classify(text) ?? null;
      },
      injectionModelInUse: () => modelPlan(this.dataDir, this.policy(), env).effective,
      onUpdate: () => {},
      onNewFindings: (rows) => newFindings.push(...rows),
      readArmed: () => readArmedSessions(this.dataDir),
      onArmedChange: (sessions) => {
        if (!snapshot) writeArmedSessions(this.dataDir, sessions);
      },
      log: (message) => this.log(message),
      // An app that starts meanwhile is waiting for this command to finish
      // writing: stop the scan at the next file and let it carry on from there.
      ...(snapshot ? {} : { shouldStop: () => this.running() !== undefined }),
    });
    engine.open();
    // Sandboxes pulled to the drop folder (`doorman sbx pull`): taken in by
    // whoever owns the store — this command, or else the owner (the app
    // drains it itself); a copy takes them in too, so what this command
    // shows already includes them, and leaves the files for the owner.
    const imported = drainImports(this.dataDir, (bundle) => engine.importSandboxBundle(bundle), { consume: !snapshot, log: (m) => this.log(m) });
    if (options.scan) await this.scan(engine);
    return {
      engine,
      snapshot,
      newFindings,
      imported,
      close: () => {
        engine.stop();
        if (temp) rmSync(temp, { recursive: true, force: true });
      },
    };
  }
}

export function defaultEnvironment(version: string, verbose: boolean): CliEnvironment {
  return {
    env: process.env,
    home: homedir(),
    platform: process.platform,
    version,
    stdout: process.stdout,
    stderr: process.stderr,
    stdin: process.stdin,
    now: () => Date.now(),
    verbose,
    spawnDetached(args) {
      // This file's own entry point (build/main/cli/index.js), run by the same
      // node: the child gets the same data directory from the same environment.
      const child = spawn(process.execPath, [join(__dirname, "index.js"), ...args], {
        detached: true,
        stdio: "ignore",
        windowsHide: true,
        env: process.env,
      });
      child.on("error", () => {}); // a failed start is retried by a later command
      child.unref();
      return child.pid;
    },
  };
}
