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

/** Whoever answers held calls right now: the desktop app, or `doorman watch`. */
export interface RunningDoorman {
  pid?: number;
  version?: string;
}

/** The engine opened for one command, and how to put it away. */
export interface EngineHandle {
  engine: CaptureEngine;
  /** True when another Doorman (the app, `watch`, or another command) owned the
   * data, so the engine works on a copy of the store. */
  snapshot: boolean;
  /** Rows minted by this command's scan (empty with `scan: false`). */
  newFindings: FindingRow[];
  close(): void;
}

/**
 * Everything a command reads and writes, resolved once per invocation.
 *
 * The CLI shares the desktop app's data directory — one store, one prefs file,
 * one guard bundle and policy — so the two never disagree about what was found
 * or what is enforced. They must not both WRITE at once: whoever holds the
 * guard heartbeat (the app, or `doorman watch`) owns the store and the prefs,
 * and so does an app that is still starting (lib/data-owner.ts). While it
 * runs, read commands work on a temporary copy of the store and commands that
 * change prefs, policy or hooks refuse (`requireWritable`).
 *
 * A command that writes first takes the CLI writer lock and only then checks
 * for the app — the app marks itself first and then waits for that lock — so
 * the two never write at once, whichever starts first. Two CLI commands don't
 * either: the second works on a copy, or refuses a change, until the first ends.
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
  private storeInstance: Store | undefined;
  /** This command holds the CLI writer lock (taken by its first write). */
  private writing = false;

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
    if (this.json || this.io.verbose) return engine.scan();
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
      return { ...(pid !== undefined ? { pid } : {}), ...(version !== undefined ? { version } : {}) };
    } catch {
      return {};
    }
  }

  /**
   * Claim the data for this command's writes: the CLI writer lock first, then
   * the check that no other Doorman owns it. Held until the command ends
   * (`releaseWrite`), so an app starting meanwhile waits for it.
   */
  private claimWrite(): { ok: true } | { ok: false; app?: RunningDoorman; cli?: { pid: number; command?: string } } {
    if (this.writing) return { ok: true };
    if (!takeLock(this.dataDir, "cli-writer", { pid: process.pid, by: "cli", command: this.commandName }, this.io.now())) {
      const holder = liveLock(this.dataDir, "cli-writer", this.io.now());
      return { ok: false, cli: { pid: holder?.pid ?? 0, ...(holder?.command ? { command: holder.command } : {}) } };
    }
    const other = this.running();
    if (other) {
      releaseLock(this.dataDir, "cli-writer", process.pid);
      return { ok: false, app: other };
    }
    this.writing = true;
    return { ok: true };
  }

  /** Let go of the writer lock (the dispatcher calls this when the command ends). */
  releaseWrite(): void {
    if (!this.writing) return;
    this.writing = false;
    releaseLock(this.dataDir, "cli-writer", process.pid);
  }

  /** Refuse a change while another Doorman owns the data: it holds the prefs
   * in memory and would write over this one. */
  requireWritable(action: string): void {
    const claim = this.claimWrite();
    if (claim.ok) return;
    if (claim.cli) {
      const what = claim.cli.command ? `\`doorman ${claim.cli.command}\`` : "Another doorman command";
      throw new CliError(`${what}${processLabel(this.io.env, claim.cli.pid)} is changing this data right now. Run this again when it finishes.`);
    }
    const who = processLabel(this.io.env, claim.app?.pid);
    throw new CliError(
      `Doorman is running${who}, so it owns this data. ${action} in the app, or quit it (or stop \`doorman watch\`) and run this again.`,
    );
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
    const snapshot = !this.claimWrite().ok;
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
    if (options.scan) await this.scan(engine);
    return {
      engine,
      snapshot,
      newFindings,
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
