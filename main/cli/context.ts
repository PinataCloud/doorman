import { cpSync, existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import { CaptureEngine } from "../capture.js";
import { guardDir, readArmedSessions, writeArmedSessions } from "../enforcement.js";
import { heartbeatFresh, heartbeatPath } from "../guard/handshake.js";
import type { GuardPolicy } from "../guard/policy.js";
import { codexHomeDir } from "../lib/codex-rollout.js";
import { doormanDataDir } from "../lib/data-dir.js";
import type { FindingRow } from "../lib/findings.js";
import type { InjectionClassifier } from "../lib/injection-classifier.js";
import { livePolicy } from "../lib/live-policy.js";
import { readPrefsFile, writePrefsFile } from "../lib/prefs-file.js";
import { Store, type Prefs } from "../state.js";
import { loadClassifier, modelPlan } from "./classifier.js";
import { CliError, styles, type Styles } from "./output.js";

export interface CliEnvironment {
  env: NodeJS.ProcessEnv;
  home: string;
  platform: NodeJS.Platform;
  /** The CLI package's version, reported as `appVersion` in what it writes. */
  version: string;
  stdout: NodeJS.WritableStream & { isTTY?: boolean };
  stderr: NodeJS.WritableStream;
  stdin: NodeJS.ReadableStream & { isTTY?: boolean };
  now(): number;
  verbose: boolean;
}

/** Whoever answers held calls right now: the desktop app, or `doorman watch`. */
export interface RunningDoorman {
  pid?: number;
  version?: string;
}

/** The engine opened for one command, and how to put it away. */
export interface EngineHandle {
  engine: CaptureEngine;
  /** True when Doorman was running and the engine works on a copy of the store. */
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
 * guard heartbeat (the app, or `doorman watch`) owns the store and the prefs.
 * While it runs, read commands work on a temporary copy of the store and
 * commands that change prefs, policy or hooks refuse (`requireWritable`).
 */
export class CliContext {
  readonly dataDir: string;
  readonly style: Styles;
  private storeInstance: Store | undefined;

  constructor(readonly io: CliEnvironment) {
    this.dataDir = doormanDataDir(io.env, io.platform, io.home);
    this.style = styles(io.stdout.isTTY === true && io.env.NO_COLOR === undefined);
  }

  get guardDir(): string {
    return guardDir(this.dataDir);
  }

  log(message: string): void {
    if (this.io.verbose) this.io.stderr.write(`${this.style.dim(message)}\n`);
  }

  /** The heartbeat's owner, when it is fresh and not this process. */
  running(): RunningDoorman | undefined {
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
      if (pid === process.pid) return undefined;
      const version = "version" in raw && typeof raw.version === "string" ? raw.version : undefined;
      return { ...(pid !== undefined ? { pid } : {}), ...(version !== undefined ? { version } : {}) };
    } catch {
      return {};
    }
  }

  /** Refuse a change while another Doorman owns the data: it holds the prefs
   * in memory and would write over this one. */
  requireWritable(action: string): void {
    const other = this.running();
    if (!other) return;
    const who = other.pid !== undefined ? ` (pid ${other.pid})` : "";
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
    const snapshot = this.running() !== undefined;
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
    });
    engine.open();
    if (options.scan) await engine.scan();
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
  };
}
