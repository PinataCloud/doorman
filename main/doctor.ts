/**
 * The setup doctor's Electron side: gather what the pure diagnosis needs,
 * run it, apply the repair plan, and check again. Entirely local — it reads
 * files and the editor's CLI, and sends nothing anywhere.
 *
 * When it runs — every path lands in `DoctorRunner.run`, so there is one
 * place that decides what "automatic" may touch:
 *   · boot, then every 30 minutes (index.ts) — the "keeps things current" loop;
 *   · a change to a watched hook document (index.ts watches them) — Claude
 *     Code rewriting settings.json on a model switch, a hand edit: repaired
 *     within seconds, not at the next relaunch;
 *   · window focus;
 *   · a guard toggle;
 *   · the Integrations card's Check now / Repair buttons.
 *
 * Automatic runs apply only repairs the plan marks lossless (`auto`). The lossy
 * one — replacing an unreadable JSON document with its backup — runs only from
 * an explicit click on that specific check. The RepairLedger stands automatic
 * repair down when the same fix keeps being re-applied (something is fighting
 * us: a tool rewriting its file back), so the app can never churn a file
 * every three seconds; the card then offers the fix by hand.
 */

import { hookWritesAllowed, SANDBOX_READ_ONLY } from "./lib/sandbox.js";
import { existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { GUARD_FILES, checkGuardRuntime, guardCommand, guardDir, installGuard } from "./enforcement.js";
import { runtimeLabel } from "./lib/node-launcher.js";
import { createSourceIo } from "./lib/source-io.js";
import type { SourceIo } from "./lib/transcript-sources.js";
import { GUARD_COMMAND_MARKER, type GuardPolicy } from "./guard/policy.js";
import {
  RepairLedger,
  describeRepair,
  diagnose,
  planRepairs,
  repairJsonText,
  type DoctorInput,
  type DoctorReport,
  type DoctorState,
  type PlannedRepair,
} from "./lib/doctor.js";
import { extensionStatus, installEditorExtension, type EditorExtensionStatus } from "./vscode-ext-install.js";
import { parseEditorWindowReport, windowReportLive, windowsDir, type EditorWindowReport } from "./lib/vscode-ext.js";

const EDITOR_PROBE_TTL_MS = 60 * 60_000;

export interface DoctorRunnerDeps {
  userDataDir: string;
  guardWanted(): boolean;
  /** `prefs.mcp_answers` — whether our MCP server is meant to be registered. */
  mcpWanted?: () => boolean;
  /** `prefs.vscode_extension` — whether the editor companion is meant to be
   * installed. Absent = off, which skips every VS Code extension row. */
  editorExtensionWanted?: () => boolean;
  /** This build's version, which is also the extension's (build-vsix.mjs
   * stamps the app version into it). */
  appVersion?: string;
  policy(): GuardPolicy;
  onState(state: DoctorState): void;
  log(line: string): void;
  now?: () => number;
}

export interface RunOptions {
  reason: string;
  /** `none` = diagnose only; `auto` = lossless repairs; `all` = everything fixable. */
  repair: "none" | "auto" | "all";
  /** Repair one check only (an explicit click on its Fix button). */
  only?: string | undefined;
  /** An explicit click: go through even where automatic repair stood down. */
  force?: boolean;
  /** Bypass the probe caches — a manual Check now wants fresh answers. */
  refresh?: boolean;
}

export class DoctorRunner {
  private state: DoctorState = { status: "idle" };
  private inflight: Promise<DoctorState> | undefined;
  private editorProbe: { at: number; hosts: EditorExtensionStatus[] } | undefined;
  /** Lazily created: a doctor run on a Mac without VS Code never opens SQLite. */
  private io: SourceIo | undefined;
  private readonly ledger: RepairLedger;

  constructor(private readonly deps: DoctorRunnerDeps) {
    this.ledger = new RepairLedger(deps.now ?? Date.now);
  }

  snapshot(): DoctorState {
    return this.state;
  }

  /** Coalesces: a run requested while one is in flight waits for it, then runs
   * once more (the files may have changed under the first one). */
  run(opts: RunOptions): Promise<DoctorState> {
    if (this.inflight) {
      return this.inflight.then(() => this.execute(opts));
    }
    this.inflight = this.execute(opts).finally(() => {
      this.inflight = undefined;
    });
    return this.inflight;
  }

  private emit(patch: Partial<DoctorState>): void {
    this.state = { ...this.state, ...patch };
    this.deps.onState(this.state);
  }

  private async execute(opts: RunOptions): Promise<DoctorState> {
    const now = (this.deps.now ?? Date.now)();
    this.emit({ status: "checking", last_reason: opts.reason });
    try {
      if (opts.refresh) this.invalidateEditorProbe();
      let report = diagnose(this.input(opts));
      const paused: string[] = [];
      let outcome: DoctorState["last_repair"] | undefined;
      if (opts.repair !== "none") {
        const plan = planRepairs(report, opts.repair, { only: opts.only });
        const runnable: PlannedRepair[] = [];
        for (const repair of plan) {
          // Automatic repair stands down when a fix keeps not sticking; an
          // explicit click (opts.only) always goes through.
          if (!opts.force && this.ledger.exhausted(repair)) {
            paused.push(...repair.checks);
            continue;
          }
          runnable.push(repair);
        }
        if (runnable.length > 0) {
          this.emit({ status: "repairing" });
          outcome = { at: new Date(now).toISOString(), applied: [], failed: [] };
          for (const repair of runnable) {
            const label = describeRepair(repair, homedir());
            try {
              const ok = await this.apply(repair);
              this.ledger.record(repair);
              (ok ? outcome.applied : outcome.failed).push(label);
              this.deps.log(`${ok ? "repaired" : "repair FAILED"}: ${label} (${repair.checks.join(", ")})`);
            } catch (err) {
              outcome.failed.push(`${label} — ${err instanceof Error ? err.message : String(err)}`);
              this.deps.log(`repair threw: ${label}: ${String(err)}`);
            }
          }
          // Re-read the world the repairs just changed.
          report = diagnose(this.input(opts));
        }
      }
      this.emit({
        status: "idle",
        report,
        last_run_at: report.at,
        last_reason: opts.reason,
        ...(outcome ? { last_repair: outcome } : {}),
        paused,
      });
    } catch (err) {
      this.deps.log(`doctor run failed: ${err instanceof Error ? err.message : String(err)}`);
      this.emit({ status: "idle", last_reason: opts.reason });
    }
    return this.state;
  }

  /** The guard.runtime row's input: fresh probes on a manual run, otherwise
   * cached per runtime file. A diagnose-only run writes nothing. */
  private guardRuntime(opts: RunOptions): DoctorInput["guardRuntime"] {
    const report = checkGuardRuntime(this.deps.userDataDir, { fresh: opts.refresh === true, persist: opts.repair !== "none" });
    if (!report) return undefined;
    if (report.working && report.using) return { ok: true, runsOn: runtimeLabel(report.using.kind, report.using.path) };
    return { ok: false, error: report.problem ?? "The guard can't start", repairable: report.ok };
  }

  private input(opts: RunOptions): DoctorInput {
    return {
      home: homedir(),
      codexHome: process.env.CODEX_HOME,
      grokHome: process.env.GROK_HOME,
      guardWanted: this.deps.guardWanted(),
      mcpWanted: this.deps.mcpWanted?.() ?? false,
      vscodeExtension: this.editorExtension(),
      vscodeWindows: this.editorWindows(),
      guardDir: guardDir(this.deps.userDataDir),
      guardFiles: GUARD_FILES,
      guardCommandMarker: GUARD_COMMAND_MARKER,
      guardCommandFor: (hostId) => guardCommand(this.deps.userDataDir, hostId),
      guardRuntime: this.deps.guardWanted() ? this.guardRuntime(opts) : undefined,
      env: process.env,
      fs: {
        exists: (p) => existsSync(p),
        read: (p) => {
          try {
            return readFileSync(p, "utf8");
          } catch {
            return undefined;
          }
        },
        listDir: (p) => {
          try {
            return readdirSync(p);
          } catch {
            return [];
          }
        },
        // VS Code's trusted-folder list lives in a SQLite database the editor
        // holds open in WAL mode; the same read-only, snapshot-first reader the
        // capture engine uses for Cursor's state.vscdb is what opens it here.
        querySqlite: (p, sql, params) => this.sourceIo().querySqlite(p, sql, params),
      },
    };
  }

  private sourceIo(): SourceIo {
    this.io ??= createSourceIo({
      snapshotDir: join(this.deps.userDataDir, "store", "sqlite-snapshots"),
      log: (message) => this.deps.log(message),
    });
    return this.io;
  }

  /**
   * What each VS Code build has installed — one `--list-extensions` per build,
   * cached for an hour. The answer changes when someone installs or removes an
   * extension, not between two doctor runs seconds apart, and the doctor runs
   * on every hook-document change; without the cache a busy agent session
   * would spawn the editor's CLI dozens of times a minute.
   */
  private editorExtension(): DoctorInput["vscodeExtension"] {
    const wanted = this.deps.editorExtensionWanted?.() ?? false;
    if (!wanted) return { wanted: false };
    const now = (this.deps.now ?? Date.now)();
    if (!this.editorProbe || now - this.editorProbe.at >= EDITOR_PROBE_TTL_MS) {
      let hosts: EditorExtensionStatus[] = [];
      try {
        hosts = extensionStatus();
      } catch (err) {
        this.deps.log(`vscode extension probe failed: ${err instanceof Error ? err.message : String(err)}`);
      }
      this.editorProbe = { at: now, hosts };
    }
    const hosts = this.editorProbe.hosts;
    // Worst state across the builds present: a machine with the extension in
    // VS Code but not in Insiders is not "installed".
    const drivable = hosts.filter((h) => !h.cliMissing);
    return {
      wanted: true,
      ...(drivable.length === 0 && hosts.length > 0 ? { cliMissing: true } : {}),
      ...(drivable.length > 0 && drivable.every((h) => h.installed) ? { installed: drivable[0]!.installed } : {}),
      ...(this.deps.appVersion ? { bundled: this.deps.appVersion } : {}),
    };
  }

  /**
   * What each open VS Code window reports about itself: the
   * companion extension writes `editor/windows/<sessionId>.json` on activation
   * and on every trust/settings change, and refreshes it every 10 s. Read
   * fresh on every run — it is a handful of small files — and stale reports
   * (a window whose extension host died before deactivate) are dropped here so
   * the diagnosis only ever sees live windows.
   */
  private editorWindows(): EditorWindowReport[] {
    const dir = windowsDir(this.deps.userDataDir);
    let names: string[];
    try {
      names = readdirSync(dir);
    } catch {
      return [];
    }
    const now = (this.deps.now ?? Date.now)();
    const out: EditorWindowReport[] = [];
    for (const name of names) {
      if (!name.endsWith(".json")) continue;
      let text: string;
      try {
        text = readFileSync(join(dir, name), "utf8");
      } catch {
        continue;
      }
      const report = parseEditorWindowReport(text);
      if (report && windowReportLive(report, now)) out.push(report);
    }
    return out;
  }

  /** Forget the cached editor probe — after an install, so the re-check that
   * follows a repair sees what it just did rather than the pre-repair answer. */
  invalidateEditorProbe(): void {
    this.editorProbe = undefined;
  }

  /** Apply one repair. Returns whether it took. Every file write keeps the
   * previous bytes beside the file — nothing here is the only copy of anything. */
  private async apply(repair: PlannedRepair): Promise<boolean> {
    // Every repair rewrites a file in the real home — none of that from a
    // sandboxed run, unless the file really lies inside its redirected home.
    if (!hookWritesAllowed(process.env, repair.file)) {
      this.deps.log(`sandboxed run: skipped repair ${repair.fix} — ${SANDBOX_READ_ONLY}`);
      return false;
    }
    switch (repair.fix) {
      case "repair-json": {
        const file = repair.file!;
        const raw = readFileSync(file, "utf8");
        const repaired = repairJsonText(raw);
        if (!repaired) return false; // changed under us — the re-check will say so
        keepCopy(file, raw, "corrupt");
        writeFileSync(file, repaired.text);
        return true;
      }
      case "restore-json": {
        const file = repair.file!;
        let raw = "";
        try {
          raw = readFileSync(file, "utf8");
        } catch {
          // nothing to keep
        }
        if (raw) keepCopy(file, raw, "corrupt");
        let restored = "{}\n";
        try {
          const bak = readFileSync(`${file}.bak`, "utf8");
          const parsed = JSON.parse(bak);
          if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) restored = bak.endsWith("\n") ? bak : `${bak}\n`;
        } catch {
          // no usable backup — start empty; the guard re-merges into it
        }
        mkdirSync(dirname(file), { recursive: true });
        writeFileSync(file, restored);
        return true;
      }
      case "install-guard": {
        // Fresh probes: a repair should not trust the results it is repairing.
        const outcome = installGuard(this.deps.userDataDir, this.deps.policy(), { fresh: true });
        if (!outcome.ok) this.deps.log(`guard install failed: ${outcome.error}`);
        return outcome.ok;
      }
      case "install-vscode-extension": {
        const version = this.deps.appVersion;
        if (!version) return false; // nothing to install against
        const outcome = installEditorExtension(version);
        if (!outcome.ok) this.deps.log(`vscode extension install failed: ${outcome.error}`);
        this.invalidateEditorProbe();
        return outcome.ok;
      }
    }
  }
}

/** `<file>.<tag>-<timestamp>` — the broken bytes, kept, never overwritten. */
function keepCopy(file: string, raw: string, tag: string): void {
  const stamp = new Date().toISOString().replace(/[-:]/g, "").replace(/\.\d+Z$/, "Z");
  try {
    writeFileSync(`${file}.${tag}-${stamp}`, raw);
  } catch {
    // a copy we couldn't write must not block the repair of the live file
  }
}

/** Which checks in a report a person has to act on (nothing automatic
 * applies): a manual instruction, or a fix marked non-auto. */
export function attentionChecks(report: DoctorReport | undefined, paused: string[] = []): DoctorReport["checks"] {
  if (!report) return [];
  return report.checks.filter(
    (c) =>
      (c.status === "fail" || c.status === "warn") &&
      (c.manual !== undefined || (c.fix !== undefined && !c.auto) || paused.includes(c.id)),
  );
}
