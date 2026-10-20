/**
 * What a Docker Sandbox (`sbx`) recorded, brought to the host.
 *
 * Inside a sandbox Doorman keeps its own store (/home/agent/.config/Doorman),
 * which the host's app never sees and `sbx rm` deletes. `doorman export
 * bundle` (run inside) writes the SANDBOX BUNDLE: the detections export and
 * the ledger export — the two published, masked documents
 * (lib/detection-schema.ts, lib/ledger-export.ts) — in one versioned envelope
 * naming the sandbox. `doorman sbx pull` (on the host) runs it through `sbx
 * exec` and drops the result in `<data dir>/imports/`; it never writes the
 * store, because the app (or another command) may own it (lib/data-owner.ts).
 * Whoever owns the store ingests the drop folder: the app on start and when a
 * file lands (`ImportsWatcher`), the CLI whenever it opens the store
 * (cli/context.ts openEngine). An ingested file moves to `imports/done/`, a
 * broken one to `imports/rejected/`.
 *
 * Identity: every id from the sandbox — session, turn, finding — is suffixed
 * `@<sandbox>`, so a sandbox row can never merge into a host one (a guard row
 * with no session hashes to the same finding id on both sides), and a re-pull
 * of the same sandbox mints the same ids: ingesting it again changes nothing.
 * The `@` also keeps a sandbox session out of the host's resume commands
 * (lib/terminal-handoff.ts SAFE_ID): it cannot be continued here.
 *
 * Origin: every imported turn, session and finding carries `sandbox: <name>`.
 * It exempts them from the "transcript still on disk" rule (their transcript
 * is in the sandbox, never on this disk) and labels them "sandbox <name>".
 *
 * Nothing imported holds a value: both documents are masked at export, and
 * every free-text field is masked once more here, at the one choke point both
 * the pull and the ingest go through (`sandboxRecords`, `sanitizeSandboxBundle`).
 */

import { existsSync, mkdirSync, readdirSync, readFileSync, renameSync, rmSync, statSync, watch, writeFileSync, type FSWatcher } from "node:fs";
import { basename, dirname, join } from "node:path";
import {
  DETECTION_SCHEMA_VERSION,
  toDetectionRecord,
  validateDetectionsExport,
  validateSchema,
  type DetectionsExport,
  type JsonSchema,
  type SchemaProblem,
} from "./detection-schema.js";
import type { FindingRow } from "./findings.js";
import { validateLedgerExport, type ExportedSession, type ExportedTurn, type LedgerExport } from "./ledger-export.js";
import { maskTurnText } from "./masking.js";
import type { LedgerTurn, SessionTitle } from "./turns.js";

export const SANDBOX_BUNDLE_SCHEMA_ID = "urn:doorman:schemas:sandbox-bundle.v1";

/** The sandbox names `sbx` mints and takes (`sbx create --name`): what may go
 * into an id suffix and a file name. */
const SANDBOX_NAME = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/;

export function validSandboxName(name: string): boolean {
  return SANDBOX_NAME.test(name);
}

export const SANDBOX_BUNDLE_SCHEMA: JsonSchema = {
  $schema: "https://json-schema.org/draft/2020-12/schema",
  $id: SANDBOX_BUNDLE_SCHEMA_ID,
  title: "Doorman sandbox bundle",
  description:
    "What Doorman recorded inside one Docker Sandbox: its detections export and its Event Ledger export, as `doorman export bundle` writes them and `doorman sbx pull` carries them to the host. Masked: no raw values.",
  type: "object",
  required: ["schema", "schema_version", "generated_at", "app_version", "sandbox", "detections", "ledger"],
  additionalProperties: false,
  properties: {
    schema: { const: SANDBOX_BUNDLE_SCHEMA_ID },
    schema_version: { const: DETECTION_SCHEMA_VERSION },
    generated_at: { type: "string", format: "date-time", description: "When the bundle was written." },
    app_version: { type: "string", description: "The Doorman that wrote it." },
    sandbox: {
      type: ["object", "null"],
      description: "The sandbox it came from; null when written outside one (`doorman sbx pull` names it from the host).",
      required: ["name"],
      additionalProperties: false,
      properties: {
        name: { type: "string", pattern: SANDBOX_NAME.source, description: "The sandbox's name, as `sbx` commands take it." },
        id: { type: "string", description: "The sandbox's id (SANDBOX_ID)." },
      },
    },
    detections: { type: "object", description: "The detections export (urn:doorman:schemas:detections-export.v1)." },
    ledger: { type: "object", description: "The Event Ledger export (urn:doorman:schemas:ledger-export.v1)." },
  },
};

export interface SandboxBundle {
  schema: typeof SANDBOX_BUNDLE_SCHEMA_ID;
  schema_version: typeof DETECTION_SCHEMA_VERSION;
  generated_at: string;
  app_version: string;
  sandbox: { name: string; id?: string } | null;
  detections: DetectionsExport;
  ledger: LedgerExport;
}

export function buildSandboxBundle(inputs: {
  detections: DetectionsExport;
  ledger: LedgerExport;
  sandbox: { name: string; id?: string } | undefined;
  app_version: string;
  generated_at: Date;
}): SandboxBundle {
  return {
    schema: SANDBOX_BUNDLE_SCHEMA_ID,
    schema_version: DETECTION_SCHEMA_VERSION,
    generated_at: inputs.generated_at.toISOString(),
    app_version: inputs.app_version,
    sandbox: inputs.sandbox ?? null,
    detections: inputs.detections,
    ledger: inputs.ledger,
  };
}

/** The envelope, then each document against its own published schema. */
export function validateSandboxBundle(value: unknown): SchemaProblem[] {
  const problems = validateSchema(SANDBOX_BUNDLE_SCHEMA, value);
  if (problems.length > 0) return problems;
  const bundle = value as SandboxBundle;
  const within = (prefix: string, list: SchemaProblem[]) => list.map((p) => ({ ...p, path: `/${prefix}${p.path}` }));
  return [...within("detections", validateDetectionsExport(bundle.detections)), ...within("ledger", validateLedgerExport(bundle.ledger))];
}

/**
 * The bundle with every free-text field masked once more — turn text, titles,
 * and each detection through the record's own choke point (toDetectionRecord).
 * The documents were masked when they were exported; this does not trust that
 * an older or altered Doorman inside the sandbox did.
 */
export function sanitizeSandboxBundle(bundle: SandboxBundle): SandboxBundle {
  const sessions = bundle.ledger.sessions.map(
    (session): ExportedSession => ({
      ...session,
      ...(session.title === undefined ? {} : { title: maskTurnText(session.title) }),
      items: session.items.map((turn): ExportedTurn => (typeof turn.text === "string" ? { ...turn, text: maskTurnText(turn.text) } : { ...turn })),
    }),
  );
  return {
    ...bundle,
    detections: { ...bundle.detections, detections: bundle.detections.detections.map(toDetectionRecord) },
    ledger: { ...bundle.ledger, sessions },
  };
}

/** An id from sandbox `name`, as the host stores it. */
export function sandboxScopedId(id: string, name: string): string {
  return `${id}@${name}`;
}

/** The id the sandbox itself knows a scoped id by. */
export function sandboxLocalId(id: string, name: string): string {
  const suffix = `@${name}`;
  return id.endsWith(suffix) ? id.slice(0, -suffix.length) : id;
}

export interface SandboxRecords {
  sandbox: string;
  turns: LedgerTurn[];
  titles: Map<string, SessionTitle>;
  findings: FindingRow[];
}

/** A bundle → the host store's records: masked, scoped by sandbox, stamped
 * with it. Throws when the bundle names no sandbox. */
export function sandboxRecords(raw: SandboxBundle): SandboxRecords {
  const name = raw.sandbox?.name;
  if (name === undefined || !validSandboxName(name)) throw new Error("the bundle names no sandbox");
  const bundle = sanitizeSandboxBundle(raw);
  const findings = bundle.detections.detections.map((row): FindingRow => {
    const out: FindingRow = { ...row, finding_id: sandboxScopedId(row.finding_id, name), sandbox: name };
    for (const key of ["session_id", "turn_id", "source_turn_id"] as const) {
      const id = row[key];
      if (id !== undefined) out[key] = sandboxScopedId(id, name);
    }
    return out;
  });
  const turns: LedgerTurn[] = [];
  const titles = new Map<string, SessionTitle>();
  for (const session of bundle.ledger.sessions) {
    const sessionId = sandboxScopedId(session.id, name);
    if (session.title !== undefined) titles.set(sessionId, { text: session.title, origin: session.title_origin ?? "auto_prompt" });
    for (const item of session.items) {
      // The export's own annotations stay behind: the text is already the
      // masked one, and its fingerprints are under the sandbox's key.
      const { text_redacted: _redacted, secrets: _secrets, ...turn } = item;
      turns.push({ ...turn, id: sandboxScopedId(turn.id, name), session_id: sandboxScopedId(turn.session_id, name), sandbox: name });
    }
  }
  return { sandbox: name, turns, titles, findings };
}

/** What one ingest added to the store. */
export interface SandboxImportResult {
  sandbox: string;
  sessions: number;
  turns_added: number;
  findings_added: number;
  findings_updated: number;
}

// ── The drop folder ───────────────────────────────────────────────────────────

export function importsDir(dataDir: string): string {
  return join(dataDir, "imports");
}

/** Ingested files kept for reference, newest first; older ones are deleted. */
const DONE_KEEP = 20;

/** `2026-10-20T09:15:02.123Z` → `20261020T091502Z`: sortable, and safe in a file name. */
function fileStamp(at: Date): string {
  return at.toISOString().replace(/[-:]/g, "").replace(/\.\d+Z$/, "Z");
}

/**
 * Write a bundle into the drop folder: `imports/sandbox-<name>-<time>.json`,
 * owner-only, through a temp name and a rename so an ingest never reads half
 * a file. Returns the path.
 */
export function writeDropFile(dataDir: string, bundle: SandboxBundle, at: Date): string {
  const name = bundle.sandbox?.name;
  if (name === undefined || !validSandboxName(name)) throw new Error("the bundle names no sandbox");
  const dir = importsDir(dataDir);
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const base = join(dir, `sandbox-${name}-${fileStamp(at)}`);
  let path = `${base}.json`;
  for (let n = 2; existsSync(path); n += 1) path = `${base}-${n}.json`;
  const temp = join(dir, `.${process.pid}-${Date.now()}.tmp`);
  writeFileSync(temp, `${JSON.stringify(bundle)}\n`, { mode: 0o600 });
  renameSync(temp, path);
  return path;
}

/** The drop files waiting, oldest first (the names sort by time per sandbox). */
export function pendingImports(dataDir: string): string[] {
  try {
    return readdirSync(importsDir(dataDir))
      .filter((name) => name.endsWith(".json") && !name.startsWith("."))
      .sort()
      .map((name) => join(importsDir(dataDir), name));
  } catch {
    return [];
  }
}

export interface ImportOutcome {
  file: string;
  ok: boolean;
  result?: SandboxImportResult;
  error?: string;
}

function moveInto(file: string, folder: string): void {
  const dir = join(dirname(file), folder);
  try {
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    renameSync(file, join(dir, basename(file)));
  } catch {
    rmSync(file, { force: true });
  }
}

function pruneDone(dataDir: string): void {
  const dir = join(importsDir(dataDir), "done");
  let names: string[];
  try {
    names = readdirSync(dir);
  } catch {
    return;
  }
  const byAge = names
    .map((name) => {
      try {
        return { name, at: statSync(join(dir, name)).mtimeMs };
      } catch {
        return { name, at: 0 };
      }
    })
    .sort((a, b) => b.at - a.at);
  for (const old of byAge.slice(DONE_KEEP)) rmSync(join(dir, old.name), { force: true });
}

/**
 * Ingest every drop file through `ingest` (CaptureEngine.importSandboxBundle).
 * With `consume` — the caller owns the store — an ingested file moves to
 * `done/` and an unreadable or invalid one to `rejected/`; a crash between the
 * ingest and the move only means the next drain ingests it again, which adds
 * nothing (the ids are stable). Without it — a read-only copy of the store —
 * the files stay for the owner.
 */
export function drainImports(
  dataDir: string,
  ingest: (bundle: SandboxBundle) => SandboxImportResult,
  options: { consume: boolean; log?: (message: string) => void },
): ImportOutcome[] {
  const outcomes: ImportOutcome[] = [];
  for (const file of pendingImports(dataDir)) {
    let bundle: SandboxBundle;
    try {
      const parsed: unknown = JSON.parse(readFileSync(file, "utf8"));
      const problems = validateSandboxBundle(parsed);
      if (problems.length > 0) throw new Error(`not a sandbox bundle: ${problems.slice(0, 3).map((p) => `${p.path} ${p.message}`).join("; ")}`);
      bundle = parsed as SandboxBundle;
      if (!bundle.sandbox) throw new Error("the bundle names no sandbox");
    } catch (err) {
      const error = err instanceof Error ? err.message : String(err);
      options.log?.(`couldn't import ${file}: ${error}`);
      if (options.consume) moveInto(file, "rejected");
      outcomes.push({ file, ok: false, error });
      continue;
    }
    let result: SandboxImportResult;
    try {
      result = ingest(bundle);
    } catch (err) {
      // The store refused it (a full disk, say): leave it for the next drain.
      const error = err instanceof Error ? err.message : String(err);
      options.log?.(`couldn't import ${file}: ${error}`);
      outcomes.push({ file, ok: false, error });
      continue;
    }
    if (options.consume) moveInto(file, "done");
    outcomes.push({ file, ok: true, result });
  }
  if (options.consume && outcomes.some((o) => o.ok)) pruneDone(dataDir);
  return outcomes;
}

/**
 * The app's side of the drop folder: drain it at start, when a file lands, and
 * on a slow interval (a watcher can miss an event) — the SpoolWatcher pattern
 * (enforcement.ts).
 */
export class ImportsWatcher {
  private watcher: FSWatcher | undefined;
  private timer: NodeJS.Timeout | undefined;
  private debounce: NodeJS.Timeout | undefined;

  constructor(
    private readonly deps: {
      dataDir: string;
      ingest(bundle: SandboxBundle): SandboxImportResult;
      log(message: string): void;
    },
  ) {}

  start(): void {
    const dir = importsDir(this.deps.dataDir);
    try {
      mkdirSync(dir, { recursive: true, mode: 0o700 });
      this.watcher = watch(dir, () => {
        clearTimeout(this.debounce);
        this.debounce = setTimeout(() => this.drain(), 300);
      });
      this.watcher.on("error", (err) => this.deps.log(`imports watch error: ${String(err)}`));
    } catch (err) {
      this.deps.log(`couldn't watch ${dir}: ${String(err)}`);
    }
    this.drain();
    this.timer = setInterval(() => this.drain(), 30_000);
    this.timer.unref?.();
  }

  stop(): void {
    this.watcher?.close();
    this.watcher = undefined;
    clearInterval(this.timer);
    this.timer = undefined;
    clearTimeout(this.debounce);
    this.debounce = undefined;
  }

  drain(): ImportOutcome[] {
    const outcomes = drainImports(this.deps.dataDir, (bundle) => this.deps.ingest(bundle), { consume: true, log: this.deps.log });
    for (const o of outcomes) {
      if (o.ok && o.result) {
        const r = o.result;
        this.deps.log(`imported sandbox ${r.sandbox}: ${r.turns_added} new turns, ${r.findings_added} new and ${r.findings_updated} updated detections`);
      }
    }
    return outcomes;
  }
}
