/**
 * The real `SourceIo` (transcript-sources.ts) — the only place a transcript
 * descriptor's reads touch the filesystem. Descriptors stay pure over this
 * interface so the tests can drive them from fixtures; the engine hands
 * them this implementation.
 *
 * THE SQLITE PART IS THE WHOLE REASON THIS FILE EXISTS. Cursor keeps its chats
 * in `state.vscdb`, a SQLite database the editor holds OPEN while it runs,
 * usually in WAL mode. Two consequences:
 *
 *  1. The newest rows live in `<db>-wal`, not in `<db>` — reading the main
 *     file alone silently returns a stale chat.
 *  2. Opening a WAL database, even read-only, makes SQLite want to create or
 *     touch the `-shm` companion. That is a WRITE into somebody else's live
 *     data directory, which this app does not do.
 *
 * So a database with WAL companions is SNAPSHOTTED first: `<db>`, `<db>-wal`
 * and `<db>-shm` are copied into `<userData>/store/sqlite-snapshots/` and the
 * COPY is what gets opened (read-only, `node:sqlite`'s `DatabaseSync`). The
 * source files are opened for reading and never for writing. The snapshot is
 * reused while the source's size+mtime are unchanged, so a scan that runs ten
 * queries copies once.
 *
 * `node:sqlite` is a Node core module, no dependency and nothing to ship:
 * verified present and un-flagged in this Electron's main process
 * (Electron 43.4.1 / Node 24.18.1 — `new DatabaseSync(":memory:")` works with
 * no `--experimental-sqlite`).
 */

import { createHash } from "node:crypto";
import { copyFileSync, existsSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync } from "node:fs";
import { createRequire } from "node:module";
import { basename, join } from "node:path";
import type { DatabaseSync as DatabaseSyncType } from "node:sqlite";
import type { SourceIo } from "./transcript-sources.js";

/**
 * `node:sqlite` is loaded through `createRequire` rather than imported at the
 * top: it is a Node core module that is NOT listed in `module.builtinModules`
 * (it is still flagged experimental), so a bundler resolving this file's
 * imports statically — vitest's Vite pipeline, for one — tries to find a
 * package called "sqlite" on disk and fails. A require behind a function is
 * opaque to that resolution and identical at runtime.
 */
type DatabaseSyncCtor = new (
  path: string,
  options?: { readOnly?: boolean },
) => DatabaseSyncType;

let databaseSync: DatabaseSyncCtor | undefined;

function loadDatabaseSync(): DatabaseSyncCtor {
  if (!databaseSync) {
    // Any base resolves a CORE module, and cwd is the one base that exists
    // under both the CommonJS main process and vitest's ESM transform (where
    // `__filename` is not defined).
    const req = createRequire(join(process.cwd(), "index.js"));
    databaseSync = (req("node:sqlite") as { DatabaseSync: DatabaseSyncCtor }).DatabaseSync;
  }
  return databaseSync;
}

/** The companions a WAL-mode database keeps beside itself. */
const SQLITE_SIDECARS = ["-wal", "-shm"] as const;

/** Values `node:sqlite` accepts as bound parameters. */
type SqliteParam = null | number | bigint | string | Uint8Array;

export interface SourceIoOptions {
  /** Where WAL-locked databases are snapshotted — `<userData>/store/sqlite-snapshots`. */
  snapshotDir: string;
  log?(message: string): void;
}

interface SnapshotRecord {
  /** The snapshotted copy's path — what queries actually open. */
  path: string;
  /** The source's fingerprint when the copy was taken. */
  fingerprint: string;
}

/** size+mtime of the database and each companion, as one comparable string. */
function sqliteFingerprint(path: string): string {
  const parts: string[] = [];
  for (const suffix of ["", ...SQLITE_SIDECARS]) {
    try {
      const stat = statSync(`${path}${suffix}`);
      parts.push(`${suffix}:${stat.size}:${stat.mtimeMs}`);
    } catch {
      parts.push(`${suffix}:-`);
    }
  }
  return parts.join("|");
}

/** A stable, collision-proof directory name for one source database. */
function snapshotKey(path: string): string {
  return createHash("sha256").update(path).digest("hex").slice(0, 16);
}

function coerceParam(value: unknown): SqliteParam {
  if (value === null || value === undefined) return null;
  if (typeof value === "number" || typeof value === "bigint" || typeof value === "string") return value;
  if (value instanceof Uint8Array) return value;
  if (typeof value === "boolean") return value ? 1 : 0;
  return String(value);
}

/**
 * The io the engine hands descriptors. Stateful only in its snapshot cache,
 * which is a pure optimisation: dropping it re-copies and returns the same
 * rows.
 */
export function createSourceIo(options: SourceIoOptions): SourceIo {
  const log = options.log ?? (() => {});
  const snapshots = new Map<string, SnapshotRecord>();

  /** Copy a live database (plus companions) into the scratch dir and return
   * the copy. Reused while the source is unchanged. */
  const snapshotOf = (path: string): string => {
    const fingerprint = sqliteFingerprint(path);
    const cached = snapshots.get(path);
    if (cached && cached.fingerprint === fingerprint && existsSync(cached.path)) return cached.path;
    const dir = join(options.snapshotDir, snapshotKey(path));
    mkdirSync(dir, { recursive: true });
    const target = join(dir, basename(path));
    // Remove a previous copy's companions first: a stale `-wal` beside a fresh
    // main file is a database that reads as of two different moments.
    for (const suffix of SQLITE_SIDECARS) rmSync(`${target}${suffix}`, { force: true });
    copyFileSync(path, target);
    for (const suffix of SQLITE_SIDECARS) {
      const companion = `${path}${suffix}`;
      if (existsSync(companion)) copyFileSync(companion, `${target}${suffix}`);
    }
    snapshots.set(path, { path: target, fingerprint });
    return target;
  };

  return {
    readText(path) {
      try {
        return readFileSync(path, "utf8");
      } catch {
        return undefined;
      }
    },
    listDir(path) {
      try {
        return readdirSync(path);
      } catch {
        return [];
      }
    },
    stat(path) {
      try {
        const stat = statSync(path);
        return { size: stat.size, mtimeMs: stat.mtimeMs, isDirectory: stat.isDirectory() };
      } catch {
        return undefined;
      }
    },
    querySqlite(path, sql, params = []) {
      if (!existsSync(path)) throw new Error(`no SQLite database at ${path}`);
      // Only snapshot when the host is holding the database open in WAL mode;
      // a quiescent database is read in place, read-only, with no copy at all.
      const walled = SQLITE_SIDECARS.some((suffix) => existsSync(`${path}${suffix}`));
      const target = walled ? snapshotOf(path) : path;
      const DatabaseSync = loadDatabaseSync();
      const db = new DatabaseSync(target, { readOnly: true });
      try {
        const rows = db.prepare(sql).all(...params.map(coerceParam));
        return rows as Record<string, unknown>[];
      } finally {
        try {
          db.close();
        } catch (err) {
          log(`couldn't close ${target}: ${String(err)}`);
        }
      }
    },
  };
}

/**
 * Delete snapshots whose source database is gone (an uninstalled editor, a
 * profile that was removed). Cheap, best-effort, and called at engine start:
 * a snapshot is a full copy of somebody's chat database, so it should not
 * outlive the thing it mirrors.
 */
export function pruneSqliteSnapshots(snapshotDir: string, liveDatabases: readonly string[]): void {
  let entries: string[];
  try {
    entries = readdirSync(snapshotDir);
  } catch {
    return;
  }
  const live = new Set(liveDatabases.map(snapshotKey));
  for (const entry of entries) {
    if (live.has(entry)) continue;
    try {
      rmSync(join(snapshotDir, entry), { recursive: true, force: true });
    } catch {
      // best effort — a snapshot we can't remove is re-tried next launch
    }
  }
}
