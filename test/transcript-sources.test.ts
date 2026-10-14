import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  TRANSCRIPT_SOURCES,
  allSourceLabels,
  sourceById,
  sourceLabel,
} from "../main/lib/transcript-sources-registry.js";
import { createSourceIo, pruneSqliteSnapshots } from "../main/lib/source-io.js";
import type { TranscriptSourceDescriptor } from "../main/lib/transcript-sources.js";

/**
 * The registry and the real io behind it. The io test writes an actual SQLite
 * database — WAL companions included — and asserts that querying it goes
 * through a snapshot and leaves the source untouched, which is the whole
 * contract Cursor's live `state.vscdb` needs.
 */

const fake = (over: Partial<TranscriptSourceDescriptor> = {}): TranscriptSourceDescriptor => ({
  id: "cursor",
  label: "Cursor",
  presencePaths: [".cursor"],
  roots: () => [],
  discover: () => [],
  parse: () => ({ turns: [], titles: [], detect: [] }),
  sessionIdOf: () => undefined,
  metered: false,
  ...over,
});

describe("the transcript-source registry", () => {
  it("ships empty until a parser is registered, and every entry is well formed", () => {
    for (const source of TRANSCRIPT_SOURCES) {
      expect(source.id).toBeTruthy();
      expect(source.label).toBeTruthy();
      expect(source.presencePaths.length).toBeGreaterThan(0);
    }
    // Ids are unique — two descriptors for one rail would double-count it.
    expect(new Set(TRANSCRIPT_SOURCES.map((s) => s.id)).size).toBe(TRANSCRIPT_SOURCES.length);
  });

  it("finds a descriptor by id", () => {
    const registry = [fake()];
    expect(sourceById("cursor", registry)?.label).toBe("Cursor");
    expect(sourceById("gemini-cli", registry)).toBeUndefined();
  });

  it("labels the two built-in rails without a descriptor, and falls back to the id", () => {
    expect(sourceLabel("claude-code", [])).toBe("Claude Code");
    expect(sourceLabel("codex", [])).toBe("Codex");
    // A stored turn from a host whose descriptor was removed still renders.
    expect(sourceLabel("gemini-cli", [])).toBe("gemini-cli");
    expect(sourceLabel("cursor", [fake()])).toBe("Cursor");
  });

  it("lists the native rails first, then the registry, for display", () => {
    expect(allSourceLabels([fake()]).map((s) => s.id)).toEqual(["claude-code", "codex", "cursor"]);
  });
});

describe("the source io", () => {
  let root: string;
  let io: ReturnType<typeof createSourceIo>;

  beforeEach(() => {
    root = mkdtempSync(join(tmpdir(), "doorman-io-"));
    io = createSourceIo({ snapshotDir: join(root, "snapshots") });
  });

  afterEach(() => {
    rmSync(root, { recursive: true, force: true });
  });

  it("reads text, lists directories and stats, answering emptily for what is missing", () => {
    mkdirSync(join(root, "docs"));
    writeFileSync(join(root, "docs", "a.json"), "{}");
    expect(io.readText(join(root, "docs", "a.json"))).toBe("{}");
    expect(io.readText(join(root, "nope.json"))).toBeUndefined();
    expect(io.listDir(join(root, "docs"))).toEqual(["a.json"]);
    expect(io.listDir(join(root, "nope"))).toEqual([]);
    expect(io.stat(join(root, "docs"))?.isDirectory).toBe(true);
    expect(io.stat(join(root, "nope"))).toBeUndefined();
  });

  it("queries a quiescent database in place, and throws for one that isn't there", () => {
    const { DatabaseSync } = createRequire(join(process.cwd(), "index.js"))("node:sqlite") as typeof import("node:sqlite");
    const dbPath = join(root, "plain.vscdb");
    const db = new DatabaseSync(dbPath);
    db.exec("CREATE TABLE ItemTable (key TEXT, value TEXT)");
    db.exec("INSERT INTO ItemTable VALUES ('chat', '{\"turns\":1}')");
    db.close();

    const rows = io.querySqlite(dbPath, "SELECT key, value FROM ItemTable WHERE key = ?", ["chat"]);
    expect(rows).toEqual([{ key: "chat", value: '{"turns":1}' }]);
    // Nothing was copied: no WAL, no snapshot.
    expect(existsSync(join(root, "snapshots"))).toBe(false);
    expect(() => io.querySqlite(join(root, "gone.vscdb"), "SELECT 1")).toThrow();
  });

  it("snapshots a WAL-mode database, reads the WAL's rows, and never writes to the source", () => {
    const { DatabaseSync } = createRequire(join(process.cwd(), "index.js"))("node:sqlite") as typeof import("node:sqlite");
    const dbPath = join(root, "state.vscdb");
    // A live editor's database: WAL journal, left OPEN with uncheckpointed rows
    // in `state.vscdb-wal` — exactly the state Cursor keeps it in.
    const live = new DatabaseSync(dbPath);
    live.exec("PRAGMA journal_mode = WAL");
    live.exec("CREATE TABLE ItemTable (key TEXT, value TEXT)");
    live.exec("INSERT INTO ItemTable VALUES ('a', 'in the main file')");
    live.exec("INSERT INTO ItemTable VALUES ('b', 'in the wal')");
    expect(existsSync(`${dbPath}-wal`)).toBe(true);

    const before = readFileSync(dbPath);
    const beforeWal = readFileSync(`${dbPath}-wal`);
    const rows = io.querySqlite(dbPath, "SELECT key, value FROM ItemTable ORDER BY key");

    // The WAL's row came back — reading the main file alone would have missed it.
    expect(rows.map((r) => r.value)).toEqual(["in the main file", "in the wal"]);
    // The source database and its journal are byte-identical: the read went to
    // a copy, and nothing of ours checkpointed or locked the live files.
    // (Compared before `live.close()`, which is the EDITOR checkpointing.)
    expect(readFileSync(dbPath).equals(before)).toBe(true);
    expect(readFileSync(`${dbPath}-wal`).equals(beforeWal)).toBe(true);
    expect(existsSync(join(root, "snapshots"))).toBe(true);
    live.close();
  });

  it("prunes snapshots whose source database is gone", () => {
    const { DatabaseSync } = createRequire(join(process.cwd(), "index.js"))("node:sqlite") as typeof import("node:sqlite");
    const dbPath = join(root, "state.vscdb");
    const live = new DatabaseSync(dbPath);
    live.exec("PRAGMA journal_mode = WAL");
    live.exec("CREATE TABLE t (a)");
    live.exec("INSERT INTO t VALUES (1)");
    io.querySqlite(dbPath, "SELECT a FROM t");
    live.close();

    const snapshots = join(root, "snapshots");
    expect(io.listDir(snapshots).length).toBe(1);
    // Still live: kept.
    pruneSqliteSnapshots(snapshots, [dbPath]);
    expect(io.listDir(snapshots).length).toBe(1);
    // The editor was uninstalled: the copy of its chat database goes too.
    pruneSqliteSnapshots(snapshots, []);
    expect(io.listDir(snapshots).length).toBe(0);
  });
});
