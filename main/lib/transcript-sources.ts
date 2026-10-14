/**
 * The transcript-source contract — one descriptor per agent host whose
 * sessions the Mac app can READ from disk and turn into ledger turns (and
 * detection units): Claude Code and Codex today, Cursor, Gemini CLI and
 * Copilot CLI next ("metering" — the guard reaches a host, this is what makes its sessions
 * show up in the Event Ledger).
 *
 * A descriptor is PURE over the `SourceIo` it is handed: no fs, no sqlite, no
 * process of its own, so the tests can drive it from fixtures. The capture
 * engine (main/capture.ts) owns the io, the size+mtime cursors, the
 * watchers and the store; it iterates the registry
 * (`TRANSCRIPT_SOURCES` in transcript-sources-registry.ts, written by the
 * engine workstream) instead of naming hosts.
 *
 * Three rules every descriptor lives by:
 *  1. STABLE TURN IDS. `parse` is re-run on every change to a document; the id
 *     of a turn must be the same across re-parses (a message id, a session id
 *     + monotonic counter) so the store converges and never duplicates.
 *  2. HONEST NUMBERS. Emit `usage` only when the host recorded token counts;
 *     a model without a known price is `cost_unknown`, never $0; settlement
 *     is `unknown` unless the host says otherwise.
 *  3. LOCAL TEXT. Prompt/assistant `text` on a turn stays on this machine
 *     (capped at TURN_TEXT_MAX_CHARS) and is never sent anywhere.
 *
 * This file is the seam every parser is built against — extend it
 * ADDITIVELY (optional fields); never rename or remove.
 */

import type { DetectUnit, TranscriptParseResult } from "./cc-transcript.js";
import type { TurnSource } from "./turns.js";

export type { DetectUnit, TranscriptParseResult };

/** The reads a descriptor may perform, all synchronous and all injectable. */
export interface SourceIo {
  /** File text, or undefined when missing/unreadable. */
  readText(path: string): string | undefined;
  /** Entries (names, not paths) of a directory; [] when missing. */
  listDir(path: string): string[];
  /** size + mtime, or undefined when missing. */
  stat(path: string): { size: number; mtimeMs: number; isDirectory: boolean } | undefined;
  /**
   * Rows of a read-only SQLite query against a database file (Cursor's
   * `state.vscdb`). The engine opens the file read-only (`node:sqlite`,
   * `DatabaseSync` with `readOnly: true`; a WAL-locked copy is read from a
   * scratch snapshot) and never writes. Throws on a missing/corrupt database.
   */
  querySqlite(path: string, sql: string, params?: readonly unknown[]): Record<string, unknown>[];
}

export interface TranscriptSourceDescriptor {
  /** The source id, also the ledger's `LedgerTurn.source`. */
  id: TurnSource;
  /** Human label ("Gemini CLI"). */
  label: string;
  /** Home-relative paths whose presence means the host is installed here. */
  presencePaths: string[];
  /**
   * The directories (absolute) under which this host keeps its session
   * documents; the engine watches these. `home` is the user's home, already
   * resolved; `env` carries overrides (CODEX_HOME-style). Pure.
   */
  roots(home: string, env: NodeJS.ProcessEnv): string[];
  /**
   * Every session document under one root — a JSON/JSONL file, or a SQLite
   * database path. The engine keeps a size+mtime cursor per returned path and
   * calls `parse` when one changes. Pure over `io`.
   */
  discover(root: string, io: SourceIo): string[];
  /**
   * Turns + detection units for one document. MUST be idempotent (rule 1) and
   * total: a document the host is still writing (a half line, a mid-write
   * database) yields what can be read and no throw. Pure over `io`.
   */
  parse(path: string, io: SourceIo): TranscriptParseResult;
  /** The session id a document belongs to, from its path alone when the host
   * encodes it there (used before the document is parsed); undefined otherwise. */
  sessionIdOf(path: string): string | undefined;
  /**
   * The host has no native session-level cost or usage signal at all — the
   * ledger shows its sessions as activity ("seen, not metered") rather than
   * as spend. Cursor's and Copilot's chats are like this unless the parser
   * finds token counts; Gemini CLI records tokens per message.
   */
  metered: boolean;
}
