/**
 * Cursor session reading — the `cursor` TranscriptSourceDescriptor.
 *
 * Cursor keeps its agent/chat state in the VS Code key-value SQLite databases
 * it inherited from its fork, NOT in per-session transcript files. Everything
 * below was read off Cursor 3.15.19 on macOS (observed 2026-09-06); none of it
 * is documented by Cursor, so treat the shapes as version-dependent and let a
 * record you don't recognise fall through rather than throwing.
 *
 *   ~/Library/Application Support/Cursor/User/globalStorage/state.vscdb
 *     cursorDiskKV(key, value)   — value is a JSON blob
 *       composerData:<composerId>   one chat/agent session ("composer")
 *         .fullConversationHeadersOnly[]  {bubbleId, type, createdAt?}
 *                                          — THE conversation order; the
 *                                            bubble rows themselves come back
 *                                            in key order, which is not it
 *         .createdAt / .lastUpdatedAt      epoch ms
 *         .name                            Cursor's own generated chat title
 *         .modelConfig.modelName           session-level model ("composer-2.5",
 *                                          "default" when the user picked Auto)
 *         .usageData                       observed ALWAYS `{}` — empty
 *       bubbleId:<composerId>:<bubbleId>   one message
 *         .type            1 = user, 2 = assistant
 *         .text            the message text (user text is already unwrapped —
 *                          no <user_query> envelope, unlike the CLI's JSONL)
 *         .tokenCount      {inputTokens, outputTokens} — see METERING below
 *         .createdAt       ISO string, only on records written by newer builds
 *         .timingInfo.clientEndTime  epoch ms, only on some 2025-era records
 *         .modelInfo.modelName       per-message model, rarely present
 *         .toolFormerData  ONE tool call: {name, tool, status, rawArgs, params,
 *                          result, error, toolCallId} — a tool call is its own
 *                          assistant bubble, and such a bubble never has text
 *     composerHeaders(composerId, workspaceId, createdAt, …)
 *                          — the newer index; `workspaceId` is a
 *                            workspaceStorage directory name
 *
 *   ~/Library/Application Support/Cursor/User/workspaceStorage/<hash>/
 *     workspace.json       {"folder": "file:///abs/path"}  → the session's cwd
 *     state.vscdb  ItemTable['composer.composerData'].allComposers[].composerId
 *                          — which composers belong to this workspace (older
 *                            builds; newer ones use composerHeaders.workspaceId)
 *
 * TURN SHAPE. The header order is always
 * `user → [tool bubbles…] → assistant text bubble`, the same settle-at-the-end
 * rhythm as a Codex rollout, so tool bubbles accumulate and land on the next
 * assistant turn (`tools`, and their detect units). Turn ids are
 * `cursor:<composerId>:<bubbleId>` — both halves are Cursor's own uuids, so a
 * re-parse mints exactly the same id.
 *
 * METERING. Cursor DOES record token counts, but only sometimes and only
 * partly: `tokenCount.inputTokens` / `.outputTokens` per assistant turn (26 of
 * 174 bubbles in the observed database), no cache split, no reasoning split,
 * and NO cost — Cursor bills requests/credits, not tokens, and records nothing
 * about which. So: `usage` only when a count is actually non-zero, cost derived
 * locally from the pricing table exactly like every other source (and therefore
 * `cost_unknown` for Cursor's own `composer-*` models, which have no public
 * per-token price), and settlement always `unknown`. The 2026 `composer-2.5`
 * records observed here carry `{inputTokens: 0, outputTokens: 0}` — a session
 * that shows up unmetered is Cursor not writing the numbers, not a bug here.
 *
 * TIMESTAMPS. Only newer records carry their own instant. A bubble without one
 * inherits, in order: its header's `createdAt`, its `timingInfo.clientEndTime`,
 * the last instant seen earlier in the same conversation, and finally the
 * composer's `createdAt`. Order is preserved from the header array, so the
 * ledger reads correctly even when several turns share an inherited instant.
 *
 * FRESHNESS (a note for the capture engine). `state.vscdb` runs in WAL mode:
 * while Cursor is open, writes can sit in `state.vscdb-wal` without changing
 * the main file's size or mtime, so a size+mtime cursor may not see a new turn
 * until SQLite checkpoints. Watching the globalStorage directory (not just the
 * file) is what catches it.
 */

import { toolTarget, type DetectUnit, type TranscriptParseResult } from "./cc-transcript.js";
import { deriveCost, inferModelProvider } from "./pricing.js";
import type { SourceIo, TranscriptSourceDescriptor } from "./transcript-sources.js";
import {
  type LedgerTurn,
  type TitleRecord,
  type TurnUsage,
  TOOL_OUTPUT_MAX_CHARS,
  TURN_TEXT_MAX_CHARS,
  TURN_TOOLS_MAX,
} from "./turns.js";

const CURSOR_USER_DIR = "Library/Application Support/Cursor/User";
const GLOBAL_STORAGE = `${CURSOR_USER_DIR}/globalStorage`;
const WORKSPACE_STORAGE = `${CURSOR_USER_DIR}/workspaceStorage`;
/** The one database file under globalStorage that holds sessions.
 * `state.vscdb.backup` is a stale copy of it — parsing both would double every
 * turn id's provenance for no new information, so it is deliberately skipped. */
const STATE_DB = "state.vscdb";

function str(value: unknown): string | undefined {
  return typeof value === "string" && value !== "" ? value : undefined;
}

function obj(value: unknown): Record<string, unknown> | undefined {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;
}

function toInt(value: unknown): number {
  const n = typeof value === "number" ? value : Number(value);
  if (!Number.isFinite(n) || n <= 0) return 0;
  return Math.floor(n);
}

/** An ISO instant from either an ISO string or Cursor's epoch-ms numbers. */
function isoOf(value: unknown): string | undefined {
  if (typeof value === "string") {
    return value !== "" && !Number.isNaN(Date.parse(value)) ? value : undefined;
  }
  if (typeof value !== "number" || !Number.isFinite(value) || value <= 0) return undefined;
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? undefined : d.toISOString();
}

/** JSON that a half-written record may not actually be. */
function parseJson(value: unknown): Record<string, unknown> | undefined {
  if (typeof value !== "string" || value === "") return undefined;
  try {
    const parsed: unknown = JSON.parse(value);
    return obj(parsed);
  } catch {
    return undefined;
  }
}

/** A SQLite blob column comes back as a string or a Buffer/Uint8Array. */
function cellText(value: unknown): string | undefined {
  if (typeof value === "string") return value;
  if (value instanceof Uint8Array) return new TextDecoder().decode(value);
  return undefined;
}

/**
 * Every query is best-effort: a database Cursor is mid-write on, a table an
 * older build never created, a corrupt page — all mean "nothing to read here",
 * never a throw out of `parse` (contract rule: total).
 */
function query(
  io: SourceIo,
  path: string,
  sql: string,
  params?: readonly unknown[],
): Record<string, unknown>[] {
  try {
    return io.querySqlite(path, sql, params) ?? [];
  } catch {
    return [];
  }
}

/** Composer ids are uuids; anything that could smuggle a LIKE wildcard or a
 * key-separator into the prefix query is refused rather than escaped. */
function safeComposerId(id: string): boolean {
  return id !== "" && id.length <= 128 && /^[A-Za-z0-9.-]+$/.test(id);
}

/** `file:///Users/dev/repo` → `/Users/dev/repo`. */
function pathFromFileUri(uri: string): string | undefined {
  if (!uri.startsWith("file://")) return undefined;
  const raw = uri.slice("file://".length);
  if (raw === "" || raw === "/") return undefined;
  try {
    return decodeURIComponent(raw);
  } catch {
    return raw;
  }
}

/** `…/User/globalStorage/state.vscdb` → `…/User/workspaceStorage`, or
 * undefined when the document isn't where Cursor actually keeps it. */
function workspaceStorageDirFor(dbPath: string): string | undefined {
  const marker = `/${GLOBAL_STORAGE}/`;
  const idx = dbPath.lastIndexOf(marker);
  if (idx < 0) return undefined;
  return `${dbPath.slice(0, idx)}/${WORKSPACE_STORAGE}`;
}

/**
 * composerId → the absolute folder its window had open, from the two mappings
 * Cursor has used: the older per-workspace `composer.composerData` list, and
 * the newer `composerHeaders.workspaceId` pointing at a workspaceStorage
 * directory. Cheap (one indexed key lookup per workspace) and only ever read
 * when the global database itself changed.
 */
function workspaceCwdMap(dbPath: string, io: SourceIo): Map<string, string> {
  const byComposer = new Map<string, string>();
  const wsRoot = workspaceStorageDirFor(dbPath);
  if (!wsRoot) return byComposer;
  const folderByDir = new Map<string, string>();
  for (const dir of io.listDir(wsRoot)) {
    const meta = parseJson(io.readText(`${wsRoot}/${dir}/workspace.json`));
    const folder = str(meta?.folder);
    // Multi-root `.code-workspace` windows record `workspace` (a path to the
    // workspace file) instead of a single `folder` — no one cwd to name, so
    // those sessions are left without one rather than given a guess.
    const cwd = folder ? pathFromFileUri(folder) : undefined;
    if (!cwd) continue;
    folderByDir.set(dir, cwd);
    for (const row of query(
      io,
      `${wsRoot}/${dir}/${STATE_DB}`,
      "SELECT value FROM ItemTable WHERE key = ?",
      ["composer.composerData"],
    )) {
      const data = parseJson(cellText(row.value));
      const all = data?.allComposers;
      if (!Array.isArray(all)) continue;
      for (const entry of all) {
        const id = str(obj(entry)?.composerId);
        if (id) byComposer.set(id, cwd);
      }
    }
  }
  for (const row of query(io, dbPath, "SELECT composerId, workspaceId FROM composerHeaders")) {
    const id = str(row.composerId);
    const ws = str(row.workspaceId);
    if (!id || !ws || byComposer.has(id)) continue;
    const cwd = folderByDir.get(ws);
    if (cwd) byComposer.set(id, cwd);
  }
  return byComposer;
}

/**
 * The file/command a Cursor tool acted on. Cursor's arg names differ per tool
 * and between the model's own `rawArgs` and the client-normalised `params`, so
 * both are tried before falling back to the shared Claude Code/Codex rule.
 */
function cursorToolTarget(name: string, args: Record<string, unknown> | undefined): string | undefined {
  if (!args) return undefined;
  const command = str(args.command);
  if (command) {
    const head = command.trim().split(/\s+/, 1)[0];
    return head === "" ? undefined : head;
  }
  return (
    str(args.target_file) ??
    str(args.relative_workspace_path) ??
    str(args.relativeWorkspacePath) ??
    str(args.directoryPath) ??
    str(args.glob_pattern) ??
    str(args.search_term) ??
    str(args.query) ??
    toolTarget(name, args)
  );
}

/** What a tool bubble returned: the JSON result envelope, or its error. */
function toolOutputText(tool: Record<string, unknown>): string | undefined {
  return str(tool.result) ?? str(tool.error);
}

interface ComposerRecord {
  id: string;
  data: Record<string, unknown>;
}

/** One session's turns + detect units, appended onto the shared accumulators. */
function parseComposer(
  composer: ComposerRecord,
  bubbles: Map<string, Record<string, unknown>>,
  cwd: string | undefined,
  out: { turns: LedgerTurn[]; detect: DetectUnit[]; titles: TitleRecord[] },
): void {
  const { id: sessionId, data } = composer;
  const headers = Array.isArray(data.fullConversationHeadersOnly)
    ? data.fullConversationHeadersOnly
    : [];
  const sessionModel = (() => {
    const name = str(obj(data.modelConfig)?.modelName);
    // "default"/"auto" is the picker's placeholder, not a model anyone can price.
    return name && name !== "default" && name !== "auto" ? name : undefined;
  })();
  const composerStart = isoOf(data.createdAt) ?? isoOf(data.lastUpdatedAt);

  // Ordered bubble ids: the header array is the conversation; anything the
  // headers missed (a bubble written between header rewrites) is appended in a
  // deterministic order so a re-parse doesn't reshuffle it.
  const ordered: { bubbleId: string; header: Record<string, unknown> | undefined }[] = [];
  const seen = new Set<string>();
  for (const raw of headers) {
    const header = obj(raw);
    const bubbleId = str(header?.bubbleId);
    if (!bubbleId || seen.has(bubbleId)) continue;
    seen.add(bubbleId);
    ordered.push({ bubbleId, header });
  }
  for (const bubbleId of [...bubbles.keys()].sort()) {
    if (!seen.has(bubbleId)) ordered.push({ bubbleId, header: undefined });
  }

  let lastAt: string | undefined;
  let pendingTools: DetectUnit[] = [];
  let emittedAnything = false;

  const flushOrphanTools = (): void => {
    // Tool calls that never reached an assistant turn still get scanned,
    // anchored to a session-stable tail id (same rule as the Codex reader).
    for (const unit of pendingTools) out.detect.push({ ...unit, turn_id: `cursor:${sessionId}:tail` });
    pendingTools = [];
  };

  for (const { bubbleId, header } of ordered) {
    const bubble = bubbles.get(bubbleId);
    if (!bubble) continue;
    // A recorded instant advances the carry-forward clock; an inherited one
    // does not, so a run of undated records all read as the last real instant
    // rather than drifting.
    const recorded =
      isoOf(bubble.createdAt) ??
      isoOf(header?.createdAt) ??
      isoOf(obj(bubble.timingInfo)?.clientEndTime);
    if (recorded) lastAt = recorded;
    const at = recorded ?? lastAt ?? composerStart;
    if (!at) continue; // no instant anywhere for this session — unchartable
    const type = bubble.type ?? header?.type;
    const text = str(bubble.text)?.trim();
    const turnId = `cursor:${sessionId}:${bubbleId}`;

    if (type === 1) {
      if (!text) continue;
      flushOrphanTools();
      out.turns.push({
        id: turnId,
        source: "cursor",
        session_id: sessionId,
        role: "user",
        at,
        text: text.slice(0, TURN_TEXT_MAX_CHARS),
        ...(cwd === undefined ? {} : { cwd }),
      });
      out.detect.push({
        kind: "prompt",
        raw: text,
        session_id: sessionId,
        turn_id: turnId,
        at,
        ...(cwd === undefined ? {} : { cwd }),
      });
      emittedAnything = true;
      continue;
    }
    if (type !== 2) continue;

    const tool = obj(bubble.toolFormerData);
    const toolName = str(tool?.name);
    if (tool && toolName) {
      const rawArgs = str(tool.rawArgs) ?? str(tool.params);
      const args = parseJson(tool.rawArgs) ?? parseJson(tool.params);
      pendingTools.push({
        kind: "tool_call",
        raw: rawArgs ?? "{}",
        tool_name: toolName,
        ...(() => {
          const target = cursorToolTarget(toolName, args);
          return target === undefined ? {} : { target };
        })(),
        session_id: sessionId,
        turn_id: "", // assigned when the settling assistant turn arrives
        at,
        ...(cwd === undefined ? {} : { cwd }),
      });
      const output = toolOutputText(tool);
      if (output) {
        pendingTools.push({
          kind: "tool_output",
          raw: output.slice(0, TOOL_OUTPUT_MAX_CHARS),
          tool_name: toolName,
          session_id: sessionId,
          turn_id: "",
          at,
          ...(cwd === undefined ? {} : { cwd }),
        });
      }
      continue;
    }

    const counts = obj(bubble.tokenCount);
    const input = toInt(counts?.inputTokens);
    const output = toInt(counts?.outputTokens);
    // An assistant bubble with nothing in it (no text, no tool, no tokens) is
    // a render placeholder, not a turn.
    if (!text && input === 0 && output === 0 && pendingTools.length === 0) continue;

    const model = str(obj(bubble.modelInfo)?.modelName) ?? sessionModel;
    // Cursor records only the two totals — no cache split exists to report, and
    // inventing zeros for buckets it never measured would be a lie the fold
    // then sums. `usage` is emitted only when a real count is present.
    const usage: TurnUsage | undefined =
      input > 0 || output > 0
        ? {
            input_tokens: input,
            output_tokens: output,
            cache_read_tokens: 0,
            cache_write_tokens: 0,
            cache_write_1h_tokens: 0,
            web_search_requests: 0,
          }
        : undefined;
    const cost =
      usage && model
        ? deriveCost({
            model_provider: inferModelProvider(model) ?? "cursor",
            model,
            input_tokens: usage.input_tokens,
            output_tokens: usage.output_tokens,
            cached_tokens: 0,
            cache_read_tokens: 0,
            cache_write_tokens: 0,
            web_search_requests: 0,
          })
        : undefined;
    const calls = pendingTools.filter((u) => u.kind === "tool_call");
    out.turns.push({
      id: turnId,
      source: "cursor",
      session_id: sessionId,
      role: "assistant",
      at,
      ...(model === undefined ? {} : { model }),
      ...(usage === undefined ? {} : { usage }),
      // No usage, or a model with no public per-token price (every `composer-*`),
      // means the cost is UNKNOWN — never a silent zero.
      ...(cost === undefined ? { cost_unknown: true } : { cost }),
      // Cursor bills by request/credit and records neither the plan state nor
      // the charge, so nothing here can honestly claim coverage.
      settlement: "unknown",
      ...(text === undefined ? {} : { text: text.slice(0, TURN_TEXT_MAX_CHARS) }),
      ...(calls.length === 0
        ? {}
        : { tools: calls.slice(0, TURN_TOOLS_MAX).map((u) => u.tool_name ?? "?") }),
      ...(cwd === undefined ? {} : { cwd }),
    });
    for (const unit of pendingTools) out.detect.push({ ...unit, turn_id: turnId });
    pendingTools = [];
    emittedAnything = true;
  }
  flushOrphanTools();

  // Cursor names a chat itself once it has content — the auto_summary tier,
  // the same rank as Claude Code's own ai-title record.
  const name = str(data.name)?.trim();
  if (name && emittedAnything) {
    out.titles.push({ session_id: sessionId, title: { text: name, origin: "auto_summary" } });
  }
}

/** Parse one Cursor `state.vscdb`. Pure over `io`, idempotent, never throws. */
export function parseCursorStateDb(path: string, io: SourceIo): TranscriptParseResult {
  const out = { turns: [] as LedgerTurn[], detect: [] as DetectUnit[], titles: [] as TitleRecord[] };
  const composerRows = query(io, path, "SELECT key, value FROM cursorDiskKV WHERE key LIKE ?", [
    "composerData:%",
  ]);
  if (composerRows.length === 0) return { turns: [], titles: [], detect: [] };
  const cwdByComposer = workspaceCwdMap(path, io);

  for (const row of composerRows) {
    const key = str(row.key);
    if (!key) continue;
    const id = key.slice("composerData:".length);
    if (!safeComposerId(id)) continue;
    const data = parseJson(cellText(row.value));
    if (!data) continue;
    const bubbles = new Map<string, Record<string, unknown>>();
    for (const bubbleRow of query(io, path, "SELECT key, value FROM cursorDiskKV WHERE key LIKE ?", [
      `bubbleId:${id}:%`,
    ])) {
      const bubbleKey = str(bubbleRow.key);
      if (!bubbleKey) continue;
      const bubbleId = bubbleKey.slice(`bubbleId:${id}:`.length);
      const parsed = parseJson(cellText(bubbleRow.value));
      if (bubbleId && parsed) bubbles.set(bubbleId, parsed);
    }
    if (bubbles.size === 0) continue;
    parseComposer({ id, data }, bubbles, cwdByComposer.get(id), out);
  }
  return { turns: out.turns, titles: out.titles, detect: out.detect };
}

export const cursorSource: TranscriptSourceDescriptor = {
  id: "cursor",
  label: "Cursor",
  presencePaths: ["/Applications/Cursor.app", ".cursor"],
  roots(home: string): string[] {
    // Only globalStorage holds sessions; workspaceStorage is a lookup `parse`
    // performs itself (which composer had which folder open), so it is not a
    // root the engine needs to watch.
    return [`${home}/${GLOBAL_STORAGE}`];
  },
  discover(root: string, io: SourceIo): string[] {
    const path = `${root}/${STATE_DB}`;
    const stat = io.stat(path);
    return stat && !stat.isDirectory ? [path] : [];
  },
  parse(path: string, io: SourceIo): TranscriptParseResult {
    return parseCursorStateDb(path, io);
  },
  sessionIdOf(): string | undefined {
    // One database holds every session — the path names no single one.
    return undefined;
  },
  // Cursor records per-turn inputTokens/outputTokens for at least some builds
  // and models; see METERING in the header for exactly how partial that is.
  metered: true,
};
