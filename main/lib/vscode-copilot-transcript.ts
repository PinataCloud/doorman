/**
 * VS Code's Copilot Chat, as a transcript source — SEEN, NOT METERED.
 *
 * WHAT IS ON DISK. One document per chat session under
 *   <user data>/User/workspaceStorage/<hash>/chatSessions/<uuid>.json[l]
 * shaped `{ sessionId, creationDate, lastMessageDate, requests: [...] }`, where
 * each request carries `timestamp`, the human `message`, the assistant
 * `response`, an `agent` ({ id: "github.copilot.default" | ".editor" | …}) and,
 * on newer VS Code builds, `modelId` ("copilot/gpt-4.1").
 *
 * TWO FORMATS, and for a while we only read one. The older `.json` file is
 * rewritten whole on every change; the newer `.jsonl` one is an append-only
 * delta log (replayChatSessionLog, whose four record kinds are taken from VS
 * Code 1.136.2's own reader). Reading only `.json` meant a chat in a current
 * build produced no ledger row AND no detection unit — a secret pasted into
 * Copilot Chat was simply never scanned.
 *
 * <user data> is per BUILD: stable VS Code, Insiders and VSCodium each keep
 * their own (lib/vscode.ts), and all of them are read.
 *
 * WHAT IS NOT ON DISK: token counts. Not in these documents, and not in the
 * newer `globalStorage/github.copilot-chat/session-store.db` either — its
 * `sessions`/`turns` schema has no usage columns at all. Copilot bills per
 * seat, and the client is never told what a request cost.
 *
 * So the turns THIS reader mints carry NO `usage` and NO `cost`: the ledger
 * shows them as activity — what was asked, when, with which model — and the
 * spend graphs leave them out rather than inventing a zero. A `$0` here would
 * be a lie about a real bill.
 *
 * THE RAIL IS METERED ANYWAY (2026-09-08). VS Code 1.136's agent mode runs on
 * the Copilot CLI SDK and writes its sessions to `~/.copilot/session-state/`
 * with `client_name: vscode`; the Copilot CLI reader (copilot-transcript.ts)
 * prices those from the CLI's own per-call usage table and attributes them to
 * THIS source, `vscode-copilot`. Hence `metered: true` below: the rail has a
 * real token signal, it just arrives through the other reader — the legacy
 * chatSessions documents here stay activity-only.
 *
 * THE WORKSPACE IS KNOWABLE AFTER ALL. The storage directory's name is an
 * opaque hash of the folder URI, but VS Code writes `workspace.json` beside the
 * chats holding the URI itself — so a single-folder window's `cwd` is read from
 * there (workspaceFolderOf) instead of being left absent. A multi-root window
 * has no single working directory and still reports none.
 *
 * Pure over `SourceIo` — no fs of its own.
 */

import type { DetectUnit } from "./cc-transcript.js";
import type { SourceIo, TranscriptSourceDescriptor } from "./transcript-sources.js";
import { type LedgerTurn, TURN_TEXT_MAX_CHARS } from "./turns.js";
import { VSCODE_VARIANTS } from "./vscode.js";

function str(value: unknown): string | undefined {
  return typeof value === "string" && value !== "" ? value : undefined;
}

/** VS Code writes `message` as a string on older builds and as
 * `{ text, parts: [...] }` on newer ones. */
function messageText(value: unknown): string {
  if (typeof value === "string") return value;
  if (!value || typeof value !== "object") return "";
  const obj = value as Record<string, unknown>;
  if (typeof obj.text === "string") return obj.text;
  const parts = obj.parts;
  if (!Array.isArray(parts)) return "";
  return parts
    .map((p) => (p && typeof p === "object" ? str((p as Record<string, unknown>).text) ?? "" : ""))
    .join("");
}

/** The assistant `response` is an array of value/markdown blocks. */
function responseText(value: unknown): string {
  if (typeof value === "string") return value;
  if (!Array.isArray(value)) return "";
  const out: string[] = [];
  for (const block of value) {
    if (typeof block === "string") {
      out.push(block);
      continue;
    }
    if (!block || typeof block !== "object") continue;
    const b = block as Record<string, unknown>;
    const v = b.value;
    if (typeof v === "string") out.push(v);
    else if (v && typeof v === "object" && typeof (v as Record<string, unknown>).value === "string") {
      out.push((v as Record<string, unknown>).value as string);
    }
  }
  return out.join("");
}

/** `.../workspaceStorage/<hash>/chatSessions/<uuid>.json[l]` → the chat's uuid.
 * The file name is VS Code's own `sessionId`, so it is stable across parses. */
export function sessionIdFromPath(path: string): string | undefined {
  const name = path.split("/").pop() ?? "";
  const stem = name.endsWith(".jsonl") ? name.slice(0, -6) : name.endsWith(".json") ? name.slice(0, -5) : "";
  return stem === "" ? undefined : stem;
}

/**
 * Replay a `.jsonl` chat session — the append-only log format VS Code writes
 * instead of rewriting the whole document on every keystroke.
 *
 * Four record kinds, read out of VS Code 1.136.2's own reader
 * (`workbench.desktop.main.js`, the `read(o)` switch beside `createInitial`):
 *
 *   {kind:0, v}          the full document — the first line, and again on
 *                        every compaction (past `_compactAfterEntries`, the
 *                        file is REPLACED by a fresh kind-0 line);
 *   {kind:1, k, v}       set `v` at the key path `k`;
 *   {kind:2, k, v, i}    at path `k`: truncate the array to length `i` (when
 *                        `i` is given), then push every element of `v`;
 *   {kind:3, k}          delete at path `k` (its own `_applySet` with
 *                        `undefined`).
 *
 * `k` is an array of object keys and array indices, walked to the second-last
 * element. Applying them in order reconstructs exactly the document the `.json`
 * format holds, so the parser below is shared.
 *
 * Torn tails are normal — VS Code appends while we read — so a line that does
 * not parse, or whose path walks into nothing, ENDS the replay and everything
 * up to it is kept. A file whose first line is not a kind 0 yields nothing: no
 * base document means every delta is a guess.
 */
export function replayChatSessionLog(contents: string): Record<string, unknown> | undefined {
  let doc: Record<string, unknown> | undefined;
  for (const line of contents.split("\n")) {
    if (line.trim() === "") continue;
    let record: { kind?: unknown; k?: unknown; v?: unknown; i?: unknown };
    try {
      record = JSON.parse(line) as typeof record;
    } catch {
      break; // a half-written last line
    }
    if (!record || typeof record !== "object") break;
    if (record.kind === 0) {
      doc = record.v && typeof record.v === "object" && !Array.isArray(record.v) ? { ...(record.v as Record<string, unknown>) } : undefined;
      continue;
    }
    if (doc === undefined) break; // "Log file is missing an initial entry"
    const path = Array.isArray(record.k) ? (record.k as (string | number)[]) : undefined;
    if (!path || path.length === 0) continue;
    // Walk to the container holding the last key; anything missing on the way
    // means the log and our reading of it have diverged, so stop rather than
    // inventing structure.
    let node: unknown = doc;
    for (let n = 0; n < path.length - 1; n++) {
      if (!node || typeof node !== "object") {
        node = undefined;
        break;
      }
      node = (node as Record<string | number, unknown>)[path[n]!];
    }
    if (!node || typeof node !== "object") break;
    const container = node as Record<string | number, unknown>;
    const key = path[path.length - 1]!;
    if (record.kind === 1) container[key] = record.v;
    else if (record.kind === 3) delete container[key];
    else if (record.kind === 2) {
      const existing = container[key];
      const array = Array.isArray(existing) ? [...existing] : [];
      if (typeof record.i === "number" && record.i >= 0) array.length = record.i;
      if (Array.isArray(record.v)) array.push(...record.v);
      container[key] = array;
    }
  }
  return doc;
}

export function parseCopilotChatSession(
  contents: string,
  sessionId: string,
  options: { cwd?: string | undefined; log?: boolean } = {},
): { turns: LedgerTurn[]; detect: DetectUnit[] } {
  const turns: LedgerTurn[] = [];
  const detect: DetectUnit[] = [];
  const cwd = options.cwd;
  let doc: Record<string, unknown>;
  if (options.log) {
    const replayed = replayChatSessionLog(contents);
    if (!replayed) return { turns, detect };
    doc = replayed;
  } else {
    try {
      const parsed = JSON.parse(contents);
      if (!parsed || typeof parsed !== "object") return { turns, detect };
      doc = parsed as Record<string, unknown>;
    } catch {
      // VS Code rewrites the whole file on each change, so a read mid-write can
      // land on truncated JSON. Nothing to salvage; the next parse gets it.
      return { turns, detect };
    }
  }
  const requests = doc.requests;
  if (!Array.isArray(requests)) return { turns, detect };

  let index = 0;
  for (const raw of requests) {
    if (!raw || typeof raw !== "object") continue;
    const req = raw as Record<string, unknown>;
    const ms = typeof req.timestamp === "number" ? req.timestamp : undefined;
    if (ms === undefined || !Number.isFinite(ms)) continue;
    const at = new Date(ms).toISOString();
    // Position in `requests` is the stable id: VS Code appends, never reorders,
    // and `requestId`/`responseId` are absent on older documents.
    const turnIndex = index;
    index += 1;

    const prompt = messageText(req.message).trim();
    if (prompt !== "") {
      const id = `vscode-copilot:${sessionId}:p${turnIndex}`;
      turns.push({
        id,
        source: "vscode-copilot",
        session_id: sessionId,
        role: "user",
        at,
        ...(cwd === undefined ? {} : { cwd }),
        text: prompt.slice(0, TURN_TEXT_MAX_CHARS),
      });
      detect.push({ kind: "prompt", raw: prompt, session_id: sessionId, turn_id: id, at });
    }

    const answer = responseText(req.response).trim();
    if (answer === "") continue;
    const id = `vscode-copilot:${sessionId}:a${turnIndex}`;
    const model = str(req.modelId);
    turns.push({
      id,
      source: "vscode-copilot",
      session_id: sessionId,
      role: "assistant",
      at,
      // `modelId` is "copilot/<model>"; keep the model half so it matches the
      // pricing table's naming even though nothing prices it here.
      ...(model === undefined ? {} : { model: model.replace(/^copilot\//, "") }),
      ...(cwd === undefined ? {} : { cwd }),
      // NO usage, NO cost — see the file header. Absent, never zero.
      text: answer.slice(0, TURN_TEXT_MAX_CHARS),
    });
    // The answer is scanned as a tool OUTPUT would be: it is model-authored text
    // that landed on this machine, so a leaked secret or an injected
    // instruction in it is worth the same look.
    detect.push({
      kind: "tool_output",
      raw: answer,
      tool_name: "copilot_chat",
      session_id: sessionId,
      turn_id: `vscode-copilot:${sessionId}:out${turnIndex}`,
      at,
    });
  }
  return { turns, detect };
}

/**
 * The FOLDER a chat belongs to. VS Code's workspaceStorage directory name is an
 * opaque hash of the folder URI — but it writes `workspace.json` beside the
 * chats, holding the URI itself:
 *   { "folder": "file:///Users/…/repo" }   single-folder window
 *   { "workspace": "file:///…/x.code-workspace" }   multi-root
 * Only the single-folder case yields a working directory; a multi-root window
 * has several and naming one would be a guess, so it stays absent.
 */
export function workspaceFolderOf(chatSessionPath: string, io: SourceIo): string | undefined {
  const dir = chatSessionPath.replace(/\/chatSessions\/[^/]*$/, "");
  if (dir === chatSessionPath) return undefined;
  const text = io.readText(`${dir}/workspace.json`);
  if (!text) return undefined;
  try {
    const parsed = JSON.parse(text) as { folder?: unknown };
    const folder = typeof parsed?.folder === "string" ? parsed.folder : undefined;
    if (!folder || !folder.startsWith("file://")) return undefined;
    return decodeURIComponent(folder.slice("file://".length)) || undefined;
  } catch {
    return undefined;
  }
}

export const vscodeCopilotSource: TranscriptSourceDescriptor = {
  id: "vscode-copilot",
  label: "VS Code + Copilot",
  presencePaths: VSCODE_VARIANTS.map((variant) => `${variant.supportRel}/User`),
  // Every build in the family, not just stable: a person on Insiders had no
  // ledger rows at all before this.
  roots: (home) => VSCODE_VARIANTS.map((variant) => `${home}/${variant.supportRel}/User/workspaceStorage`),
  discover(root, io) {
    const out: string[] = [];
    for (const workspace of io.listDir(root)) {
      const dir = `${root}/${workspace}/chatSessions`;
      if (!io.stat(dir)?.isDirectory) continue;
      for (const file of io.listDir(dir)) {
        // `.jsonl` is the newer append-only format (replayChatSessionLog).
        // Until it was read, every chat in a current VS Code build was
        // invisible here — no ledger row, and, worse, no detection unit.
        if (file.endsWith(".json") || file.endsWith(".jsonl")) out.push(`${dir}/${file}`);
      }
    }
    return out;
  },
  parse(path, io) {
    const sessionId = sessionIdFromPath(path);
    if (!sessionId) return { turns: [], titles: [], detect: [] };
    const contents = io.readText(path);
    if (!contents) return { turns: [], titles: [], detect: [] };
    const cwd = workspaceFolderOf(path, io);
    return { ...parseCopilotChatSession(contents, sessionId, { cwd, log: path.endsWith(".jsonl") }), titles: [] };
  },
  sessionIdOf: sessionIdFromPath,
  // See the header: priced turns for this rail come from the Copilot CLI
  // reader's session-store rows; these documents stay unpriced.
  metered: true,
};
