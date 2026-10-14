/**
 * Claude Desktop's Cowork / local-agent mode, as a transcript source.
 *
 * WHAT IS ON DISK. Each session gets a directory under
 *   ~/Library/Application Support/Claude/local-agent-mode-sessions/
 *     <account>/<org>/local_<uuid>/
 * holding an `audit.jsonl`, plus a sibling `local_<uuid>.json` sidecar with the
 * session's model, title, cwd, selected folders and timestamps.
 *
 * The audit log is Claude Code's own stream-json shape — `{type: "user" |
 * "assistant" | "system" | "result", message: {...}}` — with one extra field
 * per line, `_audit_hmac`, because it is written as a tamper-evident record.
 * That means it carries what a rail needs and what we had assumed was locked
 * inside the VM image: per-message `usage` (input / output / cache_creation /
 * cache_read) and a closing `result` record with `total_cost_usd`,
 * `num_turns` and `duration_ms`. So this source is METERED — real tokens, real
 * dollars — not activity-only.
 *
 * WHY IT IS NOT JUST THE CLAUDE CODE PARSER. The agent itself runs in a Linux
 * VM whose own transcripts live in `sessiondata.img`, and its hooks never fire
 * on the host (so the guard cannot reach it). The host-side audit log is a
 * different document from `~/.claude/projects/**.jsonl`: no `sessionId` on each
 * line, no `cwd`, no `gitBranch`, ids that must come from the enclosing
 * directory, and a `result` record Claude Code's transcripts do not write.
 * Sharing the parser would mean bending both.
 *
 * TURN IDS are `claude-desktop:<session>:<message id>` for an assistant turn
 * (the Anthropic message id, stable across re-parses) and
 * `claude-desktop:<session>:p<n>` for a prompt, matching the Codex rail's
 * convention for hosts that do not id their user messages.
 *
 * ONE LINE PER CONTENT BLOCK, ONE USAGE PER MESSAGE. The log splits a single
 * assistant message across several lines — one for its `thinking` block, one
 * per `text`, one per `tool_use` — and REPEATS the identical `usage` object on
 * every one of them. Summing usage-bearing lines therefore inflates a session
 * (measured: 1,173,622 cache-read tokens against a true 626,776). Messages are
 * folded by id and the usage counted once, which reproduces the log's own
 * `result.usage` exactly for input, cache_creation and cache_read.
 *
 * WHERE COST COMES FROM. The per-message `output_tokens` is a partial,
 * mid-stream figure (679 summed against the `result` record's 5,271), so
 * pricing each turn off the table would be wrong twice over — wrong tokens,
 * and list rates for a session billed under a subscription. Measured on a real
 * session: $2.96 derived, $1.10 actually recorded. So assistant turns carry
 * their verified `usage` and NO cost at all, and the session's cost is the
 * `result` record's `total_cost_usd`, attached to the last assistant turn. The
 * session total is then exactly what the host says it was, and nothing is
 * invented. A session still running has no `result` yet and reads as $0 until
 * it finishes — honest, and it settles itself on the next parse.
 *
 * Pure over `SourceIo` — no fs of its own — so tests drive it from fixtures.
 */


import type { DetectUnit } from "./cc-transcript.js";
import type { SourceIo, TranscriptSourceDescriptor } from "./transcript-sources.js";
import {
  type LedgerTurn,
  TOOL_OUTPUT_MAX_CHARS,
  TURN_TEXT_MAX_CHARS,
  TURN_TOOLS_MAX,
} from "./turns.js";

const SESSIONS_REL = "Library/Application Support/Claude/local-agent-mode-sessions";

/** `local_<uuid>` — a session directory, and the stem of its sidecar. */
const SESSION_DIR_RE = /^local_[0-9a-f-]{8,}$/i;

function str(value: unknown): string | undefined {
  return typeof value === "string" && value !== "" ? value : undefined;
}

function toInt(value: unknown): number {
  const n = typeof value === "number" ? value : Number(value);
  return Number.isFinite(n) && n > 0 ? Math.floor(n) : 0;
}

/** The session id from an audit.jsonl path: the `local_<uuid>` directory it
 * sits in, with the prefix dropped so it reads like every other session id. */
export function sessionIdFromPath(path: string): string | undefined {
  const parts = path.split("/");
  for (let i = parts.length - 1; i >= 0; i -= 1) {
    if (SESSION_DIR_RE.test(parts[i])) return parts[i].replace(/^local_/i, "");
  }
  return undefined;
}

/** Text out of an Anthropic content array (or a plain string body). */
function contentText(content: unknown): string {
  if (typeof content === "string") return content;
  if (!Array.isArray(content)) return "";
  const out: string[] = [];
  for (const block of content) {
    if (!block || typeof block !== "object") continue;
    const b = block as Record<string, unknown>;
    if (b.type === "text" && typeof b.text === "string") out.push(b.text);
  }
  return out.join("\n");
}

/**
 * The sidecar next to a session directory. Optional in every sense: a session
 * mid-write may not have one, and everything it carries (model, title, cwd)
 * has a fallback inside the audit log or is simply absent.
 */
function readSidecar(
  auditPath: string,
  io: SourceIo,
): { model?: string; title?: string; cwd?: string } {
  const dir = auditPath.slice(0, auditPath.lastIndexOf("/"));
  const text = io.readText(`${dir}.json`);
  if (!text) return {};
  try {
    const doc = JSON.parse(text) as Record<string, unknown>;
    const folders = doc.userSelectedFolders;
    return {
      model: str(doc.model),
      title: str(doc.title),
      // The VM's own `cwd` is a path inside the container (/sessions/<name>) and
      // means nothing on this Mac. The folder the person actually pointed the
      // session at is the one worth showing — and the one an ignore rule scoped
      // to a project can match.
      cwd: Array.isArray(folders) ? str(folders[0]) : undefined,
    };
  } catch {
    return {};
  }
}

export function parseClaudeDesktopAudit(
  contents: string,
  sessionId: string,
  meta: { model?: string; cwd?: string } = {},
): { turns: LedgerTurn[]; detect: DetectUnit[]; first_prompt?: string } {
  const turns: LedgerTurn[] = [];
  const detect: DetectUnit[] = [];
  let firstPrompt: string | undefined;
  let promptSeq = 0;
  let model = meta.model;
  let totalCostUsd: number | undefined;
  const cwd = meta.cwd;
  /** tool_use id → tool name, so a tool_result can name the tool it answered. */
  const toolNameById = new Map<string, string>();
  /** message id → the one turn it becomes, accumulated across its lines. */
  const byMessage = new Map<
    string,
    {
      id: string;
      at: string;
      model?: string;
      usage?: LedgerTurn["usage"];
      texts: string[];
      tools: string[];
    }
  >();
  /** First-seen order, so turns come out in transcript order. */
  const messageOrder: string[] = [];

  for (const raw of contents.split("\n")) {
    const line = raw.trim();
    if (line === "") continue;
    let obj: Record<string, unknown>;
    try {
      const parsed = JSON.parse(line);
      if (!parsed || typeof parsed !== "object") continue;
      obj = parsed as Record<string, unknown>;
    } catch {
      // A half-written final line while the session is live — skip it, never
      // throw. The next parse of the finished file picks it up.
      continue;
    }
    // Every line carries `_audit_timestamp`; the message itself carries none.
    const at = str(obj._audit_timestamp);
    const message = obj.message as Record<string, unknown> | undefined;

    if (obj.type === "user") {
      if (!message || !at) continue;
      const content = message.content;
      // A `user` line is EITHER a human prompt or the transcript's carrier for
      // tool results coming back from the VM. Only the first is a turn.
      if (Array.isArray(content)) {
        for (const block of content) {
          if (!block || typeof block !== "object") continue;
          const b = block as Record<string, unknown>;
          if (b.type !== "tool_result") continue;
          const text = contentText(b.content);
          if (text === "") continue;
          const name = str(b.tool_use_id) ? toolNameById.get(b.tool_use_id as string) : undefined;
          detect.push({
            kind: "tool_output",
            raw: text.slice(0, TOOL_OUTPUT_MAX_CHARS),
            ...(name === undefined ? {} : { tool_name: name }),
            session_id: sessionId,
            turn_id: `claude-desktop:${sessionId}:out${detect.length}`,
            at,
            ...(cwd === undefined ? {} : { cwd }),
          });
        }
      }
      const text = contentText(content).trim();
      if (text === "") continue;
      // A content array that held only tool_result blocks yields no text, so
      // this is a real prompt.
      const id = `claude-desktop:${sessionId}:p${promptSeq}`;
      promptSeq += 1;
      firstPrompt ??= text;
      turns.push({
        id,
        source: "claude-desktop",
        session_id: sessionId,
        role: "user",
        at,
        text: text.slice(0, TURN_TEXT_MAX_CHARS),
        ...(cwd === undefined ? {} : { cwd }),
      });
      detect.push({ kind: "prompt", raw: text, session_id: sessionId, turn_id: id, at });
      continue;
    }

    if (obj.type === "result") {
      // The session's own closing figure. `total_cost_usd` is what the host
      // recorded as billed — the only trustworthy cost here.
      const cost = obj.total_cost_usd;
      if (typeof cost === "number" && Number.isFinite(cost) && cost >= 0) totalCostUsd = cost;
      continue;
    }

    if (obj.type !== "assistant" || !message || !at) continue;
    model = str(message.model) ?? model;
    const messageId = str(message.id);
    if (!messageId) continue;
    const turnId = `claude-desktop:${sessionId}:${messageId}`;
    // One accumulator per message: its lines arrive separately, each holding a
    // single content block and a repeat of the same usage.
    let acc = byMessage.get(messageId);
    if (!acc) {
      acc = { id: turnId, at, texts: [], tools: [] };
      byMessage.set(messageId, acc);
      messageOrder.push(messageId);
    }
    acc.model = model;

    const content = message.content;
    if (Array.isArray(content)) {
      for (const block of content) {
        if (!block || typeof block !== "object") continue;
        const b = block as Record<string, unknown>;
        if (b.type === "text" && typeof b.text === "string" && b.text !== "") {
          acc.texts.push(b.text);
          continue;
        }
        if (b.type !== "tool_use") continue;
        const name = str(b.name) ?? "tool";
        acc.tools.push(name);
        const useId = str(b.id);
        if (useId) toolNameById.set(useId, name);
        detect.push({
          kind: "tool_call",
          raw: JSON.stringify(b.input ?? {}),
          tool_name: name,
          target: toolTarget(b.input),
          session_id: sessionId,
          turn_id: turnId,
          at,
          ...(cwd === undefined ? {} : { cwd }),
        });
      }
    }

    const usageRaw = message.usage as Record<string, unknown> | undefined;
    if (!usageRaw) continue;
    const creation = usageRaw.cache_creation as Record<string, unknown> | undefined;
    // ASSIGNED, never added: every line of a message repeats the same object.
    acc.usage = {
      input_tokens: toInt(usageRaw.input_tokens),
      output_tokens: toInt(usageRaw.output_tokens),
      cache_read_tokens: toInt(usageRaw.cache_read_input_tokens),
      cache_write_tokens: toInt(usageRaw.cache_creation_input_tokens),
      cache_write_1h_tokens: creation ? toInt(creation.ephemeral_1h_input_tokens) : 0,
      web_search_requests: 0,
    };
  }

  for (const messageId of messageOrder) {
    const acc = byMessage.get(messageId);
    if (!acc) continue;
    const text = acc.texts.join("\n").trim();
    turns.push({
      id: acc.id,
      source: "claude-desktop",
      session_id: sessionId,
      role: "assistant",
      at: acc.at,
      ...(acc.model === undefined ? {} : { model: acc.model }),
      ...(acc.usage === undefined ? {} : { usage: acc.usage }),
      // No per-turn cost — see the file header. Cost arrives once, below, from
      // the session's `result` record. `cost_unknown` is deliberately NOT set:
      // it means "this model has no price", which is a different problem and
      // would put a warning on every turn of a session we priced correctly.
      // Cowork runs on the person's Claude subscription but the log records no
      // plan window, so settlement is honestly unattributed.
      settlement: "unknown",
      ...(text === "" ? {} : { text: text.slice(0, TURN_TEXT_MAX_CHARS) }),
      ...(acc.tools.length === 0 ? {} : { tools: acc.tools.slice(0, TURN_TOOLS_MAX) }),
      ...(cwd === undefined ? {} : { cwd }),
    });
  }

  // The session's whole cost, on its last assistant turn: the fold in
  // turns.ts sums turn costs, so the session total comes out as exactly the
  // figure the host wrote down.
  if (totalCostUsd !== undefined) {
    const last = turns.filter((t) => t.role === "assistant").pop();
    if (last) last.cost = totalCostUsd;
  }

  return { turns, detect, ...(firstPrompt === undefined ? {} : { first_prompt: firstPrompt }) };
}

/** Best-effort target for a tool_use input object. */
function toolTarget(input: unknown): string | undefined {
  if (!input || typeof input !== "object") return undefined;
  const obj = input as Record<string, unknown>;
  const command = obj.command;
  if (typeof command === "string" && command.trim() !== "") {
    return command.trim().split(/\s+/, 1)[0];
  }
  const path = obj.file_path ?? obj.path ?? obj.notebook_path;
  return typeof path === "string" && path !== "" ? path : undefined;
}

export const claudeDesktopSource: TranscriptSourceDescriptor = {
  id: "claude-desktop",
  label: "Claude Desktop",
  presencePaths: ["/Applications/Claude.app", "Library/Application Support/Claude"],
  roots: (home) => [`${home}/${SESSIONS_REL}`],
  discover(root, io) {
    // <root>/<account>/<org>/local_<uuid>/audit.jsonl. The two id levels are
    // opaque, so walk them rather than assuming a depth.
    const out: string[] = [];
    for (const account of io.listDir(root)) {
      const accountDir = `${root}/${account}`;
      if (!io.stat(accountDir)?.isDirectory) continue;
      for (const org of io.listDir(accountDir)) {
        const orgDir = `${accountDir}/${org}`;
        if (!io.stat(orgDir)?.isDirectory) continue;
        for (const session of io.listDir(orgDir)) {
          if (!SESSION_DIR_RE.test(session)) continue;
          const audit = `${orgDir}/${session}/audit.jsonl`;
          if (io.stat(audit)) out.push(audit);
        }
      }
    }
    return out;
  },
  parse(path, io) {
    const sessionId = sessionIdFromPath(path);
    if (!sessionId) return { turns: [], titles: [], detect: [] };
    const contents = io.readText(path);
    if (!contents) return { turns: [], titles: [], detect: [] };
    const sidecar = readSidecar(path, io);
    const { turns, detect } = parseClaudeDesktopAudit(contents, sessionId, sidecar);
    return {
      turns,
      detect,
      // The sidecar's own title outranks a first-prompt one — it is the app's
      // summary of the session, the same tier Claude Code's ai-title record
      // occupies (titleWriteApplies lets `auto_summary` self-replace).
      titles: sidecar.title
        ? [{ session_id: sessionId, title: { text: sidecar.title, origin: "auto_summary" as const } }]
        : [],
    };
  },
  sessionIdOf: sessionIdFromPath,
  metered: true,
};
