/**
 * Live sessions — the agents working on this Mac RIGHT NOW, joined to the
 * ledger sessions they are writing.
 *
 * Three signals, folded honestly:
 *
 *   · the process table (agent-processes.ts) says an agent is alive, in which
 *     directory, on which terminal;
 *   · the guard's presence files (guard/handshake.ts) say which session id
 *     that process owns — exact, because the hook is the agent's own child;
 *   · the transcript (the ledger's SessionSummary) says what it did last and
 *     when — so a process with no presence record still joins by cwd, and a
 *     joined session can say "waiting for you" when its newest turn is an
 *     assistant answer with no tool call behind it.
 *
 * A held approval outranks everything: the agent is stopped on this window.
 *
 * Pure. The runner in main reads the inputs; this fold never touches disk.
 */

import type { AgentProcess, ProcessRow } from "./agent-processes.js";
import { agentAncestorPid } from "./agent-processes.js";
import type { PresenceRecord } from "../guard/handshake.js";
import type { SessionSummary, TurnSource } from "./turns.js";

/**
 * · `held`    — the guard is holding one of its tool calls for this window.
 * · `working` — the transcript or the guard saw activity within WORKING_MS.
 * · `waiting` — alive and quiet, and the newest turn is an assistant answer
 *               without tools: it finished and is waiting for the person.
 * · `idle`    — alive and quiet, and we cannot tell more (the newest turn
 *               ran tools and nothing has landed since, or no turns yet).
 */
export type LiveSessionState = "held" | "working" | "waiting" | "idle";

export interface LiveSession {
  /** The ledger session, when one is joined. Absent for a fresh process that
   * has not written a turn yet. */
  session_id?: string;
  source: TurnSource;
  title?: string;
  state: LiveSessionState;
  /** ISO instant of the newest thing we know about it (turn, guard call or,
   * failing both, the process start). */
  since: string;
  /** How the row was joined to its session, so the UI can say "cwd match"
   * honestly rather than implying certainty. */
  join: "presence" | "cwd" | "recent" | "none";
  pid?: number;
  tty?: string;
  terminal_app?: string;
  /** `$TERM_PROGRAM`-style name from the presence record when the process
   * table found no app bundle (tmux, ssh). */
  term_program?: string;
  term_session?: string;
  tmux?: boolean;
  cwd?: string;
  git_branch?: string;
  /** input+output tokens of the session so far — the row's one usage figure. */
  tokens: number;
  turns: number;
  alerts: number;
  /** Set when the process is a headless run (no tty) — nothing to focus. */
  headless?: boolean;
  /** An approval is waiting for this session — its id, for the row to open. */
  approval_id?: string;
}

export interface LiveCounts {
  held: number;
  working: number;
  waiting: number;
  idle: number;
}

export interface LiveState {
  /** When the process table was last read; "" before the first tick. */
  at: string;
  sessions: LiveSession[];
  counts: LiveCounts;
}

/** Activity newer than this reads as "working". Long enough that a slow tool
 * run doesn't flicker to idle between its turns; short enough that a
 * finished answer reads as waiting within a couple of minutes. */
export const WORKING_MS = 90_000;
/** A session with a turn this recent but NO process we can see is still
 * shown — the agent may run where ps cannot see it (a container, a remote
 * shell whose transcript syncs here). Beyond it, the row is just history. */
export const RECENT_NO_PROCESS_MS = 2 * 60_000;
/** A presence record older than this no longer pins its session to a pid —
 * the pid may have been recycled. */
export const PRESENCE_STALE_MS = 6 * 60 * 60_000;

export interface LiveFoldInput {
  now: Date;
  agents: readonly AgentProcess[];
  /** The whole process table, for walking a presence pid up to its agent. */
  rows: readonly ProcessRow[];
  presence: readonly PresenceRecord[];
  sessions: readonly SessionSummary[];
  approvals: readonly { id: string; session_id?: string; cwd?: string; source?: string }[];
}

export function emptyLiveState(): LiveState {
  return { at: "", sessions: [], counts: { held: 0, working: 0, waiting: 0, idle: 0 } };
}

const STATE_ORDER: Record<LiveSessionState, number> = { held: 0, working: 1, waiting: 2, idle: 3 };

export function foldLiveSessions(input: LiveFoldInput): LiveState {
  const nowMs = input.now.getTime();
  const table = new Map(input.rows.map((r) => [r.pid, r]));
  const agentByPid = new Map(input.agents.map((a) => [a.pid, a]));
  const agentPids = new Set(agentByPid.keys());
  const sessionById = new Map(input.sessions.map((s) => [s.id, s]));

  // 1. Presence: session → agent pid, newest record per session wins, and a
  //    pid claimed by a newer record is released from an older one (a resumed
  //    session in the same window).
  const pidBySession = new Map<string, { pid: number; at: string; record: PresenceRecord }>();
  const sorted = [...input.presence].sort((a, b) => (a.at < b.at ? -1 : a.at > b.at ? 1 : 0));
  for (const rec of sorted) {
    const age = nowMs - Date.parse(rec.at);
    if (!Number.isFinite(age) || age > PRESENCE_STALE_MS) continue;
    const pid = agentAncestorPid(rec.pid, table, agentPids);
    if (pid === undefined) continue;
    for (const [sid, v] of pidBySession) if (v.pid === pid && sid !== rec.session_id) pidBySession.delete(sid);
    pidBySession.set(rec.session_id, { pid, at: rec.at, record: rec });
  }

  const out: LiveSession[] = [];
  const claimedPids = new Set<number>();
  const shownSessions = new Set<string>();

  const approvalFor = (sessionId: string | undefined, cwd: string | undefined, source: TurnSource) =>
    input.approvals.find((a) =>
      sessionId !== undefined && a.session_id !== undefined
        ? a.session_id === sessionId
        : a.cwd !== undefined && cwd !== undefined && a.cwd === cwd && (a.source === undefined || a.source === source),
    );

  const build = (
    summary: SessionSummary | undefined,
    proc: AgentProcess | undefined,
    presence: PresenceRecord | undefined,
    join: LiveSession["join"],
    source: TurnSource,
  ): LiveSession => {
    const cwd = summary?.cwd ?? proc?.cwd ?? presence?.cwd;
    const approval = approvalFor(summary?.id, cwd, source);
    const times = [summary?.ended_at, presence?.at].filter((t): t is string => typeof t === "string");
    const since = times.length > 0 ? times.reduce((a, b) => (a > b ? a : b)) : proc?.started_at ?? input.now.toISOString();
    const quietMs = nowMs - Date.parse(since);
    let state: LiveSessionState;
    if (approval) state = "held";
    else if (Number.isFinite(quietMs) && quietMs <= WORKING_MS) state = "working";
    else if (summary?.last_role === "assistant" && (summary.last_turn_tools ?? 0) === 0) state = "waiting";
    else state = "idle";
    const termProgram = presence?.term?.program;
    const tmux = proc?.tmux || presence?.term?.tmux ? true : undefined;
    return {
      ...(summary ? { session_id: summary.id } : {}),
      source,
      ...(summary?.title ? { title: summary.title } : {}),
      state,
      since,
      join,
      ...(proc ? { pid: proc.pid } : {}),
      ...(proc?.tty ? { tty: proc.tty } : {}),
      ...(proc?.terminal_app ? { terminal_app: proc.terminal_app } : {}),
      ...(termProgram ? { term_program: termProgram } : {}),
      ...(presence?.term?.session ? { term_session: presence.term.session } : {}),
      ...(tmux ? { tmux } : {}),
      ...(cwd ? { cwd } : {}),
      ...(summary?.git_branch ? { git_branch: summary.git_branch } : {}),
      tokens: summary ? summary.input_tokens + summary.output_tokens : 0,
      turns: summary?.turns ?? 0,
      alerts: summary?.alerts ?? 0,
      ...(proc && !proc.tty ? { headless: true } : {}),
      ...(approval ? { approval_id: approval.id } : {}),
    };
  };

  // 2. Sessions pinned to a live process by presence.
  for (const [sid, { pid, record }] of pidBySession) {
    const proc = agentByPid.get(pid);
    if (!proc || claimedPids.has(pid)) continue;
    const summary = sessionById.get(sid);
    claimedPids.add(pid);
    shownSessions.add(sid);
    const source = summary?.source ?? proc.source;
    out.push(build(summary, proc, record, "presence", source));
  }

  // 3. Remaining processes: join by cwd to the newest same-source session
  //    that was active after the process started.
  const remaining = input.agents.filter((a) => !claimedPids.has(a.pid)).sort((a, b) => (a.started_at < b.started_at ? 1 : -1));
  for (const proc of remaining) {
    let match: SessionSummary | undefined;
    if (proc.cwd) {
      for (const s of input.sessions) {
        if (shownSessions.has(s.id) || s.source !== proc.source || s.cwd !== proc.cwd) continue;
        if (s.ended_at < proc.started_at) continue;
        if (!match || s.ended_at > match.ended_at) match = s;
      }
    }
    claimedPids.add(proc.pid);
    if (match) shownSessions.add(match.id);
    out.push(build(match, proc, undefined, match ? "cwd" : "none", proc.source));
  }

  // 4. Sessions with very recent turns but no visible process.
  for (const s of input.sessions) {
    if (shownSessions.has(s.id)) continue;
    const age = nowMs - Date.parse(s.ended_at);
    if (!Number.isFinite(age) || age > RECENT_NO_PROCESS_MS) continue;
    shownSessions.add(s.id);
    out.push(build(s, undefined, undefined, "recent", s.source));
  }

  out.sort((a, b) => STATE_ORDER[a.state] - STATE_ORDER[b.state] || (a.since < b.since ? 1 : a.since > b.since ? -1 : 0));
  const counts: LiveCounts = { held: 0, working: 0, waiting: 0, idle: 0 };
  for (const row of out) counts[row.state] += 1;
  return { at: input.now.toISOString(), sessions: out, counts };
}

/** "2 working · 1 waiting for you" — the tray and the rail header. Empty
 * when nothing is live, so a permanent "0" never wears a number. */
export function liveSummaryLine(counts: LiveCounts): string {
  const parts: string[] = [];
  if (counts.held > 0) parts.push(`${counts.held} held`);
  if (counts.working > 0) parts.push(`${counts.working} working`);
  if (counts.waiting > 0) parts.push(`${counts.waiting} waiting for you`);
  if (counts.idle > 0) parts.push(`${counts.idle} idle`);
  return parts.join(" · ");
}

/** Presence files whose pid no longer leads to an agent — the caller
 * deletes them so the folder does not grow with every session ever run. */
export function stalePresence(
  presence: readonly PresenceRecord[],
  rows: readonly ProcessRow[],
  agents: readonly AgentProcess[],
  now: Date,
): PresenceRecord[] {
  const table = new Map(rows.map((r) => [r.pid, r]));
  const agentPids = new Set(agents.map((a) => a.pid));
  return presence.filter((rec) => {
    const age = now.getTime() - Date.parse(rec.at);
    if (!Number.isFinite(age) || age > PRESENCE_STALE_MS) return true;
    return agentAncestorPid(rec.pid, table, agentPids) === undefined && age > WORKING_MS;
  });
}
