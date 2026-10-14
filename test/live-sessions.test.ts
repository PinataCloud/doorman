import { describe, expect, it } from "vitest";
import {
  agentAncestorPid,
  agentProcesses,
  appNameForCommand,
  parseLsofCwd,
  parseLstart,
  parsePsTable,
  sourceForCommand,
  terminalAncestor,
  type ProcessRow,
} from "../main/lib/agent-processes.js";
import {
  PRESENCE_STALE_MS,
  RECENT_NO_PROCESS_MS,
  WORKING_MS,
  emptyLiveState,
  foldLiveSessions,
  liveSummaryLine,
  stalePresence,
} from "../main/lib/live-sessions.js";
import {
  appleScriptString,
  focusScript,
  newWindowScript,
  planFocus,
  planResume,
  resumeCommand,
  scriptableTerminal,
  shellLine,
  shellQuote,
  termProgramApp,
} from "../main/lib/terminal-handoff.js";
import { parsePresence, presencePath, presenceTerm } from "../main/guard/handshake.js";
import { groupSessions, type LedgerTurn, type SessionSummary } from "../main/lib/turns.js";

/**
 * Live sessions: the process table, the guard's presence records and the
 * ledger's sessions folded into "who is working right now" — and the
 * terminal hand-off text the app runs. All pure; the shapes below are lifted
 * from a real `ps -axo pid=,ppid=,tty=,lstart=,command=` on a Mac with four
 * Claude Code sessions open.
 */

const PS = `
    1     0 ??       Sat Jul  4 09:00:00 2026 /sbin/launchd
41972     1 ??       Mon Sep  7 09:12:03 2026 /Applications/iTerm.app/Contents/MacOS/iTerm2
32248     1 ??       Mon Sep  7 09:12:03 2026 /Applications/Utilities/Terminal.app/Contents/MacOS/Terminal
 5001 41972 ttys003  Mon Sep  7 16:20:00 2026 -zsh
63645  5001 ttys003  Mon Sep  7 16:24:18 2026 claude --dangerously-skip-permissions
 5002 32248 ttys006  Mon Sep  7 16:25:00 2026 login -pf dev
 5003  5002 ttys006  Mon Sep  7 16:25:01 2026 -zsh
64469  5003 ttys006  Mon Sep  7 16:26:15 2026 codex
70000 64469 ttys006  Mon Sep  7 16:26:16 2026 /Users/dev/.npm/_npx/codex-aarch64-apple-darwin
75401 63645 ??       Mon Sep  7 16:40:00 2026 /bin/zsh -c ps -axo pid
 8000  5001 ttys003  Mon Sep  7 16:41:00 2026 claude mcp serve
 9000     1 ??       Mon Sep  7 16:42:00 2026 node /Users/dev/.nvm/versions/node/v22/lib/node_modules/@anthropic-ai/claude-code/cli.js -p hello
 9100  9000 ??       Mon Sep  7 16:42:01 2026 /Applications/Doorman.app/Contents/MacOS/Doorman /x/guard.js
`;

const NOW = new Date("2026-09-07T16:45:00");

describe("agent-processes: ps and lsof parsing", () => {
  it("parses pid, ppid, tty, lstart and the command tail", () => {
    const rows = parsePsTable(PS, NOW);
    const claude = rows.find((r) => r.pid === 63645)!;
    expect(claude.ppid).toBe(5001);
    expect(claude.tty).toBe("ttys003");
    expect(claude.command).toBe("claude --dangerously-skip-permissions");
    expect(new Date(claude.started_at).getHours()).toBe(16);
    expect(new Date(claude.started_at).getMinutes()).toBe(24);
    // "??" is no tty.
    expect(rows.find((r) => r.pid === 41972)!.tty).toBeUndefined();
  });

  it("lstart that does not parse falls back to now, never the epoch", () => {
    expect(parseLstart("garbage", NOW)).toBe(NOW.toISOString());
  });

  it("parses lsof -Fpn into pid → cwd", () => {
    const map = parseLsofCwd("p63645\nfcwd\nn/Users/dev/repos/hitman\np64469\nfcwd\nn/Users/dev/repos/doorman\n");
    expect(map.get(63645)).toBe("/Users/dev/repos/hitman");
    expect(map.get(64469)).toBe("/Users/dev/repos/doorman");
  });
});

describe("agent-processes: recognising agents", () => {
  it("names the CLIs by binary and by node script path", () => {
    expect(sourceForCommand("claude --dangerously-skip-permissions")).toBe("claude-code");
    expect(sourceForCommand("/usr/local/bin/claude")).toBe("claude-code");
    expect(sourceForCommand("codex")).toBe("codex");
    expect(sourceForCommand("/x/codex-aarch64-apple-darwin")).toBe("codex");
    expect(sourceForCommand("node /a/@anthropic-ai/claude-code/cli.js -p hello")).toBe("claude-code");
    expect(sourceForCommand("node /a/@openai/codex/bin/codex.js")).toBe("codex");
    expect(sourceForCommand("gemini")).toBe("gemini-cli");
    expect(sourceForCommand("copilot --resume abc")).toBe("copilot-cli");
  });

  it("does not count helpers, MCP servers or unrelated processes", () => {
    expect(sourceForCommand("claude mcp serve")).toBeUndefined();
    expect(sourceForCommand("claude --version")).toBeUndefined();
    expect(sourceForCommand("codex exec 'ls'")).toBeUndefined();
    expect(sourceForCommand("-zsh")).toBeUndefined();
    expect(sourceForCommand("/Applications/Claude.app/Contents/MacOS/Claude")).toBeUndefined();
    expect(sourceForCommand("node server.js")).toBeUndefined();
  });

  it("folds the table into agents with cwd, terminal app and headless flag; a child of the same agent is not a second row", () => {
    const rows = parsePsTable(PS, NOW);
    const cwds = new Map([[63645, "/Users/dev/repos/hitman"], [64469, "/Users/dev/repos/doorman"]]);
    const agents = agentProcesses(rows, cwds);
    expect(agents.map((a) => a.pid)).toEqual([9000, 63645, 64469]);
    const claude = agents.find((a) => a.pid === 63645)!;
    expect(claude).toMatchObject({ source: "claude-code", tty: "ttys003", cwd: "/Users/dev/repos/hitman", terminal_app: "iTerm" });
    const codex = agents.find((a) => a.pid === 64469)!;
    expect(codex).toMatchObject({ source: "codex", tty: "ttys006", terminal_app: "Terminal" });
    const headless = agents.find((a) => a.pid === 9000)!;
    expect(headless.tty).toBeUndefined();
    expect(headless.terminal_app).toBeUndefined();
  });

  it("app names are the bundle's, so iTerm2's ShellLauncher login line still says iTerm", () => {
    expect(appNameForCommand("/Applications/iTerm.app/Contents/MacOS/iTerm2")).toBe("iTerm");
    expect(appNameForCommand("/usr/bin/login -fpl dev /Applications/iTerm.app/Contents/MacOS/ShellLauncher --launch_shell")).toBe("iTerm");
    expect(appNameForCommand("/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal")).toBe("Terminal");
    expect(appNameForCommand("/Applications/Ghostty.app/Contents/MacOS/ghostty")).toBe("Ghostty");
    expect(appNameForCommand("-zsh")).toBeUndefined();
  });

  it("walks a hook pid up to its agent (through a shell wrapper) and notes tmux", () => {
    const rows = parsePsTable(PS, NOW);
    const table = new Map(rows.map((r) => [r.pid, r]));
    const agents = new Set([63645, 64469, 9000]);
    expect(agentAncestorPid(75401, table, agents)).toBe(63645);
    expect(agentAncestorPid(9100, table, agents)).toBe(9000);
    expect(agentAncestorPid(5001, table, agents)).toBeUndefined();
    expect(agentAncestorPid(424242, table, agents)).toBeUndefined();
    const withTmux: ProcessRow[] = [
      ...rows,
      { pid: 600, ppid: 41972, started_at: NOW.toISOString(), command: "tmux new -s work" },
      { pid: 601, ppid: 600, tty: "ttys009", started_at: NOW.toISOString(), command: "-zsh" },
      { pid: 602, ppid: 601, tty: "ttys009", started_at: NOW.toISOString(), command: "claude" },
    ];
    const t2 = new Map(withTmux.map((r) => [r.pid, r]));
    expect(terminalAncestor(t2.get(602)!, t2)).toEqual({ app: "iTerm", tmux: true });
  });
});

function turn(over: Partial<LedgerTurn> & Pick<LedgerTurn, "id" | "session_id" | "role" | "at">): LedgerTurn {
  return { source: "claude-code", ...over };
}

function session(over: Partial<SessionSummary> & Pick<SessionSummary, "id">): SessionSummary {
  return {
    source: "claude-code",
    cost: 1.5,
    cost_unknown_turns: 0,
    input_tokens: 10,
    output_tokens: 20,
    cache_read_tokens: 0,
    cache_write_tokens: 0,
    turns: 4,
    prompts: 2,
    models: [],
    started_at: "2026-09-07T16:30:00.000Z",
    ended_at: "2026-09-07T16:44:30.000Z",
    covered_cost: 0,
    overage_cost: 0,
    billed_cost: 0,
    unknown_cost: 0,
    covered_tokens: 0,
    overage_tokens: 0,
    billed_tokens: 0,
    unknown_tokens: 30,
    cwd: "/Users/dev/repos/hitman",
    ...over,
  };
}

describe("turns: the newest turn's role and tool count ride the summary", () => {
  it("records last_role and last_turn_tools from the newest turn by time", () => {
    const [s] = groupSessions(
      [
        turn({ id: "a", session_id: "s", role: "user", at: "2026-09-07T10:00:00.000Z", text: "do it" }),
        turn({ id: "b", session_id: "s", role: "assistant", at: "2026-09-07T10:00:05.000Z", tools: ["Bash", "Read"] }),
        turn({ id: "c", session_id: "s", role: "assistant", at: "2026-09-07T10:00:09.000Z", text: "done" }),
      ],
      new Map(),
    );
    expect(s!.last_role).toBe("assistant");
    expect(s!.last_turn_tools).toBe(0);
    const [t] = groupSessions(
      [
        turn({ id: "b", session_id: "s", role: "assistant", at: "2026-09-07T10:00:05.000Z", tools: ["Bash"] }),
        turn({ id: "a", session_id: "s", role: "user", at: "2026-09-07T10:00:00.000Z", text: "do it" }),
      ],
      new Map(),
    );
    expect(t!.last_role).toBe("assistant");
    expect(t!.last_turn_tools).toBe(1);
  });
});

describe("live-sessions fold", () => {
  const nowZ = new Date("2026-09-07T16:45:00.000Z");
  const rows: ProcessRow[] = [
    { pid: 1, ppid: 0, started_at: "2026-09-07T09:00:00.000Z", command: "/sbin/launchd" },
    { pid: 41972, ppid: 1, started_at: "2026-09-07T09:12:03.000Z", command: "/Applications/iTerm.app/Contents/MacOS/iTerm2" },
    { pid: 5001, ppid: 41972, tty: "ttys003", started_at: "2026-09-07T16:20:00.000Z", command: "-zsh" },
    { pid: 63645, ppid: 5001, tty: "ttys003", started_at: "2026-09-07T16:24:18.000Z", command: "claude" },
    { pid: 5003, ppid: 41972, tty: "ttys006", started_at: "2026-09-07T16:25:01.000Z", command: "-zsh" },
    { pid: 64469, ppid: 5003, tty: "ttys006", started_at: "2026-09-07T16:26:15.000Z", command: "claude" },
    { pid: 75401, ppid: 63645, started_at: "2026-09-07T16:40:00.000Z", command: "/bin/zsh -c hook" },
  ];
  const agents = agentProcesses(rows, new Map([[63645, "/Users/dev/repos/hitman"], [64469, "/Users/dev/repos/hitman"]]));

  it("presence pins a session to its process exactly, even through a shell wrapper; the other process joins by cwd", () => {
    const sessions = [
      session({ id: "A", ended_at: "2026-09-07T16:44:50.000Z", title: "Fix the fold", last_role: "assistant", last_turn_tools: 2 }),
      session({ id: "B", ended_at: "2026-09-07T16:30:00.000Z", title: "Older one", last_role: "assistant", last_turn_tools: 0 }),
    ];
    const live = foldLiveSessions({
      now: nowZ,
      agents,
      rows,
      presence: [{ session_id: "B", source: "claude-code", pid: 75401, at: "2026-09-07T16:40:00.000Z", cwd: "/Users/dev/repos/hitman", term: { program: "iTerm.app", session: "w0t1p0" } }],
      sessions,
      approvals: [],
    });
    const b = live.sessions.find((r) => r.session_id === "B")!;
    expect(b).toMatchObject({ pid: 63645, join: "presence", tty: "ttys003", terminal_app: "iTerm", term_program: "iTerm.app", state: "waiting" });
    // B's newest thing is the guard call at 16:40 (newer than its last turn) —
    // five minutes ago, so quiet; its last turn was a text answer: waiting.
    expect(b.since).toBe("2026-09-07T16:40:00.000Z");
    const a = live.sessions.find((r) => r.session_id === "A")!;
    expect(a).toMatchObject({ pid: 64469, join: "cwd", state: "working", title: "Fix the fold" });
    // Working sorts before waiting.
    expect(live.sessions.map((r) => r.session_id)).toEqual(["A", "B"]);
    expect(live.counts).toEqual({ held: 0, working: 1, waiting: 1, idle: 0 });
  });

  it("a held approval outranks activity, and a process with no session is a row of its own", () => {
    const live = foldLiveSessions({
      now: nowZ,
      agents,
      rows,
      presence: [],
      sessions: [session({ id: "A", ended_at: "2026-09-07T16:44:50.000Z" })],
      approvals: [{ id: "req-1", session_id: "A" }],
    });
    const a = live.sessions.find((r) => r.session_id === "A")!;
    expect(a.state).toBe("held");
    expect(a.approval_id).toBe("req-1");
    const unjoined = live.sessions.find((r) => !r.session_id)!;
    expect(unjoined).toMatchObject({ join: "none", turns: 0, tokens: 0 });
    expect(unjoined.pid).toBeDefined();
    expect(live.counts.held).toBe(1);
  });

  it("a session that ended before the process started does not join it; a quiet tool-running session is idle", () => {
    const live = foldLiveSessions({
      now: nowZ,
      agents: agents.filter((a) => a.pid === 63645),
      rows,
      presence: [],
      sessions: [
        session({ id: "OLD", ended_at: "2026-09-07T16:00:00.000Z" }),
        session({ id: "TOOLS", ended_at: "2026-09-07T16:40:00.000Z", last_role: "assistant", last_turn_tools: 3 }),
      ],
      approvals: [],
    });
    expect(live.sessions).toHaveLength(1);
    expect(live.sessions[0]).toMatchObject({ session_id: "TOOLS", state: "idle", join: "cwd" });
  });

  it("a very recent session with no visible process is still shown, and says so", () => {
    const recent = new Date(nowZ.getTime() - RECENT_NO_PROCESS_MS / 2).toISOString();
    const stale = new Date(nowZ.getTime() - RECENT_NO_PROCESS_MS * 2).toISOString();
    const live = foldLiveSessions({
      now: nowZ,
      agents: [],
      rows: [],
      presence: [],
      sessions: [session({ id: "R", ended_at: recent, cwd: "/elsewhere" }), session({ id: "S", ended_at: stale, cwd: "/elsewhere" })],
      approvals: [],
    });
    expect(live.sessions.map((r) => r.session_id)).toEqual(["R"]);
    expect(live.sessions[0]!.join).toBe("recent");
    expect(live.sessions[0]!.pid).toBeUndefined();
  });

  it("a headless process is marked so the UI offers nothing to focus", () => {
    // Started 30 s ago with no turns yet: the start IS the newest fact — working.
    const headRows: ProcessRow[] = [{ pid: 9000, ppid: 1, started_at: new Date(nowZ.getTime() - 30_000).toISOString(), command: "claude -p hi" }];
    const live = foldLiveSessions({
      now: nowZ,
      agents: agentProcesses(headRows, new Map()),
      rows: headRows,
      presence: [],
      sessions: [],
      approvals: [],
    });
    expect(live.sessions[0]).toMatchObject({ headless: true, state: "working" });
  });

  it("stale presence: dead pids past the working window and records older than the ceiling", () => {
    const fresh = { session_id: "X", source: "claude-code", pid: 63645, at: new Date(nowZ.getTime() - 60_000).toISOString() };
    const deadRecent = { session_id: "Y", source: "claude-code", pid: 424242, at: new Date(nowZ.getTime() - WORKING_MS / 2).toISOString() };
    const deadOld = { session_id: "Z", source: "claude-code", pid: 424242, at: new Date(nowZ.getTime() - WORKING_MS * 2).toISOString() };
    const ancient = { session_id: "W", source: "claude-code", pid: 63645, at: new Date(nowZ.getTime() - PRESENCE_STALE_MS - 1).toISOString() };
    const stale = stalePresence([fresh, deadRecent, deadOld, ancient], rows, agents, nowZ);
    expect(stale.map((r) => r.session_id).sort()).toEqual(["W", "Z"]);
  });

  it("summary line names only non-zero states; empty state has no rows", () => {
    expect(liveSummaryLine({ held: 1, working: 2, waiting: 0, idle: 0 })).toBe("1 held · 2 working");
    expect(liveSummaryLine({ held: 0, working: 0, waiting: 0, idle: 0 })).toBe("");
    expect(emptyLiveState()).toEqual({ at: "", sessions: [], counts: { held: 0, working: 0, waiting: 0, idle: 0 } });
  });
});

describe("presence record contract (guard ↔ app)", () => {
  it("paths reject ids outside the safe alphabet", () => {
    expect(presencePath("/g", "claude-code", "5c1e7d1a-1")).toBe("/g/presence/claude-code--5c1e7d1a-1.json");
    expect(presencePath("/g", "claude-code", "../etc")).toBeUndefined();
    expect(presencePath("/g", "Claude Code", "abc")).toBeUndefined();
  });

  it("round-trips and drops malformed records", () => {
    const rec = { session_id: "s", source: "codex", pid: 12, at: "2026-09-07T00:00:00.000Z", cwd: "/x", term: { program: "Apple_Terminal", session: "ABC" } };
    expect(parsePresence(JSON.stringify(rec))).toEqual(rec);
    expect(parsePresence("{")).toBeUndefined();
    expect(parsePresence(JSON.stringify({ session_id: "s" }))).toBeUndefined();
  });

  it("reads the terminal identity from the environment the agent inherited", () => {
    expect(presenceTerm({ TERM_PROGRAM: "iTerm.app", ITERM_SESSION_ID: "w0t2p0:UUID" })).toEqual({ program: "iTerm.app", session: "w0t2p0:UUID" });
    expect(presenceTerm({ TERM_PROGRAM: "tmux", TMUX: "/tmp/tmux-501/default,1,0" })).toEqual({ program: "tmux", tmux: true });
    expect(presenceTerm({ PATH: "/usr/bin" })).toBeUndefined();
  });
});

describe("terminal hand-off text", () => {
  it("knows the documented resume commands and refuses odd ids", () => {
    expect(resumeCommand("claude-code", "5c1e7d1a-4b2e-4f3a-9d0e-1a2b3c4d5e6f")).toBe("claude --resume 5c1e7d1a-4b2e-4f3a-9d0e-1a2b3c4d5e6f");
    expect(resumeCommand("codex", "019a-b")).toBe("codex resume 019a-b");
    expect(resumeCommand("copilot-cli", "abc")).toBe("copilot --resume abc");
    expect(resumeCommand("cursor", "abc")).toBeUndefined();
    expect(resumeCommand("claude-code", "abc; rm -rf /")).toBeUndefined();
    expect(resumeCommand("claude-code", "")).toBeUndefined();
  });

  it("quotes for the shell and for AppleScript", () => {
    expect(shellQuote("it's")).toBe(`'it'\\''s'`);
    expect(shellLine("/Users/l/my repo", "claude --resume x")).toBe(`cd '/Users/l/my repo' && claude --resume x`);
    expect(shellLine(undefined, "claude --resume x")).toBe("claude --resume x");
    expect(appleScriptString(`say "hi" \\ there`)).toBe(`"say \\"hi\\" \\\\ there"`);
  });

  it("builds a Terminal focus script that matches the tab by tty", () => {
    const script = focusScript("Terminal", "ttys003");
    expect(script).toContain('tell application "Terminal"');
    expect(script).toContain('if tty of t is "/dev/ttys003" then');
    expect(script).toContain("set selected of t to true");
    const iterm = focusScript("iTerm2", "/dev/ttys004");
    expect(iterm).toContain('tell application "iTerm2"');
    expect(iterm).toContain('if tty of s is "/dev/ttys004" then');
  });

  it("builds a new-window script that cds and runs the resume command, quoted once for each layer", () => {
    const line = shellLine("/Users/l/repos/it's", "claude --resume abc");
    const script = newWindowScript("Terminal", line);
    expect(script).toContain(`do script "cd '/Users/l/repos/it'\\\\''s' && claude --resume abc"`);
    const iterm = newWindowScript("iTerm2", "codex resume z");
    expect(iterm).toContain("create window with default profile");
    expect(iterm).toContain('write text "codex resume z"');
  });

  it("plans focus by app: scriptable + tty → tab, tmux or unknown app → activate, headless → nothing", () => {
    expect(planFocus({ tty: "ttys003", terminal_app: "iTerm" })?.kind).toBe("focus");
    expect(planFocus({ tty: "ttys003", terminal_app: "iTerm" })?.script).toContain('tell application "iTerm2"');
    expect(planFocus({ tty: "ttys003", terminal_app: "iTerm", tmux: true })).toEqual({ kind: "activate", app: "iTerm" });
    expect(planFocus({ tty: "ttys003", terminal_app: "Ghostty" })).toEqual({ kind: "activate", app: "Ghostty" });
    expect(planFocus({ tty: "ttys003", term_program: "WarpTerminal" })).toEqual({ kind: "activate", app: "Warp" });
    expect(planFocus({ tty: "ttys003", term_program: "Apple_Terminal" })?.kind).toBe("focus");
    expect(planFocus({ headless: true, tty: "ttys003", terminal_app: "Terminal" })).toBeUndefined();
    expect(planFocus({})).toBeUndefined();
  });

  it("plans a resume in the person's terminal when it is scriptable, else Terminal; none for hosts without a command", () => {
    const plan = planResume("claude-code", "abc", "/w", "iTerm2")!;
    expect(plan.kind).toBe("open");
    expect(plan.script).toContain('tell application "iTerm2"');
    expect(plan.line).toBe("cd '/w' && claude --resume abc");
    expect(planResume("codex", "abc", undefined, "ghostty")!.script).toContain('tell application "Terminal"');
    expect(planResume("gemini-cli", "abc", "/w", undefined)).toBeUndefined();
  });

  it("maps names to scriptable terminals and $TERM_PROGRAM to open -a targets", () => {
    expect(scriptableTerminal("Apple_Terminal")).toBe("Terminal");
    expect(scriptableTerminal("iTerm.app")).toBe("iTerm2");
    expect(scriptableTerminal("ghostty")).toBeUndefined();
    expect(termProgramApp("ghostty")).toBe("Ghostty");
    expect(termProgramApp("vscode")).toBe("Visual Studio Code");
    expect(termProgramApp("tmux")).toBeUndefined();
  });
});
