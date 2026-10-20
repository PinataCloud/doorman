import { readFileSync } from "node:fs";
import { join } from "node:path";
import { ReadStream } from "node:tty";
import { ApprovalWatcher, GuardHeartbeat, SpoolWatcher, guardHostStates, syncGuard } from "../../enforcement.js";
import { heartbeatFresh, heartbeatPath, type ApprovalRequest, type ApprovalVerdict } from "../../guard/handshake.js";
import { appOwner } from "../../lib/data-owner.js";
import { HOSTS } from "../../guard/hosts/index.js";
import { approvalContextNote, approvalPolicyChange, approvalSummary } from "../../lib/approvals.js";
import { localDetectorLabel } from "../../lib/findings.js";
import { dockerSandbox, processLabel } from "../docker-sandbox.js";
import type { CliCommand } from "../command.js";
import type { CliContext } from "../context.js";
import { CliError } from "../output.js";
import { tilde } from "./policy.js";

/** One held call as `watch` saw it end. */
export interface WatchDecision {
  id: string;
  at: string;
  summary: string;
  /** `expired`: it stopped waiting before anyone answered (timed out, or the agent gave up). */
  outcome: "allowed" | "denied" | "expired" | "too_late";
  via?: "terminal" | "editor";
  silenced?: string[];
  scoped?: number;
}

export interface WatchSummary {
  stopped: string;
  takeover: boolean;
  decisions: WatchDecision[];
}

export interface WatchSession {
  done: Promise<WatchSummary>;
  stop(reason: string): void;
}

const CLEAR_LINE = "\r\u001b[2K";
const BELL = "\u0007";
/** OSC 0: set the window and tab title. Invisible, moves no cursor. */
const setTitle = (title: string) => `\u001b]0;${title.replace(/[\u0000-\u001f\u007f]/g, "")}\u0007`;
/** xterm's title stack: keep the person's title, put it back on the way out.
 * Terminals without the stack ignore both. */
const PUSH_TITLE = "\u001b[22;0t";
const POP_TITLE = "\u001b[23;0t";

/** The agent a held call came from, and whether it shows its own prompt
 * when the guard prints `ask` (the approval card's wording, approvals.jsx). */
function agentOf(request: ApprovalRequest): { name: string; nativeAsk: boolean } {
  if (request.source === "mcp-gateway") return { name: "the MCP client", nativeAsk: false };
  const host = HOSTS.find((h) => h.source === request.source);
  if (host) return { name: host.label, nativeAsk: host.supportsNativeAsk };
  return { name: request.source ?? "Claude Code", nativeAsk: request.source !== "codex" };
}

/** What the guard does when the hold window runs out. */
function timeoutOutcome(request: ApprovalRequest): string {
  if (request.on_timeout === "deny") return "then denied";
  if (request.source === "mcp-gateway") return "then forwarded";
  const agent = agentOf(request);
  return agent.nativeAsk ? `then ${agent.name} asks` : `then ${agent.name} warns and continues`;
}

/**
 * Be the approver while the app is closed: hold the guard heartbeat (so the
 * guard holds `ask` calls at all), watch the pending directory, ingest the
 * guard's spool into the store, and answer each held call through the same
 * path as the app's resolveApproval (policy first, sync, then the verdict).
 * Stops on `stop()`, on Ctrl-C / end of input, or when another Doorman (the
 * app) writes the heartbeat, which it then owns.
 */
export async function startWatch(ctx: CliContext, options: { auto?: "deny"; tickMs?: number }): Promise<WatchSession> {
  const other = ctx.running();
  if (other) {
    const who = other.version?.startsWith("cli-") ? "`doorman watch`" : "Doorman";
    throw new CliError(`${who}${processLabel(ctx.io.env, other.pid)} is already answering held calls.`);
  }
  // Watch writes the store (the guard's spool) and the policy for as long as
  // it runs: it needs the data to itself, not a copy.
  ctx.requireWritable("Answer held calls");
  const s = ctx.style;
  const out = ctx.io.stderr;
  const tty = "isTTY" in out && out.isTTY === true;
  const auto = options.auto;
  const sandbox = dockerSandbox(ctx.io.env);
  // A held call waits a minute in a terminal nobody may be looking at: ring
  // and retitle it. Only on a terminal, and not under --auto (nobody answers).
  const attention = tty && !auto;
  const bell = attention && ctx.io.env.DOORMAN_NO_BELL !== "1";
  const where = sandbox ? ` (${sandbox.name})` : "";
  const idleTitle = `doorman watch${where}`;
  let shownTitle: string | undefined;
  const retitle = (waiting: number) => {
    if (!attention) return;
    const title = waiting > 0 ? `doorman${where}: ${waiting} call${waiting === 1 ? "" : "s"} waiting` : idleTitle;
    if (title === shownTitle) return;
    shownTitle = title;
    out.write(setTitle(title));
  };
  const rung = new Set<string>();
  const decisions: WatchDecision[] = [];
  const answered = new Set<string>();
  let current: ApprovalRequest | undefined;
  let promptShown = false;
  let stopped = false;
  let scheduled = false;
  let resolveDone!: (summary: WatchSummary) => void;
  const done = new Promise<WatchSummary>((resolve) => {
    resolveDone = resolve;
  });

  const clearPrompt = () => {
    if (promptShown && tty) out.write(CLEAR_LINE);
    promptShown = false;
  };
  const say = (line: string) => {
    clearPrompt();
    out.write(`${line}\n`);
  };
  const secondsLeft = (request: ApprovalRequest) =>
    Math.max(0, Math.round((Date.parse(request.at) + request.hold_seconds * 1000 - Date.now()) / 1000));
  const renderPrompt = () => {
    if (!current || auto || stopped) return;
    const line = `  ${s.bold(`${secondsLeft(current)}s`)} left, ${timeoutOutcome(current)}. Answer d, a${canScope(current) ? ", p" : ""}${canSilence(current) ? ", s" : ""}: `;
    if (tty) {
      out.write(`${CLEAR_LINE}${line}`);
      promptShown = true;
    } else {
      out.write(`${line}\n`);
    }
  };
  const canScope = (request: ApprovalRequest) => !!request.cwd && request.source !== "mcp-gateway";
  const canSilence = (request: ApprovalRequest) => request.source !== "mcp-gateway";

  const handle = await ctx.openEngine({ scan: false });
  const log = (message: string) => ctx.log(message);
  const heartbeat = new GuardHeartbeat({ userDataDir: ctx.dataDir, version: `cli-${ctx.io.version}`, log });

  const present = (request: ApprovalRequest, waiting: number) => {
    const agent = agentOf(request);
    const note = approvalContextNote(request);
    const preview = request.preview.split("\n").slice(0, 12).map((l) => `    | ${l.length > 200 ? `${l.slice(0, 200)}...` : l}`);
    say("");
    say(
      `${s.yellow(s.bold("Held"))}  ${s.bold(approvalSummary(request))}  ${s.dim(
        [agent.name, request.session_id ? `session ${request.session_id.slice(0, 8)}` : "", waiting > 1 ? `${waiting} waiting` : ""].filter(Boolean).join(" · "),
      )}`,
    );
    if (request.reason) say(`  why        ${request.reason}`);
    if (request.cwd) say(`  directory  ${tilde(request.cwd, ctx.io.home)}`);
    if (request.server) say(`  server     ${request.server}${request.tool_class ? ` · ${request.tool_class}` : ""}`);
    if (note) say(`  note       ${note}`);
    if (preview.length > 0 && request.preview !== "") say("  about to run:");
    for (const line of request.preview === "" ? [] : preview) say(s.dim(line));
    if (auto) return;
    say(
      `  [d] deny  [a] allow once${canScope(request) ? "  [p] allow for this project (30 days)" : ""}${canSilence(request) ? "  [s] allow and stop asking" : ""}`,
    );
    say(
      s.dim(
        request.source === "mcp-gateway"
          ? `  Allowing forwards the call to ${request.server ?? "the server"} as the agent sent it.`
          : `  Allowing does not auto-approve: ${agent.name} still applies its own approval flow.`,
      ),
    );
  };

  const decide = (request: ApprovalRequest, verdict: ApprovalVerdict, choice: { silence: boolean; scope: "project" | undefined }, via: "terminal" | "editor") => {
    answered.add(request.id);
    // resolveApproval: the policy change lands (and reaches the guard) before
    // the verdict, so the next call in the session isn't held again.
    const prefs = ctx.prefs();
    const change = approvalPolicyChange(prefs.policy, request, verdict, choice, new Date(ctx.io.now()));
    let syncError: string | undefined;
    if (change.policy !== prefs.policy) {
      ctx.setPrefs({ policy: change.policy });
      const outcome = syncGuard(ctx.dataDir, ctx.policy());
      if (!outcome.ok) syncError = outcome.error;
    }
    const ok = approvals.resolve(request.id, verdict, {
      silenced: change.silenced.length > 0 ? change.silenced : undefined,
      via,
      allow_scope: change.scoped > 0 ? "project" : undefined,
    });
    const prefix = via === "editor" ? "Answered in the editor: " : "";
    let words: string;
    if (!ok) words = s.yellow("Too late: the call had stopped waiting.");
    else if (verdict === "deny") words = s.red(auto ? "Denied (--auto deny)." : "Denied.");
    else {
      words = s.green("Allowed.");
      if (change.scoped > 0) words += ` Not held again under ${tilde(request.cwd ?? "", ctx.io.home)} for 30 days (${change.scoped} exception${change.scoped === 1 ? "" : "s"}).`;
      if (change.silenced.length > 0) words += ` ${change.silenced.map((d) => localDetectorLabel(d)).join(", ")} now only observed.`;
    }
    say(`  ${prefix}${words}`);
    if (syncError) say(s.yellow(`  Saved, but the guard was not updated: ${syncError}`));
    decisions.push({
      id: request.id,
      at: new Date(ctx.io.now()).toISOString(),
      summary: approvalSummary(request),
      outcome: !ok ? "too_late" : verdict === "deny" ? "denied" : "allowed",
      via,
      ...(change.silenced.length > 0 ? { silenced: change.silenced } : {}),
      ...(change.scoped > 0 ? { scoped: change.scoped } : {}),
    });
  };

  /** Show the oldest unanswered call; note the one that went away unanswered. */
  const advance = () => {
    scheduled = false;
    if (stopped) return;
    const list = approvals.list();
    const fresh = list.filter((r) => !answered.has(r.id) && !rung.has(r.id));
    for (const r of fresh) rung.add(r.id);
    if (bell && fresh.length > 0) out.write(BELL);
    if (current && !list.some((r) => r.id === current!.id)) {
      if (!answered.has(current.id)) {
        const expired = secondsLeft(current) === 0;
        say(`  ${s.dim(expired ? `No answer in time: ${timeoutOutcome(current).replace(/^then /, "")}.` : "No longer waiting: the agent stopped the call.")}`);
        decisions.push({ id: current.id, at: new Date(ctx.io.now()).toISOString(), summary: approvalSummary(current), outcome: "expired" });
        answered.add(current.id);
      }
      current = undefined;
    }
    retitle(list.filter((r) => !answered.has(r.id)).length);
    if (current) return;
    const next = list.find((r) => !answered.has(r.id));
    if (!next) {
      clearPrompt();
      return;
    }
    current = next;
    present(next, list.filter((r) => !answered.has(r.id)).length);
    if (auto) decide(next, "deny", { silence: false, scope: undefined }, "terminal");
    else renderPrompt();
  };
  // ApprovalWatcher.resolve reports the change synchronously; never re-enter.
  const schedule = () => {
    if (scheduled || stopped) return;
    scheduled = true;
    setImmediate(advance);
  };

  const approvals = new ApprovalWatcher({
    userDataDir: ctx.dataDir,
    onChange: schedule,
    onNew: schedule,
    // Answered in VS Code: the same resolve path, like the app.
    onAnswer: (answer) => {
      const request = approvals.list().find((r) => r.id === answer.id);
      if (request) decide(request, answer.verdict, { silence: answer.silence === true, scope: answer.scope }, "editor");
    },
    log,
  });
  const spool = new SpoolWatcher({
    userDataDir: ctx.dataDir,
    storeDir: join(ctx.dataDir, "store"),
    onLines: (lines) => handle.engine.ingestSpoolLines(lines),
    log,
  });

  /** Who wrote the heartbeat file (fresh or not), and whether it is fresh. */
  const readHeartbeat = (): { pid: number | undefined; fresh: boolean } | undefined => {
    try {
      const json = readFileSync(heartbeatPath(ctx.guardDir), "utf8");
      const parsed: unknown = JSON.parse(json);
      const pid = parsed && typeof parsed === "object" && "pid" in parsed && typeof parsed.pid === "number" ? parsed.pid : undefined;
      return { pid, fresh: heartbeatFresh(json, Date.now()) };
    } catch {
      return undefined;
    }
  };

  const stdin = ctx.io.stdin;
  // Raw mode: one key answers, and Ctrl-C arrives as input rather than SIGINT.
  const rawIn = !auto && stdin instanceof ReadStream && stdin.isTTY ? stdin : undefined;
  const onData = (chunk: Buffer | string) => {
    for (const ch of String(chunk)) {
      if (ch === "\u0003" || ch === "\u0004") {
        stop("interrupted");
        return;
      }
      const key = ch.toLowerCase();
      if (key !== "d" && key !== "a" && key !== "p" && key !== "s") continue;
      const request = current;
      if (!request || answered.has(request.id)) continue;
      if (key === "p" && !canScope(request)) {
        say(s.dim("  This call has no project directory to scope to."));
        renderPrompt();
        continue;
      }
      if (key === "s" && !canSilence(request)) continue;
      decide(request, key === "d" ? "deny" : "allow", { silence: key === "s", scope: key === "p" ? "project" : undefined }, "terminal");
      // The rest of the chunk was typed at this call, not the next one.
      return;
    }
  };
  const onEnd = () => stop("input closed");

  let tick: NodeJS.Timeout | undefined;
  const stop = (reason: string, takeover = false) => {
    if (stopped) return;
    stopped = true;
    clearInterval(tick);
    approvals.stop();
    spool.drain();
    spool.stop();
    // Remove the heartbeat only while it is ours: after the app's takeover it
    // is the app's. An app that is still starting hasn't written one yet, so
    // ours goes — no guard may think this stopped watch still answers.
    if (readHeartbeat()?.pid === process.pid) heartbeat.clear();
    else heartbeat.stop();
    handle.close();
    if (!auto) {
      stdin.off("data", onData);
      stdin.off("end", onEnd);
      rawIn?.setRawMode(false);
      stdin.pause();
    }
    clearPrompt();
    if (shownTitle !== undefined) out.write(`${setTitle("")}${POP_TITLE}`);
    resolveDone({ stopped: reason, takeover, decisions });
  };

  // The app's order: heartbeat before the watcher, so no guard is ever told
  // someone is listening before someone is.
  heartbeat.start();
  approvals.start();
  spool.start();
  if (!auto) {
    rawIn?.setRawMode(true);
    stdin.on("data", onData);
    stdin.on("end", onEnd);
    stdin.resume();
  }

  const policy = ctx.policy();
  if (attention) {
    out.write(PUSH_TITLE);
    retitle(0);
  }
  const who = sandbox ? `in sandbox ${sandbox.name}` : `as Doorman ${s.dim(`(pid ${process.pid})`)}`;
  say(`${s.bold("Answering held calls")} ${who}. ${auto ? "Denying every held call (--auto deny)." : "Ctrl-C to stop."}`);
  if (!guardHostStates(ctx.io.env).some((h) => h.installed)) say(s.yellow("The guard is not installed, so nothing will be held. Run `doorman guard install`."));
  if (!policy.confirm.interactive) say(s.yellow("Holds are off, so nothing will be held. Turn them on with `doorman policy confirm --interactive on`."));

  tick = setInterval(() => {
    const beat = readHeartbeat();
    if (beat?.fresh && beat.pid !== undefined && beat.pid !== process.pid) {
      say(s.yellow(`Doorman${processLabel(ctx.io.env, beat.pid)} took over answering held calls. Stopping.`));
      stop("taken over by Doorman", true);
      return;
    }
    // The app is starting: it waits for this watch to let go of the data
    // before it writes anything, then answers held calls itself.
    const starting = appOwner(ctx.dataDir);
    if (starting) {
      say(s.yellow(`Doorman${processLabel(ctx.io.env, starting.pid)} is starting and takes over answering held calls. Stopping.`));
      stop("taken over by Doorman", true);
      return;
    }
    if (tty) renderPrompt();
  }, options.tickMs ?? 1000);
  schedule();

  return { done, stop: (reason) => stop(reason) };
}

export const watchCommand: CliCommand = {
  name: "watch",
  summary: "Answer held tool calls in this terminal while the app is closed",
  usage: "[--auto deny]",
  details: [
    "Keeps the guard's heartbeat so ask-mode calls are held, then asks you about each one:",
    "  d  deny",
    "  a  allow once (the agent still applies its own approval flow)",
    "  p  allow, and don't hold it again in this project for 30 days (adds an exception)",
    "  s  allow, and stop asking: the rule drops to observe",
    "Unanswered calls end as the hold settings say (doorman policy confirm).",
    "Needs a terminal. --auto deny answers every held call with deny instead (for scripts).",
    "Refuses to start while the app (or another watch) answers; stops when the app starts.",
    "Prompts go to stderr; stdout gets the summary when it stops.",
    "On a terminal it rings once per held call and shows waiting calls in the window title (DOORMAN_NO_BELL=1 turns the bell off).",
  ],
  options: { auto: { type: "string" } },
  async run(ctx, args) {
    const autoArg = args.values.auto;
    if (autoArg !== undefined && autoArg !== "deny") throw new CliError("--auto only takes deny.", 2);
    const auto = autoArg === "deny" ? ("deny" as const) : undefined;
    if (!auto && ctx.io.stdin.isTTY !== true) {
      throw new CliError("watch asks you in the terminal, and stdin is not one. Run it in a terminal, or pass --auto deny to deny every held call.");
    }
    const session = await startWatch(ctx, { auto });
    const onSignal = () => session.stop("interrupted");
    process.on("SIGINT", onSignal);
    process.on("SIGTERM", onSignal);
    // A closed terminal window (or `sbx exec -it` session) sends SIGHUP.
    process.on("SIGHUP", onSignal);
    let summary: WatchSummary;
    try {
      summary = await session.done;
    } finally {
      process.off("SIGINT", onSignal);
      process.off("SIGTERM", onSignal);
      process.off("SIGHUP", onSignal);
    }
    const counts = { allowed: 0, denied: 0, expired: 0, too_late: 0 };
    for (const d of summary.decisions) counts[d.outcome] += 1;
    return {
      data: summary,
      text: [
        `Stopped${summary.takeover ? ": Doorman took over" : ""}. ${counts.allowed} allowed, ${counts.denied} denied, ${counts.expired + counts.too_late} unanswered.`,
      ],
    };
  },
};
