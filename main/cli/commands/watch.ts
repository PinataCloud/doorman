import { readFileSync } from "node:fs";
import { join } from "node:path";
import { ReadStream } from "node:tty";
import { ApprovalWatcher, GuardHeartbeat, SpoolWatcher, guardHostStates, syncGuard } from "../../enforcement.js";
import { heartbeatFresh, heartbeatPath, type ApprovalRequest, type ApprovalVerdict } from "../../guard/handshake.js";
import { appOwner } from "../../lib/data-owner.js";
import { HOSTS } from "../../guard/hosts/index.js";
import { approvalContextNote, approvalPolicyChange, approvalSummary } from "../../lib/approvals.js";
import { localDetectorLabel } from "../../lib/findings.js";
import { compactBanner } from "../art.js";
import { dockerSandbox, processLabel } from "../docker-sandbox.js";
import type { CliCommand } from "../command.js";
import type { CliContext } from "../context.js";
import { CliError, visibleLength } from "../output.js";
import { plural, type KvRow, type Tone, type Ui } from "../ui.js";
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

const canScope = (request: ApprovalRequest) => !!request.cwd && request.source !== "mcp-gateway";
const canSilence = (request: ApprovalRequest) => request.source !== "mcp-gateway";

/** The keys a held call takes, and what each does. */
function answerKeys(request: ApprovalRequest): [key: string, what: string][] {
  return [
    ["d", "deny"],
    ["a", "allow once"],
    ...(canScope(request) ? [["p", "allow for this project (30 days)"] as [string, string]] : []),
    ...(canSilence(request) ? [["s", "allow and stop asking"] as [string, string]] : []),
  ];
}

const secondsLeft = (request: ApprovalRequest, nowMs: number) => Math.max(0, Math.round((Date.parse(request.at) + request.hold_seconds * 1000 - nowMs) / 1000));

/** Items laid out left to right, `gap` apart, onto as many lines as `width` needs. */
function pack(items: readonly string[], width: number, gap = 3): string[] {
  const lines: string[] = [];
  let line = "";
  for (const item of items) {
    if (line && visibleLength(line) + gap + visibleLength(item) > width) {
      lines.push(line);
      line = item;
    } else line = line ? `${line}${" ".repeat(gap)}${item}` : item;
  }
  if (line) lines.push(line);
  return lines;
}

/**
 * One held call as a card on stderr: what it wants to do, who asked, why it
 * was held, then the keys. On a decorating terminal the card hangs off a
 * frame in the left margin (no right edge, so wide characters in a command
 * can't break it) and long lines wrap inside it. Plain: the same facts as
 * flat lines.
 */
export function heldCard(ui: Ui, request: ApprovalRequest, options: { waiting: number; home: string; auto: boolean }): string[] {
  const s = ui.style;
  const agent = agentOf(request);
  const note = approvalContextNote(request);
  const meta = [agent.name, request.session_id ? `session ${request.session_id.slice(0, 8)}` : "", options.waiting > 1 ? `${options.waiting} waiting` : ""].filter(Boolean);
  const facts: KvRow[] = [
    !!request.reason && ["why", request.reason],
    !!request.cwd && ["directory", tilde(request.cwd, options.home)],
    !!request.server && ["server", `${request.server}${request.tool_class ? ` · ${request.tool_class}` : ""}`],
    !!note && ["note", note],
  ];
  const preview = request.preview === "" ? [] : request.preview.split("\n").slice(0, 12).map((l) => (l.length > 200 ? `${l.slice(0, 200)}...` : l));
  const allowNote =
    request.source === "mcp-gateway"
      ? `Allowing forwards the call to ${request.server ?? "the server"} as the agent sent it.`
      : `Allowing does not auto-approve: ${agent.name} still applies its own approval flow.`;
  const keys = answerKeys(request);

  if (!ui.decorate) {
    return [
      "",
      `Held  ${approvalSummary(request)}  ${meta.join(" · ")}`,
      ...ui.kv(facts, { keyWidth: "directory".length }),
      ...(preview.length > 0 ? ["  about to run:", ...preview.map((l) => `    | ${l}`)] : []),
      ...(options.auto ? [] : [`  ${keys.map(([k, w]) => `[${k}] ${w}`).join("  ")}`, `  ${allowNote}`]),
    ];
  }

  const f = ui.glyphs.frame;
  const width = ui.width ?? 80;
  const side = s.warn(f.side);
  const inner = Math.max(20, width - 3);
  const card = [
    "",
    ui.truncate(`${s.warn(`${f.top}${f.line}`)} ${s.warn(s.bold(`${ui.glyphs.tone.held} Held`))}  ${s.bold(approvalSummary(request))}`, width),
    `${side}  ${ui.list(meta.map(s.dim))}`,
  ];
  const factLines = ui.kv(facts, { indent: 0, width: inner });
  if (factLines.length > 0) card.push(side, ...factLines.map((l) => `${side}  ${l}`));
  if (preview.length > 0) {
    card.push(side, `${side}  ${s.dim("about to run")}`);
    // At spaces and path separators; a piece with neither runs past the edge whole.
    for (const line of preview) for (const part of ui.wrap(line, inner - 2)) card.push(`${side}    ${part}`);
  }
  if (options.auto) return [...card, `${s.warn(`${f.bottom}${f.line}`)} ${s.dim("denying every held call (--auto deny)")}`];
  const keyLines = pack(
    keys.map(([k, w]) => `${s.pink(s.bold(`[${k}]`))} ${w}`),
    width - 3,
  );
  return [
    ...card,
    side,
    `${s.warn(`${f.bottom}${f.line}`)} ${keyLines[0]}`,
    ...keyLines.slice(1).map((l) => `   ${l}`),
    ...ui.wrap(allowNote, width - 3).map((l) => `   ${s.dim(l)}`),
  ];
}

/**
 * The line under the card, redrawn every second on a terminal: the time left
 * (as a bar on a decorating terminal), what happens then, and the keys.
 * Never wider than the terminal, so the redraw can't wrap.
 */
export function promptLine(ui: Ui, request: ApprovalRequest, nowMs: number): string {
  const s = ui.style;
  const left = secondsLeft(request, nowMs);
  const answer = `Answer ${answerKeys(request).map(([k]) => k).join(", ")}: `;
  if (!ui.decorate) return ui.fit(`  ${left}s left, ${timeoutOutcome(request)}. ${answer}`);
  const fraction = request.hold_seconds > 0 ? left / request.hold_seconds : 0;
  const tone: Tone = fraction > 0.3 ? "info" : fraction > 0.15 ? "warn" : "error";
  const text = `${s.bold(`${left}s`)} left, ${timeoutOutcome(request)}.  ${s.bold(answer)}`;
  const width = ui.width ?? 80;
  const cells = Math.min(20, width - 3 - visibleLength(text) - 2);
  return ui.truncate(cells >= 6 ? `   ${ui.bar(fraction, cells, tone)}  ${text}` : `   ${text}`, width - 1);
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
  const ui = ctx.errUi;
  const s = ui.style;
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
  const renderPrompt = () => {
    if (!current || auto || stopped) return;
    const line = promptLine(ui, current, Date.now());
    if (tty) {
      out.write(`${CLEAR_LINE}${line}`);
      promptShown = true;
    } else {
      out.write(`${line}\n`);
    }
  };

  const handle = await ctx.openEngine({ scan: false });
  const log = (message: string) => ctx.log(message);
  const heartbeat = new GuardHeartbeat({ userDataDir: ctx.dataDir, version: `cli-${ctx.io.version}`, log });

  const present = (request: ApprovalRequest, waiting: number) => {
    for (const line of heldCard(ui, request, { waiting, home: ctx.io.home, auto: auto !== undefined })) say(line);
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
    let tone: Tone;
    if (!ok) [tone, words] = ["warn", s.warn("Too late: the call had stopped waiting.")];
    else if (verdict === "deny") [tone, words] = ["error", s.error(auto ? "Denied (--auto deny)." : "Denied.")];
    else {
      [tone, words] = ["ok", s.ok("Allowed.")];
      if (change.scoped > 0) words += ` Not held again under ${tilde(request.cwd ?? "", ctx.io.home)} for 30 days (${plural(change.scoped, "exception")}).`;
      if (change.silenced.length > 0) words += ` ${change.silenced.map((d) => localDetectorLabel(d)).join(", ")} now only observed.`;
    }
    say(ui.decorate ? `   ${ui.mark(tone, `${prefix}${words}`)}` : `  ${prefix}${words}`);
    if (syncError) say(ui.decorate ? `   ${ui.mark("warn", s.warn(`Saved, but the guard was not updated: ${syncError}`))}` : `  Saved, but the guard was not updated: ${syncError}`);
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
        const expired = secondsLeft(current, Date.now()) === 0;
        const words = expired ? `No answer in time: ${timeoutOutcome(current).replace(/^then /, "")}.` : "No longer waiting: the agent stopped the call.";
        say(ui.decorate ? `   ${ui.mark("off", s.dim(words))}` : `  ${words}`);
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
  const warn = (text: string) => (ui.decorate ? ui.mark("warn", ui.prose(text)) : text);
  for (const line of compactBanner(ui, "doorman watch", `v${ctx.io.version}${sandbox ? `, sandbox ${sandbox.name}` : ""}`)) say(line);
  if (ui.decorate) say("");
  const intro = `${s.bold("Answering held calls")} ${who}. ${auto ? "Denying every held call (--auto deny)." : "Ctrl-C to stop."}`;
  say(ui.decorate ? ui.mark("ok", intro) : intro);
  if (!guardHostStates(ctx.io.env).some((h) => h.installed)) say(warn("The guard is not installed, so nothing will be held. Run `doorman guard install`."));
  if (!policy.confirm.interactive) say(warn("Holds are off, so nothing will be held. Turn them on with `doorman policy confirm --interactive on`."));

  tick = setInterval(() => {
    const beat = readHeartbeat();
    if (beat?.fresh && beat.pid !== undefined && beat.pid !== process.pid) {
      say(warn(`Doorman${processLabel(ctx.io.env, beat.pid)} took over answering held calls. Stopping.`));
      stop("taken over by Doorman", true);
      return;
    }
    // The app is starting: it waits for this watch to let go of the data
    // before it writes anything, then answers held calls itself.
    const starting = appOwner(ctx.dataDir);
    if (starting) {
      say(warn(`Doorman${processLabel(ctx.io.env, starting.pid)} is starting and takes over answering held calls. Stopping.`));
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
  flags: [["--auto deny", "answer every held call with deny, without asking (for scripts; needs no terminal)"]],
  notes: [
    "Keeps the guard's heartbeat so ask-mode calls are held, then asks you about each one:",
    "  d  deny",
    "  a  allow once (the agent still applies its own approval flow)",
    "  p  allow, and don't hold it in this project for 30 days (adds an exception)",
    "  s  allow, and stop asking: the rule drops to observe",
    "Unanswered calls end as the hold settings say (`doorman policy confirm`). Refuses to start while the app (or another watch) answers, and stops when the app starts.",
    "Prompts go to stderr; stdout gets the summary when it stops. On a terminal it rings once per held call and shows waiting calls in the window title (DOORMAN_NO_BELL=1 turns the bell off).",
  ],
  examples: [
    ["doorman watch", "answer held calls here"],
    ["sbx exec -it <sandbox> doorman watch", "answer a Docker Sandbox's held calls from your computer"],
    ["doorman watch --auto deny", "deny every held call (CI, scripts)"],
  ],
  options: { auto: { type: "string" } },
  async run(ctx, args) {
    const autoArg = args.values.auto;
    if (autoArg !== undefined && autoArg !== "deny") throw new CliError("--auto only takes deny.", 2, "`doorman watch --auto deny` denies every held call.");
    const auto = autoArg === "deny" ? ("deny" as const) : undefined;
    if (!auto && ctx.io.stdin.isTTY !== true) {
      throw new CliError("watch asks you in the terminal, and stdin is not one.", 1, "Run it in a terminal, or pass --auto deny to deny every held call.");
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
    return { data: summary, text: watchSummaryText(ctx.ui, summary) };
  },
};

/** What `watch` prints on stdout when it stops: the counts, then each call it saw end. */
export function watchSummaryText(ui: Ui, summary: WatchSummary): string[] {
  const s = ui.style;
  const counts = { allowed: 0, denied: 0, expired: 0, too_late: 0 };
  for (const d of summary.decisions) counts[d.outcome] += 1;
  const unanswered = counts.expired + counts.too_late;
  const stopped = `Stopped${summary.takeover ? ": Doorman took over" : ""}.`;
  const head = ui.decorate
    ? `${s.bold(stopped)}  ${ui.list([ui.mark("ok", `${counts.allowed} allowed`), ui.mark("error", `${counts.denied} denied`), ui.mark("off", `${unanswered} unanswered`)])}`
    : `${stopped} ${counts.allowed} allowed, ${counts.denied} denied, ${unanswered} unanswered.`;
  // On a terminal the summary follows the cards: a blank line between.
  const gap = ui.decorate ? [""] : [];
  if (summary.decisions.length === 0) return [...gap, head];
  const word = { allowed: "allowed", denied: "denied", expired: "unanswered", too_late: "too late" } as const;
  const tone = { allowed: "ok", denied: "error", expired: "off", too_late: "warn" } as const;
  const rows = summary.decisions.map((d) => {
    const extra = [d.via === "editor" ? "in the editor" : "", d.scoped ? "project exception" : "", d.silenced ? "rule now observed" : ""].filter(Boolean).join(", ");
    return [ui.mark(tone[d.outcome], ui.paint(tone[d.outcome], word[d.outcome])), clock(d.at), `${d.summary}${extra ? s.dim(`  (${extra})`) : ""}`];
  });
  return [...gap, head, "", ...ui.table(["Outcome", "At", "Call"], rows, { indent: 2, keep: [0, 1] })];
}

/** ISO time → local "14:02:11". */
function clock(iso: string): string {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toTimeString().slice(0, 8);
}
