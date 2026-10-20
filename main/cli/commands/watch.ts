import { readFileSync } from "node:fs";
import { join } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { ReadStream } from "node:tty";
import { ApprovalWatcher, GuardHeartbeat, SpoolWatcher, guardHostStates, syncGuard } from "../../enforcement.js";
import { heartbeatFresh, heartbeatPath, pidAlive, type ApprovalRequest, type ApprovalVerdict } from "../../guard/handshake.js";
import { appOwner } from "../../lib/data-owner.js";
import { HOSTS } from "../../guard/hosts/index.js";
import { approvalContextNote, approvalPolicyChange, approvalSummary } from "../../lib/approvals.js";
import { localDetectorLabel } from "../../lib/findings.js";
import { compactBanner } from "../art.js";
import { dockerSandbox, processLabel, sandboxWatchCommand } from "../docker-sandbox.js";
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
/** Up one row and clear it: the rows a prompt drawn wider than the terminal
 * now is (it was resized narrower) reflowed onto. */
const CLEAR_ROW_ABOVE = "\u001b[1A\u001b[2K";
const BELL = "\u0007";

/** A held call that ran out unanswered while the terminal saw no key for at
 * least this long (and none since the call came in): nobody is there. The
 * watch steps down, so agents fall back to their own prompt rather than wait
 * out every hold on a terminal nobody reads — the `sbx exec -it` session that
 * died without a SIGHUP, the window left open over a weekend. */
const STEP_DOWN_IDLE_MS = 60_000;
/** A `doorman watch` whose terminal has seen no key for this long is taken
 * over by a new one without asking; a fresher one needs `--replace`. */
const ABANDONED_IDLE_MS = 10 * 60_000;
/** How long a replaced watch gets to clean up after SIGTERM before SIGKILL. */
const REPLACE_GRACE_MS = 5_000;
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

/** What allowing does. An agent that runs with its prompts bypassed (the
 * request says so, or this is a Docker Sandbox, where every agent does) runs
 * the call the moment it is allowed: no second approval follows ours. */
function allowNote(request: ApprovalRequest, sandboxed: boolean): string {
  if (request.source === "mcp-gateway") return `Allowing forwards the call to ${request.server ?? "the server"} as the agent sent it.`;
  const agent = agentOf(request).name;
  return request.permissions_bypassed === true || sandboxed
    ? `Allowing runs it now: ${agent} runs without its own prompts here.`
    : `Allowing does not auto-approve: ${agent} still applies its own approval flow.`;
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

/** The preview a card shows, and what it leaves out: the first part the
 * request carries, or with `full` the longer copy it carries for that. */
function previewOf(request: ApprovalRequest, full: boolean): { text: string; omitted: number; expandable: boolean } {
  const text = full && request.preview_full !== undefined ? request.preview_full : request.preview;
  const total = Math.max(request.preview_chars ?? 0, text.length);
  const expandable = !full && (request.preview_full?.length ?? 0) > request.preview.length;
  return { text, omitted: total - text.length, expandable };
}

/**
 * One held call as a card on stderr: what it wants to do, who asked, why it
 * was held, then the keys. On a decorating terminal the card hangs off a
 * frame in the left margin (no right edge, so wide characters in a command
 * can't break it) and long lines wrap inside it. Plain: the same facts as
 * flat lines. The preview is never cut here: where the guard had to cut it,
 * the card says how much is missing and `v` shows the longer copy (`full`).
 * `sandboxed`: this watch runs in a Docker Sandbox, where agents run with
 * their prompts bypassed.
 */
export function heldCard(ui: Ui, request: ApprovalRequest, options: { waiting: number; home: string; auto: boolean; sandboxed?: boolean; full?: boolean }): string[] {
  const s = ui.style;
  const agent = agentOf(request);
  const note = approvalContextNote(request);
  const meta = [agent.name, request.session_id ? `session ${request.session_id.slice(0, 8)}` : "", options.waiting > 1 ? `${options.waiting} waiting` : ""].filter(Boolean);
  const facts: KvRow[] = [
    !!request.reason && ["why", request.reason],
    // The agent's own words for the call: a claim, shown as one.
    !!request.description && ["purpose", `${request.description} (the agent's words)`],
    !!request.cwd && ["directory", tilde(request.cwd, options.home)],
    !!request.server && ["server", `${request.server}${request.tool_class ? ` · ${request.tool_class}` : ""}`],
    !!note && ["note", note],
  ];
  const shown = previewOf(request, options.full === true);
  const preview = shown.text === "" ? [] : shown.text.split("\n");
  const cut =
    shown.omitted === 0
      ? undefined
      : options.full === true
        ? `… ${plural(shown.omitted, "more character")} the guard did not carry.`
        : `… ${plural(shown.omitted, "more character")} not shown.${shown.expandable ? " Press v to see the full call." : ""}`;
  const allow = allowNote(request, options.sandboxed === true);
  const keys: [string, string][] = [...answerKeys(request), ...(shown.expandable ? [["v", "show the full call"] as [string, string]] : [])];

  if (!ui.decorate) {
    return [
      "",
      `Held  ${approvalSummary(request)}  ${meta.join(" · ")}`,
      ...ui.kv(facts, { keyWidth: "directory".length }),
      ...(preview.length > 0 ? ["  about to run:", ...preview.map((l) => `    | ${l}`)] : []),
      ...(cut ? [`  ${cut}`] : []),
      ...(options.auto ? [] : [`  ${keys.map(([k, w]) => `[${k}] ${w}`).join("  ")}`, `  ${allow}`]),
    ];
  }

  const f = ui.glyphs.frame;
  const width = ui.width ?? 80;
  const side = s.warn(f.side);
  const inner = Math.max(20, width - 3);
  // The summary names the call's risky part: wrapped under the header, never cut.
  const lead = `${s.warn(`${f.top}${f.line}`)} ${s.warn(s.bold(`${ui.glyphs.tone.held} Held`))}  `;
  const summary = ui.wrap(approvalSummary(request), Math.max(20, width - visibleLength(lead)));
  const card = [
    "",
    `${lead}${s.bold(summary[0]!)}`,
    ...summary.slice(1).map((l) => `${side}  ${s.bold(l)}`),
    `${side}  ${ui.list(meta.map(s.dim))}`,
  ];
  const factLines = ui.kv(facts, { indent: 0, width: inner });
  if (factLines.length > 0) card.push(side, ...factLines.map((l) => `${side}  ${l}`));
  if (preview.length > 0) {
    card.push(side, `${side}  ${s.dim(options.full === true ? "the full call" : "about to run")}`);
    // At spaces and path separators; a piece with neither runs past the edge whole.
    for (const line of preview) for (const part of ui.wrap(line, inner - 2)) card.push(`${side}    ${part}`);
  }
  if (cut) for (const part of ui.wrap(cut, inner - 2)) card.push(`${side}    ${s.warn(part)}`);
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
    ...ui.wrap(allow, width - 3).map((l) => `   ${s.dim(l)}`),
  ];
}

/**
 * The line under the card, redrawn every second on a terminal: the time left
 * (as a bar on a decorating terminal), what happens then, and the keys.
 * Never as wide as the terminal (whose last column would wrap it), read at
 * its width NOW so a resize between ticks is honoured. What gives way first
 * is the bar, then the prose; the answer keys always show whole.
 */
export function promptLine(ui: Ui, request: ApprovalRequest, nowMs: number): string {
  const s = ui.style;
  const left = secondsLeft(request, nowMs);
  const keys = answerKeys(request).map(([k]) => k);
  const max = ui.width === undefined ? Number.POSITIVE_INFINITY : ui.width - 1;
  const indent = ui.decorate ? "   " : "  ";
  const proses = [`${s.bold(`${left}s`)} left, ${timeoutOutcome(request)}.`, `${s.bold(`${left}s`)} left.`, ""];
  const answers = [`Answer ${keys.join(", ")}: `, `${keys.join("/")}: `];
  for (const answer of answers) {
    for (const prose of proses) {
      const text = prose ? `${prose}${ui.decorate ? "  " : " "}${s.bold(answer)}` : s.bold(answer);
      if (visibleLength(indent) + visibleLength(text) > max) continue;
      if (!ui.decorate) return `${indent}${text}`;
      const fraction = request.hold_seconds > 0 ? left / request.hold_seconds : 0;
      const tone: Tone = fraction > 0.3 ? "info" : fraction > 0.15 ? "warn" : "error";
      const cells = Math.min(20, max - visibleLength(indent) - visibleLength(text) - 2);
      return cells >= 6 ? `${indent}${ui.bar(fraction, cells, tone)}  ${text}` : `${indent}${text}`;
    }
  }
  // Narrower than the keys themselves: nothing left to give way.
  return `${indent}${s.bold(answers[1]!)}`;
}

/** Who wrote the heartbeat file (fresh or not), whether it is fresh, and —
 * for a `doorman watch` — when its terminal last saw a key. */
function readHeartbeat(guardDir: string): { pid: number | undefined; fresh: boolean; inputAt: number | undefined } | undefined {
  try {
    const json = readFileSync(heartbeatPath(guardDir), "utf8");
    const parsed: unknown = JSON.parse(json);
    if (!parsed || typeof parsed !== "object") return { pid: undefined, fresh: false, inputAt: undefined };
    const pid = "pid" in parsed && typeof parsed.pid === "number" ? parsed.pid : undefined;
    const inputAt = "input_at" in parsed && typeof parsed.input_at === "string" ? Date.parse(parsed.input_at) : Number.NaN;
    return { pid, fresh: heartbeatFresh(json, Date.now()), inputAt: Number.isFinite(inputAt) ? inputAt : undefined };
  } catch {
    return undefined;
  }
}

/** Stop the `doorman watch` at `pid` so this one can answer: SIGTERM (it
 * clears its heartbeat and lets go of the data), SIGKILL if it hasn't gone
 * within REPLACE_GRACE_MS (a process stuck writing to a terminal nobody
 * drains). Only ever called for a CLI watch on this machine — or in this
 * sandbox, whose processes are the only ones that share its data. */
async function retireWatch(pid: number, label: string): Promise<void> {
  for (const [signal, waitMs] of [["SIGTERM", REPLACE_GRACE_MS], ["SIGKILL", 2_000]] as const) {
    try {
      process.kill(pid, signal);
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ESRCH") return;
      throw new CliError(`Couldn't stop \`doorman watch\`${label}: ${(err as Error).message}`);
    }
    for (const started = Date.now(); Date.now() - started < waitMs; await delay(50)) if (!pidAlive(pid)) return;
  }
  throw new CliError(`\`doorman watch\`${label} did not stop, so it still answers held calls.`);
}

/**
 * Be the approver while the app is closed: hold the guard heartbeat (so the
 * guard holds `ask` calls at all), watch the pending directory, ingest the
 * guard's spool into the store, and answer each held call through the same
 * path as the app's resolveApproval (policy first, sync, then the verdict).
 * Stops on `stop()`, on Ctrl-C / end of input, when another Doorman (the
 * app) writes the heartbeat, which it then owns, or when nobody is answering
 * (STEP_DOWN_IDLE_MS).
 *
 * Another `doorman watch` already answering is replaced when `replace` says
 * so, or without asking once its terminal has seen no key for
 * ABANDONED_IDLE_MS: a closed `sbx exec -it` session delivers no SIGHUP to
 * the watch inside, so that watch would otherwise own the heartbeat until the
 * sandbox stops. The app is never replaced.
 */
export async function startWatch(ctx: CliContext, options: { auto?: "deny"; replace?: boolean; tickMs?: number; stepDownIdleMs?: number }): Promise<WatchSession> {
  const sandbox = dockerSandbox(ctx.io.env);
  let replaced: string | undefined;
  const other = ctx.running();
  if (other) {
    const label = processLabel(ctx.io.env, other.pid);
    const cliWatch = other.version?.startsWith("cli-") === true && other.pid !== undefined;
    if (!cliWatch) throw new CliError(`Doorman${label} is already answering held calls.`);
    const inputAt = readHeartbeat(ctx.guardDir)?.inputAt;
    const idleMs = inputAt === undefined ? undefined : Date.now() - inputAt;
    const abandoned = idleMs !== undefined && idleMs >= ABANDONED_IDLE_MS;
    if (!options.replace && !abandoned) {
      const again = `${sandbox ? sandboxWatchCommand(sandbox) : "doorman watch"}${options.auto ? " --auto deny" : ""} --replace`;
      throw new CliError(
        `\`doorman watch\`${label} is already answering held calls.`,
        1,
        `If its terminal is gone (a closed window or \`sbx exec\` session), take over with \`${again}\`${sandbox ? " on your computer" : ""}.`,
      );
    }
    await retireWatch(other.pid!, label);
    replaced = `Took over from \`doorman watch\`${label}${abandoned ? `, whose terminal saw no key for ${Math.round(idleMs! / 60_000)} minutes` : ""}.`;
  }
  // Watch writes the store (the guard's spool) and the policy for as long as
  // it runs: it needs the data to itself, not a copy.
  ctx.requireWritable("Answer held calls");
  const ui = ctx.errUi;
  const s = ui.style;
  const out = ctx.io.stderr;
  const tty = "isTTY" in out && out.isTTY === true;
  const auto = options.auto;
  const stepDownIdleMs = options.stepDownIdleMs ?? STEP_DOWN_IDLE_MS;
  // The last key this terminal saw (start counts as one): what tells a person
  // at the keyboard from a terminal nobody reads.
  let lastInputMs = Date.now();
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
  /** The visible width of the prompt line on screen, 0 when none is. */
  let promptCols = 0;
  let stopped = false;
  let scheduled = false;
  let resolveDone!: (summary: WatchSummary) => void;
  const done = new Promise<WatchSummary>((resolve) => {
    resolveDone = resolve;
  });

  /** Erase the prompt line: the row the cursor is on, and the rows above it
   * that the line reflowed onto if the terminal got narrower since it was drawn. */
  const erasePrompt = (): string => {
    const rows = Math.max(1, Math.ceil(promptCols / Math.max(1, ui.width ?? 80)));
    return `${CLEAR_LINE}${CLEAR_ROW_ABOVE.repeat(rows - 1)}`;
  };
  const clearPrompt = () => {
    if (promptCols > 0 && tty) out.write(erasePrompt());
    promptCols = 0;
  };
  const say = (line: string) => {
    clearPrompt();
    out.write(`${line}\n`);
  };
  const renderPrompt = () => {
    if (!current || auto || stopped) return;
    // At the terminal's width now: a resize since the last tick is honoured.
    const line = promptLine(ui, current, Date.now());
    if (tty) {
      out.write(`${promptCols > 0 ? erasePrompt() : CLEAR_LINE}${line}`);
      promptCols = visibleLength(line);
    } else {
      out.write(`${line}\n`);
    }
  };

  const handle = await ctx.openEngine({ scan: false });
  const log = (message: string) => ctx.log(message);
  const heartbeat = new GuardHeartbeat({
    userDataDir: ctx.dataDir,
    version: `cli-${ctx.io.version}`,
    log,
    // A later watch takes over from this one once its terminal goes quiet
    // (startWatch). Under --auto nobody types, and nobody is meant to.
    ...(auto ? {} : { extra: () => ({ input_at: new Date(lastInputMs).toISOString() }) }),
  });

  const present = (request: ApprovalRequest, waiting: number, full = false) => {
    for (const line of heldCard(ui, request, { waiting, home: ctx.io.home, auto: auto !== undefined, sandboxed: sandbox !== undefined, full })) say(line);
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
        // The whole window went by without a key, and the terminal was quiet
        // before it too: nobody is here. Holding the heartbeat now only makes
        // every agent wait out each hold for nobody; letting go sends held
        // calls back to the agents' own prompts.
        if (expired && !auto && lastInputMs <= Date.parse(current.at) && Date.now() - lastInputMs >= stepDownIdleMs) {
          const again = sandbox ? `on your computer, run \`${sandboxWatchCommand(sandbox)}\`` : "run `doorman watch`";
          say(warn(`Nobody answered, and no key was pressed here for ${plural(Math.round((Date.now() - lastInputMs) / 1000), "second")}. Stopping, so agents fall back to their own prompt instead of waiting on this terminal. To answer here again, ${again}.`));
          current = undefined;
          stop("nobody answered");
          return;
        }
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

  const stdin = ctx.io.stdin;
  // Raw mode: one key answers, and Ctrl-C arrives as input rather than SIGINT.
  const rawIn = !auto && stdin instanceof ReadStream && stdin.isTTY ? stdin : undefined;
  const onData = (chunk: Buffer | string) => {
    lastInputMs = Date.now();
    for (const ch of String(chunk)) {
      if (ch === "\u0003" || ch === "\u0004") {
        stop("interrupted");
        return;
      }
      const key = ch.toLowerCase();
      const request = current;
      if (!request || answered.has(request.id)) continue;
      if (key === "v") {
        // The longer copy the guard carries, when the card had to cut it.
        // Answers nothing: the countdown runs on, and so does its outcome.
        if (!previewOf(request, false).expandable) continue;
        present(request, approvals.list().filter((r) => !answered.has(r.id)).length, true);
        renderPrompt();
        continue;
      }
      if (key !== "d" && key !== "a" && key !== "p" && key !== "s") continue;
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
  // End of input, or a read error (EIO from a terminal whose other side is
  // gone): nobody can answer here any more.
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
    if (readHeartbeat(ctx.guardDir)?.pid === process.pid) heartbeat.clear();
    else heartbeat.stop();
    handle.close();
    if (!auto) {
      stdin.off("data", onData);
      stdin.off("end", onEnd);
      stdin.off("error", onEnd);
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
    stdin.on("error", onEnd);
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
  if (replaced) say(warn(replaced));
  const intro = `${s.bold("Answering held calls")} ${who}. ${auto ? "Denying every held call (--auto deny)." : "Ctrl-C to stop."}`;
  say(ui.decorate ? ui.mark("ok", intro) : intro);
  if (!guardHostStates(ctx.io.env).some((h) => h.installed)) say(warn("The guard is not installed, so nothing will be held. Run `doorman guard install`."));
  if (!policy.confirm.interactive) say(warn("Holds are off, so nothing will be held. Turn them on with `doorman policy confirm --interactive on`."));

  tick = setInterval(() => {
    const beat = readHeartbeat(ctx.guardDir);
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
  usage: "[--auto deny] [--replace]",
  flags: [
    ["--auto deny", "answer every held call with deny, without asking (for scripts; needs no terminal)"],
    ["--replace", "take over from a `doorman watch` already answering (one whose terminal is gone)"],
  ],
  notes: [
    "Keeps the guard's heartbeat so ask-mode calls are held, then asks you about each one:",
    "  d  deny",
    "  a  allow once (an agent with its own prompts still asks; in a Docker Sandbox, or with permissions bypassed, the call runs at once)",
    "  p  allow, and don't hold it in this project for 30 days (adds an exception)",
    "  s  allow, and stop asking: the rule drops to observe",
    "  v  show the full call, when the card had to cut it (answers nothing)",
    "Unanswered calls end as the hold settings say (`doorman policy confirm`). Refuses to start while the app answers, and stops when the app starts.",
    "Takes over from another `doorman watch` whose terminal saw no key for 10 minutes, or any with --replace. When a held call goes unanswered and no key was pressed for a minute, it stops, so agents fall back to their own prompt.",
    "Prompts go to stderr; stdout gets the summary when it stops. On a terminal it rings once per held call and shows waiting calls in the window title (DOORMAN_NO_BELL=1 turns the bell off).",
  ],
  examples: [
    ["doorman watch", "answer held calls here"],
    ["sbx exec -it <sandbox> doorman watch", "answer a Docker Sandbox's held calls from your computer"],
    ["sbx exec -it <sandbox> doorman watch --replace", "the same, after the terminal that ran it closed"],
    ["doorman watch --auto deny", "deny every held call (CI, scripts)"],
  ],
  options: { auto: { type: "string" }, replace: { type: "boolean", default: false } },
  async run(ctx, args) {
    const autoArg = args.values.auto;
    if (autoArg !== undefined && autoArg !== "deny") throw new CliError("--auto only takes deny.", 2, "`doorman watch --auto deny` denies every held call.");
    const auto = autoArg === "deny" ? ("deny" as const) : undefined;
    if (!auto && ctx.io.stdin.isTTY !== true) {
      throw new CliError("watch asks you in the terminal, and stdin is not one.", 1, "Run it in a terminal, or pass --auto deny to deny every held call.");
    }
    const session = await startWatch(ctx, { auto, replace: args.values.replace === true });
    const onSignal = () => session.stop("interrupted");
    process.on("SIGINT", onSignal);
    process.on("SIGTERM", onSignal);
    // A closed terminal window sends SIGHUP. A closed `sbx exec -it` session
    // does not: the idle step-down and a later watch's takeover cover that.
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
