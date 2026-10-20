/**
 * `doorman sbx`: Docker Sandboxes, from the computer that runs them.
 *
 * Inside a sandbox the desktop app can't run, so its held calls wait for a
 * `doorman watch` in it. `sbx watch` runs one per running sandbox
 * (`sbx exec -i <name> doorman watch --stdio`, no terminal) and answers all of
 * them in ONE terminal: one queue, oldest first, the same card and keys as
 * `watch`, each card naming its sandbox. Closing it closes every child's
 * stdin, which is what ends them (and frees their heartbeats) at once — even
 * when this process is killed outright.
 *
 * `sbx ls` asks each running sandbox's Doorman how it stands
 * (`doorman status --json`, all at once, with a timeout). `sbx pull`
 * (sbx-pull.ts) brings their findings and sessions here.
 */

import type { ChildProcess } from "node:child_process";
import { ReadStream } from "node:tty";
import type { ApprovalRequest, ApprovalVerdict } from "../../guard/handshake.js";
import { approvalSummary } from "../../lib/approvals.js";
import { compactBanner } from "../art.js";
import type { CliCommand } from "../command.js";
import type { CliContext } from "../context.js";
import { CliError, stripAnsi } from "../output.js";
import {
  DOORMAN_KIT,
  commandMissing,
  firstLine,
  installKitHint,
  listSandboxes,
  sbxRun,
  sbxSpawn,
  selectSandboxes,
  updateDoormanHint,
  type HostSandbox,
} from "../sbx-host.js";
import { plural, type Tone } from "../ui.js";
import { SEVERITIES, type Severity } from "./data-shared.js";
import { sbxPullCommand } from "./sbx-pull.js";
import {
  HeldScreen,
  canScope,
  canSilence,
  parseStdioEvent,
  previewOf,
  stdioLine,
  watchSummaryText,
  type StdioEvent,
  type StdioOutcome,
  type WatchDecision,
  type WatchSession,
  type WatchSummary,
} from "./watch.js";

/** How often `sbx watch --all` looks for sandboxes that started since. */
const POLL_MS = 3_000;
/** As `watch`: a held call that ran out while this terminal saw no key for
 * this long (and none since the call came in) means nobody is here. */
const STEP_DOWN_IDLE_MS = 60_000;
/** How long the children get to exit once their stdin is closed. */
const EXIT_GRACE_MS = 5_000;
/** How long `sbx ls` waits for one sandbox's `doorman status`. */
const STATUS_TIMEOUT_MS = 20_000;

/** One sandbox's `doorman watch --stdio`, as this side sees it. */
interface Child {
  sandbox: HostSandbox;
  proc: ChildProcess;
  /** It said hello: it answers that sandbox's held calls. */
  live: boolean;
  exited: boolean;
  stderr: string;
  pending: string;
  /** Settles once it has exited (or never started). */
  gone: Promise<void>;
  settle: () => void;
}

/** One held call in the queue. */
interface Queued {
  sandbox: string;
  request: ApprovalRequest;
  /** Arrival order, for calls held in the same millisecond. */
  seq: number;
  /** Answered here; waiting for the sandbox to say how it went. */
  answered: boolean;
}

const outcomeTone: Record<StdioOutcome, Tone> = { allowed: "ok", denied: "error", too_late: "warn", timed_out: "off", withdrawn: "off" };
const decisionOutcome: Record<StdioOutcome, WatchDecision["outcome"]> = { allowed: "allowed", denied: "denied", too_late: "too_late", timed_out: "expired", withdrawn: "expired" };

/** Why a child ended before it answered anything, said once. */
function refusal(child: Child, code: number | null): string {
  const name = child.sandbox.name;
  const said = stripAnsi(child.stderr);
  if (/unknown option '--stdio'/i.test(said)) return `Sandbox ${name}: its Doorman is too old to answer from here. ${updateDoormanHint(child.sandbox)}`;
  if (commandMissing(code, said)) return `Sandbox ${name}: Doorman is not installed. ${installKitHint(child.sandbox)}`;
  const why = firstLine(said).replace(/^doorman:\s*/, "");
  if (/already answering/.test(why)) return `Sandbox ${name} skipped: ${why}`;
  return `Sandbox ${name}: ${why || `exited (${code ?? "killed"}) before answering.`}`;
}

/**
 * Answer every chosen sandbox's held calls in this terminal: `names`, or
 * with none, every running sandbox — and with `all` (or no names), each one
 * that starts while this runs. Stops on `stop()`, on Ctrl-C / Ctrl-D / end of
 * input, when no sandbox is left to answer for (named ones only), or when a
 * held call ran out with nobody at the keyboard (as `watch` does).
 */
export async function startSbxWatch(
  ctx: CliContext,
  options: { names: string[]; all: boolean; replace: boolean; tickMs?: number; pollMs?: number; stepDownIdleMs?: number },
): Promise<WatchSession> {
  const env = ctx.io.env;
  const follow = options.all || options.names.length === 0;
  const listed = await listSandboxes(env);
  const { chosen, problems } = selectSandboxes(listed, options.names);
  if (!follow && chosen.length === 0) throw new CliError(problems[0] ?? "No sandbox to answer for.", 1, "`doorman sbx ls` lists your sandboxes.");

  const ui = ctx.errUi;
  const s = ui.style;
  const screen = new HeldScreen(ui, ctx.io.stderr, {
    env,
    attention: true,
    idleTitle: "doorman sbx watch",
    waitingTitle: (waiting) => `doorman sbx: ${waiting} call${waiting === 1 ? "" : "s"} waiting`,
  });
  const stepDownIdleMs = options.stepDownIdleMs ?? STEP_DOWN_IDLE_MS;
  let lastInputMs = Date.now();
  const children = new Map<string, Child>();
  const queue = new Map<string, Queued>();
  const keyOf = (sandbox: string, id: string) => `${sandbox}\u0000${id}`;
  const decisions: WatchDecision[] = [];
  let seq = 0;
  let current: Queued | undefined;
  let stopped = false;
  let scheduled = false;
  let resolveDone!: (summary: WatchSummary) => void;
  const done = new Promise<WatchSummary>((resolve) => {
    resolveDone = resolve;
  });

  const waiting = () => [...queue.values()].filter((q) => !q.answered);
  const present = (q: Queued, full = false) =>
    screen.card(q.request, { waiting: waiting().length, home: ctx.io.home, auto: false, sandbox: q.sandbox, full });
  const renderPrompt = () => {
    if (current && !current.answered && !stopped) screen.prompt(current.request, Date.now());
  };

  /** Show the oldest unanswered call, unless one is up already. */
  const advance = () => {
    scheduled = false;
    if (stopped) return;
    screen.title(waiting().length);
    if (current) return;
    const next = waiting().sort((a, b) => Date.parse(a.request.at) - Date.parse(b.request.at) || a.seq - b.seq)[0];
    if (!next) {
      screen.clearPrompt();
      return;
    }
    current = next;
    present(next);
    renderPrompt();
  };
  const schedule = () => {
    if (scheduled || stopped) return;
    scheduled = true;
    setImmediate(advance);
  };

  const onEvent = (child: Child, event: StdioEvent) => {
    const name = child.sandbox.name;
    if (event.type === "hello") {
      child.live = true;
      screen.say(ui.mark("ok", `Sandbox ${s.bold(name)}: answering ${s.dim(`(Doorman ${event.version})`)}`));
      return;
    }
    if (event.type === "info") {
      screen.warn(`Sandbox ${name}: ${event.message}`);
      return;
    }
    if (event.type === "held") {
      const key = keyOf(name, event.request.id);
      if (queue.has(key)) return;
      queue.set(key, { sandbox: name, request: event.request, seq: seq++, answered: false });
      screen.ring();
      schedule();
      return;
    }
    if (event.type !== "resolved") return;
    const key = keyOf(name, event.id);
    const q = queue.get(key);
    if (!q) return;
    queue.delete(key);
    decisions.push({
      id: event.id,
      at: new Date(ctx.io.now()).toISOString(),
      summary: `${name}: ${approvalSummary(q.request)}`,
      outcome: decisionOutcome[event.outcome],
      ...(event.via ? { via: event.via } : {}),
    });
    const tone = outcomeTone[event.outcome];
    const text = tone === "off" ? s.dim(event.message) : ui.paint(tone, event.message);
    if (q === current) {
      current = undefined;
      screen.note(tone, text);
      // As `watch`: the whole window went by without a key, and the terminal
      // was quiet before it too. Letting go sends held calls back to the
      // agents' own prompts instead of waiting on this terminal.
      if (event.outcome === "timed_out" && lastInputMs <= Date.parse(q.request.at) && Date.now() - lastInputMs >= stepDownIdleMs) {
        screen.warn(
          `Nobody answered, and no key was pressed here for ${plural(Math.round((Date.now() - lastInputMs) / 1000), "second")}. Stopping, so agents fall back to their own prompt instead of waiting on this terminal. To answer here again, run \`doorman sbx watch\`.`,
        );
        stop("nobody answered");
        return;
      }
    } else if (event.outcome === "allowed" || event.outcome === "denied") {
      // Answered in that sandbox's editor while another card was up.
      screen.note(tone, `${s.bold(`[${name}]`)} ${text} ${s.dim(approvalSummary(q.request))}`);
    }
    schedule();
  };

  const onExit = (child: Child, code: number | null) => {
    if (child.exited) return;
    child.exited = true;
    child.settle();
    const name = child.sandbox.name;
    const dropped = [...queue.entries()].filter(([, q]) => q.sandbox === name);
    for (const [key] of dropped) queue.delete(key);
    if (current?.sandbox === name) current = undefined;
    if (stopped) return;
    if (!child.live) screen.warn(refusal(child, code));
    else {
      const lost = dropped.filter(([, q]) => !q.answered).length;
      screen.warn(`Sandbox ${name} stopped answering (it stopped, or its Doorman did)${lost > 0 ? `: dropped ${plural(lost, "waiting call")}` : ""}.`);
    }
    schedule();
    if (!follow && [...children.values()].every((c) => c.exited)) stop("no sandbox left");
  };

  const connect = (sandbox: HostSandbox) => {
    const proc = sbxSpawn(env, sandbox.name, ["doorman", "watch", "--stdio", ...(options.replace ? ["--replace"] : [])], { interactive: true });
    let settle!: () => void;
    const gone = new Promise<void>((resolve) => (settle = resolve));
    const child: Child = { sandbox, proc, live: false, exited: false, stderr: "", pending: "", gone, settle };
    children.set(sandbox.name, child);
    // The child's stdin is how it knows we're here; a write to one that
    // already went is not an error worth more than its exit.
    proc.stdin!.on("error", () => {});
    proc.stdout!.setEncoding("utf8").on("data", (chunk: string) => {
      child.pending += chunk;
      for (let nl = child.pending.indexOf("\n"); nl >= 0; nl = child.pending.indexOf("\n")) {
        const line = child.pending.slice(0, nl).trim();
        child.pending = child.pending.slice(nl + 1);
        if (!line || stopped) continue;
        const event = parseStdioEvent(line);
        if (event) onEvent(child, event);
      }
    });
    proc.stderr!.setEncoding("utf8").on("data", (chunk: string) => {
      if (child.stderr.length < 8_192) child.stderr += chunk;
    });
    proc.on("error", (err) => {
      child.stderr += `${err.message}\n`;
      onExit(child, null);
    });
    proc.on("close", (code) => onExit(child, code));
  };

  const answer = (q: Queued, verdict: ApprovalVerdict, scope: "once" | "project" | "silence") => {
    const child = children.get(q.sandbox);
    if (!child || child.exited) return;
    q.answered = true;
    child.proc.stdin!.write(stdioLine({ type: "answer", id: q.request.id, verdict, scope }));
    screen.clearPrompt();
  };

  const stdin = ctx.io.stdin;
  const rawIn = stdin instanceof ReadStream && stdin.isTTY ? stdin : undefined;
  const onData = (chunk: Buffer | string) => {
    lastInputMs = Date.now();
    for (const ch of String(chunk)) {
      if (ch === "\u0003" || ch === "\u0004") {
        stop("interrupted");
        return;
      }
      const key = ch.toLowerCase();
      const q = current;
      if (!q || q.answered) continue;
      if (key === "v") {
        if (!previewOf(q.request, false).expandable) continue;
        present(q, true);
        renderPrompt();
        continue;
      }
      if (key !== "d" && key !== "a" && key !== "p" && key !== "s") continue;
      if (key === "p" && !canScope(q.request)) {
        screen.say(s.dim("  This call has no project directory to scope to."));
        renderPrompt();
        continue;
      }
      if (key === "s" && !canSilence(q.request)) continue;
      answer(q, key === "d" ? "deny" : "allow", key === "p" ? "project" : key === "s" ? "silence" : "once");
      // The rest of the chunk was typed at this call, not the next one.
      return;
    }
  };
  const onEnd = () => stop("input closed");

  let tick: NodeJS.Timeout | undefined;
  let poll: NodeJS.Timeout | undefined;
  const stop = (reason: string) => {
    if (stopped) return;
    stopped = true;
    clearInterval(tick);
    clearInterval(poll);
    stdin.off("data", onData);
    stdin.off("end", onEnd);
    stdin.off("error", onEnd);
    rawIn?.setRawMode(false);
    stdin.pause();
    screen.close();
    // Their stdin ends: each lets go of its sandbox's heartbeat and exits.
    const left = [...children.values()].filter((c) => !c.exited);
    for (const c of left) c.proc.stdin!.end();
    const finish = () => resolveDone({ stopped: reason, takeover: false, decisions });
    if (left.length === 0) {
      finish();
      return;
    }
    const kill = setTimeout(() => {
      for (const c of left) if (!c.exited) c.proc.kill("SIGKILL");
    }, EXIT_GRACE_MS);
    void Promise.all(left.map((c) => c.gone)).then(() => {
      clearTimeout(kill);
      finish();
    });
  };

  screen.open();
  for (const line of compactBanner(ui, "doorman sbx watch", `v${ctx.io.version}, Docker Sandboxes`)) screen.say(line);
  if (ui.decorate) screen.say("");
  for (const problem of problems) screen.warn(problem);
  const intro = `${s.bold("Answering held calls")} from ${follow ? "every running sandbox" : plural(chosen.length, "sandbox", "sandboxes")}. Ctrl-C to stop.`;
  screen.say(ui.decorate ? ui.mark("ok", intro) : intro);
  if (chosen.length === 0) screen.say(s.dim("  No sandbox is running yet; each one that starts is answered here."));

  rawIn?.setRawMode(true);
  stdin.on("data", onData);
  stdin.on("end", onEnd);
  stdin.on("error", onEnd);
  stdin.resume();
  for (const sandbox of chosen) connect(sandbox);

  tick = setInterval(() => {
    if (screen.tty) renderPrompt();
  }, options.tickMs ?? 1000);
  if (follow) {
    let polling = false;
    poll = setInterval(() => {
      if (polling || stopped) return;
      polling = true;
      listSandboxes(env)
        .then((now) => {
          if (stopped) return;
          const running = new Set(now.filter((b) => b.running).map((b) => b.name));
          // A sandbox that stopped is answered again once it runs again.
          for (const [name, child] of children) if (child.exited && !running.has(name)) children.delete(name);
          for (const sandbox of now) if (sandbox.running && !children.has(sandbox.name)) connect(sandbox);
        })
        .catch((err: unknown) => ctx.log(`sbx ls: ${err instanceof Error ? err.message : String(err)}`))
        .finally(() => {
          polling = false;
        });
    }, options.pollMs ?? POLL_MS);
  }

  return { done, stop: (reason) => stop(reason) };
}

const sbxWatch: CliCommand = {
  name: "sbx watch",
  summary: "Answer every Docker Sandbox's held calls in this terminal",
  usage: "[--all | <name>...] [--replace]",
  positionals: { min: 0, max: 64 },
  flags: [
    ["--all", "every running sandbox, and each one that starts while this runs (the default with no name)"],
    ["--replace", "take over from a `doorman watch` already answering in a sandbox"],
  ],
  notes: [
    "Runs `sbx exec -i <sandbox> doorman watch --stdio` in each sandbox and shows their held calls as one queue, oldest first, each card naming its sandbox. The keys are `doorman watch`'s:",
    "  d  deny",
    "  a  allow once (sandboxed agents run without their own prompts: the call runs at once)",
    "  p  allow, and don't hold it in this project for 30 days (adds an exception in that sandbox)",
    "  s  allow, and stop asking: the rule drops to observe in that sandbox",
    "  v  show the full call, when the card had to cut it (answers nothing)",
    "A sandbox without Doorman, or with a Doorman too old for this, is named once and skipped; so is one where a `doorman watch` is answering already (unless --replace). A sandbox that stops drops its waiting calls. Ctrl-C, or closing this terminal, ends the watch in every sandbox at once.",
    "When a held call goes unanswered and no key was pressed for a minute, it stops, so agents fall back to their own prompt. Only local sandboxes (`sbx ls`).",
  ],
  examples: [
    ["doorman sbx watch", "answer every running sandbox, and the ones that start"],
    ["doorman sbx watch my-project", "just this one"],
    ["doorman sbx watch --all --replace", "take over from watches whose terminals are gone"],
  ],
  options: { all: { type: "boolean", default: false }, replace: { type: "boolean", default: false } },
  async run(ctx, args) {
    if (args.values.all === true && args.positionals.length > 0) throw new CliError("Name sandboxes or pass --all, not both.", 2);
    if (ctx.io.stdin.isTTY !== true) throw new CliError("sbx watch asks you in the terminal, and stdin is not one.", 1, "Run it in a terminal.");
    const session = await startSbxWatch(ctx, { names: args.positionals, all: args.values.all === true, replace: args.values.replace === true });
    const onSignal = () => session.stop("interrupted");
    process.on("SIGINT", onSignal);
    process.on("SIGTERM", onSignal);
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

/** What `sbx ls` learned about one sandbox. */
interface SandboxReport {
  name: string;
  agent: string | null;
  status: string;
  workspaces: string[];
  /** `installed` null: not asked (it isn't running). */
  doorman: { installed: boolean | null; version?: string; error?: string };
  guard?: { installed: string[]; not_installed: string[] };
  /** Who answers its held calls; null: nobody. */
  answering?: { by: "app" | "watch" | "sbx watch"; pid?: number } | null;
  exposures?: { open: number; by_severity: Record<Severity, number> };
}

/** `doorman status --json` from inside, read leniently. */
function readStatus(json: string): Pick<SandboxReport, "guard" | "answering" | "exposures"> & { version?: string } {
  const raw: unknown = JSON.parse(json);
  if (!raw || typeof raw !== "object") throw new Error("not a status");
  const strings = (v: unknown): string[] => (Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : []);
  const out: Pick<SandboxReport, "guard" | "answering" | "exposures"> & { version?: string } = {};
  if ("cli" in raw && raw.cli && typeof raw.cli === "object" && "version" in raw.cli && typeof raw.cli.version === "string") out.version = raw.cli.version;
  if ("guard" in raw && raw.guard && typeof raw.guard === "object") {
    const g = raw.guard;
    out.guard = { installed: strings("installed" in g ? g.installed : []), not_installed: strings("not_installed" in g ? g.not_installed : []) };
  }
  if ("running" in raw) {
    const r = raw.running;
    if (!r || typeof r !== "object") out.answering = null;
    else {
      const pid = "pid" in r && typeof r.pid === "number" ? r.pid : undefined;
      const by = "stdio" in r && r.stdio === true ? "sbx watch" : "version" in r && typeof r.version === "string" && r.version.startsWith("cli-") ? "watch" : "app";
      out.answering = { by, ...(pid !== undefined ? { pid } : {}) };
    }
  }
  if ("exposures" in raw && raw.exposures && typeof raw.exposures === "object") {
    const e = raw.exposures;
    const open = "open" in e && typeof e.open === "number" ? e.open : 0;
    const sev = new Map(Object.entries("by_severity" in e && e.by_severity && typeof e.by_severity === "object" ? e.by_severity : {}));
    const bySeverity = Object.fromEntries(SEVERITIES.map((k) => [k, typeof sev.get(k) === "number" ? (sev.get(k) as number) : 0])) as Record<Severity, number>;
    out.exposures = { open, by_severity: bySeverity };
  }
  return out;
}

/** One sandbox, asked (when it runs) how its Doorman stands. */
async function report(env: NodeJS.ProcessEnv, sandbox: HostSandbox): Promise<SandboxReport> {
  const base: SandboxReport = { name: sandbox.name, agent: sandbox.agent ?? null, status: sandbox.status, workspaces: sandbox.workspaces, doorman: { installed: null } };
  if (!sandbox.running) return base;
  const r = await sbxRun(env, sandbox.name, ["doorman", "status", "--json"], { timeoutMs: STATUS_TIMEOUT_MS });
  if (r.timedOut) return { ...base, doorman: { installed: true, error: `no answer in ${STATUS_TIMEOUT_MS / 1000}s` } };
  if (r.missing) return { ...base, doorman: { installed: false } };
  try {
    const status = readStatus(r.stdout);
    const { version, ...rest } = status;
    return { ...base, doorman: { installed: true, ...(version ? { version } : {}) }, ...rest };
  } catch {
    return { ...base, doorman: { installed: true, error: firstLine(stripAnsi(r.stderr)).replace(/^doorman:\s*/, "") || `exit ${r.code}` } };
  }
}

const sbxLs: CliCommand = {
  name: "sbx ls",
  summary: "Your Docker Sandboxes, and how Doorman stands in each",
  notes: [
    "Asks each running sandbox's Doorman (`sbx exec <sandbox> doorman status --json`, all at once): its version, whether the guard is on, who answers its held calls, and its open exposures. A stopped sandbox isn't asked: `sbx exec` would start it.",
  ],
  examples: [
    ["doorman sbx ls", "every sandbox, and Doorman in each"],
    ["doorman sbx ls --json", "the same as JSON"],
  ],
  async run(ctx) {
    const sandboxes = await listSandboxes(ctx.io.env);
    const reports = await Promise.all(sandboxes.map((b) => report(ctx.io.env, b)));
    const ui = ctx.ui;
    const s = ctx.style;
    const data = { sandboxes: reports };
    if (reports.length === 0) return { data, text: [ui.mark("off", "No sandboxes."), "", ui.next(`Start one with Doorman in it: \`sbx run <agent> <workspace> --kit ${DOORMAN_KIT}\`.`)] };
    const dash = s.dim("—");
    const rows = reports.map((r) => {
      const running = r.doorman.installed !== null;
      const doorman =
        r.doorman.installed === null
          ? dash
          : r.doorman.installed === false
            ? ui.mark("warn", s.warn("not installed"))
            : r.doorman.error
              ? ui.mark("warn", s.warn(r.doorman.error))
              : (r.doorman.version ?? "?");
      const g = r.guard;
      const guard = !g
        ? dash
        : g.installed.length === 0
          ? ui.mark("warn", s.warn("off"))
          : g.not_installed.length > 0
            ? ui.mark("warn", s.warn(`on in ${g.installed.length} of ${g.installed.length + g.not_installed.length}`))
            : ui.mark("ok", s.ok("on"));
      const answers =
        r.answering === undefined
          ? dash
          : r.answering === null
            ? s.dim("nobody")
            : r.answering.by === "sbx watch"
              ? "sbx watch (here)"
              : r.answering.by === "watch"
                ? "doorman watch"
                : "Doorman";
      const e = r.exposures;
      const counts = e ? SEVERITIES.filter((k) => e.by_severity[k] > 0).map((k) => `${e.by_severity[k]} ${k}`) : [];
      const exposures = !e ? dash : e.open === 0 ? s.ok("none") : ui.paint(e.by_severity.critical + e.by_severity.high > 0 ? "error" : "warn", `${e.open}${counts.length > 0 ? `  ${s.dim(`(${counts.join(", ")})`)}` : ""}`);
      return [s.bold(r.name), r.agent ?? dash, running ? s.ok(r.status) : s.dim(r.status), doorman, guard, answers, exposures];
    });
    const text = ui.table(["Sandbox", "Agent", "Status", "Doorman", "Guard", "Answers", "Exposures"], rows, { keep: [0, 2] });
    const missing = reports.find((r) => r.doorman.installed === false);
    const exposed = reports.find((r) => (r.exposures?.open ?? 0) > 0);
    const unanswered = reports.filter((r) => r.answering === null && (r.guard?.installed.length ?? 0) > 0);
    let next: string | undefined;
    if (missing) next = `${missing.name} has no Doorman. ${installKitHint({ name: missing.name, ...(missing.agent ? { agent: missing.agent } : {}) })}`;
    else if (exposed) next = `Review ${exposed.name}'s exposures: \`sbx exec ${exposed.name} doorman findings\`, or bring them here with \`doorman sbx pull\`.`;
    else if (unanswered.length > 0) next = `Nobody answers held calls in ${unanswered.map((r) => r.name).join(", ")}: \`doorman sbx watch\` answers them here.`;
    if (next) text.push("", ui.next(next));
    return { data, text };
  },
};

export const sbxCommands: CliCommand[] = [sbxLs, sbxWatch, sbxPullCommand];
