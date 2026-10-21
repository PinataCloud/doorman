import { maskTurnText } from "../../lib/masking.js";
import { literalForms, normalizeTraceInput, shortFile, type TraceReport, type TraceSighting } from "../../lib/secret-trace.js";
import type { CliCommand } from "../command.js";
import type { CliContext } from "../context.js";
import { CliError, visibleLength } from "../output.js";
import { startProgress } from "../progress.js";
import { plural, type Ui } from "../ui.js";
import { withEngine } from "./data-shared.js";

type RawModeStream = NodeJS.ReadableStream & { isTTY?: boolean; setRawMode?: (on: boolean) => unknown };

/**
 * The value to trace, from stdin and nowhere else: never argv (shell history,
 * `ps`), never echoed. On a terminal it is typed or pasted in raw mode, so
 * nothing appears, and ends at Enter; piped, it is the whole input.
 */
async function readSecret(ctx: CliContext): Promise<string> {
  const io = ctx.io;
  const stdin = io.stdin as RawModeStream;
  if (stdin.isTTY === true && typeof stdin.setRawMode === "function") {
    const s = ctx.errUi.style;
    io.stderr.write(`${s.bold("Paste the value to trace, then press Enter")} ${s.dim("(it won't be shown)")}: `);
    stdin.setRawMode(true);
    stdin.resume();
    try {
      return await new Promise<string>((resolve, reject) => {
        let value = "";
        const onData = (chunk: Buffer | string) => {
          for (const ch of chunk.toString()) {
            if (ch === "\r" || ch === "\n" || ch === "\u0004") {
              stdin.off("data", onData);
              resolve(value);
              return;
            }
            if (ch === "\u0003") {
              stdin.off("data", onData);
              reject(new CliError("Cancelled."));
              return;
            }
            if (ch === "\u007f" || ch === "\b") value = value.slice(0, -1);
            else value += ch;
          }
        };
        stdin.on("data", onData);
      });
    } finally {
      stdin.setRawMode(false);
      stdin.pause();
      io.stderr.write("\n");
    }
  }
  const chunks: Buffer[] = [];
  for await (const chunk of stdin) chunks.push(typeof chunk === "string" ? Buffer.from(chunk) : chunk);
  return Buffer.concat(chunks).toString("utf8");
}

/** Where the value came into an agent's context, as the route names it:
 * your prompt, a file it read, a tool's output. Undefined for what the
 * agent itself said or sent, and for a write echoed back. */
function originOf(s: TraceSighting, home: string): string | undefined {
  if (s.kind === "prompt") return "your prompt";
  if (s.kind !== "tool_output" || !s.how.startsWith("Returned by ")) return undefined;
  const path = s.target !== undefined && /^[/~.]/.test(s.target) ? s.target : undefined;
  return path ? shortFile(path, home) : s.how.slice("Returned by ".length);
}

/** Pieces one space apart, broken between pieces to fit `width` (never
 * inside one); continuation lines hang under the first. */
function flow(pieces: readonly string[], width: number | undefined): string[] {
  const lines: string[] = [];
  let line = "";
  for (const piece of pieces) {
    const next = line ? `${line} ${piece}` : `  ${piece}`;
    if (line && width !== undefined && visibleLength(next) > width) {
      lines.push(line);
      line = `      ${piece}`;
    } else line = next;
  }
  if (line) lines.push(line);
  return lines;
}

/** "a, b, c and 2 more" as pieces, so `flow` may break between names. */
function names(items: readonly string[], cap = 3): string[] {
  const shown = items.slice(0, cap);
  const more = items.length - shown.length;
  return shown.map((n, i) => (i < shown.length - 1 || more > 0 ? `${n},` : n)).concat(more > 0 ? [`and ${more} more`] : []);
}

/** Keys of a count map, most first. */
const byCount = (counts: ReadonlyMap<string, number>) => [...counts.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])).map(([k]) => k);

const bump = (counts: Map<string, number>, key: string) => counts.set(key, (counts.get(key) ?? 0) + 1);

/**
 * The value's route, one chain per agent the report found it with: where it
 * came in ─▶ the agent ─▶ the provider its transcripts reached, then what
 * the agent passed it on to (files it wrote, MCP servers it called). Only
 * steps the report holds; the counts ride on the arrows. `─▶` on a Unicode
 * terminal, `->` anywhere else.
 */
export function traceRoute(ui: Ui, report: TraceReport, home: string): string[] {
  if (report.total === 0 || report.providers.length === 0) return [];
  const s = ui.style;
  const arrow = (label: string) => (ui.term.unicode ? `${s.dim("─")} ${label} ${s.dim("─▶")}` : `- ${label} ->`);
  const sightings = report.places.flatMap((p) => p.sightings);
  const lines: string[] = [];
  for (const rail of report.providers) {
    const mine = sightings.filter((x) => x.source === rail.source);
    const origins = new Map<string, number>();
    const servers = new Map<string, number>();
    for (const x of mine) {
      const from = originOf(x, home);
      if (from) bump(origins, from);
      const mcp = x.kind === "tool_call" && x.tool_name?.startsWith("mcp__") ? x.tool_name.split("__")[1] : undefined;
      if (mcp) bump(servers, `MCP server ${mcp}`);
    }
    const files = new Map<string, number>();
    for (const w of report.writes) {
      if (mine.some((x) => x.kind === "tool_call" && x.session_id === w.session_id && x.turn_id === w.turn_id)) bump(files, shortFile(w.path, home));
    }
    const agent = s.bold(rail.label);
    const came = [...origins.values()].reduce((a, b) => a + b, 0);
    lines.push(
      ...flow(
        [
          ...(came > 0 ? [...names(byCount(origins)), arrow(plural(came, "sighting"))] : []),
          agent,
          arrow(plural(rail.sessions, "session")),
          ui.paint("error", s.bold(rail.provider)),
        ],
        ui.width,
      ),
    );
    const wrote = [...files.values()].reduce((a, b) => a + b, 0);
    if (wrote > 0) lines.push(...flow([agent, arrow(plural(wrote, "write")), ...names(byCount(files).map((n) => ui.paint("warn", n)))], ui.width));
    const called = [...servers.values()].reduce((a, b) => a + b, 0);
    if (called > 0) lines.push(...flow([agent, arrow(plural(called, "call")), ...names(byCount(servers).map((n) => ui.paint("warn", n)))], ui.width));
  }
  return lines;
}

export const traceCommand: CliCommand = {
  name: "trace",
  summary: "Trace a secret: where a value went across every transcript (read from stdin)",
  usage: "(the value on stdin)",
  notes: [
    "Searches every agent transcript and the turn store on this machine for one value and reports where it went: which agents and providers saw it, files written with it, commands that carried it, and what the guard did.",
    "The value is read from stdin only (never an argument), is not shown, and is kept for the length of the search; the report carries its shape (length, last characters, family), not the value.",
    "The text report draws the value's route: where it came in (your prompt, a file an agent read), the agent, and the provider its transcripts reached, with sightings and sessions on the arrows. --json is the report alone.",
  ],
  examples: [
    ["doorman trace", "prompts for the value"],
    ["pbpaste | doorman trace", "reads it from a pipe"],
  ],
  async run(ctx) {
    const normalized = normalizeTraceInput(await readSecret(ctx));
    if (!normalized.ok) throw new CliError(normalized.error);
    return withEngine(ctx, false, async ({ engine }) => {
      const progress = ctx.json ? undefined : startProgress(ctx.errUi, ctx.io.stderr, { label: "Tracing", format: (n) => plural(n, "document") });
      let report: TraceReport;
      try {
        report = await engine.traceSecret(normalized.value, progress ? ({ done, total }) => progress.update(done, total) : undefined);
      } finally {
        progress?.end();
      }
      // A sighting's target is a raw tool argument and could hold the value
      // itself (`KEY=... node`); nothing this prints may, so every literal
      // form of it is cut out of the whole report, Markdown included.
      const forms = literalForms(normalized.value).sort((a, b) => b.length - a.length);
      const scrubbed = forms.reduce((json, form) => json.split(JSON.stringify(form).slice(1, -1)).join("[redacted]"), JSON.stringify(report));
      const safe = JSON.parse(scrubbed) as TraceReport;
      for (const place of safe.places) for (const s of place.sightings) if (s.target !== undefined) s.target = maskTurnText(s.target);
      const text = safe.markdown.replace(/\n$/, "").split("\n");
      // The route goes under the summary's facts, before the file and sighting lists.
      const route = traceRoute(ctx.ui, safe, ctx.io.home);
      if (route.length > 0) {
        const found = text.findIndex((l) => l.startsWith("Found in "));
        const end = text.findIndex((l, i) => i > found && l === "");
        text.splice(end < 0 ? text.length : end, 0, "", "Route:", ...route);
      }
      return { data: safe, text };
    });
  },
};
