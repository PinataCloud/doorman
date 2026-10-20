import { readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import type { CaptureEngine } from "../../capture.js";
import { alertsBySession, radarRows } from "../../lib/app-views.js";
import { maskFindingRow, maskTurnText } from "../../lib/masking.js";
import type { LedgerTurn, SessionSummary } from "../../lib/turns.js";
import type { CliCommand } from "../command.js";
import { ago, CliError, compactNumber, localTime } from "../output.js";
import { plural } from "../ui.js";
import { byIdOrPrefix, cardTitle, intOption, oneLine, paintSeverity, ruleLabels, withEngine } from "./data-shared.js";

/** A session as the Ledger lists it, tokens only (the app shows no dollars),
 * its title masked like the ledger export masks it. */
function sessionJson(s: SessionSummary, label: string, alerts: number) {
  return {
    id: s.id,
    source: s.source,
    source_label: label,
    title: s.title === undefined ? null : maskTurnText(s.title),
    started_at: s.started_at,
    ended_at: s.ended_at,
    turns: s.turns + s.prompts,
    prompts: s.prompts,
    input_tokens: s.input_tokens,
    output_tokens: s.output_tokens,
    tokens: s.input_tokens + s.output_tokens,
    models: s.models,
    ...(s.task ? { task: s.task } : {}),
    ...(s.cwd ? { cwd: s.cwd } : {}),
    ...(s.git_branch ? { git_branch: s.git_branch } : {}),
    alerts,
  };
}

/** A stored turn with its text masked by the one rule (lib/masking.ts), the
 * text the ledger bubbles show; never a dollar figure. */
function turnJson(t: LedgerTurn) {
  const masked = typeof t.text === "string" ? maskTurnText(t.text) : undefined;
  return {
    id: t.id,
    session_id: t.session_id,
    source: t.source,
    role: t.role,
    at: t.at,
    ...(t.model ? { model: t.model } : {}),
    ...(t.usage ? { tokens: t.usage.input_tokens + t.usage.output_tokens } : {}),
    ...(t.tools ? { tools: t.tools } : {}),
    ...(masked !== undefined ? { text: masked, ...(masked !== t.text ? { text_redacted: true } : {}) } : {}),
  };
}

function sourceLabels(engine: CaptureEngine): Map<string, string> {
  return new Map(engine.sourceIndex().map((r) => [r.id as string, r.label]));
}

export const sessionsCommand: CliCommand = {
  name: "sessions",
  summary: "Recent agent sessions, newest first",
  usage: "[--days <n>] [--limit <n>] [--source <id>] [--scan]",
  options: {
    days: { type: "string" },
    limit: { type: "string" },
    source: { type: "string" },
    scan: { type: "boolean", default: false },
  },
  flags: [
    ["--days <n>", "sessions active in the last n days"],
    ["--limit <n>", "at most n sessions (default 20, 0 = all)"],
    ["--source <id>", "one agent: claude-code, codex, cursor, ... (id or name)"],
    ["--scan", "read new transcripts first"],
  ],
  notes: ["Newest first. The ID column is what `doorman session` takes; a unique prefix is enough."],
  examples: [
    ["doorman sessions --scan", "read new transcripts, then list sessions"],
    ["doorman sessions --days 1 --source codex", "Codex sessions from the last day"],
  ],
  async run(ctx, args) {
    const v = args.values;
    const limit = intOption(v.limit, "limit", 20);
    const days = v.days === undefined ? undefined : intOption(v.days, "days", 0, 1, 3650);
    const source = typeof v.source === "string" ? v.source.toLowerCase() : undefined;
    return withEngine(ctx, v.scan === true, ({ engine }) => {
      const labels = sourceLabels(engine);
      const alerts = alertsBySession(engine.shownFindings());
      const cutoff = days === undefined ? undefined : new Date(ctx.io.now() - days * 86_400_000).toISOString();
      const matching = engine
        .sessions()
        .filter(
          (s) =>
            (cutoff === undefined || s.ended_at >= cutoff) &&
            (source === undefined || s.source.toLowerCase() === source || (labels.get(s.source) ?? "").toLowerCase() === source),
        );
      const shown = limit === 0 ? matching : matching.slice(0, limit);
      const data = { total: matching.length, sessions: shown.map((s) => sessionJson(s, labels.get(s.source) ?? s.source, alerts.get(s.id) ?? 0)) };
      const st = ctx.style;
      const ui = ctx.ui;
      if (shown.length === 0) {
        const filtered = days !== undefined || source !== undefined;
        return {
          data,
          text: [
            ui.mark("off", "No sessions."),
            ui.next(
              v.scan !== true
                ? "`doorman sessions --scan` reads new transcripts first."
                : filtered
                  ? "`doorman sessions` without --days or --source lists them all."
                  : "`doorman doctor` checks which agents' transcripts Doorman can read.",
            ),
          ],
        };
      }
      const text = ui.table(
        ["LAST ACTIVITY", "SOURCE", "TURNS", "TOKENS", "SIGHTINGS", "TITLE", "ID"],
        shown.map((s) => {
          const n = alerts.get(s.id) ?? 0;
          return [
            ago(s.ended_at, ctx.io.now()),
            labels.get(s.source) ?? s.source,
            String(s.turns + s.prompts),
            compactNumber(s.input_tokens + s.output_tokens),
            n > 0 ? st.warn(String(n)) : st.dim("0"),
            oneLine(s.title === undefined ? "(untitled)" : maskTurnText(s.title)),
            // On a terminal the id's first block is enough for `doorman session`.
            ui.width !== undefined ? s.id.slice(0, 8) : s.id,
          ];
        }),
        { keep: [0, 2, 3, 4, 6], drop: [1, 2] },
      );
      if (shown.length < matching.length) text.push(st.dim(`... ${matching.length - shown.length} more (--limit 0 shows all)`));
      return { data, text };
    });
  },
};

export const sessionCommand: CliCommand = {
  name: "session",
  summary: "One session's turns (masked), with its sightings inline",
  usage: "<session-id> [--limit <n>] [--offset <n>] [--full]",
  positionals: { min: 1, max: 1 },
  options: {
    limit: { type: "string" },
    offset: { type: "string" },
    full: { type: "boolean", default: false },
  },
  flags: [
    ["--limit <n>", "turns per page (default 50)"],
    ["--offset <n>", "skip the first n turns"],
    ["--full", "print each turn's whole text (default: the first 400 characters)"],
  ],
  notes: [
    "Turns oldest first, text masked, times local. A unique prefix of the id is enough: `doorman sessions` lists them.",
    "Doorman keeps each tool call's name, not its input: a turn that only ran tools lists them.",
  ],
  async run(ctx, args) {
    const limit = intOption(args.values.limit, "limit", 50, 1);
    const offset = intOption(args.values.offset, "offset", 0);
    const full = args.values.full === true;
    const ruleNames = ruleLabels(ctx);
    return withEngine(ctx, false, ({ engine }) => {
      const sessions = engine.sessions();
      const summary = byIdOrPrefix(sessions, args.positionals[0]!, (s) => s.id, "session", "doorman sessions --limit 0");
      const labels = sourceLabels(engine);
      const page = engine.sessionTurns(summary.id, offset, limit);
      const rows = radarRows(engine.shownFindings(), ctx.io.home)
        .filter((f) => f.session_id === summary.id)
        .map(maskFindingRow)
        .sort((a, b) => (a.last_seen_at < b.last_seen_at ? -1 : 1));
      const open = rows.filter((f) => f.status === "open").length;
      const data = {
        session: sessionJson(summary, labels.get(summary.source) ?? summary.source, open),
        total_turns: page.total,
        offset,
        turns: page.turns.map(turnJson),
        findings: rows,
      };
      const st = ctx.style;
      const ui = ctx.ui;
      const title = summary.title === undefined ? "(untitled)" : oneLine(maskTurnText(summary.title), ui.width === undefined ? undefined : 100);
      const facts = ui.list(
        [
          labels.get(summary.source) ?? summary.source,
          plural(summary.turns + summary.prompts, "turn"),
          `${compactNumber(summary.input_tokens + summary.output_tokens)} tokens`,
          summary.models[0],
          summary.cwd,
          `${localTime(summary.started_at)} to ${localTime(summary.ended_at)}`,
        ].filter((x): x is string => !!x),
      );
      const text = [ui.section(title), ...(ui.width === undefined ? [facts] : ui.wrap(facts, ui.width)).map(st.dim), st.dim(summary.id)];
      const onPage = new Set(page.turns.map((t) => t.id));
      const findingLine = (f: (typeof rows)[number]) =>
        `    ${ui.mark("warn", st.accent("sighting"))} ${paintSeverity(st, f.severity)} ${cardTitle(f, ruleNames)} ${st.dim(f.finding_id)}`;
      for (const t of page.turns) {
        const tokens = t.usage ? ` · ${compactNumber(t.usage.input_tokens + t.usage.output_tokens)} tokens` : "";
        text.push("", `${st.dim(localTime(t.at, true))}  ${st.bold(t.role)}${st.dim(`${t.model ? ` · ${t.model}` : ""}${tokens}`)}`);
        const body = typeof t.text === "string" ? maskTurnText(t.text) : "";
        const shown = full || body.length <= 400 ? body : `${body.slice(0, 397)}...`;
        for (const line of shown.split("\n")) if (line.trim() !== "") text.push(`  ${line}`);
        // Only the tools' names are stored, not their inputs.
        if (t.tools && t.tools.length > 0) text.push(`  ${st.dim("ran")} ${t.tools.join(", ")}`);
        for (const f of rows) if (f.turn_id === t.id) text.push(findingLine(f));
      }
      if (page.turns.length === 0) text.push("", st.dim(offset > 0 ? `No turns past ${offset}; the session has ${page.total}.` : "No turns stored for this session."));
      const elsewhere = rows.filter((f) => !f.turn_id || !onPage.has(f.turn_id));
      if (elsewhere.length > 0) text.push("", ui.section(`Sightings not on these turns (${elsewhere.length})`), ...elsewhere.map(findingLine));
      const end = offset + page.turns.length;
      if (end < page.total) text.push("", st.dim(`Turns ${offset + 1}-${end} of ${page.total}.`), ui.next(`\`doorman session ${summary.id} --offset ${end}\` shows the next page.`));
      return { data, text };
    });
  },
};

export const searchCommand: CliCommand = {
  name: "search",
  summary: "Search every captured turn (masked)",
  usage: "<query...> [--limit <n>]",
  positionals: { min: 1, max: 50 },
  options: { limit: { type: "string" } },
  flags: [["--limit <n>", "at most n turns (default 20)"]],
  notes: ["Searches what agents and you wrote (prompts and replies, masked), newest first. Tool calls are kept by name only, so their commands and paths aren't searchable."],
  examples: [
    ["doorman search npm publish", "turns that mention npm publish"],
    ["doorman search .env --limit 50", "up to 50 turns that touch .env"],
  ],
  async run(ctx, args) {
    const query = args.positionals.join(" ").trim();
    if (query === "") throw new CliError("Give something to search for.", 2, "`doorman search npm publish`, for example.");
    const limit = intOption(args.values.limit, "limit", 20, 1, 500);
    return withEngine(ctx, false, ({ engine }) => {
      const labels = sourceLabels(engine);
      const hits = engine.search(query, limit).map(turnJson);
      const data = { query, turns: hits };
      const st = ctx.style;
      const ui = ctx.ui;
      if (hits.length === 0) {
        const lines = [ui.mark("off", `Nothing matches "${query}".`)];
        if (transcriptsChangedSinceScan(join(ctx.dataDir, "store"))) lines.push(ui.next("`doorman scan` reads new transcripts, then search again."));
        return { data, text: lines };
      }
      const needle = query.toLowerCase().split(/\s+/)[0] ?? "";
      const text: string[] = [];
      for (const t of hits) {
        const body = t.text ?? "";
        const at = Math.max(0, body.toLowerCase().indexOf(needle));
        const start = Math.max(0, at - 60);
        const snippet = `${start > 0 ? "..." : ""}${oneLine(body.slice(start, start + 200), 200)}`;
        text.push(
          ui.fit(`${st.dim(localTime(t.at))}  ${labels.get(t.source) ?? t.source}  ${t.role}  ${st.dim(t.session_id)}`),
          `  ${snippet}`,
        );
      }
      return { data, text };
    });
  },
};

/** Whether a transcript the last scan read has changed since (or nothing was
 * scanned yet): the scan's cursors record each file's size and mtime. */
function transcriptsChangedSinceScan(storeDir: string): boolean {
  let cursors: Record<string, { size?: number; mtimeMs?: number }>;
  try {
    cursors = JSON.parse(readFileSync(join(storeDir, "cursors.json"), "utf8")) as typeof cursors;
  } catch {
    return true;
  }
  for (const [path, cursor] of Object.entries(cursors)) {
    try {
      const st = statSync(path);
      if (st.size !== cursor.size || st.mtimeMs !== cursor.mtimeMs) return true;
    } catch {
      // A transcript removed since: nothing new to read from it.
    }
  }
  return false;
}
