import type { CaptureEngine } from "../../capture.js";
import { alertsBySession, radarRows } from "../../lib/app-views.js";
import { maskFindingRow, maskTurnText } from "../../lib/masking.js";
import type { LedgerTurn, SessionSummary } from "../../lib/turns.js";
import type { CliCommand } from "../command.js";
import { ago, CliError, compactNumber, table } from "../output.js";
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
  summary: "Recent agent sessions, like the Event Ledger",
  usage: "[--days <n>] [--limit <n>] [--source <id>] [--scan]",
  options: {
    days: { type: "string" },
    limit: { type: "string" },
    source: { type: "string" },
    scan: { type: "boolean", default: false },
  },
  details: [
    "--days <n>     sessions active in the last n days",
    "--limit <n>    at most n sessions (default 20, 0 = all)",
    "--source <id>  one agent: claude-code, codex, cursor, ... (id or name)",
    "--scan         read new transcripts first",
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
      if (shown.length === 0) return { data, text: [st.dim("No sessions.")] };
      const text = table(
        ["LAST ACTIVITY", "SOURCE", "TURNS", "TOKENS", "ALERTS", "TITLE", "ID"],
        shown.map((s) => {
          const n = alerts.get(s.id) ?? 0;
          return [
            ago(s.ended_at, ctx.io.now()),
            labels.get(s.source) ?? s.source,
            String(s.turns + s.prompts),
            compactNumber(s.input_tokens + s.output_tokens),
            n > 0 ? st.yellow(String(n)) : st.dim("0"),
            oneLine(s.title === undefined ? "(untitled)" : maskTurnText(s.title), 56),
            s.id,
          ];
        }),
      );
      if (shown.length < matching.length) text.push(st.dim(`... ${matching.length - shown.length} more (--limit 0 shows all)`));
      return { data, text };
    });
  },
};

export const sessionCommand: CliCommand = {
  name: "session",
  summary: "One session's turns (masked), with its findings inline",
  usage: "<session-id> [--limit <n>] [--offset <n>] [--full]",
  positionals: { min: 1, max: 1 },
  options: {
    limit: { type: "string" },
    offset: { type: "string" },
    full: { type: "boolean", default: false },
  },
  details: [
    "Turns oldest first, text masked as the Ledger shows it. A unique prefix of the id is enough.",
    "--limit <n>   turns per page (default 50)",
    "--offset <n>  skip the first n turns",
    "--full        print each turn's whole text (default: the first 400 characters)",
  ],
  async run(ctx, args) {
    const limit = intOption(args.values.limit, "limit", 50, 1);
    const offset = intOption(args.values.offset, "offset", 0);
    const full = args.values.full === true;
    const ruleNames = ruleLabels(ctx);
    return withEngine(ctx, false, ({ engine }) => {
      const sessions = engine.sessions();
      const summary = byIdOrPrefix(sessions, args.positionals[0]!, (s) => s.id, "session");
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
      const title = summary.title === undefined ? "(untitled)" : oneLine(maskTurnText(summary.title), 100);
      const text = [
        st.bold(title),
        st.dim(
          [
            labels.get(summary.source) ?? summary.source,
            `${summary.turns + summary.prompts} turns`,
            `${compactNumber(summary.input_tokens + summary.output_tokens)} tokens`,
            summary.models[0],
            summary.cwd,
            `${summary.started_at} to ${summary.ended_at}`,
          ]
            .filter(Boolean)
            .join(" · "),
        ),
        st.dim(summary.id),
      ];
      const onPage = new Set(page.turns.map((t) => t.id));
      const findingLine = (f: (typeof rows)[number]) =>
        `    ${st.purple("finding")} ${paintSeverity(st, f.severity)} ${cardTitle(f, ruleNames)} ${st.dim(f.finding_id)}`;
      for (const t of page.turns) {
        const tokens = t.usage ? ` · ${compactNumber(t.usage.input_tokens + t.usage.output_tokens)} tokens` : "";
        const tools = t.tools && t.tools.length > 0 ? ` · ${t.tools.join(", ")}` : "";
        text.push("", `${st.dim(t.at.slice(0, 19).replace("T", " "))}  ${st.bold(t.role)}${st.dim(`${t.model ? ` · ${t.model}` : ""}${tokens}${tools}`)}`);
        const body = typeof t.text === "string" ? maskTurnText(t.text) : "";
        const shown = full || body.length <= 400 ? body : `${body.slice(0, 397)}...`;
        for (const line of shown.split("\n")) if (line.trim() !== "") text.push(`  ${line}`);
        for (const f of rows) if (f.turn_id === t.id) text.push(findingLine(f));
      }
      const elsewhere = rows.filter((f) => !f.turn_id || !onPage.has(f.turn_id));
      if (elsewhere.length > 0) text.push("", st.bold(`Findings not on these turns (${elsewhere.length})`), ...elsewhere.map(findingLine));
      const end = offset + page.turns.length;
      if (end < page.total) text.push("", st.dim(`Turns ${offset + 1}-${end} of ${page.total}. Next: --offset ${end}`));
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
  details: ["The Event Ledger's search: newest first, text masked.", "--limit <n>  at most n turns (default 20)"],
  async run(ctx, args) {
    const query = args.positionals.join(" ").trim();
    if (query === "") throw new CliError("Give something to search for.", 2);
    const limit = intOption(args.values.limit, "limit", 20, 1, 500);
    return withEngine(ctx, false, ({ engine }) => {
      const labels = sourceLabels(engine);
      const hits = engine.search(query, limit).map(turnJson);
      const data = { query, turns: hits };
      const st = ctx.style;
      if (hits.length === 0) return { data, text: [st.dim(`Nothing matches "${query}".`)] };
      const needle = query.toLowerCase().split(/\s+/)[0] ?? "";
      const text: string[] = [];
      for (const t of hits) {
        const body = t.text ?? "";
        const at = Math.max(0, body.toLowerCase().indexOf(needle));
        const start = Math.max(0, at - 60);
        const snippet = `${start > 0 ? "..." : ""}${oneLine(body.slice(start, start + 200), 200)}`;
        text.push(
          `${st.dim(t.at.slice(0, 16).replace("T", " "))}  ${labels.get(t.source) ?? t.source}  ${t.role}  ${st.dim(t.session_id)}`,
          `  ${snippet}`,
        );
      }
      return { data, text };
    });
  },
};
