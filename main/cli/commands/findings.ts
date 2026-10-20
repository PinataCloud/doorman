import { exposureGroups, radarFeedRows, radarRows, type ExposureGroup, type FindingOutcome, type RadarRow } from "../../lib/app-views.js";
import { DETECTOR_GUIDANCE } from "../../lib/ai-guidance.js";
import { confidenceOf, SEVERITY_RANK, type FindingStatus } from "../../lib/findings.js";
import { maskFindingRow, maskTurnText } from "../../lib/masking.js";
import { hiddenConfidenceBands } from "../../state.js";
import type { CliCommand } from "../command.js";
import { ago, CliError } from "../output.js";
import { plural, type KvRow } from "../ui.js";
import {
  SEVERITIES,
  byIdOrPrefix,
  cardTitle,
  intOption,
  oneLine,
  paintSeverity,
  plain,
  ruleLabel,
  ruleLabels,
  severityLine,
  withEngine,
  type Severity,
} from "./data-shared.js";

/** The Action pill's words (renderer/screens/radar.jsx OUTCOME_WORDS). */
const OUTCOME_WORDS: Record<FindingOutcome | "mixed", string> = {
  blocked: "Blocked",
  held: "Held",
  warned: "Warned",
  excepted: "Excepted",
  observed: "Observed",
  mixed: "Mixed",
};

/** How a held call ended (renderer/components.jsx RESOLUTION_LABELS). */
const RESOLUTION_WORDS: Record<string, string> = {
  allowed: "you allowed it",
  denied: "you denied it",
  timeout: "nobody answered, denied",
  unattended: "app was closed, the agent's own fallback applied",
  unavailable: "app was closed, denied, not run",
};

/** The triage verdicts as the Radar names them. */
const STATUS_WORDS: Record<FindingStatus, string> = {
  open: "open",
  resolved: "reviewed",
  false_positive: "false positive",
  accepted_risk: "accepted risk",
};

/** The card's three lines (radar.jsx ExposureStory): the account's story,
 * consequence and next step, else the rule's guidance; when every call was
 * stopped, the consequence and the step say there is nothing to undo. */
function story(row: RadarRow, ran: boolean): { what: string; next: string } {
  const account = row.account;
  const guidance = DETECTOR_GUIDANCE[row.detector];
  const told = account ? account.sentence : (guidance?.blurb ?? "");
  const so = !ran ? "Nothing left this machine: the call was stopped before it ran, so there is nothing to undo." : (account?.so ?? "");
  const next = !ran
    ? "Nothing to clean up. Mark it reviewed, or loosen the rule if this should have been allowed."
    : account
      ? account.next
      : (guidance?.fix ?? "");
  return { what: plain([told, so].filter(Boolean).join(" ")), next: plain(next) };
}

function exposureJson(g: ExposureGroup<RadarRow>, labels: Record<string, string>) {
  return {
    id: g.face.finding_id,
    severity: g.face.severity,
    title: cardTitle(g.face, labels),
    rule: g.face.detector,
    rule_label: ruleLabel(g.face, labels),
    place: g.face.place,
    place_kind: g.face.place_kind,
    status: g.bucket === "open" ? "open" : g.face.status,
    outcome: g.outcome,
    sightings: g.rows.length,
    things: g.things,
    sessions: g.sessions,
    first_seen_at: g.earliest,
    last_seen_at: g.latest,
    finding_ids: g.rows.map((r) => r.finding_id),
  };
}

export const findingsCommand: CliCommand = {
  name: "findings",
  summary: "Open exposures, grouped like the Radar",
  usage: "[--all] [--severity <min>] [--rule <id>] [--session <id>] [--limit <n>] [--scan]",
  options: {
    all: { type: "boolean", default: false },
    severity: { type: "string" },
    rule: { type: "string" },
    session: { type: "string" },
    limit: { type: "string" },
    scan: { type: "boolean", default: false },
  },
  flags: [
    ["--all", "include reviewed exposures (and their verdict)"],
    ["--severity <min>", "critical, high, medium or low: that severity and worse"],
    ["--rule <id>", "one rule, by id (secret_file_read) or name"],
    ["--session <id>", "findings from one session (id or prefix)"],
    ["--limit <n>", "at most n exposures (default 25, 0 = all)"],
    ["--scan", "read new transcripts first"],
  ],
  notes: [
    "One row per exposure (rule x place), worst first, as the Radar's cards. Rows in confidence bands the Radar hides, and false positives unless you show them there, are left out here too.",
    "So are findings whose transcript is gone or no longer holds them, as of the last scan (the app's, or `--scan`).",
    "The ID column is the card's newest worst finding: pass it to `doorman findings show`.",
  ],
  examples: [
    ["doorman findings --scan", "read new transcripts, then list open exposures"],
    ["doorman findings --severity high", "high and critical exposures"],
    ["doorman findings --all --limit 0", "every exposure, reviewed ones too"],
  ],
  async run(ctx, args) {
    const v = args.values;
    const limit = intOption(v.limit, "limit", 25);
    const minSeverity = typeof v.severity === "string" ? v.severity.toLowerCase() : undefined;
    if (minSeverity !== undefined && !SEVERITIES.includes(minSeverity as Severity)) {
      throw new CliError("--severity takes critical, high, medium or low.", 2);
    }
    const prefs = ctx.prefs();
    const labels = ruleLabels(ctx);
    const hiddenBands = hiddenConfidenceBands(prefs);
    return withEngine(ctx, v.scan === true, ({ engine }) => {
      const all = radarRows(engine.shownFindings(), ctx.io.home);
      const feed = radarFeedRows(all, { hiddenBands, showFalsePositives: prefs.show_false_positives === true });
      const rule = typeof v.rule === "string" ? v.rule.toLowerCase() : undefined;
      const session = typeof v.session === "string" ? v.session : undefined;
      const rows = feed.filter(
        (r) =>
          (v.all === true || r.status === "open") &&
          (rule === undefined || r.detector.toLowerCase() === rule || ruleLabel(r, labels).toLowerCase() === rule) &&
          (session === undefined || (r.session_id?.startsWith(session) ?? false)),
      );
      const groups = exposureGroups(rows).filter(
        (g) => minSeverity === undefined || SEVERITY_RANK[g.face.severity] >= SEVERITY_RANK[minSeverity as Severity],
      );
      const shown = limit === 0 ? groups : groups.slice(0, limit);
      const open = groups.filter((g) => g.bucket === "open");
      const bySeverity = Object.fromEntries(SEVERITIES.map((s) => [s, open.filter((g) => g.face.severity === s).length])) as Record<Severity, number>;
      const hiddenRows = all.length - feed.length;
      const data = {
        open_exposures: open.length,
        by_severity: bySeverity,
        total: groups.length,
        hidden_confidence: hiddenBands,
        hidden_rows: hiddenRows,
        exposures: shown.map((g) => exposureJson(g, labels)),
      };
      const s = ctx.style;
      const ui = ctx.ui;
      const text: string[] = [
        open.length === 0
          ? ui.mark("ok", s.ok("No open exposures."))
          : `${s.bold(String(open.length))} open exposure${open.length === 1 ? "" : "s"}  ${s.dim(severityLine(bySeverity))}`,
      ];
      if (shown.length === 0) {
        const filtered = minSeverity !== undefined || rule !== undefined || session !== undefined;
        text.push(
          ui.next(
            v.scan !== true
              ? "`doorman findings --scan` reads new transcripts first."
              : filtered
                ? "Without --severity, --rule or --session, `doorman findings --all` lists every exposure."
                : v.all !== true
                  ? "`doorman findings --all` lists reviewed exposures too."
                  : "`doorman sessions` lists the sessions read so far.",
          ),
        );
      } else {
        const header = ["SEVERITY", "TITLE", "PLACE", "SIGHTINGS", "LAST SEEN", ...(v.all === true ? ["STATUS"] : []), "ID"];
        text.push(
          "",
          ...ui.table(
            header,
            shown.map((g) => [
              paintSeverity(s, g.face.severity),
              oneLine(cardTitle(g.face, labels), 64),
              oneLine(g.face.place, 32),
              String(g.rows.length),
              ago(g.latest, ctx.io.now()),
              ...(v.all === true ? [g.bucket === "open" ? "open" : STATUS_WORDS[g.face.status]] : []),
              g.face.finding_id,
            ]),
            { keep: [0, 3, 4, header.length - 1] },
          ),
        );
      }
      if (shown.length < groups.length) text.push(s.dim(`... ${groups.length - shown.length} more (--limit 0 shows all)`));
      if (hiddenRows > 0) {
        const why = [
          hiddenBands.length > 0 ? `${hiddenBands.join("/")} confidence` : "",
          prefs.show_false_positives === true ? "" : "false positives",
        ].filter(Boolean);
        text.push(s.dim(`${plural(hiddenRows, "finding")} hidden like on the Radar (${why.join(", ")}).`));
      }
      return { data, text };
    });
  },
};

export const findingsShowCommand: CliCommand = {
  name: "findings show",
  summary: "One finding in full, as its Radar card reads",
  usage: "<finding-id> [--reveal]",
  positionals: { min: 1, max: 1 },
  options: { reveal: { type: "boolean", default: false } },
  flags: [["--reveal", "re-read the evidence around it from the transcript (masked: secret values never print)"]],
  notes: [
    "What happened, what the guard did, where, and what to do next, plus the finding's own record. A unique prefix of the id is enough: `doorman findings` lists them.",
  ],
  async run(ctx, args) {
    const labels = ruleLabels(ctx);
    return withEngine(ctx, false, ({ engine }) => {
      const all = radarRows(engine.shownFindings(), ctx.io.home);
      const row = byIdOrPrefix(all, args.positionals[0]!, (r) => r.finding_id, "finding", "doorman findings --all");
      const bucket = row.status === "open" ? "open" : "triaged";
      const group = exposureGroups(all.filter((r) => r.exposure_key === row.exposure_key && (r.status === "open" ? "open" : "triaged") === bucket))[0]!;
      const masked = maskFindingRow(row);
      const { what, next } = story(masked, group.ran);
      const sources = [...new Set(group.rows.map((r) => r.source))];
      const where = `${group.rows.length} sighting${group.rows.length === 1 ? "" : "s"}${group.sessions > 0 ? ` · ${group.sessions} session${group.sessions === 1 ? "" : "s"}` : ""} in ${row.place}`;
      let reveal: Record<string, unknown> | undefined;
      if (args.values.reveal === true) {
        const result = engine.revealFinding(row.finding_id);
        reveal = result.ok
          ? {
              ok: true,
              source: result.evidence_source ?? null,
              at: result.at,
              ...(result.tool_name ? { tool_name: result.tool_name } : {}),
              ...(result.target ? { target: maskTurnText(result.target) } : {}),
              truncated: result.truncated,
              text: maskTurnText(result.raw),
              redacted: result.secrets.map((x) => x.label || "secret"),
            }
          : { ok: false, error: result.error };
      }
      const data = {
        finding: masked,
        title: cardTitle(masked, labels),
        rule_label: ruleLabel(row, labels),
        what,
        action: OUTCOME_WORDS[group.outcome],
        where,
        do_next: next,
        exposure: exposureJson(group, labels),
        ...(reveal ? { reveal } : {}),
      };
      const s = ctx.style;
      const ui = ctx.ui;
      const field = (k: string, val: string | undefined): KvRow => (val ? [k, val] : false);
      const text = [
        `${paintSeverity(s, row.severity)}  ${ui.section(plain(cardTitle(masked, labels)))}`,
        s.dim(ui.list([ruleLabel(row, labels), row.place, ...sources])),
        "",
        ...ui.kv([field("What", what), field("Action", OUTCOME_WORDS[group.outcome]), field("Where", where), field("Do next", next)]),
        "",
        ...ui.kv([
          field("Status", STATUS_WORDS[row.status]),
          field("Confidence", confidenceOf(row)),
          field("Seen", `${row.first_seen_at === row.last_seen_at ? row.last_seen_at : `${row.first_seen_at} to ${row.last_seen_at}`} (${row.occurrences}x)`),
          field("Session", row.session_id),
          field("Tool", row.tool_name),
          field("Target", masked.target ? oneLine(masked.target, 120) : undefined),
          field("Held", row.resolution ? RESOLUTION_WORDS[row.resolution] : undefined),
          field("Excerpt", oneLine(masked.excerpt, 200)),
          field("ID", row.finding_id),
        ]),
      ];
      if (reveal) {
        text.push("");
        if (reveal.ok === true) {
          text.push(
            ui.section("Evidence", `${String(reveal.source ?? "transcript")}, masked`),
            ...String(reveal.text)
              .split("\n")
              .map((l) => `  ${l}`),
          );
          if (reveal.truncated === true) text.push(s.dim("  (cut to the window around the finding)"));
        } else {
          text.push(ui.mark("warn", s.warn(`Couldn't reveal the evidence: ${String(reveal.error)}`)));
        }
      } else if (row.status === "open") {
        text.push("", ui.next(`\`doorman findings review ${row.finding_id}\` marks it reviewed once handled.`));
      }
      return { data, text };
    });
  },
};

/** `findings review|reopen|false-positive|accept-risk <id...>`: the Radar's
 * triage buttons. Like a card's button, each id marks its whole exposure
 * (every row on that card) unless --only. */
function statusCommand(word: string, status: FindingStatus, summary: string): CliCommand {
  return {
    name: `findings ${word}`,
    summary,
    usage: "<finding-id...> [--only]",
    positionals: { min: 1, max: 500 },
    options: { only: { type: "boolean", default: false } },
    flags: [["--only", "mark just the findings named"]],
    notes: [
      "Each id marks its whole exposure (every finding on that Radar card), like the card's button. `doorman findings` lists the ids; a unique prefix is enough.",
      "Refuses while Doorman is running: do it in the app then.",
    ],
    async run(ctx, args) {
      ctx.requireWritable(summary);
      return withEngine(ctx, false, ({ engine }) => {
        const all = radarRows(engine.shownFindings(), ctx.io.home);
        const ids = new Set<string>();
        for (const id of args.positionals) {
          const row = byIdOrPrefix(all, id, (r) => r.finding_id, "finding", "doorman findings --all");
          if (args.values.only === true) {
            ids.add(row.finding_id);
            continue;
          }
          const bucket = row.status === "open" ? "open" : "triaged";
          for (const r of all) {
            if (r.exposure_key === row.exposure_key && (r.status === "open" ? "open" : "triaged") === bucket) ids.add(r.finding_id);
          }
        }
        const updated = engine.setFindingStatuses([...ids], status);
        const data = { status, updated, finding_ids: [...ids] };
        const text = [
          updated === 0
            ? ctx.ui.mark("off", `Nothing changed: ${ids.size === 1 ? "that finding is" : "those findings are"} already ${STATUS_WORDS[status]}.`)
            : ctx.ui.mark("ok", `${status === "open" ? "Reopened" : "Marked"} ${plural(updated, "finding")}${status === "open" ? "" : ` ${STATUS_WORDS[status]}`}.`),
        ];
        return { data, text };
      });
    },
  };
}

export const findingsStatusCommands: CliCommand[] = [
  statusCommand("review", "resolved", "Mark exposures reviewed"),
  statusCommand("reopen", "open", "Put reviewed exposures back in the queue"),
  statusCommand("false-positive", "false_positive", "Mark exposures as false positives"),
  statusCommand("accept-risk", "accepted_risk", "Mark exposures reviewed as an accepted risk"),
];
