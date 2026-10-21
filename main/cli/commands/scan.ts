import { exposureGroups, exposurePlace, radarRows } from "../../lib/app-views.js";
import type { CliCommand } from "../command.js";
import { plural } from "../ui.js";
import { SEVERITIES, cardTitle, oneLine, paintSeverity, ruleLabels, severityLine, withEngine, type Severity } from "./data-shared.js";

export const scanCommand: CliCommand = {
  name: "scan",
  summary: "Read new transcripts now and say what was new",
  notes: [
    "Runs the app's own scan over every agent transcript on this machine (Claude Code, Codex and every other registered source) and reports the turns, sessions, exposures (a rule at a place, what you review) and sightings (each time it happened) it added. Progress goes to stderr.",
    "While Doorman is running it owns the store: the scan then reads into a temporary copy, so the numbers are a preview and the app records the same sightings on its own next scan.",
  ],
  examples: [
    ["doorman scan", "read new transcripts and list what they exposed"],
    ["doorman scan --json", "the counts and new exposures as JSON"],
  ],
  async run(ctx) {
    const labels = ruleLabels(ctx);
    return withEngine(ctx, false, async ({ engine, snapshot }) => {
      const beforeFindings = new Set(engine.shownFindings().map((r) => r.finding_id));
      const beforeSessions = new Set(engine.sessions().map((s) => s.id));
      const beforeTurns = engine.turns.size;
      await ctx.scan(engine);
      const rows = radarRows(engine.shownFindings(), ctx.io.home);
      const fresh = rows.filter((r) => !beforeFindings.has(r.finding_id));
      const freshKeys = new Set(fresh.map((r) => r.exposure_key));
      const oldKeys = new Set(rows.filter((r) => beforeFindings.has(r.finding_id)).map((r) => r.exposure_key));
      const newExposures = [...freshKeys].filter((k) => !oldKeys.has(k)).length;
      const bySeverity = Object.fromEntries(SEVERITIES.map((s) => [s, fresh.filter((r) => r.severity === s).length])) as Record<Severity, number>;
      const sessionsAdded = engine.sessions().filter((s) => !beforeSessions.has(s.id)).length;
      const turnsAdded = engine.turns.size - beforeTurns;
      const groups = exposureGroups(fresh);
      const data = {
        snapshot,
        files_read: engine.filesSeen,
        turns_added: turnsAdded,
        sessions_added: sessionsAdded,
        new_findings: fresh.length,
        new_exposures: newExposures,
        by_severity: bySeverity,
        findings: groups.map((g) => ({
          id: g.face.finding_id,
          severity: g.face.severity,
          title: cardTitle(g.face, labels),
          place: g.face.place,
          sightings: g.rows.length,
          finding_ids: g.rows.map((r) => r.finding_id),
        })),
      };
      const ui = ctx.ui;
      const s = ctx.style;
      const scanned = `${s.bold("Scanned")} ${plural(engine.filesSeen, "transcript file")}: +${plural(turnsAdded, "turn")}, +${plural(sessionsAdded, "session")}`;
      const text = [
        ui.mark("ok", scanned),
        fresh.length === 0
          ? `  ${ui.mark("ok", s.ok("Nothing new to review."))}`
          : `  ${ui.mark(bySeverity.critical + bySeverity.high > 0 ? "error" : "warn", `${plural(newExposures, "new exposure")}, ${plural(fresh.length, "new sighting")}${newExposures === groups.length ? "" : ` (some on exposures already listed)`}`)}  ${s.dim(severityLine(bySeverity))}`,
      ];
      if (groups.length > 0) {
        text.push(
          "",
          ...ui.table(
            ["SEVERITY", "TITLE", "PLACE", "NEW SIGHTINGS", "ID"],
            groups.map((g) => [paintSeverity(s, g.face.severity), oneLine(cardTitle(g.face, labels)), exposurePlace(g.face), String(g.rows.length), g.face.finding_id]),
            { keep: [0, 4], drop: [3] },
          ),
          "",
          ui.next(`\`doorman findings show ${groups[0]!.face.finding_id}\` shows the first in full.`),
        );
      }
      if (snapshot) text.push("", s.dim("Doorman is running, so this scan read into a temporary copy of its store."));
      return { data, text };
    });
  },
};
