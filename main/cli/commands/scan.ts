import { exposureGroups, radarRows } from "../../lib/app-views.js";
import type { CliCommand } from "../command.js";
import { table } from "../output.js";
import { SEVERITIES, cardTitle, oneLine, paintSeverity, ruleLabels, severityLine, withEngine, type Severity } from "./data-shared.js";

export const scanCommand: CliCommand = {
  name: "scan",
  summary: "Read new transcripts now and say what was new",
  details: [
    "Runs the app's own scan over every agent transcript on this machine (Claude Code, Codex and",
    "every other registered source) and reports the turns, sessions and findings it added.",
    "While Doorman is running it owns the store: the scan then reads into a temporary copy, so the",
    "numbers are a preview and the app records the same findings on its own next scan.",
  ],
  async run(ctx) {
    const labels = ruleLabels(ctx);
    return withEngine(ctx, false, async ({ engine, snapshot }) => {
      const beforeFindings = new Set(engine.shownFindings().map((r) => r.finding_id));
      const beforeSessions = new Set(engine.sessions().map((s) => s.id));
      const beforeTurns = engine.turns.size;
      await engine.scan();
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
      const s = ctx.style;
      const text = [
        `${s.bold("Scanned")} ${engine.filesSeen} transcript file${engine.filesSeen === 1 ? "" : "s"}: +${turnsAdded} turn${turnsAdded === 1 ? "" : "s"}, +${sessionsAdded} session${sessionsAdded === 1 ? "" : "s"}`,
        fresh.length === 0
          ? `  ${s.green("No new findings.")}`
          : `  ${fresh.length} new finding${fresh.length === 1 ? "" : "s"} (${newExposures} new exposure${newExposures === 1 ? "" : "s"})  ${s.dim(severityLine(bySeverity))}`,
      ];
      if (groups.length > 0) {
        text.push(
          "",
          ...table(
            ["SEVERITY", "TITLE", "PLACE", "NEW", "ID"],
            groups.map((g) => [paintSeverity(s, g.face.severity), oneLine(cardTitle(g.face, labels), 60), g.face.place, String(g.rows.length), g.face.finding_id]),
          ),
        );
      }
      if (snapshot) text.push("", s.dim("Doorman is running, so this scan read into a temporary copy of its store."));
      return { data, text };
    });
  },
};
