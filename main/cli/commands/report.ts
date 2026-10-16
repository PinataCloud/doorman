import { checkGuardIntegrity, isGuardInstalled } from "../../enforcement.js";
import { detectionsExportFor, ledgerExportFor } from "../../lib/app-views.js";
import { buildSecurityReport, renderSecurityReportMarkdown } from "../../lib/report.js";
import { mcpInventoryNow } from "../../mcp-inventory-now.js";
import { shadowAiNow } from "../../shadow-ai-now.js";
import type { CliCommand } from "../command.js";
import { CliError } from "../output.js";
import { byIdOrPrefix, withEngine, writeOut } from "./data-shared.js";

export const reportCommand: CliCommand = {
  name: "report",
  summary: "The security report the app exports (Markdown)",
  usage: "[--out <file>] [--format md|json] [--scan]",
  options: { out: { type: "string" }, format: { type: "string" }, scan: { type: "boolean", default: false } },
  details: [
    "What Doorman guards on this machine and what it has seen, masked: the report the Analytics",
    "screen exports for a security team. Markdown on stdout; --json prints the report's structure.",
    "--out <file>      write it to a file instead (Markdown, or JSON with --format json or a .json name)",
    "--format md|json  the file's format",
    "--scan            read new transcripts first",
  ],
  async run(ctx, args) {
    const format = args.values.format;
    if (format !== undefined && format !== "md" && format !== "json") throw new CliError("--format takes md or json.", 2);
    const prefs = ctx.prefs();
    const policy = ctx.policy();
    return withEngine(ctx, args.values.scan === true, ({ engine }) => {
      // The inventory sweep mints config findings first, as the app's watcher
      // does before the report ever reads them.
      const { inventory } = mcpInventoryNow(engine, { dataDir: ctx.dataDir, home: ctx.io.home, prefs, policy, log: (m) => ctx.log(m) });
      const report = buildSecurityReport({
        app_version: ctx.io.version,
        generator: "the Doorman CLI",
        generated_at: new Date(ctx.io.now()),
        findings: engine.shownFindings(),
        policy,
        guard_installed: isGuardInstalled(),
        integrity: checkGuardIntegrity(ctx.dataDir, prefs.guard_wanted),
        mcp: inventory,
        shadow_ai: shadowAiNow(ctx.io.home, engine, ctx.io.now()),
        rule_packs_enabled: prefs.rule_packs_enabled ?? [],
      });
      const markdown = renderSecurityReportMarkdown(report);
      const out = args.values.out;
      if (typeof out === "string") {
        const json = format === "json" || (format === undefined && out.toLowerCase().endsWith(".json"));
        const path = writeOut(out, json ? `${JSON.stringify(report, null, 2)}\n` : markdown);
        return { data: { path, format: json ? "json" : "md" }, text: [`Wrote the security report to ${path}`] };
      }
      return { data: report, text: markdown.replace(/\n$/, "").split("\n") };
    });
  },
};

export const exportDetectionsCommand: CliCommand = {
  name: "export detections",
  summary: "Every detection as the schema-valid JSON bundle",
  usage: "[--out <file>] [--scan]",
  options: { out: { type: "string" }, scan: { type: "boolean", default: false } },
  details: [
    "The Analytics screen's detections export (schema urn:doorman:schemas:detections-export.v1).",
    "Masked: fingerprints stand in for values. JSON on stdout, or --out <file>.",
  ],
  async run(ctx, args) {
    const policy = ctx.policy();
    return withEngine(ctx, args.values.scan === true, ({ engine }) => {
      const { bundle, problems } = detectionsExportFor(engine, policy, ctx.io.version, new Date(ctx.io.now()));
      for (const p of problems.slice(0, 5)) ctx.io.stderr.write(`doorman: the export breaks its schema: ${p.path} ${p.message}\n`);
      const out = args.values.out;
      if (typeof out === "string") {
        const path = writeOut(out, `${JSON.stringify(bundle, null, 2)}\n`);
        const count = bundle.detections.length;
        return { data: { path, count, valid: problems.length === 0 }, text: [`Wrote ${count} detection${count === 1 ? "" : "s"} to ${path}`] };
      }
      return { data: bundle, text: JSON.stringify(bundle, null, 2).split("\n") };
    });
  },
};

export const exportLedgerCommand: CliCommand = {
  name: "export ledger",
  summary: "The Event Ledger (every session, or one) as the schema-valid JSON bundle",
  usage: "[--session <id>] [--out <file>] [--scan]",
  options: { session: { type: "string" }, out: { type: "string" }, scan: { type: "boolean", default: false } },
  details: [
    "The Ledger's export (schema urn:doorman:schemas:ledger-export.v1): sessions with their turns,",
    "text masked. JSON on stdout, or --out <file>.",
    "--session <id>  one session (id or unique prefix)",
  ],
  async run(ctx, args) {
    return withEngine(ctx, args.values.scan === true, ({ engine }) => {
      const wanted = args.values.session;
      const sessionId = typeof wanted === "string" ? byIdOrPrefix(engine.sessions(), wanted, (s) => s.id, "session").id : undefined;
      const built = ledgerExportFor(engine, sessionId, ctx.io.version, new Date(ctx.io.now()));
      if (!built) throw new CliError("No sessions to export.");
      const { bundle, problems } = built;
      for (const p of problems.slice(0, 5)) ctx.io.stderr.write(`doorman: the export breaks its schema: ${p.path} ${p.message}\n`);
      const out = args.values.out;
      if (typeof out === "string") {
        const path = writeOut(out, `${JSON.stringify(bundle, null, 2)}\n`);
        const count = bundle.sessions.length;
        return { data: { path, count, valid: problems.length === 0 }, text: [`Wrote ${count} session${count === 1 ? "" : "s"} to ${path}`] };
      }
      return { data: bundle, text: JSON.stringify(bundle, null, 2).split("\n") };
    });
  },
};
