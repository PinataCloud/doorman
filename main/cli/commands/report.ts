import { join } from "node:path";
import { SpoolWatcher, checkGuardIntegrity, isGuardInstalled } from "../../enforcement.js";
import { detectionsExportFor, ledgerExportFor } from "../../lib/app-views.js";
import { buildLedgerExport } from "../../lib/ledger-export.js";
import { maskTurnText } from "../../lib/masking.js";
import { buildSandboxBundle, validateSandboxBundle } from "../../lib/sandbox-import.js";
import { buildSecurityReport, renderSecurityReportMarkdown } from "../../lib/report.js";
import { mcpInventoryNow } from "../../mcp-inventory-now.js";
import { shadowAiNow } from "../../shadow-ai-now.js";
import type { CliCommand } from "../command.js";
import type { CliContext } from "../context.js";
import { CliError } from "../output.js";
import { dockerSandbox } from "../docker-sandbox.js";
import { plural } from "../ui.js";
import { byIdOrPrefix, withEngine, writeOut } from "./data-shared.js";

/** An export's schema problems on stderr, at most five. */
function schemaProblems(ctx: CliContext, problems: readonly { path: string; message: string }[]): void {
  for (const p of problems.slice(0, 5)) {
    ctx.io.stderr.write(`${ctx.errUi.mark("warn", ctx.errUi.style.warn(`doorman: the export breaks its schema: ${p.path} ${p.message}`))}\n`);
  }
}

export const reportCommand: CliCommand = {
  name: "report",
  summary: "The security report the app exports (Markdown)",
  usage: "[--out <file>] [--format md|json] [--scan]",
  options: { out: { type: "string" }, format: { type: "string" }, scan: { type: "boolean", default: false } },
  flags: [
    ["--out <file>", "write it to a file instead (Markdown, or JSON with --format json or a .json name)"],
    ["--format md|json", "the file's format"],
    ["--scan", "read new transcripts first"],
  ],
  notes: [
    "What Doorman guards on this machine and what it has seen, masked: a report to hand a security team (the app exports the same one). Markdown on stdout; --json prints the report's structure.",
  ],
  examples: [
    ["doorman report --scan --out report.md", "read new transcripts, then write the report"],
    ["doorman report --out report.json", "the report's structure as JSON"],
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
        return { data: { path, format: json ? "json" : "md" }, text: [ctx.ui.mark("ok", `Wrote the security report to ${path}`)] };
      }
      return { data: report, text: markdown.replace(/\n$/, "").split("\n") };
    });
  },
};

export const exportDetectionsCommand: CliCommand = {
  name: "export detections",
  summary: "Every sighting as the schema-valid JSON bundle",
  usage: "[--out <file>] [--scan]",
  options: { out: { type: "string" }, scan: { type: "boolean", default: false } },
  flags: [
    ["--out <file>", "write it to a file instead of stdout"],
    ["--scan", "read new transcripts first"],
  ],
  notes: ["Schema urn:doorman:schemas:detections-export.v1, the same bundle the app exports. Masked: fingerprints stand in for values."],
  examples: [["doorman export detections --out detections.json", "write the bundle to a file"]],
  async run(ctx, args) {
    const policy = ctx.policy();
    return withEngine(ctx, args.values.scan === true, ({ engine }) => {
      const { bundle, problems } = detectionsExportFor(engine, policy, ctx.io.version, new Date(ctx.io.now()));
      schemaProblems(ctx, problems);
      const out = args.values.out;
      if (typeof out === "string") {
        const path = writeOut(out, `${JSON.stringify(bundle, null, 2)}\n`);
        const count = bundle.detections.length;
        return { data: { path, count, valid: problems.length === 0 }, text: [ctx.ui.mark("ok", `Wrote ${plural(count, "sighting")} to ${path}`)] };
      }
      return { data: bundle, text: JSON.stringify(bundle, null, 2).split("\n"), raw: true };
    });
  },
};

export const exportLedgerCommand: CliCommand = {
  name: "export ledger",
  summary: "Every session (or one) with its turns, as the schema-valid JSON bundle",
  usage: "[--session <id>] [--out <file>] [--scan]",
  options: { session: { type: "string" }, out: { type: "string" }, scan: { type: "boolean", default: false } },
  flags: [
    ["--session <id>", "one session (id or unique prefix)"],
    ["--out <file>", "write it to a file instead of stdout"],
    ["--scan", "read new transcripts first"],
  ],
  notes: ["Schema urn:doorman:schemas:ledger-export.v1, the same bundle the app exports: sessions with their turns, text masked."],
  examples: [["doorman export ledger --out ledger.json", "every session to a file"]],
  async run(ctx, args) {
    return withEngine(ctx, args.values.scan === true, ({ engine }) => {
      const wanted = args.values.session;
      const sessionId =
        typeof wanted === "string" ? byIdOrPrefix(engine.sessions(), wanted, (s) => s.id, "session", "doorman sessions --limit 0").id : undefined;
      const built = ledgerExportFor(engine, sessionId, ctx.io.version, new Date(ctx.io.now()));
      if (!built) throw new CliError("No sessions to export.", 1, "`doorman export ledger --scan` reads new transcripts first.");
      const { bundle, problems } = built;
      schemaProblems(ctx, problems);
      const out = args.values.out;
      if (typeof out === "string") {
        const path = writeOut(out, `${JSON.stringify(bundle, null, 2)}\n`);
        const count = bundle.sessions.length;
        return { data: { path, count, valid: problems.length === 0 }, text: [ctx.ui.mark("ok", `Wrote ${plural(count, "session")} to ${path}`)] };
      }
      return { data: bundle, text: JSON.stringify(bundle, null, 2).split("\n"), raw: true };
    });
  },
};

export const exportBundleCommand: CliCommand = {
  name: "export bundle",
  summary: "Sightings and sessions in one JSON bundle, for `doorman sbx pull`",
  usage: "[--out <file>] [--scan]",
  options: { out: { type: "string" }, scan: { type: "boolean", default: false } },
  flags: [
    ["--out <file>", "write it to a file instead of stdout"],
    ["--scan", "read new transcripts and the guard's sightings first"],
  ],
  notes: [
    "Schema urn:doorman:schemas:sandbox-bundle.v1: the detections export and the ledger export in one file, naming the Docker Sandbox it was written in. `doorman sbx pull` runs it inside a sandbox from the host and imports the result there. Masked like both: fingerprints stand in for values.",
  ],
  examples: [["sbx exec my-sandbox doorman export bundle --scan", "what `doorman sbx pull my-sandbox` reads"]],
  async run(ctx, args) {
    const policy = ctx.policy();
    const scan = args.values.scan === true;
    return withEngine(ctx, scan, ({ engine, snapshot }) => {
      // Held and refused calls reach the store through the guard's spool,
      // which only the app or `doorman watch` drains. Whoever owns the store
      // has drained it; when that is this command, it does — start() reads the
      // saved offset and drains once, stop() ends the watching it began.
      if (scan && !snapshot) {
        const spool = new SpoolWatcher({
          userDataDir: ctx.dataDir,
          storeDir: join(ctx.dataDir, "store"),
          onLines: (lines) => engine.ingestSpoolLines(lines),
          log: (message) => ctx.log(message),
        });
        spool.start();
        spool.stop();
      }
      const at = new Date(ctx.io.now());
      const detections = detectionsExportFor(engine, policy, ctx.io.version, at).bundle;
      const ledger =
        ledgerExportFor(engine, undefined, ctx.io.version, at)?.bundle ??
        buildLedgerExport({ sessions: [], turnsOf: () => [], detectionIdsOf: () => [], mask: maskTurnText, fingerprintsOf: () => [], app_version: ctx.io.version, generated_at: at });
      const sandbox = dockerSandbox(ctx.io.env);
      const bundle = buildSandboxBundle({
        detections,
        ledger,
        sandbox: sandbox && { name: sandbox.name, ...(ctx.io.env.SANDBOX_ID ? { id: ctx.io.env.SANDBOX_ID } : {}) },
        app_version: ctx.io.version,
        generated_at: at,
      });
      const problems = validateSandboxBundle(bundle);
      schemaProblems(ctx, problems);
      const out = args.values.out;
      if (typeof out === "string") {
        const path = writeOut(out, `${JSON.stringify(bundle, null, 2)}\n`);
        const counts = { sightings: detections.detections.length, sessions: ledger.sessions.length };
        return {
          data: { path, ...counts, valid: problems.length === 0 },
          text: [ctx.ui.mark("ok", `Wrote ${plural(counts.sightings, "sighting")} and ${plural(counts.sessions, "session")} to ${path}`)],
        };
      }
      return { data: bundle, text: [JSON.stringify(bundle)], raw: true };
    });
  },
};
