import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { foldObservedTools, mergeGatewayCalls, readGatewayCalls, routeServer, scanObservedTools, unrouteServer, type GatewayCallRecord } from "../../gateway-install.js";
import { ruleShown } from "../../guard/rule-scope.js";
import { serverScopes } from "../../lib/gateway-config.js";
import { discoveredMcpConfig } from "../../lib/mcp-inventory.js";
import { discoverMcpServers, engineCwds } from "../../mcp-inventory-now.js";
import type { CliCommand, ParsedArgs } from "../command.js";
import type { CliContext } from "../context.js";
import { ago, CliError } from "../output.js";
import { plural } from "../ui.js";
import { homeRelative } from "./mcp.js";

/** The config to rewrite, only if a sweep of the machine's MCP configs found
 * `server` in it: the rule the app's mcp:route-gateway handler applies
 * (lib/mcp-inventory.ts discoveredMcpConfig). With no path given, the one
 * config that declares the server. */
async function configFor(ctx: CliContext, args: ParsedArgs, on: boolean): Promise<{ server: string; configPath: string }> {
  const [first, second] = args.positionals;
  const server = (second ?? first)!;
  const handle = await ctx.openEngine({ scan: false });
  let servers;
  try {
    // Project .mcp.json files count once an agent has run in that project.
    servers = discoverMcpServers({ home: ctx.io.home, knownCwds: engineCwds(handle.engine), onFindings: () => {}, log: (m) => ctx.log(m) });
  } finally {
    handle.close();
  }
  if (second !== undefined) {
    const requested = resolve(first!.replace(/^~(?=$|\/)/, ctx.io.home));
    const configPath = discoveredMcpConfig(servers, server, requested);
    if (configPath === undefined) {
      throw new CliError(`No MCP server "${server}" in ${homeRelative(requested, ctx.io.home)}.`, 1, "`doorman mcp` shows where each server is configured.");
    }
    return { server, configPath };
  }
  const paths = [...new Set(servers.filter((s) => s.name === server).map((s) => s.config_path))];
  if (paths.length === 0) throw new CliError(`No MCP config on this machine declares "${server}".`, 1, "`doorman mcp` lists the servers.");
  if (paths.length > 1) {
    const where = paths.map((p) => homeRelative(p, ctx.io.home));
    throw new CliError(
      `"${server}" is configured in ${paths.length} files: ${where.join(", ")}.`,
      1,
      `Name one: \`doorman gateway ${on ? "route" : "unroute"} ${where[0]} ${server}\``,
    );
  }
  return { server, configPath: paths[0]! };
}

/**
 * Which declaration of `server` in `configPath` to change: ~/.claude.json can
 * declare one name at the top level and again per project. `--project <dir>`
 * names the project; without it the top-level entry is meant (or the only
 * one), and the other declarations are returned so the summary can say so.
 */
function projectFor(ctx: CliContext, args: ParsedArgs, configPath: string, server: string, on: boolean): { project?: string; others: string[] } {
  let scopes: string[];
  try {
    scopes = serverScopes(readFileSync(configPath, "utf8"), configPath, server);
  } catch {
    scopes = [];
  }
  const where = homeRelative(configPath, ctx.io.home);
  const requested = args.values.project;
  if (typeof requested === "string") {
    const wanted = resolve(requested.replace(/^~(?=$|\/)/, ctx.io.home));
    const project = scopes.find((s) => s !== "" && (s === requested || resolve(s) === wanted));
    if (project === undefined) {
      const declared = scopes.filter((s) => s !== "");
      throw new CliError(
        `"${server}" isn't declared for the project ${requested} in ${where}.`,
        1,
        declared.length > 0 ? `It is declared for: ${declared.join(", ")}.` : "It is declared at the top level only: leave out --project.",
      );
    }
    return { project, others: scopes.filter((s) => s !== project) };
  }
  if (scopes.length > 1 && !scopes.includes("")) {
    throw new CliError(
      `"${server}" is declared for ${scopes.length} projects in ${where}: ${scopes.join(", ")}.`,
      1,
      `Name one: \`doorman gateway ${on ? "route" : "unroute"} ${where} ${server} --project ${scopes[0]}\``,
    );
  }
  return { others: scopes.length > 1 ? scopes.filter((s) => s !== "") : [] };
}

function routeRun(on: boolean): CliCommand["run"] {
  return async (ctx, args) => {
    ctx.requireWritable(`${on ? "Route" : "Unroute"} the server`, { scope: "config" });
    const { server, configPath } = await configFor(ctx, args, on);
    const { project, others } = projectFor(ctx, args, configPath, server, on);
    const outcome = on ? routeServer(ctx.dataDir, configPath, server, project) : unrouteServer(configPath, server, project);
    if (!outcome.ok) throw new CliError(`Couldn't ${on ? "route" : "unroute"} ${server}: ${outcome.error}`);
    const where = `${homeRelative(configPath, ctx.io.home)}${project ? ` (project ${project})` : ""}`;
    const name = ctx.style.bold(server);
    const text = outcome.changed
      ? [
          ctx.ui.mark(
            "ok",
            on
              ? `${name} in ${where} now runs through Doorman's gateway, which records the tools it advertises and the calls it answers.`
              : `${name} in ${where} runs directly again.`,
          ),
          ctx.ui.next("Restart the agent to pick it up."),
        ]
      : [ctx.ui.mark("off", `${name} in ${where} was already ${on ? "routed through the gateway" : "running directly"}.`)];
    if (others.length > 0) {
      text.push(ctx.ui.next(`It is also declared for ${others.join(", ")}: add \`--project <dir>\` to ${on ? "route" : "unroute"} that one.`));
    }
    return { data: { server, config_path: configPath, ...(project ? { project } : {}), routed: on, changed: outcome.changed }, text };
  };
}

const PROJECT_OPTION = { project: { type: "string" } } as const;
const PROJECT_FLAG = ["--project <dir>", "the declaration for that project in ~/.claude.json (default: the top-level one)"] as const;

const routeCommand: CliCommand = {
  name: "gateway route",
  summary: "Run a local MCP server through Doorman's gateway (records the tools it advertises and the calls it answers)",
  usage: "[<config-path>] <server> [--project <dir>]",
  positionals: { min: 1, max: 2 },
  options: PROJECT_OPTION,
  flags: [PROJECT_FLAG],
  notes: [
    "The config must be one Doorman reads (see `doorman mcp`). Without a path, the server must be configured in exactly one file. The edit changes only that server's entry; the file as it was before Doorman's first edit is kept beside it (.doorman.bak).",
  ],
  examples: [
    ["doorman gateway route notes", "the one config that declares notes"],
    ["doorman gateway route ~/.cursor/mcp.json notes", "notes in Cursor's config"],
    ["doorman gateway route ~/.claude.json notes --project ~/src/app", "the notes declared for one project"],
  ],
  run: routeRun(true),
};

const unrouteCommand: CliCommand = {
  name: "gateway unroute",
  summary: "Restore an MCP server's original command, bypassing the gateway",
  usage: "[<config-path>] <server> [--project <dir>]",
  positionals: { min: 1, max: 2 },
  options: PROJECT_OPTION,
  flags: [PROJECT_FLAG],
  examples: [["doorman gateway unroute ~/.cursor/mcp.json notes", "notes runs its own command again"]],
  run: routeRun(false),
};

/** How a held call ended, in words. */
const HOLD_ENDING: Record<string, string> = {
  allowed: "allowed",
  denied: "denied",
  unattended: "nobody to ask, forwarded",
  unavailable: "nobody to ask, refused",
  cancelled: "cancelled by the agent",
  client_timeout: "the agent stopped waiting",
  client_gone: "the agent disconnected",
  upstream_gone: "the server exited",
};

function outcomeText(ctx: CliContext, call: GatewayCallRecord): string {
  const s = ctx.style;
  const ui = ctx.ui;
  const result = call.oversized ? "result too large to record" : call.is_error ? "error" : call.result_chars !== undefined ? "ok" : undefined;
  if (call.blocked) return ui.mark("error", s.error(`blocked${call.reason ? `: ${call.reason}` : ""}`));
  if (call.batch_refused) return ui.mark("error", s.error("refused: held inside a batch"));
  if (call.injection && call.injection.length > 0) return ui.mark("error", s.error(`injection: ${call.injection.join(", ")}`));
  if (call.hold_error) {
    return ui.mark("error", s.error(`the hold failed, ${call.forwarded ? `forwarded${result ? ` → ${result}` : ""}` : "refused"}`));
  }
  if (call.unattended) {
    return call.forwarded
      ? ui.mark("warn", s.warn(`nobody to ask, forwarded${result ? ` → ${result}` : ""}`))
      : ui.mark("error", s.error("refused: Doorman wasn't running to ask"));
  }
  if (call.held) {
    const seconds = call.hold_ms === undefined ? "" : ` ${Math.round(call.hold_ms / 1000)}s`;
    const ending =
      call.resolution === "timeout"
        ? `timed out${call.hold_seconds ? ` after ${call.hold_seconds}s` : ""}, ${call.forwarded ? "forwarded" : "refused"}`
        : `${HOLD_ENDING[call.resolution ?? ""] ?? (call.forwarded ? "allowed" : "refused")}${call.decided_via && call.resolution !== "timeout" && call.decided_via !== "app-absent" ? ` in the ${call.decided_via}` : ""}`;
    const text = `held${call.resolution === "timeout" ? "" : seconds}, ${ending}${call.forwarded && result ? ` → ${result}` : ""}`;
    return call.forwarded ? ui.mark("held", s.warn(text)) : ui.mark("error", s.error(text));
  }
  if (call.oversized) return ui.mark("ok", s.dim("ok (result too large to record)"));
  if (call.is_error) return ui.mark("warn", s.warn("error"));
  return ui.mark("ok", s.dim("ok"));
}

const callsCommand: CliCommand = {
  name: "gateway calls",
  summary: "Recent tool calls that went through the gateway, newest first",
  usage: "[--limit 20]",
  options: { limit: { type: "string", default: "20" } },
  flags: [["--limit <n>", "show at most n calls (default 20)"]],
  examples: [["doorman gateway calls --limit 5", "the five newest calls"]],
  async run(ctx, args) {
    const limit = Number(args.values.limit);
    if (!Number.isInteger(limit) || limit < 1) throw new CliError("--limit takes a positive whole number.", 2);
    const calls = mergeGatewayCalls(readGatewayCalls(ctx.dataDir))
      .map((call, index) => ({ call, index }))
      .sort((a, b) => (b.call.at ?? "").localeCompare(a.call.at ?? "") || b.index - a.index)
      .slice(0, limit)
      .map((entry) => entry.call);
    if (calls.length === 0) {
      return {
        data: [],
        text: ["No calls have gone through the gateway yet.", ctx.ui.next("`doorman gateway route <server>` sends a server's calls through it.")],
      };
    }
    const now = ctx.io.now();
    return {
      data: calls,
      text: [
        ctx.ui.section("Gateway calls", `${plural(calls.length, "call")}, newest first`),
        "",
        ...ctx.ui.table(
          ["WHEN", "SERVER", "TOOL", "CLASS", "OUTCOME"],
          calls.map((c) => [c.at ? ago(c.at, now) : "", c.server ?? "", c.tool ?? "", c.cls ?? "", outcomeText(ctx, c)]),
          { indent: 2, keep: [0, 3] },
        ),
      ],
    };
  },
};

const observedCommand: CliCommand = {
  name: "gateway observed",
  summary: "Tools the gateway has seen servers advertise",
  async run(ctx) {
    const s = ctx.style;
    // A description that changed is the `mcp_tool_changed` rule's evidence,
    // and a sighting is a rule's finding: both follow guard/rule-scope.ts,
    // which hides the MCP family today — then the tools are listed, and
    // nothing names or counts what a hidden rule saw.
    const changesShown = ruleShown("mcp_tool_changed");
    const observed = [...foldObservedTools(ctx.dataDir).values()].sort((a, b) => a.server.localeCompare(b.server) || a.name.localeCompare(b.name));
    const tools = changesShown ? observed : observed.map(({ versions: _v, changed_at: _c, change_note: _n, ...tool }) => tool);
    const findings = scanObservedTools(ctx.dataDir)
      .filter((f) => ruleShown(f.detector))
      // One sighting per finding: each session that listed the tool minted it again.
      .filter((f, i, all) => all.findIndex((g) => g.detector === f.detector && g.key_name === f.key_name) === i)
      .map((f) => ({ detector: f.detector, severity: f.severity, key_name: f.key_name, excerpt: f.excerpt, at: f.last_seen_at }));
    if (tools.length === 0) {
      return {
        data: { tools, findings },
        text: ["The gateway hasn't observed any tools yet.", ctx.ui.next("`doorman gateway route <server>` sends a server's calls through it.")],
      };
    }
    const now = ctx.io.now();
    const text = [
      ctx.ui.section("Observed tools", plural(tools.length, "tool")),
      "",
      ...(changesShown
        ? ctx.ui.table(
            ["SERVER", "TOOL", "CLASS", "VERSIONS", "CHANGED"],
            observed.map((t) => [
              t.server,
              t.name,
              t.cls,
              String(t.versions),
              t.changed_at ? ctx.ui.mark("warn", s.warn(`${ago(t.changed_at, now)}${t.change_note ? `: ${t.change_note}` : ""}`)) : s.dim("never"),
            ]),
            { indent: 2, keep: [2, 3] },
          )
        : ctx.ui.table(
            ["SERVER", "TOOL", "CLASS", "FIRST SEEN"],
            tools.map((t) => [t.server, t.name, t.cls, t.first_seen_at ? ago(t.first_seen_at, now) : ""]),
            { indent: 2, keep: [2, 3] },
          )),
    ];
    if (findings.length > 0) {
      text.push("", ctx.ui.section("Sightings", String(findings.length)));
      for (const f of findings) {
        const high = f.severity === "critical" || f.severity === "high";
        const sev = high ? s.error(f.severity) : f.severity === "medium" ? s.warn(f.severity) : s.dim(f.severity);
        text.push(`  ${ctx.ui.mark(high ? "error" : f.severity === "medium" ? "warn" : "info", sev)}  ${f.detector}  ${f.key_name}`);
      }
    }
    return { data: { tools, findings }, text };
  },
};

export const gatewayCommands: CliCommand[] = [routeCommand, unrouteCommand, callsCommand, observedCommand];
