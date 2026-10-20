import { resolve } from "node:path";
import { foldObservedTools, readGatewayCalls, routeServer, scanObservedTools, unrouteServer, type GatewayCallRecord } from "../../gateway-install.js";
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

function routeRun(on: boolean): CliCommand["run"] {
  return async (ctx, args) => {
    ctx.requireWritable(`${on ? "Route" : "Unroute"} the server`);
    const { server, configPath } = await configFor(ctx, args, on);
    const outcome = on ? routeServer(ctx.dataDir, configPath, server) : unrouteServer(configPath, server);
    if (!outcome.ok) throw new CliError(`Couldn't ${on ? "route" : "unroute"} ${server}: ${outcome.error}`);
    const where = homeRelative(configPath, ctx.io.home);
    const name = ctx.style.bold(server);
    const text = outcome.changed
      ? [
          ctx.ui.mark("ok", on ? `${name} in ${where} now runs through Doorman's gateway.` : `${name} in ${where} runs directly again.`),
          ctx.ui.next("Restart the agent to pick it up."),
        ]
      : [ctx.ui.mark("off", `${name} in ${where} was already ${on ? "routed through the gateway" : "running directly"}.`)];
    return { data: { server, config_path: configPath, routed: on, changed: outcome.changed }, text };
  };
}

const routeCommand: CliCommand = {
  name: "gateway route",
  summary: "Run a local MCP server through Doorman's gateway (holds risky calls, records results)",
  usage: "[<config-path>] <server>",
  positionals: { min: 1, max: 2 },
  notes: [
    "The config must be one Doorman reads (see `doorman mcp`). Without a path, the server must be configured in exactly one file. A backup is kept beside the config (.doorman.bak).",
  ],
  examples: [
    ["doorman gateway route notes", "the one config that declares notes"],
    ["doorman gateway route ~/.cursor/mcp.json notes", "notes in Cursor's config"],
  ],
  run: routeRun(true),
};

const unrouteCommand: CliCommand = {
  name: "gateway unroute",
  summary: "Restore an MCP server's original command, bypassing the gateway",
  usage: "[<config-path>] <server>",
  positionals: { min: 1, max: 2 },
  examples: [["doorman gateway unroute ~/.cursor/mcp.json notes", "notes runs its own command again"]],
  run: routeRun(false),
};

function outcomeText(ctx: CliContext, call: GatewayCallRecord): string {
  const s = ctx.style;
  const ui = ctx.ui;
  if (call.blocked) return ui.mark("error", s.error(`blocked${call.reason ? `: ${call.reason}` : ""}`));
  if (call.injection && call.injection.length > 0) return ui.mark("error", s.error(`injection: ${call.injection.join(", ")}`));
  if (call.held) {
    return ui.mark("held", s.warn(`held, ${call.resolution ?? (call.forwarded === false ? "denied" : "allowed")}${call.decided_via ? ` via ${call.decided_via}` : ""}`));
  }
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
    const calls = readGatewayCalls(ctx.dataDir)
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
  summary: "Tools the gateway has seen servers advertise, and description changes or poisoning in them",
  async run(ctx) {
    const s = ctx.style;
    const tools = [...foldObservedTools(ctx.dataDir).values()].sort((a, b) => a.server.localeCompare(b.server) || a.name.localeCompare(b.name));
    const findings = scanObservedTools(ctx.dataDir).map((f) => ({ detector: f.detector, severity: f.severity, key_name: f.key_name, excerpt: f.excerpt, at: f.last_seen_at }));
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
      ...ctx.ui.table(
        ["SERVER", "TOOL", "CLASS", "VERSIONS", "CHANGED"],
        tools.map((t) => [
          t.server,
          t.name,
          t.cls,
          String(t.versions),
          t.changed_at ? ctx.ui.mark("warn", s.warn(`${ago(t.changed_at, now)}${t.change_note ? `: ${t.change_note}` : ""}`)) : s.dim("never"),
        ]),
        { indent: 2, keep: [2, 3] },
      ),
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
