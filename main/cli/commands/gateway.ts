import { resolve } from "node:path";
import { foldObservedTools, readGatewayCalls, routeServer, scanObservedTools, unrouteServer, type GatewayCallRecord } from "../../gateway-install.js";
import { discoveredMcpConfig } from "../../lib/mcp-inventory.js";
import { discoverMcpServers, engineCwds } from "../../mcp-inventory-now.js";
import type { CliCommand, ParsedArgs } from "../command.js";
import type { CliContext } from "../context.js";
import { ago, CliError, table } from "../output.js";
import { homeRelative } from "./mcp.js";

/** The config to rewrite, only if a sweep of the machine's MCP configs found
 * `server` in it: the rule the app's mcp:route-gateway handler applies
 * (lib/mcp-inventory.ts discoveredMcpConfig). With no path given, the one
 * config that declares the server. */
async function configFor(ctx: CliContext, args: ParsedArgs): Promise<{ server: string; configPath: string }> {
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
      throw new CliError(`No MCP server "${server}" in ${homeRelative(requested, ctx.io.home)}. Run \`doorman mcp\` to see where each server is configured.`);
    }
    return { server, configPath };
  }
  const paths = [...new Set(servers.filter((s) => s.name === server).map((s) => s.config_path))];
  if (paths.length === 0) throw new CliError(`No MCP config on this machine declares "${server}". Run \`doorman mcp\` to list servers.`);
  if (paths.length > 1) {
    throw new CliError(`"${server}" is configured in ${paths.length} files; name one: ${paths.map((p) => homeRelative(p, ctx.io.home)).join(", ")}`);
  }
  return { server, configPath: paths[0]! };
}

function routeRun(on: boolean): CliCommand["run"] {
  return async (ctx, args) => {
    ctx.requireWritable(`${on ? "Route" : "Unroute"} the server`);
    const { server, configPath } = await configFor(ctx, args);
    const outcome = on ? routeServer(ctx.dataDir, configPath, server) : unrouteServer(configPath, server);
    if (!outcome.ok) throw new CliError(`Couldn't ${on ? "route" : "unroute"} ${server}: ${outcome.error}`);
    const where = homeRelative(configPath, ctx.io.home);
    const text = outcome.changed
      ? on
        ? `${ctx.style.bold(server)} in ${where} now runs through Doorman's gateway. Restart the agent to pick it up.`
        : `${ctx.style.bold(server)} in ${where} runs directly again. Restart the agent to pick it up.`
      : `${ctx.style.bold(server)} in ${where} was already ${on ? "routed through the gateway" : "running directly"}.`;
    return { data: { server, config_path: configPath, routed: on, changed: outcome.changed }, text: [text] };
  };
}

const routeCommand: CliCommand = {
  name: "gateway route",
  summary: "Run a local MCP server through Doorman's gateway (holds risky calls, records results)",
  usage: "[<config-path>] <server>",
  positionals: { min: 1, max: 2 },
  details: [
    "The config must be one Doorman reads (see `doorman mcp`). Without a path, the server must be",
    "configured in exactly one file. A backup is kept beside the config (.doorman.bak).",
  ],
  run: routeRun(true),
};

const unrouteCommand: CliCommand = {
  name: "gateway unroute",
  summary: "Restore an MCP server's original command, bypassing the gateway",
  usage: "[<config-path>] <server>",
  positionals: { min: 1, max: 2 },
  run: routeRun(false),
};

function outcomeText(ctx: CliContext, call: GatewayCallRecord): string {
  const s = ctx.style;
  if (call.blocked) return s.red(`blocked${call.reason ? `: ${call.reason}` : ""}`);
  if (call.injection && call.injection.length > 0) return s.red(`injection: ${call.injection.join(", ")}`);
  if (call.held) return s.yellow(`held, ${call.resolution ?? (call.forwarded === false ? "denied" : "allowed")}${call.decided_via ? ` via ${call.decided_via}` : ""}`);
  if (call.is_error) return s.yellow("error");
  return s.dim("ok");
}

const callsCommand: CliCommand = {
  name: "gateway calls",
  summary: "Recent tool calls that went through the gateway, newest first",
  usage: "[--limit 20]",
  options: { limit: { type: "string", default: "20" } },
  async run(ctx, args) {
    const limit = Number(args.values.limit);
    if (!Number.isInteger(limit) || limit < 1) throw new CliError("--limit must be a positive whole number.", 2);
    const calls = readGatewayCalls(ctx.dataDir)
      .map((call, index) => ({ call, index }))
      .sort((a, b) => (b.call.at ?? "").localeCompare(a.call.at ?? "") || b.index - a.index)
      .slice(0, limit)
      .map((entry) => entry.call);
    if (calls.length === 0) return { data: [], text: ["No calls have gone through the gateway yet (doorman gateway route <server>)."] };
    const now = ctx.io.now();
    return {
      data: calls,
      text: table(
        ["WHEN", "SERVER", "TOOL", "CLASS", "OUTCOME"],
        calls.map((c) => [c.at ? ago(c.at, now) : "", c.server ?? "", c.tool ?? "", c.cls ?? "", outcomeText(ctx, c)]),
      ),
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
    if (tools.length === 0) return { data: { tools, findings }, text: ["The gateway hasn't observed any tools yet (doorman gateway route <server>)."] };
    const now = ctx.io.now();
    const text = table(
      ["SERVER", "TOOL", "CLASS", "VERSIONS", "CHANGED"],
      tools.map((t) => [
        t.server,
        t.name,
        t.cls,
        String(t.versions),
        t.changed_at ? s.yellow(`${ago(t.changed_at, now)}${t.change_note ? `: ${t.change_note}` : ""}`) : s.dim("never"),
      ]),
    );
    if (findings.length > 0) {
      text.push("", s.bold(`Findings (${findings.length})`));
      for (const f of findings) {
        const sev = f.severity === "critical" || f.severity === "high" ? s.red(f.severity) : f.severity === "medium" ? s.yellow(f.severity) : s.dim(f.severity);
        text.push(`  ${sev}  ${f.detector}  ${f.key_name}`);
      }
    }
    return { data: { tools, findings }, text };
  },
};

export const gatewayCommands: CliCommand[] = [routeCommand, unrouteCommand, callsCommand, observedCommand];
