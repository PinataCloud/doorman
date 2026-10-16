import { syncGuard } from "../../enforcement.js";
import type { McpServerRow } from "../../lib/mcp-inventory.js";
import { mcpConfigHost } from "../../lib/mcp-inventory.js";
import { mcpInventoryNow } from "../../mcp-inventory-now.js";
import { mcpServerStatus, switchMcpAnswers, type McpInstallOutcome } from "../../mcp-install.js";
import type { CliCommand } from "../command.js";
import type { CliContext } from "../context.js";
import { ago, CliError, table } from "../output.js";

/** `/Users/me/.cursor/mcp.json` → `~/.cursor/mcp.json`. */
export function homeRelative(path: string, home: string): string {
  return path === home || path.startsWith(`${home}/`) ? `~${path.slice(home.length)}` : path;
}

/** The `mcp_answers` switch's side effect, as the app applies it
 * (index.ts applyMcpAnswers): register or unregister our server, and
 * recognize it when registered. */
export function applyMcpAnswers(ctx: CliContext, enabled: boolean): McpInstallOutcome {
  return switchMcpAnswers(enabled, ctx.dataDir, ctx.io.home, { get: () => ctx.prefs(), set: (patch) => ctx.setPrefs(patch) }, ctx.io.env);
}

function stateText(ctx: CliContext, row: McpServerRow): string {
  const s = ctx.style;
  if (row.recognized && row.recognized_stale) return s.yellow("recognized, changed since");
  if (row.recognized) return s.green("recognized");
  return s.yellow("unknown");
}

function whereText(ctx: CliContext, row: McpServerRow): string {
  if (row.observed_only) return ctx.style.dim("no config found (seen in transcripts)");
  const places = [...new Set(row.configs.map((c) => mcpConfigHost(c.path)?.label ?? homeRelative(c.path, ctx.io.home)))];
  return `${places.join(", ")}${row.gatewayed ? ctx.style.purple(" (gateway)") : ""}`;
}

const listCommand: CliCommand = {
  name: "mcp",
  summary: "MCP servers on this machine: where they are configured, use, and findings",
  options: { scan: { type: "boolean", default: false } },
  details: [
    "Reads every MCP config the app reads (Claude Code, Claude Desktop, Cursor, Windsurf, VS Code,",
    "Copilot CLI, Zed, Gemini CLI, each project's .mcp.json) and the gateway's observations.",
    "A server is unknown until you recognize it (doorman mcp recognize <server>).",
    "",
    "--scan  read new transcripts first (otherwise the store as last saved)",
  ],
  async run(ctx, args) {
    const prefs = ctx.prefs();
    const handle = await ctx.openEngine({ scan: args.values.scan === true });
    let inventory;
    try {
      ({ inventory } = mcpInventoryNow(handle.engine, {
        dataDir: ctx.dataDir,
        home: ctx.io.home,
        prefs,
        policy: ctx.policy(),
        log: (m) => ctx.log(m),
      }));
    } finally {
      handle.close();
    }
    const s = ctx.style;
    const now = ctx.io.now();
    if (inventory.servers.length === 0) return { data: inventory, text: ["No MCP servers configured or seen on this machine."] };
    const rows = inventory.servers.map((row) => {
      const findings = [
        row.poison_open > 0 ? s.red(`${row.poison_open} poisoning`) : "",
        row.unknown_open > 0 ? s.yellow(`${row.unknown_open} unknown-server`) : "",
        row.changed_tools > 0 ? s.yellow(`${row.changed_tools} changed tool${row.changed_tools === 1 ? "" : "s"}`) : "",
      ].filter((f) => f !== "");
      return [
        s.bold(row.name),
        stateText(ctx, row),
        row.calls > 0 ? `${row.calls} call${row.calls === 1 ? "" : "s"}${row.last_used_at ? s.dim(`, ${ago(row.last_used_at, now)}`) : ""}` : s.dim("unused"),
        findings.length > 0 ? findings.join(", ") : s.dim("none"),
        whereText(ctx, row),
      ];
    });
    const unknown = inventory.servers.filter((r) => !r.recognized).length;
    return {
      data: inventory,
      text: [
        `${s.bold("MCP servers")}  ${inventory.servers.length} · ${inventory.recognized_count} recognized${unknown > 0 ? ` · ${s.yellow(`${unknown} unknown`)}` : ""}${inventory.stale_recognitions > 0 ? ` · ${s.yellow(`${inventory.stale_recognitions} changed since recognized`)}` : ""} · ${inventory.gatewayed_count} through the gateway`,
        "",
        ...table(["SERVER", "STATE", "USE", "FINDINGS", "CONFIGURED IN"], rows),
      ],
    };
  },
};

/** The app's mcp:recognize handler: one entry per server, case-insensitive,
 * re-stamped on every recognize so a later description change reads as stale. */
function recognize(ctx: CliContext, server: string, recognized: boolean): string[] {
  const key = server.trim();
  if (key === "") throw new CliError("Name a server.");
  ctx.requireWritable(`${recognized ? "Recognize" : "Forget"} the server`);
  const prefs = ctx.prefs();
  const current = prefs.mcp_recognized ?? [];
  const without = current.filter((s) => s.toLowerCase() !== key.toLowerCase());
  const next = recognized ? [...without, key] : without;
  const at = { ...(prefs.mcp_recognized_at ?? {}) };
  for (const name of Object.keys(at)) if (name.toLowerCase() === key.toLowerCase()) delete at[name];
  if (recognized) at[key] = new Date(ctx.io.now()).toISOString();
  ctx.setPrefs({ mcp_recognized: next, mcp_recognized_at: at });
  // The recognized list feeds livePolicy's approved_mcp_servers.
  const synced = syncGuard(ctx.dataDir, ctx.policy());
  if (!synced.ok) throw new CliError(`Saved, but the guard's policy didn't update: ${synced.error}`);
  return next;
}

const recognizeCommand: CliCommand = {
  name: "mcp recognize",
  summary: "Mark an MCP server as one you know (the guard treats it as approved)",
  usage: "<server>",
  positionals: { min: 1, max: 1 },
  async run(ctx, args) {
    const server = args.positionals[0]!.trim();
    const recognized = recognize(ctx, server, true);
    return { data: { server, recognized }, text: [`Recognized ${ctx.style.bold(server)}.`] };
  },
};

const forgetCommand: CliCommand = {
  name: "mcp forget",
  summary: "Take an MCP server off the recognized list",
  usage: "<server>",
  positionals: { min: 1, max: 1 },
  async run(ctx, args) {
    const server = args.positionals[0]!.trim();
    const was = (ctx.prefs().mcp_recognized ?? []).some((s) => s.toLowerCase() === server.toLowerCase());
    const recognized = recognize(ctx, server, false);
    return {
      data: { server, recognized },
      text: [was ? `${ctx.style.bold(server)} is no longer recognized.` : `${ctx.style.bold(server)} wasn't recognized; nothing changed.`],
    };
  },
};

function hostRows(ctx: CliContext, hosts: McpInstallOutcome["hosts"]): string[] {
  const s = ctx.style;
  if (hosts.length === 0) return [s.dim("No MCP host Doorman registers with is on this machine (VS Code, Copilot CLI).")];
  return table(
    ["HOST", "REGISTERED", "CONFIG"],
    hosts.map((h) => [h.label, h.unreadable ? s.red("unreadable") : h.registered ? s.green("yes") : s.dim("no"), homeRelative(h.path, ctx.io.home)]),
  );
}

const serverStatusCommand: CliCommand = {
  name: "mcp server status",
  summary: "Whether Doorman's own MCP server is registered with your agents",
  async run(ctx) {
    const wanted = ctx.prefs().mcp_answers === true;
    const hosts = mcpServerStatus(ctx.dataDir, ctx.io.home, ctx.io.env);
    return {
      data: { wanted, hosts },
      text: [`${ctx.style.bold("Doorman MCP server")}  ${wanted ? ctx.style.green("on") : ctx.style.dim("off")}`, ...hostRows(ctx, hosts)],
    };
  },
};

function serverSwitch(enabled: boolean): CliCommand["run"] {
  return async (ctx) => {
    ctx.requireWritable(`${enabled ? "Register" : "Unregister"} Doorman's MCP server`);
    ctx.setPrefs({ mcp_answers: enabled });
    const outcome = applyMcpAnswers(ctx, enabled);
    if (!outcome.ok) throw new CliError(`Couldn't ${enabled ? "register" : "unregister"} the MCP server: ${outcome.error ?? "failed"}`);
    const registered = outcome.hosts.filter((h) => h.registered).map((h) => h.label);
    const head = enabled
      ? registered.length > 0
        ? `Registered Doorman's MCP server with ${registered.join(", ")}.`
        : "MCP answers are on; no host to register with yet."
      : "Doorman's MCP server is unregistered.";
    return { data: { wanted: enabled, hosts: outcome.hosts }, text: [head, ...hostRows(ctx, outcome.hosts)] };
  };
}

const serverInstallCommand: CliCommand = {
  name: "mcp server install",
  summary: "Register Doorman's MCP server with every MCP host here (VS Code, Copilot CLI)",
  details: ["Turns on the app's MCP answers setting (prefs mcp_answers) and recognizes the doorman server."],
  run: serverSwitch(true),
};

const serverUninstallCommand: CliCommand = {
  name: "mcp server uninstall",
  summary: "Take Doorman's MCP server out of every host config",
  run: serverSwitch(false),
};

export const mcpCommands: CliCommand[] = [
  listCommand,
  recognizeCommand,
  forgetCommand,
  serverStatusCommand,
  serverInstallCommand,
  serverUninstallCommand,
];
