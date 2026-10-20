import { syncGuard } from "../../enforcement.js";
import type { McpServerRow } from "../../lib/mcp-inventory.js";
import { mcpConfigHost } from "../../lib/mcp-inventory.js";
import { mcpInventoryNow } from "../../mcp-inventory-now.js";
import { mcpServerStatus, switchMcpAnswers, type McpInstallOutcome } from "../../mcp-install.js";
import type { CliCommand } from "../command.js";
import type { CliContext } from "../context.js";
import { ago, CliError } from "../output.js";
import { plural } from "../ui.js";

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
  if (row.recognized && row.recognized_stale) return ctx.ui.mark("warn", s.warn("recognized, changed since"));
  if (row.recognized) return ctx.ui.mark("ok", s.ok("recognized"));
  return ctx.ui.mark("warn", s.warn("unknown"));
}

function whereText(ctx: CliContext, row: McpServerRow): string {
  if (row.observed_only) return ctx.style.dim("no config found (seen in transcripts)");
  const places = [...new Set(row.configs.map((c) => mcpConfigHost(c.path)?.label ?? homeRelative(c.path, ctx.io.home)))];
  return `${places.join(", ")}${row.gatewayed ? ctx.style.accent(" (gateway)") : ""}`;
}

const listCommand: CliCommand = {
  name: "mcp",
  summary: "MCP servers on this machine: where they are configured, use, and what to review",
  options: { scan: { type: "boolean", default: false } },
  flags: [["--scan", "read new transcripts first (otherwise the store as last saved)"]],
  notes: [
    "Reads every MCP config the app reads (Claude Code, Claude Desktop, Cursor, Windsurf, VS Code, Copilot CLI, Zed, Gemini CLI, each project's .mcp.json) and the gateway's observations.",
    "A server is unknown until you recognize it with `doorman mcp recognize <server>`.",
  ],
  examples: [
    ["doorman mcp", "every MCP server on this machine"],
    ["doorman mcp --scan", "read new transcripts first"],
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
    if (inventory.servers.length === 0) {
      const text = ["No MCP servers configured or seen on this machine."];
      if (args.values.scan !== true) text.push(ctx.ui.next("`doorman mcp --scan` reads new transcripts first."));
      return { data: inventory, text };
    }
    const rows = inventory.servers.map((row) => {
      const findings = [
        row.poison_open > 0 ? s.error(`${row.poison_open} poisoning`) : "",
        row.unknown_open > 0 ? s.warn(`${row.unknown_open} unknown-server`) : "",
        row.changed_tools > 0 ? s.warn(plural(row.changed_tools, "changed tool")) : "",
      ].filter((f) => f !== "");
      return [
        s.bold(row.name),
        stateText(ctx, row),
        row.calls > 0 ? `${plural(row.calls, "call")}${row.last_used_at ? s.dim(`, ${ago(row.last_used_at, now)}`) : ""}` : s.dim("unused"),
        findings.length > 0 ? findings.join(", ") : s.dim("none"),
        whereText(ctx, row),
      ];
    });
    const unknown = inventory.servers.filter((r) => !r.recognized).length;
    const facts = [
      String(inventory.servers.length),
      `${inventory.recognized_count} recognized`,
      unknown > 0 ? s.warn(`${unknown} unknown`) : "",
      inventory.stale_recognitions > 0 ? s.warn(`${inventory.stale_recognitions} changed since recognized`) : "",
      `${inventory.gatewayed_count} through the gateway`,
    ].filter((f) => f !== "");
    const text = [
      ctx.ui.section("MCP servers", ctx.ui.list(facts)),
      "",
      ...ctx.ui.table(["SERVER", "STATE", "USE", "TO REVIEW", "CONFIGURED IN"], rows, { indent: 2, keep: [0] }),
    ];
    if (unknown > 0) text.push("", ctx.ui.next("`doorman mcp recognize <server>` marks a server you know."));
    return { data: inventory, text };
  },
};

/** The app's mcp:recognize handler: one entry per server, case-insensitive,
 * re-stamped on every recognize so a later description change reads as stale. */
function recognize(ctx: CliContext, server: string, recognized: boolean): string[] {
  const key = server.trim();
  if (key === "") throw new CliError("No server named.", 2, "`doorman mcp` lists the servers.");
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
  if (!synced.ok) throw new CliError(`Saved, but the guard's policy didn't update: ${synced.error}`, 1, "`doorman doctor` checks the guard setup.");
  return next;
}

const recognizeCommand: CliCommand = {
  name: "mcp recognize",
  summary: "Mark an MCP server as one you know (the guard treats it as approved)",
  usage: "<server>",
  positionals: { min: 1, max: 1 },
  notes: ["Recognizing is case-insensitive and re-stamps the server, so a later change to its tool descriptions shows as changed since recognized."],
  examples: [["doorman mcp recognize github", "approve the github server"]],
  async run(ctx, args) {
    const server = args.positionals[0]!.trim();
    const recognized = recognize(ctx, server, true);
    return { data: { server, recognized }, text: [ctx.ui.mark("ok", `Recognized ${ctx.style.bold(server)}.`)] };
  },
};

const forgetCommand: CliCommand = {
  name: "mcp forget",
  summary: "Take an MCP server off the recognized list",
  usage: "<server>",
  positionals: { min: 1, max: 1 },
  examples: [["doorman mcp forget github", "github is unknown again"]],
  async run(ctx, args) {
    const typed = args.positionals[0]!.trim();
    // A name copied with a trailing ellipsis: the recognized server it starts, if just one.
    const stem = typed.replace(/(?:…|\.\.\.)$/, "").toLowerCase();
    const starts = stem === typed.toLowerCase() ? [] : (ctx.prefs().mcp_recognized ?? []).filter((s) => s.toLowerCase().startsWith(stem));
    const server = starts.length === 1 ? starts[0]! : typed;
    const was = (ctx.prefs().mcp_recognized ?? []).some((s) => s.toLowerCase() === server.toLowerCase());
    const recognized = recognize(ctx, server, false);
    return {
      data: { server, recognized },
      text: [
        was
          ? ctx.ui.mark("ok", `${ctx.style.bold(server)} is no longer recognized.`)
          : ctx.ui.mark("off", `${ctx.style.bold(server)} wasn't recognized. Nothing changed.`),
      ],
    };
  },
};

function hostRows(ctx: CliContext, hosts: McpInstallOutcome["hosts"]): string[] {
  const s = ctx.style;
  if (hosts.length === 0) return [s.dim("No MCP host Doorman registers with is on this machine (VS Code, Copilot CLI).")];
  return ctx.ui.table(
    ["HOST", "REGISTERED", "CONFIG"],
    hosts.map((h) => [
      h.label,
      h.unreadable ? ctx.ui.mark("error", s.error("unreadable")) : h.registered ? ctx.ui.mark("ok", s.ok("yes")) : ctx.ui.mark("off", s.dim("no")),
      homeRelative(h.path, ctx.io.home),
    ]),
    { indent: 2, keep: [0, 1] },
  );
}

const serverStatusCommand: CliCommand = {
  name: "mcp server status",
  summary: "Whether Doorman's own MCP server is registered with your agents",
  async run(ctx) {
    const wanted = ctx.prefs().mcp_answers === true;
    const hosts = mcpServerStatus(ctx.dataDir, ctx.io.home, ctx.io.env);
    const s = ctx.style;
    const text = [
      `${ctx.ui.section("Doorman MCP server")}  ${wanted ? ctx.ui.mark("ok", s.ok("on")) : ctx.ui.mark("off", s.dim("off"))}`,
      ...hostRows(ctx, hosts),
    ];
    if (!wanted) text.push("", ctx.ui.next("`doorman mcp server install` registers it."));
    return { data: { wanted, hosts }, text };
  },
};

function serverSwitch(enabled: boolean): CliCommand["run"] {
  return async (ctx) => {
    ctx.requireWritable(`${enabled ? "Register" : "Unregister"} Doorman's MCP server`);
    ctx.setPrefs({ mcp_answers: enabled });
    const outcome = applyMcpAnswers(ctx, enabled);
    if (!outcome.ok) {
      throw new CliError(`Couldn't ${enabled ? "register" : "unregister"} the MCP server: ${outcome.error ?? "failed"}`, 1, "`doorman mcp server status` shows each host's config.");
    }
    const registered = outcome.hosts.filter((h) => h.registered).map((h) => h.label);
    const head = enabled
      ? registered.length > 0
        ? `Registered Doorman's MCP server with ${registered.join(", ")}.`
        : "MCP answers are on. No host to register with yet."
      : "Doorman's MCP server is unregistered.";
    return { data: { wanted: enabled, hosts: outcome.hosts }, text: [ctx.ui.mark("ok", head), ...hostRows(ctx, outcome.hosts)] };
  };
}

const serverInstallCommand: CliCommand = {
  name: "mcp server install",
  summary: "Register Doorman's MCP server with every MCP host here (VS Code, Copilot CLI)",
  notes: ["Turns on the app's MCP answers setting (prefs mcp_answers) and recognizes the doorman server."],
  examples: [["doorman mcp server install", "register with VS Code and Copilot CLI"]],
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
