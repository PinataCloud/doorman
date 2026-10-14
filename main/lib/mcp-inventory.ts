/**
 * MCP server inventory — the first-class answer to "what MCP servers does this
 * machine actually run, and do I trust them?".
 *
 * Three sources, merged by server name:
 *  1. CONFIG — the entries in `~/.claude.json` (top-level and per-project) and
 *     each known project's `.mcp.json`, extracted by the same watcher that
 *     scans them for poisoning (mcp-watch.ts calls extractMcpServers here);
 *  2. USAGE — `mcp__<server>__<tool>` names in captured turns: which tools were
 *     called, how often, in how many sessions, and when last;
 *  3. FINDINGS — open poisoning / unapproved-server rows naming the server.
 *
 * On top of that sit two judgement layers:
 *  - a PERSONAL allowlist (prefs.mcp_recognized): "I know this server". Once at
 *    least one server is recognized, the radar's `unknown_mcp_server` check has
 *    an opinion to work from (index.ts writes the list into the policy);
 *  - a small shipped RISK CATALOG for well-known servers: who makes it and
 *    whether it talks to a hosted service. Static, versioned with the app, and
 *    honest about its limits — an unknown server gets "no profile", not a guess.
 *
 * Pure over its inputs (no fs, no Electron) so it is testable in isolation.
 */

import { redact } from "../guard/redact.js";
import { mcpServerRoots } from "../guard/mcp-poison.js";
import type { McpPermissionSet, McpToolClass } from "../guard/policy.js";
import { GATEWAY_MARKER } from "./gateway-config.js";
import type { FindingRow } from "./findings.js";
import type { LedgerTurn } from "./turns.js";
import { VSCODE_VARIANTS, profiles } from "./vscode.js";

/** What the gateway has observed of one tool — gateway-install.ts
 * foldObservedTools, re-declared structurally so this module stays pure. */
export interface ObservedToolSummary {
  server: string;
  name: string;
  cls: McpToolClass;
  versions: number;
  changed_at?: string;
  change_note?: string;
}

/** Same server-segment shape flow-rules.ts derives from a tool name. */
const MCP_TOOL_RE = /^mcp__([^_]+(?:_[^_]+)*?)__/;

/** One `mcpServers` entry as configured on disk. */
export interface McpConfigServer {
  name: string;
  config_path: string;
  /** `user` = ~/.claude.json; `project` = a repo's .mcp.json or a per-project
   * block inside ~/.claude.json. */
  scope: "user" | "project";
  transport: "stdio" | "http";
  /** The command line or URL, redacted — display only, never executed. */
  entry?: string;
  /** Currently routed through the Doorman gateway (phase 1). */
  gatewayed?: boolean;
}

export interface McpServerRisk {
  vendor: string;
  /** `official` = published by the service's own vendor; `reference` = the
   * modelcontextprotocol reference set; `community` = anyone else. */
  kind: "official" | "reference" | "community";
  /** Whether using it sends data to a hosted service (vs local-only). */
  hosted: boolean;
  note: string;
}

export interface McpServerRow {
  name: string;
  /** Every config file that declares it (a server can appear in several). */
  configs: { path: string; scope: "user" | "project"; transport: "stdio" | "http"; entry?: string; gatewayed?: boolean }[];
  /** Seen in transcripts but in no watched config — e.g. configured somewhere
   * we don't read, or removed since. Worth a look by definition. */
  observed_only: boolean;
  /** Routed through the gateway in at least one config (phase 1). */
  gatewayed: boolean;
  /** Distinct tool names seen in transcripts (capped for the bridge). */
  tools: string[];
  calls: number;
  sessions: number;
  first_used_at?: string;
  last_used_at?: string;
  /** Open findings naming this server. */
  poison_open: number;
  unknown_open: number;
  recognized: boolean;
  /** When the person recognized it (prefs.mcp_recognized_at). */
  recognized_at?: string;
  risk?: McpServerRisk;
  /** Tools the gateway has seen advertised, with their permission class. */
  observed_tools: { name: string; cls: McpToolClass; versions: number; changed_at?: string; change_note?: string }[];
  /** Tools whose description changed after first sight (the rug pull). */
  changed_tools: number;
  last_changed_at?: string;
  /** Recognized BEFORE a description changed — the recognition no longer covers
   * what the server now says, so the row asks again. */
  recognized_stale: boolean;
  /** The gateway permissions in force (guard/policy.ts mcp_permissions); an
   * absent class is `allow`. */
  permissions: McpPermissionSet;
}

export interface McpInventoryState {
  servers: McpServerRow[];
  recognized_count: number;
  /** Servers whose descriptions changed after the person recognized them. */
  stale_recognitions: number;
  /** Servers routed through the gateway in at least one config. */
  gatewayed_count: number;
}

const TOOLS_CAP = 12;

/**
 * The USER-LEVEL MCP config files worth watching, one per host, home-relative.
 *
 * Every one of these is a place an agent's tool surface is configured, and
 * until this list existed only Claude Code's was read — so a poisoned server
 * added to Claude Desktop or Cursor was invisible while the identical entry in
 * `~/.claude.json` raised a finding. The guard cannot HOLD a call in most of
 * these hosts, but reading their config costs nothing and answers the question
 * the Integrations screen already asks: what is connected to what.
 *
 * `host` is the shadow-AI catalog id (lib/shadow-ai.ts) so a finding can name
 * the app the person actually installed. Paths are relative to home; a file
 * that does not exist is simply never read.
 */
export const USER_MCP_CONFIGS: ReadonlyArray<{ host: string; label: string; rel: string }> = [
  // Claude Code's own — the one this app has always watched. Listed here too so
  // there is exactly one inventory of config locations.
  { host: "claude-code", label: "Claude Code", rel: ".claude.json" },
  { host: "claude-desktop", label: "Claude Desktop", rel: "Library/Application Support/Claude/claude_desktop_config.json" },
  { host: "cursor", label: "Cursor", rel: ".cursor/mcp.json" },
  { host: "windsurf", label: "Windsurf", rel: ".codeium/windsurf/mcp_config.json" },
  // One row per VS Code BUILD. Profiles are covered by mcpConfigPaths() below,
  // which enumerates them at scan time — they cannot be spelled as a fixed
  // relative path, and a poisoned server added inside a profile was invisible
  // while the identical entry in the default profile raised a finding.
  ...VSCODE_VARIANTS.map((variant) => ({
    host: "vscode-copilot",
    label: variant.label,
    rel: `${variant.supportRel}/User/mcp.json`,
  })),
  // Copilot CLI's user-level MCP config (`mcpServers`, `type: "local"` — the
  // `url ? http : stdio` inference below reads it fine). VS Code's Copilot
  // agent host reads this file too. Added 2026-09-08 with the app's own server.
  { host: "copilot-cli", label: "Copilot CLI", rel: ".copilot/mcp-config.json" },
  { host: "zed", label: "Zed", rel: ".config/zed/settings.json" },
  { host: "gemini-cli", label: "Gemini CLI", rel: ".gemini/settings.json" },
  // NOT here: Codex's `~/.codex/config.toml`. Its `[mcp_servers]` block is TOML,
  // and everything downstream (extractMcpServers, scanMcpConfigText) parses
  // JSON — listing the path would add a file that is read, fails to parse and
  // silently contributes nothing. It needs a TOML reader first.
];

/**
 * The config path a renderer asked to rewrite, IF the app itself discovered
 * that server in exactly that file — else undefined. `mcp:route-gateway`
 * reads and rewrites the path it is handed, so it only ever takes one the
 * config watcher named (the same rule the trace handlers apply to the last
 * trace's files): a compromised renderer can't point it at any other file.
 */
export function discoveredMcpConfig(
  servers: readonly McpConfigServer[],
  server: unknown,
  configPath: unknown,
): string | undefined {
  if (typeof server !== "string" || typeof configPath !== "string") return undefined;
  return servers.some((s) => s.name === server && s.config_path === configPath) ? configPath : undefined;
}

/**
 * Every user-level MCP config on THIS machine, absolute: the fixed list above
 * joined to home, plus each VS Code profile's own `mcp.json`.
 *
 * A profile path cannot live in `USER_MCP_CONFIGS` — its directory name is an
 * id VS Code mints — so it has to be enumerated against the real filesystem.
 * The caller hands in the two reads; a machine with no profiles gets exactly
 * the fixed list back.
 */
export function mcpConfigPaths(
  home: string,
  io: { exists(path: string): boolean; listDir(path: string): string[] },
): string[] {
  const base = USER_MCP_CONFIGS.map((entry) => `${home.replace(/\/+$/, "")}/${entry.rel}`);
  const profilePaths = VSCODE_VARIANTS.flatMap((variant) =>
    profiles(variant, home, io)
      .filter((profile) => !profile.default)
      .map((profile) => `${profile.dir}/mcp.json`),
  );
  return [...new Set([...base, ...profilePaths])];
}

/** The host id whose config a path belongs to, for naming a finding. Falls
 * back to undefined for a project `.mcp.json`, which belongs to the repo
 * rather than to any one app. */
export function mcpConfigHost(path: string): { host: string; label: string } | undefined {
  for (const entry of USER_MCP_CONFIGS) {
    if (path.endsWith(entry.rel)) return { host: entry.host, label: entry.label };
  }
  return undefined;
}

/**
 * Extract the configured servers from one config document, over the SAME root
 * selection the poisoning scan walks (`mcpServerRoots` in guard/mcp-poison.ts).
 * This reads STRUCTURE (name, command, url) where that one hunts strings, but a
 * subtree is server config for both or for neither — a host wired into one and
 * not the other would mean a server that lists and is never scanned.
 */
export function extractMcpServers(json: string, filePath: string): McpConfigServer[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch {
    return [];
  }
  if (!parsed || typeof parsed !== "object") return [];
  const doc = parsed as Record<string, unknown>;

  const roots: Array<[scope: "user" | "project", servers: unknown]> = mcpServerRoots(
    doc,
    filePath,
  ).map(({ projectPath, servers }) => [
    // A repo's own `.mcp.json` and a per-project block inside a user config are
    // both project scope; the top level of a user-level file is user scope.
    projectPath !== "" || /(?:^|[\\/])\.mcp\.json$/.test(filePath) ? "project" : "user",
    servers,
  ]);

  const out: McpConfigServer[] = [];
  for (const [scope, servers] of roots) {
    if (!servers || typeof servers !== "object") continue;
    for (const [name, config] of Object.entries(servers as Record<string, unknown>)) {
      if (!config || typeof config !== "object") continue;
      const record = config as Record<string, unknown>;
      // A gatewayed entry's real command is stashed under the marker — show
      // THAT, not the `node …/mcp-gateway.js` wrapper, so the row reads as the
      // server the person configured.
      const marker = record[GATEWAY_MARKER] as { command?: string; args?: unknown } | undefined;
      const gatewayed = !!marker && typeof marker.command === "string";
      const url = typeof record.url === "string" ? record.url : undefined;
      const command = gatewayed
        ? (marker!.command as string)
        : typeof record.command === "string"
          ? record.command
          : undefined;
      const rawArgs = gatewayed ? marker!.args : record.args;
      const args = Array.isArray(rawArgs) ? rawArgs.filter((a): a is string => typeof a === "string") : [];
      // Redacted: an entry pasted from a README can carry a token — in a
      // command's args, or a remote server URL's query string — and this
      // string's only job is to be displayed.
      const raw = url ?? (command ? [command, ...args].join(" ") : undefined);
      const entry = raw === undefined ? undefined : redact(raw).slice(0, 160);
      out.push({
        name,
        config_path: filePath,
        scope,
        transport: url ? "http" : "stdio",
        ...(entry === undefined ? {} : { entry }),
        ...(gatewayed ? { gatewayed: true } : {}),
      });
    }
  }
  return out;
}

/** The server a finding names, if any. Poisoning keys read
 * `"<pattern> · <server or tool>"`; unknown-server keys are the server. */
function findingServer(row: FindingRow): string | undefined {
  if (row.detector === "unknown_mcp_server") return row.key_name;
  if (row.detector !== "mcp_tool_poisoning") return undefined;
  const named = (row.key_name ?? "").split(" · ")[1];
  if (!named) return undefined;
  const viaTool = MCP_TOOL_RE.exec(named);
  return viaTool?.[1] ?? named;
}

/**
 * The shipped risk catalog. Deliberately small and conservative: only servers
 * common enough on developer machines to be worth naming, keyed by normalized
 * server name (config keys vary: `github`, `GitHub`, `github-mcp`). A server
 * not listed here renders as "no profile" — never a guess.
 */
const norm = (name: string): string => name.toLowerCase().replace(/[^a-z0-9]/g, "");

export const MCP_RISK_CATALOG: ReadonlyArray<readonly [match: RegExp, risk: McpServerRisk]> = [
  [/^github/, { vendor: "GitHub", kind: "official", hosted: true, note: "Reads and writes your repos, issues and PRs with your GitHub credentials." }],
  [/^linear/, { vendor: "Linear", kind: "official", hosted: true, note: "Reads and writes your Linear workspace — issues, projects, comments." }],
  [/^slack/, { vendor: "community", kind: "community", hosted: true, note: "Reads channels and can post as you — private conversations included." }],
  [/^notion/, { vendor: "Notion", kind: "official", hosted: true, note: "Reads and edits workspace pages and databases." }],
  [/^sentry/, { vendor: "Sentry", kind: "official", hosted: true, note: "Reads error events and traces from your Sentry org." }],
  [/^(postgres|pg)/, { vendor: "reference", kind: "reference", hosted: false, note: "Direct database access with whatever grants its connection string carries." }],
  [/^sqlite/, { vendor: "reference", kind: "reference", hosted: false, note: "Reads and writes local SQLite files." }],
  [/^(filesystem|fs)/, { vendor: "reference", kind: "reference", hosted: false, note: "File access under its configured roots — check what those roots are." }],
  [/^(fetch|webfetch)/, { vendor: "reference", kind: "reference", hosted: true, note: "Fetches arbitrary URLs — an egress channel, and fetched pages are untrusted text." }],
  [/^(puppeteer|playwright|browser)/, { vendor: "reference", kind: "reference", hosted: true, note: "Drives a real browser — can reach any site and any logged-in session in its profile." }],
  [/^memory/, { vendor: "reference", kind: "reference", hosted: false, note: "Local knowledge-graph store; contents persist across sessions." }],
  [/^sequential/, { vendor: "reference", kind: "reference", hosted: false, note: "Local reasoning scratchpad; no external data access." }],
  [/^(gdrive|googledrive)/, { vendor: "community", kind: "reference", hosted: true, note: "Reads files in your Google Drive." }],
  [/^(jira|atlassian|confluence)/, { vendor: "Atlassian", kind: "official", hosted: true, note: "Reads and writes Jira/Confluence content in your site." }],
  [/^stripe/, { vendor: "Stripe", kind: "official", hosted: true, note: "Talks to your Stripe account — treat its key like the money it moves." }],
  [/^figma/, { vendor: "Figma", kind: "official", hosted: true, note: "Reads design files your token can see." }],
  [/^context7/, { vendor: "Upstash", kind: "community", hosted: true, note: "Fetches library documentation from a hosted index." }],
  [/^brave/, { vendor: "Brave", kind: "official", hosted: true, note: "Web search via the Brave API — queries leave the machine." }],
  [/^supabase/, { vendor: "Supabase", kind: "official", hosted: true, note: "Reads and writes your Supabase project — database included." }],
];

export function riskProfileFor(name: string): McpServerRisk | undefined {
  const key = norm(name);
  for (const [match, risk] of MCP_RISK_CATALOG) {
    if (match.test(key)) return risk;
  }
  return undefined;
}

/** Merge config, usage and findings into the inventory rows, worst-news-first:
 * open poisoning, then unrecognized-with-usage, then by recency. */
export function buildMcpInventory(
  configServers: readonly McpConfigServer[],
  turns: Iterable<LedgerTurn>,
  findings: Iterable<FindingRow>,
  opts: {
    recognized: readonly string[];
    /** When each recognized server was recognized (prefs.mcp_recognized_at). */
    recognizedAt?: Record<string, string>;
    /** The gateway's per-tool observations (gateway-install.ts foldObservedTools). */
    observed?: Iterable<ObservedToolSummary>;
    /** The gateway permissions from the live policy. */
    permissions?: Record<string, McpPermissionSet>;
  },
): McpInventoryState {
  const rows = new Map<string, McpServerRow>();
  const displayName = new Map<string, string>();

  const rowFor = (name: string): McpServerRow => {
    const key = name.toLowerCase();
    let row = rows.get(key);
    if (!row) {
      row = {
        name: displayName.get(key) ?? name,
        configs: [],
        observed_only: true,
        gatewayed: false,
        tools: [],
        calls: 0,
        sessions: 0,
        poison_open: 0,
        unknown_open: 0,
        recognized: false,
        observed_tools: [],
        changed_tools: 0,
        recognized_stale: false,
        permissions: {},
      };
      rows.set(key, row);
    }
    return row;
  };

  for (const server of configServers) {
    displayName.set(server.name.toLowerCase(), server.name);
    const row = rowFor(server.name);
    row.name = server.name;
    row.observed_only = false;
    if (server.gatewayed) row.gatewayed = true;
    row.configs.push({
      path: server.config_path,
      scope: server.scope,
      transport: server.transport,
      ...(server.entry === undefined ? {} : { entry: server.entry }),
      ...(server.gatewayed ? { gatewayed: true } : {}),
    });
  }

  const sessionsByServer = new Map<string, Set<string>>();
  const toolsByServer = new Map<string, Set<string>>();
  for (const turn of turns) {
    if (!turn.tools || turn.tools.length === 0) continue;
    for (const tool of turn.tools) {
      const match = MCP_TOOL_RE.exec(tool);
      if (!match) continue;
      const server = match[1]!;
      const row = rowFor(server);
      row.calls += 1;
      if (!row.first_used_at || turn.at < row.first_used_at) row.first_used_at = turn.at;
      if (!row.last_used_at || turn.at > row.last_used_at) row.last_used_at = turn.at;
      const key = server.toLowerCase();
      let sessions = sessionsByServer.get(key);
      if (!sessions) sessionsByServer.set(key, (sessions = new Set()));
      sessions.add(turn.session_id);
      let tools = toolsByServer.get(key);
      if (!tools) toolsByServer.set(key, (tools = new Set()));
      tools.add(tool);
    }
  }
  for (const [key, sessions] of sessionsByServer) rows.get(key)!.sessions = sessions.size;
  for (const [key, tools] of toolsByServer) rows.get(key)!.tools = [...tools].sort().slice(0, TOOLS_CAP);

  for (const finding of findings) {
    if (finding.status !== "open") continue;
    const server = findingServer(finding);
    if (!server) continue;
    const row = rowFor(server);
    if (finding.detector === "mcp_tool_poisoning") row.poison_open += 1;
    else row.unknown_open += 1;
  }

  // What the gateway saw each server advertise — and whether it changed.
  for (const tool of opts.observed ?? []) {
    const row = rowFor(tool.server);
    row.observed_tools.push({
      name: tool.name,
      cls: tool.cls,
      versions: tool.versions,
      ...(tool.changed_at === undefined ? {} : { changed_at: tool.changed_at }),
      // WHAT changed, not just that it did — the one sentence the row can show.
      ...(tool.change_note === undefined ? {} : { change_note: tool.change_note }),
    });
    if (tool.versions > 1 && tool.changed_at) {
      row.changed_tools += 1;
      if (!row.last_changed_at || tool.changed_at > row.last_changed_at) row.last_changed_at = tool.changed_at;
    }
  }
  for (const row of rows.values()) {
    row.observed_tools.sort((a, b) => a.name.localeCompare(b.name));
    if (row.observed_tools.length > TOOLS_CAP * 2) row.observed_tools = row.observed_tools.slice(0, TOOLS_CAP * 2);
  }

  const recognized = new Set(opts.recognized.map((s) => s.toLowerCase()));
  const recognizedAt = new Map(
    Object.entries(opts.recognizedAt ?? {}).map(([name, at]) => [name.toLowerCase(), at] as const),
  );
  const permissions = new Map(
    Object.entries(opts.permissions ?? {}).map(([name, set]) => [name.toLowerCase(), set] as const),
  );
  let stale = 0;
  let gatewayed = 0;
  for (const [key, row] of rows) {
    row.recognized = recognized.has(key);
    const at = recognizedAt.get(key);
    if (at) row.recognized_at = at;
    // A description that changed after the person said "I recognize this"
    // is a server they have not, in fact, seen — the recognition is stale.
    row.recognized_stale = row.recognized && row.last_changed_at !== undefined && (at === undefined || row.last_changed_at > at);
    if (row.recognized_stale) stale += 1;
    if (row.gatewayed) gatewayed += 1;
    row.permissions = permissions.get(key) ?? {};
    const risk = riskProfileFor(row.name);
    if (risk) row.risk = risk;
  }

  const sorted = [...rows.values()].sort((a, b) => {
    if (a.poison_open !== b.poison_open) return b.poison_open - a.poison_open;
    if (a.changed_tools !== b.changed_tools) return b.changed_tools - a.changed_tools;
    const aTrusted = a.recognized && !a.recognized_stale ? 1 : 0;
    const bTrusted = b.recognized && !b.recognized_stale ? 1 : 0;
    if (aTrusted !== bTrusted) return aTrusted - bTrusted;
    const aAt = a.last_used_at ?? "";
    const bAt = b.last_used_at ?? "";
    return aAt < bAt ? 1 : aAt > bAt ? -1 : a.name.localeCompare(b.name);
  });
  return { servers: sorted, recognized_count: recognized.size, stale_recognitions: stale, gatewayed_count: gatewayed };
}
