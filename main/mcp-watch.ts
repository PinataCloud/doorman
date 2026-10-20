/**
 * MCP config watcher — the file-side half of mcp_tool_poisoning (the
 * transcript-side half rides CaptureEngine's tool_output scan).
 *
 * Watches every USER-LEVEL agent config (lib/mcp-inventory.ts
 * `userMcpConfigs` — Claude Code, Claude Desktop, Cursor, Windsurf, VS Code,
 * Zed, Gemini CLI) plus each known project's `.mcp.json` (cwds come from the
 * capture engine's turns — the projects this machine actually runs agents in)
 * and re-scans on change, SpoolWatcher's shape: fs.watch where the file exists,
 * a slow interval everywhere, and a size+mtime cursor so an unchanged file
 * costs a stat. Findings are minted here (origin "config", no session) and
 * handed to the engine's ledger, which merges idempotently.
 *
 * READING a host's config is independent of GUARDING it: Doorman cannot hold
 * a tool call inside Claude Desktop, but a poisoned server configured there is
 * the same server, described the same way, and costs one stat per minute to
 * find. The finding names the app it came from so the row is actionable.
 */

import { statSync, readFileSync, watch, type FSWatcher } from "node:fs";
import { join } from "node:path";
import { scanMcpConfigText } from "./guard/mcp-poison.js";
import { mintFindingRow, type FindingRow } from "./lib/findings.js";
import { extractMcpServers, mcpConfigHost, type McpConfigServer } from "./lib/mcp-inventory.js";

const RESCAN_INTERVAL_MS = 60_000;

interface FileCursor {
  size: number;
  mtimeMs: number;
}

export class McpConfigWatcher {
  private watchers = new Map<string, FSWatcher>();
  private timer: NodeJS.Timeout | undefined;
  private cursors = new Map<string, FileCursor>();
  /** Configured servers per config path — merged into the inventory. Keyed by
   * path so a deleted/emptied file drops its entries on the next sweep. */
  private serversByPath = new Map<string, McpConfigServer[]>();

  constructor(
    private readonly deps: {
      /** The user-level Claude config — `~/.claude.json` in production. */
      claudeConfigPath: string;
      /** The other hosts' user-level configs, absolute. Production passes
       * `mcpConfigPaths(home)`; tests pass whatever they wrote. */
      hostConfigPaths?: string[];
      /** Distinct project cwds seen in captured turns. Re-read every sweep,
       * so a session in a new repo starts covering its `.mcp.json`. */
      knownCwds(): Iterable<string>;
      onFindings(rows: FindingRow[]): void;
      /** The configured-server set changed — the caller rebuilds the inventory. */
      onServers?(servers: McpConfigServer[]): void;
      log(message: string): void;
    },
  ) {}

  /** Every configured server currently known, across all watched files. */
  servers(): McpConfigServer[] {
    return [...this.serversByPath.values()].flat();
  }

  start(): void {
    this.sweep();
    this.timer = setInterval(() => this.sweep(), RESCAN_INTERVAL_MS);
    this.timer.unref?.();
  }

  stop(): void {
    for (const watcher of this.watchers.values()) watcher.close();
    this.watchers.clear();
    if (this.timer) clearInterval(this.timer);
    this.timer = undefined;
  }

  /** Every config path currently worth reading. */
  private paths(): string[] {
    const paths = new Set<string>([this.deps.claudeConfigPath]);
    for (const path of this.deps.hostConfigPaths ?? []) {
      if (typeof path === "string" && path !== "") paths.add(path);
    }
    for (const cwd of this.deps.knownCwds()) {
      if (typeof cwd === "string" && cwd !== "") paths.add(join(cwd, ".mcp.json"));
    }
    return [...paths];
  }

  sweep(): void {
    for (const path of this.paths()) {
      this.ensureWatch(path);
      this.scanIfChanged(path);
    }
  }

  private ensureWatch(path: string): void {
    if (this.watchers.has(path)) return;
    try {
      const watcher = watch(path, () => this.scanIfChanged(path));
      watcher.on("error", () => {
        // A deleted file kills its watcher; the interval sweep re-arms it.
        this.watchers.get(path)?.close();
        this.watchers.delete(path);
      });
      this.watchers.set(path, watcher);
    } catch {
      // Doesn't exist (most projects have no .mcp.json) — the sweep retries.
    }
  }

  private scanIfChanged(path: string): void {
    let size: number;
    let mtimeMs: number;
    try {
      const stat = statSync(path);
      size = stat.size;
      mtimeMs = stat.mtimeMs;
    } catch {
      this.cursors.delete(path);
      // A file that vanished must drop its servers from the inventory.
      if (this.serversByPath.delete(path)) this.deps.onServers?.(this.servers());
      return;
    }
    const cursor = this.cursors.get(path);
    if (cursor && cursor.size === size && cursor.mtimeMs === mtimeMs) return;
    this.cursors.set(path, { size, mtimeMs });

    let contents: string;
    try {
      contents = readFileSync(path, "utf8");
    } catch (err) {
      this.deps.log(`couldn't read MCP config ${path}: ${String(err)}`);
      return;
    }

    // Inventory extraction runs regardless of findings — a clean config still
    // has servers worth listing.
    const servers = extractMcpServers(contents, path);
    const prev = this.serversByPath.get(path) ?? [];
    if (JSON.stringify(prev) !== JSON.stringify(servers)) {
      if (servers.length > 0) this.serversByPath.set(path, servers);
      else this.serversByPath.delete(path);
      this.deps.onServers?.(this.servers());
    }

    const findings = scanMcpConfigText(contents, path);
    if (findings.length === 0) return;
    const at = new Date().toISOString();
    // WHICH app's config this is. The ledger's `source` is still a capture rail
    // — Claude Desktop and VS Code are not rails and have no TurnSource — so the
    // app's name rides the finding's key instead of being dropped. A row that
    // just said "claude-code" for a server configured in Cursor would send the
    // reader to the wrong file.
    const host = mcpConfigHost(path);
    this.deps.onFindings(
      findings.map((finding) =>
        mintFindingRow(
          host && host.host !== "claude-code"
            ? { ...finding, key_name: `${finding.key_name} · ${host.label}` }
            : finding,
          {
            source: "claude-code",
            origin: "config",
            // ...and the row names the app outright, so the card can wear it
            // and the ledger and report can print it, not just the key's tail.
            ...(host === undefined ? {} : { config_host: host.label }),
            at,
          },
        ),
      ),
    );
  }
}
