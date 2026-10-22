/**
 * The MCP inventory in one pass, for callers without the app's long-lived
 * watchers (the CLI): the same sources the app folds in `recompute()` —
 * McpConfigWatcher over every user-level config plus each known project's
 * `.mcp.json`, the gateway's observed tools and call records — swept once.
 *
 * Findings minted along the way (poisoned descriptions, rug pulls, injected
 * results) go into the engine's ledger exactly as the app's watchers hand
 * them over (`ingestConfigFindings`), so the inventory's open counts match.
 */

import { existsSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import type { CaptureEngine } from "./capture.js";
import { foldObservedTools, scanGatewayCalls, scanObservedTools } from "./gateway-install.js";
import type { GuardPolicy } from "./guard/policy.js";
import { buildMcpInventory, mcpConfigPaths, type McpConfigServer, type McpInventoryState } from "./lib/mcp-inventory.js";
import { McpConfigWatcher } from "./mcp-watch.js";
import type { Prefs } from "./state.js";

/** Every MCP server configured on this machine, read once. `knownCwds` are the
 * projects whose `.mcp.json` counts (the app takes them from captured turns). */
export function discoverMcpServers(deps: {
  home: string;
  /** For `$COPILOT_HOME`; the process's own when absent. */
  env?: NodeJS.ProcessEnv;
  knownCwds: Iterable<string>;
  onFindings(rows: Parameters<CaptureEngine["ingestConfigFindings"]>[0]): void;
  log(message: string): void;
}): McpConfigServer[] {
  const cwds = [...deps.knownCwds];
  const watcher = new McpConfigWatcher({
    claudeConfigPath: join(deps.home, ".claude.json"),
    hostConfigPaths: mcpConfigPaths(
      deps.home,
      {
        exists: (path) => existsSync(path),
        listDir: (path) => {
          try {
            return readdirSync(path);
          } catch {
            return [];
          }
        },
        isDir: (path) => {
          try {
            return statSync(path).isDirectory();
          } catch {
            return false;
          }
        },
      },
      process.platform,
      deps.env ?? process.env,
    ),
    knownCwds: () => cwds,
    onFindings: (rows) => deps.onFindings(rows),
    log: deps.log,
  });
  try {
    watcher.sweep();
    return watcher.servers();
  } finally {
    watcher.stop();
  }
}

/** The project directories the engine has seen agents run in. */
export function engineCwds(engine: CaptureEngine): Set<string> {
  const cwds = new Set<string>();
  for (const turn of engine.turns.values()) if (turn.cwd) cwds.add(turn.cwd);
  return cwds;
}

/** The Integrations screen's MCP inventory, as the app builds it. */
export function mcpInventoryNow(
  engine: CaptureEngine,
  opts: { dataDir: string; home: string; env?: NodeJS.ProcessEnv; prefs: Prefs; policy: GuardPolicy; log(message: string): void },
): { inventory: McpInventoryState; servers: McpConfigServer[] } {
  const servers = discoverMcpServers({
    home: opts.home,
    ...(opts.env ? { env: opts.env } : {}),
    knownCwds: engineCwds(engine),
    onFindings: (rows) => engine.ingestConfigFindings(rows),
    log: opts.log,
  });
  try {
    const rows = [...scanObservedTools(opts.dataDir), ...scanGatewayCalls(opts.dataDir)];
    if (rows.length > 0) engine.ingestConfigFindings(rows);
  } catch (err) {
    opts.log(`gateway observe scan failed: ${String(err)}`);
  }
  const inventory = buildMcpInventory(servers, engine.turns.values(), engine.shownFindings(), {
    recognized: opts.prefs.mcp_recognized ?? [],
    recognizedAt: opts.prefs.mcp_recognized_at ?? {},
    observed: foldObservedTools(opts.dataDir).values(),
    permissions: opts.policy.mcp_permissions ?? {},
  });
  return { inventory, servers };
}
