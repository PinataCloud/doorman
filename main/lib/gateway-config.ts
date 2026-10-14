/**
 * Routing an MCP server through the Doorman gateway — the reversible config
 * surgery behind the "Route through gateway" toggle (MCP gateway, phase 1).
 *
 * Same discipline as the hook installer (guard/policy.ts mergeHookDocument):
 * parse, preserve everything unrelated, refuse malformed JSON, and store the
 * ORIGINAL so restore is exact. A gatewayed entry keeps the original command
 * under `_doorman_gateway`, which doubles as the "already routed" marker (so
 * routing is idempotent) and the restore source.
 *
 * Only STDIO servers (a `command`) can be proxied this way — a remote `url`
 * server has no local process to wrap; those are left untouched and reported.
 *
 * Pure over the config text (no fs) so the tests can hold the surgery to
 * "preserves the world, round-trips exactly". The caller does the file IO with
 * the same care the hook installer takes (backup, atomic-ish write).
 */

export const GATEWAY_MARKER = "_doorman_gateway";

interface StdioEntry {
  command?: string;
  args?: unknown;
  env?: unknown;
  [key: string]: unknown;
}

interface GatewayOriginal {
  command: string;
  args: string[];
}

export type RouteOutcome =
  | { ok: true; changed: boolean; json: string }
  | { ok: false; reason: "not_json" | "no_such_server" | "remote_server" | "already" };

/** The server names in a config doc that CAN be routed (stdio, on a matched
 * root), each with whether it is currently gatewayed. For the UI toggle. */
export interface RoutableServer {
  name: string;
  gatewayed: boolean;
  transport: "stdio" | "http";
}

/** Walk the same roots mcp-poison.ts does, returning [container, name, entry]
 * for every server, so route/restore/list share one traversal. */
function eachServer(
  doc: Record<string, unknown>,
  filePath: string,
): Array<[Record<string, unknown>, string, StdioEntry]> {
  const isProjectMcpJson = /(?:^|[\\/])\.mcp\.json$/.test(filePath);
  const roots: Record<string, unknown>[] = [];
  if (isProjectMcpJson) {
    const servers = (doc.mcpServers ?? doc) as Record<string, unknown>;
    if (servers && typeof servers === "object") roots.push(servers);
  } else {
    if (doc.mcpServers && typeof doc.mcpServers === "object") roots.push(doc.mcpServers as Record<string, unknown>);
    const projects = doc.projects;
    if (projects && typeof projects === "object") {
      for (const project of Object.values(projects as Record<string, unknown>)) {
        const servers = (project as Record<string, unknown> | null)?.mcpServers;
        if (servers && typeof servers === "object") roots.push(servers as Record<string, unknown>);
      }
    }
  }
  const out: Array<[Record<string, unknown>, string, StdioEntry]> = [];
  for (const container of roots) {
    for (const [name, entry] of Object.entries(container)) {
      if (entry && typeof entry === "object") out.push([container, name, entry as StdioEntry]);
    }
  }
  return out;
}

export function listRoutableServers(json: string, filePath: string): RoutableServer[] {
  let doc: Record<string, unknown>;
  try {
    doc = JSON.parse(json) as Record<string, unknown>;
  } catch {
    return [];
  }
  if (!doc || typeof doc !== "object") return [];
  const out: RoutableServer[] = [];
  for (const [, name, entry] of eachServer(doc, filePath)) {
    const gatewayed = !!entry[GATEWAY_MARKER];
    const transport = typeof entry.url === "string" && !entry.command ? "http" : "stdio";
    out.push({ name, gatewayed, transport });
  }
  return out;
}

function parseDoc(json: string): Record<string, unknown> | undefined {
  try {
    const doc = JSON.parse(json);
    return doc && typeof doc === "object" ? (doc as Record<string, unknown>) : undefined;
  } catch {
    return undefined;
  }
}

/**
 * Rewrite `serverName`'s entry to spawn the gateway wrapping the original
 * command. `nodePath` is the interpreter (usually "node"); `gatewayJs` the
 * absolute path to the copied mcp-gateway.js.
 */
export function routeServerThroughGateway(
  json: string,
  filePath: string,
  serverName: string,
  gatewayJs: string,
  nodePath = "node",
): RouteOutcome {
  const doc = parseDoc(json);
  if (!doc) return { ok: false, reason: "not_json" };
  for (const [, name, entry] of eachServer(doc, filePath)) {
    if (name !== serverName) continue;
    if (entry[GATEWAY_MARKER]) return { ok: false, reason: "already" };
    if (typeof entry.command !== "string") return { ok: false, reason: "remote_server" };
    const original: GatewayOriginal = {
      command: entry.command,
      args: Array.isArray(entry.args) ? entry.args.filter((a): a is string => typeof a === "string") : [],
    };
    entry[GATEWAY_MARKER] = original;
    entry.command = nodePath;
    entry.args = [gatewayJs, "--server", serverName, "--", original.command, ...original.args];
    return { ok: true, changed: true, json: `${JSON.stringify(doc, null, 2)}\n` };
  }
  return { ok: false, reason: "no_such_server" };
}

/**
 * Point every entry already owned by the gateway at the current copied bundle.
 * The stored original command remains untouched, so turning routing off still
 * restores the exact pre-Doorman configuration.
 */
export function retargetGatewayRoutes(
  json: string,
  filePath: string,
  gatewayJs: string,
  nodePath = "node",
): RouteOutcome {
  const doc = parseDoc(json);
  if (!doc) return { ok: false, reason: "not_json" };
  let found = false;
  let changed = false;
  for (const [, name, entry] of eachServer(doc, filePath)) {
    const original = entry[GATEWAY_MARKER] as GatewayOriginal | undefined;
    if (!original || typeof original.command !== "string") continue;
    found = true;
    const originalArgs = Array.isArray(original.args)
      ? original.args.filter((arg): arg is string => typeof arg === "string")
      : [];
    const args = [gatewayJs, "--server", name, "--", original.command, ...originalArgs];
    if (entry.command === nodePath && JSON.stringify(entry.args) === JSON.stringify(args)) continue;
    entry.command = nodePath;
    entry.args = args;
    changed = true;
  }
  if (!found || !changed) return { ok: false, reason: "already" };
  return { ok: true, changed: true, json: `${JSON.stringify(doc, null, 2)}\n` };
}

/** Undo it — restore `command`/`args` from the marker and drop the marker. */
export function restoreServer(json: string, filePath: string, serverName: string): RouteOutcome {
  const doc = parseDoc(json);
  if (!doc) return { ok: false, reason: "not_json" };
  for (const [, name, entry] of eachServer(doc, filePath)) {
    if (name !== serverName) continue;
    const marker = entry[GATEWAY_MARKER] as GatewayOriginal | undefined;
    if (!marker || typeof marker.command !== "string") return { ok: false, reason: "already" };
    entry.command = marker.command;
    entry.args = Array.isArray(marker.args) ? marker.args : [];
    delete entry[GATEWAY_MARKER];
    return { ok: true, changed: true, json: `${JSON.stringify(doc, null, 2)}\n` };
  }
  return { ok: false, reason: "no_such_server" };
}
