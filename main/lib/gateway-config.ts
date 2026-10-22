/**
 * Routing an MCP server through the Doorman gateway — the reversible config
 * surgery behind the "Route through gateway" toggle (MCP gateway, phase 1).
 *
 * The edit is BYTE-PRESERVING (guard/jsonc.ts `editJsonc`): only the routed
 * entry's `command`/`args` and the marker change; every other byte — tabs,
 * comments, key order, escapes, a number too large for a double — is the
 * person's and stays exactly as written. A gatewayed entry keeps the original
 * launch under `_doorman_gateway`, which doubles as the "already routed"
 * marker (so routing is idempotent) and the restore source: `args` is stored
 * verbatim (numbers stay numbers) and only when the entry had them, so unroute
 * writes back the entry it found.
 *
 * Servers are found over the SAME roots the inventory and the poisoning scan
 * walk (guard/mcp-poison.ts `mcpServerRoots`): `mcpServers` (Claude, Cursor,
 * Windsurf…), `servers` (VS Code's mcp.json), `context_servers` (Zed), and
 * the per-project blocks inside ~/.claude.json. A name can be declared both
 * at the top level and for a project; `project` picks which.
 *
 * Only STDIO servers (a `command`) can be proxied this way — a remote `url`
 * server has no local process to wrap; those are left untouched and reported.
 *
 * Pure over the config text (no fs) so the tests can hold the surgery to
 * "preserves the world, round-trips exactly". The caller does the file IO.
 */

import { editJsonc, isPlainObject as isObject, readJsonc, type JsoncDialect } from "../guard/jsonc.js";
import { mcpServerRoots } from "../guard/mcp-poison.js";

export const GATEWAY_MARKER = "_doorman_gateway";

/** Editor configs (VS Code, Zed) are JSONC with trailing commas; a strict
 * JSON file reads the same under it. */
const DIALECT: JsoncDialect = { trailingCommas: true };

interface GatewayOriginal {
  command: string;
  /** Absent when the entry had no `args`. */
  args?: unknown[];
}

export type RouteOutcome =
  | { ok: true; changed: boolean; json: string }
  | { ok: false; reason: "not_json" | "no_such_server" | "remote_server" | "already" | "ambiguous"; projects?: string[] };

/** One server entry in a config document. `project` is the project path of a
 * per-project block (~/.claude.json `projects[…]`), `""` for the top level. */
interface Located {
  name: string;
  project: string;
  entry: Record<string, unknown>;
}

function readDoc(json: string): Record<string, unknown> | undefined {
  try {
    const doc = readJsonc(json, DIALECT);
    return isObject(doc) ? doc : undefined;
  } catch {
    return undefined;
  }
}

function eachServer(doc: Record<string, unknown>, filePath: string): Located[] {
  const out: Located[] = [];
  for (const { projectPath, servers } of mcpServerRoots(doc, filePath)) {
    if (!isObject(servers)) continue;
    for (const [name, entry] of Object.entries(servers)) {
      if (isObject(entry)) out.push({ name, project: projectPath, entry });
    }
  }
  return out;
}

/**
 * The entry `serverName` names. With `project` given, exactly that block
 * (`""` = the top level). Without it: the only one, else the top-level one —
 * the entry a person who typed just the name most likely means — else
 * `ambiguous`, listing the projects that declare it.
 */
function locate(
  doc: Record<string, unknown>,
  filePath: string,
  serverName: string,
  project: string | undefined,
): Located | { reason: "no_such_server" | "ambiguous"; projects?: string[] } {
  const matches = eachServer(doc, filePath).filter((s) => s.name === serverName);
  if (project !== undefined) return matches.find((s) => s.project === project) ?? { reason: "no_such_server" };
  if (matches.length === 1) return matches[0]!;
  const top = matches.find((s) => s.project === "");
  if (top) return top;
  if (matches.length === 0) return { reason: "no_such_server" };
  return { reason: "ambiguous", projects: matches.map((s) => s.project) };
}

/** The projects (`""` = top level) under which `serverName` is declared. */
export function serverScopes(json: string, filePath: string, serverName: string): string[] {
  const doc = readDoc(json);
  if (!doc) return [];
  return eachServer(doc, filePath)
    .filter((s) => s.name === serverName)
    .map((s) => s.project);
}

/**
 * Where an entry keeps its launch: `command` + `args` on the entry (every
 * host), or Zed's older `command: { path, args }` object.
 */
function launchHolder(entry: Record<string, unknown>): { holder: Record<string, unknown>; key: "command" | "path" } | undefined {
  if (typeof entry.command === "string") return { holder: entry, key: "command" };
  if (isObject(entry.command) && typeof entry.command.path === "string") return { holder: entry.command, key: "path" };
  return undefined;
}

function edited(json: string, doc: Record<string, unknown>): RouteOutcome {
  try {
    return { ok: true, changed: true, json: editJsonc(json, doc, DIALECT) };
  } catch {
    return { ok: false, reason: "not_json" };
  }
}

function gatewayArgs(gatewayJs: string, name: string, original: GatewayOriginal): string[] {
  // An argument as the gateway's argv receives it — the host would have
  // stringified a number the same way.
  const text = (arg: unknown): string => (typeof arg === "string" ? arg : typeof arg === "object" ? JSON.stringify(arg) : String(arg));
  return [gatewayJs, "--server", name, "--", original.command, ...(original.args ?? []).map(text)];
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
  project?: string,
): RouteOutcome {
  const doc = readDoc(json);
  if (!doc) return { ok: false, reason: "not_json" };
  const found = locate(doc, filePath, serverName, project);
  if (!("entry" in found)) return { ok: false, ...found };
  const { entry } = found;
  if (entry[GATEWAY_MARKER]) return { ok: false, reason: "already" };
  const launch = launchHolder(entry);
  if (!launch) return { ok: false, reason: "remote_server" };
  const { holder, key } = launch;
  const original: GatewayOriginal = {
    command: holder[key] as string,
    ...(Array.isArray(holder.args) ? { args: holder.args as unknown[] } : {}),
  };
  entry[GATEWAY_MARKER] = original;
  holder[key] = nodePath;
  holder.args = gatewayArgs(gatewayJs, serverName, original);
  return edited(json, doc);
}

function markerOf(entry: Record<string, unknown>): GatewayOriginal | undefined {
  const marker = entry[GATEWAY_MARKER];
  if (!isObject(marker) || typeof marker.command !== "string") return undefined;
  return { command: marker.command, ...(Array.isArray(marker.args) ? { args: marker.args as unknown[] } : {}) };
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
  const doc = readDoc(json);
  if (!doc) return { ok: false, reason: "not_json" };
  let changed = false;
  for (const { name, entry } of eachServer(doc, filePath)) {
    const original = markerOf(entry);
    const launch = launchHolder(entry);
    if (!original || !launch) continue;
    const args = gatewayArgs(gatewayJs, name, original);
    if (launch.holder[launch.key] === nodePath && JSON.stringify(launch.holder.args) === JSON.stringify(args)) continue;
    launch.holder[launch.key] = nodePath;
    launch.holder.args = args;
    changed = true;
  }
  if (!changed) return { ok: false, reason: "already" };
  return edited(json, doc);
}

/** Undo it — restore the launch from the marker and drop the marker. */
export function restoreServer(json: string, filePath: string, serverName: string, project?: string): RouteOutcome {
  const doc = readDoc(json);
  if (!doc) return { ok: false, reason: "not_json" };
  const found = locate(doc, filePath, serverName, project);
  if (!("entry" in found)) return { ok: false, ...found };
  const { entry } = found;
  const original = markerOf(entry);
  const launch = launchHolder(entry);
  if (!original || !launch) return { ok: false, reason: "already" };
  launch.holder[launch.key] = original.command;
  if (original.args) launch.holder.args = original.args;
  else delete launch.holder.args;
  delete entry[GATEWAY_MARKER];
  return edited(json, doc);
}
