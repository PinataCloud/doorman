/**
 * MCP gateway install plumbing: copy the self-contained gateway bundle into
 * userData, route/restore a server's config entry through it, and read back
 * what the running gateways observed.
 *
 * The bundle is COPIED to <userData>/doorman/gateway/ for the same reason
 * the guard is: an agent spawns it by absolute path from its own config, and
 * that path must survive app updates and the .app moving. It imports from the
 * sibling guard bundle (`../guard/`), so refreshing the gateway refreshes the
 * guard too — the two directories are one artifact. Two spools live next to
 * the code that writes them, which is where the app tails them from:
 *   observed.jsonl — every tool a routed server advertised (name, description,
 *                    schema, annotations), one line per DISTINCT description;
 *   calls.jsonl    — every `tools/call` the gateway saw, masked: tool, class,
 *                    what enforcement did, and whether the result carried an
 *                    injection.
 *
 * The config WRITE is opt-in and per-server (the "Route through gateway"
 * toggle). It is the first thing this app writes into `~/.claude.json` /
 * `.mcp.json`, so it takes the hook installer's care: parse, preserve
 * everything, refuse malformed JSON, keep a `.bak` of the previous bytes, and
 * store the original command under a marker so restore is exact.
 */

import { hookWritesAllowed, SANDBOX_READ_ONLY } from "./lib/sandbox.js";
import { copyFileSync, existsSync, mkdirSync, readFileSync, watch, writeFileSync, type FSWatcher } from "node:fs";
import { join } from "node:path";
import { refreshGuardBundle } from "./enforcement.js";
import {
  retargetGatewayRoutes,
  restoreServer,
  routeServerThroughGateway,
  type RouteOutcome,
} from "./lib/gateway-config.js";
import { scanMcpToolOutput } from "./guard/mcp-poison.js";
import { classifyTool, type McpToolClass, type ObservedTool } from "./gateway/framing.js";
import { mintFindingRow, type FindingRow } from "./lib/findings.js";
import { sanitizeExcerpt } from "./guard/security-detect.js";

/** Compiled gateway modules — the drift alarm (test/gateway) checks
 * this against the directory, same contract as GUARD_FILES. */
export const GATEWAY_FILES = ["framing.js", "mcp-gateway.js"] as const;

export function gatewayDir(userDataDir: string): string {
  return join(userDataDir, "doorman", "gateway");
}

export function gatewayScript(userDataDir: string): string {
  return join(gatewayDir(userDataDir), "mcp-gateway.js");
}

export function observedSpoolPath(userDataDir: string): string {
  return join(gatewayDir(userDataDir), "observed.jsonl");
}

export function callsSpoolPath(userDataDir: string): string {
  return join(gatewayDir(userDataDir), "calls.jsonl");
}

/** Copy the compiled gateway bundle into userData (idempotent, cheap). The
 * gateway imports the guard bundle, so that is refreshed in the same breath. */
export function refreshGatewayBundle(userDataDir: string): void {
  refreshGuardBundle(userDataDir);
  const target = gatewayDir(userDataDir);
  mkdirSync(target, { recursive: true });
  const source = join(__dirname, "gateway");
  for (const file of GATEWAY_FILES) {
    copyFileSync(join(source, file), join(target, file));
  }
}

function writeConfigWithBackup(path: string, before: string, next: string): void {
  try {
    writeFileSync(`${path}.doorman.bak`, before);
  } catch {
    // A missing backup is not worth aborting a reversible, marker-tracked edit.
  }
  if (!hookWritesAllowed()) throw new Error(SANDBOX_READ_ONLY);
  writeFileSync(path, next);
}

/** One line of observed.jsonl, as the gateway writes it. */
interface ObservedLine extends ObservedTool {
  at?: string;
  id?: string;
  server?: string;
}

function readJsonl<T>(path: string): T[] {
  let contents: string;
  try {
    contents = readFileSync(path, "utf8");
  } catch {
    return [];
  }
  const out: T[] = [];
  for (const line of contents.split("\n")) {
    const trimmed = line.trim();
    if (trimmed === "") continue;
    try {
      out.push(JSON.parse(trimmed) as T);
    } catch {
      // a torn line is the gateway mid-write
    }
  }
  return out;
}

/** What the gateways have seen of one tool: how many distinct descriptions
 * there have been, and when it last changed. */
export interface ObservedToolState {
  server: string;
  name: string;
  cls: McpToolClass;
  first_seen_at?: string;
  /** Distinct (description, schema) versions observed, oldest first. */
  versions: number;
  changed_at?: string;
  /** Present when a version change was observed: what moved, in words. */
  change_note?: string;
}

/** Fold observed.jsonl into per-tool state. A tool whose description line
 * appears under a NEW id after its first is a description that changed. */
export function foldObservedTools(userDataDir: string): Map<string, ObservedToolState> {
  return foldObservedLines(readJsonl<ObservedLine>(observedSpoolPath(userDataDir)));
}

/** The pure half of foldObservedTools, for tests. */
export function foldObservedLines(lines: readonly ObservedLine[]): Map<string, ObservedToolState> {
  const byTool = new Map<string, ObservedToolState & { _ids: string[]; _last?: ObservedLine }>();
  for (const rec of lines) {
    if (typeof rec.name !== "string") continue;
    const server = typeof rec.server === "string" && rec.server ? rec.server : "mcp";
    const key = `${server}/${rec.name}`;
    let state = byTool.get(key);
    if (!state) {
      state = { server, name: rec.name, cls: classifyTool(rec), versions: 0, _ids: [] };
      byTool.set(key, state);
    }
    state.cls = classifyTool(rec);
    if (typeof rec.at === "string" && (!state.first_seen_at || rec.at < state.first_seen_at)) state.first_seen_at = rec.at;
    const id = typeof rec.id === "string" ? rec.id : `${rec.description ?? ""}\0${rec.schema ?? ""}`;
    if (!state._ids.includes(id)) {
      if (state._ids.length > 0) {
        state.changed_at = typeof rec.at === "string" ? rec.at : new Date().toISOString();
        state.change_note = describeChange(state._last, rec);
      }
      state._ids.push(id);
      state.versions = state._ids.length;
      state._last = rec;
    }
  }
  const out = new Map<string, ObservedToolState>();
  for (const [key, entry] of byTool) {
    const { _ids: _a, _last: _b, ...state } = entry;
    out.set(key, state);
  }
  return out;
}

/** "description 120 → 340 chars; schema changed" — what a person needs to know
 * without either description being printed (they may be the payload). */
function describeChange(before: ObservedLine | undefined, after: ObservedLine): string {
  const parts: string[] = [];
  const b = before?.description ?? "";
  const a = after.description ?? "";
  if (b !== a) parts.push(`description ${b.length} → ${a.length} chars`);
  if ((before?.schema ?? "") !== (after.schema ?? "")) parts.push("input schema changed");
  if (JSON.stringify(before?.annotations ?? null) !== JSON.stringify(after.annotations ?? null)) parts.push("annotations changed");
  // The first differing stretch, masked — enough to see WHAT was added.
  let i = 0;
  while (i < b.length && i < a.length && b[i] === a[i]) i += 1;
  const added = a.slice(i, i + 120).replace(/\s+/g, " ").trim();
  if (added) parts.push(`new text: "${sanitizeExcerpt(added)}"`);
  return parts.join("; ") || "changed";
}

/**
 * Scan the gateway's observed tool descriptions for poisoning, and for the
 * mcp-scan headline case: a description that CHANGED after it was first seen
 * (a server that turned malicious after it was approved). Both are minted as
 * gateway-origin findings with no session; identity hashes server/tool so two
 * servers can't fold into one row. Whole-file re-scan on every change —
 * findings are idempotent, so no offset bookkeeping is needed.
 */
export function scanObservedTools(userDataDir: string): FindingRow[] {
  const lines = readJsonl<ObservedLine>(observedSpoolPath(userDataDir));
  const at = new Date().toISOString();
  const rows: FindingRow[] = [];
  for (const rec of lines) {
    if (typeof rec.name !== "string") continue;
    const server = typeof rec.server === "string" && rec.server ? rec.server : "mcp";
    const text = [rec.description ?? "", rec.schema ?? ""].join("\n");
    if (text.trim() === "") continue;
    for (const finding of scanMcpToolOutput(text, `${server}/${rec.name}`)) {
      rows.push(mintFindingRow(finding, { source: "claude-code", origin: "gateway", at: rec.at ?? at }));
    }
  }
  for (const state of foldObservedLines(lines).values()) {
    if (state.versions < 2 || !state.changed_at) continue;
    rows.push(
      mintFindingRow(
        {
          detector: "mcp_tool_changed",
          severity: "high",
          key_name: `${state.server}/${state.name}`,
          excerpt: `${state.server} · ${state.name} changed its description after first sight (${state.versions} versions) — ${state.change_note ?? "changed"}`,
          occurrences: state.versions - 1,
          tool_name: `mcp__${state.server}__${state.name}`,
          target: `${state.server}/${state.name}`,
        },
        { source: "claude-code", origin: "gateway", at: state.changed_at },
      ),
    );
  }
  return rows;
}

/** One line of calls.jsonl, as the gateway writes it. */
export interface GatewayCallRecord {
  at?: string;
  server?: string;
  tool?: string;
  cls?: McpToolClass;
  called_at?: string;
  is_error?: boolean;
  result_chars?: number;
  excerpt?: string;
  injection?: string[];
  blocked?: boolean;
  held?: boolean;
  unattended?: boolean;
  /** The hold machinery itself failed; `resolution` says what the policy did. */
  hold_error?: boolean;
  resolution?: string;
  /** Whether the call reached the server after an ask (2026-09-10): a refused
   * unattended ask has `forwarded: false` and `resolution: "unavailable"`. */
  forwarded?: boolean;
  decided_via?: string;
  held_at?: string;
  decided_at?: string;
  hold_ms?: number;
  reason?: string;
}

export function readGatewayCalls(userDataDir: string): GatewayCallRecord[] {
  return readJsonl<GatewayCallRecord>(callsSpoolPath(userDataDir));
}

/**
 * Findings from the gateway's call records: a result that carried an
 * injection is an `injected_instruction` (or poisoning) sighting the transcript
 * scan may also see — same detector family, masked evidence — and the
 * gateway's row is there seconds earlier and survives a transcript that
 * truncated the result.
 */
export function scanGatewayCalls(userDataDir: string): FindingRow[] {
  const rows: FindingRow[] = [];
  for (const rec of readGatewayCalls(userDataDir)) {
    if (!Array.isArray(rec.injection) || rec.injection.length === 0) continue;
    const server = rec.server ?? "mcp";
    const tool = rec.tool ?? "tool";
    for (const marker of rec.injection) {
      const detector = marker.startsWith("mcp_tool_poisoning")
        ? ("mcp_tool_poisoning" as const)
        : marker.startsWith("invisible_unicode")
          ? ("invisible_unicode" as const)
          : marker.startsWith("exfil_render_link")
            ? ("exfil_render_link" as const)
            : ("injected_instruction" as const);
      rows.push(
        mintFindingRow(
          {
            detector,
            severity: "high",
            key_name: `${server}/${tool} · ${marker}`,
            excerpt: `${server} · ${tool} returned ${marker}${rec.excerpt ? ` — ${rec.excerpt}` : ""}`.slice(0, 240),
            occurrences: 1,
            tool_name: `mcp__${server}__${tool}`,
            target: tool,
          },
          { source: "claude-code", origin: "gateway", at: rec.at ?? new Date().toISOString() },
        ),
      );
    }
  }
  return rows;
}

/**
 * Watch the gateway directory and re-scan both spools on change — the gateway
 * runs in agent processes we don't control, appending as servers advertise
 * their tools and answer calls. fs.watch where the dir exists, a slow interval
 * as backstop, debounced.
 */
export class ObservedWatcher {
  private watcher: FSWatcher | undefined;
  private timer: NodeJS.Timeout | undefined;
  private debounce: NodeJS.Timeout | undefined;

  constructor(
    private readonly deps: {
      userDataDir: string;
      onFindings(rows: FindingRow[]): void;
      /** The observed-tool fold changed — the inventory re-reads it. */
      onObserved?(tools: Map<string, ObservedToolState>): void;
      log(message: string): void;
    },
  ) {}

  private scan(): void {
    try {
      const rows = [...scanObservedTools(this.deps.userDataDir), ...scanGatewayCalls(this.deps.userDataDir)];
      if (rows.length > 0) this.deps.onFindings(rows);
      this.deps.onObserved?.(foldObservedTools(this.deps.userDataDir));
    } catch (err) {
      this.deps.log(`gateway observe scan failed: ${String(err)}`);
    }
  }

  start(): void {
    const dir = gatewayDir(this.deps.userDataDir);
    this.scan();
    if (existsSync(dir)) {
      try {
        this.watcher = watch(dir, () => {
          if (this.debounce) clearTimeout(this.debounce);
          this.debounce = setTimeout(() => this.scan(), 1_000);
        });
        this.watcher.on("error", (err) => this.deps.log(`gateway watch error: ${String(err)}`));
      } catch (err) {
        this.deps.log(`couldn't watch the gateway dir: ${String(err)}`);
      }
    }
    this.timer = setInterval(() => this.scan(), 60_000);
    this.timer.unref?.();
  }

  stop(): void {
    this.watcher?.close();
    this.watcher = undefined;
    if (this.timer) clearInterval(this.timer);
    if (this.debounce) clearTimeout(this.debounce);
  }
}

export type GatewayInstallResult =
  | { ok: true; changed: boolean }
  | { ok: false; error: string };

const REASON_TEXT: Record<Exclude<RouteOutcome & { ok: false }, { ok: true }>["reason"], string> = {
  not_json: "the config file isn't valid JSON — not touching it",
  no_such_server: "that server isn't in this config file any more",
  remote_server: "a remote (URL) MCP server has no local process to route",
  already: "already in that state",
};

/** Route `serverName` in `configPath` through the gateway. Refreshes the bundle
 * first, so the path the config points at always exists. */
export function routeServer(
  userDataDir: string,
  configPath: string,
  serverName: string,
): GatewayInstallResult {
  let before: string;
  try {
    before = readFileSync(configPath, "utf8");
  } catch (err) {
    return { ok: false, error: `couldn't read the config file: ${String(err)}` };
  }
  refreshGatewayBundle(userDataDir);
  const outcome = routeServerThroughGateway(before, configPath, serverName, gatewayScript(userDataDir));
  if (!outcome.ok) {
    return outcome.reason === "already" ? { ok: true, changed: false } : { ok: false, error: REASON_TEXT[outcome.reason] };
  }
  try {
    writeConfigWithBackup(configPath, before, outcome.json);
  } catch (err) {
    return { ok: false, error: `couldn't write the config file: ${String(err)}` };
  }
  return { ok: true, changed: true };
}

/** Rewrite every already-routed server in a config to this build's bundle. */
export function retargetGatewayConfig(userDataDir: string, configPath: string): GatewayInstallResult {
  let before: string;
  try {
    before = readFileSync(configPath, "utf8");
  } catch (err) {
    return { ok: false, error: `couldn't read the config file: ${String(err)}` };
  }
  refreshGatewayBundle(userDataDir);
  const outcome = retargetGatewayRoutes(before, configPath, gatewayScript(userDataDir));
  if (!outcome.ok) {
    return outcome.reason === "already" ? { ok: true, changed: false } : { ok: false, error: REASON_TEXT[outcome.reason] };
  }
  try {
    writeConfigWithBackup(configPath, before, outcome.json);
  } catch (err) {
    return { ok: false, error: `couldn't write the config file: ${String(err)}` };
  }
  return { ok: true, changed: true };
}

/** Undo it. */
export function unrouteServer(configPath: string, serverName: string): GatewayInstallResult {
  let before: string;
  try {
    before = readFileSync(configPath, "utf8");
  } catch (err) {
    return { ok: false, error: `couldn't read the config file: ${String(err)}` };
  }
  const outcome = restoreServer(before, configPath, serverName);
  if (!outcome.ok) {
    return outcome.reason === "already" ? { ok: true, changed: false } : { ok: false, error: REASON_TEXT[outcome.reason] };
  }
  try {
    writeConfigWithBackup(configPath, before, outcome.json);
  } catch (err) {
    return { ok: false, error: `couldn't write the config file: ${String(err)}` };
  }
  return { ok: true, changed: true };
}
