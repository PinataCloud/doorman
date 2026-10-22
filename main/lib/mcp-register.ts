/**
 * Registering Doorman's MCP server (mcp/doorman-mcp.ts) in the hosts' MCP
 * configs — pure text surgery, one target per host document.
 *
 * Unlike a hook document (where Copilot globs a directory and we own our own
 * file), every host keeps ONE MCP config the user also edits, so this is a
 * merge into a foreign document under the same discipline as the gateway
 * routing (gateway-config.ts): parse, change exactly our entry, refuse
 * anything that does not parse. The edit is BYTE-PRESERVING (guard/jsonc.ts
 * editJsonc): comments, indentation, key order and every other server stay
 * exactly as written, so install-then-uninstall gives back the same bytes.
 *
 * WHICH ENTRY IS OURS (2026-10-21). An entry is ours when it runs the Doorman
 * MCP script (`…/doorman-mcp.js`, isOurEntry) — whatever key it sits under.
 *  · A server of the person's own that happens to be called `doorman` is NOT
 *    ours: registration refuses that document and says how to resolve it
 *    (rename that server). It is never overwritten, and never removed.
 *  · A renamed copy of ours that runs THIS install's script counts as the
 *    registration (no second `doorman` is added beside it); a renamed copy
 *    pointing at an older install's script is dead and is dropped when the
 *    live entry is written. Uninstall takes out every entry of ours.
 *  · Fields the person added to our entry (`env`, `cwd`, …) are kept: only the
 *    fields we write are compared and refreshed, in any key order.
 *  · A server container that isn't an object (`"mcpServers": [...]`) is
 *    refused, like a root that isn't one.
 *
 * Verified 2026-09-08 (docs + VS Code 1.136.2 / Copilot CLI 1.0.83 bundles):
 *  · VS Code: `<user data>/User/mcp.json` (`~/Library/Application Support/Code`
 *    on macOS, `%APPDATA%\Code` on Windows, `~/.config/Code` on Linux), root key
 *    `servers`, stdio entry `{ type: "stdio", command, args }`. First start
 *    shows "Trust and run MCP server doorman?"; `chat.mcp.access` (default
 *    `all`) gates the feature. VS Code reads the file as JSONC — comments and
 *    trailing commas are normal there, and so accepted here.
 *  · Copilot CLI: `~/.copilot/mcp-config.json` (or `$COPILOT_HOME/…`), root
 *    key `mcpServers`, local entry `{ type: "local", command, args, tools:
 *    ["*"] }`. Each tool call goes through the CLI's own allow prompt until
 *    the user picks Always allow. VS Code's Copilot agent host reads this
 *    file too, so the two targets overlap on purpose. Strict JSON.
 *
 * ONE HOST IS NOT ONE DOCUMENT (2026-09-11). VS Code is a family — Insiders and
 * VSCodium keep their own user-data directory — and each of its PROFILES keeps
 * its own `mcp.json`, which VS Code resolves per resource through
 * `useDefaultFlags.mcp`. Registering only in
 * `Library/Application Support/Code/User` therefore left a person on Insiders,
 * or in any non-default profile, with a switch that read "connected" and a
 * server no agent could see. `resolveRegistrationDocuments` expands a target
 * into every document that is genuinely read on this machine; nothing is ever
 * written into a location whose owner is not installed (a machine with only
 * Insiders gets no stable `Code/User/mcp.json`).
 */

import { join } from "node:path";
import { editJsonc, isPlainObject, jsonEqual, readHostJson, type JsoncDialect } from "../guard/jsonc.js";
import { nodeProgramForScript } from "./node-launcher.js";
import { VSCODE_VARIANTS, profiles, userDir } from "./vscode.js";

export const MCP_SERVER_KEY = "doorman";
export const MCP_SCRIPT_BASENAME = "doorman-mcp.js";

/** The filesystem questions resolving documents needs. `isDir` tells a
 * profile folder from a stray file; absent, dot-entries are still skipped. */
export interface RegistrationIo {
  exists(path: string): boolean;
  listDir(path: string): string[];
  isDir?(path: string): boolean;
}

export interface McpRegistrationTarget {
  /** Shadow-AI / coverage row id this document belongs to. */
  host: string;
  label: string;
  /** The root object that holds server entries. */
  root: "servers" | "mcpServers";
  /** Our entry for a given absolute script path. */
  entry(script: string): Record<string, unknown>;
  /** What the host's own parser accepts beyond strict JSON; absent = strict. */
  dialect?: JsoncDialect;
  /** Whether the host is on this machine at all. */
  present(home: string, env: NodeJS.ProcessEnv, io: RegistrationIo): boolean;
  /**
   * The documents this host reads here, in display order. `all` adds the ones
   * nothing present reads any more (an editor build uninstalled since), so
   * taking our entry OUT reaches them too.
   */
  documents(home: string, env: NodeJS.ProcessEnv, io: RegistrationIo, all: boolean): { label: string; path: string }[];
}

/** What the document-surgery helpers below actually need: a name for the error
 * message, the root key, our entry and the dialect. Both a target and a
 * resolved document satisfy it. */
export type McpDocumentShape = Pick<McpRegistrationDocument, "label" | "root" | "entry" | "dialect">;

/** One resolved document, which is what install/uninstall/status act on. */
export interface McpRegistrationDocument {
  host: string;
  label: string;
  path: string;
  root: "servers" | "mcpServers";
  entry(script: string): Record<string, unknown>;
  dialect?: JsoncDialect;
}

/** `$COPILOT_HOME`, or `~/.copilot`. A trailing separator (either kind — a
 * Windows `D:\cp\`) is dropped before the file name is joined on. */
export function copilotHome(home: string, env: NodeJS.ProcessEnv): string {
  const override = env.COPILOT_HOME?.trim();
  return override ? override.replace(/(?<=.)[\\/]+$/, "") : join(home, ".copilot");
}

/** Copilot CLI's user-level MCP config. */
export function copilotMcpConfigPath(home: string, env: NodeJS.ProcessEnv): string {
  return join(copilotHome(home, env), "mcp-config.json");
}

export const MCP_REGISTRATION_TARGETS: readonly McpRegistrationTarget[] = [
  {
    host: "vscode-copilot",
    label: "VS Code",
    root: "servers",
    entry: (script) => ({ type: "stdio", command: nodeProgramForScript(script), args: [script] }),
    dialect: { trailingCommas: true },
    // The whole family, so a machine on Insiders or VSCodium is not reported
    // as having no VS Code at all (lib/vscode.ts is the canonical list).
    present: (home, _env, io) => VSCODE_VARIANTS.some((v) => io.exists(userDir(v, home))),
    // Every profile of every build that is HERE — the default profile and each
    // named one. VS Code resolves `mcp.json` per profile
    // (`useDefaultFlags.mcp`), so a profile that does not inherit gets no server
    // without its own entry. A build that isn't here contributes nothing.
    documents: (home, _env, io, all) =>
      VSCODE_VARIANTS.flatMap((variant) => {
        const found = profiles(variant, home, io).map((profile) => ({
          label: profile.default ? variant.label : `${variant.label} · ${profile.id}`,
          path: join(profile.dir, "mcp.json"),
        }));
        return found.length === 0 && all ? [{ label: variant.label, path: join(userDir(variant, home), "mcp.json") }] : found;
      }),
  },
  {
    host: "copilot-cli",
    label: "Copilot CLI",
    root: "mcpServers",
    entry: (script) => ({ type: "local", command: nodeProgramForScript(script), args: [script], tools: ["*"] }),
    present: (home, env, io) => io.exists(copilotHome(home, env)),
    documents: (home, env) => [{ label: "Copilot CLI", path: copilotMcpConfigPath(home, env) }],
  },
];

/**
 * Every MCP document to register in on this machine, in display order. A host
 * that is not here contributes nothing (unless `requirePresence: false`, for
 * uninstall); a host that is contributes every document it reads.
 */
export function resolveRegistrationDocuments(
  home: string,
  env: NodeJS.ProcessEnv,
  io: RegistrationIo,
  targets: readonly McpRegistrationTarget[] = MCP_REGISTRATION_TARGETS,
  opts: { requirePresence?: boolean } = {},
): McpRegistrationDocument[] {
  const all = opts.requirePresence === false;
  const out: McpRegistrationDocument[] = [];
  const seen = new Set<string>();
  for (const target of targets) {
    if (!all && !target.present(home, env, io)) continue;
    for (const { label, path } of target.documents(home, env, io, all)) {
      if (seen.has(path)) continue;
      seen.add(path);
      out.push({ host: target.host, label, path, root: target.root, entry: target.entry, ...(target.dialect ? { dialect: target.dialect } : {}) });
    }
  }
  return out;
}

const STRICT: JsoncDialect = { trailingCommas: false };

/** The document as an object; undefined for a blank one. Throws a refusal for
 * a document the host itself couldn't read, or whose root isn't an object. */
function parseDocument(docText: string | undefined, shape: McpDocumentShape): Record<string, unknown> | undefined {
  if (docText === undefined || docText.trim() === "") return undefined;
  const value = readHostJson(docText, shape.dialect, `${shape.label}'s MCP config`);
  if (!isPlainObject(value)) throw new Error(`${shape.label}'s MCP config is not a JSON object; not touching it`);
  return value;
}

/** The server container, undefined when absent. Throws for one that is there
 * but isn't an object of servers — replacing it would delete the person's
 * servers. */
function serverMap(doc: Record<string, unknown>, shape: McpDocumentShape): Record<string, unknown> | undefined {
  const value = doc[shape.root];
  if (value === undefined) return undefined;
  if (isPlainObject(value)) return value;
  const kind = Array.isArray(value) ? "a list" : value === null ? "null" : `a ${typeof value}`;
  throw new Error(`${shape.label}'s MCP config has "${shape.root}" as ${kind}, not an object of servers; not touching it`);
}

/** Why this document can't be registered in, or undefined when it can. */
export function documentProblem(docText: string | undefined, shape: McpDocumentShape): string | undefined {
  try {
    const doc = parseDocument(docText, shape);
    if (doc) serverMap(doc, shape);
    return undefined;
  } catch (err) {
    return err instanceof Error ? err.message : String(err);
  }
}

/** Is this entry ours — the Doorman MCP script, whatever path it was installed
 * at? On Windows that path is written with `\`. */
export function isOurEntry(entry: unknown): boolean {
  if (!isPlainObject(entry)) return false;
  const args = entry.args;
  return Array.isArray(args) && args.some((a) => typeof a === "string" && a.replace(/\\/g, "/").endsWith(`/${MCP_SCRIPT_BASENAME}`));
}

/** Our entry for exactly this script: every field WE write matches, in any
 * key order; fields the person added are theirs. */
function entryCurrent(entry: unknown, desired: Record<string, unknown>): boolean {
  return isPlainObject(entry) && Object.entries(desired).every(([key, value]) => jsonEqual(entry[key], value));
}

/** The edit, byte-preserving. */
function edit(docText: string, next: Record<string, unknown>, shape: McpDocumentShape): string {
  try {
    return editJsonc(docText, next, shape.dialect ?? STRICT);
  } catch {
    throw new Error(`${shape.label}'s MCP config couldn't be edited without disturbing the rest of it; not touching it`);
  }
}

/** Add or refresh our entry. Returns the same text when nothing changed. */
export function mergeRegistration(docText: string | undefined, target: McpDocumentShape, script: string): string {
  const desired = target.entry(script);
  const doc = parseDocument(docText, target);
  if (!doc || docText === undefined) return `${JSON.stringify({ [target.root]: { [MCP_SERVER_KEY]: desired } }, null, 2)}\n`;
  const servers = serverMap(doc, target) ?? {};
  const ours = Object.keys(servers).filter((key) => isOurEntry(servers[key]));
  // Under `doorman` when that is ours; else a renamed copy already running
  // this script (the person's name for it); else a fresh `doorman`.
  const keep = ours.includes(MCP_SERVER_KEY) ? MCP_SERVER_KEY : (ours.find((key) => entryCurrent(servers[key], desired)) ?? MCP_SERVER_KEY);
  if (keep === MCP_SERVER_KEY && MCP_SERVER_KEY in servers && !ours.includes(MCP_SERVER_KEY)) {
    throw new Error(
      `${target.label}'s MCP config already has a server named "${MCP_SERVER_KEY}" that isn't Doorman's; not touching it. Rename that server (any other name), then try again.`,
    );
  }
  const next: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(servers)) {
    if (key === keep) next[key] = isPlainObject(value) ? { ...value, ...desired } : desired;
    else if (!ours.includes(key)) next[key] = value; // a stale copy of ours goes
  }
  if (!(keep in next)) next[keep] = desired;
  return edit(docText, { ...doc, [target.root]: next }, target);
}

/** Remove every entry of ours — never anyone else's. undefined when the
 * document holds nothing of ours. An emptied container is dropped. */
export function removeRegistration(docText: string | undefined, target: McpDocumentShape): string | undefined {
  const doc = parseDocument(docText, target);
  if (!doc || docText === undefined) return undefined;
  const servers = doc[target.root];
  if (!isPlainObject(servers)) return undefined;
  const kept = Object.entries(servers).filter(([, value]) => !isOurEntry(value));
  if (kept.length === Object.keys(servers).length) return undefined;
  const next = { ...doc };
  if (kept.length === 0) delete next[target.root];
  else next[target.root] = Object.fromEntries(kept);
  return edit(docText, next, target);
}

/** The key our entry for exactly this script sits under, if any. */
export function registeredKey(docText: string | undefined, target: McpDocumentShape, script: string): string | undefined {
  let servers: Record<string, unknown> | undefined;
  try {
    const doc = parseDocument(docText, target);
    servers = doc && serverMap(doc, target);
  } catch {
    return undefined;
  }
  if (!servers) return undefined;
  const desired = target.entry(script);
  const keys = Object.keys(servers).filter((key) => isOurEntry(servers[key]) && entryCurrent(servers[key], desired));
  return keys.includes(MCP_SERVER_KEY) ? MCP_SERVER_KEY : keys[0];
}

/** Whether the document carries our entry for exactly this script. */
export function registrationInstalled(docText: string | undefined, target: McpDocumentShape, script: string): boolean {
  return registeredKey(docText, target, script) !== undefined;
}
