/**
 * Registering Doorman's MCP server (mcp/doorman-mcp.ts) in the hosts' MCP
 * configs — pure text surgery, one target per host document.
 *
 * Unlike a hook document (where Copilot globs a directory and we own our own
 * file), every host keeps ONE MCP config the user also edits, so this is a
 * merge into a foreign document under the same discipline as the gateway
 * routing (gateway-config.ts): parse, change exactly our entry, serialize,
 * refuse anything that does not parse. Our entry is keyed `doorman` and is
 * recognized by its script path (`…/doorman-mcp.js`), so a stale copy from an
 * older install is replaced and a user-renamed copy is left alone.
 *
 * Verified 2026-09-08 (docs + VS Code 1.136.2 / Copilot CLI 1.0.83 bundles):
 *  · VS Code: `~/Library/Application Support/Code/User/mcp.json`, root key
 *    `servers`, stdio entry `{ type: "stdio", command, args }`. First start
 *    shows "Trust and run MCP server doorman?"; `chat.mcp.access` (default
 *    `all`) gates the feature.
 *  · Copilot CLI: `~/.copilot/mcp-config.json` (or `$COPILOT_HOME/…`), root
 *    key `mcpServers`, local entry `{ type: "local", command, args, tools:
 *    ["*"] }`. Each tool call goes through the CLI's own allow prompt until
 *    the user picks Always allow. VS Code's Copilot agent host reads this
 *    file too, so the two targets overlap on purpose.
 *
 * ONE HOST IS NOT ONE DOCUMENT (2026-09-11). VS Code is a family — Insiders and
 * VSCodium keep their own user-data directory — and each of its PROFILES keeps
 * its own `mcp.json`, which VS Code resolves per resource through
 * `useDefaultFlags.mcp`. Registering only in
 * `Library/Application Support/Code/User` therefore left a person on Insiders,
 * or in any non-default profile, with a switch that read "connected" and a
 * server no agent could see. `resolveRegistrationDocuments` expands a target
 * into every document that is genuinely read on this machine; nothing is ever
 * written into a location whose owner is not installed.
 */

import { DEFAULT_VARIANT, VSCODE_VARIANTS, profiles } from "./vscode.js";

export const MCP_SERVER_KEY = "doorman";
export const MCP_SCRIPT_BASENAME = "doorman-mcp.js";

export interface McpRegistrationTarget {
  /** Shadow-AI / coverage row id this document belongs to. */
  host: string;
  label: string;
  /** Absolute path of the document for this home + env. */
  path(home: string, env: NodeJS.ProcessEnv): string;
  /** The root object that holds server entries. */
  root: "servers" | "mcpServers";
  /** Our entry for a given absolute script path. */
  entry(script: string): Record<string, unknown>;
  /** Home-relative footprints that mean the host is on this Mac. */
  presencePaths: string[];
  /**
   * Documents BEYOND `path` on this machine — a second editor build, a second
   * profile. Only paths that are genuinely read by something present are
   * returned, so registration never creates a file in a location nobody looks
   * at. The primary `path` is returned by the resolver regardless, since that
   * is the one a fresh install writes.
   */
  extra?(home: string, env: NodeJS.ProcessEnv, io: RegistrationIo): { label: string; path: string }[];
}

/** The two filesystem questions resolving documents needs. */
export interface RegistrationIo {
  exists(path: string): boolean;
  listDir(path: string): string[];
}

/** What the document-surgery helpers below actually need: a name for the error
 * message, the root key, and our entry. Both a target and a resolved document
 * satisfy it, so merge/remove/installed take either. */
export type McpDocumentShape = Pick<McpRegistrationDocument, "label" | "root" | "entry">;

/** One resolved document, which is what install/uninstall/status act on. */
export interface McpRegistrationDocument {
  host: string;
  label: string;
  path: string;
  root: "servers" | "mcpServers";
  entry(script: string): Record<string, unknown>;
}

function trimSlash(path: string): string {
  return path.replace(/\/+$/, "");
}

export const MCP_REGISTRATION_TARGETS: readonly McpRegistrationTarget[] = [
  {
    host: "vscode-copilot",
    label: "VS Code",
    path: (home) => `${trimSlash(home)}/Library/Application Support/Code/User/mcp.json`,
    root: "servers",
    entry: (script) => ({ type: "stdio", command: "node", args: [script] }),
    // The whole family, so a machine on Insiders or VSCodium is not reported
    // as having no VS Code at all (lib/vscode.ts is the canonical list).
    presencePaths: VSCODE_VARIANTS.map((v) => `${v.supportRel}/User`),
    extra: (home, _env, io) =>
      VSCODE_VARIANTS.flatMap((variant) =>
        profiles(variant, home, io)
          // The default profile of the FIRST variant is `path` above; every
          // other default profile, and every named profile, is extra. VS Code
          // resolves `mcp.json` per profile (`useDefaultFlags.mcp`), so a
          // profile that does not inherit gets no server without its own entry.
          .filter((profile) => !(variant.id === DEFAULT_VARIANT.id && profile.default))
          .map((profile) => ({
            label: profile.default ? variant.label : `${variant.label} · ${profile.id}`,
            path: `${profile.dir}/mcp.json`,
          })),
      ),
  },
  {
    host: "copilot-cli",
    label: "Copilot CLI",
    path: (home, env) => {
      const override = env.COPILOT_HOME && env.COPILOT_HOME.trim() !== "" ? trimSlash(env.COPILOT_HOME.trim()) : undefined;
      return `${override ?? `${trimSlash(home)}/.copilot`}/mcp-config.json`;
    },
    root: "mcpServers",
    entry: (script) => ({ type: "local", command: "node", args: [script], tools: ["*"] }),
    presencePaths: [".copilot"],
  },
];

/** Whether a target's host is on this Mac at all. */
export function targetPresent(target: McpRegistrationTarget, home: string, io: RegistrationIo): boolean {
  return target.presencePaths.some((rel) => io.exists(`${trimSlash(home)}/${rel}`));
}

/**
 * Every MCP document to register in on this machine, in display order. A host
 * that is not here contributes nothing; a host that is contributes its primary
 * document plus whatever `extra` found (other editor builds, other profiles).
 */
export function resolveRegistrationDocuments(
  home: string,
  env: NodeJS.ProcessEnv,
  io: RegistrationIo,
  targets: readonly McpRegistrationTarget[] = MCP_REGISTRATION_TARGETS,
  opts: { requirePresence?: boolean } = {},
): McpRegistrationDocument[] {
  const out: McpRegistrationDocument[] = [];
  const seen = new Set<string>();
  for (const target of targets) {
    if (opts.requirePresence !== false && !targetPresent(target, home, io)) continue;
    const documents = [{ label: target.label, path: target.path(home, env) }, ...(target.extra?.(home, env, io) ?? [])];
    for (const { label, path } of documents) {
      if (seen.has(path)) continue;
      seen.add(path);
      out.push({ host: target.host, label, path, root: target.root, entry: target.entry });
    }
  }
  return out;
}

function parseDocument(docText: string | undefined, label: string): Record<string, unknown> {
  if (docText === undefined || docText.trim() === "") return {};
  let parsed: unknown;
  try {
    parsed = JSON.parse(docText);
  } catch {
    throw new Error(`${label}'s MCP config is not valid JSON; not touching it`);
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error(`${label}'s MCP config is not a JSON object; not touching it`);
  }
  return parsed as Record<string, unknown>;
}

/** Is this entry ours — the Doorman MCP script, whatever path it was installed at? */
export function isOurEntry(entry: unknown): boolean {
  if (!entry || typeof entry !== "object" || Array.isArray(entry)) return false;
  const args = (entry as Record<string, unknown>).args;
  return Array.isArray(args) && args.some((a) => typeof a === "string" && a.endsWith(`/${MCP_SCRIPT_BASENAME}`));
}

function serialize(doc: Record<string, unknown>, original: string | undefined): string {
  // Two-space JSON with a trailing newline — what both hosts write themselves.
  const text = `${JSON.stringify(doc, null, 2)}\n`;
  return original !== undefined && original.trim() === JSON.stringify(doc, null, 2).trim() ? original : text;
}

/** Add or refresh our entry. Returns the same text when nothing changed. */
export function mergeRegistration(docText: string | undefined, target: McpDocumentShape, script: string): string {
  const doc = parseDocument(docText, target.label);
  const rootValue = doc[target.root];
  const root: Record<string, unknown> =
    rootValue && typeof rootValue === "object" && !Array.isArray(rootValue) ? { ...(rootValue as Record<string, unknown>) } : {};
  const desired = target.entry(script);
  const current = root[MCP_SERVER_KEY];
  if (current && JSON.stringify(current) === JSON.stringify(desired)) {
    return docText ?? serialize({ ...doc, [target.root]: root }, undefined);
  }
  // A stale copy under another key (an older install renamed by hand) is left
  // alone; only OUR key is rewritten.
  root[MCP_SERVER_KEY] = desired;
  return serialize({ ...doc, [target.root]: root }, undefined);
}

/** Remove our entry — never anyone else's. undefined when nothing of ours. */
export function removeRegistration(docText: string | undefined, target: McpDocumentShape): string | undefined {
  const doc = parseDocument(docText, target.label);
  const rootValue = doc[target.root];
  if (!rootValue || typeof rootValue !== "object" || Array.isArray(rootValue)) return undefined;
  const root = { ...(rootValue as Record<string, unknown>) };
  if (!(MCP_SERVER_KEY in root) || !isOurEntry(root[MCP_SERVER_KEY])) return undefined;
  delete root[MCP_SERVER_KEY];
  const next = { ...doc };
  if (Object.keys(root).length === 0) delete next[target.root];
  else next[target.root] = root;
  return serialize(next, undefined);
}

/** Whether the document carries our entry for exactly this script. */
export function registrationInstalled(docText: string | undefined, target: McpDocumentShape, script: string): boolean {
  let doc: Record<string, unknown>;
  try {
    doc = parseDocument(docText, target.label);
  } catch {
    return false;
  }
  const rootValue = doc[target.root];
  if (!rootValue || typeof rootValue !== "object" || Array.isArray(rootValue)) return false;
  const current = (rootValue as Record<string, unknown>)[MCP_SERVER_KEY];
  return JSON.stringify(current) === JSON.stringify(target.entry(script));
}
