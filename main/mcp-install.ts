/**
 * Installing Doorman's MCP server (mcp/doorman-mcp.ts): copy the compiled
 * module next to the guard bundle, then register it in every MCP-capable
 * host's config (lib/mcp-register.ts) — VS Code's Copilot agent mode and the
 * Copilot CLI to start. Driven by the `mcp_answers` preference: on → bundle
 * refreshed and every present host registered (idempotent, re-run on boot so
 * a moved userData or an upgraded script is re-pointed); off → our entry
 * removed from each document, nothing else touched.
 *
 * Write discipline (lib/config-file.ts): a config that exists but can't be
 * read is refused, never treated as absent; the edit is byte-preserving; the
 * pre-Doorman original is kept once as `<config>.doorman.bak` with the
 * original's mode; symlinks are written through and read-only files refused;
 * malformed JSON is refused rather than overwritten; and nothing is written in
 * a sandboxed run (lib/sandbox.ts hookWritesAllowed).
 *
 * Uninstall gives the original back: when the document, minus our entry,
 * reads the same as the kept original, the original's exact bytes are
 * restored (and the backup, now redundant, removed); a file Doorman created
 * and left holding nothing is deleted.
 */

import { copyFileSync, existsSync, mkdirSync, readdirSync, statSync } from "node:fs";
import { dirname, join } from "node:path";
import { refreshGuardBundle } from "./enforcement.js";
import { jsonEqual, parseJsonc } from "./guard/jsonc.js";
import { backupOnce, readBackup, readConfigFile, removeBackup, removeConfigFile, writeConfigFile, type ConfigRead } from "./lib/config-file.js";
import {
  MCP_SCRIPT_BASENAME,
  documentProblem,
  mergeRegistration,
  registeredKey,
  removeRegistration,
  resolveRegistrationDocuments,
  type McpRegistrationDocument,
  type RegistrationIo,
} from "./lib/mcp-register.js";
import { hookWritesAllowed, SANDBOX_READ_ONLY } from "./lib/sandbox.js";

/** The filesystem the document resolver asks about editor builds and profiles. */
const REGISTRATION_IO: RegistrationIo = {
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
};

/** Compiled MCP server modules — the drift alarm (test/mcp-server)
 * checks this against the directory, same contract as GATEWAY_FILES. */
export const MCP_FILES = [MCP_SCRIPT_BASENAME] as const;

export function mcpDir(userDataDir: string): string {
  return join(userDataDir, "doorman", "mcp");
}

export function mcpScript(userDataDir: string): string {
  return join(mcpDir(userDataDir), MCP_SCRIPT_BASENAME);
}

/** Copy the compiled server into userData (idempotent, cheap). It imports the
 * sibling guard bundle, so that is refreshed in the same breath. */
export function refreshMcpBundle(userDataDir: string): void {
  refreshGuardBundle(userDataDir);
  const target = mcpDir(userDataDir);
  mkdirSync(target, { recursive: true });
  const source = join(__dirname, "mcp");
  for (const file of MCP_FILES) {
    copyFileSync(join(source, file), join(target, file));
  }
}

export interface McpHostStatus {
  host: string;
  label: string;
  /** The MCP config document for this host. */
  path: string;
  /** The host itself is on this Mac (its footprint exists). */
  present: boolean;
  /** Our entry is in the document, pointing at this install's script. */
  registered: boolean;
  /** The server name our entry sits under (`doorman`, or the person's own
   * name for a renamed copy). Only when registered. */
  key?: string;
  /** The document exists but can't be read or parsed — we refuse to touch it. */
  unreadable?: boolean;
  /** Why, when unreadable. */
  problem?: string;
}

export interface McpInstallOutcome {
  ok: boolean;
  /** Every failure, one sentence per document, newline-separated. */
  error?: string;
  /** The same failures, one per document. */
  errors?: string[];
  hosts: McpHostStatus[];
}

function statusOf(document: McpRegistrationDocument, userDataDir: string): McpHostStatus {
  let read: ConfigRead;
  let problem: string | undefined;
  try {
    read = readConfigFile(document.path, `${document.label}'s MCP config`);
    problem = read.exists ? documentProblem(read.text, document) : undefined;
  } catch (err) {
    read = { exists: false };
    problem = err instanceof Error ? err.message : String(err);
  }
  const key = read.exists ? registeredKey(read.text, document, mcpScript(userDataDir)) : undefined;
  return {
    host: document.host,
    label: document.label,
    path: document.path,
    // Resolution already required the host to be here, so a returned document
    // is by construction one something on this Mac reads.
    present: true,
    registered: key !== undefined,
    ...(key === undefined ? {} : { key }),
    ...(problem === undefined ? {} : { unreadable: true, problem }),
  };
}

/** Per document: is our server registered in it? One row per editor build and
 * profile, not one per product — see resolveRegistrationDocuments. */
export function mcpServerStatus(userDataDir: string, home: string, env: NodeJS.ProcessEnv = process.env): McpHostStatus[] {
  return resolveRegistrationDocuments(home, env, REGISTRATION_IO).map((d) => statusOf(d, userDataDir));
}

function outcome(errors: string[], userDataDir: string, home: string, env: NodeJS.ProcessEnv): McpInstallOutcome {
  return {
    ok: errors.length === 0,
    ...(errors.length > 0 ? { error: errors.join("\n"), errors } : {}),
    hosts: mcpServerStatus(userDataDir, home, env),
  };
}

/** Register the server with every host present on this Mac. A host whose
 * document we cannot read, parse or safely edit is reported and skipped; the
 * others still land. */
export function installMcpServer(userDataDir: string, home: string, env: NodeJS.ProcessEnv = process.env): McpInstallOutcome {
  if (!hookWritesAllowed(env, home)) return outcome([SANDBOX_READ_ONLY], userDataDir, home, env);
  refreshMcpBundle(userDataDir);
  const script = mcpScript(userDataDir);
  const errors: string[] = [];
  for (const document of resolveRegistrationDocuments(home, env, REGISTRATION_IO)) {
    try {
      if (!hookWritesAllowed(env, document.path)) throw new Error(SANDBOX_READ_ONLY);
      const label = `${document.label}'s MCP config`;
      const before = readConfigFile(document.path, label);
      const next = mergeRegistration(before.exists ? before.text : undefined, document, script);
      if (before.exists && next === before.text) continue;
      if (before.exists) backupOnce(document.path, before.text, before.mode);
      else mkdirSync(dirname(document.path), { recursive: true });
      writeConfigFile(document.path, next, label);
    } catch (err) {
      errors.push(err instanceof Error ? err.message : String(err));
    }
  }
  return outcome(errors, userDataDir, home, env);
}

/** The value a document's text reads as, `{}` for a blank one; undefined
 * when it doesn't parse. */
function valueOf(text: string): Record<string, unknown> | undefined {
  return text.trim() === "" ? {} : parseJsonc(text);
}

/** Remove our entry from every host document that carries it. */
export function uninstallMcpServer(userDataDir: string, home: string, env: NodeJS.ProcessEnv = process.env): McpInstallOutcome {
  if (!hookWritesAllowed(env, home)) return outcome([SANDBOX_READ_ONLY], userDataDir, home, env);
  const errors: string[] = [];
  // `requirePresence: false` — taking our entry OUT must reach a document whose
  // owner this app can no longer see (an editor uninstalled since we wrote to
  // it, a profile deleted from the app but still on disk). A document that
  // isn't there is skipped by the read below anyway.
  for (const document of resolveRegistrationDocuments(home, env, REGISTRATION_IO, undefined, { requirePresence: false })) {
    try {
      const label = `${document.label}'s MCP config`;
      const before = readConfigFile(document.path, label);
      if (!before.exists) continue;
      const next = removeRegistration(before.text, document);
      if (next === undefined) continue;
      if (!hookWritesAllowed(env, document.path)) throw new Error(SANDBOX_READ_ONLY);
      const original = readBackup(document.path);
      const nextValue = valueOf(next);
      const originalValue = original === undefined ? undefined : valueOf(original);
      // Removal drops a container our entry emptied; the original may have
      // had it empty already (`"mcpServers": {}`), which still counts as same.
      const same =
        nextValue !== undefined &&
        originalValue !== undefined &&
        (jsonEqual(nextValue, originalValue) || (!(document.root in nextValue) && jsonEqual({ ...nextValue, [document.root]: {} }, originalValue)));
      if (original !== undefined && same) {
        // Nothing but our entry changed since Doorman's first edit: the
        // original's own bytes, not a re-rendering of them.
        writeConfigFile(document.path, original, label);
        removeBackup(document.path);
      } else if (original === undefined && next.replace(/\s/g, "") === "{}") {
        // No original was kept because there was no file: Doorman made it.
        removeConfigFile(document.path, label);
      } else {
        writeConfigFile(document.path, next, label);
      }
    } catch (err) {
      errors.push(err instanceof Error ? err.message : String(err));
    }
  }
  return outcome(errors, userDataDir, home, env);
}

/** The prefs the `mcp_answers` switch reads and writes. */
export interface McpAnswersPrefs {
  get(): { mcp_recognized?: string[]; mcp_recognized_at?: Record<string, string> };
  set(patch: { mcp_recognized: string[]; mcp_recognized_at: Record<string, string> }): void;
}

/** The `mcp_answers` switch moved: register the server with every MCP-capable
 * host present, or take our entry back out. Our own server is recognized —
 * under every name it is registered as — as soon as it is in ANY host's config
 * (one failing host must not leave the others listing an unknown `doorman`),
 * so the inventory never reports it as an MCP server nobody approved. Shared
 * by the app (index.ts applyMcpAnswers) and the CLI. */
export function switchMcpAnswers(
  enabled: boolean,
  userDataDir: string,
  home: string,
  prefs: McpAnswersPrefs,
  env: NodeJS.ProcessEnv = process.env,
): McpInstallOutcome {
  const result = enabled ? installMcpServer(userDataDir, home, env) : uninstallMcpServer(userDataDir, home, env);
  if (!enabled) return result;
  const keys = [...new Set(result.hosts.flatMap((h) => (h.key === undefined ? [] : [h.key.normalize("NFC")])))];
  const current = prefs.get().mcp_recognized ?? [];
  const missing = keys.filter((key) => !current.some((name) => name.normalize("NFC").toLowerCase() === key.toLowerCase()));
  if (missing.length > 0) {
    const at = new Date().toISOString();
    prefs.set({
      mcp_recognized: [...current, ...missing],
      mcp_recognized_at: { ...(prefs.get().mcp_recognized_at ?? {}), ...Object.fromEntries(missing.map((key) => [key, at])) },
    });
  }
  return result;
}
