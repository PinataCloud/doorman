/**
 * Installing Doorman's MCP server (mcp/doorman-mcp.ts): copy the compiled
 * module next to the guard bundle, then register it in every MCP-capable
 * host's config (lib/mcp-register.ts) — VS Code's Copilot agent mode and the
 * Copilot CLI to start. Driven by the `mcp_answers` preference: on → bundle
 * refreshed and every present host registered (idempotent, re-run on boot so
 * a moved userData or an upgraded script is re-pointed); off → our entry
 * removed from each document, nothing else touched.
 *
 * Same write discipline as the guard's hook documents and the gateway routes:
 * a backup of the previous text, an atomic rename into place, malformed JSON
 * refused rather than overwritten, and no write at all in a sandboxed run
 * (lib/sandbox.ts hookWritesAllowed).
 */

import { copyFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { refreshGuardBundle, writeDocumentAtomically } from "./enforcement.js";
import { readdirSync } from "node:fs";
import {
  MCP_SCRIPT_BASENAME,
  mergeRegistration,
  registrationInstalled,
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
  /** The document exists but cannot be parsed — we refuse to touch it. */
  unreadable?: boolean;
}

export interface McpInstallOutcome {
  ok: boolean;
  error?: string;
  hosts: McpHostStatus[];
}

function readDoc(path: string): string | undefined {
  try {
    return existsSync(path) ? readFileSync(path, "utf8") : undefined;
  } catch {
    return undefined;
  }
}

function statusOf(document: McpRegistrationDocument, userDataDir: string): McpHostStatus {
  const doc = readDoc(document.path);
  let unreadable = false;
  if (doc !== undefined && doc.trim() !== "") {
    try {
      const parsed = JSON.parse(doc);
      unreadable = !parsed || typeof parsed !== "object" || Array.isArray(parsed);
    } catch {
      unreadable = true;
    }
  }
  return {
    host: document.host,
    label: document.label,
    path: document.path,
    // Resolution already required the host to be here, so a returned document
    // is by construction one something on this Mac reads.
    present: true,
    registered: registrationInstalled(doc, document, mcpScript(userDataDir)),
    ...(unreadable ? { unreadable: true } : {}),
  };
}

/** Per document: is our server registered in it? One row per editor build and
 * profile, not one per product — see resolveRegistrationDocuments. */
export function mcpServerStatus(userDataDir: string, home: string, env: NodeJS.ProcessEnv = process.env): McpHostStatus[] {
  return resolveRegistrationDocuments(home, env, REGISTRATION_IO).map((d) => statusOf(d, userDataDir));
}

function writeWithBackup(path: string, before: string | undefined, next: string): void {
  mkdirSync(join(path, ".."), { recursive: true });
  if (before !== undefined) {
    try {
      writeFileSync(`${path}.doorman.bak`, before);
    } catch {
      // best effort — the atomic write below is what matters
    }
  }
  writeDocumentAtomically(path, next);
}

/** Register the server with every host present on this Mac. A host whose
 * document we cannot parse is reported and skipped; the others still land. */
export function installMcpServer(userDataDir: string, home: string, env: NodeJS.ProcessEnv = process.env): McpInstallOutcome {
  if (!hookWritesAllowed(env)) return { ok: false, error: SANDBOX_READ_ONLY, hosts: mcpServerStatus(userDataDir, home, env) };
  refreshMcpBundle(userDataDir);
  const script = mcpScript(userDataDir);
  const errors: string[] = [];
  for (const document of resolveRegistrationDocuments(home, env, REGISTRATION_IO)) {
    const before = readDoc(document.path);
    try {
      const next = mergeRegistration(before, document, script);
      if (next !== before) writeWithBackup(document.path, before, next);
    } catch (err) {
      errors.push(err instanceof Error ? err.message : String(err));
    }
  }
  return {
    ok: errors.length === 0,
    ...(errors.length > 0 ? { error: errors.join(" ") } : {}),
    hosts: mcpServerStatus(userDataDir, home, env),
  };
}

/** Remove our entry from every host document that carries it. */
export function uninstallMcpServer(userDataDir: string, home: string, env: NodeJS.ProcessEnv = process.env): McpInstallOutcome {
  if (!hookWritesAllowed(env)) return { ok: false, error: SANDBOX_READ_ONLY, hosts: mcpServerStatus(userDataDir, home, env) };
  const errors: string[] = [];
  // `requirePresence: false` — taking our entry OUT must reach a document whose
  // owner this app can no longer see (an editor uninstalled since we wrote to
  // it, a profile deleted from the app but still on disk). A document that
  // isn't there is skipped by the read below anyway.
  for (const document of resolveRegistrationDocuments(home, env, REGISTRATION_IO, undefined, { requirePresence: false })) {
    const before = readDoc(document.path);
    if (before === undefined) continue;
    try {
      const next = removeRegistration(before, document);
      if (next !== undefined) writeWithBackup(document.path, before, next);
    } catch (err) {
      errors.push(err instanceof Error ? err.message : String(err));
    }
  }
  return {
    ok: errors.length === 0,
    ...(errors.length > 0 ? { error: errors.join(" ") } : {}),
    hosts: mcpServerStatus(userDataDir, home, env),
  };
}

/** The prefs the `mcp_answers` switch reads and writes. */
export interface McpAnswersPrefs {
  get(): { mcp_recognized?: string[]; mcp_recognized_at?: Record<string, string> };
  set(patch: { mcp_recognized: string[]; mcp_recognized_at: Record<string, string> }): void;
}

/** The `mcp_answers` switch moved: register the server with every MCP-capable
 * host present, or take our entry back out. Our own server is recognized in
 * the same breath, so the inventory never reports it as an MCP server nobody
 * approved. Shared by the app (index.ts applyMcpAnswers) and the CLI. */
export function switchMcpAnswers(
  enabled: boolean,
  userDataDir: string,
  home: string,
  prefs: McpAnswersPrefs,
  env: NodeJS.ProcessEnv = process.env,
): McpInstallOutcome {
  const outcome = enabled ? installMcpServer(userDataDir, home, env) : uninstallMcpServer(userDataDir, home, env);
  if (enabled && outcome.ok) {
    const current = prefs.get().mcp_recognized ?? [];
    if (!current.includes("doorman")) {
      prefs.set({
        mcp_recognized: [...current, "doorman"],
        mcp_recognized_at: { ...(prefs.get().mcp_recognized_at ?? {}), doorman: new Date().toISOString() },
      });
    }
  }
  return outcome;
}
