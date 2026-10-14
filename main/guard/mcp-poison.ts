/**
 * MCP tool poisoning — the mcp-scan attack class, ported from Invariant
 * Guardrails' corpus: an MCP server's tool DESCRIPTION (or its output) carries
 * instructions aimed at the model rather than the user — a hidden
 * `<IMPORTANT>` block telling the agent to reroute recipients, read
 * `~/.ssh/id_rsa` "for validation", or keep all of it from the user. The
 * canonical sample is a WhatsApp server's innocent-looking `get_fact_of_the_day`
 * whose description rewrites where `send_message` sends.
 *
 * What this can actually SEE, honestly: real tool descriptions live inside
 * running MCP servers and are fetched over stdio at session start — no file on
 * disk carries them. Two places the same attack text does surface locally:
 *
 *  1. MCP server CONFIG files (`~/.claude.json` mcpServers blocks, a project's
 *     `.mcp.json`) — env values, args and headers are attacker-controllable
 *     when a server entry was pasted from a README, and instruction text has
 *     no business in any of them;
 *  2. MCP tool OUTPUTS in transcripts (`mcp__*` tool_result blocks) — where a
 *     poisoned description's *behaviour* manifests, and where rug-pull servers
 *     deliver the injection itself.
 *
 * Deterministic patterns only, each named so the finding explains itself.
 * Radar-only, same mechanism as flow rules: the id is not in ALL_DETECTORS.
 * Evidence is a window around the matched PATTERN, never a whole description,
 * with invisible characters escaped visible.
 */

import { foldForMatching, type SecuritySeverity } from "./security-detect.js";

export type McpDetectorId = "mcp_tool_poisoning";

export interface McpFinding {
  detector: McpDetectorId;
  severity: SecuritySeverity;
  /** `"<pattern name> · <server or tool>"` — the ledger's identity hashes
   * detector + session + key_name, and config rows have no session, so the
   * key must carry WHO was poisoned or two servers would fold into one row. */
  key_name: string;
  /** Masked window around the match, invisible characters escaped. */
  excerpt: string;
  occurrences: number;
  /** The config path (config scans) or tool name (output scans). */
  target: string;
}

/** Window either side of a match, matching the detector file's habit. */
const CONTEXT = 70;
const EXCERPT_MAX = 240;

/** Cap what one config read scans — ~/.claude.json also stores history. */
export const MCP_CONFIG_MAX_CHARS = 512_000;

/** Same class the invisible_unicode detector reads; here it marks a config
 * string smuggling instructions invisibly. */
const INVISIBLE_RE = /[\u200B-\u200F\u2060-\u2064\u00AD\u061C\uFEFF\u202A-\u202E\u2066-\u2069\u{E0000}-\u{E007F}]/gu;

/**
 * The corpus-derived patterns. Every one is present in real poisoned tools
 * (invariant's `sample_mcp_scan_request.jsonl`, mcp-scan's write-ups) and none
 * has a legitimate reason to appear in a tool description, a config value, or
 * a tool's returned text.
 */
export const MCP_POISON_PATTERNS: ReadonlyArray<readonly [name: string, re: RegExp, sev: SecuritySeverity]> = [
  // Hidden instruction blocks aimed at the model. The negative lookahead
  // matters: Claude Code's own harness appends benign `<system-reminder>`
  // tags to tool results, and `\b` alone matches straight through the hyphen —
  // dogfooding raised 100+ rows of exactly that before this excluded `-`/word
  // continuations of the keyword.
  // A `-`/`_` continuation IS allowed (`<IMPORTANT-NOTE>`, `<SYSTEM_INSTRUCTIONS>`)
  // as long as it is not the harness's own `<system-reminder>`.
  ["hidden instruction block", /<\s*(?:IMPORTANT|SYSTEM|INSTRUCTIONS?|SECRET|HIDDEN)(?!-reminder\b)(?:[-_][\w-]{0,30})?(?!\w)[^>]{0,40}>/i, "high"],
  // Concealment: the tell that separates an attack from a quirky description.
  ["concealment instruction", /(?:do not|don['’]t|never)\s+(?:tell|inform|notify|mention|reveal|show|alert)[^.\n]{0,80}\b(?:user|human|anyone)/i, "high"],
  ["concealment instruction", /without (?:telling|informing|notifying|alerting)[^.\n]{0,40}\b(?:the )?(?:user|human)/i, "high"],
  // Instruction override.
  ["instruction override", /(?:ignore|disregard|forget)\s+(?:all\s+|any\s+)?(?:previous|prior|earlier|other|above)\s+(?:instructions|rules|prompts|tools)/i, "high"],
  // Cross-tool steering: this tool rewriting how ANOTHER tool must be called.
  ["cross-tool steering", /when(?:ever)?\s+[^.\n]{0,60}\b(?:is invoked|is called|is used)[^.\n]{0,80}\b(?:change|replace|modify|rewrite|set)\s+(?:the\s+)?(?:recipient|address|url|argument|parameter|value)/i, "high"],
  ["cross-tool steering", /instead of (?:using|calling)\s+(?:the\s+)?[\w.:-]{1,60}\s*,?\s*(?:use|call|invoke)/i, "high"],
  ["tool precondition coercion", /(?:before|whenever) (?:using|calling) (?:this|any|the) tool[^.\n]{0,80}\b(?:must|always|first|read|include)/i, "high"],
  // Exfiltration demands: prior context or sensitive files rerouted outward.
  ["history exfiltration", /(?:include|attach|append|send)[^.\n]{0,60}\b(?:full |entire |all )?(?:list of )?(?:previous|prior|last|recent) (?:messages|chats|conversation|history)/i, "high"],
  // The agents' own config files are as sensitive as a key: the corpus's `add`
  // samples coerce a read of `~/.cursor/mcp.json` (every other server's
  // credentials) as the "sidenote".
  ["sensitive path coercion", /(?:read|open|cat|access|pass|include)[^.\n]{0,60}(?:~\/\.ssh|id_rsa|\.aws\/credentials|\.env\b|private key|\.cursor\/mcp\.json|\.mcp\.json|\.claude\.json|\.claude\/settings|\.codex\/(?:config|auth))/i, "high"],
  // Coercion theatre: threats that only exist to keep the model compliant.
  ["coercion threat", /(?:the )?(?:system|application|server) (?:will|would) (?:crash|break|fail)[^.\n]{0,60}/i, "medium"],
];

/** Rewrite invisible characters as visible escapes — evidence must show them. */
function escapeInvisible(text: string): string {
  INVISIBLE_RE.lastIndex = 0;
  return text.replace(INVISIBLE_RE, (ch) => `\\u{${ch.codePointAt(0)!.toString(16).toUpperCase()}}`);
}

function collapse(text: string): string {
  return text.replace(/\s+/g, " ").trim();
}

function windowAround(text: string, start: number, end: number): string {
  const from = Math.max(0, start - CONTEXT);
  const to = Math.min(text.length, end + CONTEXT);
  const lead = from > 0 ? "…" : "";
  const tail = to < text.length ? "…" : "";
  return `${lead}${collapse(escapeInvisible(text.slice(from, to)))}${tail}`.slice(0, EXCERPT_MAX);
}

/** Run the pattern set over one string, tagging findings with `target`. */
function scanText(rawText: string, target: string): McpFinding[] {
  const found = new Map<string, McpFinding>();
  // The keyword rules run over the text as the model reads it — entities
  // decoded, lookalike letters and leetspeak folded — see foldForMatching.
  // The invisible-character rule below keeps the RAW text: folding removes
  // exactly the characters it is there to count.
  const text = foldForMatching(rawText);
  for (const [name, pattern, severity] of MCP_POISON_PATTERNS) {
    const match = pattern.exec(text);
    if (!match) continue;
    const existing = found.get(name);
    if (existing) {
      existing.occurrences += 1;
      continue;
    }
    found.set(name, {
      detector: "mcp_tool_poisoning",
      severity,
      key_name: name,
      excerpt: windowAround(text, match.index, match.index + match[0].length),
      occurrences: 1,
      target,
    });
  }
  // Invisible characters inside an MCP string: the smuggled variant of all of
  // the above. Two or more, same bar as the per-unit detector.
  INVISIBLE_RE.lastIndex = 0;
  const first = INVISIBLE_RE.exec(rawText);
  if (first && INVISIBLE_RE.exec(rawText)) {
    found.set("invisible characters", {
      detector: "mcp_tool_poisoning",
      severity: "high",
      key_name: "invisible characters",
      excerpt: windowAround(rawText, first.index, first.index + first[0].length),
      occurrences: 1,
      target,
    });
  }
  // "Coercion threat" ("the server will crash…") matches ordinary error
  // messages and docs a tool legitimately returns, so on its own it is noise —
  // in real poisoning it only appears ALONGSIDE concealment/steering/override,
  // which the other patterns catch. Keep it only as corroboration, never alone.
  if (found.has("coercion threat") && found.size === 1) found.delete("coercion threat");
  return [...found.values()];
}

/** An MCP tool's returned text (`mcp__*` tool_result). `target` names the tool. */
export function scanMcpToolOutput(text: string, toolName: string): McpFinding[] {
  return scanText(text, toolName).map((f) => ({ ...f, key_name: `${f.key_name} · ${toolName}` }));
}

/**
 * The keys different hosts park their MCP server map under. Claude Code,
 * Claude Desktop, Cursor and Windsurf all use `mcpServers`; VS Code's own
 * `mcp.json` uses `servers`; Zed uses `context_servers`. Walking a fixed list
 * (rather than "any object of objects") is what keeps the scan off the rest of
 * a document — `~/.claude.json` also stores prompt history, and a prompt SAYING
 * "ignore previous instructions" is a person talking about an attack, not a
 * poisoned server.
 */
export const MCP_SERVER_CONTAINERS = ["mcpServers", "servers", "context_servers"] as const;

/** A file whose ENTIRE content is a server map, with no container key. */
const WHOLE_DOC_IS_SERVERS = /(?:^|[\\/])\.mcp\.json$/;

/**
 * The server maps inside one parsed config document, each tagged with the
 * project path it is scoped to (`""` = user level).
 *
 * SHARED ON PURPOSE. mcp-inventory.ts reads STRUCTURE from these roots where
 * this file hunts strings, but both must agree on WHICH subtrees are server
 * config — a host added to one and not the other means a server that shows in
 * the inventory and is never scanned, or the reverse. This lives here because
 * mcp-poison.js ships inside the guard bundle (GUARD_FILES) and so may not
 * import from ../lib/; the dependency runs the other way.
 */
export function mcpServerRoots(
  doc: Record<string, unknown>,
  filePath: string,
): Array<{ projectPath: string; servers: unknown }> {
  if (WHOLE_DOC_IS_SERVERS.test(filePath)) {
    for (const key of MCP_SERVER_CONTAINERS) {
      if (doc[key]) return [{ projectPath: "", servers: doc[key] }];
    }
    return [{ projectPath: "", servers: doc }];
  }
  const roots: Array<{ projectPath: string; servers: unknown }> = [];
  for (const key of MCP_SERVER_CONTAINERS) {
    if (doc[key]) roots.push({ projectPath: "", servers: doc[key] });
  }
  const projects = doc.projects;
  if (projects && typeof projects === "object") {
    for (const [projectPath, project] of Object.entries(projects as Record<string, unknown>)) {
      const servers = (project as Record<string, unknown> | null)?.mcpServers;
      if (servers) roots.push({ projectPath, servers });
    }
  }
  return roots;
}

/**
 * Scan one MCP config document. Walks ONLY the server subtrees
 * `mcpServerRoots` identifies. Every string leaf is scanned, keyed by its
 * server name.
 */
export function scanMcpConfigText(json: string, filePath: string): McpFinding[] {
  const capped = json.length > MCP_CONFIG_MAX_CHARS ? json.slice(0, MCP_CONFIG_MAX_CHARS) : json;
  let parsed: unknown;
  try {
    parsed = JSON.parse(capped);
  } catch {
    try {
      parsed = JSON.parse(json);
    } catch {
      return []; // Not JSON (or truncated by the cap) — nothing trustworthy to walk.
    }
  }
  if (!parsed || typeof parsed !== "object") return [];
  const doc = parsed as Record<string, unknown>;

  const findings: McpFinding[] = [];
  for (const { servers } of mcpServerRoots(doc, filePath)) {
    if (!servers || typeof servers !== "object") continue;
    for (const [serverName, config] of Object.entries(servers as Record<string, unknown>)) {
      const strings: string[] = [];
      collectStrings(config, strings);
      for (const value of strings) {
        for (const finding of scanText(value, filePath)) {
          findings.push({ ...finding, key_name: `${finding.key_name} · ${serverName}` });
        }
      }
    }
  }
  return findings;
}

function collectStrings(value: unknown, out: string[], depth = 0): void {
  if (depth > 6 || out.length > 500) return;
  if (typeof value === "string") {
    if (value.length > 2) out.push(value);
    return;
  }
  if (Array.isArray(value)) {
    for (const item of value) collectStrings(item, out, depth + 1);
    return;
  }
  if (value && typeof value === "object") {
    for (const item of Object.values(value as Record<string, unknown>)) {
      collectStrings(item, out, depth + 1);
    }
  }
}
