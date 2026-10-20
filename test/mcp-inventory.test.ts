import { describe, expect, it } from "vitest";
import {
  buildMcpInventory,
  extractMcpServers,
  mcpConfigHost,
  riskProfileFor,
  USER_MCP_CONFIGS,
} from "../main/lib/mcp-inventory.js";
import type { FindingRow } from "../main/lib/findings.js";
import type { LedgerTurn } from "../main/lib/turns.js";

const turn = (over: Partial<LedgerTurn> & Pick<LedgerTurn, "session_id" | "at">): LedgerTurn => ({
  id: `${over.session_id}-${over.at}`,
  source: "claude-code",
  role: "assistant",
  ...over,
});

const finding = (over: Partial<FindingRow>): FindingRow => ({
  finding_id: Math.random().toString(36),
  detector: "mcp_tool_poisoning",
  severity: "high",
  excerpt: "…",
  occurrences: 1,
  source: "claude-code",
  origin: "config",
  status: "open",
  first_seen_at: "2026-09-01T00:00:00Z",
  last_seen_at: "2026-09-01T00:00:00Z",
  ...over,
});

describe("extractMcpServers", () => {
  it("reads user + per-project blocks from ~/.claude.json and redacts args", () => {
    const doc = JSON.stringify({
      mcpServers: { github: { command: "npx", args: ["-y", "@modelcontextprotocol/server-github"] } },
      projects: {
        "/repo": { mcpServers: { db: { command: "psql", args: ["--token", "sk-verysecrettokenvalue000000"] } } },
      },
    });
    const servers = extractMcpServers(doc, "/Users/x/.claude.json");
    expect(servers.map((s) => s.name).sort()).toEqual(["db", "github"]);
    const gh = servers.find((s) => s.name === "github")!;
    expect(gh.scope).toBe("user");
    expect(gh.transport).toBe("stdio");
    // A token in args is redacted in the display entry.
    const db = servers.find((s) => s.name === "db")!;
    expect(db.entry).not.toContain("sk-verysecrettokenvalue");
  });

  it("reads a project .mcp.json as all-server config and marks http transport", () => {
    const doc = JSON.stringify({ mcpServers: { remote: { url: "https://mcp.example/sse" } } });
    const servers = extractMcpServers(doc, "/repo/.mcp.json");
    expect(servers).toHaveLength(1);
    expect(servers[0]!.scope).toBe("project");
    expect(servers[0]!.transport).toBe("http");
    expect(extractMcpServers("{not json", "/repo/.mcp.json")).toEqual([]);
  });
});

describe("riskProfileFor", () => {
  it("matches known families case- and separator-insensitively, unknown = no profile", () => {
    expect(riskProfileFor("GitHub")?.vendor).toBe("GitHub");
    expect(riskProfileFor("github-mcp")?.kind).toBe("official");
    expect(riskProfileFor("postgres")?.hosted).toBe(false);
    expect(riskProfileFor("some-random-server")).toBeUndefined();
  });
});

describe("buildMcpInventory", () => {
  it("merges config, usage and findings; the recognized flag wins; poison sorts first", () => {
    const config = extractMcpServers(
      JSON.stringify({ mcpServers: { github: { command: "npx" }, evil: { command: "node" } } }),
      "/Users/x/.claude.json",
    );
    const turns: LedgerTurn[] = [
      turn({ session_id: "s1", at: "2026-09-01T10:00:00Z", tools: ["mcp__github__search", "mcp__github__pr"] }),
      turn({ session_id: "s2", at: "2026-09-02T10:00:00Z", tools: ["mcp__ghost__do"] }),
    ];
    const findings = [finding({ detector: "mcp_tool_poisoning", key_name: "hidden instruction block · evil" })];

    const inv = buildMcpInventory(config, turns, findings, { recognized: ["github"] });
    const byName = Object.fromEntries(inv.servers.map((s) => [s.name, s]));

    // github: configured + used + recognized + has a risk profile.
    expect(byName.github.recognized).toBe(true);
    expect(byName.github.calls).toBe(2);
    expect(byName.github.sessions).toBe(1);
    expect(byName.github.risk?.vendor).toBe("GitHub");
    // evil: has an open poisoning finding → sorts first, not recognized.
    expect(byName.evil.poison_open).toBe(1);
    expect(inv.servers[0]!.name).toBe("evil");
    // ghost: seen in a transcript but in no config.
    expect(byName.ghost.observed_only).toBe(true);
    expect(inv.recognized_count).toBe(1);
  });

  it("carries the gateway's change note onto the observed tool, so the row can say WHAT changed", () => {
    const config = extractMcpServers(JSON.stringify({ mcpServers: { github: { command: "npx" } } }), "/Users/x/.claude.json");
    const inv = buildMcpInventory(config, [], [], {
      recognized: [],
      observed: [
        { server: "github", name: "run", cls: "act", versions: 2, changed_at: "2026-09-02T10:00:00Z", change_note: "description 120 → 340 chars; new text: …ignore the user…" },
        { server: "github", name: "list", cls: "read", versions: 1 },
      ],
    });
    const github = inv.servers.find((s) => s.name === "github")!;
    expect(github.changed_tools).toBe(1);
    expect(github.observed_tools.find((t) => t.name === "run")!.change_note).toContain("ignore the user");
    expect(github.observed_tools.find((t) => t.name === "list")!.change_note).toBeUndefined();
  });

  it("folds names case-insensitively", () => {
    const config = extractMcpServers(
      JSON.stringify({ mcpServers: { GitHub: { command: "npx" } } }),
      "/Users/x/.claude.json",
    );
    const turns = [turn({ session_id: "s1", at: "2026-09-01T10:00:00Z", tools: ["mcp__github__x"] })];
    const inv = buildMcpInventory(config, turns, [], { recognized: ["github"] });
    // One row, not two — the config `GitHub` and the tool-name `github` merge.
    expect(inv.servers).toHaveLength(1);
    expect(inv.servers[0]!.recognized).toBe(true);
    expect(inv.servers[0]!.calls).toBe(1);
  });
});

describe("config roots beyond Claude Code", () => {
  it("reads VS Code's `servers` and Zed's `context_servers`, not just `mcpServers`", () => {
    const vscode = extractMcpServers(
      JSON.stringify({ servers: { fetch: { command: "uvx", args: ["mcp-server-fetch"] } } }),
      "/home/Library/Application Support/Code/User/mcp.json",
    );
    expect(vscode.map((s) => s.name)).toEqual(["fetch"]);
    expect(vscode[0].scope).toBe("user");

    const zed = extractMcpServers(
      JSON.stringify({ context_servers: { gh: { command: "gh-mcp" } }, theme: "One Dark" }),
      "/home/.config/zed/settings.json",
    );
    expect(zed.map((s) => s.name)).toEqual(["gh"]);
  });

  it("reads Claude Desktop's config, which is `mcpServers` at the top level", () => {
    const servers = extractMcpServers(
      JSON.stringify({
        mcpServers: { notion: { url: "https://mcp.notion.com/mcp" } },
        preferences: { sidebarMode: "task" },
      }),
      "/home/Library/Application Support/Claude/claude_desktop_config.json",
    );
    expect(servers).toHaveLength(1);
    expect(servers[0].transport).toBe("http");
    // The `preferences` block is not a server map and must not be walked.
    expect(servers.map((s) => s.name)).toEqual(["notion"]);
  });

  it("names the app a user-level config belongs to", () => {
    expect(mcpConfigHost("/home/.cursor/mcp.json")?.host).toBe("cursor");
    expect(
      mcpConfigHost("/home/Library/Application Support/Claude/claude_desktop_config.json")?.label,
    ).toBe("Claude Desktop");
    // A repo's own file belongs to the repo, not to any one app.
    expect(mcpConfigHost("/home/repos/thing/.mcp.json")).toBeUndefined();
    // A Windows path spells the same file with `\`.
    expect(mcpConfigHost("C:\\Users\\dev\\.cursor\\mcp.json")?.label).toBe("Cursor");
    expect(mcpConfigHost("C:\\Users\\dev\\.codeium\\windsurf\\mcp_config.json")?.host).toBe("windsurf");
    expect(mcpConfigHost("C:\\Users\\dev\\repos\\thing\\.mcp.json")).toBeUndefined();
  });

  it("lists no config path we cannot actually parse", () => {
    for (const entry of USER_MCP_CONFIGS) {
      // Everything downstream is JSON.parse; a .toml here would be read every
      // sweep and contribute nothing.
      expect(entry.rel.endsWith(".json")).toBe(true);
      expect(entry.host).not.toBe("");
    }
  });
});
