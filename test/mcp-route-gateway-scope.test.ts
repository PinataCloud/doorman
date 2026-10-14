import { describe, expect, it } from "vitest";
import { discoveredMcpConfig, type McpConfigServer } from "../main/lib/mcp-inventory.js";

/**
 * `mcp:route-gateway` rewrites the config file the renderer names. It must
 * only ever touch a config the app itself discovered holding that server —
 * never an arbitrary path a compromised renderer passes.
 */
const servers: McpConfigServer[] = [
  { name: "github", config_path: "/Users/u/.claude.json", scope: "user", transport: "stdio" },
  { name: "fs", config_path: "/repo/.mcp.json", scope: "project", transport: "stdio", gatewayed: true },
];

describe("discoveredMcpConfig", () => {
  it("accepts a (server, config) pair the watcher discovered", () => {
    expect(discoveredMcpConfig(servers, "github", "/Users/u/.claude.json")).toBe("/Users/u/.claude.json");
    expect(discoveredMcpConfig(servers, "fs", "/repo/.mcp.json")).toBe("/repo/.mcp.json");
  });

  it("refuses any other path, or a server that config does not hold", () => {
    expect(discoveredMcpConfig(servers, "github", "/Users/u/.zshrc")).toBeUndefined();
    expect(discoveredMcpConfig(servers, "github", "/Users/u/Library/Application Support/Doorman/doorman/guard/policy.json")).toBeUndefined();
    expect(discoveredMcpConfig(servers, "github", "/repo/.mcp.json")).toBeUndefined();
    expect(discoveredMcpConfig(servers, "github", "/Users/u/../u/.claude.json")).toBeUndefined();
    expect(discoveredMcpConfig(servers, 42, "/Users/u/.claude.json")).toBeUndefined();
    expect(discoveredMcpConfig(servers, "github", undefined)).toBeUndefined();
  });
});
