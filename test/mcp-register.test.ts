import { describe, expect, it } from "vitest";

import {
  MCP_REGISTRATION_TARGETS,
  MCP_SERVER_KEY,
  isOurEntry,
  mergeRegistration,
  registrationInstalled,
  removeRegistration,
} from "../main/lib/mcp-register.js";

const SCRIPT = "/Users/dev/Library/Application Support/Doorman/doorman/mcp/doorman-mcp.js";
/** Not a bare `node`: the launcher beside the guard (lib/node-launcher.ts). */
const NODE = process.platform === "win32" ? "node" : "/Users/dev/Library/Application Support/Doorman/doorman/guard/node-runtime";
const vscode = MCP_REGISTRATION_TARGETS.find((t) => t.host === "vscode-copilot")!;
const copilot = MCP_REGISTRATION_TARGETS.find((t) => t.host === "copilot-cli")!;

/**
 * Registering Doorman's MCP server is a merge into a document the person also
 * edits (unlike the guard's own hook file), so the invariants are the gateway
 * routing's: only our key changes, foreign entries survive byte-for-byte in
 * meaning, malformed JSON is refused, and the two hosts get their own shapes.
 */
describe("MCP registration surgery", () => {
  it("knows VS Code's mcp.json and Copilot CLI's mcp-config.json, with COPILOT_HOME honoured", () => {
    expect(vscode.path("/Users/dev", {})).toBe("/Users/dev/Library/Application Support/Code/User/mcp.json");
    expect(copilot.path("/Users/dev", {})).toBe("/Users/dev/.copilot/mcp-config.json");
    expect(copilot.path("/Users/dev", { COPILOT_HOME: "/tmp/ch/" })).toBe("/tmp/ch/mcp-config.json");
    for (const t of MCP_REGISTRATION_TARGETS) expect(t.presencePaths.length).toBeGreaterThan(0);
  });

  it("writes each host its own entry shape under its own root key", () => {
    const vs = JSON.parse(mergeRegistration(undefined, vscode, SCRIPT));
    expect(vs).toEqual({ servers: { doorman: { type: "stdio", command: NODE, args: [SCRIPT] } } });
    const cli = JSON.parse(mergeRegistration(undefined, copilot, SCRIPT));
    expect(cli).toEqual({ mcpServers: { doorman: { type: "local", command: NODE, args: [SCRIPT], tools: ["*"] } } });
  });

  it("is idempotent, and re-points a stale copy of ours instead of adding a second", () => {
    const first = mergeRegistration(undefined, vscode, SCRIPT);
    expect(mergeRegistration(first, vscode, SCRIPT)).toBe(first);
    const moved = mergeRegistration(first, vscode, "/elsewhere/doorman/mcp/doorman-mcp.js");
    const doc = JSON.parse(moved);
    expect(Object.keys(doc.servers)).toEqual([MCP_SERVER_KEY]);
    expect(doc.servers.doorman.args).toEqual(["/elsewhere/doorman/mcp/doorman-mcp.js"]);
  });

  it("preserves foreign servers and unrelated keys through merge AND remove", () => {
    const before = JSON.stringify(
      {
        inputs: [{ id: "tok", type: "promptString", password: true }],
        servers: { playwright: { type: "stdio", command: "npx", args: ["@playwright/mcp"] } },
      },
      null,
      2,
    );
    const merged = mergeRegistration(before, vscode, SCRIPT);
    const doc = JSON.parse(merged);
    expect(doc.inputs).toEqual([{ id: "tok", type: "promptString", password: true }]);
    expect(doc.servers.playwright).toEqual({ type: "stdio", command: "npx", args: ["@playwright/mcp"] });
    expect(doc.servers.doorman.args).toEqual([SCRIPT]);
    const removed = removeRegistration(merged, vscode)!;
    expect(JSON.parse(removed)).toEqual(JSON.parse(before));
  });

  it("remove takes only OUR key, drops an emptied root, and reports nothing to do honestly", () => {
    const ours = mergeRegistration(undefined, copilot, SCRIPT);
    expect(JSON.parse(removeRegistration(ours, copilot)!)).toEqual({});
    expect(removeRegistration(undefined, copilot)).toBeUndefined();
    expect(removeRegistration(JSON.stringify({ mcpServers: { other: { command: "x" } } }), copilot)).toBeUndefined();
    // A user who renamed our entry keeps it: the key is not ours any more.
    const renamed = JSON.stringify({ mcpServers: { "my-doorman": { type: "local", command: "node", args: [SCRIPT] } } });
    expect(removeRegistration(renamed, copilot)).toBeUndefined();
    // …and a foreign server that happens to sit under our key is not ours either.
    const squatted = JSON.stringify({ mcpServers: { doorman: { command: "npx", args: ["something-else"] } } });
    expect(removeRegistration(squatted, copilot)).toBeUndefined();
  });

  it("recognizes and removes our entry when the script path is a Windows one", () => {
    const windows = "C:\\Users\\dev\\AppData\\Roaming\\Doorman\\doorman\\mcp\\doorman-mcp.js";
    expect(isOurEntry({ command: "node", args: [windows] })).toBe(true);
    expect(isOurEntry({ command: "node", args: ["C:\\x\\not-doorman-mcp.js"] })).toBe(false);
    const ours = mergeRegistration(undefined, copilot, windows);
    expect(JSON.parse(removeRegistration(ours, copilot)!)).toEqual({});
  });

  it("refuses a document it cannot parse rather than overwriting it", () => {
    expect(() => mergeRegistration("{ not json", vscode, SCRIPT)).toThrow(/not valid JSON/);
    expect(() => mergeRegistration("[]", vscode, SCRIPT)).toThrow(/not a JSON object/);
    expect(() => removeRegistration("{ not json", vscode)).toThrow(/not valid JSON/);
    expect(registrationInstalled("{ not json", vscode, SCRIPT)).toBe(false);
  });

  it("installed is true only for exactly this script", () => {
    const merged = mergeRegistration(undefined, copilot, SCRIPT);
    expect(registrationInstalled(merged, copilot, SCRIPT)).toBe(true);
    expect(registrationInstalled(merged, copilot, "/other/doorman-mcp.js")).toBe(false);
    expect(registrationInstalled(undefined, copilot, SCRIPT)).toBe(false);
    expect(isOurEntry({ command: "node", args: [SCRIPT] })).toBe(true);
    expect(isOurEntry({ command: "node", args: ["/x/gateway.js"] })).toBe(false);
    expect(isOurEntry(null)).toBe(false);
  });
});
