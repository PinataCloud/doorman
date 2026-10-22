import { join } from "node:path";
import { describe, expect, it } from "vitest";

import {
  MCP_REGISTRATION_TARGETS,
  MCP_SERVER_KEY,
  copilotMcpConfigPath,
  documentProblem,
  isOurEntry,
  mergeRegistration,
  registeredKey,
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
  it("knows Copilot CLI's mcp-config.json, with COPILOT_HOME honoured (either trailing separator)", () => {
    expect(copilotMcpConfigPath("/Users/dev", {})).toBe(join("/Users/dev", ".copilot", "mcp-config.json"));
    expect(copilotMcpConfigPath("/Users/dev", { COPILOT_HOME: "/tmp/ch/" })).toBe(join("/tmp/ch", "mcp-config.json"));
    // A Windows `D:\cp\` must not come out as `D:\cp\/mcp-config.json`.
    expect(copilotMcpConfigPath("/Users/dev", { COPILOT_HOME: "D:\\cp\\" })).not.toMatch(/\\[\\/]mcp-config/);
    expect(copilotMcpConfigPath("/Users/dev", { COPILOT_HOME: "  " })).toBe(join("/Users/dev", ".copilot", "mcp-config.json"));
    // Present when the COPILOT_HOME folder is, not only ~/.copilot.
    const io = { exists: (p: string) => p === "/tmp/ch", listDir: () => [] };
    expect(copilot.present("/Users/dev", { COPILOT_HOME: "/tmp/ch" }, io)).toBe(true);
    expect(copilot.present("/Users/dev", {}, io)).toBe(false);
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

  it("remove takes every entry of ours (renamed too), drops an emptied root, and reports nothing to do honestly", () => {
    const ours = mergeRegistration(undefined, copilot, SCRIPT);
    expect(JSON.parse(removeRegistration(ours, copilot)!)).toEqual({});
    expect(removeRegistration(undefined, copilot)).toBeUndefined();
    expect(removeRegistration(JSON.stringify({ mcpServers: { other: { command: "x" } } }), copilot)).toBeUndefined();
    // A renamed copy still runs Doorman's server: switching it off takes it out.
    const renamed = JSON.stringify({ mcpServers: { "my-doorman": { type: "local", command: "node", args: [SCRIPT] }, other: { command: "x" } } });
    expect(JSON.parse(removeRegistration(renamed, copilot)!)).toEqual({ mcpServers: { other: { command: "x" } } });
    // …but a foreign server that happens to sit under our key is not ours.
    const squatted = JSON.stringify({ mcpServers: { doorman: { command: "npx", args: ["something-else"] } } });
    expect(removeRegistration(squatted, copilot)).toBeUndefined();
  });

  it("never overwrites a server of the person's own named doorman", () => {
    const theirs = `{"mcpServers":{"doorman":{"command":"python","args":["-m","my_doorman_tool"]}}}`;
    expect(() => mergeRegistration(theirs, copilot, SCRIPT)).toThrow(/already has a server named "doorman" that isn't Doorman's.*Rename that server/);
    expect(registrationInstalled(theirs, copilot, SCRIPT)).toBe(false);
  });

  it("refuses a server container that isn't an object instead of replacing it", () => {
    const list = `{"mcpServers":[{"name":"x","command":"y"}],"other":1}`;
    expect(() => mergeRegistration(list, copilot, SCRIPT)).toThrow(/"mcpServers" as a list, not an object of servers; not touching it/);
    expect(() => mergeRegistration(`{"servers":null}`, vscode, SCRIPT)).toThrow(/as null/);
    expect(removeRegistration(list, copilot)).toBeUndefined();
    expect(documentProblem(list, copilot)).toMatch(/not touching it/);
    expect(documentProblem(`{"mcpServers":{}}`, copilot)).toBeUndefined();
  });

  it("edits VS Code's JSONC mcp.json in place: comments, trailing commas, BOM and indentation survive, and remove gives the exact bytes back", () => {
    const before =
      "\uFEFF{\n    // my servers\n    \"servers\": {\n        \"playwright\": { \"command\": \"npx\", \"args\": [\"@playwright/mcp\"] }, // browser\n    },\n    /* inputs */\n    \"inputs\": [],\n}\n";
    const merged = mergeRegistration(before, vscode, SCRIPT);
    expect(merged).toContain("// my servers");
    expect(merged).toContain("// browser");
    expect(merged).toContain("/* inputs */");
    expect(merged.startsWith("\uFEFF{\n    // my servers")).toBe(true);
    expect(registrationInstalled(merged, vscode, SCRIPT)).toBe(true);
    expect(removeRegistration(merged, vscode)).toBe(before);
    // Uninstall with nothing of ours in a commented file is a no-op, not a refusal.
    expect(removeRegistration(before, vscode)).toBeUndefined();
  });

  it("edits a strict JSON file byte-preservingly too (tabs, one-line), and still refuses comments where the host is strict", () => {
    const tabs = `{\n\t"mcpServers": {\n\t\t"precious": {"command": "keep-me"}\n\t}\n}`;
    const merged = mergeRegistration(tabs, copilot, SCRIPT);
    expect(merged).toContain(`\t\t"precious": {"command": "keep-me"}`);
    expect(removeRegistration(merged, copilot)).toBe(tabs);
    const oneLine = `{"mcpServers":{"a":{"command":"x"}},"z":1}`;
    expect(removeRegistration(mergeRegistration(oneLine, copilot, SCRIPT), copilot)).toBe(oneLine);
    expect(() => mergeRegistration(`// c\n{"mcpServers":{}}`, copilot, SCRIPT)).toThrow(/not valid JSON/);
  });

  it("treats our entry as registered in any key order, and keeps fields the person added", () => {
    const desired = copilot.entry(SCRIPT);
    const reordered = JSON.stringify({ mcpServers: { doorman: { tools: desired.tools, args: desired.args, command: desired.command, type: desired.type, env: { DEBUG: "1" } } } });
    expect(registrationInstalled(reordered, copilot, SCRIPT)).toBe(true);
    expect(mergeRegistration(reordered, copilot, SCRIPT)).toBe(reordered);
    // A stale path is re-pointed; the person's `env` stays.
    const moved = JSON.parse(mergeRegistration(reordered, copilot, "/elsewhere/doorman-mcp.js"));
    expect(moved.mcpServers.doorman.args).toEqual(["/elsewhere/doorman-mcp.js"]);
    expect(moved.mcpServers.doorman.env).toEqual({ DEBUG: "1" });
  });

  it("counts a renamed live copy as the registration, and drops a renamed stale one", () => {
    const live = JSON.stringify({ mcpServers: { "my-doorman": copilot.entry(SCRIPT) } });
    expect(registeredKey(live, copilot, SCRIPT)).toBe("my-doorman");
    expect(mergeRegistration(live, copilot, SCRIPT)).toBe(live);
    const stale = JSON.stringify({ mcpServers: { "doorman-old": copilot.entry("/old/install/doorman-mcp.js"), other: { command: "x" } } });
    const next = JSON.parse(mergeRegistration(stale, copilot, SCRIPT));
    expect(Object.keys(next.mcpServers).sort()).toEqual(["doorman", "other"]);
    expect(registeredKey(JSON.stringify(next), copilot, SCRIPT)).toBe("doorman");
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
