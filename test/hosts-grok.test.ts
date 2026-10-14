import { describe, expect, it } from "vitest";
import { grokHost } from "../main/guard/hosts/grok.js";
import { GUARD_COMMAND_MARKER } from "../main/guard/policy.js";

const command = `node /tmp/${GUARD_COMMAND_MARKER}/guard.js --host grok`;
// Source-derived from xai-org/grok-build docs/user-guide/10-hooks.md, not a live recording.
describe("Grok Build hooks", () => {
  it("installs a global JSON hook with an explicit timeout and preserves foreign entries", () => {
    const original = JSON.stringify({ setting: "keep", hooks: { PreToolUse: [{ hooks: [{ type: "command", command: "other" }] }] } });
    const installed = grokHost.merge(original, command, 60, 75);
    expect(grokHost.installed(installed, command)).toBe(true);
    expect(grokHost.merge(installed, command, 60, 75)).toBe(installed);
    expect(JSON.parse(installed).hooks.PreToolUse.at(-1).hooks[0].timeout).toBe(75);
    expect(JSON.parse(grokHost.remove(installed)!)).toEqual(JSON.parse(original));
    expect(() => grokHost.merge("{broken", command, 60)).toThrow();
    expect(grokHost.documents("/dev", { GROK_HOME: "/grok-alt" })[0]?.path).toBe("/grok-alt/hooks/doorman.json");
    expect(grokHost.presencePathsFor?.("/dev", { GROK_HOME: "/grok-alt" })).toEqual(["/grok-alt"]);
  });
  it("normalizes camelCase hook payloads, MCP names and file edits", () => {
    const envelope = { hookEventName: "pre_tool_use", sessionId: "s", cwd: "/repo" };
    expect(grokHost.normalizeInput({ ...envelope, toolName: "run_terminal_command", toolInput: { command: "git status" } }))
      .toMatchObject({ session_id: "s", cwd: "/repo", tool_name: "Bash", tool_input: { command: "git status" } });
    expect(grokHost.normalizeInput({ ...envelope, toolName: "search_replace", toolInput: { file_path: "a.ts", old_string: "a", new_string: "b" } }))
      .toMatchObject({ tool_name: "Edit", tool_input: { file_path: "a.ts", old_string: "a", new_string: "b" } });
    expect(grokHost.normalizeInput({ ...envelope, toolName: "linear__save_issue", toolInput: {} })?.tool_name).toBe("mcp__linear__save_issue");
    expect(grokHost.normalizeInput({ ...envelope, toolName: "read_file", toolInput: { target_file: "/repo/.env" } }))
      .toMatchObject({ tool_name: "Read", tool_input: { file_path: "/repo/.env" } });
    expect(grokHost.normalizeInput({ ...envelope, hookEventName: "post_tool_use", toolName: "read_file" })).toBeUndefined();
  });
  it("leaves host approvals alone on allow and emits native ask/deny", () => {
    expect(grokHost.emit("allow")).toEqual({ exitCode: 0 });
    for (const decision of ["ask", "deny"] as const) {
      const out = grokHost.emit(decision, "Review this call");
      expect(out.exitCode).toBe(0);
      expect(JSON.parse(out.stdout!).hookSpecificOutput).toMatchObject({ hookEventName: "PreToolUse", permissionDecision: decision });
    }
    expect(grokHost.warn("review")).toEqual(grokHost.emit("ask", "review"));
  });
});
