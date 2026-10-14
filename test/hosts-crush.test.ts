/**
 * Crush — a Claude-family guard host (main/guard/hosts/crush.ts).
 * Every payload here is DOCS-DERIVED (see `_provenance`), not a recording: the
 * fixture-first rule still owes this host a real payload before it ships as
 * verified. The shared registry suite (hosts-registry.test.ts) covers the
 * invariants; this file pins the host's own facts.
 */

import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { crushHost } from "../main/guard/hosts/crush.js";
import { GUARD_COMMAND_MARKER } from "../main/guard/policy.js";

const FIXTURES = join(fileURLToPath(new URL(".", import.meta.url)), "fixtures/hooks/crush");
const fixture = (name: string): Record<string, unknown> =>
  JSON.parse(readFileSync(join(FIXTURES, `${name}.json`), "utf8")) as Record<string, unknown>;

const COMMAND = `node "/Users/dev/Library/Application Support/Doorman/doorman/guard/guard.js" --host crush`;

describe("the fixtures themselves", () => {
  it("all parse and all say where they came from", () => {
    const files = readdirSync(FIXTURES).filter((f) => f.endsWith(".json"));
    expect(files.length).toBeGreaterThanOrEqual(4);
    for (const file of files) {
      const payload = fixture(file.replace(/\.json$/, ""));
      expect(String(payload._provenance), file).toContain("not a live recording");
      expect(String(payload.event).toLowerCase(), file).toBe("pretooluse");
    }
  });
});

describe("identity and documents", () => {
  it("has the fixed id, label and source, and installs at the user level", () => {
    expect(crushHost.id).toBe("crush");
    expect(crushHost.label).toBe("Crush");
    expect(crushHost.source).toBe("crush");
    const user = crushHost.documents("/Users/dev", {}).find((d) => d.level === "user");
    expect(user?.path).toBe("/Users/dev/.config/crush/crush.json");
  });
});

describe("normalizeInput", () => {
  it("maps bash onto Bash and drops the description", () => {
    expect(crushHost.normalizeInput(fixture("bash"))).toMatchObject({"tool_name": "Bash", "tool_input": {"command": "rm -rf ~/.ssh"}, "session_id": "crush-8d2b4e6f-1a3c-4d5e-8f9a-0b1c2d3e4f5a", "cwd": "/Users/dev/projects/api"});
  });
  it("maps write onto Write", () => {
    expect(crushHost.normalizeInput(fixture("write"))).toMatchObject({"tool_name": "Write", "tool_input": {"file_path": "/Users/dev/projects/api/.env", "content": "GITHUB_TOKEN=ghp_RFQRSLZCGAEHLNBHCEVYVSDWREschjcxpbtj\n"}});
  });
  it("maps edit onto Edit", () => {
    expect(crushHost.normalizeInput(fixture("edit"))).toMatchObject({"tool_name": "Edit"});
  });
  it("maps view onto Read", () => {
    expect(crushHost.normalizeInput(fixture("view"))).toMatchObject({"tool_name": "Read", "tool_input": {"file_path": "/Users/dev/.netrc"}});
  });
  it("qualifies mcp_<server>_<tool> on the first underscore", () => {
    expect(crushHost.normalizeInput(fixture("mcp"))).toMatchObject({"tool_name": "mcp__github__create_pull_request", "tool_input": {"owner": "acme", "repo": "api"}});
  });

  it("ignores payloads that are not tool calls", () => {
    expect(crushHost.normalizeInput(null)).toBeUndefined();
    expect(crushHost.normalizeInput({ event: "PostToolUse", tool_name: "x", tool_input: {} })).toBeUndefined();
  });
});

describe("document surgery", () => {
  it("writes our entry with the hold-derived timeout, idempotently, and remove() takes it back out", () => {
    const doc = crushHost.merge(undefined, COMMAND, 60, 75);
    expect(doc).toContain(GUARD_COMMAND_MARKER);
    const handler = JSON.parse(doc).hooks.PreToolUse[0];
    expect(handler).toEqual({ name: "Doorman", command: COMMAND, timeout: 75 });
    expect(crushHost.merge(doc, COMMAND, 60, 75)).toBe(doc);
    expect(crushHost.installed(doc, COMMAND)).toBe(true);
    const removed = crushHost.remove(doc);
    expect(removed).toBeDefined();
    expect(removed).not.toContain(GUARD_COMMAND_MARKER);
  });
});

describe("output contract", () => {
  it("prints nothing on allow, the host's own deny, and never a deny for a warning", () => {
    expect(crushHost.emit("allow")).toEqual({ exitCode: 0 });
    const out = crushHost.emit("deny", "why");
    expect(JSON.parse(out.stdout!)).toEqual({ decision: "deny", reason: "why" });
    expect(crushHost.emit("ask", "why").stdout ?? "").not.toContain("deny");
    expect(crushHost.emit("ask", "why").exitCode).toBe(0);
    expect(crushHost.warn("why")).toEqual({ exitCode: 0 });
    expect(crushHost.exitSemantics).toBe("fail-open");
  });
});
