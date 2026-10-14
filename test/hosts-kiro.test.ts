/**
 * Kiro CLI — a Claude-family guard host (main/guard/hosts/kiro.ts).
 * Every payload here is DOCS-DERIVED (see `_provenance`), not a recording: the
 * fixture-first rule still owes this host a real payload before it ships as
 * verified. The shared registry suite (hosts-registry.test.ts) covers the
 * invariants; this file pins the host's own facts.
 */

import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { kiroHost } from "../main/guard/hosts/kiro.js";
import { evaluateToolCall, parsePolicy } from "../main/guard/decision.js";
import { GUARD_COMMAND_MARKER } from "../main/guard/policy.js";

const FIXTURES = join(fileURLToPath(new URL(".", import.meta.url)), "fixtures/hooks/kiro");
const fixture = (name: string): Record<string, unknown> =>
  JSON.parse(readFileSync(join(FIXTURES, `${name}.json`), "utf8")) as Record<string, unknown>;

const COMMAND = `node "/Users/dev/Library/Application Support/Doorman/doorman/guard/guard.js" --host kiro`;

describe("the fixtures themselves", () => {
  it("all parse and all say where they came from", () => {
    const files = readdirSync(FIXTURES).filter((f) => f.endsWith(".json"));
    expect(files.length).toBeGreaterThanOrEqual(4);
    for (const file of files) {
      const payload = fixture(file.replace(/\.json$/, ""));
      expect(String(payload._provenance), file).toContain("not a live recording");
      expect(String(payload.hook_event_name).toLowerCase(), file).toBe("pretooluse");
    }
  });
});

describe("identity and documents", () => {
  it("has the fixed id, label and source, and installs at the user level", () => {
    expect(kiroHost.id).toBe("kiro");
    expect(kiroHost.label).toBe("Kiro CLI");
    expect(kiroHost.source).toBe("kiro");
    const user = kiroHost.documents("/Users/dev", {}).find((d) => d.level === "user");
    expect(user?.path).toBe("/Users/dev/.kiro/hooks/doorman.json");
  });
});

describe("normalizeInput", () => {
  it("maps execute_bash onto Bash", () => {
    expect(kiroHost.normalizeInput(fixture("execute_bash"))).toMatchObject({"tool_name": "Bash", "tool_input": {"command": "aws iam create-access-key --user-name admin"}, "session_id": "abc123-def456-789", "cwd": "/Users/dev/projects/api"});
  });
  it("maps fs_write create onto Write { file_path, content }", () => {
    expect(kiroHost.normalizeInput(fixture("fs_write-create"))).toMatchObject({"tool_name": "Write", "tool_input": {"file_path": "/Users/dev/projects/api/.env", "content": "DATABASE_URL=postgres://admin:hunter2@db.internal/prod\n"}});
  });
  it("maps fs_write str_replace onto Edit", () => {
    expect(kiroHost.normalizeInput(fixture("fs_write-str_replace"))).toMatchObject({"tool_name": "Edit", "tool_input": {"file_path": "/Users/dev/projects/api/src/auth.ts", "old_string": "verify(token)", "new_string": "true"}});
  });
  it("maps a batched read onto Read with the first path, and says the batch was whole", () => {
    expect(kiroHost.normalizeInput(fixture("fs_read"))).toEqual({
      session_id: "abc123-def456-789",
      cwd: "/Users/dev/projects/api",
      tool_name: "Read",
      tool_input: { file_path: "/Users/dev/projects/api/docs/hooks.md", batch: { operations: 1, complete: true } },
    });
  });

  it("keeps EVERY operation of a batched read — a .env in position two is not lost (review F4)", () => {
    const payload = {
      hook_event_name: "preToolUse",
      cwd: "/Users/dev/projects/api",
      session_id: "s",
      tool_name: "fs_read",
      tool_input: {
        operations: [
          { mode: "Line", path: "/Users/dev/projects/api/README.md" },
          { mode: "Line", path: "/Users/dev/projects/api/.env" },
          { mode: "Search", pattern: "TODO" },
          "garbage",
        ],
      },
    };
    const input = kiroHost.normalizeInput(payload)!;
    expect(input.tool_name).toBe("Read");
    expect(input.tool_input).toEqual({
      file_path: "/Users/dev/projects/api/README.md",
      file_paths: ["/Users/dev/projects/api/README.md", "/Users/dev/projects/api/.env"],
      operations: [{ mode: "Search", pattern: "TODO" }],
      batch: { operations: 4, complete: false },
    });
    // What matters: the detectors see the second path. They scan the whole
    // (redacted) tool_input, so the credential-file read fires on this batch.
    const result = evaluateToolCall(input, parsePolicy(undefined));
    expect(result.findings.map((f) => f.detector)).toContain("dotenv_read");
  });
  it("qualifies @server/tool as mcp__server__tool, PascalCase event included", () => {
    expect(kiroHost.normalizeInput(fixture("mcp"))).toMatchObject({"tool_name": "mcp__postgres__query", "tool_input": {"sql": "SELECT * FROM orders LIMIT 10;"}});
  });
  it("passes use_aws through", () => {
    expect(kiroHost.normalizeInput(fixture("use_aws-passthrough"))).toMatchObject({"tool_name": "use_aws"});
  });

  it("ignores payloads that are not tool calls", () => {
    expect(kiroHost.normalizeInput(null)).toBeUndefined();
    expect(kiroHost.normalizeInput({ hook_event_name: "PostToolUse", tool_name: "x", tool_input: {} })).toBeUndefined();
  });
});

describe("document surgery", () => {
  it("writes our entry with the hold-derived timeout, idempotently, and remove() takes it back out", () => {
    const doc = kiroHost.merge(undefined, COMMAND, 60, 75);
    expect(doc).toContain(GUARD_COMMAND_MARKER);
    const parsed = JSON.parse(doc);
    expect(parsed.version).toBe("v1");
    expect(parsed.hooks[0]).toMatchObject({ trigger: "PreToolUse", action: { type: "command", command: COMMAND }, timeout: 75, enabled: true });
    expect(kiroHost.merge(doc, COMMAND, 60, 75)).toBe(doc);
    expect(kiroHost.installed(doc, COMMAND)).toBe(true);
    const removed = kiroHost.remove(doc);
    expect(removed).toBeDefined();
    expect(removed).not.toContain(GUARD_COMMAND_MARKER);
  });
});

describe("output contract", () => {
  it("prints nothing on allow, the host's own deny, and never a deny for a warning", () => {
    expect(kiroHost.emit("allow")).toEqual({ exitCode: 0 });
    const out = kiroHost.emit("deny", "why");
    // Exit 2 is the verdict; the reason rides stderr, which Kiro returns to the model.
    expect(out).toEqual({ exitCode: 2, stderr: "why" });
    expect(kiroHost.emit("ask", "why").stdout ?? "").not.toContain("deny");
    expect(kiroHost.emit("ask", "why").exitCode).toBe(0);
    expect(kiroHost.warn("why")).toEqual({ exitCode: 0 });
    expect(kiroHost.exitSemantics).toBe("fail-open");
  });
});
