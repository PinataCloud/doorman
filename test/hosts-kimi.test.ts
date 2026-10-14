/**
 * Kimi Code — a Claude-family guard host (main/guard/hosts/kimi.ts).
 * Every payload here is DOCS-DERIVED (see `_provenance`), not a recording: the
 * fixture-first rule still owes this host a real payload before it ships as
 * verified. The shared registry suite (hosts-registry.test.ts) covers the
 * invariants; this file pins the host's own facts.
 */

import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { kimiHost } from "../main/guard/hosts/kimi.js";
import { GUARD_COMMAND_MARKER } from "../main/guard/policy.js";

const FIXTURES = join(fileURLToPath(new URL(".", import.meta.url)), "fixtures/hooks/kimi");
const fixture = (name: string): Record<string, unknown> =>
  JSON.parse(readFileSync(join(FIXTURES, `${name}.json`), "utf8")) as Record<string, unknown>;

const COMMAND = `node "/Users/dev/Library/Application Support/Doorman/doorman/guard/guard.js" --host kimi`;

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
    expect(kimiHost.id).toBe("kimi");
    expect(kimiHost.label).toBe("Kimi Code");
    expect(kimiHost.source).toBe("kimi-code");
    const user = kimiHost.documents("/Users/dev", {}).find((d) => d.level === "user");
    expect(user?.path).toBe("/Users/dev/.kimi-code/config.toml");
  });
});

describe("normalizeInput", () => {
  it("maps Bash onto Bash", () => {
    expect(kimiHost.normalizeInput(fixture("bash"))).toMatchObject({"tool_name": "Bash", "tool_input": {"command": "git push --force origin main"}, "session_id": "session_abc", "cwd": "/Users/dev/projects/api"});
  });
  it("maps WriteFile { path, content } onto Write", () => {
    expect(kimiHost.normalizeInput(fixture("writefile"))).toMatchObject({"tool_name": "Write", "tool_input": {"file_path": "/Users/dev/projects/api/.env", "content": "SLACK_TOKEN=xoxb-4754237455-SYFFRBRSLCPUDWJXQSNMUATA\n"}});
  });
  it("maps StrReplaceFile { old_str, new_str } onto Edit", () => {
    expect(kimiHost.normalizeInput(fixture("strreplace"))).toMatchObject({"tool_name": "Edit", "tool_input": {"file_path": "/Users/dev/projects/api/src/auth.ts", "old_string": "verify(token)", "new_string": "true"}});
  });
  it("maps ReadFile onto Read", () => {
    expect(kimiHost.normalizeInput(fixture("readfile"))).toMatchObject({"tool_name": "Read", "tool_input": {"file_path": "/Users/dev/.ssh/id_rsa"}});
  });
  it("maps WebFetch onto WebFetch", () => {
    expect(kimiHost.normalizeInput(fixture("webfetch"))).toMatchObject({"tool_name": "WebFetch", "tool_input": {"url": "https://example.com/install.sh"}});
  });

  it("ignores payloads that are not tool calls", () => {
    expect(kimiHost.normalizeInput(null)).toBeUndefined();
    expect(kimiHost.normalizeInput({ hook_event_name: "PostToolUse", tool_name: "x", tool_input: {} })).toBeUndefined();
  });
});

describe("document surgery", () => {
  it("writes our entry with the hold-derived timeout, idempotently, and remove() takes it back out", () => {
    const doc = kimiHost.merge(undefined, COMMAND, 60, 75);
    expect(doc).toContain(GUARD_COMMAND_MARKER);
    expect(doc).toBe(`[[hooks]]\nevent = "PreToolUse"\ncommand = ${JSON.stringify(COMMAND)}\ntimeout = 75\n`);
    expect(kimiHost.merge(doc, COMMAND, 60, 75)).toBe(doc);
    expect(kimiHost.installed(doc, COMMAND)).toBe(true);
    const removed = kimiHost.remove(doc);
    expect(removed).toBeDefined();
    expect(removed).not.toContain(GUARD_COMMAND_MARKER);
  });
});

describe("output contract", () => {
  it("prints nothing on allow, the host's own deny, and never a deny for a warning", () => {
    expect(kimiHost.emit("allow")).toEqual({ exitCode: 0 });
    const out = kimiHost.emit("deny", "why");
    expect(JSON.parse(out.stdout!).hookSpecificOutput.permissionDecision).toBe("deny");
    expect(kimiHost.emit("ask", "why").stdout ?? "").not.toContain("deny");
    expect(kimiHost.emit("ask", "why").exitCode).toBe(0);
    expect(kimiHost.warn("why")).toEqual({ exitCode: 0 });
    expect(kimiHost.exitSemantics).toBe("fail-open");
  });
});
