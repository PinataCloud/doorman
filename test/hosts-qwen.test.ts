/**
 * Qwen Code — a Claude-family guard host (main/guard/hosts/qwen.ts).
 * Every payload here is DOCS-DERIVED (see `_provenance`), not a recording: the
 * fixture-first rule still owes this host a real payload before it ships as
 * verified. The shared registry suite (hosts-registry.test.ts) covers the
 * invariants; this file pins the host's own facts.
 */

import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { qwenHost } from "../main/guard/hosts/qwen.js";
import { documentReadable } from "../main/guard/hosts/index.js";
import { stripJsonc } from "../main/guard/jsonc.js";
import { GUARD_COMMAND_MARKER } from "../main/guard/policy.js";

const FIXTURES = join(fileURLToPath(new URL(".", import.meta.url)), "fixtures/hooks/qwen");
const fixture = (name: string): Record<string, unknown> =>
  JSON.parse(readFileSync(join(FIXTURES, `${name}.json`), "utf8")) as Record<string, unknown>;

const COMMAND = `node "/Users/dev/Library/Application Support/Doorman/doorman/guard/guard.js" --host qwen`;

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
    expect(qwenHost.id).toBe("qwen");
    expect(qwenHost.label).toBe("Qwen Code");
    expect(qwenHost.source).toBe("qwen-code");
    const user = qwenHost.documents("/Users/dev", {}).find((d) => d.level === "user");
    expect(user?.path).toBe("/Users/dev/.qwen/settings.json");
  });
});

describe("normalizeInput", () => {
  it("maps run_shell_command onto Bash { command } and drops the description", () => {
    expect(qwenHost.normalizeInput(fixture("run_shell_command"))).toMatchObject({"tool_name": "Bash", "tool_input": {"command": "aws s3 rm s3://prod-backups --recursive"}, "session_id": "qwen-7c1e2a3b-5d4f-4e6a-9b8c-0d1e2f3a4b5c", "cwd": "/Users/dev/projects/api"});
  });
  it("maps write_file onto Write", () => {
    expect(qwenHost.normalizeInput(fixture("write_file"))).toMatchObject({"tool_name": "Write", "tool_input": {"file_path": "/Users/dev/projects/api/.env", "content": "OPENAI_API_KEY=sk-proj-abc123def456ghi789jkl012mno345pqr678\n"}});
  });
  it("maps edit onto Edit", () => {
    expect(qwenHost.normalizeInput(fixture("edit"))).toMatchObject({"tool_name": "Edit", "tool_input": {"file_path": "/Users/dev/projects/api/src/auth.ts", "old_string": "verify(token)", "new_string": "true // verify(token)"}});
  });
  it("maps read_file with absolute_path onto Read { file_path }", () => {
    expect(qwenHost.normalizeInput(fixture("read_file"))).toMatchObject({"tool_name": "Read", "tool_input": {"file_path": "/Users/dev/.ssh/id_ed25519"}});
  });
  it("maps web_fetch onto WebFetch { url }", () => {
    expect(qwenHost.normalizeInput(fixture("web_fetch"))).toMatchObject({"tool_name": "WebFetch", "tool_input": {"url": "https://example.com/install.sh"}});
  });
  it("passes glob through untouched", () => {
    expect(qwenHost.normalizeInput(fixture("glob-passthrough"))).toMatchObject({"tool_name": "glob", "tool_input": {"pattern": "**/*.pem"}});
  });

  it("ignores payloads that are not tool calls", () => {
    expect(qwenHost.normalizeInput(null)).toBeUndefined();
    expect(qwenHost.normalizeInput({ hook_event_name: "PostToolUse", tool_name: "x", tool_input: {} })).toBeUndefined();
  });
});

describe("document surgery", () => {
  it("writes our entry with the hold-derived timeout, idempotently, and remove() takes it back out", () => {
    const doc = qwenHost.merge(undefined, COMMAND, 60, 75);
    expect(doc).toContain(GUARD_COMMAND_MARKER);
    const parsed = JSON.parse(doc);
    const group = parsed.hooks.PreToolUse[0];
    const handler = group.hooks[0];
    expect(handler.command).toBe(COMMAND);
    expect(handler.timeout).toBe(75_000);
    expect(qwenHost.merge(doc, COMMAND, 60, 75)).toBe(doc);
    expect(qwenHost.installed(doc, COMMAND)).toBe(true);
    const removed = qwenHost.remove(doc);
    expect(removed).toBeDefined();
    expect(removed).not.toContain(GUARD_COMMAND_MARKER);
  });

  it("edits a commented, BOM-prefixed settings.json in place, keeping every comment", () => {
    // Qwen Code strips a BOM and comments before JSON.parse, so this is a
    // valid settings file there — and a trailing comma is not.
    const commented = [
      "\uFEFF// Qwen settings",
      "{",
      "    /* model */",
      '    "model": { "name": "qwen3-coder" },',
      '    "hooks": {',
      '        "PreToolUse": [',
      "            // a teammate's hook",
      '            { "matcher": "run_shell_command", "hooks": [{ "type": "command", "command": "/opt/audit.sh" }] }',
      "        ]",
      "    } // hooks end",
      "}",
      "// trailing",
      "",
    ].join("\n");
    expect(documentReadable(qwenHost, commented)).toBe(true);
    const merged = qwenHost.merge(commented, COMMAND, 60, 75);
    expect(merged.startsWith("\uFEFF// Qwen settings\n{\n    /* model */\n")).toBe(true);
    for (const comment of commented.match(/\/\/ [^\n]*|\/\*.*?\*\//g)!) expect(merged).toContain(comment);
    const stripped = stripJsonc(merged);
    expect(stripped.changes).not.toContain("removed trailing commas");
    expect(JSON.parse(stripped.text)).toEqual(JSON.parse(qwenHost.merge(stripJsonc(commented).text, COMMAND, 60, 75)));
    expect(qwenHost.installed(merged, COMMAND)).toBe(true);
    expect(qwenHost.merge(merged, COMMAND, 60, 75)).toBe(merged);
    expect(qwenHost.remove(merged)).toBe(commented);
    expect(() => qwenHost.merge('{ "model": {}, }', COMMAND, 60, 75)).toThrow(/\.qwen\/settings\.json is not valid JSON \(line 1: trailing comma\)/);
  });
});

describe("output contract", () => {
  it("prints nothing on allow, the host's own deny, and never a deny for a warning", () => {
    expect(qwenHost.emit("allow")).toEqual({ exitCode: 0 });
    const out = qwenHost.emit("deny", "why");
    expect(JSON.parse(out.stdout!).hookSpecificOutput.permissionDecision).toBe("deny");
    expect(JSON.parse(qwenHost.emit("ask", "why").stdout!).hookSpecificOutput.permissionDecision).toBe("ask");
    expect(JSON.parse(qwenHost.warn("why").stdout!).systemMessage).toContain("why");
    expect(qwenHost.exitSemantics).toBe("fail-open");
  });
});
