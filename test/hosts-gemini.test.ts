/**
 * The Gemini CLI host adapter — workstream A of the guard coverage expansion.
 *
 * Two families of promise are under test here and neither is cosmetic:
 *  · CONFIG SURGERY on a `settings.json` that is mostly not ours. Gemini keeps
 *    the whole CLI's configuration in that file, so every unrelated key, every
 *    foreign hook and every hook event we do not use has to come out the other
 *    side untouched, and a file we cannot parse has to be refused rather than
 *    rewritten.
 *  · STDOUT PURITY. Gemini parses stdout as JSON and treats a stray line of
 *    text as an allow-with-a-message, so "prints nothing on allow" and "prints
 *    nothing but JSON, ever" are security properties, not tidiness.
 */

import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { geminiHost } from "../main/guard/hosts/gemini.js";
import { documentReadable } from "../main/guard/hosts/index.js";
import { stripJsonc } from "../main/guard/jsonc.js";

const FIXTURES = join(fileURLToPath(new URL(".", import.meta.url)), "fixtures/hooks/gemini");
const fixture = (name: string): Record<string, unknown> =>
  JSON.parse(readFileSync(join(FIXTURES, `${name}.json`), "utf8")) as Record<string, unknown>;

const COMMAND = "/Users/dev/Library/Application Support/Doorman/doorman/guard/guard.js --host gemini";
const HOLD = 60;
// merge() writes Gemini's timeout in MILLISECONDS, hold + the same 15s slack
// policy.ts uses.
const TIMEOUT_MS = (60 + 15) * 1000;

describe("the fixtures themselves", () => {
  it("all parse and all say where they came from", () => {
    const files = readdirSync(FIXTURES).filter((f) => f.endsWith(".json"));
    expect(files.length).toBeGreaterThan(5);
    for (const file of files) {
      const payload = JSON.parse(readFileSync(join(FIXTURES, file), "utf8")) as Record<string, unknown>;
      expect(String(payload._provenance), file).toContain("not a live recording");
      expect(payload.hook_event_name, file).toBe("BeforeTool");
    }
  });
});

describe("normalizeInput", () => {
  it("maps run_shell_command onto Bash { command }, keeping the run options beside it", () => {
    // `dir_path` is where a relative command lands; every key is scanned text
    // (P2, 2026-09-10) — the fields used to be dropped for a smaller card.
    expect(geminiHost.normalizeInput(fixture("run_shell_command"))).toEqual({
      session_id: "9f1c2b74-3f0a-4a51-9b1e-2c8d4a6e7f01",
      cwd: "/Users/dev/projects/api",
      tool_name: "Bash",
      tool_input: {
        command: "aws s3 rm s3://prod-backups --recursive",
        description: "Remove the stale backup bucket contents",
        dir_path: "/Users/dev/projects/api",
        is_background: false,
      },
    });
  });

  it("maps write_file onto Write { file_path, content }", () => {
    const input = geminiHost.normalizeInput(fixture("write_file"));
    expect(input?.tool_name).toBe("Write");
    expect(input?.tool_input).toEqual({
      file_path: "/Users/dev/projects/api/.env",
      content: "OPENAI_API_KEY=sk-proj-abc123def456ghi789jkl012mno345pqr678\n",
    });
  });

  it("maps replace onto Edit and keeps the fields Claude Code's Edit has no name for", () => {
    const input = geminiHost.normalizeInput(fixture("replace"));
    expect(input?.tool_name).toBe("Edit");
    expect(input?.tool_input).toEqual({
      file_path: "/Users/dev/projects/api/src/config.ts",
      instruction: "Point the client at the staging host",
      old_string: 'const HOST = "api.example.com";',
      new_string: 'const HOST = "staging.example.com";',
      allow_multiple: false,
    });
  });

  it("maps read_file onto Read { file_path }, the read window beside it", () => {
    const input = geminiHost.normalizeInput(fixture("read_file"));
    expect(input?.tool_name).toBe("Read");
    expect(input?.tool_input).toEqual({ file_path: "/Users/dev/.aws/credentials", offset: 0, limit: 200 });
  });

  it("lifts the URL out of web_fetch's prompt — the tool has no url field — and keeps the prompt", () => {
    const input = geminiHost.normalizeInput(fixture("web_fetch"));
    expect(input?.tool_name).toBe("WebFetch");
    expect(input?.tool_input).toEqual({
      prompt: "Summarise the release notes at https://example.com/releases/v2 and list the breaking changes",
      url: "https://example.com/releases/v2",
    });
  });

  it("passes a web_fetch with no URL through as itself rather than inventing one", () => {
    const raw = { ...fixture("web_fetch"), tool_input: { prompt: "what did I ask you earlier" } };
    const input = geminiHost.normalizeInput(raw);
    expect(input?.tool_name).toBe("web_fetch");
    expect(input?.tool_input).toEqual({ prompt: "what did I ask you earlier" });
  });

  it("rewrites mcp_<server>_<tool> into the mcp__server__tool the rules key on", () => {
    const input = geminiHost.normalizeInput(fixture("mcp_tool"));
    expect(input?.tool_name).toBe("mcp__github__create_issue");
    expect(input?.tool_input).toEqual({
      repo: "Doorman/doorman-app",
      title: "Rotate the leaked deploy key",
      body: "Found in the build log.",
    });
  });

  it("splits on the server mcp_context names, so an underscored server survives", () => {
    // The wire name alone is ambiguous; mcp_context is the only thing that can
    // settle it, and when it does we believe it over the first-underscore rule.
    const input = geminiHost.normalizeInput({
      hook_event_name: "BeforeTool",
      tool_name: "mcp_my_server_create_issue",
      mcp_context: { server_name: "my_server" },
      tool_input: {},
    });
    expect(input?.tool_name).toBe("mcp__my_server__create_issue");
  });

  it("falls back to the first underscore when nothing names the server", () => {
    const input = geminiHost.normalizeInput({
      hook_event_name: "BeforeTool",
      tool_name: "mcp_slack_send_message",
      tool_input: { channel: "#eng" },
    });
    expect(input?.tool_name).toBe("mcp__slack__send_message");
  });

  it("passes an unmapped built-in through with its own name and arguments", () => {
    const input = geminiHost.normalizeInput(fixture("glob"));
    expect(input?.tool_name).toBe("glob");
    expect(input?.tool_input).toMatchObject({ pattern: "**/*.pem" });
  });

  it("carries session_id and cwd across for every fixture — armed taints and scoped rules need them", () => {
    for (const file of readdirSync(FIXTURES).filter((f) => f.endsWith(".json"))) {
      const raw = JSON.parse(readFileSync(join(FIXTURES, file), "utf8")) as Record<string, unknown>;
      const input = geminiHost.normalizeInput(raw);
      expect(input, file).toBeDefined();
      expect(input?.session_id, file).toBe(raw.session_id);
      expect(input?.cwd, file).toBe(raw.cwd);
    }
  });

  it("ignores every event that is not BeforeTool", () => {
    for (const event of ["AfterTool", "BeforeModel", "SessionStart", "Notification"]) {
      expect(
        geminiHost.normalizeInput({ hook_event_name: event, tool_name: "run_shell_command", tool_input: {} }),
        event,
      ).toBeUndefined();
    }
  });

  it("returns undefined for junk rather than guessing", () => {
    expect(geminiHost.normalizeInput(undefined)).toBeUndefined();
    expect(geminiHost.normalizeInput("{}")).toBeUndefined();
    expect(geminiHost.normalizeInput([])).toBeUndefined();
    expect(geminiHost.normalizeInput({ hook_event_name: "BeforeTool" })).toBeUndefined();
  });
});

describe("emit", () => {
  it("prints NOTHING on allow — our check passed, Gemini's own machinery is untouched", () => {
    expect(geminiHost.emit("allow")).toEqual({ exitCode: 0 });
    expect(geminiHost.emit("allow", "some reason")).toEqual({ exitCode: 0 });
  });

  it("denies with the documented decision/reason body at exit 0, not exit 2", () => {
    // Exit 2 also blocks, but takes its reason from stderr — the structured
    // field is the documented, preferred path.
    const out = geminiHost.emit("deny", "Doorman flagged this tool call: secret_egress.");
    expect(out.exitCode).toBe(0);
    expect(JSON.parse(out.stdout!)).toEqual({
      decision: "deny",
      reason: "Doorman flagged this tool call: secret_egress.",
    });
  });

  it("turns an ask into a warning, because Gemini cannot ask", () => {
    const reason = "Doorman flagged this tool call: destructive_command.";
    const ask = geminiHost.emit("ask", reason);
    expect(ask).toEqual(geminiHost.warn(reason));
    const body = JSON.parse(ask.stdout!) as Record<string, unknown>;
    expect(Object.keys(body)).toEqual(["systemMessage"]);
    expect(body.systemMessage).toBe(
      `${reason} Doorman could not ask in the app; Gemini CLI does not support a native ask, ` +
        "so this call is continuing.",
    );
    expect(ask.exitCode).toBe(0);
    expect(geminiHost.supportsNativeAsk).toBe(false);
  });

  it("never carries a decision in the warn body — a warning is not a verdict", () => {
    const body = JSON.parse(geminiHost.warn("careful").stdout!) as Record<string, unknown>;
    expect(body.decision).toBeUndefined();
  });

  it("emits stdout that is pure JSON with nothing before or after it", () => {
    // A stray character makes Gemini read the whole thing as an allow.
    for (const out of [
      geminiHost.emit("allow"),
      geminiHost.emit("deny", "no"),
      geminiHost.emit("ask", "maybe"),
      geminiHost.warn("maybe"),
    ]) {
      if (out.stdout === undefined) continue;
      expect(out.stdout).toBe(out.stdout.trim());
      expect(out.stdout.startsWith("{")).toBe(true);
      expect(out.stdout.endsWith("}")).toBe(true);
      expect(() => JSON.parse(out.stdout!)).not.toThrow();
      expect(JSON.stringify(JSON.parse(out.stdout!))).toBe(out.stdout);
    }
  });

  it("never returns a non-zero exit code — a crash is the only non-zero, and it fails open", () => {
    expect(geminiHost.exitSemantics).toBe("fail-open");
    for (const d of ["allow", "ask", "deny"] as const) expect(geminiHost.emit(d, "r").exitCode).toBe(0);
  });
});

describe("documents", () => {
  it("installs at the user level and hands the doctor the two documents above it", () => {
    const docs = geminiHost.documents("/Users/dev", {});
    expect(docs).toEqual([
      { path: "/Users/dev/.gemini/settings.json", level: "user" },
      { path: ".gemini/settings.json", level: "project" },
      { path: "/Library/Application Support/GeminiCli/settings.json", level: "system" },
    ]);
  });

  it("honours GEMINI_CLI_SYSTEM_SETTINGS_PATH, the one documented path override", () => {
    const docs = geminiHost.documents("/Users/dev", { GEMINI_CLI_SYSTEM_SETTINGS_PATH: "/etc/gemini.json" });
    expect(docs.find((d) => d.level === "system")?.path).toBe("/etc/gemini.json");
  });

  it("agrees with the shadow-AI catalog on what 'Gemini CLI is here' looks like", () => {
    expect(geminiHost.presencePaths).toEqual([".gemini"]);
    expect(geminiHost.id).toBe("gemini");
    expect(geminiHost.source).toBe("gemini-cli");
  });
});

describe("merge", () => {
  it("creates the document when there is none", () => {
    const doc = JSON.parse(geminiHost.merge(undefined, COMMAND, HOLD));
    expect(doc).toEqual({
      hooks: {
        BeforeTool: [
          {
            matcher: "*",
            hooks: [{ name: "Doorman", type: "command", command: COMMAND, timeout: TIMEOUT_MS }],
          },
        ],
      },
    });
  });

  it("derives the per-hook timeout from the hold window, in milliseconds", () => {
    // A timeout under the hold window is a silent fail-open: Gemini kills the
    // hook, no verdict is printed, and the call proceeds.
    for (const hold of [30, 60, 300]) {
      const doc = JSON.parse(geminiHost.merge(undefined, COMMAND, hold));
      const timeout = doc.hooks.BeforeTool[0].hooks[0].timeout as number;
      expect(timeout).toBeGreaterThan(hold * 1000);
      expect(timeout).toBe((hold + 15) * 1000);
    }
  });

  it("leaves every unrelated key of a real settings.json alone", () => {
    const existing = JSON.stringify(
      {
        theme: "GitHub",
        selectedAuthType: "oauth-personal",
        mcpServers: { linear: { command: "npx", args: ["-y", "linear-mcp"] } },
        contextFileName: "GEMINI.md",
        telemetry: { enabled: false },
      },
      null,
      2,
    );
    const doc = JSON.parse(geminiHost.merge(existing, COMMAND, HOLD));
    expect(doc.theme).toBe("GitHub");
    expect(doc.selectedAuthType).toBe("oauth-personal");
    expect(doc.mcpServers).toEqual({ linear: { command: "npx", args: ["-y", "linear-mcp"] } });
    expect(doc.contextFileName).toBe("GEMINI.md");
    expect(doc.telemetry).toEqual({ enabled: false });
    expect(doc.hooks.BeforeTool).toHaveLength(1);
  });

  it("leaves foreign BeforeTool handlers, other hook events and their group shapes intact", () => {
    const existing = JSON.stringify({
      hooks: {
        BeforeTool: [
          {
            matcher: "write_file|replace",
            sequential: true,
            hooks: [
              {
                name: "security-check",
                type: "command",
                command: "$GEMINI_PROJECT_DIR/.gemini/hooks/security.sh",
                timeout: 5000,
              },
            ],
          },
        ],
        AfterTool: [{ matcher: "*", hooks: [{ type: "command", command: "./log.sh" }] }],
        SessionStart: [{ hooks: [{ type: "command", command: "./greet.sh" }] }],
      },
    });
    const doc = JSON.parse(geminiHost.merge(existing, COMMAND, HOLD));
    expect(doc.hooks.BeforeTool[0]).toEqual({
      matcher: "write_file|replace",
      sequential: true,
      hooks: [
        {
          name: "security-check",
          type: "command",
          command: "$GEMINI_PROJECT_DIR/.gemini/hooks/security.sh",
          timeout: 5000,
        },
      ],
    });
    expect(doc.hooks.BeforeTool[1].hooks[0].command).toBe(COMMAND);
    expect(doc.hooks.AfterTool).toEqual([{ matcher: "*", hooks: [{ type: "command", command: "./log.sh" }] }]);
    expect(doc.hooks.SessionStart).toEqual([{ hooks: [{ type: "command", command: "./greet.sh" }] }]);
  });

  it("does not touch a foreign handler that shares a group with ours", () => {
    const first = geminiHost.merge(undefined, COMMAND, HOLD);
    const withNeighbour = JSON.parse(first);
    withNeighbour.hooks.BeforeTool[0].hooks.push({ type: "command", command: "./their-audit.sh" });
    const doc = JSON.parse(geminiHost.merge(JSON.stringify(withNeighbour), COMMAND, HOLD));
    expect(doc.hooks.BeforeTool[0].hooks).toHaveLength(2);
    expect(doc.hooks.BeforeTool[0].hooks[1]).toEqual({ type: "command", command: "./their-audit.sh" });
  });

  it("is idempotent — the second merge returns the input text byte for byte", () => {
    const once = geminiHost.merge(undefined, COMMAND, HOLD);
    expect(geminiHost.merge(once, COMMAND, HOLD)).toBe(once);
    expect(geminiHost.merge(once, COMMAND, HOLD)).toBe(once);
  });

  it("replaces a stale copy of ours in place, and drops a stray duplicate", () => {
    const stale = JSON.stringify({
      hooks: {
        BeforeTool: [
          { matcher: "run_shell_command", hooks: [{ name: "Doorman", type: "command", command: `${COMMAND} --old`, timeout: 1000 }] },
          { matcher: "*", hooks: [{ type: "command", command: "/opt/doorman/guard/guard.js" }] },
        ],
      },
    });
    const doc = JSON.parse(geminiHost.merge(stale, COMMAND, HOLD));
    // One group, one handler of ours, the canonical match-all matcher back.
    expect(doc.hooks.BeforeTool).toHaveLength(1);
    expect(doc.hooks.BeforeTool[0]).toEqual({
      matcher: "*",
      hooks: [{ name: "Doorman", type: "command", command: COMMAND, timeout: TIMEOUT_MS }],
    });
  });

  it("re-widens a matcher somebody narrowed on our own group — a narrowed security hook is a bypass", () => {
    const narrowed = JSON.parse(geminiHost.merge(undefined, COMMAND, HOLD));
    narrowed.hooks.BeforeTool[0].matcher = "read_file";
    const doc = JSON.parse(geminiHost.merge(JSON.stringify(narrowed), COMMAND, HOLD));
    expect(doc.hooks.BeforeTool[0].matcher).toBe("*");
  });

  it("replaces an inert `hooks: []`, which would swallow the event at stringify time", () => {
    const doc = JSON.parse(geminiHost.merge(JSON.stringify({ theme: "Dracula", hooks: [] }), COMMAND, HOLD));
    expect(doc.theme).toBe("Dracula");
    expect(doc.hooks.BeforeTool[0].hooks[0].command).toBe(COMMAND);
  });

  it("refuses a malformed settings.json rather than overwriting it", () => {
    expect(() => geminiHost.merge("{ not json", COMMAND, HOLD)).toThrow(/not valid JSON/);
    expect(() => geminiHost.merge('{"hooks": {},}', COMMAND, HOLD)).toThrow(/\.gemini\/settings\.json/);
  });

  it("edits a commented settings.json in place — Gemini CLI reads comments, so every one survives", () => {
    const commented = [
      "// my Gemini settings",
      "{",
      '  "theme": "GitHub", /* picked by hand */',
      '  "hooks": {',
      "    // the linter runs first",
      '    "BeforeTool": [',
      "      // theirs",
      '      { "matcher": "write_.*", "hooks": [{ "type": "command", "command": "/opt/lint.sh" }] } // keep',
      "    ]",
      "  },",
      '  "proxy": "http://proxy//not-a-comment"',
      "  // the end of the object",
      "}",
      "// trailing",
      "",
    ].join("\n");
    expect(documentReadable(geminiHost, commented)).toBe(true);
    const merged = geminiHost.merge(commented, COMMAND, HOLD);
    for (const comment of commented.match(/\/\/ [^\n]*|\/\*.*?\*\//g)!) expect(merged).toContain(comment);
    // What Gemini itself reads (comments stripped, then strict JSON — no
    // trailing comma) is the object-level merge of the uncommented document.
    const stripped = stripJsonc(merged);
    expect(stripped.changes).toEqual(["removed comments"]);
    expect(JSON.parse(stripped.text)).toEqual(
      JSON.parse(geminiHost.merge(stripJsonc(commented).text, COMMAND, HOLD)),
    );
    expect(geminiHost.installed(merged, COMMAND)).toBe(true);
    expect(geminiHost.merge(merged, COMMAND, HOLD)).toBe(merged);
    expect(geminiHost.remove(merged)).toBe(commented);
  });

  it("treats an empty file as a fresh document", () => {
    expect(JSON.parse(geminiHost.merge("   ", COMMAND, HOLD)).hooks.BeforeTool).toHaveLength(1);
  });
});

describe("installed", () => {
  it("recognises exactly this command and nothing else", () => {
    const doc = geminiHost.merge(undefined, COMMAND, HOLD);
    expect(geminiHost.installed(doc, COMMAND)).toBe(true);
    expect(geminiHost.installed(doc, `${COMMAND} --host claude`)).toBe(false);
    expect(geminiHost.installed(undefined, COMMAND)).toBe(false);
    expect(geminiHost.installed("", COMMAND)).toBe(false);
    expect(geminiHost.installed("{ not json", COMMAND)).toBe(false);
    expect(geminiHost.installed(JSON.stringify({ theme: "GitHub" }), COMMAND)).toBe(false);
  });

  it("is false once an upgrade has moved the guard, so the installer re-runs merge", () => {
    const old = geminiHost.merge(undefined, `${COMMAND.replace("guard.js", "guard-0.14.js")}`, HOLD);
    expect(geminiHost.installed(old, COMMAND)).toBe(false);
  });
});

describe("remove", () => {
  it("inverts merge on a document that was only ours", () => {
    const merged = geminiHost.merge(JSON.stringify({ theme: "GitHub" }, null, 2), COMMAND, HOLD);
    const removed = geminiHost.remove(merged);
    expect(JSON.parse(removed!)).toEqual({ theme: "GitHub" });
  });

  it("takes our handler and leaves the foreign one, group shape included", () => {
    const existing = JSON.stringify({
      hooks: {
        BeforeTool: [
          { matcher: "write_file", hooks: [{ name: "security-check", type: "command", command: "./security.sh", timeout: 5000 }] },
        ],
        AfterTool: [{ hooks: [{ type: "command", command: "./log.sh" }] }],
      },
    });
    const merged = geminiHost.merge(existing, COMMAND, HOLD);
    const doc = JSON.parse(geminiHost.remove(merged)!);
    expect(doc.hooks.BeforeTool).toEqual([
      { matcher: "write_file", hooks: [{ name: "security-check", type: "command", command: "./security.sh", timeout: 5000 }] },
    ]);
    expect(doc.hooks.AfterTool).toEqual([{ hooks: [{ type: "command", command: "./log.sh" }] }]);
    expect(geminiHost.installed(JSON.stringify(doc), COMMAND)).toBe(false);
  });

  it("keeps a neighbour that shares our group", () => {
    const merged = JSON.parse(geminiHost.merge(undefined, COMMAND, HOLD));
    merged.hooks.BeforeTool[0].hooks.push({ type: "command", command: "./their-audit.sh" });
    const doc = JSON.parse(geminiHost.remove(JSON.stringify(merged))!);
    expect(doc.hooks.BeforeTool[0].hooks).toEqual([{ type: "command", command: "./their-audit.sh" }]);
  });

  it("returns undefined when there is nothing of ours to remove", () => {
    expect(geminiHost.remove(undefined)).toBeUndefined();
    expect(geminiHost.remove("")).toBeUndefined();
    expect(geminiHost.remove("{ not json")).toBeUndefined();
    expect(geminiHost.remove(JSON.stringify({ theme: "GitHub" }))).toBeUndefined();
    expect(
      geminiHost.remove(JSON.stringify({ hooks: { BeforeTool: [{ hooks: [{ type: "command", command: "./x.sh" }] }] } })),
    ).toBeUndefined();
  });
});
