/**
 * The Hermes Agent host adapter.
 *
 * Two families of promise are under test here and neither is cosmetic:
 *  · CONFIG SURGERY on a `config.yaml` that is the whole agent's configuration
 *    and that we edit WITHOUT a YAML library. Every unrelated key, every
 *    comment, every blank line and every foreign hook has to come out the
 *    other side byte-for-byte, and a document the line model cannot follow has
 *    to be refused rather than rewritten.
 *  · THE CONSENT COMPANION. Hermes silently skips an unconsented shell hook in
 *    a non-TTY run, so the allowlist entry is what makes the guard real for
 *    the gateway — and it must never touch anyone else's approvals.
 */

import { chmodSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  HERMES_PLUGIN_ID,
  HERMES_PLUGIN_MANIFEST,
  HERMES_PLUGIN_SOURCE,
  hermesHome,
  hermesHost,
  hermesPluginDir,
  withoutLegacyAllowlistEntries,
} from "../main/guard/hosts/hermes.js";
import { GUARD_COMMAND_MARKER, HOOK_TIMEOUT_SLACK_SECONDS } from "../main/guard/policy.js";

const FIXTURES = join(fileURLToPath(new URL(".", import.meta.url)), "fixtures/hooks/hermes");
const fixture = (name: string): Record<string, unknown> =>
  JSON.parse(readFileSync(join(FIXTURES, `${name}.json`), "utf8")) as Record<string, unknown>;

const COMMAND = `node "/Users/dev/Library/Application Support/Doorman/doorman/guard/guard.js" --host hermes`;
const HOLD = 60;
const TIMEOUT = HOLD + HOOK_TIMEOUT_SLACK_SECONDS;
// The command carries double quotes, so it goes out single-quoted.
/** The whole block a fresh install writes. */
const OUR_BLOCK = [
  "plugins:",
  "  enabled:",
  `    - ${HERMES_PLUGIN_ID}`,
  `  hook_callback_timeout: ${TIMEOUT}`,
  "  entries:",
  `    ${HERMES_PLUGIN_ID}:`,
  "      settings:",
  `        command: '${COMMAND}'`,
  `        timeout: ${TIMEOUT}`,
  "",
].join("\n");
/** The pre-2026-09-10 shell-hook entry an upgrade finds. */
const LEGACY_HOOK = `hooks:\n  pre_tool_call:\n    - command: '${COMMAND}'\n      timeout: ${TIMEOUT}\n`;

describe("the fixtures themselves", () => {
  it("all parse and all say where they came from", () => {
    const files = readdirSync(FIXTURES).filter((f) => f.endsWith(".json"));
    expect(files.length).toBeGreaterThanOrEqual(4);
    for (const file of files) {
      const payload = JSON.parse(readFileSync(join(FIXTURES, file), "utf8")) as Record<string, unknown>;
      // Either a live recording (terminal/write_file/read_file/patch,
      // 2026-09-08) or an honestly labelled docs-derived shape.
      expect(String(payload._provenance), file).toMatch(/recorded live|not a live recording/);
      expect(payload.hook_event_name, file).toBe("pre_tool_call");
    }
  });
});

describe("documents", () => {
  it("lives in ~/.hermes/config.yaml, and follows $HERMES_HOME exactly as Hermes does", () => {
    expect(hermesHost.documents("/Users/dev", {})).toEqual([
      { path: "/Users/dev/.hermes/config.yaml", level: "user" },
    ]);
    expect(hermesHost.documents("/Users/dev", { HERMES_HOME: "/srv/hermes" })[0]?.path).toBe(
      "/srv/hermes/config.yaml",
    );
    expect(hermesHome("/Users/dev", { HERMES_HOME: "  " })).toBe("/Users/dev/.hermes");
    expect(hermesHost.documentFormat).toBe("yaml");
    expect(hermesHost.presencePaths).toEqual([".hermes"]);
  });
});

describe("merge: the plugin entry in config.yaml", () => {
  it("writes the whole plugins block from nothing", () => {
    expect(hermesHost.merge(undefined, COMMAND, HOLD)).toBe(OUR_BLOCK);
    expect(hermesHost.installed(OUR_BLOCK, COMMAND)).toBe(true);
    expect(hermesHost.installed(OUR_BLOCK, `${COMMAND}-other`)).toBe(false);
  });

  it("appends after an unrelated document, touching nothing above it", () => {
    const before = "model:\n  provider: openrouter\n  default: anthropic/claude-haiku-4.5\n";
    const merged = hermesHost.merge(before, COMMAND, HOLD);
    expect(merged.startsWith(before)).toBe(true);
    expect(merged.slice(before.length)).toBe(OUR_BLOCK);
  });

  it("passes the installer's exact timeout through, capped at Hermes's 600 s plugin ceiling", () => {
    expect(hermesHost.merge(undefined, COMMAND, HOLD, 10)).toContain("hook_callback_timeout: 10");
    expect(hermesHost.merge(undefined, COMMAND, HOLD, 10)).toContain("        timeout: 10");
    expect(hermesHost.merge(undefined, COMMAND, 900, 900)).toContain("hook_callback_timeout: 600");
  });

  it("joins an existing enabled list and an existing entries mapping, keeping every other plugin", () => {
    const before = [
      "plugins:",
      "  enabled:",
      "    - memory-core",
      "  hook_callback_timeout: 30",
      "  entries:",
      "    memory-core:",
      "      settings:",
      "        depth: 3",
      "",
    ].join("\n");
    const merged = hermesHost.merge(before, COMMAND, HOLD);
    expect(merged).toBe(
      [
        "plugins:",
        "  enabled:",
        "    - memory-core",
        `    - ${HERMES_PLUGIN_ID}`,
        // Never lowered: 30 < ours, so raised to ours.
        `  hook_callback_timeout: ${TIMEOUT}`,
        "  entries:",
        "    memory-core:",
        "      settings:",
        "        depth: 3",
        `    ${HERMES_PLUGIN_ID}:`,
        "      settings:",
        `        command: '${COMMAND}'`,
        `        timeout: ${TIMEOUT}`,
        "",
      ].join("\n"),
    );
    expect(hermesHost.installed(merged, COMMAND)).toBe(true);
    // A LARGER budget somebody set is kept.
    const generous = hermesHost.merge(before.replace("hook_callback_timeout: 30", "hook_callback_timeout: 300"), COMMAND, HOLD);
    expect(generous).toContain("hook_callback_timeout: 300");
  });

  it("is idempotent, refreshes a stale command in place, and remove() puts a foreign document back", () => {
    const merged = hermesHost.merge(undefined, COMMAND, HOLD);
    expect(hermesHost.merge(merged, COMMAND, HOLD)).toBe(merged);
    const moved = hermesHost.merge(merged, `${COMMAND} --host later`, HOLD);
    expect(hermesHost.installed(moved, COMMAND)).toBe(false);
    expect(hermesHost.installed(moved, `${COMMAND} --host later`)).toBe(true);
    expect(moved.split(GUARD_COMMAND_MARKER).length - 1).toBe(1);

    const foreign = "someUnrelatedKey: keep\nplugins:\n  enabled:\n    - memory-core\n  entries:\n    memory-core:\n      settings:\n        depth: 3\n";
    const withOurs = hermesHost.merge(foreign, COMMAND, HOLD);
    const removed = hermesHost.remove(withOurs)!;
    // Our entry and our enabled item are gone; the raised timeout stays (see the header).
    // (A key we ADD to an existing block goes at its end — after `entries:`.)
    expect(removed).toBe(
      "someUnrelatedKey: keep\nplugins:\n  enabled:\n    - memory-core\n" +
        "  entries:\n    memory-core:\n      settings:\n        depth: 3\n" +
        `  hook_callback_timeout: ${TIMEOUT}\n`,
    );
    expect(hermesHost.remove(removed)).toBeUndefined();
  });

  it("removes the containers it alone filled — enabled:, entries:, plugins: — and no others", () => {
    const fresh = hermesHost.merge(undefined, COMMAND, HOLD);
    // Only hook_callback_timeout is left of the block we wrote.
    expect(hermesHost.remove(fresh)).toBe(`plugins:\n  hook_callback_timeout: ${TIMEOUT}\n`);
    const prefixed = hermesHost.merge("model:\n  provider: openrouter\n", COMMAND, HOLD);
    expect(hermesHost.remove(prefixed)).toBe(`model:\n  provider: openrouter\nplugins:\n  hook_callback_timeout: ${TIMEOUT}\n`);
  });

  it("drops a legacy shell-hook entry on upgrade, in the same pass, and remove() takes both out", () => {
    const upgraded = hermesHost.merge(`model:\n  provider: openrouter\n${LEGACY_HOOK}`, COMMAND, HOLD);
    expect(upgraded).not.toContain("pre_tool_call");
    expect(upgraded).not.toContain("hooks:");
    expect(upgraded.split(GUARD_COMMAND_MARKER).length - 1).toBe(1);
    expect(hermesHost.installed(upgraded, COMMAND)).toBe(true);
    // A foreign shell hook beside ours survives the upgrade.
    const mixed = hermesHost.merge(
      `hooks:\n  pre_tool_call:\n    - command: /opt/somebody-else/their-hook.sh\n      timeout: 5\n    - command: '${COMMAND}'\n      timeout: ${TIMEOUT}\n`,
      COMMAND,
      HOLD,
    );
    expect(mixed).toContain("/opt/somebody-else/their-hook.sh");
    expect(mixed.split(GUARD_COMMAND_MARKER).length - 1).toBe(1);
    // remove() on a never-upgraded legacy document still cleans it.
    expect(hermesHost.remove(LEGACY_HOOK)).toBe("");
    expect(hermesHost.installed(LEGACY_HOOK, COMMAND)).toBe(false);
  });

  it("refuses documents the line model cannot follow, and removes nothing from them", () => {
    for (const doc of ["{ not json", "[1, 2]", "plugins: {}\n", "plugins:\n  enabled: [memory-core]\n", "plugins:\n  enabled:\n    key: value\n", "- just\n- a list\n"]) {
      expect(() => hermesHost.merge(doc, COMMAND, HOLD), doc).toThrow();
      expect(hermesHost.installed(doc, COMMAND), doc).toBe(false);
    }
    expect(hermesHost.remove("{ not json")).toBeUndefined();
    // `enabled: []` is empty and can be opened; a duplicate top-level key cannot be followed.
    expect(hermesHost.merge("plugins:\n  enabled: []\n", COMMAND, HOLD)).toContain(`  enabled:\n    - ${HERMES_PLUGIN_ID}`);
  });
});

describe("the registry suite's shared documents", () => {
  it("preserves a foreign YAML hook entry and an unrelated key through merge AND remove", () => {
    const foreign = "someUnrelatedKey: keep\nhooks:\n  pre_tool_call:\n    - command: /opt/somebody-else/their-hook.sh\n      timeout: 5\n";
    const merged = hermesHost.merge(foreign, COMMAND, HOLD);
    expect(merged.startsWith(foreign)).toBe(true);
    expect(merged).toContain(`command: '${COMMAND}'`);
    const removed = hermesHost.remove(merged)!;
    expect(removed).toContain("/opt/somebody-else/their-hook.sh");
    expect(removed).toContain("someUnrelatedKey");
    expect(removed).not.toContain(GUARD_COMMAND_MARKER);
  });
});

describe("the legacy consent allowlist", () => {
  it("strips only our stale entries, and reports nothing to do honestly", () => {
    const doc = JSON.stringify({ approvals: [{ event: "pre_tool_call", command: "/opt/theirs.sh", approved_at: 1 }, { event: "pre_tool_call", command: COMMAND }] });
    const cleaned = withoutLegacyAllowlistEntries(doc)!;
    expect(JSON.parse(cleaned)).toEqual({ approvals: [{ event: "pre_tool_call", command: "/opt/theirs.sh", approved_at: 1 }] });
    expect(withoutLegacyAllowlistEntries(cleaned)).toBeUndefined();
    expect(withoutLegacyAllowlistEntries(undefined)).toBeUndefined();
    expect(withoutLegacyAllowlistEntries("{ not json")).toBeUndefined();
    // The descriptor no longer carries a companion: the plugin needs no consent entry.
    expect(hermesHost.companions).toBeUndefined();
  });
});

describe("normalizeInput", () => {
  it("reads terminal's legacy `code` alias as the command (tools/terminal_tool.py still honours it)", () => {
    expect(
      hermesHost.normalizeInput({ hook_event_name: "pre_tool_call", tool_name: "terminal", tool_input: { code: "rm -rf /" } })
        ?.tool_input,
    ).toEqual({ command: "rm -rf /" });
    // `command` wins when both are present.
    expect(
      hermesHost.normalizeInput({ tool_name: "terminal", tool_input: { command: "ls", code: "rm -rf /" } })?.tool_input,
    ).toEqual({ command: "ls" });
  });

  it("maps a live terminal call onto Bash { command } with Hermes's session id and cwd", () => {
    // The recorded stdin (Hermes 0.21.1, 2026-09-08): `extra` rides along
    // with task_id / tool_call_id / turn_id / api_request_id and is dropped.
    expect(hermesHost.normalizeInput(fixture("terminal"))).toEqual({
      session_id: "20260908_144708_bc03e9",
      cwd: "/Users/dev/projects/api",
      tool_name: "Bash",
      tool_input: { command: "cat notes/e2e.txt && echo DOORMAN_DENY_ME" },
    });
    expect((fixture("terminal").extra as Record<string, unknown>).tool_call_id).toBe("toolu_bdrk_0179qNoGGdpWAgRpe5hg9C8a");
  });

  it("keeps terminal's run options (background, timeout, workdir, pty, notify) beside the command", () => {
    // `workdir` is where a relative command lands, and every key is text the
    // detectors scan (P2, 2026-09-10) — they used to be dropped for a smaller
    // card. The `code` alias is folded into `command`, never kept twice.
    expect(
      hermesHost.normalizeInput({
        hook_event_name: "pre_tool_call",
        tool_name: "terminal",
        tool_input: { command: "aws s3 rm s3://prod-backups --recursive", background: false, timeout: 120, workdir: "/Users/dev/projects/api" },
        session_id: "sess_7f3a9c2e",
        cwd: "/Users/dev/projects/api",
      }),
    ).toEqual({
      session_id: "sess_7f3a9c2e",
      cwd: "/Users/dev/projects/api",
      tool_name: "Bash",
      tool_input: { background: false, timeout: 120, workdir: "/Users/dev/projects/api", command: "aws s3 rm s3://prod-backups --recursive" },
    });
    expect(
      hermesHost.normalizeInput({ tool_name: "terminal", tool_input: { code: "ls", background: true } })?.tool_input,
    ).toEqual({ background: true, command: "ls" });
  });

  it("maps live write_file / patch / read_file onto Write / Edit / Read with Claude's field names", () => {
    // Hermes's file tools really do spell it `path` (+ `old_string` /
    // `new_string`) on the wire — recorded, not read off tools/file_tools.py.
    expect(hermesHost.normalizeInput(fixture("write_file"))).toEqual({
      session_id: "20260908_144708_bc03e9",
      cwd: "/Users/dev/projects/api",
      tool_name: "Write",
      tool_input: { file_path: "notes/e2e.txt", content: "hello from e2e" },
    });
    expect(hermesHost.normalizeInput(fixture("patch"))).toEqual({
      session_id: "20260908_144708_bc03e9",
      cwd: "/Users/dev/projects/api",
      tool_name: "Edit",
      tool_input: { file_path: "notes/e2e.txt", old_string: "hello", new_string: "goodbye" },
    });
    expect(hermesHost.normalizeInput(fixture("read_file"))).toEqual({
      session_id: "20260908_144708_bc03e9",
      cwd: "/Users/dev/projects/api",
      tool_name: "Read",
      tool_input: { file_path: "notes/e2e.txt" },
    });
    // An absolute path passes; `offset`/`limit` and `replace_all` ride along
    // beside the guard keys (P2, 2026-09-10) rather than being dropped.
    expect(
      hermesHost.normalizeInput({ tool_name: "read_file", tool_input: { path: "/Users/dev/.ssh/id_ed25519", offset: 1, limit: 40 } })
        ?.tool_input,
    ).toEqual({ offset: 1, limit: 40, file_path: "/Users/dev/.ssh/id_ed25519" });
    expect(
      hermesHost.normalizeInput({
        tool_name: "patch",
        tool_input: { path: "/Users/dev/projects/api/src/config.ts", old_string: "a", new_string: "b", replace_all: true },
      })?.tool_input,
    ).toEqual({ replace_all: true, file_path: "/Users/dev/projects/api/src/config.ts", old_string: "a", new_string: "b" });
  });

  it("maps web_extract's urls[] onto WebFetch { url }, keeping the rest of the list", () => {
    expect(hermesHost.normalizeInput(fixture("web_extract"))).toMatchObject({
      tool_name: "WebFetch",
      tool_input: {
        url: "https://pastebin.com/raw/x9Yz8Wv7",
        urls: ["https://pastebin.com/raw/x9Yz8Wv7", "https://example.com/notes"],
      },
    });
    expect(
      hermesHost.normalizeInput({ tool_name: "web_extract", tool_input: { urls: ["https://a.example"] } })?.tool_input,
    ).toEqual({ url: "https://a.example" });
    // No URL at all: the call passes through as itself.
    expect(hermesHost.normalizeInput({ tool_name: "web_extract", tool_input: { char_limit: 5 } })).toMatchObject({
      tool_name: "web_extract",
    });
  });

  it("passes every other tool through under its own name", () => {
    expect(hermesHost.normalizeInput(fixture("search_files"))).toMatchObject({
      tool_name: "search_files",
      tool_input: { pattern: "AWS_SECRET" },
    });
  });

  it("ignores non-tool events and non-objects", () => {
    expect(
      hermesHost.normalizeInput({ hook_event_name: "post_tool_call", tool_name: "terminal", tool_input: {} }),
    ).toBeUndefined();
    expect(
      hermesHost.normalizeInput({ hook_event_name: "pre_llm_call", tool_name: null, tool_input: null }),
    ).toBeUndefined();
    expect(hermesHost.normalizeInput(null)).toBeUndefined();
    expect(hermesHost.normalizeInput("nope")).toBeUndefined();
    expect(hermesHost.normalizeInput([])).toBeUndefined();
  });
});

describe("emit", () => {
  it("prints nothing on allow", () => {
    expect(hermesHost.emit("allow")).toEqual({ exitCode: 0 });
  });

  it("blocks with Claude Code's shape on exit 0, the reason in the field the plugin and a shell hook both read", () => {
    expect(JSON.parse(hermesHost.emit("deny", "Secret in command").stdout!)).toEqual({ decision: "block", reason: "Secret in command" });
    expect(hermesHost.emit("deny").exitCode).toBe(0);
  });

  it("asks natively only for a plugin envelope, and continues silently otherwise", () => {
    // The plugin turns `approval: true` into Hermes's approve directive.
    expect(JSON.parse(hermesHost.emit("ask", "Looks risky").stdout!)).toEqual({ decision: "ask", reason: "Looks risky", approval: true });
    // The `continue` path (warn): no channel, no output, the call runs.
    expect(hermesHost.warn("Looks risky")).toEqual({ exitCode: 0 });
    expect(hermesHost.supportsNativeAsk).toBe(false);
    expect(hermesHost.supportsNativeAskFor!({ hook_event_name: "pre_tool_call", tool_name: "terminal", native_ask: true })).toBe(true);
    expect(hermesHost.supportsNativeAskFor!(fixture("terminal"))).toBe(false);
    expect(hermesHost.maxHoldSeconds).toBeUndefined();
  });
});

describe("the plugin artefacts", () => {
  it("are two machine-independent files under $HERMES_HOME/plugins/doorman-guard", () => {
    const files = hermesHost.artifacts!("/Users/dev", {});
    expect(files.map((f) => f.path)).toEqual([
      "/Users/dev/.hermes/plugins/doorman-guard/plugin.yaml",
      "/Users/dev/.hermes/plugins/doorman-guard/__init__.py",
    ]);
    for (const file of files) {
      expect(file.content).not.toContain("/Users/dev");
      expect(file.content).not.toContain(GUARD_COMMAND_MARKER);
    }
    expect(hermesPluginDir("/Users/x", { HERMES_HOME: "/srv/h" })).toBe("/srv/h/plugins/doorman-guard");
    expect(HERMES_PLUGIN_MANIFEST).toContain(`name: ${HERMES_PLUGIN_ID}`);
    expect(HERMES_PLUGIN_SOURCE).toContain("def register(ctx)");
    expect(HERMES_PLUGIN_SOURCE).toContain('ctx.register_hook(EVENT');
    // Standard library only — no Hermes import to break on.
    expect(HERMES_PLUGIN_SOURCE).not.toMatch(/^(from|import) (hermes|agent|tools)/m);
  });
});

describe("the plugin itself (python3)", () => {
  const python = spawnSync("python3", ["--version"]).status === 0;
  const dir = mkdtempSync(join(tmpdir(), "doorman-hermes-plugin-"));
  const pluginDir = join(dir, "doorman_guard");
  writeFileSync(join(dir, "placeholder"), "");
  rmSync(join(dir, "placeholder"));
  /** A stand-in guard: a node script that prints a fixed decision. */
  const fakeGuard = (stdout: string, exit = 0): string => {
    const script = join(dir, `guard-${Math.random().toString(36).slice(2)}.js`);
    writeFileSync(script, `process.stdin.resume(); process.stdin.on("end", () => { process.stdout.write(${JSON.stringify(stdout)}); process.exit(${exit}); });`);
    chmodSync(script, 0o755);
    return `${JSON.stringify(process.execPath)} ${JSON.stringify(script)}`;
  };
  /** Drive register() with a fake ctx and fire the hook once; print the directive. */
  const drive = (command: string | undefined, toolName: string, args: Record<string, unknown>, presence: "cli" | "gateway" | "none" = "cli"): unknown => {
    const { mkdirSync } = require("node:fs") as typeof import("node:fs");
    mkdirSync(pluginDir, { recursive: true });
    writeFileSync(join(pluginDir, "__init__.py"), HERMES_PLUGIN_SOURCE);
    const harness = `
import json, sys, types
sys.path.insert(0, ${JSON.stringify(dir)})
# A stand-in for Hermes's tools.approval: presence is what the harness says.
approval = types.ModuleType("tools.approval")
approval._presence = lambda cb=None: (None, ${presence === "cli" ? "True" : "False"}, ${presence === "gateway" ? "True" : "False"}, False)
tools = types.ModuleType("tools"); tools.approval = approval
sys.modules["tools"] = tools; sys.modules["tools.approval"] = approval
import doorman_guard as plugin
class Ctx:
    def __init__(self):
        self.hooks = {}
    def get_config(self, key, default=None):
        return {"command": ${JSON.stringify(command ?? null)}, "timeout": 5}.get(key, default) if ${command === undefined ? "False" : "True"} else default
    def register_hook(self, name, cb):
        self.hooks[name] = cb
ctx = Ctx()
plugin.register(ctx)
hook = ctx.hooks.get("pre_tool_call")
if hook is None:
    print(json.dumps({"registered": False}))
else:
    out = hook(${JSON.stringify(toolName)}, ${JSON.stringify(args)}, session_id="s1", task_id="t1", tool_call_id="c1", turn_id="u1")
    print(json.dumps({"registered": True, "directive": out}))
`;
    const run = spawnSync("python3", ["-c", harness], { encoding: "utf8" });
    if (run.status !== 0) throw new Error(run.stderr);
    return JSON.parse(run.stdout.trim().split("\n").pop()!);
  };

  it.skipIf(!python)("registers pre_tool_call only when a command is configured", () => {
    expect(drive(undefined, "terminal", { command: "ls" })).toEqual({ registered: false });
  });

  it.skipIf(!python)("blocks on a deny with the guard's reason, approves on a native ask with an exact-call rule_key, and proceeds on everything else", () => {
    expect(drive(fakeGuard('{"decision":"block","reason":"Destructive command."}'), "terminal", { command: "rm -rf x" })).toEqual({
      registered: true,
      directive: { action: "block", message: "Destructive command." },
    });
    const asked = drive(fakeGuard('{"decision":"ask","reason":"Held.","approval":true}'), "terminal", { command: "rm -rf x" }) as { directive: Record<string, string> };
    expect(asked.directive.action).toBe("approve");
    expect(asked.directive.message).toBe("Held.");
    expect(asked.directive.rule_key).toMatch(/^doorman:terminal:[0-9a-f]{16}$/);
    // Same tool, other arguments → another grain for Hermes's [a]lways.
    const other = drive(fakeGuard('{"decision":"ask","reason":"Held.","approval":true}'), "terminal", { command: "rm -rf y" }) as { directive: Record<string, string> };
    expect(other.directive.rule_key).not.toBe(asked.directive.rule_key);
    // Silence, an ask without the approval flag (the `continue` path), a non-zero exit, garbage: proceed.
    for (const guard of [fakeGuard(""), fakeGuard('{"decision":"ask","reason":"x"}'), fakeGuard('{"decision":"block","reason":"x"}', 1), fakeGuard("not json"), "/nonexistent/guard"]) {
      expect(drive(guard, "terminal", { command: "ls" })).toEqual({ registered: true, directive: null });
    }
  });

  it.skipIf(!python)("claims a native ask only where Hermes's gate reaches a person (interactive CLI or gateway)", () => {
    const script = join(dir, "echo-ask-guard.js");
    writeFileSync(
      script,
      `let s=""; process.stdin.on("data", (d) => (s += d)); process.stdin.on("end", () => { const p = JSON.parse(s); process.stdout.write(JSON.stringify({ decision: "block", reason: String(p.native_ask) })); });`,
    );
    const command = `${JSON.stringify(process.execPath)} ${JSON.stringify(script)}`;
    const flag = (presence: "cli" | "gateway" | "none") => (drive(command, "terminal", { command: "ls" }, presence) as { directive: { message: string } }).directive.message;
    expect(flag("cli")).toBe("true");
    expect(flag("gateway")).toBe("true");
    // A one-shot / cron run: Hermes would auto-resolve the escalation itself,
    // so the guard's unattended rule must decide instead.
    expect(flag("none")).toBe("false");
  });

  it.skipIf(!python)("sends the shell hook's payload shape plus native_ask and the observability ids", () => {
    const script = join(dir, "echo-guard.js");
    writeFileSync(
      script,
      `let s=""; process.stdin.on("data", (d) => (s += d)); process.stdin.on("end", () => { const p = JSON.parse(s); process.stdout.write(JSON.stringify({ decision: "block", reason: JSON.stringify(p) })); });`,
    );
    const out = drive(`${JSON.stringify(process.execPath)} ${JSON.stringify(script)}`, "write_file", { path: "/tmp/x", content: "hi" }) as { directive: { message: string } };
    const payload = JSON.parse(out.directive.message) as Record<string, unknown>;
    expect(payload).toMatchObject({
      hook_event_name: "pre_tool_call",
      tool_name: "write_file",
      tool_input: { path: "/tmp/x", content: "hi" },
      session_id: "s1",
      extra: { task_id: "t1", tool_call_id: "c1", turn_id: "u1" },
      native_ask: true,
      via: "plugin",
    });
    expect(typeof payload.cwd).toBe("string");
    // …and the adapter reads it as a Write with the native-ask flag.
    expect(hermesHost.normalizeInput(payload)).toMatchObject({ tool_name: "Write", session_id: "s1" });
    expect(hermesHost.supportsNativeAskFor!(payload)).toBe(true);
  });

  it.skipIf(!python)("cleans up", () => {
    rmSync(dir, { recursive: true, force: true });
  });
});
