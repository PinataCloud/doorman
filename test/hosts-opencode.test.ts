/**
 * The OpenCode host adapter — the second PLUGIN-artefact host.
 *
 * Three families of promise, as for OpenClaw:
 *  · SIDECAR SURGERY on `<config>/doorman-guard.json`, a file that is ours
 *    but may carry somebody's extra keys: those survive merge and remove, and
 *    an unparseable file is refused.
 *  · THE ARTEFACT is the same bytes on every machine — the guard command
 *    travels in the sidecar — exports exactly ONE plugin function (OpenCode
 *    calls every exported function as a plugin), and imports nothing from
 *    OpenCode.
 *  · THE PLUGIN'S HOOK fails open: only an explicit deny from the guard throws;
 *    silence, an exit code, a timeout and an `ask` all let the call run.
 *
 * Every payload here is DOCS-DERIVED (see `_provenance`): OpenCode is not
 * installed on the development Mac. A live run is still owed before this host
 * is called verified.
 */

import { chmodSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { afterAll, describe, expect, it } from "vitest";
import {
  OPENCODE_PLUGIN_ID,
  OPENCODE_PLUGIN_SOURCE,
  opencodeConfigDir,
  opencodeHost,
  opencodePluginPath,
  opencodeSidecarPath,
} from "../main/guard/hosts/opencode.js";
import { evaluateToolCall, parsePolicy } from "../main/guard/decision.js";
import { GUARD_COMMAND_MARKER } from "../main/guard/policy.js";

const FIXTURES = join(fileURLToPath(new URL(".", import.meta.url)), "fixtures/hooks/opencode");
const fixture = (name: string): Record<string, unknown> =>
  JSON.parse(readFileSync(join(FIXTURES, `${name}.json`), "utf8")) as Record<string, unknown>;

const COMMAND = `node "/Users/dev/Library/Application Support/Doorman/doorman/guard/guard.js" --host opencode`;
const HOLD = 60;
const HOME = "/Users/dev";
const parse = (doc: string): Record<string, unknown> => JSON.parse(doc) as Record<string, unknown>;

describe("the fixtures themselves", () => {
  it("all parse and all say they are not recordings", () => {
    const files = readdirSync(FIXTURES).filter((f) => f.endsWith(".json"));
    expect(files.length).toBeGreaterThanOrEqual(6);
    for (const file of files) {
      const payload = fixture(file.replace(/\.json$/, ""));
      expect(String(payload._provenance), file).toContain("not a live recording");
      expect(payload.hook_event_name, file).toBe("tool.execute.before");
    }
  });
});

describe("paths", () => {
  it("resolves the config dir from OPENCODE_CONFIG_DIR, then XDG_CONFIG_HOME, then ~/.config", () => {
    expect(opencodeConfigDir(HOME, {})).toBe("/Users/dev/.config/opencode");
    expect(opencodeConfigDir(HOME, { XDG_CONFIG_HOME: "/xdg" })).toBe("/xdg/opencode");
    expect(opencodeConfigDir(HOME, { OPENCODE_CONFIG_DIR: "/srv/oc " })).toBe("/srv/oc");
    expect(opencodeSidecarPath(HOME, {})).toBe("/Users/dev/.config/opencode/doorman-guard.json");
    // The plugin lives INSIDE the plugins directory; the sidecar beside it —
    // every file in that directory is loaded as a plugin.
    expect(opencodePluginPath(HOME, {})).toBe("/Users/dev/.config/opencode/plugins/doorman-guard.js");
    expect(opencodeHost.documents(HOME, {})).toEqual([
      { path: "/Users/dev/.config/opencode/doorman-guard.json", level: "user" },
      { path: "/Users/dev/.config/opencode/opencode.json", level: "system" },
    ]);
  });
});

describe("sidecar surgery", () => {
  it("writes the command and a timeout above the hold window, idempotently", () => {
    const doc = opencodeHost.merge(undefined, COMMAND, HOLD);
    expect(parse(doc)).toEqual({ command: COMMAND, timeoutMs: (HOLD + 15) * 1000 });
    expect(doc).toContain(GUARD_COMMAND_MARKER);
    expect(opencodeHost.installed(doc, COMMAND)).toBe(true);
    expect(opencodeHost.merge(doc, COMMAND, HOLD)).toBe(doc);
    expect(parse(opencodeHost.merge(undefined, COMMAND, HOLD, 10)).timeoutMs).toBe(10_000);
  });

  it("keeps somebody's extra keys through merge and remove, and refreshes a stale command", () => {
    const before = JSON.stringify({ note: "keep me", command: "stale", timeoutMs: 1 });
    const merged = opencodeHost.merge(before, COMMAND, HOLD);
    expect(parse(merged)).toEqual({ note: "keep me", command: COMMAND, timeoutMs: 75_000 });
    expect(opencodeHost.installed(merged, "stale")).toBe(false);
    const removed = opencodeHost.remove(merged)!;
    expect(parse(removed)).toEqual({ note: "keep me" });
    expect(removed).not.toContain(GUARD_COMMAND_MARKER);
    expect(opencodeHost.remove(removed)).toBeUndefined();
  });

  it("refuses a sidecar it cannot parse, and removes nothing from one", () => {
    expect(() => opencodeHost.merge("{ not json", COMMAND, HOLD)).toThrow(/not valid JSON/);
    expect(opencodeHost.remove("{ not json")).toBeUndefined();
    expect(opencodeHost.remove(undefined)).toBeUndefined();
    expect(opencodeHost.installed("{ not json", COMMAND)).toBe(false);
  });
});

describe("normalizeInput", () => {
  it("maps bash onto Bash { command }, workdir winning over the session directory as cwd", () => {
    expect(opencodeHost.normalizeInput(fixture("bash1"))).toEqual({
      session_id: "ses_01JOPENCODEDEMO0001",
      cwd: "/Users/dev/projects/api/infra",
      tool_name: "Bash",
      tool_input: { command: "aws s3 rm s3://prod-backups --recursive", timeout: 120000, workdir: "/Users/dev/projects/api/infra" },
    });
    expect(opencodeHost.normalizeInput({ hook_event_name: "tool.execute.before", tool_name: "bash", tool_input: { command: "ls" }, cwd: "/w" })?.cwd).toBe("/w");
  });

  it("maps edit / write / read onto Claude's field names, folding OpenCode's camelCase", () => {
    expect(opencodeHost.normalizeInput(fixture("edit2"))?.tool_input).toEqual({
      replaceAll: false,
      file_path: "/Users/dev/projects/api/src/config.ts",
      old_string: 'const HOST = "api.example.com";',
      new_string: 'const HOST = "staging.example.com";',
    });
    const write = opencodeHost.normalizeInput(fixture("write3"))!;
    expect(write.tool_name).toBe("Write");
    expect(write.tool_input).toEqual({
      file_path: "/Users/dev/projects/api/.env",
      content: "OPENAI_API_KEY=sk-proj-abc123def456ghi789jkl012mno345pqr678\n",
    });
    // The detectors see it: a credential written into a dotenv file.
    expect(evaluateToolCall(write, parsePolicy(undefined)).findings.length).toBeGreaterThan(0);
    expect(opencodeHost.normalizeInput(fixture("read4"))).toEqual({
      session_id: "ses_01JOPENCODEDEMO0001",
      cwd: "/Users/dev/projects/api",
      tool_name: "Read",
      tool_input: { offset: 0, limit: 200, file_path: "/Users/dev/.aws/credentials" },
    });
  });

  it("maps webfetch onto WebFetch { url } and apply_patch onto a Write naming every file", () => {
    expect(opencodeHost.normalizeInput(fixture("webfetch5"))).toMatchObject({ tool_name: "WebFetch", tool_input: { url: "https://pastebin.com/raw/x9Yz1AbC", format: "text" } });
    const patch = opencodeHost.normalizeInput(fixture("apply_patch6"))!;
    expect(patch.tool_name).toBe("Write");
    expect(patch.tool_input).toMatchObject({
      file_path: "deploy/secrets.yaml",
      file_paths: ["deploy/secrets.yaml", "deploy/.env"],
    });
    expect(String((patch.tool_input as Record<string, unknown>).content)).toContain("wJalrXUtnFEMI/S5FRSUZ/tQjWbrCYPZPAKTFWYN");
    // No URL → the call passes as itself rather than as an empty fetch.
    expect(opencodeHost.normalizeInput({ tool_name: "webfetch", tool_input: { format: "text" } })?.tool_name).toBe("webfetch");
  });

  it("passes MCP tools (server_tool, unsplittable) and task through under their own names", () => {
    const mcp = opencodeHost.normalizeInput(fixture("mcp7"))!;
    expect(mcp.tool_name).toBe("linear_create_comment");
    expect(JSON.stringify(mcp.tool_input)).toContain("AKIAMQHGCTEF5EUSLEJR");
    expect(opencodeHost.normalizeInput(fixture("task8"))?.tool_name).toBe("task");
  });

  it("ignores other events and non-objects", () => {
    expect(opencodeHost.normalizeInput({ hook_event_name: "tool.execute.after", tool_name: "bash", tool_input: {} })).toBeUndefined();
    expect(opencodeHost.normalizeInput({ hook_event_name: "tool.execute.before" })).toBeUndefined();
    expect(opencodeHost.normalizeInput(null)).toBeUndefined();
    expect(opencodeHost.normalizeInput("bash")).toBeUndefined();
  });
});

describe("output contract", () => {
  it("prints nothing on allow, a deny with its reason, and an ask the plugin lets through", () => {
    expect(opencodeHost.emit("allow")).toEqual({ exitCode: 0 });
    expect(JSON.parse(opencodeHost.emit("deny", "Secret in command").stdout!)).toEqual({ decision: "deny", reason: "Secret in command" });
    const asked = JSON.parse(opencodeHost.warn("Looks risky").stdout!) as Record<string, string>;
    expect(asked.decision).toBe("ask");
    expect(asked.reason).toContain("continuing");
    expect(opencodeHost.supportsNativeAsk).toBe(false);
    expect(opencodeHost.exitSemantics).toBe("fail-open");
  });
});

describe("the plugin artefact", () => {
  it("is one machine-independent file inside the plugins directory, with exactly one export", () => {
    const files = opencodeHost.artifacts!(HOME, {});
    expect(files.map((f) => f.path)).toEqual(["/Users/dev/.config/opencode/plugins/doorman-guard.js"]);
    expect(files[0]!.content).not.toContain("/Users/dev");
    expect(files[0]!.content).not.toContain(GUARD_COMMAND_MARKER);
    expect(opencodeHost.artifacts!("/Users/other", { OPENCODE_CONFIG_DIR: "/srv/oc" })[0]!.path).toBe("/srv/oc/plugins/doorman-guard.js");
    // OpenCode calls every exported function as a plugin: only DoormanGuard may be exported.
    const exports = [...OPENCODE_PLUGIN_SOURCE.matchAll(/^export\s+(?:const|function|async function|default)\s+(\w+)/gm)].map((m) => m[1]);
    expect(exports).toEqual(["DoormanGuard"]);
    expect(OPENCODE_PLUGIN_SOURCE).not.toContain("@opencode-ai/plugin");
  });
});

describe("the plugin itself", () => {
  const dir = mkdtempSync(join(tmpdir(), "doorman-opencode-plugin-"));
  afterAll(() => rmSync(dir, { recursive: true, force: true }));
  // Lay it out as OpenCode would: <config>/plugins/doorman-guard.mjs beside
  // <config>/doorman-guard.json.
  const pluginsDir = join(dir, "plugins");
  writeFileSync(join(dir, "placeholder"), "");
  rmSync(join(dir, "placeholder"));
  const load = async () => {
    const { mkdirSync } = await import("node:fs");
    mkdirSync(pluginsDir, { recursive: true });
    writeFileSync(join(pluginsDir, "doorman-guard.mjs"), OPENCODE_PLUGIN_SOURCE);
    const mod = (await import(pathToFileURL(join(pluginsDir, "doorman-guard.mjs")).href)) as {
      DoormanGuard: ((ctx: unknown) => Promise<Record<string, (input: unknown, output: unknown) => Promise<void>>>) & {
        internals: {
          sidecarCandidates(env: Record<string, string>, selfUrl: string): string[];
          readSidecar(env: Record<string, string>, selfUrl: string): Record<string, unknown> | undefined;
          envelopeFor(input: unknown, output: unknown, ctx: unknown): Record<string, unknown>;
          createHook(ctx: unknown, env: Record<string, string>, selfUrl: string): (input: unknown, output: unknown) => Promise<void>;
          PLUGIN_ID: string;
        };
      };
    };
    return mod;
  };
  /** A stand-in guard: a node one-liner that prints a fixed decision. */
  const fakeGuard = (stdout: string, exitCode = 0) => {
    const script = join(dir, `guard-${Math.random().toString(36).slice(2)}.js`);
    writeFileSync(script, `process.stdin.resume(); process.stdin.on("end", () => { process.stdout.write(${JSON.stringify(stdout)}); process.exit(${exitCode}); });`);
    chmodSync(script, 0o755);
    return `${JSON.stringify(process.execPath)} ${JSON.stringify(script)}`;
  };
  const selfUrl = pathToFileURL(join(pluginsDir, "doorman-guard.mjs")).href;

  it("finds the sidecar beside its own directory first, then the configured dir, then ~/.config", async () => {
    const mod = await load();
    const candidates = mod.DoormanGuard.internals.sidecarCandidates({ OPENCODE_CONFIG_DIR: "/srv/oc", HOME: "/Users/dev" }, selfUrl);
    expect(candidates[0]).toBe(join(dir, "doorman-guard.json"));
    expect(candidates[1]).toBe("/srv/oc/doorman-guard.json");
    expect(candidates[2]!.endsWith("/.config/opencode/doorman-guard.json")).toBe(true);
    expect(mod.DoormanGuard.internals.readSidecar({}, selfUrl)).toBeUndefined();
    writeFileSync(join(dir, "doorman-guard.json"), opencodeHost.merge(undefined, COMMAND, HOLD));
    expect(mod.DoormanGuard.internals.readSidecar({}, selfUrl)).toMatchObject({ command: COMMAND });
  });

  it("builds the envelope the adapter normalizes", async () => {
    const mod = await load();
    const env = mod.DoormanGuard.internals.envelopeFor(
      { tool: "bash", sessionID: "ses_1", callID: "call_1" },
      { args: { command: "ls" } },
      { directory: "/Users/dev/projects/api", worktree: "/Users/dev/projects/api" },
    );
    expect(env).toEqual({
      hook_event_name: "tool.execute.before",
      tool_name: "bash",
      tool_input: { command: "ls" },
      session_id: "ses_1",
      tool_call_id: "call_1",
      cwd: "/Users/dev/projects/api",
      worktree: "/Users/dev/projects/api",
    });
    expect(opencodeHost.normalizeInput(env)).toMatchObject({ tool_name: "Bash", session_id: "ses_1", cwd: "/Users/dev/projects/api" });
  });

  it("throws on a deny (the block), and lets silence, an ask, an exit code and a missing sidecar through", async () => {
    const mod = await load();
    const call = { tool: "bash", sessionID: "s", callID: "c" };
    const args = { args: { command: "rm -rf /" } };
    const run = (command: string | undefined) => {
      writeFileSync(join(dir, "doorman-guard.json"), command === undefined ? "{}" : JSON.stringify({ command, timeoutMs: 5000 }));
      return mod.DoormanGuard.internals.createHook({ directory: dir }, {}, selfUrl)(call, args);
    };
    await expect(run(fakeGuard('{"decision":"deny","reason":"Destructive command."}'))).rejects.toThrow("Destructive command.");
    await expect(run(fakeGuard(""))).resolves.toBeUndefined();
    await expect(run(fakeGuard('{"decision":"ask","reason":"Looks risky. …continuing."}'))).resolves.toBeUndefined();
    await expect(run(fakeGuard('{"decision":"deny","reason":"x"}', 1))).resolves.toBeUndefined();
    await expect(run(fakeGuard("not json"))).resolves.toBeUndefined();
    await expect(run(undefined)).resolves.toBeUndefined();
  });

  it("returns exactly one hook, under OpenCode's event name", async () => {
    const mod = await load();
    const hooks = await mod.DoormanGuard({ directory: dir });
    expect(Object.keys(hooks)).toEqual(["tool.execute.before"]);
    expect(typeof hooks["tool.execute.before"]).toBe("function");
    expect(mod.DoormanGuard.internals.PLUGIN_ID).toBe(OPENCODE_PLUGIN_ID);
  });
});
