/**
 * The Claude-family factory (main/guard/hosts/claude-family.ts): the
 * four document surgeries, the tool-map normalization and the four decision
 * dialects, exercised through minimal specs rather than through any one host —
 * so a host file stays a table of facts and this stays the mechanics.
 */

import { describe, expect, it } from "vitest";
import {
  claudeFamilyHost,
  mcpFirstUnderscore,
  type ClaudeFamilySpec,
} from "../main/guard/hosts/claude-family.js";
import { GUARD_COMMAND_MARKER } from "../main/guard/policy.js";

const COMMAND = `node "/Users/x/Library/Application Support/Doorman/doorman/guard/guard.js" --host fam`;
const FOREIGN = "/opt/somebody-else/their-hook.sh";

function spec(overrides: Partial<ClaudeFamilySpec>): ClaudeFamilySpec {
  return {
    id: "fam",
    label: "Family",
    source: "fam",
    presencePaths: [".fam"],
    documents: (home) => [{ path: `${home}/.fam/settings.json`, level: "user" }],
    invalidDocument: "~/.fam/settings.json",
    style: "grouped",
    event: "PreToolUse",
    acceptedEvents: ["PreToolUse"],
    timeoutUnit: "seconds",
    matcher: ".*",
    tools: {
      sh: { to: "Bash", args: { command: "cmd" } },
      put: { to: "Write", args: { file_path: ["path", "file_path"], content: "content" } },
    },
    decision: "hook-specific",
    warn: "system-message",
    supportsNativeAsk: true,
    exitSemantics: "fail-open",
    ...overrides,
  };
}

describe("grouped JSON surgery", () => {
  const host = claudeFamilyHost(spec({}));

  it("creates the document, is idempotent, writes the timeout in seconds and restores on remove", () => {
    const doc = host.merge(undefined, COMMAND, 60, 75);
    const parsed = JSON.parse(doc);
    expect(parsed.hooks.PreToolUse).toEqual([
      { matcher: ".*", hooks: [{ type: "command", command: COMMAND, timeout: 75 }] },
    ]);
    expect(host.merge(doc, COMMAND, 60, 75)).toBe(doc);
    expect(host.installed(doc, COMMAND)).toBe(true);
    expect(host.installed(doc, `${COMMAND} --other`)).toBe(false);
    expect(host.remove(doc)).toBe("{}\n");
    expect(host.remove("{}\n")).toBeUndefined();
  });

  it("recognises its own entry at a Windows path: replaces it on update, removes it on uninstall", () => {
    // Windows writes the bundle path with backslashes; the marker is
    // `doorman/guard`, so a slash-only match treated our entry as foreign.
    const win = `node "C:\\Users\\x\\AppData\\Roaming\\Doorman\\doorman\\guard\\guard.js" --host fam`;
    const doc = host.merge(undefined, win, 60, 75);
    expect(host.installed(doc, win)).toBe(true);
    const moved = host.merge(doc, `${win} --newer`, 60, 75);
    expect(JSON.parse(moved).hooks.PreToolUse[0].hooks).toHaveLength(1);
    expect(host.remove(moved)).toBe("{}\n");
  });

  it("multiplies into milliseconds when the host wants them", () => {
    const ms = claudeFamilyHost(spec({ timeoutUnit: "milliseconds" }));
    const parsed = JSON.parse(ms.merge(undefined, COMMAND, 60, 75));
    expect(parsed.hooks.PreToolUse[0].hooks[0].timeout).toBe(75_000);
  });

  it("falls back to hold + slack when no timeout is passed", () => {
    const parsed = JSON.parse(host.merge(undefined, COMMAND, 100));
    expect(parsed.hooks.PreToolUse[0].hooks[0].timeout).toBe(115);
  });

  it("updates our handler in place inside a shared group and never touches the foreign one", () => {
    const before = JSON.stringify({
      keep: 1,
      hooks: {
        PreToolUse: [
          { matcher: "Bash", hooks: [{ type: "command", command: FOREIGN, timeout: 5 }, { type: "command", command: `${COMMAND} --old`, timeout: 9 }] },
        ],
        Stop: [{ hooks: [{ type: "command", command: "echo done" }] }],
      },
    });
    const merged = JSON.parse(host.merge(before, COMMAND, 60, 75));
    expect(merged.keep).toBe(1);
    expect(merged.hooks.Stop).toEqual([{ hooks: [{ type: "command", command: "echo done" }] }]);
    // Shared group: shape (matcher "Bash") preserved, our handler replaced in place.
    expect(merged.hooks.PreToolUse).toEqual([
      { matcher: "Bash", hooks: [{ type: "command", command: FOREIGN, timeout: 5 }, { type: "command", command: COMMAND, timeout: 75 }] },
    ]);
    const removed = JSON.parse(host.remove(JSON.stringify(merged))!);
    expect(removed.hooks.PreToolUse).toEqual([{ matcher: "Bash", hooks: [{ type: "command", command: FOREIGN, timeout: 5 }] }]);
  });

  it("collapses stray duplicate copies of ours to one and re-asserts the canonical matcher on our own group", () => {
    const before = JSON.stringify({
      hooks: {
        PreToolUse: [
          { matcher: "Write", hooks: [{ type: "command", command: COMMAND, timeout: 75 }] },
          { hooks: [{ type: "command", command: COMMAND, timeout: 75 }] },
        ],
      },
    });
    const merged = JSON.parse(host.merge(before, COMMAND, 60, 75));
    expect(merged.hooks.PreToolUse).toEqual([{ matcher: ".*", hooks: [{ type: "command", command: COMMAND, timeout: 75 }] }]);
  });

  it("refuses malformed JSON and an inert `hooks: []`", () => {
    expect(() => host.merge("{ not json", COMMAND, 60)).toThrow(/not touching it/);
    expect(host.remove("{ not json")).toBeUndefined();
    const parsed = JSON.parse(host.merge('{"hooks": []}', COMMAND, 60, 75));
    expect(Array.isArray(parsed.hooks)).toBe(false);
    expect(parsed.hooks.PreToolUse).toHaveLength(1);
  });
});

describe("flat JSON surgery", () => {
  const host = claudeFamilyHost(spec({ style: "flat", matcher: undefined }));

  it("appends a named handler with no matcher, idempotently, and preserves a grouped foreign entry it does not understand", () => {
    const before = JSON.stringify({
      someUnrelatedKey: 1,
      hooks: { PreToolUse: [{ matcher: "*", hooks: [{ type: "command", command: FOREIGN, timeout: 5 }] }, { name: "theirs", command: FOREIGN, timeout: 3 }] },
    });
    const doc = host.merge(before, COMMAND, 60, 75);
    const parsed = JSON.parse(doc);
    expect(parsed.someUnrelatedKey).toBe(1);
    expect(parsed.hooks.PreToolUse).toHaveLength(3);
    expect(parsed.hooks.PreToolUse[2]).toEqual({ name: "Doorman", command: COMMAND, timeout: 75 });
    expect(host.merge(doc, COMMAND, 60, 75)).toBe(doc);
    expect(host.installed(doc, COMMAND)).toBe(true);
    const removed = JSON.parse(host.remove(doc)!);
    expect(removed.hooks.PreToolUse).toHaveLength(2);
    expect(JSON.stringify(removed)).toContain(FOREIGN);
    expect(host.remove(JSON.stringify(removed))).toBeUndefined();
  });

  it("replaces a moved command instead of adding a second entry", () => {
    const first = host.merge(undefined, `${COMMAND} --v1`, 60, 75);
    const moved = JSON.parse(host.merge(first, COMMAND, 60, 75));
    expect(moved.hooks.PreToolUse).toEqual([{ name: "Doorman", command: COMMAND, timeout: 75 }]);
  });
});

describe("Kiro's versioned array surgery", () => {
  const host = claudeFamilyHost(spec({ style: "kiro" }));

  it("writes a v1 file with one trigger entry, idempotently, and removes only ours", () => {
    const doc = host.merge(undefined, COMMAND, 60, 75);
    expect(JSON.parse(doc)).toEqual({
      version: "v1",
      hooks: [{ name: "Doorman", trigger: "PreToolUse", matcher: ".*", action: { type: "command", command: COMMAND }, timeout: 75, enabled: true }],
    });
    expect(host.merge(doc, COMMAND, 60, 75)).toBe(doc);
    expect(host.installed(doc, COMMAND)).toBe(true);
    const foreign = JSON.stringify({
      version: "v1",
      someUnrelatedKey: { keep: "me" },
      hooks: [{ name: "theirs", trigger: "PreToolUse", action: { type: "command", command: FOREIGN }, timeout: 5 }],
    });
    const merged = host.merge(foreign, COMMAND, 60, 75);
    expect(JSON.parse(merged).hooks).toHaveLength(2);
    const removed = host.remove(merged)!;
    expect(removed).toContain(FOREIGN);
    expect(removed).toContain("someUnrelatedKey");
    expect(removed).not.toContain(GUARD_COMMAND_MARKER);
    expect(host.remove(removed)).toBeUndefined();
  });

  it("refuses a document whose `hooks` is not an array — not a Kiro hooks file", () => {
    expect(() => host.merge('{"hooks": {"PreToolUse": []}}', COMMAND, 60)).toThrow(/not a Kiro hooks file/);
    expect(() => host.merge("{ not json", COMMAND, 60)).toThrow();
  });

  it("does not count a disabled copy of ours as installed", () => {
    const doc = JSON.parse(host.merge(undefined, COMMAND, 60, 75));
    doc.hooks[0].enabled = false;
    expect(host.installed(JSON.stringify(doc), COMMAND)).toBe(false);
  });
});

describe("TOML table-array surgery", () => {
  const host = claudeFamilyHost(spec({ style: "toml", documentFormat: "toml", matcher: undefined }));
  const foreign = `someUnrelatedKey = "keep"

[[hooks]]
event = "PreToolUse"
command = "${FOREIGN}"
timeout = 5
`;

  it("appends exactly the four allowed fields and leaves every other byte alone", () => {
    const doc = host.merge(foreign, COMMAND, 60, 75);
    expect(doc.startsWith(foreign.trimEnd())).toBe(true);
    expect(doc.endsWith(`\n\n[[hooks]]\nevent = "PreToolUse"\ncommand = ${JSON.stringify(COMMAND)}\ntimeout = 75\n`)).toBe(true);
    expect(doc).not.toMatch(/\nname = /);
    expect(host.merge(doc, COMMAND, 60, 75)).toBe(doc);
    expect(host.installed(doc, COMMAND)).toBe(true);
    expect(host.installed(doc, `${COMMAND} --x`)).toBe(false);
  });

  it("removes only our table, restoring the original text", () => {
    const doc = host.merge(foreign, COMMAND, 60, 75);
    expect(host.remove(doc)).toBe(foreign);
    expect(host.remove(foreign)).toBeUndefined();
    expect(host.remove(host.merge(undefined, COMMAND, 60, 75))).toBe("");
  });

  it("re-merges a changed command or timeout as one table", () => {
    const first = host.merge(undefined, `${COMMAND} --old`, 60, 75);
    const moved = host.merge(first, COMMAND, 60, 90);
    expect(moved.split("[[hooks]]").length - 1).toBe(1);
    expect(moved).toContain("timeout = 90");
    expect(moved).not.toContain("--old");
  });

  it("keeps a multi-line array value and comments intact, and refuses what is not TOML", () => {
    const tricky = `# kimi\n[models]\nlist = [\n  "a",\n  "b",\n]\n\n[[hooks]]\nevent = "Stop"\ncommand = "echo hi # not a comment"\n`;
    const doc = host.merge(tricky, COMMAND, 60, 75);
    expect(doc.startsWith(tricky.trimEnd())).toBe(true);
    expect(host.remove(doc)).toBe(tricky);
    expect(() => host.merge("{ not json", COMMAND, 60)).toThrow(/not valid TOML/);
    expect(host.remove("{ not json")).toBeUndefined();
  });

  // Documents Kimi Code writes itself (smol-toml stringify / its line writeback).
  const OURS = `[[hooks]]\nevent = "PreToolUse"\ncommand = ${JSON.stringify(COMMAND)}\ntimeout = 75\n`;
  const roundTrips = (doc: string, eol = "\n"): void => {
    const merged = host.merge(doc, COMMAND, 60, 75);
    expect(merged).toBe(`${doc}${eol}${OURS.replace(/\n/g, eol)}`);
    expect(host.merge(merged, COMMAND, 60, 75)).toBe(merged);
    expect(host.installed(merged, COMMAND)).toBe(true);
    expect(host.remove(merged)).toBe(doc);
  };

  it("follows quoted and dotted table headers", () => {
    roundTrips(
      `default_model = "kimi-code/k3"\n[providers."managed:kimi-code"]\ntype = "kimi"\n[models."kimi-code/k3"]\nprovider = "managed:kimi-code"\n[models."kimi-code/kimi-for-coding".overrides]\nmax_context_size = 131072\n`,
    );
    roundTrips(`[ models . 'a:b' ]\nx = 1\n[[profiles."x/y"]]\nname = "p"\n`);
  });

  it("counts every spelling of the `hooks` table array, and only that one", () => {
    const foreignForms = `[[ hooks ]]\nevent = "Stop"\ncommand = "${FOREIGN}"\n[["hooks"]]\nevent = "Stop"\ncommand = "echo"\n[hooks.sub]\nk = 1\n[[hooks.x]]\nk = 2\n`;
    roundTrips(foreignForms);
    const quotedOurs = OURS.replace("[[hooks]]", `[[ "hooks" ]]`);
    expect(host.installed(quotedOurs, COMMAND)).toBe(true);
    expect(host.remove(`a = 1\n\n${quotedOurs}`)).toBe("a = 1\n");
    expect(host.installed(OURS.replace("[[hooks]]", "[[hooks.x]]"), COMMAND)).toBe(false);
  });

  it("follows dotted keys", () => {
    roundTrips(`thinking.enabled = true\n[models]\n"kimi-code/k3".display_name = "K3"\n`);
  });

  it("replaces an empty root `hooks = []` with the table array", () => {
    const doc = `a = 1\nhooks = []\n\n[x]\ny = 2\n`;
    expect(host.installed(doc, COMMAND)).toBe(false);
    expect(host.remove(doc)).toBeUndefined();
    const merged = host.merge(doc, COMMAND, 60, 75);
    expect(merged).toBe(`a = 1\n\n[x]\ny = 2\n\n${OURS}`);
    expect(host.installed(merged, COMMAND)).toBe(true);
    expect(host.remove(merged)).toBe(`a = 1\n\n[x]\ny = 2\n`);
    expect(host.merge(`hooks = [\n  # none yet\n] # empty\n`, COMMAND, 60, 75)).toBe(OURS);
    // What an earlier build appended next to `hooks = []`: repaired, never counted.
    const corrupt = `hooks = []\n\n${OURS}`;
    expect(host.installed(corrupt, COMMAND)).toBe(false);
    expect(host.merge(corrupt, COMMAND, 60, 75)).toBe(OURS);
  });

  it("refuses any other root `hooks` instead of redefining it", () => {
    for (const doc of [
      `hooks = [ { event = "PreToolUse", command = ${JSON.stringify(COMMAND)}, timeout = 75 } ]\n`,
      `hooks = [\n  { event = "Stop", command = "x" },\n]\n`,
      `hooks.x = 1\n`,
      `[hooks]\nx = 1\n`,
      `[hooks.x]\ny = 1\n`,
      `[[hooks]]\nevent = "Stop"\ncommand = "e"\n[z]\n[hooks.x]\ny = 1\n`,
    ]) {
      expect(() => host.merge(doc, COMMAND, 60, 75)).toThrow(/`hooks`.*not touching it/);
      expect(host.installed(doc, COMMAND)).toBe(false);
      expect(host.remove(doc)).toBeUndefined();
    }
  });

  it("leaves comments that lead into the next table where they are", () => {
    const doc = `${OURS}\n# keep me\n[thinking]\nenabled = true\n`;
    expect(host.remove(doc)).toBe("# keep me\n[thinking]\nenabled = true\n");
    expect(host.remove(`a = 1\n\n${doc}`)).toBe("a = 1\n\n# keep me\n[thinking]\nenabled = true\n");
    const moved = host.merge(doc, `${COMMAND} --v2`, 60, 75);
    expect(moved.startsWith("# keep me\n[thinking]\nenabled = true\n\n[[hooks]]\n")).toBe(true);
  });

  it("follows CRLF line endings and writes its own lines in them", () => {
    roundTrips(`[thinking] # p\r\nenabled = true\r\n`, "\r\n");
  });

  it("never reads the inside of a multi-line string as headers or keys", () => {
    roundTrips(`n = """\nhello world\n"""\n`);
    roundTrips(`n = '''\n[[hooks]]\ncommand = ${JSON.stringify(COMMAND)}\n'''\nm = """a ""b""""\n`);
    expect(host.installed(`n = """\n${OURS}"""\n`, COMMAND)).toBe(false);
    expect(host.remove(`n = """\n${OURS}"""\n`)).toBeUndefined();
    expect(() => host.merge(`n = """\nnever closed\n`, COMMAND, 60, 75)).toThrow(/not valid TOML/);
  });
});

describe("normalizeInput", () => {
  const host = claudeFamilyHost(spec({}));

  it("maps a known tool through the table, reading the first present key, and keeps every key it did not consume", () => {
    // `extra` rides along (P2, 2026-09-10): the detectors scan the whole
    // input, so a key the table does not know about is still looked at.
    expect(host.normalizeInput({ hook_event_name: "PreToolUse", session_id: "s", cwd: "/w", tool_name: "put", tool_input: { file_path: "/f", content: "x", extra: 1 } })).toEqual({
      session_id: "s",
      cwd: "/w",
      tool_name: "Write",
      tool_input: { extra: 1, file_path: "/f", content: "x" },
    });
    // The consumed host key is folded into the guard key, never kept twice.
    expect(host.normalizeInput({ tool_name: "sh", tool_input: { cmd: "ls" } })?.tool_input).toEqual({ command: "ls" });
    // A secret under a key our table guessed wrong is still in the scanned text.
    const wrongGuess = host.normalizeInput({ tool_name: "put", tool_input: { file_path: "/f", body: "AKIAMQHGCTEF5EUSLEJR" } });
    expect(JSON.stringify(wrongGuess?.tool_input)).toContain("AKIAMQHGCTEF5EUSLEJR");
  });

  it("passes an unknown tool through untouched, rewrites MCP names when told how, and ignores other events", () => {
    expect(host.normalizeInput({ hook_event_name: "PreToolUse", tool_name: "glob", tool_input: { pattern: "*" } })).toMatchObject({ tool_name: "glob", tool_input: { pattern: "*" } });
    expect(host.normalizeInput({ hook_event_name: "PostToolUse", tool_name: "sh", tool_input: {} })).toBeUndefined();
    expect(host.normalizeInput({ event: "PreToolUse", tool_name: "sh", tool_input: { cmd: "x" } })?.tool_name).toBe("Bash");
    expect(host.normalizeInput(null)).toBeUndefined();
    expect(host.normalizeInput({ hook_event_name: "PreToolUse" })).toBeUndefined();
    const mcp = claudeFamilyHost(spec({ mcpName: (n) => mcpFirstUnderscore(n) }));
    expect(mcp.normalizeInput({ tool_name: "mcp_github_create_issue", tool_input: { a: 1 } })?.tool_name).toBe("mcp__github__create_issue");
    expect(mcpFirstUnderscore("mcp__already__there")).toBeUndefined();
    expect(mcpFirstUnderscore("mcp_solo")).toBeUndefined();
  });

  it("reads the working directory from the host's own field", () => {
    const g = claudeFamilyHost(spec({ cwdField: "working_dir" }));
    expect(g.normalizeInput({ tool_name: "sh", tool_input: { cmd: "x" }, working_dir: "/w" })?.cwd).toBe("/w");
  });
});

describe("emit dialects", () => {
  it("hook-specific: JSON verdicts at exit 0, ask native, allow silent", () => {
    const host = claudeFamilyHost(spec({}));
    expect(host.emit("allow")).toEqual({ exitCode: 0 });
    expect(JSON.parse(host.emit("deny", "why").stdout!)).toEqual({ hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "deny", permissionDecisionReason: "why" } });
    expect(JSON.parse(host.emit("ask").stdout!).hookSpecificOutput.permissionDecision).toBe("ask");
    expect(JSON.parse(host.warn("why").stdout!).systemMessage).toContain("why");
  });

  it("decision-deny / decision-block: the host's own word, and ask degrades to a warning", () => {
    const deny = claudeFamilyHost(spec({ decision: "decision-deny", supportsNativeAsk: false, warn: "silent" }));
    expect(JSON.parse(deny.emit("deny", "why").stdout!)).toEqual({ decision: "deny", reason: "why" });
    expect(deny.emit("ask", "why")).toEqual({ exitCode: 0 });
    const block = claudeFamilyHost(spec({ decision: "decision-block", supportsNativeAsk: false, warn: "silent" }));
    expect(JSON.parse(block.emit("deny").stdout!)).toEqual({ decision: "block", reason: "Doorman security policy" });
  });

  it("exit-2: a bare exit code for deny, silence for everything else", () => {
    const host = claudeFamilyHost(spec({ decision: "exit-2", supportsNativeAsk: false, warn: "silent" }));
    expect(host.emit("deny", "why")).toEqual({ exitCode: 2, stderr: "why" });
    expect(host.emit("ask", "why")).toEqual({ exitCode: 0 });
    expect(host.emit("allow")).toEqual({ exitCode: 0 });
  });

  it("carries documentFormat and artifacts through when the spec sets them", () => {
    const host = claudeFamilyHost(spec({ documentFormat: "toml", style: "toml", artifacts: () => [{ path: "/a", content: "b" }] }));
    expect(host.documentFormat).toBe("toml");
    expect(host.artifacts?.("/h", {})).toEqual([{ path: "/a", content: "b" }]);
    expect(claudeFamilyHost(spec({})).documentFormat).toBeUndefined();
  });
});
