import { existsSync, readdirSync, readFileSync } from "node:fs";
import { dirname, isAbsolute, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  DEFAULT_HOST,
  HOSTS,
  documentReadable,
  hostById,
  hostBySource,
  hostForArgv,
  hostLabel,
  hostLabels,
} from "../main/guard/hosts/index.js";
import type { HostDocumentFormat } from "../main/guard/hosts/types.js";
import { GUARD_COMMAND_MARKER } from "../main/guard/policy.js";
import { guardCommand } from "../main/enforcement.js";

/**
 * The host registry's contract, parameterized over EVERY registered host — so
 * an adapter added later (Cursor, Gemini CLI, Copilot CLI…) inherits the
 * guard's three rules instead of being trusted to re-implement them:
 *
 *  1. never print "allow" — an approved call is silence;
 *  2. a fail-closed host never gets a non-zero exit for a decision we did not
 *     make (its non-zero IS a deny);
 *  3. config surgery is idempotent, reversible, and never touches anybody
 *     else's entry in the same document.
 */

const COMMAND = `node "/Users/x/Library/Application Support/Doorman/doorman/guard/guard.js"`;
const HOME = "/Users/x";
const HOLD = 60;

const each = HOSTS.map((host) => [host.id, host] as const);

/** JSON hosts whose document is JSON but not Claude-shaped: Kiro CLI's
 * `hooks` is a versioned ARRAY, and its merge refuses anything else. */
const FOREIGN_OVERRIDES: Record<string, string> = {
  kiro: JSON.stringify(
    {
      version: "v1",
      someUnrelatedKey: { keep: "me" },
      hooks: [
        {
          name: "theirs",
          trigger: "PreToolUse",
          action: { type: "command", command: "/opt/somebody-else/their-hook.sh" },
          timeout: 5,
        },
      ],
    },
    null,
    2,
  ),
};

const FOREIGN_JSON = JSON.stringify(
  {
    someUnrelatedKey: { keep: "me" },
    hooks: {
      PreToolUse: [
        {
          matcher: "*",
          hooks: [{ type: "command", command: "/opt/somebody-else/their-hook.sh", timeout: 5 }],
        },
      ],
    },
  },
  null,
  2,
);

/** The same, commented — legal in every host that reads comments. */
const FOREIGN_COMMENTED = `// not ours\n${FOREIGN_JSON.replace('"hooks": {', '"hooks": { // theirs')}\n// end\n`;

/** A document that is not ours, per format — see the foreign-entry test. */
const FOREIGN_DOCUMENTS: Record<HostDocumentFormat, string> = {
  json: FOREIGN_JSON,
  jsonc: FOREIGN_COMMENTED,
  json5: FOREIGN_COMMENTED,
  yaml: [
    "someUnrelatedKey: keep",
    "hooks:",
    "  pre_tool_call:",
    "    - command: /opt/somebody-else/their-hook.sh",
    "      timeout: 5",
    "",
  ].join("\n"),
  toml: [
    'someUnrelatedKey = "keep"',
    "",
    "[[hooks]]",
    'event = "PreToolUse"',
    'command = "/opt/somebody-else/their-hook.sh"',
    "timeout = 5",
    "",
  ].join("\n"),
};

describe("the guard host registry", () => {
  it("registers Claude Code and Codex with their historical ids and sources", () => {
    expect(hostById("claude")?.source).toBe("claude-code");
    expect(hostById("codex")?.source).toBe("codex");
    expect(DEFAULT_HOST.id).toBe("claude");
  });

  it("has one descriptor per id and per source", () => {
    expect(new Set(HOSTS.map((h) => h.id)).size).toBe(HOSTS.length);
    expect(new Set(HOSTS.map((h) => h.source)).size).toBe(HOSTS.length);
    expect(HOSTS.every((h) => h.id !== "" && h.label !== "" && h.source !== "")).toBe(true);
  });

  it("resolves --host, and falls back to the default host rather than failing", () => {
    expect(hostForArgv(["node", "guard.js"]).id).toBe("claude");
    expect(hostForArgv(["node", "guard.js", "--host", "codex"]).id).toBe("codex");
    // Unknown or truncated: fail OPEN on the default host, never throw.
    expect(hostForArgv(["node", "guard.js", "--host", "nope"]).id).toBe(DEFAULT_HOST.id);
    expect(hostForArgv(["node", "guard.js", "--host"]).id).toBe(DEFAULT_HOST.id);
    for (const [, host] of each) {
      expect(hostForArgv(["node", "guard.js", "--host", host.id]).id).toBe(host.id);
    }
  });

  it("labels a source, and returns an unknown one unchanged", () => {
    expect(hostLabel("claude-code")).toBe("Claude Code");
    expect(hostLabel("codex")).toBe("Codex");
    expect(hostLabel("some-host-from-a-newer-build")).toBe("some-host-from-a-newer-build");
    expect(hostLabel(undefined)).toBe(DEFAULT_HOST.label);
    expect(hostLabels()).toEqual(HOSTS.map((h) => h.label));
    for (const [, host] of each) expect(hostBySource(host.source)?.id).toBe(host.id);
  });

  it("keeps Claude Code's command bare and names every other host", () => {
    // Claude Code's trust state is keyed on the exact installed string.
    expect(guardCommand("/u")).not.toContain("--host");
    expect(guardCommand("/u", "claude")).toBe(guardCommand("/u"));
    for (const [, host] of each) {
      const command = guardCommand("/u", host.id);
      expect(command).toContain(GUARD_COMMAND_MARKER);
      if (host.id !== DEFAULT_HOST.id) expect(command).toContain(`--host ${host.id}`);
    }
  });
});

describe.each(each)("host %s", (_id, host) => {
  it("prints nothing for allow and exits 0", () => {
    const allowed = host.emit("allow");
    if (host.exitSemantics === "exit-is-verdict") {
      // The one shape where silence is impossible — the exit code IS the
      // answer, so allow still may not print, but it may exit non-zero.
      expect(allowed.stdout).toBeUndefined();
    } else {
      expect(allowed.stdout, "an approved call must print NOTHING").toBeUndefined();
      expect(allowed.exitCode).toBe(0);
    }
  });

  it("emits valid JSON, or nothing at all, for every decision", () => {
    for (const decision of ["allow", "ask", "deny"] as const) {
      for (const reason of [undefined, "Flagged by Doorman."]) {
        const out = host.emit(decision, reason);
        if (out.stdout !== undefined) expect(() => JSON.parse(out.stdout!)).not.toThrow();
        expect(Number.isInteger(out.exitCode)).toBe(true);
      }
    }
    const warned = host.warn("Flagged by Doorman.");
    if (warned.stdout !== undefined) expect(() => JSON.parse(warned.stdout!)).not.toThrow();
    // A warning is the "nobody could answer" path: it must let the call run.
    expect(warned.stdout ?? "").not.toContain('"deny"');
  });

  it("never returns a non-zero exit when the host reads that as a deny", () => {
    if (host.exitSemantics !== "fail-closed") return;
    for (const decision of ["allow", "ask", "deny"] as const) {
      expect(host.emit(decision, "why").exitCode, `${host.id} ${decision}`).toBe(0);
    }
    expect(host.warn("why").exitCode).toBe(0);
  });

  it("resolves absolute user-level document paths", () => {
    const docs = host.documents(HOME, {});
    expect(docs.length).toBeGreaterThan(0);
    const user = docs.filter((d) => d.level === "user");
    expect(user.length).toBeGreaterThan(0);
    for (const doc of user) expect(isAbsolute(doc.path), `${host.id}: ${doc.path}`).toBe(true);
    // Project documents are relative to a project root the caller supplies.
    for (const doc of docs.filter((d) => d.level === "project")) {
      expect(isAbsolute(doc.path)).toBe(false);
    }
    expect(host.presencePaths.length).toBeGreaterThan(0);
  });

  it("merges idempotently, and remove() puts the document back", () => {
    const first = host.merge(undefined, COMMAND, HOLD);
    expect(first).toContain(GUARD_COMMAND_MARKER);
    expect(host.installed(first, COMMAND)).toBe(true);
    // Idempotent: a second merge of the same command changes nothing.
    expect(host.merge(first, COMMAND, HOLD)).toBe(first);
    const removed = host.remove(first);
    expect(removed).toBeDefined();
    expect(removed).not.toContain(GUARD_COMMAND_MARKER);
    expect(host.installed(removed, COMMAND)).toBe(false);
    // Nothing of ours left to remove.
    expect(host.remove(removed)).toBeUndefined();
  });

  it("re-merges a changed command instead of leaving two entries", () => {
    const first = host.merge(undefined, COMMAND, HOLD);
    const moved = host.merge(first, `${COMMAND} --host later`, HOLD);
    expect(host.installed(moved, COMMAND)).toBe(false);
    expect(host.installed(moved, `${COMMAND} --host later`)).toBe(true);
    // A host may register under several events (Cursor writes three); the
    // invariant is "no duplicate", so the count matches a fresh install's.
    const entries = (doc: string) => doc.split(GUARD_COMMAND_MARKER).length - 1;
    expect(entries(moved)).toBe(entries(first));
  });

  it("preserves a foreign entry in the same document, through merge AND remove", () => {
    const foreign = "/opt/somebody-else/their-hook.sh";
    // In the host's OWN document format (hosts/types.ts documentFormat): a
    // Claude-shaped JSON document for the JSON hosts (commented for the hosts
    // that read comments), a block-mapping YAML for Hermes, a `[[hooks]]` table
    // array for Kimi Code. The invariant is the same in each: somebody else's
    // hook and an unrelated key come out intact.
    const before = FOREIGN_OVERRIDES[host.id] ?? FOREIGN_DOCUMENTS[host.documentFormat ?? "json"];
    const merged = host.merge(before, COMMAND, HOLD);
    expect(merged).toContain(foreign);
    expect(merged).toContain("someUnrelatedKey");
    const removed = host.remove(merged);
    expect(removed).toBeDefined();
    expect(removed).toContain(foreign);
    expect(removed).toContain("someUnrelatedKey");
    expect(removed).not.toContain(GUARD_COMMAND_MARKER);
  });

  it("refuses a document it cannot parse rather than overwriting it", () => {
    expect(() => host.merge("{ not json", COMMAND, HOLD)).toThrow();
    // Removal from an unparseable document is a no-op, not a rewrite.
    expect(host.remove("{ not json")).toBeUndefined();
    // …and the registry's format-aware readability check agrees, in both
    // directions: what merge() refuses is unreadable, what it accepts is not.
    expect(documentReadable(host, "{ not json")).toBe(false);
    expect(documentReadable(host, undefined)).toBe(true);
    expect(documentReadable(host, host.merge(undefined, COMMAND, HOLD))).toBe(true);
  });

  it("declares artefacts and companions purely, when it has them", () => {
    for (const artifact of host.artifacts?.(HOME, {}) ?? []) {
      expect(isAbsolute(artifact.path), `${host.id}: ${artifact.path}`).toBe(true);
      // Machine-independent bytes: the command lives in the document.
      expect(artifact.content).not.toContain(GUARD_COMMAND_MARKER);
      expect(artifact.content).not.toContain(HOME);
    }
    for (const companion of host.companions ?? []) {
      expect(isAbsolute(companion.path(HOME, {}))).toBe(true);
      const first = companion.merge(undefined, COMMAND);
      expect(first).toContain(GUARD_COMMAND_MARKER);
      expect(companion.merge(first, COMMAND)).toBe(first);
      const removed = companion.remove(first);
      expect(removed ?? "").not.toContain(GUARD_COMMAND_MARKER);
      expect(companion.remove(removed)).toBeUndefined();
    }
  });

  it("normalizes a tool call into the guard's vocabulary, and ignores non-calls", () => {
    // Each host speaks its own payload dialect: use the host's recorded/derived
    // fixtures (test/fixtures/hooks/<id>/) when it has them, else the
    // Claude Code shape the two original hosts share.
    const fixtureDir = join(dirname(fileURLToPath(import.meta.url)), "fixtures", "hooks", host.id);
    const samples: unknown[] = existsSync(fixtureDir)
      ? readdirSync(fixtureDir)
          .filter((f) => f.endsWith(".json"))
          .map((f) => JSON.parse(readFileSync(join(fixtureDir, f), "utf8")))
      : [{ session_id: "s1", tool_name: "Bash", tool_input: { command: "printenv" }, cwd: "/w" }];
    const calls = samples.map((s) => host.normalizeInput(s)).filter((c) => c !== undefined);
    expect(calls.length).toBeGreaterThan(0);
    for (const call of calls) expect(typeof call?.tool_name).toBe("string");
    expect(host.normalizeInput(null)).toBeUndefined();
    expect(host.normalizeInput("not an object")).toBeUndefined();
  });
});
