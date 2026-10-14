import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  assessGuardIntegrity,
  describeIntegrity,
  guardCommandsIn,
  type IntegrityInputs,
} from "../main/lib/guard-integrity.js";
import { guardAuxiliaryPaths, guardBundleHashes, guardDir, GUARD_FILES } from "../main/enforcement.js";

/**
 * Guard self-integrity: the guard's hook entry or copied bundle changing under
 * the app is a SILENT fail-open, and the whole point of this module is to make
 * it loud — without calling the person's own uninstall an attack.
 */

const command = 'node "/Users/x/Library/Application Support/Doorman/doorman/guard/guard.js"';
const codexCommand = `${command} --host codex`;

const doc = (cmd: string | undefined, extra: Record<string, unknown> = {}) =>
  JSON.stringify({
    ...extra,
    hooks: {
      PreToolUse: [
        { matcher: "*", hooks: cmd === undefined ? [{ type: "command", command: "other-tool" }] : [{ type: "command", command: cmd, timeout: 75 }] },
      ],
    },
  });

const inputs = (over: Partial<IntegrityInputs> = {}): IntegrityInputs => ({
  wanted: true,
  hosts: [
    { host: "claude-code", doc_path: "/Users/x/.claude/settings.json", present: true, doc: doc(command), expected_command: command },
    { host: "codex", doc_path: "/Users/x/.codex/hooks.json", present: true, doc: doc(codexCommand), expected_command: codexCommand },
  ],
  shipped: { "guard.js": "aaa", "policy.js": "bbb" },
  copied: { "guard.js": "aaa", "policy.js": "bbb" },
  policy_readable: true,
  ...over,
});

describe("guardCommandsIn", () => {
  it("finds our handlers by marker across groups, and reports an unparseable document", () => {
    expect(guardCommandsIn(doc(command))).toEqual([command]);
    expect(guardCommandsIn(doc(undefined))).toEqual([]);
    expect(guardCommandsIn(undefined)).toEqual([]);
    expect(guardCommandsIn("{broken")).toBeUndefined();
    expect(guardCommandsIn(JSON.stringify({ hooks: [] }))).toEqual([]);
  });
});

describe("assessGuardIntegrity", () => {
  it("is healthy when both entries are exact and the bundle matches", () => {
    const r = assessGuardIntegrity(inputs());
    expect(r.status).toBe("healthy");
    expect(r.problems).toEqual([]);
    expect(describeIntegrity(r)).toContain("as the app left it");
  });

  it("calls a missing entry tampering ONLY when the guard is wanted", () => {
    const missing = inputs({ hosts: [{ host: "claude-code", doc_path: "p", present: true, doc: doc(undefined), expected_command: command }] });
    const r = assessGuardIntegrity(missing);
    expect(r.status).toBe("tampered");
    expect(r.problems).toEqual(["entry_missing"]);
    expect(describeIntegrity(r)).toContain("gone from claude-code");
    // The person switched it off themselves: not tampering, not installed.
    const off = assessGuardIntegrity({ ...missing, wanted: false });
    expect(off.status).toBe("not_installed");
    expect(off.problems).toEqual([]);
  });

  it("calls a rewritten command tampering (a narrowed or re-pointed hook is a bypass)", () => {
    const r = assessGuardIntegrity(
      inputs({ hosts: [{ host: "claude-code", doc_path: "p", present: true, doc: doc(`${command} --observe-only`), expected_command: command }] }),
    );
    expect(r.status).toBe("tampered");
    expect(r.problems).toEqual(["entry_altered"]);
    expect(r.hosts[0]!.entry_present).toBe(true);
    expect(r.hosts[0]!.entry_exact).toBe(false);
  });

  it("ignores a host that isn't on the machine, and reports an unparseable document", () => {
    const r = assessGuardIntegrity(
      inputs({
        hosts: [
          { host: "claude-code", doc_path: "p", present: true, doc: doc(command), expected_command: command },
          { host: "codex", doc_path: "q", present: false, doc: undefined, expected_command: codexCommand },
        ],
      }),
    );
    expect(r.status).toBe("healthy");
    const broken = assessGuardIntegrity(
      inputs({ hosts: [{ host: "claude-code", doc_path: "p", present: true, doc: "{nope", expected_command: command }] }),
    );
    expect(broken.hosts[0]!.unreadable).toBe(true);
    expect(describeIntegrity(broken)).toContain("no longer parses");
  });

  it("takes the host descriptor's own verdict when the caller supplies one — a Cursor-shaped document is not 'missing'", () => {
    // Cursor keeps the hook under three event arrays, Gemini under BeforeTool,
    // Copilot under preToolUse[].bash: none of them is the PreToolUse shape the
    // fallback walk understands. Before, that read as entry_missing → tampered,
    // and Reinstall (writing the same correct file) could never clear it.
    const cursorDoc = JSON.stringify({ version: 1, hooks: { beforeShellExecution: [{ command: `${command} --host cursor`, timeout: 75 }] } });
    const ok = assessGuardIntegrity(
      inputs({ hosts: [{ host: "cursor", doc_path: "p", present: true, doc: cursorDoc, expected_command: `${command} --host cursor`, entry_present: true, entry_exact: true }] }),
    );
    expect(ok.status).toBe("healthy");
    expect(ok.problems).toEqual([]);
    // The same document judged by the fallback walk alone is (wrongly) missing — which is why the verdict must come from the host.
    const walk = assessGuardIntegrity(inputs({ hosts: [{ host: "cursor", doc_path: "p", present: true, doc: cursorDoc, expected_command: `${command} --host cursor` }] }));
    expect(walk.problems).toEqual(["entry_missing"]);
    // And a host that says its entry is there but rewritten is still tampering.
    const altered = assessGuardIntegrity(
      inputs({ hosts: [{ host: "cursor", doc_path: "p", present: true, doc: cursorDoc, expected_command: command, entry_present: true, entry_exact: false }] }),
    );
    expect(altered.problems).toEqual(["entry_altered"]);
  });

  it("calls a missing plugin artefact or consent entry tampering once the entry itself is there, and names the host", () => {
    // OpenClaw: openclaw.json still carries the entry, the plugin directory is
    // gone → the marker reads installed while OpenClaw loads nothing.
    const openclaw = {
      host: "openclaw",
      label: "OpenClaw",
      doc_path: "/Users/x/.openclaw/openclaw.json",
      present: true,
      expected_command: `${command} --host openclaw`,
      entry_present: true,
      entry_exact: true,
      artifacts_missing: ["/Users/x/.openclaw/extensions/doorman-guard/index.js"],
    };
    const r = assessGuardIntegrity(inputs({ hosts: [openclaw] }));
    expect(r.status).toBe("tampered");
    expect(r.problems).toEqual(["artifact_missing"]);
    expect(r.hosts[0]?.artifacts_missing).toEqual(["/Users/x/.openclaw/extensions/doorman-guard/index.js"]);
    expect(describeIntegrity(r)).toContain("plugin files for OpenClaw are missing or changed");
    // Hermes: config.yaml declares the hook, the allowlist no longer consents
    // to it → Hermes skips the hook with a log line.
    const hermes = {
      host: "hermes",
      label: "Hermes Agent",
      doc_path: "/Users/x/.hermes/config.yaml",
      present: true,
      expected_command: `${command} --host hermes`,
      entry_present: true,
      entry_exact: true,
      companions_missing: ["/Users/x/.hermes/shell-hooks-allowlist.json"],
    };
    const h = assessGuardIntegrity(inputs({ hosts: [hermes] }));
    expect(h.problems).toEqual(["companion_missing"]);
    expect(describeIntegrity(h)).toContain("consent entry for Hermes Agent is gone");
    // Neither counts while the entry itself is missing (that is entry_missing,
    // and the one reinstall writes both), nor when the guard is not wanted.
    const noEntry = assessGuardIntegrity(inputs({ hosts: [{ ...openclaw, entry_present: false, entry_exact: false }] }));
    expect(noEntry.problems).toEqual(["entry_missing"]);
    expect(assessGuardIntegrity(inputs({ wanted: false, hosts: [openclaw] })).problems).toEqual([]);
    // Empty lists are not reported at all.
    const clean = assessGuardIntegrity(inputs({ hosts: [{ ...openclaw, artifacts_missing: [], companions_missing: [] }] }));
    expect(clean.hosts[0]).not.toHaveProperty("artifacts_missing");
    expect(clean.status).toBe("healthy");
  });

  it("flags a modified or missing bundle file", () => {
    const r = assessGuardIntegrity(inputs({ copied: { "guard.js": "zzz", "policy.js": undefined } }));
    expect(r.status).toBe("tampered");
    expect(r.problems.sort()).toEqual(["bundle_missing", "bundle_modified"]);
    expect(r.bundle_modified).toEqual(["guard.js"]);
    expect(r.bundle_missing).toEqual(["policy.js"]);
    // An entry that exists but a bundle nobody wants is still reported — the
    // hook would run a modified guard.
    const unwanted = assessGuardIntegrity(inputs({ wanted: false, copied: { "guard.js": "zzz", "policy.js": "bbb" } }));
    expect(unwanted.status).toBe("tampered");
  });
});

describe("guardAuxiliaryPaths", () => {
  it("lists every plugin artefact and companion document the watcher must watch, honouring the hosts' home overrides", () => {
    const home = homedir();
    const defaults = guardAuxiliaryPaths({});
    expect(defaults).toContain(join(home, ".openclaw", "extensions", "doorman-guard", "index.js"));
    expect(defaults).toContain(join(home, ".openclaw", "extensions", "doorman-guard", "openclaw.plugin.json"));
    // Hermes is a plugin host since 2026-09-10: its two plugin files, no consent companion.
    expect(defaults).toContain(join(home, ".hermes", "plugins", "doorman-guard", "__init__.py"));
    expect(defaults).toContain(join(home, ".hermes", "plugins", "doorman-guard", "plugin.yaml"));
    expect(defaults).not.toContain(join(home, ".hermes", "shell-hooks-allowlist.json"));
    // Never a hook document itself — those are guardDocumentPaths' job.
    expect(defaults).not.toContain(join(home, ".openclaw", "openclaw.json"));
    const moved = guardAuxiliaryPaths({ OPENCLAW_STATE_DIR: "/srv/claw", HERMES_HOME: "/srv/hermes" });
    expect(moved).toContain("/srv/claw/extensions/doorman-guard/index.js");
    expect(moved).toContain("/srv/hermes/plugins/doorman-guard/__init__.py");
  });
});

describe("guardBundleHashes", () => {
  let userData: string;
  beforeEach(() => {
    userData = mkdtempSync(join(tmpdir(), "doorman-integrity-"));
  });
  afterEach(() => {
    rmSync(userData, { recursive: true, force: true });
  });

  it("hashes what the app ships against what was copied, file by file", () => {
    // The shipped side is the app's own compiled guard/ next to enforcement.js;
    // in a test that directory may not be built, so only the copied side is
    // asserted structurally.
    mkdirSync(guardDir(userData), { recursive: true });
    writeFileSync(join(guardDir(userData), "guard.js"), "tampered");
    const { shipped, copied } = guardBundleHashes(userData);
    for (const file of Object.keys(shipped)) {
      expect((GUARD_FILES as readonly string[]).includes(file)).toBe(true);
      expect(shipped[file]).toMatch(/^[0-9a-f]{64}$/);
    }
    if ("guard.js" in shipped) {
      expect(copied["guard.js"]).toMatch(/^[0-9a-f]{64}$/);
      expect(copied["guard.js"]).not.toBe(shipped["guard.js"]);
      expect(copied["policy.js"]).toBeUndefined();
    }
  });
});
