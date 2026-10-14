import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  RepairLedger,
  diagnose,
  planRepairs,
  repairJsonText,
  type DoctorInput,
  type DoctorReport,
} from "../main/lib/doctor.js";
import { GUARD_FILES } from "../main/enforcement.js";
import { GUARD_COMMAND_MARKER, mergeCodexGuardHook, mergeGuardHook } from "../main/guard/policy.js";
import { hermesHost } from "../main/guard/hosts/hermes.js";
import { openclawHost } from "../main/guard/hosts/openclaw.js";

/**
 * The doctor is held to documents written by the REAL guard merge, not to
 * hand-written JSON that happens to match its own tables: a guarded machine
 * must diagnose clean, and each corruption class this module exists for — an
 * unparseable hook document, an entry an agent dropped on a rewrite, a guard
 * plugin or module gone — must map to exactly one check with exactly one fix.
 */

const roots: string[] = [];
afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

/** A HOME with Claude Code and Codex "installed" (their dirs exist) and
 * nothing of ours in either yet. */
function freshMachine(): string {
  const home = mkdtempSync(join(tmpdir(), "doctor-"));
  roots.push(home);
  mkdirSync(join(home, ".claude"), { recursive: true });
  mkdirSync(join(home, ".codex"), { recursive: true });
  return home;
}

/** Both documents carrying the guard entry, exactly as installGuard writes it. */
function guardBoth(home: string, guardDir: string): void {
  const command = `node "${join(guardDir, "guard.js")}"`;
  const settingsPath = join(home, ".claude", "settings.json");
  const hooksPath = join(home, ".codex", "hooks.json");
  writeFileSync(settingsPath, mergeGuardHook(existsSync(settingsPath) ? readFileSync(settingsPath, "utf8") : undefined, command, 75));
  writeFileSync(hooksPath, mergeCodexGuardHook(existsSync(hooksPath) ? readFileSync(hooksPath, "utf8") : undefined, `${command} --host codex`, 75));
}

const realFs = {
  exists: (p: string) => existsSync(p),
  read: (p: string) => {
    try {
      return readFileSync(p, "utf8");
    } catch {
      return undefined;
    }
  },
};

function guardDirFor(home: string): string {
  const dir = join(home, "userData", "doorman", "guard");
  mkdirSync(dir, { recursive: true });
  for (const f of GUARD_FILES) {
    // GUARD_FILES carries the host registry's `hosts/` subdirectory too.
    mkdirSync(dirname(join(dir, f)), { recursive: true });
    writeFileSync(join(dir, f), "// guard\n");
  }
  return dir;
}

function input(home: string, over: Partial<DoctorInput> = {}): DoctorInput {
  return {
    home,
    guardWanted: false,
    guardDir: join(home, "userData", "doorman", "guard"),
    guardFiles: GUARD_FILES,
    guardCommandMarker: GUARD_COMMAND_MARKER,
    fs: realFs,
    ...over,
  };
}

const byId = (report: DoctorReport, id: string) => {
  const check = report.checks.find((c) => c.id === id);
  expect(check, `no check ${id} in ${report.checks.map((c) => c.id).join(", ")}`).toBeDefined();
  return check!;
};

describe("the guard", () => {
  it("is skipped, not failed, while switched off", () => {
    const report = diagnose(input(freshMachine()));
    expect(byId(report, "guard.off").status).toBe("skip");
    expect(report.fail + report.warn).toBe(0);
  });

  it("wants the guard entry in every host when switched on, and installs it", () => {
    const home = freshMachine();
    const guardDir = guardDirFor(home);
    const report = diagnose(input(home, { guardWanted: true, guardDir }));
    const hooks = byId(report, "guard.hooks");
    expect(hooks.status).toBe("fail");
    expect(hooks.detail).toContain("Claude Code and Codex");
    expect(hooks.fix).toBe("install-guard");
    expect(planRepairs(report, "auto").map((r) => r.fix)).toEqual(["install-guard"]);
  });

  it("counts a host as present by its own footprint, not by a hook directory we have yet to create", () => {
    // Copilot CLI's hook document lives under `~/.copilot/hooks/`; on a Mac
    // that has Copilot but has never had the guard, that directory does not
    // exist — keying presence on it hid the host from the doctor forever.
    const home = freshMachine();
    const guardDir = guardDirFor(home);
    mkdirSync(join(home, ".copilot"), { recursive: true });
    const hooks = byId(diagnose(input(home, { guardWanted: true, guardDir })), "guard.hooks");
    expect(hooks.status).toBe("fail");
    expect(hooks.detail).toContain("Copilot CLI");
    // ...and a host whose directory is absent stays out of the row entirely.
    expect(hooks.detail).not.toContain("Gemini CLI");
  });

  it("diagnoses clean once the guard is merged into both documents", () => {
    const home = freshMachine();
    const guardDir = guardDirFor(home);
    guardBoth(home, guardDir);
    const report = diagnose(input(home, { guardWanted: true, guardDir }));
    expect(report.fail + report.warn).toBe(0);
    expect(byId(report, "guard.hooks").status).toBe("ok");
    expect(report.headline).toBe("Everything is wired");
  });

  it("an entry an agent dropped on a settings rewrite is a lossless re-wire", () => {
    const home = freshMachine();
    const guardDir = guardDirFor(home);
    guardBoth(home, guardDir);
    writeFileSync(join(home, ".claude", "settings.json"), `${JSON.stringify({ model: "opus" }, null, 2)}\n`);
    const check = byId(diagnose(input(home, { guardWanted: true, guardDir })), "guard.hooks");
    expect(check.status).toBe("fail");
    expect(check.detail).toContain("Claude Code");
    expect(check.detail).not.toContain("Codex");
    expect(check.auto).toBe(true);
  });

  it("sees past the marker: OpenClaw's and Hermes's entries with their plugin files gone are reinstalls", () => {
    // Both are silent fail-opens the document alone cannot show — the entry
    // still carries our marker while the host loads nothing. Both installed
    // exactly as installGuard writes them, then broken the way a person (or
    // an agent "tidying up") would break them. (Hermes is a plugin host since
    // 2026-09-10; its consent companion is gone with the shell hook.)
    const home = freshMachine();
    const guardDir = guardDirFor(home);
    const command = `node "${join(guardDir, "guard.js")}"`;
    guardBoth(home, guardDir);
    // Nothing to say while no present host has artefacts or companions.
    expect(diagnose(input(home, { guardWanted: true, guardDir })).checks.find((c) => c.id === "guard.artifacts")).toBeUndefined();

    mkdirSync(join(home, ".openclaw"), { recursive: true });
    writeFileSync(join(home, ".openclaw", "openclaw.json"), openclawHost.merge(undefined, `${command} --host openclaw`, 60, 75));
    mkdirSync(join(home, ".hermes"), { recursive: true });
    writeFileSync(join(home, ".hermes", "config.yaml"), hermesHost.merge("model:\n  provider: openrouter\n", `${command} --host hermes`, 60, 75));
    // Entries present, but neither plugin directory yet.
    let report = diagnose(input(home, { guardWanted: true, guardDir }));
    expect(byId(report, "guard.hooks").status).toBe("ok");
    let check = byId(report, "guard.artifacts");
    expect(check.status).toBe("fail");
    expect(check.detail).toContain("plugin files are missing");
    expect(check.detail).toContain("OpenClaw");
    expect(check.detail).toContain("Hermes Agent");
    expect(check.fix).toBe("install-guard");
    expect(check.auto).toBe(true);
    expect(planRepairs(report, "auto").map((r) => r.fix)).toEqual(["install-guard"]);

    // What installGuard writes: OpenClaw's three plugin files, Hermes's two.
    for (const artifact of [...openclawHost.artifacts!(home, {}), ...hermesHost.artifacts!(home, {})]) {
      mkdirSync(dirname(artifact.path), { recursive: true });
      writeFileSync(artifact.path, artifact.content);
    }
    report = diagnose(input(home, { guardWanted: true, guardDir }));
    expect(byId(report, "guard.artifacts").status).toBe("ok");
    expect(report.fail + report.warn).toBe(0);

    // A plugin file rewritten by hand is as broken as a missing one.
    writeFileSync(join(home, ".openclaw", "extensions", "doorman-guard", "index.js"), "export default {}\n");
    writeFileSync(join(home, ".hermes", "plugins", "doorman-guard", "__init__.py"), "def register(ctx):\n    pass\n");
    check = byId(diagnose(input(home, { guardWanted: true, guardDir })), "guard.artifacts");
    expect(check.status).toBe("fail");
    expect(check.detail).toContain("OpenClaw");
    expect(check.detail).toContain("Hermes Agent");

    // The doctor resolves the hosts' homes like the installer does: with the
    // state moved by environment, the default location no longer counts.
    const elsewhere = join(home, "claw-elsewhere");
    mkdirSync(elsewhere, { recursive: true });
    writeFileSync(join(elsewhere, "openclaw.json"), openclawHost.merge(undefined, `${command} --host openclaw`, 60, 75));
    for (const artifact of openclawHost.artifacts!(home, { OPENCLAW_STATE_DIR: elsewhere })) {
      mkdirSync(dirname(artifact.path), { recursive: true });
      writeFileSync(artifact.path, artifact.content);
    }
    check = byId(diagnose(input(home, { guardWanted: true, guardDir, env: { OPENCLAW_STATE_DIR: elsewhere } })), "guard.artifacts");
    expect(check.detail).not.toContain("OpenClaw");
    expect(check.detail).toContain("Hermes Agent");
  });

  it("a guard bundle with a missing module is a reinstall of the guard, because the hook would fail open", () => {
    const home = freshMachine();
    const guardDir = guardDirFor(home);
    unlinkSync(join(guardDir, "handshake.js"));
    const check = byId(diagnose(input(home, { guardWanted: true, guardDir })), "guard.bundle");
    expect(check.status).toBe("fail");
    expect(check.detail).toContain("handshake.js");
    expect(check.fix).toBe("install-guard");
  });
});

describe("unreadable hook documents", () => {
  it("a settings.json with comments and trailing commas is repaired losslessly, automatically", () => {
    const home = freshMachine();
    const guardDir = guardDirFor(home);
    guardBoth(home, guardDir);
    const settingsPath = join(home, ".claude", "settings.json");
    const valid = readFileSync(settingsPath, "utf8");
    writeFileSync(settingsPath, `// edited by hand\n${valid.replace(/\n}\s*$/, ",\n}\n")}`);
    const report = diagnose(input(home, { guardWanted: true, guardDir }));
    const check = byId(report, "guard.document:claude");
    expect(check.status).toBe("fail");
    expect(check.fix).toBe("repair-json");
    expect(check.auto).toBe(true);
    expect(check.file).toBe(settingsPath);
    // The guard row waits for the document rather than guessing at it.
    expect(byId(report, "guard.hooks").status).toBe("skip");
    expect(planRepairs(report, "auto")).toEqual([{ fix: "repair-json", file: settingsPath, checks: ["guard.document:claude"] }]);
  });

  it("a truncated settings.json is a LOSSY restore that is offered, never applied unasked", () => {
    const home = freshMachine();
    const guardDir = guardDirFor(home);
    guardBoth(home, guardDir);
    const settingsPath = join(home, ".claude", "settings.json");
    writeFileSync(settingsPath, '{"hooks": {"PreToolUse": [');
    const report = diagnose(input(home, { guardWanted: true, guardDir }));
    const check = byId(report, "guard.document:claude");
    expect(check.fix).toBe("restore-json");
    expect(check.auto).toBe(false);
    expect(check.detail).toContain("There is no backup");
    expect(planRepairs(report, "auto")).toEqual([]);
    expect(planRepairs(report, "all", { only: "guard.document:claude" })).toEqual([
      { fix: "restore-json", file: settingsPath, checks: ["guard.document:claude"] },
    ]);
    // With a readable backup beside it, the offer says so.
    writeFileSync(`${settingsPath}.bak`, "{}\n");
    expect(byId(diagnose(input(home, { guardWanted: true, guardDir })), "guard.document:claude").detail).toContain("would be restored");
  });
});

describe("the plan", () => {
  it("orders documents first and the guard last, one entry per fix", () => {
    const report: DoctorReport = {
      at: "",
      ok: 0,
      warn: 0,
      fail: 0,
      headline: "",
      checks: [
        { id: "guard.hooks", host: "guard", title: "", status: "fail", detail: "", fix: "install-guard", auto: true },
        { id: "guard.artifacts", host: "guard", title: "", status: "fail", detail: "", fix: "install-guard", auto: true },
        { id: "guard.document:codex", host: "guard", title: "", status: "fail", detail: "", fix: "restore-json", auto: false, file: "/h" },
        { id: "guard.document:claude", host: "guard", title: "", status: "fail", detail: "", fix: "repair-json", auto: true, file: "/s" },
        { id: "vscode.hooks", host: "vscode", title: "", status: "fail", detail: "", manual: "flip the setting" },
      ],
    };
    expect(planRepairs(report, "all")).toEqual([
      { fix: "repair-json", file: "/s", checks: ["guard.document:claude"] },
      { fix: "restore-json", file: "/h", checks: ["guard.document:codex"] },
      { fix: "install-guard", checks: ["guard.hooks", "guard.artifacts"] },
    ]);
    expect(planRepairs(report, "auto").map((r) => r.fix)).toEqual(["repair-json", "install-guard"]);
    expect(planRepairs(report, "all", { only: "guard.artifacts" })).toEqual([{ fix: "install-guard", checks: ["guard.artifacts"] }]);
  });

  it("the ledger stands automatic repair down after three applications in an hour", () => {
    let now = 0;
    const ledger = new RepairLedger(() => now);
    const repair = { fix: "install-guard" as const, checks: [] };
    expect(ledger.exhausted(repair)).toBe(false);
    ledger.record(repair);
    ledger.record(repair);
    expect(ledger.exhausted(repair)).toBe(false);
    ledger.record(repair);
    expect(ledger.exhausted(repair)).toBe(true);
    now = 61 * 60_000;
    expect(ledger.exhausted(repair)).toBe(false);
  });
});

describe("repairJsonText", () => {
  it("leaves valid JSON alone and refuses to guess at a truncated document", () => {
    expect(repairJsonText('{"a": 1}')).toBeNull();
    expect(repairJsonText('{"a": [1, 2')).toBeNull();
    expect(repairJsonText("[1, 2]")).toBeNull();
  });

  it("keeps comment-like text inside strings", () => {
    const repaired = repairJsonText('{"url": "https://x//y", "c": "/* not a comment */",}\n')!;
    expect(repaired.value).toEqual({ url: "https://x//y", c: "/* not a comment */" });
    expect(repaired.changes).toEqual(["removed trailing commas"]);
  });
});
