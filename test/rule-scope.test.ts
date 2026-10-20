import { mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { createContext, runInContext } from "node:vm";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { CaptureEngine } from "../main/capture.js";
import { HIDDEN_RULES, HIDDEN_RULE_PACKS, rulePackShown, ruleShown, shownRecord, shownRules } from "../main/guard/rule-scope.js";
import { RULE_PACKS, RULE_PACK_IDS, SHIPPED_RULE_PACKS, defaultEnabledPacks, packRules } from "../main/guard/rule-packs.js";
import { ALL_DETECTORS, DEFAULT_MODES, KNOWN_IGNORE_SCOPES, decideEnforcement, defaultPolicy, levelModes, parsePolicy, SECURITY_LEVELS } from "../main/guard/policy.js";
import { GUARD_FILES } from "../main/enforcement.js";
import { DETECTOR_GUIDANCE } from "../main/lib/ai-guidance.js";
import { LOCAL_DETECTOR_LABELS, mintFindingRow, type FindingRow } from "../main/lib/findings.js";

/**
 * — the desktop app shows ONE kind of rule (sensitive-information
 * exposure) and hides the rest without deleting them. guard/rule-scope.ts is
 * the single decision; these tests pin the two choke points that consume it
 * (the rule catalog and the findings view), the renderer's mirror of the list,
 * and the promise that a hidden rule is recorded but never surfaces.
 */

const rendererDir = new URL("../renderer/", import.meta.url);

function loadRenderer(files: string[]): Record<string, any> {
  const babelSrc = readFileSync(new URL("../assets/vendor/babel.js", import.meta.url), "utf8");
  const ctx: Record<string, any> = { console, setTimeout, clearTimeout, Date, Math, JSON };
  ctx.window = ctx;
  ctx.self = ctx;
  ctx.globalThis = ctx;
  createContext(ctx);
  runInContext(babelSrc, ctx as object, { filename: "babel.js" });
  runInContext("var React = { Fragment: 'F', createElement: function () { return null; } };", ctx as object);
  for (const file of files) {
    const source = readFileSync(new URL(file, rendererDir), "utf8");
    const { code } = ctx.Babel.transform(source, { presets: ["react"], filename: file });
    runInContext(code as string, ctx as object, { filename: file });
  }
  return ctx;
}

/** The kept families, spelled out: what a reader of the proposal expects to still see. */
const KEPT = [
  // credentials & secrets
  "credential_in_prompt", "credential_in_tool_arg", "secret_egress", "env_dump", "dotenv_read",
  "hardcoded_credential", "unrecognized_secret", "secret_manager_read", "flow_secret_egress",
  // crypto wallets & keys
  "wallet_key_material", "wallet_address_exposed", "wallet_address_tampered",
  // personal data
  "pii_exposure",
];

describe("the rule scope (guard/rule-scope.ts)", () => {
  it("hides only real rule ids, and none of the kept families", () => {
    // A typo in HIDDEN_RULES would hide nothing and fail silently; every id
    // must be one the app actually mints.
    const known = new Set<string>([...Object.keys(LOCAL_DETECTOR_LABELS), "mcp_permission"]);
    for (const id of HIDDEN_RULES) expect(known.has(id), `${id} is not a rule the app knows`).toBe(true);
    for (const id of KEPT) expect(ruleShown(id), `${id} must stay visible`).toBe(true);
    // The person's own rules are always theirs to see.
    expect(ruleShown("custom:deploy")).toBe(true);
    expect(shownRules(["secret_egress", "destructive_command", "pii_exposure"])).toEqual(["secret_egress", "pii_exposure"]);
    expect(shownRecord({ secret_egress: 1, destructive_command: 2 })).toEqual({ secret_egress: 1 });
  });

  it("is mirrored exactly by the renderer (components.jsx HIDDEN_RULES)", () => {
    // The renderer is a separate no-import bundle, so it carries a copy. The
    // copy and the original must never part: main would then drop a rule's
    // findings that the renderer still lists, or the other way round.
    const ctx = loadRenderer(["components.jsx"]);
    const mirror = runInContext("[...HIDDEN_RULES]", ctx as object) as string[];
    expect([...mirror].sort()).toEqual([...HIDDEN_RULES].sort());
    // …and the renderer's own tables are already narrowed through it.
    const detectors = runInContext("Object.keys(SEC_DETECTORS)", ctx as object) as string[];
    const families = runInContext("RULE_FAMILIES", ctx as object) as Array<{ key: string; label: string; detectors: string[] }>;
    for (const id of detectors) expect(HIDDEN_RULES.has(id), `${id} is hidden but still in SEC_DETECTORS`).toBe(false);
    for (const fam of families) {
      expect(fam.detectors.length, `${fam.key} is an empty heading`).toBeGreaterThan(0);
      for (const id of fam.detectors) expect(HIDDEN_RULES.has(id), `${id} is hidden but still in ${fam.key}`).toBe(false);
    }
    expect(families.map((f) => f.key)).toEqual(["credentials", "wallets", "pii"]);
    // The dead second copy of the families is gone.
    expect(runInContext("typeof DATA_CATEGORIES", ctx as object)).toBe("undefined");
  });

  it("ships with the guard bundle", () => {
    // policy.js imports it, and the guard runs from a copy in userData: a
    // missing file there is MODULE_NOT_FOUND in someone's session — fail open.
    expect((GUARD_FILES as readonly string[]).includes("rule-scope.js")).toBe(true);
  });
});

describe("the rule packs (guard/rule-packs.ts)", () => {
  it("offers, enables and applies only the packs the app shows", () => {
    for (const id of HIDDEN_RULE_PACKS) {
      expect(SHIPPED_RULE_PACKS.some((p) => p.id === id), `${id} is not a shipped pack`).toBe(true);
      expect(RULE_PACK_IDS, id).not.toContain(id);
      expect(defaultEnabledPacks(), id).not.toContain(id);
      // Even if a prefs file still names it, it contributes no rule to the policy.
      expect(packRules([id]), id).toEqual([]);
    }
    expect(RULE_PACKS.map((p) => p.id)).toEqual(["crypto_operations"]);
    expect(rulePackShown("crypto_operations")).toBe(true);
    expect(packRules(["crypto_operations"]).length).toBeGreaterThan(0);
  });
});

/** Every .ts under main, path relative to it. */
function mainSources(): Array<{ rel: string; text: string }> {
  const root = new URL("../main/", import.meta.url);
  const out: Array<{ rel: string; text: string }> = [];
  const walk = (dir: string, rel: string) => {
    for (const name of readdirSync(dir)) {
      const full = join(dir, name);
      if (statSync(full).isDirectory()) walk(full, `${rel}${name}/`);
      else if (name.endsWith(".ts")) out.push({ rel: `${rel}${name}`, text: readFileSync(full, "utf8") });
    }
  };
  walk(fileURLToPath(root), "");
  return out;
}

describe("the choke points stay the only readers", () => {
  it("nothing outside capture.ts reads the ledger, and nothing outside rule-packs.ts reads the shipped pack list", () => {
    // The whole design is two read paths. A third one — `engine.ledger` in a
    // new snapshot field, or SHIPPED_RULE_PACKS in a new screen's data — would
    // put a hidden rule back on a surface without anyone deciding to.
    for (const { rel, text } of mainSources()) {
      if (rel !== "capture.ts") {
        expect(text, `${rel} reads the ledger directly`).not.toMatch(/\bengine\.ledger\b|\.ledger\.(values|get|size|has)\(/);
      }
      if (rel !== "guard/rule-packs.ts") {
        expect(text, `${rel} reads the shipped pack list`).not.toContain("SHIPPED_RULE_PACKS");
      }
    }
  });
});

describe("choke point 1 — the rule catalog (ALL_DETECTORS)", () => {
  it("lists no hidden rule anywhere a 'which rules exist' surface reads", () => {
    for (const id of ALL_DETECTORS) expect(HIDDEN_RULES.has(id), id).toBe(false);
    for (const id of Object.keys(DEFAULT_MODES)) expect(HIDDEN_RULES.has(id), id).toBe(false);
    for (const id of KNOWN_IGNORE_SCOPES) expect(HIDDEN_RULES.has(id), id).toBe(false);
    for (const id of Object.keys(DETECTOR_GUIDANCE)) expect(HIDDEN_RULES.has(id), id).toBe(false);
    for (const level of SECURITY_LEVELS) {
      for (const id of Object.keys(levelModes(level))) expect(HIDDEN_RULES.has(id), `${level}: ${id}`).toBe(false);
    }
    // The kept enforceable rules are all still there.
    for (const id of ["credential_in_tool_arg", "secret_egress", "wallet_key_material", "pii_exposure", "env_dump"]) {
      expect(ALL_DETECTORS).toContain(id);
    }
  });

  it("means a hidden rule can never hold, warn or block — the guard observes it", () => {
    // A policy file that names hidden rules (written by an older build, or by
    // hand) loses those modes on parse, so decideEnforcement reads observe.
    const policy = parsePolicy(JSON.stringify({ modes: { destructive_command: "block", exfil_render_link: "ask", license_contamination: "warn" }, disabled: ["agent_config_tamper"] }));
    expect(policy.modes).toEqual(defaultPolicy().modes);
    expect(policy.disabled).toEqual([]);
    for (const detector of ["destructive_command", "exfil_render_link", "license_contamination", "agent_config_tamper"] as const) {
      const d = decideEnforcement([{ detector, severity: "critical", confidence: "high", excerpt: "", occurrences: 1 } as never], policy);
      expect(d.decision, detector).toBe("allow");
      expect(d.detectors, detector).toEqual([]);
      expect(d.warned, detector).toEqual([]);
    }
    // …while a kept rule still holds as shipped.
    expect(decideEnforcement([{ detector: "secret_egress", severity: "high", confidence: "high", excerpt: "", occurrences: 1 } as never], policy).decision).toBe("ask");
  });
});

describe("choke point 2 — the findings view (CaptureEngine.shownFindings)", () => {
  let root: string;
  let notified: FindingRow[][];
  let engine: CaptureEngine;

  beforeEach(() => {
    root = mkdtempSync(join(tmpdir(), "doorman-scope-"));
    mkdirSync(join(root, "claude", "projects"), { recursive: true });
    mkdirSync(join(root, "codex", "sessions"), { recursive: true });
    notified = [];
    engine = new CaptureEngine({
      storeDir: join(root, "store"),
      claudeProjectsDir: join(root, "claude", "projects"),
      codexSessionsDir: join(root, "codex", "sessions"),
      home: root,
      policy: () => defaultPolicy(),
      retentionDays: () => 0,
      onUpdate: () => {},
      onNewFindings: (rows) => {
        notified.push([...rows]);
      },
      log: () => {},
    });
  });

  afterEach(() => {
    engine.stop();
    rmSync(root, { recursive: true, force: true });
  });

  // A config row names the file it came from, as the MCP watcher's rows do:
  // without one there is nothing to open and the evidence rule hides it
  //, which is not what this file is testing.
  const row = (detector: string, key_name: string) =>
    mintFindingRow(
      { detector: detector as never, severity: "high", key_name, excerpt: "[redacted]", occurrences: 1, target: "/Users/dev/.claude.json" },
      { source: "claude-code", origin: "config", at: "2026-09-21T10:00:00.000Z" },
    );

  it("records a hidden rule's finding in the ledger but shows it to no one, and never announces it", async () => {
    await engine.start();
    const shown = row("secret_egress", "aws");
    const hidden = row("destructive_command", "rm -rf");
    engine.ingestConfigFindings([shown, hidden]);
    // The ledger — the store of record — has both.
    expect(engine.ledger.size).toBe(2);
    expect(engine.ledger.get(hidden.finding_id)?.detector).toBe("destructive_command");
    // What the app shows has one.
    expect(engine.shownFindings().map((r) => r.detector)).toEqual(["secret_egress"]);
    expect(engine.shownFinding(shown.finding_id)?.detector).toBe("secret_egress");
    // A hidden row by id reads exactly like an unknown id.
    expect(engine.shownFinding(hidden.finding_id)).toBeUndefined();
    expect(engine.shownFinding("nope")).toBeUndefined();
    // Only the shown row was announced.
    expect(notified.flat().map((r) => r.detector)).toEqual(["secret_egress"]);
  });

  it("the guard's own alarm is recorded but not shown — hidden with its family since 2026-09-21", async () => {
    // The Settings integrity row still reports the guard's state from the
    // integrity check itself; only the Radar card for the finding is hidden.
    await engine.start();
    engine.ingestConfigFindings([row("guard_tampered", "hook entry missing")]);
    expect(engine.ledger.size).toBe(1);
    expect(engine.shownFindings()).toEqual([]);
  });
});
