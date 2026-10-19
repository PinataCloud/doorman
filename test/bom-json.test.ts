import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { prefsPath, readPrefsFile } from "../main/lib/prefs-file.js";
import { defaultPolicy, parsePolicy } from "../main/guard/policy.js";

/**
 * Windows PowerShell 5.1's `Set-Content -Encoding UTF8` (and Notepad) write a
 * UTF-8 byte-order mark, EF BB BF, in front of the JSON. JSON.parse throws on
 * it; the readers below treat a throw as "no file yet", so a hand-edited file
 * silently reset the person's settings to defaults — and prefs.json was then
 * rewritten with those defaults.
 */

const BOM = "\uFEFF";
let dir: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "doorman-bom-"));
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

describe("prefs.json with a byte-order mark", () => {
  it("keeps its values", () => {
    const prefs = { guard_wanted: true, appearance: "dark", onboarded: true };
    writeFileSync(prefsPath(dir), `${BOM}${JSON.stringify(prefs, null, 2)}\n`);

    expect(readPrefsFile(dir)).toEqual(prefs);
  });
});

describe("policy.json with a byte-order mark", () => {
  it("keeps its rules instead of falling back to the defaults", () => {
    const policy = defaultPolicy();
    policy.confirm.hold_seconds = policy.confirm.hold_seconds + 42;

    expect(parsePolicy(`${BOM}${JSON.stringify(policy)}`).confirm.hold_seconds).toBe(policy.confirm.hold_seconds);
  });
});
