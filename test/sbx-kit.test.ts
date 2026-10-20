/**
 * The Doorman kit for Docker Sandboxes comes in two formats (v2:
 * integrations/sbx-kit/spec.yaml, v3: integrations/sbx-kit/v3/doorman) that
 * must do the same thing, and three places point at them: the CLI's advice
 * for a sandbox without Doorman, the publish workflow, and the docs. These
 * keep the pair in step and the pointers on real folders. `sbx kit validate`
 * / `sbx kit inspect` check each file's own shape; that needs `sbx`, so it is
 * the publish workflow's job, not this test's.
 */
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { DOORMAN_KIT, DOORMAN_KIT_V3 } from "../main/cli/sbx-host";

const root = join(__dirname, "..");
const read = (path: string) => readFileSync(join(root, path), "utf8");
const v2 = read("integrations/sbx-kit/spec.yaml");
const v3 = read("integrations/sbx-kit/v3/doorman/doorman.yaml");

describe("the Doorman sbx kits", () => {
  it("declare their formats", () => {
    expect(v2).toMatch(/^schemaVersion: "2"$/m);
    expect(v2).toMatch(/^kind: mixin$/m);
    // The v3 frontend is selected by the first line.
    expect(v3.split("\n")[0]).toBe("# syntax=docker/sandbox-kit:3");
    expect(v3).toMatch(/^schemaVersion: "3"$/m);
    expect(v3).toMatch(/^kind: mixin$/m);
  });

  it("let the sandbox reach the classifier's hosts, the CDN included", () => {
    for (const kit of [v2, v3]) {
      expect(kit).toMatch(/^\s+- huggingface\.co$/m);
      // *.hf.co would miss us.aws.cdn.hf.co, where the model files redirect.
      expect(kit).toMatch(/^\s+- "\*\*\.hf\.co"$/m);
    }
  });

  it("install the same CLI the same way and run the same setup", () => {
    // The `version` argument's `pattern:` line.
    const pattern = /^\s*pattern: (.+)$/m;
    expect(pattern.exec(v3)?.[1]).toBe(pattern.exec(v2)?.[1]);
    for (const kit of [v2, v3]) {
      expect(kit).toMatch(/^\s+default: latest$/m);
      expect(kit).toContain('"@pinata/doorman@${{ kit.args.version }}"');
      expect(kit).toMatch(/command: doorman guard install$/m);
      // Startup commands never fail: a failing one can stop the sandbox.
      expect(kit).toContain("doorman doctor --repair auto > /dev/null || true");
      expect(kit).toContain("doorman model download --auto > /dev/null || true");
      expect(kit).toMatch(/model download[^\n]*\n\s+background: true$/m);
    }
  });

  it("are where the CLI's advice and the publish workflow point", () => {
    for (const ref of [DOORMAN_KIT, DOORMAN_KIT_V3]) {
      const dir = /#dir=([^&]+)$/.exec(ref)?.[1];
      expect(dir, ref).toBeDefined();
      expect(existsSync(join(root, dir!)), ref).toBe(true);
    }
    expect(existsSync(join(root, DOORMAN_KIT.split("#dir=")[1]!, "spec.yaml"))).toBe(true);
    expect(existsSync(join(root, DOORMAN_KIT_V3.split("#dir=")[1]!, "doorman.yaml"))).toBe(true);

    const workflow = read(".github/workflows/sbx-kit.yml");
    expect(workflow).toMatch(/^\s+KIT_V2: integrations\/sbx-kit$/m);
    expect(workflow).toMatch(/^\s+KIT_V3: integrations\/sbx-kit\/v3\/doorman$/m);
    expect(workflow).toContain('-f "$KIT_V3/doorman.yaml"');
  });
});
