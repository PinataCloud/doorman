import { execFileSync } from "node:child_process";
import { cpSync, existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { evaluatePrompt } from "../main/guard/decision.js";
import { claudeHost, claudeNormalizeInput, claudeNormalizePrompt, claudePromptOutput } from "../main/guard/hosts/claude.js";
import { codexHost } from "../main/guard/hosts/codex.js";
import {
  defaultPolicy,
  hookDocumentCommands,
  mergeGuardHook,
  PROMPT_HOOK_EVENT,
  removeGuardHook,
} from "../main/guard/policy.js";

/**
 * The prompt door: Claude Code's UserPromptSubmit event runs the
 * same guard, so a seed phrase pasted into a prompt is stopped BEFORE the
 * model sees it. Everything here is the public BIP-39 test vector.
 */

const COMMAND = 'node "/Users/x/Library/Application Support/Doorman/doorman/guard/guard.js"';
const MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

describe("settings.json carries the guard under both events", () => {
  it("claudeHost.merge writes PreToolUse (matcher *) and UserPromptSubmit (no matcher) with one command", () => {
    const doc = claudeHost.merge(undefined, COMMAND, 60, 75);
    const parsed = JSON.parse(doc) as { hooks: Record<string, Array<{ matcher?: string; hooks: Array<{ command: string; timeout: number }> }>> };
    expect(parsed.hooks.PreToolUse).toHaveLength(1);
    expect(parsed.hooks.PreToolUse[0]!.matcher).toBe("*");
    expect(parsed.hooks[PROMPT_HOOK_EVENT]).toHaveLength(1);
    expect(parsed.hooks[PROMPT_HOOK_EVENT]![0]!.matcher).toBeUndefined();
    expect(parsed.hooks[PROMPT_HOOK_EVENT]![0]!.hooks).toEqual([{ type: "command", command: COMMAND, timeout: 75 }]);
    // Idempotent, and `installed` still reads the tool-call entry.
    expect(claudeHost.merge(doc, COMMAND, 60, 75)).toBe(doc);
    expect(claudeHost.installed(doc, COMMAND)).toBe(true);
    expect(hookDocumentCommands(doc, PROMPT_HOOK_EVENT)).toEqual([COMMAND]);
  });

  it("a plain mergeGuardHook (other callers) does not grow the prompt entry", () => {
    const parsed = JSON.parse(mergeGuardHook(undefined, COMMAND)) as { hooks: Record<string, unknown> };
    expect(parsed.hooks[PROMPT_HOOK_EVENT]).toBeUndefined();
  });

  it("removes ours from both events and leaves a co-tenant's prompt hook alone", () => {
    const before = JSON.stringify({
      hooks: { [PROMPT_HOOK_EVENT]: [{ hooks: [{ type: "command", command: "their-prompt-linter" }] }] },
    });
    const merged = claudeHost.merge(before, COMMAND, 60, 75);
    const removed = JSON.parse(claudeHost.remove(merged)!) as { hooks: Record<string, Array<{ hooks: Array<{ command: string }> }>> };
    expect(removed.hooks.PreToolUse).toBeUndefined();
    expect(removed.hooks[PROMPT_HOOK_EVENT]).toHaveLength(1);
    expect(removed.hooks[PROMPT_HOOK_EVENT]![0]!.hooks[0]!.command).toBe("their-prompt-linter");
    expect(removeGuardHook(claudeHost.merge(undefined, COMMAND, 60, 75))).toBe("{}\n");
  });

  it("Codex keeps its PreToolUse-only document", () => {
    const parsed = JSON.parse(codexHost.merge(undefined, COMMAND, 60, 75)) as { hooks: Record<string, unknown> };
    expect(parsed.hooks[PROMPT_HOOK_EVENT]).toBeUndefined();
    expect(codexHost.normalizePrompt).toBeUndefined();
  });
});

describe("the Claude Code prompt payload and output contract", () => {
  const payload = { hook_event_name: PROMPT_HOOK_EVENT, session_id: "s1", cwd: "/repo", prompt: "hello", prompt_id: "p1" };

  it("is a prompt to normalizePrompt and NOT a tool call to normalizeInput", () => {
    expect(claudeNormalizePrompt(payload)).toEqual({ prompt: "hello", session_id: "s1", cwd: "/repo" });
    expect(claudeNormalizeInput(payload)).toBeUndefined();
    // A PreToolUse payload is the other way round.
    const call = { session_id: "s1", tool_name: "Bash", tool_input: { command: "ls" }, hook_event_name: "PreToolUse" };
    expect(claudeNormalizePrompt(call)).toBeUndefined();
    expect(claudeNormalizeInput(call)?.tool_name).toBe("Bash");
  });

  it("deny is stderr + exit 2 (erases the prompt); warn is additionalContext; allow is silence", () => {
    const denied = claudePromptOutput("deny", "Doorman flagged this prompt: Wallet key material.");
    expect(denied.exitCode).toBe(2);
    expect(denied.stderr).toContain("Wallet key material");
    expect(denied.stdout).toBeUndefined();
    const warned = claudePromptOutput("warn", "reason", "Do not use the seed phrase.");
    expect(warned.exitCode).toBe(0);
    expect(JSON.parse(warned.stdout!)).toEqual({
      hookSpecificOutput: { hookEventName: PROMPT_HOOK_EVENT, additionalContext: "Do not use the seed phrase." },
    });
    expect(claudePromptOutput("allow")).toEqual({ exitCode: 0 });
  });
});

describe("evaluatePrompt", () => {
  it("holds a seed phrase and a pasted credential under the default policy, lets prose through", () => {
    const seed = evaluatePrompt({ prompt: `my recovery phrase is ${MNEMONIC}` }, defaultPolicy());
    expect(seed.decision.decision).toBe("ask");
    expect(seed.decision.detectors).toEqual(["wallet_key_material"]);
    expect(seed.redacted).toContain("[redacted:bip39]");
    expect(seed.redacted).not.toContain("abandon abandon");

    // credential_in_prompt ships on ask (2026-09-22): the prompt is held
    // before it is sent, which is the whole point of reaching this path.
    const key = evaluatePrompt({ prompt: "use AKIAZ7Q3LMN4P5R6S2TX for the deploy" }, defaultPolicy());
    expect(key.decision.decision).toBe("ask");
    expect(key.findings.map((f) => f.detector)).toEqual(["credential_in_prompt"]);
    // AWS's own documentation example is not a credential: scrubbed, never held.
    const docs = evaluatePrompt({ prompt: "the docs use AKIAIOSFODNN7EXAMPLE as the key id" }, defaultPolicy());
    expect(docs.decision.decision).toBe("allow");
    expect(docs.redacted).not.toContain("AKIAIOSFODNN7EXAMPLE");
    // …and observed, it is recorded but lets the prompt through.
    const quiet = defaultPolicy();
    quiet.modes.credential_in_prompt = "observe";
    const seen = evaluatePrompt({ prompt: "use AKIAZ7Q3LMN4P5R6S2TX for the deploy" }, quiet);
    expect(seen.decision.decision).toBe("allow");
    expect(seen.findings.map((f) => f.detector)).toEqual(["credential_in_prompt"]);

    expect(evaluatePrompt({ prompt: "refactor the fold in capture.ts" }, defaultPolicy()).findings).toEqual([]);
  });

  it("credential_in_prompt raised to block becomes a deny — the default was never a limit of the path", () => {
    const policy = defaultPolicy();
    policy.modes.credential_in_prompt = "block";
    expect(evaluatePrompt({ prompt: "use AKIAZ7Q3LMN4P5R6S2TX" }, policy).decision.decision).toBe("deny");
  });
});

describe("the compiled guard, end to end on a prompt", () => {
  const built = join(process.cwd(), "desktop", "build", "main", "guard", "guard.js");
  const roots: string[] = [];
  afterAll(() => {
    for (const r of roots) rmSync(r, { recursive: true, force: true });
  });

  const run = (policy: unknown, payload: unknown): { code: number; stdout: string; stderr: string } => {
    const dir = mkdtempSync(join(tmpdir(), "doorman-prompt-guard-"));
    roots.push(dir);
    cpSync(join(process.cwd(), "desktop", "build", "main", "guard"), join(dir, "guard"), { recursive: true });
    writeFileSync(join(dir, "guard", "policy.json"), JSON.stringify(policy));
    try {
      const stdout = execFileSync(process.execPath, [join(dir, "guard", "guard.js")], {
        input: JSON.stringify(payload),
        stdio: ["pipe", "pipe", "pipe"],
        env: { PATH: process.env.PATH ?? "", HOME: dir },
      });
      return { code: 0, stdout: stdout.toString(), stderr: "" };
    } catch (error) {
      const e = error as { status?: number; stdout?: Buffer; stderr?: Buffer };
      return { code: e.status ?? -1, stdout: e.stdout?.toString() ?? "", stderr: e.stderr?.toString() ?? "" };
    }
  };

  // `npm run compile` has not run in this checkout — skip rather than fail.
  const maybe = existsSync(built) ? it : it.skip;

  maybe("blocks the prompt (exit 2, reason on stderr, nothing on stdout) when the rule is block", () => {
    const policy = { ...defaultPolicy(), modes: { wallet_key_material: "block" } };
    const out = run(policy, { hook_event_name: PROMPT_HOOK_EVENT, session_id: "s-e2e", prompt: `seed: ${MNEMONIC}` });
    expect(out.code).toBe(2);
    expect(out.stderr).toMatch(/Wallet key material/);
    expect(out.stderr).not.toContain("abandon");
    expect(out.stdout).toBe("");
  });

  maybe("with the app absent, the default ask ERASES the prompt (exit 2) — nobody could be asked, and that is not an approval", () => {
    // Since 2026-09-10 (`confirm.unattended: "deny"`, review F1): no host has a
    // native ask for a prompt, so an unheld ask is denied. The reason says the
    // user was never reached, never that they denied it.
    const out = run(defaultPolicy(), { hook_event_name: PROMPT_HOOK_EVENT, session_id: "s-e2e", prompt: `seed: ${MNEMONIC}` });
    expect(out.code).toBe(2);
    // stderr is what the PERSON sees in Claude Code once the prompt is erased:
    // the human line naming the rule, never the seed phrase.
    expect(out.stderr).toMatch(/Wallet key material/);
    expect(out.stderr).not.toContain("abandon");
    expect(out.stdout).toBe("");
  });

  maybe("with the app absent and `unattended: continue`, the ask degrades to a note for the agent and exit 0", () => {
    const policy = { ...defaultPolicy(), confirm: { ...defaultPolicy().confirm, unattended: "continue" as const } };
    const out = run(policy, { hook_event_name: PROMPT_HOOK_EVENT, session_id: "s-e2e", prompt: `seed: ${MNEMONIC}` });
    expect(out.code).toBe(0);
    const parsed = JSON.parse(out.stdout) as { hookSpecificOutput: { hookEventName: string; additionalContext: string } };
    expect(parsed.hookSpecificOutput.hookEventName).toBe(PROMPT_HOOK_EVENT);
    expect(parsed.hookSpecificOutput.additionalContext).toMatch(/^Do not use, write or send the seed phrase/);
  });

  maybe("an ordinary prompt is silence", () => {
    const out = run(defaultPolicy(), { hook_event_name: PROMPT_HOOK_EVENT, session_id: "s-e2e", prompt: "rename the helper" });
    expect(out).toEqual({ code: 0, stdout: "", stderr: "" });
  });
});
