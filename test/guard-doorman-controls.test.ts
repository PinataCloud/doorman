import { spawnSync } from "node:child_process";
import { cpSync, mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { doormanControl } from "../main/guard/decision.js";

/**
 * An agent must not stand down the check it is under: Doorman's own commands
 * that turn protection down, answer held calls or hide what was recorded are
 * held whatever the policy says, and so is any write into Doorman's data
 * directory (prefs.json is copied into the guard's policy at the next sync).
 */
const held = (command: string, platform: NodeJS.Platform = "darwin") => doormanControl("Bash", { command }, platform)?.label;

describe("doormanControl", () => {
  it("holds the commands that turn protection down, answer held calls or hide what was recorded", () => {
    for (const command of [
      "doorman guard uninstall",
      "doorman rules set secret_egress observe",
      "doorman rules disable secret_egress",
      "doorman policy level relaxed",
      "doorman policy confirm --unattended continue",
      "doorman packs disable crypto_operations",
      "doorman custom-rules add rule.json",
      "doorman custom-rules remove no-prod",
      "doorman custom-rules accept p-0123456789ab",
      "doorman exceptions add --pattern AKIA",
      "doorman watch",
      "doorman watch --stdio",
      "doorman sbx watch",
      "doorman mcp recognize slack",
      "doorman gateway unroute github",
      "doorman findings resolve e-12",
      "doorman findings false-positive e-12",
      "doorman model remove",
      "doorman config set retention_days 1",
    ]) {
      expect(held(command), command).toBeDefined();
    }
  });

  it("finds Doorman however the shell runs it", () => {
    for (const command of [
      "nohup doorman watch --stdio > /dev/null 2>&1 &",
      "FORCE_COLOR=0 doorman --json watch --stdio",
      "cd /tmp && doorman guard uninstall",
      'bash -c "doorman policy level relaxed"',
      "echo y | sudo doorman guard uninstall",
      "/usr/local/bin/doorman watch --stdio",
      "npx -y @pinata/doorman@0.7.1 watch --stdio",
      "npm exec --yes -- @pinata/doorman rules set secret_egress observe",
      "npx -p @pinata/doorman doorman guard uninstall",
      "node ~/x/node_modules/@pinata/doorman/build/main/cli/index.js watch --stdio",
      "ELECTRON_RUN_AS_NODE=1 /Applications/Doorman.app/Contents/MacOS/Doorman /Applications/Doorman.app/Contents/Resources/app.asar/build/main/cli/index.js watch",
      "x=$(doorman packs disable crypto_operations)",
    ]) {
      expect(held(command), command).toBeDefined();
    }
  });

  it("holds a Doorman subcommand the guard can't read", () => {
    expect(held('doorman "$CMD"')).toBeDefined();
    expect(held("doorman rules $(echo set) secret_egress observe")).toBeDefined();
    expect(held("doorman config set $KEY 1")).toBeDefined();
  });

  it("leaves reading, tightening and suggesting alone", () => {
    for (const command of [
      "doorman status --json",
      "doorman scan",
      "doorman findings",
      "doorman findings show e-12",
      'doorman search "$QUERY"',
      "doorman custom-rules",
      "doorman custom-rules dry-run rule.json",
      "doorman custom-rules dismiss p-0123456789ab",
      "doorman rules enable secret_egress",
      "doorman packs enable crypto_operations",
      "doorman guard install",
      "doorman config set appearance dark",
      "doorman constructor",
      'echo "doorman watch --stdio"',
      "grep 'doorman watch' notes.md",
      "node server.js watch",
      "npx some-other-tool watch",
    ]) {
      expect(held(command), command).toBeUndefined();
    }
    // Not a shell call at all.
    expect(doormanControl("Read", { file_path: "/tmp/doorman watch" })).toBeUndefined();
  });

  it("reads Windows spellings", () => {
    expect(held("doorman.cmd watch --stdio", "win32")).toBeDefined();
    expect(held("& 'C:\\Users\\u\\AppData\\Roaming\\npm\\doorman.cmd' guard uninstall", "win32")).toBeDefined();
    expect(held("doorman.cmd scan", "win32")).toBeUndefined();
  });
});

describe("the installed guard", () => {
  // Doorman's usual layout: the guard in <data>/doorman/guard.
  const root = mkdtempSync(join(tmpdir(), "doorman-controls-"));
  const data = join(root, "Doorman");
  const guardDir = join(data, "doorman", "guard");
  mkdirSync(guardDir, { recursive: true });
  cpSync(join(__dirname, "..", "build", "main", "guard"), guardDir, { recursive: true });
  afterAll(() => rmSync(root, { recursive: true, force: true }));

  const decide = (tool_name: string, tool_input: unknown) => {
    const run = spawnSync(process.execPath, [join(guardDir, "guard.js")], {
      input: JSON.stringify({ session_id: "s-controls", transcript_path: "/tmp/none.jsonl", hook_event_name: "PreToolUse", permission_mode: "default", cwd: "/work/repo", tool_name, tool_input }),
      env: { ...process.env, HOME: root },
      encoding: "utf8",
    });
    const out = run.stdout.trim();
    if (out === "") return undefined;
    const parsed: unknown = JSON.parse(out);
    const hook = parsed && typeof parsed === "object" && "hookSpecificOutput" in parsed ? parsed.hookSpecificOutput : undefined;
    const decision = hook && typeof hook === "object" && "permissionDecision" in hook ? hook.permissionDecision : undefined;
    return typeof decision === "string" ? decision : undefined;
  };

  it("holds an agent starting doorman watch --stdio, and lets doorman scan through", () => {
    expect(decide("Bash", { command: "doorman watch --stdio" })).toBe("ask");
    expect(decide("Bash", { command: "doorman scan" })).toBeUndefined();
  });

  it("holds a write to Doorman's settings, beside the guard directory", () => {
    expect(decide("Write", { file_path: join(data, "prefs.json"), content: "{}" })).toBe("ask");
    expect(decide("Bash", { command: `sed -i '' s/ask/observe/ "${join(data, "prefs.json")}"` })).toBe("ask");
    expect(decide("Bash", { command: `cat "${join(data, "prefs.json")}"` })).toBeUndefined();
  });
});
