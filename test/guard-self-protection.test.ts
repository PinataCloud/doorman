import { describe, expect, it } from "vitest";
import { guardSelfWrite } from "../main/guard/decision.js";
import { detectSecurityFindings } from "../main/guard/security-detect.js";

/**
 * The guard's own directory — the approval handshake, policy.json, armed.json,
 * the guard itself — must not be writable by the agent it guards, whatever the
 * policy or the hidden-rule scope says (the scope hides agent_config_tamper).
 */
const HOME = "/Users/u";
const GUARD = `${HOME}/Library/Application Support/Doorman/doorman/guard`;
const bash = (command: string, cwd = "/repo") => guardSelfWrite("Bash", { command }, cwd, [GUARD], HOME);

describe("guardSelfWrite", () => {
  it("holds approving its own hold, by absolute and by relative path", () => {
    expect(bash(`echo '{"verdict":"allow"}' > "${GUARD}/pending/abc.reply.json"`)).toBeDefined();
    expect(bash(`cd "${GUARD}" && echo '{"verdict":"allow"}' > pending/x.reply.json`)).toBeDefined();
    expect(bash(`echo x>pending/x.reply.json`, GUARD)).toBeDefined();
    expect(bash(`cd ~/Library/"Application Support"/Doorman/doorman/guard; tee pending/y.reply.json < /tmp/r`)).toBeDefined();
  });

  it("holds rewriting the policy or the guard, from any tool", () => {
    expect(guardSelfWrite("Write", { file_path: `${GUARD}/policy.json`, content: "{}" }, "/repo", [GUARD], HOME)).toBeDefined();
    expect(guardSelfWrite("Edit", { file_path: `${GUARD.toUpperCase()}/guard.js` }, "/repo", [GUARD], HOME)).toBeDefined();
    expect(bash(`sed -i '' s/ask/observe/ "${GUARD}/policy.json"`)).toBeDefined();
    expect(bash(`rm -f "${GUARD}/armed.json"`)).toBeDefined();
    expect(bash(`cp /tmp/evil.js "${GUARD}/guard.js"`)).toBeDefined();
    expect(bash(`mv "${GUARD}/policy.json" /tmp/p`)).toBeDefined();
    expect(bash(`find "${GUARD}/pending" -delete`)).toBeDefined();
  });

  it("lets the directory be READ, and leaves other paths alone", () => {
    expect(bash(`cat "${GUARD}/spool.jsonl" | tail -5`)).toBeUndefined();
    expect(bash(`ls -la "${GUARD}/pending" > /tmp/list`)).toBeUndefined();
    expect(bash(`cp "${GUARD}/spool.jsonl" /tmp/spool-copy`)).toBeUndefined();
    expect(bash(`grep -c held "${GUARD}/spool.jsonl"`)).toBeUndefined();
    expect(bash(`echo hi > pending/x.reply.json`, "/repo")).toBeUndefined();
    expect(guardSelfWrite("Write", { file_path: "/repo/policy.json" }, "/repo", [GUARD], HOME)).toBeUndefined();
    expect(guardSelfWrite("Read", { file_path: `${GUARD}/policy.json` }, "/repo", [GUARD], HOME)).toBeUndefined();
  });
});

describe("guardSelfWrite — macOS symlinked roots", () => {
  // macOS rules on any OS: Windows has no /private, and reads these paths its own way.
  const mac = { platform: "darwin" } as const;
  it("treats /private/var and /var as the same directory", () => {
    const real = "/private/var/folders/xy/T/guard";
    expect(guardSelfWrite("Bash", { command: `echo x > pending/a.reply.json` }, "/var/folders/xy/T/guard", [real], HOME, mac)).toBeDefined();
    expect(guardSelfWrite("Write", { file_path: "/private/var/folders/xy/T/guard/policy.json" }, "/r", ["/var/folders/xy/T/guard"], HOME, mac)).toBeDefined();
  });
});

describe("agent_config_tamper — the guard's own files", () => {
  const tamper = (command: string) =>
    detectSecurityFindings({ kind: "tool_call", text: command, tool_name: "Bash", target: command.split(" ")[0] }).filter(
      (f) => f.detector === "agent_config_tamper",
    );

  it("flags a write into the installed guard directory", () => {
    const found = tamper(`echo '{}' > "${GUARD}/policy.json"`);
    expect(found).toHaveLength(1);
    expect(found[0]!.key_name).toBe("Doorman guard files");
  });

  it("leaves a project directory that merely mentions the name alone", () => {
    expect(tamper(`echo x > /repo/doormanguard/notes.txt`)).toEqual([]);
  });
});
