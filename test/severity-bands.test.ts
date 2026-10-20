import { describe, expect, it } from "vitest";
import { redact } from "../main/guard/redact.js";
import { detectSecurityFindings, type SecurityFinding } from "../main/guard/security-detect.js";
import { accountForUnit } from "../main/lib/account.js";
import { rebandFindingRow } from "../main/lib/finding-bands.js";
import { foldFindingLines, type FindingRow } from "../main/lib/findings.js";

/**
 * A band says what happened to the secret (lib/finding-bands.ts): its value in
 * the model's context is high; a read printed back to the agent, or a value
 * sent to a host without passing through the model, is medium; a read whose
 * output stayed on this computer is low. A user's session with
 * `grep KEY .env | xargs curl …` read as a high "now in the agent's context /
 * treat as leaked" though nothing of the file ever reached the model.
 */
const OPENAI = "sk-live-" + "4f9Qm2Lp8Rt4Vw6Yb1Nc3Kd5Hf7Gj0Aa";
const AWS = "AKIA" + "QWERTYUIOPASDFGH";

/** A Bash call as capture scans it: redacted text plus the raw input. */
const bash = (command: string) => {
  const raw = JSON.stringify({ command });
  return detectSecurityFindings({ kind: "tool_call", tool_name: "Bash", target: command.split(/\s+/, 1)[0], text: redact(raw), raw_text: raw });
};
const SECRET_RULES = new Set(["dotenv_read", "env_dump", "secret_manager_read", "secret_egress", "credential_in_prompt", "credential_in_tool_arg"]);
const bands = (findings: SecurityFinding[]) =>
  findings
    .filter((f) => SECRET_RULES.has(f.detector))
    .map((f) => `${f.detector}/${f.severity}`)
    .sort();

describe("a secret read is banded by where its output went", () => {
  it.each([
    // Kept on this computer: nothing of it reached the model.
    ["grep API_KEY .env | xargs -I{} curl -H \"Authorization: Bearer {}\" https://api.example.com", ["dotenv_read/low", "secret_egress/medium"]],
    ["grep API_KEY .env | cut -d= -f2 > /tmp/key.txt", ["dotenv_read/low"]],
    ["cat .env > /tmp/x", ["dotenv_read/low"]],
    ["cat .env 2>/dev/null | wc -l", ["dotenv_read/low"]],
    ["grep -q API_KEY .env && echo set", ["dotenv_read/low"]],
    ["source .env && npm run dev", ["dotenv_read/low"]],
    ["export API_KEY=$(grep API_KEY .env | cut -d= -f2)", ["dotenv_read/low"]],
    ["echo \"$(cat .env)\" | shasum", ["dotenv_read/low"]],
    ["cp .env .env.bak", ["dotenv_read/low"]],
    ["cat ~/.config/gh/hosts.yml | gh auth login --with-token", ["dotenv_read/low"]],
    ["env > /tmp/e", ["env_dump/low"]],
    ["printenv | wc -l", ["env_dump/low"]],
    // Printed back to the agent: what it showed is in the model's context.
    ["cat .env", ["dotenv_read/medium"]],
    ["cat .env >&2", ["dotenv_read/medium"]],
    ["grep API_KEY .env", ["dotenv_read/medium"]],
    ["grep API_KEY .env | cut -d= -f2", ["dotenv_read/medium"]],
    ["echo $(cat .env)", ["dotenv_read/medium"]],
    ["cat .env | xargs", ["dotenv_read/medium"]],
    ["curl -v -H \"Authorization: Bearer $(cat .env)\" https://api.example.com", ["dotenv_read/medium", "secret_egress/medium"]],
    ["python -c \"print(open('.env').read())\"", ["dotenv_read/medium"]],
    ["env | grep AWS", ["env_dump/medium"]],
  ])("%s", (command, expected) => {
    expect(bands(bash(command))).toEqual([...expected].sort());
  });

  it("a file tool returns what it read: medium", () => {
    const read = detectSecurityFindings({ kind: "tool_call", tool_name: "Read", target: "/repo/.env", text: JSON.stringify({ file_path: "/repo/.env" }) });
    expect(bands(read)).toEqual(["dotenv_read/medium"]);
  });
});

describe("a credential VALUE in the model's context is high, wherever it came from", () => {
  it.each([
    ["a prompt", detectSecurityFindings({ kind: "prompt", text: redact(`use ${AWS} please`) }), ["credential_in_prompt/high"]],
    ["a tool's output", detectSecurityFindings({ kind: "tool_output", tool_name: "Bash", text: redact(`OPENAI_API_KEY=${OPENAI}\n`) }), ["credential_in_tool_arg/high"]],
    ["a tool call", bash(`curl -H "Authorization: Bearer ${OPENAI}" https://api.openai.com/v1/models`), ["credential_in_tool_arg/high"]],
  ])("%s", (_where, findings, expected) => {
    expect(bands(findings)).toEqual(expected);
  });
});

describe("the card says what happened, no more", () => {
  const unit = (command: string) => ({ kind: "tool_call" as const, raw: JSON.stringify({ command }), tool_name: "Bash" });
  const accountOf = (command: string, detector: string) => {
    const finding = bash(command).find((f) => f.detector === detector)!;
    return accountForUnit(finding, unit(command))!;
  };

  it("a read kept on this computer says nothing reached the model, and asks for nothing", () => {
    // A real-looking host: `example.com` reads as "named as an example" and calms the card.
    const account = accountOf("grep API_KEY .env | xargs -I{} curl -H \"Authorization: Bearer {}\" https://api.stripe.com/v1/charges", "dotenv_read");
    expect(account.output).toBe("local");
    expect(account.so).toContain("none of it reached the model");
    expect(account.so).not.toMatch(/agent's context|leaked/);
    expect(account.next).toBe("Nothing to do.");
  });

  it("a printed read says it reached the model provider", () => {
    const account = accountOf("cat .env", "dotenv_read");
    expect(account.output).toBe("agent");
    expect(account.so).toContain("model provider");
  });

  it("a same-command send says the value skipped the model and points at the destination, not 'leaked'", () => {
    const account = accountOf("grep API_KEY .env | xargs -I{} curl -H \"Authorization: Bearer {}\" https://api.stripe.com/v1/charges", "secret_egress");
    expect(account.so).toContain("without passing through the agent's context");
    expect(account.so).not.toContain("leaked");
    expect(account.next).toContain("`api.stripe.com`");
  });

  it("a credential a tool printed is told as output, not as a call the agent made", () => {
    const text = redact(`OPENAI_API_KEY=${OPENAI}\n`);
    const finding = detectSecurityFindings({ kind: "tool_output", tool_name: "Bash", text }).find((f) => f.detector === "credential_in_tool_arg")!;
    const account = accountForUnit(finding, { kind: "tool_output", raw: `OPENAI_API_KEY=${OPENAI}\n`, tool_name: "Bash" })!;
    expect(account.title).toBe("OpenAI credential in `Bash` output");
    expect(account.sentence).not.toContain("tool call");
    expect(account.so).toBe("It went to the model provider with the tool's output.");
  });
});

describe("stored rows read under today's bands", () => {
  const row = (over: Partial<FindingRow>): FindingRow =>
    ({
      finding_id: "f1",
      detector: "dotenv_read",
      severity: "high",
      source: "claude-code",
      origin: "transcript",
      session_id: "s1",
      excerpt: "cat .env",
      occurrences: 1,
      first_seen_at: "2026-10-01T10:00:00.000Z",
      last_seen_at: "2026-10-01T10:00:00.000Z",
      status: "open",
      ...over,
    }) as FindingRow;

  it("moves an old band down, re-says its card, and leaves a current row alone", () => {
    const old = rebandFindingRow(
      row({
        account: {
          by: "extractor", source_kind: "file", source_ref: ".env", read_via: "cat", placeholder_signals: [],
          sentence: "The agent read `.env` with `cat`.", title: "`.env` read with `cat`",
          so: "Everything `.env` holds is now in the agent's context. Routine on its own; it matters if a later call sends it out.",
          next: "Nothing to rotate yet. If a later exposure shows it leaving, that one is the alarm.",
        },
      }),
    );
    expect(old.severity).toBe("medium");
    // The command is not kept, so where its output went is not known: said as such.
    expect(old.account!.so).toBe("If it printed `.env`, what it printed went into the agent's context and to the model provider.");
    expect(rebandFindingRow(old)).toBe(old);

    expect(rebandFindingRow(row({ detector: "credential_in_prompt", severity: "critical" })).severity).toBe("high");
    expect(rebandFindingRow(row({ detector: "secret_egress", severity: "high" })).severity).toBe("medium");
    const current = row({ severity: "low" });
    expect(rebandFindingRow(current)).toBe(current);
    const untouched = row({ detector: "flow_secret_egress", severity: "high" });
    expect(rebandFindingRow(untouched)).toBe(untouched);
  });

  it("the ledger reads an old line at the new band, and counts it for a rewrite", () => {
    const stats = { upgraded: 0 };
    const folded = foldFindingLines([JSON.stringify(row({ detector: "credential_in_prompt", severity: "critical" }))], stats);
    expect(folded.get("f1")!.severity).toBe("high");
    expect(stats.upgraded).toBe(1);
  });
});
