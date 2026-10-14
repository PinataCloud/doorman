import { describe, expect, it } from "vitest";
import { evaluateToolCall, parsePolicy } from "../main/guard/decision.js";
import { redact } from "../main/guard/redact.js";

/**
 * evaluateToolCall redacts `JSON.stringify(tool_input)`, so every quote in a
 * command arrives as `\"`. A redactor that anchors on a bare quote let the
 * secret through to the spool and the approval card.
 */
const HEX = "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318";
const policy = parsePolicy("{}");
const redacted = (command: string) => evaluateToolCall({ tool_name: "Bash", tool_input: { command }, session_id: "s" }, policy).redacted;

describe("redaction of JSON-escaped tool input", () => {
  it("redacts a quoted --private-key", () => {
    for (const command of [
      `cast send 0xabc "transfer()" --private-key "0x${HEX}"`,
      `cast send --private-key '0x${HEX}'`,
      `forge script --private-key="${HEX}"`,
    ]) {
      expect(redacted(command), command).not.toContain(HEX);
    }
  });

  it("redacts signer / mnemonic / seed-phrase assignments", () => {
    expect(redacted(`SIGNER_KEY="0x${HEX}" node deploy.js`)).not.toContain(HEX);
    expect(redacted(`export SIGNING_KEY="0x${HEX}"`)).not.toContain(HEX);
    expect(redact(`MNEMONIC="abandon ability able about above absent absorb abstract"`)).not.toContain("absorb");
    expect(redact(`SEED_PHRASE=zebra-horse-battery-staple`)).not.toContain("zebra-horse");
    expect(redact(JSON.stringify({ command: `WALLET_PASSPHRASE="hunter2-correct" run` }))).not.toContain("hunter2");
  });

  it("redacts a gitleaks-family token terminated by an escaped quote", () => {
    const token = `pul-${"a1b2c3d4e5".repeat(4)}`;
    expect(redacted(`pulumi login --token "${token}"`)).not.toContain(token);
  });
});
