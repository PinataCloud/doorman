import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

import { redact } from "../main/guard/redact.js";
import { detectSecurityFindings } from "../main/guard/security-detect.js";
import { scanMcpToolOutput } from "../main/guard/mcp-poison.js";
import { INJECTION_MARKER_DETECTORS } from "../main/guard/armed.js";

/**
 * The first corpus fixture in this suite: 1,128 distinct MCP tool descriptions
 * from Invariant Guardrails' `sample_mcp_scan_request.jsonl` (real servers —
 * filesystem, desktop-commander, sequential-thinking, WhatsApp, … — plus the
 * mcp-scan poisoning samples), deduplicated by (name, description). This is
 * the false-positive test the hand-built fixtures could never be: the poison
 * scanner and the injection markers must fire on the poisoned samples and on
 * NOTHING else.
 */

interface CorpusTool {
  name: string;
  description: string;
  inputSchema: unknown;
}

const corpus = JSON.parse(readFileSync(new URL("./fixtures/invariant/mcp-tools.json", import.meta.url), "utf8")) as {
  tools: CorpusTool[];
};

/** What every poisoned sample in the corpus has in common: a hidden block, or
 * the one sample that steers "all communication tools" without a block. */
const POISONED_SHAPE = /<\s*(?:important|system|secret|instructions?)\s*>|modify the behavior of all communication tools/i;

describe("Invariant MCP corpus — poison scanner and injection markers", () => {
  const scanned = corpus.tools.map((tool) => {
    const text = `${tool.description}\n${JSON.stringify(tool.inputSchema ?? {})}`;
    const toolName = `mcp__corpus__${tool.name}`;
    const poison = scanMcpToolOutput(text, toolName).map((f) => f.key_name.split(" · ")[0]!);
    const markers = detectSecurityFindings({ kind: "tool_output", text: redact(text), tool_name: toolName })
      .filter((f) => INJECTION_MARKER_DETECTORS.has(f.detector))
      .map((f) => f.detector);
    return { tool, poison, markers };
  });

  it("is the size it claims", () => {
    expect(corpus.tools.length).toBeGreaterThan(1000);
  });

  it("flags every poisoned sample", () => {
    const poisoned = scanned.filter((s) => POISONED_SHAPE.test(s.tool.description));
    expect(poisoned.length).toBeGreaterThanOrEqual(15);
    for (const s of poisoned) {
      expect(s.poison.length, `${s.tool.name}: ${s.tool.description.slice(0, 80)}`).toBeGreaterThan(0);
    }
    // The WhatsApp headline sample carries the full pattern set.
    const whatsapp = scanned.find((s) => s.tool.name === "get_fact_of_the_day")!;
    expect(whatsapp.poison).toEqual(
      expect.arrayContaining(["hidden instruction block", "concealment instruction", "cross-tool steering", "history exfiltration"]),
    );
    // The `add` samples: precondition coercion aimed at ~/.cursor/mcp.json.
    const add = scanned.find((s) => s.tool.name === "malicious_add")!;
    expect(add.poison).toEqual(expect.arrayContaining(["tool precondition coercion", "sensitive path coercion"]));
  });

  it("stays silent on every legitimate description — zero false positives across the corpus", () => {
    const clean = scanned.filter((s) => !POISONED_SHAPE.test(s.tool.description));
    expect(clean.length).toBeGreaterThan(1000);
    const falsePositives = clean.filter((s) => s.poison.length > 0 || s.markers.length > 0);
    expect(
      falsePositives.map((s) => `${s.tool.name}: ${[...s.poison, ...s.markers].join(",")} — ${s.tool.description.slice(0, 100)}`),
    ).toEqual([]);
  });
});
