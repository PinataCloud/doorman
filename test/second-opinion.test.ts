import { describe, expect, it } from "vitest";
import {
  SECOND_OPINION_DETECTORS,
  applySecondOpinion,
  askLocalModel,
  buildSecondOpinionPrompt,
  eligibleForSecondOpinion,
  parseSecondOpinionVerdict,
  rawWindow,
  SECOND_OPINION_TOTAL_BUDGET_MS,
  secondOpinion,
  secondOpinionRawText,
  type FetchLike,
} from "../main/guard/second-opinion.js";
import {
  SECOND_OPINION_DEFAULT_ENDPOINT,
  SECOND_OPINION_TIMEOUT_MAX_MS,
  SECOND_OPINION_TIMEOUT_MIN_MS,
  decideEnforcement,
  defaultPolicy,
  isLoopbackEndpoint,
  normalizeSecondOpinion,
  parsePolicy,
  type GuardPolicy,
  type SecondOpinionPolicy,
} from "../main/guard/policy.js";
import { evaluateToolCall } from "../main/guard/decision.js";
import type { SecurityFinding } from "../main/guard/security-detect.js";

const enabled = (over: Partial<SecondOpinionPolicy> = {}): SecondOpinionPolicy => ({
  enabled: true,
  endpoint: SECOND_OPINION_DEFAULT_ENDPOINT,
  model: "test-model",
  timeout_ms: 1000,
  ...over,
});

/** A fetch that answers every question with the given model reply. */
const answering = (content: string, status = 200): FetchLike & { calls: Array<{ url: string; body: unknown }> } => {
  const calls: Array<{ url: string; body: unknown }> = [];
  const impl = (async (url: string, init: RequestInit) => {
    calls.push({ url, body: JSON.parse(String(init.body)) });
    return {
      ok: status >= 200 && status < 300,
      status,
      text: async () => JSON.stringify({ choices: [{ message: { content } }] }),
    };
  }) as FetchLike & { calls: typeof calls };
  impl.calls = calls;
  return impl;
};

const finding = (over: Partial<SecurityFinding> = {}): SecurityFinding => ({
  detector: "hardcoded_credential",
  severity: "high",
  key_name: "PASSWORD_INPUT",
  excerpt: "…and generative art never combine a password input with a form. const PASSWORD_INPUT = [redacted] ;…",
  occurrences: 1,
  ...over,
});

/** A policy that holds on the two guessing detectors, second opinion on. */
const holding = (so: Partial<SecondOpinionPolicy> = {}): GuardPolicy => ({
  ...defaultPolicy(),
  modes: { ...defaultPolicy().modes, hardcoded_credential: "ask", unrecognized_secret: "ask", destructive_command: "ask" },
  second_opinion: enabled(so),
});

describe("the loopback rule", () => {
  it("accepts only addresses that are this machine", () => {
    for (const ok of [
      "http://127.0.0.1:11434/v1/chat/completions",
      "http://localhost:1234/v1/chat/completions",
      "http://[::1]:8080/v1/chat/completions",
      "https://127.0.0.1/v1/chat/completions",
    ]) {
      expect(isLoopbackEndpoint(ok), ok).toBe(true);
    }
    for (const bad of [
      "http://localhost.evil.example/v1/chat/completions",
      "http://127.0.0.1.nip.io/v1",
      "http://10.0.0.5:11434/v1/chat/completions",
      "http://api.openai.com/v1/chat/completions",
      "ftp://127.0.0.1/x",
      "not a url",
      "",
    ]) {
      expect(isLoopbackEndpoint(bad), bad).toBe(false);
    }
  });

  it("normalize refuses to enable a non-loopback endpoint, keeping the URL so Settings can say why", () => {
    const so = normalizeSecondOpinion({ enabled: true, endpoint: "http://10.0.0.5:11434/v1/chat/completions" });
    expect(so.enabled).toBe(false);
    expect(so.endpoint).toBe("http://10.0.0.5:11434/v1/chat/completions");
  });

  it("normalize clamps the time budget and rejects a junk model id", () => {
    expect(normalizeSecondOpinion({ timeout_ms: 1 }).timeout_ms).toBe(SECOND_OPINION_TIMEOUT_MIN_MS);
    expect(normalizeSecondOpinion({ timeout_ms: 60_000 }).timeout_ms).toBe(SECOND_OPINION_TIMEOUT_MAX_MS);
    expect(normalizeSecondOpinion({ model: "llama3.2:1b" }).model).toBe("llama3.2:1b");
    expect(normalizeSecondOpinion({ model: "a model with spaces" }).model).toBe(normalizeSecondOpinion({}).model);
    expect(normalizeSecondOpinion(undefined).enabled).toBe(false);
  });

  it("rides policy.json through parsePolicy", () => {
    const policy = parsePolicy(
      JSON.stringify({ version: 1, second_opinion: { enabled: true, model: "qwen2.5:1.5b", timeout_ms: 2000 } }),
    );
    expect(policy.second_opinion).toEqual({
      enabled: true,
      endpoint: SECOND_OPINION_DEFAULT_ENDPOINT,
      model: "qwen2.5:1.5b",
      timeout_ms: 2000,
    });
    expect(parsePolicy(JSON.stringify({ version: 1 })).second_opinion).toBeUndefined();
  });
});

describe("secondOpinionRawText", () => {
  it("hands a write tool its parsed payload fields, and anything else the JSON argument", () => {
    expect(secondOpinionRawText("Write", { file_path: "a.ts", content: 'x = "y"\nz' })).toBe('x = "y"\nz');
    expect(secondOpinionRawText("Edit", { file_path: "a.ts", old_string: "o", new_string: "n" })).toBe("n");
    expect(secondOpinionRawText("Bash", { command: "echo hi" })).toBe('{"command":"echo hi"}');
    expect(secondOpinionRawText("Write", { file_path: "a.ts" })).toBe('{"file_path":"a.ts"}');
  });
});

describe("rawWindow", () => {
  it("re-locates the masked excerpt in the raw text and returns the raw value around it", () => {
    const raw = secondOpinionRawText("Write", {
      file_path: "src/utils/contentsniffer.ts",
      content:
        "//icons, charts and generative art never combine a password input with a form.\nconst PASSWORD_INPUT = /<input[^>]*type\\s*=\\s*['\"]?password/i;\nconst DOCUMENT_CAPABILITY = /<foreignObject/i;",
    });
    const window = rawWindow(raw, finding());
    expect(window).toContain("const PASSWORD_INPUT = /<input");
    expect(window).toContain("password/i;");
  });

  it("falls back to the key name, then to the head of the payload", () => {
    const raw = "x".repeat(50) + " const TOKEN = 'abc' " + "y".repeat(50);
    expect(rawWindow(raw, finding({ key_name: "TOKEN", excerpt: "nothing that appears [redacted] here" }))).toContain("const TOKEN = 'abc'");
    expect(rawWindow("short payload", finding({ key_name: undefined, excerpt: "[redacted]" }))).toBe("short payload");
  });

  it("is bounded", () => {
    const raw = "const SECRET = 'a'; " + "z".repeat(5000);
    expect(rawWindow(raw, finding({ key_name: "SECRET", excerpt: "const SECRET = [redacted]" }), 300).length).toBeLessThanOrEqual(300);
  });
});

describe("the prompt", () => {
  it("asks one narrow question and carries only the detector, key name, tool and raw window", () => {
    const messages = buildSecondOpinionPrompt(finding(), "const PASSWORD_INPUT = /password/i;", "Write");
    expect(messages[0].role).toBe("system");
    expect(messages[0].content).toMatch(/not_credential/);
    expect(messages[0].content).toMatch(/Prefer unsure over not_credential/);
    const user = JSON.parse(messages[1].content) as Record<string, unknown>;
    expect(Object.keys(user).sort()).toEqual(["detector", "key_name", "raw_window", "tool"]);
    expect(user.raw_window).toBe("const PASSWORD_INPUT = /password/i;");
  });
});

describe("parseSecondOpinionVerdict", () => {
  it("accepts the three words in the asked-for JSON, or bare", () => {
    expect(parseSecondOpinionVerdict('{"verdict":"not_credential","reason":"a regex literal"}')).toEqual({
      verdict: "not_credential",
      reason: "a regex literal",
    });
    expect(parseSecondOpinionVerdict('Sure! ```json\n{"verdict": "credential", "reason": "looks live"}\n```').verdict).toBe("credential");
    expect(parseSecondOpinionVerdict("unsure").verdict).toBe("unsure");
    expect(parseSecondOpinionVerdict("not_credential.").verdict).toBe("not_credential");
  });

  it("treats anything else as unsure, and clamps the reason", () => {
    expect(parseSecondOpinionVerdict("This is definitely not a credential, trust me").verdict).toBe("unsure");
    expect(parseSecondOpinionVerdict('{"verdict":"safe"}').verdict).toBe("unsure");
    expect(parseSecondOpinionVerdict("").verdict).toBe("unsure");
    const long = parseSecondOpinionVerdict(`{"verdict":"unsure","reason":"${"r".repeat(500)}"}`);
    expect(long.reason?.length).toBe(200);
  });
});

describe("askLocalModel", () => {
  it("posts an OpenAI-compatible chat request at temperature 0 and parses the answer", async () => {
    const fetchImpl = answering('{"verdict":"not_credential","reason":"regex"}');
    const answer = await askLocalModel(enabled(), buildSecondOpinionPrompt(finding(), "w"), fetchImpl);
    expect(answer).toEqual({ verdict: "not_credential", reason: "regex" });
    expect(fetchImpl.calls[0].url).toBe(SECOND_OPINION_DEFAULT_ENDPOINT);
    const body = fetchImpl.calls[0].body as Record<string, unknown>;
    expect(body.model).toBe("test-model");
    expect(body.temperature).toBe(0);
    expect(body.stream).toBe(false);
  });

  it("is unsure on an HTTP error, a shapeless body, a thrown fetch and a timeout", async () => {
    expect((await askLocalModel(enabled(), [], answering("x", 500))).verdict).toBe("unsure");
    const shapeless: FetchLike = async () => ({ ok: true, status: 200, text: async () => JSON.stringify({ nope: 1 }) });
    expect((await askLocalModel(enabled(), [], shapeless))).toEqual({ verdict: "unsure", error: "no content" });
    const throwing: FetchLike = async () => {
      throw new Error("ECONNREFUSED");
    };
    expect((await askLocalModel(enabled(), [], throwing)).error).toBe("ECONNREFUSED");
    const hanging: FetchLike = (_url, init) =>
      new Promise((_resolve, reject) => {
        init.signal?.addEventListener("abort", () => {
          const err = new Error("aborted");
          err.name = "AbortError";
          reject(err);
        });
      });
    const slow = await askLocalModel(enabled({ timeout_ms: 20 }), [], hanging);
    expect(slow).toEqual({ verdict: "unsure", error: "timeout" });
  });
});

describe("eligibility and application", () => {
  it("only the two guessing detectors, only when driving the interrupt, only at full confidence", () => {
    const drive = finding();
    const notDriving = finding({ detector: "unrecognized_secret", key_name: "b" });
    const alreadyMedium = finding({ key_name: "c", confidence: "medium" });
    const deterministic = finding({ detector: "destructive_command", key_name: "rm -rf" });
    const custom = { ...finding({ key_name: "d" }), detector: "custom:mine", mode: "ask" as const, label: "mine" };
    const picked = eligibleForSecondOpinion(
      [drive, notDriving, alreadyMedium, deterministic, custom as never],
      ["hardcoded_credential", "destructive_command", "custom:mine"],
    );
    expect(picked).toEqual([drive]);
    expect([...SECOND_OPINION_DETECTORS].sort()).toEqual(["hardcoded_credential", "unrecognized_secret"]);
  });

  it("a not_credential lowers that finding to medium; credential and unsure change nothing", () => {
    const a = finding({ key_name: "a" });
    const b = finding({ key_name: "b" });
    const c = finding({ key_name: "c" });
    const downgraded = applySecondOpinion([
      { finding: a, verdict: "not_credential" },
      { finding: b, verdict: "credential" },
      { finding: c, verdict: "unsure" },
    ]);
    expect(downgraded).toEqual(["hardcoded_credential"]);
    expect(a.confidence).toBe("medium");
    expect(b.confidence).toBeUndefined();
    expect(c.confidence).toBeUndefined();
    expect(a.severity).toBe("high"); // severity is never touched — only confidence
  });
});

describe("the whole pass against the fold", () => {
  const write = (content: string) => ({
    tool_name: "Write",
    tool_input: { file_path: "src/auth.ts", content },
  });

  it("stands a hold down when the model says not_credential — and the re-fold allows", async () => {
    const policy = holding();
    const result = evaluateToolCall(write(`const password = "hunter2000"; // fixture for the login form test`), policy);
    expect(result.decision.decision).toBe("ask");
    const telemetry = await secondOpinion(
      result.findings,
      result.decision.detectors,
      JSON.stringify(write("x").tool_input),
      policy.second_opinion!,
      "Write",
      answering('{"verdict":"not_credential","reason":"a test fixture"}'),
      (() => {
        let t = 1000;
        return () => (t += 40);
      })(),
    );
    expect(telemetry).toMatchObject({
      model: "test-model",
      downgraded: ["hardcoded_credential"],
      judged: [{ detector: "hardcoded_credential", key_name: "password", verdict: "not_credential", reason: "a test fixture" }],
    });
    expect(telemetry!.latency_ms).toBeGreaterThan(0);
    expect(decideEnforcement(result.findings, policy).decision).toBe("allow");
  });

  it("leaves the hold alone on credential, unsure, an error, or a disabled policy", async () => {
    for (const reply of ['{"verdict":"credential"}', '{"verdict":"unsure"}', "I think it is fine"]) {
      const policy = holding();
      const result = evaluateToolCall(write(`const password = "hunter2000";`), policy);
      const telemetry = await secondOpinion(result.findings, result.decision.detectors, "{}", policy.second_opinion!, "Write", answering(reply));
      expect(telemetry?.downgraded, reply).toEqual([]);
      expect(decideEnforcement(result.findings, policy).decision, reply).toBe("ask");
    }
    const policy = holding();
    const result = evaluateToolCall(write(`const password = "hunter2000";`), policy);
    const failed = await secondOpinion(result.findings, result.decision.detectors, "{}", policy.second_opinion!, "Write", answering("x", 503));
    expect(failed).toMatchObject({ downgraded: [], error: "HTTP 503" });
    expect(decideEnforcement(result.findings, policy).decision).toBe("ask");
    const off = await secondOpinion(result.findings, result.decision.detectors, "{}", { ...policy.second_opinion!, enabled: false }, "Write", answering('{"verdict":"not_credential"}'));
    expect(off).toBeUndefined();
  });

  it("never stands down a hold that a deterministic detector also drives", async () => {
    const policy = holding();
    const findings: SecurityFinding[] = [
      finding({ key_name: "password", excerpt: 'const password = [redacted] ;' }),
      finding({ detector: "destructive_command", key_name: "rm -rf", excerpt: "rm -rf /" }),
    ];
    const before = decideEnforcement(findings, policy);
    expect(before.decision).toBe("ask");
    expect(before.detectors).toEqual(["hardcoded_credential", "destructive_command"]);
    const fetchImpl = answering('{"verdict":"not_credential"}');
    const telemetry = await secondOpinion(findings, before.detectors, 'const password = "x"; rm -rf /', policy.second_opinion!, "Bash", fetchImpl);
    // The credential finding was judged and lowered…
    expect(telemetry?.downgraded).toEqual(["hardcoded_credential"]);
    expect(fetchImpl.calls.length).toBe(1);
    // …and the call is still held, now for the reason that was never a guess.
    const after = decideEnforcement(findings, policy);
    expect(after.decision).toBe("ask");
    expect(after.detectors).toEqual(["destructive_command"]);
  });

  it("returns undefined — asks nothing — when the interrupt is not one of the guessing detectors", async () => {
    const policy = holding();
    const result = evaluateToolCall({ tool_name: "Bash", tool_input: { command: "rm -rf /" } }, policy);
    expect(result.decision.decision).toBe("ask");
    const fetchImpl = answering('{"verdict":"not_credential"}');
    expect(await secondOpinion(result.findings, result.decision.detectors, "{}", policy.second_opinion!, "Bash", fetchImpl)).toBeUndefined();
    expect(fetchImpl.calls.length).toBe(0);
  });

  it("sends the raw window — the model sees what the excerpt masked", async () => {
    const policy = holding();
    const content = `const password = "hunter2000";`;
    const result = evaluateToolCall(write(content), policy);
    const fetchImpl = answering('{"verdict":"unsure"}');
    await secondOpinion(result.findings, result.decision.detectors, secondOpinionRawText("Write", write(content).tool_input), policy.second_opinion!, "Write", fetchImpl);
    const body = fetchImpl.calls[0].body as { messages: Array<{ content: string }> };
    expect(body.messages[1].content).toContain("hunter2000");
  });
});

describe("the whole pass fits inside the hook's budget", () => {
  it("stops asking once the overall deadline is spent, and bounds each question by what is left", async () => {
    const policy = holding({ timeout_ms: 6_000 });
    const findings = ["A_TOKEN", "B_TOKEN", "C_TOKEN"].map((key_name) => finding({ key_name }));
    const seen: number[] = [];
    // Each answer "takes" 4 s of the clock.
    let now = 0;
    const slow = (async (_url: string, init: RequestInit) => {
      seen.push(Number((init as RequestInit & { signal?: AbortSignal }).signal ? 1 : 0));
      now += 4_000;
      return { ok: true, status: 200, text: async () => JSON.stringify({ choices: [{ message: { content: '{"verdict":"unsure"}' } }] }) };
    }) as FetchLike;
    const telemetry = await secondOpinion(findings, ["hardcoded_credential"], "{}", policy.second_opinion!, "Write", slow, () => now);
    // 3 × 6 s used to be allowed (18 s against a 10 s hook budget).
    expect(SECOND_OPINION_TOTAL_BUDGET_MS).toBeLessThanOrEqual(6_000);
    expect(telemetry!.judged.length).toBeLessThan(3);
    expect(telemetry!.latency_ms).toBeLessThanOrEqual(SECOND_OPINION_TOTAL_BUDGET_MS + 4_000);
    expect(telemetry!.downgraded).toEqual([]);
  });
});

