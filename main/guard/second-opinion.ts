/**
 * The local-model second opinion — a precision pass the guard runs on ITS OWN
 * findings, right before it would interrupt someone.
 *
 * The deterministic detectors own recall and are the only thing allowed to
 * raise a finding (see security-detect.ts). Two of them are honest guesses at
 * the edge — `hardcoded_credential` and `unrecognized_secret` judge a value on
 * its shape — and a guess is exactly what a small language model is good at
 * checking: shown the surrounding lines, it can tell a test fixture, a regex
 * literal or a doc example from a pasted key far better than a charset rule.
 *
 * Four rules, none negotiable:
 *
 * 1. DOWNGRADE ONLY. The model's answer can lower a finding's confidence to
 *    `medium` (which decideEnforcement never holds on) and nothing else. It
 *    cannot raise severity, add a finding, or touch a detector it was not asked
 *    about. Recall stays reproducible from the text alone.
 * 2. LOOPBACK ONLY. The model sees the RAW window around the match — that is
 *    the whole point, a masked excerpt cannot be re-judged — so the endpoint
 *    must be this machine (policy.ts isLoopbackEndpoint). Raw tool content
 *    never crosses the network from here.
 * 3. ONLY WHEN IT MATTERS. It runs when the fold already said `ask` or `deny`
 *    and one of the eligible detectors is among the reasons. Observe-mode
 *    findings are never sent: no latency on a call that was going to run.
 * 4. ABSENT MEANS UNCHANGED. Endpoint down, model missing, timeout, garbage
 *    reply, `unsure` — every one of those leaves the decision exactly as the
 *    detectors made it. The model can never be the reason a hold did NOT
 *    happen unless it said, in the one word asked for, that this is not a
 *    credential.
 *
 * Self-containment rule: copied verbatim into userData with the rest of the
 * guard, so nothing here may import from outside main/guard/.
 */

import { HOOK_TIMEOUT_FAST_SECONDS, SECOND_OPINION_TIMEOUT_MIN_MS, type GuardFinding, type SecondOpinionPolicy } from "./policy.js";
import { isWriteTool, type SecurityDetectorId, type SecurityFinding } from "./security-detect.js";

/** The detectors whose finding is a shape guess a model may re-judge. */
export const SECOND_OPINION_DETECTORS: ReadonlySet<SecurityDetectorId> = new Set<SecurityDetectorId>([
  "hardcoded_credential",
  "unrecognized_secret",
]);

export type SecondOpinionVerdict = "credential" | "not_credential" | "unsure";

/** One judged finding, as the spool carries it: names, never values. */
export interface SecondOpinionJudgement {
  detector: string;
  key_name?: string;
  verdict: SecondOpinionVerdict;
  /** The model's one-line reason, clamped. Written for the spool row only. */
  reason?: string;
}

/** What the guard spools next to the decision when the pass ran. */
export interface SecondOpinionTelemetry {
  model: string;
  latency_ms: number;
  judged: SecondOpinionJudgement[];
  /** Detectors whose finding(s) the verdict lowered to medium confidence. */
  downgraded: string[];
  /** Why nothing was judged, when the pass ran but could not answer. */
  error?: string;
}

/**
 * The text the detectors actually scanned, so the excerpt's context re-locates
 * in it. For a write tool that is the payload FIELDS (the same keys the
 * detector's own readWritePayload walks), parsed — the JSON argument has `\n`
 * and `\"` where the excerpt has a newline and a quote, and nothing lines up
 * across that. For anything else the JSON argument is what was scanned.
 */
export function secondOpinionRawText(toolName: string | undefined, toolInput: unknown): string {
  const json = JSON.stringify(toolInput ?? {});
  if (!isWriteTool(toolName) || !toolInput || typeof toolInput !== "object") return json;
  const record = toolInput as Record<string, unknown>;
  const parts: string[] = [];
  for (const key of ["new_string", "content", "new_str", "patch", "text"]) {
    const value = record[key];
    if (typeof value === "string" && value !== "") parts.push(value);
  }
  return parts.length > 0 ? parts.join("\n") : json;
}

/** How much raw context the model is shown around the match. */
export const RAW_WINDOW_CHARS = 600;
const MAX_REASON_CHARS = 200;
const MASK = "[redacted]";

/**
 * Re-locate a finding in the RAW text. The masked excerpt is `…before MASK
 * after…` with `before`/`after` copied verbatim (whitespace-collapsed) from the
 * text, so the longest run of `before` that still occurs in the raw payload
 * finds the spot. Falls back to the key name, then to the head of the payload —
 * a model shown the wrong window answers `unsure` or wrong-but-harmless, since
 * a wrong answer here can only fail to downgrade.
 */
export function rawWindow(raw: string, finding: SecurityFinding, span: number = RAW_WINDOW_CHARS): string {
  const collapsed = raw.replace(/\s+/g, " ");
  const excerpt = finding.excerpt.replace(/^…/, "").replace(/…$/, "");
  const maskAt = excerpt.indexOf(MASK);
  const before = (maskAt >= 0 ? excerpt.slice(0, maskAt) : excerpt).trim();
  const after = maskAt >= 0 ? excerpt.slice(maskAt + MASK.length).replace(/\[redacted[^\]]*\]/g, " ").trim() : "";
  let anchor = -1;
  // Longest suffix of `before` (≥ 12 chars) that appears in the collapsed raw…
  for (let take = before.length; take >= 12 && anchor < 0; take -= 1) {
    anchor = collapsed.indexOf(before.slice(before.length - take));
  }
  // …else the longest prefix of `after`, then the key name.
  for (let take = after.length; take >= 12 && anchor < 0; take -= 1) {
    anchor = collapsed.indexOf(after.slice(0, take));
  }
  if (anchor < 0 && finding.key_name) anchor = collapsed.indexOf(finding.key_name);
  if (anchor < 0) anchor = 0;
  const start = Math.max(0, anchor - Math.floor(span / 3));
  return collapsed.slice(start, start + span);
}

/**
 * The question. Narrow on purpose — a model asked to "review this file" will
 * volunteer opinions; a model asked whether one named value is a literal
 * credential answers the question. The conservative default is stated twice
 * because small models drift toward whichever answer the prompt makes easy.
 */
export function buildSecondOpinionPrompt(
  finding: SecurityFinding,
  window: string,
  toolName?: string,
): Array<{ role: "system" | "user"; content: string }> {
  const what =
    finding.detector === "hardcoded_credential"
      ? `a value assigned to a secret-shaped name${finding.key_name ? ` (\`${finding.key_name}\`)` : ""}`
      : "a high-entropy token no known credential pattern claimed";
  return [
    {
      role: "system",
      content: [
        "You are a second reviewer for a deterministic secret scanner that runs before an AI coding agent's tool call.",
        `The scanner flagged ${what} inside content the agent is about to write or run. You will see the raw text around that spot.`,
        "Decide ONE thing: is the flagged value a LITERAL, LIVE-LOOKING CREDENTIAL (a real API key, password, token, private key or connection secret written out as a literal)?",
        "Answer not_credential ONLY when the text makes it clear: the value is code rather than a literal (a variable, a call, a regex, a type), an obvious placeholder or example (`your-key-here`, `xxx`, `changeme`, documentation samples), a test fixture that is plainly fake, or the name merely describes something about credentials rather than holding one.",
        "Answer credential when it looks like a real secret literal, even a short one. Answer unsure whenever the window does not settle it. A wrong not_credential lets a real key be written down; a wrong credential costs someone a click. Prefer unsure over not_credential.",
        'Reply with ONLY this JSON, nothing else: {"verdict":"credential"|"not_credential"|"unsure","reason":"one short sentence"}',
      ].join(" "),
    },
    {
      role: "user",
      content: JSON.stringify(
        {
          detector: finding.detector,
          ...(finding.key_name ? { key_name: finding.key_name } : {}),
          ...(toolName ? { tool: toolName } : {}),
          raw_window: window,
        },
        null,
        1,
      ),
    },
  ];
}

/**
 * Model output is DATA. Only the three words count, only inside a `verdict`
 * field or as the whole reply; anything else is `unsure`, which changes nothing.
 */
export function parseSecondOpinionVerdict(text: string): { verdict: SecondOpinionVerdict; reason?: string } {
  const trimmed = text.trim();
  const field = /"verdict"\s*:\s*"(credential|not_credential|unsure)"/i.exec(trimmed);
  const word = field?.[1]?.toLowerCase() ?? (/^(credential|not_credential|unsure)\W*$/i.exec(trimmed)?.[1]?.toLowerCase());
  if (word !== "credential" && word !== "not_credential" && word !== "unsure") return { verdict: "unsure" };
  const reasonMatch = /"reason"\s*:\s*"((?:[^"\\]|\\.)*)"/.exec(trimmed);
  const reason = reasonMatch ? reasonMatch[1].replace(/\\"/g, '"').replace(/\s+/g, " ").trim().slice(0, MAX_REASON_CHARS) : undefined;
  return { verdict: word, ...(reason ? { reason } : {}) };
}

export type FetchLike = (input: string, init: RequestInit) => Promise<{ ok: boolean; status: number; text(): Promise<string> }>;

/**
 * One question to the OpenAI-compatible chat endpoint (Ollama, LM Studio and
 * llama.cpp's server all speak it). Any failure — network, HTTP, timeout,
 * shape — is `unsure`.
 */
export async function askLocalModel(
  policy: SecondOpinionPolicy,
  messages: Array<{ role: "system" | "user"; content: string }>,
  fetchImpl: FetchLike = fetch as unknown as FetchLike,
): Promise<{ verdict: SecondOpinionVerdict; reason?: string; error?: string }> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), policy.timeout_ms);
  try {
    const res = await fetchImpl(policy.endpoint, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ model: policy.model, messages, temperature: 0, max_tokens: 80, stream: false }),
      signal: controller.signal,
    });
    if (!res.ok) return { verdict: "unsure", error: `HTTP ${res.status}` };
    const body = JSON.parse(await res.text()) as { choices?: Array<{ message?: { content?: unknown } }> };
    const content = body.choices?.[0]?.message?.content;
    if (typeof content !== "string") return { verdict: "unsure", error: "no content" };
    return parseSecondOpinionVerdict(content);
  } catch (err) {
    const aborted = err instanceof Error && err.name === "AbortError";
    return { verdict: "unsure", error: aborted ? "timeout" : err instanceof Error ? err.message.slice(0, 120) : "failed" };
  } finally {
    clearTimeout(timer);
  }
}

function isShipped(finding: GuardFinding): finding is SecurityFinding {
  return !("mode" in finding && typeof (finding as { mode?: unknown }).mode === "string");
}

/** The findings this pass may judge: shipped, eligible, and still at the
 * confidence that lets them interrupt. Nothing else is ever sent. */
export function eligibleForSecondOpinion(findings: readonly GuardFinding[], drivingDetectors: readonly string[]): SecurityFinding[] {
  return findings.filter(
    (f): f is SecurityFinding =>
      isShipped(f) &&
      SECOND_OPINION_DETECTORS.has(f.detector) &&
      drivingDetectors.includes(f.detector) &&
      f.confidence !== "medium" &&
      f.confidence !== "low",
  );
}

/**
 * Apply verdicts: a `not_credential` lowers THAT finding to medium confidence
 * (in place — the spooled row records what the guard decided on). Everything
 * else is untouched. Returns the detectors downgraded.
 */
export function applySecondOpinion(
  judged: ReadonlyArray<{ finding: SecurityFinding; verdict: SecondOpinionVerdict }>,
): string[] {
  const downgraded: string[] = [];
  for (const { finding, verdict } of judged) {
    if (verdict !== "not_credential") continue;
    finding.confidence = "medium";
    if (!downgraded.includes(finding.detector)) downgraded.push(finding.detector);
  }
  return downgraded;
}

/**
 * The whole pass, as guard.ts calls it: pick the eligible findings behind the
 * interrupt, ask about each (few — a held call rarely has more than one or two),
 * apply, and report. Returns undefined when there was nothing to ask about, so
 * the caller knows whether to re-fold.
 */
/**
 * The whole second-opinion pass must finish inside the shortest hook budget
 * with room for the guard's own start-up, redaction and spool write: 6 s of a
 * 10 s budget.
 */
export const SECOND_OPINION_TOTAL_BUDGET_MS = HOOK_TIMEOUT_FAST_SECONDS * 1000 - 4_000;

export async function secondOpinion(
  findings: readonly GuardFinding[],
  drivingDetectors: readonly string[],
  raw: string,
  policy: SecondOpinionPolicy,
  toolName?: string,
  fetchImpl?: FetchLike,
  nowMs: () => number = Date.now,
): Promise<SecondOpinionTelemetry | undefined> {
  if (!policy.enabled) return undefined;
  const candidates = eligibleForSecondOpinion(findings, drivingDetectors).slice(0, 3);
  if (candidates.length === 0) return undefined;
  const started = nowMs();
  const judged: SecondOpinionJudgement[] = [];
  const results: Array<{ finding: SecurityFinding; verdict: SecondOpinionVerdict }> = [];
  let error: string | undefined;
  for (const finding of candidates) {
    // ONE deadline for the whole pass, not one per question: three questions
    // at the 6 s per-question ceiling was 18 s, past the 10 s hook budget —
    // and a host that kills the hook on an `ask` lets the call run. Whatever
    // is left of the budget bounds the next question; none left, stop asking
    // (an unanswered finding keeps its confidence, so the hold stands).
    const remaining = SECOND_OPINION_TOTAL_BUDGET_MS - (nowMs() - started);
    if (remaining < SECOND_OPINION_TIMEOUT_MIN_MS) break;
    const bounded = { ...policy, timeout_ms: Math.min(policy.timeout_ms, remaining) };
    const answer = await askLocalModel(bounded, buildSecondOpinionPrompt(finding, rawWindow(raw, finding), toolName), fetchImpl);
    if (answer.error && !error) error = answer.error;
    judged.push({
      detector: finding.detector,
      ...(finding.key_name ? { key_name: finding.key_name } : {}),
      verdict: answer.verdict,
      ...(answer.reason ? { reason: answer.reason } : {}),
    });
    results.push({ finding, verdict: answer.verdict });
    // One failure is the endpoint's state, not this finding's: stop asking.
    if (answer.error) break;
  }
  const downgraded = applySecondOpinion(results);
  return {
    model: policy.model,
    latency_ms: Math.max(0, nowMs() - started),
    judged,
    downgraded,
    ...(error ? { error } : {}),
  };
}
