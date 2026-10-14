/**
 * The environment is the only knob left for the injection classifier and the
 * guard's credential second opinion (Settings dropped them 2026-09-05). These
 * pin the contract: unset means no opinion, values ride the same normalizers
 * the switches used, and the loopback-only rule still holds.
 */
import { describe, expect, it } from "vitest";
import { applyPolicyEnv, policyEnvActive } from "../main/lib/policy-env.js";
import {
  INJECTION_SUPPRESS_BELOW_MAX,
  SECOND_OPINION_TIMEOUT_MAX_MS,
  defaultInjectionClassifierConfig,
  defaultSecondOpinion,
} from "../main/guard/policy.js";

const base = () => ({
  injection_classifier: defaultInjectionClassifierConfig(),
  second_opinion: defaultSecondOpinion(),
});

describe("applyPolicyEnv", () => {
  it("with nothing set, returns the policy untouched (same reference)", () => {
    const policy = base();
    expect(applyPolicyEnv(policy, {})).toBe(policy);
    expect(policyEnvActive({})).toBe(false);
  });

  it("the classifier stays on by default and the environment can turn it off", () => {
    expect(applyPolicyEnv(base(), {}).injection_classifier?.enabled).toBe(true);
    for (const off of ["off", "0", "false", "no", " OFF "]) {
      expect(applyPolicyEnv(base(), { DOORMAN_INJECTION_CLASSIFIER: off }).injection_classifier?.enabled).toBe(false);
    }
    expect(applyPolicyEnv(base(), { DOORMAN_INJECTION_CLASSIFIER: "on" }).injection_classifier?.enabled).toBe(true);
    // Junk is no opinion, not a reset.
    expect(applyPolicyEnv(base(), { DOORMAN_INJECTION_CLASSIFIER: "maybe" }).injection_classifier?.enabled).toBe(true);
  });

  it("fills in the block when the stored prefs never had one", () => {
    const out = applyPolicyEnv({} as ReturnType<typeof base>, { DOORMAN_SECOND_OPINION: "on" });
    expect(out.second_opinion).toMatchObject({ enabled: true, endpoint: defaultSecondOpinion().endpoint });
    expect(out.injection_classifier).toBeUndefined();
  });

  it("the threshold rides the policy clamp", () => {
    expect(applyPolicyEnv(base(), { DOORMAN_INJECTION_CLASSIFIER_SUPPRESS_BELOW: "0.35" }).injection_classifier?.suppress_below).toBe(0.35);
    expect(applyPolicyEnv(base(), { DOORMAN_INJECTION_CLASSIFIER_SUPPRESS_BELOW: "9" }).injection_classifier?.suppress_below).toBe(INJECTION_SUPPRESS_BELOW_MAX);
    expect(applyPolicyEnv(base(), { DOORMAN_INJECTION_CLASSIFIER_SUPPRESS_BELOW: "lots" }).injection_classifier?.suppress_below).toBe(0.2);
  });

  it("the second opinion turns on with endpoint, model and budget from the environment", () => {
    const out = applyPolicyEnv(base(), {
      DOORMAN_SECOND_OPINION: "1",
      DOORMAN_SECOND_OPINION_ENDPOINT: "http://localhost:1234/v1/chat/completions",
      DOORMAN_SECOND_OPINION_MODEL: "qwen2.5:3b",
      DOORMAN_SECOND_OPINION_TIMEOUT_MS: "60000",
    });
    expect(out.second_opinion).toEqual({
      enabled: true,
      endpoint: "http://localhost:1234/v1/chat/completions",
      model: "qwen2.5:3b",
      timeout_ms: SECOND_OPINION_TIMEOUT_MAX_MS,
    });
  });

  it("a non-loopback endpoint from the environment is stored but refused, exactly as the switch was", () => {
    const out = applyPolicyEnv(base(), {
      DOORMAN_SECOND_OPINION: "on",
      DOORMAN_SECOND_OPINION_ENDPOINT: "http://models.example.com/v1/chat/completions",
    });
    expect(out.second_opinion?.enabled).toBe(false);
    expect(out.second_opinion?.endpoint).toBe("http://models.example.com/v1/chat/completions");
  });

  it("lays over a stored choice rather than replacing it wholesale", () => {
    const stored = { ...base(), second_opinion: { ...defaultSecondOpinion(), enabled: true, model: "mine:1b" } };
    const out = applyPolicyEnv(stored, { DOORMAN_SECOND_OPINION_TIMEOUT_MS: "1500" });
    expect(out.second_opinion).toMatchObject({ enabled: true, model: "mine:1b", timeout_ms: 1500 });
    // The other block is the same object when nothing named it.
    expect(out.injection_classifier).toBe(stored.injection_classifier);
  });
});
