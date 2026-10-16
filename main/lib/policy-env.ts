/**
 * Environment overrides for the model-assisted rules — the ONLY control surface
 * for the injection classifier and the guard's credential second opinion now
 * that Settings no longer shows them (2026-09-05). Both keep working on their
 * defaults (classifier on, second opinion off) and anyone who needs a knob sets
 * it in the environment the app is launched from:
 *
 *   DOORMAN_INJECTION_CLASSIFIER=off              turn the classifier off (`on` turns it on)
 *   DOORMAN_INJECTION_CLASSIFIER_SUPPRESS_BELOW=0.35   the overrule threshold, clamped by the policy
 *   DOORMAN_SECOND_OPINION=on                    ask a local model before a credential hold
 *   DOORMAN_SECOND_OPINION_ENDPOINT=http://127.0.0.1:1234/v1/chat/completions
 *   DOORMAN_SECOND_OPINION_MODEL=qwen2.5:3b
 *   DOORMAN_SECOND_OPINION_TIMEOUT_MS=6000
 *   DOORMAN_INJECTION_CLASSIFIER_MODEL=stock      which model re-reads the hit (`doorman-1` = default); pins the Settings choice
 *   DOORMAN_INJECTION_CLASSIFIER_SOURCE=/path/to/package   where doorman-1's files come from (beats lib/model-sources.ts)
 *
 * A Finder launch inherits nothing from a shell, so these reach a packaged app
 * via `launchctl setenv` or an `open` from a terminal. Values are laid over the
 * stored prefs (an old install that toggled the switch while it existed keeps
 * that choice unless the environment says otherwise) and pass through the same
 * normalizers Settings used, so the clamps and the loopback-only rule hold.
 * Unset or unparseable means "no opinion", never a reset.
 */

import {
  defaultInjectionClassifierConfig,
  defaultSecondOpinion,
  normalizeInjectionClassifierConfig,
  normalizeSecondOpinion,
  type GuardPolicy,
  type InjectionModelId,
} from "../guard/policy.js";

export const POLICY_ENV_VARS = [
  "DOORMAN_INJECTION_CLASSIFIER",
  "DOORMAN_INJECTION_CLASSIFIER_SUPPRESS_BELOW",
  "DOORMAN_SECOND_OPINION",
  "DOORMAN_SECOND_OPINION_ENDPOINT",
  "DOORMAN_SECOND_OPINION_MODEL",
  "DOORMAN_SECOND_OPINION_TIMEOUT_MS",
] as const;

/**
 * The injection-model choice and the fine-tuned model's download source. Not
 * in POLICY_ENV_VARS: that list is what makes the on/off switch read-only
 * ("set by the environment"), and choosing the model does not decide whether
 * the classifier is on. The model choice is laid over the prefs by
 * applyPolicyEnv like every other classifier knob and makes the Settings
 * model control read-only while set (injectionModelFromEnv); `stock` and
 * `doorman-1` parse, anything else is no opinion.
 */
export const INJECTION_MODEL_ENV = "DOORMAN_INJECTION_CLASSIFIER_MODEL";
export const INJECTION_MODEL_SOURCE_ENV = "DOORMAN_INJECTION_CLASSIFIER_SOURCE";

/** The model the environment pins, or undefined when it has no opinion. */
export function injectionModelFromEnv(env: NodeJS.ProcessEnv = process.env): InjectionModelId | undefined {
  const raw = str(env[INJECTION_MODEL_ENV])?.toLowerCase();
  return raw === "stock" || raw === "doorman-1" ? raw : undefined;
}

/**
 * Where doorman-1 is fetched from when the environment says so, overriding
 * `DOORMAN_MODEL_BASE_URL` (lib/model-sources.ts) — an http(s) URL prefix
 * the file names are appended to, or a
 * local directory (absolute path or file:// URL) holding the package. Every
 * file is verified against the manifest's size + sha256 pins either way
 * (lib/model-assets.ts), so the source is a location, never a trust decision.
 */
export function injectionModelSourceFromEnv(env: NodeJS.ProcessEnv = process.env): string | undefined {
  return str(env[INJECTION_MODEL_SOURCE_ENV]);
}

function flag(value: string | undefined): boolean | undefined {
  if (value === undefined) return undefined;
  const v = value.trim().toLowerCase();
  if (["1", "on", "true", "yes"].includes(v)) return true;
  if (["0", "off", "false", "no"].includes(v)) return false;
  return undefined;
}

function num(value: string | undefined): number | undefined {
  if (value === undefined || value.trim() === "") return undefined;
  const n = Number(value);
  return Number.isFinite(n) ? n : undefined;
}

function str(value: string | undefined): string | undefined {
  if (value === undefined || value.trim() === "") return undefined;
  return value.trim();
}

/** True when at least one of the variables is set to something — what a status
 * line can use to say the environment, not the person, chose. */
export function policyEnvActive(env: NodeJS.ProcessEnv = process.env): boolean {
  return POLICY_ENV_VARS.some((k) => str(env[k]) !== undefined);
}

export function applyPolicyEnv<P extends Pick<GuardPolicy, "injection_classifier" | "second_opinion">>(
  policy: P,
  env: NodeJS.ProcessEnv = process.env,
): P {
  const icEnabled = flag(env.DOORMAN_INJECTION_CLASSIFIER);
  const icBelow = num(env.DOORMAN_INJECTION_CLASSIFIER_SUPPRESS_BELOW);
  const icModel = injectionModelFromEnv(env);
  const soEnabled = flag(env.DOORMAN_SECOND_OPINION);
  const soEndpoint = str(env.DOORMAN_SECOND_OPINION_ENDPOINT);
  const soModel = str(env.DOORMAN_SECOND_OPINION_MODEL);
  const soTimeout = num(env.DOORMAN_SECOND_OPINION_TIMEOUT_MS);

  let out: P = policy;
  if (icEnabled !== undefined || icBelow !== undefined || icModel !== undefined) {
    const current = policy.injection_classifier ?? defaultInjectionClassifierConfig();
    out = {
      ...out,
      injection_classifier: normalizeInjectionClassifierConfig({
        ...current,
        ...(icEnabled !== undefined ? { enabled: icEnabled } : {}),
        ...(icBelow !== undefined ? { suppress_below: icBelow } : {}),
        ...(icModel !== undefined ? { model: icModel } : {}),
      }),
    };
  }
  if (soEnabled !== undefined || soEndpoint !== undefined || soModel !== undefined || soTimeout !== undefined) {
    const current = policy.second_opinion ?? defaultSecondOpinion();
    out = {
      ...out,
      second_opinion: normalizeSecondOpinion({
        ...current,
        ...(soEnabled !== undefined ? { enabled: soEnabled } : {}),
        ...(soEndpoint !== undefined ? { endpoint: soEndpoint } : {}),
        ...(soModel !== undefined ? { model: soModel } : {}),
        ...(soTimeout !== undefined ? { timeout_ms: soTimeout } : {}),
      }),
    };
  }
  return out;
}
