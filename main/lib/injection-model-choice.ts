/**
 * Which injection model the app RUNS, given the one the person (or the
 * environment) SELECTED.
 *
 * The fine-tuned `doorman-1` is the default selection, but until it is
 * published (lib/model-sources.ts) or an operator names a source, it cannot
 * be downloaded. Selecting it must never leave someone with NO model, so the
 * app runs the stock Prompt Guard 2 model in its place — its download, its
 * windowing, its threshold — and switches to doorman-1 by itself the moment
 * doorman-1 is installed. Everything that names "the model" (the classifier
 * instance, the verdict cache, the probe, Settings) reads the EFFECTIVE one.
 *
 * Pure: what is installed and where doorman-1 would come from are passed in.
 */

import type { InjectionModelId } from "../guard/policy.js";

/** Why the effective model is not the selected one. */
export type InjectionModelFallback =
  /** doorman-1 has no download location yet (empty URL, no env source). */
  | "unpublished"
  /** doorman-1's download or verification failed. */
  | "download_failed"
  /** doorman-1 is on its way (or about to be fetched). */
  | "not_installed";

export interface InjectionModelPlan {
  selected: InjectionModelId;
  effective: InjectionModelId;
  fallback?: InjectionModelFallback;
}

export interface InjectionModelPlanInput {
  selected: InjectionModelId;
  /** Every pinned file of the model is installed and verified. */
  installed: (model: InjectionModelId) => boolean;
  /** Where doorman-1 would be fetched from; undefined = nowhere yet. */
  doormanSource: string | undefined;
  /** The last doorman-1 download failure, if the latest attempt failed. */
  doormanError?: string;
}

export function planInjectionModel(input: InjectionModelPlanInput): InjectionModelPlan {
  if (input.selected === "stock" || input.installed("doorman-1")) {
    return { selected: input.selected, effective: input.selected };
  }
  const fallback: InjectionModelFallback =
    input.doormanSource === undefined ? "unpublished" : input.doormanError !== undefined ? "download_failed" : "not_installed";
  return { selected: input.selected, effective: "stock", fallback };
}

/** Where doorman-1 comes from: the environment's source wins, else the
 * manifest's base URL (lib/model-sources.ts); empty = nowhere. */
export function doormanModelSource(envSource: string | undefined, baseUrl: string): string | undefined {
  return envSource ?? (baseUrl === "" ? undefined : baseUrl);
}

/** What the download orchestration needs from the app — injected for tests. */
export interface InjectionModelFetchDeps {
  /** The plan as things stand NOW (re-read after each download). */
  plan(): InjectionModelPlan;
  doormanSource(): string | undefined;
  stockInstalled(): boolean;
  /** Download and verify one model; never throws. */
  download(model: InjectionModelId): Promise<{ ok: boolean; error?: string }>;
}

/** Whether anything the plan needs is still missing and could be fetched. */
export function injectionModelsMissing(deps: Pick<InjectionModelFetchDeps, "plan" | "doormanSource" | "stockInstalled">): boolean {
  const plan = deps.plan();
  if (plan.effective === "doorman-1") return false;
  if (plan.selected === "doorman-1" && deps.doormanSource() !== undefined) return true;
  return !deps.stockInstalled();
}

/**
 * Bring the models the plan needs onto disk, in order: doorman-1 first when it
 * is selected, missing and has a source; then — if doorman-1 is still not the
 * model that runs (no source, or its download or verification failed) — the
 * stock model it falls back to. Resolves whether nothing failed.
 */
export async function fetchInjectionModels(deps: InjectionModelFetchDeps): Promise<{ ok: boolean; error?: string; fetched: InjectionModelId[] }> {
  const fetched: InjectionModelId[] = [];
  let error: string | undefined;
  const before = deps.plan();
  if (before.selected === "doorman-1" && before.effective === "stock" && deps.doormanSource() !== undefined) {
    fetched.push("doorman-1");
    const r = await deps.download("doorman-1");
    if (!r.ok) error = `doorman-1: ${r.error ?? "download failed"}`;
  }
  if (deps.plan().effective === "stock" && !deps.stockInstalled()) {
    fetched.push("stock");
    const r = await deps.download("stock");
    if (!r.ok) error = error ?? `stock: ${r.error ?? "download failed"}`;
  }
  return error === undefined ? { ok: true, fetched } : { ok: false, error, fetched };
}
