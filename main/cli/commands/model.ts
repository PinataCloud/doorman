import { syncGuard } from "../../enforcement.js";
import { normalizeInjectionClassifierConfig, defaultInjectionClassifierConfig, type InjectionModelId } from "../../guard/policy.js";
import { runtimePresent } from "../../lib/injection-classifier.js";
import {
  downloadModel,
  injectionModelManifest,
  manifestBytes,
  modelDir,
  modelStatus,
  removeModel,
  PROMPT_GUARD_2_22M_DOORMAN_1,
  type DownloadProgress,
  type ModelManifest,
} from "../../lib/model-assets.js";
import { injectionModelSourceFromEnv } from "../../lib/policy-env.js";
import { doormanSource, loadClassifier, modelPlan, modelsRoot, runtimeDir } from "../classifier.js";
import type { CliCommand } from "../command.js";
import type { CliContext } from "../context.js";
import { CliError } from "../output.js";

const MODELS: readonly InjectionModelId[] = ["doorman-1", "stock"];

function parseModel(raw: unknown): InjectionModelId | undefined {
  if (raw === undefined) return undefined;
  if (raw === "doorman-1" || raw === "stock") return raw;
  throw new CliError(`Unknown model "${String(raw)}". Models: ${MODELS.join(", ")}.`, 2);
}

function megabytes(bytes: number): string {
  if (bytes < 1e3) return `${bytes} B`;
  if (bytes < 1e6) return `${(bytes / 1e3).toFixed(1)} KB`;
  return `${(bytes / 1e6).toFixed(1)} MB`;
}

function modelView(ctx: CliContext, model: InjectionModelId) {
  const manifest = injectionModelManifest(model);
  const status = modelStatus(modelsRoot(ctx.dataDir), manifest);
  return {
    model,
    name: manifest.name,
    label: manifest.label,
    version: manifest.version,
    dir: modelDir(modelsRoot(ctx.dataDir), manifest),
    installed: status.present,
    bytes_total: manifestBytes(manifest),
    files: manifest.files.map((f) => ({ name: f.name, size: f.size, verified: !status.missing.includes(f.name) })),
  };
}

const FALLBACK_TEXT: Record<string, string> = {
  unpublished: "doorman-1 has no download location (set DOORMAN_INJECTION_CLASSIFIER_SOURCE)",
  download_failed: "doorman-1's download failed",
  not_installed: "doorman-1 isn't downloaded yet: doorman model download",
};

const statusRun: CliCommand["run"] = async (ctx) => {
  const policy = ctx.policy();
  const enabled = (policy.injection_classifier ?? defaultInjectionClassifierConfig()).enabled;
  const plan = modelPlan(ctx.dataDir, policy, ctx.io.env);
  const runtime = runtimePresent(runtimeDir());
  const models = MODELS.map((m) => modelView(ctx, m));
  const s = ctx.style;
  const text = [
    `${s.bold("Injection classifier")}  ${enabled ? s.green("on") : s.yellow("off")}`,
    `  selected  ${plan.selected}`,
    `  running   ${plan.effective}${plan.fallback ? s.yellow(`  (${FALLBACK_TEXT[plan.fallback]})`) : ""}`,
    `  runtime   ${runtime ? s.green("present") : s.red(`missing (${runtimeDir()})`)}`,
  ];
  for (const m of models) {
    text.push("", `  ${s.bold(m.model)}  ${m.label}, ${m.version}  ${m.installed ? s.green("installed") : s.dim("not downloaded")}  ${s.dim(megabytes(m.bytes_total))}`);
    for (const f of m.files) text.push(`    ${f.verified ? s.green("verified") : s.dim("missing ")}  ${f.name}  ${s.dim(megabytes(f.size))}`);
  }
  return {
    data: {
      enabled,
      selected: plan.selected,
      effective: plan.effective,
      ...(plan.fallback ? { fallback: plan.fallback } : {}),
      runtime_present: runtime,
      doorman_source: doormanSource(ctx.io.env) ?? null,
      models,
    },
    text,
  };
};

const modelCommand: CliCommand = {
  name: "model",
  summary: "The injection classifier: which model runs, and what is downloaded",
  run: statusRun,
};

const statusCommand: CliCommand = {
  name: "model status",
  summary: "Same as `doorman model`",
  run: statusRun,
};

/** One progress line on stderr: rewritten in place on a terminal, a line per
 * quarter otherwise (so logs stay short). */
function progressReporter(ctx: CliContext, manifest: ModelManifest): { update(p: DownloadProgress): void; done(): void } {
  const stderr = ctx.io.stderr as NodeJS.WritableStream & { isTTY?: boolean };
  const tty = stderr.isTTY === true;
  let lastAt = 0;
  let lastQuarter = -1;
  let drawn = false;
  return {
    update(p) {
      const total = p.bytes_total || manifestBytes(manifest);
      const pct = total > 0 ? Math.floor((p.bytes_done / total) * 100) : 0;
      const line = `Downloading ${manifest.name}: ${megabytes(p.bytes_done)} of ${megabytes(total)} (${pct}%)`;
      if (tty) {
        const now = Date.now();
        if (now - lastAt < 200 && p.bytes_done < total) return;
        lastAt = now;
        stderr.write(`\r${line}\u001b[K`);
        drawn = true;
      } else if (Math.floor(pct / 25) > lastQuarter) {
        lastQuarter = Math.floor(pct / 25);
        stderr.write(`${line}\n`);
      }
    },
    done() {
      if (drawn) stderr.write("\n");
    },
  };
}

const downloadCommand: CliCommand = {
  name: "model download",
  summary: "Download and verify a classifier model (sha256-pinned, as the app does)",
  usage: "[--model doorman-1|stock]",
  options: { model: { type: "string" } },
  details: [
    "Default: the selected model. doorman-1 comes from DOORMAN_INJECTION_CLASSIFIER_SOURCE when set",
    "(a URL or an absolute directory), else its pinned Hugging Face revision. Every file is checked",
    "against its pinned size and sha256 before it is kept. Progress goes to stderr.",
  ],
  async run(ctx, args) {
    const model = parseModel(args.values.model) ?? modelPlan(ctx.dataDir, ctx.policy(), ctx.io.env).selected;
    const manifest = injectionModelManifest(model);
    // doorman-1 comes from the environment's source when one is named;
    // every other model from its manifest (the app's startModelDownload).
    const source = manifest.name === PROMPT_GUARD_2_22M_DOORMAN_1.name ? injectionModelSourceFromEnv(ctx.io.env) : undefined;
    const before = modelStatus(modelsRoot(ctx.dataDir), manifest).present;
    const progress = progressReporter(ctx, manifest);
    try {
      await downloadModel(modelsRoot(ctx.dataDir), manifest, { ...(source === undefined ? {} : { source }), onProgress: (p) => progress.update(p) });
    } catch (err) {
      progress.done();
      throw new CliError(`Couldn't download ${model}: ${err instanceof Error ? err.message : String(err)}`);
    }
    progress.done();
    const view = modelView(ctx, model);
    if (!view.installed) throw new CliError(`${model} downloaded but didn't verify; run it again.`);
    return {
      data: view,
      text: [before ? `${model} was already installed and verified.` : `Downloaded and verified ${model} (${megabytes(view.bytes_total)}) in ${view.dir}.`],
    };
  },
};

const removeCommand: CliCommand = {
  name: "model remove",
  summary: "Delete a downloaded model (default: the one that runs)",
  usage: "[--model doorman-1|stock]",
  options: { model: { type: "string" } },
  async run(ctx, args) {
    const model = parseModel(args.values.model) ?? modelPlan(ctx.dataDir, ctx.policy(), ctx.io.env).effective;
    const manifest = injectionModelManifest(model);
    const root = modelsRoot(ctx.dataDir);
    const had = modelStatus(root, manifest).missing.length < manifest.files.length;
    removeModel(root, manifest);
    return { data: { model, removed: had }, text: [had ? `Removed ${model}.` : `${model} wasn't downloaded; nothing to remove.`] };
  },
};

const selectCommand: CliCommand = {
  name: "model select",
  summary: "Choose the classifier model (the app's Settings choice)",
  usage: "<doorman-1|stock>",
  positionals: { min: 1, max: 1 },
  async run(ctx, args) {
    const model = parseModel(args.positionals[0])!;
    ctx.requireWritable("Choose the model");
    // The app's radar:injection-classifier handler: patch the STORED policy
    // (not the env-folded live one), then follow it into the guard's policy.json.
    const prefs = ctx.prefs();
    const current = prefs.policy.injection_classifier ?? defaultInjectionClassifierConfig();
    const injection_classifier = normalizeInjectionClassifierConfig({ ...current, model });
    ctx.setPrefs({ policy: { ...prefs.policy, injection_classifier } });
    const synced = syncGuard(ctx.dataDir, ctx.policy());
    if (!synced.ok) throw new CliError(`Saved, but the guard's policy didn't update: ${synced.error}`);
    const plan = modelPlan(ctx.dataDir, ctx.policy(), ctx.io.env);
    const text = [`Selected ${model}.`];
    if (plan.selected !== model) text.push(ctx.style.yellow(`DOORMAN_INJECTION_CLASSIFIER_MODEL overrides it here: ${plan.selected} is selected.`));
    if (!modelStatus(modelsRoot(ctx.dataDir), injectionModelManifest(plan.selected)).present) {
      text.push(`${plan.selected} isn't downloaded yet: doorman model download. Until then ${plan.effective} runs.`);
    }
    return { data: { selected: plan.selected, effective: plan.effective, injection_classifier }, text };
  },
};

async function readStdin(ctx: CliContext): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of ctx.io.stdin) chunks.push(typeof chunk === "string" ? Buffer.from(chunk) : (chunk as Buffer));
  return Buffer.concat(chunks).toString("utf8");
}

const checkCommand: CliCommand = {
  name: "model check",
  summary: "Score text with the injection classifier",
  usage: "<text | ->",
  positionals: { min: 1, max: 1 },
  details: [
    "Runs the model that runs in the app (doorman model status) over the text, or stdin with `-`.",
    "Prints the label (malicious or benign) and P(malicious).",
    "Exit code 1 when the text is classified as malicious.",
  ],
  async run(ctx, args) {
    const text = args.positionals[0] === "-" ? await readStdin(ctx) : args.positionals[0]!;
    if (text.trim() === "") throw new CliError("Nothing to classify.");
    const { classifier, manifest, changed } = await loadClassifier(ctx.dataDir, ctx.policy(), ctx.io.env, (m) => ctx.log(m));
    if (!classifier) {
      if (changed.length > 0) throw new CliError(`${manifest.name}: ${changed.join(", ")} no longer match their pins. Run \`doorman model download\` to replace them.`);
      if (!runtimePresent(runtimeDir())) throw new CliError(`The classifier runtime is missing (${runtimeDir()}).`);
      if (!modelStatus(modelsRoot(ctx.dataDir), manifest).present) throw new CliError(`No model downloaded. Run \`doorman model download\` first.`);
      throw new CliError(`${manifest.name} is present but failed to load; run with --verbose to see why.`);
    }
    const verdict = await classifier.classify(text);
    if (!verdict) throw new CliError("The model didn't answer; run with --verbose to see why.");
    const s = ctx.style;
    const label = verdict.malicious ? "malicious" : "benign";
    const score = Math.round(verdict.score * 1000) / 1000;
    return {
      data: { label, malicious: verdict.malicious, score, model: manifest.name },
      text: [`${verdict.malicious ? s.red(label) : s.green(label)}  score ${score.toFixed(3)}  ${s.dim(manifest.name)}`],
      exitCode: verdict.malicious ? 1 : 0,
    };
  },
};

export const modelCommands: CliCommand[] = [modelCommand, statusCommand, downloadCommand, removeCommand, selectCommand, checkCommand];
