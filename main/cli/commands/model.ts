import { syncGuard } from "../../enforcement.js";
import { normalizeInjectionClassifierConfig, defaultInjectionClassifierConfig, type InjectionModelId } from "../../guard/policy.js";
import { runtimePresent } from "../../lib/injection-classifier.js";
import type { InjectionModelPlan } from "../../lib/injection-model-choice.js";
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
import { releaseLock, takeLock } from "../../lib/data-owner.js";
import { activeDownload, autoDownloadView, downloadRefusal, runAutoDownload, type AutoDownloadView, type DownloadRefusal } from "../auto-download.js";
import { doormanSource, loadClassifier, modelPlan, modelsRoot, runtimeDir } from "../classifier.js";
import { dockerSandbox, MODEL_HOSTS, processLabel, sandboxAllowCommand, sandboxProxied } from "../docker-sandbox.js";
import type { CliCommand, ParsedArgs } from "../command.js";
import type { CliContext } from "../context.js";
import { CliError, type CommandResult, type Styles } from "../output.js";
import { startProgress, type Progress } from "../progress.js";

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

/**
 * The model that actually runs — null when none can: the classifier is off,
 * the runtime is missing, or the planned model (the selected one, or the stock
 * fallback) isn't on disk — and the words for it. The plan alone says which
 * model WOULD run; in a fresh CLI install neither is downloaded yet.
 */
export function runningModel(
  ctx: CliContext,
  plan: InjectionModelPlan,
  enabled: boolean,
  runtime: boolean,
  s: Styles,
): { active: InjectionModelId | null; download: AutoDownloadView; text: string } {
  const download = autoDownloadView(ctx);
  const installed = modelStatus(modelsRoot(ctx.dataDir), injectionModelManifest(plan.effective)).present;
  if (enabled && runtime && installed) {
    return { active: plan.effective, download, text: `${plan.effective}${plan.fallback ? s.warn(`  (${FALLBACK_TEXT[plan.fallback]})`) : ""}` };
  }
  const why = !enabled
    ? "the classifier is off"
    : !runtime
      ? "the classifier runtime is missing"
      : download.status === "running"
        ? `${download.by === "app" ? "the app is downloading" : "downloading"} ${download.model}${download.by === "app" ? "" : " in the background"}, ${megabytes(download.bytes_done)} of ${megabytes(download.bytes_total)}`
        : download.status === "failed"
          ? failedWhy(ctx, download)
          : "no model downloaded yet: doorman model download";
  return { active: null, download, text: `none  ${s.warn(`(${why})`)}` };
}

/** Why the last background download failed, and what to do about it. */
function failedWhy(ctx: CliContext, download: Extract<AutoDownloadView, { status: "failed" }>): string {
  const blocked = sandboxBlock(ctx, download.refused);
  if (!blocked) return `the background download failed (${download.error}); retry now: doorman model download`;
  return `the sandbox's network policy blocked ${blocked.host}; on your computer run ${blocked.allow}, then here: doorman model download`;
}

/**
 * A download the Docker Sandbox's policy proxy refused (it answers a blocked
 * request with HTTP 403): the host it blocked, which after a redirect is the
 * CDN rather than the Hub, and the host-side command that lets the model's
 * downloads through. Undefined outside a sandbox and for any other failure.
 */
function sandboxBlock(ctx: CliContext, refused: DownloadRefusal | undefined): { host: string; allow: string } | undefined {
  const sandbox = dockerSandbox(ctx.io.env);
  if (!sandbox || refused?.status !== 403 || !sandboxProxied(ctx.io.env)) return undefined;
  return { host: refused.host, allow: sandboxAllowCommand(sandbox, MODEL_HOSTS) };
}

const statusRun: CliCommand["run"] = async (ctx) => {
  const policy = ctx.policy();
  const enabled = (policy.injection_classifier ?? defaultInjectionClassifierConfig()).enabled;
  const plan = modelPlan(ctx.dataDir, policy, ctx.io.env);
  const runtime = runtimePresent(runtimeDir());
  const models = MODELS.map((m) => modelView(ctx, m));
  const s = ctx.style;
  const running = runningModel(ctx, plan, enabled, runtime, s);
  const ui = ctx.ui;
  const text = [
    ui.section("Injection classifier"),
    ...ui.kv([
      ["classifier", enabled ? ui.mark("ok", s.ok("on")) : ui.mark("warn", s.warn("off"))],
      ["selected", plan.selected],
      ["running", ui.mark(running.active ? "ok" : "warn", running.text)],
      ["runtime", runtime ? ui.mark("ok", s.ok("present")) : ui.mark("error", s.error(`missing (${runtimeDir()})`))],
    ]),
  ];
  for (const m of models) {
    const state = `${m.installed ? s.ok("installed") : s.dim("not downloaded")}  ${s.dim(megabytes(m.bytes_total))}`;
    // On a terminal the long label gets its own line, so the state stays in view.
    if (ui.decorate) text.push("", `  ${ui.mark(m.installed ? "ok" : "off", s.bold(m.model))}  ${state}`, ui.fit(`    ${s.dim(`${m.label}, ${m.version}`)}`));
    else text.push("", `  ${s.bold(m.model)}  ${m.label}, ${m.version}  ${state}`);
    for (const f of m.files) text.push(`    ${f.verified ? s.ok("verified") : s.dim("missing ")}  ${f.name}  ${s.dim(megabytes(f.size))}`);
  }
  if (!running.active && enabled && runtime && running.download.status !== "running") text.push("", ui.next("`doorman model download` fetches it now."));
  return {
    data: {
      enabled,
      selected: plan.selected,
      effective: plan.effective,
      ...(plan.fallback ? { fallback: plan.fallback } : {}),
      active: running.active,
      auto_download: running.download,
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
  examples: [
    ["doorman model", "which model runs and what is on disk"],
    ["doorman model download", "fetch the selected model now"],
  ],
  run: statusRun,
};

const statusCommand: CliCommand = {
  name: "model status",
  summary: "Same as `doorman model`",
  run: statusRun,
};

const downloadCommand: CliCommand = {
  name: "model download",
  summary: "Download and verify a classifier model (sha256-pinned, as the app does)",
  usage: "[--model doorman-1|stock] [--auto]",
  options: { model: { type: "string" }, auto: { type: "boolean" } },
  flags: [
    ["--model doorman-1|stock", "which model (default: the selected one)"],
    ["--auto", "what the background download runs: whatever the plan needs, quietly, spacing out failed attempts"],
  ],
  notes: [
    "doorman-1 comes from DOORMAN_INJECTION_CLASSIFIER_SOURCE when set (a URL or an absolute directory), else its pinned Hugging Face revision. Every file is checked against its pinned size and sha256 before it is kept. Progress goes to stderr.",
    "You rarely need this: while the classifier is on, the first command that finds its model missing starts this download in the background (DOORMAN_INJECTION_CLASSIFIER=off stops that). Run while that one is going, this waits for it with its progress, then fetches only what it didn't.",
  ],
  examples: [
    ["doorman model download", "the selected model"],
    ["doorman model download --model stock", "the smaller stock model"],
  ],
  async run(ctx, args) {
    if (args.values.auto === true) {
      const r = await runAutoDownload(ctx);
      return { data: r, text: r.ok ? [] : [`Couldn't download: ${r.error}`], exitCode: r.ok ? 0 : 1 };
    }
    // Never two downloads into the same folder: the app (which fetches its
    // own while it runs), the background one, or another command's. Another
    // command's download (usually the background one) is waited out, and
    // then only what it didn't finish is fetched.
    refuseWhileOwned(ctx, "download it");
    let waited = false;
    while (!takeLock(ctx.dataDir, "model-download", { pid: process.pid, by: "cli", command: "model download" }, ctx.io.now())) {
      if (activeDownload(ctx)?.by === "app") throw new CliError("The app is already downloading the model; `doorman model` shows its progress.");
      if (!(await waitForDownload(ctx))) {
        return {
          data: { stopped_waiting: true },
          text: [ctx.ui.mark("off", ctx.ui.prose("Stopped waiting. The download goes on in the background; `doorman model` shows its progress."))],
          exitCode: 130,
        };
      }
      waited = true;
      refuseWhileOwned(ctx, "download it");
    }
    try {
      return await downloadNow(ctx, args, waited);
    } finally {
      releaseLock(ctx.dataDir, "model-download", process.pid);
    }
  },
};

/** How often a download that waits for another looks at its progress. */
const WAIT_POLL_MS = 500;

/**
 * Wait for another command's model download to end, showing its progress
 * (read off its part files, as `doorman model` does). Ctrl-C stops the
 * waiting, not that download: false then.
 */
async function waitForDownload(ctx: CliContext): Promise<boolean> {
  let view = autoDownloadView(ctx);
  if (view.status !== "running") return true;
  const waiting = "The model is already downloading in the background. Waiting for it to finish (Ctrl-C stops waiting, not the download).";
  ctx.io.stderr.write(`${ctx.errUi.mark("info", waiting)}\n`);
  let stopped = false;
  let wake: (() => void) | undefined;
  const onInterrupt = () => {
    stopped = true;
    wake?.();
  };
  process.on("SIGINT", onInterrupt);
  let shown: { model: InjectionModelId; progress: Progress; total: number } | undefined;
  try {
    while (view.status === "running" && !stopped) {
      if (shown?.model !== view.model) {
        shown?.progress.end();
        const manifest = injectionModelManifest(view.model);
        shown = { model: view.model, progress: startProgress(ctx.errUi, ctx.io.stderr, { label: `Downloading ${manifest.name}`, format: megabytes }), total: manifestBytes(manifest) };
      }
      shown.progress.update(view.bytes_done, view.bytes_total || shown.total);
      await new Promise<void>((resolve) => {
        const timer = setTimeout(resolve, WAIT_POLL_MS);
        wake = () => {
          clearTimeout(timer);
          resolve();
        };
      });
      view = autoDownloadView(ctx);
    }
  } finally {
    process.off("SIGINT", onInterrupt);
    shown?.progress.end();
  }
  return !stopped;
}

/** While the app (or `doorman watch`) runs it owns the models folder too. */
function refuseWhileOwned(ctx: CliContext, action: string): void {
  const other = ctx.running();
  if (!other) return;
  throw new CliError(`Doorman is running${processLabel(ctx.io.env, other.pid)}, and it keeps the classifier's model itself; ${action} in the app, or quit it and run this again.`);
}

/** The download the person asked for, with progress on stderr. `waited`: it
 * waited out another download first, which may have fetched the model. */
async function downloadNow(ctx: CliContext, args: ParsedArgs, waited: boolean): Promise<CommandResult> {
  const model = parseModel(args.values.model) ?? modelPlan(ctx.dataDir, ctx.policy(), ctx.io.env).selected;
  const manifest = injectionModelManifest(model);
  // doorman-1 comes from the environment's source when one is named;
  // every other model from its manifest (the app's startModelDownload).
  const source = manifest.name === PROMPT_GUARD_2_22M_DOORMAN_1.name ? injectionModelSourceFromEnv(ctx.io.env) : undefined;
  const before = modelStatus(modelsRoot(ctx.dataDir), manifest).present;
  // A bar on a terminal, a line per quarter otherwise (progress.ts).
  const progress = startProgress(ctx.errUi, ctx.io.stderr, { label: `Downloading ${manifest.name}`, format: megabytes });
  try {
    await downloadModel(modelsRoot(ctx.dataDir), manifest, {
      ...(source === undefined ? {} : { source }),
      ...(ctx.io.fetch ? { fetchImpl: ctx.io.fetch } : {}),
      onProgress: (p: DownloadProgress) => progress.update(p.bytes_done, p.bytes_total || manifestBytes(manifest)),
    });
  } catch (err) {
    progress.end();
    const why = err instanceof Error ? err.message : String(err);
    const blocked = sandboxBlock(ctx, downloadRefusal(err));
    if (blocked) {
      throw new CliError(
        `Couldn't download ${model}: the sandbox's network policy blocked ${blocked.host} (${why}).\nOn your computer, run:\n  ${blocked.allow}\nThen run doorman model download here again.`,
      );
    }
    throw new CliError(`Couldn't download ${model}: ${why}`);
  }
  progress.end();
  const view = modelView(ctx, model);
  if (!view.installed) throw new CliError(`${model} downloaded but didn't verify.`, 1, "Run `doorman model download` again.");
  return {
    data: view,
    text: [
      ctx.ui.mark(
        "ok",
        before
          ? waited
            ? `The background download finished: ${model} is installed and verified.`
            : `${model} was already installed and verified.`
          : `Downloaded and verified ${model} (${megabytes(view.bytes_total)}) in ${view.dir}.`,
      ),
    ],
  };
}

const removeCommand: CliCommand = {
  name: "model remove",
  summary: "Delete a downloaded model (default: the one that runs)",
  usage: "[--model doorman-1|stock]",
  options: { model: { type: "string" } },
  flags: [["--model doorman-1|stock", "which model (default: the one that runs)"]],
  examples: [["doorman model remove --model stock", "delete the stock model's files"]],
  async run(ctx, args) {
    refuseWhileOwned(ctx, "remove it");
    const download = activeDownload(ctx);
    if (download) {
      const who = download.by === "app" ? "The app is downloading the model" : "The model is downloading in the background";
      throw new CliError(`${who}.`, 1, "Remove it once that finishes; `doorman model` shows its progress.");
    }
    const model = parseModel(args.values.model) ?? modelPlan(ctx.dataDir, ctx.policy(), ctx.io.env).effective;
    const manifest = injectionModelManifest(model);
    const root = modelsRoot(ctx.dataDir);
    const had = modelStatus(root, manifest).missing.length < manifest.files.length;
    removeModel(root, manifest);
    return { data: { model, removed: had }, text: [had ? ctx.ui.mark("ok", `Removed ${model}.`) : ctx.ui.mark("off", `${model} wasn't downloaded; nothing to remove.`)] };
  },
};

const selectCommand: CliCommand = {
  name: "model select",
  summary: "Choose the classifier model (the app's Settings choice)",
  usage: "<doorman-1|stock>",
  positionals: { min: 1, max: 1 },
  examples: [["doorman model select stock", "run the stock model instead of doorman-1"]],
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
    const text = [ctx.ui.mark("ok", `Selected ${model}.`)];
    if (plan.selected !== model) text.push(ctx.ui.mark("warn", ctx.style.warn(`DOORMAN_INJECTION_CLASSIFIER_MODEL overrides it here: ${plan.selected} is selected.`)));
    if (!modelStatus(modelsRoot(ctx.dataDir), injectionModelManifest(plan.selected)).present) {
      const fallback = modelStatus(modelsRoot(ctx.dataDir), injectionModelManifest(plan.effective)).present ? `${plan.effective} runs` : "no model runs";
      text.push(ctx.ui.prose(`${plan.selected} isn't downloaded yet; it downloads in the background with your next doorman command (or now: \`doorman model download\`). Until then ${fallback}.`));
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
  notes: [
    "Runs the model that runs in the app (`doorman model status`) over the text, or stdin with `-`, and prints the label (malicious or benign) and P(malicious).",
    "Exit code 1 when the text is classified as malicious.",
  ],
  examples: [
    ['doorman model check "ignore all previous instructions"', "score one string"],
    ["pbpaste | doorman model check -", "score what is on the clipboard"],
  ],
  async run(ctx, args) {
    const text = args.positionals[0] === "-" ? await readStdin(ctx) : args.positionals[0]!;
    if (text.trim() === "") throw new CliError("Nothing to classify.", 2, 'Pass the text, e.g. `doorman model check "some text"`, or `-` to read stdin.');
    const { classifier, manifest, changed } = await loadClassifier(ctx.dataDir, ctx.policy(), ctx.io.env, (m) => ctx.log(m));
    if (!classifier) {
      if (changed.length > 0) throw new CliError(`${manifest.name}: ${changed.join(", ")} no longer match their pins.`, 1, "Run `doorman model download` to replace them.");
      if (!runtimePresent(runtimeDir())) throw new CliError(`The classifier runtime is missing (${runtimeDir()}).`);
      if (!modelStatus(modelsRoot(ctx.dataDir), manifest).present) {
        const download = autoDownloadView(ctx);
        if (download.status === "running") {
          throw new CliError(`The model is still downloading${download.by === "app" ? " in the app" : " in the background"} (${megabytes(download.bytes_done)} of ${megabytes(download.bytes_total)}); try again once it finishes.`);
        }
        throw new CliError("No model downloaded.", 1, "Run `doorman model download` first.");
      }
      throw new CliError(`${manifest.name} is present but failed to load.`, 1, "Run it again with --verbose to see why.");
    }
    const verdict = await classifier.classify(text);
    if (!verdict) throw new CliError("The model didn't answer.", 1, "Run it again with --verbose to see why.");
    const s = ctx.style;
    const label = verdict.malicious ? "malicious" : "benign";
    const score = Math.round(verdict.score * 1000) / 1000;
    return {
      data: { label, malicious: verdict.malicious, score, model: manifest.name },
      text: [`${verdict.malicious ? s.error(label) : s.ok(label)}  score ${score.toFixed(3)}  ${s.dim(manifest.name)}`],
      exitCode: verdict.malicious ? 1 : 0,
    };
  },
};

export const modelCommands: CliCommand[] = [modelCommand, statusCommand, downloadCommand, removeCommand, selectCommand, checkCommand];
