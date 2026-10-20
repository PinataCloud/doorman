import { basename, dirname, join } from "node:path";
import {
  importsDir,
  sanitizeSandboxBundle,
  validSandboxName,
  validateSandboxBundle,
  writeDropFile,
  type ImportOutcome,
  type SandboxBundle,
  type SandboxImportResult,
} from "../../lib/sandbox-import.js";
import type { CliCommand } from "../command.js";
import type { CliContext } from "../context.js";
import { CliError } from "../output.js";
import { firstLine, installKitHint, listSandboxes, sbxRemove, sbxRun, updateDoormanHint, type HostSandbox } from "../sbx-host.js";
import { plural } from "../ui.js";
import { withEngine } from "./data-shared.js";

/** How long one sandbox may take to scan its transcripts and answer. */
const PULL_TIMEOUT_MS = 5 * 60_000;
const REMOVE_TIMEOUT_MS = 2 * 60_000;

/** What `doorman export bundle --scan` inside a sandbox came back as. */
type Pulled =
  | { sandbox: string; ok: true; file: string; sightings: number; sessions: number }
  | { sandbox: string; ok: false; problem: string };

/**
 * Read one sandbox: `doorman export bundle --scan` through `sbx exec`, checked
 * against its schema, named by the host's name for it, masked once more, and
 * written to the drop folder. Never throws for the sandbox's own failings —
 * those are a problem line, and the other sandboxes carry on.
 */
async function pullOne(ctx: CliContext, sandbox: HostSandbox): Promise<Pulled> {
  const name = sandbox.name;
  const run = await sbxRun(ctx.io.env, name, ["doorman", "export", "bundle", "--scan", "--quiet"], { timeoutMs: PULL_TIMEOUT_MS });
  if (run.missing) return { sandbox: name, ok: false, problem: `Doorman isn't installed in ${name}. ${installKitHint(sandbox)}` };
  if (run.timedOut) return { sandbox: name, ok: false, problem: `${name} didn't answer within ${PULL_TIMEOUT_MS / 60_000} minutes.` };
  // A Doorman from before `export bundle`: its dispatcher's usage error.
  if (run.code === 2 && /Unknown (export )?command/.test(run.stderr)) {
    return { sandbox: name, ok: false, problem: `The Doorman in ${name} is too old to pull from. ${updateDoormanHint(sandbox)}` };
  }
  if (run.code !== 0) return { sandbox: name, ok: false, problem: `Couldn't read ${name}: ${firstLine(run.stderr) || `exit ${run.code}`}.` };
  let parsed: unknown;
  try {
    parsed = JSON.parse(run.stdout);
  } catch {
    return { sandbox: name, ok: false, problem: `${name} answered with something that isn't a bundle: ${firstLine(run.stdout).slice(0, 80) || "nothing"}.` };
  }
  const problems = validateSandboxBundle(parsed);
  if (problems.length > 0) {
    const first = problems[0]!;
    return {
      sandbox: name,
      ok: false,
      problem: `${name} sent a bundle this Doorman can't read (${first.path} ${first.message}). Update Doorman here (\`doorman update\`) or in it.`,
    };
  }
  const given = parsed as SandboxBundle;
  // The host's name for it is the one its rows will carry and `sbx` takes.
  const id = sandbox.id ?? given.sandbox?.id;
  const bundle = sanitizeSandboxBundle({ ...given, sandbox: { name, ...(id ? { id } : {}) } });
  let file: string;
  try {
    file = writeDropFile(ctx.dataDir, bundle, new Date(ctx.io.now()));
  } catch (err) {
    return { sandbox: name, ok: false, problem: `Couldn't write ${name}'s bundle to ${importsDir(ctx.dataDir)}: ${err instanceof Error ? err.message : String(err)}.` };
  }
  return { sandbox: name, ok: true, file, sightings: bundle.detections.detections.length, sessions: bundle.ledger.sessions.length };
}

/** One line from the terminal: yes, or anything else. */
function confirm(ctx: CliContext, question: string): Promise<boolean> {
  ctx.io.stderr.write(`${question} [y/N] `);
  const stdin = ctx.io.stdin;
  return new Promise((resolve) => {
    let text = "";
    const done = () => {
      stdin.off("data", onData);
      stdin.off("end", done);
      stdin.pause();
      resolve(/^\s*y(es)?\s*$/i.test(text.split("\n")[0] ?? ""));
    };
    const onData = (chunk: Buffer | string) => {
      text += chunk.toString();
      if (text.includes("\n")) done();
    };
    stdin.on("data", onData);
    stdin.on("end", done);
    stdin.resume();
  });
}

export const sbxPullCommand: CliCommand = {
  name: "sbx pull",
  summary: "Bring a sandbox's sightings and sessions to this computer's Doorman",
  usage: "[--all | <name>...] [--remove-after] [--yes]",
  positionals: { min: 0, max: 64 },
  options: {
    all: { type: "boolean", default: false },
    "remove-after": { type: "boolean", default: false },
    yes: { type: "boolean", default: false },
  },
  flags: [
    ["--all", "every running sandbox"],
    ["--remove-after", "then remove each sandbox pulled (`sbx rm`), after asking"],
    ["--yes", "remove without asking"],
  ],
  notes: [
    "Inside a sandbox Doorman keeps its own record, which `sbx rm` deletes. This runs `doorman export bundle --scan` in each sandbox (`sbx exec`) and drops what it prints in the imports folder of this computer's Doorman. Whoever owns the data here takes it in: this command when nothing else runs, else the desktop app (at once) or the next doorman command once it quits.",
    "Sandbox sightings and sessions then read as \"sandbox <name>\" in the app and in `doorman findings` and `doorman sessions`; their ids end in @<name>. Pulling again adds only what is new. Masked like every export: no secret value leaves the sandbox.",
    "A sandbox you name is read even when stopped (`sbx exec` starts it); --all reads the running ones.",
    "--remove-after removes a sandbox only once its bundle is written. Without --yes it asks first, so it needs a terminal.",
  ],
  examples: [
    ["doorman sbx pull my-sandbox", "bring one sandbox's record here"],
    ["doorman sbx pull --all", "every running sandbox"],
    ["doorman sbx pull my-sandbox --remove-after", "keep its record, then remove it"],
  ],
  async run(ctx, args) {
    const names = [...new Set(args.positionals)];
    const all = args.values.all === true;
    const removeAfter = args.values["remove-after"] === true;
    const yes = args.values.yes === true;
    if (all === (names.length > 0)) {
      throw new CliError(all ? "Name sandboxes or pass --all, not both." : "Name a sandbox, or pass --all.", 2, "`doorman sbx ls` lists them.");
    }
    for (const name of names) if (!validSandboxName(name)) throw new CliError(`"${name}" isn't a sandbox name.`, 2, "`doorman sbx ls` lists them.");
    // Asked before anything runs: a pull that ends at a question nobody can
    // answer would have kept the sandbox anyway, after all that work.
    if (removeAfter && !yes && (ctx.json || ctx.io.stdin.isTTY !== true)) {
      throw new CliError("--remove-after deletes sandboxes, and there is no terminal to ask.", 2, "Add --yes to remove them without asking.");
    }

    const listed = await listSandboxes(ctx.io.env);
    const problems: string[] = [];
    const chosen: HostSandbox[] = [];
    if (all) {
      chosen.push(...listed.filter((s) => s.running));
      if (chosen.length === 0) problems.push("No sandbox is running. `sbx ls` lists them.");
    } else {
      for (const name of names) {
        const found = listed.find((s) => s.name === name);
        if (found) chosen.push(found);
        else problems.push(`No sandbox named ${name}. \`sbx ls\` lists them.`);
      }
    }

    const pulls = await Promise.all(chosen.map((sandbox) => pullOne(ctx, sandbox)));
    for (const p of pulls) if (!p.ok) problems.push(p.problem);
    const written = pulls.filter((p): p is Extract<Pulled, { ok: true }> => p.ok);

    // Take the files in now when this command can own the store; else the
    // owner does (the copy withEngine opens took them in to count them).
    let outcomes: ImportOutcome[] = [];
    let owner = false;
    if (written.length > 0) {
      ({ outcomes, owner } = await withEngine(ctx, false, (handle) => ({ outcomes: handle.imported, owner: !handle.snapshot })));
    }
    const resultOf = (file: string): SandboxImportResult | undefined => outcomes.find((o) => o.file === file && o.ok)?.result;
    // Taken in → moved to done/ (lib/sandbox-import.ts drainImports).
    const landed = (file: string): string => (owner && resultOf(file) ? join(dirname(file), "done", basename(file)) : file);

    const removed: string[] = [];
    if (removeAfter && written.length > 0) {
      const list = written.map((p) => p.sandbox).join(", ");
      const go = yes || (await confirm(ctx, `Remove ${written.length === 1 ? "sandbox" : "sandboxes"} ${list}? Everything else in ${written.length === 1 ? "it" : "them"} is deleted.`));
      if (go) {
        for (const p of written) {
          // Our question stands in for sbx's own: --force skips it.
          const rm = await sbxRemove(ctx.io.env, p.sandbox, { timeoutMs: REMOVE_TIMEOUT_MS });
          if (rm.code === 0) removed.push(p.sandbox);
          else problems.push(`Couldn't remove ${p.sandbox}: ${rm.timedOut ? "`sbx rm` did not finish in time" : firstLine(rm.stderr) || `exit ${rm.code}`}.`);
        }
      } else {
        problems.push(`Kept ${list}: not removed.`);
      }
    }

    const data = {
      imports_dir: importsDir(ctx.dataDir),
      imported_now: owner,
      pulled: written.map((p) => {
        const result = resultOf(p.file);
        return {
          sandbox: p.sandbox,
          file: landed(p.file),
          sightings: p.sightings,
          sessions: p.sessions,
          ...(owner && result ? { turns_added: result.turns_added, findings_added: result.findings_added, findings_updated: result.findings_updated } : {}),
        };
      }),
      removed,
      problems,
    };

    const ui = ctx.ui;
    const s = ctx.style;
    const text: string[] = [];
    for (const p of written) {
      const result = owner ? resultOf(p.file) : undefined;
      const what = `${plural(p.sightings, "sighting")} and ${plural(p.sessions, "session")}`;
      const news = result ? `: ${plural(result.findings_added, "new sighting")}, ${plural(result.turns_added, "new turn")}` : "";
      text.push(ui.mark("ok", `Pulled ${what} from sandbox ${s.bold(p.sandbox)}${news}`));
      if (!result) text.push(`  ${s.dim(`waiting in ${landed(p.file)}`)}`);
    }
    if (written.length > 0) {
      text.push(
        owner
          ? ui.next("`doorman findings` and `doorman sessions` list them.")
          : ui.next("Doorman is running here, so it takes them in: the app shows them now, or the next doorman command once it quits."),
      );
    }
    for (const name of removed) text.push(ui.mark("ok", `Removed sandbox ${s.bold(name)}`));
    for (const problem of problems) ctx.io.stderr.write(`${ctx.errUi.mark("warn", ctx.errUi.style.warn(`doorman: ${problem}`))}\n`);
    return { data, text, ...(problems.length > 0 ? { exitCode: 1 } : {}) };
  },
};
