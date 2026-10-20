/**
 * Host-side Docker Sandboxes (`sbx`): the sandboxes on this computer, and
 * Doorman commands run inside them with `sbx exec`. What `doorman sbx`
 * (commands/sbx.ts) is built on.
 *
 * Read off sbx 0.46.0 (2026-10-20): `sbx ls --json` prints
 * `{"sandboxes":[{"name","id","agent","status","workspaces",…}]}` with
 * `status` "running" or "stopped", local sandboxes only (cloud ones need
 * `sbx --cloud`, which Doorman doesn't use). `sbx exec <name> <cmd…>` runs a
 * command inside (`-i` keeps stdin open, `-t` would allocate a terminal) —
 * and STARTS a stopped sandbox first, so nothing here ever execs one that
 * isn't running. Inside, `doorman` is on the PATH once the kit installed it;
 * a missing command fails the way `docker exec` does (exit 126/127,
 * "executable file not found").
 *
 * DOORMAN_SBX_BIN names the `sbx` to run (tests point it at a fake one).
 */

import { spawn, type ChildProcess } from "node:child_process";
import { CliError } from "./output.js";

/** The kit that installs Doorman in a sandbox, as `sbx kit add` takes it. */
export const DOORMAN_KIT = "git+https://github.com/PinataCloud/doorman.git#dir=integrations/sbx-kit";
/** The same for a sandbox built from a v3 kit workload (agent `sbx-kit-…`),
 * which `sbx kit add` can't extend: it is created again with `--kit`. */
export const DOORMAN_KIT_V3 = "git+https://github.com/PinataCloud/doorman.git#dir=integrations/sbx-kit/v3/doorman";

/** One sandbox `sbx ls` lists. */
export interface HostSandbox {
  name: string;
  id?: string;
  /** The agent it runs (`claude`, `codex`, …), as sbx names it. */
  agent?: string;
  /** As sbx says it: `running`, `stopped`, … */
  status: string;
  running: boolean;
  workspaces: string[];
}

/** What one `sbx exec` printed, and how it ended. */
export interface SbxRunResult {
  /** Exit code; null when it was killed (its timeout) or never started. */
  code: number | null;
  stdout: string;
  stderr: string;
  timedOut: boolean;
  /** The command isn't there inside the sandbox (Doorman not installed). */
  missing: boolean;
}

export function sbxBin(env: NodeJS.ProcessEnv): string {
  return env.DOORMAN_SBX_BIN?.trim() || "sbx";
}

/** `sbx exec` failed because the command isn't installed inside. */
export function commandMissing(code: number | null, stderr: string): boolean {
  return code === 126 || code === 127 || /executable file not found|command not found/i.test(stderr);
}

/** How Doorman gets into `sandbox` (or back, newer): `sbx kit add` for a
 * sandbox running one of sbx's own agents; a v3 kit sandbox (agent
 * `sbx-kit-…`) takes no mixin afterwards and is created again with it. */
function kitAdvice(sandbox: Pick<HostSandbox, "name" | "agent">): string {
  return sandbox.agent?.startsWith("sbx-kit-")
    ? `create it again with \`--kit ${DOORMAN_KIT_V3}\` (a v3 kit sandbox takes no \`sbx kit add\`)`
    : `\`sbx kit add ${sandbox.name} ${DOORMAN_KIT}\``;
}

/** The advice for a sandbox without Doorman. */
export function installKitHint(sandbox: Pick<HostSandbox, "name" | "agent">): string {
  return `Add the Doorman kit: ${kitAdvice(sandbox)}.`;
}

/** The advice for a sandbox whose Doorman is older than the host needs.
 * Through the kit, never by hand: the kit's next install would undo it. */
export function updateDoormanHint(sandbox: Pick<HostSandbox, "name" | "agent">): string {
  return `Update Doorman in it through the kit: ${kitAdvice(sandbox)} (the kit installs the latest).`;
}

/** `sbx ls --json`, read leniently: entries without a name are skipped. */
export function parseSandboxList(json: string): HostSandbox[] {
  const parsed: unknown = JSON.parse(json);
  const list = parsed && typeof parsed === "object" && "sandboxes" in parsed ? parsed.sandboxes : parsed;
  if (!Array.isArray(list)) return [];
  const out: HostSandbox[] = [];
  for (const r of list as unknown[]) {
    if (!r || typeof r !== "object" || !("name" in r) || typeof r.name !== "string" || r.name === "") continue;
    const status = "status" in r && typeof r.status === "string" ? r.status : "unknown";
    const workspaces: unknown[] = "workspaces" in r && Array.isArray(r.workspaces) ? r.workspaces : [];
    out.push({
      name: r.name,
      ...("id" in r && typeof r.id === "string" ? { id: r.id } : {}),
      ...("agent" in r && typeof r.agent === "string" ? { agent: r.agent } : {}),
      status,
      running: status.toLowerCase() === "running",
      workspaces: workspaces.filter((w): w is string => typeof w === "string"),
    });
  }
  return out;
}

/** Run `sbx <args…>` to the end, killed after `timeoutMs`. */
function runSbx(env: NodeJS.ProcessEnv, args: readonly string[], timeoutMs: number): Promise<{ code: number | null; stdout: string; stderr: string; timedOut: boolean; error?: NodeJS.ErrnoException }> {
  return new Promise((resolve) => {
    let stdout = "";
    let stderr = "";
    let timedOut = false;
    let child: ChildProcess;
    try {
      child = spawn(sbxBin(env), [...args], { env, stdio: ["ignore", "pipe", "pipe"], windowsHide: true });
    } catch (err) {
      resolve({ code: null, stdout, stderr, timedOut, error: err as NodeJS.ErrnoException });
      return;
    }
    child.stdout!.setEncoding("utf8").on("data", (c: string) => (stdout += c));
    child.stderr!.setEncoding("utf8").on("data", (c: string) => (stderr += c));
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill("SIGKILL");
    }, timeoutMs);
    let failure: NodeJS.ErrnoException | undefined;
    child.on("error", (err) => (failure = err));
    child.on("close", (code) => {
      clearTimeout(timer);
      resolve({ code, stdout, stderr, timedOut, ...(failure ? { error: failure } : {}) });
    });
  });
}

/** Every sandbox `sbx ls` lists, running or not. Throws a CliError when
 * there is no `sbx` here, or it fails. */
export async function listSandboxes(env: NodeJS.ProcessEnv, options: { timeoutMs?: number } = {}): Promise<HostSandbox[]> {
  const r = await runSbx(env, ["ls", "--json"], options.timeoutMs ?? 15_000);
  if (r.error?.code === "ENOENT") {
    throw new CliError("`sbx` (Docker Sandboxes) is not installed here, or not on the PATH.", 1, "`doorman sbx` runs on the computer that runs your sandboxes.");
  }
  if (r.error) throw new CliError(`Couldn't run \`sbx ls\`: ${r.error.message}`);
  if (r.timedOut) throw new CliError("`sbx ls` did not answer in time.", 1, "Is the Docker Sandboxes daemon running? `sbx ls` should list your sandboxes.");
  if (r.code !== 0) throw new CliError(`\`sbx ls\` failed: ${firstLine(r.stderr) || `exit ${r.code}`}`);
  try {
    return parseSandboxList(r.stdout);
  } catch {
    throw new CliError("`sbx ls --json` printed something that isn't JSON.", 1, "Update sbx, or check that `sbx ls --json` works.");
  }
}

/**
 * The sandboxes a command acts on: the running ones (`names` empty), or the
 * ones named. A name that is not a sandbox, or one that isn't running, is a
 * problem line instead: `sbx exec` would start a stopped one.
 */
export function selectSandboxes(all: readonly HostSandbox[], names: readonly string[]): { chosen: HostSandbox[]; problems: string[] } {
  if (names.length === 0) return { chosen: all.filter((s) => s.running), problems: [] };
  const chosen: HostSandbox[] = [];
  const problems: string[] = [];
  for (const name of [...new Set(names)]) {
    const found = all.find((s) => s.name === name);
    if (!found) problems.push(`No sandbox named ${name}. \`sbx ls\` lists them.`);
    else if (!found.running) problems.push(`Sandbox ${name} is ${found.status}. Start it (\`sbx run ${name}\`) first.`);
    else chosen.push(found);
  }
  return { chosen, problems };
}

/** `sbx exec <name> <argv…>` to the end, with no stdin, killed after `timeoutMs`. */
export async function sbxRun(env: NodeJS.ProcessEnv, name: string, argv: readonly string[], options: { timeoutMs: number }): Promise<SbxRunResult> {
  const r = await runSbx(env, ["exec", name, ...argv], options.timeoutMs);
  if (r.error?.code === "ENOENT") throw new CliError("`sbx` (Docker Sandboxes) is not installed here, or not on the PATH.");
  return { code: r.code, stdout: r.stdout, stderr: r.stderr, timedOut: r.timedOut, missing: !r.timedOut && r.code !== 0 && commandMissing(r.code, r.stderr) };
}

/** `sbx rm --force <name>`: the sandbox and everything in it, gone. */
export async function sbxRemove(env: NodeJS.ProcessEnv, name: string, options: { timeoutMs: number }): Promise<{ code: number | null; stderr: string; timedOut: boolean }> {
  const r = await runSbx(env, ["rm", "--force", name], options.timeoutMs);
  if (r.error?.code === "ENOENT") throw new CliError("`sbx` (Docker Sandboxes) is not installed here, or not on the PATH.");
  return { code: r.code, stderr: r.stderr, timedOut: r.timedOut };
}

/** `sbx exec [-i] <name> <argv…>`, its stdio piped. Never `-t`: the
 * command inside gets no terminal, so the end of its stdin is what tells it
 * this side has gone. */
export function sbxSpawn(env: NodeJS.ProcessEnv, name: string, argv: readonly string[], options: { interactive: boolean }): ChildProcess {
  return spawn(sbxBin(env), ["exec", ...(options.interactive ? ["-i"] : []), name, ...argv], {
    env,
    stdio: [options.interactive ? "pipe" : "ignore", "pipe", "pipe"],
    windowsHide: true,
  });
}

/** The first non-empty line of a command's output, trimmed. */
export function firstLine(text: string): string {
  return (
    text
      .split("\n")
      .map((l) => l.trim())
      .find(Boolean) ?? ""
  );
}
