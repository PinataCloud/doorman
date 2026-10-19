import { spawnSync } from "node:child_process";
import { existsSync, readFileSync, realpathSync } from "node:fs";
import { join, sep } from "node:path";
import type { CliCommand } from "../command.js";
import type { CliContext } from "../context.js";
import { CliError } from "../output.js";
import { checkForUpdate, updateCachePath } from "../update-check.js";

/** How this copy of the CLI was installed, which decides how it updates. */
export type InstallKind = "global" | "npx" | "project" | "source";

/** Run npm with `args`; status and combined output. */
export type NpmRunner = (args: readonly string[]) => { status: number | null; output: string };

const npmBin = (platform: NodeJS.Platform) => (platform === "win32" ? "npm.cmd" : "npm");

export function defaultNpmRunner(platform: NodeJS.Platform): NpmRunner {
  return (args) => {
    // npm.cmd is a batch file: Windows only runs it through a shell.
    const r = spawnSync(npmBin(platform), [...args], { encoding: "utf8", shell: platform === "win32", windowsHide: true });
    return { status: r.status, output: `${r.stdout ?? ""}${r.stderr ?? ""}${r.error ? String(r.error) : ""}` };
  };
}

/** The package directory this CLI runs from (three levels above build/main/cli). */
export function cliPackageDir(): string {
  return join(__dirname, "..", "..", "..", "..");
}

/** Where this copy came from: npm's global root, an npx cache, a project's
 * node_modules, or a source checkout. */
export function installKind(packageDir: string, npm: NpmRunner): InstallKind {
  const real = (p: string) => {
    try {
      return realpathSync(p);
    } catch {
      return p;
    }
  };
  const dir = real(packageDir);
  if (existsSync(join(dir, "cli", "package.json"))) return "source";
  if (dir.includes(`${sep}_npx${sep}`)) return "npx";
  const root = npm(["root", "-g"]);
  const globalRoot = root.status === 0 ? root.output.trim().split(/\r?\n/).pop() : undefined;
  if (globalRoot && dir.toLowerCase().startsWith(real(globalRoot).toLowerCase())) return "global";
  return "project";
}

function installedVersion(packageDir: string): string | undefined {
  try {
    const raw: unknown = JSON.parse(readFileSync(join(packageDir, "package.json"), "utf8"));
    return raw && typeof raw === "object" && "version" in raw && typeof raw.version === "string" ? raw.version : undefined;
  } catch {
    return undefined;
  }
}

export const updateCommand: CliCommand = {
  name: "update",
  summary: "Check for a newer Doorman CLI and install it",
  usage: "[--check]",
  options: { check: { type: "boolean", default: false } },
  details: [
    "--check  only say whether an update is available (exit 0 either way)",
    "",
    "Doorman checks npm for a newer version at most once a day and says so after a",
    "command. Turn that off with DOORMAN_NO_UPDATE_CHECK=1 (it is also off under CI",
    "and when stderr is not a terminal).",
  ],
  async run(ctx: CliContext, args) {
    const name = ctx.io.packageName ?? "@pinata/doorman";
    const current = ctx.io.version;
    const status = await checkForUpdate(ctx, name, current);
    if (status.latest === undefined) throw new CliError(`couldn't check for updates: ${status.error ?? "no answer from the registry"}`);
    const s = ctx.style;
    if (!status.update_available) {
      return { data: { ...status, updated: false }, text: [`Doorman CLI ${current} is up to date (latest on npm: ${status.latest}).`] };
    }
    const available = `Doorman CLI ${status.latest} is available (you have ${current}).`;
    if (args.values.check === true) return { data: { ...status, updated: false }, text: [available] };

    const npm = ctx.io.runNpm ?? defaultNpmRunner(ctx.io.platform);
    const packageDir = ctx.io.packageDir ?? cliPackageDir();
    const kind = installKind(packageDir, npm);
    const spec = `${name}@${status.latest}`;
    if (kind !== "global") {
      const how =
        kind === "npx"
          ? `You are running it through npx: run \`npx ${name}@latest\` to get ${status.latest}.`
          : kind === "project"
            ? `It is installed in a project: run \`npm install ${spec}\` there.`
            : "It runs from a source checkout: pull the repo and run `npm run compile`.";
      return { data: { ...status, updated: false, install: kind }, text: [available, how] };
    }

    ctx.io.stderr.write(s.dim(`Installing ${spec} with npm...\n`));
    const result = npm(["install", "--global", "--no-audit", "--no-fund", spec]);
    const now = installedVersion(packageDir);
    if (result.status !== 0 || now !== status.latest) {
      const tail = result.output.trim().split(/\r?\n/).slice(-6).join("\n");
      throw new CliError(
        `npm couldn't install ${spec}${result.status !== 0 ? ` (exit ${result.status})` : ""}. Run \`npm install -g ${spec}\` yourself${tail ? `:\n${tail}` : "."}`,
      );
    }
    return {
      data: { ...status, updated: true, install: kind, version: now, cache: updateCachePath(ctx.dataDir) },
      text: [s.green(`Updated the Doorman CLI from ${current} to ${now}.`)],
    };
  },
};
