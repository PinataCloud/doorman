import { existsSync } from "node:fs";
import {
  clearEditorStatus,
  extensionStatus,
  installEditorExtension,
  uninstallEditorExtension,
  vsixPath,
  type EditorExtensionStatus,
  type EditorInstallOutcome,
} from "../../vscode-ext-install.js";
import type { CliCommand } from "../command.js";
import type { CliContext } from "../context.js";
import { CliError, table } from "../output.js";

/**
 * The `vscode_extension` switch's side effect, as the app applies it
 * (index.ts applyEditorExtension): install the extension this build ships
 * (build/vscode, beside build/main) into every VS Code family build with a
 * command line, or take it back out. Off also removes the status file the
 * extension reads. The app publishes that file while it runs; the CLI only
 * changes these settings while the app is closed, so it never writes one.
 */
export function applyEditorExtension(ctx: CliContext, enabled: boolean): EditorInstallOutcome {
  if (enabled) return installEditorExtension(ctx.io.version, ctx.io.home);
  const outcome = uninstallEditorExtension(ctx.io.home);
  clearEditorStatus(ctx.dataDir);
  return outcome;
}

function hostRows(ctx: CliContext, hosts: EditorExtensionStatus[]): string[] {
  const s = ctx.style;
  if (hosts.length === 0) return [s.dim("No VS Code family editor (VS Code, Insiders, VSCodium, Cursor, Windsurf) found on this machine.")];
  return table(
    ["EDITOR", "EXTENSION"],
    hosts.map((h) => [h.label, h.cliMissing ? s.yellow("no command line, can't install") : h.installed ? s.green(`installed ${h.installed}`) : s.dim("not installed")]),
  );
}

const statusCommand: CliCommand = {
  name: "editor status",
  summary: "The Doorman VS Code companion: wanted, packaged, and installed per editor",
  async run(ctx) {
    const wanted = ctx.prefs().vscode_extension === true;
    const vsix = vsixPath();
    const hosts = extensionStatus(ctx.io.home);
    const s = ctx.style;
    return {
      data: { wanted, vsix: existsSync(vsix) ? vsix : null, hosts },
      text: [
        `${s.bold("VS Code companion")}  ${wanted ? s.green("on") : s.dim("off")}${existsSync(vsix) ? "" : s.yellow("  (no packaged extension in this build)")}`,
        ...hostRows(ctx, hosts),
      ],
    };
  },
};

function switchRun(enabled: boolean): CliCommand["run"] {
  return async (ctx) => {
    ctx.requireWritable(`${enabled ? "Install" : "Remove"} the VS Code companion`);
    ctx.setPrefs({ vscode_extension: enabled });
    const outcome = applyEditorExtension(ctx, enabled);
    if (!outcome.ok) throw new CliError(`Couldn't ${enabled ? "install" : "remove"} the VS Code companion: ${outcome.error ?? "failed"}`);
    const labels = outcome.hosts.filter((h) => outcome.installed.includes(h.variant)).map((h) => h.label);
    const head = enabled
      ? labels.length > 0
        ? `The VS Code companion is installed in ${labels.join(", ")}.`
        : "The VS Code companion is on; no editor to install it in yet."
      : "The VS Code companion is removed.";
    return { data: { wanted: enabled, installed: outcome.installed, hosts: outcome.hosts }, text: [head, ...hostRows(ctx, outcome.hosts)] };
  };
}

const installCommand: CliCommand = {
  name: "editor install",
  summary: "Install the VS Code companion in every VS Code family editor here",
  details: ["Turns on the app's VS Code extension setting (prefs vscode_extension). Uses each editor's own CLI."],
  run: switchRun(true),
};

const uninstallCommand: CliCommand = {
  name: "editor uninstall",
  summary: "Remove the VS Code companion from every editor that has it",
  run: switchRun(false),
};

export const editorCommands: CliCommand[] = [statusCommand, installCommand, uninstallCommand];
