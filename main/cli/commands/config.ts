import { CONFIDENCE_BANDS } from "../../lib/findings.js";
import { RETENTION_CHOICES, sanitizePrefs, type Prefs } from "../../state.js";
import type { CliCommand } from "../command.js";
import type { CliContext } from "../context.js";
import { CliError } from "../output.js";
import { applyEditorExtension } from "./editor.js";
import { applyMcpAnswers } from "./mcp.js";

type ConfigKey = "retention_days" | "confidence_bands" | "show_false_positives" | "vscode_extension" | "mcp_answers" | "appearance";

function parseBoolean(raw: string): boolean | undefined {
  const v = raw.trim().toLowerCase();
  if (v === "true" || v === "on" || v === "yes") return true;
  if (v === "false" || v === "off" || v === "no") return false;
  return undefined;
}

/** The prefs that mean something without the window. Everything else in
 * prefs.json is the app's (notifications, tray, onboarding) or has its own
 * command (policy: rules, model, guard). */
const SETTINGS: Record<ConfigKey, { help: string; parse(raw: string): Prefs[ConfigKey] | undefined }> = {
  retention_days: {
    help: `${RETENTION_CHOICES.join(", ")} (days of history kept; 0 = keep everything)`,
    parse: (raw) => (/^\d+$/.test(raw.trim()) ? Number(raw.trim()) : undefined),
  },
  confidence_bands: {
    help: `comma list of ${CONFIDENCE_BANDS.join(", ")} (which findings show)`,
    parse: (raw) => {
      const parts = raw.split(",").map((p) => p.trim().toLowerCase()).filter((p) => p !== "");
      if (parts.length === 0 || parts.some((p) => !(CONFIDENCE_BANDS as readonly string[]).includes(p))) return undefined;
      return CONFIDENCE_BANDS.filter((b) => parts.includes(b));
    },
  },
  show_false_positives: { help: "true or false (list findings marked false positive)", parse: parseBoolean },
  vscode_extension: { help: "true or false (VS Code companion; installs or removes it)", parse: parseBoolean },
  mcp_answers: { help: "true or false (Doorman's MCP server for your agents)", parse: parseBoolean },
  // Any word; the sanitizer below refuses what isn't a theme.
  appearance: { help: "auto, light or dark (the app's theme)", parse: (raw) => raw.trim().toLowerCase() as Prefs["appearance"] },
};

const KEYS = Object.keys(SETTINGS) as ConfigKey[];

function configKey(raw: string): ConfigKey {
  if ((KEYS as string[]).includes(raw)) return raw as ConfigKey;
  throw new CliError(`Unknown setting "${raw}". Settings: ${KEYS.join(", ")}.`, 2, "`doorman config --help` says what each one takes.");
}

function show(value: unknown): string {
  return Array.isArray(value) ? value.join(",") : String(value);
}

/** The settings list for `--help`, one row per key. */
const SETTINGS_NOTES = ["Settings:", ...KEYS.map((k) => `  ${k.padEnd(21)}${SETTINGS[k].help}`)];

const getCommand: CliCommand = {
  name: "config get",
  summary: "Show settings shared with the app",
  usage: "[key]",
  positionals: { min: 0, max: 1 },
  notes: SETTINGS_NOTES,
  examples: [
    ["doorman config get", "every setting"],
    ["doorman config get retention_days", "just the value, for scripts"],
  ],
  async run(ctx, args) {
    const prefs = ctx.prefs();
    const keys = args.positionals[0] === undefined ? KEYS : [configKey(args.positionals[0])];
    const data = Object.fromEntries(keys.map((k) => [k, prefs[k]]));
    // One key: the bare value, so scripts can read it.
    if (keys.length === 1) return { data: data[keys[0]!], text: [show(prefs[keys[0]!])] };
    return { data, text: [ctx.ui.section("Settings"), ...ctx.ui.kv(keys.map((k) => [k, show(prefs[k])] as const))] };
  },
};

/** What the app does when a setting moves (index.ts prefs:set): history is
 * pruned at once, and the two install switches install or remove. */
async function applySideEffects(ctx: CliContext, key: ConfigKey, value: Prefs[ConfigKey]): Promise<string[]> {
  if (key === "retention_days") {
    const handle = await ctx.openEngine({ scan: false });
    try {
      handle.engine.applyRetentionNow();
    } finally {
      handle.close();
    }
    return [];
  }
  if (key === "mcp_answers") {
    const outcome = applyMcpAnswers(ctx, value === true);
    if (!outcome.ok) {
      throw new CliError(`Saved, but the MCP server ${value ? "registration" : "removal"} failed: ${outcome.error ?? "failed"}`, 1, "`doorman mcp server status` shows each host's config.");
    }
    const hosts = outcome.hosts.filter((h) => h.registered).map((h) => h.label);
    if (!value) return [ctx.ui.mark("ok", "Unregistered.")];
    return [hosts.length > 0 ? ctx.ui.mark("ok", `Registered with ${hosts.join(", ")}.`) : ctx.ui.mark("off", "No MCP host to register with yet.")];
  }
  if (key === "vscode_extension") {
    const outcome = applyEditorExtension(ctx, value === true);
    if (!outcome.ok) {
      throw new CliError(`Saved, but the VS Code companion ${value ? "install" : "removal"} failed: ${outcome.error ?? "failed"}`, 1, "`doorman editor status` shows each editor.");
    }
    const labels = outcome.hosts.filter((h) => outcome.installed.includes(h.variant)).map((h) => h.label);
    if (!value) return [ctx.ui.mark("ok", "Removed.")];
    return [labels.length > 0 ? ctx.ui.mark("ok", `Installed in ${labels.join(", ")}.`) : ctx.ui.mark("off", "No editor to install it in yet.")];
  }
  return [];
}

const setCommand: CliCommand = {
  name: "config set",
  summary: "Change a setting shared with the app",
  usage: "<key> <value>",
  positionals: { min: 2, max: 2 },
  notes: SETTINGS_NOTES,
  examples: [
    ["doorman config set retention_days 30", "keep 30 days of history"],
    ["doorman config set confidence_bands high,medium", "hide low-confidence findings"],
    ["doorman config set mcp_answers true", "register Doorman's MCP server"],
  ],
  async run(ctx, args) {
    const key = configKey(args.positionals[0]!);
    const raw = args.positionals[1]!;
    const value = SETTINGS[key].parse(raw);
    // The Store's own sanitizer decides: a value it would drop is refused here
    // instead of being silently replaced by the default.
    const before = ctx.prefs();
    if (value === undefined || JSON.stringify(sanitizePrefs({ ...before, [key]: value })[key]) !== JSON.stringify(value)) {
      throw new CliError(`Invalid value for ${key}: "${raw}". Expected ${SETTINGS[key].help}.`, 2);
    }
    ctx.requireWritable(`Change ${key}`);
    const next = ctx.setPrefs({ [key]: value });
    const changed = JSON.stringify(next[key]) !== JSON.stringify(before[key]);
    const notes = changed ? await applySideEffects(ctx, key, next[key]) : [];
    return {
      data: { key, value: next[key], changed },
      text: [changed ? ctx.ui.mark("ok", `${key} = ${show(next[key])}`) : ctx.ui.mark("off", `${key} = ${show(next[key])}${ctx.style.dim(" (unchanged)")}`), ...notes],
    };
  },
};

const configCommand: CliCommand = {
  name: "config",
  summary: "Same as `doorman config get`",
  notes: getCommand.notes!,
  examples: getCommand.examples!,
  run: getCommand.run,
};

export const configCommands: CliCommand[] = [configCommand, getCommand, setCommand];
