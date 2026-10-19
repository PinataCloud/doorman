/**
 * Shadow-AI discovery — a local, no-network "what other AI is on this Mac?".
 *
 * Doorman captures exactly two rails (Claude Code, Codex). This is the honest
 * coverage map for everything ELSE a developer runs: which AI tools are
 * installed, which look active (recent writes under their state directories),
 * and — the point — which sit OUTSIDE the guard entirely. Harmonic's Explore,
 * scaled to one machine and to inventory-only: we do not hook these tools, we
 * just stop pretending the two we cover are the whole picture.
 *
 * Detection is filesystem probing only: an app bundle, a config/state
 * directory, a CLI's dot-dir. No process listing (needs entitlements we don't
 * want), no network. "Active" is the newest mtime under the tool's state paths
 * within a window — a heuristic, labelled as one.
 *
 * THE CATALOG IS ALSO THE VOCABULARY. Any list of approved apps can only name
 * tools this file can find, so adding an entry is what makes an app
 * governable — see `SHADOW_AI_IDS`. Two rules keep the list
 * worth reading: an entry needs a path that is specific to the tool (a bundle
 * id or its own dot-dir, never a shared directory), and an entry whose presence
 * says nothing useful on every Mac is left OUT rather than added as noise —
 * which is why the mainstream browsers are absent despite shipping assistants.
 *
 * The two rails Doorman already captures are reported here too, so the card
 * reads as one coverage map rather than "these are the ones we miss" floating
 * next to the rails board. `covered` is COMPUTED from the guard host registry
 * (guard/hosts/index.ts) plus the capture rails: registering a host adapter
 * and installing the guard into it moves that row from uncovered to covered
 * with no edit here.
 *
 * fs lives behind an injected probe so the catalog and the roll-up are testable
 * from the tests without touching a real home directory.
 */

export type ShadowAiKind =
  | "agent-cli"
  | "desktop-app"
  | "editor"
  | "local-model"
  | "browser"
  | "productivity";

export interface ShadowAiTool {
  id: string;
  name: string;
  kind: ShadowAiKind;
  /** Doorman captures or guards this tool. COMPUTED (scanShadowAi), never
   * declared: a capture rail is covered outright, and every other entry is
   * covered exactly while the guard is installed into its host. */
  covered: boolean;
  /** What using it typically does with your data, one line — same register as
   * the MCP risk catalog. */
  note: string;
}

export interface ShadowAiProbe {
  /** Any of these paths exists (absolute, `~` already expanded by the caller). */
  present: string[];
  /** mtimes under these paths decide "active"; usually a subset of `present`. */
  activity: string[];
}

/** A catalog entry: the tool, minus the computed `covered` flag, plus how to
 * find it and — when the guard can reach it — which registered host id
 * (guard/hosts/index.ts) covering it would mean. */
export type ShadowAiCatalogEntry = Omit<ShadowAiTool, "covered"> & {
  /** Doorman reads this rail's transcripts natively, guard or no guard — the
   * two the capture engine was born with. Every OTHER host earns `captured`
   * from the transcript-source registry at scan time (see `capturedSourceIds`
   * below), so the catalog never claims a rail a parser doesn't exist for. */
  captured?: boolean;
  /** The guard host id that covers this tool once it is installed there. */
  guard_host?: string;
  present: string[];
  activity: string[];
};

/** The catalog: one entry per tool, with the home-relative paths that reveal
 * it. Paths are RELATIVE to home; the caller (index.ts) joins them and supplies
 * the fs probe, so this stays pure and testable. */
export const SHADOW_AI_CATALOG: ReadonlyArray<ShadowAiCatalogEntry> = [
  {
    id: "claude-code",
    name: "Claude Code",
    kind: "agent-cli",
    captured: true,
    guard_host: "claude",
    note: "Captured and guarded by Doorman.",
    present: [".claude"],
    activity: [".claude/projects"],
  },
  {
    id: "codex",
    name: "Codex",
    kind: "agent-cli",
    captured: true,
    guard_host: "codex",
    note: "Captured and guarded by Doorman.",
    present: [".codex"],
    activity: [".codex/sessions"],
  },
  {
    id: "claude-desktop",
    name: "Claude Desktop",
    kind: "desktop-app",
    note: "Chats and any connected MCP servers run outside the guard.",
    present: ["/Applications/Claude.app", "Library/Application Support/Claude"],
    activity: ["Library/Application Support/Claude"],
  },
  {
    id: "chatgpt-desktop",
    name: "ChatGPT Desktop",
    kind: "desktop-app",
    note: "Its CODEX MODE is read from the rollouts it writes; ordinary chats and uploads go to OpenAI, unseen here.",
    present: ["/Applications/ChatGPT.app", "Library/Application Support/com.openai.chat"],
    activity: ["Library/Application Support/com.openai.chat"],
  },
  {
    id: "cursor",
    name: "Cursor",
    kind: "editor",
    guard_host: "cursor",
    note: "An AI editor with its own agent — its tool calls never reach the guard.",
    present: ["/Applications/Cursor.app", ".cursor"],
    activity: [".cursor", "Library/Application Support/Cursor"],
  },
  {
    id: "windsurf",
    name: "Windsurf",
    kind: "editor",
    guard_host: "windsurf",
    note: "AI editor (Codeium) with an in-editor agent, outside the guard.",
    present: ["/Applications/Windsurf.app", ".codeium"],
    activity: [".codeium", "Library/Application Support/Windsurf"],
  },
  {
    id: "vscode-copilot",
    name: "VS Code + Copilot",
    kind: "editor",
    // VS Code's agent hooks (1.109+, preview, default on) read the same
    // `~/.copilot/hooks/` directory as the Copilot CLI, so the `copilot`
    // descriptor's ONE document guards both — this row and the next share it.
    guard_host: "copilot",
    note: "Copilot's agent mode inside VS Code — its tool calls run outside the guard.",
    present: [".vscode/extensions", "Library/Application Support/Code"],
    activity: [".vscode/extensions"],
  },
  {
    id: "copilot-cli",
    name: "Copilot CLI",
    kind: "agent-cli",
    guard_host: "copilot",
    note: "GitHub's terminal agent — its tool calls run outside the guard.",
    // Only the CLI creates session-state; `~/.copilot` alone also appears on Macs where
    // just VS Code's Copilot Chat shim ran, which read as "Copilot CLI installed".
    present: [".copilot/session-state"],
    activity: [".copilot/session-state"],
  },
  {
    id: "gemini-cli",
    name: "Gemini CLI",
    kind: "agent-cli",
    guard_host: "gemini",
    note: "Google's terminal agent — prompts and tool runs go to Gemini, uncaptured.",
    present: [".gemini"],
    activity: [".gemini"],
  },
  {
    id: "amazon-q",
    name: "Amazon Q Developer",
    kind: "agent-cli",
    note: "AWS's terminal agent — prompts and tool runs go to Amazon, uncaptured.",
    present: [".aws/amazonq", "/Applications/Amazon Q.app"],
    activity: [".aws/amazonq"],
  },
  {
    id: "aider",
    name: "Aider",
    kind: "agent-cli",
    note: "Runs on your own API keys — spend lands on the provider bill, not a plan.",
    present: [".aider.conf.yml", ".aider"],
    activity: [".aider"],
  },
  {
    id: "opencode",
    name: "OpenCode",
    kind: "agent-cli",
    guard_host: "opencode",
    note: "Terminal agent, any provider — its tool calls run outside the guard.",
    present: [".config/opencode", ".local/share/opencode", ".opencode"],
    activity: [".local/share/opencode", ".config/opencode"],
  },
  {
    id: "amp",
    name: "Amp",
    kind: "agent-cli",
    note: "Sourcegraph's agent — prompts and file edits are unseen here.",
    present: [".config/amp", ".cache/amp"],
    activity: [".config/amp", ".cache/amp"],
  },
  {
    id: "goose",
    name: "Goose",
    kind: "agent-cli",
    guard_host: "goose",
    note: "Block's local agent — its MCP extensions and shell runs are outside the guard.",
    present: [".config/goose", "/Applications/Goose.app", "Library/Application Support/Block.block.goose"],
    activity: [".config/goose", "Library/Application Support/Block.block.goose", ".local/share/goose"],
  },
  {
    id: "crush",
    name: "Crush",
    kind: "agent-cli",
    guard_host: "crush",
    note: "Charm's terminal agent — prompts and tool runs are unseen here.",
    present: [".config/crush", ".local/share/crush"],
    activity: [".local/share/crush"],
  },
  {
    id: "qwen-code",
    name: "Qwen Code",
    kind: "agent-cli",
    guard_host: "qwen",
    note: "Alibaba's terminal agent — prompts go to Qwen, uncaptured.",
    present: [".qwen"],
    activity: [".qwen"],
  },
  // 2026-09-06: the harnesses the
  // guard and the ledger reach next. Each has its own dot-dir (rule 1).
  {
    id: "openclaw",
    name: "OpenClaw",
    kind: "agent-cli",
    guard_host: "openclaw",
    note: "A gateway daemon running agents over Telegram, Discord, Slack and cron — tool calls happen with nobody at the keyboard.",
    present: [".openclaw"],
    activity: [".openclaw/agents", ".openclaw"],
  },
  {
    id: "hermes",
    name: "Hermes Agent",
    kind: "agent-cli",
    guard_host: "hermes",
    note: "Nous Research's always-on agent (CLI, messaging gateway, cron) — runs shell and file tools unattended.",
    present: [".hermes"],
    activity: [".hermes"],
  },
  {
    id: "kiro",
    name: "Kiro CLI",
    kind: "agent-cli",
    guard_host: "kiro",
    note: "AWS's terminal agent (ex Amazon Q CLI) — shell, file and AWS calls run outside the guard.",
    present: [".kiro"],
    activity: [".kiro"],
  },
  {
    id: "factory-droid",
    name: "Factory Droid",
    kind: "agent-cli",
    guard_host: "droid",
    note: "Factory's terminal agent — its shell and file tools run outside the guard.",
    present: [".factory"],
    activity: [".factory"],
  },
  {
    id: "kimi-code",
    name: "Kimi Code",
    kind: "agent-cli",
    guard_host: "kimi",
    note: "Moonshot's terminal agent — prompts go to Kimi, its shell runs are outside the guard.",
    present: [".kimi-code", ".kimi"],
    activity: [".kimi-code", ".kimi"],
  },
  {
    id: "grok-build",
    name: "Grok Build",
    kind: "agent-cli",
    guard_host: "grok",
    note: "xAI's terminal agent — its shell, file and web tools run outside the guard.",
    present: [".grok"],
    activity: [".grok/sessions", ".grok"],
  },
  {
    id: "openhands",
    name: "OpenHands",
    kind: "agent-cli",
    note: "Autonomous agent runner — executes code on your machine, outside the guard.",
    present: [".openhands"],
    activity: [".openhands"],
  },
  {
    id: "warp",
    name: "Warp",
    kind: "agent-cli",
    note: "A terminal with a built-in agent — its command runs never reach the guard.",
    present: ["/Applications/Warp.app", ".warp"],
    activity: [".warp", "Library/Application Support/dev.warp.Warp-Stable"],
  },
  {
    id: "zed",
    name: "Zed",
    kind: "editor",
    note: "Editor with a built-in agent panel and its own MCP servers, unseen here.",
    present: ["/Applications/Zed.app", ".config/zed"],
    activity: [".config/zed", "Library/Application Support/Zed"],
  },
  {
    id: "cline",
    name: "Cline",
    kind: "editor",
    note: "A VS Code agent extension — it edits files and runs commands outside the guard.",
    present: ["Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev"],
    activity: ["Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev"],
  },
  {
    id: "roo-code",
    name: "Roo Code",
    kind: "editor",
    note: "A VS Code agent extension (Cline fork) — its tool calls are unseen here.",
    present: ["Library/Application Support/Code/User/globalStorage/rooveterinaryinc.roo-cline"],
    activity: ["Library/Application Support/Code/User/globalStorage/rooveterinaryinc.roo-cline"],
  },
  {
    id: "continue",
    name: "Continue",
    kind: "editor",
    note: "In-editor assistant on your own API keys — spend lands on the provider bill.",
    present: [".continue"],
    activity: [".continue"],
  },
  {
    id: "jetbrains-ai",
    name: "JetBrains IDEs",
    kind: "editor",
    // Presence of the IDE support dir, NOT proof the AI plugin is in use — the
    // note says so rather than implying we detected AI Assistant itself.
    note: "AI Assistant and Junie run inside these IDEs, unseen here.",
    present: ["Library/Application Support/JetBrains"],
    activity: ["Library/Application Support/JetBrains"],
  },
  {
    id: "ollama",
    name: "Ollama",
    kind: "local-model",
    note: "Local models — no cloud egress, but prompts and pulled models are unseen here.",
    present: ["/Applications/Ollama.app", ".ollama"],
    activity: [".ollama/logs", ".ollama/models"],
  },
  {
    id: "lm-studio",
    name: "LM Studio",
    kind: "local-model",
    note: "Local model runner — activity outside Doorman's view.",
    present: ["/Applications/LM Studio.app", ".lmstudio", ".cache/lm-studio"],
    activity: [".lmstudio", ".cache/lm-studio"],
  },
  {
    id: "jan",
    name: "Jan",
    kind: "local-model",
    note: "Local model runner — prompts stay on this computer but are unseen here.",
    present: ["/Applications/Jan.app", "Library/Application Support/Jan"],
    activity: ["Library/Application Support/Jan"],
  },
  {
    id: "gpt4all",
    name: "GPT4All",
    kind: "local-model",
    note: "Local model runner — prompts stay on this computer but are unseen here.",
    present: ["/Applications/gpt4all.app", "Library/Application Support/nomic.ai/GPT4All"],
    activity: ["Library/Application Support/nomic.ai/GPT4All"],
  },
  // AI-FIRST browsers only. Chrome, Edge, Brave and Safari all ship optional
  // assistants, but every Mac has at least one of them and a filesystem probe
  // cannot tell whether the assistant was ever opened — a row for each would be
  // noise on every machine, not a finding.
  {
    id: "comet",
    name: "Comet",
    kind: "browser",
    note: "Perplexity's agentic browser — it can act on any page you are signed into.",
    present: ["/Applications/Comet.app", "Library/Application Support/Comet"],
    activity: ["Library/Application Support/Comet"],
  },
  {
    id: "dia",
    name: "Dia",
    kind: "browser",
    note: "An AI browser — page content is sent to its model as you browse.",
    present: ["/Applications/Dia.app", "Library/Application Support/Dia"],
    activity: ["Library/Application Support/Dia"],
  },
  {
    id: "arc",
    name: "Arc",
    kind: "browser",
    note: "Browser with built-in AI (Max) — page content can be summarized off-machine.",
    present: ["/Applications/Arc.app", "Library/Application Support/Arc"],
    activity: ["Library/Application Support/Arc"],
  },
  {
    id: "perplexity",
    name: "Perplexity",
    kind: "desktop-app",
    note: "Prompts and uploads go to Perplexity, unseen here.",
    present: ["/Applications/Perplexity.app", "Library/Application Support/ai.perplexity.mac"],
    activity: ["Library/Application Support/ai.perplexity.mac"],
  },
  {
    id: "msty",
    name: "Msty",
    kind: "desktop-app",
    note: "Multi-provider chat client — prompts go wherever it is pointed.",
    present: ["/Applications/Msty.app", "Library/Application Support/Msty"],
    activity: ["Library/Application Support/Msty"],
  },
  {
    id: "raycast",
    name: "Raycast",
    kind: "productivity",
    note: "Raycast AI answers from the launcher — prompts leave the Mac, unseen here.",
    present: ["/Applications/Raycast.app", "Library/Application Support/com.raycast.macos"],
    activity: ["Library/Application Support/com.raycast.macos"],
  },
  {
    id: "granola",
    name: "Granola",
    kind: "productivity",
    note: "Transcribes and summarizes meetings — audio and notes leave the Mac.",
    present: ["/Applications/Granola.app", "Library/Application Support/Granola"],
    activity: ["Library/Application Support/Granola"],
  },
  {
    id: "superwhisper",
    name: "superwhisper",
    kind: "productivity",
    note: "Dictation into any app; whether audio stays local depends on its model setting.",
    present: ["/Applications/superwhisper.app", "Documents/superwhisper"],
    activity: ["Documents/superwhisper"],
  },
  {
    id: "grammarly",
    name: "Grammarly",
    kind: "productivity",
    note: "Reads and rewrites text in any app — content is sent to Grammarly.",
    present: ["/Applications/Grammarly Desktop.app", "Library/Application Support/com.grammarly.ProjectLlama"],
    activity: ["Library/Application Support/com.grammarly.ProjectLlama"],
  },
  {
    id: "notion",
    name: "Notion",
    kind: "productivity",
    note: "Notion AI runs inside it, over whatever your workspace holds.",
    present: ["/Applications/Notion.app", "Library/Application Support/Notion"],
    activity: ["Library/Application Support/Notion"],
  },
];

/**
 * Every app id the catalog can name, sorted. This is the stable VOCABULARY an
 * approved-apps list is written in: such a list can only speak about tools
 * this catalog can detect, so the two must be the same list. Exported so the Settings screen, the report and any future policy
 * editor enumerate one source rather than hard-coding names.
 */
export const SHADOW_AI_IDS: readonly string[] = SHADOW_AI_CATALOG.map((e) => e.id)
  .slice()
  .sort();

export interface ShadowAiRow extends ShadowAiTool {
  installed: boolean;
  /** A capture rail: transcripts are read whatever the guard does. */
  captured: boolean;
  /** The guard is wired into this tool's host right now. */
  guarded: boolean;
  /** The guard has an adapter for this tool's host: switching the guard on (or
   * the next boot / doctor pass, if it already is) wires it in. Uncovered AND
   * guardable is the row that deserves a call to action, not a shrug. */
  guardable: boolean;
  /** Newest mtime under the tool's activity paths, ISO — undefined if none. */
  last_active_at?: string;
}

export interface ShadowAiState {
  tools: ShadowAiRow[];
  installed_count: number;
  /** Installed tools Doorman does NOT cover — neither metered nor guarded. */
  uncovered_installed: number;
  /** The subset of those the guard has an adapter for — the actionable number
   * the Radar raises while the guard is OFF; the rest are "coming soon". */
  guardable_uncovered: number;
  active_uncovered: number;
  /**
   * Observation and prevention counted APART (2026-09-10): `covered` is
   * metered OR guarded, which let a capture rail with the guard off read as
   * covered. These three say which it is.
   *  · `guarded_installed` — the guard is wired in: tool calls are held.
   *  · `metered_unguarded` — transcripts are read, tool calls run unchecked.
   *  · `guardable_unguarded` — an adapter exists and is not wired in, metered
   *    or not: what "Wire in" fixes while the guard is on (the Radar's count
   *    in that state), and what switching the guard on fixes while it is off.
   *  · `active_unguarded` — installed, not guarded, active in the window.
   */
  guarded_installed: number;
  metered_unguarded: number;
  guardable_unguarded: number;
  active_unguarded: number;
}

/** Days within which a tool counts as "active" for the roll-up headline. */
export const SHADOW_ACTIVE_DAYS = 14;

/**
 * Roll the catalog up against the probes. `probe(path)` returns whether a path
 * exists; `newestMtime(paths)` returns the newest mtime ms under any of them
 * (0/undefined for none). Both injected so this is pure.
 *
 * `guardedHostIds` are the registered hosts the guard is actually installed
 * into (enforcement.ts `installedGuardHostIds`). That — not a hard-coded flag
 * — is what makes a tool `covered`: the card can never claim coverage the
 * guard does not have, and a host stops being covered the moment its entry is
 * removed.
 *
 * `capturedSourceIds` is the same idea for METERING: the transcript sources
 * registered on this build whose host is present (capture.ts `presentSources`),
 * matched against a row's own id OR its `guard_host`. Register a Cursor
 * descriptor and Cursor's row reads "Captured" with no edit here; remove it
 * and the row stops claiming it. The two built-in rails keep their declared
 * flag because the engine reads them without a descriptor.
 */
export function scanShadowAi(
  probe: (relPath: string) => boolean,
  newestMtimeMs: (relPaths: string[]) => number | undefined,
  now: number = Date.now(),
  guardedHostIds: readonly string[] = [],
  guardableHostIds: readonly string[] = [],
  capturedSourceIds: readonly string[] = [],
): ShadowAiState {
  const guarded = new Set(guardedHostIds);
  const guardableHosts = new Set(guardableHostIds);
  // Catalog ids the engine has actually read sessions for: a REGISTERED source
  // (its id is the catalog id) or an app whose sessions another rail carried.
  // ChatGPT Desktop is the second case — its Codex mode writes rollouts into
  // ~/.codex/sessions stamped `originator: "Codex Desktop"`, so those turns are
  // ALREADY in the ledger, and listing the app as uncovered would be a claim we
  // can see is false.
  const capturedSources = new Set(capturedSourceIds);
  const tools: ShadowAiRow[] = [];
  for (const entry of SHADOW_AI_CATALOG) {
    const installed = entry.present.some((p) => probe(p));
    const mtime = installed ? newestMtimeMs(entry.activity) : undefined;
    const { present: _p, activity: _a, captured: _c, guard_host: _g, ...tool } = entry;
    // A capture rail is covered whatever the guard is doing (its transcripts
    // are read either way); everything else is covered only while the guard
    // is wired into its host.
    const captured =
      entry.captured === true ||
      capturedSources.has(entry.id) ||
      (!!entry.guard_host && capturedSources.has(entry.guard_host));
    const isGuarded = !!entry.guard_host && guarded.has(entry.guard_host);
    // The union, kept for the sort and older readers. It is NOT a single
    // guarantee: read `captured` and `guarded` for what is actually true.
    const covered = captured || isGuarded;
    const guardable = !!entry.guard_host && guardableHosts.has(entry.guard_host);
    // The catalog note describes a tool the guard cannot reach. For every tool
    // Doorman does something for, say what is true RIGHT NOW instead — a
    // captured rail with the guard off is metered but unchecked, and the card
    // must not read "covered" as if it were both.
    const note = captured
      ? isGuarded
        ? "Captured and guarded — transcripts are read, risky tool calls are held before they run."
        : guardable
          ? "Captured — transcripts are read; tool calls run unchecked while the guard is off."
          : // Read, but there is no switch to throw: no adapter exists for this
            // host and none is pending. Saying "while the guard is off" here
            // would promise a control that turning the guard on does not give.
            "Captured — sessions and token usage are read; its tool calls are not something Doorman can hold."
      : isGuarded
        ? "Guarded — tool calls are held and checked before they run. Spend is not metered yet."
        : guardable
          ? "One switch away — the guard can hold and check its tool calls."
          : tool.note;
    tools.push({
      ...tool,
      note,
      covered,
      captured,
      guarded: isGuarded,
      guardable,
      installed,
      ...(mtime && mtime > 0 ? { last_active_at: new Date(mtime).toISOString() } : {}),
    });
  }
  const activeCutoff = now - SHADOW_ACTIVE_DAYS * 86_400_000;
  const installedRows = tools.filter((t) => t.installed);
  const uncovered = installedRows.filter((t) => !t.covered);
  const activeUncovered = uncovered.filter(
    (t) => t.last_active_at && Date.parse(t.last_active_at) >= activeCutoff,
  );
  // What the Radar raises: only the uncovered tools the guard COULD reach —
  // one button covers them. A tool no adapter exists for yet is a roadmap
  // fact ("coming soon"), not a defect the person can act on today.
  const guardableUncovered = uncovered.filter((t) => t.guardable);
  const unguarded = installedRows.filter((t) => !t.guarded);
  const activeUnguarded = unguarded.filter((t) => t.last_active_at && Date.parse(t.last_active_at) >= activeCutoff);
  // Covered rails first (reassurance), then uncovered, each block active-first.
  tools.sort((a, b) => {
    if (a.installed !== b.installed) return a.installed ? -1 : 1;
    if (a.covered !== b.covered) return a.covered ? -1 : 1;
    const aAt = a.last_active_at ?? "";
    const bAt = b.last_active_at ?? "";
    return aAt < bAt ? 1 : aAt > bAt ? -1 : a.name.localeCompare(b.name);
  });
  return {
    tools,
    installed_count: installedRows.length,
    uncovered_installed: uncovered.length,
    guardable_uncovered: guardableUncovered.length,
    active_uncovered: activeUncovered.length,
    guarded_installed: installedRows.length - unguarded.length,
    metered_unguarded: unguarded.filter((t) => t.captured).length,
    guardable_unguarded: unguarded.filter((t) => t.guardable).length,
    active_unguarded: activeUnguarded.length,
  };
}
