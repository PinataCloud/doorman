/* Shared primitives for the Doorman renderer. Classic scripts sharing one
   global scope (no import/export). This file loads first; screens reference
   its top-level consts as bare globals.

   The visual language: Usage & Spend / Event Ledger / Security Radar /
   Settings screens — see the screens for what was deliberately left out. */

const { useState, useEffect, useCallback, useMemo, useRef } = React;

/* Platform wording. `state.platform` is main's HostPlatform ("macos",
   "windows" or "linux"; main/state.ts). Every sentence that names the
   machine, the OS, its notification list or its file browser goes through
   these, so a Mac word can't reach a Linux or Windows window as a literal.
   Unknown or missing platform reads as the neutral wording, never the Mac's. */
const PLATFORM_LABELS = { macos: "macOS", windows: "Windows", linux: "Linux" };

/** "this Mac" on macOS, "this computer" everywhere else. */
function thisMachine(platform) {
  return platform === "macos" ? "this Mac" : "this computer";
}

/** Where a banner that was not clicked ends up. */
function notificationListName(platform) {
  if (platform === "macos") return "Notification Center";
  if (platform === "windows") return "the Windows notification center";
  return "the desktop's notification list";
}

/** The button that opens a folder in the OS file browser. */
const REVEAL_LABELS = { macos: "Reveal in Finder", windows: "Show in Explorer", linux: "Open folder" };
/** The same as a trailing link ("show in Finder →"). */
const REVEAL_LINKS = { macos: "show in Finder", windows: "show in Explorer", linux: "show in folder" };
/** What encrypts the evidence vault: Electron's safeStorage, which is the
 * Keychain on macOS, DPAPI (the signed-in account) on Windows and the
 * desktop keyring on Linux. */
function keyStoreName(platform) {
  if (platform === "macos") return "your Keychain";
  if (platform === "windows") return "your Windows account";
  return "your system keyring";
}

/* The app's icon set — one stroke treatment, so the same concept always
   looks the same. */
const ICONS = {
  overview: "M3 13h8V3H3v10zm0 8h8v-6H3v6zm10 0h8V11h-8v10zm0-18v6h8V3h-8z",
  ledger: "M4 6h16M4 10h16M4 14h16M4 18h10",
  shield: "M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z",
  integrations: "M9 2v6m6-6v6M5 8h14v3a7 7 0 0 1-14 0V8zm7 13v-3",
  settings: "M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6zM4 12h2m12 0h2M12 4v2m0 12v2M6.3 6.3l1.4 1.4m8.6 8.6l1.4 1.4m0-11.4l-1.4 1.4m-8.6 8.6l-1.4 1.4",
  /* Security section siblings: a column chart for Analytics, a rule list with
     a tick for Rules — same stroke treatment as the rest. */
  analytics: "M4 20h16M7 16V10M12 16V5M17 16v-7",
  rules: "M5 7h9M5 12h9M5 17h6M17 6l2 2 4-4",
  /* Doorman AI's mark: a four-point spark. */
  spark: "M12 3l1.8 5.2L19 10l-5.2 1.8L12 17l-1.8-5.2L5 10l5.2-1.8L12 3zM19 16l.8 2.2L22 19l-2.2.8L19 22l-.8-2.2L16 19l2.2-.8L19 16z",
  search: "M11 19a8 8 0 1 0 0-16 8 8 0 0 0 0 16zm10 2l-4.3-4.3",
  external: "M14 3h7v7M21 3l-9 9M19 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V7a2 2 0 0 1 2-2h6",
  /* Disclosure: ONE glyph that rotates, rather than the ▸/▾ character pair it
     replaces — a rotation reads as the same row opening, two characters read
     as two states. */
  chevron: "M9 5l7 7-7 7",
  /* A done step on the rule wizard's rail. */
  check: "M5 12.5l4.5 4.5L19 7",
  /* Outcome glyphs for the feed's leading status circle. Each is drawn WITHOUT
     its own enclosing circle — .glyph already is one, and two concentric rings
     at 26px is a target, not a status. */
  block: "M6 6l12 12M18 6L6 18",
  bang: "M12 6v7M12 17.2v.6",
  eye: "M2 12s3.5-6 10-6 10 6 10 6-3.5 6-10 6-10-6-10-6zM12 14.5a2.5 2.5 0 1 0 0-5 2.5 2.5 0 0 0 0 5z",
  key: "M8 20a4 4 0 1 0 0-8 4 4 0 0 0 0 8zM10.8 13.2L20 4M17 7l2 2M14 10l2 2",
  /* Three dots: the row-actions trigger (ActionMenu). Horizontal, so it
     reads as "more" rather than as a vertical drag handle. */
  more: "M5 12h.01M12 12h.01M19 12h.01",
};

function Icon({ name, size = 18, style, strokeWidth = 1.8, className }) {
  const d = ICONS[name] || "";
  return (
    <svg className={className} width={size} height={size} viewBox="0 0 24 24" fill="none"
      stroke="currentColor" strokeWidth={strokeWidth} strokeLinecap="round" strokeLinejoin="round" style={style}>
      {d.split("M").filter(Boolean).map((seg, i) => <path key={i} d={"M" + seg} />)}
    </svg>
  );
}

/* ---- formatters (kept identical in behaviour to main/lib/format.ts) ----

   There is deliberately NO dollar formatter here. Every figure the
   app shows is a token count measured from the transcripts; a cost derived
   on-device from a bundled rate table is an estimate the app cannot stand
   behind, and a "$4.21" on a tile reads as an invoice. */

const fmtTokens = (v) => {
  if (!Number.isFinite(v) || v <= 0) return "0";
  if (v < 1000) return String(Math.round(v));
  if (v < 1_000_000) return (v / 1000).toFixed(1) + "k";
  if (v < 1_000_000_000) return (v / 1_000_000).toFixed(1) + "M";
  return (v / 1_000_000_000).toFixed(1) + "B";
};

/** Engaged time, human-grained: "12s", "48m", "3h 24m". Never decimals — a
    duration with a decimal point reads as a measurement, not time. */
const fmtDur = (seconds) => {
  if (!Number.isFinite(seconds) || seconds <= 0) return "0m";
  const s = Math.round(seconds);
  if (s < 60) return s + "s";
  const m = Math.round(s / 60);
  if (m < 60) return m + "m";
  const h = Math.floor(m / 60);
  const rem = m % 60;
  return rem > 0 ? h + "h " + rem + "m" : h + "h";
};

/** Axis-tick form of the same: one unit, one token ("45m", "2.5h"). */
const fmtDurShort = (seconds) => {
  if (!Number.isFinite(seconds) || seconds <= 0) return "0";
  if (seconds < 60) return Math.round(seconds) + "s";
  if (seconds < 3600) return Math.round(seconds / 60) + "m";
  const h = seconds / 3600;
  return (h < 10 && h !== Math.round(h) ? h.toFixed(1) : String(Math.round(h))) + "h";
};

const relTime = (iso, now = Date.now()) => {
  if (!iso) return "never";
  const t = Date.parse(iso);
  if (!Number.isFinite(t)) return "never";
  const s = Math.round((now - t) / 1000);
  if (s < 0) return "just now";
  if (s < 60) return s + "s ago";
  const m = Math.round(s / 60);
  if (m < 60) return m + "m ago";
  const h = Math.round(m / 60);
  if (h < 48) return h + "h ago";
  return Math.round(h / 24) + "d ago";
};

const clockTime = (iso) => {
  const t = Date.parse(iso || "");
  if (!Number.isFinite(t)) return "";
  return new Date(t).toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit", hour12: false });
};

/** TODAY / YESTERDAY / weekday+date group label for the ledger list. */
const dayGroupLabel = (iso, now = new Date()) => {
  const t = Date.parse(iso || "");
  if (!Number.isFinite(t)) return "EARLIER";
  const d = new Date(t);
  const key = d.toDateString();
  if (key === now.toDateString()) return "TODAY";
  const yesterday = new Date(now.getTime() - 86400000);
  if (key === yesterday.toDateString()) return "YESTERDAY";
  return d.toLocaleDateString("en-US", { month: "short", day: "numeric" }).toUpperCase();
};

const dayLabel = (iso) => {
  const t = Date.parse(iso + "T00:00:00Z");
  if (!Number.isFinite(t)) return iso;
  return new Date(t).toLocaleDateString("en-US", { weekday: "short", timeZone: "UTC" }).toUpperCase();
};

/** "Mon, Aug 25" — the axis says WED, a tooltip has room to say which one. */
const fullDayLabel = (iso) => {
  const t = Date.parse(iso + "T00:00:00Z");
  if (!Number.isFinite(t)) return iso;
  return new Date(t).toLocaleDateString("en-US", {
    weekday: "short",
    month: "short",
    day: "numeric",
    timeZone: "UTC",
  });
};

/* Rail labels, keyed by TurnSource. The two native rails are written down here
   because a chip has to render before the first snapshot arrives; every other
   rail's label comes from the transcript-source registry in main and is folded
   in by `learnSourceLabels` on each state update — so a newly registered host
   is named by its descriptor, in one place, rather than by a second list here
   that drifts from it. */
const SOURCE_LABELS = { "claude-code": "CLAUDE CODE", codex: "CODEX" };
/* The same names in their own case, for sentences and tooltips (RailMark). */
const SOURCE_NAMES = { "claude-code": "Claude Code", codex: "Codex" };

/** Fold the snapshot's rail labels into SOURCE_LABELS / SOURCE_NAMES.
 * Idempotent; called on every state update. An unknown rail still renders as
 * its own id. */
function learnSourceLabels(capture) {
  const sources = (capture && capture.sources) || {};
  for (const id of Object.keys(sources)) {
    const label = sources[id] && sources[id].label;
    if (label) {
      SOURCE_LABELS[id] = String(label).toUpperCase();
      SOURCE_NAMES[id] = String(label);
    }
  }
}

/** Positional colors for the rails — the theme's validated ramp in its fixed
 * order, indexed by the rail's position in the snapshot's source list, never by
 * a per-host brand color. Same rule as every other categorical series. */
function railColor(state, rail) {
  const ids = Object.keys((state.capture && state.capture.sources) || {});
  const i = ids.indexOf(rail);
  return i >= 0 ? seriesColor(i, rail) : "var(--c-other)";
}

/* ---- Which shipped rules the app SHOWS ------------------------
   A MIRROR of main/guard/rule-scope.ts HIDDEN_RULES — the renderer is a
   separate no-import bundle, so it cannot read main's copy;
   test/rule-scope.test.ts pins the two lists equal. Main already
   drops a hidden rule's findings, modes and guidance from the snapshot; this
   list keeps the renderer's OWN tables (SEC_DETECTORS, RULE_FAMILIES, the
   MCP review controls) from naming a rule the rest of the app has forgotten.
   To bring a family back, delete its ids here AND in rule-scope.ts. */
const HIDDEN_RULES = new Set([
  // Infrastructure & destructive
  "destructive_command", "infra_mutation", "unsafe_fetch_exec", "security_control_disabled",
  "flow_fetch_then_exec", "flow_fetch_then_install", "flow_sql_second_order", "agent_loop",
  // Code & agent config
  "insecure_code_written", "flow_insecure_code_executed", "agent_config_tamper", "guard_tampered",
  // Exfiltration & hidden content
  "exfil_render_link", "invisible_unicode", "injected_instruction", "flow_injection_followed",
  "flow_read_then_send", "egress_new_destination",
  // MCP servers
  "mcp_tool_poisoning", "mcp_tool_changed", "unknown_mcp_server", "mcp_permission",
  // Licensing
  "license_contamination",
]);
function ruleShown(id) {
  return !HIDDEN_RULES.has(id);
}

/* The mirror of main/lib/surface-scope.ts HIDDEN_SURFACES — whole settings
   sections and integration cards held back for now. Delete an id here AND
   there to bring its surface back (test/surface-scope.test.ts). */
const HIDDEN_SURFACES = new Set(["editor_extension", "digests"]);
function surfaceShown(id) {
  return !HIDDEN_SURFACES.has(id);
}

/* ---- Security Radar metadata (labels mirror main/guard/policy.ts) ---- */

const SEC_DETECTORS = {
  credential_in_prompt: {
    label: "Credential in prompt",
    blurb: "A real password or API key was typed into a prompt. It has already gone to the AI provider, so treat it as leaked and replace it.",
  },
  credential_in_tool_arg: {
    label: "Credential in tool argument",
    blurb: "The agent put a real password or API key into a command it was about to run.",
  },
  secret_egress: {
    label: "Secret egress",
    blurb: "One command reads a password or key and sends it out over the network in the same step.",
  },
  env_dump: {
    label: "Environment dump",
    blurb: "A command printed every environment variable at once. API keys usually live there.",
  },
  dotenv_read: {
    label: "Credential file read",
    blurb: "Something read a file whose whole job is holding secrets — .env, ~/.aws/credentials, a private key.",
  },
  hardcoded_credential: {
    label: "Hardcoded credential",
    blurb: "A password or key was written straight into a file, where it will be committed and shared.",
  },
  unsafe_fetch_exec: {
    label: "Download piped into interpreter",
    blurb: "A command downloads something from the internet and runs it immediately, with nobody reading it first.",
  },
  destructive_command: {
    label: "Destructive command",
    blurb: "A command that destroys rather than changes — rm -rf, a force push, dropping a database table.",
  },
  infra_mutation: {
    label: "Infrastructure mutation",
    blurb: "A command that changes live cloud or database infrastructure, not just files on this computer.",
  },
  unrecognized_secret: {
    label: "Unrecognized secret",
    blurb: "A long random-looking string that could be a key, but matches no format we recognise.",
  },
  invisible_unicode: {
    label: "Invisible characters",
    blurb: "Characters you cannot see were hidden in the text — a way to slip instructions past a human reader.",
  },
  exfil_render_link: {
    label: "Data-carrying link",
    blurb: "A link or image whose address carries data out with it the moment something loads it.",
  },
  secret_manager_read: {
    label: "Secret manager read",
    blurb: "A secret was fetched out of a vault: 1Password, AWS Secrets Manager, the macOS Keychain, the system keyring.",
  },
  agent_config_tamper: {
    label: "Agent configuration write",
    blurb: "A change to the files that decide what your AI tools may do on their own — hooks, permissions, shell startup.",
  },
  // radarOnly: evidence-only rules that live outside the guard's policy — they
  // can never hold or block a call, and the Rules table renders them without a
  // mode control. (Session-flow analysis needs the whole transcript, which the
  // per-call guard never has; tool OUTPUT arrives after the call the PreToolUse
  // guard was asked about.)
  injected_instruction: {
    label: "Injected instruction",
    blurb: "Text a tool RETURNED trying to steer the agent — instruction overrides, secrecy demands, credential requests.",
    radarOnly: true,
  },
  insecure_code_written: {
    label: "Insecure code written",
    blurb: "Code on its way to disk contains a known-risky pattern, like running text as code or switching off certificate checks.",
  },
  pii_exposure: {
    label: "Personal data exposed",
    blurb: "A real payment card, bank account or national ID number appeared in the session.",
  },
  license_contamination: {
    label: "License contamination",
    blurb: "Text from a strongly licensed project (GPL, AGPL) landed in a file, which can force the same licence onto your own code.",
  },
  security_control_disabled: {
    label: "Security control switched off",
    blurb: "Something switched off one of the computer's own defences, like the firewall, Gatekeeper, SIP or SELinux.",
  },
  wallet_key_material: {
    label: "Wallet key material",
    blurb: "A crypto seed phrase or private key appeared. Unlike a password this cannot be reset: whoever has it owns the wallet.",
  },
  wallet_address_exposed: {
    label: "Wallet address exposed",
    blurb: "A crypto wallet address appeared. Addresses are public by design, but they reveal who you are and what you hold.",
  },
  wallet_address_tampered: {
    label: "Outside address written",
    blurb: "A wallet address that arrived in tool output — a fetched page, an MCP result — was then written into a file or paid to. The address-poisoning shape, matched on the address itself.",
    radarOnly: true,
  },
  flow_secret_egress: {
    label: "Secret read, then egress",
    blurb: "A credential read in one tool call, a network egress in a later one — the cross-call exfiltration shape.",
    radarOnly: true,
  },
  flow_injection_followed: {
    label: "Injection, then acted on",
    blurb: "Text from outside told the agent to do something, and a later call did it. The detectors say an injection arrived; this says it was obeyed.",
    radarOnly: true,
  },
  flow_fetch_then_exec: {
    label: "Fetched, then executed",
    blurb: "Content downloaded from a non-local URL, then run by a later call — curl|sh split across two steps.",
    radarOnly: true,
  },
  flow_read_then_send: {
    label: "Private data, then sent",
    blurb: "A read from mail/chat/docs followed by an outbound send — the classic assistant exfiltration shape.",
    radarOnly: true,
  },
  flow_fetch_then_install: {
    label: "Fetched, then installed what it named",
    blurb: "Content fetched from outside named a package, and a later call installed it — the supply-chain shape: an untrusted page choosing your dependencies.",
    radarOnly: true,
  },
  flow_insecure_code_executed: {
    label: "Insecure code written, then run",
    blurb: "A file this session wrote with a known-dangerous construct (eval of a variable, pickle.loads, shell=True…) was executed by a later call.",
    radarOnly: true,
  },
  flow_sql_second_order: {
    label: "Database result, then a query",
    blurb: "Data read from a database, then a later query built from it — second-order SQL injection.",
    radarOnly: true,
  },
  unknown_mcp_server: {
    label: "Unapproved MCP server",
    blurb: "A session used an MCP server you haven't recognized. Silent until you recognize at least one.",
    radarOnly: true,
  },
  agent_loop: {
    label: "Agent loop",
    blurb: "The same tool call repeated with identical arguments and nothing changing — with what the repeats cost.",
    radarOnly: true,
  },
  mcp_tool_poisoning: {
    label: "MCP tool poisoning",
    blurb: "Injection patterns in MCP server configs or tool outputs — hidden instruction blocks, cross-tool steering, concealment.",
    radarOnly: true,
  },
  egress_new_destination: {
    label: "New external destination",
    blurb: "The first time this machine sent to an exfil-shaped destination (paste site, webhook, file-share, cloud storage, or an unrecognized host).",
    radarOnly: true,
  },
};

/* The desktop-only ids that are NOT in SEC_DETECTORS' static map but still
   reach the radar: the gateway's description-change (rug pull) row and the
   guard's own integrity row. */
SEC_DETECTORS.mcp_tool_changed = {
  label: "MCP tool description changed",
  blurb: "A routed server changed a tool's description after it was first seen — the rug pull: a tool that turns malicious after it was approved. Its recognition is stale until you review it.",
  radarOnly: true,
};
SEC_DETECTORS.guard_tampered = {
  label: "Guard entry or bundle altered",
  blurb: "The guard's hook entry went missing or was rewritten, or a copied guard file changed — a silent fail-open, until it is restored.",
  radarOnly: true,
};

/* The table above is the complete shipped set so that a hidden rule's words
   are one deletion away from returning; what the app USES is the shown part. */
for (const id of Object.keys(SEC_DETECTORS)) if (!ruleShown(id)) delete SEC_DETECTORS[id];

/* Every rule the app knows, in the families the Rules screen groups by. A
   detector lives in exactly one family; radar-only rules sit in the families
   their evidence belongs to and render without a mode control. Kept as a
   flat list of (family, id) so the screen never has to guess an ordering.
   Written in full and narrowed through ruleShown below: a family
   whose every rule is hidden is not a heading with nothing under it, it is
   gone. */
const RULE_FAMILIES = [
  {
    key: "credentials",
    label: "Credentials & secrets",
    detectors: [
      "credential_in_prompt",
      "credential_in_tool_arg",
      "secret_egress",
      "env_dump",
      "dotenv_read",
      "hardcoded_credential",
      "unrecognized_secret",
      "secret_manager_read",
      "flow_secret_egress",
    ],
  },
  {
    key: "infra",
    label: "Infrastructure & destructive",
    detectors: ["destructive_command", "infra_mutation", "unsafe_fetch_exec", "security_control_disabled", "flow_fetch_then_exec", "flow_fetch_then_install", "flow_sql_second_order", "agent_loop"],
  },
  {
    key: "code",
    label: "Code & agent config",
    detectors: ["insecure_code_written", "flow_insecure_code_executed", "agent_config_tamper"],
  },
  {
    key: "exfil",
    label: "Exfiltration & hidden content",
    detectors: ["exfil_render_link", "invisible_unicode", "injected_instruction", "flow_injection_followed", "flow_read_then_send", "egress_new_destination"],
  },
  {
    key: "mcp",
    label: "MCP servers",
    detectors: ["mcp_tool_poisoning", "mcp_tool_changed", "unknown_mcp_server"],
  },
  {
    key: "wallets",
    label: "Crypto wallets & keys",
    detectors: ["wallet_key_material", "wallet_address_exposed", "wallet_address_tampered"],
  },
  { key: "pii", label: "Personal data", detectors: ["pii_exposure"] },
  { key: "licensing", label: "Licensing", detectors: ["license_contamination"] },
  // The guard's own alarm, in a family of one so it can be hidden or shown on
  // its own; hidden since 2026-09-21 (rule-scope.ts), so this row filters away.
  { key: "guard", label: "Guard integrity", detectors: ["guard_tampered"] },
]
  .map((fam) => ({ ...fam, detectors: fam.detectors.filter(ruleShown) }))
  .filter((fam) => fam.detectors.length > 0);

/* ---- Security levels ---------------------------------------- */

/* The guard's ladder, named once. The INDEX is the rung, which is also how
   many segments of an outcome bar fill — so the bar is the model, not a
   decoration. Mirrors EnforcementMode in main/guard/policy.ts; the per-level
   mode tables themselves are NOT mirrored here (they arrive in the snapshot as
   `state.level_modes`), because a renderer-side copy is a table that can
   disagree with the guard. */
/* `word` is what the rung IS, as the past-tense outcome a row reports
   ("Held"). `verb` is what it DOES, for the sentences that need one ("this
   level would hold it") — without it you get "would held it". */
/* `word` is PRESENT tense — what the rule does, not what it did: the Guardrails
   page is a control panel, and its counts ("5 Block") describe a standing
   posture. The Radar's cards speak of what happened and use the past. */
const RUNGS = [
  {
    mode: "observe",
    word: "Observe",
    verb: "only watch it",
    tip: "Recorded and flagged on the Security Radar. The call goes through untouched.",
  },
  {
    mode: "warn",
    word: "Warn",
    verb: "warn you about it",
    tip: "The action still runs. You get a heads-up naming the rule and what it saw.",
  },
  {
    mode: "ask",
    word: "Hold",
    verb: "hold it",
    tip: "The tool stops and waits for your answer. No answer and it is refused.",
  },
  { mode: "block", word: "Block", verb: "block it", tip: "Refused before it runs. You are not asked." },
];

const RUNG_OF = { observe: 0, warn: 1, ask: 2, block: 3 };

/* The four stops, in ladder order. `blurb` is what the stop DOES, in the words
   a person would use to choose one — never a restatement of its name. */
const SECURITY_LEVELS = [
  {
    id: "relaxed",
    name: "Relaxed",
    blurb: "Nothing is ever held or refused. Everything is still recorded and still shows up on the Radar.",
  },
  {
    id: "watchful",
    name: "Watchful",
    blurb: "A secret in a prompt or a tool call, or personal data on its way out, warns you as it happens. Still nothing is interrupted.",
  },
  {
    id: "protective",
    name: "Protective",
    recommended: true,
    blurb: "A secret leaving this computer, in a prompt or a tool call, and personal data on its way out — held until you answer. Reading or writing credentials gets a heads-up.",
  },
  {
    id: "locked_down",
    name: "Locked down",
    blurb: "Secrets on their way out are refused outright, and reading or writing credentials is held until you answer.",
  },
];

/** The stop a level id names, or Protective's index for anything unknown. */
function levelIndex(id) {
  const i = SECURITY_LEVELS.findIndex((l) => l.id === id);
  return i < 0 ? 2 : i;
}

/**
 * Which level a mode map IS, or null for a hand-edited map that is no level at
 * all — what the control renders as "Custom". The renderer's half of
 * `levelOfModes` in main/guard/policy.ts, over the same table the main process
 * put in the snapshot, so the two cannot drift.
 */
function levelOfModes(modes, levelModes) {
  if (!levelModes) return null;
  for (const level of SECURITY_LEVELS) {
    const want = levelModes[level.id];
    if (!want) continue;
    const ids = Object.keys(want);
    if (ids.every((id) => (modes[id] || "observe") === want[id])) return level.id;
  }
  return null;
}

/**
 * The rules that sit at a rung their level does not put them on — what a level
 * move would overwrite, and the only honest count to put in front of someone
 * before it does.
 */
function handEditedDetectors(modes, levelId, levelModes) {
  const want = (levelModes || {})[levelId];
  if (!want) return [];
  return Object.keys(want).filter((id) => (modes[id] || "observe") !== want[id]);
}

/* Which family each shipped rule belongs to for the LEVEL card. The card shows
   kinds of risk, so it shows the families that actually contain a rule the
   guard can act on — RULE_FAMILIES with its radar-only members dropped, and in
   the order a person reads down them. Kept as a derivation rather than a
   second list so adding a detector to a family reaches both screens. */
function levelCategories(levelModes) {
  const known = (levelModes && levelModes.protective) || {};
  return RULE_FAMILIES.map((fam) => ({
    key: fam.key,
    label: fam.label,
    // A rule belongs here only if the ladder has an opinion about it — which is
    // exactly the set the guard can act on.
    detectors: fam.detectors.filter((id) => known[id] !== undefined),
  })).filter((fam) => fam.detectors.length > 0);
}

/**
 * The one way the renderer turns a detector id into words. Shipped ids read
 * SEC_DETECTORS; a `custom:<id>` reads the rule's own label from the live
 * policy (or the label a finding row recorded when it fired, for a rule since
 * edited or deleted). Never undefined — a row must always be nameable.
 */
function detectorMeta(id, policy, row) {
  const known = SEC_DETECTORS[id];
  if (known) return known;
  const label = (row && row.detector_label) || null;
  if (typeof id === "string" && id.indexOf("custom:") === 0) {
    const rules = (policy && policy.custom_rules) || [];
    const rule = rules.find((r) => "custom:" + r.id === id);
    return {
      label: (rule && rule.label) || label || "Your rule: " + id.slice("custom:".length),
      blurb: (rule && (rule.blurb || describeCustomRule(rule))) || "A rule you wrote. It has since been edited or removed.",
      custom: true,
      rule: rule || null,
      radarOnly: !!(rule && rule.after),
    };
  }
  if (id === "mcp_permission") {
    return { label: "MCP gateway permission", blurb: "A tools/call the gateway held under your per-server read / write / act permissions.", radarOnly: true };
  }
  return { label: label || id, blurb: "", radarOnly: true };
}

/** One sentence for a custom rule with no blurb of its own. */
function describeCustomRule(rule) {
  const parts = [];
  const w = rule.when || {};
  if (w.tool) parts.push("tool matches /" + w.tool + "/");
  if (w.server) parts.push("server matches /" + w.server + "/");
  if (w.command) parts.push("command matches /" + w.command + "/");
  if (w.target) parts.push("target matches /" + w.target + "/");
  if (w.arg) for (const k of Object.keys(w.arg)) parts.push(k + " matches /" + w.arg[k] + "/");
  const when = parts.length ? parts.join(", ") : "any call";
  const after = rule.after ? ", after a " + rule.after.taint.replace(/_/g, " ") + " taint in the same session" : "";
  const scope = rule.scope && rule.scope.cwd_prefix ? ", under " + rule.scope.cwd_prefix : "";
  return "Fires when " + when + after + scope + ".";
}

const SEVERITY_ORDER = ["critical", "high", "medium", "low"];

/* Severity fills for SMALL marks only (the mix meter, row dots). Deliberately
   NOT used as a stacked-chart ramp: four steps this close in lightness are not
   reliably separable as adjacent segments (the house validator fails them as an
   ordinal ramp — hue spread 54°, ΔL 0.05). Every use here sits beside its own
   count in text, so the color is a reinforcement, never the encoding. */
const SEV_FILL = {
  critical: "var(--bad)",
  high: "color-mix(in srgb, var(--bad) 55%, var(--warn))",
  medium: "var(--warn)",
  low: "var(--c-other)",
};

/* What the guard DID, which is the axis the Radar's trend is painted on: three
   status colors that are already this app's outcome vocabulary (blocked = bad,
   held/asked = warn, observed = neutral) and are far apart enough to stack. */
const OUTCOME_META = {
  blocked: { label: "blocked", color: "var(--bad)" },
  held: { label: "held for you", color: "var(--warn)" },
  warned: { label: "warned", color: "var(--gold)" },
  observed: { label: "observed", color: "var(--tan-3)" },
  // A scoped exception of yours let it run. Its own bucket, so
  // a 30-day "allow for this project" is a count you can see, not a silence.
  excepted: { label: "allowed by your exception", color: "var(--tan-2)" },
};

/** How a held call ended. Mirrors ApprovalResolution in main/guard/handshake.ts. */
const RESOLUTION_LABELS = {
  allowed: "you allowed it",
  denied: "you denied it",
  timeout: "nobody answered — denied",
  unattended: "app was closed — the agent's own fallback applied",
  // Not a human decision: nobody could be asked, so the guard returned the
  // agent's deny (Settings → "Deny when Doorman can't ask").
  unavailable: "app was closed — denied, not run",
};

const RESOLUTION_SENTENCE = {
  allowed: "Doorman held the call and you allowed it.",
  denied: "Doorman held the call and you denied it — it never ran.",
  timeout: "Doorman held the call, nobody answered, and it was denied.",
  unattended: "Doorman wasn't running, so the agent's own permission prompt or a warning applied instead.",
  unavailable: "Doorman wasn't running to ask you, so the call was denied — it never ran. Retry it with the app open if it was intended.",
};

/** Which outcome bucket a finding row falls in. */
const findingOutcome = (f) =>
  f.enforced === "deny"
    ? "blocked"
    : f.enforced === "ask"
      ? "held"
      : f.enforced === "warn"
        ? "warned"
        : f.enforced === "excepted"
          ? "excepted"
          : "observed";

/* A MIRROR of main/lib/findings.ts callNeverRan — the renderer is
   a classic script and cannot import main. A call the guard refused, or held
   without a recorded allow, never ran: nothing of it reached a transcript, so
   the record keeps its masked line but offers no VIEW RAW, and NEVER_RAN_NOTE
   sits under it. Kept identical by test/evidence-readable.test.ts. */
const callNeverRan = (f) => {
  if (f.resolution === "denied" || f.resolution === "unavailable") return true;
  const held = f.enforced === "deny" || f.enforced === "ask";
  return held && f.resolution !== "allowed" && f.resolution !== "unattended";
};
const NEVER_RAN_NOTE = "This call was blocked before it ran, so no raw text was produced.";

/** One line naming the exception that let an "excepted" row run. */
const exceptionPhrase = (f) => {
  const x = f && f.exception;
  if (!x) return "your exception let it run";
  const who = x.origin === "approval" ? "an exception you made from the approval panel" : "an exception you wrote";
  const where = x.cwd_prefix ? " for " + (x.cwd_prefix.split("/").filter(Boolean).pop() || x.cwd_prefix) : "";
  const until = x.expires_at ? " until " + new Date(x.expires_at).toLocaleDateString("en-US", { month: "short", day: "numeric" }) : "";
  return who + where + until + " let it run";
};

/* Chart series colors: the theme's validated brand-only ramp, in its fixed
   order (adjacent slots always cross hue families — see theme.css). */
const SERIES_VARS = ["--c1", "--c2", "--c3", "--c4", "--c5", "--c6", "--c7", "--c8"];
const seriesColor = (i, key) =>
  key === "other" ? "var(--c-other)" : `var(${SERIES_VARS[i % SERIES_VARS.length]})`;

/* ---- tiny components ---- */

/**
 * A panel. `hint` is a one-line, sentence-case description that sits beside the
 * title — beautifului.dev's "02 Thinking · Expandable traces — steps, reasoning,
 * search, coding" header. It exists so the sentence explaining a chart can be
 * read BEFORE the chart instead of underneath it in a `.cardnote`, which is
 * where this app kept putting it.
 */
function Card({ title, hint, children, right, className, section }) {
  // `section` names the card for cross-screen links (IntegrationsScreen scrolls
  // `[data-section]` into view). It is an attribute on the card itself, not a
  // wrapper: a wrapper div broke the `.card + .card` stack spacing — the rule
  // saw div siblings, and Integrations lost the gap Settings kept.
  return (
    <div className={"card" + (className ? " " + className : "")} data-section={section || undefined}>
      {title ? (
        <div className="card-head">
          <h3>{title}</h3>
          {hint ? <span className="hint">{hint}</span> : null}
          <span className="spacer" />
          {right || null}
        </div>
      ) : null}
      {children}
    </div>
  );
}

/**
 * Segmented control: N mutually-exclusive views, one inset track, one thumb
 * that travels to the active option.
 *
 * The thumb is positioned by MEASURING the active button rather than by
 * `width / options.length`, because the options here are words of very
 * different lengths ("7 days" vs "Claude Code") and equal thirds would leave
 * the thumb sitting off-centre under every label but one.
 */
function Segmented({ value, options, onPick, ariaLabel }) {
  const trackRef = useRef(null);
  const [thumb, setThumb] = useState(null);

  // Re-measure on selection change, on mount, and on resize — the sidebar is
  // fixed but the window is not, and a wrapped filter bar moves the track.
  useEffect(() => {
    const measure = () => {
      const track = trackRef.current;
      if (!track) return;
      const active = track.querySelector("button.on");
      if (!active) return setThumb(null);
      setThumb({ left: active.offsetLeft, width: active.offsetWidth });
    };
    measure();
    // Web fonts land after first paint and change every label's width.
    const fonts = document.fonts;
    if (fonts && fonts.ready) fonts.ready.then(measure);
    window.addEventListener("resize", measure);
    return () => window.removeEventListener("resize", measure);
  }, [value, options.map((o) => o.key + ":" + (o.count ?? "")).join("|")]);

  return (
    <span className="seg" ref={trackRef} role="radiogroup" aria-label={ariaLabel}>
      <span
        className={"seg-thumb" + (thumb ? "" : " unmeasured")}
        style={thumb ? { width: thumb.width + "px", transform: "translateX(" + thumb.left + "px)" } : undefined}
      />
      {options.map((o) => (
        <button
          key={o.key}
          role="radio"
          aria-checked={value === o.key}
          className={value === o.key ? "on" : ""}
          title={o.title}
          onClick={() => onPick(o.key)}
        >
          {o.label}
          {o.count !== undefined ? <span className="n">{o.count}</span> : null}
        </button>
      ))}
    </span>
  );
}

/**
 * A filter that states its own cost: one chip per value, each wearing a colored
 * dot and the number of rows it would leave you with. Use it only where the
 * dimension has a handful of values — past four, a dropdown (`FilterMenu`,
 * which carries the same counts inside) is the honest shape.
 *
 * A chip whose count is 0 is disabled rather than hidden, so the strip doesn't
 * reflow under the pointer as data arrives.
 */
function DotChips({ value, options, onPick, ariaLabel }) {
  return (
    <span className="chips" role="group" aria-label={ariaLabel}>
      {options.map((o) => {
        const empty = o.count === 0 && o.key !== value;
        return (
          <button
            key={o.key}
            className={"dotchip" + (value === o.key ? " on" : "")}
            aria-pressed={value === o.key}
            disabled={empty}
            title={o.title}
            onClick={() => onPick(o.key)}
          >
            {o.dot ? <span className="dot" style={{ background: o.dot }} /> : null}
            {o.label}
            {o.count !== undefined ? <span className="n">{o.count}</span> : null}
          </button>
        );
      })}
    </span>
  );
}

/* `tip` explains the LABEL, not the number: "covered by plan" and "API
   credits" are settlement terms this app coined, and a tile is where someone
   first meets them. The dotted rule under the words is the only invitation.
   `title` is the whole tile's native tooltip, for the rare tile whose NUMBER
   needs the aside instead. */
function Kpi({ num, label, note, tone, tip, title }) {
  return (
    <div className={"card kpi" + (tone ? " tone-" + tone : "")} title={title}>
      <div className="lab">
        {tip ? (
          <span className="tipword" data-tip={tip} tabIndex={0}>
            {label}
          </span>
        ) : (
          label
        )}
      </div>
      <div className="num">{num}</div>
      {note ? <div className="note">{note}</div> : null}
    </div>
  );
}

/** "▲ 12% vs prior 7d" — hidden entirely when the prior window is empty. */
function Delta({ current, prev, suffix }) {
  if (!(prev > 0) || !Number.isFinite(current)) return null;
  const pct = Math.round(((current - prev) / prev) * 100);
  if (!Number.isFinite(pct) || pct === 0) return <span className="delta">— flat {suffix}</span>;
  const up = pct > 0;
  return (
    <span className={"delta " + (up ? "up" : "down")}>
      {up ? "▲" : "▼"} {Math.abs(pct)}% {suffix}
    </span>
  );
}

function SourceChip({ source }) {
  return <span className={"srclabel src-" + source}>{SOURCE_LABELS[source] || source}</span>;
}

/* The rail's brand mark — the logo a reader already knows, drawn from each
   brand's own single-path SVG on a 0 0 24 24 grid. Keyed by TurnSource: two Anthropic surfaces
   share one mark, as do GitHub's two Copilots. A rail without a mark here
   falls back to the named chip, so a newly registered host is never a blank.

   A row is `{ color, path }` plus two optional flags: `fillRule: "evenodd"`
   when the drawing's holes are holes, and `viewBox` when the brand publishes
   on a grid other than 24 — carried through to the <svg> rather than rewriting
   every coordinate, which is the one step in vendoring a mark that can silently
   deform it. Multi-shape marks are their subpaths concatenated into one `d`. */
const RAIL_MARKS = {
  anthropic: { color: "#D97757", path: "M17.3041 3.541h-3.6718l6.696 16.918H24Zm-10.6082 0L0 20.459h3.7442l1.3693-3.5527h7.0052l1.3693 3.5528h3.7442L10.5363 3.5409Zm-.3712 10.2232 2.2914-5.9456 2.2914 5.9456Z" },
  openai: { color: "#0A0A0A", path: "M22.2819 9.8211a5.9847 5.9847 0 0 0-.5157-4.9108 6.0462 6.0462 0 0 0-6.5098-2.9A6.0651 6.0651 0 0 0 4.9807 4.1818a5.9847 5.9847 0 0 0-3.9977 2.9 6.0462 6.0462 0 0 0 .7427 7.0966 5.98 5.98 0 0 0 .511 4.9107 6.051 6.051 0 0 0 6.5146 2.9001A5.9847 5.9847 0 0 0 13.2599 24a6.0557 6.0557 0 0 0 5.7718-4.2058 5.9894 5.9894 0 0 0 3.9977-2.9001 6.0557 6.0557 0 0 0-.7475-7.0729zm-9.022 12.6081a4.4755 4.4755 0 0 1-2.8764-1.0408l.1419-.0804 4.7783-2.7582a.7948.7948 0 0 0 .3927-.6813v-6.7369l2.02 1.1686a.071.071 0 0 1 .038.052v5.5826a4.504 4.504 0 0 1-4.4945 4.4944zm-9.6607-4.1254a4.4708 4.4708 0 0 1-.5346-3.0137l.142.0852 4.783 2.7582a.7712.7712 0 0 0 .7806 0l5.8428-3.3685v2.3324a.0804.0804 0 0 1-.0332.0615L9.74 19.9502a4.4992 4.4992 0 0 1-6.1408-1.6464zM2.3408 7.8956a4.485 4.485 0 0 1 2.3655-1.9728V11.6a.7664.7664 0 0 0 .3879.6765l5.8144 3.3543-2.0201 1.1685a.0757.0757 0 0 1-.071 0l-4.8303-2.7865A4.504 4.504 0 0 1 2.3408 7.872zm16.5963 3.8558L13.1038 8.364 15.1192 7.2a.0757.0757 0 0 1 .071 0l4.8303 2.7913a4.4944 4.4944 0 0 1-.6765 8.1042v-5.6772a.79.79 0 0 0-.407-.667zm2.0107-3.0231l-.142-.0852-4.7735-2.7818a.7759.7759 0 0 0-.7854 0L9.409 9.2297V6.8974a.0662.0662 0 0 1 .0284-.0615l4.8303-2.7866a4.4992 4.4992 0 0 1 6.6802 4.66zM8.3065 12.863l-2.02-1.1638a.0804.0804 0 0 1-.038-.0567V6.0742a4.4992 4.4992 0 0 1 7.3757-3.4537l-.142.0805L8.704 5.459a.7948.7948 0 0 0-.3927.6813zm1.0976-2.3654l2.602-1.4998 2.6069 1.4998v2.9994l-2.5974 1.4997-2.6067-1.4997Z" },
  github: { color: "#181717", path: "M12 .297c-6.63 0-12 5.373-12 12 0 5.303 3.438 9.8 8.205 11.385.6.113.82-.258.82-.577 0-.285-.01-1.04-.015-2.04-3.338.724-4.042-1.61-4.042-1.61C4.422 18.07 3.633 17.7 3.633 17.7c-1.087-.744.084-.729.084-.729 1.205.084 1.838 1.236 1.838 1.236 1.07 1.835 2.809 1.305 3.495.998.108-.776.417-1.305.76-1.605-2.665-.3-5.466-1.332-5.466-5.93 0-1.31.465-2.38 1.235-3.22-.135-.303-.54-1.523.105-3.176 0 0 1.005-.322 3.3 1.23.96-.267 1.98-.399 3-.405 1.02.006 2.04.138 3 .405 2.28-1.552 3.285-1.23 3.285-1.23.645 1.653.24 2.873.12 3.176.765.84 1.23 1.91 1.23 3.22 0 4.61-2.805 5.625-5.475 5.92.42.36.81 1.096.81 2.22 0 1.606-.015 2.896-.015 3.286 0 .315.21.69.825.57C20.565 22.092 24 17.592 24 12.297c0-6.627-5.373-12-12-12" },
  gemini: { color: "#4285F4", path: "M12 1c0 6.075 4.925 11 11 11-6.075 0-11 4.925-11 11 0-6.075-4.925-11-11-11 6.075 0 11-4.925 11-11z" },
  // xAI (Grok Build). xAI publishes no single-path asset, so this is the
  // mark's SHAPE drawn here — the broken X: one unbroken stroke and one split
  // into two segments — as three subpaths of one fill. Labelled as drawn, the
  // way the Cursor cube and the Gemini star below are.
  xai: { color: "#0A0A0A", path: "M18.3 2h3.2L4.5 22H1.3zM2.5 2h3.2l6.5 7.65H9zM13 14.35h3.2l6.5 7.65H19.5z" },
  /* Vendored from LobeHub's lobe-icons static set (MIT; fetched 2026-09-07 from
     packages/static-svg/icons/{nousresearch,openclaw}.svg) for the two harnesses
     simple-icons does not carry. Both are drawn with the EVEN-ODD rule (the
     lobster's eye rings are holes, the pupils fill back in), which `fillRule`
     hands to the <path>; a mark without the flag keeps the nonzero default. */
  // Nous Research — Hermes Agent's maker; its portrait mark (the same path the
  // set ships for "Hermes Agent" itself). Monochrome, like the OpenAI/xAI marks.
  nousresearch: { color: "#0A0A0A", fillRule: "evenodd", path: "M5.938 12.835c.127-.039.285.02.373.143.028.038.036.092.046.14.003.014-.02.033-.04.05-.124-.098-.24-.194-.354-.291-.011-.01-.016-.027-.025-.042zM8.396 9.412c.195-.032.39-.06.588-.05a.54.54 0 01.148.026c.202.071.402.147.601.224.028.01.05.036.075.055l-.013.027a9.203 9.203 0 01-.26-.089c-.115-.038-.213-.077-.315-.098-.25-.05-.25-.046-.292-.014l.574.144c.275.139.55.276.823.417.042.022.09.057.107.098.026.06.063.076.117.072.066-.006.132-.017.213-.027l-.04.086c.051.08.142.02.216.064-.074.13-.247.09-.334.199l.061.074-.12.087c0 .106-.038.168-.306.243l.026.085-.196.042.07.124h-.25l-.007.137c-.081-.01-.161-.018-.244-.027l-.053.123c-.027-.008-.052-.011-.073-.023-.067-.038-.128-.056-.195.006-.019.017-.063.014-.093.008-.026-.006-.05-.029-.07-.042-.11.095-.11.095-.208.003-.057.046-.12.074-.186.011-.063.027-.123-.02-.178-.014-.07.007-.097-.035-.133-.07l-.13.033c-.013-.236-.194-.19-.34-.203.005-.072.05-.092.095-.094a.474.474 0 01.159.022c.164.05.32.12.496.138.203.021.405.029.601-.015.265-.059.52-.149.707-.365.049-.056.083-.127.117-.195.019-.038.02-.084-.02-.116a1.397 1.397 0 00-.382-.217c.024.12-.031.182-.115.221 0 .014-.004.025 0 .03.08.115.084.16-.007.267a1.39 1.39 0 01-.218.211.477.477 0 01-.641-.05 1.36 1.36 0 01-.133-.152c-.078-.107-.076-.108-.033-.236-.165-.08-.128-.226-.104-.364.008-.05.028-.096.049-.163-.04.014-.067.017-.087.032a.897.897 0 00-.316.357c-.007.016-.01.034-.02.047-.012.015-.034.038-.045.035-.02-.006-.037-.027-.05-.045-.008-.012-.007-.032-.012-.057h-.126l.053-.172a14.82 14.82 0 00-.039-.049l.11-.284c-.06.026-.091.044-.124.051-.03.007-.064 0-.095 0 0-.031-.01-.07.004-.092.149-.22.305-.428.593-.476z M8.06 10.788c-.003-.038-.004-.075.037-.062.016.006.034.048.028.067-.01.04-.038.032-.064-.005z M11.981.009c.226-.012.453-.011.679 0 .247.01.495.024.74.062.401.064.798.157 1.19.273.463.138.92.299 1.356.511a7.31 7.31 0 012.948 2.642c.292.469.536.963.739 1.479.219.556.446 1.11.623 1.683.204.654.329 1.326.458 1.997.097.504.182 1.01.29 1.511.156.722.329 1.44.494 2.16.186.812.4 1.615.63 2.415.102.355.193.713.282 1.072.11.436.202.876.254 1.323.031.278.066.557.073.837a7.56 7.56 0 01-.017.88c-.037.413-.1.818-.226 1.212a5.017 5.017 0 01-.915 1.649l-.13.156.018.023c.043-.023.088-.041.127-.068.2-.138.373-.307.531-.49.4-.46.721-.973.975-1.529a3.59 3.59 0 00.325-1.72c-.024-.424-.097-.834-.3-1.213-.013-.027-.015-.06-.03-.121.05.035.082.048.101.072.107.13.22.258.315.398.33.494.46 1.052.486 1.64a3.75 3.75 0 01-.47 1.97c-.36.655-.887 1.14-1.526 1.506-.193.111-.394.21-.595.308-.157.078-.248.211-.318.365a.522.522 0 00-.033.406.359.359 0 01.013.139c-.005.077-.077.155-.14.162-.054.006-.125-.043-.15-.116a1.206 1.206 0 01-.06-.233c-.04-.314-.155-.6-.308-.87a3.906 3.906 0 00-.73-.91 2.129 2.129 0 00-.897-.524 4.093 4.093 0 00-.692-.131c-.075-.008-.15-.04-.22.01.18.06.363.11.538.18.434.173.82.43 1.18.728.308.255.58.543.794.884.098.155.186.315.227.496.027.123.042.25.067.375.013.062-.002.109-.053.144-.047.033-.122.034-.163-.01a.455.455 0 01-.08-.14c-.03-.073-.038-.159-.078-.225a7.314 7.314 0 00-1.423-1.664c-.16-.137-.329-.26-.537-.323-.376-.114-.753-.203-1.15-.154-.213.025-.427.032-.64.053a1.6 1.6 0 00-.736.278 5.14 5.14 0 00-.834.72c-.329.342-.642.699-.955 1.055-.136.155-.264.319-.314.531a5.227 5.227 0 00-.012.051.096.096 0 01-.09.076h-.31c-.046 0-.082-.048-.072-.094.023-.108.045-.216.07-.324.075-.325.19-.635.368-.917.024-.039.04-.088.104-.08l.01.049.027.077c.28-.435.571-.834.996-1.135.283-.204.584-.378.89-.55a.196.196 0 00-.098-.002c-.162.043-.325.084-.485.134-.402.124-.764.33-1.11.566-.147.1-.298.193-.414.333a7.314 7.314 0 00-1.07 1.767.845.845 0 00-.04.12.075.075 0 01-.072.056h-.494c-.04 0-.062-.051-.036-.082.123-.14.246-.282.377-.415.275-.281.58-.532.777-.884.027-.048.063-.09.095-.135.238-.333.54-.607.818-.902.082-.086.175-.16.26-.24.029-.027.053-.057.079-.085l-.018-.025-.135.041c-.034.017-.07.031-.102.05-.248.144-.494.292-.743.433-.408.23-.825.439-1.209.711-.281.2-.591.358-.889.533-.02.012-.044.015-.08.028-.015-.135.143-.201.108-.336-.033.014-.064.02-.085.038-.111.096-.227.19-.328.296-.148.157-.284.325-.425.488-.125.143-.25.286-.373.431A.153.153 0 019.89 24H8.762a.316.316 0 00.016-.042c.028-.09.085-.172.083-.28-.091-.018-.162.001-.212.077a4.45 4.45 0 00-.136.215c-.01.016-.024.03-.042.03h-.093c-.019 0-.029-.022-.017-.037.071-.088.14-.178.209-.268.001-.002-.006-.012-.012-.024-.014.004-.03.006-.045.013-.176.09-.352.181-.527.274a.363.363 0 01-.168.042H5.202c-.026 0-.039-.036-.019-.053.21-.178.402-.374.558-.605.335-.496.538-1.047.667-1.629.004-.02-.003-.043-.006-.091-.037.048-.059.072-.076.1a1.943 1.943 0 01-.334.415c-.28.258-.59.448-.983.464-.297.012-.588 0-.865-.127-.46-.21-.722-.57-.794-1.072-.025-.17-.017-.171-.182-.219A3.513 3.513 0 011.97 20.6a2.286 2.286 0 01-.808-1.13 3.569 3.569 0 01-.16-1.245c.002-.034.016-.067.024-.1.032.023.046.043.05.066.033.153.059.308.096.46.086.355.257.664.516.92.258.256.571.419.91.532.358.118.717.138 1.07-.016a1.89 1.89 0 00.621-.452c.328-.348.533-.76.648-1.223.009-.034.005-.071.007-.11-.015.006-.026.006-.03.011-.031.05-.064.1-.093.152-.284.502-.679.887-1.196 1.135-.351.17-.718.255-1.11.159a1.607 1.607 0 01-.971-.64 2.006 2.006 0 01-.368-.924 2.903 2.903 0 01.02-.886c.05-.439.466-1.17.742-1.271-.02.063-.035.112-.053.16-.043.116-.097.227-.13.345a1.901 1.901 0 00-.05.82c.033.212.09.416.204.6.147.236.346.407.62.465.11.023.225.014.338.018a.576.576 0 00.386-.131c.164-.128.282-.292.366-.481.168-.375.24-.777.309-1.179.05-.296.093-.594.133-.893.039-.281.071-.563.104-.845.026-.232.048-.464.074-.696.024-.228.052-.455.076-.683.024-.227.047-.455.069-.683.013-.14.022-.28.034-.42l.037-.417c.022-.25.041-.5.065-.748.008-.082-.02-.132-.09-.177a2.46 2.46 0 01-.492-.418c-.1-.109-.188-.228-.282-.342-.035-.042-.056-.097-.116-.118a2.084 2.084 0 00.275.597c.06.092.131.176.196.265.063.086.182.115.234.226-.028.003-.046.01-.06.006a4.74 4.74 0 01-.22-.057 2.71 2.71 0 01-1.287-.819c-.435-.487-.656-1.076-.71-1.723a5.206 5.206 0 01.014-1.06c.072-.602.22-1.186.45-1.745.155-.376.338-.741.526-1.102.205-.393.466-.75.765-1.076.512-.559 1.104-1.024 1.726-1.448.717-.49 1.478-.898 2.277-1.233C8.244.828 8.767.632 9.31.494c.655-.166 1.31-.33 1.982-.415.229-.03.458-.058.688-.07zm-1.847 22.82c-.07.06-.147.111-.207.18-.238.27-.464.549-.668.869l-.044.108a.177.177 0 00.093-.057c.174-.19.351-.378.519-.574.104-.122.195-.255.288-.386.024-.034.03-.08.046-.12l-.027-.02zm1.65-3.695a5.51 5.51 0 00-.653.593l-.37.386a.963.963 0 01-.377.25 1.372 1.372 0 01-.467.09c-.044 0-.087.006-.151.012.028.058.043.097.064.131.15.242.301.482.45.724.136.22.276.438.399.666.068.125.105.267.156.404.077.027.14-.018.202-.048.29-.135.579-.274.867-.412.213-.101.437-.186.636-.31.347-.215.68-.455 1.018-.685.015-.01.026-.028.042-.046-.023-.019-.038-.037-.056-.044-.287-.111-.527-.3-.77-.482a5.319 5.319 0 01-.506-.42 1.757 1.757 0 01-.41-.653c-.019-.049-.045-.095-.075-.156zm-5.847.264c-.06.096-.097.194-.132.293a3.38 3.38 0 01-.555 1.01c-.2.25-.455.412-.762.493-.23.06-.464.076-.7.07-.048-.002-.097.002-.158.005.016.04.021.066.035.085.1.145.23.246.4.295.157.046.316.034.498.023.181-.037.343-.115.485-.234.238-.199.402-.454.536-.732.175-.363.264-.751.342-1.144.01-.053.008-.11.011-.164zm14.945-4.586c.008.029.016.057.027.107.024.155.051.31.072.464.03.219.067.437.078.657.017.344.027.689-.014 1.033-.037.315-.063.633-.116.946a6.153 6.153 0 01-.46 1.518c-.008.018-.01.039-.02.082.047-.03.077-.042.098-.064.085-.083.17-.167.248-.255.271-.305.458-.66.596-1.043.18-.498.228-1.011.145-1.531-.103-.65-.33-1.263-.597-1.881a9.055 9.055 0 00-.024-.055l-.033.022zM5.797 8.29a.26.26 0 00.018.153c.124.251.25.501.379.75.025.049.066.09.03.163-.284.06-.578.119-.88.255.059.038.097.06.132.087.042.032.112.058.09.12-.01.033-.075.048-.117.072.017.01.043.021.067.036.166.102.33.207.447.368.138.192.229.404.188.644-.079.469-.306.85-.69 1.132-.054.04-.106.083-.161.122a.243.243 0 00-.103.245.77.77 0 00.055.195c.083.196.22.35.375.492.083.076.159.164.222.257a.37.37 0 01.025.377c-.023.05-.05.099-.076.148-.03.06-.028.111.022.162.041.042.08.089.112.138.038.058.078.079.147.05a.486.486 0 01.333-.006c.16.046.302.126.444.21.13.077.264.149.4.219.067.035.14.05.219.026.071-.022.124.01.145.076.02.064-.003.108-.074.139-.07.03-.137.063-.209.088-.1.035-.201.073-.314.077-.013-.107.11-.088.127-.159-.206-.126-.643-.145-.801-.034.063.112.035.21-.096.313-.13-.1-.025-.202.002-.3a.209.209 0 00-.249.17c-.015.101.067.216.178.224.108.007.218-.005.326-.012.06-.005.12-.027.199 0-.103.123-.248.127-.357.19.002.05.07.086.019.131-.053.048-.095-.001-.132-.03-.08-.063-.16-.126-.231-.197a.474.474 0 01-.157-.311.52.52 0 00-.043-.172c-.032-.074-.032-.137.033-.19-.018-.03-.028-.053-.045-.072a1.222 1.222 0 01-.196-.369c-.053-.137-.046-.264.048-.381.024-.03.05-.06.064-.095a.664.664 0 00.047-.168c.017-.165-.064-.287-.182-.387-.186-.156-.36-.322-.46-.551-.005-.011-.024-.017-.037-.026-.011.017-.024.027-.025.038-.019.185-.045.37-.052.557-.014.377.058.743.162 1.104.118.41.289.798.488 1.173.267.502.537 1.002.812 1.5.055.098.13.189.208.27.198.202.452.272.724.273.202 0 .404-.006.605-.026.295-.03.59-.073.884-.113.183-.025.365-.057.548-.08.21-.026.38.073.522.21.16.156.305.327.447.5.22.265.397.56.554.867.05.098.07.1.147.03.13-.121.26-.242.394-.36.067-.059.088-.12.067-.213a3.535 3.535 0 01-.085-.796c.002-.157.006-.314.018-.471.015-.224.03-.45.06-.672a59.114 59.114 0 01.362-2.298c.087-.493.182-.984.268-1.477.06-.347.118-.694.162-1.043.034-.273.055-.55.063-.825.011-.332.003-.665.002-.998 0-.077.004-.155-.01-.23-.028-.142-.01-.155-.162-.19a5.826 5.826 0 00-.607-.107c-.146-.018-.207-.053-.221-.19-.006-.049-.025-.098-.041-.146-.009-.025-.024-.048-.046-.09l-.025.264c-.009.096-.029.116-.127.115-.055 0-.11-.008-.164-.008-.476 0-.952-.008-1.426.032-.095.008-.173-.015-.226-.103-.04-.066-.088-.126-.134-.186-.063-.084-.086-.093-.182-.06-.195.068-.388.138-.582.21a2.71 2.71 0 00-.675.394.986.986 0 01-.323.168c-.033.01-.07.008-.127.013.02-.066.024-.114.047-.15.064-.105.135-.205.205-.306.023-.033.049-.063.073-.095l-.015-.023-.201.037c-.146.04-.296.07-.437.122-.148.053-.266.023-.386-.072a3.623 3.623 0 01-.733-.786l-.093-.132zm8.592 8.963l-.147.09c-.22.134-.44.266-.659.402-.093.058-.184.12-.27.188-.085.07-.124.161-.072.272.047.1.093.2.147.294.047.08.124.138.213.147.11.01.228.012.336-.012.217-.05.372-.205.528-.357a.291.291 0 00.087-.308c-.046-.18-.079-.365-.118-.547-.011-.052-.027-.103-.045-.169zm-.257-2.409c-.12.291-.205.597-.325.91-.151.433-.294.87-.435 1.323.036-.01.054-.01.067-.018.261-.16.522-.324.785-.484.054-.033.071-.078.065-.138-.012-.13-.024-.262-.034-.393l-.068-.886c-.008-.103-.02-.206-.029-.31-.009 0-.017-.002-.026-.004zm3.081-8.13l.099.285c.08.231.159.463.24.714l.58 1.952c.187.63.372 1.262.558 1.893.114.382.235.762.343 1.146.072.257.126.519.186.799.044.206.087.413.127.64.034.106.023.226.077.325l.025-.006-.068-.362c-.038-.206-.077-.412-.113-.638-.015-.07-.029-.141-.046-.211-.095-.396-.177-.796-.29-1.187-.196-.685-.413-1.364-.618-2.046-.165-.549-.322-1.1-.488-1.648-.069-.227-.15-.45-.226-.695l-.117-.336c-.037-.107-.075-.216-.115-.322-.04-.106-.084-.21-.127-.314a7.558 7.558 0 01-.027.01zM6.225 14.304c-.063-.001-.115.014-.134.083a.35.35 0 00.41.012 4.533 4.533 0 00-.276-.095zM5.23 11.98c-.026-.027-.057-.048-.075.002-.012.032-.007.07-.01.113.082-.037.082-.037.085-.115zm.062-1.189a.135.135 0 00-.088.056.197.197 0 00-.025.11c.005.152.01.306.026.457a.751.751 0 00.066.218c.061.136.157.167.288.101.055-.027.06-.054.025-.11a4.52 4.52 0 01-.129-.211c-.015-.068-.066-.131-.033-.207.04-.09-.076-.116-.074-.19V10.874c-.003-.038-.006-.087-.056-.083zm-.017-.968a.867.867 0 00-.467.127c-.076.045-.084.07-.05.158.034.087.07.173.115.254.064.117.09.125.21.077a.657.657 0 01.336-.053c.202.022.357.136.504.264l.092.077c.007-.006.014-.013.022-.018-.019-.105-.035-.226-.149-.264-.157-.053-.324-.075-.508-.117l-.24-.005c.24-.169.452-.044.687.009-.063-.115-.153-.147-.23-.193-.082-.05-.17-.092-.25-.144-.06-.037-.12-.08-.072-.172zm10.233.325c-.23-.01-.427.08-.608.211-.034.026-.06.065-.105.117.087.026.15.046.232.065.044-.015.088-.03.13-.046.306-.114.61-.115.904.031.126.063.237.04.366-.005-.02-.031-.03-.054-.045-.071a.986.986 0 00-.448-.273c-.14-.044-.284-.024-.426-.03zM7.99 6.483a.308.308 0 00.002.133c.08.321.156.643.242.962.104.387.27.75.456 1.103.02.037.061.08.098.087a.404.404 0 00.253-.051l-.472-.84c-.23-.448-.405-.92-.579-1.394zM10.397.497c-.2-.008-.405.004-.603.034-.236.035-.47.087-.7.152-.287.08-.569.18-.852.273-.04.013-.074.038-.11.058.028.014.05.018.07.014.287-.068.58-.085.873-.09.134-.002.269.009.402.025.19.024.382.048.57.09.456.104.874.3 1.265.556.464.306.888.66 1.257 1.078.205.232.395.475.56.739.17.274.315.561.449.856.273.601.456 1.232.6 1.876.04.173.07.348.1.524.017.104.065.167.17.19.122.028.2.105.22.251-.003.102-.06.174-.129.24a1.065 1.065 0 00-.268.358.164.164 0 00.083-.039c.08-.086.162-.172.235-.265a.56.56 0 00.13-.333c.009-.05.022-.1.024-.15.007-.124-.017-.15-.143-.168-.025-.004-.049-.014-.073-.015-.082-.007-.125-.063-.137-.131-.033-.198-.004-.355.247-.408.086-.018.174-.03.26-.042.158-.023.315-.053.473-.067.14-.012.19.033.226.167.008.029.018.057.021.087.019.179-.008.225-.141.288-.027.013-.055.024-.078.042a.148.148 0 00-.051.067c-.039.144.073.382.206.445l.673.32c.023.011.05.015.075.023l.018-.026c-.015-.008-.032-.013-.044-.024a2.27 2.27 0 00-.544-.32 4.898 4.898 0 00-.173-.075.203.203 0 01-.126-.191c-.003-.085.045-.154.128-.187l.059-.025c.099-.044.118-.076.112-.187a.384.384 0 00-.008-.063c-.067-.294-.123-.59-.205-.88a9.478 9.478 0 00-.826-2.036 7.465 7.465 0 00-1.39-1.805 4.536 4.536 0 00-1.177-.824 3.656 3.656 0 00-1.016-.328 6.155 6.155 0 00-.712-.074zm6.719 5.955c.01.014.018.028.038.034l-.022-.044-.016.01zM4.103 3.917a.062.062 0 01-.03.012.455.455 0 01-.04.039c-.01.01-.02.02-.045.04l-.363.354c-.088.085-.17.178-.266.253-.284.22-.425.53-.544.855a.132.132 0 00-.007.071c.013.055.033.108.052.168l.074.026c-.017.056-.03.105-.047.152-.058.164-.118.327-.175.491-.005.015.008.036.019.077.08-.175.158-.33.225-.489.228-.544.484-1.074.819-1.561.09-.133.182-.266.283-.401.004-.006.007-.013.022-.03.001-.016.003-.032.015-.04l.008-.017zm12.976 2.408a.023.023 0 01.009.019.073.073 0 00-.006.01.188.188 0 00.007.02l.018.022c.002-.007.007-.016.005-.021-.003-.01-.012-.018-.02-.038a1.331 1.331 0 01-.013-.012zM4.199 4.48c-.003.004-.008.008-.027.014-.005.013-.011.025-.031.047a2.085 2.085 0 01-.124.167c-.048.07-.116.055-.181.041-.134-.028-.228.016-.287.143-.089.187-.187.37-.273.56-.049.108-.11.216-.118.36.081.003.154.007.228.008h.228a2.563 2.563 0 01-.079.264c-.01.052-.022.103-.033.155l.02.004c.018-.046.037-.092.067-.153.066-.142.13-.285.2-.426.02-.04.034-.1.116-.092 0 .043.004.084 0 .124-.005.045-.017.09-.028.143.141.043.086.174.115.269.102-.022.104-.195.248-.144v.205l.017.002.439-1.059c-.13 0-.246-.02-.358.033-.024.011-.058-.001-.108-.004.075-.15.139-.278.211-.417a.128.128 0 01.025-.036c0-.015-.001-.03.008-.038l.006-.02c-.005.006-.01.011-.028.017-.004.012-.009.024-.026.045a.085.085 0 01-.032.033c-.123.157-.09.164-.258.106-.079-.027-.078-.028-.047-.144.028-.046.056-.093.098-.15 0-.016-.001-.032.007-.042L4.2 4.48zm2.073-.67c-.003.006-.007.011-.027.016-.094.125-.194.246-.28.377-.155.238-.301.481-.451.723-.14.224-.345.368-.575.481-.017.008-.04.006-.079.011.012-.059.016-.109.033-.153a6.076 6.076 0 01.229-.518l-.007-.02a.138.138 0 01-.035.025c-.028.05-.055.1-.093.164-.26.424-.443.817-.442.95.024.004.048.011.073.013.177.013.188.007.26-.165.03-.07.077-.12.147-.15l.175-.07c.044-.018.085-.057.146-.032.003.05-.01.11.014.145.042.062.044.125.047.193.002.049.017.098.026.147.029-.034.039-.065.05-.097.142-.39.277-.782.428-1.17.1-.256.22-.504.33-.756.013-.03.013-.067.03-.092V3.81zm3.987-.34c0 .045.01.084.021.123.042.16.094.318.124.48.024.133.023.27.028.406 0 .033-.019.067-.032.11-.094-.058-.047-.158-.106-.215h-.125c-.015.072-.01.152-.046.2-.066.085-.155.154-.236.227-.043.038-.078.018-.103-.025l-.046-.087c-.065.035-.117.069-.172.093-.116.051-.235.095-.35.147-.085.038-.09.053-.07.147.014.075.034.148.047.223.013.072.05.109.123.124.233.05.462.115.657.265.058-.102.058-.102.168-.151.03-.014.06-.03.092-.042.08-.03.115-.017.15.06.023.048.041.098.066.158.06-.14-.042-.267.017-.416.157.18.24.39.375.567a.235.235 0 00.022-.098c.002-.124 0-.247.002-.371 0-.034.013-.067.02-.1l.032-.003c.11.155.13.354.226.52a3.036 3.036 0 00-.01-.392c-.004-.045 0-.074.05-.088.08.036.116.14.215.158-.03-.275-.423-1.137-.798-1.635-.114-.127-.2-.28-.34-.386zm-2.667.696c-.019.034-.03.05-.037.067-.061.185-.125.37-.18.556-.031.105-.087.169-.195.19-.09.019-.178.052-.268.073-.038.009-.089.015-.118-.003-.024-.016-.025-.069-.036-.106-.064.076-.082.087-.17.047-.133-.062-.262-.135-.393-.201-.048-.025-.093-.063-.17-.03-.043.12-.091.25-.137.382-.099.28-.087.242.095.453.046.048.102.03.154.023.054-.009.106-.03.16-.036.13-.013.26-.08.367-.015.204-.064.387-.122.571-.178.05-.015.089.005.114.054.022.042.034.093.082.121.038-.056-.013-.128.063-.178l.14.241-.042-1.46zm.278.358c-.096-.01-.107.01-.11.108-.002.038-.003.078.002.115.03.2.099.386.174.57.002.006.012.01.022.015l.078-.05c.052.036.081.088.153.088.205-.002.41.014.616.012.099-.001.158.042.205.12.018.03.024.077.088.066l-.08-.394c-.05-.195-.085-.395-.172-.589-.057.057-.114.068-.18.046a.72.72 0 00-.135-.028c-.22-.028-.44-.059-.66-.08zm10.254-1.727c.089.163.155.316.139.491-.016.168.026.342-.044.516-.047-.033-.088-.082-.112-.075-.117.035-.164-.057-.227-.115a4.772 4.772 0 01-.286-.29l-.104-.113a4.856 4.856 0 01-.023.019c.035.046.07.093.11.156.04.064.084.127.122.193.034.058.065.118.031.205-.082-.01-.164-.019-.246-.032-.06-.01-.101 0-.124.07-.031.098-.037.096-.15.09.02.042.036.08.057.116.041.074.03.138-.03.196-.06.06-.118.122-.178.181a.175.175 0 01-.185.046c-.222-.061-.447-.113-.67-.174-.032-.009-.063-.04-.086-.068-.03-.04-.052-.087-.08-.13-.044-.07-.09-.138-.136-.207a.18.18 0 00-.014.105c.012.127.03.253.035.38.005.1-.024.12-.121.104-.104-.017-.206-.04-.31-.058-.064-.012-.131-.028-.202.03l.081.208c.09 0 .166-.01.237.002a.819.819 0 01.458.251c.078.083.154.168.241.26l.018-.005c-.004-.006-.008-.013-.01-.04.014-.056-.062-.118.018-.178.031.03.064.057.088.09.058.078.111.159.169.257l.089.141.024-.013a2093.819 2093.819 0 01-.427-.934c.055.007.083.007.108.016.193.07.385.142.577.216.074.028.147.06.219.094.062.028.112.018.157-.033.05-.056.102-.112.154-.167.05-.051.095-.046.132.014.016.025.026.053.04.08.071.138.143.277.217.433l.159.308.025-.011c-.044-.106-.07-.218-.138-.334-.057-.182-.168-.346-.206-.545.136.034.362.326.567.732l.057.074.018-.011a1.563 1.563 0 01-.052-.127c-.046-.145-.097-.29-.136-.436-.022-.083-.036-.173.022-.26l.109.058-.026-.207.027-.016c.022.02.05.036.065.06.073.108.143.22.215.33.01.016.029.029.043.043-.036-.217-.2-.38-.229-.626l.155.112c.014-.166.012-.319.042-.465.032-.158-.023-.297-.063-.445.024.004.036.006.055.025.092.124.183.249.277.371.02.027.05.047.069.087l.04.063.019-.015a.293.293 0 01-.053-.082 27.922 27.922 0 01-.332-.49c-.221-.311-.363-.467-.485-.521zm-6.57.327c-.003.161.092.275.069.415l-.368.087c.09.139.032.237-.052.331-.05.057-.092.122-.143.178-.037.04-.046.078-.018.126l.16.275c.029.048.072.066.128.064.076-.003.152 0 .228-.001.116-.003.216.022.275.137.006.014.02.024.044.052.004-.059-.003-.098.01-.13.016-.04.04-.099.072-.108.084-.023.173-.024.26-.03.013-.001.027.018.04.029l.071.065c.019-.11-.082-.198-.024-.31l.126.04c-.026-.123-.07-.245-.071-.366 0-.123.051-.243.115-.36.107.062.16.156.234.253.183.265.36.533.494.834.165-.078.27.068.407.088-.003-.106-.133-.441-.197-.492a.142.142 0 00-.102-.028c-.06.011-.119.039-.191.063-.025-.039-.056-.078-.077-.122a3.936 3.936 0 00-.473-.783c-.076-.094-.16-.182-.228-.26l-.391.285c-.049.035-.094.03-.132-.017l-.169-.207c-.025-.03-.053-.059-.097-.108z" },
  // OpenClaw's lobster, flat-filled at the midpoint of its brand gradient
  // (#FF4D4D → #991B1B) — a registry entry carries one colour, not a gradient.
  openclaw: { color: "#CC3434", fillRule: "evenodd", path: "M9.046 7.104a.527.527 0 110 1.055.527.527 0 010-1.055z M15.376 7.104a.528.528 0 110 1.056.528.528 0 010-1.056z M16.877 1.912c.58-.27 1.14-.323 1.616-.037a.317.317 0 01-.326.542c-.227-.136-.547-.153-1.022.068-.352.165-.765.45-1.234.866 2.683 1.17 4.4 3.5 5.148 5.921a6.421 6.421 0 00-.704.184c-.578.016-1.174.204-1.502.735-.338.55-.268 1.276.072 2.069l.005.012.007.014c.523 1.045 1.318 1.91 2.2 2.284-.912 3.274-3.44 6.144-5.972 6.988v2.109h-2.11v-2.11c-1.043.417-2.086.01-2.11 0v2.11h-2.11v-2.11c-2.531-.843-5.061-3.713-5.973-6.987.882-.373 1.678-1.238 2.2-2.284l.007-.014.006-.012c.34-.793.41-1.518.071-2.069-.327-.531-.923-.719-1.503-.735a6.409 6.409 0 00-.704-.183c.749-2.421 2.466-4.751 5.149-5.922-.47-.416-.88-.701-1.234-.866-.474-.221-.794-.204-1.021-.068a.318.318 0 01-.435-.109.317.317 0 01.109-.433c.476-.286 1.036-.233 1.615.037.49.229 1.031.628 1.621 1.182A9.924 9.924 0 0112 2.568c1.199 0 2.284.19 3.256.526.59-.554 1.13-.953 1.62-1.182zM8.835 6.577a1.266 1.266 0 100 2.532 1.266 1.266 0 000-2.532zm6.33 0a1.267 1.267 0 100 2.533 1.267 1.267 0 000-2.533z M.395 13.118c-.966-1.932-.163-3.863 2.41-3.365v-.001l.05.01c.084.018.17.038.26.06.033.009.067.017.1.027.084.022.168.048.255.076l.09.027c.528 0 .95.158 1.16.501.212.343.212.87-.105 1.61-.085.17-.178.333-.276.489l-.01.017a4.967 4.967 0 01-.62.791l-.019.02c-1.092 1.117-2.496 1.336-3.295-.262z M21.193 9.753c2.574-.5 3.378 1.433 2.411 3.365-.58 1.159-1.476 1.361-2.342.96l-.011-.005a2.419 2.419 0 01-.114-.056l-.019-.01a2.751 2.751 0 01-.115-.067l-.023-.014c-.035-.022-.071-.044-.106-.068l-.05-.035c-.55-.388-1.062-1.007-1.44-1.76-.276-.647-.311-1.132-.174-1.472.176-.439.636-.639 1.23-.639.032-.011.066-.02.099-.03.08-.026.16-.05.238-.072l.117-.03a5.502 5.502 0 01.3-.067z" },
  /* Vendored from simple-icons (CC0) at the versions recorded in
     docs/shipped-surface.md. */
  // GitHub Copilot's own mark, for the two Copilot rails and the VS Code row.
  githubcopilot: { color: "#000000", path: "M23.922 16.997C23.061 18.492 18.063 22.02 12 22.02 5.937 22.02.939 18.492.078 16.997A.641.641 0 0 1 0 16.741v-2.869a.883.883 0 0 1 .053-.22c.372-.935 1.347-2.292 2.605-2.656.167-.429.414-1.055.644-1.517a10.098 10.098 0 0 1-.052-1.086c0-1.331.282-2.499 1.132-3.368.397-.406.89-.717 1.474-.952C7.255 2.937 9.248 1.98 11.978 1.98c2.731 0 4.767.957 6.166 2.093.584.235 1.077.546 1.474.952.85.869 1.132 2.037 1.132 3.368 0 .368-.014.733-.052 1.086.23.462.477 1.088.644 1.517 1.258.364 2.233 1.721 2.605 2.656a.841.841 0 0 1 .053.22v2.869a.641.641 0 0 1-.078.256Zm-11.75-5.992h-.344a4.359 4.359 0 0 1-.355.508c-.77.947-1.918 1.492-3.508 1.492-1.725 0-2.989-.359-3.782-1.259a2.137 2.137 0 0 1-.085-.104L4 11.746v6.585c1.435.779 4.514 2.179 8 2.179 3.486 0 6.565-1.4 8-2.179v-6.585l-.098-.104s-.033.045-.085.104c-.793.9-2.057 1.259-3.782 1.259-1.59 0-2.738-.545-3.508-1.492a4.359 4.359 0 0 1-.355-.508Zm2.328 3.25c.549 0 1 .451 1 1v2c0 .549-.451 1-1 1-.549 0-1-.451-1-1v-2c0-.549.451-1 1-1Zm-5 0c.549 0 1 .451 1 1v2c0 .549-.451 1-1 1-.549 0-1-.451-1-1v-2c0-.549.451-1 1-1Zm3.313-6.185c.136 1.057.403 1.913.878 2.497.442.544 1.134.938 2.344.938 1.573 0 2.292-.337 2.657-.751.384-.435.558-1.15.558-2.361 0-1.14-.243-1.847-.705-2.319-.477-.488-1.319-.862-2.824-1.025-1.487-.161-2.192.138-2.533.529-.269.307-.437.808-.438 1.578v.021c0 .265.021.562.063.893Zm-1.626 0c.042-.331.063-.628.063-.894v-.02c-.001-.77-.169-1.271-.438-1.578-.341-.391-1.046-.69-2.533-.529-1.505.163-2.347.537-2.824 1.025-.462.472-.705 1.179-.705 2.319 0 1.211.175 1.926.558 2.361.365.414 1.084.751 2.657.751 1.21 0 1.902-.394 2.344-.938.475-.584.742-1.44.878-2.497Z" },
  windsurf: { color: "#0B100F", path: "M23.55 5.067c-1.2038-.002-2.1806.973-2.1806 2.1765v4.8676c0 .972-.8035 1.7594-1.7597 1.7594-.568 0-1.1352-.286-1.4718-.7659l-4.9713-7.1003c-.4125-.5896-1.0837-.941-1.8103-.941-1.1334 0-2.1533.9635-2.1533 2.153v4.8957c0 .972-.7969 1.7594-1.7596 1.7594-.57 0-1.1363-.286-1.4728-.7658L.4076 5.1598C.2822 4.9798 0 5.0688 0 5.2882v4.2452c0 .2147.0656.4228.1884.599l5.4748 7.8183c.3234.462.8006.8052 1.3509.9298 1.3771.313 2.6446-.747 2.6446-2.0977v-4.893c0-.972.7875-1.7593 1.7596-1.7593h.003a1.798 1.798 0 0 1 1.4718.7658l4.9723 7.0994c.4135.5905 1.05.941 1.8093.941 1.1587 0 2.1515-.9645 2.1515-2.153v-4.8948c0-.972.7875-1.7594 1.7596-1.7594h.194a.22.22 0 0 0 .2204-.2202v-4.622a.22.22 0 0 0-.2203-.2203Z" },
  // Qwen Code is Alibaba's; the Qwen models ship under Alibaba Cloud.
  alibabacloud: { color: "#FF6A00", path: "M3.996 4.517h5.291L8.01 6.324 4.153 7.506a1.668 1.668 0 0 0-1.165 1.601v5.786a1.668 1.668 0 0 0 1.165 1.6l3.857 1.183 1.277 1.807H3.996A3.996 3.996 0 0 1 0 15.487V8.513a3.996 3.996 0 0 1 3.996-3.996m16.008 0h-5.291l1.277 1.807 3.857 1.182c.715.227 1.17.889 1.165 1.601v5.786a1.668 1.668 0 0 1-1.165 1.6l-3.857 1.183-1.277 1.807h5.291A3.996 3.996 0 0 0 24 15.487V8.513a3.996 3.996 0 0 0-3.996-3.996m-4.007 8.345H8.002v-1.804h7.995Z" },
  warp: { color: "#01A4FF", path: "M12.035 2.723h9.253A2.712 2.712 0 0 1 24 5.435v10.529a2.712 2.712 0 0 1-2.712 2.713H8.047Zm-1.681 2.6L6.766 19.677h5.598l-.399 1.6H2.712A2.712 2.712 0 0 1 0 18.565V8.036a2.712 2.712 0 0 1 2.712-2.712Z" },
  zedindustries: { color: "#084CCF", path: "M2.25 1.5a.75.75 0 0 0-.75.75v16.5H0V2.25A2.25 2.25 0 0 1 2.25 0h20.095c1.002 0 1.504 1.212.795 1.92L10.764 14.298h3.486V12.75h1.5v1.922a1.125 1.125 0 0 1-1.125 1.125H9.264l-2.578 2.578h11.689V9h1.5v9.375a1.5 1.5 0 0 1-1.5 1.5H5.185L2.562 22.5H21.75a.75.75 0 0 0 .75-.75V5.25H24v16.5A2.25 2.25 0 0 1 21.75 24H1.655C.653 24 .151 22.788.86 22.08L13.19 9.75H9.75v1.5h-1.5V9.375A1.125 1.125 0 0 1 9.375 8.25h5.314l2.625-2.625H5.625V15h-1.5V5.625a1.5 1.5 0 0 1 1.5-1.5h13.19L21.438 1.5z" },
  jetbrains: { color: "#000000", path: "M2.345 23.997A2.347 2.347 0 0 1 0 21.652V10.988C0 9.665.535 8.37 1.473 7.433l5.965-5.961A5.01 5.01 0 0 1 10.989 0h10.666A2.347 2.347 0 0 1 24 2.345v10.664a5.056 5.056 0 0 1-1.473 3.554l-5.965 5.965A5.017 5.017 0 0 1 13.007 24v-.003H2.345Zm8.969-6.854H5.486v1.371h5.828v-1.371ZM3.963 6.514h13.523v13.519l4.257-4.257a3.936 3.936 0 0 0 1.146-2.767V2.345c0-.678-.552-1.234-1.234-1.234H10.989a3.897 3.897 0 0 0-2.767 1.145L3.963 6.514Zm-.192.192L2.256 8.22a3.944 3.944 0 0 0-1.145 2.768v10.664c0 .678.552 1.234 1.234 1.234h10.666a3.9 3.9 0 0 0 2.767-1.146l1.512-1.511H3.771V6.706Z" },
  ollama: { color: "#000000", path: "M16.361 10.26a.894.894 0 0 0-.558.47l-.072.148.001.207c0 .193.004.217.059.353.076.193.152.312.291.448.24.238.51.3.872.205a.86.86 0 0 0 .517-.436.752.752 0 0 0 .08-.498c-.064-.453-.33-.782-.724-.897a1.06 1.06 0 0 0-.466 0zm-9.203.005c-.305.096-.533.32-.65.639a1.187 1.187 0 0 0-.06.52c.057.309.31.59.598.667.362.095.632.033.872-.205.14-.136.215-.255.291-.448.055-.136.059-.16.059-.353l.001-.207-.072-.148a.894.894 0 0 0-.565-.472 1.02 1.02 0 0 0-.474.007Zm4.184 2c-.131.071-.223.25-.195.383.031.143.157.288.353.407.105.063.112.072.117.136.004.038-.01.146-.029.243-.02.094-.036.194-.036.222.002.074.07.195.143.253.064.052.076.054.255.059.164.005.198.001.264-.03.169-.082.212-.234.15-.525-.052-.243-.042-.28.087-.355.137-.08.281-.219.324-.314a.365.365 0 0 0-.175-.48.394.394 0 0 0-.181-.033c-.126 0-.207.03-.355.124l-.085.053-.053-.032c-.219-.13-.259-.145-.391-.143a.396.396 0 0 0-.193.032zm.39-2.195c-.373.036-.475.05-.654.086-.291.06-.68.195-.951.328-.94.46-1.589 1.226-1.787 2.114-.04.176-.045.234-.045.53 0 .294.005.357.043.524.264 1.16 1.332 2.017 2.714 2.173.3.033 1.596.033 1.896 0 1.11-.125 2.064-.727 2.493-1.571.114-.226.169-.372.22-.602.039-.167.044-.23.044-.523 0-.297-.005-.355-.045-.531-.288-1.29-1.539-2.304-3.072-2.497a6.873 6.873 0 0 0-.855-.031zm.645.937a3.283 3.283 0 0 1 1.44.514c.223.148.537.458.671.662.166.251.26.508.303.82.02.143.01.251-.043.482-.08.345-.332.705-.672.957a3.115 3.115 0 0 1-.689.348c-.382.122-.632.144-1.525.138-.582-.006-.686-.01-.853-.042-.57-.107-1.022-.334-1.35-.68-.264-.28-.385-.535-.45-.946-.03-.192.025-.509.137-.776.136-.326.488-.73.836-.963.403-.269.934-.46 1.422-.512.187-.02.586-.02.773-.002zm-5.503-11a1.653 1.653 0 0 0-.683.298C5.617.74 5.173 1.666 4.985 2.819c-.07.436-.119 1.04-.119 1.503 0 .544.064 1.24.155 1.721.02.107.031.202.023.208a8.12 8.12 0 0 1-.187.152 5.324 5.324 0 0 0-.949 1.02 5.49 5.49 0 0 0-.94 2.339 6.625 6.625 0 0 0-.023 1.357c.091.78.325 1.438.727 2.04l.13.195-.037.064c-.269.452-.498 1.105-.605 1.732-.084.496-.095.629-.095 1.294 0 .67.009.803.088 1.266.095.555.288 1.143.503 1.534.071.128.243.393.264.407.007.003-.014.067-.046.141a7.405 7.405 0 0 0-.548 1.873c-.062.417-.071.552-.071.991 0 .56.031.832.148 1.279L3.42 24h1.478l-.05-.091c-.297-.552-.325-1.575-.068-2.597.117-.472.25-.819.498-1.296l.148-.29v-.177c0-.165-.003-.184-.057-.293a.915.915 0 0 0-.194-.25 1.74 1.74 0 0 1-.385-.543c-.424-.92-.506-2.286-.208-3.451.124-.486.329-.918.544-1.154a.787.787 0 0 0 .223-.531c0-.195-.07-.355-.224-.522a3.136 3.136 0 0 1-.817-1.729c-.14-.96.114-2.005.69-2.834.563-.814 1.353-1.336 2.237-1.475.199-.033.57-.028.776.01.226.04.367.028.512-.041.179-.085.268-.19.374-.431.093-.215.165-.333.36-.576.234-.29.46-.489.822-.729.413-.27.884-.467 1.352-.561.17-.035.25-.04.569-.04.319 0 .398.005.569.04a4.07 4.07 0 0 1 1.914.997c.117.109.398.457.488.602.034.057.095.177.132.267.105.241.195.346.374.43.14.068.286.082.503.045.343-.058.607-.053.943.016 1.144.23 2.14 1.173 2.581 2.437.385 1.108.276 2.267-.296 3.153-.097.15-.193.27-.333.419-.301.322-.301.722-.001 1.053.493.539.801 1.866.708 3.036-.062.772-.26 1.463-.533 1.854a2.096 2.096 0 0 1-.224.258.916.916 0 0 0-.194.25c-.054.109-.057.128-.057.293v.178l.148.29c.248.476.38.823.498 1.295.253 1.008.231 2.01-.059 2.581a.845.845 0 0 0-.044.098c0 .006.329.009.732.009h.73l.02-.074.036-.134c.019-.076.057-.3.088-.516.029-.217.029-1.016 0-1.258-.11-.875-.295-1.57-.597-2.226-.032-.074-.053-.138-.046-.141.008-.005.057-.074.108-.152.376-.569.607-1.284.724-2.228.031-.26.031-1.378 0-1.628-.083-.645-.182-1.082-.348-1.525a6.083 6.083 0 0 0-.329-.7l-.038-.064.131-.194c.402-.604.636-1.262.727-2.04a6.625 6.625 0 0 0-.024-1.358 5.512 5.512 0 0 0-.939-2.339 5.325 5.325 0 0 0-.95-1.02 8.097 8.097 0 0 1-.186-.152.692.692 0 0 1 .023-.208c.208-1.087.201-2.443-.017-3.503-.19-.924-.535-1.658-.98-2.082-.354-.338-.716-.482-1.15-.455-.996.059-1.8 1.205-2.116 3.01a6.805 6.805 0 0 0-.097.726c0 .036-.007.066-.015.066a.96.96 0 0 1-.149-.078A4.857 4.857 0 0 0 12 3.03c-.832 0-1.687.243-2.456.698a.958.958 0 0 1-.148.078c-.008 0-.015-.03-.015-.066a6.71 6.71 0 0 0-.097-.725C8.997 1.392 8.337.319 7.46.048a2.096 2.096 0 0 0-.585-.041Zm.293 1.402c.248.197.523.759.682 1.388.03.113.06.244.069.292.007.047.026.152.041.233.067.365.098.76.102 1.24l.002.475-.12.175-.118.178h-.278c-.324 0-.646.041-.954.124l-.238.06c-.033.007-.038-.003-.057-.144a8.438 8.438 0 0 1 .016-2.323c.124-.788.413-1.501.696-1.711.067-.05.079-.049.157.013zm9.825-.012c.17.126.358.46.498.888.28.854.36 2.028.212 3.145-.019.14-.024.151-.057.144l-.238-.06a3.693 3.693 0 0 0-.954-.124h-.278l-.119-.178-.119-.175.002-.474c.004-.669.066-1.19.214-1.772.157-.623.434-1.185.68-1.382.078-.062.09-.063.159-.012z" },
  // Perplexity, and Comet — Perplexity's browser — under the same mark.
  perplexity: { color: "#1FB8CD", path: "M22.3977 7.0896h-2.3106V.0676l-7.5094 6.3542V.1577h-1.1554v6.1966L4.4904 0v7.0896H1.6023v10.3976h2.8882V24l6.932-6.3591v6.2005h1.1554v-6.0469l6.9318 6.1807v-6.4879h2.8882V7.0896zm-3.4657-4.531v4.531h-5.355l5.355-4.531zm-13.2862.0676 4.8691 4.4634H5.6458V2.6262zM2.7576 16.332V8.245h7.8476l-6.1149 6.1147v1.9723H2.7576zm2.8882 5.0404v-3.8852h.0001v-2.6488l5.7763-5.7764v7.0111l-5.7764 5.2993zm12.7086.0248-5.7766-5.1509V9.0618l5.7766 5.7766v6.5588zm2.8882-5.0652h-1.733v-1.9723L13.3948 8.245h7.8478v8.087z" },
  raycast: { color: "#FF6363", path: "M6.004 15.492v2.504L0 11.992l1.258-1.249Zm2.504 2.504H6.004L12.008 24l1.253-1.253zm14.24-4.747L24 11.997 12.003 0 10.75 1.251 15.491 6h-2.865L9.317 2.692 8.065 3.944l2.06 2.06H8.691v9.31H18v-1.432l2.06 2.06 1.252-1.252-3.312-3.32V8.506ZM6.63 5.372 5.38 6.625l1.342 1.343 1.251-1.253Zm10.655 10.655-1.247 1.251 1.342 1.343 1.253-1.251zM3.944 8.059 2.692 9.31l3.312 3.314v-2.506zm9.936 9.937h-2.504l3.314 3.312 1.25-1.252z" },
  grammarly: { color: "#027E6F", path: "M12 24H.032V12c0-3.314 1.341-6.314 3.504-8.486C5.703 1.344 8.694 0 12 0c3.305 0 6.297 1.344 8.463 3.514 2.164 2.172 3.505 5.172 3.505 8.486s-1.338 6.314-3.505 8.486C18.297 22.656 15.305 24 12 24m2.889-13.137-1.271 2.205h4.418c-.505 2.882-3.018 5.078-6.036 5.078-3.38 0-6.132-2.757-6.132-6.146S8.618 5.854 12 5.854c1.821 0 3.458.801 4.584 2.069l1.143-1.988c-1.493-1.418-3.506-2.29-5.725-2.29-4.6 0-8.332 3.74-8.332 8.355s3.73 8.354 8.332 8.354c4.603 0 8.332-3.739 8.332-8.354 0-.387-.029-.765-.079-1.137z" },
  notion: { color: "#000000", path: "M4.459 4.208c.746.606 1.026.56 2.428.466l13.215-.793c.28 0 .047-.28-.046-.326L17.86 1.968c-.42-.326-.981-.7-2.055-.607L3.01 2.295c-.466.046-.56.28-.374.466zm.793 3.08v13.904c0 .747.373 1.027 1.214.98l14.523-.84c.841-.046.935-.56.935-1.167V6.354c0-.606-.233-.933-.748-.887l-15.177.887c-.56.047-.747.327-.747.933zm14.337.745c.093.42 0 .84-.42.888l-.7.14v10.264c-.608.327-1.168.514-1.635.514-.748 0-.935-.234-1.495-.933l-4.577-7.186v6.952L12.21 19s0 .84-1.168.84l-3.222.186c-.093-.186 0-.653.327-.746l.84-.233V9.854L7.822 9.76c-.094-.42.14-1.026.793-1.073l3.456-.233 4.764 7.279v-6.44l-1.215-.139c-.093-.514.28-.887.747-.933zM1.936 1.035l13.31-.98c1.634-.14 2.055-.047 3.082.7l4.249 2.986c.7.513.934.653.934 1.213v16.378c0 1.026-.373 1.634-1.68 1.726l-15.458.934c-.98.047-1.448-.093-1.962-.747l-3.129-4.06c-.56-.747-.793-1.306-.793-1.96V2.667c0-.839.374-1.54 1.447-1.632z" },
  // Amazon Q Developer and Kiro CLI (ex Amazon Q CLI) are AWS products.
  aws: { color: "#232F3E", path: "M6.763 10.036c0 .296.032.535.088.71.064.176.144.368.256.576.04.063.056.127.056.183 0 .08-.048.16-.152.24l-.503.335a.383.383 0 0 1-.208.072c-.08 0-.16-.04-.239-.112a2.47 2.47 0 0 1-.287-.375 6.18 6.18 0 0 1-.248-.471c-.622.734-1.405 1.101-2.347 1.101-.67 0-1.205-.191-1.596-.574-.391-.384-.59-.894-.59-1.533 0-.678.239-1.23.726-1.644.487-.415 1.133-.623 1.955-.623.272 0 .551.024.846.064.296.04.6.104.918.176v-.583c0-.607-.127-1.03-.375-1.277-.255-.248-.686-.367-1.3-.367-.28 0-.568.031-.863.103-.295.072-.583.16-.862.272a2.287 2.287 0 0 1-.28.104.488.488 0 0 1-.127.023c-.112 0-.168-.08-.168-.247v-.391c0-.128.016-.224.056-.28a.597.597 0 0 1 .224-.167c.279-.144.614-.264 1.005-.36a4.84 4.84 0 0 1 1.246-.151c.95 0 1.644.216 2.091.647.439.43.662 1.085.662 1.963v2.586zm-3.24 1.214c.263 0 .534-.048.822-.144.287-.096.543-.271.758-.51.128-.152.224-.32.272-.512.047-.191.08-.423.08-.694v-.335a6.66 6.66 0 0 0-.735-.136 6.02 6.02 0 0 0-.75-.048c-.535 0-.926.104-1.19.32-.263.215-.39.518-.39.917 0 .375.095.655.295.846.191.2.47.296.838.296zm6.41.862c-.144 0-.24-.024-.304-.08-.064-.048-.12-.16-.168-.311L7.586 5.55a1.398 1.398 0 0 1-.072-.32c0-.128.064-.2.191-.2h.783c.151 0 .255.025.31.08.065.048.113.16.16.312l1.342 5.284 1.245-5.284c.04-.16.088-.264.151-.312a.549.549 0 0 1 .32-.08h.638c.152 0 .256.025.32.08.063.048.12.16.151.312l1.261 5.348 1.381-5.348c.048-.16.104-.264.16-.312a.52.52 0 0 1 .311-.08h.743c.127 0 .2.065.2.2 0 .04-.009.08-.017.128a1.137 1.137 0 0 1-.056.2l-1.923 6.17c-.048.16-.104.263-.168.311a.51.51 0 0 1-.303.08h-.687c-.151 0-.255-.024-.32-.08-.063-.056-.119-.16-.15-.32l-1.238-5.148-1.23 5.14c-.04.16-.087.264-.15.32-.065.056-.177.08-.32.08zm10.256.215c-.415 0-.83-.048-1.229-.143-.399-.096-.71-.2-.918-.32-.128-.071-.215-.151-.247-.223a.563.563 0 0 1-.048-.224v-.407c0-.167.064-.247.183-.247.048 0 .096.008.144.024.048.016.12.048.2.08.271.12.566.215.878.279.319.064.63.096.95.096.502 0 .894-.088 1.165-.264a.86.86 0 0 0 .415-.758.777.777 0 0 0-.215-.559c-.144-.151-.416-.287-.807-.415l-1.157-.36c-.583-.183-1.014-.454-1.277-.813a1.902 1.902 0 0 1-.4-1.158c0-.335.073-.63.216-.886.144-.255.335-.479.575-.654.24-.184.51-.32.83-.415.32-.096.655-.136 1.006-.136.175 0 .359.008.535.032.183.024.35.056.518.088.16.04.312.08.455.127.144.048.256.096.336.144a.69.69 0 0 1 .24.2.43.43 0 0 1 .071.263v.375c0 .168-.064.256-.184.256a.83.83 0 0 1-.303-.096 3.652 3.652 0 0 0-1.532-.311c-.455 0-.815.071-1.062.223-.248.152-.375.383-.375.71 0 .224.08.416.24.567.159.152.454.304.877.44l1.134.358c.574.184.99.44 1.237.767.247.327.367.702.367 1.117 0 .343-.072.655-.207.926-.144.272-.336.511-.583.703-.248.2-.543.343-.886.447-.36.111-.734.167-1.142.167zM21.698 16.207c-2.626 1.94-6.442 2.969-9.722 2.969-4.598 0-8.74-1.7-11.87-4.526-.247-.223-.024-.527.272-.351 3.384 1.963 7.559 3.153 11.877 3.153 2.914 0 6.114-.607 9.06-1.852.439-.2.814.287.383.607zM22.792 14.961c-.336-.43-2.22-.207-3.074-.103-.255.032-.295-.192-.063-.36 1.5-1.053 3.967-.75 4.254-.399.287.36-.08 2.826-1.485 4.007-.215.184-.423.088-.327-.151.32-.79 1.03-2.57.695-2.994z" },
  /* Vendored from LobeHub's lobe-icons static set (MIT; fetched 2026-09-08 from
     packages/static-svg/icons/) — the AI-tool marks neither simple-icons nor
     the sets above carry. Each is the set's monochrome file, its subpaths
     concatenated into the one `path` a registry row holds; a file drawn with
     the even-odd rule says so, or Cline's eyes fill in solid. */
  // Amp — Sourcegraph's agent (ampcode.com), in its own red.
  amp: { color: "#F34E3F", path: "M15.087 23.18L12.03 24l-2.097-7.823-5.738 5.738-2.251-2.251 5.718-5.719-7.769-2.082.82-3.057 11.294 3.08 3.08 11.295z M19.505 18.762l-3.057.82-2.564-9.573-9.572-2.564.819-3.057 11.295 3.079 3.08 11.295z M23.893 14.374l-3.057.82-2.565-9.572L8.7 3.057 9.52 0l11.295 3.08 3.079 11.294z" },
  cline: { color: "#0A0A0A", fillRule: "evenodd", path: "M17.035 3.991c2.75 0 4.98 2.24 4.98 5.003v1.667l1.45 2.896a1.01 1.01 0 01-.002.909l-1.448 2.864v1.668c0 2.762-2.23 5.002-4.98 5.002H7.074c-2.751 0-4.98-2.24-4.98-5.002V17.33l-1.48-2.855a1.01 1.01 0 01-.003-.927l1.482-2.887V8.994c0-2.763 2.23-5.003 4.98-5.003h9.962zM8.265 9.6a2.274 2.274 0 00-2.274 2.274v4.042a2.274 2.274 0 004.547 0v-4.042A2.274 2.274 0 008.265 9.6zm7.326 0a2.274 2.274 0 00-2.274 2.274v4.042a2.274 2.274 0 104.548 0v-4.042A2.274 2.274 0 0015.59 9.6z M12.054 5.558a2.779 2.779 0 100-5.558 2.779 2.779 0 000 5.558z" },
  // Goose is Block's; the mark is the goose, not the Block square.
  goose: { color: "#0A0A0A", fillRule: "evenodd", path: "M21.595 23.61c1.167-.254 2.405-.944 2.405-.944l-2.167-1.784a12.124 12.124 0 01-2.695-3.131 12.127 12.127 0 00-3.97-4.049l-.794-.462a1.115 1.115 0 01-.488-.815.844.844 0 01.154-.575c.413-.582 2.548-3.115 2.94-3.44.503-.416 1.065-.762 1.586-1.159.074-.056.148-.112.221-.17.003-.002.007-.004.009-.007.167-.131.325-.272.45-.438.453-.524.563-.988.59-1.193-.061-.197-.244-.639-.753-1.148.319.02.705.272 1.056.569.235-.376.481-.773.727-1.171.165-.266-.08-.465-.086-.471h-.001V3.22c-.007-.007-.206-.25-.471-.086-.567.35-1.134.702-1.639 1.021 0 0-.597-.012-1.305.599a2.464 2.464 0 00-.438.45l-.007.009c-.058.072-.114.147-.17.221-.397.521-.743 1.083-1.16 1.587-.323.391-2.857 2.526-3.44 2.94a.842.842 0 01-.574.153 1.115 1.115 0 01-.815-.488l-.462-.794a12.123 12.123 0 00-4.049-3.97 12.133 12.133 0 01-3.13-2.695L1.332 0S.643 1.238.39 2.405c.352.428 1.27 1.49 2.34 2.302C1.58 4.167.73 3.75.06 3.4c-.103.765-.063 1.92.043 2.816.726.317 1.961.806 3.219 1.066-1.006.236-2.11.278-2.961.262.15.554.358 1.119.64 1.688.119.263.25.52.39.77.452.125 2.222.383 3.164.171l-2.51.897a27.776 27.776 0 002.544 2.726c2.031-1.092 2.494-1.241 4.018-2.238-2.467 2.008-3.108 2.828-3.8 3.67l-.483.678c-.25.351-.469.725-.65 1.117-.61 1.31-1.47 4.1-1.47 4.1-.154.486.202.842.674.674 0 0 2.79-.861 4.1-1.47.392-.182.766-.4 1.118-.65l.677-.483c.227-.187.453-.37.701-.586 0 0 1.705 2.02 3.458 3.349l.896-2.511c-.211.942.046 2.712.17 3.163.252.142.509.272.772.392.569.28 1.134.49 1.688.64-.016-.853.026-1.956.261-2.962.26 1.258.75 2.493 1.067 3.219.895.106 2.051.146 2.816.043a73.87 73.87 0 01-1.308-2.67c.811 1.07 1.874 1.988 2.302 2.34h-.001z" },
  // Kimi Code is Moonshot's; the K wears the wordmark's ink, not the accent
  // blue that belongs to the dot alone.
  kimi: { color: "#0A0A0A", path: "M21.846 0a1.923 1.923 0 110 3.846H20.15a.226.226 0 01-.227-.226V1.923C19.923.861 20.784 0 21.846 0z M11.065 11.199l7.257-7.2c.137-.136.06-.41-.116-.41H14.3a.164.164 0 00-.117.051l-7.82 7.756c-.122.12-.302.013-.302-.179V3.82c0-.127-.083-.23-.185-.23H3.186c-.103 0-.186.103-.186.23V19.77c0 .128.083.23.186.23h2.69c.103 0 .186-.102.186-.23v-3.25c0-.069.025-.135.069-.178l2.424-2.406a.158.158 0 01.205-.023l6.484 4.772a7.677 7.677 0 003.453 1.283c.108.012.2-.095.2-.23v-3.06c0-.117-.07-.212-.164-.227a5.028 5.028 0 01-2.027-.807l-5.613-4.064c-.117-.078-.132-.279-.028-.381z" },
  // LM Studio's stack is two-tone; a row carries one colour, so this is the
  // full-width bars — the silhouette — without the lighter overlay.
  lmstudio: { color: "#0A0A0A", path: "M2.84 2a1.273 1.273 0 100 2.547h14.107a1.273 1.273 0 100-2.547H2.84zM7.935 5.33a1.273 1.273 0 000 2.548H22.04a1.274 1.274 0 000-2.547H7.935zM3.624 9.935c0-.704.57-1.274 1.274-1.274h14.106a1.274 1.274 0 010 2.547H4.898c-.703 0-1.274-.57-1.274-1.273zM1.273 12.188a1.273 1.273 0 100 2.547H15.38a1.274 1.274 0 000-2.547H1.273zM3.624 16.792c0-.704.57-1.274 1.274-1.274h14.106a1.273 1.273 0 110 2.547H4.898c-.703 0-1.274-.57-1.274-1.273zM13.029 18.849a1.273 1.273 0 100 2.547h9.698a1.273 1.273 0 100-2.547h-9.698z" },
  opencode: { color: "#0A0A0A", path: "M16 6H8v12h8V6zm4 16H4V2h16v20z" },
  // OpenHands, from the colour file's fill layer: the hands without the
  // outline pass, which is 4× the path data and invisible at 15px.
  openhands: { color: "#0A0A0A", path: "M4.75 6.313c.743 0 1.083.357 1.083 1.94 0-1.374.449-1.551.993-1.552.544 0 .9.455.84 1.803-.074 1.719-.235 2.57-.297 3.755-.195 3.751.477 2.62.552 2.432.185-.467.756-1.56 1.559-2.193 1.003-.792 1.504.2 1.348.475-.178.308-.978 1.533-1.348 2.775-.296.994-1.003 2.004-1.56 2.457-1.136.925-3.832 1.004-5.364.317C1.023 17.835.722 16.321.6 15.748c-.211-.99 0-2.07 0-2.59 0-.58-.158-2.335-.21-2.936-.073-.84.166-1.214.694-1.25.406-.026.943.225.943 1.086V8.267c0-.714.614-.98.92-.98.307 0 .903.083.904.98V7.37c0-.528.278-1.056.898-1.057zM19.25 6.313c.62 0 .899.53.899 1.057v.897c0-.896.596-.98.903-.98.306 0 .92.266.92.98v1.791c0-.861.539-1.112.944-1.085.529.035.768.41.695 1.25-.052.6-.212 2.355-.212 2.935 0 .52.212 1.6 0 2.59-.122.573-.423 2.087-1.955 2.774-1.533.687-4.227.608-5.364-.317-.557-.453-1.263-1.463-1.56-2.457-.37-1.242-1.17-2.467-1.347-2.775-.157-.275.344-1.268 1.348-.475.803.634 1.374 1.726 1.559 2.193.075.189.745 1.32.55-2.432-.062-1.186-.221-2.036-.296-3.755-.06-1.348.296-1.802.84-1.803.544 0 .994.177.994 1.553 0-1.583.338-1.94 1.082-1.94z" },
  // Roo Code (the Cline fork) — its kangaroo.
  roocode: { color: "#0A0A0A", fillRule: "evenodd", path: "M20.113 5.5l-.442 1.557a.157.157 0 01-.196.106l-7.414-2.157a.16.16 0 00-.143.028l-7.342 5.74a.159.159 0 01-.074.032l-4.37.656a.154.154 0 00-.132.162l.02.245c.005.078.071.14.152.141l5.074.128.058.002 3.75-1.953a.16.16 0 01.164.01l2.657 1.847a.152.152 0 01.066.125l-.023 2.45c0 .032.01.063.028.089l3.737 5.227c.03.04.077.065.129.065h1.182a.153.153 0 00.14-.224l-2.664-4.919a.15.15 0 01.005-.152l1.389-2.169a.156.156 0 01.062-.055l4.965-2.456a.16.16 0 01.158.01l1.418.921a.16.16 0 00.087.026h1.289c.125 0 .2-.136.13-.237l-3.578-5.29c-.074-.109-.246-.082-.282.044z" },
  /* Vendored from simple-icons (CC0), `simple-icons@15`, fetched 2026-09-08. */
  // Arc's published brand hex is a pale pink (#FCBFBD) that disappears against
  // this card, so the mark is drawn in the app's ink like the monochrome marks
  // around it — the shape is the logo, the colour is ours and said so.
  arc: { color: "#0A0A0A", path: "M23.9371 8.5089c.1471-.7147.0367-1.4661-.3364-2.0967-.4203-.7094-1.1035-1.1876-1.9075-1.3506a2.9178 2.9178 0 0 0-.5623-.0578h-.0105c-1.3768 0-2.5329.988-2.8061 2.3385-.1629.7935-.4782 1.5607-.9196 2.2701a.263.263 0 0 1-.2363.1205.2627.2627 0 0 1-.2209-.1468l-2.8587-5.9906c-.3626-.762-1.0142-1.361-1.8235-1.5975-1.3873-.4099-2.8166.2838-3.4052 1.524L5.897 9.7333c-.0788.1629-.31.1576-.3784-.0053v-.0052a2.8597 2.8597 0 0 0-2.6642-1.7972c-.3784 0-.7515.0736-1.1088.2207-1.4714.6148-2.1283 2.349-1.5187 3.8203.557 1.3295 1.4714 2.5855 2.659 3.668.084.0788.1103.1997.063.3048l-.9563 2.0074c-.6727 1.4188-.1314 3.1477 1.2664 3.8571.4099.2049.846.31 1.298.31 1.1035 0 2.123-.6411 2.5959-1.6395l.825-1.7289a.254.254 0 0 1 .3048-.1366c1.0037.2732 2.0127.4204 3.0058.4204 1.1193 0 2.2229-.1682 3.2896-.4782a.2626.2626 0 0 1 .3101.1366l.8145 1.7131c.4834 1.0195 1.4924 1.7131 2.6169 1.7184.4572 0 .8986-.0999 1.3138-.3101 1.403-.7094 1.939-2.4435 1.2664-3.8676L19.875 15.787c-.0473-.1051-.0263-.226.0578-.3048 1.9864-1.8497 3.4525-4.2723 4.0043-6.9733ZM6.2121 20.0172a1.835 1.835 0 0 1-.6764.7622 1.8352 1.8352 0 0 1-.9788.2835c-.2733 0-.5518-.063-.8093-.1891-.9038-.4467-1.2454-1.5713-.8093-2.4804l.7935-1.6658c.0684-.1471.2575-.1997.3837-.1051.1681.1209.3415.2365.5202.3521.6989.4467 1.4293.825 2.1808 1.1351.1419.0578.205.2154.1419.352l-.7462 1.5555Zm5.0763-2.0442c-4.2092 0-8.6548-2.8534-10.1262-6.4951a1.8286 1.8286 0 0 1 1.009-2.3805c.2259-.0893.4571-.1366.683-.1366.7252 0 1.4084.431 1.6974 1.1456.9196 2.2806 4.0043 4.2092 6.7368 4.2092.4204 0 .8408-.042 1.256-.1156a.2643.2643 0 0 1 .2837.1419l1.3768 2.9007c.0683.1471-.0105.3205-.1629.3626-.8986.2365-1.8182.3678-2.7536.3678Zm-.599-4.9291.6358-1.3348c.0526-.1051.205-.1051.2575 0l.6201 1.3033c.042.0841-.0158.1891-.1051.2049-.268.0368-.536.0578-.7988.0578a5.0634 5.0634 0 0 1-.4887-.0263c-.1103-.0157-.1629-.1208-.1208-.2049Zm8.4604 7.8246a1.831 1.831 0 0 1-2.0329-.2788 1.8292 1.8292 0 0 1-.4316-.5778l-4.987-10.4836c-.0998-.2102-.3994-.2102-.4939 0l-1.545 3.2529a.2623.2623 0 0 1-.3205.1366c-1.051-.3626-2.0495-.9774-2.7904-1.7184a.2552.2552 0 0 1-.0473-.2943l3.3421-7.031c.1156-.247.2943-.4677.5203-.6201 1.051-.6884 2.2806-.2575 2.7378.7041l6.8577 14.4248c.4309.9144.0946 2.0389-.8093 2.4856Zm-1.4451-9.6481a.258.258 0 0 1 .0315-.2732c.783-1.0037 1.3558-2.1756 1.6028-3.421.1734-.867.9354-1.4714 1.7919-1.4714.1472 0 .2943.0158.4467.0526.9722.2417 1.5344 1.2507 1.3295 2.2333-.4835 2.3017-1.6816 4.3879-3.3159 6.0222-.1313.1314-.3468.0946-.4256-.0683l-1.4609-3.0742Z" },
  /* Vendored from thesvg (MIT, glincker/thesvg; fetched 2026-09-08 via the
     Iconify API) for the three no other set carries. These are drawn on their
     own grids, which `viewBox` carries rather than rewriting every coordinate. */
  // Continue's hexagon glyph alone — the set draws it on a light disc, which is
  // the favicon's background rather than part of the mark.
  continue: { color: "#33333B", viewBox: "0 0 300 300", path: "m206.97 92.797l-9.19 15.932l23.229 40.203c.17.305.272.678.272 1.017s-.102.712-.272 1.017l-23.229 40.237l9.19 15.933L240 149.949l-33.03-57.186zm-12.751 13.864l9.19-15.932h-18.38l-9.19 15.932h18.414zm-18.414 4.136l21.466 37.118h18.38l-21.432-37.118zm18.414 78.372l21.432-37.152h-18.38l-21.466 37.152zm-18.414 4.136l9.19 15.864h18.38l-9.19-15.864h-18.414zm-62.296 19.797c-.373 0-.712-.102-1.017-.272a1.97 1.97 0 0 1-.747-.745l-23.263-40.238h-18.38L103.132 229h66.026l-9.19-15.898zm50.02-2.068l9.19 15.898l9.19-15.932l-9.19-15.932l-9.19 15.932zm5.629-18h-42.864l-9.19 15.932h42.864zM122.699 191l-21.466-37.153l-9.19 15.933l21.466 37.152zm-52.631-23.288h18.38l9.19-15.932H79.292zm41.576-79.763c.169-.305.441-.576.746-.746s.678-.27 1.017-.27H159.9L169.09 71h-66.06L70 128.186h18.38l23.196-40.203zM97.638 148.22l-9.19-15.932h-18.38l9.19 15.932zm15.803-55.118L92.009 130.22l9.19 15.933l21.432-37.119zm46.493-2.068h-42.932l9.19 15.932h42.932zm12.785 13.864L181.875 89l-9.156-15.932l-9.19 15.898z" },
  granola: { color: "#1E1E1E", viewBox: "0 0 32 32", path: "M15.826 31.914c3.3 0 6.76-.732 8.153-1.746c.89-.634 1.332-.572 2.125-1.33c.22-.222.317-.287.38-.35c3.013-2.476 4.759-5.68 4.759-9.836c0-6.76-4.79-11.36-11.644-11.36c-6.029 0-10.63 3.838-10.63 8.756c0 4.474 3.49 7.678 8.47 7.678c.287 0 .415-.159.732-.159c1.207 0 2.19-.348 2.825-1.014c.317-.348.92-1.048.983-1.08c.286-.255.348-.634.414-.793c.062-.158.19-.255.255-.476c.062-.255-.031-.572-.031-.855c0-.507.22-1.014.22-1.49c0-1.331-1.586-2.666-3.014-2.666c-.159 0-.159-.128-.255-.128c-.097 0-.19.097-.286.097c-.097 0-.221-.159-.349-.159s-.19.128-.38.128c-.413 0-.444.062-.761.062a1 1 0 0 0-.318.062c-.127.062-.127.159-.255.159q-.255 0-.255.096c0 .349.031.287-.128.287q-.255 0-.317.03c-.128.063-.031.221-.159.318c-.127.062-.158.159-.19.348c-.03.19-.22.255-.22.445c0 .097.031.159.031.22c0 .19-.38.128-.38.318c0 .128.097.22.097.349c0 .096-.062.158-.062.255c0 .096.062.158.062.22c0 .16-.22.19-.22.318c0 .127.127.22.127.317c0 .062-.097.097-.097.19s-.03-.062.16.22c.127.19.127.287 0 .445c-.128.16-.38.256-.697.256c-1.332 0-1.49-1.366-2.222-1.587c-.22-.062-.255-.096-.255-.19c0-.093 0-.062.128-.19c.127-.127.158-.22.158-.317c0-.096 0-.127-.062-.19c-.255-.413-.38-.92-.38-1.49c0-2.917 3.553-5.362 6.92-5.362c1.014 0 .855.255 1.459.255c.158 0 .096 0 .317-.031c.572-.097 1.617.127 2.442.538c2.283 1.142 3.776 3.839 3.776 6.98c0 5.364-4.76 9.265-11.105 9.265c-3.46 0-5.84-1.08-8.188-3.712c-.255-.286.127.063-.287-.665c-.507-.89-.444-.318-.444-.318c-.16-.19-.445-.73-.604-.92c-.19-.221-.445-.19-.538-.318c-.128-.158.062-.445 0-.603c-.062-.255-.604-.635-.666-.825s-.286-1.396-.286-1.617c0-.255.19-.286.19-.445c0-.22-.287-.286-.445-.604c-.159-.317-.255-1.048-.255-1.841c0-.414 0-.573.127-1.525c.031-.317.507-.317.507-.665c0-.128-.062-.287-.062-.38c0-.127 0-.159.031-.255c1.331-5.584 7.298-9.74 13.93-9.74c2.284 0 4.029.414 6.726 1.556c.89.379 2.19-.287 2.19-.983c.062-.221-.062-.287-.096-.414c-.032-.128-.16-.287-.287-.318c-.062-.03-.096-.127-.158-.22c-.097-.159-.19-.221-.445-.287a.47.47 0 0 1-.256-.127a.74.74 0 0 0-.286-.255c-.127-.063-.22 0-.286-.031c-.062-.032-.097-.097-.159-.128c-.03-.031-.096-.031-.19-.031c-3.2-1.714-5.294-1.97-8.084-1.97c-6.029 0-11.423 2.604-14.754 7.14c-.287.38-.128 1.014-.538 1.397C1.74 9.353.757 13.35.757 15.89c0 2.124.507 4.949 1.173 6.504c1.3 3.046.731 1.777.92 2.063c.38.603.698.665.856.855c0 0 .097.19.097.38c0 .127 0 .158.03.22c.097.19.539.507.666.635c.287.286.507.89.983 1.366c.732.73 1.777 1.3 5.108 2.855c1.173.538.507.256.635.287c.286.096.666.096.89.255c.127.097-.031.062.317.062c.062 0 .062.031.128.062c.062.031.127.128.22.128c.063 0 .097-.062.19-.031c.093.03.317.19.507.286c.159.096.19.096.255.031c.19-.128.318.031.507.031c.062 0 .159-.031.349-.031c.255 0 .255.062 1.238.062" },
  gpt4all: { color: "#0A0A0A", path: "M12.002.236c-1.823 0-2.998 1.962-2.662 2.66l.003.001c1.857-.853 3.75-.698 5.32 0c.136-.785-.838-2.66-2.66-2.66m3.476 2.946c-1.065-.01-2.024.73-2.026 1.23c1.685.031 3.035.824 3.951 1.904c.382-.533.329-2.275-1.024-2.927a2.1 2.1 0 0 0-.901-.207m-6.973.002a2.1 2.1 0 0 0-.881.207C6.27 4.043 6.1 5.919 6.6 6.318c1.075-1.298 2.536-1.859 3.951-1.902c-.14-.494-1.02-1.24-2.045-1.23m10.76.656c-.69.017-1.272.257-1.43.585c1.826.92 2.884 2.499 3.318 4.161c.7-.382 1.558-2.314.421-3.74c-.603-.756-1.527-1.025-2.31-1.006m-14.739.036c-.726.002-1.53.257-2.098.97c-1.136 1.425-.335 3.566.422 3.738c.491-1.984 1.793-3.368 3.318-4.16c-.264-.298-.915-.55-1.642-.548M12 4.21c-1.23 0-2.025 1.324-1.796 1.797c1.254-.575 2.533-.473 3.593 0c.095-.53-.566-1.797-1.797-1.797m4.909 2.434c-.467.011-.86.175-.967.396c1.234.623 1.948 1.689 2.24 2.81c.473-.257 1.053-1.56.286-2.525c-.407-.513-1.03-.694-1.56-.681m-9.959.026c-.49.002-1.033.173-1.417.655c-.766.962-.226 2.407.285 2.526c.331-1.341 1.212-2.276 2.241-2.81c-.178-.202-.618-.372-1.109-.37m12.663 1.795a.7.7 0 0 0-.4.122c1.026 1.334 1.25 2.884.977 4.273c.655-.033 1.982-1.16 1.649-2.624c-.271-1.189-1.504-1.798-2.226-1.771m-15.26.055c-.752.014-1.916.527-2.188 1.717c-.335 1.465 1.025 2.768 1.649 2.626c-.344-1.647.127-3.142.977-4.275a1.1 1.1 0 0 0-.438-.068m6.437 1.105a.383.383 0 1 0 .02 0zm2.382 0a.383.383 0 1 0 .02 0zM12 11.242a1.237 1.237 0 1 0 0 2.474a1.237 1.237 0 0 0 0-2.474m-2.695.244a.383.383 0 1 0 .02 0zm5.352 0a.383.383 0 1 0 .02 0zm7.43.52a.6.6 0 0 0-.15.012c.418 2-.155 3.812-1.185 5.187c.734.31 2.78-.224 3.185-2.001c.38-1.666-1.046-3.161-1.85-3.198m-20.021.015c-.796.041-2.407 1.407-2.002 3.184c.406 1.776 2.58 2.486 3.186 2.001c-1.246-1.619-1.516-3.499-1.184-5.185m16.75.138a.4.4 0 0 0-.103.01c.284 1.352-.103 2.576-.799 3.504c.497.208 1.88-.151 2.152-1.353c.257-1.126-.708-2.135-1.25-2.16m-13.527.01c-.538.027-1.626.95-1.353 2.151c.273 1.202 1.743 1.68 2.152 1.353c-.84-1.095-1.022-2.365-.799-3.505m4.566 1.64a.383.383 0 1 0-.001.767a.383.383 0 0 0 .001-.768m4.292 0a.383.383 0 1 0 .001.765a.383.383 0 0 0 0-.766m-2.165 1.032a.384.384 0 0 0 .02.767a.383.383 0 0 0 0-.767zm-7.521.85c-.576.315-1.284 1.906-.348 3.08c.937 1.174 2.804.923 3.08.347c-1.504-.758-2.376-2.057-2.732-3.427m15.08 0c-.403 1.635-1.475 2.776-2.732 3.427c.435.492 2.143.827 3.08-.347s.277-2.939-.347-3.08m-11.969 1.84c-.314.439-.272 1.866.838 2.4c1.11.535 2.4-.314 2.4-.838v-.002c-1.38-.024-2.487-.675-3.238-1.56m8.858.003c-.88 1.065-2.078 1.526-3.238 1.56c.148.518 1.291 1.373 2.4.839c1.109-.535 1.25-2.073.838-2.4M5.446 19.96c-.464.648-.4 2.761 1.243 3.552s3.551-.467 3.551-1.242c-2.044-.036-3.683-1-4.794-2.31m13.111 0c-1.303 1.575-3.078 2.258-4.795 2.31c.217.767 1.908 2.033 3.552 1.242c1.643-.79 1.85-3.069 1.243-3.552m-8.747.417c-.114.646.69 2.191 2.192 2.191s2.47-1.615 2.192-2.191c-1.53.703-3.091.576-4.384 0" },
};

/* A mark's fill. The near-black rows are makers' one-colour logos (OpenAI,
   GitHub, Ollama…), which publish a white version for dark backgrounds; drawn
   in the text colour they flip with the theme instead of vanishing on a dark
   page. Coloured marks keep their colour. Relative luminance < .04 is the
   cut: the darkest coloured mark (AWS #232F3E, also one-colour) sits at .027,
   the lightest true colour mark far above it. */
function markFill(color) {
  const m = /^#([0-9a-f]{2})([0-9a-f]{2})([0-9a-f]{2})$/i.exec(color || "");
  if (!m) return color;
  const lin = (h) => {
    const c = parseInt(h, 16) / 255;
    return c <= 0.04045 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4);
  };
  const lum = 0.2126 * lin(m[1]) + 0.7152 * lin(m[2]) + 0.0722 * lin(m[3]);
  return lum < 0.04 ? "currentColor" : color;
}

/* TurnSource → mark. A rail with no honest mark is deliberately absent and
   falls back to the named chip; inventing a logo is worse than a word. */
const RAIL_BRAND = {
  "claude-code": "anthropic",
  "claude-desktop": "anthropic",
  codex: "openai",
  cursor: "cursor",
  "gemini-cli": "gemini",
  "copilot-cli": "githubcopilot",
  "vscode-copilot": "githubcopilot",
  "qwen-code": "alibabacloud",
  "grok-build": "xai",
  // The two autonomous-agent frameworks (2026-09-06 registry additions).
  hermes: "nousresearch",
  openclaw: "openclaw",
};
/* Catalog id → mark for the coverage card ("AI on this Mac"), which lists
   tools Doorman does not capture as well as the rails it does. Every id the
   ledger already knows keeps the same mark, so Claude Code is the same logo on
   both screens; the rest are the tools whose own mark we can draw. A tool
   missing here shows its state dot and its name, and nothing else. */
const TOOL_BRAND = {
  ...RAIL_BRAND,
  "chatgpt-desktop": "openai",
  windsurf: "windsurf",
  "amazon-q": "aws",
  kiro: "aws",
  warp: "warp",
  zed: "zedindustries",
  "jetbrains-ai": "jetbrains",
  ollama: "ollama",
  perplexity: "perplexity",
  comet: "perplexity",
  raycast: "raycast",
  grammarly: "grammarly",
  notion: "notion",
  // 2026-09-08: the rest of the catalog, wherever a mark could be sourced
  // honestly. Seven rows still have none — Aider, Crush, Factory Droid, Jan,
  // Msty, superwhisper and Dia publish no vector any permissive set carries —
  // and those stay a name and a dot rather than wear something invented.
  amp: "amp",
  goose: "goose",
  cline: "cline",
  "roo-code": "roocode",
  "kimi-code": "kimi",
  opencode: "opencode",
  openhands: "openhands",
  "lm-studio": "lmstudio",
  gpt4all: "gpt4all",
  continue: "continue",
  granola: "granola",
  arc: "arc",
};

/* A session row's rail as its mark, with the name one hover (or focus) away —
   the list is scanned, and a word repeated on every row read slower than the
   logo did. `title` is the accessible name; the bubble is the app's tip layer. */
function RailMark({ source, size = 15 }) {
  const brand = RAIL_BRAND[source];
  const label = SOURCE_NAMES[source] || source;
  if (!brand) return <SourceChip source={source} />;
  const mark = RAIL_MARKS[brand];
  return (
    <span className={"railmark src-" + source} data-tip={label} aria-label={label} role="img" tabIndex={-1}>
      {brand === "cursor" ? (
        <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinejoin="round" strokeLinecap="round" aria-hidden="true">
          <path d="M12 2 3 7v10l9 5 9-5V7z" />
          <path d="M3 7l9 5 9-5M12 12v10" opacity=".55" />
        </svg>
      ) : (
        <svg width={size} height={size} viewBox={mark.viewBox || "0 0 24 24"} fill={markFill(mark.color)} aria-hidden="true">
          <path d={mark.path} fillRule={mark.fillRule} />
        </svg>
      )}
    </span>
  );
}

/* One catalog tool's own mark, for the coverage card. Unlike RailMark there is
   no chip fallback: that card already prints the name beside it and colours the
   row's state dot, so an unknown tool is a name and a dot rather than a
   monogram standing in for a logo. */
function ToolMark({ tool, size = 15 }) {
  const brand = TOOL_BRAND[tool];
  const mark = brand && RAIL_MARKS[brand];
  if (brand === "cursor") return (
    <span className="toolmark" aria-hidden="true">
      <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinejoin="round" strokeLinecap="round">
        <path d="M12 2 3 7v10l9 5 9-5V7z" />
        <path d="M3 7l9 5 9-5M12 12v10" opacity=".55" />
      </svg>
    </span>);
  if (!mark) return null;
  return (
    <span className="toolmark" aria-hidden="true">
      <svg width={size} height={size} viewBox={mark.viewBox || "0 0 24 24"} fill={markFill(mark.color)}><path d={mark.path} fillRule={mark.fillRule} /></svg>
    </span>);
}

/* A MODEL's provider mark, inferred from the model name the transcript wrote
   down — a ledger turn records `model` and nothing about who serves it, and
   the renderer has no pricing table to ask. Presentation only: an unmatched
   name simply has no mark, so a new family costs a missing logo, never a
   wrong one. The families are the ones the mark registry can draw. */
const MODEL_BRAND_RULES = [
  [/^claude/, "anthropic"],
  [/^(gpt|o[1-9]|chatgpt|codex|text-davinci)/, "openai"],
  [/^gemini/, "gemini"],
  [/^grok/, "xai"],
  [/^qwen/, "alibabacloud"],
];
function modelBrand(model) {
  const m = String(model || "").trim().toLowerCase();
  for (const [re, brand] of MODEL_BRAND_RULES) if (re.test(m)) return brand;
  return null;
}
function ModelMark({ model, size = 13 }) {
  const brand = modelBrand(model);
  const mark = brand && RAIL_MARKS[brand];
  if (!mark) return null;
  return (
    <span className="toolmark modelmark" aria-hidden="true">
      <svg width={size} height={size} viewBox={mark.viewBox || "0 0 24 24"} fill={markFill(mark.color)}><path d={mark.path} fillRule={mark.fillRule} /></svg>
    </span>);
}

/* Abbreviations are spelled out rather than sliced: severity.slice(0,4) turns
   "medium" into "MEDI", which is not a word and not an abbreviation. */
const SEV_SHORT = { critical: "CRIT", high: "HIGH", medium: "MED", low: "LOW" };

function SeverityBadge({ severity, outcome }) {
  const label =
    (SEV_SHORT[severity] || severity.toUpperCase()) +
    (outcome ? " · " + outcome.toUpperCase() : "");
  return <span className={"sevbadge sev-" + severity} title={severity + " severity"}>{label}</span>;
}

function Empty({ children }) {
  return <div className="empty">{children}</div>;
}

/**
 * Seconds since `active` last became true, ticking once a second; null while
 * it is false.
 *
 * The gallery's Loading State puts an elapsed clock next to its spinner, and
 * that is the honest half of a loader: this app's rescan walks ~200 transcript
 * files and can run for many seconds, during which a bare "Scanning…" is
 * indistinguishable from "wedged". Timed from when the RENDERER saw the status
 * flip, which is what the reader is actually waiting on — the main process
 * publishes no scan-start timestamp, and inventing one that disagreed with the
 * label would be worse than a clock that starts a beat late.
 */
function useElapsed(active) {
  const startedAt = useRef(null);
  const [secs, setSecs] = useState(null);
  useEffect(() => {
    if (!active) {
      startedAt.current = null;
      setSecs(null);
      return;
    }
    startedAt.current = Date.now();
    setSecs(0);
    const tick = setInterval(
      () => setSecs(Math.round((Date.now() - startedAt.current) / 1000)),
      1000,
    );
    return () => clearInterval(tick);
  }, [active]);
  return secs;
}

/** "Scanning… 4s" — the label plus its elapsed clock, or the idle label. */
function Working({ active, label, idle }) {
  const secs = useElapsed(active);
  if (!active) return idle;
  return (
    <React.Fragment>
      {label} <span className="elapsed">{secs}s</span>
    </React.Fragment>
  );
}

/** Search input with a magnifier. */
function SearchBox({ value, onChange, placeholder }) {
  return (
    <div className="searchbox">
      <Icon name="search" size={15} />
      <input type="search" placeholder={placeholder} value={value} onChange={onChange} />
    </div>
  );
}

/** The OBS / ASK / BLOCK tri-state, per the Detection Rules design. Each mode
 * carries its meaning as a tooltip rather than a paragraph above the table —
 * explained where the choice is actually made. */
function ModeSeg({ value, onChange, disabled }) {
  const modes = [
    { id: "observe", label: "OBS", title: "Observe — record it, let the call through" },
    { id: "warn", label: "WARN", title: "Warn — let the call through, but raise a heads-up banner" },
    { id: "ask", label: "ASK", title: "Ask — hold the call open until you answer" },
    { id: "block", label: "BLOCK", title: "Block — refuse the call without asking" },
  ];
  return (
    <span className={"modeseg" + (disabled ? " off" : "")}>
      {modes.map((m) => (
        <button
          key={m.id}
          data-tip={value === m.id ? undefined : m.title}
          aria-label={m.title}
          className={value === m.id ? "on mode-" + m.id : ""}
          disabled={disabled}
          onClick={() => onChange(m.id)}
        >
          {m.label}
        </button>
      ))}
    </span>
  );
}

/**
 * A filter dropdown that STATES what it is doing: the button wears the active
 * value (not the dimension name) and every option carries its own count, so
 * you can see what narrowing costs you before you click it.
 */
/* No `align` prop any more: the popover is anchor-positioned and flips itself
   away from whichever window edge it would cross (see .fmenu-pop in app.css). */
/* `multi`: the options are TICK BOXES rather than one choice — `value` is
   the array of ticked keys, `onPick(key)` toggles one, the list stays open
   across picks (you are composing a set, not answering a question), and the
   button wears `summary` (the caller's one-line account of the set) and is
   "on" while `narrowed` says the set is not the rest state. */
function FilterMenu({ label, value, options, onPick, multi, summary, narrowed: narrowedProp }) {
  const [open, setOpen] = useState(false);
  const ref = useRef(null);
  useEffect(() => {
    if (!open) return;
    const onDown = (e) => {
      if (ref.current && !ref.current.contains(e.target)) setOpen(false);
    };
    const onKey = (e) => (e.key === "Escape" ? setOpen(false) : null);
    // The popover is fixed + anchored so it can flip away from a window edge,
    // and a fixed box does NOT follow its anchor through a scroll (measured:
    // scroll the pane 220px and the list stays put while its button leaves).
    // So movement closes it rather than letting it drift. A scroll INSIDE the
    // list is not movement.
    const onScroll = (e) => {
      if (ref.current && ref.current.contains(e.target)) return;
      setOpen(false);
    };
    document.addEventListener("mousedown", onDown);
    document.addEventListener("keydown", onKey);
    document.addEventListener("scroll", onScroll, true);
    window.addEventListener("resize", onScroll);
    return () => {
      document.removeEventListener("mousedown", onDown);
      document.removeEventListener("keydown", onKey);
      document.removeEventListener("scroll", onScroll, true);
      window.removeEventListener("resize", onScroll);
    };
  }, [open]);
  const picked = (key) => (multi ? (value || []).indexOf(key) !== -1 : key === value);
  const active = multi ? null : options.find((o) => o.key === value);
  const narrowed = narrowedProp !== undefined ? narrowedProp : !multi && value !== options[0].key;
  return (
    <span className="fmenu-wrap" ref={ref}>
      <button
        className={"fmenu" + (narrowed ? " on" : "")}
        aria-haspopup="listbox"
        aria-expanded={open}
        onClick={() => setOpen(!open)}
      >
        {multi ? summary || label : (active && active.short) || (active && active.label) || label}
        <span className="caret">⌄</span>
      </button>
      {open ? (
        <div className="fmenu-pop" role="listbox" aria-multiselectable={multi ? true : undefined}>
          {options.map((o) => (
            <button
              key={o.key}
              role="option"
              aria-selected={picked(o.key)}
              className={picked(o.key) ? "on" : ""}
              onClick={() => {
                if (!multi) setOpen(false);
                onPick(o.key);
              }}
            >
              <span className="tick">{picked(o.key) ? "✓" : ""}</span>
              {o.dot ? <span className="dot" style={{ background: o.dot }} /> : null}
              <span className="lab">{o.label}</span>
              {o.count !== undefined ? <span className="cnt">{o.count}</span> : null}
            </button>
          ))}
        </div>
      ) : null}
    </span>
  );
}

/**
 * With `trigger` (a label) the menu opens from an ordinary labelled button
 * with a caret instead of the "⋯" — a screen's toolbar collapsing several
 * related actions (the export formats) into one control.
 *
 * A row's actions behind one "⋯" button — for a list where every row offers
 * the same two or three verbs. Spelling the verbs out on each row made the
 * list read as a wall of links (and put "Delete" one pixel from "Restore" on
 * every line); one trigger per row keeps the row about its name.
 *
 * `items` are `{ id, label, onPick, disabled, danger }`. Picking closes the
 * menu and calls `onPick` — nothing else, so a caller that needs a confirm
 * step puts it where the trigger was, as the saved rule sets do.
 *
 * Fixed + anchored like .verdict-pop, so the card's own scroll cannot clip
 * it; and, for the same reason, movement closes it rather than letting it
 * drift from its button.
 */
function ActionMenu({ label, items, disabled, trigger }) {
  const [open, setOpen] = useState(false);
  const ref = useRef(null);
  useEffect(() => {
    if (!open) return;
    const onDown = (e) => {
      if (ref.current && !ref.current.contains(e.target)) setOpen(false);
    };
    const onKey = (e) => (e.key === "Escape" ? setOpen(false) : null);
    const onScroll = (e) => {
      if (ref.current && ref.current.contains(e.target)) return;
      setOpen(false);
    };
    document.addEventListener("mousedown", onDown);
    document.addEventListener("keydown", onKey);
    document.addEventListener("scroll", onScroll, true);
    window.addEventListener("resize", onScroll);
    return () => {
      document.removeEventListener("mousedown", onDown);
      document.removeEventListener("keydown", onKey);
      document.removeEventListener("scroll", onScroll, true);
      window.removeEventListener("resize", onScroll);
    };
  }, [open]);
  return (
    <span className="rowmenu-wrap" ref={ref}>
      {trigger ? (
        <button
          type="button"
          className={"btn menu-trigger" + (open ? " on" : "")}
          aria-label={label}
          aria-haspopup="menu"
          aria-expanded={open}
          disabled={disabled}
          onClick={() => setOpen(!open)}
        >
          {trigger}
          <Icon name="chevron" size={12} strokeWidth={2.2} className="caret" />
        </button>
      ) : (
        <button
          type="button"
          className={"iconbtn more" + (open ? " on" : "")}
          aria-label={label}
          title={label}
          aria-haspopup="menu"
          aria-expanded={open}
          disabled={disabled}
          onClick={() => setOpen(!open)}
        >
          <Icon name="more" size={16} strokeWidth={2.4} />
        </button>
      )}
      {open ? (
        <div className="rowmenu-pop" role="menu" aria-label={label}>
          {items.map((it) => (
            <button
              key={it.id}
              type="button"
              role="menuitem"
              className={it.danger ? "danger" : undefined}
              disabled={it.disabled}
              title={it.hint}
              onClick={() => {
                setOpen(false);
                it.onPick();
              }}
            >
              {it.label}
            </button>
          ))}
        </div>
      ) : null}
    </span>
  );
}

/**
 * Plan headroom — how much of a host's own allowance is gone.
 *
 * A GAUGE, not a series: the question is "where am I against a ceiling", so
 * this is the one place the house rule sends you to the semantic ramp
 * (`--good` / `--warn` / `--bad`) instead of the positional chart colors. The
 * thresholds are the same ones the status string uses, so the bar and the
 * words can never disagree.
 *
 * Colour is redundant by construction: the percentage, the counts and the
 * state are all written out, so the row reads identically in greyscale, under
 * any CVD, and to a screen reader. That is also why there is no legend — one
 * mark per row, named by the row.
 */
function headroomTone(pct) {
  if (pct >= 100) return "bad";
  return pct >= 90 ? "warn" : "good";
}

function HeadroomBar({ used_percentage }) {
  const pct = Math.max(0, Math.min(100, Number(used_percentage) || 0));
  const tone = headroomTone(pct);
  const color = tone === "bad" ? "var(--bad)" : tone === "warn" ? "var(--warn)" : "var(--good)";
  return (
    <span className="sharebar headroom" role="img" aria-label={Math.round(pct) + "% of the plan window used"}>
      <span className="track">
        {/* A floor of 2px so a tiny-but-real slice is still a mark rather than
            nothing; 0 stays empty, because "none used" must not look like
            "barely used". */}
        <span
          className="fill"
          style={{ width: pct > 0 ? "max(2px, " + pct + "%)" : "0", background: color }}
        />
      </span>
      {/* "<1%" rather than "0%" for a real-but-tiny slice: the bar is drawing a
          mark, and a label reading zero beside a visible mark is the two
          disagreeing. */}
      <span className="pct">{pct > 0 && pct < 1 ? "<1%" : Math.round(pct) + "%"}</span>
    </span>
  );
}

/** Horizontal share bar for the model table (value 0..1). */
function ShareBar({ share, color }) {
  return (
    <span className="sharebar">
      <span className="track">
        <span className="fill" style={{ width: Math.round(share * 100) + "%", background: color }} />
      </span>
      <span className="pct">{Math.round(share * 100)}%</span>
    </span>
  );
}

/* StackedBars/ChartLegend moved to charts.jsx — see the dataviz notes there
   (thin marks, 2px surface gaps, rounded data-ends, hover on every mark). */

/** Model-series descriptors for a by_model GraphDay fold. */
function modelSeries(models) {
  return models.map((m, i) => ({
    key: m,
    label: m,
    color: seriesColor(i, m),
    valueOf: (day) => day.by_model[m] || 0,
  }));
}

/** Use-case labels — MUST mirror TASK_LABELS in main/lib/task-class.ts;
    test/renderer-logic.test.ts holds the two maps identical. */
const TASK_META = {
  coding: "Coding",
  debugging: "Debugging",
  testing: "Testing",
  refactor: "Refactoring",
  data: "Data & analysis",
  docs: "Docs & writing",
  infra: "Infra & ops",
  research: "Research",
  review: "Review",
  other: "Other",
};
const taskLabel = (t) => TASK_META[t] || t;

/** Task-series descriptors for a by_task TimeDay fold — colors are positional
    by rank (house rule), with "other" always the reserved neutral. */
function taskSeries(tasks) {
  return tasks.map((t, i) => ({
    key: t,
    label: taskLabel(t),
    color: seriesColor(i, t),
    valueOf: (day) => day.by_task[t] || 0,
  }));
}

/**
 * A binary setting, as a switch rather than a two-option <select>.
 *
 * On/Off through a dropdown costs a click to see a state the control could
 * simply be showing, and reads as a choice among many when there are exactly
 * two. The switch states the current value at rest.
 */
/**
 * `pending`: the position the switch is MOVING to, while the work behind it is
 * still running.
 *
 * Why it exists: installing or removing the guard writes
 * several hook documents and can take a beat. A switch that held its OLD
 * position and greyed out for that whole beat would show a person who flipped
 * it nothing moving — and they would press it again. So the knob travels immediately, the
 * track goes striped to say "not yet true", and it settles once the app's own
 * state agrees. It stays `disabled` throughout, so the flip can only fire ONCE
 * however many times it is pressed.
 *
 * `aria-checked` follows the pending position with `aria-busy` beside it: the
 * position is what was asked for, and the busy flag is what says it hasn't
 * landed. Reporting the old position would be telling a screen reader the
 * press did nothing.
 */
function Switch({ on, onChange, disabled, ariaLabel, pending }) {
  const busy = pending != null;
  const shown = busy ? !!pending : !!on;
  return (
    <button
      type="button"
      role="switch"
      aria-checked={shown}
      aria-busy={busy || undefined}
      aria-label={ariaLabel}
      disabled={disabled || busy}
      className={"switch" + (shown ? " on" : "") + (busy ? " pending" : disabled ? " off" : "")}
      onClick={() => onChange(!on)}
    />
  );
}

/** A reason as one sentence with exactly one full stop: main's reasons arrive
 * with and without one, and the screens used to add a second. */
function endSentence(text) {
  const s = String(text || "").trim().replace(/\.+$/, "");
  return s ? s + "." : "";
}

/**
 * What a guard install, sync or removal couldn't finish: a headline, then one
 * short line per agent it couldn't reach (or the one reason, when it isn't any
 * agent's). It used to be a single sentence with every reason strung into it,
 * which ran to a paragraph as soon as more than one agent was involved.
 */
function GuardProblem({ title, error, failures, note }) {
  const list = failures || [];
  return (
    <div className="callout bad guardproblem" role="alert">
      <div className="gp-head">{title}</div>
      {list.length > 0 ? (
        <ul className="gp-list">
          {list.map((f) => (
            <li key={f.id}>
              <b>{f.label}</b> {endSentence(f.error)}
            </li>
          ))}
        </ul>
      ) : error ? (
        <div className="gp-detail">{endSentence(error)}</div>
      ) : null}
      {note ? <div className="gp-note">{note}</div> : null}
    </div>
  );
}

/** "The guard couldn't be updated in Hermes Agent" / "in 3 agents". */
function guardSyncTitle(failures) {
  const list = failures || [];
  if (list.length === 1) return "The guard couldn't be updated in " + list[0].label;
  if (list.length > 1) return "The guard couldn't be updated in " + list.length + " agents";
  return "The guard couldn't be updated";
}

/**
 * Progressive disclosure for the settings nobody needs on a first run —
 * self-hosting, key pasting. Collapsed by default: an input pre-filled with a
 * value that is already correct is an invitation to break it.
 */
/**
 * A model's second look at a finding (FindingRow.assist), in one sentence the
 * card, the ledger and the report can share. The rule always fired first; this
 * says what the model made of it and — for the one verdict that changes
 * anything — what changed. Scores are the classifier's P(attack).
 */
function assistPhrase(a) {
  if (!a) return "";
  const pct = a.score != null ? Math.round(a.score * 100) + "% likely an attack" : null;
  if (a.by === "injection_classifier") {
    if (a.verdict === "stood_down")
      return a.model + " re-read the output as ordinary text" + (pct ? " (" + pct + ")" : "") + " — stood down to medium confidence: kept on the Radar, not announced, no hold armed.";
    if (a.verdict === "confirmed") return a.model + " agrees it is an injection" + (pct ? " (" + pct + ")" : "") + ".";
    return a.model + " was unsure" + (pct ? " (" + pct + ")" : "") + " — the rule stands.";
  }
  const who = a.model + " (local model)";
  if (a.verdict === "stood_down") return who + " read the value as not a credential — confidence lowered to medium before the guard decided.";
  if (a.verdict === "confirmed") return who + " agrees it is a credential.";
  return who + " was unsure — the rule stands.";
}

/** The short label the collapsed row wears when a model changed the outcome. */
function assistChip(a) {
  return a && a.verdict === "stood_down" ? "STOOD DOWN" : null;
}

/** The injection-model choices (main: guard/policy.ts InjectionModelId),
 * the default first. */
const INJECTION_MODEL_OPTIONS = [
  { value: "doorman-1", label: "Doorman (fine-tuned, recommended)" },
  { value: "stock", label: "Prompt Guard 2 (stock)" },
];

/**
 * The line under Settings' AI-protection row about WHICH model runs
 * (ModelAssistState.injection_classifier.model_choice): empty while the
 * selected model is the one running and nothing pins it; otherwise the truth —
 * the fine-tuned model is not published yet, is downloading, or failed, and
 * Prompt Guard 2 runs in its place — and whether the environment pins it.
 */
function injectionModelNote(choice) {
  if (!choice) return "";
  const parts = [];
  if (choice.selected === "doorman-1" && choice.effective === "stock") {
    if (choice.fallback === "unpublished") parts.push("Doorman model · not published yet — using Prompt Guard 2 for now.");
    else if (choice.fallback === "download_failed")
      parts.push("Doorman model · download failed" + (choice.selected_error ? " (" + choice.selected_error + ")" : "") + " — using Prompt Guard 2 until it succeeds.");
    else parts.push("Doorman model · " + (choice.selected_downloading ? "downloading" : "on its way") + " — using Prompt Guard 2 until it is installed.");
  }
  if (choice.env) parts.push("Model set by the environment (DOORMAN_INJECTION_CLASSIFIER_MODEL) — the choice is read-only.");
  return parts.join(" ");
}

/**
 * The confidence band a row carries (FindingRow.confidence), for the closed
 * card. Absent means high and says nothing — a high-confidence chip on every
 * row would be noise. A model's STOOD DOWN chip already means "medium", so the
 * two never stack; this is for the rows a RULE was unsure about on its own,
 * which used to look identical to the ones it was certain of.
 */
function confidenceChip(row) {
  if (!row || !row.confidence || row.confidence === "high") return null;
  if (assistChip(row.assist)) return null;
  return row.confidence.toUpperCase() + " CONFIDENCE";
}

/** The band a row is read at — absent means high, the way main's
 * `confidenceOf` reads it. */
function confidenceBandOf(row) {
  return (row && row.confidence) || "high";
}

/** The bands, most certain first — the order the Confidence menu lists them. */
const CONFIDENCE_BANDS = ["high", "medium", "low"];

/** The bands the prefs tick: `confidence_bands`, every band unless
 * it says otherwise — an unknown or empty value is the default, never
 * nothing. In the canonical order. */
function confidenceBandsOf(prefs) {
  const raw = prefs && Array.isArray(prefs.confidence_bands) ? prefs.confidence_bands : [];
  const bands = CONFIDENCE_BANDS.filter((b) => raw.indexOf(b) !== -1);
  return bands.length === 0 ? CONFIDENCE_BANDS.slice() : bands;
}

/**
 * The confidence bands the Radar is folding away under these prefs
 * — every band not ticked. The renderer's copy of main's
 * `hiddenConfidenceBands` (state.ts): the feed, the Overview's per-session
 * lists and the summary's counts must all leave out the same rows, or the
 * badge and the list disagree.
 */
function hiddenConfidenceBands(prefs) {
  const shown = confidenceBandsOf(prefs);
  return CONFIDENCE_BANDS.filter((b) => shown.indexOf(b) === -1);
}

/** Is this row's band one the person is seeing? `hidden` is the list above. */
function confidenceShown(row, hidden) {
  return hidden.indexOf(confidenceBandOf(row)) === -1;
}

/** The rows a screen may show under the prefs — every band the person has
 * not folded away. Rows in a hidden band stay in `state.radar.findings` (so
 * the Radar's Show boxes can bring them back); a screen reads through this. */
function visibleConfidenceRows(rows, prefs) {
  const hidden = hiddenConfidenceBands(prefs);
  return hidden.length === 0 ? rows : rows.filter((f) => confidenceShown(f, hidden));
}

/** The sentence behind the chip — what a lowered confidence means for the row. */
function confidencePhrase(row) {
  if (!row || !row.confidence || row.confidence === "high") return "";
  const band = row.confidence === "low" ? "Low" : "Medium";
  if (row.assist) return band + " confidence — " + assistPhrase(row.assist);
  return band + " confidence — the rule matched a shape it is not certain about. Kept on the Radar and not announced; read it as a lead, not a verdict.";
}

/** "4s" / "3m" / "1.5h" between a flow row's two ends; null for per-unit rows. */
function flowSpan(row) {
  if (!row || !row.source_at || !row.last_seen_at) return null;
  const ms = Date.parse(row.last_seen_at) - Date.parse(row.source_at);
  if (!Number.isFinite(ms) || ms < 0) return null;
  if (ms < 60_000) return Math.max(1, Math.round(ms / 1000)) + "s";
  if (ms < 3_600_000) return Math.round(ms / 60_000) + "m";
  return Math.round(ms / 360_000) / 10 + "h";
}

/**
 * What each end of a session flow IS, by rule — mirrors main/lib/reveal.ts
 * flowEndLabels, so the card, the ledger marker and the raw strip agree.
 */
function flowEnds(detector) {
  switch (detector) {
    case "flow_secret_egress": return ["credential read", "egress"];
    case "flow_read_then_send": return ["private data read", "send"];
    case "flow_injection_followed": return ["injected instruction arrived", "the call that followed"];
    case "flow_fetch_then_exec": return ["fetched", "executed"];
    case "flow_fetch_then_install": return ["fetched content named a package", "installed"];
    case "flow_insecure_code_executed": return ["insecure code written", "executed"];
    case "flow_sql_second_order": return ["database result", "later query"];
    case "agent_loop": return ["first repeat", "last repeat"];
    default: return ["source", "sink"];
  }
}

function Advanced({ label = "Advanced", children }) {
  const [open, setOpen] = useState(false);
  return (
    <div className={"advanced" + (open ? " open" : "")}>
      <button type="button" className="advanced-toggle" aria-expanded={open} onClick={() => setOpen(!open)}>
        <Icon name="chevron" size={13} />
        {label}
      </button>
      {open ? <div className="advanced-body">{children}</div> : null}
    </div>
  );
}

/* ---- the tooltip layer ----------------------------------------------------
   One bubble for every `data-tip` in the app (app.css .tipbubble explains why
   it is an element on <body> and not a ::after). Event delegation on the
   document, so it needs no wiring per component: hover or focus an element
   carrying data-tip and the bubble takes its text and its place — centred
   above, kept 8px inside the window, below when there is no room above. It
   hides on leave, blur, any scroll or resize (the element moved; guessing
   where is worse than disappearing) and on mousedown (the person is acting,
   not reading). Inert under the renderer test harness, whose document has no
   createElement. */
(function installTipLayer() {
  if (typeof document === "undefined" || typeof document.createElement !== "function" || !document.body) return;
  let bubble = null;
  let current = null;
  const ensure = () => {
    if (!bubble) {
      bubble = document.createElement("div");
      bubble.className = "tipbubble";
      bubble.setAttribute("role", "tooltip");
      bubble.setAttribute("aria-hidden", "true");
      document.body.appendChild(bubble);
    }
    return bubble;
  };
  const place = () => {
    if (!current) return;
    const b = ensure();
    const r = current.getBoundingClientRect();
    const vw = window.innerWidth;
    const bw = b.offsetWidth;
    const bh = b.offsetHeight;
    let left = r.left + r.width / 2 - bw / 2;
    left = Math.max(8, Math.min(vw - bw - 8, left));
    let top = r.top - bh - 6;
    if (top < 8) top = r.bottom + 6;
    b.style.left = left + "px";
    b.style.top = top + "px";
  };
  const show = (el) => {
    const text = el.getAttribute("data-tip");
    if (!text) return;
    current = el;
    const b = ensure();
    b.textContent = text;
    b.classList.add("on");
    place();
  };
  const hide = () => {
    current = null;
    if (bubble) bubble.classList.remove("on");
  };
  const from = (t) => (t && typeof t.closest === "function" ? t.closest("[data-tip]") : null);
  document.addEventListener("mouseover", (e) => {
    const el = from(e.target);
    if (el) {
      if (el !== current) show(el);
    } else if (current) hide();
  }, true);
  document.addEventListener("mouseout", (e) => {
    const el = from(e.target);
    if (el && el === current && !(e.relatedTarget && el.contains(e.relatedTarget))) hide();
  }, true);
  document.addEventListener("focusin", (e) => {
    const el = from(e.target);
    if (el) show(el);
  }, true);
  document.addEventListener("focusout", (e) => {
    if (from(e.target) === current) hide();
  }, true);
  document.addEventListener("scroll", hide, true);
  document.addEventListener("mousedown", hide, true);
  window.addEventListener("resize", hide);
})();
