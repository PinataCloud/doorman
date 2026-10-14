/**
 * Egress destination intelligence — classifying WHERE a tool call sends data,
 * and noticing the first time this machine reaches a given destination.
 *
 * The per-unit `secret_egress` / flow `flow_read_then_send` rules already ask
 * "did a credential/secret leave?"; this asks the complementary question the
 * detectors never did — "leave to WHERE?". Harmonic's per-tool risk profile,
 * reduced to the point of interaction: a paste site, a webhook sink and a
 * package registry are very different destinations for the same bytes.
 *
 * Two products:
 *  - `classifyDestination(host)` over a small static catalog (kept in the same
 *    honest register as the MCP risk catalog — a known family, else "generic");
 *  - `extractHosts(text)` to pull destinations out of a redacted command / tool
 *    input blob, so the caller (capture engine, approval enrichment) can name
 *    and rank them.
 *
 * Pure — no fs, no Electron — and unit-tested.
 */

/** The radar-only detector id for a first-seen external destination. Kept here
 * (not in the guard) because it is post-hoc and never enforceable — same class
 * as the flow_* ids. */
export type EgressDetectorId = "egress_new_destination";

export type EgressClass =
  | "ai"
  | "paste"
  | "file_share"
  | "webhook"
  | "code_host"
  | "cloud_storage"
  | "package_registry"
  | "generic";

export interface EgressProfile {
  class: EgressClass;
  label: string;
  /** One line for the approval card / finding excerpt. */
  note: string;
}

const PROFILES: Record<Exclude<EgressClass, "generic">, { label: string; note: string }> = {
  ai: { label: "AI / LLM endpoint", note: "A model provider or AI API — expected for agent traffic, but prompt content leaves the machine." },
  paste: { label: "Paste / snippet site", note: "A paste service — a common exfiltration channel for code and secrets." },
  file_share: { label: "File sharing / transfer", note: "A file-transfer service — bulk data can leave this way." },
  webhook: { label: "Webhook sink", note: "A webhook/relay endpoint — arbitrary payloads, often used to smuggle data out." },
  code_host: { label: "Code host", note: "A source host (GitHub/GitLab/…) — expected, but pushes and gists carry code out." },
  cloud_storage: { label: "Cloud storage", note: "Object/cloud storage — a bulk data destination worth a look." },
  package_registry: { label: "Package registry", note: "A package registry — expected for installs and publishes." },
};

/** Host-suffix catalog. Matched against the destination's lowercased host, by
 * exact host or dotted suffix (`api.openai.com` matches `openai.com`). */
const CATALOG: ReadonlyArray<readonly [suffix: string, cls: Exclude<EgressClass, "generic">]> = [
  // AI / LLM providers.
  ["openai.com", "ai"], ["anthropic.com", "ai"], ["googleapis.com", "ai"],
  ["openrouter.ai", "ai"], ["groq.com", "ai"], ["perplexity.ai", "ai"],
  ["x.ai", "ai"], ["mistral.ai", "ai"], ["cohere.ai", "ai"], ["huggingface.co", "ai"],
  // Paste / snippet.
  ["pastebin.com", "paste"], ["paste.ee", "paste"], ["hastebin.com", "paste"],
  ["dpaste.com", "paste"], ["ghostbin.com", "paste"], ["0bin.net", "paste"],
  ["termbin.com", "paste"], ["ix.io", "paste"], ["rentry.co", "paste"],
  // File sharing / transfer.
  ["transfer.sh", "file_share"], ["file.io", "file_share"], ["wetransfer.com", "file_share"],
  ["anonfiles.com", "file_share"], ["gofile.io", "file_share"], ["0x0.st", "file_share"],
  ["bashupload.com", "file_share"], ["oshi.at", "file_share"],
  // Webhook / relay sinks.
  ["webhook.site", "webhook"], ["requestbin.com", "webhook"], ["pipedream.net", "webhook"],
  ["hookb.in", "webhook"], ["ngrok.io", "webhook"], ["ngrok-free.app", "webhook"],
  ["discord.com", "webhook"], ["discordapp.com", "webhook"], ["hooks.slack.com", "webhook"],
  ["burpcollaborator.net", "webhook"], ["interact.sh", "webhook"], ["oast.fun", "webhook"],
  // Code hosts.
  ["github.com", "code_host"], ["githubusercontent.com", "code_host"], ["gitlab.com", "code_host"],
  ["bitbucket.org", "code_host"], ["gist.github.com", "code_host"], ["sourcehut.org", "code_host"],
  // Cloud storage.
  ["amazonaws.com", "cloud_storage"], ["blob.core.windows.net", "cloud_storage"],
  ["storage.googleapis.com", "cloud_storage"], ["r2.cloudflarestorage.com", "cloud_storage"],
  ["digitaloceanspaces.com", "cloud_storage"], ["backblazeb2.com", "cloud_storage"],
  // Package registries.
  ["npmjs.org", "package_registry"], ["registry.npmjs.org", "package_registry"],
  ["pypi.org", "package_registry"], ["files.pythonhosted.org", "package_registry"],
  ["rubygems.org", "package_registry"], ["crates.io", "package_registry"],
  ["packagist.org", "package_registry"], ["nuget.org", "package_registry"],
  ["ghcr.io", "package_registry"], ["docker.io", "package_registry"], ["quay.io", "package_registry"],
];

export function classifyDestination(host: string): EgressProfile {
  const h = host.trim().toLowerCase().replace(/:\d+$/, "");
  for (const [suffix, cls] of CATALOG) {
    if (h === suffix || h.endsWith(`.${suffix}`)) {
      return { class: cls, ...PROFILES[cls] };
    }
  }
  return { class: "generic", label: "External host", note: "No profile for this destination — an external host this machine sent to." };
}

const LOCAL_HOST_RE = /^(localhost|127(?:\.\d{1,3}){3}|0\.0\.0\.0|::1|.*\.local|.*\.internal|host\.docker\.internal)$/i;
/** Private IPv4 ranges — local network, not real egress. Anchored at both
 * ends: `10.attacker.example` is a hostname, not the 10/8 network. */
const PRIVATE_IP_RE =
  /^(?:10(?:\.\d{1,3}){3}|192\.168(?:\.\d{1,3}){2}|172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2}|169\.254(?:\.\d{1,3}){2})$/;

/** The bare host of an authority: userinfo, port, IPv6 brackets and a
 * trailing root dot dropped, lowercased. */
function normalizeHost(raw: string): string {
  let h = raw.trim().toLowerCase();
  const at = h.lastIndexOf("@");
  if (at >= 0) h = h.slice(at + 1);
  const bracketed = /^\[([^\]]+)\](?::\d+)?$/.exec(h);
  if (bracketed) h = bracketed[1]!;
  else if ((h.match(/:/g) ?? []).length === 1) h = h.replace(/:\d*$/, "");
  return h.replace(/\.+$/, "");
}

export function isLocalHost(host: string): boolean {
  const h = normalizeHost(host);
  return LOCAL_HOST_RE.test(h) || PRIVATE_IP_RE.test(h);
}

// The authority ends at the first `/`, `?` or `#` — a `?a@localhost` query or
// `#@localhost` fragment is not userinfo, and must not become the host.
const URL_RE = /\b(?:https?|wss?):\/\/([^/?#\s"'`)\\]+)/gi;
const SCP_RE = /(?:^|\s)(?:scp|rsync|sftp)\s+(?:\S+\s+)*?[\w.-]+@([\w.-]+):/gi;

/**
 * Pull external destination hosts out of a command / tool-input blob. Only
 * `http(s)` URLs and scp/rsync/sftp `user@host:` targets — the shapes that
 * actually carry data off the machine. Local and private-network hosts are
 * dropped. De-duplicated, order preserved.
 */
export function extractHosts(text: string): string[] {
  if (!text) return [];
  const out: string[] = [];
  const seen = new Set<string>();
  const push = (raw: string | undefined) => {
    if (!raw) return;
    const host = normalizeHost(raw);
    if (!host || seen.has(host) || isLocalHost(host)) return;
    // A bare token with no dot and not localhost isn't a host we can classify.
    if (!host.includes(".") && !host.includes(":")) return;
    seen.add(host);
    out.push(host);
  };
  for (const m of text.matchAll(URL_RE)) push(m[1]);
  for (const m of text.matchAll(SCP_RE)) push(m[1]);
  return out;
}

/**
 * Classes worth flagging the FIRST time a machine sends there — only the ones
 * whose exfil-to-noise ratio earns a radar row. Deliberately NARROW:
 *  - AI endpoints, code hosts and package registries are the agent's own
 *    expected traffic;
 *  - `cloud_storage` (S3 and friends) and `generic` (any unrecognized external
 *    host) are hit constantly in ordinary development — flagging every first
 *    sight of those turned the signal into a log of every API a session
 *    touches. They are still TRACKED (added to the seen-set, shown in a held
 *    call's context line), just not raised as their own finding.
 * Paste sites, file-transfer services and webhook sinks are what remains: a
 * destination with little legitimate reason inside an agent session.
 */
const NOTABLE_FIRST_SIGHT: ReadonlySet<EgressClass> = new Set<EgressClass>([
  "paste",
  "file_share",
  "webhook",
]);

export function isNotableFirstSight(cls: EgressClass): boolean {
  return NOTABLE_FIRST_SIGHT.has(cls);
}
