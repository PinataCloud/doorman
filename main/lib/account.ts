/**
 * The exposure ACCOUNT — what actually happened, in quotable fields.
 *
 * A card's rule name says what KIND of thing happened; its raw window shows
 * the transcript; neither says, in a sentence, "your agent read `.env` with
 * `cat`, then 3 minutes later sent it to api.example.com with `curl`". This
 * module reads that sentence out of the raw text the app already has in hand
 * (at scan time in capture.ts, at reveal time in lib/reveal.ts) and hands the
 * card a small record of fields plus the sentence rendered from them.
 *
 * Two rules shape everything here:
 *
 * 1. FIELDS ARE QUOTES, NOT OPINIONS. Every string field is a substring of the
 *    raw text it was read from — a path, a command word, a host — and
 *    `verifyQuotes` drops any that is not. This is the deterministic floor; a
 *    local-model reader (layer 3) fills the same shape and passes
 *    through the same verifier, so the model can point at things that are
 *    there and never invent one.
 * 2. NOTHING HERE TOUCHES ENFORCEMENT. An account changes what the card SAYS —
 *    the sentence, and the calmer MEANS / DO NEXT when the value looks like a
 *    placeholder — never severity, confidence or the guard's decision. A
 *    fixture heuristic that softened a hold would let a real key named
 *    EXAMPLE_KEY walk past the guard.
 *
 * Only the sensitive-information families the app shows (guard/rule-scope.ts,
 *) get an account: credentials & secrets, crypto wallets & keys,
 * personal data. Everything is pure and synchronous; nothing is stored beyond
 * the account itself, which carries no secret value.
 */

import { createHash } from "node:crypto";
import type { RedactedSecret } from "./reveal.js";
import { flowGapLabel } from "./reveal.js";
import { extractHosts } from "./egress-intel.js";
import { maskText } from "./masking.js";

export type PlaceholderSignal = "test_path" | "doc_example" | "synthetic_value" | "named_as_example";

export type AccountSourceKind = "file" | "env" | "prompt" | "secret_manager" | "tool_output" | "unknown";

export interface ExposureAccount {
  /** Who read the text: the deterministic extractor, or a future local model. */
  by: "extractor" | "local_reader";
  /** Where the exposed value came from, when the text says. */
  source_kind: AccountSourceKind;
  /** Quoted: the file the value came from (`.env`, `config/prod.yaml`),
   * relative to the session's working directory when it lies under it. */
  source_ref?: string;
  /** Quoted: the secret-shaped NAME a value was assigned to (`DB_PASSWORD`,
   * `secrets`) — hardcoded_credential's key_name. */
  name?: string;
  /** Quoted: the command or tool that read it (`cat`, `Read`). */
  read_via?: string;
  /** Quoted: the command or tool that carried it out (`curl`, `Bash`). */
  sink_tool?: string;
  /** Quoted: the host it was sent to. */
  destination_host?: string;
  /** For a secret READ (dotenv_read, env_dump, secret_manager_read): where its
   * output went — `agent`, printed back as the tool's output and so into the
   * model's context; `local`, used without being printed. Absent: not known
   * (a row minted before this was read). The detector's band says the same:
   * medium for `agent`, low for `local`. */
  output?: "agent" | "local";
  /** The redaction family of the value (`aws`, `github`, `credentials`). */
  credential_family?: string;
  /** The family in words, no article — "AWS credential", "Grafana API key" —
   * so the renderer can generalise across a card's rows ("AWS, GitHub and
   * OpenAI credentials") without owning the family tables. */
  family_noun?: string;
  /** "4s" / "3m" between a flow's two ends. Derived, not quoted. */
  gap?: string;
  /** Why the value looks like a placeholder rather than a live secret. Empty
   * when nothing says so — the card then keeps its ordinary advice. */
  placeholder_signals: PlaceholderSignal[];
  /** The sentence the card shows, rendered from the fields above. */
  sentence: string;
  /** The card's headline — specific to THIS exposure ("`.env` read, then sent
   * to `api.example.com`"), not the rule's name. Stable: derived from the
   * fields, so it never rewrites itself under a scrolling eye. */
  title: string;
  /** What that means for the person, in one line — the consequence. */
  so: string;
  /** What to do about it, in one line. Calm when the value looks like a
   * placeholder; the renderer overrides both when the call was stopped. */
  next: string;
}

/** What `accountForUnit` / `accountForFlow` need to know about a unit. */
export interface AccountUnit {
  kind: "prompt" | "tool_call" | "tool_output";
  raw: string;
  tool_name?: string;
  target?: string;
  at?: string;
}

export interface AccountFinding {
  detector: string;
  key_name?: string;
  /** The band the detector gave it — for a secret read, the record of where
   * its output went (see ExposureAccount.output). */
  severity?: string;
}

/* ---- Family words --------------------------------------------------------
 *
 * The redactor names what it removed with a FAMILY label (guard/redact.ts
 * BUILTIN_SECRET_LABELS — 86 of them, most generated from gitleaks' ruleset).
 * A label is `<vendor>[_<kind>]`: `aws`, `grafana_api_key`,
 * `settlemint_personal_access_token`. The card wants words — "an AWS
 * credential", "a Grafana API key" — so this derives them from the label's
 * own structure rather than keeping a second list that drifts: VENDOR_WORDS
 * spells the brand (the one thing a label cannot encode), KIND_WORDS spells
 * the kind, and WHOLE_LABEL covers the handful whose meaning is neither
 * ("bip39" is a seed phrase, "url_credentials" is a password in a URL).
 *
 * test/account.test.ts walks every label the redactor can emit and
 * fails if one has a vendor this table does not know — so a new rule in the
 * corpus is a failing test, not a card that says "a clojars api token
 * credential". */

/** Brand spelling per vendor token. A vendor may span two tokens (the key
 *  is the tokens joined with `_`); longest match wins. */
const VENDOR_WORDS: Readonly<Record<string, string>> = {
  "1password": "1Password",
  adobe: "Adobe",
  age: "age",
  alibaba: "Alibaba Cloud",
  anthropic: "Anthropic",
  aws: "AWS",
  azure: "Azure",
  clojars: "Clojars",
  cloudflare: "Cloudflare",
  coinbase_cdp: "Coinbase CDP",
  databricks: "Databricks",
  digitalocean: "DigitalOcean",
  doppler: "Doppler",
  duffel: "Duffel",
  dynatrace: "Dynatrace",
  easypost: "EasyPost",
  eth: "Ethereum",
  facebook: "Facebook",
  flutterwave: "Flutterwave",
  flyio: "Fly.io",
  frameio: "Frame.io",
  freemius: "Freemius",
  github: "GitHub",
  gitlab: "GitLab",
  google: "Google",
  grafana: "Grafana",
  grafana_cloud: "Grafana Cloud",
  groq: "Groq",
  harness: "Harness",
  huggingface: "Hugging Face",
  infracost: "Infracost",
  intra42: "42 Intra",
  linear: "Linear",
  maxmind: "MaxMind",
  microsoft_teams: "Microsoft Teams",
  npm: "npm",
  nuget: "NuGet",
  doorman: "Doorman",
  octopus_deploy: "Octopus Deploy",
  openai: "OpenAI",
  openrouter: "OpenRouter",
  openshift: "OpenShift",
  perplexity: "Perplexity",
  planetscale: "PlanetScale",
  postman: "Postman",
  prefect: "Prefect",
  pulumi: "Pulumi",
  pypi: "PyPI",
  readme: "ReadMe",
  robinhood: "Robinhood",
  rubygems: "RubyGems",
  scalingo: "Scalingo",
  sendgrid: "SendGrid",
  sendinblue: "Sendinblue",
  sentry: "Sentry",
  settlemint: "SettleMint",
  shippo: "Shippo",
  shopify: "Shopify",
  sidekiq: "Sidekiq",
  slack: "Slack",
  solana: "Solana",
  square: "Square",
  stripe: "Stripe",
  twilio: "Twilio",
  vault: "Vault",
  xai: "xAI",
};

/** The kind half, spelled: `api_token` → "API token". Longest match wins;
 *  an unlisted kind falls back to its tokens joined with spaces. */
const KIND_WORDS: Readonly<Record<string, string>> = {
  access_key_id: "access key id",
  access_token: "access token",
  api_key: "API key",
  api_token: "API token",
  application_access_token: "application access token",
  batch_token: "batch token",
  client_secret: "client secret",
  config_password: "config password",
  encryption_key: "encryption key",
  keypair: "keypair",
  keystore: "keystore",
  license_key: "license key",
  oauth_token: "OAuth token",
  org_token: "org token",
  page_access_token: "page access token",
  password: "password",
  personal_access_token: "personal access token",
  public_key: "public key",
  secret_key: "secret key",
  sensitive_url: "URL with a secret in it",
  service_access_token: "service access token",
  service_account_token: "service account token",
  test_api_token: "test API token",
  user_token: "user token",
  webhook: "webhook URL",
};

/** Labels whose words are neither a vendor nor a kind. `null` means "no
 *  family worth naming" — the caller's plain noun stands. */
const WHOLE_LABEL: Readonly<Record<string, string | null>> = {
  "": null,
  generic: null,
  bip39: "seed phrase (BIP-39)",
  email: "email address",
  evm_private_key: "EVM private key",
  jwt: "JWT",
  private_key: "private key",
  rpc_key: "RPC API key",
  url_credentials: "password embedded in a URL",
  wif: "WIF private key",
  xprv: "extended private key (xprv)",
  xpub: "extended public key (xpub)",
};

/** The vendor prefix of a label, longest first, or undefined. */
function vendorOf(tokens: readonly string[]): { word: string; used: number } | undefined {
  for (let n = Math.min(2, tokens.length); n >= 1; n--) {
    const word = VENDOR_WORDS[tokens.slice(0, n).join("_")];
    if (word !== undefined) return { word, used: n };
  }
  return undefined;
}

/**
 * The family as a noun phrase without an article — "AWS credential",
 * "Grafana API key", "seed phrase (BIP-39)" — or undefined when the label
 * names no family worth saying (anonymous, generic). `noun` is what stands in
 * when the label carries a vendor but no kind.
 */
export function familyNoun(family: string | undefined, noun = "credential"): string | undefined {
  const label = family ?? "";
  if (label in WHOLE_LABEL) return WHOLE_LABEL[label] ?? undefined;
  const tokens = label.split("_").filter((t) => t !== "");
  const vendor = vendorOf(tokens);
  const kindTokens = vendor ? tokens.slice(vendor.used) : tokens;
  const kind = kindTokens.length === 0 ? undefined : (KIND_WORDS[kindTokens.join("_")] ?? kindTokens.join(" "));
  if (vendor) return `${vendor.word} ${kind ?? noun}`;
  // No vendor we know: a KNOWN kind alone ("api_token") still reads; anything
  // else — a detector's key_name that is not a redactor family ("bearer",
  // "alpha"), a label from some other build — is no family worth naming, and
  // the caller's plain noun stands rather than a raw token on the card.
  return kindTokens.length > 0 && kindTokens.join("_") in KIND_WORDS ? kind : undefined;
}

/** Whether a label is one this table can put into words without falling back
 *  to raw tokens — what the coverage test asserts for every redactor label. */
export function familyKnown(family: string): boolean {
  if (family in WHOLE_LABEL) return true;
  const tokens = family.split("_").filter((t) => t !== "");
  const vendor = vendorOf(tokens);
  if (!vendor) return false;
  const rest = tokens.slice(vendor.used);
  return rest.length === 0 || rest.join("_") in KIND_WORDS;
}

/** "an" before a vowel SOUND: vowels, and the acronyms said letter by letter
 *  whose first letter starts with one (npm, xAI, RPC, SDK…); "1Password" is a
 *  consonant sound. */
function article(phrase: string): "a" | "an" {
  const first = phrase.split(/\s/)[0] ?? "";
  if (/^1/.test(first)) return "a";
  if (/^[aeiou]/i.test(first)) return "an";
  if (/^(npm|xAI|xprv|xpub|RPC|SDK|SQL|SSH|SSL|HTML|HTTP|FTP|LDAP|MFA|NFT|XML)\b/.test(first)) return "an";
  return "a";
}

/** "an AWS credential", "a Grafana API key", "a credential". Never the value. */
export function familyPhrase(family: string | undefined, noun = "credential"): string {
  const phrase = familyNoun(family, noun) ?? noun;
  return `${article(phrase)} ${phrase}`;
}

/* ---- Reading a unit ------------------------------------------------------ */

const READERS = /\b(cat|less|more|head|tail|sed|awk|grep|rg|source|bat|strings|xxd|base64)\b/;
const ENV_DUMPERS = /\b(printenv|env|set|export -p|declare -x|Get-ChildItem Env:)\b/;
const SECRET_MANAGERS = /\b(aws secretsmanager|aws ssm get-parameter|vault kv get|vault read|gcloud secrets|az keyvault|op read|op item get|doppler secrets|bw get|security find-generic-password)\b/;
const SENDERS = /\b(curl|wget|http|https|xh|nc|ncat|netcat|ssh|scp|sftp|rsync|ftp|telnet|openssl s_client|git push|mail|sendmail|aws s3 cp|gsutil cp)\b/;
const PATH_TOKEN = /(?:^|[\s"'`=(<])((?:~|\.{1,2})?\/?(?:[\w.@-]+\/)*[\w.@-]*\.[\w.-]+)(?=$|[\s"'`);>|&])/g;
const ENV_FILE = /(?:^|[\s"'`/=])((?:[\w.-]+\/)*\.env(?:\.[\w-]+)?)\b/;

function firstWord(re: RegExp, text: string): string | undefined {
  const m = re.exec(text);
  return m ? m[1] : undefined;
}

/** The file a reading command names, preferring a `.env`-shaped one. */
function readPath(text: string): string | undefined {
  const env = ENV_FILE.exec(text);
  if (env) return env[1];
  for (const m of text.matchAll(PATH_TOKEN)) {
    const p = m[1]!;
    // Skip the program itself and URL-ish tokens; keep something file-shaped.
    if (/^https?:/.test(p) || p.endsWith("/")) continue;
    return p;
  }
  return undefined;
}

/** The source half of an account, read off one unit. */
export function readSource(unit: AccountUnit): Pick<ExposureAccount, "source_kind" | "source_ref" | "read_via"> {
  if (unit.kind === "prompt") return { source_kind: "prompt" };
  if (unit.kind === "tool_output") return { source_kind: "tool_output", ...(unit.tool_name ? { read_via: unit.tool_name } : {}) };
  const text = unit.raw;
  const manager = firstWord(SECRET_MANAGERS, text);
  if (manager) return { source_kind: "secret_manager", read_via: manager };
  const dumper = firstWord(ENV_DUMPERS, text);
  const reader = firstWord(READERS, text);
  const path = readPath(text);
  if (dumper && !path) return { source_kind: "env", read_via: dumper };
  if (path) {
    return {
      source_kind: "file",
      source_ref: path,
      ...(reader ? { read_via: reader } : unit.tool_name ? { read_via: unit.tool_name } : {}),
    };
  }
  if (unit.tool_name && /^(Read|Edit|Write|MultiEdit|NotebookEdit)$/.test(unit.tool_name) && unit.target) {
    return { source_kind: "file", source_ref: unit.target, read_via: unit.tool_name };
  }
  return { source_kind: "unknown", ...(unit.tool_name ? { read_via: unit.tool_name } : {}) };
}

/** The sink half: what carried the value out, and to where. */
export function readSink(unit: AccountUnit): Pick<ExposureAccount, "sink_tool" | "destination_host"> {
  const sender = firstWord(SENDERS, unit.raw);
  const host = extractHosts(unit.raw)[0];
  return {
    ...(sender ? { sink_tool: sender } : unit.tool_name ? { sink_tool: unit.tool_name } : {}),
    ...(host ? { destination_host: host } : {}),
  };
}

/* ---- Placeholder signals ------------------------------------------------- */

/**
 * SHA-256 of values a provider PUBLISHES as examples in its own documentation
 * (AWS's access key id and secret access key examples). Hashed so the bundle
 * ships no example key literal — a reader of the DMG sees digests, and the
 * guard that scans this repo's own commits sees no key shape. A value here
 * cannot authenticate anywhere, which is why it is the one placeholder signal
 * a caller may treat as certain.
 */
export const DOC_EXAMPLE_SHA256: ReadonlySet<string> = new Set([
  "1a5d44a2dca19669d72edf4c4f1c27c4c1ca4b4408fbb17f6ce4ad452d78ddb3",
  "78314b11be2e581549ac1c4f616563fad3fdf0c3b71678f6e2299182080e0598",
]);

export function isDocExample(value: string): boolean {
  return DOC_EXAMPLE_SHA256.has(createHash("sha256").update(value).digest("hex"));
}

const TEST_PATH = /(^|[\\/])(tests?|__tests__|spec|specs|fixtures?|examples?|docs?|samples?|mocks?|__mocks__|testdata)([\\/]|$)|\.(test|spec|stories)\.[cm]?[jt]sx?$|_test\.(go|py|rb)$|\btest_[\w.-]*\.py$/i;
const SYNTHETIC_WORDS = /EXAMPLE|SAMPLE|DUMMY|FAKE|PLACEHOLDER|CHANGEME|CHANGE_ME|REPLACE_ME|YOUR[_-]?(KEY|TOKEN|SECRET)|XXXX|TESTKEY|TEST_KEY|NOTREAL|NOT_REAL/i;
const NAMED_AS_EXAMPLE = /\b(example|fixture|placeholder|mock|dummy|fake|sample|live-looking|synthetic|made-up|not real|for (the )?tests?|test (key|token|secret|value|credential|fixture)|doc(s|umentation)? example)\b/i;
/** How far back from the value a naming comment or identifier may sit. */
const NAMING_REACH = 240;

/**
 * Fields of a tool call the AGENT wrote about the call rather than the data it
 * acts on — Claude's Bash `description`, Cursor's `explanation`, Codex's
 * `justification`. The agent's own label ("Test key") is its opinion of a
 * value it may not have looked at; a live Stripe key sent to a webhook read
 * as a placeholder because of one. Removed (string value and all, a cut-off
 * one too) before any naming is read.
 */
const AUTHORED_FIELD = /"(?:description|explanation|justification|reason|reasoning|rationale|summary|thought|thoughts)"\s*:\s*"(?:[^"\\]|\\.)*"?/g;

/** A host is where a value went, not what it is: `api.example.com` and
 *  `evil.example` are reserved test hosts, not text calling a value an
 *  example. URL authorities, mail domains and bare example.* hosts. */
const HOSTS = /\b[a-z][a-z0-9+.-]*:\/\/[^\s/"'`?#\\]+|@[\w.-]+\.[a-z]{2,}\b|\b(?:[\w-]+\.)*example\.(?:com|org|net|edu)\b/gi;

/** Where a masked text (an excerpt) has the value it is about. */
const MASK_MARKER = /\[redacted(?::[a-z0-9_]+)?\]/g;

/**
 * A value whose vendor prefix says it is LIVE — the families guard/redact.ts
 * names whose key carries a live/test mode (Stripe `sk_live_`/`rk_live_`,
 * Shippo, Duffel, Flutterwave's non-TEST secret) and AWS access key ids
 * (`AKIA` long-lived, `ASIA` session), which have no test mode at all. Where
 * such a value sits and what is written near it cannot make it a placeholder;
 * only the value itself can (a published example, a synthetic shape).
 */
const LIVE_VALUE = /^(?:(?:sk|rk|shippo|duffel)_live_|FLWSECK-|(?:AKIA|ASIA)[A-Z0-9]{16,17}$)/;

/** A run of consecutive ascending letters or digits, ≥ `n` long. */
export function hasSequentialRun(value: string, n = 8): boolean {
  let run = 1;
  for (let i = 1; i < value.length; i++) {
    const a = value.charCodeAt(i - 1);
    const b = value.charCodeAt(i);
    const sameClass = (/[A-Z]/.test(value[i - 1]!) && /[A-Z]/.test(value[i]!)) || (/[a-z]/.test(value[i - 1]!) && /[a-z]/.test(value[i]!)) || (/\d/.test(value[i - 1]!) && /\d/.test(value[i]!));
    run = sameClass && b === a + 1 ? run + 1 : 1;
    if (run >= n) return true;
  }
  return false;
}

/** The same character repeated ≥ `n` times in a row. */
export function hasRepeatRun(value: string, n = 6): boolean {
  return new RegExp(`(.)\\1{${n - 1},}`).test(value);
}

/**
 * Why `value` looks like a placeholder: its own shape, the path it lives in,
 * and naming in the DATA just before it — never text the agent wrote about
 * the call (AUTHORED_FIELD) and never a host. Empty when nothing says so.
 * `value` may be undefined (the reveal could not recover it): the path still
 * applies, and naming counts only right before a `[redacted…]` marker in a
 * masked text — with no value and no marker, there is nothing to be next to.
 * A LIVE_VALUE keeps only the signals read off the value itself.
 */
export function placeholderSignals(
  value: string | undefined,
  raw: string,
  paths: ReadonlyArray<string | undefined> = [],
): PlaceholderSignal[] {
  const out: PlaceholderSignal[] = [];
  const hasValue = value !== undefined && value !== "";
  const live = hasValue && LIVE_VALUE.test(value);
  if (!live && paths.some((p) => p !== undefined && TEST_PATH.test(p))) out.push("test_path");
  if (hasValue && isDocExample(value)) out.push("doc_example");
  if (hasValue && (SYNTHETIC_WORDS.test(value) || hasSequentialRun(value) || hasRepeatRun(value))) out.push("synthetic_value");
  const data = raw.replace(AUTHORED_FIELD, "");
  // Where the value sits in the data: the value itself, or — none recovered —
  // each mask marker standing in for it.
  const spots = hasValue ? [data.indexOf(value)].filter((at) => at >= 0) : [...data.matchAll(MASK_MARKER)].map((m) => m.index);
  if (!live && spots.some((at) => NAMED_AS_EXAMPLE.test(data.slice(Math.max(0, at - NAMING_REACH), at).replace(HOSTS, " ")))) {
    out.push("named_as_example");
  }
  return out;
}

/* ---- Verification --------------------------------------------------------- */

const QUOTED_FIELDS = ["source_ref", "name", "read_via", "sink_tool", "destination_host"] as const;

/** `/Users/x/repo/src/a.ts` under cwd `/Users/x/repo` → `src/a.ts`. A path
 *  a person can place at a glance; still a substring of the absolute one, so
 *  it verifies against the row's target. */
export function relativeTo(path: string | undefined, cwd: string | undefined): string | undefined {
  if (!path) return undefined;
  if (!cwd || cwd === "" || cwd === "/") return path;
  const base = cwd.endsWith("/") ? cwd : `${cwd}/`;
  return path.startsWith(base) && path.length > base.length ? path.slice(base.length) : path;
}

/**
 * Drop every quoted field that is not literally in one of `raws`. The
 * deterministic extractor cannot fail this (it read the fields out of the
 * text), so this is the contract the local-model reader is held to: a model
 * points at things that are there, or says nothing.
 */
export function verifyQuotes<T extends Partial<ExposureAccount>>(account: T, raws: readonly string[]): T {
  const out = { ...account };
  for (const field of QUOTED_FIELDS) {
    const value = out[field];
    if (typeof value !== "string") continue;
    const needle = value.toLowerCase();
    if (!raws.some((r) => r.toLowerCase().includes(needle))) delete out[field];
  }
  return out;
}

/* ---- Sentences ------------------------------------------------------------ */

const code = (s: string) => `\`${s}\``;

function whereRead(a: Partial<ExposureAccount>): string {
  switch (a.source_kind) {
    case "file":
      return `read ${a.source_ref ? code(a.source_ref) : "a file"}${a.read_via ? ` with ${code(a.read_via)}` : ""}`;
    case "env":
      return `dumped the environment${a.read_via ? ` with ${code(a.read_via)}` : ""}`;
    case "secret_manager":
      return `fetched it from a secret manager${a.read_via ? ` (${code(a.read_via)})` : ""}`;
    case "prompt":
      return "took it from a prompt";
    case "tool_output":
      return `saw it in a tool's output${a.read_via ? ` (${code(a.read_via)})` : ""}`;
    default:
      return a.read_via ? `read it with ${code(a.read_via)}` : "read it";
  }
}

function whereSent(a: Partial<ExposureAccount>): string {
  const to = a.destination_host ? ` to ${code(a.destination_host)}` : "";
  const with_ = a.sink_tool ? ` with ${code(a.sink_tool)}` : "";
  return `sent it${to}${with_}`;
}

/** The sentence for one account — what the transcript shows, and only that.
 *  Whether the value looks like a placeholder is the consequence's line
 *  (`renderSo`), so the two never say it twice. Pure; `detector` picks the frame. */
export function renderAccount(detector: string, a: Partial<ExposureAccount>): string {
  const fam = a.credential_family;
  switch (detector) {
    case "flow_secret_egress":
      return `Your agent ${whereRead(a)}, then${a.gap ? ` ${a.gap} later` : ""} ${whereSent(a)}.`;
    case "secret_egress":
      return `One command ${whereRead(a)} and ${whereSent(a)} in the same step.`;
    case "credential_in_tool_arg":
      if (a.source_kind === "tool_output") {
        return `A tool's output${a.read_via ? ` (${code(a.read_via)})` : ""} showed ${familyPhrase(fam)} to the agent.`;
      }
      return `The agent put ${familyPhrase(fam)} into ${a.sink_tool ? `a ${code(a.sink_tool)} call` : "a tool call"}${a.destination_host ? ` that reached ${code(a.destination_host)}` : ""}.`;
    case "credential_in_prompt":
      return `${capital(familyPhrase(fam))} was typed into a prompt.`;
    case "dotenv_read":
      return `The agent ${whereRead({ ...a, source_kind: "file" })}.`;
    case "env_dump":
      return `The agent ${whereRead({ ...a, source_kind: "env" })}; API keys usually live there.`;
    case "secret_manager_read":
      return `The agent ${whereRead({ ...a, source_kind: "secret_manager" })}.`;
    case "hardcoded_credential":
      return `A high-entropy value was assigned to ${q(a.name, "a secret-shaped name")} in ${q(a.source_ref, "a file")}${a.read_via ? ` (${code(a.read_via)})` : ""}.`;
    case "unrecognized_secret":
      return `A high-entropy token no named pattern claimed appeared ${inWhere(a)}.`;
    case "wallet_key_material":
      return `Wallet key material appeared ${inWhere(a)} — the one credential with no rotation.`;
    case "wallet_address_exposed":
      return `A wallet address appeared ${inWhere(a)}.`;
    case "wallet_address_tampered":
      return `A wallet address arrived from outside${a.gap ? ` and ${a.gap} later` : ", then"} was written or paid to${a.sink_tool ? ` with ${code(a.sink_tool)}` : ""}.`;
    case "pii_exposure":
      return `Personal data appeared ${inWhere(a)}.`;
    default:
      return `${capital(whereRead(a))}${a.destination_host || a.sink_tool ? `, then ${whereSent(a)}` : ""}.`;
  }
}

function inWhere(a: Partial<ExposureAccount>): string {
  switch (a.source_kind) {
    case "prompt":
      return "in a prompt";
    case "tool_output":
      return `in a tool's output${a.read_via ? ` (${code(a.read_via)})` : ""}`;
    case "file":
      return `in ${a.source_ref ? code(a.source_ref) : "a file"}`;
    default:
      return a.read_via ? `in a ${code(a.read_via)} call` : "in a tool call";
  }
}

function capital(s: string): string {
  return s.charAt(0).toUpperCase() + s.slice(1);
}

/* ---- Title, consequence, next step ---------------------------------------- */

/** "`.env`" / "a file"; "`curl`" / "a command" — a quoted field or its noun. */
const q = (value: string | undefined, noun: string) => (value ? code(value) : noun);

/** The headline for one exposure — what happened, specifically, in a few words. */
export function renderTitle(detector: string, a: Partial<ExposureAccount>): string {
  const fam = a.credential_family;
  const famNoun = familyNoun(fam);
  const cred = famNoun ? capital(famNoun) : "Credential";
  switch (detector) {
    case "flow_secret_egress":
      return `${q(a.source_ref, "Secret")} read, then sent${a.destination_host ? ` to ${code(a.destination_host)}` : " out"}`;
    case "secret_egress":
      return `Secret read and sent${a.destination_host ? ` to ${code(a.destination_host)}` : " out"} in one command`;
    case "credential_in_tool_arg":
      if (a.source_kind === "tool_output") return `${cred} in ${a.read_via ? `${code(a.read_via)} output` : "a tool's output"}`;
      return `${cred} in a ${q(a.sink_tool, "tool")} call`;
    case "credential_in_prompt":
      return `${cred} pasted into a prompt`;
    case "dotenv_read":
      return `${q(a.source_ref, "Credential file")} read${a.read_via ? ` with ${code(a.read_via)}` : ""}`;
    case "env_dump":
      return `Environment dumped${a.read_via ? ` with ${code(a.read_via)}` : ""}`;
    case "secret_manager_read":
      return `Secret fetched${a.read_via ? ` with ${code(a.read_via)}` : " from a secret manager"}`;
    case "hardcoded_credential":
      return a.name
        ? `${code(a.name)} assigned a secret-shaped value in ${q(a.source_ref, "a file")}`
        : `${famNoun ? capital(famNoun) : "Secret-shaped value"} written into ${q(a.source_ref, "a file")}`;
    case "unrecognized_secret":
      return `Unrecognized token ${inWhere(a)}`;
    case "wallet_key_material":
      return `Wallet key material ${inWhere(a)}`;
    case "wallet_address_exposed":
      return `Wallet address ${inWhere(a)}`;
    case "wallet_address_tampered":
      return "Wallet address from outside, then paid to";
    case "pii_exposure":
      return `Personal data ${inWhere(a)}`;
    default:
      return capital(whereRead(a));
  }
}

/** The consequence — what the exposure means for the person. */
export function renderSo(detector: string, a: Partial<ExposureAccount>): string {
  const ph = a.placeholder_signals ?? [];
  if (ph.length > 0) {
    // No `secret:`-shaped phrase: the masker reads `<word>: <word>` as a
    // credential assignment and would swallow the word after the colon.
    const why: string[] = [];
    if (ph.includes("doc_example")) why.push("it is a provider's published example value");
    if (ph.includes("test_path")) why.push("it lives under a test or docs path");
    if (ph.includes("named_as_example")) why.push("the data next to it calls it an example");
    if (ph.includes("synthetic_value")) why.push("its shape is synthetic");
    const reasons = why.length > 1 ? `${why.slice(0, -1).join(", ")} and ${why.at(-1)}` : why[0];
    return `It looks like a placeholder rather than a live secret, because ${reasons}.`;
  }
  const file = q(a.source_ref, "that file");
  const host = a.destination_host ? code(a.destination_host) : undefined;
  switch (detector) {
    case "flow_secret_egress":
      return `What ${file} holds may now be at ${host ?? "the destination"}. If that is not where those credentials belong, rotate them.`;
    case "secret_egress":
      return `The value went ${host ? `to ${host}` : "off this computer"} without passing through the agent's context. Routine if ${host ?? "the destination"} is where this credential is used; if not, rotate it.`;
    case "credential_in_tool_arg":
      if (a.source_kind === "tool_output") return "It went to the model provider with the tool's output.";
      return `It was in the agent's context, so the model provider has it; the command ran with it${host ? ` and reached ${host}` : ""}.`;
    case "credential_in_prompt":
      return "It went to the model provider with the prompt.";
    case "dotenv_read":
      if (a.output === "local") return `Its contents stayed on this computer: the command used ${file} without printing it, so none of it reached the model.`;
      if (a.output === "agent") return "What it printed went into the agent's context, and with it to the model provider.";
      return `If it printed ${file}, what it printed went into the agent's context and to the model provider.`;
    case "env_dump":
      if (a.output === "local") return "The environment stayed on this computer: the command used it without printing it.";
      if (a.output === "agent") return "Every variable it printed, keys included, went into the agent's context and to the model provider.";
      return "If it printed the environment, every variable it showed went into the agent's context and to the model provider.";
    case "secret_manager_read":
      if (a.output === "local") return "The value stayed on this computer: the command used it without printing it.";
      if (a.output === "agent") return "The value it printed went into the agent's context, and with it to the model provider.";
      return "If it printed the value, it went into the agent's context and to the model provider.";
    case "hardcoded_credential":
      return `${a.name ? `${code(a.name)} looks like a secret by name and the value by shape` : "The value looks like a secret by shape and its name"}; it now sits in ${file}, where it can be committed and pushed. The rule cannot tell a real key from a digest or a fixture — that is why it reads medium confidence.`;
    case "unrecognized_secret":
      return "The shape matched a secret; nothing named it. It may or may not be one.";
    case "wallet_key_material":
      return "A seed phrase or signer key cannot be rotated — its exposure is the loss.";
    case "wallet_address_exposed":
      return "An address is public by design; this is a record, not an alarm.";
    case "wallet_address_tampered":
      return "An address that arrived from outside was written or paid to — the swap an attacker's message is for.";
    case "pii_exposure":
      return "Personal data was in the agent's context and may have gone to the model provider.";
    default:
      return "";
  }
}

/** What to do about it. */
export function renderNext(detector: string, a: Partial<ExposureAccount>): string {
  if ((a.placeholder_signals ?? []).length > 0) {
    return "Nothing to rotate unless this value is also used somewhere real. If it is a fixture, mark it a false positive.";
  }
  const cred = `the ${familyNoun(a.credential_family) ?? "credential"}`;
  const file = q(a.source_ref, "that file");
  switch (detector) {
    case "flow_secret_egress":
      return `${a.destination_host ? `Check what ${code(a.destination_host)} is and why the agent sent there; rotate` : "Rotate"} what ${file} holds if it should not have gone there.`;
    case "secret_egress":
      return `Check that ${a.destination_host ? code(a.destination_host) : "the destination"} is where ${cred} is meant to go; rotate it if not.`;
    case "credential_in_tool_arg":
      if (a.source_kind === "tool_output") return `Rotate ${cred}, then find what printed it — a file read, an environment dump, a config print.`;
      return `Rotate ${cred}, then find how the agent got it — a pasted prompt or a file it read.`;
    case "credential_in_prompt":
      return `Rotate ${cred}, then find what put it in the prompt — a pasted .env, a config block.`;
    case "dotenv_read":
    case "env_dump":
    case "secret_manager_read":
      return a.output === "local" ? "Nothing to do." : "If what it printed included live credentials, rotate them.";
    case "hardcoded_credential":
      return `Open ${file}: if ${a.name ? code(a.name) : "the value"} is a real secret, move it to an environment variable or a secret manager before it is committed. If it is a digest, an id or a fixture, mark this a false positive.`;
    case "unrecognized_secret":
      return "Decide whether it is a real secret. If not, mark it a false positive; this rule never holds a call.";
    case "wallet_key_material":
      return "Move the funds to a fresh wallet, then find how the key got here.";
    case "wallet_address_exposed":
      return "Nothing to do, unless the address was not yours to share.";
    case "wallet_address_tampered":
      return "Check the address that was paid to against the one you meant.";
    case "pii_exposure":
      return "Check whether it should have been there. If it is test data, mark it a false positive.";
    default:
      return "";
  }
}

/* ---- Entry points --------------------------------------------------------- */

/** The families that get an account (guard/rule-scope.ts keeps exactly these). */
const ACCOUNTED = new Set([
  "credential_in_prompt", "credential_in_tool_arg", "secret_egress", "env_dump", "dotenv_read",
  "hardcoded_credential", "unrecognized_secret", "secret_manager_read", "flow_secret_egress",
  "wallet_key_material", "wallet_address_exposed", "wallet_address_tampered", "pii_exposure",
]);

export function accountable(detector: string): boolean {
  return ACCOUNTED.has(detector);
}

/** Where a secret read's output went, as its band records it (see
 * ExposureAccount.output): low is `local`, medium `agent`. Any other band — a
 * row from before the bands said so — leaves it unknown. */
export function readOutputOf(detector: string, severity: string | undefined): ExposureAccount["output"] {
  if (detector !== "dotenv_read" && detector !== "env_dump" && detector !== "secret_manager_read") return undefined;
  return severity === "low" ? "local" : severity === "medium" ? "agent" : undefined;
}

/** The recovered value this finding is about, if the reveal has it. */
function ownValue(finding: AccountFinding, secrets: readonly RedactedSecret[]): RedactedSecret | undefined {
  return secrets.find((s) => s.label === (finding.key_name ?? "")) ?? secrets[0];
}

/**
 * The account of a per-unit finding: the unit it fired on, plus the redacted
 * values the reveal recovered from it (may be [] — the fields then come from
 * the text and the path alone).
 */
/** A unit whose text and target are masked (lib/masking.ts) — what every
 * quoted field is read from. */
function maskedUnit(unit: AccountUnit): AccountUnit {
  return { ...unit, raw: maskText(unit.raw), ...(unit.target === undefined ? {} : { target: maskText(unit.target) }) };
}

export function accountForUnit(
  finding: AccountFinding,
  unit: AccountUnit,
  secrets: readonly RedactedSecret[] = [],
  cwd?: string,
): ExposureAccount | undefined {
  if (!accountable(finding.detector)) return undefined;
  const own = ownValue(finding, secrets);
  // Quotes come from the MASKED unit: the extractor picks tokens by shape (the
  // first dotted word is a "file"), and a SendGrid key or a JWT is dotted. The
  // placeholder judgement reads the raw text around a recovered value — it
  // yields signals, never quotes — and, with none recovered, the masked text,
  // whose markers stand where a value was.
  const quoted = maskedUnit(unit);
  const source = readSource(quoted);
  const sink = unit.kind === "tool_call" ? readSink(quoted) : {};
  const named = finding.detector === "hardcoded_credential" && finding.key_name ? { name: finding.key_name } : {};
  const family = finding.detector === "hardcoded_credential" ? {} : own?.label ? { credential_family: own.label } : finding.key_name ? { credential_family: finding.key_name } : {};
  const partial: Partial<ExposureAccount> = {
    by: "extractor",
    ...source,
    ...(source.source_ref ? { source_ref: relativeTo(source.source_ref, cwd) } : {}),
    ...sink,
    ...named,
    ...family,
    ...outputOf(readOutputOf(finding.detector, finding.severity)),
    placeholder_signals: placeholderSignals(own?.value, own ? unit.raw : quoted.raw, [unit.target, source.source_ref, cwd]),
  };
  // The tool's name, target and the finding's key are the unit's own metadata
  // — quotable, though not in the command text itself.
  const verified = verifyQuotes(partial, [quoted.raw, quoted.target ?? "", unit.tool_name ?? "", maskText(finding.key_name ?? "")]);
  return finish(finding.detector, verified);
}

/**
 * A THIN account from a row's own fields — no raw text. For rows minted before
 * accounts existed (the ledger keeps them) and for rows the guard's spool
 * minted at hold time, so the card is still specific: the file, the tool, the
 * name, the family, and the path-based placeholder signals. The snapshot
 * applies it to any row that lacks an account (index.ts); nothing is stored.
 */
export function accountForRow(row: {
  detector: string;
  key_name?: string;
  target?: string;
  tool_name?: string;
  cwd?: string;
  excerpt?: string;
  origin?: string;
  severity?: string;
}): ExposureAccount | undefined {
  if (!accountable(row.detector) || row.origin === "config") return undefined;
  const editor = row.tool_name !== undefined && /^(Read|Edit|Write|MultiEdit|NotebookEdit)$/.test(row.tool_name);
  const file = editor && row.target ? relativeTo(row.target, row.cwd) : undefined;
  const source: Pick<ExposureAccount, "source_kind" | "source_ref" | "read_via"> = file
    ? { source_kind: "file", source_ref: file, ...(row.tool_name ? { read_via: row.tool_name } : {}) }
    : row.detector === "credential_in_prompt"
      ? { source_kind: "prompt" }
      : { source_kind: "unknown", ...(row.tool_name ? { read_via: row.tool_name } : {}) };
  const named = row.detector === "hardcoded_credential" && row.key_name ? { name: row.key_name } : {};
  const family =
    row.detector === "hardcoded_credential" || row.detector === "unrecognized_secret" || !row.key_name
      ? {}
      : { credential_family: row.key_name };
  const partial: Partial<ExposureAccount> = {
    by: "extractor",
    ...source,
    ...(!editor && row.tool_name && row.detector === "credential_in_tool_arg" ? { sink_tool: row.tool_name } : {}),
    ...named,
    ...family,
    placeholder_signals: placeholderSignals(undefined, row.excerpt ?? "", [row.target, row.cwd]),
    ...outputOf(readOutputOf(row.detector, row.severity)),
  };
  const verified = verifyQuotes(partial, [row.target ?? "", row.tool_name ?? "", row.key_name ?? "", row.excerpt ?? ""]);
  return finish(row.detector, verified);
}

/**
 * The account of a flow: the source unit says where the value came from, the
 * sink unit says where it went, and the gap is the time between.
 */
export function accountForFlow(
  finding: AccountFinding & { source_at?: string; at?: string },
  source: AccountUnit,
  sink: AccountUnit,
  secrets: readonly RedactedSecret[] = [],
  cwd?: string,
): ExposureAccount | undefined {
  if (!accountable(finding.detector)) return undefined;
  const own = ownValue(finding, secrets);
  const quotedSource = maskedUnit(source);
  const quotedSink = maskedUnit(sink);
  const from = readSource(quotedSource);
  const to = readSink(quotedSink);
  const sourceAt = finding.source_at ?? source.at;
  const sinkAt = finding.at ?? sink.at;
  const partial: Partial<ExposureAccount> = {
    by: "extractor",
    ...from,
    ...(from.source_ref ? { source_ref: relativeTo(from.source_ref, cwd) } : {}),
    ...to,
    ...(own?.label ? { credential_family: own.label } : {}),
    ...(sourceAt && sinkAt ? { gap: flowGapLabel(sourceAt, sinkAt) } : {}),
    placeholder_signals: placeholderSignals(own?.value, own ? `${source.raw}\n${sink.raw}` : `${quotedSource.raw}\n${quotedSink.raw}`, [source.target, sink.target, from.source_ref, cwd]),
  };
  const verified = verifyQuotes(partial, [quotedSource.raw, quotedSink.raw, quotedSource.target ?? "", quotedSink.target ?? "", source.tool_name ?? "", sink.tool_name ?? ""]);
  return finish(finding.detector, verified);
}

/** `{ output }` when known, nothing otherwise — the field is optional on the record. */
function outputOf(output: ExposureAccount["output"]): Pick<ExposureAccount, "output"> {
  return output === undefined ? {} : { output };
}

/**
 * The same account with its sentence, title, consequence and next step
 * rendered again from its fields — for a stored row whose words were written
 * by an older template (lib/finding-bands.ts), and with `output` set when the
 * caller has since learned it.
 */
export function refreshAccountText(detector: string, account: ExposureAccount, output?: ExposureAccount["output"]): ExposureAccount {
  return finish(detector, output === undefined ? account : { ...account, output });
}

function finish(detector: string, a: Partial<ExposureAccount>): ExposureAccount {
  const account: ExposureAccount = {
    by: a.by ?? "extractor",
    source_kind: a.source_kind ?? "unknown",
    ...(a.source_ref ? { source_ref: a.source_ref } : {}),
    ...(a.name ? { name: a.name } : {}),
    ...(a.read_via ? { read_via: a.read_via } : {}),
    ...(a.sink_tool ? { sink_tool: a.sink_tool } : {}),
    ...(a.destination_host ? { destination_host: a.destination_host } : {}),
    ...outputOf(a.output),
    ...(a.credential_family ? { credential_family: a.credential_family } : {}),
    ...(familyNoun(a.credential_family) !== undefined ? { family_noun: familyNoun(a.credential_family) } : {}),
    ...(a.gap ? { gap: a.gap } : {}),
    placeholder_signals: a.placeholder_signals ?? [],
    sentence: "",
    title: "",
    so: "",
    next: "",
  };
  account.sentence = renderAccount(detector, account);
  account.title = renderTitle(detector, account);
  account.so = renderSo(detector, account);
  account.next = renderNext(detector, account);
  return account;
}
