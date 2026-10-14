// Local redaction — runs on the developer's machine, before any text is
// stored, exported or shown.
//
// This module is the privacy keystone of the app. The ordering matters and is
// not negotiable: text is redacted first, and only the redacted form is kept in
// the ledger, written to an export or folded into a prompt — so a copied report
// or an over-broad export cannot expose a secret that was scrubbed at the
// source.
//
// It is deliberately CONSERVATIVE — it over-redacts. A false positive costs a
// slightly less readable audit trail; a false negative writes somebody's
// production key into a ledger with a months-long retention window. When the
// two trade off, the redaction wins every time.
//
// IMPORTANT: this file is part of the guard bundle that is copied next to the
// agents' hook entries, so it may import nothing but a sibling module in that
// bundle (never a Node built-in). It takes exactly one:
// `findWalletKeyMaterial` from wallet-codec.ts, because a seed phrase is twelve
// ordinary English words and a WIF key is a Base58 run — neither is a regex
// shape, both need a wordlist or a checksum to tell from prose, and the codec
// is the one place those live (the security detectors read the same module).

import { findWalletKeyMaterial, type WalletKeyKind } from "./wallet-codec.js";

/**
 * High-signal secret shapes, matched before the generic rules below so a
 * recognised credential is replaced by a NAMED placeholder (`[redacted:aws]`)
 * rather than an anonymous one. Ordered most-specific first.
 *
 * Every pattern is anchored on a distinctive prefix or structural shape rather
 * than on entropy: an entropy heuristic flags base64-encoded prose and misses
 * short keys, which is exactly backwards for this use.
 */
const NAMED_SECRET_PATTERNS: ReadonlyArray<readonly [string, RegExp]> = [
  // ── Cloud + VCS provider tokens (prefix-addressable by design) ──
  // AWS publishes the full set of access-key-id prefixes, and they are all the
  // same shape: a 4-char type prefix + 16 base32 chars. Matching only
  // AKIA/ASIA (long-lived + STS) missed the rest — AROA (role), AIDA (user),
  // AGPA (group), APKA (public key), ANPA/ANVA (managed policy), ABIA/ACCA
  // (bearer/context), ASCA (certificate) — which are the ids that show up in a
  // pasted IAM policy or an `aws sts` transcript.
  //
  // 16 OR 17 body chars: access key ids are 20 chars total (AKIA + 16) but the
  // principal unique ids (AROA…, AIDA…) are 21. A flat {16} plus the trailing
  // \b silently matched NEITHER of the 21-char forms — the boundary can't fall
  // mid-word — so every role and user id sailed through untouched.
  ["aws", /\bA(?:KIA|SIA|ROA|IDA|IPA|GPA|PKA|NPA|NVA|BIA|CCA|SCA)[0-9A-Z]{16,17}\b/g],
  // The SECRET half of an AWS key pair: exactly 40 base64 characters. No prefix
  // to anchor on, so the shape does all the work — the run must be EXACTLY 40
  // (the trailing guard fails inside longer base64 blobs, so a pasted cert or
  // image never trips it), must contain a `+` or `/` (excludes base62 ids and
  // hex digests), and must mix cases and carry a digit (excludes prose and
  // PascalCase paths). Boundary guards exclude `-`/`=`/`/`-adjacent runs, which
  // is what keeps 40-char path segments out.
  // The extra boundary exclusions (`.`/`_` before, `_` after) and the
  // slash-count veto in the replacer are corpus-earned: without them this
  // matched 40-char windows of Google-Docs URLs and long filenames — path
  // text has many `/`s, a base64 secret rarely more than two.
  ["aws", /(?<![A-Za-z0-9+/=._-])(?=[A-Za-z0-9/+]*[+/])(?=[A-Za-z0-9/+]*[A-Z])(?=[A-Za-z0-9/+]*[a-z])(?=[A-Za-z0-9/+]*\d)[A-Za-z0-9/+]{40}(?![A-Za-z0-9+/=_-])/g],
  ["github", /\bgh[pousr]_[A-Za-z0-9]{16,}\b/g],
  // Fine-grained personal access tokens are a different prefix entirely — and
  // their underscores meant the generic high-entropy fallback ALSO discarded
  // them as identifier-shaped, so before this row they shipped unredacted.
  ["github", /\bgithub_pat_[A-Za-z0-9_]{22,}\b/g],
  ["gitlab", /\bgl(?:pat|rt|soat|ptt)-[A-Za-z0-9_-]{16,}\b/g],
  ["slack", /\bxox[abposr]-[A-Za-z0-9-]{10,}\b/g],
  // Slack app-level tokens are a different prefix and carry a `-` triplet.
  ["slack", /\bxapp-\d-[A-Za-z0-9-]{10,}\b/g],
  // An incoming-webhook URL IS the credential: anyone holding it can post to
  // the channel, and it carries no `xox` prefix, so neither rule above sees it.
  // The gitleaks sync skips the whole `slack` family (the hand-written rules
  // above are more specific), which is exactly how this shape fell through the
  // gap — it is the one Slack credential that looks like an ordinary URL.
  ["slack", /\bhooks\.slack\.com\/(?:services|workflows|triggers)\/[A-Za-z0-9+/_-]{8,}/g],
  // `whsec_` (webhook signing secret) alongside the API-key prefixes: it is
  // the credential a Stripe integration pastes most often when debugging, and
  // it does not match the `(sk|rk|pk)_(live|test)_` shape at all.
  ["stripe", /\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{16,}\b/g],
  ["stripe", /\bwhsec_[A-Za-z0-9]{16,}\b/g],
  // Anthropic and OpenRouter BEFORE OpenAI: `sk-ant-…` and `sk-or-…` also
  // satisfy the generic `sk-…` shape, so the looser rule would win on order
  // and mislabel the placeholder. All redact either way; the ordering is about
  // the label being truthful.
  ["anthropic", /\bsk-ant-[A-Za-z0-9_-]{20,}\b/g],
  ["openrouter", /\bsk-or-[A-Za-z0-9_-]{20,}\b/g],
  ["openai", /\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b/g],
  ["google", /\bAIza[0-9A-Za-z_-]{35}\b/g],
  // Google's OTHER two credential shapes, which `AIza` never saw: an OAuth
  // client secret (`GOCSPX-` + 28 base64url — the half of a client_secret.json
  // people paste when an OAuth flow breaks) and a live OAuth access token
  // (`ya29.` + a long base64url run; real ones are 150+ chars, so 20 is a
  // floor prose can't reach, not a length claim). The gitleaks sync skips the
  // whole `google`/`gcp` family, so these rows are the only coverage. The
  // client secret can END in `-`, where \b cannot fall — an explicit guard.
  ["google", /\bGOCSPX-[A-Za-z0-9_-]{28}(?![A-Za-z0-9_-])/g],
  ["google", /\bya29\.[0-9A-Za-z_-]{20,}/g],
  // The rest of the LLM-provider keys a spend monitor sees pasted all day.
  ["groq", /\bgsk_[A-Za-z0-9]{20,}\b/g],
  ["perplexity", /\bpplx-[A-Za-z0-9]{20,}\b/g],
  ["xai", /\bxai-[A-Za-z0-9_-]{20,}\b/g],
  // Azure AD client secrets carry a fixed `8Q~` at offset 3 — the one
  // structural anchor the format has. `~`/`.` sit at the edges of word
  // boundaries, so explicit guards instead of \b.
  ["azure", /(?<![A-Za-z0-9_~.-])[A-Za-z0-9_~.]{3}8Q~[A-Za-z0-9_~.-]{30,}(?![A-Za-z0-9_~.-])/g],
  // Fixed-length hex/base62 bodies, so each is anchored tightly enough that
  // prose can't trip it. These are the tokens that turn up in a pasted CI
  // config or a "why is my deploy failing" prompt.
  ["sendgrid", /\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b/g],
  ["npm", /\bnpm_[A-Za-z0-9]{36}\b/g],
  ["pypi", /\bpypi-[A-Za-z0-9_-]{16,}\b/g],
  ["huggingface", /\bhf_[A-Za-z0-9]{16,}\b/g],
  ["digitalocean", /\bdop_v1_[a-f0-9]{64}\b/g],
  ["shopify", /\bshp(?:at|ca|pa|ss)_[a-f0-9]{32}\b/g],
  ["linear", /\blin_api_[A-Za-z0-9]{32,}\b/g],
  ["databricks", /\bdapi[a-f0-9]{32}\b/g],
  ["twilio", /\b(?:AC|SK)[a-f0-9]{32}\b/g],
  ["cloudflare", /\bv1\.0-[A-Za-z0-9]{16,}-[A-Za-z0-9_-]{40,}\b/g],
  // ── Generic secret-prefixed tokens ──
  // The long tail of bespoke and smaller-provider keys that NAME themselves:
  // `secret_…` (Notion's shape, among others), `token_…`, `api_key_…`, `key-…`
  // (legacy Mailgun). The body must be one unbroken alphanumeric run of 16+
  // carrying a digit — `secret_key_base` and other snake_case identifiers stop
  // at their next underscore and never match, prose has no 16-char digit-bearing
  // runs, and anything shorter is likelier a name than a key.
  ["generic", /\b(?:secret|token|apikey|api[_-]?key|api|key)[_-](?=[A-Za-z0-9]*\d)[A-Za-z0-9]{16,}\b/gi],
  // Two vendor prefixes the rule above can't see (neither says `secret`/
  // `token`) and gitleaks v8.24.3 doesn't carry. Labelled `generic` rather than
  // a vendor family ON PURPOSE: a new label must also be named in the card
  // words (account.ts), and until then the redaction is what matters. The cost
  // is that security-detect treats `generic` as a heuristic (medium
  // confidence); promoting these to `notion`/`supabase` in both places is the
  // follow-up.
  //  · Notion integration tokens (the `ntn_` form that replaced `secret_` in
  //    2024) are `ntn_` + 46 base62 today; 40+ keeps a slightly shorter or
  //    longer revision redacted, and no prose word is 40 unbroken base62 chars.
  //  · Supabase personal access tokens: `sbp_` + exactly 40 lowercase hex.
  ["generic", /\bntn_[0-9A-Za-z]{40,}\b/g],
  ["generic", /\bsbp_[0-9a-f]{40}\b/g],
  // ── Structural shapes ──
  ["jwt", /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g],
  ["private_key", /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g],
  // ── Crypto exchange + chain-infrastructure credentials ──
  // Wallet KEY MATERIAL — seed
  // phrases, WIF, xprv, keystores — is not in this table: those shapes need a
  // wordlist or a checksum, so redactWalletKeys below hands them to the codec.
  // Robinhood Crypto's trading API key id (`rh-api-<uuid>`); the Ed25519
  // private key it pairs with has no prefix and is the assignment rules' job.
  ["robinhood", /\brh-api-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi],
  // Coinbase Developer Platform key NAME — the PEM half is `private_key` above.
  ["coinbase_cdp", /\borganizations\/[0-9a-f-]{36}\/apiKeys\/[0-9a-f-]{36}\b/gi],
  // A node-provider RPC URL's key segment: whoever holds it spends the
  // person's quota and can front-run what they broadcast through it. The host
  // is kept (lookbehind) so the line still reads as the endpoint it was.
  // A raw EVM signer key, recognised by what NAMES it: `--private-key 0x…`
  // (cast / forge / hardhat), `PRIVATE_KEY=0x…`, `privateKey: "0x…"`. The
  // 32-byte hex body has no prefix of its own — bare it is every SHA-256 in a
  // lockfile — so the naming argument is the whole anchor, kept readable by
  // the lookbehind. Before this, `cast send … --private-key <hex>` reached the
  // spool and the approval preview in cleartext: the one crypto_operations
  // pack rule built to catch signer keys was the channel that stored one.
  // The hex body is tested FIRST (a lookahead that fails on the first non-hex
  // character) and the naming lookbehind is bounded and unambiguous: an
  // open-ended `\s*[=:\s]\s*` lookbehind re-scanned every whitespace run from
  // every position, and 4,000 spaces took 40 s — past the hook's timeout.
  ["evm_private_key", /(?<![0-9a-fA-F])(?=(?:0x)?[0-9a-fA-F]{64}(?![0-9a-fA-F]))(?<=(?:--private-keys?|--pk)(?:=|[ \t]{1,4})(?:\\?["'])?|(?:private[_-]?key|sign(?:er|ing)[_-]?key|deployer[_-]?(?:private[_-]?)?key)(?:\\?["'])?[ \t]{0,4}[=:][ \t]{0,4}(?:\\?["'])?)(?:0x)?[0-9a-fA-F]{64}(?![0-9a-fA-F])/gi],
  ["rpc_key", /(?<=\.g\.alchemy\.com\/v2\/)[A-Za-z0-9_-]{16,}\b/g],
  ["rpc_key", /(?<=\.infura\.io\/v3\/)[0-9a-f]{32}\b/gi],
  ["rpc_key", /(?<=helius-rpc\.com\/\?api-key=)[0-9a-f-]{36}\b/gi],
  ["rpc_key", /(?<=\.quiknode\.pro\/)[A-Za-z0-9]{20,}\b/g],
  // A URL carrying inline credentials (postgres://user:pw@host, https://x:y@h).
  // The user half may be EMPTY: `redis://:pw@host` is how Redis spells a
  // password-only URL, and requiring a user let the email rule below claim
  // `pw@host` as an address instead.
  //
  // Every quantifier here is BOUNDED and every match starts at a token
  // boundary (lookbehind), because these run over up to 64 KB of tool output
  // on the hook's clock: unbounded, `a.` × 30,000 took 14 s in the email rule
  // alone — past the hook timeout, which fails open.
  //
  // The password half may contain `/` (people do write `mysql://root:a/b@db`,
  // and stopping at the slash leaked `a/`) — but not when it is a PORT, so
  // `https://host:8080/p?to=a@b.c` stays a URL with a path. It may also hold
  // a space or two (`admin:pa ss@db`), which left `admin:pa` behind as text
  // while the email rule claimed only `ss@db…`.
  ["url_credentials", /(?<![A-Za-z0-9+.-])([a-z][a-z0-9+.-]{0,31}:\/\/)[^\s/@:]{0,256}:(?!\d{1,5}(?:[/?#\s]|$))[^\s@]{1,256}(?: [^\s@/]{1,64}){0,2}@/gi],
  ["email", /(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,24}\b/g],
];

// === GITLEAKS RULES BELOW — generated from gitleaks v8.24.3 config (MIT) by bin/dev/sync-gitleaks-rules.mjs; do not edit by hand ===
const GITLEAKS_PATTERNS: ReadonlyArray<readonly [string, RegExp]> = [
  ["1password_service_account_token", /ops_eyJ[a-zA-Z0-9+\/]{250,}={0,3}/g],
  ["adobe_client_secret", /\b(p8e-[a-z0-9]{32})(?:[\x60'"\s;]|\\[nrt"'\\]|$)/gi],
  ["age_secret_key", /AGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}/g],
  ["alibaba_access_key_id", /\b(LTAI[a-z0-9]{20})(?:[\x60'"\s;]|\\[nrt"'\\]|$)/gi],
  ["clojars_api_token", /CLOJARS_[a-z0-9]{60}/gi],
  ["doppler_api_token", /dp\.pt\.[a-z0-9]{43}/gi],
  ["duffel_api_token", /duffel_(?:test|live)_[a-z0-9_\-=]{43}/gi],
  ["dynatrace_api_token", /dt0c01\.[a-z0-9]{24}\.[a-z0-9]{64}/gi],
  ["easypost_api_token", /\bEZAK[a-z0-9]{54}\b/gi],
  ["easypost_test_api_token", /\bEZTK[a-z0-9]{54}\b/gi],
  ["facebook_access_token", /\b(\d{15,16}(\||%)[0-9a-z\-_]{27,40})(?:[\x60'"\s;]|\\[nrt"'\\]|$)/gi],
  ["facebook_page_access_token", /\b(EAA[MC][a-z0-9]{100,})(?:[\x60'"\s;]|\\[nrt"'\\]|$)/gi],
  ["flutterwave_encryption_key", /FLWSECK_TEST-[a-h0-9]{12}/gi],
  ["flutterwave_public_key", /FLWPUBK_TEST-[a-h0-9]{32}-X/gi],
  ["flutterwave_secret_key", /FLWSECK_TEST-[a-h0-9]{32}-X/gi],
  ["flyio_access_token", /\b((?:fo1_[\w-]{43}|fm1[ar]_[a-zA-Z0-9+\\/]{100,}={0,3}|fm2_[a-zA-Z0-9+\\/]{100,}={0,3}))(?:[\x60'"\s;]|\\[nrt"'\\]|$)/g],
  ["frameio_api_token", /fio-u-[a-z0-9\-_=]{64}/gi],
  ["freemius_secret_key", /\\?["']secret_key\\?["']\s*=>\s*\\?["'](sk_[\S]{29})\\?["']/gi],
  ["grafana_api_key", /\b(eyJrIjoi[A-Za-z0-9]{70,400}={0,3})(?:[\x60'"\s;]|\\[nrt"'\\]|$)/gi],
  ["grafana_cloud_api_token", /\b(glc_[A-Za-z0-9+\/]{32,400}={0,3})(?:[\x60'"\s;]|\\[nrt"'\\]|$)/gi],
  ["grafana_service_account_token", /\b(glsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8})(?:[\x60'"\s;]|\\[nrt"'\\]|$)/gi],
  ["harness_api_key", /(?:pat|sat)\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9]{24}\.[a-zA-Z0-9]{20}/g],
  ["infracost_api_token", /\b(ico-[a-zA-Z0-9]{32})(?:[\x60'"\s;]|\\[nrt"'\\]|$)/g],
  ["intra42_client_secret", /\b(s-s4t2(?:ud|af)-[abcdef0123456789]{64})(?:[\x60'"\s;]|\\[nrt"'\\]|$)/gi],
  ["maxmind_license_key", /\b([A-Za-z0-9]{6}_[A-Za-z0-9]{29}_mmk)(?:[\x60'"\s;]|\\[nrt"'\\]|$)/g],
  ["microsoft_teams_webhook", /https:\/\/[a-z0-9]+\.webhook\.office\.com\/webhookb2\/[a-z0-9]{8}-([a-z0-9]{4}-){3}[a-z0-9]{12}@[a-z0-9]{8}-([a-z0-9]{4}-){3}[a-z0-9]{12}\/IncomingWebhook\/[a-z0-9]{32}\/[a-z0-9]{8}-([a-z0-9]{4}-){3}[a-z0-9]{12}/g],
  ["nuget_config_password", /<add key=\"(?:(?:ClearText)?Password)\"\s*value=\"(.{8,})\"\s*\/>/gi],
  ["octopus_deploy_api_key", /\b(API-[A-Z0-9]{26})(?:[\x60'"\s;]|\\[nrt"'\\]|$)/g],
  ["openshift_user_token", /\b(sha256~[\w-]{43})(?:[^\w-]|$)/g],
  ["planetscale_api_token", /\b(pscale_tkn_[\w=\.-]{32,64})(?:[\x60'"\s;]|\\[nrt"'\\]|$)/gi],
  ["planetscale_oauth_token", /\b(pscale_oauth_[\w=\.-]{32,64})(?:[\x60'"\s;]|\\[nrt"'\\]|$)/g],
  ["planetscale_password", /\b(pscale_pw_[\w=\.-]{32,64})(?:[\x60'"\s;]|\\[nrt"'\\]|$)/gi],
  ["postman_api_token", /\b(PMAK-[a-f0-9]{24}\-[a-f0-9]{34})(?:[\x60'"\s;]|\\[nrt"'\\]|$)/gi],
  ["prefect_api_token", /\b(pnu_[a-zA-Z0-9]{36})(?:[\x60'"\s;]|\\[nrt"'\\]|$)/g],
  ["pulumi_api_token", /\b(pul-[a-f0-9]{40})(?:[\x60'"\s;]|\\[nrt"'\\]|$)/g],
  ["readme_api_token", /\b(rdme_[a-z0-9]{70})(?:[\x60'"\s;]|\\[nrt"'\\]|$)/g],
  ["rubygems_api_token", /\b(rubygems_[a-f0-9]{48})(?:[\x60'"\s;]|\\[nrt"'\\]|$)/g],
  ["scalingo_api_token", /\b(tk-us-[\w-]{48})(?:[\x60'"\s;]|\\[nrt"'\\]|$)/g],
  ["sendinblue_api_token", /\b(xkeysib-[a-f0-9]{64}\-[a-z0-9]{16})(?:[\x60'"\s;]|\\[nrt"'\\]|$)/gi],
  ["sentry_org_token", /\bsntrys_eyJpYXQiO[a-zA-Z0-9+\/]{10,200}(?:LCJyZWdpb25fdXJs|InJlZ2lvbl91cmwi|cmVnaW9uX3VybCI6)[a-zA-Z0-9+\/]{10,200}={0,2}_[a-zA-Z0-9+\/]{43}(?:[^a-zA-Z0-9+\/]|$)/g],
  ["sentry_user_token", /\b(sntryu_[a-f0-9]{64})(?:[\x60'"\s;]|\\[nrt"'\\]|$)/g],
  ["settlemint_application_access_token", /\b(sm_aat_[a-zA-Z0-9]{16})(?:[\x60'"\s;]|\\[nrt"'\\]|$)/g],
  ["settlemint_personal_access_token", /\b(sm_pat_[a-zA-Z0-9]{16})(?:[\x60'"\s;]|\\[nrt"'\\]|$)/g],
  ["settlemint_service_access_token", /\b(sm_sat_[a-zA-Z0-9]{16})(?:[\x60'"\s;]|\\[nrt"'\\]|$)/g],
  ["shippo_api_token", /\b(shippo_(?:live|test)_[a-fA-F0-9]{40})(?:[\x60'"\s;]|\\[nrt"'\\]|$)/g],
  ["sidekiq_sensitive_url", /\bhttps?:\/\/([a-f0-9]{8}:[a-f0-9]{8})@(?:gems.contribsys.com|enterprise.contribsys.com)(?:[\\/|\#|\?|:]|$)/gi],
  ["square_access_token", /\b((?:EAAA|sq0atp-)[\w-]{22,60})(?:[\x60'"\s;]|\\[nrt"'\\]|$)/g],
  ["vault_batch_token", /\b(hvb\.[\w-]{138,300})(?:[\x60'"\s;]|\\[nrt"'\\]|$)/g],
];
// === GITLEAKS RULES END (48 rules) ===

/**
 * Every pattern one pass applies: the hand-written table first (its labels are
 * more specific and its ordering deliberate), then the generated gitleaks
 * corpus for the long tail of providers nobody hand-writes rows for.
 */
const ALL_SECRET_PATTERNS: ReadonlyArray<readonly [string, RegExp]> = [
  ...NAMED_SECRET_PATTERNS,
  ...GITLEAKS_PATTERNS,
];

// ── Crypto wallet key material ───────────────────────────────────────────────
//
// The placeholder family each codec kind becomes. `bip39` is the one shape no
// secret scanner ships (gitleaks #1082 is still open): a seed phrase is
// dictionary words, so it needs the 2048-word list and the checksum, both of
// which live in wallet-codec.ts. security-detect.ts reads these same labels to
// raise `wallet_key_material` instead of the generic credential detectors.
export const WALLET_KEY_LABELS: Readonly<Record<WalletKeyKind, string>> = {
  bip39_mnemonic: "bip39",
  wif: "wif",
  xprv: "xprv",
  xpub: "xpub",
  solana_keypair: "solana_keypair",
  eth_keystore: "eth_keystore",
};

/**
 * The distinct credential families the built-in table recognises, in table
 * order — the "always redacted" floor a person gets before writing a single
 * rule.
 *
 * Derived from NAMED_SECRET_PATTERNS rather than hand-listed, so a pattern
 * added above cannot drift out of a list built from it.
 */
export const BUILTIN_SECRET_LABELS: readonly string[] = [
  ...new Set([...ALL_SECRET_PATTERNS.map(([label]) => label), ...Object.values(WALLET_KEY_LABELS)]),
];

// ── Placeholders that merely LOOK like credentials ──────────────────────────
//
// A named family is a claim — "a live stripe key was here" — and three things
// act on it: the guard asks before the call runs, Radar raises
// credential_in_prompt / credential_in_tool_arg, and the session-flow rules
// taint every later network call. So the claim must not be made for text that
// is visibly a stand-in: a template (`postgres://{user}:{password}@…`), an
// env-var reference, filler (`sk_test_xxxx…`, `AC000…0`), a "your key here"
// sentence, or a key a provider PUBLISHED in its docs. Such a match is still
// scrubbed — it becomes the anonymous `[redacted]`, so the over-redaction rule
// above holds — it just names no family, which is what stops it raising
// anything. Deliberately narrow: each test is a property random key material
// has with negligible probability, never a guess about entropy.

/**
 * Keys providers print in their own documentation — real-shaped, never live:
 * Stripe's docs-wide test key and the jwt.io debugger's default signature.
 * Held as digests, not literals, for the reason account.ts's DOC_EXAMPLE_SHA256
 * gives: nothing this file ships should itself read as a key shape. cyrb53
 * rather than SHA-256 because this file is part of the guard bundle and may
 * import no built-in;
 * a collision would only cost one real key its family label, never its
 * redaction. (AWS's published examples need no entry — they say EXAMPLE.)
 */
const PUBLISHED_EXAMPLE_DIGESTS: ReadonlySet<string> = new Set(["23d0ux4pvz2", "2d7cjjo7jtk"]);

function cyrb53(text: string): string {
  let h1 = 0xdeadbeef;
  let h2 = 0x41c6ce57;
  for (let i = 0; i < text.length; i += 1) {
    const c = text.charCodeAt(i);
    h1 = Math.imul(h1 ^ c, 2654435761);
    h2 = Math.imul(h2 ^ c, 1597334677);
  }
  h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507);
  h1 ^= Math.imul(h2 ^ (h2 >>> 13), 3266489909);
  h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507);
  h2 ^= Math.imul(h1 ^ (h1 >>> 13), 3266489909);
  return (4294967296 * (2097151 & h2) + (h1 >>> 0)).toString(36);
}

/** Words a stand-in says out loud. `example` covers AWS's AKIAIOSFODNN7EXAMPLE
 * and its secret-key twin. */
const PLACEHOLDER_WORD_RE = /your|placeholder|example|here|changeme|dummy|fake|redacted|replace|insert|x{4,}|\*{4,}/i;

/** Ascending runs nobody's RNG produces: `1234567890`, `abcdefghij`. */
const SEQUENTIAL_RUN_RE = /0123456789|1234567890|abcdefghij/i;

/** Template / variable syntax inside a value: `{user}`, `${PW}`, `$PW`, `%s`,
 * `<password>`, a JS template's backtick. */
const TEMPLATE_SYNTAX_RE = /[{}<>`]|\$[A-Za-z_(]|%[sd]/;

/** What documentation writes in a URL's userinfo instead of a credential. */
const USERINFO_WORD_RE = /^(?:user(?:name)?|usr|login|name|pass(?:word)?|passwd|pwd|pw|secret|x|y)$/i;

/** Is one run of key material filler — one character repeated, near enough? */
function isFillerRun(run: string): boolean {
  if (run.length < 8) return false;
  const counts = new Map<string, number>();
  for (const ch of run.toLowerCase()) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  return Math.max(...counts.values()) / run.length >= 0.75;
}

/**
 * Is this named-table match a stand-in rather than a credential? `label` is
 * the family it would be given; `match` the full matched text.
 */
export function isPlaceholderSecret(label: string, match: string): boolean {
  if (label === "email") return false;
  if (label === "url_credentials") {
    const userinfo = match.replace(/^[a-z][a-z0-9+.-]*:\/\//i, "").replace(/@$/, "");
    const colon = userinfo.indexOf(":");
    const user = userinfo.slice(0, colon);
    const password = userinfo.slice(colon + 1);
    if (TEMPLATE_SYNTAX_RE.test(userinfo)) return true;
    if (PLACEHOLDER_WORD_RE.test(password) || isFillerRun(password) || /^\*+$/.test(password)) return true;
    // `username:password`, `user:pass` — both halves are the NAMES of fields.
    return (user === "" || USERINFO_WORD_RE.test(user)) && USERINFO_WORD_RE.test(password);
  }
  if (label === "private_key") {
    const body = match.replace(/-----(?:BEGIN|END) [A-Z ]*PRIVATE KEY-----/g, "");
    // A real key's body is hundreds of base64 characters; `...` or
    // `YOUR_KEY_HERE` between the armour lines is a template.
    return (body.match(/[A-Za-z0-9+/]/g) ?? []).length < 64 || PLACEHOLDER_WORD_RE.test(body);
  }
  // No template test for token shapes: their bodies can't hold `{`/`$`, and
  // the gitleaks rows' trailing delimiter class includes a backtick, so a key
  // quoted in Markdown would read as a JS template.
  for (const run of match.match(/[A-Za-z0-9_-]{20,}/g) ?? []) if (PUBLISHED_EXAMPLE_DIGESTS.has(cyrb53(run))) return true;
  if (PLACEHOLDER_WORD_RE.test(match) || SEQUENTIAL_RUN_RE.test(match)) return true;
  // Filler: the body's longest alphanumeric run is (nearly) one character —
  // `ghp_xxxx…`, `SG.xxxx….yyyy…`, `AC` + 32 zeros, a Slack webhook's `XXXX`.
  const runs = match.match(/[A-Za-z0-9]+/g) ?? [];
  const longest = runs.reduce((a, b) => (b.length > a.length ? b : a), "");
  if (isFillerRun(longest)) return true;
  if (label === "facebook_access_token") {
    // gitleaks' shape is `<15-16 digits>|<27-40 chars>` — which a log or
    // table row satisfies. A real app token's second half is hex/base62 key
    // material: letters AND digits, no word separators.
    const tail = match.split(/\||%/)[1] ?? "";
    const body = tail.replace(/[\x60'"\s;]+$|\\[nr]$/, "");
    return /[_-]/.test(body) || !/\d.*\d.*\d/.test(body) || !/[a-z].*[a-z].*[a-z]/i.test(body);
  }
  return false;
}

/** Replace every codec-verified key span, back to front so indices hold. */
function redactWalletKeys(text: string): string {
  const hits = findWalletKeyMaterial(text);
  if (hits.length === 0) return text;
  let out = text;
  for (let i = hits.length - 1; i >= 0; i -= 1) {
    const hit = hits[i]!;
    out = `${out.slice(0, hit.start)}[redacted:${WALLET_KEY_LABELS[hit.kind]}]${out.slice(hit.end)}`;
  }
  return out;
}

/**
 * Generic `KEY=value` / `"key": "value"` assignments whose KEY NAME implies a
 * secret. This is the rule that catches the long tail — a bespoke internal
 * token has no recognisable prefix, but it is almost always assigned to
 * something called `*_TOKEN`, `*_SECRET`, `password`, etc.
 *
 * Only the VALUE is replaced; the key name is preserved, because "an
 * DATABASE_PASSWORD was present here" is exactly the useful part of the audit
 * trail and carries no secret itself.
 */
const SECRET_KEY_NAME = "(?:api[_-]?key|secret|token|password|passwd|pwd|credential|auth|bearer|private[_-]?key|access[_-]?key|session[_-]?id|sign(?:er|ing)[_-]?key|mnemonic|seed[_-]?phrase|passphrase)";
const ASSIGNMENT_PATTERNS: ReadonlyArray<RegExp> = [
  // Authorization headers FIRST. The generic rule below also matches
  // "Authorization" (it contains "auth"), but it would treat the scheme as the
  // value — yielding "Authorization: [redacted] <token>" and leaving the actual
  // credential in place. Consuming the scheme here is what prevents that.
  // Group 1 + group 2 is the preserved prefix ("Authorization: " + "Bearer "),
  // group 3 is the value dropped — the same two-leading-groups shape the
  // generic rule uses, which is what lets one replacer handle both.
  // The value class excludes BACKSLASH, and that is load-bearing: a tool input
  // arrives here as `JSON.stringify(tool_input)`, so the header reads
  // `…Bearer sk-ant-…\"` and a backslash-tolerant class swallowed the trailing
  // `\` into the value. That made the already-substituted `[redacted:anthropic]`
  // read as `[redacted:anthropic]\`, which fails PLACEHOLDER_ONLY_RE below, so
  // the family label was overwritten with the anonymous placeholder — and
  // `credential_in_tool_arg` only fires on a NAMED family, so a live bearer
  // token in a curl call produced no finding at all. Every tool call is the
  // JSON-escaped shape, so this was the common case, not an edge one.
  /\b(Authorization\s*:\s*)((?:Bearer|Basic|Token)\s+(?:\\?["'])?)([^\s"',;\\]+)/gi,
  // KEY=value / KEY: value  (shell, env files, YAML) and the JSON form
  // `"key": "value"` — the optional closing quote before the separator is what
  // makes the JSON case work. Without it the quote terminated the key match and
  // `{"access_token": "…"}` sailed through unredacted, which is precisely the
  // shape a captured tool argument arrives in. Value runs to whitespace, quote,
  // comma, or semicolon.
  //
  // The BACKSLASH-ESCAPED quote form (`\"value\"`) is listed first, and it is
  // not a theoretical case: an activity row stores `JSON.stringify(tool_input)`,
  // so an Edit that writes `const API_TOKEN = "…"` into a source file arrives
  // here as `…new_string":"const API_TOKEN = \"…\";"`. Without this alternative
  // the bare-value branch matched the lone backslash, produced
  // `API_TOKEN = [redacted]"…"`, and left the credential itself in the excerpt —
  // which then persisted for the whole activity retention window. Editing source
  // code is the most common tool call there is, so this was the common case, not
  // an edge one.
  new RegExp(
    `(?<![A-Za-z0-9_.-])([A-Za-z0-9_.-]{0,64}${SECRET_KEY_NAME}[A-Za-z0-9_.-]{0,64})((?:\\\\?")?\\s*[:=]\\s*)(?:\\\\"([^"\\\\]*)\\\\"|"([^"]*)"|'([^']*)'|([^\\s"',;]+))`,
    "gi",
  ),
  // -H 'Authorization: ...' style curl flags are covered by the rules above.
];

export const REDACTED = "[redacted]";

// ── Invisible-character smuggling ────────────────────────────────────────────
//
// One zero-width character inside a key defeats every pattern above: the run
// breaks, no placeholder is emitted, and the split halves are individually too
// short for even the entropy fallback. So the named table is ALSO run against a
// shadow copy with invisible characters removed, and a match found only there
// is mapped back to its raw span (invisible characters included) and replaced.
//
// Only spans that actually contained an invisible character are rewritten this
// way — everything else is the ordinary pass's job — and characters OUTSIDE a
// matched span are left alone, so the invisible-unicode detector downstream
// still sees the smuggling it exists to flag.
const INVISIBLE_CHAR_RE =
  /[\u00AD\u034F\u061C\u200B-\u200F\u2060-\u2064\u202A-\u202E\u2066-\u2069\uFEFF\u{E0000}-\u{E007F}]/gu;

function redactSmuggledSecrets(text: string): string {
  INVISIBLE_CHAR_RE.lastIndex = 0;
  if (!INVISIBLE_CHAR_RE.test(text)) return text;

  // Shadow copy + index map: normalized[i] came from raw index map[i].
  let normalized = "";
  const map: number[] = [];
  let i = 0;
  for (const ch of text) {
    INVISIBLE_CHAR_RE.lastIndex = 0;
    if (!INVISIBLE_CHAR_RE.test(ch)) {
      normalized += ch;
      for (let k = 0; k < ch.length; k += 1) map.push(i + k);
    }
    i += ch.length;
  }

  const spans: Array<[start: number, end: number, label: string]> = [];
  for (const [label, pattern] of ALL_SECRET_PATTERNS) {
    // Structural text shapes (emails, URLs) aren't smuggling targets worth a
    // second pass; every provider token above them is.
    if (label === "email" || label === "url_credentials" || label === "private_key") continue;
    pattern.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = pattern.exec(normalized)) !== null) {
      const rawStart = map[match.index]!;
      const rawEnd = map[match.index + match[0].length - 1]! + 1;
      // Only a span the ordinary pass CANNOT see (it contained an invisible
      // character) is handled here.
      if (rawEnd - rawStart > match[0].length) spans.push([rawStart, rawEnd, label]);
    }
  }
  if (spans.length === 0) return text;

  // Replace back-to-front so earlier spans keep their indices; skip overlaps.
  spans.sort((a, b) => b[0] - a[0]);
  let out = text;
  let lastStart = Infinity;
  for (const [start, end, label] of spans) {
    if (end > lastStart) continue;
    const tag = isPlaceholderSecret(label, text.slice(start, end).replace(INVISIBLE_CHAR_RE, ""))
      ? REDACTED
      : `[redacted:${label}]`;
    out = `${out.slice(0, start)}${tag}${out.slice(end)}`;
    lastStart = start;
  }
  return out;
}

/** Matches either placeholder form this module emits: the anonymous `[redacted]`
 * and the named `[redacted:aws]`. */
const PLACEHOLDER_RE = /\[redacted(?::[a-z0-9_]+)?\]/g;

/** The same, anchored: is this value ENTIRELY a placeholder already? */
const PLACEHOLDER_ONLY_RE = /^\[redacted(?::[a-z0-9_]+)?\]$/;

/**
 * Is `text` nothing but redaction placeholders (plus punctuation/whitespace)?
 *
 * True for a string that was ENTIRELY a credential — "[redacted:aws]" — and
 * false as soon as any real word survives. Callers that use redacted text as a
 * LABEL (a session title, a feature name) use this to skip it: a title reading
 * "[redacted]" carries nothing, and on the auto-title path it would also stick,
 * since a session's first auto title is the one that applies. That would let a
 * pasted key permanently cost a session its name.
 *
 * Not applied inside `redact` itself — an activity excerpt that redacts to
 * nothing but placeholders is a truthful and useful record ("a secret was here").
 */
export function isOnlyRedactions(text: string): boolean {
  return !/[A-Za-z0-9]/.test(text.replace(PLACEHOLDER_RE, " "));
}

export interface RedactOptions {
  /**
   * Extra user-supplied regex sources, applied after the built-ins. Each is
   * compiled with the `g` flag and silently skipped if it doesn't compile — a
   * bad rule must never crash a developer's hook.
   */
  extraPatterns?: readonly string[];
}

/** Compile a user-supplied pattern, or undefined if it's not a usable regex. */
function compileExtra(source: string): RegExp | undefined {
  try {
    // A pattern that can match the empty string would loop forever against a
    // global replace, so reject it rather than hang the hook.
    if (new RegExp(source).test("")) return undefined;
    return new RegExp(source, "g");
  } catch {
    return undefined;
  }
}

/**
 * Scrub secrets out of `text`. Always returns a string; a non-string input
 * yields "". Applied to every piece of content before it is shipped — prompts,
 * tool arguments, and tool output alike.
 */
export function redact(text: unknown, options: RedactOptions = {}): string {
  if (typeof text !== "string" || text === "") return "";
  // Smuggled-secret pass first: a key broken by an invisible character must be
  // stitched back together and replaced BEFORE the ordinary pass, which cannot
  // see across the break.
  let out = redactSmuggledSecrets(text);
  for (const [label, pattern] of ALL_SECRET_PATTERNS) {
    // `url_credentials` keeps its scheme so the line still reads as a URL.
    out = out.replace(pattern, (match, scheme?: string) => {
      // The prefixless AWS-secret shape's last veto: a window with three or
      // more `/` and no `+` is a path, not a key — base64 of 30 random bytes
      // has ~0.6 slashes in expectation, paths have one per segment.
      if (label === "aws" && !match.includes("+") && (match.match(/\//g) ?? []).length >= 3) {
        return match;
      }
      // Userinfo an earlier row already replaced (`https://x:[redacted:github]@`)
      // keeps that row's family — it is the more specific claim.
      if (label === "url_credentials" && /\[redacted(?::[a-z0-9_]+)?\]/.test(match)) return match;
      // A stand-in is scrubbed but named nothing (see isPlaceholderSecret).
      const tag = isPlaceholderSecret(label, match) ? REDACTED : `[redacted:${label}]`;
      return label === "url_credentials" && typeof scheme === "string"
        ? `${scheme}${tag === REDACTED ? REDACTED : "[redacted:credentials]"}@`
        : tag;
    });
  }
  // Wallet key material AFTER the named table (a Base58 run inside a longer
  // token the table already claimed stays claimed) and BEFORE the assignment
  // rules, whose placeholder-only check then keeps `MNEMONIC="[redacted:bip39]"`
  // labelled rather than overwriting it with the anonymous form.
  out = redactWalletKeys(out);
  for (const pattern of ASSIGNMENT_PATTERNS) {
    out = out.replace(pattern, (match: string, ...args: unknown[]) => {
      // replace() hands the capture groups, then the offset and the whole
      // string; the groups are all this rule reads except the scheme check.
      const whole = args[args.length - 1];
      const offset = args[args.length - 2];
      const groups = args.slice(0, -2);
      // Both assignment shapes keep everything up to (and including) the
      // separator/scheme and replace only the value that follows it.
      const key = typeof groups[0] === "string" ? groups[0] : "";
      const sep = typeof groups[1] === "string" ? groups[1] : "";
      // A value the NAMED table already replaced is left exactly as it is.
      // These rules run after that table, so `access_token: "AKIA…"` arrives
      // here as `access_token: "[redacted:aws]"` and would otherwise be
      // overwritten with the anonymous placeholder — trading the credential
      // family for nothing. Which family it was is the whole content of the
      // audit trail (and what the security detectors read), and this module
      // already treats a truthful label as worth ordering the table around.
      const value = groups.slice(2).find((g): g is string => typeof g === "string");
      if (value !== undefined && PLACEHOLDER_ONLY_RE.test(value)) return match;
      // A bare literal is not a secret: `rejectUnauthorized: false`,
      // `auth: null`, `retries: 3` name a setting, and masking the setting's
      // value hid the one insecure-code shape (`rejectUnauthorized: false`)
      // whose key happens to contain "auth" from the detector that reads the
      // redacted payload.
      if (value !== undefined && /^(?:true|false|null|none|nil|undefined|\d{1,6})[)\]},]*$/i.test(value)) return match;
      // An env lookup names where the secret lives, not the secret — and the
      // bare-value branch stops at its first quote, so masking it garbled
      // `TOKEN = os.environ["TOKEN"]` into `TOKEN = [redacted]"TOKEN"]`.
      if (value !== undefined && /^(?:os\.environ(?:\.get)?[[(]|os\.getenv\(|getenv\(|System\.getenv\(|ENV(?:\.fetch)?[[(])/.test(value)) return match;
      // `Authorization: Bearer [redacted:bearer]` — the header rule above
      // already consumed the token; the key-name rule then saw "Authorization"
      // with the value "Bearer" and masked the SCHEME. Only when the token
      // right after it was already replaced, so a scheme with an unredacted
      // quoted token behind it still loses its value.
      if (
        value !== undefined &&
        /^(?:Bearer|Basic|Token|Digest)$/i.test(value) &&
        typeof whole === "string" &&
        typeof offset === "number" &&
        /^\s+\\?["']?\[redacted(?::[a-z0-9_]+)?\]/.test(whole.slice(offset + match.length))
      ) {
        return match;
      }
      // An Authorization header whose value is concretely token-shaped gets a
      // NAMED placeholder: a live bearer credential in captured text is a
      // finding the detectors should be able to raise, and the anonymous form
      // deliberately says nothing. A `$VAR` reference or a short scheme demo
      // stays anonymous — claiming "credential" for an env lookup would be
      // false.
      if (
        /^(?:Bearer|Basic|Token)\s+(?:\\?["'])?$/i.test(sep) &&
        value !== undefined &&
        /^[A-Za-z0-9+/_.=-]{16,}$/.test(value) &&
        !isPlaceholderSecret("bearer", value)
      ) {
        return `${key}${sep}[redacted:bearer]`;
      }
      return `${key}${sep}${REDACTED}`;
    });
  }
  for (const source of options.extraPatterns ?? []) {
    const compiled = compileExtra(source);
    if (compiled) out = out.replace(compiled, REDACTED);
  }
  return out;
}

/**
 * Redact, then hard-cap the length. Content capture stores an EXCERPT, never a
 * whole file: a 40 KB tool output is not an audit trail, it's a copy of the
 * repository. The cap is applied after redaction so a secret can't survive by
 * sitting near a truncation boundary.
 *
 * Returns the flag separately so the UI can say "truncated" rather than
 * silently implying the excerpt is the whole thing.
 */
export function redactAndTruncate(
  text: unknown,
  maxChars: number,
  options: RedactOptions = {},
): { text: string; truncated: boolean } {
  const scrubbed = redact(text, options);
  if (scrubbed.length <= maxChars) return { text: scrubbed, truncated: false };
  return { text: `${scrubbed.slice(0, Math.max(0, maxChars - 1))}…`, truncated: true };
}
