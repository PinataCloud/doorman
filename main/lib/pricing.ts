// The model pricing table and cost derivation — the app derives every turn's
// cost on-device from the token counts in the transcripts.

/**
 * A turn's token counts, as the transcript readers build them. They come from
 * on-disk transcripts rather than untrusted input, so a type suffices.
 */
export interface SpendDetails {
  model_provider: string;
  model: string;
  input_tokens: number;
  output_tokens: number;
  /** Canonical TOTAL of cache-read + cache-write tokens. */
  cached_tokens: number;
  cache_write_tokens?: number;
  cache_read_tokens?: number;
  /** The SUBSET of cache_write_tokens written with the 1-hour TTL (2x input). */
  cache_write_1h_tokens?: number;
  /** Server-side web searches, billed per request rather than per token. */
  web_search_requests?: number;
  /** Context window as observed in the transcript, when a source reports it. */
  context_window_tokens?: number;
}

export interface ModelRate {
  /** USD per 1,000,000 input tokens. */
  input_per_million_usd: number;
  /** USD per 1,000,000 output tokens. */
  output_per_million_usd: number;
  /**
   * USD per 1,000,000 cached-input tokens — the legacy single cached rate, used
   * to price the canonical `cached_tokens` total when no read/write split is
   * supplied. Conventionally equal to the cache *read* rate. When absent, the
   * standard input rate is used as a conservative fallback.
   */
  cached_per_million_usd?: number;
  /**
   * USD per 1,000,000 cache-*write* (creation) tokens — Anthropic bills 5-minute
   * cache writes at ~1.25x the input rate. When absent, falls back to 1.25x
   * input for Anthropic only; every other provider falls back to the plain
   * input rate, since a write premium is not the norm there (OpenAI's older
   * models and Gemini publish none) — a row whose provider does publish one
   * must state it explicitly.
   */
  cache_write_per_million_usd?: number;
  /**
   * USD per 1,000,000 cache-write tokens at the **1-hour** TTL, which Anthropic
   * bills at 2x the input rate against the 5-minute TTL's 1.25x. Falls back to
   * 2x input for Anthropic when absent (the published multiple, not the 5m
   * rate); other providers fall back to their 5-minute write rate.
   * Only consulted for the `cache_write_1h_tokens` subset; the remainder of
   * `cache_write_tokens` keeps the 5-minute rate.
   */
  cache_write_1h_per_million_usd?: number;
  /**
   * USD per 1,000,000 cache-*read* tokens — ~0.1x input. Falls back to
   * `cached_per_million_usd`, then 0.1x input, when absent.
   */
  cache_read_per_million_usd?: number;
  /**
   * USD per server-side **web search request** — billed per request, not per
   * token. Falls back to {@link WEB_SEARCH_PER_REQUEST_USD}. Web *fetch* has no
   * per-request charge, so it has no rate here by design.
   */
  web_search_per_request_usd?: number;
  /**
   * The model's context window in tokens (the standard/GA window, not opt-in
   * long-context betas), used to derive per-request context utilization —
   * (input + cache read + cache creation) / window. Absent for models whose
   * window we don't confidently know; utilization then reports as unknown
   * rather than dividing by a guess.
   */
  context_window_tokens?: number;
}

const TOKENS_PER_MILLION = 1_000_000;

/**
 * USD per server-side web search request — "$10 per 1,000 searches" on the
 * Claude API (platform.claude.com/docs/en/agents-and-tools/tool-use/web-search-tool,
 * fetched 2026-08-11). One search counts as one use regardless of how many
 * results come back, and a search that ERRORS is not billed — so this multiplies
 * the successful-request count the provider reports, never an attempt count.
 *
 * The companion web *fetch* tool is explicitly "no additional cost" beyond the
 * tokens its content occupies (same date, .../web-fetch-tool), which is why
 * `web_fetch_requests` is carried as metadata and never priced.
 */
export const WEB_SEARCH_PER_REQUEST_USD = 0.01;

function pricingKey(provider: string, model: string): string {
  return `${provider.trim()}/${model.trim()}`;
}

export const PRICING_TABLE: Readonly<Record<string, ModelRate>> = {
  // OpenAI
  "openai/gpt-4o": {
    input_per_million_usd: 2.5,
    output_per_million_usd: 10,
    cached_per_million_usd: 1.25,
    context_window_tokens: 128_000,
  },
  "openai/gpt-4o-mini": {
    input_per_million_usd: 0.15,
    output_per_million_usd: 0.6,
    cached_per_million_usd: 0.075,
    context_window_tokens: 128_000,
  },
  "openai/gpt-4-turbo": {
    input_per_million_usd: 10,
    output_per_million_usd: 30,
    context_window_tokens: 128_000,
  },
  "openai/gpt-4": {
    input_per_million_usd: 30,
    output_per_million_usd: 60,
    context_window_tokens: 8_192,
  },
  "openai/gpt-3.5-turbo": {
    input_per_million_usd: 0.5,
    output_per_million_usd: 1.5,
    context_window_tokens: 16_385,
  },
  "openai/o1": {
    input_per_million_usd: 15,
    output_per_million_usd: 60,
    cached_per_million_usd: 7.5,
    context_window_tokens: 200_000,
  },
  "openai/o1-mini": {
    input_per_million_usd: 3,
    output_per_million_usd: 12,
    cached_per_million_usd: 1.5,
    context_window_tokens: 128_000,
  },
  // GPT-5 family. `gpt-5-codex` is the model the Codex CLI reports; reasoning
  // tokens are already folded into output_tokens by the API, so they price at
  // the output rate. Cached input bills at 0.1x input (OpenAI prompt caching).
  "openai/gpt-5": {
    input_per_million_usd: 1.25,
    output_per_million_usd: 10,
    cached_per_million_usd: 0.125,
    context_window_tokens: 400_000,
  },
  "openai/gpt-5-mini": {
    input_per_million_usd: 0.25,
    output_per_million_usd: 2,
    cached_per_million_usd: 0.025,
    context_window_tokens: 400_000,
  },
  "openai/gpt-5-codex": {
    input_per_million_usd: 1.25,
    output_per_million_usd: 10,
    cached_per_million_usd: 0.125,
    context_window_tokens: 400_000,
  },
  "openai/gpt-5.1-codex-max": {
    input_per_million_usd: 1.25,
    output_per_million_usd: 10,
    cached_per_million_usd: 0.125,
    context_window_tokens: 400_000,
  },
  "openai/gpt-5.2-codex": {
    input_per_million_usd: 1.75,
    output_per_million_usd: 14,
    cached_per_million_usd: 0.175,
    context_window_tokens: 400_000,
  },
  "openai/gpt-5.3-codex": {
    input_per_million_usd: 1.75,
    output_per_million_usd: 14,
    cached_per_million_usd: 0.175,
    context_window_tokens: 400_000,
  },
  // GPT-5.6 family — confirmed against developers.openai.com/api/docs/pricing
  // (fetched 2026-07-09). OpenAI dropped the mini/nano suffixes for named
  // tiers: sol is the flagship (same rate as gpt-5.5), terra the mid tier
  // (same as gpt-5.4), luna the small tier. No 5.6 codex or pro variant is
  // listed yet. The same page lists a cache-write column for the 5.6 family at
  // 1.25x input (re-checked 2026-09-29), so it is stated per row — the 1.25x
  // default in `deriveCost` is Anthropic-only.
  "openai/gpt-5.6-sol": {
    input_per_million_usd: 5,
    output_per_million_usd: 30,
    cached_per_million_usd: 0.5,
    cache_write_per_million_usd: 6.25,
    context_window_tokens: 400_000,
  },
  "openai/gpt-5.6-terra": {
    input_per_million_usd: 2.5,
    output_per_million_usd: 15,
    cached_per_million_usd: 0.25,
    cache_write_per_million_usd: 3.125,
    context_window_tokens: 400_000,
  },
  "openai/gpt-5.6-luna": {
    input_per_million_usd: 1,
    output_per_million_usd: 6,
    cached_per_million_usd: 0.1,
    cache_write_per_million_usd: 1.25,
    context_window_tokens: 400_000,
  },
  // GPT-6 Astra — developers.openai.com/api/docs/pricing and
  // .../models/gpt-6-astra (both fetched 2026-09-06): $10 input, $1 cached
  // input, $50 output, and a 1,050,000-token window (922K in / 128K out).
  // The published cache-write column ($12.50) is stated explicitly: the 1.25x
  // write default in `deriveCost` applies to Anthropic only.
  // NOT modelled: the long-context tier. A prompt over 272K input tokens
  // prices the WHOLE request at 2x input/cache and 1.5x output, which is a
  // per-request threshold this table has no column for — those turns
  // under-cost rather than being rejected, the same way every other
  // threshold-tiered model here behaves.
  "openai/gpt-6-astra": {
    input_per_million_usd: 10,
    output_per_million_usd: 50,
    cached_per_million_usd: 1,
    cache_write_per_million_usd: 12.5,
    context_window_tokens: 1_050_000,
  },
  // Confirmed against developers.openai.com/api/docs/pricing (fetched
  // 2026-07-01) — gpt-5.5 was the model reported as unpriced/`cost_unknown`
  // by a real `codex exec` run (see the OTLP field-name fix above).
  "openai/gpt-5.5": {
    input_per_million_usd: 5,
    output_per_million_usd: 30,
    cached_per_million_usd: 0.5,
    context_window_tokens: 400_000,
  },
  "openai/gpt-5.5-pro": {
    input_per_million_usd: 30,
    output_per_million_usd: 180,
    context_window_tokens: 400_000,
  },
  "openai/gpt-5.4": {
    input_per_million_usd: 2.5,
    output_per_million_usd: 15,
    cached_per_million_usd: 0.25,
    context_window_tokens: 400_000,
  },
  "openai/gpt-5.4-mini": {
    input_per_million_usd: 0.75,
    output_per_million_usd: 4.5,
    cached_per_million_usd: 0.075,
    context_window_tokens: 400_000,
  },
  "openai/gpt-5.4-nano": {
    input_per_million_usd: 0.2,
    output_per_million_usd: 1.25,
    cached_per_million_usd: 0.02,
    context_window_tokens: 400_000,
  },
  "openai/gpt-5.4-pro": {
    input_per_million_usd: 30,
    output_per_million_usd: 180,
    context_window_tokens: 400_000,
  },
  // A floating alias some clients report literally as the model name instead
  // of resolving it — currently mirrors gpt-5.5's rate.
  "openai/chat-latest": {
    input_per_million_usd: 5,
    output_per_million_usd: 30,
    cached_per_million_usd: 0.5,
    context_window_tokens: 400_000,
  },

  // Anthropic — current-generation Opus is $5/$25 per MTok (cache read ~0.5,
  // 5-min cache write ~6.25). These were previously $15/$75, which 3x
  // over-costed every Opus event and ~12.5x under-counted cache-creation.
  // The 1-HOUR cache-write column (2x input, against the 5-minute TTL's 1.25x)
  // is from the per-model table at
  // platform.claude.com/docs/en/build-with-claude/prompt-caching, fetched
  // 2026-08-11. Stated literally per row rather than left to the 2x fallback,
  // because that page prints the dollar figures and a future row may not follow
  // the multiple.
  // Context windows: Fable 5, Opus 4.6+, Sonnet 4.6+ ship with a 1M standard
  // window (no opt-in beta); 200K is only correct for Haiku 4.5 and for
  // Opus 4.5 / Sonnet 4.5 and older, whose 1M was an opt-in long-context beta.
  // Claude Fable 5.1 — same $10/$50 headline and cache-write columns as Fable
  // 5, but cache READS are $0.25 per MTok (0.025x input, versus the 0.1x every
  // other Anthropic row uses): a quarter of Fable 5's rate. Stated literally
  // for that reason — the 0.1x default in `deriveCost` would 4x-overcost every
  // cache read on this model. platform.claude.com/docs/en/about-claude/pricing,
  // fetched 2026-09-02.
  "anthropic/claude-fable-5-1": {
    input_per_million_usd: 10,
    output_per_million_usd: 50,
    cached_per_million_usd: 0.25,
    cache_write_per_million_usd: 12.5,
    cache_write_1h_per_million_usd: 20,
    cache_read_per_million_usd: 0.25,
    context_window_tokens: 1_000_000,
  },
  "anthropic/claude-fable-5": {
    input_per_million_usd: 10,
    output_per_million_usd: 50,
    cached_per_million_usd: 1,
    cache_write_per_million_usd: 12.5,
    cache_write_1h_per_million_usd: 20,
    cache_read_per_million_usd: 1,
    context_window_tokens: 1_000_000,
  },
  // Claude Opus 5 — the current Opus, a drop-in upgrade at Opus 4.8's rates
  // ($5/$25 per MTok, 1M standard window). Fast mode (`speed: "fast"`) bills at
  // $10/$50, but it's a request parameter rather than a distinct model id, so a
  // fast-mode call is indistinguishable here and prices at the standard rate.
  "anthropic/claude-opus-5": {
    input_per_million_usd: 5,
    output_per_million_usd: 25,
    cached_per_million_usd: 0.5,
    cache_write_per_million_usd: 6.25,
    cache_write_1h_per_million_usd: 10,
    cache_read_per_million_usd: 0.5,
    context_window_tokens: 1_000_000,
  },
  "anthropic/claude-opus-4-6": {
    input_per_million_usd: 5,
    output_per_million_usd: 25,
    cached_per_million_usd: 0.5,
    cache_write_per_million_usd: 6.25,
    cache_write_1h_per_million_usd: 10,
    cache_read_per_million_usd: 0.5,
    context_window_tokens: 1_000_000,
  },
  "anthropic/claude-opus-4-7": {
    input_per_million_usd: 5,
    output_per_million_usd: 25,
    cached_per_million_usd: 0.5,
    cache_write_per_million_usd: 6.25,
    cache_write_1h_per_million_usd: 10,
    cache_read_per_million_usd: 0.5,
    context_window_tokens: 1_000_000,
  },
  "anthropic/claude-opus-4-8": {
    input_per_million_usd: 5,
    output_per_million_usd: 25,
    cached_per_million_usd: 0.5,
    cache_write_per_million_usd: 6.25,
    cache_write_1h_per_million_usd: 10,
    cache_read_per_million_usd: 0.5,
    context_window_tokens: 1_000_000,
  },
  "anthropic/claude-opus-4-5": {
    input_per_million_usd: 5,
    output_per_million_usd: 25,
    cached_per_million_usd: 0.5,
    cache_write_per_million_usd: 6.25,
    cache_write_1h_per_million_usd: 10,
    cache_read_per_million_usd: 0.5,
    context_window_tokens: 200_000,
  },
  // Retired except on Bedrock/Google Cloud (platform.claude.com/.../pricing) —
  // kept so an old event reported from those platforms still prices correctly.
  "anthropic/claude-opus-4-1": {
    input_per_million_usd: 15,
    output_per_million_usd: 75,
    cached_per_million_usd: 1.5,
    cache_write_per_million_usd: 18.75,
    cache_write_1h_per_million_usd: 30,
    cache_read_per_million_usd: 1.5,
    context_window_tokens: 200_000,
  },
  "anthropic/claude-opus-4": {
    input_per_million_usd: 15,
    output_per_million_usd: 75,
    cached_per_million_usd: 1.5,
    cache_write_per_million_usd: 18.75,
    cache_write_1h_per_million_usd: 30,
    cache_read_per_million_usd: 1.5,
    context_window_tokens: 200_000,
  },
  // Introductory pricing (platform.claude.com/.../pricing, fetched 2026-07-01):
  // $2/$10 through 2026-08-31, then $3/$15 standard — same rate as Sonnet 4.6.
  // Bump this to the standard row (matching claude-sonnet-4-6 below) after
  // that date.
  "anthropic/claude-sonnet-5": {
    input_per_million_usd: 2,
    output_per_million_usd: 10,
    cached_per_million_usd: 0.2,
    cache_write_per_million_usd: 2.5,
    cache_write_1h_per_million_usd: 4,
    cache_read_per_million_usd: 0.2,
    context_window_tokens: 1_000_000,
  },
  "anthropic/claude-sonnet-4-5": {
    input_per_million_usd: 3,
    output_per_million_usd: 15,
    cached_per_million_usd: 0.3,
    cache_write_per_million_usd: 3.75,
    cache_write_1h_per_million_usd: 6,
    cache_read_per_million_usd: 0.3,
    context_window_tokens: 200_000,
  },
  "anthropic/claude-sonnet-4-6": {
    input_per_million_usd: 3,
    output_per_million_usd: 15,
    cached_per_million_usd: 0.3,
    cache_write_per_million_usd: 3.75,
    cache_write_1h_per_million_usd: 6,
    cache_read_per_million_usd: 0.3,
    context_window_tokens: 1_000_000,
  },
  // Retired except on Bedrock/Google Cloud — same rate as 4-5/4-6.
  "anthropic/claude-sonnet-4": {
    input_per_million_usd: 3,
    output_per_million_usd: 15,
    cached_per_million_usd: 0.3,
    cache_write_per_million_usd: 3.75,
    cache_write_1h_per_million_usd: 6,
    cache_read_per_million_usd: 0.3,
    context_window_tokens: 200_000,
  },
  "anthropic/claude-haiku-4-5": {
    input_per_million_usd: 1,
    output_per_million_usd: 5,
    cached_per_million_usd: 0.1,
    cache_write_per_million_usd: 1.25,
    cache_write_1h_per_million_usd: 2,
    cache_read_per_million_usd: 0.1,
    context_window_tokens: 200_000,
  },
  "anthropic/claude-haiku-4-5-20251001": {
    input_per_million_usd: 1,
    output_per_million_usd: 5,
    cached_per_million_usd: 0.1,
    cache_write_per_million_usd: 1.25,
    cache_write_1h_per_million_usd: 2,
    cache_read_per_million_usd: 0.1,
    context_window_tokens: 200_000,
  },
  "anthropic/claude-3-5-sonnet": {
    input_per_million_usd: 3,
    output_per_million_usd: 15,
    cached_per_million_usd: 0.3,
    context_window_tokens: 200_000,
  },
  "anthropic/claude-3-5-haiku": {
    input_per_million_usd: 0.8,
    output_per_million_usd: 4,
    cached_per_million_usd: 0.08,
    context_window_tokens: 200_000,
  },
  "anthropic/claude-3-opus": {
    input_per_million_usd: 15,
    output_per_million_usd: 75,
    cached_per_million_usd: 1.5,
    context_window_tokens: 200_000,
  },

  // Google
  "google/gemini-1.5-pro": {
    input_per_million_usd: 1.25,
    output_per_million_usd: 5,
    context_window_tokens: 2_097_152,
  },
  "google/gemini-1.5-flash": {
    input_per_million_usd: 0.075,
    output_per_million_usd: 0.3,
    context_window_tokens: 1_048_576,
  },
  "google/gemini-2.0-flash": {
    input_per_million_usd: 0.1,
    output_per_million_usd: 0.4,
    context_window_tokens: 1_048_576,
  },
  // Confirmed against ai.google.dev/gemini-api/docs/pricing (fetched
  // 2026-07-01). Gemini's standard tier is priced per request threshold
  // (≤200k tokens vs >200k, and a separate audio-input rate) — we use the
  // ≤200k / non-audio rate as a single flat rate, same simplification every
  // other flat per-model entry here already makes.
  "google/gemini-2.5-pro": {
    input_per_million_usd: 1.25,
    output_per_million_usd: 10,
    context_window_tokens: 1_048_576,
  },
  "google/gemini-2.5-flash": {
    input_per_million_usd: 0.3,
    output_per_million_usd: 2.5,
    context_window_tokens: 1_048_576,
  },
  "google/gemini-2.5-flash-lite": {
    input_per_million_usd: 0.1,
    output_per_million_usd: 0.4,
    context_window_tokens: 1_048_576,
  },
  "google/gemini-3.1-pro-preview": {
    input_per_million_usd: 2,
    output_per_million_usd: 12,
    context_window_tokens: 1_048_576,
  },
  "google/gemini-3.1-flash-lite": {
    input_per_million_usd: 0.25,
    output_per_million_usd: 1.5,
    context_window_tokens: 1_048_576,
  },
  "google/gemini-3.5-flash": {
    input_per_million_usd: 1.5,
    output_per_million_usd: 9,
    context_window_tokens: 1_048_576,
  },
};

// A dated snapshot suffix in either vendor convention: Anthropic's
// `-YYYYMMDD` (claude-haiku-4-5-20251001) and OpenAI's `-YYYY-MM-DD`
// (gpt-4o-2024-08-06). The gateway prefers the response's model, which OpenAI
// reports dated, so missing the dashed form priced every such call at $0.
const DATE_SUFFIX_RE = /-(?:\d{8}|\d{4}-\d{2}-\d{2})$/;

/**
 * Resolve a provider/model pair to a pricing-table key, tolerating the two
 * ways the same model is reported: a bare alias (`claude-haiku-4-5`) and a
 * dated snapshot (`claude-haiku-4-5-20251001`). Exact match wins; otherwise a
 * trailing `-YYYYMMDD` / `-YYYY-MM-DD` is stripped to try the alias, and a bare alias is
 * matched against any dated snapshot of the same family. Returns the direct
 * key unchanged when nothing resolves (so lookups still cleanly miss for
 * genuinely unknown models).
 *
 * `overrides` is an optional caller-supplied rate table checked alongside —
 * never instead of — the built-in {@link PRICING_TABLE}, so custom/fine-tuned
 * model families resolve their own dated snapshots the same way built-in ones
 * do.
 */
export function normalizeModelKey(
  provider: string,
  model: string,
  overrides?: Readonly<Record<string, ModelRate>>,
): string {
  const known = (key: string): boolean =>
    key in PRICING_TABLE || (overrides !== undefined && key in overrides);
  const direct = pricingKey(provider, model);
  if (known(direct)) return direct;
  const m = model.trim();
  const alias = m.replace(DATE_SUFFIX_RE, "");
  if (alias !== m) {
    const aliasKey = pricingKey(provider, alias);
    if (known(aliasKey)) return aliasKey;
  }
  const prefix = `${direct}-`;
  const candidateKeys = overrides
    ? [...Object.keys(PRICING_TABLE), ...Object.keys(overrides)]
    : Object.keys(PRICING_TABLE);
  for (const key of candidateKeys) {
    if (key.startsWith(prefix) && DATE_SUFFIX_RE.test(key)) return key;
  }
  return direct;
}

/**
 * Look up the per-million rate for a provider/model pair, if known. An
 * `overrides` table (when given) takes priority over the built-in
 * {@link PRICING_TABLE} for the same key — that's the whole point of an
 * override — but a model absent from `overrides` still resolves against the
 * built-in table, so an override only needs the models it wants to change or
 * add.
 */
export function lookupModelRate(
  provider: string,
  model: string,
  overrides?: Readonly<Record<string, ModelRate>>,
): ModelRate | undefined {
  const key = normalizeModelKey(provider, model, overrides);
  return overrides?.[key] ?? PRICING_TABLE[key];
}

/**
 * Look up a model's context window in tokens, if known. Overrides resolve like
 * {@link lookupModelRate} — an override's entry wins for the same key — with one
 * extra fallback: an override that only re-prices a built-in model (no
 * `context_window_tokens` of its own) keeps the built-in window rather than
 * losing it.
 */
export function lookupContextWindow(
  provider: string,
  model: string,
  overrides?: Readonly<Record<string, ModelRate>>,
): number | undefined {
  const key = normalizeModelKey(provider, model, overrides);
  return (
    overrides?.[key]?.context_window_tokens ??
    PRICING_TABLE[key]?.context_window_tokens
  );
}

export interface ContextUtilization {
  /** Prompt-side tokens on this request: input + cache read + cache creation. */
  prompt_tokens: number;
  context_window_tokens: number;
  /**
   * prompt_tokens / context_window_tokens × 100. Uncapped — a value over 100
   * means the catalog window is stale for that model, which is worth seeing.
   */
  utilization_pct: number;
}

/**
 * How full the model's context window was on this request:
 * (input + cache read + cache creation) / context window × 100 — "how much of
 * the capacity we pay for do we actually use" as the efficiency counterpart to
 * `cost`. Output tokens are the response, not the prompt, so they're excluded.
 * Same split convention as {@link deriveCost}: when the read/write split is
 * present it is authoritative; otherwise the canonical `cached_tokens` total
 * (which normalization keeps equal to read + write) stands in. Returns
 * undefined when the model's window is unknown, so callers report "unknown"
 * instead of dividing by a guess.
 *
 * Window precedence is **observed → override → catalog**. The observed value
 * (`spend_details.context_window_tokens`, reported by the rail on this very
 * event) wins because it is the only one of the three that cannot be stale: the
 * override and the built-in table are both a human's snapshot of what the
 * provider published, while the observation is what the model actually ran with.
 * It is also inherently model-keyed — it rides the event whose model it
 * describes — so a session that switches models gets each event's real window
 * instead of one window smeared across both.
 */
export function deriveContextUtilization(
  spendDetails: SpendDetails,
  overrides?: Readonly<Record<string, ModelRate>>,
): ContextUtilization | undefined {
  const window =
    spendDetails.context_window_tokens ??
    lookupContextWindow(
      spendDetails.model_provider,
      spendDetails.model,
      overrides,
    );
  if (window === undefined || window <= 0) return undefined;
  const hasSplit =
    spendDetails.cache_write_tokens !== undefined ||
    spendDetails.cache_read_tokens !== undefined;
  const cacheTokens = hasSplit
    ? (spendDetails.cache_write_tokens ?? 0) +
      (spendDetails.cache_read_tokens ?? 0)
    : spendDetails.cached_tokens;
  const prompt_tokens = spendDetails.input_tokens + cacheTokens;
  return {
    prompt_tokens,
    context_window_tokens: window,
    utilization_pct: (prompt_tokens / window) * 100,
  };
}

/**
 * Infer the model_provider from the model name when a source doesn't report one
 * (e.g. a raw Cursor/Codex event that carries `model: "gpt-4o"` but no
 * provider). Without this, an unset provider defaults to "anthropic" and
 * `anthropic/gpt-4o` never matches the pricing table, so OpenAI/Google spend
 * silently prices at $0. Returns undefined when the family is unrecognized, so
 * the caller keeps its own fallback.
 */
export function inferModelProvider(model: string): string | undefined {
  const m = model.trim().toLowerCase();
  if (!m) return undefined;
  if (/^(gpt-|o[1-9]|chatgpt|chat-latest|text-|davinci|babbage|ada|curie)/.test(m)) {
    return "openai";
  }
  if (m.startsWith("claude")) return "anthropic";
  if (m.startsWith("gemini")) return "google";
  if (m.startsWith("grok")) return "xai";
  return undefined;
}

const VENDOR_PREFIXED_MODEL_RE = /^([^/]+)\/(.+)$/;

/**
 * Split a "<vendor>/<model>" combined id into its parts — OpenRouter's own
 * catalog convention for identifying which underlying provider actually
 * serves a model (e.g. "anthropic/claude-3-5-sonnet"), also echoed back by
 * any OpenAI-compatible endpoint an operator has re-routed through OpenRouter
 * (its chat/completions response's `model` field carries the same combined
 * id). No native provider's own model names contain a "/", so a match here is
 * a reliable "this came through a router" signal; a plain model string
 * returns undefined rather than a guess.
 */
export function splitVendorPrefixedModel(
  raw: string,
): { provider: string; model: string } | undefined {
  const m = VENDOR_PREFIXED_MODEL_RE.exec(raw.trim());
  return m ? { provider: m[1]!, model: m[2]! } : undefined;
}

/**
 * Same split, for contexts where every row is already KNOWN to come from
 * OpenRouter (its admin usage-report import) — unlike
 * {@link splitVendorPrefixedModel}, a combined id with no vendor prefix still
 * resolves to a definite provider ("openrouter" itself — e.g. a
 * OpenRouter-hosted/custom model with no upstream vendor) instead of
 * undefined, since there's no "maybe this isn't routed" ambiguity to preserve.
 */
export function splitOpenRouterModel(
  raw: string | undefined,
): { provider: string; model: string } | undefined {
  if (!raw) return undefined;
  return splitVendorPrefixedModel(raw) ?? { provider: "openrouter", model: raw };
}

/**
 * Compute USD spend from a SpendDetails record using the PRICING_TABLE (or the
 * `overrides`, when given — see {@link lookupModelRate}).
 *
 * The three token buckets (input, output, cached) are billed independently:
 * callers are expected to report them as non-overlapping counts. When the
 * model is unknown, returns undefined so the caller can decide how to
 * handle it (skip, reject, or fall through to a caller-supplied cost).
 */
export function deriveCost(
  spendDetails: SpendDetails,
  overrides?: Readonly<Record<string, ModelRate>>,
): number | undefined {
  const rate = lookupModelRate(
    spendDetails.model_provider,
    spendDetails.model,
    overrides,
  );
  if (!rate) return undefined;
  const cacheReadRate =
    rate.cache_read_per_million_usd ??
    rate.cached_per_million_usd ??
    rate.input_per_million_usd * 0.1;
  // The 1.25x (5m) / 2x (1h) write premiums are Anthropic's published
  // multiples. Other providers (OpenAI, Gemini) mostly charge no write premium,
  // so an unstated write rate there is the input rate — a row that does publish
  // one (gpt-6-astra, gpt-5.6-*) carries it explicitly.
  const writePremium =
    spendDetails.model_provider.trim().toLowerCase() === "anthropic";
  const cacheWriteRate =
    rate.cache_write_per_million_usd ??
    rate.input_per_million_usd * (writePremium ? 1.25 : 1);
  const cacheWrite1hRate =
    rate.cache_write_1h_per_million_usd ??
    (writePremium ? rate.input_per_million_usd * 2 : cacheWriteRate);
  // When a source reports the cache-read/cache-write split, price each bucket at
  // its own rate and ignore the `cached_tokens` total (it is their sum, so
  // counting both would double-bill). Otherwise fall back to the single total at
  // the legacy cached rate (cached_per_million_usd, else the full input rate) —
  // unchanged from before the split existed.
  const legacyCachedRate =
    rate.cached_per_million_usd ?? rate.input_per_million_usd;
  const hasSplit =
    spendDetails.cache_write_tokens !== undefined ||
    spendDetails.cache_read_tokens !== undefined ||
    spendDetails.cache_write_1h_tokens !== undefined;
  // `cache_write_1h_tokens` is a SUBSET of `cache_write_tokens`, so the 5-minute
  // portion is the remainder rather than a second bucket. Two guards keep a
  // sloppy producer from inventing spend: the subset is clamped to the total, so
  // it can never make the 5m remainder negative, and a source that reports ONLY
  // the 1h count is read as "these are the writes I know about" rather than
  // silently dropping them against a zero total.
  const cacheWriteTotal =
    spendDetails.cache_write_tokens ?? spendDetails.cache_write_1h_tokens ?? 0;
  const cacheWrite1h = Math.min(
    spendDetails.cache_write_1h_tokens ?? 0,
    cacheWriteTotal,
  );
  const cacheWrite5m = Math.max(0, cacheWriteTotal - cacheWrite1h);
  const cacheMicroUsd = hasSplit
    ? cacheWrite5m * cacheWriteRate +
      cacheWrite1h * cacheWrite1hRate +
      (spendDetails.cache_read_tokens ?? 0) * cacheReadRate
    : spendDetails.cached_tokens * legacyCachedRate;
  const totalMicroUsd =
    spendDetails.input_tokens * rate.input_per_million_usd +
    spendDetails.output_tokens * rate.output_per_million_usd +
    cacheMicroUsd;
  // Per-REQUEST charges are added after the per-million division because they are
  // already whole USD. Web search only: web fetch is free, so its request count
  // never reaches this function (see WEB_SEARCH_PER_REQUEST_USD).
  const webSearchUsd =
    (spendDetails.web_search_requests ?? 0) *
    (rate.web_search_per_request_usd ?? WEB_SEARCH_PER_REQUEST_USD);
  return totalMicroUsd / TOKENS_PER_MILLION + webSearchUsd;
}
