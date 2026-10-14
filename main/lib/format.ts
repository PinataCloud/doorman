/**
 * Number/time formatting for the parts of the app the main process renders —
 * above all the menu-bar title. The renderer keeps its own equivalents (it is
 * a separate runtime loading raw JSX); kept
 * small and identical in behaviour rather than shared through a bundler.
 */

/**
 * Token counts, short enough to share the menu bar: "0", "840", "12.4k",
 * "1.2M", "1.2B". Identical to the renderer's fmtTokens (components.jsx).
 *
 * The app says TOKENS, never dollars: a dollar figure derived
 * on-device from a built-in rate table is an estimate that ignores what
 * actually paid for the turn, and a precise-looking "$4.21" reads as an
 * invoice. Token counts are measured straight from the transcripts.
 */
export function formatTokens(tokens: number): string {
  if (!Number.isFinite(tokens) || tokens <= 0) return "0";
  if (tokens < 1000) return String(Math.round(tokens));
  if (tokens < 1_000_000) return `${(tokens / 1000).toFixed(1)}k`;
  if (tokens < 1_000_000_000) return `${(tokens / 1_000_000).toFixed(1)}M`;
  return `${(tokens / 1_000_000_000).toFixed(1)}B`;
}

/** "3m ago" / "2d ago"; "never" for null — "no data" and "unknown" must differ. */
export function relativeTime(iso: string | null | undefined, now = Date.now()): string {
  if (!iso) return "never";
  const t = Date.parse(iso);
  if (!Number.isFinite(t)) return "never";
  const seconds = Math.round((now - t) / 1000);
  if (seconds < 0) return "just now";
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 48) return `${hours}h ago`;
  return `${Math.round(hours / 24)}d ago`;
}

/**
 * electron-updater's GitHub provider reports "no releases published yet" as a
 * bare 404 with a paragraph about authentication tokens — alarming, and wrong:
 * an empty feed is the expected state before the first release, not a
 * misconfiguration.
 */
export function describeUpdateError(message: string): string {
  if (/\b404\b/.test(message) && /releases/.test(message)) {
    return "No published releases to update from yet.";
  }
  return message.split("\n")[0]!.slice(0, 160);
}
