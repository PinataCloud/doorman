/**
 * Session use-case classification — a local, deterministic "what kind of work
 * was this?" for a coding-agent session.
 *
 * "Which use cases drive the work?", scaled to one machine and kept honest:
 * heuristics over signals we already store, NO model. The
 * only signals a stored turn carries are its tool names (`tools`) and its text
 * (`text`, prompts and assistant messages) — not per-tool file paths — so
 * classification leans on the tool mix plus prompt keywords, and reports
 * `other` rather than guessing when neither speaks.
 *
 * Pure over a session's turns (no fs, no Electron), so it is unit-tested the
 * same way turns.ts is.
 */

import type { LedgerTurn } from "./turns.js";

export type TaskClass =
  | "coding"
  | "debugging"
  | "testing"
  | "refactor"
  | "data"
  | "docs"
  | "infra"
  | "research"
  | "review"
  | "other";

export const TASK_LABELS: Record<TaskClass, string> = {
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

/** Tool-name buckets. MCP tools are matched by verb where it helps, but the
 * dominant signal is whether the session WROTE files vs only read them. */
const WRITE_TOOLS = /^(edit|write|multiedit|notebookedit|str_replace|apply_patch|create_file|update)/i;
const READ_TOOLS = /^(read|grep|glob|ls|cat|search|find)/i;
const WEB_TOOLS = /(?:^|_)(?:web)?(?:fetch|search)(?:$|_)/i;
const EXEC_TOOLS = /^(bash|shell|local_shell|run)/i;
const NOTEBOOK_TOOLS = /notebook/i;

/**
 * Prompt-keyword signals. Each category gets a weight when its pattern hits the
 * combined (lowercased) prompt text. Ordering here doesn't matter — the caller
 * sums and takes the max, with an explicit tie-break.
 */
const KEYWORDS: ReadonlyArray<readonly [TaskClass, RegExp, number]> = [
  ["testing", /\b(test|tests|spec|specs|vitest|jest|pytest|unit test|coverage|e2e)\b/i, 3],
  ["debugging", /\b(bug|debug|fix|failing|error|crash|stack ?trace|broken|regression|traceback)\b/i, 3],
  ["refactor", /\b(refactor|rename|clean ?up|restructure|extract|deduplicate|tidy|simplify)\b/i, 3],
  ["infra", /\b(deploy|terraform|kubernetes|kubectl|docker|helm|ci|pipeline|infra|provision|rollout|ansible|nginx|systemd)\b/i, 3],
  ["data", /\b(sql|query|dataframe|pandas|csv|dataset|analy[sz]e|analytics|etl|migration|schema|aggregate|chart)\b/i, 3],
  // Weight 3 so a documentation session outweighs the write-tool coding bump
  // (writing a README uses Write). "comment"/"docstring" deliberately excluded —
  // too common in ordinary coding to mean "this was a docs session".
  ["docs", /\b(readme|documentation|changelog|write[- ]?up|blog|user guide|tutorial|docs)\b/i, 3],
  ["research", /\b(how do|how to|what is|research|explain|compare|investigate|look into|understand|explore)\b/i, 2],
  ["review", /\b(review|audit|inspect|walk through|code review|security review|assess)\b/i, 2],
  // "refactor" is deliberately absent — it belongs to the refactor category;
  // leaving it here made a refactor session tie with coding and lose the order.
  ["coding", /\b(implement|add|build|create|feature|function|component|endpoint|support)\b/i, 1],
];

const SCORABLE: readonly TaskClass[] = [
  "coding",
  "debugging",
  "testing",
  "refactor",
  "data",
  "docs",
  "infra",
  "research",
  "review",
];

/** How much prompt text to weigh — the first few prompts frame a session; a
 * long tail of follow-ups mostly repeats the theme. */
const MAX_PROMPT_CHARS = 4_000;

export function classifySession(turns: readonly LedgerTurn[]): TaskClass {
  const scores: Record<TaskClass, number> = {
    coding: 0, debugging: 0, testing: 0, refactor: 0, data: 0,
    docs: 0, infra: 0, research: 0, review: 0, other: 0,
  };

  let promptText = "";
  let wrote = false;
  let read = false;
  let web = false;
  let notebook = false;
  let exec = false;
  let sawTool = false;

  for (const turn of turns) {
    if (turn.role === "user" && turn.text && promptText.length < MAX_PROMPT_CHARS) {
      promptText += " " + turn.text;
    }
    for (const tool of turn.tools ?? []) {
      sawTool = true;
      if (WRITE_TOOLS.test(tool)) wrote = true;
      else if (WEB_TOOLS.test(tool)) web = true;
      else if (READ_TOOLS.test(tool)) read = true;
      if (NOTEBOOK_TOOLS.test(tool)) notebook = true;
      if (EXEC_TOOLS.test(tool)) exec = true;
    }
  }

  const haystack = promptText.slice(0, MAX_PROMPT_CHARS).toLowerCase();
  for (const [category, pattern, weight] of KEYWORDS) {
    if (pattern.test(haystack)) scores[category] += weight;
  }

  // Tool-mix signals. Writing is the strongest "this changed the codebase" tell;
  // web-only sessions are research; notebooks lean data; a read-only session
  // with no writes reads as review/research rather than coding.
  if (wrote) scores.coding += 2;
  if (web) scores.research += 2;
  if (notebook) scores.data += 2;
  if (exec && !wrote) scores.infra += 1;
  if (read && !wrote) scores.review += 1;

  let best: TaskClass = "other";
  let bestScore = 0;
  for (const category of SCORABLE) {
    if (scores[category] > bestScore) {
      best = category;
      bestScore = scores[category];
    }
  }
  if (bestScore > 0) return best;
  // Nothing spoke: fall back to the coarsest tool signal.
  if (wrote) return "coding";
  if (web) return "research";
  if (read || sawTool) return "review";
  return "other";
}
