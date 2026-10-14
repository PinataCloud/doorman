/**
 * Claude Code — the host the guard was written against.
 *
 * Its command line is deliberately BARE (no `--host claude`): the installed
 * command string is what Claude Code's own trust/settings state is keyed on,
 * and adding an argument would rewrite an entry that has been on disk since
 * the first release. `hostForArgv` therefore falls back to this descriptor
 * whenever no `--host` is given.
 *
 * Pure: document surgery over text plus the output contract. Everything that
 * touches the filesystem lives in enforcement.ts.
 */

import { join } from "node:path";
import type { GuardHookInput, GuardPromptInput } from "../decision.js";
import {
  HOOK_TIMEOUT_SLACK_SECONDS,
  hookDocumentCommands,
  mergeGuardHook,
  PROMPT_HOOK_EVENT,
  removeGuardHook,
} from "../policy.js";
import type { GuardHostDescriptor, HostDecision, HostDocument, HostEmit } from "./types.js";

/** The message an empty reason falls back to — unchanged since the first
 * release, because it is what a person reads in their session. */
export const DEFAULT_REASON = "Doorman security policy";

/** Claude Code's `hookSpecificOutput` answer. `allow` is never printed: this
 * guard adds a check on top of the native flow, it never removes one. */
export function claudeHookOutput(decision: HostDecision, reason?: string): string | undefined {
  if (decision === "allow") return undefined;
  return JSON.stringify({
    hookSpecificOutput: {
      hookEventName: "PreToolUse",
      permissionDecision: decision,
      permissionDecisionReason: reason ?? DEFAULT_REASON,
    },
  });
}

/**
 * A UserPromptSubmit payload: `{ hook_event_name: "UserPromptSubmit",
 * prompt, session_id, cwd, … }`. Anything else — including a PreToolUse
 * payload, which carries no `hook_event_name` we rely on — is not a prompt.
 */
export function claudeNormalizePrompt(raw: unknown): GuardPromptInput | undefined {
  if (!raw || typeof raw !== "object") return undefined;
  const obj = raw as Record<string, unknown>;
  if (obj.hook_event_name !== PROMPT_HOOK_EVENT || typeof obj.prompt !== "string") return undefined;
  return {
    prompt: obj.prompt,
    ...(typeof obj.session_id === "string" ? { session_id: obj.session_id } : {}),
    ...(typeof obj.cwd === "string" ? { cwd: obj.cwd } : {}),
  };
}

/**
 * Claude Code's prompt-event contract: exit 2 blocks the prompt AND erases it
 * from context, with stderr as the message the person sees; exit 0 with a
 * `hookSpecificOutput.additionalContext` hands the agent a note; exit 0 and
 * silence lets the prompt through. There is no native "ask" on this event —
 * the guard's own hold (the app's approval panel) is the ask, and a denied or
 * timed-out hold prints the block.
 */
export function claudePromptOutput(decision: "allow" | "warn" | "deny", reason?: string, context?: string): HostEmit {
  if (decision === "deny") return { stderr: `${reason ?? DEFAULT_REASON}\n`, exitCode: 2 };
  if (decision === "warn" && context) {
    return {
      stdout: JSON.stringify({ hookSpecificOutput: { hookEventName: PROMPT_HOOK_EVENT, additionalContext: context } }),
      exitCode: 0,
    };
  }
  return { exitCode: 0 };
}

/** The hook payload is already the guard's vocabulary — Claude Code IS the
 * vocabulary every other adapter normalizes into. */
export function claudeNormalizeInput(raw: unknown): GuardHookInput | undefined {
  if (!raw || typeof raw !== "object") return undefined;
  const obj = raw as Record<string, unknown>;
  // A prompt payload is not a tool call: it has its own door (claudeNormalizePrompt).
  if (obj.hook_event_name === PROMPT_HOOK_EVENT) return undefined;
  return {
    ...(typeof obj.session_id === "string" ? { session_id: obj.session_id } : {}),
    ...(typeof obj.tool_name === "string" ? { tool_name: obj.tool_name } : {}),
    ...(obj.tool_input === undefined ? {} : { tool_input: obj.tool_input }),
    ...(typeof obj.cwd === "string" ? { cwd: obj.cwd } : {}),
  };
}

export const claudeHost: GuardHostDescriptor = {
  id: "claude",
  label: "Claude Code",
  source: "claude-code",

  documents(home: string): HostDocument[] {
    return [{ path: join(home, ".claude", "settings.json"), level: "user" }];
  },

  merge(docText, command, holdSeconds, timeoutSeconds): string {
    // The installer knows whether holding is on at all, so it passes the exact
    // timeout; deriving it from the hold window is the fallback for a caller
    // that doesn't (and still clears the window by the same slack).
    return mergeGuardHook(
      docText,
      command,
      timeoutSeconds ?? holdSeconds + HOOK_TIMEOUT_SLACK_SECONDS,
      // The same command under UserPromptSubmit too — the one host where the
      // guard can stop a prompt before the model sees it.
      { promptEvent: true },
    );
  },

  remove(docText) {
    return removeGuardHook(docText);
  },

  installed(docText, command) {
    return (hookDocumentCommands(docText) ?? []).includes(command);
  },

  normalizePrompt: claudeNormalizePrompt,
  emitPrompt: claudePromptOutput,

  normalizeInput: claudeNormalizeInput,

  emit(decision, reason): HostEmit {
    const stdout = claudeHookOutput(decision, reason);
    return stdout === undefined ? { exitCode: 0 } : { stdout, exitCode: 0 };
  },

  /** Claude Code has a native ask, so "nobody could answer in the app" hands
   * the question straight back to it. */
  warn(reason): HostEmit {
    return { stdout: claudeHookOutput("ask", reason)!, exitCode: 0 };
  },

  supportsNativeAsk: true,
  exitSemantics: "fail-open",
  presencePaths: [".claude"],
};
