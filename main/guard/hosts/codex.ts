/**
 * Codex — the second host, and the shape every "no native ask" host after it
 * follows: the app mediates the question when it can, and when it cannot the
 * call CONTINUES with a visible warning rather than being denied on a human's
 * behalf (guard.ts rule 3).
 *
 * Its command carries `--host codex`. Codex trusts a handler by its definition
 * as well as its position, so that string must stay byte-stable.
 *
 * Pure: no fs. `$CODEX_HOME` arrives through the `env` argument.
 */

import { join } from "node:path";
import type { GuardHookInput } from "../decision.js";
import {
  HOOK_TIMEOUT_SLACK_SECONDS,
  hookDocumentCommands,
  mergeCodexGuardHook,
  removeCodexGuardHook,
} from "../policy.js";
import { DEFAULT_REASON, claudeHookOutput, claudeNormalizeInput } from "./claude.js";
import type { GuardHostDescriptor, HostDocument, HostEmit } from "./types.js";

/** The Codex home, honouring `$CODEX_HOME` exactly as the CLI does. */
export function codexHome(home: string, env: NodeJS.ProcessEnv): string {
  const configured = env.CODEX_HOME?.trim();
  return configured || join(home, ".codex");
}

export const codexHost: GuardHostDescriptor = {
  id: "codex",
  label: "Codex",
  source: "codex",

  documents(home: string, env: NodeJS.ProcessEnv): HostDocument[] {
    return [{ path: join(codexHome(home, env), "hooks.json"), level: "user" }];
  },

  merge(docText, command, holdSeconds, timeoutSeconds): string {
    return mergeCodexGuardHook(
      docText,
      command,
      timeoutSeconds ?? holdSeconds + HOOK_TIMEOUT_SLACK_SECONDS,
    );
  },

  remove(docText) {
    return removeCodexGuardHook(docText);
  },

  installed(docText, command) {
    return (hookDocumentCommands(docText) ?? []).includes(command);
  },

  normalizeInput(raw: unknown): GuardHookInput | undefined {
    // Codex sends the same PreToolUse envelope Claude Code does.
    return claudeNormalizeInput(raw);
  },

  emit(decision, reason): HostEmit {
    if (decision === "allow") return { exitCode: 0 };
    if (decision === "ask") return codexHost.warn(reason ?? DEFAULT_REASON);
    return { stdout: claudeHookOutput(decision, reason)!, exitCode: 0 };
  },

  /** No native PreToolUse ask: say so out loud and let the call through. */
  warn(reason): HostEmit {
    return {
      stdout: JSON.stringify({
        systemMessage:
          `${reason ?? DEFAULT_REASON} Doorman could not ask in the app; Codex does not support native ` +
          "PreToolUse ask, so this call is continuing.",
      }),
      exitCode: 0,
    };
  },

  supportsNativeAsk: false,
  exitSemantics: "fail-open",
  presencePaths: [".codex"],
};
