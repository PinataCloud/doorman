/**
 * The CLI's advice inside a Docker Sandbox (`sbx`). Whether this is one, and
 * which, is guard/sandbox.ts's call — the guard bundle words its reasons from
 * the same check, so the two never disagree.
 *
 * Read off sbx 0.46.0 (2026-10-20): a sandbox's traffic goes through its proxy
 * at `gateway.docker.internal:3128` (`HTTPS_PROXY`), which enforces the network
 * policy and answers a blocked request with HTTP 403.
 *
 * Inside one, the desktop app cannot run, so the CLI's advice changes: held
 * calls are answered by `doorman watch` started from the host with
 * `sbx exec -it <name> doorman watch`, and a download the proxy refuses needs
 * an `sbx policy allow network` rule rather than a retry.
 */

import { dockerSandbox, type DockerSandbox } from "../guard/sandbox.js";

export { dockerSandbox, sandboxFindingsCommand, sandboxWatchCommand, type DockerSandbox } from "../guard/sandbox.js";

/** How a message names another Doorman process, with a leading space: its
 * pid on this machine, the sandbox inside one (a container's pid means
 * nothing to a person on the host). Empty when there is nothing to name. */
export function processLabel(env: NodeJS.ProcessEnv, pid: number | undefined): string {
  const sandbox = dockerSandbox(env);
  if (sandbox) return ` in sandbox ${sandbox.name}`;
  return pid !== undefined ? ` (pid ${pid})` : "";
}

/** Whether outbound HTTP goes through the sandbox's policy proxy. */
export function sandboxProxied(env: NodeJS.ProcessEnv): boolean {
  const proxy = env.HTTPS_PROXY ?? env.https_proxy ?? "";
  return /\/\/gateway\.docker\.internal(?::\d+)?\/?$/i.test(proxy.trim());
}

/** The sandbox whose network policy refused a request that got `status`:
 * the policy proxy answers a blocked request with 403. Undefined outside a
 * sandbox, without its proxy, and for any other answer. */
export function sandboxPolicyBlock(env: NodeJS.ProcessEnv, status: number | undefined): DockerSandbox | undefined {
  const sandbox = dockerSandbox(env);
  return sandbox && status === 403 && sandboxProxied(env) ? sandbox : undefined;
}

/** The host-side command that lets this sandbox reach `hosts`. */
export function sandboxAllowCommand(sandbox: DockerSandbox, hosts: readonly string[]): string {
  return `sbx policy allow network --sandbox ${sandbox.name} "${hosts.join(",")}"`;
}

/** What the classifier model download needs: the Hub, and the CDN it
 * redirects files to (`us.aws.cdn.hf.co` and similar, several levels deep). */
export const MODEL_HOSTS = ["huggingface.co", "**.hf.co"] as const;
