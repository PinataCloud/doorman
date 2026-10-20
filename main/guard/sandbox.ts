/**
 * Whether this process runs inside a Docker Sandbox (`sbx`), and which one —
 * the one implementation the guard and the CLI share (cli/docker-sandbox.ts
 * builds the CLI's advice on it).
 *
 * Read off sbx 0.46.0 (2026-10-20): every sandbox's processes get
 * `SANDBOX_NAME` (the name `sbx` commands take), `SANDBOX_ID` and
 * `WORKSPACE_DIR`.
 *
 * Inside one, the desktop app cannot run and the host's app has none of the
 * sandbox's data, so whatever sends a person to "Doorman" names the host-side
 * command instead: held calls are answered by `doorman watch` started from the
 * host, findings are read with `doorman findings` the same way.
 *
 * Self-containment rule: this file is copied into the guard bundle and run
 * with plain `node`; it imports nothing.
 */

export interface DockerSandbox {
  /** The sandbox's name, as `sbx exec` / `sbx policy --sandbox` take it. */
  name: string;
}

export function dockerSandbox(env: NodeJS.ProcessEnv): DockerSandbox | undefined {
  const name = env.SANDBOX_NAME?.trim();
  if (!name || !env.SANDBOX_ID) return undefined;
  return { name };
}

/** The host-side command that answers this sandbox's held calls. */
export function sandboxWatchCommand(sandbox: DockerSandbox): string {
  return `sbx exec -it ${sandbox.name} doorman watch`;
}

/** The host-side command that lists this sandbox's findings. */
export function sandboxFindingsCommand(sandbox: DockerSandbox): string {
  return `sbx exec ${sandbox.name} doorman findings`;
}
