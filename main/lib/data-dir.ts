import { homedir } from "node:os";
import { join } from "node:path";

/**
 * Doorman's data directory, resolved the way the desktop app's Electron
 * `app.getPath("userData")` resolves it (main/index.ts sets it to
 * `<appData>/Doorman`), so the CLI and the app share one store, one prefs file
 * and one guard bundle:
 *
 * - `DOORMAN_APPDATA_DIR` set → `<that>/Doorman` (the same override the app takes)
 * - macOS → `~/Library/Application Support/Doorman`
 * - Windows → `%APPDATA%\Doorman`
 * - Linux and the rest → `$XDG_CONFIG_HOME/Doorman`, else `~/.config/Doorman`
 */
export function doormanDataDir(
  env: NodeJS.ProcessEnv = process.env,
  platform: NodeJS.Platform = process.platform,
  home: string = homedir(),
): string {
  if (env.DOORMAN_APPDATA_DIR) return join(env.DOORMAN_APPDATA_DIR, "Doorman");
  if (platform === "darwin") return join(home, "Library", "Application Support", "Doorman");
  if (platform === "win32") return join(env.APPDATA || join(home, "AppData", "Roaming"), "Doorman");
  return join(env.XDG_CONFIG_HOME || join(home, ".config"), "Doorman");
}
