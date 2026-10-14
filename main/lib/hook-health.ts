/**
 * Gatekeeper translocation: macOS launches a quarantined app that was never
 * moved from where it was unpacked from a randomized, ephemeral
 * `/private/var/folders/…/AppTranslocation/<uuid>/` mount that stops existing
 * when the app quits. Anything that records the app's own path from there —
 * the guard install, the editor companion — points at nothing after a relaunch,
 * so the app asks to be moved to /Applications first.
 *
 * No Electron import, so the test exercises it with plain Node.
 */

export const TRANSLOCATION_FRAGMENT = "/AppTranslocation/";

/** Is this process running from a Gatekeeper translocation mount? */
export function isTranslocated(execPath: string = process.execPath): boolean {
  return execPath.includes(TRANSLOCATION_FRAGMENT);
}
