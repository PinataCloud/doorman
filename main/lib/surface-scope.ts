/**
 * Which whole SURFACES the app shows — the settings sections and integration
 * cards held back for now, beside guard/rule-scope.ts, which does the same for
 * rules. Hidden rather than deleted: the code, the stored preferences and the
 * doctor's health rows stay; bringing one back is deleting its id here AND in
 * the renderer's mirror (components.jsx HIDDEN_SURFACES — pinned equal by
 * test/surface-scope.test.ts).
 *
 * What hiding each one means beyond its card:
 *  · `editor_extension` — the "Show Doorman in the editor" card on
 *    Integrations. Card only: the companion keeps installing at boot as its
 *    stored preference says.
 *  · `digests` — the security, usage and startup digest rows in Settings. The
 *    digests PAUSE while hidden: the security digest is on by default, and a
 *    weekly banner with no switch left to stop it is not a hidden feature but
 *    an unremovable one. The startup delivery check falls back to its silent
 *    probe, as it does with the startup digest switched off.
 */

export type SurfaceId = "editor_extension" | "digests";

export const HIDDEN_SURFACES: ReadonlySet<SurfaceId> = new Set<SurfaceId>(["editor_extension", "digests"]);

export function surfaceShown(id: SurfaceId): boolean {
  return !HIDDEN_SURFACES.has(id);
}
