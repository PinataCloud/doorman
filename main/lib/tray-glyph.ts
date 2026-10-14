/**
 * The menu-bar glyph, drawn as pixels rather than loaded from a file.
 *
 * Why not just ship an SVG: Electron's `nativeImage` decodes PNG and JPEG only.
 * An SVG data URL silently produces an EMPTY image — the tray item still appears
 * (its title is text) so nothing looks broken, which is precisely how a menu-bar
 * app ends up with no icon and nobody notices.
 *
 * Why not ship a PNG: the status dot is composited onto the mark per state,
 * with a clear ring knocked out of the mark behind it — that needs the mark's
 * coverage, not a finished picture.
 *
 * So the mark's silhouette is an alpha mask (tray-mask.ts, generated from the
 * brand master by scripts/make-brand.py) sampled into a BGRA buffer at whatever
 * size the tray asks for. It is pure, so the tests can assert the shape
 * directly, and it renders crisply at any scale factor.
 *
 * Output is a macOS TEMPLATE image: black with a real alpha channel, which the
 * system re-tints for light/dark menu bars, for selection, and for reduced
 * transparency. Colour here would defeat all three.
 */

import { TRAY_MASK_BASE64, TRAY_MASK_SIZE } from "./tray-mask.js";

/** The glyph's unit box; the dot's geometry below is in the same units. */
const BOX = 16;
/** Supersampling per axis. 4 is the point where the curves stop stair-stepping. */
const SAMPLES = 4;

let mask: Uint8Array | undefined;

/** How much of this point (in the 16×16 box) is ink, 0–1 — the mask
 * sampled bilinearly, so edges keep the master's own anti-aliasing. */
export function inkCoverage(x: number, y: number): number {
  mask ??= new Uint8Array(Buffer.from(TRAY_MASK_BASE64, "base64"));
  const n = TRAY_MASK_SIZE;
  const fx = Math.min(n - 1, Math.max(0, (x / BOX) * n - 0.5));
  const fy = Math.min(n - 1, Math.max(0, (y / BOX) * n - 0.5));
  const x0 = Math.floor(fx);
  const y0 = Math.floor(fy);
  const x1 = Math.min(n - 1, x0 + 1);
  const y1 = Math.min(n - 1, y0 + 1);
  const tx = fx - x0;
  const ty = fy - y0;
  const at = (cx: number, cy: number): number => mask![cy * n + cx]! / 255;
  const top = at(x0, y0) * (1 - tx) + at(x1, y0) * tx;
  const bottom = at(x0, y1) * (1 - tx) + at(x1, y1) * tx;
  return top * (1 - ty) + bottom * ty;
}

export interface TrayGlyph {
  width: number;
  height: number;
  /** Premultiplied BGRA, the layout `nativeImage.createFromBitmap` expects. */
  bitmap: Buffer;
}

/** An sRGB colour, 0–255 per channel. */
export type Rgb = readonly [number, number, number];

export interface TrayGlyphOptions {
  /** The mark's own colour. Default black — the template-image case, where
   * macOS re-tints it. Given a colour the image is NOT a template any more, so
   * the caller picks black/white for the menu bar it is drawn on. */
  ink?: Rgb;
  /** A status dot in the mark's bottom-right corner, in its own colour, with a
   * clear ring knocked out of the mark behind it so it reads against the
   * mark rather than sitting on it. The guard's state: green = enforcing,
   * red = tampered with. No dot = the guard is off. */
  dot?: Rgb;
}

/** The status dot's geometry, in the same 16×16 box. It overlaps the tile's
 * corner, beside the front leg, so it belongs to the mark. */
const DOT_CX = 12.9;
const DOT_CY = 12.9;
const DOT_R = 3.1;
/** Clear ring around the dot: the mark's ink stops this far outside the dot. */
const DOT_RING = 1.0;

function distanceToDot(x: number, y: number): number {
  const dx = x - DOT_CX;
  const dy = y - DOT_CY;
  return Math.sqrt(dx * dx + dy * dy);
}

/**
 * Sample the glyph into a bitmap `size`×`size`. Anti-aliased by supersampling:
 * a menu-bar icon is small enough that hard edges on the oval read as damage.
 */
export function renderTrayGlyph(size: number, options: TrayGlyphOptions = {}): TrayGlyph {
  const bitmap = Buffer.alloc(size * size * 4);
  const step = BOX / size;
  const sub = step / SAMPLES;
  const ink: Rgb = options.ink ?? [0, 0, 0];
  const dot = options.dot;
  for (let py = 0; py < size; py++) {
    for (let px = 0; px < size; px++) {
      let inkHits = 0;
      let dotHits = 0;
      for (let sy = 0; sy < SAMPLES; sy++) {
        for (let sx = 0; sx < SAMPLES; sx++) {
          const x = px * step + (sx + 0.5) * sub;
          const y = py * step + (sy + 0.5) * sub;
          if (dot) {
            const d = distanceToDot(x, y);
            if (d <= DOT_R) { dotHits++; continue; }
            // The ring: mark ink is erased here so the dot has an edge.
            if (d <= DOT_R + DOT_RING) continue;
          }
          inkHits += inkCoverage(x, y);
        }
      }
      if (inkHits === 0 && dotHits === 0) continue;
      const total = SAMPLES * SAMPLES;
      const i = (py * size + px) * 4;
      // Two coverages blended into one premultiplied pixel (they never overlap:
      // a sample is the dot, the ring, or the mark).
      const inkA = inkHits / total;
      const dotA = dotHits / total;
      const alpha = inkA + dotA;
      const mix = (c: number): number => {
        const inkPart = ink[c] * inkA;
        const dotPart = dot ? dot[c] * dotA : 0;
        return Math.round(inkPart + dotPart);
      };
      // BGRA order.
      bitmap[i] = mix(2);
      bitmap[i + 1] = mix(1);
      bitmap[i + 2] = mix(0);
      bitmap[i + 3] = Math.round(alpha * 255);
    }
  }
  return { width: size, height: size, bitmap };
}

/** Logical size of the menu-bar item; macOS draws it at 1× and 2×. */
export const TRAY_GLYPH_SIZE = 16;
