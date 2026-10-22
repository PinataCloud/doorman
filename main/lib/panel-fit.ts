/**
 * Where the floating approval panel's window goes once its content has said
 * how tall it is (main/approval-window.ts). A held call's card varies — a
 * context note, a description, up to 96px of evidence, a second row of
 * actions — so a fixed height cut the bottom off.
 *
 * The window keeps its x, width and top edge (where it was placed, or dragged
 * to), grows to the content, never past the work area minus a margin top and
 * bottom (the card scrolls past that), and moves up when growing would run it
 * off the bottom of the screen.
 */

export interface PanelArea {
  x: number;
  y: number;
  width: number;
  height: number;
}

export function fitPanelBounds(bounds: PanelArea, content: number, work: PanelArea, margin: number, min: number): PanelArea {
  const max = Math.max(min, work.height - 2 * margin);
  const height = Math.min(max, Math.max(min, Math.ceil(content)));
  const bottom = work.y + work.height - margin;
  const y = Math.max(work.y + margin, Math.min(bounds.y, bottom - height));
  return { x: bounds.x, width: bounds.width, y, height };
}
