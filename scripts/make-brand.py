#!/usr/bin/env python3
"""Derive every brand asset from the one master, assets/doorman-logo.png.

Outputs (all committed — Pillow and fontTools are generation-time tools, not
build dependencies, so nothing in CI or in the app needs Python):

  assets/doorman-mark-512.png      the mark on a transparent square — the
                                   sidebar, the setup flow, the "How to fix
                                   this?" button, notification banners and the
                                   VS Code extension's icon
  assets/doorman-app-icon.png      the app icon: the mark on a white tile,
                                   full-bleed 1024 px — scripts/make-icons.mjs
                                   slices the .icns and the Linux PNG from it
  assets/doorman-app-icon-win.png  the Windows icon: the mark itself, ringed in
                                   white, no tile — see win_icon()
  assets/mac/Doorman.icon/         the macOS 26+ app icon, an Icon Composer
                                   document with a Dark variant — see
                                   mac_icon(); scripts/make-mac-icon.mjs
                                   compiles it to assets/mac/Assets.car
  main/lib/tray-mask.ts            the mark's silhouette as an alpha mask, which
                                   main/lib/tray-glyph.ts samples into the
                                   menu-bar template image
  vscode-extension/doorman-icons.woff
                                   a one-glyph icon font of the same silhouette
                                   for the VS Code status bar, which shows only
                                   font glyphs, never bitmaps

Re-run after replacing the master:

    python3 -m venv /tmp/brandenv && /tmp/brandenv/bin/pip install pillow fonttools brotli
    /tmp/brandenv/bin/python scripts/make-brand.py
"""

import base64
import json
from pathlib import Path

from fontTools.fontBuilder import FontBuilder
from fontTools.pens.ttGlyphPen import TTGlyphPen
from PIL import Image, ImageDraw, ImageFilter

ROOT = Path(__file__).resolve().parent.parent
MASTER = ROOT / "assets" / "doorman-logo.png"

# Alpha at or below this is background — the master's anti-aliased fringe
# starts above it.
ALPHA_FLOOR = 16
# The mask's resolution. 64 per side is 4× the 16-pt menu-bar item, so its 2×
# rendering still has two mask samples per pixel to blend.
MASK_SIZE = 64
# The tray glyph and the font glyph threshold the mask here: at or above is ink.
INK_THRESHOLD = 128


def trimmed_square(img: Image.Image) -> Image.Image:
    """The master cropped to its ink, centred on a transparent square."""
    alpha = img.getchannel("A").point(lambda v: 255 if v > ALPHA_FLOOR else 0)
    box = alpha.getbbox()
    crop = img.crop(box)
    side = max(crop.size)
    out = Image.new("RGBA", (side, side), (0, 0, 0, 0))
    out.paste(crop, ((side - crop.width) // 2, (side - crop.height) // 2))
    return out


def app_icon(mark: Image.Image, size: int = 1024) -> Image.Image:
    """The mark at ~80% of a white rounded tile, edge to edge. make-icons.mjs
    pads it onto Apple's icon grid for the .icns; Linux and Windows draw it
    full-bleed as it is."""
    scale = 4  # draw the tile large and downsample, for a smooth corner
    big = size * scale
    tile = Image.new("RGBA", (big, big), (0, 0, 0, 0))
    ImageDraw.Draw(tile).rounded_rectangle((0, 0, big - 1, big - 1), radius=round(big * 0.2237), fill=(255, 255, 255, 255))
    tile = tile.resize((size, size), Image.LANCZOS)
    inner = round(size * 0.80)
    m = mark.resize((inner, inner), Image.LANCZOS)
    tile.alpha_composite(m, ((size - inner) // 2, (size - inner) // 2))
    return tile


def ringed(art: Image.Image, reach: int, soften: float) -> Image.Image:
    """`art` with a white ring `reach` px wide around its ink."""
    solid = art.getchannel("A").point(lambda v: 255 if v > 40 else 0)
    ring = solid.filter(ImageFilter.MaxFilter(2 * reach + 1)).filter(ImageFilter.GaussianBlur(soften))
    out = Image.new("RGBA", art.size, (255, 255, 255, 0))
    out.putalpha(ring)
    out.alpha_composite(art)
    return out


def win_icon(mark: Image.Image, size: int = 1024) -> Image.Image:
    """The mark edge to edge, ringed in white, on a transparent square. Windows
    draws app icons as shapes at 16-32 px in the taskbar, title bar and Start
    menu; the white tile made a full-bleed white square there with the llama
    an 11 px speck inside it. The ring is what keeps the black jacket and cap
    readable on a dark taskbar."""
    pad = round(size * 0.03)
    inner = size - 2 * pad
    canvas = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    canvas.alpha_composite(mark.resize((inner, inner), Image.LANCZOS), (pad, pad))
    return ringed(canvas, round(size * 0.035), size / 512)


# The Icon Composer document (macOS 26+). The system draws the tile — the
# squircle, the glass, the light and dark fill — and the mark is one layer on
# it, at the same 80% the legacy tile uses. Without this the Dock's Dark icon
# style left Doorman the one white tile in a dark Dock: macOS only darkens
# icons that ship their own variants.
#
# The dark fill would swallow the mark's black jacket and cap, so the Dark
# appearance swaps in the mark ringed in white. One layer per appearance, each
# hidden in the other: a layer's IMAGE can't be specialized per appearance
# (actool ignores image-name-specializations), its visibility can.
MAC_ICON_DOCUMENT = {
    "fill": {"automatic-gradient": "extended-srgb:1.00000,1.00000,1.00000,1.00000"},
    "fill-specializations": [
        {"appearance": "dark", "value": {"automatic-gradient": "extended-srgb:0.16000,0.16000,0.17000,1.00000"}},
    ],
    "groups": [
        {
            "layers": [
                {
                    "glass": False,
                    "image-name": "mark-dark.png",
                    "name": "mark-dark",
                    "hidden-specializations": [{"value": True}, {"appearance": "dark", "value": False}],
                },
                {
                    "glass": False,
                    "image-name": "mark.png",
                    "name": "mark",
                    "hidden-specializations": [{"appearance": "dark", "value": True}],
                },
            ],
            "shadow": {"kind": "neutral", "opacity": 0.5},
            "translucency": {"enabled": False, "value": 0.5},
        }
    ],
    "supported-platforms": {"squares": ["macOS"]},
}


def mac_icon(mark: Image.Image, size: int = 1024) -> None:
    doc = ROOT / "assets" / "mac" / "Doorman.icon"
    (doc / "Assets").mkdir(parents=True, exist_ok=True)
    inner = round(size * 0.80)
    layer = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    layer.alpha_composite(mark.resize((inner, inner), Image.LANCZOS), ((size - inner) // 2, (size - inner) // 2))
    layer.save(doc / "Assets" / "mark.png", optimize=True)
    ringed(layer, round(size * 0.018), 1.5).save(doc / "Assets" / "mark-dark.png", optimize=True)
    (doc / "icon.json").write_text(json.dumps(MAC_ICON_DOCUMENT, indent=2) + "\n")


def write_mask(mark: Image.Image) -> list[list[int]]:
    alpha = mark.getchannel("A").resize((MASK_SIZE, MASK_SIZE), Image.LANCZOS)
    rows = [[alpha.getpixel((x, y)) for x in range(MASK_SIZE)] for y in range(MASK_SIZE)]
    data = base64.b64encode(bytes(v for row in rows for v in row)).decode("ascii")
    chunks = [data[i : i + 96] for i in range(0, len(data), 96)]
    body = "\n".join(f'  "{c}" +' for c in chunks).rstrip(" +")
    out = ROOT / "main" / "lib" / "tray-mask.ts"
    out.write_text(
        "// GENERATED by scripts/make-brand.py from assets/doorman-logo.png — do not edit.\n"
        "// The mark's silhouette: one alpha byte per cell, row-major, top row first.\n\n"
        f"export const TRAY_MASK_SIZE = {MASK_SIZE};\n\n"
        "export const TRAY_MASK_BASE64 =\n"
        f"{body};\n"
    )
    print(f"wrote {out.relative_to(ROOT)}")
    return rows


def write_font(rows: list[list[int]]) -> None:
    """The silhouette as filled rectangles — one per horizontal run of ink, so
    the glyph stays a few hundred points rather than one square per cell."""
    upm = 1000
    cell = 900 / MASK_SIZE
    x0, y0 = 50, -60
    pen = TTGlyphPen(None)
    for y, row in enumerate(rows):
        x = 0
        while x < MASK_SIZE:
            if row[x] < INK_THRESHOLD:
                x += 1
                continue
            start = x
            while x < MASK_SIZE and row[x] >= INK_THRESHOLD:
                x += 1
            left, right = round(x0 + start * cell), round(x0 + x * cell)
            top, bottom = round(y0 + (MASK_SIZE - y) * cell), round(y0 + (MASK_SIZE - y - 1) * cell)
            # Clockwise in font space: the filled direction for TrueType.
            pen.moveTo((left, bottom))
            pen.lineTo((left, top))
            pen.lineTo((right, top))
            pen.lineTo((right, bottom))
            pen.closePath()
    glyph = "doorman-mark"
    fb = FontBuilder(upm, isTTF=True)
    fb.setupGlyphOrder([".notdef", glyph])
    fb.setupCharacterMap({0xE001: glyph})
    fb.setupGlyf({".notdef": TTGlyphPen(None).glyph(), glyph: pen.glyph()})
    advance = 900 + 2 * x0
    fb.setupHorizontalMetrics({".notdef": (advance, 0), glyph: (advance, x0)})
    fb.setupHorizontalHeader(ascent=900, descent=-100)
    fb.setupOS2(sTypoAscender=900, sTypoDescender=-100, usWinAscent=900, usWinDescent=100)
    fb.setupNameTable({"familyName": "Doorman Icons", "styleName": "Regular", "psName": "DoormanIcons-Regular",
                       "copyright": "Pinata. The product's own mark; no third-party material."})
    fb.setupPost()
    font = fb.font
    font.flavor = "woff"
    out = ROOT / "vscode-extension" / "doorman-icons.woff"
    font.save(str(out))
    print(f"wrote {out.relative_to(ROOT)} ({out.stat().st_size} bytes)")


def main() -> None:
    mark = trimmed_square(Image.open(MASTER).convert("RGBA"))
    mark.resize((512, 512), Image.LANCZOS).save(ROOT / "assets" / "doorman-mark-512.png", optimize=True)
    print("wrote assets/doorman-mark-512.png")
    app_icon(mark).save(ROOT / "assets" / "doorman-app-icon.png", optimize=True)
    print("wrote assets/doorman-app-icon.png")
    win_icon(mark).save(ROOT / "assets" / "doorman-app-icon-win.png", optimize=True)
    print("wrote assets/doorman-app-icon-win.png")
    mac_icon(mark)
    print("wrote assets/mac/Doorman.icon (compile it with `npm run icons:mac`)")
    write_font(write_mask(mark))


if __name__ == "__main__":
    main()
