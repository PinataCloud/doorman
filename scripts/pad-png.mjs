// Pure-Node PNG padder: centers an RGBA PNG on a larger transparent canvas.
//
// Why this exists: the brand mark is FULL-BLEED (the rounded square touches
// every edge), but a macOS app icon is drawn inside Apple's icon grid — the
// artwork occupies ~80% of the canvas and the rest is transparent margin. An
// unpadded icon reads oversized and blocky next to every native icon in the
// dock. No stock macOS tool pads transparently (sips --padColor is opaque
// only), and the repo's rule is no build-time deps the CI runner doesn't
// have — so this decodes/encodes the PNG itself with node:zlib.
//
// Scope, stated: 8-bit RGBA (color type 6), non-interlaced — which is what
// the brand assets are. Anything else fails loudly rather than mis-rendering.

import { inflateSync, deflateSync } from "node:zlib";

const PNG_SIG = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);

const CRC_TABLE = new Int32Array(256).map((_, n) => {
  let c = n;
  for (let k = 0; k < 8; k += 1) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  return c;
});

function crc32(buf) {
  let c = 0xffffffff;
  for (const byte of buf) c = CRC_TABLE[(c ^ byte) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

function chunk(type, data) {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length);
  const body = Buffer.concat([Buffer.from(type, "latin1"), data]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(body));
  return Buffer.concat([len, body, crc]);
}

/** Decode an 8-bit RGBA non-interlaced PNG into { width, height, pixels }. */
export function decodePng(buf) {
  if (!buf.subarray(0, 8).equals(PNG_SIG)) throw new Error("not a PNG");
  let pos = 8;
  let width = 0;
  let height = 0;
  const idat = [];
  while (pos < buf.length) {
    const len = buf.readUInt32BE(pos);
    const type = buf.toString("latin1", pos + 4, pos + 8);
    const data = buf.subarray(pos + 8, pos + 8 + len);
    if (type === "IHDR") {
      width = data.readUInt32BE(0);
      height = data.readUInt32BE(4);
      const [bitDepth, colorType, , , interlace] = [data[8], data[9], data[10], data[11], data[12]];
      if (bitDepth !== 8 || colorType !== 6 || interlace !== 0) {
        throw new Error(
          `unsupported PNG (bitDepth=${bitDepth} colorType=${colorType} interlace=${interlace}) — need 8-bit RGBA non-interlaced`,
        );
      }
    } else if (type === "IDAT") {
      idat.push(data);
    } else if (type === "IEND") {
      break;
    }
    pos += 12 + len;
  }
  const raw = inflateSync(Buffer.concat(idat));
  const stride = width * 4;
  const pixels = Buffer.alloc(height * stride);
  let prev = Buffer.alloc(stride);
  for (let y = 0; y < height; y += 1) {
    const filter = raw[y * (stride + 1)];
    const line = raw.subarray(y * (stride + 1) + 1, (y + 1) * (stride + 1));
    const out = pixels.subarray(y * stride, (y + 1) * stride);
    for (let x = 0; x < stride; x += 1) {
      const a = x >= 4 ? out[x - 4] : 0;
      const b = prev[x];
      const c = x >= 4 ? prev[x - 4] : 0;
      let value = line[x];
      switch (filter) {
        case 0:
          break;
        case 1:
          value = (value + a) & 0xff;
          break;
        case 2:
          value = (value + b) & 0xff;
          break;
        case 3:
          value = (value + ((a + b) >> 1)) & 0xff;
          break;
        case 4: {
          const p = a + b - c;
          const pa = Math.abs(p - a);
          const pb = Math.abs(p - b);
          const pc = Math.abs(p - c);
          value = (value + (pa <= pb && pa <= pc ? a : pb <= pc ? b : c)) & 0xff;
          break;
        }
        default:
          throw new Error(`unsupported PNG filter ${filter}`);
      }
      out[x] = value;
    }
    prev = out;
  }
  return { width, height, pixels };
}

/** Encode 8-bit RGBA pixels as a PNG (filter 0 — size doesn't matter here). */
export function encodePng(width, height, pixels) {
  const stride = width * 4;
  const raw = Buffer.alloc(height * (stride + 1));
  for (let y = 0; y < height; y += 1) {
    raw[y * (stride + 1)] = 0;
    pixels.copy(raw, y * (stride + 1) + 1, y * stride, (y + 1) * stride);
  }
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(width, 0);
  ihdr.writeUInt32BE(height, 4);
  ihdr[8] = 8; // bit depth
  ihdr[9] = 6; // RGBA
  return Buffer.concat([
    PNG_SIG,
    chunk("IHDR", ihdr),
    chunk("IDAT", deflateSync(raw, { level: 9 })),
    chunk("IEND", Buffer.alloc(0)),
  ]);
}

/**
 * Center the image on a transparent canvas so the artwork occupies
 * `contentRatio` of the output edge (Apple's grid is ~0.805).
 */
export function padToIconGrid(buf, contentRatio = 0.805) {
  const { width, height, pixels } = decodePng(buf);
  const size = Math.round(Math.max(width, height) / contentRatio);
  const ox = Math.floor((size - width) / 2);
  const oy = Math.floor((size - height) / 2);
  const out = Buffer.alloc(size * size * 4);
  for (let y = 0; y < height; y += 1) {
    pixels.copy(out, ((oy + y) * size + ox) * 4, y * width * 4, (y + 1) * width * 4);
  }
  return encodePng(size, size, out);
}
