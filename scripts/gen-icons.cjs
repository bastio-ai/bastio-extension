#!/usr/bin/env node
/**
 * Generate placeholder icon PNGs at 16/32/48/128 px.
 * Solid-fill bastio-cyan (#2ee5d8) on dark (#0d1117) background, with a small "B"
 * shape in the center. No external dependencies — uses Node built-ins (zlib + crc32).
 *
 * Replace these with the real brand mark before public release.
 */

const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

const SIZES = [16, 32, 48, 128];
const BG = [0x0d, 0x11, 0x17];
const FG = [0x2e, 0xe5, 0xd8];

function crc32(buf) {
  let c, table = [];
  for (let n = 0; n < 256; n++) {
    c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    table[n] = c;
  }
  let crc = 0xffffffff;
  for (let i = 0; i < buf.length; i++) crc = table[(crc ^ buf[i]) & 0xff] ^ (crc >>> 8);
  return (crc ^ 0xffffffff) >>> 0;
}

function chunk(type, data) {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length, 0);
  const typeBuf = Buffer.from(type, 'ascii');
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(Buffer.concat([typeBuf, data])), 0);
  return Buffer.concat([len, typeBuf, data, crc]);
}

function makePNG(size) {
  // Build pixel grid with simple "B" glyph in center
  const pixels = [];
  for (let y = 0; y < size; y++) {
    const row = [0]; // filter byte = none
    for (let x = 0; x < size; x++) {
      const cx = size / 2;
      const cy = size / 2;
      const inset = Math.max(2, Math.floor(size * 0.18));
      const inX = x >= inset && x < size - inset;
      const inY = y >= inset && y < size - inset;
      // Outer rounded square: bg with cyan border
      const border = (Math.abs(x - cx) > size / 2 - 2) || (Math.abs(y - cy) > size / 2 - 2);
      let color = border ? FG : BG;
      // Center mark: a vertical bar + two horizontal stems (simplified B)
      if (inX && inY) {
        const left = x - inset < Math.max(1, Math.floor(size * 0.12));
        const middleY = Math.abs(y - cy) < Math.max(1, Math.floor(size * 0.05));
        const topY = y - inset < Math.max(1, Math.floor(size * 0.10));
        const botY = (size - 1 - inset) - y < Math.max(1, Math.floor(size * 0.10));
        if (left || ((topY || middleY || botY) && x - inset < size - inset * 2 - Math.max(1, Math.floor(size * 0.16)))) {
          color = FG;
        }
      }
      row.push(color[0], color[1], color[2]);
    }
    pixels.push(Buffer.from(row));
  }
  const raw = Buffer.concat(pixels);
  const idat = zlib.deflateSync(raw);

  const sig = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(size, 0);
  ihdr.writeUInt32BE(size, 4);
  ihdr[8] = 8;  // bit depth
  ihdr[9] = 2;  // color type: RGB
  ihdr[10] = 0; // compression
  ihdr[11] = 0; // filter
  ihdr[12] = 0; // interlace

  return Buffer.concat([
    sig,
    chunk('IHDR', ihdr),
    chunk('IDAT', idat),
    chunk('IEND', Buffer.alloc(0)),
  ]);
}

const outDir = path.join(__dirname, '..', 'public', 'icons');
fs.mkdirSync(outDir, { recursive: true });
for (const size of SIZES) {
  const png = makePNG(size);
  const outPath = path.join(outDir, `icon-${size}.png`);
  fs.writeFileSync(outPath, png);
  console.log(`wrote ${outPath} (${png.length} bytes)`);
}
