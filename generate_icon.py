"""Generate assets/icons/app.ico for the packaged app.

Draws a simple phishing-hook / shield icon using only stdlib (struct + zlib)
and Pillow (already a transitive dependency of several packages in the venv).
Run once: python generate_icon.py
"""
from __future__ import annotations

import os
import struct
import zlib
from pathlib import Path

try:
    from PIL import Image, ImageDraw, ImageFont
    USE_PILLOW = True
except ImportError:
    USE_PILLOW = False


def _draw_icon_pillow(size: int) -> Image.Image:
    """Draw a dark-navy shield with a white fish-hook / @ symbol inside."""
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    pad = max(2, size // 16)
    # Shield body — rounded rectangle
    shield_color = (15, 40, 90, 255)   # dark navy
    accent_color = (220, 60, 60, 255)  # red accent for the hook
    text_color   = (255, 255, 255, 255)

    # Shield shape: filled rounded rect
    r = max(4, size // 8)
    draw.rounded_rectangle([pad, pad, size - pad, size - pad - size // 6],
                           radius=r, fill=shield_color)
    # Shield bottom point
    mid_x = size // 2
    bottom = size - pad
    top_of_point = size - pad - size // 6
    draw.polygon([(pad, top_of_point),
                  (size - pad, top_of_point),
                  (mid_x, bottom)],
                 fill=shield_color)

    # Draw "@" as the "phishing hook" symbol in the centre
    font_size = max(8, int(size * 0.45))
    try:
        font = ImageFont.truetype("arialbd.ttf", font_size)
    except (IOError, OSError):
        try:
            font = ImageFont.truetype("arial.ttf", font_size)
        except (IOError, OSError):
            font = ImageFont.load_default()

    # Centre the glyph
    bbox = draw.textbbox((0, 0), "@", font=font)
    tw, th = bbox[2] - bbox[0], bbox[3] - bbox[1]
    tx = (size - tw) // 2 - bbox[0]
    ty = (size - th) // 2 - bbox[1] - size // 14   # nudge up slightly
    draw.text((tx, ty), "@", font=font, fill=accent_color)

    return img


def _make_png_bytes_raw(size: int) -> bytes:
    """Minimal solid-colour PNG as a fallback when Pillow is unavailable."""
    # 32x32 RGBA image — dark navy shield-ish colour, opaque
    width = height = size
    raw_rows = []
    for y in range(height):
        row = bytearray()
        for x in range(width):
            # Simple shield silhouette: filled except top-corners
            in_shield = not (
                (x < size // 8 and y < size // 8) or
                (x > size - size // 8 and y < size // 8)
            )
            if in_shield:
                row += bytes([15, 40, 90, 255])   # RGBA navy
            else:
                row += bytes([0, 0, 0, 0])         # transparent
        raw_rows.append(b'\x00' + bytes(row))

    raw = b''.join(raw_rows)
    compressed = zlib.compress(raw)

    def chunk(tag: bytes, data: bytes) -> bytes:
        c = struct.pack('>I', len(data)) + tag + data
        crc = zlib.crc32(tag + data) & 0xFFFFFFFF
        return c + struct.pack('>I', crc)

    ihdr_data = struct.pack('>IIBBBBB', width, height, 8, 6, 0, 0, 0)
    png = b'\x89PNG\r\n\x1a\n'
    png += chunk(b'IHDR', ihdr_data)
    png += chunk(b'IDAT', compressed)
    png += chunk(b'IEND', b'')
    return png


def build_ico(out_path: Path) -> None:
    """Build a multi-size .ico containing 256x256, 64x64, 32x32, 16x16."""
    sizes = [256, 64, 32, 16]
    images_png: list[bytes] = []

    if USE_PILLOW:
        for sz in sizes:
            img = _draw_icon_pillow(sz)
            import io
            buf = io.BytesIO()
            img.save(buf, format="PNG")
            images_png.append(buf.getvalue())
        print("Icon generated using Pillow.")
    else:
        for sz in sizes:
            images_png.append(_make_png_bytes_raw(sz))
        print("Pillow not available — generated minimal fallback icon.")

    # ICO format: header + directory entries + image data
    n = len(sizes)
    header = struct.pack('<HHH', 0, 1, n)   # reserved, type=1 (ICO), count

    # Each directory entry: width, height, color-count, reserved,
    #                        planes, bit-count, size, offset
    dir_entry_size = 16
    image_data_offset = 6 + n * dir_entry_size  # 6-byte header + n*16

    entries = b''
    offsets = []
    cur_offset = image_data_offset
    for i, sz in enumerate(sizes):
        png_bytes = images_png[i]
        w = sz if sz < 256 else 0   # ICO uses 0 to mean 256
        h = w
        entries += struct.pack('<BBBBHHII',
                               w, h,
                               0, 0,     # color count, reserved
                               1, 32,    # planes, bit depth
                               len(png_bytes), cur_offset)
        offsets.append(cur_offset)
        cur_offset += len(png_bytes)

    ico = header + entries
    for png_bytes in images_png:
        ico += png_bytes

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(ico)
    print(f"Wrote {out_path}  ({len(ico):,} bytes, {n} sizes: {sizes})")


if __name__ == "__main__":
    build_ico(Path("assets/icons/app.ico"))
