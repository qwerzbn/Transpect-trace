"""Build a single, equal-length zstd frame from independently inspected JSON."""
from __future__ import annotations

import time

import zstandard as zstd


def pack_history_zstd(clean: bytes, wire_length: int, deadline: float) -> bytes:
    # Zero-output blocks preserve the encoded content size and checksum. A
    # raw empty block occupies 3 bytes, an empty RLE block occupies 4. Insert
    # them immediately after the frame header, before the first real block.
    for level in (3, 1, 5, 7, 9):
        for checksum in (False, True):
            if time.monotonic() >= deadline:
                raise TimeoutError("history compression deadline")
            frame = zstd.ZstdCompressor(level=level, write_checksum=checksum).compress(clean)
            gap = wire_length - len(frame)
            if not 0 <= gap <= 64 * 1024:
                continue
            rle_blocks = gap % 3
            remaining = gap - 4 * rle_blocks
            if remaining < 0:
                continue
            header = zstd.frame_header_size(frame)
            padded = (frame[:header] + bytes(remaining) + b"\x02\x00\x00\x00" * rle_blocks
                      + frame[header:])
            if (len(padded) == wire_length and zstd.ZstdDecompressor().decompress(
                    padded, allow_extra_data=False) == clean):
                return padded
    raise ValueError("cannot fit a verified zstd frame into the outbound body")
