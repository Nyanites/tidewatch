#!/usr/bin/env python3
"""Build a large, valid .evtx file for benchmarking by replicating real 64 KiB chunks.

Large real-world event logs are rarely public, so this takes the chunks of existing public
sample logs and repeats them until the requested size is reached. Every event is genuine
Windows event data; only the repetition is synthetic.

Usage:
    scripts/make-big-evtx.py OUTPUT.evtx --chunks 73000 BASE.evtx [EXTRA.evtx ...] [--extra-every 50]

BASE.evtx provides the file header and most chunks. Chunks from EXTRA files (e.g. attack
samples) are inserted once every --extra-every chunks so detections have work to do.

The benchmark in the README used:
    BASE  = samples/security.evtx from https://github.com/omerbenamram/evtx
    EXTRA = logs from https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES
"""

import argparse
import struct
import sys
import zlib

HEADER_BLOCK = 4096
CHUNK = 65536


def chunks_of(path):
    with open(path, "rb") as f:
        data = f.read()
    if data[:8] != b"ElfFile\0":
        sys.exit(f"{path}: not an EVTX file")
    block = struct.unpack_from("<H", data, 40)[0] or HEADER_BLOCK
    out = []
    for off in range(block, len(data) - CHUNK + 1, CHUNK):
        c = data[off:off + CHUNK]
        if c[:8] == b"ElfChnk\0":
            out.append(c)
    return data[:block], out


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("output")
    ap.add_argument("base")
    ap.add_argument("extra", nargs="*")
    ap.add_argument("--chunks", type=int, required=True, help="number of chunks to write")
    ap.add_argument("--extra-every", type=int, default=50)
    args = ap.parse_args()

    header, base = chunks_of(args.base)
    extra = [c for p in args.extra for c in chunks_of(p)[1]]
    if not base:
        sys.exit("base file has no chunks")

    header = bytearray(header)
    n = args.chunks
    # File header: first/last chunk number, next record id, chunk count (u16, capped), flags.
    struct.pack_into("<QQ", header, 8, 0, n - 1)
    struct.pack_into("<H", header, 42, min(n, 0xFFFF))
    struct.pack_into("<I", header, 120, 0)  # clear "dirty"/"full" flags
    struct.pack_into("<I", header, 124, zlib.crc32(bytes(header[:120])) & 0xFFFFFFFF)

    with open(args.output, "wb") as out:
        out.write(header)
        bi = ei = 0
        for i in range(n):
            if extra and args.extra_every and i % args.extra_every == args.extra_every - 1:
                out.write(extra[ei % len(extra)])
                ei += 1
            else:
                out.write(base[bi % len(base)])
                bi += 1
    print(f"wrote {args.output}: {n} chunks ({n * CHUNK / 1e9:.2f} GB), {ei} attack-sample chunks")


if __name__ == "__main__":
    main()
