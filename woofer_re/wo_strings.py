#!/usr/bin/env python3
"""wo_strings.py — string map for Woofer_unpacked.exe (x86, ImageBase 0x400000).
Outputs JSON: {va_hex: {"text":..., "enc":"asc"|"u16", "sec":..., "foff":...}}
"""
import json, re, struct, sys

PATH = "Woofer_unpacked.exe"
IB = 0x400000
SECS = [  # (name, va, vsize, raw, rsize)
    (".code", 0x1000, 0x387e, 0x400, 0x3a00),
    (".text", 0x5000, 0xd962, 0x3e00, 0xda00),
    (".rdata", 0x13000, 0x33a5, 0x11800, 0x3400),
    (".data", 0x17000, 0x178c, 0x14c00, 0x1200),
    (".rsrc", 0x19000, 0xd244, 0x15e00, 0xd400),
]

def main():
    data = open(PATH, "rb").read()
    out = {}
    # ASCII
    for m in re.finditer(rb"[\x20-\x7e]{6,}", data):
        foff = m.start()
        for nm, v, vs, r, rs in SECS:
            if r <= foff < r + rs:
                va = IB + (v + (foff - r))
                t = m.group().decode()
                out[hex(va)] = {"text": t, "enc": "asc", "sec": nm}
                break
    # UTF-16LE
    txt16 = data.decode("utf-16-le", "ignore")
    for m in re.finditer(r"[\u0020-\u007e]{6,}", txt16):
        foff = m.start() * 2
        for nm, v, vs, r, rs in SECS:
            if r <= foff < r + rs:
                va = IB + (v + (foff - r))
                out[hex(va)] = {"text": m.group(), "enc": "u16", "sec": nm}
                break
    out = dict(sorted(out.items(), key=lambda kv: int(kv[0], 16)))
    if len(sys.argv) > 1:
        pat = sys.argv[1].lower()
        out = {k: v for k, v in out.items() if pat in v["text"].lower()}
    json.dump(out, open("wo_strings.json", "w"), indent=0)
    for k, v in out.items():
        print(f"{k}  [{v['sec']}/{v['enc']}]  {v['text'][:100]}")
    print(f"total: {len(out)}", file=sys.stderr)

if __name__ == "__main__":
    main()
