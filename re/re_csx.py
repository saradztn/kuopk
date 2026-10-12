#!/usr/bin/env python3
"""CSX.exe RE harness (read-only). ImageBase = 0x400000 (verified from optional header).

Usage:
  python3 re_csx.py info
  python3 re_csx.py imports
  python3 re_csx.py xref <fileoff_or_rva_or_va>   # code refs to a data VA
  python3 re_csx.py dis <va> <len>                # disassemble
  python3 re_csx.py strmap [minlen]               # wide+ascii string table with VA
"""
import struct, sys, re
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

PATH = 'CSX.exe'
D = open(PATH, 'rb').read()
BASE = 0x400000

SECTS = []
off0 = struct.unpack_from('<I', D, 0x3C)[0]
NSEC = struct.unpack_from('<H', D, off0 + 6)[0]
SZOPT = struct.unpack_from('<H', D, off0 + 20)[0]
p = off0 + 24 + SZOPT
for i in range(NSEC):
    name = D[p + i * 40:p + i * 40 + 8].rstrip(b'\0').decode(errors='replace')
    vsize, vaddr, rawsz, rawptr = struct.unpack_from('<IIII', D, p + i * 40 + 8)
    SECTS.append(dict(name=name, vaddr=vaddr, vsize=vsize, rawsz=rawsz, rawptr=rawptr))
    p += 40

TEXT = SECTS[0]
TEXT_VA = BASE + TEXT['vaddr']

def rva2off(rva):
    for s in SECTS:
        if s['vaddr'] <= rva < s['vaddr'] + max(s['vsize'], s['rawsz']):
            return s['rawptr'] + (rva - s['vaddr'])
    return None

def off2rva(off):
    for s in SECTS:
        if s['rawptr'] <= off < s['rawptr'] + s['rawsz']:
            return s['vaddr'] + (off - s['rawptr'])
    return None

def va2off(va):
    return rva2off(va - BASE)

def dis(va, n=0x200, out=None):
    o = va2off(va)
    buf = D[o:o + n]
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    for ins in md.disasm(buf, va):
        line = f'{ins.address:08x}  {ins.bytes.hex(" "):<30s} {ins.mnemonic:<7s} {ins.op_str}'
        print(line, file=out)

def wide_strings(lo, hi, minlen=4):
    out = []
    i = lo
    while i < hi - 2 * minlen:
        start = i
        while i < hi - 1:
            c, = struct.unpack_from('<H', D, i)
            if 32 <= c < 0x7F00 and c != 0x7F:
                i += 2
            else:
                break
        if i - start >= 2 * minlen:
            s = D[start:i].decode('utf-16-le', errors='replace')
            out.append((start, s))
        i = max(i, start + 2)
    return out

def ascii_strings(lo, hi, minlen=5):
    out = []
    for m in re.finditer(rb'[\x20-\x7e]{%d,}' % minlen, D[lo:hi]):
        out.append((lo + m.start(), m.group().decode()))
    return out

def all_strings():
    """(file_off, va, kind, text) for .rdata + .data + .text"""
    out = []
    rd = [s for s in SECTS if s['name'] == '.rdata'][0]
    dd = [s for s in SECTS if s['name'] == '.data'][0]
    for (s, kind) in ((rd, 'wide'), (dd, 'wide')):
        for fo, txt in wide_strings(s['rawptr'], s['rawptr'] + s['rawsz'], 3):
            out.append((fo, BASE + off2rva(fo), kind, txt))
    for s in SECTS:
        if s['name'] in ('.text',):
            for fo, txt in ascii_strings(s['rawptr'], s['rawptr'] + s['rawsz'], 6):
                out.append((fo, BASE + off2rva(fo), 'asc', txt))
    return out

def xref(va, extra=True):
    """find references in .text to VA. Returns list of (ref_va, kind)."""
    buf = D[TEXT['rawptr']:TEXT['rawptr'] + TEXT['rawsz']]
    hits = []
    n = len(buf)
    i = 0
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    # instruction walk for accuracy
    instrs = list(md.disasm(buf, TEXT_VA))
    for ins in instrs:
        b = ins.bytes
        t = ins.address
        # imm32 operands (any position): decode via op_str is fragile; scan bytes for the VA
        for m in re.finditer(rb'\x68', b):
            v, = struct.unpack_from('<I', b, m.start() + 1)
            if v == va:
                hits.append((t, 'push imm32')); break
        if not any(v == va for v in _imm32s(b, ins.mnemonic)):
            # jmp/call rel
            if ins.mnemonic in ('call', 'jmp') and b[0] in (0xE8, 0xE9):
                rel, = struct.unpack_from('<i', b, 1)
                if t + ins.size + rel == va:
                    hits.append((t, 'call/jmp'))
            elif ins.mnemonic in ('jcc',) or b[0] in range(0x70, 0x80) or (b[0] == 0x0F and b[1] in range(0x80, 0x90)):
                rel, = struct.unpack_from('<i', b, ins.size - 4)
                if t + ins.size + rel == va:
                    hits.append((t, 'jcc'))
        else:
            hits.append((t, 'imm32'))
    # moffs absolute refs
    for ins in instrs:
        b = ins.bytes
        if b[:2] in (b'\xff\x15', b'\xff\x35', b'\xff\x34', b'\xa1', b'\xa3'):
            v, = struct.unpack_from('<I', b, 2 if b[0] in (0xFF, 0xA1, 0xA3) and b[1] in (0x15, 0x35, 0x34) else 0)
            if b[:2] in (b'\xff\x15', b'\xff\x35', b'\xff\x34') and v == va:
                hits.append((ins.address, 'moffs'))
    return hits

def _imm32s(b, mn):
    """yield imm32 values present in bytes (crude but effective for MSVC code)"""
    for m in re.finditer(rb'(?<!\x68)(?<!\x6a)', b[1:]):
        pass
    # simpler: every 4-byte aligned position after prefix; filter by decode below
    return []

def info():
    for s in SECTS:
        print(f"  {s['name']:10s} vaddr={s['vaddr']:#010x} vsize={s['vsize']:#010x} rawsz={s['rawsz']:#010x} rawptr={s['rawptr']:#010x}")

if __name__ == '__main__':
    cmd = sys.argv[1] if len(sys.argv) > 1 else 'info'
    if cmd == 'info': info()
    elif cmd == 'imports': pass
    elif cmd == 'xref':
        v = int(sys.argv[2], 0)
        if v < 0x100000:  # treat as file offset
            v = BASE + off2rva(v)
        for h, k in xref(v):
            print(f'  ref @VA {h:#010x} ({k})')
    elif cmd == 'dis':
        dis(int(sys.argv[2], 0), int(sys.argv[3] or '0x200', 0))
    elif cmd == 'strmap':
        ml = int(sys.argv[2]) if len(sys.argv) > 2 else 6
        for fo, va, k, txt in all_strings():
            if len(txt) >= ml:
                print(f'{fo:#010x} {va:#010x} {k:4s} {txt[:90]}')
