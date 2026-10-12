#!/usr/bin/env python3
"""Function boundary detection for CSX.exe .text (heuristic, MSVC x86)."""
import struct, json, sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

D = open('CSX.exe', 'rb').read()
BASE = 0x400000
off0 = struct.unpack_from('<I', D, 0x3C)[0]
NSEC = struct.unpack_from('<H', D, off0 + 6)[0]
SZOPT = struct.unpack_from('<H', D, off0 + 20)[0]
SECTS = []
p = off0 + 24 + SZOPT
for i in range(NSEC):
    name = D[p + i*40:p + i*40 + 8].rstrip(b'\0').decode(errors='replace')
    vsize, vaddr, rawsz, rawptr = struct.unpack_from('<IIII', D, p + i*40 + 8)
    SECTS.append(dict(name=name, vaddr=vaddr, vsize=vsize, rawsz=rawsz, rawptr=rawptr))
    p += 40
TEXT = SECTS[0]
TEXT_VA = BASE + TEXT['vaddr']
buf = D[TEXT['rawptr']:TEXT['rawptr'] + TEXT['rawsz']]
md = Cs(CS_ARCH_X86, CS_MODE_32)
INSTRS = list(md.disasm(buf, TEXT_VA))

def va2off(va):
    rva = va - BASE
    for s in SECTS:
        if s['vaddr'] <= rva < s['vaddr'] + max(s['vsize'], s['rawsz']):
            return s['rawptr'] + (rva - s['vaddr'])
    return None

targets = set()
rets = {}  # va of ret -> addr after ret
for ins in INSTRS:
    b = ins.bytes
    if b[0] in (0xE8,):
        rel, = struct.unpack_from('<i', b, 1)
        t = ins.address + ins.size + rel
        if TEXT_VA <= t < TEXT_VA + len(buf):
            targets.add(t)
    elif b[0] == 0xE9:
        rel, = struct.unpack_from('<i', b, 1)
        t = ins.address + ins.size + rel
        if TEXT_VA <= t < TEXT_VA + len(buf):
            targets.add(t)
    elif b[0] == 0xC3 or b[0] == 0xC2 or (b[0] == 0xC9):
        rets[ins.address] = ins.address + ins.size
    elif b[0] in (0xFF,) and b[1] in (0x15, 0x10, 0x12, 0x13, 0xD5, 0xD1, 0xD2, 0xD3):
        v, = struct.unpack_from('<I', b, 2) if b[1] == 0x15 else (0,)
        if b[1] == 0x15 and TEXT_VA <= v < TEXT_VA + len(buf):
            targets.add(v)

cands = sorted(set([TEXT_VA] + list(targets) + [0x422052]))
starts = set()
for c in cands:
    o = va2off(c)
    prev = buf[o - 1]
    # function starts: after ret / int3 / nop / end of prev instr
    if c == TEXT_VA or prev in (0xC3, 0xCC, 0x90, 0xEB) or (prev == 0xC2 and buf[o-2] in (0,4,8)):
        starts.add(c)
    else:
        # target landing inside a call-relative chain: still keep if 16-byte aligned? keep all call targets
        starts.add(c)
starts = sorted(starts)
# merge: drop a start if another start is within 0..7 bytes before it (thunk chains)
merged = []
for s in starts:
    if merged and s - merged[-1] <= 0:
        continue
    merged.append(s)
starts = merged

def func_of(va):
    best = None
    for s in starts:
        if s <= va:
            best = s
        else:
            break
    return best

funcs = {}
for i, s in enumerate(starts):
    e = starts[i+1] if i + 1 < len(starts) else TEXT_VA + len(buf)
    if e - s <= 0x80000:
        funcs[s] = (s, e)

json.dump({hex(k): [hex(v[0]), hex(v[1])] for k, v in funcs.items()}, open('csx_funcs.json', 'w'), indent=0)
print(f'{len(starts)} candidate starts, {len(funcs)} funcs')
# which funcs cover the interesting refs
refs = json.load(open('csx_str_xrefs.json'))
want = ['Resetting MTA serial', 'resetting MTA serial', 'Serial reset complete',
        'MachineGuid', 'Win32_VideoController', 'Win32_BaseBoard', 'Win32_DiskDrive',
        'Win32_ComputerSystem', 'Win32_BIOS', 'dxdiag_cache', 'audio_cache', 'cache.dat',
        'ipify', 'ip-api', 'csxprobe', '.banned', '/api/heartbeat', '/api/event',
        'LoadLibrary inject', 'direct injection', 'rescue injection', 'agent mapped and ready',
        'agent bootstrap', 'version.dll', 'DARKANARCHY', 'SSO_RND', 'Cryptography']
seen = set()
for r in refs:
    if any(w.lower() in r['text'].lower() for w in want):
        for ref in r['refs']:
            f = func_of(int(ref, 16))
            key = (f, r['text'][:40])
            if key not in seen:
                seen.add(key)
                print(f"func {f:#010x}..{funcs[f][1]:#010x}  <- ref {ref}  [{r['text'][:60]}]")
