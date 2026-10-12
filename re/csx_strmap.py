#!/usr/bin/env python3
"""Build string table + xrefs for CSX.exe, then map functions from refs."""
import struct, re, json
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

def off2rva(off):
    for s in SECTS:
        if s['rawptr'] <= off < s['rawptr'] + s['rawsz']:
            return s['vaddr'] + (off - s['rawptr'])
    return None

TEXT = SECTS[0]
TEXT_VA = BASE + TEXT['vaddr']
buf = D[TEXT['rawptr']:TEXT['rawptr'] + TEXT['rawsz']]
md = Cs(CS_ARCH_X86, CS_MODE_32)
INSTRS = list(md.disasm(buf, TEXT_VA))
print(f'{len(INSTRS)} instructions in .text', file=__import__('sys').stderr)

def wide_strings(lo, hi, minlen=3):
    out = []
    i = lo
    while i < hi - 2*minlen:
        start = i
        while i < hi - 1:
            c, = struct.unpack_from('<H', D, i)
            if 32 <= c < 0x7F00 and c != 0x7F:
                i += 2
            else:
                break
        if i - start >= 2*minlen:
            out.append((start, D[start:i].decode('utf-16-le', errors='replace')))
        i = max(i, start + 2)
    return out

strings = []  # (fileoff, va, kind, text)
for s in SECTS:
    if s['name'] in ('.rdata', '.data'):
        for fo, txt in wide_strings(s['rawptr'], s['rawptr'] + s['rawsz'], 3):
            strings.append((fo, BASE + off2rva(fo), s['name'], 'wide', txt))
for s in SECTS:
    if s['name'] == '.text':
        for m in re.finditer(rb'[\x20-\x7e]{5,}', D[s['rawptr']:s['rawptr']+s['rawsz']]):
            fo = s['rawptr'] + m.start()
            strings.append((fo, BASE + off2rva(fo), s['name'], 'asc', m.group().decode()))

# xref scan: for each string VA, find instrs containing it as imm32/rel target
pat_bytes = {}
def find_refs(va):
    hits = []
    b4 = struct.pack('<I', va)
    for ins in INSTRS:
        b = ins.bytes
        if b4 in b:
            hits.append(ins.address)
            continue
        if ins.mnemonic in ('call', 'jmp') and len(b) >= 5 and b[0] in (0xE8, 0xE9):
            rel, = struct.unpack_from('<i', b, 1)
            if ins.address + ins.size + rel == va:
                hits.append(ins.address)
        elif (b[0] in range(0x70, 0x80) or (b[0] == 0x0F and b[1] in range(0x80, 0x90))) and len(b) >= 6:
            rel, = struct.unpack_from('<i', b, len(b) - 4)
            if ins.address + ins.size + rel == va:
                hits.append(ins.address)
    return hits

refs = {}
for fo, va, sect, kind, txt in strings:
    r = find_refs(va)
    if r:
        refs[va] = (fo, sect, kind, txt, r)

out = []
for va in sorted(refs):
    fo, sect, kind, txt, r = refs[va]
    out.append(dict(va=hex(va), fileoff=hex(fo), kind=kind, text=txt, refs=[hex(x) for x in r]))
json.dump(out, open('csx_str_xrefs.json', 'w'), indent=1)
print(f'{len(out)} referenced strings written to csx_str_xrefs.json')
for o in out:
    t = o['text']
    if any(k in t for k in ['serial', 'Serial', 'MachineGuid', 'Win32_', 'WQL', 'Cryptography',
                            'cache', 'csxprobe', 'banned', 'Banned', 'api/', 'github', 'jsdelivr',
                            'version', 'dxdiag', 'audio', 'agent', 'Agent', 'CSX', 'DARK',
                            'INSERT', 'inject', 'Inject', 'mta', 'MTA', 'Thief', 'thief',
                            'probe', 'tsclient', 'vbox', 'vmware', 'ipify', 'ip-api',
                            'heartbeat', 'event', 'discord', 'CredDelete', 'Reg', 'probe']):
        print(f"{o['va']}  refs={','.join(o['refs'])[-40:]:40s} {t[:80]}")
