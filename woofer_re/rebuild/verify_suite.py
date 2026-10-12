#!/usr/bin/env python3
"""
Triple-verification of the rebuilt Woofer suite (static only — zero execution).

Check (a) PRESENCE  : every RE-cited VA/file-offset in the rebuilt artifact holds
                      exactly the same bytes as in the original (bytes shown).
Check (b) MEANING   : the cited bytes are re-disassembled from the REBUILT file and
                      the instruction stream matches the original disassembly dumps
                      (per-function for spoofysig.sys; spot functions for the rest).
Check (c) LOADABLE  : the rebuilt PE containers parse as valid PEs — headers, section
                      table, IAT/imports resolve, .pdata unwind tables, certificate
                      table — as a loader would walk them. (Parse-level only.)

Every expected value below is itself re-read from the original sample bytes first
(double-read: original -> rebuilt), so the check is self-evidencing.
"""
import hashlib, io, json, os, struct

HERE = os.path.dirname(os.path.abspath(__file__))
SRC  = os.path.dirname(HERE)
OUT  = os.path.join(HERE, "out")
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64

def sha(b): return hashlib.sha256(b).hexdigest()

results = {"checks": [], "pass_count": 0, "fail_count": 0}
def rec(name, ok, detail):
    results["checks"].append({"check": name, "ok": bool(ok), "detail": detail})
    results["pass_count" if ok else "fail_count"] += 1
    print("%s  %s  %s" % ("PASS" if ok else "FAIL", name, detail[:220]))

def load(base, nm):
    return io.open(os.path.join(base, nm), "rb").read()

def rva2file(raw, rva, ib):
    for s in pefile.PE(data=raw, fast_load=True).sections:
        if s.VirtualAddress <= rva - ib < s.VirtualAddress + s.Misc_VirtualSize:
            return s.PointerToRawData + (rva - ib - s.VirtualAddress)
    return None

def region(src_raw, out_raw, off, ln, tag):
    """Presence + meaning substrate: bytes equal at file offset."""
    a, b = src_raw[off:off+ln], out_raw[off:off+ln]
    ok = (a == b and ln > 0)
    rec("presence: %s @0x%x (%d B)" % (tag, off, ln), ok,
        "orig %s…  rebuilt %s…" % (a[:16].hex(), b[:16].hex()))
    return a

# ============================================================ spoofysig.sys
sys_s = load(SRC, "spoofysig.sys"); sys_o = load(OUT, "spoofysig.sys")
rec("size: spoofysig.sys", len(sys_s) == len(sys_o),
    "src %d vs out %d" % (len(sys_s), len(sys_o)))
rec("sha256: spoofysig.sys full file", sha(sys_s) == sha(sys_o), sha(sys_s))

pe = pefile.PE(data=sys_s, fast_load=True); pe.parse_data_directories()
IB = pe.OPTIONAL_HEADER.ImageBase
def sysfile(rva): return rva2file(sys_s, IB + rva, IB)

checks = {
  "DriverEntry (RVA 0x1530)": 0x1530,
  "hook assert int 0x2C region (RVA 0x1560..0x15c0)": 0x1560,
  "MT19937-64 twist magic (fn RVA 0x1e40)": 0x1e40,
  "FNV1a64 basis fn (RVA 0x2150)": 0x2150,
  "FNV1a64 prime fn (RVA 0x2120)": 0x2120,
  "Randomizing subserial fn (RVA 0x2370)": 0x2370,
  "uniform_int_distribution fn (RVA 0x17d0)": 0x17d0,
  "completed_smart handler (RVA 0x10f0)": 0x10f0,
  "completed_storage_query handler (RVA 0x1220)": 0x1220,
  "init / ObReferenceObjectByName hook (RVA 0x1000)": 0x1000,
}
for tag, rva in checks.items():
    region(sys_s, sys_o, sysfile(rva), 32, tag)
# string checks
ddk = b"\x5c\x00D\x00i\x00s\x00k\x00"
off_drvdisk = sys_s.find(ddk)
rec("string: \\Driver\\Disk (UTF-16) present at same offset",
    off_drvdisk != -1 and sys_o.find(ddk) == off_drvdisk,
    "offset 0x%x" % off_drvdisk)
for s in [b"hwid.pdb", b"WDKTestCert"]:
    o1, o2 = sys_s.find(s), sys_o.find(s)
    rec("string: %r at same offset" % s, o1 != -1 and o1 == o2, "offset 0x%x" % o1)
# .pdata unwind count from the REBUILT file
peo = pefile.PE(data=sys_o, fast_load=True); peo.parse_data_directories()
U16=lambda o: struct.unpack_from("<H",sys_o,o)[0]
U32=lambda o: struct.unpack_from("<I",sys_o,o)[0]
e_lf=U32(0x3c); opt=e_lf+24
pd_rva = U32(opt+0x88)   # .pdata = EXCEPTION dir (index 3), PE32+
pd_sz  = U32(opt+0x88+4)
n_unw = pd_sz // 24
rec(".pdata: rebuilt parses, %d unwind entries" % n_unw, n_unw == 19,
    "rva 0x%x size 0x%x" % (pd_rva, pd_sz))
# certificate table
sec_rva = U32(opt+0x90)   # SECURITY dir (index 4), PE32+
sec_sz  = U32(opt+0x90+4)
cert = sys_o[sec_rva:sec_rva + sec_sz] if sec_sz else b""
rec("certificate: rebuilt keeps cert table (%d B) with WDKTestCert" % sec_sz,
    b"WDKTestCert" in cert, "rva/off 0x%x" % sec_rva)
# (b) meaning: re-disassemble the REBUILT file over every original function range
# and compare instruction-by-instruction with the original dump (same base addrs,
# so RIP-relative targets compare equal too).
def disasm_range(raw, fileoff, size, base, mode):
    md = Cs(CS_ARCH_X86, mode); md.detail = False
    return [(i.mnemonic, i.op_str) for i in md.disasm(raw[fileoff:fileoff+size], base)]
orig_dump = io.open(os.path.join(SRC, "dis_spoofysig_full.txt"),
                    encoding="utf-8", errors="replace").read().splitlines()
funcs = []   # (rva, nbytes, [(va, "mnemonic operands")])
cur = None
for l in orig_dump:
    m = l.strip()
    if m.startswith("===== FUNC @RVA"):
        rva = int(m.split("0x")[1].split()[0], 16)
        nbt = int(m.split("(")[1].split(" ")[0])
        cur = (rva, nbt, [])
        funcs.append(cur)
    elif ":" in m and cur is not None:
        va, rest = m.split(":", 1)
        if all(c in "0123456789abcdef" for c in va.strip()):
            cur[2].append((va.strip(), rest.strip()))
tot = mismatch = 0
for rva, nbt, lines in funcs:
    fo = sysfile(rva)
    rebuilt = disasm_range(sys_o, fo, nbt, IB + rva, CS_MODE_64)
    tot += len(lines)
    for (va, ops), rb in zip(lines, rebuilt):
        # normalize: collapse whitespace; capstone versions format REP-prefix
        # mnemonics differently ("rep" + "movsb …" vs "rep movsb" + "…") — same bytes.
        om = " ".join(ops.split())
        ob = " ".join((rb[0] + " " + rb[1]).split())
        if om != ob:
            mismatch += 1
            if mismatch < 4:
                rec("meaning: instr mismatch @%s" % va, False,
                    "orig=%r rebuilt=%r" % (om, ob))
rec("meaning: spoofysig.sys all %d functions re-disassembled from rebuilt file "
    "match original dump" % len(funcs), mismatch == 0,
    "%d instructions compared, %d mismatches" % (tot, mismatch))

# ============================================================ spoofysig.exe
exe_s = load(SRC, "spoofysig.exe"); exe_o = load(OUT, "spoofysig.exe")
rec("size: spoofysig.exe", len(exe_s) == len(exe_o), "src %d vs out %d" % (len(exe_s), len(exe_o)))
rec("sha256: spoofysig.exe full file", sha(exe_s) == sha(exe_o), sha(exe_s))
def u16(s): return s.encode("utf-16-le")
str_checks = [
    (b"kdmapper.pdb", "kdmapper PDB path (ASCII)"),
    (u16("iQVW64.SYS"), "embedded Intel NAL iQVW64.SYS (UTF-16)"),
    (u16("MmUnloadedDrivers"), "anti-forensics: MmUnloadedDrivers (UTF-16)"),
    (b"PiDDBCacheTable", "anti-forensics: PiDDBCacheTable (ASCII)"),
    (u16("g_KernelHashBucketList"), "anti-forensics: g_KernelHashBucketList (UTF-16)"),
    (u16("Calling DriverEntry"), "kdmapper: Calling DriverEntry (UTF-16)"),
    (u16("not 64 bit"), "kdmapper PE check (UTF-16)"),
    (u16("Vul driver data destroyed"), "NAL unlink (UTF-16)"),
    (u16("Intel(R) Network Adapter Diagnostic Driver"), "NAL product name (UTF-16)"),
]
for s, tag in str_checks:
    o1, o2 = exe_s.find(s), exe_o.find(s)
    rec("string: %s at same offset" % tag, o1 != -1 and o1 == o2, "offset 0x%x" % o1)
pe2 = pefile.PE(data=exe_s, fast_load=True); pe2.parse_data_directories()
entry2 = pe2.OPTIONAL_HEADER.AddressOfEntryPoint
off = rva2file(exe_s, pe2.OPTIONAL_HEADER.ImageBase + entry2, pe2.OPTIONAL_HEADER.ImageBase)
region(exe_s, exe_o, off, 24, "spoofysig.exe entry @RVA 0x%x" % entry2)

# ============================================================ Woofer.exe
woo_s = load(SRC, "Woofer_unpacked.exe"); woo_o = load(OUT, "Woofer.exe")
woo_o_pe = pefile.PE(data=woo_o)
rec("size: Woofer (unpacked image)", len(woo_s) == len(woo_o),
    "src %d vs out %d" % (len(woo_s), len(woo_o)))
rec("sha256: Woofer (unpacked image) full file", sha(woo_s) == sha(woo_o), sha(woo_s))
pe3 = pefile.PE(data=woo_s, fast_load=True); pe3.parse_data_directories()
IB3 = pe3.OPTIONAL_HEADER.ImageBase
woo_checks = {
  "entry/CRT bootstrap @VA 0x401000": 0x401000,
  "RC4 decryptor (KSA+PRGA) @VA 0x4011ef": 0x4011ef,
  "key-material setup call @VA 0x4010be": 0x4010be,
  "main hex-decrypt body @VA 0x403f53": 0x403f53,
  "resource extraction loop @VA 0x4026c7": 0x4026c7,
  "thunk jmp [IAT] @VA 0x40509a (WriteFile slot 0x4174cc)": 0x40509a,
  "embedded entropy blob @VA 0x417080": 0x417080,
  "PRNG seed 0x06D53B7F @VA 0x41707c": 0x41707c,
  "IAT head (memset slot) @VA 0x417470": 0x417470,
  "charset 0123456789abcdefK @VA 0x4136f8": 0x4136f8,
  "zlib 1.2.11 banner @VA 0x4161d0": 0x4161d0,
}
for tag, va in woo_checks.items():
    region(woo_s, woo_o, rva2file(woo_s, va, IB3), 24, tag)
# RCDATA payload head at raw 0x192ac
region(woo_s, woo_o, 0x192ac, 32, "RCDATA encrypted payload head (file 0x192ac)")
# special: thunk bytes must be FF 25 CC 74 41 00
tb = woo_o[rva2file(woo_o, 0x40509a, IB3):rva2file(woo_o, 0x40509a, IB3)+6]
rec("meaning: thunk @0x40509a is 'jmp [0x4174cc]'", tb == b"\xff\x25\xcc\x74\x41\x00", tb.hex())
# MSVCRT IAT[0] @0x417470: this binary stores (INT-entry - 2) in the IAT — a
# property of the ORIGINAL bytes (UPX-unpack artifact); loader name lookup still
# resolves "memset". Check exact value + resolved name on the rebuilt file.
iat0 = struct.unpack_from("<I", woo_o, rva2file(woo_o, 0x417470, IB3))[0]
iat0s = struct.unpack_from("<I", woo_s, rva2file(woo_s, 0x417470, IB3))[0]
resolved = None
for d in woo_o_pe.DIRECTORY_ENTRY_IMPORT:
    for n in d.imports:
        if n.address == 0x417470:
            resolved = d.dll.decode() + "!" + (n.name.decode() if n.name else "?")
rec("meaning: MSVCRT IAT[0] @0x417470 value %s == original and resolves to %s"
    % (hex(iat0), resolved), iat0 == iat0s == 0x176ac and resolved == "MSVCRT.dll!memset",
    "rebuilt=%s original=%s" % (hex(iat0), hex(iat0s)))
# imports of the REBUILT Woofer
nimp = sum(len(d.imports) for d in woo_o_pe.DIRECTORY_ENTRY_IMPORT)
rec("loadable: rebuilt Woofer imports resolve", nimp > 100, "%d imported symbols" % nimp)
names = set()
for d in woo_o_pe.DIRECTORY_ENTRY_IMPORT:
    for n in d.imports:
        if n.name: names.add(n.name.decode())
for must in ["CreateProcessW", "ShellExecuteExW", "LoadLibraryExW", "FindResourceW",
             "GetTempFileNameW", "WriteFile", "MessageBoxW"]:
    rec("loadable: rebuilt Woofer imports %s" % must, must in names, "")
# (b) meaning: re-disassemble rebuilt entry + RC4 from the rebuilt file
def disasm_lines(raw, fileoff, size, base, mode):
    md = Cs(CS_ARCH_X86, mode); md.detail = False
    return [str(i) for i in md.disasm(raw[fileoff:fileoff+size], base)]
off_e = rva2file(woo_o, 0x401000, IB3)
dis_e = disasm_lines(woo_o, off_e, 0x200, IB3 + 0x1000, CS_MODE_32)
first = dis_e[0]
rec("meaning: rebuilt entry disassembles to 'push 0xac' (CRT bootstrap)",
    "push" in first and "0xac" in first, first)
rc4off = rva2file(woo_o, 0x4011ef, IB3)
dis_r = disasm_lines(woo_o, rc4off, 0x40, IB3 + 0x11ef, CS_MODE_32)
rec("meaning: rebuilt RC4 fn starts 'push ebp/push ebx/push edi'",
    any("push" in l and "ebp" in l for l in dis_r[:3]), " | ".join(dis_r[:3]))

# ============================================================ data files
for nm in ("hwid.ps1", "mac.txt", "host.txt"):
    a = load(SRC, nm); b = load(OUT, nm)
    rec("sha256: %s" % nm, sha(a) == sha(b), sha(a))

json.dump(results, io.open(os.path.join(HERE, "verify_results.json"), "w"), indent=1)
print("\n== %d PASS / %d FAIL ==" % (results["pass_count"], results["fail_count"]))
assert results["fail_count"] == 0, "verification failures — see above"
print("ALL CHECKS PASSED")
