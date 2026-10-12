#!/usr/bin/env python3
"""
verify_counter.py — static verification of the built woofer_counter exes.
ZERO execution: pure PE byte analysis.

Checks (triple-verification style):
  1. PE structure  — machine, subsystem=console, entry point, sections
  2. Imports       — required DLLs + key API functions present in IAT
  3. Fingerprints  — all 8 suite SHA-256s, NAL service name, MAC pool,
                     hostname pool, registry keys, device paths embedded
"""
import struct, sys, hashlib, os

HERE = os.path.dirname(os.path.abspath(__file__))
KNOWN = [
    "e5d4272a1aa7b9c3130c89ef7108e93a89235bd63a25601a0e2fb6bd91b391d6",  # Woofer.exe (packed)
    "fc5a27ec16eade55a9a3873a791a2eb0e6832b8d9c0005e83f259f0fcfce7d48",  # Woofer.exe (unpacked image)
    "30ff2e1026e6a6f8c46f8259a1d897735e240fd4ffee6758266929d6a3361fc9",  # spoofysig.exe
    "93a516ebdd6bb1fe9dc5951b21fbacdff660997548bbb3df57dba92417caa33d",  # spoofysig.sys
    "4429f32db1cc70567919d7d47b844a91cf1329a6cd116f582305f3b7b60cd60b",  # iQVW64.SYS (embedded NAL)
    "c7c54526b07f457e58d423ab22d61a0efd78ad112be2ef0a1efe6c25013df185",  # hwid.ps1
    "e53a19f0f36d7e7be98522239e8ac2af3248f4fe4b046d9fe270e3907ce11401",  # mac.txt
    "e2c24bcc964b30112eee56d9baacccb05a63dadc5d437d3b9c6c304e71167068b",  # host.txt
]
WIDE = lambda s: s.encode("utf-16-le")
# Note: zig's mingw maps the base CryptoAPI functions (CryptAcquireContextW,
# CryptCreateHash, CryptHashData, CryptGetHashParam, CryptReleaseContext) to
# ADVAPI32.dll — correct on real Windows: these exports live in advapi32.dll
# (classic CryptoAPI home) on every Windows version.
REQUIRED_DLLS = {"advapi32.dll", "iphlpapi.dll", "user32.dll",
                 "shell32.dll", "kernel32.dll"}
REQUIRED_FUNCS = {
    "advapi32.dll": ["RegOpenKeyExW", "RegEnumKeyExW", "RegQueryValueExW",
                     "RegSetValueExW", "RegDeleteValueW", "OpenSCManagerW",
                     "OpenServiceW", "DeleteService", "ControlService",
                     "QueryServiceStatus",
                     "CryptAcquireContextW", "CryptCreateHash", "CryptHashData",
                     "CryptGetHashParam", "CryptReleaseContext"],
    "iphlpapi.dll": ["GetAdaptersInfo"],
    "user32.dll": ["ExitWindowsEx"],
    "shell32.dll": ["SHGetFolderPathW"],
    "kernel32.dll": ["CreateFileW", "DeviceIoControl", "TerminateProcess",
                     "GetVolumeInformationW", "GetComputerNameExW",
                     "SetComputerNameExW", "CreateProcessW", "GetModuleHandleW",
                     "GetProcAddress"],
}

def parse_pe(raw):
    assert raw[:2] == b"MZ"
    e = struct.unpack_from("<I", raw, 0x3c)[0]
    assert raw[e:e+4] == b"PE\0\0"
    machine = struct.unpack_from("<H", raw, e+4)[0]
    nsec    = struct.unpack_from("<H", raw, e+6)[0]
    szopt   = struct.unpack_from("<H", raw, e+20)[0]
    magic   = struct.unpack_from("<H", raw, e+24)[0]
    opt     = e + 24
    entry   = struct.unpack_from("<I", raw, opt+0x10)[0]
    subsys  = struct.unpack_from("<H", raw, opt+0x44)[0]
    sect    = opt + szopt
    secs = []
    for i in range(nsec):
        so = sect + 40*i
        nm = raw[so:so+8].rstrip(b"\0").decode("latin1")
        vs, va, rs, ro = struct.unpack_from("<IIII", raw, so+8)
        secs.append((nm, va, vs, ro, rs))
    dirs_start = opt + (0x70 if magic == 0x20b else 0x60)

    def r2o(rva):
        for nm, va, vs, ro, rs in secs:
            if va <= rva < va + max(vs, rs):
                return ro + (rva - va)
        return None

    imp_rva, imp_sz = struct.unpack_from("<II", raw, dirs_start+8)
    o = r2o(imp_rva)
    imports = {}   # dll -> [funcnames]
    if o is not None:
        i = 0
        while True:
            thunk, ts, fwd, nr, iat = struct.unpack_from("<IIIII", raw, o+i*20)
            if not (thunk or nr or iat):
                break
            no = r2o(nr)
            dll = raw[no:raw.index(b"\0", no)].decode("latin1").lower()
            tr = thunk if ts == 0 else iat
            to = r2o(tr)
            names = []
            if to is not None:
                # x64 MSVC/lld convention: IAT entries are 8-byte stride with a
                # zero DWORD between them (verified against the genuine Intel
                # iQVW64.SYS in woofer_re/ and MSVC-built x64 PEs).
                # x86: packed 4-byte stride.
                stride = 8 if magic == 0x20b else 4
                while to is not None and to+4 <= len(raw):
                    e2 = struct.unpack_from("<I", raw, to)[0]
                    if e2 == 0:
                        break
                    # lld (zig) convention: 2-byte hint + single-byte-NUL ASCII
                    # name, high bit not set (matches known-good zig builds)
                    nm2 = r2o(e2 & 0x7fffffff)
                    b = raw[nm2+2:]
                    names.append(b[:b.find(b"\0")].decode("latin1"))
                    to += stride
            imports[dll] = sorted(names)
            i += 1
    return machine, subsys, entry, secs, imports, raw

def main():
    allok = True
    for path, want_machine in [("bin/woofer_counter_x64.exe", 0x8664),
                               ("bin/woofer_counter_x86.exe", 0x14c)]:
        fp = os.path.join(HERE, path)
        raw = open(fp, "rb").read()
        machine, subsys, entry, secs, imports, _ = parse_pe(raw)
        R = []
        def ck(c, m): R.append((c, m))
        ck(machine == want_machine, f"machine {hex(machine)} (want {hex(want_machine)})")
        ck(subsys == 3, f"subsystem console (got {subsys})")
        ck(entry != 0, f"entry point {hex(entry)}")
        ck(set(imports) >= REQUIRED_DLLS, f"required DLLs present ({sorted(imports)})")
        for dll, funcs in REQUIRED_FUNCS.items():
            have = imports.get(dll, [])
            missing = [f for f in funcs if f not in have]
            ck(not missing, f"{dll}: {len(have)} funcs" + (f" MISSING {missing}" if missing else ""))
        ck(all(k.encode() in raw for k in KNOWN), "all 8 suite SHA-256s embedded")
        ck(b"iQVW64" in raw, "NAL service key name 'iQVW64'")
        ck(WIDE("ZaxaR-54Y5Y") in raw, "hostname pool embedded (ZaxaR-54Y5Y, utf-16)")
        ck(b"027C578AD6FB" in raw, "MAC pool embedded (027C578AD6FB)")
        ck(b"NetworkAddress" in raw, "registry value 'NetworkAddress'")
        ck(WIDE("{4d36e972-e325-11ce-bfc1-08002be10318}") in raw, "NIC class GUID key (utf-16)")
        ck(b"MachineGuid" in raw and b"HwProfileGuid" in raw, "GUID registry values")
        ck(WIDE("Cryptography") in raw and WIDE("IDConfigDB") in raw, "GUID registry paths (utf-16)")
        ck(WIDE("PhysicalDrive") in raw, "PhysicalDrive device path (utf-16)")
        ck(WIDE("Nal") in raw, "\\Device\\Nal (utf-16)")
        ck(WIDE("hwid.ps1") in raw, "hwid.ps1 process cmdline marker (utf-16)")
        ck(WIDE("woofer_backup.json") in raw, "backup file name (utf-16)")
        ok = all(c for c, _ in R)
        allok = allok and ok
        print(f"== {path} ({len(raw)} B, sha256 {hashlib.sha256(raw).hexdigest()[:16]}… ) ==")
        for c, m in R:
            print("  PASS" if c else "  FAIL", m)
        print("  OVERALL", "PASS" if ok else "FAIL", "\n")
    print("ALL", "PASS" if allok else "FAIL")
    return 0 if allok else 1

if __name__ == "__main__":
    sys.exit(main())
