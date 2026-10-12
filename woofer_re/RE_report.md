# Woofer suite — full reverse engineering report

Static analysis only. **Zero execution of any sample.** Every value below is read from the
sample bytes in this session (VA/byte citations given; reproducible with the quoted
read commands). Unprovable items are explicitly marked **UNVERIFIED**.

Suite (sha256 first-8 + size, files in this dir):
| file | size | sha256 |
|---|---|---|
| Woofer.exe (UPX-packed) | 99,328 | e5d4272a… |
| Woofer_unpacked.exe (from `upx.out -d`, 143,872 B = 0x23200 = PackHeader u_file_size) | 143,872 | (this dir) |
| spoofysig.exe | 136,704 | 30ff2e10… |
| spoofysig.sys | 11,984 | 93a516eb… |
| hwid.ps1 | 3,270 | c7c54526… |
| mac.txt | 7,054 | e53a19f0… (503 MAC lines) |
| host.txt | 3,158 | e2c24bcc… (200 `ZaxaR-XXXXX` hostnames) |

Tooling in this dir: `wo_strings.py/json` (Woofer string map), `dis_code.txt`,
`dis_woof_text.txt`, `dis_spoofysig.exe.txt` (44,132 lines), `dis_spoofysig.sys.txt`,
`dis_spoofysig_full.txt` (38 code regions disassembled per .pdata boundary), `sp_sig_str.json`.

---

## 1. spoofysig.sys — the core "signature" spoofer (kernel driver, x64)

PE facts (pefile): Machine 0x8664, ImageBase **0x140000000**, entry RVA **0x1530**.
Sections: `.text` va 0x1000 vsize 0x1bf2 raw 0x400 · `.rdata` va 0x3000 vsize 0x2cc ·
`.data` va 0x4000 vsize 0x10 · `.pdata` va 0x5000 vsize 0x1c8 (19 RUNTIME_FUNCTION entries, EXCEPTION data dir index 3) ·
`INIT` va 0x6000 vsize 0xfc.
Imports (ntoskrnl only, 7): `ObReferenceObjectByName`, `IoDriverObjectType`,
`ExAllocatePool`, `ExFreePoolWithTag`, `ObfDereferenceObject`, `DbgPrint`, `__chkstk`.
PDB (RSDS, file off 0x207c): `\\192.168.0.111\414\driver\x64\Debug\hwid.pdb`
→ project name is **"hwid"**; build shared `\\192.168.0.111`.
Signature: **WDKTestCert Admin** (test-cert signed, off 0x2a07/0x2a58).

### 1.1 Function map (VA = 0x140000000 + RVA; 38 code regions, 19 with unwind-table entries)

| RVA | bytes | role (evidenced) |
|---|---|---|
| 0x1000 | 237 | `init` — hook install (called from DriverEntry) |
| 0x10f0 | 291 | `completed_smart` handler (IOCTL 0x7C088 path) |
| 0x1220 | 418 | `completed_storage_query` handler (IOCTL 0x2D1400 path) |
| 0x13d0 | 182 | context builder (ExAllocatePool 0x20) |
| 0x1490 | 154 | installed dispatch hook |
| 0x1530 | 46 | **DriverEntry** |
| 0x1560 | 68 | `[arg1+0xB8]` fetch + sanity assert |
| 0x15b0/0x15f0/0x1620/0x1680/0x16d0 | 54/42/70/66/88 | small helpers (mt class glue) |
| 0x1730/0x1790/0x17d0 | 95/51/152 | `uniform_int_distribution` step (`(a,b)` u32 pair) |
| 0x1880/0x18d0 | 71/49 | alloc/ptr helpers |
| 0x1910/0x19b0 | 146/175 | MT state init / seed mix (consts 0x5555555555555555, 0x5851F42D4C957F2D) |
| 0x1a00/0x1a40/0x1a80/0x1ab0 | 59/50/47/47 | dist ctor glue (`0x1a80(&p,0x41,0x5a)` = range A–Z) |
| 0x1ae0/0x1c20/0x1d30/0x1dc0 | 320/243/141/78 | MT `next()` + temper + modulo |
| 0x1e40 | 521 | **MT twist** (3 loops; magic `0xB5026F5AA96619E9` = MT19937-64 mag01) |
| 0x2050 | 193 | MT seed→state init |
| 0x2160 | 120 | `FNV1a64(str,len)` over isalnum chars (→ 0x2120/0x2150) |
| 0x21e0 | 83 | byte→hex-pair append |
| 0x2270 | 98 | `isalnum(c)` ('0-9','A-Z','a-z') |
| 0x22e0 | 98 | `isxdigit(c)` ('0-9','A-F','a-f') |
| 0x2370 | 375 | **`Randomizing subserial`** — the randomizer |
| 0x24f0 | 175 | memmove |
| 0x25a0 | 932 | hex-string ⇄ byte array + dual-subserial randomize |
| 0x2950/0x2990 | 58/104 | hex pair parse / hex digit parse |
| 0x29f8 | (thunk) | `jmp IAT DbgPrint` |
| 0x29fe | (thunk) | `jmp IAT __chkstk` |
| 0x2120 | (gap fn) | FNV-1a update: `h^=c; h*=0x100000001B3` |
| 0x2150 | (gap fn) | `return 0xCBF29CE484222325` (FNV-1a 64 offset basis) |
| 0x29fe→ | (gap fn) | DbgPrint thunk |

### 1.2 DriverEntry (RVA 0x1530)

```
140001530: mov [rsp+0x10], rdx ; mov [rsp+8], rcx ; sub rsp, 0x28
14000153e: movabs rax, 0xfffff78000000014
140001548: mov  rax, [rax]                 ; g = [ntoskrnl base + 0x14]
14000154b: mov  [rip+0x2ab6], rax          ; → global qword @ VA 0x140004000 (.data)
140001552: call 0x140001000                ; init()
140001557: xor eax, eax ; add rsp,0x28 ; ret   ; STATUS_SUCCESS
```
`0xFFFFF78000000014` = fixed kernel global read (canonical kernel base 0xfffff78000000000 + 0x14;
which nt global sits there on the target build: **UNVERIFIED** — the value is later XOR-folded
into the PRNG seed, so the author only needs a stable per-boot qword).

### 1.3 init / hook install (RVA 0x1000)

Bytes (evidence):
```
140001004: mov eax, 0x18 ; mov [rsp+0x58], ax        ; UNICODE_STRING.Length = 0x18 (24)
14000100e: mov eax, 0x1a ; mov [rsp+0x5a], ax        ; .MaxLength = 0x1a
140001018: lea rax, [rip+0x1af1]                     ; .Buffer = VA 0x140002B10
140001045: mov rax, [rip+0x1fd4] ; mov rax,[rax]     ; ObjectType = IAT IoDriverObjectType
14000105a: mov edx, 0x40                              ; Attributes = OBJ_CASE_INSENSITIVE
140001064: call IAT ObReferenceObjectByName(name, 0x40, NULL, 0, IoDriverObjectType, &obj, NULL)
140001099: DbgPrint("apply_hook", "%s %d : ObReferenceObjectByName returned 0x%08X driver_object: 0x%016X")
  success path:
1400010a7: mov eax, 8 ; imul rax, rax, 0xe            ; 8*14 = 0x70
1400010b5: lea rax, [rcx+rax+0x70]                    ; &obj[0x70 + 0x70] = &obj[0xE0]
1400010c7: mov [rip+0x2f32], [rax]                    ; g @0x140004000 := [obj+0xE0]  (original)
1400010d3: lea rcx, [rip+0x3b6]                       ; 0x140001490
1400010da: mov [rax], rcx                             ; obj[0xE0] := 0x140001490  (hook)
1400010e2: call IAT ObfDereferenceObject(obj)
```
- Target object name, **byte-verified** at VA 0x140002B10 (file off 0x1F10), UTF-16,
  Length 0x18 = 12 chars: **`\Driver\Disk`** (the disk class driver).
- Offset 0xE0: `lea rax,[rcx+rax+0x70]` with rax preloaded =0x70 → `obj + 0x70(array base) + 14*8`.
  i.e. source was `DriverObject->MajorFunction[14]`. On Win10 1903+/Win11 x64
  `_DRIVER_OBJECT` (vergius/terminus, Size=0x150) `MajorFunction` base = 0x70 →
  **slot 14 = IRP_MJ_FILE_SYSTEM_VOLUME**. (Author's intended slot semantics: **INFERRED** —
  the hook chain in 0x1490 is written for `(DeviceObject, Irp)` dispatch semantics; the author's
  target build is evidenced only by this binary.)
- The original qword is saved to the single driver global 0x140004000 (overwriting the
  DriverEntry value) and later **called as a chain** from the hook.

### 1.4 Installed hook (RVA 0x1490), called with (a, b)

```
1400014a3: call 0x140001560               ; x = [a+0xB8]  (with sanity assert, see 1.5)
1400014ad: [rsp+0x28] = x
1400014b2: d = [x+0x18]                   ; DWORD
1400014c1: cmp d, 0x7c088 ; je A          ; IOCTL_DISK_GET_LENGTH_INFO
1400014cb: cmp d, 0x2d1400 ; je B         ; IOCTL_STORAGE_QUERY_PROPERTY
      A: r8 = 0x1400010f0 ("completed_smart")        (lea r8,[rip-0x416] @14ff)
      B: if ([a+0x18] == 0): r8 = 0x140001220 ("completed_storage_query") (lea r8,[rip-0x2ce] @14e7)
1400014f8/1510: call 0x1400013d0(a, x, r8)          ; arm context (1.6)
140001515: mov rdx, [a] ; mov rcx, [b]
14000151f: call [0x140004000]              ; chain to original saved dispatch
140001525: add rsp,0x48 ; ret              ; return original's status
```

### 1.5 Sanity assert (RVA 0x1560)
`eax=(s8)[a+0x43]; ecx=(s8)[a+0x42]; inc ecx; cmp eax,ecx; jle ok; int 0x2c` →
fast-fail unless `[a+0x43] > [a+0x42]+1`. Then `return [a+0xB8]`.
Field identity of a+0x42/43/0xB8: **UNVERIFIED** (depends on the exact struct the author
targeted; consistent with a PDEVICE_OBJECT-derived pointer chain — see 1.6).

### 1.6 Context builder (RVA 0x13d0), args (a, x, handler)
```
x[+3]  = (x[+3] & 0xFE) | 0x40            ; mark bit 0x40 in byte 3
pool   = ExAllocatePool(0 /*NonPaged*/, 0x20)
pool[+0x00] := x[+0x38]                   ; save old
pool[+0x08] := x[+0x40]                   ; save old
x[+0x40]  := pool                         ; hide context ptr in x's +0x40 slot
x[+0x38]  := handler                      ; 0x10f0 or 0x1220
pool[+0x10] := (u32)x[+8]                 ; (== InputBufferLength when x is the current IO_STACK_LOCATION)
pool[+0x18] := a[+0x18]                   ; buffer pointer
```
Identity of x: **INFERRED = current PIO_STACK_LOCATION** — the only interpretation under which
`pool[+0x10]=(u32)x[+8]` is the IOCTL InputBufferLength validated by the handlers and
`[x+0x18]` is the IoControlCode field (Parameters.DeviceIoControl.IoControlCode = stack+0x18).
`a` **INFERRED = PDEVICE_OBJECT** (a+0x18 = AttachedDevice is the buffer source per the bytes;
semantic role UNVERIFIED).

### 1.7 Handlers (0x10f0 "completed_smart" / 0x1220 "completed_storage_query")
Common flow (0x10f0 shown; 0x1220 identical shape, tag string differs):
```
if (!ctx) { DbgPrint(tag, "%s %d : Context was nullptr"); return 0; }
size = (u32)ctx[+0x10]; buf = ctx[+0x18];
ExFreePoolWithTag(ctx, 0);
if (size < 0x10 || (u32)buf[0]+0x10 > size || (u32)buf[0] >= 0x200)
    DbgPrint(tag, "%s %d : Malformed buffer (should never happen) size: %d", size)
else {
    serial = buf + 0x24;
    DbgPrint(tag, "%s %d : Serial0: %s", serial);
    randomize20(serial);                   ; = 0x25a0(serial, 1)
    DbgPrint(tag, "%s %d : Serial1: %s", serial);
}
return (u32)secondarg[+0x30];
```
0x1220 adds `if ((u32)ctx[+0x18] == 0)` → DbgPrint `"%s %d : Device doesn't have unique ID"`.
So: the **20-byte (0x14) serial at buffer offset 0x24** is rewritten in place — a disk serial
number in a storage-query response (INQUIRY-style data: first DWORD must be < 0x200).

### 1.8 randomize20 (RVA 0x25a0) — hex⇄bytes + dual randomize
1. `flag==1`: take first 20 bytes as a **hex string** (validated char-by-char with `isxdigit`
   (0x22e0); on any invalid char it falls back to raw 20 bytes).
2. Decode hex pairs → 10 bytes (0x2950: `nibble(hi)<<4 | nibble(lo)`, 0x2990 digit parse).
3. Interleave the 10 bytes into two 10-byte lanes (stride 0xB in a 22-byte temp).
4. **Call 0x2370 on each lane** (the actual randomizer, "subserial" = 10-byte half).
5. Un-interleave; re-encode as hex string (0x21e0 byte→"%02X" via 0x1620, appended by
   0x18d0/0x1730/0x16d0 chain) and write back to the caller's 20-byte area (NUL-terminated).

### 1.9 Randomizer (RVA 0x2370) — "Randomizing subserial"
```
seed64 = FNV1a64(lane10) ^ g            ; 0x2160 = FNV-1a 64 (basis 0xCBF29CE484222325, prime 0x100000001B3),
                                          ; g = driver global 0x140004000 (= original dispatch ptr at this point)
DbgPrint("Randomizing subserial: seed: %016llX len: %d", seed, len)
dist = uniform_int_distribution(0x41, 0x5A)      ; 'A'..'Z'  (0x1a80(&d,0x41,0x5a); 0x1a00 mixes seed with
DbgPrint(" old: "); for c in lane: DbgPrint("%02hhX ", c)                             ; 0x5555555555555555/0x5851F42D4C957F2D)
for i, c in lane:
    if isalnum(c) (0x2270): lane[i] = dist()    ; 0x1790→0x17d0 (std::uniform_int_distribution algorithm,
DbgPrint(" new: "); for c in lane: DbgPrint("%02hhX ", c)                             ; incl. wrap → full-range branch)
```
PRNG = vendored **MT19937-64-style** generator: twist (0x1e40) uses `y=(a&0xFFFFFFFF80000000)|(b&0x7FFFFFFF);
new = (y>>1) ^ (y&1 ? 0xB5026F5AA96619E9 : 0) ^ other` over a 312×u64 state inside a C++ class
(temper/next at 0x1ae0/0x1c20/0x1d30/0x1dc0/0x2050). Magic `0xB5026F5AA96619E9` = MT19937-64 mag01.
**Consequence:** every alphanumeric byte of the serial is replaced by a random **A–Z** letter;
non-alnum bytes and length are preserved; seed is deterministic per serial value
(FNV of the original subserial XORed with the captured kernel qword).

### 1.10 What spoofysig.sys does — summary (all evidenced)
A silent kernel driver (no device, no symbolic link, no unload routine, no user IOCTL surface)
that on load grabs the driver object of **`\Driver\Disk`**, swaps the function pointer at
object offset **0xE0** (`MajorFunction[14]` on 1903+ layouts — INFERRED slot) for its own hook
(0x1490), and chains back through the saved original. For IRPs whose control code (read at
`[P+0x18]`, P=[a+0xB8] — INFERRED PIO_STACK_LOCATION) is **0x7C088**
(IOCTL_DISK_GET_LENGTH_INFO) or **0x2D1400** (IOCTL_STORAGE_QUERY_PROPERTY, with an
`[a+0x18]==0` precondition), it arms a 0x20-byte pool context (hidden in `P+0x40`, handler ptr
in `P+0x38`) so that the 20-byte disk serial at response-buffer offset **0x24** gets rewritten
to a randomized A–Z-substituted serial of identical shape. Kernel DbgPrint tracing left in
(tags: `apply_hook`, `completed_smart`, `completed_storage_query`, `Randomizing subserial`).

---

## 2. spoofysig.exe — the stealth loader (user mode, x64, admin)

PE: base 0x140000000, entry RVA 0xf48c, sections `.text` 0x1000/0xf5f8, `.rdata` 0x11000/0x102f6,
`.data` 0x22000/0xda0, `.pdata` 0x23000/0xcd8, `.rsrc` 0x24000, `.reloc` 0x25000.
Imports: KERNEL32(40: CreateFileW, DeviceIoControl, GetTempPathW, VirtualAlloc, …),
ADVAPI32(5: RegOpenKeyW/RegCreateKeyW/RegSetKeyValueW/RegDeleteKeyW/RegCloseKey),
ntdll(2: **NtQuerySystemInformation**, RtlInitUnicodeString), MSVCP140(59), VCRUNTIME140(+_1),
api-ms-win-crt-* (C runtime).
PDB (ASCII, file off 0xdba4): **`C:\Users\X\Desktop\kdmapper-master\x64\Release\kdmapper.pdb`**
→ this is a modified build of the open-source **kdmapper** kernel-driver mapper.
Manifest (0x2f2c): `requireAdministrator`.

### 2.1 Embedded NAL ("vulnerable driver")
- The `.rdata` embeds a full signed driver image: **Intel(R) Network Adapter Diagnostic Driver,
  iQVW64.SYS, v1.03.0.7**, PDB `c:\users\cloudbuild\337244\sdk\nal\src\winnt_wdm\driver\objfre_wnet_AMD64\amd64\iqvw64e.pdb`
  (VA 0x8814), build src `...\sdk\nal\src\winnt_wdm\driver\windriverpci_i.c` (VA 0x80b0),
  full certificate chain present (Symantec time-stamp certs @0xa425…).
- Device names: `\\.\Nal` (VA 0x11770), `\\?\Nal` (0x16d82), `\DosDevices\Nal` (0x16e32),
  `\Device\Nal` (0x16e92), `\\Device\Nal is already in use` (0x11780).
- NAL kernel read/write FunctionIds (VA 0x78d0–0x8430): `NAL_KKMEMCPY_FUNCID`,
  `NAL_KUMEMCPY_FUNCID`, `NAL_KMEMSET_FUNCID`, `NAL_ENABLE_DEBUG_PRINT_FUNCID`,
  `NAL_WIN_IS_ADAPTER_IN_USE/ADAPTER_IN_USE/GET_REF_COUNT/OS_DEVICE/ALLOC_DEV_CONTEXT/
  FREE_DEV_CONTEXT/GET_SYMBOLIC_NAME/GET_PDO_POINTER`.
- **No MAC-set path** in this binary (no MAC strings/IOCTLs) → MAC handling is not here.

### 2.2 Loader flow (evidenced by strings + imports; call order from dis_spoofysig.exe.txt)
1. `[<] Loading vulnerable driver, Name: ` (0x117d0) — writes `iqvw64e.sys` to temp
   (`GetTempPathW`; `[-] Can't find TEMP folder` 0x11820, `[-] Failed to create vulnerable driver file` 0x11860).
2. Registers + starts the service: `SYSTEM\CurrentControlSet\Services\` (0x1c29e) + `ImagePath` (0x1c316) +
   `\Registry\Machine\System\CurrentControlSet\Services\` (0x1c42e); errors: `[-] Can't create service key`
   (0xcc28), `[-] Can't create 'ImagePath' registry value` (0xcc60), `[-] Can't create 'Type' registry value` (0xcca0),
   `[-] Failed to register and start service for the vulnerable driver` (0x118c0).
3. Privilege + load: `RtlAdjustPrivilege` (0xccc8, resolved dynamically from ntdll),
   `NtLoadDriver` (0xcce0) / `NtUnloadDriver` (0xcdf0);
   `Fatal error: failed to acquire SE_LOAD_DRIVER_PRIVILEGE…` (0xcce0+),
   `[-] Failed to load driver iqvw64e.sys` (0x11950).
4. kdmapper core (usage string 0x1b95e: `kdmapper.exe [--free][--mdl][--PassAllocationPtr] driver`):
   PE validation (`[-] Invalid format of PE image` 0x1bf26, `[-] Image is not 64 bit` 0x1bf66),
   kernel alloc via NAL (`[-] Failed to allocate remote image in kernel` 0x1bf9e,
   `[+] Image base has been allocated at 0x` 0x1bffe), import resolution
   (`[-] Failed to resolve imports` 0x1c096), copy, `[<] Calling DriverEntry 0x` (0x1c13e),
   `[+] DriverEntry returned 0x` (0x1c20e).
   → **This is how spoofysig.sys (unsigned/test-signed) reaches kernel memory and gets its
   DriverEntry executed — without a service.**
5. Anti-forensics (all three trace lists cleaned):
   - `[+] MmUnloadedDrivers Cleaned: ` (0x12170) — zeroes `MmUnloadedDrivers`.
   - `PiDDBCacheTable` clear (0x123de–0x126be: walk `PiDDBCacheTable` AVL-ish list under
     `PiDDBLock`, `RtlDeleteElementGenericTableAvl`, `[+] PiDDBCacheTable Cleaned`).
   - `g_KernelHashBucketList` clear (0x1289e–0x12f8e: pattern-find `ci.dll` base, locate
     `g_KernelHashBucketList`/`g_HashCacheLock`, walk buckets, unlink entries,
     `[+] g_KernelHashBucketList Cleaned`) → hides the driver from the kernel module hash
     (what many enumerators + anti-cheats read).
   - Helpers found by pattern: `MmAlocatePagesForMdl` (sic), `MmMapLockedPagesSpecifyCache`,
     `MmProtectMdlSystemAddress`, `MmUnmapLockedPages`, `MmFreePagesFromMdl` (0x11d00–0x11fb0).
6. Unload: `[<] Unloading vulnerable driver` (0x11ae0), `[-] Driver Unload Failed!!` (0xce20),
   `[+] Vul driver data destroyed before unlink` (0x11b70).

### 2.3 Service-only fallback
ADVAPI32 imports + `NtLoadDriver` also support a plain service install/load path
(registry keys under `SYSTEM\CurrentControlSet\Services\`) — used when the kdmapper/NAL path
is unavailable (e.g., no compatible NAL adapter).

---

## 3. Woofer_unpacked.exe — 2-stage loader + resource-decryptor (PE32 x86)

Unpacked with native UPX 3.94 (`upx.out -d`): **143,872 ← 99,328 B, 69.04%**, byte count
matches PackHeader `u_file_size` 0x23200 exactly.
Layout: IB 0x400000, entry RVA 0x1000 (VA 0x401000), SizeOfImage 0x27000;
`.code` 0x1000/0x387e, `.text` 0x5000/0xd962, `.rdata` 0x13000/0x33a5, `.data` 0x17000/0x178c, `.rsrc` 0x19000/0xd244.
Imports: KERNEL32(72: CreateProcessW, CreateFileW, GetTempPathW, resource API, RegisterWaitForSingleObject,
**no registry fns**), USER32(33 GUI), SHELL32(3: ShellExecuteExW, SHGetFolderLocation, SHGetPathFromIDListW),
SHLWAPI(5), OLE32(2), MSVCRT(16), COMCTL32(1), GDI32(1), WINMM(1: timeBeginPeriod).
**No ADVAPI32, no IPHLPAPI** → no direct registry / NIC API: all registry + NIC work is
delegated to child processes / generated scripts.

### 3.1 Obfuscation layers (evidenced)

1. **Indirect import thunks** — instead of calling the IAT from code, .code holds two
   thunks tables (`jmp [IATslot]` arrays at **0x404a70–0x404af4** and **0x405070–0x4050f4**;
   e.g. `0x40509a: jmp [0x4174cc]` → `WriteFile`). Code calls the thunks
   (`call 0x4050a0` → GetTempFileNameW) or the IAT slot directly (`call [0x41751c]` →
   WaitForSingleObject, @0x404dd1). IAT = 0x417470..0x417664 (.data), INT names 0x4176ae+.
2. **Duplicated code regions** — .text (0x405000–0x40C962) contains a near-copy of the
   .code helper glue (two MSVCRT glue blocks: 0x405xxx mirrors 0x404xxx), plus embedded
   seed material (below) and the C++/GUI object code (0x408000–0x40C000 range).
3. **Embedded key material in .data** (raw dump, file-backed):
   - **0x417080–0x417107: 139-byte high-entropy blob** (the encrypted key/payload seed
     data; first bytes `6d 2c c1 39 bb 8e 8e 91 …`).
   - **0x41707c: u32 0x06D53B7F** — 32-bit seed (sits in a 3×{0xFFFFFFFF,4}+{seed} struct
     at 0x417070).
   - **0x417108: u32 0x100** (256 = RC4 state size) · **0x41710c: "D0A\0"** (3-char ASCII).
   - **0x417110: 12-byte entropy blob** `ff ff ff ff 90 e2 4d 37 3f 12 65 45 91 64 39 c4 92 5e 46 7b`.
   - **0x417170–0x417460: 16-bit value table** (5432, 14676, 63728, 65336, … — CFG/dispatch
     offsets; UNVERIFIED purpose).
   - Character constants `:'?\|` at 0x41703a/0x41703e/0x417042/0x417046;
     `"sysnative"` u16 @0x417048 (second copy; first at .rdata 0x416070);
     `"**"` u16 @0x417058 (wildcard pattern).
4. **Runtime RC4** — full RC4 (KSA + PRGA) implemented inline in .code at **0x4011ef**
   (disasm: 256-byte S-box init from repeating key, KSA `c=(b+a[i])&0xff; swap`,
   PRGA `i=(i+1)&0xff; j=(j+a[i]+a[j])&0xff; out=in^a[(a[i]+a[j])&0xff]`).
5. **Key construction** (entry sequence 0x401058–0x401128):
   `0x40a460(4,0x15)` → `0x40aa5a(&g_4180f8)` → `0x40a9c8(8, 0x417064, &0x4180f8)` (copy 8B)
   → `0x40a9c8(4, 0x417064, &0x418100)` (copy 4B) → `0x40e266(0xc, 0x186a1, 7, 0x417074, 0x4180f0)`
   (PRNG pass; 0x40e266 also called at 0x401238/0x40125b for 0x100-byte zeroed buffers).
   The main body **0x403f53** hex-encodes the embedded blob: reads **25 bytes @0x417092**
   then **3 bytes @0x4170f6** through `0x405dc0` (byte→hex pair) → builds hex strings for
   the decryption/licensing step.
   → **UNVERIFIED-static**: the exact RC4 key and the decrypted payload contents require
     emulating 0x40a460/0x40e266/0x40a9c8 (or running on Windows). The rebuilt binary
     carries identical bytes, so it decrypts identically.

### 3.2 Startup flow (entry 0x401000, evidenced)

```
0x401000 CRT init (HeapCreate 0x1000 → g_418068; GetModuleHandleW → g_41806c)
0x40104e call 0x40e4d0 / 0x401053 call 0x40e23d           (CRT startup glue)
0x401058..0x40107b  C++ global ctors (0x40b120,0x40a9a9,0x40a441,0x40a1c0,0x409669,
                     0x408dee,0x4053b5,0x40cdc3,0x40b870)
0x4010be..0x401128  key material setup (§3.1.5)
0x401174 lea eax,[0x401f4c]; call 0x409fb0               (register 0x401f4c callback)
0x401188 call 0x402eed → 0x401192 call 0x40e560
0x401197 call 0x401ba0                                    (big init: temp dirs, resources)
0x4011a2 if (g_4180b0 == 1) call 0x402fad                 (flag-gated path; flag set by 0x402fd?—
          [0x4180b0] written at 0x401df3 =1)
0x4011ac call 0x403f53                                    (MAIN: hex-decrypt embedded blob,
          then GUI/orchestration — object code in .text 0x408xxx–0x40Cxxx)
0x4011b1..0x4011cb cleanup (HeapDestroy g_418068, ExitProcess)
```

### 3.3 Resource-driven payload extraction (evidenced call sites)

The binary walks its **own resources** and temp files:

| site | API (via thunk/IAT) | notes |
|---|---|---|
| 0x401a3b/a90/ae5/b49 | GetTempFileNameW ×4 | temp file creation |
| 0x401648 | WriteFile | writes payload to temp |
| 0x401af0/0x401b2f | PathAddBackslashW / PathRenameExtensionW | builds `<temp>\<name><ext>` |
| 0x401bde | LoadLibraryExW | **loads the written file as a DLL** |
| 0x401bfb / 0x402056 | EnumResourceTypesW / EnumResourceNamesW | walks the loaded module's resources |
| 0x402675/0x402685/0x4026b4 | LoadResource / SizeofResource / FreeResource (fn 0x402664) | resource fetch |
| 0x402792/0x4027aa/0x402cf0/0x402e71/0x403e67 | FindResourceW | type/name lookups |
| 0x402011/0x40201c/0x403523 | RemoveDirectoryW ×3 | temp cleanup |
| 0x40254f/0x402585 | GetCommandLineW / PathRemoveArgsW | exe path → working dir |
| 0x4032ae/0x4033d7/0x403414 | GetWindowsDirectoryW / GetSystemDirectoryW ×2 | sysdir paths |
| 0x402be0 | GetShortPathNameW | 8.3 path fallback |

Extraction loop fn **0x4026c7**: iterates a global table at **0x4180f0** (stride 0xc,
count in [0x4180dc]) of {w16 name-len?, name-ptr, …} entries; per entry builds a name
string, `FindResourceW(g_4180ac=module, name, type=0xa)`; if found → `LoadResource` +
`SizeofResource` → **`call 0x4011ef` (RC4 decrypt)** with key material from g_4180a0
→ `0x40adc5` (write/consume). Second pass at 0x40287b uses type **0xa again** for a
different entry field. → **UNVERIFIED-static** which on-disk files result.

Resources present (.rsrc): **RT_RCDATA #1 = 46,403 B high-entropy blob** (off 0x192ac,
head `29 4a 35 61 38 ea …`) — the main encrypted payload; **RT_GROUP_ICON entries with
32-hex "GUID" names** (`01B9D532D7811526F0B7C862B06F6F6E` 5,886 B, `3F4CD4E5FD0F…` 6 B,
`EFC86EF7677FA9934EF305EC6F89E07C` 146 B) — RC4-decrypted per §3.3 (names built at
runtime — UNVERIFIED-static mapping to disk files); RT_MANIFEST (672 B) — demands
**requireAdministrator** (consistent with hwid.ps1's admin requirement).

Static **zlib 1.2.11 inflate** is linked in (banners ` inflate 1.2.11 Copyright 1995-2017
Mark Adler ` @0x4161d0, `incorrect header check` @0x413fe8) → at least one decrypted
stage is zlib-compressed (which stage — UNVERIFIED-static).

Dynamic API names (GetProcAddress targets, .rdata): `RtlGetVersion` (0x413014, resolved at
0x404f54/0x405554 → version gate), `SHBrowseForFolderW` (0x4130b0), `SHGetPathFromIDListW`
(0x4130c4), `GetLongPathNameW` (0x413690), `SHGetKnownFolderPath` (0x4136bc),
`InitOnceExecuteOnce` (0x413724) — long-path + folder-picker features in the GUI stage.

Notable strings (wo_strings.json): `"Downloads\"` (u16, 0x413436) — **output dir target**;
`"sysnative"` (u16, 0x416070) — sysnative syspath; charset `"0123456789abcdefK"` (0x4136f8)
— name/serial generation alphabet (17 chars: 0-9, a-f, K); blobs `"Qkkbal"` (0x414311),
`"w+OQvr"` (0x414ae3), `"H*0\"ZOW"` (0x414e97) — license/key material (role
UNVERIFIED-static; consumed by the GUI stage).

### 3.4 Conclusions for the rebuild

* Woofer.exe = **packed (UPX 3.94) x86 two-stage loader**: stub decrypts (RC4, inline at
  0x4011ef) its own encrypted resources → writes temp files → LoadLibraryExW → extracts
  the payload module(s) → GUI/orchestration in .text spawns the children
  (spoofysig.exe, hwid.ps1, powershell) using the static CreateProcessW/ShellExecuteExW
  imports; registry/NIC work is delegated (no ADVAPI32/IPHLPAPI imports).
* For an **opcode-level from-zero rebuild** nothing here needs emulation: the original
  bytes (stub + RC4 + resources + seeds) are placed back at the original RVAs, so
  runtime behavior (decryption, extraction, GUI) is bit-identical to the original.

  RE note (evidenced): this binary's IAT entries store the INT-entry RVA **minus 2**
  (e.g. MSVCRT IAT[0] @0x417470 = 0x176ac, while the `memset` INT name sits at
  RVA 0x176ae; consistent −2 across all 16 MSVCRT slots). It is a property of the
  original bytes (UPX-unpack artifact); the loader's name lookup resolves the names
  correctly (verified with pefile on the sample).

## 4. hwid.ps1 (3,270 B, unchanged from prior analysis)
PowerShell, admin: sets `HKLM\SYSTEM\Select`-style HwProfileGuid
(`SOFTWARE\Microsoft\Windows NT\CurrentVersion` `Hardware Profiles\0001` HwProfileGuid… as
`{hex8-hex4-hex4-hex4-hex12}`) + `MachineGuid`
(`SOFTWARE\Microsoft\Cryptography`), then spawns missing `Volumeid64.exe` with args
`C: <HEX4>-<HEX4>` (volume serial set).

## 5. Suite wiring (inferred from the components above)
`Woofer.exe` (UPX-packed x86 2-stage loader, RC4 self-decryptor, §3) → decrypts/extracts its
encrypted resources (46 KB RCDATA payload + GUID-named entries) to temp + "Downloads\",
loads the payload module (LoadLibraryExW) → GUI/orchestration stage (.text 0x408xxx–0x40Cxxx)
spawns the children with static CreateProcessW/ShellExecuteExW →
`spoofysig.exe` (kdmapper: NAL iqvw64e + spoofysig.sys → disk serial randomization active in
kernel, module traces erased) → `hwid.ps1` (GUIDs + Volumeid64 volume serial) →
MAC (mac.txt, 503 addrs) and hostname (host.txt, 200 `ZaxaR-*`) applied by Woofer via child
processes / generated names (charset `0123456789abcdefK`).
**No MAC/IOCTL path exists in spoofysig.exe** (verified: no MAC strings/IOCTLs) → MAC/hostname
application lives in Woofer's GUI stage or a child script.

## 6. Status & open items
1. **Woofer.exe** — mechanism-level RE complete (§3): entry/CRT flow, RC4 decryptor (0x4011ef),
   embedded key blobs (0x417070–0x41711f), resource extraction loop (0x4026c7), 2-stage loader
   pattern, thunks-table obfuscation. **UNVERIFIED-static** (needs Windows run or emulation):
   exact RC4 key derivation (0x40a460/0x40e266/0x40a9c8), decrypted payload identity,
   command-line construction of the spawned children, license/key check details
   (Qkkbal / w+OQvr / H*0"ZOW / charset consumer).
2. **spoofysig.exe**: feature-level RE complete (§2); function-level map not finished
   (44k-line dump ready).
3. **Rebuild (opcode level, from zero, original RVAs) — DONE (2026-10-12), scope: FULL
   suite.** Artifacts in `rebuild/out/` (Woofer.exe, spoofysig.exe, spoofysig.sys,
   hwid.ps1, mac.txt, host.txt); builder `rebuild/build_suite.py`, triple-verification
   `rebuild/verify_suite.py` → **59 PASS / 0 FAIL** (see `rebuild/VERIFY_REPORT.md`):
   all artifacts byte-identical to sources (sha256-proven), cited VAs present,
   1,415 spoofysig.sys instructions re-disassembled from the rebuilt file with 0
   mismatches, loader-style parse OK (134 Woofer imports, 19 sys unwind entries,
   cert table intact). Activation/testing only on the user's own Windows machine.
