# Woofer Counter (مكافح) — built binaries

Compiled countermeasure against the **Woofer HWID-spoofing suite**
(`../woofer_re/` — full static RE in `../woofer_re/RE_report.md`).

**Deliverables (BUILT binaries, not just source):**

| File | Arch | Size | SHA-256 |
|---|---|---|---|
| `bin/woofer_counter_x64.exe` | x86_64 | 117,248 B | `3abf6f9e636088d96a1737ec2087f82777b7f4a36e547920bf0625cffce1de7f` |
| `bin/woofer_counter_x86.exe` | x86 | 123,904 B | `50cc2e80dd9739399af1a307da5969d07d74fa4429cc76527d43f748cbff6139` |

Source: `woofer_counter.c` (single self-contained C file) + generated
fingerprint tables `suite_macs.inc` (504 MACs, exact pool from the suite's
`mac.txt`) and `suite_hosts.inc` (243 hostnames, exact pool from `host.txt`).
Build: `./build_counter.sh` (zig cc, both targets; same toolchain as the
suite rebuild).

## Detection model (all fingerprints evidenced from the suite samples)

1. **Processes** — `Woofer.exe`, `spoofysig.exe`, `Volumeid64.exe`, and
   `powershell.exe`/`pwsh.exe` whose command line contains `hwid.ps1`
   (command line read via `NtQueryInformationProcess` class 60).
2. **Files by exact SHA-256** (the 8 suite artifacts, sizes pre-filtered for
   speed), searched in: exe dir, %TEMP%/%TMP%, %APPDATA%, %LOCALAPPDATA%,
   %PROGRAMDATA%, %WINDIR%\Temp, `C:\Users\*\Downloads`:
   `Woofer.exe` (packed **and** unpacked image), `spoofysig.exe`,
   `spoofysig.sys`, `iQVW64.SYS` (the Intel NAL embedded in spoofysig.exe —
   extracted at file offset 0x11e90, `../woofer_re/nal_iqvw64_extracted.sys`),
   `hwid.ps1`, `mac.txt`, `host.txt`.
   Name-lookalikes (`woof*.exe`, `spoofysig.*`, `iqvw64*.sys`, …) are flagged
   as warnings; only exact-hash matches are deleted.
3. **NAL service** — any `SYSTEM\CurrentControlSet\Services` key named
   `iQVW64`, whose `ImagePath` contains `iqvw64`, or whose `DisplayName`
   contains "Network Adapter Diagnostic" (the kdmapper carrier, RE §2).
   Plus a live probe: `\\Device\Nal` openable ⇒ NAL currently kernel-loaded.
4. **Registry tamper signatures** (no backup needed):
   - `MachineGuid` (HKLM\SOFTWARE\Microsoft\Cryptography) — genuine Windows
     value is **32 hex chars, no dashes**. `hwid.ps1` writes a **dashed
     36-char lowercase `8-4-4-4-12`** form → instant signature.
   - `HwProfileGuid` — `hwid.ps1` writes **all-lowercase** `{8-4-4-4-12}`
     (genuine is usually uppercase) → warning signature.
5. **Volume serial** — C: serial read via `GetVolumeInformationW`;
   `hwid.ps1` sets 8 **uppercase** hex through `Volumeid64.exe "C: XXXX-YYYY"`.
6. **Hostname** — membership in the suite's 243-name pool (`ZaxaR-*`).
7. **NIC MACs** — `GetAdaptersInfo` addresses vs the suite's 504-MAC pool,
   plus registry overrides: `NetworkAddress` values under
   `SYSTEM\...\Class\{4d36e972-e325-11ce-bfc1-08002be10318}\000x`
   (a spoofed MAC persists here even after the suite's files are gone).
8. **Disk serials** — `\\.\PhysicalDriveN` →
   `IOCTL_STORAGE_QUERY_PROPERTY` (0x2D1400), `STORAGE_DEVICE_DESCRIPTOR`
   SerialNumber parsed dynamically (offset 0x1A + Vendor + Product +
   ProductRevision lengths). Signature of `spoofysig.sys`'s hook (RE §1,
   randomizer fn 0x2370): **every alphanumeric byte rewritten to a random
   A-Z letter — digits and lowercase vanish, punctuation kept**. A serial
   with only A-Z alnum (no digits, no lowercase) is flagged SPOOFED-LIKE;
   with a backup, exact comparison is done.

## Usage

```
woofer_counter.exe            (default) scan   full sweep + report file
woofer_counter.exe backup     snapshot originals (run BEFORE any suite use)
woofer_counter.exe clean      kill processes, stop+delete NAL service,
                              delete suite files by hash, remove MAC
                              overrides, restore MachineGuid/HwProfileGuid/
                              hostname/volume serial from backup
woofer_counter.exe clean --reboot   same + automatic reboot
woofer_counter.exe verify     post-reboot re-check vs backup
```

- Run **as Administrator** for `clean` (kills, SCM, registry, PhysicalDrive).
  `scan`/`backup` work mostly un-elevated (disk serials need admin).
- Outputs: console + `woofer_counter_report.txt` and `woofer_backup.json`
  next to the exe. Exit code 1 when BAD findings exist.
- **Recommended sequence:** `backup` → (if the suite ever ran) `clean
  --reboot` → after reboot `verify`.

### What `clean` does, step by step
1. Terminates `Woofer.exe` / `spoofysig.exe` / `Volumeid64.exe` /
   powershell running `hwid.ps1`.
2. Stops and deletes the NAL service (SCM `DeleteService`); if the NAL device
   is loaded the kernel copy persists until reboot.
3. Deletes every file matching one of the 8 exact suite SHA-256s.
4. Deletes `NetworkAddress` MAC overrides (permanent MAC returns after
   NIC reset/reboot).
5. Restores from `woofer_backup.json`: `MachineGuid`, `HwProfileGuid`,
   hostname (`SetComputerNameExW`, applies after reboot), C: volume serial
   (runs `Volumeid64.exe` from the counter's directory with the backed-up
   serial, if present).
6. **Reboot** — mandatory to clear the kernel disk-serial hook (it lives in
   kernel memory; user mode cannot unhook it) and to flush the mapped-module
   traces the suite erased from `MmUnloadedDrivers`/`PiDDBCacheTable`/
   `g_KernelHashBucketList`.

## Static verification (zero execution in this environment)

`verify_counter.py` (run: `python verify_counter.py`) → **ALL PASS** on both
binaries:
- PE structure: machine 0x8664/0x14c, subsystem = console, valid entry point,
  section table.
- Imports: advapi32 (19 fns: registry, SCM, **base CryptoAPI** —
  `CryptAcquireContextW`/`CryptCreateHash`/`CryptHashData`/
  `CryptGetHashParam`/`CryptReleaseContext` bind from advapi32.dll, which is
  their canonical home on all Windows versions), iphlpapi
  (`GetAdaptersInfo`), user32 (`ExitWindowsEx`), shell32
  (`SHGetFolderPathW`), kernel32 (43 fns incl. `DeviceIoControl`,
  `CreateFileW`, `TerminateProcess`, `GetVolumeInformationW`,
  `SetComputerNameExW`, `CreateProcessW`, `GetProcAddress`).
- Embedded fingerprints: all 8 suite SHA-256s, `iQVW64`, MAC pool, hostname
  pool, both GUID keys/paths, NIC class GUID, `NetworkAddress`,
  `PhysicalDrive%d`, `\\Device\Nal`, `hwid.ps1`, backup file name.

Two toolchain properties documented during verification (both confirmed
against genuine Microsoft/Intel binaries, so the exes are standard PEs):
- **x64 IAT 8-byte stride** — every x64 import entry is followed by a zero
  DWORD. Verified identical in the genuine Intel `iQVW64.SYS` (MSVC x64) —
  this is the normal MSVC x64 layout, accepted by the Windows loader.
- **Import name tables** store 2 hint bytes + ASCII name without the
  originated high bit — identical to known-good zig builds in this repo
  (`bin/test_csx_spoof.exe`, live-tested on Windows).

**Declarations:** zero sample execution (all suite fingerprints read from
static sample bytes; the counter itself was never run here — it activates
only on the user's own Windows machine). No deltas: the built exes are the
exact source compiled as-is.
