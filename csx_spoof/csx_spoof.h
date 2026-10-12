#pragma once
/* ============================================================================
 * csx_spoof — interface header
 * ----------------------------------------------------------------------------
 * Faithful (behavioral) replica of the "spoofer" feature of CSX.exe — the
 * "Reset MTA Serial" function:
 *
 *   Sample   : CSX.exe  (4,392,448 bytes)
 *   SHA-256  : d5ed9e6a57952d2a2d7876813376784868126e9295ee55ba01b45a395fc4ee556
 *   PE       : PE32 x86, ImageBase 0x00400000, entry 0x00422052
 *   Feature  : UI wrapper 0x0040FA60  ("R E S E T   S E R I A L" button,
 *              "Resetting MTA serial..." VA 0x004455FC,
 *              "Serial reset complete" VA 0x004456EC)
 *              -> workhorse 0x0040EFF0 (0x44A bytes)
 *              -> helper 0x0040EC10 (recursive HKCU key-tree delete)
 *              -> helper 0x0040E8C0 (recursive directory delete)
 *
 * Result category: R2 (behavioral/structural reconstruction).
 * Every constant in this header and in csx_spoof_core.cpp was read from the
 * bytes of CSX.exe in this working session (VAs are runtime image VAs; the
 * .rdata file offset = VA - 0x402000, the .text file offset = VA - 0x400C00).
 * The rebuilt code is NOT byte-for-byte the original MSVC output — the
 * *behavior* is the original: same API calls, same order, same strings, same
 * registry keys, same value names, same value types and sizes.
 *
 * Zero execution of the sample was performed during the reverse engineering.
 * ========================================================================== */

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
typedef int32_t  BOOL;
typedef void    *HWND;
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* ----------------------------------------------------------------------------
 * Original constant evidence (all in CSX.exe .rdata unless noted).
 *
 * Step 1 — credential (workhorse 0x0040EFF0):
 *   0x0040F01D..0x0040F026  CredDeleteW(L"SSO_RND_Device", 1, 0)
 *       L"SSO_RND_Device" UTF-16 @ VA 0x00445364 (push imm @0x0040F021)
 *       CRED_GENERIC_TARGET_TYPE = 1 (push @0x0040F01F), flags 0 (push @0x0040F01D)
 *       IAT slot 0x0043A008 = ADVAPI32!CredDeleteW
 *
 * Step 2 — HKCU key trees, via helper 0x0040EC10(path-in-EDX):
 *   0x0040F02C mov edx, 0x00445384 -> "Software\Microsoft\Windows\CurrentVersion\Explorer\CLSID"
 *   0x0040F031 call 0x0040EC10
 *   0x0040F036 mov edx, 0x004453C0 -> "Software\Microsoft\Windows\CurrentVersion\Explorer\CLSID2"
 *   0x0040F03B call 0x0040EC10
 *   0x0040F040 mov edx, 0x00445400 -> "Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections"
 *   0x0040F045 call 0x0040EC10
 *   0x0040EC10 = RegOpenKeyExA(HKCU 0x80000001, path, 0, 0xF003F); if absent
 *               return FALSE; enumerate subkeys (RegEnumKeyExA, 0x100-byte
 *               buffer) and delete each recursively (self-call @0x0040EF1B);
 *               RegCloseKey @0x0040EFA8; RegDeleteKeyA(HKCU, path)
 *               @0x0040EFB4.  (HKCU push @0x0040EC54, KEY_ALL push @0x0040EC4C)
 *
 * Steps 3-4 — NTFS alternate data streams + roaming ADS:
 *   0x0040F04A mov edi, [0x0043A1C0] = KERNEL32!DeleteFileA
 *   0x0040F050 push 0x00445448 "C:\ProgramData:NT"    ; 0x0040F055 call edi
 *   0x0040F057 push 0x0044545C "C:\ProgramData:NT2"   ; 0x0040F05C call edi
 *   0x0040F06C..0x0040F08C  std::string S; S.reserve(0x100);
 *                           DWORD len = 0x100; GetUserNameA(&S[0], &len)
 *                           IAT 0x0043A01C, call @0x0040F08C
 *   0x0040F0AB movq [S2], [0x00445484] + byte [0x0044548C]  -> S2 = "C:\Users\" (9)
 *   S2 += S (username)                        @0x0040F134 (append helper 0x0041E0B0)
 *   0x0040F195 push 0x00445470 "\AppData\Roaming" (len 0x10) -> S2 += ...
 *   0x0040F2EA push 0x00445490 ":NT"  (len 3)   -> S3 = S2 + ":NT"
 *   0x0040F318 call edi (DeleteFileA(S3))
 *   0x0040F37B push 0x00445494 ":NT2" (len 4)   -> S4 = S2 + ":NT2"
 *   0x0040F3A9 call edi (DeleteFileA(S4))
 *
 * Step 5 — shared MTA cache directory:
 *   0x0040F3E5 push 0x0044549C "C:\ProgramData\MTA San Andreas All"
 *   0x0040F3EA call [0x0043A1A8] = KERNEL32!GetFileAttributesA
 *   0x0040F3F0 cmp eax,-1 / 0x0040F3F9 test al,0x10 -> skip if absent or SYSTEM
 *   heap buffer 0x40 (0x0040F40E/0x0040F421) receives the 0x35-byte blob
 *   "C:\ProgramData\MTA San Andreas All\Common\data\cache"
 *   (16B @0x004454C0 + 16B @0x004454D0 + 16B @0x004454E0 + 4B @0x004454F0 + NUL)
 *   0x0040F47B call 0x0040E8C0(string*) = recursive directory delete:
 *     FindFirstFileA(path + "\\*", @0x0040E93D; "\\*" UTF-16 @ VA 0x00445352
 *     is the wide constant set, A-version API), skip "." (VA 0x00445358) and
 *     ".." (VA 0x0044535C), recurse on subdirs (call @0x0040EB5C),
 *     DeleteFileA on files (@0x0040EB6F via 0x0043A1C0), FindClose
 *     (@0x0040EBC9 via 0x0043A16C), RemoveDirectoryA(path)
 *     (@0x0040EBD8 via 0x0043A1F8).
 *
 * Step 6 — MTA registry values (2-iteration loop over the key table at
 *   0x0040F4E5/0x0040F4EF: [ebp-0x1e0] = 0x004454F8, [ebp-00x1dc] = 0x00445534):
 *     K0 = "SOFTWARE\WOW6432Node\Multi Theft Auto: San Andreas All\1.5" @0x004454F8
 *     K1 = "SOFTWARE\WOW6432Node\Multi Theft Auto: San Andreas All\1.6" @0x00445534
 *   body @0x0040F4FF, all opens HKLM (0x80000002, push @0x0040F658/0x0040F6BE/
 *   0x0040F7FB/0x0040F923) with KEY_ALL_ACCESS (0xF003F) via
 *   IAT 0x0040F4DA->0x0043A014 RegOpenKeyExA; writes via
 *   0x0040F4BE->0x0043A018 RegSetValueExA (edi); closes via
 *   0x0040F4E0->0x0043A024 RegCloseKey:
 *     (a) h = RegOpenKeyExA(HKLM, K + "\Settings\general", 0, KEY_ALL)
 *         @0x0040F66E   ("\Settings\general" VA 0x00445570, len 0x11,
 *         push @0x0040F554); on success:
 *         RegSetValueExA(h, "cachechecksum", 0, REG_SZ, &0x00, 1) @0x0040F68D
 *         ("cachechecksum" VA 0x00445584 push @0x0040F682,
 *         data 1-byte NUL VA 0x00443884 push @0x0040F67A); RegCloseKey
 *         (b) h = RegOpenKeyExA(HKLM, K + "\Settings\general", 0, KEY_ALL)
 *         @0x0040F6C3 (the original opens the same key a second time);
 *         on success:
 *         RegSetValueExA(h, "serial", 0, REG_SZ, &0x00, 1) @0x0040F6E2
 *         ("serial" VA 0x00445594 push @0x0040F6D7); RegCloseKey
 *     (c) h = RegOpenKeyExA(HKLM, K + "\Settings\diagnostics", 0, KEY_ALL)
 *         @0x0040F800   ("\Settings\diagnostics" VA 0x0044559C, len 0x15,
 *         push @0x0040F73F); on success:
 *         RegSetValueExA(h, "crash-data",  0, REG_SZ, &0x00, 1) @0x0040F8BE
 *         ("crash-data"  VA 0x004455B4 push @0x0040F8B3)
 *         RegSetValueExA(h, "crash-data1", 0, REG_SZ, &0x00, 1) @0x0040F8D6
 *         ("crash-data1" VA 0x004455C0 push @0x0040F8CB)
 *         RegSetValueExA(h, "crash-data2", 0, REG_SZ, &0x00, 1) @0x0040F8EE
 *         ("crash-data2" VA 0x004455CC push @0x0040F8E3)
 *         RegSetValueExA(h, "send-dumps",  0, REG_SZ, "no", 3) @0x0040F906
 *         ("send-dumps" VA 0x004455DC push @0x0040F8FB,
 *         "no" VA 0x004455D8 push @0x0040F8F2, size 3 = no trailing NUL)
 *         RegCloseKey
 *     (d) h = RegOpenKeyExA(HKLM, K, 0, KEY_ALL) @0x0040F928 (the version key
 *         itself, no suffix — lpSubKey = esi restored to the raw key string
 *         @0x0040F774); on success:
 *         RegSetValueExA(h, "Last Run Path Hash", 0, REG_SZ, &0x00, 1)
 *         @0x0040F947 ("Last Run Path Hash" VA 0x004455E8 push @0x0040F93C);
 *         RegCloseKey
 *   Net effect: for 1.5 and 1.6 the values serial, cachechecksum,
 *   "Last Run Path Hash" and the three crash-data* values are erased (set to
 *   a 1-byte empty REG_SZ) and send-dumps is set to "no" — MTA regenerates
 *   its serial/fingerprint on next start.
 *
 * Step 7 — UI (caller 0x0040FA60, only performed in CSX's own window):
 *   SetWindowTextW(hwnd, "Resetting MTA serial...")  (VA 0x004455FC,
 *   IAT 0x0043A33C), around the 0x0040EFF0 call, then
 *   SetWindowTextW(hwnd, "Serial reset complete") (VA 0x004456EC) and
 *   InvalidateRect(hwnd, NULL, 0) (IAT 0x0043A314).
 * ========================================================================== */

/* ----------------------------------------------------------------------------
 * Probe structure — read-only mirror of everything the reset touches, so the
 * user can verify before/after state on Windows + MTA:SA.
 * For every registry value the reset writes, the probe reads the current
 * value text plus an explicit "present" flag (absent != empty).
 * -------------------------------------------------------------------------- */
typedef struct _CSXResetProbe {
    BOOL ssoCredentialPresent;   /* generic credential "SSO_RND_Device" (CredReadW) */
    BOOL clsidKeyPresent;        /* HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\CLSID */
    BOOL clsid2KeyPresent;       /* HKCU\...\Explorer\CLSID2 */
    BOOL connectionsKeyPresent;  /* HKCU\...\Internet Settings\Connections */
    BOOL programDataNtStream;    /* C:\ProgramData:NT   (NTFS alternate data stream) */
    BOOL programDataNt2Stream;   /* C:\ProgramData:NT2 */
    BOOL roamingNtStream;        /* C:\Users\<user>\AppData\Roaming:NT */
    BOOL roamingNt2Stream;       /* C:\Users\<user>\AppData\Roaming:NT2 */
    BOOL mtaSharedDirPresent;    /* C:\ProgramData\MTA San Andreas All */
    BOOL mtaSharedCachePresent;  /* C:\ProgramData\MTA San Andreas All\Common\data\cache */
    BOOL mtaReg15Present;        /* HKLM\SOFTWARE\WOW6432Node\Multi Theft Auto: San Andreas All\1.5 */
    BOOL mtaReg16Present;        /* HKLM\SOFTWARE\WOW6432Node\Multi Theft Auto: San Andreas All\1.6 */
    /* values of ...\<version>\Settings\general   (erased to "" by the reset) */
    char serial15[64];           BOOL serial15Present;
    char cacheChecksum15[64];    BOOL cacheChecksum15Present;
    char serial16[64];           BOOL serial16Present;
    char cacheChecksum16[64];    BOOL cacheChecksum16Present;
    /* values of the version key itself           (erased to "" by the reset) */
    char lastRunHash15[64];      BOOL lastRunHash15Present;   /* "Last Run Path Hash" */
    char lastRunHash16[64];      BOOL lastRunHash16Present;
    /* values of ...\<version>\Settings\diagnostics (erased to "" / "no") */
    char crashData15[64];        BOOL crashData15Present;     /* "crash-data" */
    char crashData1_15[64];      BOOL crashData1_15Present;   /* "crash-data1" */
    char crashData2_15[64];      BOOL crashData2_15Present;   /* "crash-data2" */
    char sendDumps15[64];        BOOL sendDumps15Present;     /* "send-dumps" */
    char crashData16[64];        BOOL crashData16Present;
    char crashData1_16[64];      BOOL crashData1_16Present;
    char crashData2_16[64];      BOOL crashData2_16Present;
    char sendDumps16[64];        BOOL sendDumps16Present;
} CSXResetProbe;

/* Destructive steps executed by CSX_SpooferResetMtaSerial (7: the UI step is
 * step 7 and is only executed when a window handle is supplied). */
#define CSX_SPOOF_STEP_COUNT 7

/* Define CSX_SPOOF_BUILD_DLL when compiling the DLL itself; consumers of the
 * header (the test harness, the NRTH build) get plain extern "C" declarations. */
#ifdef CSX_SPOOF_BUILD_DLL
#define CSX_SPOOF_API extern "C" __declspec(dllexport)
#else
#define CSX_SPOOF_API extern "C"
#endif

/* Full run of the original 0x0040EFF0 procedure, in the original order
 * (see the evidence block above). Returns TRUE when every target that existed
 * was cleared; a target that was already absent does not fail the run.
 * `hwnd` may be NULL (then step 7 is skipped). */
CSX_SPOOF_API BOOL CSX_SpooferResetMtaSerial(HWND hwnd);

/* Individual steps (original order; exposed for A/B testing). */
CSX_SPOOF_API BOOL CSX_SpooferClearSsoCredential();        /* step 1  @0x0040F026 */
CSX_SPOOF_API BOOL CSX_SpooferClearExplorerKeyTrees();     /* step 2  @0x0040F031..0x0040F045 */
CSX_SPOOF_API BOOL CSX_SpooferClearNtDataStreams();        /* steps 3-4 @0x0040F050..0x0040F3A9 */
CSX_SPOOF_API BOOL CSX_SpooferClearMtaSharedCache();       /* step 5  @0x0040F3EA..0x0040F47B */
CSX_SPOOF_API BOOL CSX_SpooferResetMtaRegValues();         /* step 6  @0x0040F4FF..0x0040F9AF */

/* Read-only state probe (never writes). */
CSX_SPOOF_API BOOL CSX_SpooferProbe(CSXResetProbe *out);

/* Human-readable result of the last operation. ASCII, NUL-terminated,
 * single global buffer (not thread-safe — matches how the original used one
 * UI status line). */
CSX_SPOOF_API const char *CSX_SpooferLastStatus();

#ifdef __cplusplus
}
#endif
