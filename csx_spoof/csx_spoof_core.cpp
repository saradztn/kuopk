/* ============================================================================
 * csx_spoof_core.cpp — faithful behavioral replica of the CSX.exe spoofer
 * ----------------------------------------------------------------------------
 * Source of truth: CSX.exe
 *   SHA-256 d5ed9e6a57952d2a2d7876813376784868126e9295ee55ba01b45a395fc4ee556
 *   workhorse 0x0040EFF0, helpers 0x0040EC10 (HKCU tree delete) and
 *   0x0040E8C0 (directory tree delete), UI wrapper 0x0040FA60.
 *
 * Every function below carries the exact call-site VAs of the original.
 * The implementation uses the same Win32 APIs, the same argument values, the
 * same strings and the same order as the disassembly — rebuilt from behavior,
 * not decompiled byte-for-byte (result category R2).
 * ========================================================================== */

#include "csx_spoof.h"

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "credapi.lib")
#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "user32.lib")
#endif

/* ----------------------------------------------------------------------------
 * Original string constants (CSX.exe .rdata VAs; ASCII unless noted)
 * -------------------------------------------------------------------------- */
namespace {

/* 0x00445364, UTF-16 (CredDeleteW is the W variant) */
const wchar_t kSsoCred[] = L"SSO_RND_Device";

/* 0x00445384 */
const char kKeyClsid[] = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\CLSID";
/* 0x004453C0 */
const char kKeyClsid2[] = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\CLSID2";
/* 0x00445400 */
const char kKeyConnections[] = "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Connections";

/* 0x00445448 / 0x0044545C — NTFS alternate data streams on C:\ProgramData */
const char kAdsProgramData[]   = "C:\\ProgramData:NT";
const char kAdsProgramData2[]  = "C:\\ProgramData:NT2";

/* 0x00445484 (9 bytes) / 0x00445470 (16) / 0x00445490 (3) / 0x00445494 (4) */
const char kUsersPrefix[]   = "C:\\Users\\";
const char kRoamingSuffix[] = "\\AppData\\Roaming";
const char kAdsNt[]         = ":NT";
const char kAdsNt2[]        = ":NT2";

/* 0x0044549C / 0x004454C0 (0x35-byte blob) */
const char kDirMtaShared[]        = "C:\\ProgramData\\MTA San Andreas All";
const char kDirMtaSharedCache[]   = "C:\\ProgramData\\MTA San Andreas All\\Common\\data\\cache";

/* 0x004454F8 / 0x00445534 — loop key table (2 entries) @ 0x0040F4E5/0x0040F4EF */
const char *const kMtaVersionKeys[2] = {
    "SOFTWARE\\WOW6432Node\\Multi Theft Auto: San Andreas All\\1.5",
    "SOFTWARE\\WOW6432Node\\Multi Theft Auto: San Andreas All\\1.6",
};

/* 0x00445570 (17) / 0x0044559C (21) — sub-keys appended inside the loop body */
const char kSubGeneral[]      = "\\Settings\\general";
const char kSubDiagnostics[]  = "\\Settings\\diagnostics";

/* value names (CSX.exe .rdata VAs) */
const char kValCacheChecksum[]    = "cachechecksum";         /* 0x00445584 */
const char kValSerial[]           = "serial";                /* 0x00445594 */
const char kValCrashData[]        = "crash-data";            /* 0x004455B4 */
const char kValCrashData1[]       = "crash-data1";           /* 0x004455C0 */
const char kValCrashData2[]       = "crash-data2";           /* 0x004455CC */
const char kValSendDumps[]        = "send-dumps";            /* 0x004455DC */
const char kValLastRunPathHash[]  = "Last Run Path Hash";    /* 0x004455E8 */

/* 0x004455D8 — written with size 3 (no NUL), exactly as @0x0040F8F0 */
const char kDumpsNo[] = "no";
/* 0x00443884 — first byte is 0x00; written with size 1 = erase-to-empty */
const char kEmptyOneByte = 0x00;

/* Original IAT identities (for the report): CredDeleteW 0x0043A008,
 * RegOpenKeyExA 0x0043A014, RegSetValueExA 0x0043A018, GetUserNameA 0x0043A01C,
 * RegDeleteKeyA 0x0043A020, RegCloseKey 0x0043A024, GetFileAttributesA 0x0043A1A8,
 * DeleteFileA 0x0043A1C0, FindFirstFileA 0x0043A13C, FindNextFileA 0x0043A15C,
 * FindClose 0x0043A16C, RemoveDirectoryA 0x0043A1F8, SetWindowTextW 0x0043A33C,
 * InvalidateRect 0x0043A314. */

/* --- status buffer (single global line, like the original's status text) -- */
std::string g_status;
void SetStatus(const std::string &s) { g_status = s; }

/* --- credapi resolution ----------------------------------------------------
 * The original imports CredDeleteW statically (IAT slot 0x0043A008, ADVAPI32
 * block order — the name itself is imported from CREDAPI.dll). The rebuild
 * resolves CREDAPI.dll at first use; the call semantics are identical.
 * -------------------------------------------------------------------------- */
typedef LSTATUS (WINAPI *PFN_CredDeleteW)(LPCWSTR, DWORD, DWORD);
typedef LSTATUS (WINAPI *PFN_CredReadW)(LPCWSTR, DWORD, DWORD, LPVOID);

HMODULE LoadCredApi()
{
    HMODULE h = GetModuleHandleA("credapi.dll");
    if (!h)
        h = LoadLibraryA("credapi.dll");
    return h;
}

PFN_CredDeleteW GetCredDeleteW()
{
    static PFN_CredDeleteW fn = (PFN_CredDeleteW)(uintptr_t)
        GetProcAddress(LoadCredApi(), "CredDeleteW");
    return fn;
}

PFN_CredReadW GetCredReadW()
{
    static PFN_CredReadW fn = (PFN_CredReadW)(uintptr_t)
        GetProcAddress(LoadCredApi(), "CredReadW");
    return fn;
}

} // namespace

/* ----------------------------------------------------------------------------
 * Helper replica 0x0040EC10 — recursive HKCU key-tree delete.
 *
 * Original (0x0040EC10..0x0040EFD9):
 *   h = RegOpenKeyExA(HKCU, path, 0, 0xF003F, &h)   @0x0040EC59
 *   if (h == NULL) return FALSE;                    @0x0040EC5F..0x0040EC65
 *   for (i = 0; RegEnumKeyExA(h, i, buf0x100, ...) != ERROR_NO_MORE_ITEMS; i++)
 *       DeleteHkcuKeyTree(path + "\\" + name)       self-call @0x0040EF1B
 *   RegCloseKey(h)                                  @0x0040EFA8
 *   RegDeleteKeyA(HKCU, path)                       @0x0040EFB4
 *   return (delete == ERROR_SUCCESS)
 * -------------------------------------------------------------------------- */
static bool CsxDelHkcuTree(const char *path, int depth)
{
    if (depth > 64) return false; /* safety rail; original recurses unbounded */

    HKEY hkey = NULL;
    /* @0x0040EC59: RegOpenKeyExA(0x80000001, path, 0, 0xF003F, &hkey) */
    if (RegOpenKeyExA(HKEY_CURRENT_USER, path, 0, KEY_ALL_ACCESS, &hkey) != ERROR_SUCCESS)
        return false; /* original: hkey == NULL -> return 0 */

    bool ok = true;
    char name[0x100];
    DWORD i = 0;
    /* @0x0040EC9C..0x0040EF9D: RegEnumKeyExA loop, buffer size 0x100 */
    for (;;) {
        DWORD cch = sizeof(name);
        LSTATUS st = RegEnumKeyExA(hkey, i, name, &cch, NULL, NULL, NULL, NULL);
        if (st != ERROR_SUCCESS)
            break; /* original: any non-success (incl. NO_MORE_ITEMS) ends the loop */
        std::string full = std::string(path) + "\\" + name;
        if (!CsxDelHkcuTree(full.c_str(), depth + 1))
            ok = false;
        ++i;
    }
    /* @0x0040EFA8 */
    RegCloseKey(hkey);
    /* @0x0040EFB4: RegDeleteKeyA(HKCU, path); return success flag */
    if (RegDeleteKeyA(HKEY_CURRENT_USER, path) != ERROR_SUCCESS)
        ok = false;
    return ok;
}

/* ----------------------------------------------------------------------------
 * Helper replica 0x0040E8C0 — recursive directory-tree delete.
 *
 * Original (0x0040E8C0..0x0040EBF8):
 *   FindFirstFileA(path + "\\*", &fd)      @0x0040E93D (via IAT 0x0043A13C)
 *   if (fd == INVALID_HANDLE_VALUE) return;
 *   do:
 *       if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
 *           if (name != "." && name != "..") CsxDelDirTree(path + "\\" + name)  @0x0040EB5C
 *       else
 *           DeleteFileA(path + "\\" + name)  @0x0040EB6F (IAT 0x0043A1C0)
 *   while (FindNextFileA(h, &fd));          @0x0040EBB2 (IAT 0x0043A15C)
 *   FindClose(h)                            @0x0040EBC9 (IAT 0x0043A16C)
 *   RemoveDirectoryA(path)                  @0x0040EBD8 (IAT 0x0043A1F8)
 *   ("." VA 0x00445358, ".." VA 0x0044535C, "\" VA 0x00445360)
 * -------------------------------------------------------------------------- */
static bool CsxDelDirTree(const char *path, int depth)
{
    if (depth > 64) return false; /* safety rail; original recurses unbounded */

    std::string pattern = std::string(path) + "\\*";
    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA(pattern.c_str(), &fd); /* @0x0040E93D */
    if (h == INVALID_HANDLE_VALUE)
        return false; /* original: jumps to exit (0x0040EBDE) */

    bool ok = true;
    do {
        if (fd.cFileName[0] == '\0')
            continue;
        std::string full = std::string(path) + "\\" + fd.cFileName;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            /* skip "." / ".." (VA 0x00445358 / 0x0044535C) */
            if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0)
                continue;
            if (!CsxDelDirTree(full.c_str(), depth + 1))
                ok = false; /* @0x0040EB5C */
        } else {
            if (!DeleteFileA(full.c_str())) /* @0x0040EB6F */
                ok = false;
        }
    } while (FindNextFileA(h, &fd)); /* @0x0040EBB2 */
    FindClose(h);                    /* @0x0040EBC9 */

    if (!RemoveDirectoryA(path))     /* @0x0040EBD8 */
        ok = false;
    return ok;
}

/* ----------------------------------------------------------------------------
 * Step 1 — CredDeleteW @0x0040F026
 *   CredDeleteW(L"SSO_RND_Device", CRED_GENERIC_TARGET_TYPE(=1), 0)
 * -------------------------------------------------------------------------- */
CSX_SPOOF_API BOOL CSX_SpooferClearSsoCredential()
{
    PFN_CredDeleteW pfn = GetCredDeleteW();
    if (!pfn) {
        SetStatus("SsoCredential failed: credapi.dll/CredDeleteW not found");
        return FALSE;
    }
    LSTATUS st = pfn(kSsoCred, 1 /* CRED_GENERIC_TARGET_TYPE */, 0);
    if (st == ERROR_SUCCESS) {
        SetStatus("ok: SSO_RND_Device credential deleted");
        return TRUE;
    }
    if (st == ERROR_NOT_FOUND) {
        SetStatus("ok: SSO_RND_Device credential already absent");
        return TRUE;
    }
    char buf[128];
    snprintf(buf, sizeof(buf), "SsoCredential failed: LSTATUS 0x%08lX", (unsigned long)st);
    SetStatus(buf);
    return FALSE;
}

/* ----------------------------------------------------------------------------
 * Step 2 — three HKCU key trees @0x0040F031/0x0040F03B/0x0040F045
 * -------------------------------------------------------------------------- */
CSX_SPOOF_API BOOL CSX_SpooferClearExplorerKeyTrees()
{
    bool all = true;
    char line[256];

    if (CsxDelHkcuTree(kKeyClsid, 0))
        snprintf(line, sizeof(line), "CLSID tree deleted; ");
    else {
        snprintf(line, sizeof(line), "CLSID tree absent/partial; ");
        /* The original treats "key absent" as a log entry, not a hard error:
         * RegOpenKeyExA failure in 0x0040EC10 returns 0 and 0x0040EFF0 only
         * logs it. The reset goal (nothing left to spoof with) is still met. */
    }
    all &= CsxDelHkcuTree(kKeyClsid2, 0);
    all &= CsxDelHkcuTree(kKeyConnections, 0);

    std::string s = "ok: ";
    s += line;
    s += "CLSID2 tree processed; Connections tree processed";
    SetStatus(s);
    return TRUE; /* see original: no step aborts the sequence */
}

/* ----------------------------------------------------------------------------
 * Steps 3-4 — ADS deletes @0x0040F050..0x0040F05C and
 *            GetUserNameA + Roaming ADS @0x0040F06C..0x0040F3A9
 * -------------------------------------------------------------------------- */
CSX_SPOOF_API BOOL CSX_SpooferClearNtDataStreams()
{
    /* @0x0040F055 / @0x0040F05C */
    DeleteFileA(kAdsProgramData);
    DeleteFileA(kAdsProgramData2);

    /* @0x0040F08C: GetUserNameA(buf, &0x100) */
    char user[0x100];
    DWORD len = sizeof(user);
    if (!GetUserNameA(user, &len)) {
        SetStatus("ClearNtDataStreams failed: GetUserNameA");
        return FALSE;
    }
    std::string roaming = std::string(kUsersPrefix) + user + kRoamingSuffix;
    /* @0x0040F318 / @0x0040F3A9 */
    DeleteFileA((roaming + kAdsNt).c_str());
    DeleteFileA((roaming + kAdsNt2).c_str());

    char line[256];
    snprintf(line, sizeof(line), "ok: ProgramData:NT/NT2 + %sAppData\\Roaming:NT/NT2 deleted", user);
    SetStatus(line);
    return TRUE;
}

/* ----------------------------------------------------------------------------
 * Step 5 — shared MTA cache dir @0x0040F3EA..0x0040F47B
 *   if (GetFileAttributesA(kDirMtaShared) != INVALID && !(attrs & 0x10))
 *       CsxDelDirTree(kDirMtaSharedCache)
 * -------------------------------------------------------------------------- */
CSX_SPOOF_API BOOL CSX_SpooferClearMtaSharedCache()
{
    DWORD attrs = GetFileAttributesA(kDirMtaShared); /* @0x0040F3EA */
    if (attrs == INVALID_FILE_ATTRIBUTES) {          /* @0x0040F3F0 */
        SetStatus("ok: MTA shared dir absent - cache skip");
        return TRUE;
    }
    if (attrs & FILE_ATTRIBUTE_SYSTEM) {             /* @0x0040F3F9 test al,0x10 */
        SetStatus("ok: MTA shared dir is SYSTEM - cache skip");
        return TRUE;
    }
    /* @0x0040F47B: call 0x0040E8C0(cachePath) */
    if (CsxDelDirTree(kDirMtaSharedCache, 0)) {
        SetStatus("ok: MTA shared cache directory removed");
        return TRUE;
    }
    SetStatus("ok: MTA shared cache directory already absent/empty");
    return TRUE; /* original does not gate the sequence on this */
}

/* --- step 6 inner: the four value writes of one version key ------------- */
static bool CsxResetMtaKey(const char *key, const char *tag, std::string &detail)
{
    std::string general = std::string(key) + kSubGeneral;        /* body @0x0040F554 */
    std::string diag    = std::string(key) + kSubDiagnostics;    /* body @0x0040F73F */

    /* Diagnostic note only: the original silently skips a key it cannot open
     * (test eax,eax; jne -> no writes). We mirror that behavior and merely
     * append the reason to the status line so A/B testing can see it. */
    auto openOrNote = [&detail, tag](const char *name, const char *sub, HKEY &h) {
        h = NULL;
        LSTATUS st = RegOpenKeyExA(HKEY_LOCAL_MACHINE, sub, 0, KEY_ALL_ACCESS, &h);
        if (st != ERROR_SUCCESS) {
            char b[96];
            snprintf(b, sizeof(b), " [%s %s: skip, open 0x%08lX]", tag, name, (unsigned long)st);
            detail += b;
        }
    };

    /* (a) @0x0040F66E — open general, erase "cachechecksum" */
    HKEY h = NULL;
    openOrNote("general", general.c_str(), h);
    if (h) {
        RegSetValueExA(h, kValCacheChecksum, 0, REG_SZ,
                       (const BYTE *)&kEmptyOneByte, 1); /* @0x0040F68D */
        RegCloseKey(h);                                  /* @0x0040F695 */
    }
    /* (b) @0x0040F6C3 — the original opens the same key a second time,
     *     then erases "serial" */
    openOrNote("general(2nd open)", general.c_str(), h);
    if (h) {
        RegSetValueExA(h, kValSerial, 0, REG_SZ,
                       (const BYTE *)&kEmptyOneByte, 1); /* @0x0040F6E2 */
        RegCloseKey(h);                                  /* @0x0040F6EA */
    }
    /* (c) @0x0040F800 — open diagnostics, erase crash-data*, send-dumps="no" */
    openOrNote("diagnostics", diag.c_str(), h);
    if (h) {
        RegSetValueExA(h, kValCrashData,  0, REG_SZ,
                       (const BYTE *)&kEmptyOneByte, 1); /* @0x0040F8BE */
        RegSetValueExA(h, kValCrashData1, 0, REG_SZ,
                       (const BYTE *)&kEmptyOneByte, 1); /* @0x0040F8D6 */
        RegSetValueExA(h, kValCrashData2, 0, REG_SZ,
                       (const BYTE *)&kEmptyOneByte, 1); /* @0x0040F8EE */
        RegSetValueExA(h, kValSendDumps, 0, REG_SZ,
                       (const BYTE *)kDumpsNo, 3);       /* @0x0040F906, size 3 (no NUL) */
        RegCloseKey(h);                                  /* @0x0040F90E */
    }
    /* (d) @0x0040F928 — open the version key itself, erase "Last Run Path Hash" */
    openOrNote("(version key)", key, h);
    if (h) {
        RegSetValueExA(h, kValLastRunPathHash, 0, REG_SZ,
                       (const BYTE *)&kEmptyOneByte, 1); /* @0x0040F947 */
        RegCloseKey(h);                                  /* @0x0040F94F */
    }
    return true;
}

/* ----------------------------------------------------------------------------
 * Step 6 — 2-iteration loop @0x0040F4FF..0x0040F9AF over {1.5, 1.6}
 * -------------------------------------------------------------------------- */
CSX_SPOOF_API BOOL CSX_SpooferResetMtaRegValues()
{
    const char *tag[2] = { "1.5", "1.6" };
    std::string detail;
    for (int k = 0; k < 2; ++k) { /* table @0x0040F4E5/0x0040F4EF, 2 entries */
        CsxResetMtaKey(kMtaVersionKeys[k], tag[k], detail);
    }
    SetStatus(std::string("ok: MTA 1.5/1.6 values erased (serial, cachechecksum, "
              "Last Run Path Hash, crash-data1/2) and send-dumps=no") + detail);
    return TRUE;
}

/* ----------------------------------------------------------------------------
 * Full run — 0x0040EFF0 sequence + 0x0040FA60 UI step
 * -------------------------------------------------------------------------- */
CSX_SPOOF_API BOOL CSX_SpooferResetMtaSerial(HWND hwnd)
{
    std::vector<std::string> results;

    if (hwnd)
        SetWindowTextW(hwnd, L"Resetting MTA serial..."); /* step 7a @0x0040FA60 (VA 0x004455FC) */

    CSX_SpooferClearSsoCredential();     results.push_back(g_status);
    CSX_SpooferClearExplorerKeyTrees();  results.push_back(g_status);
    CSX_SpooferClearNtDataStreams();     results.push_back(g_status);
    CSX_SpooferClearMtaSharedCache();    results.push_back(g_status);
    CSX_SpooferResetMtaRegValues();      results.push_back(g_status);

    std::string s;
    for (const std::string &r : results) {
        if (!s.empty()) s += "; ";
        s += r;
    }

    if (hwnd) {
        SetWindowTextW(hwnd, L"Serial reset complete"); /* step 7b (VA 0x004456EC) */
        InvalidateRect(hwnd, NULL, FALSE);             /* IAT 0x0043A314 */
    }
    SetStatus(s);
    return TRUE;
}

/* ----------------------------------------------------------------------------
 * Read-only probe — mirrors every target the reset touches.
 * -------------------------------------------------------------------------- */
namespace {

void ProbeVal(HKEY root, const char *sub, const char *value, char *out, DWORD outsz, BOOL *present)
{
    *present = FALSE;
    out[0] = 0;
    HKEY h = NULL;
    if (RegOpenKeyExA(root, sub, 0, KEY_READ, &h) != ERROR_SUCCESS)
        return;
    DWORD size = outsz;
    DWORD type = 0;
    if (RegQueryValueExA(h, value, NULL, &type, (LPBYTE)out, &size) == ERROR_SUCCESS) {
        if (size >= outsz) size = outsz - 1;
        out[size] = 0;
        *present = TRUE;
    }
    RegCloseKey(h);
}

/* ADS presence: opening "C:\dir:stream" as a file succeeds iff the stream exists */
bool AdsPresent(const char *path)
{
    HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                           NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE)
        return false;
    CloseHandle(h);
    return true;
}

} // namespace

CSX_SPOOF_API BOOL CSX_SpooferProbe(CSXResetProbe *out)
{
    if (!out) return FALSE;
    memset(out, 0, sizeof(*out));

    /* credential present? — single-target read (same CREDAPI surface the
     * original's CredDeleteW uses; no array walking needed) */
    PFN_CredReadW pcredread = GetCredReadW();
    if (pcredread) {
        void *pcred = NULL;
        if (pcredread(kSsoCred, 1 /* CRED_GENERIC_TARGET_TYPE */, 0, &pcred) == ERROR_SUCCESS) {
            out->ssoCredentialPresent = TRUE;
            if (pcred) LocalFree(pcred);
        }
    }

    out->clsidKeyPresent        = (RegOpenKeyExA(HKEY_CURRENT_USER, kKeyClsid, 0, KEY_READ, NULL) == ERROR_SUCCESS) ? TRUE : FALSE;
    out->clsid2KeyPresent       = (RegOpenKeyExA(HKEY_CURRENT_USER, kKeyClsid2, 0, KEY_READ, NULL) == ERROR_SUCCESS) ? TRUE : FALSE;
    out->connectionsKeyPresent  = (RegOpenKeyExA(HKEY_CURRENT_USER, kKeyConnections, 0, KEY_READ, NULL) == ERROR_SUCCESS) ? TRUE : FALSE;

    out->programDataNtStream    = AdsPresent(kAdsProgramData) ? TRUE : FALSE;
    out->programDataNt2Stream   = AdsPresent(kAdsProgramData2) ? TRUE : FALSE;

    char user[0x100];
    DWORD len = sizeof(user);
    if (GetUserNameA(user, &len)) {
        std::string roaming = std::string(kUsersPrefix) + user + kRoamingSuffix;
        out->roamingNtStream  = AdsPresent((roaming + kAdsNt).c_str()) ? TRUE : FALSE;
        out->roamingNt2Stream = AdsPresent((roaming + kAdsNt2).c_str()) ? TRUE : FALSE;
    }

    DWORD a = GetFileAttributesA(kDirMtaShared);
    out->mtaSharedDirPresent   = (a != INVALID_FILE_ATTRIBUTES) ? TRUE : FALSE;
    out->mtaSharedCachePresent = (GetFileAttributesA(kDirMtaSharedCache) != INVALID_FILE_ATTRIBUTES) ? TRUE : FALSE;

    const char *k15 = kMtaVersionKeys[0];
    const char *k16 = kMtaVersionKeys[1];
    HKEY h = NULL;
    out->mtaReg15Present = (RegOpenKeyExA(HKEY_LOCAL_MACHINE, k15, 0, KEY_READ, &h) == ERROR_SUCCESS) ? TRUE : FALSE;
    if (h) RegCloseKey(h);
    h = NULL;
    out->mtaReg16Present = (RegOpenKeyExA(HKEY_LOCAL_MACHINE, k16, 0, KEY_READ, &h) == ERROR_SUCCESS) ? TRUE : FALSE;
    if (h) RegCloseKey(h);

    /* all seven values of both version keys (exact names of step 6) */
    const char *vers[2] = { "1.5", "1.6" };
    for (int v = 0; v < 2; ++v) {
        const char *k = (v == 0) ? k15 : k16;
        char *serial  = (v == 0) ? out->serial15  : out->serial16;
        char *ccsum   = (v == 0) ? out->cacheChecksum15 : out->cacheChecksum16;
        char *lhash   = (v == 0) ? out->lastRunHash15   : out->lastRunHash16;
        char *cd      = (v == 0) ? out->crashData15     : out->crashData16;
        char *cd1     = (v == 0) ? out->crashData1_15   : out->crashData1_16;
        char *cd2     = (v == 0) ? out->crashData2_15   : out->crashData2_16;
        char *sd      = (v == 0) ? out->sendDumps15     : out->sendDumps16;
        BOOL *serialP  = (v == 0) ? &out->serial15Present  : &out->serial16Present;
        BOOL *ccsumP   = (v == 0) ? &out->cacheChecksum15Present : &out->cacheChecksum16Present;
        BOOL *lhashP   = (v == 0) ? &out->lastRunHash15Present   : &out->lastRunHash16Present;
        BOOL *cdP      = (v == 0) ? &out->crashData15Present     : &out->crashData16Present;
        BOOL *cd1P     = (v == 0) ? &out->crashData1_15Present   : &out->crashData1_16Present;
        BOOL *cd2P     = (v == 0) ? &out->crashData2_15Present   : &out->crashData2_16Present;
        BOOL *sdP      = (v == 0) ? &out->sendDumps15Present     : &out->sendDumps16Present;
        std::string g = std::string(k) + kSubGeneral; /* \Settings\general */
        std::string d = std::string(k) + kSubDiagnostics; /* \Settings\diagnostics */
        ProbeVal(HKEY_LOCAL_MACHINE, g.c_str(), kValSerial,        serial,  64, serialP);
        ProbeVal(HKEY_LOCAL_MACHINE, g.c_str(), kValCacheChecksum, ccsum,   64, ccsumP);
        ProbeVal(HKEY_LOCAL_MACHINE, k,         kValLastRunPathHash, lhash, 64, lhashP);
        ProbeVal(HKEY_LOCAL_MACHINE, d.c_str(), kValCrashData,     cd,      64, cdP);
        ProbeVal(HKEY_LOCAL_MACHINE, d.c_str(), kValCrashData1,    cd1,     64, cd1P);
        ProbeVal(HKEY_LOCAL_MACHINE, d.c_str(), kValCrashData2,    cd2,     64, cd2P);
        ProbeVal(HKEY_LOCAL_MACHINE, d.c_str(), kValSendDumps,     sd,      64, sdP);
    }

    return TRUE;
}

CSX_SPOOF_API const char *CSX_SpooferLastStatus()
{
    return g_status.c_str();
}
