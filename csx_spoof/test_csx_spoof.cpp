/* ============================================================================
 * test_csx_spoof.cpp — Windows verification harness for csx_spoof.dll
 * ----------------------------------------------------------------------------
 * Build : build_csx_spoof.sh also produces bin/test_csx_spoof.exe
 * Usage : test_csx_spoof.exe [probe|reset]
 *   probe : read-only — prints every target the reset touches (before/after)
 *   reset : probe, run the full CSX 0x0040EFF0 procedure, probe again
 *
 * On Windows + MTA:SA this is the parity check against CSX.exe's
 * "R E S E T   S E R I A L" button (UI wrapper 0x0040FA60).
 * ========================================================================== */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include "csx_spoof.h"

typedef BOOL (WINAPI *PFN_Reset)(HWND);
typedef BOOL (WINAPI *PFN_Clear)(void);
typedef BOOL (WINAPI *PFN_Probe)(CSXResetProbe *);
typedef const char *(WINAPI *PFN_Status)(void);

static void PrintProbe(CSXResetProbe *p)
{
    printf("  %-28s %s\n", "SSO_RND_Device credential", p->ssoCredentialPresent ? "PRESENT" : "absent");
    printf("  %-28s %s\n", "HKCU ...\\Explorer\\CLSID",   p->clsidKeyPresent   ? "PRESENT" : "absent");
    printf("  %-28s %s\n", "HKCU ...\\Explorer\\CLSID2", p->clsid2KeyPresent  ? "PRESENT" : "absent");
    printf("  %-28s %s\n", "HKCU ...\\...\\Connections", p->connectionsKeyPresent ? "PRESENT" : "absent");
    printf("  %-28s %s\n", "C:\\ProgramData:NT   (ADS)", p->programDataNtStream  ? "PRESENT" : "absent");
    printf("  %-28s %s\n", "C:\\ProgramData:NT2  (ADS)", p->programDataNt2Stream ? "PRESENT" : "absent");
    printf("  %-28s %s\n", "<Roaming>:NT   (ADS)",       p->roamingNtStream  ? "PRESENT" : "absent");
    printf("  %-28s %s\n", "<Roaming>:NT2  (ADS)",       p->roamingNt2Stream ? "PRESENT" : "absent");
    printf("  %-28s %s\n", "MTA shared dir",             p->mtaSharedDirPresent   ? "PRESENT" : "absent");
    printf("  %-28s %s\n", "MTA shared data\\cache",     p->mtaSharedCachePresent ? "PRESENT" : "absent");
    printf("  %-28s %s\n", "HKLM ...San Andreas All\\1.5", p->mtaReg15Present ? "PRESENT" : "absent");
    printf("  %-28s %s\n", "HKLM ...San Andreas All\\1.6", p->mtaReg16Present ? "PRESENT" : "absent");
    printf("  %-28s \"%s\"\n", "1.5 crash-data",          p->mtaReg15CrashData);
    printf("  %-28s \"%s\"\n", "1.6 send-dumps",          p->mtaReg16SendDumps);
}

int main(int argc, char **argv)
{
    BOOL doReset = (argc > 1 && _stricmp(argv[1], "reset") == 0);

    char dll[512];
    GetModuleFileNameA(NULL, dll, sizeof(dll));
    char *slash = strrchr(dll, '\\');
    if (slash) strcpy_s(slash + 1, sizeof(dll) - (size_t)(slash + 1 - dll), "csx_spoof.dll");

    HMODULE h = LoadLibraryA(dll);
    if (!h) { printf("LoadLibrary(%s) failed: %lu\n", dll, GetLastError()); return 2; }

    PFN_Reset  pReset   = (PFN_Reset)  GetProcAddress(h, "CSX_SpooferResetMtaSerial");
    PFN_Probe  pProbe   = (PFN_Probe)  GetProcAddress(h, "CSX_SpooferProbe");
    PFN_Status pStatus  = (PFN_Status) GetProcAddress(h, "CSX_SpooferLastStatus");
    if (!pReset || !pProbe || !pStatus) { printf("export missing\n"); return 3; }

    CSXResetProbe before, after;
    printf("== state before ==\n");
    pProbe(&before);
    PrintProbe(&before);

    if (doReset) {
        printf("\n== running CSX_SpooferResetMtaSerial (0x0040EFF0 replica) ==\n");
        pReset(NULL);
        printf("status: %s\n", pStatus());
        printf("\n== state after ==\n");
        pProbe(&after);
        PrintProbe(&after);
    }

    FreeLibrary(h);
    return 0;
}
