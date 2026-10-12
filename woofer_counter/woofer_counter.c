/*
 * woofer_counter.c — countermeasure (مكافح) for the "Woofer" HWID-spoofing suite.
 *
 * Built from the static RE in ../woofer_re/RE_report.md (zero sample execution
 * was performed; every fingerprint below is evidenced from the sample bytes):
 *
 *  Fingerprinted artifacts (SHA-256, from the samples):
 *    Woofer.exe (packed)        e5d4272a1aa7b9c3130c89ef7108e93a89235bd63a25601a0e2fb6bd91b391d6
 *    Woofer.exe (unpacked img)  fc5a27ec16eade55a9a3873a791a2eb0e6832b8d9c0005e83f259f0fcfce7d48
 *    spoofysig.exe              30ff2e1026e6a6f8c46f8259a1d897735e240fd4ffee6758266929d6a3361fc9
 *    spoofysig.sys              93a516ebdd6bb1fe9dc5951b21fbacdff660997548bbb3df57dba92417caa33d
 *    iQVW64.SYS (embedded NAL)  4429f32db1cc70567919d7d47b844a91cf1329a6cd116f582305f3b7b60cd60b
 *    hwid.ps1                   c7c54526b07f457e58d423ab22d61a0efd78ad112be2ef0a1efe6c25013df185
 *    mac.txt                    e53a19f0f36d7e7be98522239e8ac2af3248f4fe4b046d9fe270e3907ce11401
 *    host.txt                   e2c24bcc964b30112eee56d9baacccb05a63dadc5d437d3b9c6c304e71167068b
 *
 *  Behavioral fingerprints (from RE):
 *    - spoofysig.sys hooks Disk MajorFunction[14] (IRP_MJ_DEVICE_CONTROL) and
 *      rewrites the 20-byte serial in storage-query responses: every
 *      alphanumeric byte becomes a RANDOM UPPERCASE A-Z letter (digits and
 *      lowercase disappear, punctuation kept) — RE_report.md §1 (fn 0x2370).
 *      The hook lives in kernel memory and is cleared by REBOOT only.
 *    - spoofysig.exe (modified kdmapper) loads the signed Intel NAL iQVW64.SYS
 *      as a service, kernel-maps spoofysig.sys, then erases traces
 *      (MmUnloadedDrivers / PiDDBCacheTable / g_KernelHashBucketList).
 *      User-mode counter: remove the NAL service + driver files; reboot clears
 *      the kernel hook and the mapped-module traces.
 *    - hwid.ps1 sets:  HwProfileGuid = "{a-f0-9 x8-4-4-4-12}" (lowercase, braces)
 *      and MachineGuid = "a-f0-9 x8-4-4-4-12" (lowercase, DASHED) — genuine
 *      Windows MachineGuid is 32 hex chars WITHOUT dashes. Runs
 *      Volumeid64.exe "C: XXXX-YYYY" (8 uppercase hex) on C:.
 *    - Woofer applies MACs from its pool (suite_macs.inc, from the suite's
 *      mac.txt) and hostnames from its pool (suite_hosts.inc, from host.txt);
 *      a spoofed MAC survives as the registry value NetworkAddress under the
 *      NIC class keys.
 *
 *  Modes (clean needs admin; scan/backup work mostly un-elevated):
 *    woofer_counter.exe scan               full sweep + report file
 *    woofer_counter.exe backup             snapshot originals (run BEFORE suite use)
 *    woofer_counter.exe clean [--reboot]   neutralize: kill, del service/files,
 *                                          restore from backup, advise reboot
 *    woofer_counter.exe verify             post-reboot confirmation vs backup
 *
 *  Zero sample execution; this tool is only activated on the user's own
 *  Windows machine.
 */
#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <shlobj.h>
#include <tlhelp32.h>
#include <iphlpapi.h>
#include <wincrypt.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>

static int read_backup_flat(const char *key, char out[], int outn); /* fwd */

#include "suite_macs.inc"
#include "suite_hosts.inc"

typedef struct { const char *name; const char *sha256; unsigned size; } KnownFile;
static const KnownFile KNOWN[] = {
    {"Woofer.exe (packed)",    "e5d4272a1aa7b9c3130c89ef7108e93a89235bd63a25601a0e2fb6bd91b391d6", 99328},
    {"Woofer.exe (unpacked)",  "fc5a27ec16eade55a9a3873a791a2eb0e6832b8d9c0005e83f259f0fcfce7d48", 143872},
    {"spoofysig.exe",          "30ff2e1026e6a6f8c46f8259a1d897735e240fd4ffee6758266929d6a3361fc9", 136704},
    {"spoofysig.sys",          "93a516ebdd6bb1fe9dc5951b21fbacdff660997548bbb3df57dba92417caa33d", 11984},
    {"iQVW64.SYS (Intel NAL)", "4429f32db1cc70567919d7d47b844a91cf1329a6cd116f582305f3b7b60cd60b", 34568},
    {"hwid.ps1",               "c7c54526b07f457e58d423ab22d61a0efd78ad112be2ef0a1efe6c25013df185", 3270},
    {"mac.txt",                "e53a19f0f36d7e7be98522239e8ac2af3248f4fe4b046d9fe270e3907ce11401", 7054},
    {"host.txt",               "e2c24bcc964b30112eee56d9baacccb05a63dadc5d437d3b9c6c304e71167068b", 3158},
};
#define KNOWN_N (int)(sizeof(KNOWN)/sizeof(KNOWN[0]))

static const wchar_t *PROCS[] = {L"Woofer.exe", L"spoofysig.exe", L"Volumeid64.exe"};
#define PROCS_N (int)(sizeof(PROCS)/sizeof(PROCS[0]))

typedef struct { USHORT Length, MaximumLength; PWSTR Buffer; } RtlUserStr;

/* ------------------------------------------------------------------ state */
static wchar_t g_exedir[MAX_PATH];
static wchar_t g_report[MAX_PATH];
static wchar_t g_backup[MAX_PATH];
static FILE   *g_rep = 0;
static int     g_admin = 0;
static int     g_bad = 0, g_warn = 0, g_ok = 0;
static int     g_walk_depth = 0;
static char    g_cur_machineguid[128]  = "";
static char    g_cur_hwprofileguid[128]= "";
static char    g_cur_hostname[128]     = "";
static char    g_cur_volsnc[16]        = "";
static char    g_cur_diskserial[8][96] = {0};

/* ------------------------------------------------------------------ util */
static char g_tmpstr[1024];
static const char *w2a(const wchar_t *w){
    if(!w) return "";
    WideCharToMultiByte(CP_UTF8, 0, w, -1, g_tmpstr, (int)sizeof g_tmpstr, 0, NULL);
    return g_tmpstr;
}
static void say(int lvl, const char *what, const char *detail){
    const char *tag = (lvl==0)?" OK ":(lvl==1)?"WARN":"BAD ";
    if(lvl==0) g_ok++; else if(lvl==1) g_warn++; else g_bad++;
    printf("  [%s] %-20s %s\n", tag, what, detail);
    if(g_rep){ fprintf(g_rep, "  [%s] %-20s %s\n", tag, what, detail); fflush(g_rep); }
}
static void say_w(int lvl, const char *what, const wchar_t *detail){ say(lvl, what, w2a(detail)); }
static void sayf(int lvl, const char *what, const char *fmt, ...){
    char d[1024]; va_list ap; va_start(ap, fmt);
    vsnprintf(d, sizeof d, fmt, ap); va_end(ap);
    say(lvl, what, d);
}
static void sec(const char *s){
    printf("%s\n", s);
    if(g_rep){ fprintf(g_rep, "%s\n", s); fflush(g_rep); }
}
static void tolower_str(char *s){ for(;*s;s++){ if(*s>='A'&&*s<='Z') *s+=32; } }
static int str_icontains(const wchar_t *hay, const wchar_t *needle){
    for(const wchar_t *p=hay; *p; p++){
        const wchar_t *a=p, *b=needle;
        while(*a && *b){
            wchar_t ca=*a, cb=*b;
            if(ca>='A'&&ca<='Z') ca+=32;
            if(cb>='A'&&cb<='Z') cb+=32;
            if(ca!=cb) break; a++; b++;
        }
        if(!*b) return 1;
    }
    return 0;
}
static unsigned dw_le(const unsigned char *p){
    return (unsigned)p[0] | ((unsigned)p[1]<<8) | ((unsigned)p[2]<<16) | ((unsigned)p[3]<<24);
}

static int sha256_file(const wchar_t *path, char out[65]){
    HANDLE h=CreateFileW(path, GENERIC_READ, FILE_SHARE_READ|FILE_SHARE_DELETE, 0,
                         OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
    if(h==INVALID_HANDLE_VALUE) return 0;
    int ok=0;
    HCRYPTPROV prov=0; HCRYPTHASH hash=0;
    if(CryptAcquireContextW(&prov, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)){
        if(CryptCreateHash(prov, CALG_SHA_256, 0, 0, &hash)){
            ok=1;
            char buf[8192]; DWORD got;
            for(;;){
                if(!ReadFile(h, buf, sizeof buf, &got, NULL) || got==0) break;
                CryptHashData(hash, (BYTE*)buf, got, 0);
            }
            BYTE dv[32]; DWORD dl=32;
            if(!CryptGetHashParam(hash, HP_HASHVAL, dv, &dl, 0) || dl!=32) ok=0;
            else for(int i=0;i<32;i++) sprintf(out+2*i, "%02x", dv[i]);
        }
        CryptReleaseContext(prov, 0);
    }
    CloseHandle(h);
    return ok;
}
static int file_size(const wchar_t *path, unsigned *sz){
    WIN32_FILE_ATTRIBUTE_DATA fa;
    if(!GetFileAttributesExW(path, GetFileExInfoStandard, &fa)) return 0;
    *sz=(unsigned)fa.nFileSizeLow;
    return 1;
}
static int match_known(const char *hex){
    for(int i=0;i<KNOWN_N;i++)
        if(strcmp(hex, KNOWN[i].sha256)==0) return i;
    return -1;
}
static int name_looks_suite(const wchar_t *fn){
    wchar_t t[256]; int n=(int)wcslen(fn); if(n>255) return 0;
    wcscpy(t, fn);
    for(wchar_t *p=t;*p;p++){ if(*p>='A'&&*p<='Z') *p+=32; }
    int isexe = n>=4 && _wcsicmp(t+n-4, L".exe")==0;
    int issys = n>=4 && _wcsicmp(t+n-4, L".sys")==0;
    return (wcsncmp(t, L"woof", 4)==0 && isexe)
        || _wcsicmp(t, L"spoofysig.exe")==0 || _wcsicmp(t, L"spoofysig.sys")==0
        || (wcsncmp(t, L"iqvw64", 6)==0 && issys)
        || _wcsicmp(t, L"hwid.ps1")==0
        || _wcsicmp(t, L"volumeid64.exe")==0;
}

/* ------------------------------------------------------------- file scan */
static int s_clean = 0;
static const wchar_t *SKIP_DIRS[] = {
    L"$RECYCLE.BIN", L"System Volume Information", L".git", L"node_modules",
    L".cache", L".venv", L".vs", L"AppData\\Local\\Temp"
};
static int skip_dir(const wchar_t *name){
    for(int i=0;i<(int)(sizeof SKIP_DIRS/sizeof SKIP_DIRS[0]);i++)
        if(_wcsicmp(name, SKIP_DIRS[i])==0) return 1;
    return 0;
}
static void scan_dir(const wchar_t *dir){
    if(g_walk_depth > 9) return;
    wchar_t pat[MAX_PATH+16];
    if((unsigned)wcslen(dir)+3 > MAX_PATH) return;
    wsprintfW(pat, L"%s\\*", dir);
    WIN32_FIND_DATAW fd;
    HANDLE h=FindFirstFileW(pat, &fd);
    if(h==INVALID_HANDLE_VALUE) return;
    g_walk_depth++;
    do {
        if(_wcsicmp(fd.cFileName, L".")==0 || _wcsicmp(fd.cFileName, L"..")==0) continue;
        wchar_t full[MAX_PATH];
        if((unsigned)wcslen(dir)+3+(unsigned)wcslen(fd.cFileName) >= MAX_PATH) continue;
        wsprintfW(full, L"%s\\%s", dir, fd.cFileName);
        if(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY){
            if(!(fd.dwFileAttributes & FILE_ATTRIBUTE_SYSTEM) && !skip_dir(fd.cFileName))
                scan_dir(full);
        } else {
            int hit=0; char hex[65]="";
            if(name_looks_suite(fd.cFileName)){
                if(sha256_file(full, hex)){
                    int k=match_known(hex);
                    if(k>=0){ hit=1; sayf(2, "suite file (hash)", "%s  [%s]", w2a(full), KNOWN[k].name); }
                    else     say_w(1, "suite-named file", full);
                } else say_w(1, "suite-named file (unreadable)", full);
            } else {
                unsigned sz=0;
                if(file_size(full, &sz)){
                    for(int k=0;k<KNOWN_N;k++) if(sz==KNOWN[k].size){
                        if(sha256_file(full, hex) && match_known(hex)==k){
                            hit=1; sayf(2, "suite file (hash)", "%s  [%s]", w2a(full), KNOWN[k].name);
                        }
                        break;
                    }
                }
            }
            if(hit && s_clean){
                SetFileAttributesW(full, FILE_ATTRIBUTE_NORMAL);
                if(DeleteFileW(full)) say_w(0, "[clean] deleted", full);
                else sayf(1, "[clean] delete failed", "%s err %lu", w2a(full), (unsigned)GetLastError());
            }
        }
    } while(FindNextFileW(h, &fd));
    FindClose(h);
    g_walk_depth--;
}
static void add_root(const wchar_t *dir){
    if(dir && dir[0] && GetFileAttributesW(dir)!=INVALID_FILE_ATTRIBUTES)
        scan_dir(dir);
}
static void check_files(int clean){
    s_clean = clean;
    sec(clean ? "[files] deleting suite fingerprints by exact hash"
              : "[files] scanning for suite fingerprints (8 known SHA-256 + names)");
    int before_bad = g_bad;
    wchar_t tmp[MAX_PATH]={0}, tmp2[MAX_PATH]={0}, appd[MAX_PATH]={0},
            locald[MAX_PATH]={0}, progd[MAX_PATH]={0}, windtmp[MAX_PATH]={0};
    GetTempPathW(MAX_PATH, tmp);
    GetEnvironmentVariableW(L"TMP", tmp2, MAX_PATH);
    SHGetFolderPathW(NULL, CSIDL_APPDATA, NULL, 0, appd);
    SHGetFolderPathW(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, locald);
    GetEnvironmentVariableW(L"PROGRAMDATA", progd, MAX_PATH);
    wchar_t wind[MAX_PATH]; GetWindowsDirectoryW(wind, MAX_PATH);
    wsprintfW(windtmp, L"%s\\Temp", wind);
    add_root(g_exedir);
    add_root(tmp);
    if(tmp2[0] && _wcsicmp(tmp2, tmp)!=0) add_root(tmp2);
    add_root(appd);
    add_root(locald);
    add_root(progd);
    add_root(windtmp);
    {   /* C:\Users\*\Downloads */
        WIN32_FIND_DATAW fd;
        HANDLE h=FindFirstFileW(L"C:\\Users\\*", &fd);
        if(h!=INVALID_HANDLE_VALUE){
            do {
                if(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY){
                    wchar_t dl[MAX_PATH];
                    wsprintfW(dl, L"C:\\Users\\%s\\Downloads", fd.cFileName);
                    add_root(dl);
                }
            } while(FindNextFileW(h, &fd));
            FindClose(h);
        }
    }
    if(g_bad==before_bad)
        say(0, "files", "no suite fingerprints found (exe dir, temp, appdata, programdata, home, downloads)");
    else
        say(2, "files", "suite fingerprints present — see lines above");
}

/* ------------------------------------------------------------- processes */
static void get_cmdline(HANDLE h, RtlUserStr *us){
    static NTSTATUS (NTAPI *NtQIP)(HANDLE, ULONG, PVOID, ULONG, PULONG) = 0;
    if(!NtQIP) NtQIP=(NTSTATUS (NTAPI *)(HANDLE, ULONG, PVOID, ULONG, PULONG))
                   GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess");
    if(!NtQIP) return;
    NtQIP(h, 60 /* ProcessCommandLine */, us, sizeof *us, NULL);
}
static int g_kill = 0;
static void proc_cb(const wchar_t *name, DWORD pid, const wchar_t *cmdline){
    for(int i=0;i<PROCS_N;i++){
        if(_wcsicmp(name, PROCS[i])==0){
            if(g_kill){
                HANDLE h=OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
                if(h){
                    if(TerminateProcess(h, 1)) sayf(0, "[clean] killed", "%s (pid %lu)", w2a(name), pid);
                    else sayf(1, "[clean] kill failed", "%s (pid %lu) err %lu", w2a(name), pid, GetLastError());
                    CloseHandle(h);
                }
            } else
                sayf(2, "suite process", "%s (pid %lu)", w2a(name), pid);
            return;
        }
    }
    if(_wcsicmp(name, L"powershell.exe")==0 || _wcsicmp(name, L"pwsh.exe")==0){
        if(cmdline && str_icontains(cmdline, L"hwid.ps1")){
            if(g_kill){
                HANDLE h=OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
                if(h){
                    if(TerminateProcess(h, 1)) sayf(0, "[clean] killed", "%s (hwid.ps1, pid %lu)", w2a(name), pid);
                    else sayf(1, "[clean] kill failed", "%s (pid %lu) err %lu", w2a(name), pid, GetLastError());
                    CloseHandle(h);
                }
            } else
                sayf(2, "hwid.ps1 runner", "%s (pid %lu)", w2a(name), pid);
        }
    }
}
static void check_processes(int kill){
    sec("[processes] Woofer.exe / spoofysig.exe / Volumeid64.exe / powershell(hwid.ps1)");
    g_kill = kill;
    HANDLE snap=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if(snap==INVALID_HANDLE_VALUE) return;
    PROCESSENTRY32W pe; pe.dwSize=sizeof pe;
    if(Process32FirstW(snap, &pe)){
        do {
            const wchar_t *cmd=NULL; RtlUserStr us={0,0,0};
            HANDLE h=OpenProcess(PROCESS_QUERY_INFORMATION, 0, pe.th32ProcessID);
            if(h){
                get_cmdline(h, &us);
                cmd = us.Buffer ? (const wchar_t*)us.Buffer : NULL;
                CloseHandle(h);
            }
            proc_cb(pe.szExeFile, pe.th32ProcessID, cmd);
        } while(Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
}

/* --------------------------------------------------------- NAL service */
static int svc_match(const wchar_t *key, const wchar_t *img, const wchar_t *disp){
    if(_wcsicmp(key, L"iQVW64")==0) return 1;
    if(img  && str_icontains(img,  L"iqvw64")) return 1;
    if(disp && str_icontains(disp, L"Network Adapter Diagnostic")) return 1;
    return 0;
}
static int g_nal_loaded = 0;
static void check_service(int clean){
    sec("[service] iQVW64 / Intel NAL (kdmapper carrier)");
    int found=0;
    HKEY hk;
    if(RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services",
                     0, KEY_READ, &hk)==ERROR_SUCCESS){
        wchar_t name[128]; DWORD sz;
        for(DWORD i=0;;i++){
            sz=(DWORD)sizeof name/2;
            if(RegEnumKeyExW(hk, i, name, &sz, NULL, NULL, NULL, NULL)!=ERROR_SUCCESS) break;
            wchar_t sub[256]; wsprintfW(sub, L"SYSTEM\\CurrentControlSet\\Services\\%s", name);
            HKEY k2; wchar_t img[1024]={0}, disp[256]={0};
            if(RegOpenKeyExW(HKEY_LOCAL_MACHINE, sub, 0, KEY_READ, &k2)==ERROR_SUCCESS){
                DWORD tsz=(DWORD)sizeof img, dsz=(DWORD)sizeof disp;
                RegQueryValueExW(k2, L"ImagePath", 0, NULL, (LPBYTE)img, &tsz);
                RegQueryValueExW(k2, L"DisplayName", 0, NULL, (LPBYTE)disp, &dsz);
                RegCloseKey(k2);
            }
            if(svc_match(name, img[0]?img:NULL, disp[0]?disp:NULL)){
                found=1;
                if(clean){
                    SC_HANDLE scm=OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
                    if(scm){
                        SC_HANDLE sv=OpenServiceW(scm, name, SERVICE_ALL_ACCESS);
                        if(sv){
                            SERVICE_STATUS ss;
                            if(QueryServiceStatus(sv, &ss) && ss.dwCurrentState==SERVICE_RUNNING){
                                say_w(1, "stopping service", name);
                                ControlService(sv, SERVICE_CONTROL_STOP, &ss);
                                for(int w=0;w<25;w++){
                                    Sleep(200);
                                    if(QueryServiceStatus(sv,&ss) && ss.dwCurrentState==SERVICE_STOPPED) break;
                                }
                            }
                            if(DeleteService(sv)) say_w(0, "service deleted", name);
                            else sayf(1, "DeleteService failed", "%s err %lu (reboot will drop it)", w2a(name), GetLastError());
                        } else sayf(1, "OpenService failed", "%s err %lu", w2a(name), GetLastError());
                        CloseServiceHandle(scm);
                    }
                } else
                    say_w(2, "NAL service present", name);
            }
        }
        RegCloseKey(hk);
    }
    HANDLE d=CreateFileW(L"\\\\.\\Nal", 0, FILE_SHARE_READ|FILE_SHARE_WRITE, 0, OPEN_EXISTING, 0, 0);
    if(d!=INVALID_HANDLE_VALUE){
        CloseHandle(d); g_nal_loaded=1;
        say(2, "NAL device loaded", "\\Device\\Nal is openable — kernel-mapped module active");
    } else if(!found && !clean) say(0, "service", "no iQVW64 / NAL service, no \\Device\\Nal");
    if(clean && !found) say(0, "service", "nothing to remove");
}

/* ----------------------------------------------------- registry + values */
static void read_reg_sz(HKEY root, const wchar_t *sub, const wchar_t *val, char out[], int outn){
    out[0]=0;
    HKEY hk;
    if(RegOpenKeyExW(root, sub, 0, KEY_READ, &hk)!=ERROR_SUCCESS) return;
    wchar_t w[512]; DWORD sz=(DWORD)sizeof w;
    if(RegQueryValueExW(hk, val, 0, NULL, (LPBYTE)w, &sz)==ERROR_SUCCESS)
        WideCharToMultiByte(CP_UTF8, 0, w, -1, out, outn, 0, NULL);
    RegCloseKey(hk);
}
static void check_registry(void){
    sec("[registry] MachineGuid / HwProfileGuid tamper signatures");
    read_reg_sz(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Cryptography",
                L"MachineGuid", g_cur_machineguid, (int)sizeof g_cur_machineguid);
    read_reg_sz(HKEY_LOCAL_MACHINE,
                L"SYSTEM\\CurrentControlSet\\Control\\IDConfigDB\\Hardware Profiles\\0001",
                L"HwProfileGuid", g_cur_hwprofileguid, (int)sizeof g_cur_hwprofileguid);
    int dashed=0, allhex=1;
    for(const char *p=g_cur_machineguid;*p;p++){
        if(*p=='-') dashed=1;
        if(!((*p>='0'&&*p<='9')||(*p>='a'&&*p<='f')||(*p>='A'&&*p<='F'))) allhex=0;
    }
    if(dashed && allhex && strlen(g_cur_machineguid)==36)
        sayf(2, "MachineGuid", "%s — DASHED 36-char form = hwid.ps1 fingerprint (genuine: 32 hex, no dashes)", g_cur_machineguid);
    else if(g_cur_machineguid[0]) sayf(0, "MachineGuid", "%s", g_cur_machineguid);
    else say(1, "MachineGuid", "unreadable (run elevated?)");
    int alllower=1;
    for(const char *p=g_cur_hwprofileguid;*p;p++)
        if((*p>='A'&&*p<='F')) alllower=0;
    if(g_cur_hwprofileguid[0] && alllower && strchr(g_cur_hwprofileguid,'{'))
        sayf(1, "HwProfileGuid", "%s — all-lowercase {8-4-4-4-12} (hwid.ps1 writes lowercase; genuine usually uppercase)", g_cur_hwprofileguid);
    else if(g_cur_hwprofileguid[0]) sayf(0, "HwProfileGuid", "%s", g_cur_hwprofileguid);
    else say(1, "HwProfileGuid", "unreadable");
}

/* ------------------------------------------------------------- volume */
static void check_volume(void){
    sec("[volume] C: serial (hwid.ps1 → Volumeid64.exe \"C: XXXX-YYYY\")");
    DWORD serial=0;
    if(GetVolumeInformationW(L"C:\\", NULL, 0, &serial, NULL, NULL, NULL, 0)){
        sprintf(g_cur_volsnc, "%08lX", (unsigned long)serial);
        sayf(0, "volume serial C:", "%s (backup comparison at verify)", g_cur_volsnc);
    } else say(1, "volume serial C:", "unreadable");
}

/* ------------------------------------------------------------ hostname */
static int host_in_suite(const char *h){
    char low[128]; strncpy(low, h, sizeof low-1); low[sizeof low-1]=0;
    tolower_str(low);
    for(int i=0;i<SUITE_HOSTS_N;i++){
        char t[128];
        WideCharToMultiByte(CP_UTF8, 0, SUITE_HOSTS[i], -1, t, sizeof t, 0, NULL);
        tolower_str(t);
        if(strcmp(low, t)==0) return 1;
    }
    return 0;
}
static void check_host(void){
    sec("[hostname] suite pool membership (host.txt)");
    wchar_t wn[128]; DWORD sz=(DWORD)sizeof wn/2;
    if(GetComputerNameExW(ComputerNamePhysicalDnsHostname, wn, &sz)){
        WideCharToMultiByte(CP_UTF8, 0, wn, -1, g_cur_hostname, (int)sizeof g_cur_hostname, 0, NULL);
        if(host_in_suite(g_cur_hostname))
            sayf(2, "hostname", "%s — IN the suite's host.txt pool", g_cur_hostname);
        else
            sayf(0, "hostname", "%s", g_cur_hostname);
    } else { g_cur_hostname[0]=0; say(1, "hostname", "unreadable"); }
}

/* ----------------------------------------------------------------- MAC */
static int mac_in_suite(const unsigned char *m){
    char t[13]; for(int i=0;i<6;i++) sprintf(t+2*i, "%02X", m[i]); t[12]=0;
    for(int i=0;i<SUITE_MACS_N;i++)
        if(strcmp(t, SUITE_MACS[i])==0) return 1;
    return 0;
}
static void check_mac(int clean){
    sec("[mac] NIC addresses vs suite pool + NetworkAddress overrides");
    IP_ADAPTER_INFO *ai=0; DWORD sz=0;
    if(GetAdaptersInfo(NULL, &sz)==ERROR_BUFFER_OVERFLOW){
        ai=(IP_ADAPTER_INFO*)GlobalAlloc(GMEM_MOVEABLE, sz);
        if(ai && GetAdaptersInfo(ai, &sz)==NO_ERROR){
            for(IP_ADAPTER_INFO *p=ai;p;p=p->Next){
                if(p->AddressLength==6){
                    char t[20]; for(int i=0;i<6;i++) sprintf(t+3*i, "%02X:", p->Address[i]); t[18]=0;
                    if(mac_in_suite(p->Address))
                        sayf(2, "MAC in suite pool", "%s (%s)", t, p->Description);
                    else
                        sayf(0, "MAC", "%s (%s)", t, p->Description);
                }
            }
        }
        GlobalFree(ai);
    }
    HKEY hk;
    int over=0;
    if(RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e972-e325-11ce-bfc1-08002be10318}",
        0, clean?(KEY_READ|KEY_WRITE):KEY_READ, &hk)==ERROR_SUCCESS){
        for(DWORD i=0;i<64;i++){
            wchar_t sub[16]; wsprintfW(sub, L"%04lu", i);
            HKEY k2;
            if(RegOpenKeyExW(hk, sub, 0, clean?(KEY_READ|KEY_WRITE):KEY_READ, &k2)!=ERROR_SUCCESS) continue;
            wchar_t v[64]; DWORD vsz=(DWORD)sizeof v;
            if(RegQueryValueExW(k2, L"NetworkAddress", 0, NULL, (LPBYTE)v, &vsz)==ERROR_SUCCESS){
                over++;
                if(clean){
                    if(RegDeleteValueW(k2, L"NetworkAddress")==ERROR_SUCCESS)
                        sayf(0, "[clean] MAC override removed", "%s\\%s (was %s — permanent MAC returns after NIC reset/reboot)", w2a(sub), w2a(L"NetworkAddress"), w2a(v));
                    else sayf(1, "[clean] override delete failed", "%s err %lu", w2a(sub), GetLastError());
                } else
                    sayf(2, "MAC override (registry)", "%s = %s", w2a(sub), w2a(v));
            }
            RegCloseKey(k2);
        }
        RegCloseKey(hk);
    }
    if(!over && !clean) say(0, "mac overrides", "no NetworkAddress overrides");
}

/* ---------------------------------------------------------- disk serial */
static void check_disk(void){
    sec("[disk] storage serials vs spoofysig.sys randomizer signature");
    sec("       (hook rewrites every alnum byte to random A-Z; digits/lowercase vanish)");
    int any=0;
    for(int i=0;i<8;i++){
        wchar_t dev[32]; wsprintfW(dev, L"\\\\.\\PhysicalDrive%d", i);
        HANDLE h=CreateFileW(dev, GENERIC_READ, FILE_SHARE_READ|FILE_SHARE_WRITE, 0, OPEN_EXISTING, 0, 0);
        if(h==INVALID_HANDLE_VALUE) continue;
        g_cur_diskserial[i][0]=0;
        DWORD got=0;
        unsigned char out[16384];
        struct { DWORD PropertyId; DWORD QueryType; DWORD Reserved; } q = {0,0,0};
        if(DeviceIoControl(h, 0x2D1400 /*IOCTL_STORAGE_QUERY_PROPERTY*/, &q, sizeof q,
                           out, sizeof out, &got, NULL) && got>=40){
            /* STORAGE_DEVICE_DESCRIPTOR:
               0x00 Size | 0x04 DeviceType | 0x08 TypeMod | 0x0C BusTypeFactor
               0x10 RawDataLength | 0x14 VendorLen | 0x15 ProductLen
               0x16 ProdRevLen | 0x17 SerialLen | 0x18 BusType
               0x1A Vendor[VL] Product[PL] ProdRev[PRL] Serial[SNL]   (lengths = bytes) */
            int VL=out[0x14], PL=out[0x15], PRL=out[0x16], SNL=out[0x17];
            unsigned size=dw_le(out);
            int so=0x1A+VL+PL+PRL;
            if(SNL>0 && so+SNL<=(int)size && so+SNL<=(int)got && (SNL&1)==0){
                WideCharToMultiByte(CP_UTF8, 0, (const wchar_t*)(out+so), SNL/2,
                                    g_cur_diskserial[i], (int)sizeof g_cur_diskserial[i]-1, 0, NULL);
            }
        }
        CloseHandle(h);
        if(!g_cur_diskserial[i][0]) continue;
        any=1;
        int has_digit=0, has_lower=0, has_AZ=0;
        for(const char *p=g_cur_diskserial[i];*p;p++){
            if(*p>='0'&&*p<='9') has_digit=1;
            else if(*p>='a'&&*p<='z') has_lower=1;
            else if(*p>='A'&&*p<='Z') has_AZ=1;
        }
        int spoofed_like = has_AZ && !has_digit && !has_lower;
        char key[32], b[128];
        sprintf(key, "DiskSerial%d", i);
        if(read_backup_flat(key, b, (int)sizeof b)){
            if(strcmp(b, g_cur_diskserial[i])==0)
                sayf(0, "disk serial %d", "%s — matches backup (original)", g_cur_diskserial[i]);
            else if(spoofed_like)
                sayf(2, "disk serial %d", "%s — SPOOFED-LIKE vs backup %s (all-A-Z alnum, digits/lowercase stripped)", g_cur_diskserial[i], b);
            else
                sayf(1, "disk serial %d", "%s — differs from backup %s (verify hardware manually)", g_cur_diskserial[i], b);
        } else if(spoofed_like){
            sayf(2, "disk serial %d", "%s — SPOOFED-LIKE (no digits/lowercase in alnum part; spoofysig.sys randomizer class; no backup to confirm)", g_cur_diskserial[i]);
        } else {
            sayf(0, "disk serial %d", "%s", g_cur_diskserial[i]);
        }
    }
    if(!any) say(1, "disk serial", "no physical drive serial readable (needs admin)");
}

/* ------------------------------------------------------------ backup */
static int g_have_backup = 0;
static int read_backup_flat(const char *key, char out[], int outn){
    out[0]=0;
    if(!g_have_backup) return 0;
    FILE *f=_wfopen(g_backup, L"r");
    if(!f) return 0;
    char line[1024]; char wk[64];
    sprintf(wk, "\"%s\"", key);
    int rc=0;
    while(fgets(line, sizeof line, f)){
        char *p=line; while(*p==' '||*p=='\t') p++;
        if(strncmp(p, wk, strlen(wk))==0){
            p+=strlen(wk);
            while(*p==' '||*p==':'||*p==',') p++;
            if(*p=='\"'){
                p++; int i=0;
                while(*p && *p!='\"' && i<outn-1) out[i++]=*p++;
                out[i]=0; rc=1; break;
            }
        }
    }
    fclose(f);
    return rc;
}
static void do_backup(void){
    check_registry(); check_volume(); check_host(); check_disk();
    g_have_backup=1;
    FILE *f=_wfopen(g_backup, L"w");
    if(!f){ say(2, "backup", "cannot write backup file"); return; }
    SYSTEMTIME st; GetLocalTime(&st);
    fprintf(f, "{\n");
    fprintf(f, "  \"tool\": \"woofer_counter backup v1\",\n");
    fprintf(f, "  \"local_time\": \"%04d-%02d-%02d %02d:%02d:%02d\",\n",
            st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    fprintf(f, "  \"MachineGuid\": \"%s\",\n",   g_cur_machineguid);
    fprintf(f, "  \"HwProfileGuid\": \"%s\",\n", g_cur_hwprofileguid);
    fprintf(f, "  \"VolumeSerialC\": \"%s\",\n", g_cur_volsnc);
    fprintf(f, "  \"Hostname\": \"%s\",\n",     g_cur_hostname);
    for(int i=0;i<8;i++)
        if(g_cur_diskserial[i][0])
            fprintf(f, "  \"DiskSerial%d\": \"%s\",\n", i, g_cur_diskserial[i]);
    fprintf(f, "}\n");
    fclose(f);
    say(0, "backup written", w2a(g_backup));
    say(0, "MachineGuid",   g_cur_machineguid);
    say(0, "HwProfileGuid", g_cur_hwprofileguid);
    say(0, "VolumeSerialC", g_cur_volsnc);
    say(0, "Hostname",      g_cur_hostname);
    printf("\n[backup] run this BEFORE using any spoofer; 'clean' restores from it.\n");
}

/* ------------------------------------------------------------- verify */
static void do_verify(void){
    sec("== verify (post-reboot) ==");
    check_processes(0);
    check_service(0);
    check_files(0);
    check_registry();
    check_volume();
    check_host();
    check_mac(0);
    check_disk();
    char b[256];
    sec("[verify] comparison vs backup");
    if(read_backup_flat("MachineGuid", b, sizeof b)){
        char cur[128];
        read_reg_sz(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Cryptography", L"MachineGuid", cur, sizeof cur);
        if(strcmp(b, cur)==0) say(0, "MachineGuid", "restored — matches backup");
        else sayf(2, "MachineGuid", "NOT restored: %s (backup %s)", cur, b);
    } else say(1, "MachineGuid", "no backup on file — cannot verify");
    if(g_nal_loaded) say(2, "NAL", "still loaded after reboot?");
}

/* ---------------------------------------------------------------- clean */
static void do_clean(int reboot){
    if(!g_admin)
        printf("\n[clean] NOT ELEVATED — service/registry/delete actions will fail. Re-run as Administrator.\n\n");
    check_processes(1);                     /* kill suite processes */
    check_service(1);                       /* stop+delete NAL service */
    check_files(1);                         /* delete by exact hash */
    check_mac(1);                           /* remove NetworkAddress overrides */
    sec("[restore] from backup");
    char b[256];
    if(read_backup_flat("MachineGuid", b, sizeof b)){
        char cur[128];
        read_reg_sz(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Cryptography", L"MachineGuid", cur, sizeof cur);
        if(strcmp(b, cur)!=0){
            HKEY hk;
            if(RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Cryptography", 0, KEY_SET_VALUE, &hk)==ERROR_SUCCESS){
                wchar_t w[256]; MultiByteToWideChar(CP_UTF8, 0, b, -1, w, 256);
                if(RegSetValueExW(hk, L"MachineGuid", 0, REG_SZ, (LPBYTE)w, (DWORD)((wcslen(w)+1)*2)))
                    sayf(0, "MachineGuid", "restored to %s", b);
                else sayf(1, "MachineGuid", "set failed err %lu", GetLastError());
                RegCloseKey(hk);
            }
        }
    } else say(1, "MachineGuid", "no backup — not restored (run 'backup' next time before the suite)");
    if(read_backup_flat("HwProfileGuid", b, sizeof b)){
        char cur[128];
        read_reg_sz(HKEY_LOCAL_MACHINE,
                    L"SYSTEM\\CurrentControlSet\\Control\\IDConfigDB\\Hardware Profiles\\0001",
                    L"HwProfileGuid", cur, sizeof cur);
        if(strcmp(b, cur)!=0){
            HKEY hk;
            if(RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                    L"SYSTEM\\CurrentControlSet\\Control\\IDConfigDB\\Hardware Profiles\\0001",
                    0, KEY_SET_VALUE, &hk)==ERROR_SUCCESS){
                wchar_t w[256]; MultiByteToWideChar(CP_UTF8, 0, b, -1, w, 256);
                if(RegSetValueExW(hk, L"HwProfileGuid", 0, REG_SZ, (LPBYTE)w, (DWORD)((wcslen(w)+1)*2)))
                    sayf(0, "HwProfileGuid", "restored to %s", b);
                else sayf(1, "HwProfileGuid", "set failed err %lu", GetLastError());
                RegCloseKey(hk);
            }
        }
    } else say(1, "HwProfileGuid", "no backup — not restored");
    if(read_backup_flat("Hostname", b, sizeof b)){
        wchar_t wn[128]; DWORD wsz=(DWORD)sizeof wn/2;
        if(GetComputerNameExW(ComputerNamePhysicalDnsHostname, wn, &wsz)){
            char cur[128];
            WideCharToMultiByte(CP_UTF8, 0, wn, -1, cur, sizeof cur, 0, NULL);
            if(strcmp(b, cur)!=0){
                wchar_t wb[128]; MultiByteToWideChar(CP_UTF8, 0, b, -1, wb, 128);
                if(SetComputerNameExW(ComputerNamePhysicalDnsHostname, wb))
                    sayf(0, "hostname", "rename to %s queued (applies after reboot)", b);
                else sayf(1, "hostname", "SetComputerNameEx failed err %lu", GetLastError());
            }
        }
    } else say(1, "hostname", "no backup — not restored");
    if(read_backup_flat("VolumeSerialC", b, sizeof b)){
        if(strcmp(b, g_cur_volsnc)!=0){
            wchar_t vpath[MAX_PATH]; wsprintfW(vpath, L"%s\\Volumeid64.exe", g_exedir);
            if(GetFileAttributesW(vpath)!=INVALID_FILE_ATTRIBUTES){
                wchar_t cmd[300]; wchar_t bs[16];
                MultiByteToWideChar(CP_UTF8, 0, b, -1, bs, 16);
                wsprintfW(cmd, L"\"%s\" C: %ls-%ls", vpath, bs, bs+4);
                STARTUPINFOW si; memset(&si, 0, sizeof si); si.cb=(UINT)sizeof si;
                PROCESS_INFORMATION pi;
                if(CreateProcessW(NULL, cmd, NULL, NULL, 0, CREATE_NO_WINDOW, NULL, g_exedir, &si, &pi)){
                    WaitForSingleObject(pi.hProcess, 10000);
                    CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
                    sayf(0, "volume serial", "Volumeid64.exe run with %s (needs admin)", b);
                } else sayf(1, "volume serial", "CreateProcess failed err %lu", GetLastError());
            } else sayf(1, "volume serial", "backup %s differs but Volumeid64.exe not found next to counter — set manually", b);
        }
    }
    printf("\n[!] REBOOT REQUIRED: the kernel disk-serial hook (spoofysig.sys) survives until reboot.\n");
    if(reboot){
        printf("    rebooting now...\n");
        Sleep(1500);
        ExitWindowsEx(EWX_REBOOT | EWX_FORCE, 0);
    } else {
        printf("    (use --reboot to reboot automatically, then run 'verify')\n");
    }
}

/* --------------------------------------------------------------- main */
static void set_paths(void){
    GetModuleFileNameW(NULL, g_exedir, MAX_PATH);
    wchar_t *sl=wcsrchr(g_exedir, L'\\'); if(sl) *sl=0;
    wsprintfW(g_report, L"%s\\woofer_counter_report.txt", g_exedir);
    wsprintfW(g_backup, L"%s\\woofer_backup.json", g_exedir);
    TOKEN_ELEVATION te={0};
    HANDLE ht; DWORD tl;
    if(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &ht)){
        if(GetTokenInformation(ht, TokenElevation, &te, sizeof te, &tl)) g_admin=te.TokenIsElevated;
        CloseHandle(ht);
    }
    g_have_backup = (GetFileAttributesW(g_backup)!=INVALID_FILE_ATTRIBUTES);
}
int main(int argc, char **argv){
    set_paths();
    const char *mode="scan";
    int reboot=0;
    for(int i=1;i<argc;i++){
        if(strcmp(argv[i], "scan")==0) mode="scan";
        else if(strcmp(argv[i], "backup")==0) mode="backup";
        else if(strcmp(argv[i], "clean")==0) mode="clean";
        else if(strcmp(argv[i], "verify")==0) mode="verify";
        else if(strcmp(argv[i], "--reboot")==0) reboot=1;
    }
    printf("=== Woofer suite countermeasure (counter v1) ===\n");
    printf("mode: %s   elevated: %s\n", mode, g_admin?"yes":"no");
    FILE *rf=_wfopen(g_report, L"w");
    if(rf){ fprintf(rf, "=== Woofer suite countermeasure report ===\nmode: %s   elevated: %s\n\n", mode, g_admin?"yes":"no"); g_rep=rf; }

    if(strcmp(mode, "backup")==0){
        do_backup();
    } else if(strcmp(mode, "clean")==0){
        do_clean(reboot);
    } else if(strcmp(mode, "verify")==0){
        do_verify();
    } else {
        check_processes(0);
        check_service(0);
        check_files(0);
        check_registry();
        check_volume();
        check_host();
        check_mac(0);
        check_disk();
    }
    printf("\n== summary: %d OK, %d WARN, %d BAD ==\n", g_ok, g_warn, g_bad);
    if(g_rep){
        fprintf(g_rep, "\n== summary: %d OK, %d WARN, %d BAD ==\n", g_ok, g_warn, g_bad);
        if(g_bad==0 && g_warn==0)
            fprintf(g_rep, "VERDICT: CLEAN — no Woofer-suite traces detected.\n");
        else if(g_bad>0)
            fprintf(g_rep, "VERDICT: COMPROMISED — 'backup' (if not done) then 'clean --reboot', then 'verify'.\n");
        else
            fprintf(g_rep, "VERDICT: INCONCLUSIVE — warnings only; review above.\n");
        if(g_bad>0)
            fprintf(g_rep, "NOTE: an active kernel disk-serial hook survives until REBOOT.\n");
        fclose(g_rep);
    }
    if(g_bad>0)
        printf("VERDICT: COMPROMISED — run 'backup' (if not done) then 'clean --reboot'.\n");
    else if(g_warn>0)
        printf("VERDICT: INCONCLUSIVE — warnings only; review above.\n");
    else
        printf("VERDICT: CLEAN — no Woofer-suite traces detected.\n");
    if(g_bad>0)
        printf("NOTE: an active kernel disk-serial hook survives until REBOOT.\n");
    return g_bad>0 ? 1 : 0;
}
