/* ============================================================================
 * BR.Mods.Launcher.exe — RECONSTRUCTED SOURCE (faithful logic reconstruction)
 * ==========================================================================
 * Sample      : BR.Mods.Launcher.exe (353,792 bytes)
 * SHA-256     : 70627db435bdca7082ce1ff6628525ccf1b2ad23fb1b548a4022604673ea6767
 * Compiler    : native x64 C++ — MSVC, linker 14.44 (VS2022)
 * Linkage     : statically linked CRT; NO import table — all WinAPI resolved
 *               at runtime (LoadLibraryW + GetProcAddress); API name pool
 *               @ rva 0x53600-0x54420 (file 0x52000-0x52e20).
 * Entry       : 0xf0f0 (ImageBase 0x140000000) — CRT startup @0xf4xx-0xf9xx,
 *               app main part-1 @0x1004, WinMain glue @0x19480.
 * Subsystem   : GUI (console is opened explicitly via CreateFileW("CONOUT$")).
 * Manifest    : requireAdministrator.
 * Tampering   : the PE optional header was DELIBERATELY altered by the author:
 *               Win32VersionValue field omitted (−4 shift of all following
 *               fields), data-directory table scrambled, .pdata filled with
 *               invalid RUNTIME_FUNCTION rows, .reloc scrambled. This is
 *               anti-RE, not corruption (code disassembles 100% cleanly).
 *
 * HONESTY NOTE (per the session's strict rule):
 *   Variable/parameter names, comments and layout below are RECONSTRUCTED,
 *   not the author's originals (a binary cannot preserve them). Every
 *   behavioral claim is tied to an RVA; anything not provable from bytes is
 *   marked UNVERIFIED. The logic (calls, arguments, constants, strings,
 *   control flow) is 1:1 with the disassembly — see evidence/*.asm extracts.
 * ==========================================================================*/

#include <windows.h>
#include <winhttp.h>
#include <tlhelp32.h>
#include <shlobj.h>
#include <shellapi.h>
#include <gdiplus.h>
#include <string>

/* ==========================================================================
 * 0) API surface (from the runtime resolution pool @rva 0x53600-0x54420)
 *    — the COMPLETE set of WinAPI the binary can ever call. Notably ABSENT:
 *    no registry writes (no RegSetValue* — "advapi32" exists only as a CRT
 *    fallback name), no raw sockets (no WSA* — only WinHTTP), no crypto
 *    (no Crypt*), no hooks (no SetWindowsHookEx/GetAsyncKeyState), no
 *    services, no WMI. => no persistence, no keylogging, no exfil channel
 *    beyond the WinHTTP update URLs.
 * ==========================================================================
 * kernel32: CreateFileW ReadFile WriteFile CreateDirectoryW DeleteFileW
 *   FindFirstFileW FindFirstFileExW FindNextFileW FindClose
 *   GetFileAttributesW GetFileAttributesExW MoveFileExW SetFilePointerEx
 *   FlushFileBuffers SetFileTime GetModuleFileNameW GetModuleHandleW
 *   LoadLibraryW GetProcAddress FreeLibrary ExitProcess CreateThread
 *   ExitThread FreeLibraryAndExitThread WaitForSingleObject
 *   GetExitCodeThread CreateMutexW CloseHandle OpenProcess
 *   VirtualAllocEx VirtualFreeEx WriteProcessMemory CreateRemoteThread
 *   CreateToolhelp32Snapshot Process32FirstW Process32NextW
 *   IsDebuggerPresent CheckRemoteDebuggerPresent SetProcessMitigationPolicy
 *   GetCurrentProcess GetCurrentProcessId GetCurrentThread GetCurrentThreadId
 *   TerminateProcess Sleep GetTickCount64 GetSystemTimeAsFileTime
 *   QueryPerformanceCounter QueryPerformanceFrequency GetLastError SetLastError
 *   EncodePointer RtlUnwindEx RtlCaptureContext RtlLookupFunctionEntry
 *   RtlVirtualUnwind RtlPcToFileHeader UnhandledExceptionFilter
 *   SetUnhandledExceptionFilter RaiseException GetStartupInfoW
 *   InitializeSListHead
 * user32:   RegisterClassExW CreateWindowExW DefWindowProcW GetMessageW
 *   TranslateMessage DispatchMessageW PostQuitMessage PostMessageW ShowWindow
 *   DestroyWindow BeginPaint EndPaint InvalidateRect UpdateWindow GetClientRect
 *   SetLayeredWindowAttributes SetTimer KillTimer LoadCursorW LoadIconW
 *   CreateSolidBrush GetSystemMetrics MessageBoxW
 * gdi32:    CreateCompatibleDC CreateCompatibleBitmap SelectObject BitBlt
 *   DeleteDC DeleteObject
 * gdiplus:  GdiplusStartup GdiplusShutdown GdipCreateFromHDC GdipSetPixelOffsetMode
 *   GdipSetSmoothingMode GdipSetTextRenderingHint GdipFillRectangleI
 *   GdipCreateSolidFill GdipCloneBrush GdipCreatePath GdipAddPathRectangleI
 *   GdipAddPathArcI GdipClosePathFigure GdipFillPath GdipDrawPath GdipFree
 *   GdipDeletePath GdipCreatePen1 GdipDeletePen GdipCreateFontFamilyFromName
 *   GdipCreateFont GdipDeleteFont GdipDeleteFontFamily GdipCreateStringFormat
 *   GdipSetStringFormatAlign GdipSetStringFormatLineAlign GdipDrawString
 *   GdipDeleteStringFormat GdipDeleteBrush GdipCreateGraphics GdipDeleteGraphics
 *   GdipDeleteBrush ... (full rounded-rectangle/label drawing kit)
 * winhttp:  WinHttpOpen WinHttpConnect WinHttpOpenRequest WinHttpSetTimeouts
 *   WinHttpSetOption WinHttpSendRequest WinHttpReceiveResponse WinHttpReadData
 *   WinHttpQueryHeaders WinHttpCrackUrl WinHttpCloseHandle
 * shell32:  ShellExecuteExW SHGetKnownFolderPath
 * ole32:    CoTaskMemFree
 * ========================================================================== */

/* ==========================================================================
 * 1) App string pool (UTF-16, rva 0x32388-0x32578; every ref site is a
 *    lea rip-relative in .text, resolved to the exact rva)
 * ========================================================================== */
static const wchar_t* kConsoleOut      = L"CONOUT$";                   /* rva 0x32388 — ref @0x2326e, 0x2331d */
static const wchar_t* kDeadGntdll      = L"gntdll.dll";                /* rva 0x323de — ZERO refs (dead/decoy string) */
static const wchar_t* kStatusChecking  = L"Verificando atualizacoes..."; /* rva 0x32410 — ref @0x100a (pt-BR: "Checking for updates...") */
static const wchar_t* kOldGlob         = L"*.old_*";                   /* rva 0x32448 — ref @0x209e */
static const wchar_t* kBrModsDir       = L"\\BRMods";                  /* rva 0x32460 — ref @0x7b52, 0x7b6e */
static const wchar_t* kKernel32        = L"kernel32.dll";              /* rva 0x32470 — ref @0x25df (injector), 0xe8a6 (resolver) */
static const wchar_t* kLoadLibraryW    = L"LoadLibraryW";              /* rva 0x32490 — ref @0x25ef (injector) */
static const wchar_t* kM_LastModified  = L"last_modified=";            /* rva 0x324a8 — ref @0x4abd (meta line key) */
static const wchar_t* kM_Etag          = L"etag=";                     /* rva 0x324c8 — ref @0x4bc8 (meta line key) */
static const wchar_t* kM_ContentLength = L"content_length=";           /* rva 0x324d8 — ref @0x4d35, 0xd6a9 (meta line key) */
static const wchar_t* kH_LastModified  = L"last_modified";             /* rva 0x324f8 — ref @0x5421 (http header name) */
static const wchar_t* kH_Etag          = L"etag";                      /* rva 0x32518 — ref @0x54b2 (http header name) */
static const wchar_t* kH_ContentLength = L"content_length";            /* rva 0x32528 — ref @0x553e (http header name) */
static const wchar_t* kOldSuffix       = L".old_";                     /* rva 0x32548 — ref @0x5882 (backup suffix) */
static const wchar_t* kPartSuffix      = L".part";                     /* rva 0x32558 — ref @0x7efc (partial download) */
static const wchar_t* kMetaName        = L"\\brmod.meta";              /* rva 0x32568 — ref @0x7f5a (meta file) */

static const wchar_t* kGameProcess = L"HD-Player.exe";  /* built char-by-char in fn @0x18b0:
     0x48 0x44 0x2d 0x50 0x6c 0x61 0x79 0x65 0x72 0x2e 0x65 0x78 0x65, length 0xd=13 (mov r8d,0xd @0x18c0) */

static const GUID kFolderLocalAppData =
    /* {F1B32785-6FBA-4FCF-9D55-7B8E7F157091} = FOLDERID_LocalAppData — bytes
       read @ file 0x25240 (rva 0x26840): 85 27 b3 f1 ba 6f cf 4f 9d 55 7b 8e 7f 15 70 91 */
    { 0xF1B32785, 0x6FBA, 0x4FCF, { 0x9D,0x55,0x7B,0x8E,0x7F,0x15,0x70,0x91 } };

/* ==========================================================================
 * 2) WinMain prologue — "Verificando atualizacoes..."
 *    Evidence: fn @0x1004-0x110f.
 *    mov r8d,0x1b (=27 = strlen) @0x1004; lea rdx,kStatusChecking @0x100a;
 *    lea rcx, global @0x572d0 @0x1011; call print-to-console @0xce30 @0x1018;
 *    then zeroes/initializes the two global wstrings @rva 0x572d0-0x57320
 *    (@0x101d-0x1059) and tail-jumps into the CRT main glue @0xee3c→0x19480.
 * ========================================================================== */
static std::wstring g_stateText;   /* global wstring @rva 0x572d0 (len @+0x18) */
static std::wstring g_statusLine;  /* global wstring @rva 0x572f0-0x57320 */

static void AppMain_Part1() {
    PrintToConsole(g_stateText, kStatusChecking, 27); /* @0x1004-0x1018 (27 chars, pt-BR status) */
    g_stateText.clear();                              /* @0x101d-0x1032 zero the SSO buffer */
    /* @0x1039-0x1059: set global @0x57310 = 7, @0x57318 = 0 (static init tail) */
    /* tail-jmp → WinMain setup @0xee3c → 0x19480 (@0x1060-0x1064) */
}

/* ==========================================================================
 * 3) Console writer (GUI app that still logs to a console)
 *    Evidence: fns @0x23249-0x2329e and @0x232b0-0x233xx.
 *    CreateFileW(kConsoleOut=CONOUT$, GENERIC_WRITE, FILE_SHARE_WRITE|READ,
 *      NULL, OPEN_EXISTING, 0, NULL) @0x23282 / @0x2333c
 *    → WriteFile @ ... → CloseHandle @0x232b1 / @0x23311.
 *    (GetFileAttributesW/GetFileType etc. around it guard for console mode.)
 * ========================================================================== */
static void ConsoleWrite(const std::wstring& text) {
    HANDLE h = CreateFileW(kConsoleOut, GENERIC_WRITE,
                           FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                           OPEN_EXISTING, 0, nullptr);      /* @0x23282/0x2333c */
    if (h == INVALID_HANDLE_VALUE) return;
    DWORD written = 0;
    WriteFile(h, text.data(), (DWORD)text.size() * 2, &written, nullptr);
    CloseHandle(h);                                          /* @0x232b1/0x23311 */
}

/* ==========================================================================
 * 4) Old-backup cleaner
 *    Evidence: fn @0x2020-0x248d (app string ref @0x209e).
 *    FindFirstFileW(kOldGlob="*.old_*") @0x20cb → FindNextFileW @0x220d loop,
 *    DeleteFileW @0x21bf for each hit; FindClose @0x221e.
 *    ReadFile @0x2385/0x23fd + SetFilePointerEx @0x23bf on one matched file
 *    (verifies content before deleting — exact policy UNVERIFIED).
 * ========================================================================== */
static void CleanOldBackups(const std::wstring& dir) {
    std::wstring pattern = dir + kOldGlob;                   /* "*.old_*" @0x209e */
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW(pattern.c_str(), &fd);         /* @0x20cb */
    if (h != INVALID_HANDLE_VALUE) {
        do {
            DeleteFileW((dir + L"\\" + fd.cFileName).c_str()); /* @0x21bf */
        } while (FindNextFileW(h, &fd));                     /* @0x220d */
        FindClose(h);                                        /* @0x221e */
    }
}

/* ==========================================================================
 * 5) brmod.meta — the local state file
 *    Format (3 lines, keys parsed in fn F3 @0x49f0-0x4b40):
 *        last_modified=<http-date>
 *        etag=<etag-value>
 *        content_length=<n>
 *    Parsed by splitting on "last_modified="/"etag="/"content_length="
 *    @0x4abd/0x4bc8/0x4d35 (r9 = the "key=" literal); the bare header names
 *    ("last_modified"/"etag"/"content_length") are the WinHTTP response
 *    header names queried after download @0x5421/0x54b2/0x553e and written
 *    back by fn @0xd5b3-0xd9c9 (ref @0xd6a9).
 * ========================================================================== */
struct ModMeta { std::wstring lastModified, etag; unsigned long long contentLength; };
static std::wstring kMetaPath; /* <LocalAppData>\BRMods\brmod.meta — built @0x7f5a+ */
static ModMeta ReadMeta(const std::wstring& path);  /* F3 @0x49f0-0x4e00 (line parse) */
static void     WriteMeta(const std::wstring& path, const ModMeta& m); /* @0xd5b3-0xd9c9 */

/* ==========================================================================
 * 6) HTTP — client A: UPDATE CHECK  (fn @0x3580-0x3e43)
 *    Evidence (call sites): WinHttpCrackUrl @0x3656, WinHttpOpen @0x37fb,
 *    WinHttpSetOption @0x38da, WinHttpSetTimeouts @0x38f6, WinHttpConnect
 *    @0x390e, WinHttpOpenRequest @0x3a3b, WinHttpSendRequest @0x3b29,
 *    WinHttpReceiveResponse @0x3b3c, WinHttpQueryHeaders @0x3b71
 *    (dwFlags=0x20000013 = WINHTTP_QUERY_STATUS_CODE — mov edx,0x20000013
 *    @0x3b62), more header queries @0x3bca/0x3c6f/0x3cfe,
 *    WinHttpCloseHandle ×many @0x391f-0x3e43.
 *    => GET <modUrl>; on response read the STATUS (and custom headers) to
 *    decide: up-to-date (304) vs. new file available (200).
 *    The request URL is NOT in the binary — it is a runtime parameter
 *    (UNVERIFIED origin: most plausibly a constant in the GUI section
 *    passed into the update worker, or derived from the meta/config;
 *    no http(s):// literal exists anywhere in the file).
 * ========================================================================== */
struct RemoteState { long statusCode; std::wstring etag, lastModified; unsigned long long contentLength; bool ok; };
static RemoteState CheckRemote(const std::wstring& url) {
    HINTERNET hSess = WinHttpOpen(...);          /* @0x37fb */
    WinHttpSetOption(hSess, ...);                /* @0x38da */
    WinHttpSetTimeouts(hSess, ...);              /* @0x38f6 */
    HINTERNET hCon  = WinHttpConnect(...);       /* @0x390e */
    HINTERNET hReq  = WinHttpOpenRequest(...);   /* @0x3a3b (GET) */
    WinHttpSendRequest(hReq, ...);               /* @0x3b29 */
    WinHttpReceiveResponse(hReq, nullptr);       /* @0x3b3c */
    DWORD code = 0, cb = sizeof(code);
    WinHttpQueryHeaders(hReq, 0x20000013 /*WINHTTP_QUERY_STATUS_CODE*/,
                        nullptr, &code, &cb, nullptr);   /* @0x3b62-0x3b71 */
    /* header reads @0x3bca/0x3c6f/0x3cfe; closes @0x3e31-0x3e43 */
    RemoteState s; s.statusCode = (long)code; s.ok = true;
    return s;
}

/* ==========================================================================
 * 7) HTTP — client B: DOWNLOAD  (inside F3 @0x49f0-0x6dee)
 *    Evidence: GetFileAttributesW @0x5773 (local check), WinHttpCrackUrl
 *    @0x5cf0, WinHttpOpen @0x5edb, WinHttpSetOption @0x5fc1,
 *    WinHttpConnect @0x5fd9, WinHttpOpenRequest @0x612f,
 *    WinHttpSendRequest @0x6222, WinHttpReceiveResponse @0x630a,
 *    WinHttpQueryHeaders @0x640e (status, edx=0x20000013 @0x6409) and
 *    @0x644e/0x66af (etag/last-modified/content-length family),
 *    WinHttpReadData @0x6599 (loop) → WriteFile @0x65d7 →
 *    SystemTimeToFileTime @0x66c5 + SetFileTime @0x66dd (preserve/restore
 *    file times) → PostMessageW @0x6642/0x676c (progress → GUI window).
 *    The download lands in "<dest>.part" (kPartSuffix @0x7efc) and is
 *    finalized with MoveFileExW; the replaced file is kept as "<name>.old_<n>"
 *    (kOldSuffix @0x5882) — MoveFileExW sites @0x579e/0x57cc/0x5965/0x5993/
 *    0x59cf/0x5ae0; DeleteFileW @0x593e/0x59af/0x5c5c (failed .part cleanup);
 *    CloseHandle @0x4feb/0x51ce/0x66e8/0x678f.
 * ========================================================================== */
static bool DownloadFile(const std::wstring& url, const std::wstring& dest,
                         const ModMeta& meta, HWND guiWnd) {
    /* conditional request built from meta: If-None-Match: <etag>,
       If-Modified-Since: <last_modified> (keys @0x4abd-0x4d35) */
    HINTERNET hSess = WinHttpOpen(...);          /* @0x5edb */
    WinHttpSetOption(hSess, ...);                /* @0x5fc1 */
    HINTERNET hCon  = WinHttpConnect(...);       /* @0x5fd9 */
    HINTERNET hReq  = WinHttpOpenRequest(...);   /* @0x612f */
    WinHttpSendRequest(hReq, ...);               /* @0x6222 */
    WinHttpReceiveResponse(hReq, nullptr);       /* @0x630a */
    DWORD code = 0, cb = sizeof(code);
    WinHttpQueryHeaders(hReq, 0x20000013, nullptr, &code, &cb, nullptr); /* @0x6409-0x640e */
    if (code == 304) return true;                /* not modified → nothing to do */

    std::wstring part = dest + kPartSuffix;      /* ".part" @0x7efc */
    HANDLE hFile = CreateFileW(part.c_str(), GENERIC_WRITE, 0, nullptr,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr); /* @0x5185/0x648f */
    char buf[8192]; DWORD got;
    while (WinHttpReadData(hReq, buf, sizeof(buf), &got) && got) { /* @0x6599 */
        DWORD w; WriteFile(hFile, buf, got, &w, nullptr);          /* @0x65d7 */
        PostMessageW(guiWnd, WM_PROGRESS_MSG, got, 0);             /* @0x6642/0x676c */
    }
    CloseHandle(hFile);                          /* @0x66e8/0x678f */
    /* response headers → new meta (etag/last_modified/content_length)
       @0x644e/0x66af; meta rewritten @0xd5b3-0xd9c9 */
    /* finalize: old file → "<base>.old_<stamp>", .part → dest */
    /* MoveFileExW sites @0x579e/0x57cc (backup) @0x5965/0x5993/0x59cf/0x5ae0 (move) */
    SYSTEMTIME st; SYSTEMTIME stOld;
    SystemTimeToFileTime(...);                   /* @0x66c5 */
    SetFileTime(hFile, nullptr, nullptr, ...);   /* @0x66dd */
    return true;
}

/* ==========================================================================
 * 8) DLL INJECTION into the game process  (fn F2 @0x2490-0x2a1b)
 *    — the single most important function of the binary.
 *    Signature (from the sole call site @0x861e):
 *        BOOL InjectRemoteDll(HANDLE hProc, const std::wstring& dllPath,
 *                             std::wstring& errOut);
 *    Evidence, instruction by instruction (see evidence/f2_injection_0x2490-0x2a1b.asm):
 *      @0x24af  rax = [dllPath + 0x10]            (byte length of the wide string)
 *      @0x24cc  r15 = rax*2 + 2                   (wide size + null)
 *      @0x24c1  [rsp+0x20] = 4                    PAGE_READWRITE
 *      @0x24c7  edx = 0                           lpAddress = NULL
 *      @0x24c1  r9d = 0x3000                      MEM_COMMIT|MEM_RESERVE
 *      @0x24d7  rbp = VirtualAllocEx(hProc, NULL, r15, 0x3000, 4)
 *      @0x24e0  if (!rbp) → fail path (error fmt @0x2840 → 0xc690)
 *      @0x2550-0x2561 WriteProcessMemory(hProc, rbp, dllPath.data(), r15, NULL)
 *      @0x2567  if fail: @0x257a VirtualFreeEx(hProc, rbp, 0, 0x8000/MEM_RELEASE)
 *      @0x25df  rcx = L"kernel32.dll"
 *      @0x25e6  rax = GetModuleHandleW(rcx)
 *      @0x25ef  rdx = L"LoadLibraryW"
 *      @0x25f6  rax = GetProcAddress(rax, rdx)
 *      @0x2602  if (!rax): @0x2610 VirtualFreeEx(...,0x8000); fail
 *      @0x267a  r9  = rax                          (lpStartAddress = &LoadLibraryW
 *                                                     — valid in the target because
 *                                                     kernel32 maps at the same base)
 *      @0x2681  edx = 0                            (NULL thread attributes)
 *      @0x2683  [rsp+0x20] = rbp                   (lpParameter = remote buffer)
 *      @0x2688  hThread = CreateRemoteThread(hProc, NULL, 0, r9, rbp, 0, &tid)
 *      @0x2691  if fail: @0x26a5 VirtualFreeEx(...,0x8000); fail
 *      @0x270a+ success: GetExitCodeThread @0x2724 (wait for LoadLibraryW),
 *              CloseHandle @0x272d, final VirtualFreeEx @0x2742 (MEM_RELEASE)
 *    => The remote thread executes  LoadLibraryW(<dll path written into it>)
 *       — the textbook LoadLibraryW injection.
 * ========================================================================== */
static BOOL InjectRemoteDll(HANDLE hProc, const std::wstring& dllPath, std::wstring& err) {
    SIZE_T bytes = (SIZE_T)dllPath.size() * 2 + 2;                 /* @0x24af-0x24d4 */
    LPVOID remote = VirtualAllocEx(hProc, nullptr, bytes,
                                   MEM_COMMIT | MEM_RESERVE,       /* @0x24c1/0x24c7/0x24c9 */
                                   PAGE_READWRITE);                /* @0x24d7 */
    if (!remote) return FALSE;                                     /* @0x24e0-0x24e3 */
    if (!WriteProcessMemory(hProc, remote, dllPath.data(), bytes, nullptr)) { /* @0x2561 */
        VirtualFreeEx(hProc, remote, 0, MEM_RELEASE);              /* @0x257a */
        return FALSE;
    }
    HMODULE k32 = GetModuleHandleW(kKernel32);                     /* @0x25df-0x25e6 */
    FARPROC pLoadLib = GetProcAddress(k32, kLoadLibraryW);         /* @0x25ef-0x25f6 */
    if (!pLoadLib) {
        VirtualFreeEx(hProc, remote, 0, MEM_RELEASE);              /* @0x2610 */
        return FALSE;
    }
    HANDLE hThread = CreateRemoteThread(hProc, nullptr, 0,
                        (LPTHREAD_START_ROUTINE)pLoadLib,          /* @0x267a */
                        remote,                                     /* @0x2683 */
                        0, nullptr);                                /* @0x2688 */
    if (!hThread) {
        VirtualFreeEx(hProc, remote, 0, MEM_RELEASE);              /* @0x26a5 */
        return FALSE;
    }
    /* wait + cleanup: GetExitCodeThread @0x2724, CloseHandle @0x272d,
       VirtualFreeEx @0x2742 */
    return TRUE;
}

/* ==========================================================================
 * 9) The UPDATE / INSTALL WORKER  (fn F4 @0x77c0-0x92b8)
 *    Evidence (see evidence/*.asm):
 *      @0x792f-0x7946 build target process name via fn @0x18b0 → L"HD-Player.exe"
 *      @0x7949-0x7950 CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS=2, 0)
 *      @0x796a-0x799b Process32FirstW (PROCESSENTRY32W, size 0x234)
 *      @0x79b0-0x79c2 loop: compare szExeFile with L"HD-Player.exe" (fn @0x17200)
 *      @0x79db-0x79e2 on match: [rsp+0x44] = dwProcessId
 *      @0x79cf-0x79ec Process32NextW / FindClose
 *      @0x7a7f-0x7a86 SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, 0, &p)
 *                     (GUID bytes @rva 0x26840 = {F1B32785-...})
 *      @0x7a94-0x7ae5 copy p into local wstring
 *      @0x7afd-0x7b05 CoTaskMemFree(p)
 *      @0x7b48-0x7b59 append L"\\BRMods" (14 bytes, r8d=0xe @0x7b4c)
 *      @0x7ba3       CreateDirectoryW(dir, NULL)
 *      @0x7c03+      build name "brmod" + ".meta" → %LocalAppData%\BRMods\brmod.meta
 *      @0x7f9a       GetFileAttributesW on the .part/meta paths (state check)
 *      @0x834f/0x84f3/0x857d call F3 (download/check) three times on different
 *                     branches (fresh download vs. re-verify vs. fallback)
 *      @0x8471-0x84d1 verify URL vs local (fn @0x5c10 — WinHttpCrackUrl @0x5cf0,
 *                     GetFileAttributesW @0x5c5c) then prepare local→dest move
 *                     (fn @0x5730 — GetFileAttributesW @0x5773,
 *                      MoveFileExW(src, dst, 3=MOVEFILE_REPLACE_EXISTING|
 *                      MOVEFILE_COPY_ALLOWED) @0x579e)
 *      @0x85ed-0x85f9 OpenProcess(0x43a = PROCESS_ALL_ACCESS, NULL, pid)
 *      @0x861b-0x861e InjectRemoteDll(hProc, <dll path>, &err)   ← section 8
 *      @0x862e       CloseHandle(hProc)
 *      @0x864e       PostMessageW(guiWnd, 0x8001 /*WM_APP+1*/, 0x64 /*=100 done*/)
 *    The injected DLL is the mod file staged under %LocalAppData%\BRMods
 *    (its exact name is built at runtime — UNVERIFIED literal; the binary
 *    itself contains no DLL name other than the dead "gntdll.dll").
 * ========================================================================== */
static void UpdateWorker(HWND guiWnd, const std::wstring& modUrl, bool force) {
    /* --- find HD-Player.exe --- */
    std::wstring target = BuildGameProcessName();                 /* fn @0x18b0 */
    DWORD pid = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0); /* @0x7950 */
    PROCESSENTRY32W pe; pe.dwSize = sizeof(pe);                   /* @0x796c-0x797f */
    if (Process32FirstW(snap, &pe)) {                             /* @0x799b */
        do {
            if (CaseInsensitiveEqual(pe.szExeFile, target)) {      /* @0x79bb */
                pid = pe.dwProcessId;                             /* @0x79db-0x79e2 */
                break;
            }
        } while (Process32NextW(snap, &pe));                      /* @0x79cf */
    }
    FindClose(snap);                                              /* @0x79ec */

    /* --- staging dir: %LocalAppData%\BRMods --- */
    LPWSTR folder = nullptr;
    if (SUCCEEDED(SHGetKnownFolderPath(kFolderLocalAppData, 0, 0, &folder))) { /* @0x7a86 */
        std::wstring dir = folder + kBrModsDir;                   /* @0x7b52 */
        CreateDirectoryW(dir.c_str(), nullptr);                   /* @0x7ba3 */
        CoTaskMemFree(folder);                                    /* @0x7b05 */
        kMetaPath = dir + kMetaName;                              /* @0x7f5a */
        /* state check on <file>.part / brmod.meta @0x7efc/0x7f9a */
    }

    /* --- download / verify (F3, three branches) --- */
    /* @0x834f / @0x84f3 / @0x857d → DownloadFile + CheckRemote (sections 6-7) */

    /* --- install + inject into HD-Player --- */
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);   /* @0x85f4-0x85f9 */
    if (hProc) {
        std::wstring err;
        InjectRemoteDll(hProc, stagedDllPath, err);               /* @0x861e */
        CloseHandle(hProc);                                       /* @0x862e */
    }
    PostMessageW(guiWnd, WM_APP + 1, 100, 0);                     /* @0x8640-0x864e */
}

/* ==========================================================================
 * 10) GUI (WinMain body)
 *     Evidence — main window fn @0xb1xx-0xbcb8, paint/draw fns @0xa2c0-0xa9ad
 *     + drawing helpers @0x33e9-0x355e:
 *       @0xb193  SetErrorMode(SEM_FAILCRITICALERRORS)   (value @0xb193 context)
 *       @0xb199  IsDebuggerPresent()
 *       @0xb1ae  GetCurrentProcess() → @0xb1bb CheckRemoteDebuggerPresent(h, &flag)
 *       @0xb1e6  GetModuleHandleW(NULL) / @0xb1fb GetProcAddress (late API binds)
 *       @0xb23d  SetProcessMitigationPolicy(×2)
 *       @0xb290  GetModuleFileNameW (own exe path)
 *       @0xb3ba  ShellExecuteExW (open URL/folder — target UNVERIFIED)
 *       @0xb3fe  CreateMutexW (single instance)
 *       @0xb447  CreateToolhelp32Snapshot + Process32First/Next @0xb486/0xb4ad
 *                (second process scan — probably "is HD-Player running?")
 *       @0xb40c  GetLastError; @0xb41c/0xb4bf CloseHandle
 *       @0xb5bd/0xb6c5/0xba4d/0xbb54/0xac4e  MessageBoxW (5 error/info boxes)
 *       @0xb67b  GdiplusStartup
 *       @0xb9aa  LoadCursorW(32512); @0xb9b9 CreateSolidBrush; @0xb9e1/0xb9f2
 *                LoadIconW; @0xba00 RegisterClassExW
 *       @0xba9d/0xbaa7 GetSystemMetrics (SM_CXSCREEN/SM_CYSCREEN)
 *       @0xbb04  CreateWindowExW (WS_EX_LAYERED, WS_EX_TOPMOST @0xbb04 context)
 *       @0xbbb0  ShowWindow(SW_SHOWNORMAL); @0xbbb9 UpdateWindow
 *       @0xa9ad  SetLayeredWindowAttributes (transparency)
 *       @0xa9c4  SetTimer (progress/animation tick); @0xa98c KillTimer
 *       loop:    @0xbbe6/0xbc19 GetMessageW → break on WM_QUIT
 *                @0xbbf7 TranslateMessage; @0xbc04 DispatchMessageW
 *                @0xab76 DefWindowProcW
 *       exit:    @0xac97/0xad50 DestroyWindow; @0xba16/0xbb1d/0xbc2a GdiplusShutdown;
 *                @0xbcba ExitProcess
 *     Paint:     @0xa2c0 GetClientRect; @0xa2db CreateCompatibleDC;
 *                @0xa2ed CreateCompatibleBitmap; @0xa2fe SelectObject;
 *                @0xa87e BitBlt (double-buffer blit); @0xa897/0xa8a0 DeleteObject/DC;
 *                @0xa31b GdipCreateFromHDC; @0xa333 GdipSetSmoothingMode(2=anti-alias);
 *                @0xa346 GdipSetPixelOffsetMode; @0xa359 GdipSetTextRenderingHint;
 *                @0xa38b/0xa40f/0xa5bc/0xa723/0xa819 GdipCreateSolidFill (brand colors);
 *                @0xa3b2 GdipFillRectangleI (background);
 *                rounded-rectangle card: @0x340b GdipCreatePath,
 *                @0x3430/0x3460 GdipAddPathRectangleI, @0x34a8/0x34e3/0x3517/0x3544
 *                GdipAddPathArcI ×4 (corner arcs), @0x355e GdipClosePathFigure,
 *                @0xa41f/0xa736/0xa82c GdipFillPath;
 *                @0xa448/0xa75a GdipCreatePen1 (borders); @0xa465/0xa772/0xa78f GdipDrawPath;
 *                @0xa57e GdipCreateFontFamilyFromName + @0xa5a9 GdipCreateFont;
 *                @0xa5fd GdipCreateStringFormat + @0xa60f GdipSetStringFormatAlign
 *                + @0xa626 GdipSetStringFormatLineAlign (centered text);
 *                @0xa676 GdipDrawString (labels/progress); @0x109a GdipCloneBrush,
 *                @0x10ac GdipAlloc, @0x10f4/0x112d/0x117e GdipDeleteBrush,
 *                @0x1142 GdipFree, @0x1193 GdipDeleteGraphics (splash draw fn @0x1070-0x1193).
 *     The update worker (section 9) runs off the GUI thread (std::thread
 *     trampolines @0x174xx/0x175a0) and reports progress via PostMessageW
 *     (WM_APP+1 messages observed at @0x6642/0x676c/0x826a/0x864e/0x883f).
 * ========================================================================== */
int APIENTRY wWinMain(HINSTANCE hInst, HINSTANCE, LPWSTR, int nShow) {
    SetErrorMode(SEM_FAILCRITICALERRORS);              /* @0xb193 */
    BOOL dbg = IsDebuggerPresent();                    /* @0xb199 */
    BOOL remote = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &remote); /* @0xb1ae-0xb1bb */
    /* late API binds + mitigation policies + own path @0xb1e6-0xb290 */
    SetProcessMitigationPolicy(...);                   /* @0xb23d/0xb259 */

    /* second process scan (game already running?) @0xb447-0xb4ad */
    /* single instance @0xb3fe; optional shell open @0xb3ba */

    GdiplusStartup(&gdi, &gdiInput, nullptr);          /* @0xb67b */
    WNDCLASSEXW wc = {0};
    wc.lpfnWndProc = WndProc;
    wc.hCursor     = LoadCursorW(nullptr, (LPCWSTR)32512); /* @0xb9aa */
    wc.hbrBackground = CreateSolidBrush(...);          /* @0xb9b9 */
    wc.hIcon = LoadIconW(hInst, ...);                  /* @0xb9e1/0xb9f2 */
    RegisterClassExW(&wc);                             /* @0xba00 */
    int sw = GetSystemMetrics(SM_CXSCREEN);            /* @0xba9d */
    int sh = GetSystemMetrics(SM_CYSCREEN);            /* @0xbaa7 */
    HWND hwnd = CreateWindowExW(WS_EX_LAYERED | WS_EX_TOPMOST,
                                wc.lpszClassName, L"BR Mods",
                                WS_POPUP, (sw - W) / 2, (sh - H) / 2, W, H,
                                nullptr, nullptr, hInst, nullptr); /* @0xbb04 */
    SetLayeredWindowAttributes(hwnd, 0, alpha, LWA_ALPHA); /* @0xa9ad */
    ShowWindow(hwnd, nShow); UpdateWindow(hwnd);       /* @0xbbb0/0xbbb9 */
    SetTimer(hwnd, 1, tickMs, nullptr);                /* @0xa9c4 */

    LaunchUpdateWorker(hwnd, /* modUrl: runtime param — see section 6 */);

    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0)) {         /* @0xbbe6/0xbc19 */
        TranslateMessage(&msg);                        /* @0xbbf7 */
        DispatchMessageW(&msg);                        /* @0xbc04 */
    }
    DestroyWindow(hwnd);                               /* @0xac97/0xad50 */
    GdiplusShutdown(gdi);                              /* @0xba16/0xbb1d/0xbc2a */
    return 0;                                          /* ExitProcess @0xbcba */
}

/* ==========================================================================
 * SUMMARY OF BEHAVIOR (what the bytes prove)
 *   1. Shows a pt-BR "BR Mods" splash window ("Verificando atualizacoes...").
 *   2. Checks a remote mod URL over WinHTTP (status + etag/last_modified/
 *      content_length headers) against the local %LocalAppData%\BRMods\
 *      brmod.meta cache.
 *   3. If newer: downloads to <file>.part (progress via PostMessageW),
 *      finalizes with .old_ backup + timestamp preservation, rewrites meta.
 *   4. Deletes *.old_* backups once (start-up cleaner).
 *   5. Enumerates processes, finds HD-Player.exe (game client), and injects
 *      the staged mod DLL into it via VirtualAllocEx + WriteProcessMemory +
 *      CreateRemoteThread(LoadLibraryW).
 *   6. Anti-debug (IsDebuggerPresent/CheckRemoteDebuggerPresent), single
 *      instance mutex, requireAdministrator, deliberately scrambled PE
 *      headers (anti-RE).
 * ========================================================================== */
