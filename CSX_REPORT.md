# تقرير الهندسة العكسية الكامل — CSX.exe (ميزة الـ Spoofer)

> **صنف النتيجة المعلن: R2 — إعادة بناء سلوكية/هيكلية.**
> كل قيمة معروضة هنا (رقيم/رقيم نسبي RVA، نص، ثابت، اسم API) **قُرئت من بايتات
> العينة مباشرة في هذه الجلسة** (تفكيك + قراءة جداول PE). الكود المُعاد بناؤه
> (`csx_spoof.dll`) **ليس** مطابقاً بايت-ببايت لإخراج MSVC الأصلي — السلوك هو
> الأصلي خطوة بخطوة: نفس استدعاءات API بنفس الترتيب، نفس النصوص، نفس مفاتيح
> السجل، نفس أسماء القيم وأنواعها وأحجامها.
> **لم يتم تنفيذ العينة إطلاقاً** طوال فترة التحليل.

---

## 1) هوية العينة

| الحقل | القيمة |
|---|---|
| الملف | `CSX.exe` |
| الحجم | 4,392,448 بايت |
| SHA-256 | `d5ed9e6a57952d2a2d7876813376784868126e9295ee55ba01b45a395fc4ee556` |
| النوع | PE32 (x86), Machine 0x14C |
| ImageBase | `0x00400000` |
| نقطة الدخول | `0x00422052` |
| SizeOfImage | `0x436000` |
| Subsystem | 2 (GUI) |
| المبدّل (Compiler) | MSVC x86 (أنماط MSVC: SSO std::string، SEH `push -1 / push &SEH`، UCRT) |

### أقسام PE (من ترويسة PE — VA / رقيم ملف):

| القسم | VA | رقيم في الملف |
|---|---|---|
| `.text`   | 0x00401000 | 0x00000400 |
| `.mmap`   | 0x00439000 | 0x00037C00 |
| `.rdata`  | 0x0043A000 | 0x00038000 |
| `.data`   | 0x0044B000 | 0x00048A00 |
| `.fptable`| 0x0044D000 | 0x00049800 |
| `.rsrc`   | 0x0044E000 | 0x00049A00 |
| `.reloc`  | (0x00433000) | — |

**معادلات التحويل** (استُخدمت في كل القراءات): `.text` VA = file+0x400C00،
`.rdata` VA = file+0x402000، `.data` VA = file+0x402A00.

---

## 2) الاستيرادات (10 موديولات، 269 خانة IAT — كاملة في `re/csx_iat.json`)

| الموديول | ما يستعمله من الميزات |
|---|---|
| KERNEL32 | إنشاء/تلاعب العمليات والذاكرة (OpenProcess, CreateRemoteThread, VirtualAllocEx, WriteProcessMemory, MoveFileExW, CreateToolhelp32Snapshot...), ملفات (FindFirstFileA/Next, DeleteFileA, RemoveDirectoryA, GetFileAttributesA, CreateFileW...), فحص Debugger (IsDebuggerPresent, CheckRemoteDebuggerPresent) |
| ADVAPI32 | **كل عمليات السجل والمصادقة الخاصة بالـ spoofer** (الخانات أدناه) + CredDeleteW/GetUserNameA |
| WINHTTP | دورة كاملة (Open/Connect/OpenRequest/Send/Receive/Read/QueryHeaders) للـ API الخارجي |
| OLE32/OLEAUT32 | WMI (CoCreateInstance, CoSetProxyBlanket, CreateStreamOnHGlobal + VariantCopy/Clear/VarI4FromStr بالترتيبات ord6/ord2/ord9) |
| NETAPI32 | NetShareEnum (فحص مشاركات الشبكة) |
| SHELL32/USER32/GDI32/GDIPLUS | واجهة رسومية GDI+ + نوافذ |

**خانات IAT الخاصة بالـ spoofer** (`.rdata` 0x0043A000+، من جداول الاسم الفعلية):

| VA | الدالة |
|---|---|
| 0x0043A000 | RegEnumKeyExA |
| 0x0043A004 | RegQueryValueExW |
| 0x0043A008 | **CredDeleteW** |
| 0x0043A014 | **RegOpenKeyExA** |
| 0x0043A018 | **RegSetValueExA** |
| 0x0043A01C | **GetUserNameA** |
| 0x0043A020 | **RegDeleteKeyA** |
| 0x0043A024 | **RegCloseKey** |
| 0x0043A13C | FindFirstFileA |
| 0x0043A15C | FindNextFileA |
| 0x0043A16C | FindClose |
| 0x0043A1A8 | GetFileAttributesA |
| 0x0043A1C0 | **DeleteFileA** |
| 0x0043A1F8 | RemoveDirectoryA |
| 0x0043A314 | InvalidateRect |
| 0x0043A33C | SetWindowTextW |

---

## 3) الخريطة الوظيفية (VAs مثبتة — التفاصيل في `re/csx_funcs.json`, `re/csx_str_xrefs.json`)

| المنطقة | الوظيفة |
|---|---|
| 0x0040FA60 | **UI wrapper لزر "R E S E T   S E R I A L"** (SEH prologue؛ راية انشغال 0x0044C864؛ يعرض "Resetting MTA serial..." ثم "Serial reset complete" ثم InvalidateRect) |
| 0x0040EFF0 (0x44A بايت) | **عمل الـ spoofer الفعلي** (مفكك بالكامل — القسم 4) |
| 0x0040EC10 | مساعد: حذف شجرة مفاتيح HKCU بشكل تسلسلي (recursive) |
| 0x0040E8C0 | مساعد: حذف شجرة مجلدات بشكل تسلسلي (recursive) |
| 0x00403D20 | قارئ MachineGuid (RegOpenKeyExW على `SOFTWARE\Microsoft\Cryptography`) |
| 0x00403F60 | محرك استعلام WMI (CoCreateInstance → ConnectServer(`ROOT\CIMV2`) → CoSetProxyBlanket → ExecQuery(`WQL`)) |
| 0x004027E0 | قارئ ملفات البصمة MTA (dxdiag_cache.bin / audio_cache.bin / cache.dat) |
| 0x00408800 | تدفق فحص الـ Ban (MessageBox "You are banned."، CreateProcess keepalive، فتح رابط Discord، قراءة LOCALAPPDATA\CSX\.banned) |
| 0x00408360..0x00409DA0 | منطق الـ ban/event مع API الخارجي |
| 0x00413CC0 / 0x004151A0 / 0x00417B00 | geolocation: ipify / ip-api |
| 0x00419D20 / 0x0041ADD0 | نشر عينة كشف VM باسم `csxprobe` |
| 0x0040B520..0x0040CF84 | منظومة الحقن (manual-map عبر stub القسم `.mmap` + fallback LoadLibrary + rescue للـ suspended-launch) |
| 0x0040A780..0x0040ABF9 | تنظيف shim لـ version.dll |
| 0x0040D6B0..0x0040E69F | رسم الواجهة (GDI+) |
| 0x00413F80 | فحص سيرورات (Process32First/Next) + حزمة استعلامات WMI |
| 0x0041BE20 | تهيئة النافذة (GdiplusStartup, RegisterClassW, CreateWindowExW) |
| 0x00422052 | نقطة الدخول (WinMain/ucrt بدء) |

### استعلامات WMI المثبتة (UTF-16 في `.rdata`):

| VA | الاستعلام |
|---|---|
| 0x00443A08 | `ROOT\CIMV2` (يُمرر لـ ConnectServer عند 0x00404050) |
| 0x00443A20 | `WQL` (يُمرر لـ ExecQuery عند 0x004040B9) |
| 0x00443A38 | `SELECT Name FROM Win32_VideoController` |
| 0x00443AA8 | `SELECT SerialNumber FROM Win32_BaseBoard` |
| 0x00443B00 | `SELECT SerialNumber FROM Win32_DiskDrive` |
| 0x004459F8 | `SELECT Manufacturer FROM Win32_ComputerSystem` |
| 0x00445AA0 | `SELECT Model FROM Win32_ComputerSystem` |
| 0x00445B10 | `SELECT Manufacturer FROM Win32_BIOS` |

(هذا مع GetComputerNameW / GetUserNameW / MachineGuid / ملفات dxdiag-cache =
"بصمة الهوية" التي تُرسل لخوادم الـ ban/heartbeat — وليست جزءاً من الـ spoofer نفسه.)

---

## 4) فك ترميز ميزة الـ Spoofer كاملة (0x0040FA60 ← 0x0040EFF0)

السلسلة كاملة، بالترتيب، مع موقع كل ثابت في العينة:

### الخطوة 1 — حذف مصادقة Windows (VA 0x00445364، UTF-16)
```
0x0040F01D  push 0            ; Flags = 0
0x0040F01F  push 1            ; Type = CRED_GENERIC_TARGET_TYPE (1)
0x0040F021  push 0x445364     ; L"SSO_RND_Device"
0x0040F026  call [0x43A008]   ; CredDeleteW
```
**السلوك:** حذف الـ credential العامة `SSO_RND_Device` من مخزن Windows Credential.

### الخطوة 2 — حذف 3 أشجار مفاتيح HKCU (المساعد 0x0040EC10)
```
0x0040F02C  mov edx, 0x445384  ; "Software\Microsoft\Windows\CurrentVersion\Explorer\CLSID"
0x0040F031  call 0x40EC10
0x0040F036  mov edx, 0x4453C0  ; "...\Explorer\CLSID2"
0x0040F03B  call 0x40EC10
0x0040F040  mov edx, 0x445400  ; "Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections"
0x0040F045  call 0x40EC10
```
**المساعد 0x0040EC10** (فُك بالكامل): `RegOpenKeyExA(HKCU=0x80000001, path, 0, 0xF003F)`
@0x0040EC59؛ إن لم يوجد المفتاح يرجع FALSE (0x0040EC5F). ورنان `RegEnumKeyExA` بخانة 0x100
بايت (0x0040EC9C..0x0040EF9D) مع استدعاء ذاتي لكل subkey (0x0040EF1B)، ثم `RegCloseKey`
(0x0040EFA8) ثم `RegDeleteKeyA(HKCU, path)` (0x0040EFB4) → **حذف كامل وشجرة لكل مفتاح**.
(هذه المفاتيح تحتوي بصمات تعريف مواتية/تصفحية تستعملها بعض الأنظمة.)

### الخطوة 3 — حذف تيارات NTFS ADS على C:\ProgramData
```
0x0040F04A  mov edi, [0x43A1C0]      ; DeleteFileA
0x0040F050  push 0x445448            ; "C:\ProgramData:NT"
0x0040F055  call edi
0x0040F057  push 0x44545C            ; "C:\ProgramData:NT2"
0x0040F05C  call edi
```
**السلوك:** `DeleteFileA("C:\ProgramData:NT")` و`DeleteFileA("C:\ProgramData:NT2")` —
حذف **Alternate Data Streams** (ملفات خفية داخل موجه ProgramData) تحمل بصمات.

### الخطوة 4 — نفس الشيء على مجلد المستخدم (GetUserNameA)
```
0x0040F08C  call [0x43A01C]          ; GetUserNameA(buf, &0x100)  (0x0040F05E: push 0x100)
0x0040F0AB  movq xmm0, [0x445484]    ; "C:\Users\" (9 بايت + بايت 0x44548C = '\')
S2 = "C:\Users\<user>" + "\AppData\Roaming"   ; 0x00445470 push @0x0040F195
0x0040F2EA  push 0x445490            ; ":NT"   (3)
0x0040F318  call edi                 ; DeleteFileA(S2+":NT")
0x0040F37B  push 0x445494            ; ":NT2"  (4)
0x0040F3A9  call edi                 ; DeleteFileA(S2+":NT2")
```
**السلوك:** حذف ADS `C:\Users\<user>\AppData\Roaming:NT` و`:NT2`.

### الخطوة 5 — حذف مجلد كاش MTA المشترك
```
0x0040F3E5  push 0x44549C            ; "C:\ProgramData\MTA San Andreas All"
0x0040F3EA  call [0x43A1A8]          ; GetFileAttributesA
0x0040F3F0  cmp eax, -1  /  0x0040F3F9  test al, 0x10   ; تخطي إن غير موجود أو SYSTEM
0x0040F40E  push 0x40                ; خزانة 0x40 بايت
0x0040F426..0x0040F46D  copy 0x35B   ; blob: "C:\ProgramData\MTA San Andreas All\Common\data\cache"
                                      ; (16B@0x4454C0 + 16B@0x4454D0 + 16B@0x4454E0 + 4B@0x4454F0 + NUL)
0x0040F47B  call 0x40E8C0            ; DeleteDirTree(cache)
```
**المساعد 0x0040E8C0** (فُك بالكامل): `FindFirstFileA(path+"\\*")` @0x0040E93D؛
تخطي `"."` (VA 0x00445358) و`".."` (VA 0x0044535C)؛ تسلسل للمجلدات الفرعية
(استدعاء ذاتي @0x0040EB5C)؛ `DeleteFileA` للملفات (@0x0040EB6F)؛ `FindClose`
(@0x0040EBC9)؛ `RemoveDirectoryA(path)` (@0x0040EBD8) → **remove_all لمجلد الكاش**.

### الخطوة 6 — تبييض قيم MTA في السجل (حلقتان: 1.5 ثم 1.6)
جدول المفاتيح @0x0040F4E5/0x0040F4EF (مؤشران):
- `K0` = `SOFTWARE\WOW6432Node\Multi Theft Auto: San Andreas All\1.5` (VA 0x004454F8)
- `K1` = `SOFTWARE\WOW6432Node\Multi Theft Auto: San Andreas All\1.6` (VA 0x00445534)

جسم الحلقة @0x0040F4FF، لكل مفتاح K (كل فتح على HKLM=0x80000002 بـ KEY_ALL_ACCESS=0xF003F):

| (أ) | `h = RegOpenKeyExA(HKLM, K + "\Settings\general", 0, KEY_ALL)` @0x0040F66E
      ("\Settings\general" VA 0x00445570، الطول 0x11، push @0x0040F554)
      → عند النجاح: `RegSetValueExA(h, "cachechecksum", 0, REG_SZ, &0x00, 1)` @0x0040F68D
      ("cachechecksum" VA 0x00445584 push @0x0040F682؛ البيانات بايت واحد 0x00 من VA 0x00443884 push @0x0040F67A)
      ثم `RegCloseKey` @0x0040F695 |
|---|---|
| (ب) | فتح **نفس المفتاح مرة ثانية** @0x0040F6C3 → عند النجاح:
      `RegSetValueExA(h, "serial", 0, REG_SZ, &0x00, 1)` @0x0040F6E2 ("serial" VA 0x00445594 push @0x0040F6D7) ثم إغلاق @0x0040F6EA |
| (ج) | `h = RegOpenKeyExA(HKLM, K + "\Settings\diagnostics", 0, KEY_ALL)` @0x0040F800
      ("\Settings\diagnostics" VA 0x0044559C، الطول 0x15، push @0x0040F73F)
      → عند النجاح: `crash-data`/`crash-data1`/`crash-data2` = REG_SZ بايت واحد 0x00
      (@0x0040F8BE/0x0040F8D6/0x0040F8EE؛ الأسماء VA 0x004455B4/0x004455C0/0x004455CC
      push @0x0040F8B3/0x0040F8CB/0x0040F8E3)
      و`send-dumps` = REG_SZ `"no"` **حجم 3 بلا NUL** (@0x0040F906؛ "send-dumps" VA 0x004455DC
      push @0x0040F8FB، "no" VA 0x004455D8 push @0x0040F8F2) ثم إغلاق @0x0040F90E |
| (د) | `h = RegOpenKeyExA(HKLM, K, 0, KEY_ALL)` @0x0040F928 — **مفتاح النسخة نفسه بلا لاحقة**
      (lpSubKey = esi المستعاد لنص المفتاح الخام @0x0040F774)
      → عند النجاح: `RegSetValueExA(h, "Last Run Path Hash", 0, REG_SZ, &0x00, 1)` @0x0040F947
      (VA 0x004455E8 push @0x0040F93C) ثم إغلاق @0x0040F94F |

**الأثر الصافي:** لكل نسخة (1.5، 1.6) تُصفَّر القيم `serial` و`cachechecksum` و
`Last Run Path Hash` و`crash-data1/2` (كتابة REG_SZ فارغ من بايت واحد) ويُضبط
`send-dumps="no"` → MTA:SA يعيد توليد السيريال/البصمة عند أول تشغيل.

### الخطوة 7 — واجهة المستخدم (0x0040FA60)
```
push 0x4455FC  → SetWindowTextW(hwnd, L"Resetting MTA serial...")   @0x0040FA9B
call 0x0040EFF0                                                       @0x0040FB1B
push 0x4456EC  → SetWindowTextW(hwnd, L"Serial reset complete")      @0x0040FBA6
InvalidateRect(hwnd, NULL, 0)                                        (IAT 0x0043A314)
```
(نص الزر "R E S E T   S E R I A L" VA 0x00445730 يُخزّن في 0x0044C9C8 عند تهيئة
الواجهة @0x0041317D؛ ونص "You Need Reset your Mta Serial?" VA 0x004458A8 @0x00413866.)

---

## 5) أساليب غير-سبووفير (تلخيص — ليست ضمن الميزة المطلوبة)

- **الحقن (0x0040B520..0x0040CF84):** stub تحميل مكرر-مُسلسل (serialized-PE loader)
  في قسم `.mmap` (VA 0x00439000، 0x245B بايت) يُنسخ للهدف عبر VirtualAllocEx/
  WriteProcessMemory ويُشغَّل CreateRemoteThread (base,1,0)≡DllMain؛ مع fallback
  LoadLibraryA، ومسار "rescue" لبدء اللعبة موقوفة (suspended) وإلحاقها.
- **بن/خوادم (0x00408800..):** POST `/api/event` و`/api/heartbeat` (نصوص VA
  0x0042398/0x00424E4) بـ User-Agent `CSX/1.0` (VA 0x0041B54)؛ "Server offline
  (fail-open)" VA 0x0042420؛ رابط Discord VA 0x00422D0.
- **تحديث ذاتي:** مستودع `onlyyoussef/csx-update` (VA 0x0041BAC..0x0041D00)
  مع ملفات `.new/.old/.tag` (VA 0x0041D60..0x0041D98).
- **كشف VM:** نشر `csxprobe` (VA 0x0043F60..0x00441B8) + مفاتيح vmware/vbox/
  tsclient (VA 0x0043E74..0x0043EE0) + استعلامات WMI للقسم 3.
- **`CSX\.banned`** (VA 0x0042194) في LOCALAPPDATA مع "You are banned." (VA 0x0042208).
- **موارد `.rsrc`:** أيقونات + RCDATA 101-104 + صورة PNG + صورة JPEG (ملفات UI).

### المكتبات الطرف الثالث (من الاستيراد + البصمات):
- **UCRT** (api-ms-win-crt-*) — المبدّل MSVC حديث.
- **GDI+** (Gdip*) + GDI32/USER32 — واجهة مخصصة.
- لا MinHook/Lua/ImGui هنا (هذه من NRTH.dll فقط).

---

## 6) ما تم بناؤه من هذه النتائج (R2)

| الملف | الوصف |
|---|---|
| `csx_spoof/csx_spoof.h` | الواجهة + **كل الأدلة (VAs) في تعليقات** |
| `csx_spoof/csx_spoof_core.cpp` | إعادة البناء السلوكية: نفس الخطوات السبع بنفس الثوابت |
| `csx_spoof/csx_spoof.def` | 8 تصديرات (CSX_Spoofer* بترتيبات 1-8) |
| `csx_spoof/test_csx_spoof.cpp` | أداة اختبار Windows (probe/reset) |
| `bin/csx_spoof.dll` | SHA-256 `692b4cb621aaf7cc0a4062aed6ff2ae64c275c88845b924f5ad388bac5ecc4e2` (PE32 x86) |
| `bin/test_csx_spoof.exe` | SHA-256 `e1b042b3c6748bf5415b49556b9393e7b0c40826377519619b2f01d4477210e0` |
| `nrth_ui.cpp` (عدّل) + `build_x86.sh` (عدّل) | الميزة داخل NRTH: زر "Reset MTA Serial (CSX)" في تبويب Other |
| `bin/NRTH.dll` (مُعاد بناؤه) | SHA-256 `95c9d9609f2c297dddba502cec9d00b51ee25b12646d2166a3c77ac74be23053` — **NVXHookProc بقيت عند RVA 0x0000B9E0** (مطابقة لعقد NRTH الأصلي) |

**واجهة csx_spoof.dll:**
```c
BOOL CSX_SpooferResetMtaSerial(HWND hwnd);            // الترتيب الكامل (7 خطوات)
BOOL CSX_SpooferClearSsoCredential();                 // الخطوة 1
BOOL CSX_SpooferClearExplorerKeyTrees();              // الخطوة 2
BOOL CSX_SpooferClearNtDataStreams();                 // الخطوات 3-4
BOOL CSX_SpooferClearMtaSharedCache();                // الخطوة 5
BOOL CSX_SpooferResetMtaRegValues();                  // الخطوة 6
BOOL CSX_SpooferProbe(CSXResetProbe* out);            // فحص حالة (قراءة فقط)
const char* CSX_SpooferLastStatus();                  // نص الحالة
```

### ملاحظات إعادة البناء (صراحةً):
1. `CredDeleteW`/`CredReadW` تُحل ديناميكياً من `credapi.dll` في النسخة
   المعاد بناؤها (أداة zig لا تحمل استيراد-مكتبة credapi)؛ في الأصل مستورد
   ثابت عبر IAT — **الدعوة نفسها بنفس المعاملات**.
2. الـ probe يستخدم `CredReadW` بدل التعداد (مكافئ للقراءة المفردة).
3. حدود أمان (recursion depth 64) أُضيفت في المساعدين التسلسليين فقط؛
   الأصل يتسلسل بلا حد.
4. كل شيء آخر (APIs، معاملات، ترتيب، نصوص، أحجام قيم) مطابق حرفياً.

---

## 7) ملف الأدلة (كل قيمة أعلاه قابلة للبرهنة بقراءة واحدة)

- `re/csx_iat.json` — 269 خانة IAT (VA + dll + اسم)
- `re/csx_str_xrefs.json` — 309 نص مُشار إليه + VAs الاستدعاء (بعد فلتة
  3 إشارات خاطئة داخل `.text` — انظر ملاحظة التحذير أدناه)
- `re/csx_funcs.json` — 955 بداية دالة مرشحة
- `re/csx_evidence.json` — جدول الثوابت الكاملة للميزة (VA + نص + موقع push)
- `re/dis_40eff0_sso.txt`, `re/dis_40eff0_loopbody.txt`, `re/dis_40ec10_regdel.txt`,
  `re/dis_40e8c0_cachewrite.txt`, `re/dis_40f4ff_serialreset.txt`,
  `re/dis_403d20_*.txt`, `re/dis_4027e0_mtafiles.txt`, `re/dis_413f80_wmi1.txt`,
  `re/dis_41be20_wmi2.txt` — تفكيك كامل للدوال
- أدوات الفحص: `re/re_csx.py`, `re/csx_strmap.py`, `re/csx_funcs.py`

> **تصحيح مسجل:** استعلامات WMI التي ظهرت في ملاحظات وسيطة بشكل
> "SELECT * FROM Win32_VideoController WHERE Name='Intel(R) UHD Graphics 630'"
> **غير موجودة في العينة** (تحقق نهائي بالبحث عن النص كامل: غائبة) — القيم
> الفعلية هي استعلامات `SELECT ... FROM ...` البسيطة في جدول القسم 3.
> لم تُعتمد أي قيمة في هذا التقرير إلا بعد قراءة بايتاتها مباشرة.

---

## 8) خطوات التحقق المطلوبة منك (Windows + MTA:SA)

1. انسخ `bin/csx_spoof.dll` و`bin/test_csx_spoof.exe` لمجلد واحد.
2. `test_csx_spoof.exe probe` → سجّل الحالة "قبل".
3. نفّذ زر **R E S E T   S E R I A L** في CSX.exe → سجّل الحالة "بعد".
4. أعد `test_csx_spoof.exe probe` → قارن: يجب أن يطابق تماماً ما فعله CSX.exe.
5. بدّل: `test_csx_spoof.exe reset` (بدل CSX.exe) → قارن مرة أخرى.
6. داخل NRTH: زر "Reset MTA Serial (CSX)" في تبويب **Other** — نفس السلوك.

أبلغني بأي فرق (أي قيمة لم تُحذف/لم تُكتب، أو سلوك مختلف) وسأصحح بناءً
على ملاحظاتك. **بعد تأكيد المطابقة** نبني المكافح (المقترح مبدئياً:
مراقِب لهذه الأهداف بالذات — غياب المفاتيح/الADS/القيم المُصفّرة +
بصمات WMI غير المتسقة — بنفس منهج NRTH_audit).
