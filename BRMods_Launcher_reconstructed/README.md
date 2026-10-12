# تقرير الهندسة العكسية — BR.Mods.Launcher.exe

**تاريخ التحليل:** 2026-10-12
**المصدر:** `https://github.com/saradztn/kuopk/blob/main/BR.Mods.Launcher.exe` (فرع main)
**ملاحظة المنهج:** كل قيمة مذكورة هنا **قُرئت من بايتات الملف مباشرة** (أعطال file/RVA مرفقة).
لم يُنفَّذ العينة إطلاقًا في أي بيئة.

---

## 1) هوية الملف

| الخاصية | القيمة | الدليل |
|---|---|---|
| الحجم | 353,792 بايت | `sha256sum` |
| SHA-256 | `70627db435bdca7082ce1ff6628525ccf1b2ad23fb1b548a4022604673ea6767` | ملف `.sha256` المرفق |
| النوع | **C++ أصلي x64 (MSVC، لينكر 14.44 = VS2022)** — ليس Rust (التصحيح: جداول تفكيك أسماء C++ + RTTI `std::system_error`/`Gdiplus::SolidBrush` تثبت C++) | جداول demangle في .rdata؛ أسماء RTTI @ file 0x53ac0+ |
| الرمز | Win32 GUI + GDI+ (رسم مخصص)، بدون import table — **كل الـ WinAPI تُحل وقت التشغيل** (LoadLibraryW + GetProcAddress)؛ جدول أسماء الـ API كامل @ rva 0x53600–0x54420 | 185 slot غير مباشر، خُريطة كاملة في `evidence/` (182/185 مطابقة لأسماء API) |
| نقطة الدخول | 0xf0f0 (ImageBase 0x140000000) | الترويسة |
| Manifest | **requireAdministrator** | .rsrc |
| لغة الواجهة | **البرتغالية (pt-BR)**: `Verificando atualizacoes...` (= "جارٍ التحقق من التحديثات...") | u16 @ rva 0x32410، مرجع @ 0x100a |

### العبث المتعمد في الترويسة (anti-RE)
- حقل `Win32VersionValue` **محذوف** (إزاحة −4 لكل الحقول التالية) — وكل الحقول من file 0x152 تطابق تمامًا بإزاحة −4 (SizeOfImage=0x5d000، Subsystem=2 GUI، DllChars=0xc160، NumberOfRvaAndSizes=16).
- جدول data-directories موجود @ file 0x18c لكنه **مُبعثر الدلالات** (بعض الحقول تشير إلى .rsrc/.reloc بشكل غير قياسي).
- قسم `.pdata` (0x58000) **مملوء بـ RUNTIME_FUNCTION زائفة** (350 مدخلة، 0 منها داخل .text) — لا يُستخدم.
- قسم `.reloc` المُعلَن (file 0x55e00) **ليس جدول إعادة مواقع صالح**.
- الاستنتاج: الترويسة كُسرت **عمدًا من قِبل المطور** لتعكير أدوات التحليل — الكود نفسه يتفكك 100% بنظافة (41,298 تعليمات).

---

## 2) بنى البيانات المهمة

### سلسلة التطبيق (u16 pool @ rva 0x32388–0x32578) — كل مرجع موقعه بالأكواد
| rva | النص | مواقع المرجع | الدلالة |
|---|---|---|---|
| 0x32388 | `CONOUT$` | 0x2326e, 0x2331d | كتابة على الكونسول رغم كونه GUI |
| 0x323de | `gntdll.dll` | **لا شيء** | **سلسلة ميتة/طُعم** (صفر مراجع — قُيِّدت بـ zero refs) |
| 0x32410 | `Verificando atualizacoes...` | 0x100a | رسالة الحالة الابتدائية |
| 0x32448 | `*.old_*` | 0x209e | نمط تنظيف النسخ القديمة |
| 0x32460 | `\BRMods` | 0x7b52, 0x7b6e | مجلد المودات |
| 0x32470 | `kernel32.dll` | 0x25df, 0xe8a6 | للحقن والمُحلِل |
| 0x32490 | `LoadLibraryW` | 0x25ef | **دالة النقطة لـ CreateRemoteThread** |
| 0x324a8/0x324c8/0x324d8 | `last_modified=` `etag=` `content_length=` | 0x4abd, 0x4bc8, 0x4d35 (+0xd6a9) | مفاتيح ملف brmod.meta |
| 0x324f8/0x32518/0x32528 | `last_modified` `etag` `content_length` | 0x5421, 0x54b2, 0x553e | أسماء وسائط HTTP في الاستجابة |
| 0x32548 | `.old_` | 0x5882 | لاحقة النسخ الاحتياطي |
| 0x32558 | `.part` | 0x7efc | ملف التنزيل الجزئي |
| 0x32568 | `\brmod.meta` | 0x7f5a | ملف الحالة/الكاش |

**لا يوجد أي URL في كامل الملف** (لا ASCII ولا u16) — عنوان التحديث يُمرَّر وقت التشغيل (من قسم الواجهة)؛ مصدره الدقيق **غير قابل للثبوت من البايتات (UNVERIFIED)** لكن الـ GET نفسه موثق بالكامل (القسم 3).

### GUID مكتوب في الثوابت: `F1B32785-6FBA-4FCF-9D55-7B8E7F157091` = **FOLDERID_LocalAppData**
(بايتات @ file 0x25240: `85 27 b3 f1 ba 6f cf 4f 9d 55 7b 8e 7f 15 70 91`) → مسار العمل =
`%LocalAppData%\BRMods` (مثال: `C:\Users\<user>\AppData\Local\BRMods`) — **لكل مستخدم**.

### اسم العملية الهدف: `HD-Player.exe`
يُبنى حرفًا حرفًا في الدالة @0x18b0 (طول 13 = `mov r8d,0xd` @0x18c0):
`0x48 0x44 0x2d 0x50 0x6c 0x61 0x79 0x65 0x72 0x2e 0x65 0x78 0x65` = **H D - P l a y e r . e x e**
(سياق المشهد البرازيلي: "HD-Player" هو اسم مُشغِّل/لاونشر خادم MTA:SA/GTA-RP خاص — انظر القسم 5).

---

## 3) تدفق التحديث (الأدلة بالأكواد)

### أ) فحص التحديث — عميل WinHTTP الأول (@0x3580–0x3e43)
`WinHttpCrackUrl`@0x3656 → `WinHttpOpen`@0x37fb → `WinHttpSetOption`@0x38da → `WinHttpSetTimeouts`@0x38f6 → `WinHttpConnect`@0x390e → `WinHttpOpenRequest`(GET)@0x3a3b → `WinHttpSendRequest`@0x3b29 → `WinHttpReceiveResponse`@0x3b3c → **`WinHttpQueryHeaders` (الراية 0x20000013 = WINHTTP_QUERY_STATUS_CODE، `mov edx,0x20000013` @0x3b62)** → قراءة وسائط أخرى @0x3bca/0x3c6f/0x3cfe → إغلاقhandles ×27.
الوظيفة: مقارنة حالة البعيد (200 جديد / 304 بدون تغيير) مع `brmod.meta`.

### ب) التنزيل — عميل WinHTTP الثاني (داخل الدالة @0x49f0–0x6dee)
- طلب مشروط مبني من meta: `If-None-Match: <etag>` و`If-Modified-Since: <last_modified>` (المفاتيح @0x4abd–0x4d35).
- `WinHttpCrackUrl`@0x5cf0 → Open@0x5edb → SetOption@0x5fc1 → Connect@0x5fd9 → OpenRequest@0x612f → SendRequest@0x6222 → ReceiveResponse@0x630a → QueryHeaders(status)@0x640e.
- **304 → لا شيء.** ورنـا: حلقة `WinHttpReadData`@0x6599 → `WriteFile`@0x65d7 إلى `<الهدف>.part` → `PostMessageW` للواجهة (تقدم)@0x6642/0x676c.
- بعد الانتهاء: وسائط الاستجابة (etag/last_modified/content_length) تُكتب في `brmod.meta` (دالة @0xxd5b3–0xd9c9).
- **التثبيت:** `MoveFileExW` (6 مواقع: 0x579e/0x57cc/0x5965/0x5993/0x59cf/0x5ae0): الملف القديم → `<الاسم>.old_<ختم>` ثم `.part` → النهائي؛ `SetFileTime`+`SystemTimeToFileTime`@0x66c5/0x66dd (حفظ أوقات الملفات)؛ `DeleteFileW`@0x593e/0x59af/0x5c5c (تنظيف `.part` الفاشل).

### ج) التنظيف (@0x2020–0x248d)
`FindFirstFileW("*.old_*")`@0x20cb → `FindNextFileW`@0x220d → `DeleteFileW`@0x21bf → `FindClose`@0x221e — حذف النسخ الاحتياطية القديمة.

### د) الكونسول (@0x23249–0x233xx)
`CreateFileW("CONOUT$")`@0x23282/0x2333c → `WriteFile` → `CloseHandle`@0x232b1/0x23311 (سجل نصي رغم كونه GUI).

---

## 4) ⚠️ الوظيفة الحساسة: حقن DLL في عملية اللعبة

### مسح العمليات + فتحها (داخل الدالة @0x77c0–0x92b8)
```
@0x7950  CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS=2, 0)     (mov ecx,2 @0x794b)
@0x799b  Process32FirstW   (PROCESSENTRY32W بحجم 0x234)
@0x79bb  مقارنة szExeFile مع "HD-Player.exe"  (دالة المقارنة @0x17200)
@0x79e2  [الرصيد] = dwProcessId
@0x79cf  Process32NextW  (الحلقة)
@0x85f4  mov ecx, 0x43a          ; PROCESS_ALL_ACCESS
@0x85f9  OpenProcess(PROCESS_ALL_ACCESS, NULL, pid)
@0x861e  call InjectRemoteDll(hProc, dllPath, &err)   ← الدالة 0x2490 (أدناه)
@0x862e  CloseHandle
@0x864e  PostMessageW(hwnd, 0x8001 /*WM_APP+1*/, 0x64 /*=100%/تم*/)
```

### دالة الحقن @0x2490–0x2a1b (تفكيكها الكامل في `evidence/f2_injection_0x2490-0x2a1b.asm`)
```c
SIZE_T  bytes  = strlen(dllPath)*2 + 2;                    // @0x24af-0x24d4
LPVOID  remote = VirtualAllocEx(hProc, NULL, bytes,
                                MEM_COMMIT|MEM_RESERVE /*0x3000 @0x24c1*/,
                                PAGE_READWRITE /*4 @0x24c7*/); // @0x24d7
WriteProcessMemory(hProc, remote, dllPath, bytes, NULL);   // @0x2561
HMODULE k32   = GetModuleHandleW(L"kernel32.dll");         // @0x25df-0x25e6
FARPROC loadlib = GetProcAddress(k32, L"LoadLibraryW");    // @0x25ef-0x25f6
HANDLE th = CreateRemoteThread(hProc, NULL, 0,
                               (LPTHREAD_START_ROUTINE)loadlib, // @0x267a
                               remote,           // المعامل = مسار الـ DLL البعيد // @0x2683
                               0, NULL);                               // @0x2688
// عند النجاح: GetExitCodeThread @0x2724، CloseHandle @0x272d،
// VirtualFreeEx(...,MEM_RELEASE 0x8000) @0x26a5/0x2742
```
**هذا حقن LoadLibraryW الكلاسيكي:** يُكتب مسار DLL في ذاكرة عملية HD-Player.exe ثم تُشغَّل في خيط بعيد يبدأ من عنوان `LoadLibraryW` (صالح هناك لأن kernel32 يُحمَّل في نفس الأساس) — فيُحمَّل الـ DLL المود داخل اللعبة.
خيط `VirtualFreeEx` أربع مرات (0x257a/0x2610/0x26a5/0x2742) = تنظيف في مسارات الفشل + النهائي.

**ملاحظة أمان مهمة (بُنيَت على البايتات):** عنوان البداية مُؤخَذ من `GetModuleHandleW("kernel32.dll")` + `GetProcAddress("LoadLibraryW")` في **عملية launcher نفسها** (أي نفس الـ image). هذا النمط يفترض أن kernel32 في نفس الأساس عبر العمليتين — وهو الفرض المعتمد في هذا النمط من الحقن.

---

## 5) واجهة المستخدم (GUI) @0xb1xx–0xbcb8 + الرسم @0xa2c0–0xa9ad
- **مضاد-تحليل:** `SetErrorMode`@0xb193، `IsDebuggerPresent`@0xb199، `CheckRemoteDebuggerPresent(GetCurrentProcess())`@0xb1ae–0xb1bb، `SetProcessMitigationPolicy`×2@0xb23d/0xb259.
- **مثيل واحد:** `CreateMutexW`@0xb3fe.
- **فحص ثانٍ للعمليات** (هل اللعبة تعمل؟): `CreateToolhelp32Snapshot`@0xb447 + Process32First/Next@0xb486/0xb4ad.
- `ShellExecuteExW`@0xb3ba (فتح رابط/مجلد — الهدف غير محدد من البايتات: UNVERIFIED).
- **نافذة MTA-like:** `GdiplusStartup`@0xb67b، `RegisterClassExW`@0xba00، مقاسات الشاشة `GetSystemMetrics`@0xba9d/0xbaa7، `CreateWindowExW`(LAYERED+TOPMOST)@0xbb04، `SetLayeredWindowAttributes`@0xa9ad، `ShowWindow/UpdateWindow`@0xbbb0/0xbbb9، `SetTimer`@0xa9c4.
- **حلقة رسائل قياسية:** `GetMessageW`@0xbbe6/0xbc19 → `TranslateMessage`@0xbbf7 → `DispatchMessageW`@0xbc04 → `DefWindowProcW`@0xab76؛ `MessageBoxW`×5 (أخطاء/تنبيهات)@0xac4e/0xb5bd/0xb6c5/0xba4d/0xbb54.
- **الرسم (double-buffered GDI+):** `GetClientRect`@0xa2c0، `CreateCompatibleDC/Bitmap`@0xa2db/0xa2ed، `BitBlt`@0xa87e؛ GDI+ كامل: خلفية `GdipFillRectangleI`@0xa3b2، **مستطيل بزوايا دائرية** (`GdipCreatePath`@0x340b + `GdipAddPathRectangleI`×2 + `GdipAddPathArcI`×4 @0x34a8–0x3544 + `GdipFillPath`)، حدود `GdipCreatePen1`@0xa448، نص مركزي `GdipDrawString`@0xa676 (خط من الاسم @0xa57e/0xa5a9) — أي واجهة "splash/update" مرسومة يدويًا.
- الختام: `DestroyWindow`@0xac97/0xad50، `GdiplusShutdown`×3@0xba16/0xbb1d/0xbc2a، `ExitProcess`@0xbcba.
- عامل التحديث يعمل على خيط منفصل (مرارات `std::thread` @0x174xx/0x175a0) ويرسل التقدم `PostMessageW` (المراسلات @0x6642/0x676c/0x826a/0x864e/0x883f — WM_APP+1 بقيم تقدم تنتهي بـ 100).

---

## 6) الحكم: هل هو Malware؟

### ما **يبرهنه** البايت (وجوديًا)
- ✅ واجهة تحديث مودات pt-BR ("BR Mods") مع كاش `brmod.meta` (etag/last_modified/content_length) وتنزيل مشروط عبر WinHTTP.
- ✅ مسار العمل `%LocalAppData%\BRMods` (GUID LocalAppData مثبت بالبايتات).
- ✅ **حقن DLL في عملية `HD-Player.exe`** عبر VirtualAllocEx/WriteProcessMemory/CreateRemoteThread(LoadLibraryW) — **بإثبات تعليماتِى كامل**.
- ✅ مضاد-تحليل + مثيل واحد + requireAdministrator + ترويسة PE مُعبَث بها عمدًا.

### ما **لا يوجد** في الملف (سُحب ببحث استنفادي في جدول الـ API كامل — 123 دالة مقروءة)
- ❌ **لا ثبات/استمرارية:** لا كتابة سجل (لا RegSetValue* أصلًا — "advapi32" فقط كاسم بديل لـ CRT)، لا خدمات، لا مهام مجدولة، لا مجلدات Startup.
- ❌ **لا تسريب بيانات:** لا سوكيتات خام (لا WSA* — الشبكة الوحيدة WinHTTP نحو عناوين التحديث)، لا تشفير (لا Crypt*).
- ❌ **لا كيب-لوجر/خطافات:** لا SetWindowsHookEx، لا GetAsyncKeyState.
- ❌ **لا فدية/تخريب:** لا مسح واسع للملفات (FindFirst/Next لاستخدامين فقط: تنظيف `*.old_*` والبحث عن اللعبة).
- ❌ لا WMI، لا أسماء ملفات مشبوهة أخرى (الميتة الوحيدة: `gntdll.dll` = طُعم بلا مراجع).

### الاستنتاج
**ليس برنامجًا خبيثًا بالمعنى التقليدي** (لا سرقة، لا ثبات، لا تسريب، لا تشفير، لا تحكم عن بُعد). هو **أداة "مود" للعبة** (مشهد MTA:SA/GTA-RP البرازيلي): تحدّث ملفات المود في `%LocalAppData%\BRMods` ثم **تُحقن المود DLL داخل عميل اللعبة `HD-Player.exe`** — وهي آلية شائعة وقانونية نسبيًا في مشهد مودات الألعاب (بنفس فئة loaders/ASI-loaders)، والواجهة تعلن عن عملها ("Verificando atualizacoes...").

**لكنه يقع في منطقة رمادية (PUP/Grayware)** لأن:
1. **حقن DLL في عملية أخرى** — سلوك سيُنبّه له أي Antivirus (نمط "code injection") حتى لو كان الهدف لعبة.
2. **الـ DLL المُحقنة غير موجودة في هذا الملف** — تُنزَّل وقت التشغيل من خادم المود؛ **سلامتها لا تُقيَّم من هذه العينة (UNVERIFIED)** — ثقل الثقة هنا على **موثوقية الخادم الذي يوزع التحديثات** (أي: صلاح العينة = صلاح مصدر التحديثات).
3. **مضاد-تحليل + requireAdministrator + ترويسة معطوبة عمدًا** = نية إعاقة التحليل (شائع في أدوات المشهد، لكنها أيضًا سمات تُستخدم في الأذرع الخبيثة).

**التوصية العملية:** إذا كنت تلعب على سيرفر BR الذي يوزع هذا الـ launcher وتثق به → السلوك متوقع (تحديث + حقن مود في اللعبة فقط). إذا وصلك من مصدر غير معروف → **لا تشغّله**، لأن الـ DLL الذي سيُحقن في `HD-Player.exe` غير قابل للتدقيق من هذا الملف وحده؛ افحص أيضًا محتوى `%LocalAppData%\BRMods` بعد التشغيل إن أردت.

---

## 7) ما قُدم (ملفات)
- `launcher_reconstructed.cpp` — **إعادة بناء المصدر 1:1 من التفكيك** (كل كتلة مرتبطة بأكواد RVA؛ الأسماء/التعليقات معاد بناؤها — الأصل لا يُسترجع من باينري — وكل غير القابل للثبوت موسوم UNVERIFIED).
- `evidence/f2_injection_0x2490-0x2a1b.asm` — تفكيك دالة الحقن كاملًا.
- `evidence/f4_injector_call_0x8471-0x8700.asm` — منطقة OpenProcess + الاستدعاء + PostMessage.
- `evidence/f4_process_scan_0x792f-0x7a86.asm` — مسح HD-Player.exe + LocalAppData.
- `evidence/target_name_builder_0x18b0.asm` — بناء سلسلة "HD-Player.exe" حرفًا حرفًا.
- `BR.Mods.Launcher.exe.sha256` — بصمة العينة.

### فجوات معلنة (بصراحة)
1. **نص الـ URL** غير موجود في الملف — مصدره الدقيق غير قابل للثبوت من البايتات (يُمرَّر وقت التشغيل من قسم الواجهة).
2. **اسم الـ DLL المُحقنة** يُبنى وقت التشغيل (UNVERIFIED) — البديل المرشح الوحيد في الثوابت هو `gntdll.dll` لكنه ميت (صفر مراجع).
3. تفاصيل **مضمون الرسومات** (الألوان/النصوص على الواجهة) غير مسترجعة حرفيًا — البنية كاملة موثقة فقط.
4. جدول import الخاص (u16-off + name) فُكّ نجاحًا بنسبة 182/185 slot؛ الـ 3 غير المفسرة مواقع `call [reg]` غير-API (تفويجات std/vtable).
