# csx_spoof — إعادة بناء "الـ Spoofer" من CSX.exe (R2)

تكرار **سلوكي دقيق** لميزة "Reset MTA Serial" في `CSX.exe`
(SHA-256 `d5ed9e6a57952d2a2d7876813376784868126e9295ee55ba01b45a395fc4ee556`).

- الدليل الكامل (كل الثوابت + مواقعها في العينة): [`csx_spoof.h`](csx_spoof.h)
- التقرير الكامل بالعربية: [`../CSX_REPORT.md`](../CSX_REPORT.md)
- أدلة آليّة: [`../re/csx_evidence.json`](../re/csx_evidence.json)

## البناء (Linux/Windows — zig كـ cross-compiler)
```bash
pip install --target /tmp/py_zig ziglang   # إذا لم يكن موجوداً
bash build_csx_spoof.sh
# -> ../bin/csx_spoof.dll  +  ../bin/test_csx_spoof.exe
```
أو عبر السكربت الرئيسي `../build_x86.sh` (يبني NRTH + csx_spoof معاً).

## الاختبار على Windows + MTA:SA
```
test_csx_spoof.exe probe    # الحالة قبل (قراءة فقط)
test_csx_spoof.exe reset    # الحالة قبل + تنفيذ + الحالة بعد
```
قارن "بعد" بما يفعله زر **R E S E T   S E R I A L** في CSX.exe الأصلي —
يجب أن يطابق (نفس المفاتيح، نفس القيم، نفس التيارات ADS، نفس مجلد الكاش).

## التصديرات (8)
`CSX_SpooferResetMtaSerial`, `CSX_SpooferClearSsoCredential`,
`CSX_SpooferClearExplorerKeyTrees`, `CSX_SpooferClearNtDataStreams`,
`CSX_SpooferClearMtaSharedCache`, `CSX_SpooferResetMtaRegValues`,
`CSX_SpooferProbe`, `CSX_SpooferLastStatus` (الترتيبات 1-8).

**تحذير:** التنفيذ يغيّر مفاتيح سجل المستخدم/النظام ومسارات NTFS ADS ومجلد
كاش MTA المشترك — كما يفعل الأصلي. لا يوجد هنا أي "تمكين" إضافي: الوصف
للمعرفة، والتشغيل قرار المستخدم.
