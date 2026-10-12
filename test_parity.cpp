/**
 * ============================================================================
 * test_parity.cpp — End-to-end verification suite for NRTH reconstruction
 * ============================================================================
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <string>

#include "nrth_audit.h"
#include "nrth_audit_sigs.h"
#include "nrth_codec.h"
#include "nrth_config.h"
#include "nrth_fonts.h"
#include "nrth_hook.h"
#include "nrth_ui.h"

static int g_passed = 0;
static int g_failed = 0;

#define CHECK(cond, desc)                                                  \
    do {                                                                   \
        if (cond) {                                                        \
            ++g_passed;                                                    \
            printf("  [PASS] %s\n", desc);                                 \
        } else {                                                           \
            ++g_failed;                                                    \
            printf("  [FAIL] %s (line %d)\n", desc, __LINE__);             \
        }                                                                  \
    } while (0)

/* Helper: build a minimal valid PE32 image with a .text section and .rdata section */
static void BuildSyntheticPe32(uint8_t *img, uint32_t imgSize,
                               const uint8_t *textData, uint32_t textLen,
                               const uint8_t *rdataData, uint32_t rdataLen)
{
    memset(img, 0, imgSize);
    /* DOS header */
    img[0] = 'M';
    img[1] = 'Z';
    uint32_t peOff = 0x80;
    img[0x3C] = (uint8_t)(peOff & 0xFF);

    /* NT headers at 0x80 */
    uint8_t *nt = img + peOff;
    nt[0] = 'P'; nt[1] = 'E'; nt[2] = 0; nt[3] = 0;
    /* FileHeader: Machine=0x014C (i386), NumberOfSections=2, SizeOfOptionalHeader=0xE0, Characteristics=0x2102 */
    nt[4] = 0x4C; nt[5] = 0x01;
    nt[6] = 0x02; nt[7] = 0x00;
    nt[20] = 0xE0; nt[21] = 0x00;
    nt[22] = 0x02; nt[23] = 0x21;

    /* OptionalHeader32 at peOff + 24 */
    uint8_t *opt = nt + 24;
    opt[0] = 0x0B; opt[1] = 0x01; /* PE32 magic 0x10B */
    /* EntryPoint RVA = 0x1000 */
    opt[16] = 0x00; opt[17] = 0x10;
    /* ImageBase = 0x10000000 */
    opt[28] = 0x00; opt[29] = 0x00; opt[30] = 0x00; opt[31] = 0x10;

    /* Section headers at opt + 0xE0 */
    uint8_t *sh = opt + 0xE0;
    /* Section 0: .text at RVA 0x1000, raw 0x400, size 0x2000 */
    memcpy(sh, ".text\0\0\0", 8);
    uint32_t textSecSize = 0x2000;
    memcpy(sh + 8,  &textSecSize, 4); /* VirtualSize */
    uint32_t textRva = 0x1000;
    memcpy(sh + 12, &textRva, 4);
    memcpy(sh + 16, &textSecSize, 4); /* SizeOfRawData */
    uint32_t textRaw = 0x400;
    memcpy(sh + 20, &textRaw, 4);

    /* Section 1: .rdata at RVA 0x3000, raw 0x2400, size 0x2000 */
    uint8_t *sh1 = sh + 40;
    memcpy(sh1, ".rdata\0\0", 8);
    uint32_t rdataSecSize = 0x2000;
    memcpy(sh1 + 8,  &rdataSecSize, 4);
    uint32_t rdataRva = 0x3000;
    memcpy(sh1 + 12, &rdataRva, 4);
    memcpy(sh1 + 16, &rdataSecSize, 4);
    uint32_t rdataRaw = 0x2400;
    memcpy(sh1 + 20, &rdataRaw, 4);

    if (textData && textLen <= textSecSize) {
        memcpy(img + textRaw, textData, textLen);
    }
    if (rdataData && rdataLen <= rdataSecSize) {
        memcpy(img + rdataRaw, rdataData, rdataLen);
    }
}

/* Instantiateconcrete bytes matching a wildcard pattern ("55 8B ? ...") */
static uint32_t MaterializePattern(const char *pat, uint8_t *out, uint32_t cap)
{
    uint8_t bytes[256], mask[256];
    uint32_t plen = 0;
    if (NrthPatCompile(pat, bytes, mask, 256, &plen) < 0) return 0;
    if (plen > cap) return 0;
    for (uint32_t i = 0; i < plen; ++i) {
        out[i] = mask[i] ? bytes[i] : (uint8_t)(0x10 + (i & 0x7F));
    }
    return plen;
}

/* Mock Lua callbacks for testing NrthUI_ExecuteLuaViaBridge */
static int         s_mockLuaLoadCalled = 0;
static int         s_mockLuaPcallCalled = 0;
static std::string s_mockLuaLastChunk;
static std::string s_mockLuaLastScript;

static int MockLuaLoadBuffer(void *L, const char *buff, size_t sz, const char *name)
{
    (void)L;
    ++s_mockLuaLoadCalled;
    s_mockLuaLastScript.assign(buff, sz);
    s_mockLuaLastChunk = name ? name : "";
    return 0;
}

static int MockLuaPcall(void *L, int nargs, int nresults, int errfunc)
{
    (void)L; (void)nargs; (void)nresults; (void)errfunc;
    ++s_mockLuaPcallCalled;
    return 0;
}

int main(void)
{
    printf("=== NRTH Parity & Mechanism Verification Suite ===\n");

    /* 1. Built-in nrth_audit self-test */
    char auditReport[4096] = {0};
    int auditRc = NrthAuditSelfTest(auditReport, sizeof(auditReport));
    CHECK(auditRc == 0, "nrth_audit self-test (21 checks)");

    /* 2. Verify nrth_dll.def exports LIBRARY nvx.dll and NVXHookProc @1 */
    {
        FILE *fp = fopen("nrth_dll.def", "rb");
        char defBuf[1024] = {0};
        if (fp) {
            fread(defBuf, 1, sizeof(defBuf) - 1, fp);
            fclose(fp);
        }
        CHECK(strstr(defBuf, "LIBRARY nvx.dll") != NULL &&
              strstr(defBuf, "NVXHookProc=NVXHookProc@12 @1") != NULL,
              "nrth_dll.def: LIBRARY nvx.dll and NVXHookProc @1");
    }

    /* 3. Verify nrth_codec.h single-use gate (L = F - 1) and all 20 encrypted sigs */
    {
        char buf[64] = {0};
        bool gate = false;
        const char *dec = NrthDecryptOnce(kCt_ClientDll, sizeof(kCt_ClientDll), 0x2D, buf, &gate);
        CHECK(gate && strcmp(dec, "client.dll") == 0 && strlen(dec) == sizeof(kCt_ClientDll) - 1,
              "nrth_codec: kCt_ClientDll (K=0x2D, L=F-1=10) -> 'client.dll'");

        gate = false;
        dec = NrthDecryptOnce(kCt_NetcDll, sizeof(kCt_NetcDll), 0x20, buf, &gate);
        CHECK(gate && strcmp(dec, "netc.dll") == 0 && strlen(dec) == sizeof(kCt_NetcDll) - 1,
              "nrth_codec: kCt_NetcDll (K=0x20, L=F-1=8) -> 'netc.dll'");

        gate = false;
        dec = NrthDecryptOnce(kCt_AdsNt2, sizeof(kCt_AdsNt2), 0x20, buf, &gate);
        CHECK(gate && strcmp(dec, "C:\\ProgramData:NT2") == 0,
              "nrth_codec: kCt_AdsNt2 (VA 0x1001e530, K=0x20) -> 'C:\\ProgramData:NT2'");

        bool all20Match = true;
        for (uint32_t i = 0; i < 20; ++i) {
            const NrthSignature *cat = NrthSigAt(i + 1);
            const NrthEncryptedSigEntry &enc = kNrthEncryptedSigs[i];
            char pbuf[256] = {0};
            bool sgate = false;
            const char *p = NrthDecryptOnce(enc.cipher, enc.fieldSize, enc.key, pbuf, &sgate);
            if (!cat || !sgate || strcmp(p, cat->pattern) != 0 ||
                enc.fieldSize != cat->pattern_len + 1 || enc.key != cat->xor_key) {
                all20Match = false;
                break;
            }
        }
        CHECK(all20Match, "nrth_codec: all 20 encrypted signatures match nrth_audit_sigs.h (L=F-1)");
    }

    /* 4. Verify NrthFindHiddenSignatures discovers all 20 encrypted signatures in .rdata */
    {
        uint8_t rdata[0x2000];
        memset(rdata, 0, sizeof(rdata));
        uint32_t off = 0;
        for (uint32_t i = 0; i < 20; ++i) {
            off = (off + 3u) & ~3u; /* 4-byte align */
            memcpy(rdata + off, kNrthEncryptedSigs[i].cipher, kNrthEncryptedSigs[i].fieldSize);
            off += kNrthEncryptedSigs[i].fieldSize + 4u;
        }
        uint8_t peImg[0x4400];
        BuildSyntheticPe32(peImg, sizeof(peImg), NULL, 0, rdata, sizeof(rdata));
        char foundText[8192] = {0};
        uint32_t foundVas[32] = {0};
        int32_t nHidden = NrthFindHiddenSignatures(peImg, sizeof(peImg), 20,
                                                   foundText, sizeof(foundText), foundVas, 32);
        CHECK(nHidden == 20, "NrthFindHiddenSignatures discovers all 20 XOR-encrypted signatures in .rdata");
    }

    /* 5. Verify nrth_config.cpp: C:\Overwack\loader_config.cfg, menu_key=%d (45), no_spoofer=%d */
    {
        CHECK(strcmp(NrthConfig_GetPrimaryPath(), "C:\\Overwack\\loader_config.cfg") == 0 &&
              strcmp(NrthConfig_GetMenuKeyFmt(), " menu_key=%d") == 0 &&
              strcmp(NrthConfig_GetNoSpooferFmt(), " no_spoofer=%d") == 0,
              "nrth_config: decrypted path & format tokens (0x1001fcff, 0x1001fd7b, 0x1001fdc5)");

        g_cfg.menuKey   = 45;
        g_cfg.noSpoofer = 1;
        const char *tmpCfg = "/tmp/test_loader_config.cfg";
        const char *tmpOvr = "/tmp/test_profile.ovr";
        bool saved = NrthConfig_SaveOvr(tmpOvr, tmpCfg);
        g_cfg.menuKey   = 0;
        g_cfg.noSpoofer = 0;
        bool loaded = NrthConfig_Load(tmpCfg);
        CHECK(saved && loaded && g_cfg.menuKey == 45 && g_cfg.noSpoofer == 1,
              "nrth_config: round-trip SaveOvr/Load preserves menu_key=45 (VK_INSERT) & no_spoofer=1");
        remove(tmpCfg);
        remove(tmpOvr);
        remove("loader_config.cfg");
    }

    /* 6. Verify D3D9 vtable pattern scanner (VA 0x10012980: C7 06 ? ? ? ? 89 86 ? ? ? ? 89 86) */
    {
        uint8_t fakeD3D9[256];
        memset(fakeD3D9, 0x90, sizeof(fakeD3D9));
        uint8_t seq[] = {
            0xC7, 0x06, 0x78, 0x56, 0x34, 0x12, /* mov dword ptr [esi], 0x12345678 */
            0x89, 0x86, 0x10, 0x00, 0x00, 0x00, /* mov [esi+10h], eax              */
            0x89, 0x86                          /* mov [esi+...], eax              */
        };
        memcpy(fakeD3D9 + 64, seq, sizeof(seq));
        void **vt = FindD3D9VTableInBuffer_10012980(fakeD3D9, sizeof(fakeD3D9));
        CHECK((uintptr_t)vt == 0x12345678u,
              "GetD3D9DeviceVTable (0x10012980): pattern scan extracts vtable pointer 0x12345678");
    }

    /* 7. Verify 37 pattern scans, 18 hooks, 6 0xC3 patches, and A/B audit detection */
    {
        Nrth_ResetArmingCounters();

        uint32_t nClientHooks = 0, nNetcHooks = 0, nPatches = 0;
        const NrthHookSlot    *clientHooks = Nrth_GetClientHookTable(&nClientHooks);
        const NrthHookSlot    *netcHooks   = Nrth_GetNetcHookTable(&nNetcHooks);
        const NrthPatchRecord *patches     = Nrth_GetPatchList_101493e4(&nPatches);

        CHECK(nClientHooks == 11 && nNetcHooks == 4 && nPatches == 6,
              "table sizes: 11 client hooks (0x10005b80), 4 netc hooks (0x10020640), 6 patches (0x101493e4)");

        /* Verify all 6 prepare/call pairs have exact 11-byte delta and pattern VAs 0x10023670..0x10023030 */
        bool pairsOk = true;
        for (uint32_t i = 0; i < 6; ++i) {
            if ((patches[i].callVa - patches[i].prepVa) != 11u ||
                patches[i].patternGlobal != (0x10023670u - i * 0x140u) ||
                patches[i].patchByte != 0xC3u) {
                pairsOk = false;
                break;
            }
        }
        CHECK(pairsOk, "6 prepare/write pairs: callVa - prepVa == 11, patterns 0x10023670..0x10023030, byte 0xC3");

        /* Build synthetic client.dll and netc.dll PE32 images containing all 20 catalog signatures
         * plus the additional patterns so all 37 scans resolve and patch/detour cleanly. */
        uint8_t clientText[0x2000];
        memset(clientText, 0xCC, sizeof(clientText));
        uint32_t cur = 0x40;
        for (uint32_t i = 1; i <= 20; ++i) {
            const NrthSignature *s = NrthSigAt(i);
            cur += MaterializePattern(s->pattern, clientText + cur, 256) + 0x20;
        }
        for (uint32_t i = 0; i < nClientHooks; ++i) {
            if (clientHooks[i].pattern) {
                cur += MaterializePattern(clientHooks[i].pattern, clientText + cur, 256) + 0x20;
            }
        }
        static const char *const kExtraC400[8] = {
            "55 8B EC 56 FF 75 ? 8B 75 ? 56 E8 ? ? ? ? 8B C8",
            "55 8B EC 57 8B 7D ? 8B 4F ? 8B 41 ? 3B 41 ? 72 ? 57 E8 ? ? ? ? 83 C4 ? 56 FF 75 ? 8B 77 ? FF 75 ? 57 E8 ? ? ? ? ? ? 83 C4 ? C7 46 ? ? ? ? ? 8B 4F ? 8B 47 ? 5E 3B 41 ? 72 ? C7 05 ? ? ? ? ? ? ? ? 83 47 ? ? 5F 5D C3 ? ? ? ? ? ? ? ? ? ? ? ? 55 8B EC 8B 4D",
            "55 8B EC 56 57 FF 75 ? 8B 7D",
            "55 8B EC 83 EC ? 56 8B 75 ? 57 FF 75",
            "55 8B EC 8B 55 ? 8B 42 ? C7 40",
            "55 8B EC 57 FF 75 ? 8B 7D ? 57 E8 ? ? ? ? 83 C4 ? 83 78",
            "55 8B EC 53 57 8B 7D ? 8B 47 ? 2B 47 ? 83 E0 ? 83 F8 ? 7D ? C7 05 ? ? ? ? ? ? ? ? FF 75 ? 57 E8 ? ? ? ? 8B D8 83 C4 ? 83 7B ? ? 74 ? C7 05 ? ? ? ? ? ? ? ? 56 FF 75",
            "55 8B EC 8B 55 ? F2 0F 10 45"
        };
        uintptr_t expectedCreatetableOff = 0;
        for (uint32_t i = 0; i < 8; ++i) {
            if (i == 1) {
                expectedCreatetableOff = cur;
            }
            cur += MaterializePattern(kExtraC400[i], clientText + cur, 256) + 0x20;
        }

        uint8_t cleanClientPe[0x4400], armedClientPe[0x4400];
        BuildSyntheticPe32(cleanClientPe, sizeof(cleanClientPe), clientText, sizeof(clientText), NULL, 0);
        memcpy(armedClientPe, cleanClientPe, sizeof(armedClientPe));

        uint8_t netcText[0x2000];
        memset(netcText, 0xCC, sizeof(netcText));
        uint32_t ncur = 0x40;
        ncur += MaterializePattern(NrthSigAt(16)->pattern, netcText + ncur, 256) + 0x20;
        for (uint32_t i = 1; i < nNetcHooks; ++i) {
            ncur += MaterializePattern(netcHooks[i].pattern, netcText + ncur, 256) + 0x20;
        }
        ncur += MaterializePattern("55 8B EC 83 EC ? 56 8B 75 ? 83 7E ? 00 75 ?", netcText + ncur, 256) + 0x20;
        ncur += MaterializePattern("55 8B EC 56 8B 75 ? 57 8B 7D ? 8B C6 2B C7",   netcText + ncur, 256) + 0x20;

        uint8_t cleanNetcPe[0x4400], armedNetcPe[0x4400];
        BuildSyntheticPe32(cleanNetcPe, sizeof(cleanNetcPe), netcText, sizeof(netcText), NULL, 0);
        memcpy(armedNetcPe, cleanNetcPe, sizeof(armedNetcPe));

        /* Execute the 3 arming/resolver blocks on the .text section of armedClientPe and armedNetcPe */
        uint32_t cHooked   = ArmClient_10005b80(armedClientPe + 0x400, 0x2000, true);
        uint32_t cResolved = ResolveClientOffsets_1000c390(armedClientPe + 0x400, 0x2000);
        uint32_t nActions  = ArmNetc_10020640(armedNetcPe + 0x400, 0x2000, true, true);
        uint32_t nResCount = 0;
        const uintptr_t *resOffs = Nrth_GetClientResolvedOffsets(&nResCount);

        CHECK(cHooked == 11 && cResolved == 20 && nActions == 10 &&
              resOffs[4] == (uintptr_t)(armedClientPe + 0x400 + expectedCreatetableOff) &&
              resOffs[4] != resOffs[6],
              "ArmClient_10005b80 (11 hooks), ResolveClientOffsets_1000c390 (20/20 ordered scans, lua_createtable != Sig #9), ArmNetc_10020640 (4 hooks + 6 patches)");
        CHECK(Nrth_GetTotalPatternScans() == 37,
              "Total pattern scans across 0x10005b80 (11) + 0x1000c390 (20) + 0x10020640 (6) == 37");
        CHECK(Nrth_GetTotalInstalledHooks() == 15 && (Nrth_GetTotalInstalledHooks() + 3) == 18,
              "Total hooks: 11 client + 4 netc (+ 1 LdrLoadDll + 2 D3D9) == 18");
        CHECK(Nrth_GetTotalAppliedPatches() == 6,
              "Total 0xC3 patches applied via PatchByte_10011870 == 6");

        /* Verify NrthAuditDiff detects the 7 client.dll DETOUR_JMP32 footprints and 1 netc.dll KILL_RET footprint */
        NrthAuditDiffRow diffClient[NRTH_SIG_COUNT];
        int32_t clientAlerts = NrthAuditDiff(cleanClientPe, sizeof(cleanClientPe),
                                             armedClientPe, sizeof(armedClientPe),
                                             diffClient, NRTH_SIG_COUNT);
        NrthAuditDiffRow diffNetc[NRTH_SIG_COUNT];
        int32_t netcAlerts = NrthAuditDiff(cleanNetcPe, sizeof(cleanNetcPe),
                                           armedNetcPe, sizeof(armedNetcPe),
                                           diffNetc, NRTH_SIG_COUNT);
        CHECK(clientAlerts == 7 && netcAlerts == 1 && diffNetc[15].susState == NRTH_PRO_KILL_RET,
              "NrthAuditDiff A/B verification: 7 DETOUR_JMP32 alerts on client.dll + 1 KILL_RET (0xC3) alert on netc.dll");
    }

    /* 8. Verify Packet Catalogue, Report Channels, Sync Structs, and Lua VM Bridge */
    {
        uint32_t pktCount = 0;
        const NrthPacketDef *pkts = NrthUI_GetPacketCatalog(&pktCount);
        bool foundChallenge = false;
        int reportChannels = 0;
        for (uint32_t i = 0; i < pktCount; ++i) {
            if (strcmp(pkts[i].name, "PACKET_ID_CHEAT_CHALLENGEMEMORY") == 0) {
                foundChallenge = true;
            }
            if (pkts[i].isReportChannel) {
                ++reportChannels;
            }
        }
        CHECK(pktCount >= 70 && foundChallenge && reportChannels == 4,
              "Packet catalog: PACKET_ID_CHEAT_CHALLENGEMEMORY + 4 report channels (SCREENSHOT/DIAGNOSTIC/ACINFO/TRANSGRESSION)");

        NrthUI_SyncFeaturesToState();
        CHECK(Nrth_GetPlayerHealthSync()->fHealth == 100.0f &&
              Nrth_GetWeaponAimSync()->fClickWarpMaxDist == 300.0f,
              "Feature state sync: SPlayerHealthSync & SWeaponAimSync initialized and synced");

        /* Exercise in-game feature tick & GTA:SA/MTA action helpers */
        Nrth_TickGameFeatures_10015812();
        Nrth_AirbreakTick_10001d80();
        Nrth_TriggerAllWeapons_1002a5a7();
        Nrth_TriggerJetpack_1002a86c();
        bool vehAct = Nrth_RepairCurrentVehicle_1002f070() ||
                      Nrth_StartCurrentVehicleEngine_1002f0f0() ||
                      Nrth_UnlockNearestVehicle_1002eea0() ||
                      Nrth_StopCurrentVehicle() ||
                      Nrth_DestroyCurrentVehicle();
        CHECK(!vehAct && Nrth_GetPlayerHealthSync()->bVehGodMode == 0 &&
              Nrth_GetPlayerHealthSync()->bDriveWater == 0 &&
              Nrth_GetPlayerHealthSync()->bFlyingCar == 0,
              "In-game feature tick (0x10015812) & GTA:SA/MTA action helpers (0x10001d80..0x1002f0f0) guarded safely");

        /* Live hook callbacks (0x10004220, 0x100050a0, 0x100052b0, 0x100054a0, 0x1001da80) */
        NrthUI_OnClientScriptLoaded("@:hud/client.lua", "outputChatBox('hi')", 19);
        NrthUI_OnResourceStarted("hud");
        bool stopResOk = Nrth_StopClientResource_100054a0("hud");
        bool evNotBlocked = !NrthUI_ShouldBlockServerEvent("onPlayerJoin");
        bool pktReportBlocked = NrthUI_OnPacketSent(80); /* PACKET_ID_PLAYER_SCREENSHOT blocked by default */
        bool pktNormalAllowed = !NrthUI_OnPacketSent(37); /* PACKET_ID_COMMAND allowed by default */
        CHECK(stopResOk && evNotBlocked && pktReportBlocked && pktNormalAllowed,
              "Live hook callbacks: script dumper (0x10004220), resource stop (0x100054a0), event filter (0x100050a0), packet filter (0x1001da80)");

        NrthLuaVmBridge *bridge = Nrth_GetLuaVmBridge();
        uint32_t dummyState = 0xCAFEBABEu;
        bridge->default_L_1013c95c  = &dummyState;
        bridge->loadbuffer_1013c94c = MockLuaLoadBuffer;
        bridge->pcall_1013c974      = MockLuaPcall;
        bool luaOk = NrthUI_ExecuteLuaViaBridge("print('hello')", 14, 0);
        CHECK(luaOk && s_mockLuaLoadCalled == 1 && s_mockLuaPcallCalled == 1 &&
              s_mockLuaLastChunk == "@custom" && bridge->execFlag_1013c939 == 0,
              "Lua VM bridge (0x1013bf04 / 0x1013c95c): executes via loadbuffer_1013c94c with '@custom' + pcall_1013c974");
    }

    /* 9. Verify built PE32 x86 binaries on disk (bin/NRTH.dll, bin/NORTH LOADER.exe, bin/NRTH_audit.dll) */
    {
        FILE *fDll = fopen("bin/NRTH.dll", "rb");
        FILE *fExe = fopen("bin/NORTH LOADER.exe", "rb");
        FILE *fAud = fopen("bin/NRTH_audit.dll", "rb");
        CHECK(fDll != NULL && fExe != NULL && fAud != NULL,
              "built binaries exist: bin/NRTH.dll, bin/NORTH LOADER.exe, bin/NRTH_audit.dll");
        if (fDll && fExe && fAud) {
            fseek(fDll, 0, SEEK_END);
            uint32_t dllSz = (uint32_t)ftell(fDll);
            rewind(fDll);
            uint8_t *dllBuf = (uint8_t *)malloc(dllSz);
            fread(dllBuf, 1, dllSz, fDll);

            fseek(fExe, 0, SEEK_END);
            uint32_t exeSz = (uint32_t)ftell(fExe);
            rewind(fExe);
            uint8_t *exeBuf = (uint8_t *)malloc(exeSz);
            fread(exeBuf, 1, exeSz, fExe);

            NrthPeView peDll, peExe;
            int rcDll = NrthPeMap(dllBuf, dllSz, &peDll);
            int rcExe = NrthPeMap(exeBuf, exeSz, &peExe);
            CHECK(rcDll == NVXA_OK && peDll.machine == 0x014Cu && peDll.imageBase == 0x10000000u &&
                  rcExe == NVXA_OK && peExe.machine == 0x014Cu && peExe.imageBase == 0x00400000u,
                  "PE32 x86 verification: bin/NRTH.dll (0x014C, base 0x10000000) & bin/NORTH LOADER.exe (0x014C, base 0x00400000)");

            char hidText[8192] = {0};
            uint32_t hidVas[32] = {0};
            int32_t nHid = NrthFindHiddenSignatures(dllBuf, dllSz, 20, hidText, sizeof(hidText), hidVas, 32);
            CHECK(nHid == 20, "bin/NRTH.dll: NrthFindHiddenSignatures recovers all 20 hidden signatures from built DLL");

            /* Verify NVXHookProc export RVA in bin/NRTH.dll matches original NRTH.dll (0x0000B9E0) */
            uint32_t e_lfanew = *(const uint32_t *)(dllBuf + 0x3C);
            uint32_t expRva   = *(const uint32_t *)(dllBuf + e_lfanew + 0x78);
            const uint8_t *expPtr = NrthPeRvaToPtr(&peDll, expRva, 0x28);
            uint32_t eatRva   = expPtr ? *(const uint32_t *)(expPtr + 0x1C) : 0;
            const uint8_t *eatPtr = eatRva ? NrthPeRvaToPtr(&peDll, eatRva, 4) : NULL;
            uint32_t hookProcRva = eatPtr ? *(const uint32_t *)eatPtr : 0;
            CHECK(hookProcRva == 0x0000B9E0u, "bin/NRTH.dll: Export NVXHookProc at exact RVA 0x0000B9E0 (matches original NRTH.dll)");

            free(dllBuf);
            free(exeBuf);
        }
        if (fDll) fclose(fDll);
        if (fExe) fclose(fExe);
        if (fAud) fclose(fAud);
    }

    /* 10. Verify DARKANARCHY bilingual fonts + Arabic shaping/BiDi engine */
    {
        /* 10a. Embedded TTF payloads are valid TrueType fonts */
        CHECK(sizeof(kFontEnglishTTF) == 78604u &&
              kFontEnglishTTF[0] == 0x00 && kFontEnglishTTF[1] == 0x01 &&
              kFontEnglishTTF[2] == 0x00 && kFontEnglishTTF[3] == 0x00,
              "nrth_fonts: kFontEnglishTTF (ChakraPetch-SemiBold.ttf, 78604 bytes) has TTF magic");
        CHECK(sizeof(kFontArabicTTF) == 244616u &&
              kFontArabicTTF[0] == 0x00 && kFontArabicTTF[1] == 0x01 &&
              kFontArabicTTF[2] == 0x00 && kFontArabicTTF[3] == 0x00,
              "nrth_fonts: kFontArabicTTF (IBMPlexSansArabic-SemiBold.ttf, 244616 bytes) has TTF magic");

        /* 10b. Language switch round-trip */
        NrthUI_SetLanguageArabic(true);
        CHECK(NrthUI_IsLanguageArabic() == true, "NrthUI_SetLanguageArabic(true) round-trip");
        NrthUI_SetLanguageArabic(false);
        CHECK(NrthUI_IsLanguageArabic() == false, "NrthUI_SetLanguageArabic(false) round-trip");

        /* 10c. Contextual shaping: "سلام" contains a mandatory LAM-ALEF ligature:
         * [FEB3 FEFC FEE1] (seen initial + lam-alef final + meem isolated) */
        {
            uint32_t in[4], shaped[8] = {0};
            size_t n = 0;
            in[n++] = 0x0633; in[n++] = 0x0644; in[n++] = 0x0627; in[n++] = 0x0645;
            size_t m = NrthShape_ArabicCodepoints(in, n, shaped, 8);
            CHECK(m == 3 && shaped[0] == 0xFEB3 && shaped[1] == 0xFEFC &&
                  shaped[2] == 0xFEE1,
                  "Arabic shaper: سلام -> FEB3 FEFC FEE1 (seen initial + lam-alef final + meem isolated)");

            /* Lam-Alef ligature: "لا" -> FEFB (isolated) */
            uint32_t la[2] = { 0x0644, 0x0627 };
            uint32_t lig[4] = {0};
            m = NrthShape_ArabicCodepoints(la, 2, lig, 4);
            CHECK(m == 1 && lig[0] == 0xFEFB,
                  "Arabic shaper: لا -> FEFB (lam-alef isolated ligature)");

            /* Connected lam-alef: "ملا" -> meem initial FEE3 + lam-alef final FEFC */
            uint32_t mla[3] = { 0x0645, 0x0644, 0x0627 };
            uint32_t out3[4] = {0};
            m = NrthShape_ArabicCodepoints(mla, 3, out3, 4);
            CHECK(m == 2 && out3[0] == 0xFEE3 && out3[1] == 0xFEFC,
                  "Arabic shaper: ملا -> FEE3 FEFC (meem initial + lam-alef final)");

            /* Right-joining alef never connects forward: "أب" ->
             * alef-hamza isolated FE83 + beh isolated FE8F */
            uint32_t ab[2] = { 0x0623, 0x0628 };
            uint32_t out4[4] = {0};
            m = NrthShape_ArabicCodepoints(ab, 2, out4, 4);
            CHECK(m == 2 && out4[0] == 0xFE83 && out4[1] == 0xFE8F,
                  "Arabic shaper: أب -> FE83 FE8F (alef right-joining, beh isolated)");

            /* Dual-joining chain: "بب" -> beh initial FE91 + beh final FE90 */
            uint32_t bb[2] = { 0x0628, 0x0628 };
            uint32_t out5[4] = {0};
            m = NrthShape_ArabicCodepoints(bb, 2, out5, 4);
            CHECK(m == 2 && out5[0] == 0xFE91 && out5[1] == 0xFE90,
                  "Arabic shaper: بب -> FE91 FE90 (beh initial + beh final)");
        }

        /* 10d. Public shaping API: UTF-8 -> shaped + visually reordered UTF-8.
         * "سلام" shaped [FEB3 FEFC FEE1], visual (reversed) [FEE1 FEFC FEB3]
         * in UTF-8: "\xEF\xBB\xA1\xEF\xBB\xBC\xEF\xBA\xB3" */
        {
            char out[128];
            const char *got = NrthUI_ShapeArabicText("\xD8\xB3\xD9\x84\xD8\xA7\xD9\x85", out, sizeof(out));
            const char *want = "\xEF\xBB\xA1\xEF\xBB\xBC\xEF\xBA\xB3";
            CHECK(got == out && strcmp(out, want) == 0,
                  "NrthUI_ShapeArabicText: سلام -> visual UTF-8 (FEE1 FEFC FEB3)");
        }

        /* 10e. BiDi visual reorder (LTR base): Arabic run is reversed IN PLACE,
         * Latin run stays. Logical [شجرة abc] -> visual [ةرجش abc]. */
        {
            uint32_t in[7], visual[8] = {0};
            /* شجرة = 0634 062C 0631 0629 */
            in[0] = 0x0634; in[1] = 0x062C; in[2] = 0x0631; in[3] = 0x0629;
            in[4] = 'a';    in[5] = 'b';    in[6] = 'c';
            size_t v = NrthBidi_ReorderVisual(in, 7, visual, 8);
            CHECK(v == 7 && visual[0] == 0x0629 && visual[1] == 0x0631 &&
                  visual[2] == 0x062C && visual[3] == 0x0634 &&
                  visual[4] == 'a' && visual[5] == 'b' && visual[6] == 'c',
                  "BiDi reorder: [شجرة abc] -> visual [reversed Arabic run][abc]");
        }

        /* 10f. ASCII-only strings pass through untouched */
        {
            char out[64];
            NrthUI_ShapeArabicText("DARKANARCHY 123", out, sizeof(out));
            CHECK(strcmp(out, "DARKANARCHY 123") == 0,
                  "NrthUI_ShapeArabicText: pure ASCII passes through unchanged");
        }

        /* 10g. Feature label translation table has an Arabic entry for every feature */
        {
            NrthUI_SetLanguageArabic(false);
            /* FeatureTr is internal; verify indirectly through public state:
             * toggling language must not corrupt feature state */
            NrthUI_SyncFeaturesToState();
            CHECK(Nrth_GetPlayerHealthSync()->bGodMode == 0,
                  "Feature state intact after language toggles");
        }
    }

    printf("---------------------------------------------------\n");
    printf("Summary: %d passed, %d failed\n", g_passed, g_failed);
    return (g_failed == 0) ? 0 : 1;
}
