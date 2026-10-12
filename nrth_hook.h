#pragma once
/**
 * ============================================================================
 * NRTH.dll — Interface, Resolver, Hook & State Reconstruction Header
 * Reverse engineered from native x86 library "NRTH.dll"
 * (SHA-256 947b81be2d0f84cc5f51742ef8e9dbf6183597ed98afaf1377bfc4352e007861)
 * ============================================================================
 */

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <stdint.h>
#include <stddef.h>
typedef int32_t  LRESULT;
typedef uintptr_t WPARAM;
typedef intptr_t LPARAM;
#define CALLBACK
#endif

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- Counts matching original NRTH.dll ----------------------------------- */
#define NRTH_CLIENT_HOOK_COUNT      11   /* VA 0x10005b80: 11 scans + 11 hooks */
#define NRTH_NETC_SCAN_COUNT         6   /* VA 0x10020640: 6 scans             */
#define NRTH_NETC_HOOK_COUNT         4   /* VA 0x10020640: 4 hooks             */
#define NRTH_NETC_PATCH_COUNT        6   /* VA 0x10020640: 6 0xC3 writes       */
#define NRTH_CLIENT_RESOLVE_COUNT   20   /* VA 0x1000c390: 20 scans, 0 hooks   */
#define NRTH_TOTAL_HOOK_COUNT       18   /* 1 LdrLoadDll + 2 D3D9 + 11 + 4     */
#define NRTH_TOTAL_SCAN_COUNT       37   /* 11 + 6 + 20                        */
#define NRTH_VM_REGISTRY_CAP        32   /* VA 0x1013bf04 table capacity       */

/* ---- Patch descriptor in list VA 0x101493e4 (written by 0x10011870) ------ */
typedef struct _NrthPatchRecord {
    uint32_t prepVa;        /* mov byte ptr [ebp-disp8], 0xC3 site VA          */
    uint32_t callVa;        /* call 0x10011870 site VA (prepVa + 11)           */
    uint32_t patternGlobal; /* pattern buffer VA (0x10023670..0x10023030)      */
    void    *targetAddr;    /* resolved target address in netc.dll             */
    uint8_t  origByte;      /* original prologue byte before write             */
    uint8_t  patchByte;     /* written byte (0xC3 = RET)                       */
    uint8_t  applied;       /* 1 if written to targetAddr                      */
    uint8_t  reserved;
} NrthPatchRecord;

/* ---- Hook descriptor for client.dll (0x10005b80) & netc.dll (0x10020640) - */
typedef struct _NrthHookSlot {
    uint32_t    index;
    uint32_t    handlerVa;     /* Original handler VA (e.g. 0x10002ff0)        */
    uint32_t    patternSiteVa; /* Original pattern construction site VA        */
    uint8_t     xorKey;        /* Positional XOR key (0x2D / 0x20 / 0x40)      */
    const char *pattern;       /* Wildcard byte pattern for 0x10002960         */
    void       *detourFn;      /* Reconstructed detour function pointer        */
    void       *targetAddr;    /* Resolved address in target module            */
    void       *origTrampoline;/* MinHook original trampoline                  */
    bool        installed;     /* True after MH_CreateHook + MH_EnableHook     */
} NrthHookSlot;

/* ---- Lua VM registry slot at 0x1013bf04 (stride 0x1C, L at +0x18) -------- */
#pragma pack(push, 1)
typedef struct _NrthLuaVmSlot {
    uint8_t  resourceMeta[0x18]; /* +0x00..+0x17 resource metadata             */
    uint32_t luaStatePtr32;      /* +0x18..+0x1B lua_State* (total = 0x1C)     */
} NrthLuaVmSlot;
#pragma pack(pop)

#ifdef __cplusplus
static_assert(sizeof(NrthLuaVmSlot) == 0x1C, "VM slot stride must be 0x1C (28 bytes)");
static_assert(offsetof(NrthLuaVmSlot, luaStatePtr32) == 0x18, "lua_State* must sit at +0x18");
#endif

typedef int (*PFN_NrthLuaLoadBuffer)(void *L, const char *buff, size_t sz, const char *name);
typedef int (*PFN_NrthLuaPcall)(void *L, int nargs, int nresults, int errfunc);

typedef struct _NrthLuaVmBridge {
    NrthLuaVmSlot         registry_1013bf04[NRTH_VM_REGISTRY_CAP];
    uint32_t              slotCount;
    void                 *default_L_1013c95c;
    PFN_NrthLuaLoadBuffer loadbuffer_1013c94c;
    PFN_NrthLuaPcall      pcall_1013c974;
    uint8_t               execFlag_1013c939;
    char                  scriptBuf_1013beec[65536];
} NrthLuaVmBridge;

/* ---- Sync state structs (RTTI in .data: SPlayerHealthSync / SWeaponAimSync) */
typedef struct _SPlayerHealthSync {
    float    fHealth;       /* Give HP / GodMode target health                 */
    float    fArmor;        /* Give Armor target armor                         */
    uint8_t  bGodMode;      /* Invulnerability flag                            */
    uint8_t  bInfiniteAmmo; /* Infinite ammo flag                              */
    uint8_t  bAntiSpread;   /* Zero weapon spread flag                         */
    uint8_t  bHighJump;     /* High jump flag                                  */
    float    fAirBreakSpeed;/* AirBreak speed                                  */
    float    fAirBreakIncr; /* AirBreak increment                              */
    uint8_t  bAirBreak;     /* AirBreak active                                 */
    uint8_t  bJetpack;      /* Jetpack active                                  */
    uint8_t  bGiveHp;       /* Continuous/active Give HP                       */
    uint8_t  bGiveArmor;    /* Continuous/active Give Armor                    */
    uint8_t  bVehGodMode;   /* Vehicle God-Mode (0x101490b3)                   */
    uint8_t  bFallBike;     /* Anti Fall Bike                                  */
    uint8_t  bFastStop;     /* Fast Stop (0x101490b8)                          */
    uint8_t  bFlyingCar;    /* Flying Car (0x10148f10 -> 0x969152)             */
    uint8_t  bDriveWater;   /* Drive Water (0x101490a0 -> 0x969160)            */
    uint8_t  bVehicleChaos; /* Vehicle Chaos (0x101490b9)                      */
    uint8_t  bUnlockCar;    /* Unlock Car (0x10149088)                         */
    uint8_t  bRepairCar;    /* Repair Car (0x101490c9 / 0x101490b1)            */
    uint8_t  bStartEngine;  /* Start Engine (0x10149110 / 0x10148f11)          */
    uint8_t  bCrasher;      /* Crasher (0x1013c938 -> 0x4f800000 in 0x10005ab0)*/
} SPlayerHealthSync;

typedef struct _SWeaponAimSync {
    float    fAimX;
    float    fAimY;
    float    fAimZ;
    float    fClickWarpMaxDist;
    float    fCrosshairSize;
    uint8_t  bClickWarp;
    uint8_t  bGroundWarp;
    uint8_t  bEnterVehicle;
    uint8_t  bAllWeapons;
} SWeaponAimSync;

/* ---- Report channel state (netc.dll 0x1001dd30..0x1001fa80) -------------- */
typedef struct _NrthReportChannelState {
    uint32_t screenshotCount;     /* PLAYER_SCREENSHOT                         */
    uint32_t transgressionCount;  /* PLAYER_TRANSGRESSION                      */
    uint32_t diagnosticCount;     /* PLAYER_DIAGNOSTIC                         */
    uint32_t acinfoCount;         /* PLAYER_ACINFO                             */
    uint32_t challengeMemCount;   /* PACKET_ID_CHEAT_CHALLENGEMEMORY           */
    bool     suppressReports;     /* Anti-ScreenShot / report filter active    */
} NrthReportChannelState;

/* ---- Exported hook procedure (ordinal 1) --------------------------------- */
LRESULT CALLBACK NVXHookProc(int nCode, WPARAM wParam, LPARAM lParam);

/* ---- Exposed internal mechanisms (for UI & verification tests) ----------- */
const uint8_t *ResolvePattern_10002960(const uint8_t *base, uint32_t size, const char *pattern);
void **FindD3D9VTableInBuffer_10012980(const uint8_t *base, uint32_t size);
bool PatchByte_10011870(void *targetAddr, uint8_t opcodeByte, uint32_t prepVa,
                        uint32_t callVa, uint32_t patternGlobal);

uint32_t ArmClient_10005b80(uint8_t *moduleBase, uint32_t moduleSize, bool applyDetours);
uint32_t ResolveClientOffsets_1000c390(const uint8_t *moduleBase, uint32_t moduleSize);
uint32_t ArmNetc_10020640(uint8_t *moduleBase, uint32_t moduleSize, bool applyDetours, bool applyPatches);

/* ---- Accessors for tables and runtime counters --------------------------- */
const NrthHookSlot    *Nrth_GetClientHookTable(uint32_t *outCount);
const NrthHookSlot    *Nrth_GetNetcHookTable(uint32_t *outCount);
const NrthPatchRecord *Nrth_GetPatchList_101493e4(uint32_t *outCount);
const uintptr_t       *Nrth_GetClientResolvedOffsets(uint32_t *outCount);
uint32_t               Nrth_GetTotalPatternScans(void);
uint32_t               Nrth_GetTotalInstalledHooks(void);
uint32_t               Nrth_GetTotalAppliedPatches(void);
void                   Nrth_ResetArmingCounters(void);

NrthLuaVmBridge        *Nrth_GetLuaVmBridge(void);
SPlayerHealthSync      *Nrth_GetPlayerHealthSync(void);
SWeaponAimSync         *Nrth_GetWeaponAimSync(void);
NrthReportChannelState *Nrth_GetReportChannelState(void);
bool                    Nrth_IsPointerReadable_VirtualQuery(const void *ptr);

/* ---- In-game feature execution & GTA:SA/MTA actions (0x10001d80..0x1002f370) */
void Nrth_AirbreakTick_10001d80(void);
void Nrth_TickGameFeatures_10015812(void);
void Nrth_TriggerAllWeapons_1002a5a7(void);
void Nrth_TriggerJetpack_1002a86c(void);
bool Nrth_RepairCurrentVehicle_1002f070(void);
bool Nrth_StartCurrentVehicleEngine_1002f0f0(void);
bool Nrth_UnlockNearestVehicle_1002eea0(void);
bool Nrth_StopCurrentVehicle(void);
bool Nrth_DestroyCurrentVehicle(void);
bool Nrth_GetLocalPlayerPosition(float *outX, float *outY, float *outZ);
bool Nrth_TeleportLocalPlayer(float x, float y, float z);
bool Nrth_StopClientResource_100054a0(const char *resName);

#ifdef __cplusplus
}
#endif
