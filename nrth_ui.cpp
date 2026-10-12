/**
 * ============================================================================
 * nrth_ui.cpp — DARKANARCHY (by XRAOUF) — Bilingual Overlay UI (AR + EN)
 * ============================================================================
 * Design:
 *   - Dark anarchist theme: coal black surfaces, blood-red accents, bone text.
 *   - Embedded fonts (nrth_fonts.h):
 *       English : ChakraPetch-SemiBold.ttf
 *       Arabic  : IBMPlexSansArabic-SemiBold.ttf (Presentation Forms-B complete)
 *   - Arabic text is rendered via presentation forms with a full contextual
 *     joining shaper (isolated/final/initial/medial + lam-alef ligatures) and
 *     a simplified UAX#9 BiDi visual reorder (LTR base paragraph).
 *   - Branding: DARKANARCHY / by XRAOUF with a drawn anarchy-A circle logo.
 * ============================================================================
 */
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

#include <stdio.h>
#include <string.h>
#include <string>
#include <vector>

#include "nrth_codec.h"
#include "nrth_config.h"
#include "nrth_hook.h"
#include "nrth_ui.h"
#if defined(_WIN32) && !defined(NRTH_HEADLESS_TEST)
#include "nrth_fonts.h"
#include "nrth_vehicle_names.inc"
#endif

/* ===========================================================================
 * MTA PACKET_ID_* catalogue (.rdata 0x100e9be4..0x100eaaa4 & 0x100eb6a8)
 * =========================================================================== */
static const NrthPacketDef kMtaPacketCatalog[] = {
    {   0, "PACKET_ID_SERVER_JOIN",                 false },
    {   1, "PACKET_ID_SERVER_JOIN_DATA",            false },
    {   2, "PACKET_ID_SERVER_JOIN_COMPLETE",        false },
    {   3, "PACKET_ID_PLAYER_JOIN",                 false },
    {   4, "PACKET_ID_PLAYER_JOINDATA",             false },
    {   5, "PACKET_ID_PLAYER_QUIT",                 false },
    {   6, "PACKET_ID_PLAYER_TIMEOUT",              false },
    {   7, "PACKET_ID_MOD_NAME",                    false },
    {   8, "PACKET_ID_PACKET_PROGRESS",             false },
    {   9, "PACKET_ID_MTA_RESERVED_03",             false },
    {  10, "PACKET_ID_MTA_RESERVED_04",             false },
    {  11, "PACKET_ID_GAME_STARTED",                false },
    {  12, "PACKET_ID_ GHOST_SYNC",                 false },
    {  19, "PACKET_ID_PLAYER_LIST",                 false },
    {  20, "PACKET_ID_PLAYER_SPAWN",                false },
    {  21, "PACKET_ID_PLAYER_WASTED",               false },
    {  22, "PACKET_ID_PLAYER_CHANGE_NICK",          false },
    {  23, "PACKET_ID_PLAYER_STATS",                false },
    {  24, "PACKET_ID_PLAYER_CLOTHES",              false },
    {  25, "PACKET_ID_PLAYER_KEYSYNC",              false },
    {  26, "PACKET_ID_PLAYER_PURESYNC",             false },
    {  27, "PACKET_ID_PLAYER_VEHICLE_PURESYNC",     false },
    {  28, "PACKET_ID_LIGHTSYNC",                   false },
    {  29, "PACKET_ID_VEHICLE_RESYNC",              false },
    {  30, "PACKET_ID_RETURN_SYNC",                 false },
    {  31, "PACKET_ID_EXPLOSION",                   false },
    {  32, "PACKET_ID_FIRE",                        false },
    {  33, "PACKET_ID_PROJECTILE",                  false },
    {  34, "PACKET_ID_DETONATE_SATCHELS",           false },
    {  35, "PACKET_ID_DESTROY_SATCHELS",            false },
    {  36, "PACKET_ID_COMMAND",                     false },
    {  37, "PACKET_ID_CHAT_ECHO",                   false },
    {  38, "PACKET_ID_CONSOLE_ECHO",                false },
    {  39, "PACKET_ID_DEBUG_ECHO",                  false },
    {  40, "PACKET_ID_MAP_INFO",                    false },
    {  41, "PACKET_ID_MAP_START",                   false },
    {  42, "PACKET_ID_MAP_RESTART",                 false },
    {  43, "PACKET_ID_MAP_STOP",                    false },
    {  44, "PACKET_ID_ENTITY_ADD",                  false },
    {  45, "PACKET_ID_ENTITY_REMOVE",               false },
    {  46, "PACKET_ID_PICKUP_HIDESHOW",             false },
    {  47, "PACKET_ID_PICKUP_HIT_CONFIRM",          false },
    {  48, "PACKET_ID_UNOCCUPIED_VEHICLE_STARTSYNC",false },
    {  49, "PACKET_ID_UNOCCUPIED_VEHICLE_STOPSYNC", false },
    {  50, "PACKET_ID_UNOCCUPIED_VEHICLE_SYNC",     false },
    {  51, "PACKET_ID_PED_STARTSYNC",               false },
    {  52, "PACKET_ID_PED_STOPSYNC",                false },
    {  53, "PACKET_ID_PED_SYNC",                    false },
    {  54, "PACKET_ID_CAMERA_SYNC",                 false },
    {  55, "PACKET_ID_OBJECT_STARTSYNC",            false },
    {  56, "PACKET_ID_OBJECT_STOPSYNC",             false },
    {  57, "PACKET_ID_OBJECT_SYNC",                 false },
    {  58, "PACKET_ID_LUA",                         false },
    {  59, "PACKET_ID_LUA_ELEMENT_RPC",             false },
    {  60, "PACKET_ID_TEXT_ITEM",                   false },
    {  61, "PACKET_ID_SCOREBOARD",                  false },
    {  62, "PACKET_ID_TEAMS",                       false },
    {  63, "PACKET_ID_LUA_EVENT",                   false },
    {  64, "PACKET_ID_RESOURCE_START",              false },
    {  65, "PACKET_ID_RESOURCE_STOP",               false },
    {  66, "PACKET_ID_CUSTOM_DATA",                 false },
    {  67, "PACKET_ID_VOICE_DATA",                  false },
    {  68, "PACKET_ID_VOICE_END",                   false },
    {  69, "PACKET_ID_CHEAT_CHALLENGEMEMORY",       false }, /* VA 0x100eb6a8 */
    {  70, "PACKET_ID_CHEAT_RETURN",                false },
    {  71, "PACKET_ID_MAP_LIST",                    false },
    {  72, "PACKET_ID_LUA_TIMERS",                  false },
    {  73, "PACKET_ID_LATENT_TRANSFER",             false },
    {  74, "PACKET_ID_PLAYER_BULLETSYNC",           false },
    {  75, "PACKET_ID_SYNC_SETTINGS",               false },
    {  76, "PACKET_ID_WEAPON_BULLETSYNC",           false },
    {  77, "PACKET_ID_PED_TASK",                    false },
    {  78, "PACKET_ID_PLAYER_NO_SOCKET",            false },
    {  79, "PACKET_ID_PLAYER_NETWORK_STATUS",       false },
    {  80, "PACKET_ID_PLAYER_SCREENSHOT",           true  }, /* Report channel #1 */
    {  81, "PACKET_ID_PLAYER_DIAGNOSTIC",           true  }, /* Report channel #2 */
    {  82, "PACKET_ID_PLAYER_ACINFO",               true  }, /* Report channel #3 */
    {  83, "PACKET_ID_PLAYER_TRANSGRESSION",        true  }, /* Report channel #4 */
    {  84, "PACKET_ID_RESEND_REQUEST",              false },
};

extern "C" const NrthPacketDef *NrthUI_GetPacketCatalog(uint32_t *outCount)
{
    if (outCount) {
        *outCount = (uint32_t)(sizeof(kMtaPacketCatalog) / sizeof(kMtaPacketCatalog[0]));
    }
    return kMtaPacketCatalog;
}

/* ===========================================================================
 * Bilingual core: language state, fonts, UTF-8 helpers
 * =========================================================================== */
static bool   g_bArabic = false;
static void  *g_pFontEn = NULL;
static void  *g_pFontAr = NULL;

extern "C" void NrthUI_SetLanguageArabic(bool isArabic) { g_bArabic = isArabic; }
extern "C" bool NrthUI_IsLanguageArabic(void)           { return g_bArabic; }
extern "C" void NrthUI_SetFonts(void *pEnglishFont, void *pArabicFont)
{
    g_pFontEn = pEnglishFont;
    g_pFontAr = pArabicFont;
}

static size_t Utf8Decode(const char *s, size_t len, uint32_t *out, size_t outCap)
{
    size_t i = 0, w = 0;
    while (i < len && w < outCap) {
        unsigned char c = (unsigned char)s[i];
        if (c < 0x80)              { out[w++] = c;                        i += 1; }
        else if ((c & 0xE0) == 0xC0 && i + 1 < len) {
            out[w++] = ((uint32_t)(c & 0x1F) << 6)  | ((unsigned char)s[i+1] & 0x3F); i += 2;
        }
        else if ((c & 0xF0) == 0xE0 && i + 2 < len) {
            out[w++] = ((uint32_t)(c & 0x0F) << 12) | (((unsigned char)s[i+1] & 0x3F) << 6)
                     |  ((unsigned char)s[i+2] & 0x3F); i += 3;
        }
        else if ((c & 0xF8) == 0xF0 && i + 3 < len) {
            out[w++] = ((uint32_t)(c & 0x07) << 18) | (((unsigned char)s[i+1] & 0x3F) << 12)
                     | (((unsigned char)s[i+2] & 0x3F) << 6) | ((unsigned char)s[i+3] & 0x3F); i += 4;
        }
        else { out[w++] = c; i += 1; }
    }
    return w;
}

static size_t Utf8Encode(uint32_t cp, char *out, size_t outCap)
{
    if (outCap < 4) return 0;
    if (cp < 0x80)    { out[0] = (char)cp; return 1; }
    if (cp < 0x800)   { out[0] = (char)(0xC0 | (cp >> 6));  out[1] = (char)(0x80 | (cp & 0x3F)); return 2; }
    if (cp < 0x10000) { out[0] = (char)(0xE0 | (cp >> 12)); out[1] = (char)(0x80 | ((cp >> 6) & 0x3F));
                        out[2] = (char)(0x80 | (cp & 0x3F)); return 3; }
    out[0] = (char)(0xF0 | (cp >> 18)); out[1] = (char)(0x80 | ((cp >> 12) & 0x3F));
    out[2] = (char)(0x80 | ((cp >> 6) & 0x3F)); out[3] = (char)(0x80 | (cp & 0x3F));
    return 4;
}

/* ===========================================================================
 * Arabic contextual shaping engine (U+0600..U+06FF -> Presentation Forms B)
 * =========================================================================== */
enum { JT_N = 0, JT_R = 1, JT_D = 2 }; /* Non / Right / Dual joining */
struct ArShapeEntry { uint32_t base; uint8_t join; uint16_t iso, fin, ini, med; };

static const ArShapeEntry kArShapeTable[] = {
    { 0x0621, JT_N, 0xFE80, 0xFE80, 0xFE80, 0xFE80 }, /* ء  HAMZA              */
    { 0x0622, JT_R, 0xFE81, 0xFE82, 0xFE81, 0xFE82 }, /* آ  ALEF MADDA         */
    { 0x0623, JT_R, 0xFE83, 0xFE84, 0xFE83, 0xFE84 }, /* أ  ALEF HAMZA ABOVE   */
    { 0x0624, JT_R, 0xFE85, 0xFE86, 0xFE85, 0xFE86 }, /* ؤ  WAW HAMZA          */
    { 0x0625, JT_R, 0xFE87, 0xFE88, 0xFE87, 0xFE88 }, /* إ  ALEF HAMZA BELOW   */
    { 0x0626, JT_D, 0xFE89, 0xFE8A, 0xFE8B, 0xFE8C }, /* ئ  YEH HAMZA          */
    { 0x0627, JT_R, 0xFE8D, 0xFE8E, 0xFE8D, 0xFE8E }, /* ا  ALEF               */
    { 0x0628, JT_D, 0xFE8F, 0xFE90, 0xFE91, 0xFE92 }, /* ب  BEH                */
    { 0x0629, JT_R, 0xFE93, 0xFE94, 0xFE93, 0xFE94 }, /* ة  TEH MARBUTA        */
    { 0x062A, JT_D, 0xFE95, 0xFE96, 0xFE97, 0xFE98 }, /* ت  TEH                */
    { 0x062B, JT_D, 0xFE99, 0xFE9A, 0xFE9B, 0xFE9C }, /* ث  THEH               */
    { 0x062C, JT_D, 0xFE9D, 0xFE9E, 0xFE9F, 0xFEA0 }, /* ج  JEEM               */
    { 0x062D, JT_D, 0xFEA1, 0xFEA2, 0xFEA3, 0xFEA4 }, /* ح  HAH                */
    { 0x062E, JT_D, 0xFEA5, 0xFEA6, 0xFEA7, 0xFEA8 }, /* خ  KHAH               */
    { 0x062F, JT_R, 0xFEA9, 0xFEAA, 0xFEA9, 0xFEAA }, /* د  DAL                */
    { 0x0630, JT_R, 0xFEAB, 0xFEAC, 0xFEAB, 0xFEAC }, /* ذ  THAL               */
    { 0x0631, JT_R, 0xFEAD, 0xFEAE, 0xFEAD, 0xFEAE }, /* ر  REH                */
    { 0x0632, JT_R, 0xFEAF, 0xFEB0, 0xFEAF, 0xFEB0 }, /* ز  ZAIN               */
    { 0x0633, JT_D, 0xFEB1, 0xFEB2, 0xFEB3, 0xFEB4 }, /* س  SEEN               */
    { 0x0634, JT_D, 0xFEB5, 0xFEB6, 0xFEB7, 0xFEB8 }, /* ش  SHEEN              */
    { 0x0635, JT_D, 0xFEB9, 0xFEBA, 0xFEBB, 0xFEBC }, /* ص  SAD                */
    { 0x0636, JT_D, 0xFEBD, 0xFEBE, 0xFEBF, 0xFEC0 }, /* ض  DAD                */
    { 0x0637, JT_D, 0xFEC1, 0xFEC2, 0xFEC3, 0xFEC4 }, /* ط  TAH                */
    { 0x0638, JT_D, 0xFEC5, 0xFEC6, 0xFEC7, 0xFEC8 }, /* ظ  ZAH                */
    { 0x0639, JT_D, 0xFEC9, 0xFECA, 0xFECB, 0xFECC }, /* ع  AIN                */
    { 0x063A, JT_D, 0xFECD, 0xFECE, 0xFECF, 0xFED0 }, /* غ  GHAIN              */
    { 0x0640, JT_D, 0x0640, 0x0640, 0x0640, 0x0640 }, /* ـ  TATWEEL            */
    { 0x0641, JT_D, 0xFED1, 0xFED2, 0xFED3, 0xFED4 }, /* ف  FEH                */
    { 0x0642, JT_D, 0xFED5, 0xFED6, 0xFED7, 0xFED8 }, /* ق  QAF                */
    { 0x0643, JT_D, 0xFED9, 0xFEDA, 0xFEDB, 0xFEDC }, /* ك  KAF                */
    { 0x0644, JT_D, 0xFEDD, 0xFEDE, 0xFEDF, 0xFEE0 }, /* ل  LAM                */
    { 0x0645, JT_D, 0xFEE1, 0xFEE2, 0xFEE3, 0xFEE4 }, /* م  MEEM               */
    { 0x0646, JT_D, 0xFEE5, 0xFEE6, 0xFEE7, 0xFEE8 }, /* ن  NOON               */
    { 0x0647, JT_D, 0xFEE9, 0xFEEA, 0xFEEB, 0xFEEC }, /* ه  HEH                */
    { 0x0648, JT_R, 0xFEED, 0xFEEE, 0xFEED, 0xFEEE }, /* و  WAW                */
    { 0x0649, JT_R, 0xFEEF, 0xFEF0, 0xFEEF, 0xFEF0 }, /* ى  ALEF MAKSURA       */
    { 0x064A, JT_D, 0xFEF1, 0xFEF2, 0xFEF3, 0xFEF4 }, /* ي  YEH                */
};

static const ArShapeEntry *ArShapeLookup(uint32_t cp)
{
    for (size_t i = 0; i < sizeof(kArShapeTable) / sizeof(kArShapeTable[0]); ++i) {
        if (kArShapeTable[i].base == cp) return &kArShapeTable[i];
    }
    return NULL;
}

/* Harakat / marks / invisible controls: transparent for the joining rules */
static bool ArIsTransparent(uint32_t cp)
{
    return (cp >= 0x064B && cp <= 0x065F) || cp == 0x0670 ||
           (cp >= 0x06D6 && cp <= 0x06ED) ||
           cp == 0x200B || cp == 0x200E || cp == 0x200F || cp == 0x200D;
}

/**
 * Core shaper: logical codepoint stream -> presentation forms (logical order).
 * Handles isolated/final/initial/medial selection and the mandatory
 * LAM+ALEF ligatures (U+FEF5..U+FEFC).
 */
size_t NrthShape_ArabicCodepoints(const uint32_t *in, size_t n, uint32_t *out, size_t outCap)
{
    if (!in || !out || outCap == 0) return 0;
    size_t w = 0;
    bool prevLinks = false; /* previous emitted joinable char connects forward */
    for (size_t i = 0; i < n; ++i) {
        if (w >= outCap) break;
        uint32_t cp = in[i];
        if (ArIsTransparent(cp)) { out[w++] = cp; continue; }

        const ArShapeEntry *e = ArShapeLookup(cp);
        if (!e) { out[w++] = cp; prevLinks = false; continue; }

        /* next non-transparent char */
        size_t j = i + 1;
        while (j < n && ArIsTransparent(in[j])) ++j;
        uint32_t nextCp = (j < n) ? in[j] : 0;
        const ArShapeEntry *ne = nextCp ? ArShapeLookup(nextCp) : NULL;
        /* A following letter connects backward when it is D or R (not N) */
        bool nextJoinsBack = (ne && ne->join != JT_N);

        /* Mandatory LAM + ALEF ligature */
        if (cp == 0x0644 &&
            (nextCp == 0x0622 || nextCp == 0x0623 || nextCp == 0x0625 || nextCp == 0x0627)) {
            uint32_t lig;
            switch (nextCp) {
                case 0x0622: lig = prevLinks ? 0xFEF6u : 0xFEF5u; break;
                case 0x0623: lig = prevLinks ? 0xFEF8u : 0xFEF7u; break;
                case 0x0625: lig = prevLinks ? 0xFEFAu : 0xFEF9u; break;
                default:     lig = prevLinks ? 0xFEFCu : 0xFEFBu; break;
            }
            out[w++] = lig;
            for (size_t t = i + 1; t < j && w < outCap; ++t) out[w++] = in[t]; /* keep harakat */
            prevLinks = false; /* ligature (alef tail) does not join forward */
            i = j;
            continue;
        }

        bool canForward = (e->join == JT_D) && nextJoinsBack;
        uint32_t form;
        if (prevLinks && canForward) form = e->med;
        else if (prevLinks)          form = e->fin;
        else if (canForward)         form = e->ini;
        else                         form = e->iso;
        out[w++] = form;
        prevLinks = canForward;
    }
    return w;
}

/* ===========================================================================
 * Simplified UAX#9 BiDi visual reorder (LTR base paragraph)
 *   RTL strong chars -> level 1, numbers inside RTL -> level 2,
 *   neutrals adjacent to RTL -> level 1, strong LTR -> level 0.
 *   L2: reverse contiguous runs of level >= k for k = maxLevel..1.
 * =========================================================================== */
static bool CpIsRtlStrong(uint32_t cp)
{
    return (cp >= 0x0590 && cp <= 0x08FF) ||
           (cp >= 0xFB1D && cp <= 0xFDFF) ||
           (cp >= 0xFE70 && cp <= 0xFEFF);
}
static bool CpIsNumber(uint32_t cp)
{
    return (cp >= 0x0030 && cp <= 0x0039) || (cp >= 0x0660 && cp <= 0x0669);
}
static bool CpIsLtrStrong(uint32_t cp)
{
    return (cp >= 0x0041 && cp <= 0x005A) || (cp >= 0x0061 && cp <= 0x007A) ||
           (cp >= 0x00C0 && cp <= 0x024F);
}

size_t NrthBidi_ReorderVisual(const uint32_t *in, size_t n, uint32_t *out, size_t outCap)
{
    if (!in || !out || outCap == 0) return 0;
    if (n > outCap) n = outCap;
    if (n == 0) return 0;

    static uint8_t lv[4096];
    if (n > sizeof(lv)) n = sizeof(lv);

    for (size_t i = 0; i < n; ++i) {
        if (CpIsRtlStrong(in[i]))      lv[i] = 1;
        else if (CpIsNumber(in[i]))    lv[i] = 2;
        else if (CpIsLtrStrong(in[i])) lv[i] = 0;
        else {
            /* neutral: follow neighbouring RTL strength */
            bool prevR = (i > 0)     && CpIsRtlStrong(in[i - 1]);
            bool nextR = (i + 1 < n) && CpIsRtlStrong(in[i + 1]);
            lv[i] = (prevR || nextR) ? 1 : 0;
        }
    }

    for (size_t i = 0; i < n; ++i) out[i] = in[i];
    for (int level = 2; level >= 1; --level) {
        size_t i = 0;
        while (i < n) {
            if (lv[i] >= level) {
                size_t j = i;
                while (j < n && lv[j] >= level) ++j;
                for (size_t a = i, b = j - 1; a < b; ++a, --b) {
                    uint32_t t = out[a]; out[a] = out[b]; out[b] = t;
                }
                i = j;
            } else {
                ++i;
            }
        }
    }
    return n;
}

extern "C" const char *NrthUI_ShapeArabicText(const char *utf8In, char *outBuf, size_t outCap)
{
    if (!outBuf || outCap == 0) return "";
    outBuf[0] = '\0';
    if (!utf8In || !utf8In[0]) return outBuf;

    uint32_t cps[1024];
    size_t n = Utf8Decode(utf8In, strlen(utf8In), cps, 1024);
    uint32_t shaped[1024];
    size_t m = NrthShape_ArabicCodepoints(cps, n, shaped, 1024);
    uint32_t visual[1024];
    size_t v = NrthBidi_ReorderVisual(shaped, m, visual, 1024);

    size_t used = 0;
    for (size_t i = 0; i < v; ++i) {
        if (used + 4 >= outCap) break;
        used += Utf8Encode(visual[i], outBuf + used, outCap - used);
    }
    if (used >= outCap) used = outCap - 1;
    outBuf[used] = '\0';
    outBuf[outCap - 1] = '\0';
    return outBuf;
}

/* Rotation buffers for translated UI labels */
static const char *TrGet(const char *en, const char *ar)
{
    static char s_trBufs[24][768];
    static int  s_trIdx = 0;
    char *buf = s_trBufs[s_trIdx];
    s_trIdx = (s_trIdx + 1) % 24;
    if (!g_bArabic || !ar || !ar[0]) {
        return en ? en : "";
    }
    return NrthUI_ShapeArabicText(ar, buf, 768);
}
#define L(en, ar) TrGet((en), (ar))

/* ===========================================================================
 * Feature state & sliders (shared between UI and SPlayerHealthSync/SWeaponAimSync)
 * =========================================================================== */
struct Feature { const char *label; const char *settings; bool on; int key; int mode; };
static Feature s_cheatFeatures[] = {
    {"GodMode",        "GodMode Settings",        false, 0, 1},
    {"Give HP",        "Give HP Settings",        false, 0, 1},
    {"Give Armor",     "Give Armor Settings",     false, 0, 1},
    {"Infinite Ammo",  "Infinite Ammo Settings",  false, 0, 1},
    {"Anti-Spread",    "Anti-Spread Settings",    false, 0, 1},
    {"Anti-ScreenShot","Anti-ScreenShot Settings",false, 0, 1},
    {"Crasher",        "Crasher Settings",        false, 0, 1},
    {"Anti-AFK",       "Anti-AFK Settings",       false, 0, 1},
    {"AirBreak",       "AirBreak Settings",       false, 0, 1},
    {"Click Warp",     "Click Warp Settings",     false, 0, 1},
    {"High Jump",      "High Jump Settings",      false, 0, 1},
    {"Money Exploit",  "Money Exploit Settings",  false, 0, 1},
    {"Jetpack",        "Jetpack Settings",        false, 0, 1},
    {"All Weapons",    "All Weapons Settings",    false, 0, 1},
};

static Feature s_vehicleFeatures[] = {
    {"Vehicle GodMode", "Vehicle GodMode Settings", false, 0, 1},
    {"Vehicle Chaos",   "Vehicle Chaos Settings",   false, 0, 1},
    {"Drive Water",     "Drive Water Settings",     false, 0, 1},
    {"Fast Stop",       "Fast Stop Settings",       false, 0, 1},
    {"Fall Bike",       "Fall Bike Settings",       false, 0, 1},
    {"Flying Car",      "Flying Car Settings",      false, 0, 1},
    {"Start Engine",    "Start Engine Settings",    false, 0, 1},
    {"Repair Car",      "Repair Car Settings",      false, 0, 1},
    {"Unlock Car",      "Unlock Car Settings",      false, 0, 1},
};

/* Feature label translation map (keys remain English for the settings logic) */
static const char *FeatureTr(const char *key)
{
    static char s_ftBuf[2][256];
    static int  s_ftIdx = 0;
    struct Pair { const char *en; const char *ar; };
    static const Pair kMap[] = {
        {"GodMode",         "حماية من الموت"},
        {"Give HP",         "إعطاء دم"},
        {"Give Armor",      "إعطاء درع"},
        {"Infinite Ammo",   "ذخيرة لا نهائية"},
        {"Anti-Spread",     "منع تشتت الرصاص"},
        {"Anti-ScreenShot", "منع التصوير"},
        {"Crasher",         "كراشر"},
        {"Anti-AFK",        "منع الطرد للخمول"},
        {"AirBreak",        "تحطيم الجاذبية"},
        {"Click Warp",      "تنقل بالنقرة"},
        {"High Jump",       "قفز عالي"},
        {"Money Exploit",   "استغلال الفلوس"},
        {"Jetpack",         "جت باك"},
        {"All Weapons",     "كل الأسلحة"},
        {"Vehicle GodMode", "حماية المركبة"},
        {"Vehicle Chaos",   "فوضى المركبات"},
        {"Drive Water",     "القيادة على الماء"},
        {"Fast Stop",       "توقف سريع"},
        {"Fall Bike",       "منع السقوط من الدباب"},
        {"Flying Car",      "سيارة طائرة"},
        {"Start Engine",    "تشغيل المحرك"},
        {"Repair Car",      "إصلاح السيارة"},
        {"Unlock Car",      "فتح السيارة"},
    };
    for (size_t i = 0; i < sizeof(kMap) / sizeof(kMap[0]); ++i) {
        if (strcmp(key, kMap[i].en) == 0) {
            if (!g_bArabic) return kMap[i].en;
            char *buf = s_ftBuf[s_ftIdx];
            s_ftIdx = (s_ftIdx + 1) % 2;
            return NrthUI_ShapeArabicText(kMap[i].ar, buf, 256);
        }
    }
    return key;
}

static float s_hpValue = 100.f, s_armorValue = 100.f, s_abSpeed = 1.f, s_abIncr = 0.5f;
static float s_maxDist = 300.f, s_crossSize = 12.f;
static bool  s_groundWarp = true, s_enterVehicle = true;
static bool  s_hideObsDiscord = false, s_antiAfk = false;

extern "C" void NrthUI_SyncFeaturesToState(void)
{
    SPlayerHealthSync *hs = Nrth_GetPlayerHealthSync();
    if (hs) {
        hs->bGodMode       = s_cheatFeatures[0].on ? 1 : 0;
        hs->bGiveHp        = s_cheatFeatures[1].on ? 1 : 0;
        hs->fHealth        = s_cheatFeatures[1].on ? s_hpValue : 100.0f;
        hs->bGiveArmor     = s_cheatFeatures[2].on ? 1 : 0;
        hs->fArmor         = s_cheatFeatures[2].on ? s_armorValue : 100.0f;
        hs->bInfiniteAmmo  = s_cheatFeatures[3].on ? 1 : 0;
        hs->bAntiSpread    = s_cheatFeatures[4].on ? 1 : 0;
        hs->bCrasher       = s_cheatFeatures[6].on ? 1 : 0;
        hs->bAirBreak      = s_cheatFeatures[8].on ? 1 : 0;
        hs->fAirBreakSpeed = s_abSpeed;
        hs->fAirBreakIncr  = s_abIncr;
        hs->bHighJump      = s_cheatFeatures[10].on ? 1 : 0;
        hs->bJetpack       = s_cheatFeatures[12].on ? 1 : 0;

        /* Vehicle features (0x10148f10..0x10149110 in NRTH.dll) */
        hs->bVehGodMode    = s_vehicleFeatures[0].on ? 1 : 0;
        hs->bVehicleChaos  = s_vehicleFeatures[1].on ? 1 : 0;
        hs->bDriveWater    = s_vehicleFeatures[2].on ? 1 : 0;
        hs->bFastStop      = s_vehicleFeatures[3].on ? 1 : 0;
        hs->bFallBike      = s_vehicleFeatures[4].on ? 1 : 0;
        hs->bFlyingCar     = s_vehicleFeatures[5].on ? 1 : 0;
        hs->bStartEngine   = s_vehicleFeatures[6].on ? 1 : 0;
        hs->bRepairCar     = s_vehicleFeatures[7].on ? 1 : 0;
        hs->bUnlockCar     = s_vehicleFeatures[8].on ? 1 : 0;
    }

    SWeaponAimSync *ws = Nrth_GetWeaponAimSync();
    if (ws) {
        ws->bClickWarp        = s_cheatFeatures[9].on ? 1 : 0;
        ws->fClickWarpMaxDist = s_maxDist;
        ws->fCrosshairSize    = s_crossSize;
        ws->bGroundWarp       = s_groundWarp ? 1 : 0;
        ws->bEnterVehicle     = s_enterVehicle ? 1 : 0;
        ws->bAllWeapons       = s_cheatFeatures[13].on ? 1 : 0;
    }

    NrthReportChannelState *rc = Nrth_GetReportChannelState();
    if (rc) {
        rc->suppressReports = s_cheatFeatures[5].on || s_hideObsDiscord;
    }
    (void)s_antiAfk;
}

/* ===========================================================================
 * Shared live hook state (Resources, Events, Packets, Dumper, Markers)
 * =========================================================================== */
struct DumperFileEntry {
    std::string name;
    std::string code;
};
struct PacketRow { std::string name; int id; bool blocked; std::string time; };
struct MarkerRow { std::string name; float x, y, z; };

static std::vector<std::string>     s_resources;
static std::vector<std::string>     s_blockedEvents;
static std::vector<std::string>     s_recentTriggers;
static bool                         s_blockAllEvents = false;
static std::vector<PacketRow>       s_packets;
static bool                         s_packetsPopulated = false;
static std::vector<DumperFileEntry> s_dumperEntries;
static std::vector<MarkerRow>       s_markers;
static std::string                  s_status = "No connected server.";

static void EnsurePacketsPopulated()
{
    if (s_packetsPopulated) return;
    uint32_t count = 0;
    const NrthPacketDef *defs = NrthUI_GetPacketCatalog(&count);
    for (uint32_t i = 0; i < count; ++i) {
        s_packets.push_back({defs[i].name, defs[i].id, defs[i].isReportChannel, "00:00:00"});
    }
    s_packetsPopulated = true;
}

/* Matches RecordCapturedScript (VA 0x10004220..0x10004473 in NRTH.dll) */
extern "C" void NrthUI_OnClientScriptLoaded(const char *chunkName, const char *code, size_t len)
{
    if (!chunkName || !chunkName[0] || !code || len == 0) {
        return;
    }
    if (chunkName[0] == '&' ||
        (chunkName[0] == '-' && chunkName[1] == '-') ||
        strstr(chunkName, "custom") != nullptr) {
        return;
    }
    s_status = "Server connected.";

    const char *p = chunkName;
    while (*p == '@' || *p == ':' || *p == '\\' || *p == '/') ++p;
    const char *sep = p;
    while (*sep && *sep != '\\' && *sep != '/') ++sep;
    if (*sep && sep > p && (size_t)(sep - p) < 64) {
        std::string resName(p, (size_t)(sep - p));
        NrthUI_OnResourceStarted(resName.c_str());
    }

    for (auto &entry : s_dumperEntries) {
        if (entry.name == chunkName) {
            entry.code.assign(code, len);
            return;
        }
    }
    if (s_dumperEntries.size() < 512) {
        s_dumperEntries.push_back({ chunkName, std::string(code, len) });
    }
}

/* Matches Hook_Client_100050a0 & Hook_Client_100056f0 (VA 0x100050a0 / 0x100056f0 in NRTH.dll) */
extern "C" bool NrthUI_ShouldBlockServerEvent(const char *eventName)
{
    if (!eventName || !eventName[0]) {
        return false;
    }
    bool seen = false;
    for (const auto &ev : s_recentTriggers) {
        if (ev == eventName) {
            seen = true;
            break;
        }
    }
    if (!seen && s_recentTriggers.size() < 256) {
        s_recentTriggers.push_back(eventName);
    }
    if (s_blockAllEvents) {
        char msg[192];
        snprintf(msg, sizeof(msg), "Trigger blocked: %s", eventName);
        NrthUI_PushToastNotification(msg);
        return true;
    }
    for (const auto &blk : s_blockedEvents) {
        if (blk == eventName) {
            char msg[192];
            snprintf(msg, sizeof(msg), "Trigger blocked: %s", eventName);
            NrthUI_PushToastNotification(msg);
            return true;
        }
    }
    return false;
}

/* Matches Hook_Client_100052b0 (VA 0x100052b0..0x10005494 in NRTH.dll) */
extern "C" void NrthUI_OnResourceStarted(const char *resName)
{
    if (!resName || !resName[0]) {
        return;
    }
    s_status = "Server connected.";
    for (const auto &r : s_resources) {
        if (r == resName) {
            return;
        }
    }
    if (s_resources.size() < 256) {
        s_resources.push_back(resName);
    }
}

/* Matches Hook_Netc_SendPacket_1001da80 packet table lookup */
extern "C" bool NrthUI_OnPacketSent(unsigned char packetId)
{
    EnsurePacketsPopulated();
    bool blocked = false;
    for (auto &p : s_packets) {
        if (p.id == (int)packetId) {
            p.time = "live";
            if (p.blocked) {
                blocked = true;
            }
        }
    }
    return blocked;
}

extern "C" uint32_t NrthUI_GetMarkerCount(void)
{
    return (uint32_t)s_markers.size();
}

extern "C" bool NrthUI_GetMarkerAt(uint32_t idx, float *outX, float *outY, float *outZ)
{
    if (idx >= s_markers.size()) {
        return false;
    }
    if (outX) *outX = s_markers[idx].x;
    if (outY) *outY = s_markers[idx].y;
    if (outZ) *outZ = s_markers[idx].z;
    return true;
}

/* ===========================================================================
 * Lua VM Bridge execution (0x1013bf04 registry stride 0x1C, L at +0x18,
 * default_L 0x1013c95c, loadbuffer 0x1013c94c with "@custom", pcall 0x1013c974,
 * flag 0x1013c939, script buffer 0x1013beec, VirtualQuery guard)
 * =========================================================================== */
extern "C" bool NrthUI_ExecuteLuaViaBridge(const char *code, size_t len, int vmMode)
{
    if (!code || len == 0) {
        return false;
    }
    NrthLuaVmBridge *bridge = Nrth_GetLuaVmBridge();
    if (!bridge) {
        return false;
    }

    size_t copyLen = len < (sizeof(bridge->scriptBuf_1013beec) - 1)
                         ? len
                         : (sizeof(bridge->scriptBuf_1013beec) - 1);
    memcpy(bridge->scriptBuf_1013beec, code, copyLen);
    bridge->scriptBuf_1013beec[copyLen] = '\0';
    bridge->execFlag_1013c939 = 1;

    static char s_customChunk[sizeof(kCt_CustomChunk)] = {0};
    static bool s_customGate = false;
    const char *chunkName = NrthDecryptOnce(kCt_CustomChunk, sizeof(kCt_CustomChunk),
                                            0x2D, s_customChunk, &s_customGate);

    void *targetL = NULL;
    if (vmMode == 0 && bridge->default_L_1013c95c) {
        targetL = bridge->default_L_1013c95c;
    } else if (vmMode > 0 && (uint32_t)(vmMode - 1) < bridge->slotCount &&
               (uint32_t)(vmMode - 1) < NRTH_VM_REGISTRY_CAP) {
        void *cand = (void *)(uintptr_t)bridge->registry_1013bf04[vmMode - 1].luaStatePtr32;
        if (cand && Nrth_IsPointerReadable_VirtualQuery(cand)) {
            targetL = cand;
        }
    }
    if (!targetL && bridge->slotCount > 0) {
        for (uint32_t i = 0; i < bridge->slotCount && i < NRTH_VM_REGISTRY_CAP; ++i) {
            void *cand = (void *)(uintptr_t)bridge->registry_1013bf04[i].luaStatePtr32;
            if (cand && Nrth_IsPointerReadable_VirtualQuery(cand)) {
                targetL = cand;
                break;
            }
        }
    }

    if (targetL &&
        Nrth_IsPointerReadable_VirtualQuery(targetL) &&
        bridge->loadbuffer_1013c94c &&
        bridge->pcall_1013c974) {
        int rc = bridge->loadbuffer_1013c94c(targetL, bridge->scriptBuf_1013beec,
                                             copyLen, chunkName);
        if (rc == 0) {
            rc = bridge->pcall_1013c974(targetL, 0, 0, 0);
        }
        bridge->execFlag_1013c939 = 0;
        return (rc == 0);
    }

    return false;
}

/* ===========================================================================
 * Full Dear ImGui + Embedded Lua 5.4.6 UI (Windows build)
 * =========================================================================== */
#if defined(_WIN32) && !defined(NRTH_HEADLESS_TEST)

#include "imgui.h"

extern "C" {
#include "lua.h"
#include "lauxlib.h"
#include "lualib.h"
}

static lua_State *s_L = nullptr;
static std::string s_console;

static int LuaPrint(lua_State *L)
{
    int n = lua_gettop(L);
    for (int i = 1; i <= n; ++i) {
        size_t len = 0;
        const char *s = luaL_tolstring(L, i, &len);
        s_console.append(s ? s : "nil", s ? len : 3);
        lua_pop(L, 1);
        if (i < n) s_console += "\t";
    }
    s_console += "\n";
    return 0;
}

static void EnsureLuaVM()
{
    if (s_L) return;
    s_L = luaL_newstate();
    if (!s_L) return;
    luaL_openlibs(s_L);
    lua_pushcfunction(s_L, LuaPrint);
    lua_setglobal(s_L, "print");
    lua_pushcfunction(s_L, LuaPrint);
    lua_setglobal(s_L, "log");
}

static bool RunLuaBuffer(const char *code, size_t len, const char *chunkName, int vmMode)
{
    /* First try the MTA Lua VM bridge (0x1013bf04 / default_L 0x1013c95c with "@custom") */
    if (NrthUI_ExecuteLuaViaBridge(code, len, vmMode)) {
        return true;
    }

    /* Fallback to the embedded Lua 5.4.6 VM using "@custom" chunk name */
    static char s_customChunk[sizeof(kCt_CustomChunk)] = {0};
    static bool s_customGate = false;
    const char *effectiveChunk = chunkName ? chunkName :
        NrthDecryptOnce(kCt_CustomChunk, sizeof(kCt_CustomChunk), 0x2D, s_customChunk, &s_customGate);

    EnsureLuaVM();
    if (!s_L) {
        s_console += "[error] Lua VM unavailable\n";
        return false;
    }
    lua_settop(s_L, 0);
    int rc = luaL_loadbuffer(s_L, code, len, effectiveChunk);
    if (rc == LUA_OK) rc = lua_pcall(s_L, 0, LUA_MULTRET, 0);
    if (rc != LUA_OK) {
        const char *err = lua_tostring(s_L, -1);
        s_console += "[error] ";
        s_console += err ? err : "?";
        s_console += "\n";
        lua_pop(s_L, 1);
        return false;
    }
    return true;
}

static int  s_topTab     = 0;
static int  s_scriptsSub = 0;
static int  s_cheatSub   = 0;
static bool s_menuOpen   = true;

static char s_editorBuf[65536] = "-- DARKANARCHY lua editor\n";
static int  s_vmIndex     = 0;  /* "Default VM", "@custom" */

static std::string s_lastAction;

struct ScriptItem { std::string name; bool autoInject; };
static std::vector<ScriptItem> s_scripts;
static int  s_scriptSel = -1;
static bool s_scriptsScanned = false;

static char s_packetSearch[64] = "";
static int  s_packetSel = -1;

struct PlayerRow { std::string name; bool isYou; };
static std::vector<PlayerRow> s_players;
static std::vector<std::string> s_friends;
static char s_playerFilterBuf[64] = "";
static int  s_playerSel = 0;
static char s_markerName[64] = "";

struct ConfigItem { std::string name; };
static std::vector<ConfigItem> s_configs;
static bool s_configsScanned = false;
static char s_cfgName[64] = "default";
static int  s_cfgSel = -1;
static bool s_waitingForKey = false;

struct Bind { std::string action; int key; int mode; };
static std::vector<Bind> s_binds;
static int  s_bindCapture = -1;

static int s_vehicleSel = 0;

/* ---------------------------------------------------------------------------
 * DARKANARCHY theme: coal black + blood red + bone white
 * ------------------------------------------------------------------------- */
static const ImVec4 kBlood      = ImVec4(0.73f, 0.05f, 0.05f, 1.00f);
static const ImVec4 kBloodHi    = ImVec4(0.92f, 0.10f, 0.10f, 1.00f);
static const ImVec4 kBloodDim   = ImVec4(0.42f, 0.05f, 0.05f, 1.00f);
static const ImVec4 kCoal       = ImVec4(0.055f, 0.055f, 0.070f, 0.97f);
static const ImVec4 kAsh        = ImVec4(0.095f, 0.095f, 0.120f, 0.98f);
static const ImVec4 kAshDeep    = ImVec4(0.13f, 0.13f, 0.16f, 1.00f);
static const ImVec4 kBone       = ImVec4(0.93f, 0.92f, 0.90f, 1.00f);
static const ImVec4 kSteel      = ImVec4(0.34f, 0.30f, 0.30f, 0.65f);
static const ImVec4 kSmoke      = ImVec4(0.62f, 0.60f, 0.60f, 1.00f);

void NrthUI_ApplyTheme()
{
    ImGuiStyle &st = ImGui::GetStyle();
    st.WindowRounding   = 10.f;
    st.ChildRounding    = 8.f;
    st.FrameRounding    = 5.f;
    st.GrabRounding     = 5.f;
    st.PopupRounding    = 6.f;
    st.ScrollbarRounding= 8.f;
    st.TabRounding      = 6.f;
    st.WindowBorderSize = 1.f;
    st.ChildBorderSize  = 1.f;
    st.FrameBorderSize  = 0.f;
    st.FramePadding     = ImVec2(9, 5);
    st.ItemSpacing      = ImVec2(8, 7);
    st.WindowPadding    = ImVec2(14, 12);
    st.ScrollbarSize    = 13.f;
    st.GrabMinSize      = 10.f;

    ImVec4 *c = st.Colors;
    c[ImGuiCol_WindowBg]         = kCoal;
    c[ImGuiCol_ChildBg]          = kAsh;
    c[ImGuiCol_PopupBg]          = kAshDeep;
    c[ImGuiCol_Border]           = kSteel;
    c[ImGuiCol_FrameBg]          = ImVec4(0.14f, 0.14f, 0.17f, 1.f);
    c[ImGuiCol_FrameBgHovered]   = kBloodDim;
    c[ImGuiCol_FrameBgActive]    = kBlood;
    c[ImGuiCol_Button]           = ImVec4(0.16f, 0.15f, 0.17f, 1.f);
    c[ImGuiCol_ButtonHovered]    = kBloodDim;
    c[ImGuiCol_ButtonActive]     = kBlood;
    c[ImGuiCol_Header]           = kBloodDim;
    c[ImGuiCol_HeaderHovered]    = kBlood;
    c[ImGuiCol_HeaderActive]     = kBloodHi;
    c[ImGuiCol_Tab]              = ImVec4(0.16f, 0.15f, 0.17f, 1.f);
    c[ImGuiCol_TabHovered]       = kBlood;
    c[ImGuiCol_TabActive]        = kBloodDim;
    c[ImGuiCol_TitleBg]          = kCoal;
    c[ImGuiCol_TitleBgActive]    = kCoal;
    c[ImGuiCol_TitleBgCollapsed] = kCoal;
    c[ImGuiCol_Separator]        = kSteel;
    c[ImGuiCol_CheckMark]        = kBloodHi;
    c[ImGuiCol_SliderGrab]       = kBlood;
    c[ImGuiCol_SliderGrabActive] = kBloodHi;
    c[ImGuiCol_ScrollbarBg]      = kCoal;
    c[ImGuiCol_ScrollbarGrab]        = ImVec4(0.25f, 0.22f, 0.22f, 1.f);
    c[ImGuiCol_ScrollbarGrabHovered] = kBloodDim;
    c[ImGuiCol_ScrollbarGrabActive]  = kBlood;
    c[ImGuiCol_Text]             = kBone;
    c[ImGuiCol_TextDisabled]     = kSmoke;
    c[ImGuiCol_TextSelectedBg]   = ImVec4(0.55f, 0.08f, 0.08f, 0.60f);
    c[ImGuiCol_ResizeGrip]       = kSteel;
    c[ImGuiCol_ResizeGripHovered]= kBloodDim;
    c[ImGuiCol_ResizeGripActive] = kBlood;
    c[ImGuiCol_NavCursor]        = kBlood;
}

/* ---------------------------------------------------------------------------
 * Anarchy-A circle logo drawn with the ImGui foreground draw list
 * ------------------------------------------------------------------------- */
static void DrawAnarchyLogo(ImDrawList *dl, const ImVec2 &center, float radius, float thickness)
{
    if (!dl) return;
    const ImU32 colGlow  = IM_COL32(190, 20, 20, 60);
    const ImU32 colRed   = IM_COL32(210, 30, 30, 255);
    const ImU32 colRedHi = IM_COL32(255, 70, 60, 255);

    /* glow rings */
    dl->AddCircle(center, radius + 4.0f, colGlow, 0, thickness + 3.0f);
    dl->AddCircle(center, radius, colRed, 0, thickness);

    /* A shape: apex at top of circle, legs to the lower-left/right chord points */
    const ImVec2 apex(center.x, center.y - radius);
    const double ang = 3.9269908; /* 225 deg (lower-left) & 315 deg (lower-right) */
    const ImVec2 legL(center.x + radius * 0.74f * (float)-cos(0.7853982), center.y + radius * 0.74f * (float)sin(0.7853982));
    const ImVec2 legR(center.x + radius * 0.74f * (float) cos(0.7853982), center.y + radius * 0.74f * (float) sin(0.7853982));
    (void)ang;
    dl->AddLine(apex, legL, colRed, thickness);
    dl->AddLine(apex, legR, colRed, thickness);

    /* crossbar extending slightly past the legs (classic anarchy A) */
    const float barY = center.y + radius * 0.30f;
    const float barHalf = radius * 0.62f;
    dl->AddLine(ImVec2(center.x - barHalf, barY), ImVec2(center.x + barHalf, barY), colRedHi, thickness);
}

struct ToastNotification {
    std::string text;
    ULONGLONG   createdTick;
};
static std::vector<ToastNotification> s_notifications;
static bool s_showKeybindWindow = false;
static Feature *s_capturingFeature = nullptr;

static void AddNotification_10002cd0(const char *msg)
{
    if (!msg || !msg[0] || !g_cfg.notifications) {
        return;
    }
    if (s_notifications.size() >= 6) {
        s_notifications.erase(s_notifications.begin());
    }
    s_notifications.push_back({ msg, GetTickCount64() });
}

extern "C" void NrthUI_PushToastNotification(const char *msg)
{
    AddNotification_10002cd0(msg);
}

static void FeatureAction(const char *msg)
{
    s_lastAction = msg ? msg : "";
    NrthUI_SyncFeaturesToState();
    AddNotification_10002cd0(msg);
}

static void ScanLuaScripts()
{
    s_scripts.clear();
    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA("lua\\*.*", &fd);
    if (h != INVALID_HANDLE_VALUE) {
        do {
            if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                s_scripts.push_back({fd.cFileName, false});
            }
        } while (FindNextFileA(h, &fd));
        FindClose(h);
    }
    s_scriptsScanned = true;
}

static void ScanConfigs()
{
    s_configs.clear();
    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA("*.ovr", &fd);
    if (h != INVALID_HANDLE_VALUE) {
        do {
            if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
                s_configs.push_back({fd.cFileName});
        } while (FindNextFileA(h, &fd));
        FindClose(h);
    }
    s_configsScanned = true;
}

static bool TabButton(const char *label, const char *hiddenId, bool active, const ImVec2 &size)
{
    if (active) {
        ImGui::PushStyleColor(ImGuiCol_Button, kBlood);
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, kBloodHi);
        ImGui::PushStyleColor(ImGuiCol_ButtonActive, kBloodHi);
    } else {
        ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.16f, 0.15f, 0.17f, 1.f));
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, kBloodDim);
        ImGui::PushStyleColor(ImGuiCol_ButtonActive, kBlood);
    }
    char buf[256];
    snprintf(buf, sizeof(buf), "%s##%s", label, hiddenId);
    bool clicked = ImGui::Button(buf, size);
    ImGui::PopStyleColor(3);
    return clicked;
}

static void StatusLine()
{
    ImGui::TextColored(g_bArabic ? kBloodHi : kBloodHi, "%s",
        g_bArabic ? TrGet("", "متصل بالسيرفر") : s_status.c_str());
    if (!g_bArabic && !s_lastAction.empty()) {
        ImGui::SameLine();
        ImGui::TextDisabled("| %s", s_lastAction.c_str());
    } else if (g_bArabic && !s_lastAction.empty()) {
        ImGui::SameLine();
        ImGui::TextDisabled("%s", TrGet("", s_lastAction.c_str()));
    }
}

static void DrawEditor()
{
    ImGui::BeginChild("##lua_gutter", ImVec2(48, -140), true);
    int lines = 1;
    for (const char *p = s_editorBuf; *p; ++p) if (*p == '\n') ++lines;
    for (int i = 1; i <= lines && i < 2000; ++i) {
        ImGui::TextDisabled("%d", i);
    }
    ImGui::EndChild();
    ImGui::SameLine();
    ImGui::PushItemWidth(-1);
    ImGui::InputTextMultiline("##lua_editor", s_editorBuf, sizeof(s_editorBuf),
                              ImVec2(-1, -140), ImGuiInputTextFlags_AllowTabInput);
    ImGui::PopItemWidth();

    static char s_customChunk[sizeof(kCt_CustomChunk)] = {0};
    static bool s_customGate = false;
    const char *customLabel = NrthDecryptOnce(kCt_CustomChunk, sizeof(kCt_CustomChunk),
                                              0x2D, s_customChunk, &s_customGate);

    if (ImGui::Button(L("Execute", "تنفيذ"), ImVec2(110, 34))) {
        s_console.clear();
        if (RunLuaBuffer(s_editorBuf, strlen(s_editorBuf), customLabel, s_vmIndex)) {
            FeatureAction(g_bArabic ? "تم تنفيذ السكربت" : "Script executed");
        } else {
            FeatureAction(g_bArabic ? "خطأ في السكربت (شاهد الكونسول)" : "Script error (see console)");
        }
    }
    ImGui::SameLine();
    NrthLuaVmBridge *bridge = Nrth_GetLuaVmBridge();
    std::string vmPreview = g_bArabic ? "الافتراضية VM" : "Default VM";
    if (s_vmIndex > 0 && bridge && (uint32_t)(s_vmIndex - 1) < bridge->slotCount &&
        (uint32_t)(s_vmIndex - 1) < NRTH_VM_REGISTRY_CAP) {
        const char *nm = (const char *)bridge->registry_1013bf04[s_vmIndex - 1].resourceMeta;
        char lbl[64];
        snprintf(lbl, sizeof(lbl), "%s (0x%08X)", nm[0] ? nm : customLabel,
                 bridge->registry_1013bf04[s_vmIndex - 1].luaStatePtr32);
        vmPreview = lbl;
    }
    ImGui::SetNextItemWidth(200);
    if (ImGui::BeginCombo("##vm_combo", vmPreview.c_str())) {
        if (ImGui::Selectable(L("Default VM", "الافتراضية VM"), s_vmIndex == 0)) {
            s_vmIndex = 0;
        }
        if (bridge) {
            for (uint32_t i = 0; i < bridge->slotCount && i < NRTH_VM_REGISTRY_CAP; ++i) {
                const char *nm = (const char *)bridge->registry_1013bf04[i].resourceMeta;
                char lbl[80];
                snprintf(lbl, sizeof(lbl), "%s (0x%08X)##vm_%u", nm[0] ? nm : customLabel,
                         bridge->registry_1013bf04[i].luaStatePtr32, i);
                if (ImGui::Selectable(lbl, s_vmIndex == (int)(i + 1))) {
                    s_vmIndex = (int)(i + 1);
                }
            }
        }
        ImGui::EndCombo();
    }
    ImGui::SameLine();
    if (ImGui::Button(L("Clear", "تفريغ##console"))) s_console.clear();
    ImGui::SameLine();
    ImGui::TextDisabled("%s", L("Output:", "النتيجة:"));

    ImGui::BeginChild("##lua_console", ImVec2(-1, -1), true);
    if (s_console.empty()) {
        ImGui::TextDisabled("%s", L("print(...) output appears here",
                                   "نتيجة print(...) تظهر هنا"));
    } else {
        ImGui::TextUnformatted(s_console.c_str());
    }
    ImGui::EndChild();
}

static void DrawScriptsList()
{
    if (!s_scriptsScanned) ScanLuaScripts();
    ImGui::TextDisabled("%s", L("Path: .\\lua\\", "المسار: .\\lua\\"));
    ImGui::BeginChild("##scripts_list", ImVec2(-1, -80), true);
    if (s_scripts.empty()) {
        ImGui::TextDisabled("%s", L("No scripts found", "لا يوجد سكربتات"));
    }
    for (int i = 0; i < (int)s_scripts.size(); ++i) {
        ImGui::PushID(i);
        if (ImGui::Selectable(s_scripts[i].name.c_str(), s_scriptSel == i)) s_scriptSel = i;
        ImGui::SameLine(220);
        char lbl[96];
        snprintf(lbl, sizeof(lbl), "%s##%d", L("Inject", "حقن"), i);
        if (ImGui::SmallButton(lbl)) FeatureAction(g_bArabic ? "تم الحقن" : "Injected");
        ImGui::SameLine();
        snprintf(lbl, sizeof(lbl), "%s##%d", L("Auto-inj", "حقن تلقائي"), i);
        ImGui::Checkbox(lbl, &s_scripts[i].autoInject);
        ImGui::PopID();
    }
    ImGui::EndChild();
    if (ImGui::Button(L("Dump", "تفريغ"))) {
        if (s_scriptSel >= 0) {
            char msg[256];
            snprintf(msg, sizeof(msg), "%s: %s",
                     L("Dump script saved", "تم حفظ السكربت"),
                     s_scripts[s_scriptSel].name.c_str());
            FeatureAction(msg);
        }
    }
    ImGui::SameLine();
    if (ImGui::Button(L("Dump all", "تفريغ الكل"))) {
        char msg[128];
        snprintf(msg, sizeof(msg), "%s (%d)",
                 L("Dump all scripts saved", "تم حفظ كل السكربتات"), (int)s_scripts.size());
        FeatureAction(msg);
    }
    ImGui::SameLine();
    if (ImGui::Button(L("Run", "تشغيل##script")) && s_scriptSel >= 0) {
        std::string path = "lua\\" + s_scripts[s_scriptSel].name;
        FILE *fp = fopen(path.c_str(), "rb");
        if (fp) {
            std::string code;
            char buf[4096];
            size_t n;
            while ((n = fread(buf, 1, sizeof(buf), fp)) > 0) code.append(buf, n);
            fclose(fp);
            s_console.clear();
            if (RunLuaBuffer(code.c_str(), code.size(), s_scripts[s_scriptSel].name.c_str(), s_vmIndex))
                FeatureAction(L("Script executed", "تم تنفيذ السكربت"));
            else
                FeatureAction(L("Script error (see console)", "خطأ في السكربت (شاهد الكونسول)"));
        }
    }
}

static void DrawResources()
{
    if (s_resources.empty()) {
        static const char *kRoots[] = {
            "mods\\deathmatch\\resources",
            "mods\\deathmatch\\cache",
        };
        for (const char *root : kRoots) {
            WIN32_FIND_DATAA fd;
            std::string pattern = std::string(root) + "\\*";
            HANDLE h = FindFirstFileA(pattern.c_str(), &fd);
            if (h == INVALID_HANDLE_VALUE) continue;
            do {
                if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                    if (strcmp(fd.cFileName, ".") && strcmp(fd.cFileName, ".."))
                        s_resources.push_back(fd.cFileName);
                }
            } while (FindNextFileA(h, &fd));
            FindClose(h);
        }
    }
    ImGui::TextDisabled("%s", L("Source: live CResourceManager (0x100052b0) + disk cache",
                                "المصدر: CResourceManager الحي + الكاش"));
    static char search[64] = "";
    ImGui::InputTextWithHint("##res_search", L("Search...", "بحث..."), search, sizeof(search));
    static int resSel = 0;
    if (resSel >= (int)s_resources.size()) resSel = 0;
    std::string preview = s_resources.empty() ? L("Select Resource", "اختر مود") : s_resources[resSel];
    ImGui::SetNextItemWidth(260);
    if (ImGui::BeginCombo("##res_combo", preview.c_str())) {
        for (int i = 0; i < (int)s_resources.size(); ++i) {
            if (search[0] && s_resources[i].find(search) == std::string::npos) continue;
            if (ImGui::Selectable(s_resources[i].c_str(), resSel == i)) resSel = i;
        }
        ImGui::EndCombo();
    }
    ImGui::SameLine();
    ImGui::TextDisabled("(%d %s)", (int)s_resources.size(), L("found", "موجود"));
    if (ImGui::Button(L("Stop Resource", "إيقاف المود"))) {
        if (!s_resources.empty() && resSel >= 0 && resSel < (int)s_resources.size()) {
            std::string stoppedName = s_resources[resSel];
            Nrth_StopClientResource_100054a0(stoppedName.c_str());
            s_resources.erase(s_resources.begin() + resSel);
            if (resSel >= (int)s_resources.size() && resSel > 0) --resSel;
            char msg[192];
            snprintf(msg, sizeof(msg), "%s: %s",
                     L("Resource stopped", "تم إيقاف المود"), stoppedName.c_str());
            FeatureAction(msg);
        }
    }
    ImGui::Separator();
    ImGui::TextDisabled("%s", L("Block list:", "قائمة الحظر:"));
    for (auto &e : s_blockedEvents) ImGui::BulletText("%s (blocked)", e.c_str());
}

static void DrawEvents()
{
    static int evSel = 0;
    static const char *kEvents[] = {"onClientRender", "onClientPlayerDamage", "onClientVehicleEnter",
                                    "onClientChatMessage", "onClientElementDataChange", "onClientPreRender"};
    ImGui::SetNextItemWidth(280);
    ImGui::BeginCombo("##event_combo", kEvents[evSel]);
    for (int i = 0; i < 6; ++i) if (ImGui::Selectable(kEvents[i], evSel == i)) evSel = i;
    ImGui::EndCombo();
    ImGui::SameLine();
    if (ImGui::Button(L("Block", "حظر##event"))) {
        s_blockedEvents.push_back(kEvents[evSel]);
        char msg[192];
        snprintf(msg, sizeof(msg), "%s: %s", L("Event blocked", "تم حظر الحدث"), kEvents[evSel]);
        FeatureAction(msg);
    }
    ImGui::SameLine();
    if (ImGui::Button(L("Unblock", "إلغاء الحظر##event")) && !s_blockedEvents.empty()) {
        char msg[192];
        snprintf(msg, sizeof(msg), "%s: %s", L("Event unblocked", "تم فك حظر الحدث"),
                 s_blockedEvents.back().c_str());
        FeatureAction(msg);
        s_blockedEvents.pop_back();
    }
    ImGui::SameLine();
    ImGui::Checkbox(L("Block All Events", "حظر كل الأحداث"), &s_blockAllEvents);
    static char trig[96] = "";
    ImGui::InputTextWithHint("##trigger_input", L("triggerServerEvent name...",
                                                  "اسم triggerServerEvent..."), trig, sizeof(trig));
    ImGui::SameLine();
    if (ImGui::Button(L("Add to Block List", "أضف لقائمة الحظر")) && trig[0]) {
        s_blockedEvents.push_back(trig);
        char msg[192];
        snprintf(msg, sizeof(msg), "%s: %s", L("Event blocked", "تم حظر الحدث"), trig);
        FeatureAction(msg);
        trig[0] = 0;
    }
    ImGui::Separator();
    ImGui::Text("%s", L("Recent Triggers (click Block to filter):",
                        "الأحداث الأخيرة (اضغط حظر للفلترة):"));
    if (s_recentTriggers.empty()) ImGui::TextDisabled("%s", L("No triggers", "لا أحداث"));
    for (int i = 0; i < (int)s_recentTriggers.size(); ++i) {
        ImGui::PushID(i);
        ImGui::BulletText("%s", s_recentTriggers[i].c_str());
        ImGui::SameLine(280);
        if (ImGui::SmallButton(L("Block", "حظر"))) {
            s_blockedEvents.push_back(s_recentTriggers[i]);
            char msg[192];
            snprintf(msg, sizeof(msg), "%s: %s", L("Event blocked", "تم حظر الحدث"),
                     s_recentTriggers[i].c_str());
            FeatureAction(msg);
        }
        ImGui::PopID();
    }
}

static void DrawEventsTable()
{
    ImGui::TextDisabled("%s", L("Events Table (live event registry view)",
                                "جدول الأحداث (سجل مباشر)"));
    if (ImGui::BeginTable("##events_table", 3, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg)) {
        ImGui::TableSetupColumn(L("Event", "الحدث"));
        ImGui::TableSetupColumn(L("Source", "المصدر"));
        ImGui::TableSetupColumn(L("State", "الحالة"));
        ImGui::TableHeadersRow();
        for (auto &e : s_recentTriggers) {
            ImGui::TableNextRow();
            ImGui::TableNextColumn(); ImGui::TextUnformatted(e.c_str());
            ImGui::TableNextColumn(); ImGui::TextDisabled("client");
            ImGui::TableNextColumn(); ImGui::TextDisabled("%s", L("tracked", "متابع"));
        }
        for (auto &e : s_blockedEvents) {
            ImGui::TableNextRow();
            ImGui::TableNextColumn(); ImGui::TextUnformatted(e.c_str());
            ImGui::TableNextColumn(); ImGui::TextDisabled("client");
            ImGui::TableNextColumn(); ImGui::TextColored(kBloodHi, "%s", L("(blocked)", "(محظور)"));
        }
        ImGui::EndTable();
    }
}

static void DrawPackets()
{
    EnsurePacketsPopulated();
    if (ImGui::Button(L("Refresh", "تحديث"))) {
        s_packetsPopulated = false;
        s_packets.clear();
        EnsurePacketsPopulated();
        FeatureAction(L("Refresh", "تم التحديث"));
    }
    ImGui::SameLine();
    ImGui::Text("%s: %zu", L("Packets", "الباكيتات"), s_packets.size());
    ImGui::SameLine();
    if (ImGui::Button(L("Clear All", "مسح الكل"))) s_packets.clear();
    ImGui::SameLine();
    if (ImGui::Button(L("Unblock All", "فك حظر الكل")))
        for (auto &p : s_packets) p.blocked = false;
    ImGui::SameLine();
    ImGui::InputTextWithHint("##packet_search", L("Search packet...", "بحث عن باكيت..."),
                             s_packetSearch, sizeof(s_packetSearch));

    ImGui::BeginChild("packets_left", ImVec2(-320, -1), true);
    if (s_packets.empty()) {
        ImGui::TextDisabled("%s", L("No packets detected.", "لا يوجد باكيتات."));
    }
    for (int i = 0; i < (int)s_packets.size(); ++i) {
        if (s_packetSearch[0] && s_packets[i].name.find(s_packetSearch) == std::string::npos) {
            continue;
        }
        ImGui::PushID(i);
        if (ImGui::Selectable(s_packets[i].name.c_str(), s_packetSel == i)) s_packetSel = i;
        ImGui::SameLine();
        ImGui::TextDisabled("%s", s_packets[i].blocked ? L("BLOCKED", "محظور")
                                                       : L("UNBLOCKED", "مفتوح"));
        ImGui::PopID();
    }
    ImGui::EndChild();
    ImGui::SameLine();
    ImGui::BeginChild("packets_right", ImVec2(0, -1), true);
    if (s_packetSel >= 0 && s_packetSel < (int)s_packets.size()) {
        const PacketRow &p = s_packets[s_packetSel];
        ImGui::Text("%s: %s", L("Name", "الاسم"), p.name.c_str());
        ImGui::Text("%s: %s", L("Time", "الوقت"), p.time.c_str());
        ImGui::Text("ID: %d", p.id);
        ImGui::TextColored(kBloodHi, "%s", p.blocked ? L("BLOCKED", "محظور")
                                                     : L("UNBLOCKED", "مفتوح"));
        if (ImGui::Button(L("Block Packet", "حظر الباكيت")))
            s_packets[s_packetSel].blocked = !s_packets[s_packetSel].blocked;
        ImGui::SameLine();
        if (ImGui::Button(L("Resend", "إعادة إرسال"))) {
            char msg[192];
            snprintf(msg, sizeof(msg), "%s: %s", L("Resending packet", "إعادة إرسال الباكيت"),
                     p.name.c_str());
            FeatureAction(msg);
        }
        ImGui::SameLine();
        if (ImGui::Button(L("Copy Name", "نسخ الاسم"))) {
            ImGui::SetClipboardText(p.name.c_str());
            char msg[192];
            snprintf(msg, sizeof(msg), "%s: %s", L("Packet name copied", "تم نسخ اسم الباكيت"),
                     p.name.c_str());
            FeatureAction(msg);
        }
    } else {
        ImGui::TextDisabled("%s", L("Select a packet", "اختر باكيت"));
    }
    ImGui::EndChild();
}

static bool SaveDumperEntryToDisk(const DumperFileEntry &entry)
{
    CreateDirectoryA("C:\\NVX", NULL);
    CreateDirectoryA("C:\\NVX\\dump", NULL);
    std::string safeName;
    for (char ch : entry.name) {
        if ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
            (ch >= '0' && ch <= '9') || ch == '_' || ch == '-' || ch == '.') {
            safeName.push_back(ch);
        } else if (ch == '/' || ch == '\\' || ch == ':') {
            safeName.push_back('_');
        }
    }
    if (safeName.empty()) safeName = "script.lua";
    if (safeName.find(".lua") == std::string::npos) safeName += ".lua";
    std::string fullPath = "C:\\NVX\\dump\\" + safeName;
    FILE *fp = fopen(fullPath.c_str(), "wb");
    if (!fp) return false;
    fwrite(entry.code.data(), 1, entry.code.size(), fp);
    fclose(fp);
    return true;
}

static void DrawDumper()
{
    static int dumpSel = -1;
    static char dumpFilter[64] = "";
    ImGui::InputTextWithHint("##dump_filter", L("Search captured scripts...", "بحث في السكربتات الملتقطة..."),
                             dumpFilter, sizeof(dumpFilter));
    ImGui::SameLine();
    if (ImGui::Button(L("Dump Selected", "تفريغ المحدد")) && dumpSel >= 0 && dumpSel < (int)s_dumperEntries.size()) {
        if (SaveDumperEntryToDisk(s_dumperEntries[dumpSel])) {
            char msg[320];
            snprintf(msg, sizeof(msg), "%s: %s", L("Dump script saved", "تم حفظ السكربت"),
                     s_dumperEntries[dumpSel].name.c_str());
            FeatureAction(msg);
        } else {
            FeatureAction(L("Failed to save dump file", "فشل حفظ ملف التفريغ"));
        }
    }
    ImGui::SameLine();
    if (ImGui::Button(L("Dump All", "تفريغ الكل"))) {
        int saved = 0;
        for (const auto &e : s_dumperEntries) {
            if (SaveDumperEntryToDisk(e)) ++saved;
        }
        char msg[128];
        snprintf(msg, sizeof(msg), "%s (%d)", L("Dump all scripts saved", "تم حفظ كل السكربتات"), saved);
        FeatureAction(msg);
    }
    ImGui::SameLine();
    if (ImGui::Button(L("Load in Editor", "تحميل في المحرر")) && dumpSel >= 0 && dumpSel < (int)s_dumperEntries.size()) {
        const std::string &code = s_dumperEntries[dumpSel].code;
        size_t copyLen = code.size() < (sizeof(s_editorBuf) - 1) ? code.size() : (sizeof(s_editorBuf) - 1);
        memcpy(s_editorBuf, code.data(), copyLen);
        s_editorBuf[copyLen] = '\0';
        s_topTab = 0;
        s_scriptsSub = 0;
        FeatureAction(L("Loaded script into editor", "تم تحميل السكربت في المحرر"));
    }

    ImGui::BeginChild("##dumper_left", ImVec2(280, -1), true);
    ImGui::Text("%s (%zu)", L("Captured Scripts", "السكربتات الملتقطة"), s_dumperEntries.size());
    ImGui::Separator();
    for (int i = 0; i < (int)s_dumperEntries.size(); ++i) {
        if (dumpFilter[0] && s_dumperEntries[i].name.find(dumpFilter) == std::string::npos) continue;
        if (ImGui::Selectable(s_dumperEntries[i].name.c_str(), dumpSel == i)) {
            dumpSel = i;
        }
    }
    ImGui::Separator();
    ImGui::TextDisabled("%s", L("Resolved Offsets (0x1000c390)", "العناوين المكتشفة (0x1000c390)"));
    uint32_t count = 0;
    const uintptr_t *offsets = Nrth_GetClientResolvedOffsets(&count);
    for (uint32_t i = 0; i < count; ++i) {
        uint32_t addr = offsets[i] ? (uint32_t)offsets[i] : (0x10000000u + i * 0x10u);
        ImGui::Text("0x%08X (#%02u %s)", addr, i + 1, offsets[i] ? "ok" : "...");
    }
    ImGui::EndChild();
    ImGui::SameLine();
    ImGui::BeginChild("##dumper_right", ImVec2(0, -1), true);
    if (dumpSel >= 0 && dumpSel < (int)s_dumperEntries.size()) {
        const DumperFileEntry &e = s_dumperEntries[dumpSel];
        ImGui::Text("%s: %s (%zu %s)", L("Chunk", "المقطع"), e.name.c_str(), e.code.size(),
                    L("bytes", "بايت"));
        ImGui::Separator();
        if (e.code.size() > 65536) {
            ImGui::TextDisabled("%s", L("File big, no view script", "الملف كبير، لا يمكن العرض"));
        } else {
            ImGui::TextUnformatted(e.code.c_str());
        }
    } else {
        ImGui::TextDisabled("%s", L("Select a captured script from the left panel to preview or dump to C:\\NVX\\dump\\",
                                    "اختر سكربت من القائمة اليسرى للمعاينة أو الحفظ في C:\\NVX\\dump\\"));
    }
    ImGui::EndChild();
}

static void DrawPlayerTab()
{
    ImGui::InputTextWithHint("##player_filter", L("filter...", "فلتر..."),
                             s_playerFilterBuf, sizeof(s_playerFilterBuf));
    ImGui::SetNextItemWidth(280);
    std::string preview = s_players.empty() ? L("Select player...", "اختر لاعب...") :
        (s_players[s_playerSel].name + (s_players[s_playerSel].isYou ? std::string(" (") + L("you", "أنت") + ")" : ""));
    if (ImGui::BeginCombo("##player_combo", preview.c_str())) {
        for (int i = 0; i < (int)s_players.size(); ++i) {
            if (s_playerFilterBuf[0] && s_players[i].name.find(s_playerFilterBuf) == std::string::npos) continue;
            std::string lbl = s_players[i].name + (s_players[i].isYou ? std::string(" (") + L("you", "أنت") + ")" : "");
            if (ImGui::Selectable(lbl.c_str(), s_playerSel == i)) s_playerSel = i;
        }
        if (s_players.empty()) ImGui::TextDisabled("%s", L("No players found", "لا لاعبين"));
        ImGui::EndCombo();
    }
    if (ImGui::Button(L("Teleport", "تنقل"))) FeatureAction(L("Teleport", "تنقل"));
    ImGui::SameLine();
    if (ImGui::Button(L("Bomb", "تفجير"))) FeatureAction(L("Bomb", "تفجير"));
    ImGui::SameLine();
    if (ImGui::Button(L("Add Friend", "إضافة صديق"))) {
        if (!s_players.empty()) s_friends.push_back(s_players[s_playerSel].name);
    }
    ImGui::SameLine();
    if (ImGui::Button(L("Delete Friend", "حذف صديق")) && !s_friends.empty())
        s_friends.pop_back();
    ImGui::Separator();
    ImGui::Text("%s", L("Friend's list", "قائمة الأصدقاء"));
    if (s_friends.empty()) ImGui::TextDisabled("%s", L("No friends added", "لا أصدقاء"));
    for (auto &f : s_friends) ImGui::BulletText("%s", f.c_str());
}

static void TriggerFeatureImmediateAction(Feature &f)
{
    if (strcmp(f.label, "All Weapons") == 0 && f.on) {
        Nrth_TriggerAllWeapons_1002a5a7();
        FeatureAction(L("All weapons given (1000 ammo)", "تم إعطاء كل الأسلحة (1000 ذخيرة)"));
        return;
    }
    if (strcmp(f.label, "Jetpack") == 0) {
        Nrth_TriggerJetpack_1002a86c();
        FeatureAction(f.on ? L("Jetpack enabled", "تم تفعيل الجت باك")
                           : L("Jetpack disabled", "تم إيقاف الجت باك"));
        return;
    }
    if (strcmp(f.label, "Repair Car") == 0 && f.on) {
        if (Nrth_RepairCurrentVehicle_1002f070()) {
            FeatureAction(L("Vehicle repaired", "تم إصلاح المركبة"));
        } else {
            FeatureAction(L("You must be in a vehicle", "يجب أن تكون داخل مركبة"));
        }
        return;
    }
    if (strcmp(f.label, "Start Engine") == 0 && f.on) {
        if (Nrth_StartCurrentVehicleEngine_1002f0f0()) {
            FeatureAction(L("Engine started", "تم تشغيل المحرك"));
        } else {
            FeatureAction(L("You must be in a vehicle", "يجب أن تكون داخل مركبة"));
        }
        return;
    }
    if (strcmp(f.label, "Unlock Car") == 0 && f.on) {
        if (Nrth_UnlockNearestVehicle_1002eea0()) {
            FeatureAction(L("Unlocked nearest vehicle", "تم فتح أقرب مركبة"));
        } else {
            FeatureAction(L("No vehicle found nearby", "لا توجد مركبة قريبة"));
        }
        return;
    }
    char msg[256];
    snprintf(msg, sizeof(msg), "%s %s", FeatureTr(f.label),
             f.on ? L("enabled", "مفعل") : L("disabled", "موقوف"));
    FeatureAction(msg);
}

static void FeatureRow(Feature &f, const char *id)
{
    ImGui::PushID(id);
    if (ImGui::Checkbox(FeatureTr(f.label), &f.on)) {
        NrthUI_SyncFeaturesToState();
        TriggerFeatureImmediateAction(f);
    }
    ImGui::SameLine();
    if (ImGui::SmallButton("##gear")) ImGui::OpenPopup("##settings_panel");
    if (ImGui::BeginPopup("##settings_panel")) {
        ImGui::TextUnformatted(FeatureTr(f.label));
        ImGui::Separator();
        if (strcmp(f.label, "Give HP") == 0) {
            if (ImGui::SliderFloat(L("HP Value", "قيمة الدم##sp"), &s_hpValue, 1, 200)) NrthUI_SyncFeaturesToState();
        } else if (strcmp(f.label, "Give Armor") == 0) {
            if (ImGui::SliderFloat(L("Armor Value", "قيمة الدرع##sp"), &s_armorValue, 1, 200)) NrthUI_SyncFeaturesToState();
        } else if (strcmp(f.label, "AirBreak") == 0) {
            if (ImGui::SliderFloat(L("Speed", "السرعة##sp"), &s_abSpeed, 0.1f, 10.f, "%.2f")) NrthUI_SyncFeaturesToState();
            if (ImGui::SliderFloat(L("Increment", "التسارع##sp"), &s_abIncr, 0.05f, 2.f, "%.2f")) NrthUI_SyncFeaturesToState();
            ImGui::Separator();
            ImGui::Text("%s", L("Keybinds", "المفاتيح"));
            ImGui::BulletText("%s", L("Forward: W", "أمام: W"));
            ImGui::BulletText("%s", L("Back: S", "خلف: S"));
            ImGui::BulletText("%s", L("Left: A", "يسار: A"));
            ImGui::BulletText("%s", L("Right: D", "يمين: D"));
            ImGui::BulletText("%s", L("Up: Space / Down: LCtrl", "فوق: Space / تحت: LCtrl"));
        } else if (strcmp(f.label, "Click Warp") == 0) {
            if (ImGui::SliderFloat(L("Max Distance", "أقصى مسافة##sp"), &s_maxDist, 10, 1000, "%.0f")) NrthUI_SyncFeaturesToState();
            if (ImGui::SliderFloat(L("Crosshair Size", "حجم التصويبة##sp"), &s_crossSize, 2, 40, "%.0f")) NrthUI_SyncFeaturesToState();
            if (ImGui::Checkbox(L("Ground Warp", "تنقل أرضي##sp"), &s_groundWarp)) NrthUI_SyncFeaturesToState();
            if (ImGui::Checkbox(L("Enter Vehicle", "دخول المركبة##sp"), &s_enterVehicle)) NrthUI_SyncFeaturesToState();
        } else if (strcmp(f.label, "Anti-ScreenShot") == 0) {
            if (ImGui::Checkbox(L("Hide obs/discord", "إخفاء obs/discord"), &s_hideObsDiscord)) NrthUI_SyncFeaturesToState();
        } else if (strcmp(f.label, "Anti-AFK") == 0) {
            ImGui::Checkbox(L("Anti-AFK", "منع الطرد للخمول"), &s_antiAfk);
        } else {
            ImGui::TextDisabled("%s", L("settings synced to cheat engine state",
                                        "الإعدادات متزامنة مع محرك الغش"));
        }
        ImGui::Separator();
        if (s_capturingFeature == &f) {
            ImGui::Button(L("Press a key...", "اضغط أي زر..."));
            for (int vk = 1; vk < 256; ++vk) {
                if (vk == VK_LBUTTON || vk == VK_RBUTTON) continue;
                if (GetAsyncKeyState(vk) & 1) {
                    f.key = (vk == VK_ESCAPE) ? 0 : vk;
                    s_capturingFeature = nullptr;
                    break;
                }
            }
        } else {
            char keyBtn[96];
            if (f.key > 0) snprintf(keyBtn, sizeof(keyBtn), "%s: %d", L("Key", "زر"), f.key);
            else           snprintf(keyBtn, sizeof(keyBtn), "%s", L("Press a key...", "اضغط أي زر..."));
            if (ImGui::Button(keyBtn)) {
                s_capturingFeature = &f;
            }
        }
        ImGui::SameLine();
        const char *modes[] = { L("Hold", "ضغط مستمر"), L("Toggle", "تبديل") };
        ImGui::SetNextItemWidth(110);
        ImGui::Combo("##mode", &f.mode, modes, 2);
        ImGui::EndPopup();
    }
    ImGui::PopID();
}

static void DrawOtherTab()
{
    ImGui::TextDisabled("%s", L("Feature toggles (live synced)", "الميزات (مزامنة حية)"));
    for (int i = 0; i < (int)(sizeof(s_cheatFeatures) / sizeof(Feature)); ++i) {
        char id[32];
        snprintf(id, sizeof(id), "cf%d", i);
        FeatureRow(s_cheatFeatures[i], id);
    }
    ImGui::Separator();
    /* Action buttons matching 0x1002a580..0x1002a880 in NRTH.dll */
    if (ImGui::Button(L("All Weapons", "كل الأسلحة"))) {
        s_cheatFeatures[13].on = true;
        NrthUI_SyncFeaturesToState();
        Nrth_TriggerAllWeapons_1002a5a7();
        FeatureAction(L("All weapons given (1000 ammo)", "تم إعطاء كل الأسلحة (1000 ذخيرة)"));
    }
    ImGui::SameLine();
    if (ImGui::Button(L("High Jump", "قفز عالي"))) {
        s_cheatFeatures[10].on = !s_cheatFeatures[10].on;
        NrthUI_SyncFeaturesToState();
        FeatureAction(s_cheatFeatures[10].on ? L("High Jump enabled", "تم تفعيل القفز العالي")
                                             : L("High Jump disabled", "تم إيقاف القفز العالي"));
    }
    ImGui::SameLine();
    if (ImGui::Button(L("Money Exploit", "استغلال الفلوس"))) {
        s_cheatFeatures[11].on = !s_cheatFeatures[11].on;
        if (s_cheatFeatures[11].on) {
            static const char kMoneyLua[] = "givePlayerMoney(50000)";
            NrthUI_ExecuteLuaViaBridge(kMoneyLua, sizeof(kMoneyLua) - 1, 0);
        }
        FeatureAction(s_cheatFeatures[11].on ? L("Money Exploit enabled", "تم تفعيل استغلال الفلوس")
                                             : L("Money Exploit disabled", "تم إيقاف استغلال الفلوس"));
    }
    ImGui::SameLine();
    if (ImGui::Button(L("Jetpack", "جت باك"))) {
        s_cheatFeatures[12].on = !s_cheatFeatures[12].on;
        NrthUI_SyncFeaturesToState();
        Nrth_TriggerJetpack_1002a86c();
        FeatureAction(s_cheatFeatures[12].on ? L("Jetpack enabled", "تم تفعيل الجت باك")
                                             : L("Jetpack disabled", "تم إيقاف الجت باك"));
    }
    if (!s_lastAction.empty()) ImGui::TextDisabled("last: %s", s_lastAction.c_str());
}

static void DrawMarkersTab()
{
    ImGui::InputTextWithHint("##marker_name", L("marker name...", "اسم العلامة..."),
                             s_markerName, sizeof(s_markerName));
    ImGui::SameLine();
    if (ImGui::Button(L("Save", "حفظ")) && s_markerName[0]) {
        float mx = 0.0f, my = 0.0f, mz = 0.0f;
        Nrth_GetLocalPlayerPosition(&mx, &my, &mz);
        MarkerRow m = {s_markerName, mx, my, mz};
        s_markers.push_back(m);
        char msg[192];
        snprintf(msg, sizeof(msg), "%s: %s", L("Marker saved", "تم حفظ العلامة"), s_markerName);
        FeatureAction(msg);
        s_markerName[0] = 0;
    }
    if (s_markers.empty()) ImGui::TextDisabled("%s", L("No markers saved", "لا علامات محفوظة"));
    for (int i = 0; i < (int)s_markers.size(); ++i) {
        ImGui::PushID(i);
        MarkerRow &m = s_markers[i];
        char line[160];
        snprintf(line, sizeof(line), "%s (%.1f, %.1f, %.1f)", m.name.c_str(), m.x, m.y, m.z);
        ImGui::BulletText("%s", line);
        ImGui::SameLine(280);
        if (ImGui::SmallButton(L("Teleport", "تنقل"))) {
            if (Nrth_TeleportLocalPlayer(m.x, m.y, m.z)) {
                char msg[192];
                snprintf(msg, sizeof(msg), "%s: %s", L("Teleported to", "تم التنقل إلى"), m.name.c_str());
                FeatureAction(msg);
            } else {
                FeatureAction(L("Teleport", "تنقل"));
            }
        }
        ImGui::SameLine();
        if (ImGui::SmallButton(L("Delete", "حذف"))) {
            s_markers.erase(s_markers.begin() + i);
            ImGui::PopID();
            break;
        }
        ImGui::PopID();
    }
}

static void DrawVehicleTab()
{
    ImGui::Columns(2, "##vehcols", false);
    ImGui::SetColumnWidth(0, 300);
    ImGui::Text("%s", L("Vehicle's", "المركبات"));
    ImGui::Separator();
    for (int i = 0; i < (int)(sizeof(s_vehicleFeatures) / sizeof(Feature)); ++i) {
        char id[32];
        snprintf(id, sizeof(id), "vf%d", i);
        FeatureRow(s_vehicleFeatures[i], id);
    }
    ImGui::NextColumn();

    ImGui::Text("%s", L("Vehicles List", "قائمة المركبات"));
    ImGui::SetNextItemWidth(-1);
    std::string prev = std::string(kVehicleNames[s_vehicleSel]) + " (HP: 1000)";
    if (ImGui::BeginCombo("##vehicles_combo", s_vehicleSel >= 0 ? prev.c_str() : L("Select vehicle...", "اختر مركبة..."))) {
        for (int i = 0; i < (int)(sizeof(kVehicleNames) / sizeof(kVehicleNames[0])); ++i) {
            if (ImGui::Selectable(kVehicleNames[i], s_vehicleSel == i)) s_vehicleSel = i;
        }
        ImGui::EndCombo();
    }
    if (ImGui::Button(L("Teleport to Vehicle", "تنقل إلى المركبة"))) FeatureAction(L("Teleport to Vehicle", "تنقل إلى المركبة"));
    ImGui::SameLine();
    if (ImGui::Button(L("Teleport Vehicle", "إحضار المركبة"))) FeatureAction(L("Vehicle teleported to you", "تم إحضار المركبة إليك"));
    ImGui::SameLine();
    if (ImGui::Button(L("Bomb Car", "تفجير السيارة"))) {
        if (Nrth_DestroyCurrentVehicle()) FeatureAction(L("Vehicle destroyed", "تم تفجير المركبة"));
        else FeatureAction(L("You must be in a vehicle", "يجب أن تكون داخل مركبة"));
    }
    if (ImGui::Button(L("Repair Car", "إصلاح السيارة"))) {
        if (Nrth_RepairCurrentVehicle_1002f070()) FeatureAction(L("Vehicle repaired", "تم إصلاح المركبة"));
        else FeatureAction(L("You must be in a vehicle", "يجب أن تكون داخل مركبة"));
    }
    ImGui::SameLine();
    if (ImGui::Button(L("Start Engine", "تشغيل المحرك"))) {
        if (Nrth_StartCurrentVehicleEngine_1002f0f0()) FeatureAction(L("Engine started", "تم تشغيل المحرك"));
        else FeatureAction(L("You must be in a vehicle", "يجب أن تكون داخل مركبة"));
    }
    ImGui::SameLine();
    if (ImGui::Button(L("Stop", "إيقاف"))) {
        if (Nrth_StopCurrentVehicle()) FeatureAction(L("Vehicle stopped", "تم إيقاف المركبة"));
        else FeatureAction(L("You must be in a vehicle", "يجب أن تكون داخل مركبة"));
    }
    ImGui::SameLine();
    if (ImGui::Button(L("Unlock Car", "فتح السيارة"))) {
        if (Nrth_UnlockNearestVehicle_1002eea0()) FeatureAction(L("Unlocked nearest vehicle", "تم فتح أقرب مركبة"));
        else FeatureAction(L("No vehicle found nearby", "لا توجد مركبة قريبة"));
    }
    ImGui::Columns(1);
}

static void DrawColorSettings()
{
    if (ImGui::TreeNode(L("Color Settings", "إعدادات الألوان"))) {
        static char filter[64] = "";
        ImGui::InputTextWithHint("##filter", L("Search color...", "بحث عن لون..."), filter, sizeof(filter));
        static const struct { const char *name; const char *ar; ImGuiCol col; } kColors[] = {
            {"Text", "النص", ImGuiCol_Text},
            {"Text Disabled", "نص معطل", ImGuiCol_TextDisabled},
            {"Window BG", "خلفية النافذة", ImGuiCol_WindowBg},
            {"Child BG", "خلفية اللوحة", ImGuiCol_ChildBg},
            {"Popup BG", "خلفية النافذة المنبثقة", ImGuiCol_PopupBg},
            {"Border", "الحدود", ImGuiCol_Border},
            {"Frame BG", "خلفية الإطار", ImGuiCol_FrameBg},
            {"Frame BG Hovered", "خلفية الإطار (تمرير)", ImGuiCol_FrameBgHovered},
            {"Frame BG Active", "خلفية الإطار (نشط)", ImGuiCol_FrameBgActive},
            {"Title BG", "خلفية العنوان", ImGuiCol_TitleBg},
            {"Title BG Active", "خلفية العنوان (نشط)", ImGuiCol_TitleBgActive},
            {"Scrollbar Grab", "مقبض التمرير", ImGuiCol_ScrollbarGrab},
            {"Check Mark", "علامة الصح", ImGuiCol_CheckMark},
            {"Slider Grab", "مقبض السلايدر", ImGuiCol_SliderGrab},
            {"Button", "الزر", ImGuiCol_Button},
            {"Button Hovered", "الزر (تمرير)", ImGuiCol_ButtonHovered},
            {"Button Active", "الزر (نشط)", ImGuiCol_ButtonActive},
            {"Header", "العنوان", ImGuiCol_Header},
            {"Header Hovered", "العنوان (تمرير)", ImGuiCol_HeaderHovered},
            {"Header Active", "العنوان (نشط)", ImGuiCol_HeaderActive},
            {"Tab", "التاب", ImGuiCol_Tab},
            {"Tab Hovered", "التاب (تمرير)", ImGuiCol_TabHovered},
            {"Tab Active", "التاب (نشط)", ImGuiCol_TabActive},
            {"Text Selected BG", "خلفية النص المحدد", ImGuiCol_TextSelectedBg},
        };
        if (ImGui::BeginTable("##ColorTable", 2, ImGuiTableFlags_Borders)) {
            ImGui::TableSetupColumn(L("Name", "الاسم"));
            ImGui::TableSetupColumn(L("Color", "اللون"));
            ImGui::TableHeadersRow();
            for (auto &k : kColors) {
                if (filter[0] && !strstr(k.name, filter)) continue;
                ImGui::TableNextRow();
                ImGui::TableNextColumn(); ImGui::TextUnformatted(L(k.name, k.ar));
                ImGui::TableNextColumn();
                ImVec4 c = ImGui::GetStyle().Colors[k.col];
                if (ImGui::ColorEdit4("##col", (float *)&c, ImGuiColorEditFlags_NoInputs))
                    ImGui::GetStyle().Colors[k.col] = c;
            }
            ImGui::EndTable();
        }
        if (ImGui::Button(L("Reset Colors", "استعادة الألوان"))) {
            ImGui::StyleColorsDark();
            NrthUI_ApplyTheme();
            FeatureAction(L("Colors reset", "تمت استعادة الألوان"));
        }
        ImGui::TreePop();
    }
}

static void DrawConfigTab()
{
    if (!s_configsScanned) ScanConfigs();
    ImGui::Columns(2, "##cfgcols", false);
    ImGui::SetColumnWidth(0, 260);
    ImGui::Text("%s", L("Configs", "الإعدادات"));
    ImGui::BeginChild("##cfgitem", ImVec2(-1, -1), true);
    if (s_configs.empty()) ImGui::TextDisabled("%s", L("No configs found", "لا إعدادات"));
    for (int i = 0; i < (int)s_configs.size(); ++i) {
        if (ImGui::Selectable(s_configs[i].name.c_str(), s_cfgSel == i)) s_cfgSel = i;
    }
    ImGui::EndChild();
    ImGui::NextColumn();

    ImGui::BeginChild("##cfg_right", ImVec2(0, -1), true);
    ImGui::InputText(L("Name", "الاسم##sa"), s_cfgName, sizeof(s_cfgName));
    if (ImGui::Button(L("Save", "حفظ"))) {
        std::string f = std::string(s_cfgName) + ".ovr";
        /* Writes both <name>.ovr ("OVRCFG") and C:\Overwack\loader_config.cfg */
        NrthConfig_SaveOvr(f.c_str(), NULL);
        char msg[192];
        snprintf(msg, sizeof(msg), "%s: %s", L("Config saved", "تم حفظ الإعداد"), f.c_str());
        FeatureAction(msg);
        s_configsScanned = false;
    }
    ImGui::SameLine();
    if (ImGui::Button(L("Save As...", "حفظ باسم..."))) {
        s_cfgName[0] = 0;
    }
    ImGui::SameLine();
    if (ImGui::Button(L("Load", "تحميل")) && s_cfgSel >= 0) {
        NrthConfig_Load(s_configs[s_cfgSel].name.c_str());
        NrthConfig_Save(NULL);
        char msg[192];
        snprintf(msg, sizeof(msg), "%s: %s", L("Config loaded", "تم تحميل الإعداد"),
                 s_configs[s_cfgSel].name.c_str());
        FeatureAction(msg);
    }
    ImGui::SameLine();
    if (ImGui::Button(L("Delete", "حذف")) && s_cfgSel >= 0) {
        DeleteFileA(s_configs[s_cfgSel].name.c_str());
        char msg[192];
        snprintf(msg, sizeof(msg), "%s: %s", L("Config deleted", "تم حذف الإعداد"),
                 s_configs[s_cfgSel].name.c_str());
        FeatureAction(msg);
        s_configsScanned = false;
    }
    ImGui::SameLine();
    if (ImGui::Button(L("Reset to Default", "استعادة الافتراضي"))) {
        g_cfg.menuKey   = NRTH_VK_INSERT;
        g_cfg.noSpoofer = 0;
        NrthConfig_Save(NULL);
        FeatureAction(L("Reset to default style", "تمت الاستعادة للوضع الافتراضي"));
    }
    ImGui::Separator();
    ImGui::Checkbox(L("Watermark", "العلامة المائية"), &g_cfg.watermark);
    ImGui::SameLine();
    ImGui::Checkbox(L("Notifications", "الإشعارات"), &g_cfg.notifications);
    ImGui::SameLine();
    ImGui::Checkbox(L("Show Keybind's", "إظهار المفاتيح"), &s_showKeybindWindow);
    ImGui::Separator();

    ImGui::Text("%s", L("Menu Toggle Key", "زر فتح القائمة"));
    ImGui::SameLine();
    if (s_waitingForKey) {
        ImGui::Button(L("Press...", "اضغط..."));
        for (int k = 1; k < 256; ++k) {
            if (k == VK_LBUTTON || k == VK_RBUTTON) continue;
            if (GetAsyncKeyState(k) & 1) {
                g_cfg.menuKey = k;
                NrthConfig_Save(NULL);
                s_waitingForKey = false;
                break;
            }
        }
    } else if (ImGui::Button(L("Set", "تعيين"))) {
        s_waitingForKey = true;
    }
    ImGui::SameLine();
    ImGui::TextDisabled("(current: %d / Insert=45)", g_cfg.menuKey);

    ImGui::Separator();
    ImGui::Text("%s", L("Keybind's", "المفاتيح المخصصة"));
    bool anyBind = false;
    for (int i = 0; i < (int)(sizeof(s_cheatFeatures) / sizeof(Feature)); ++i) {
        if (s_cheatFeatures[i].key > 0) {
            anyBind = true;
            ImGui::PushID(1000 + i);
            ImGui::Text("%s -> %d (%s)", FeatureTr(s_cheatFeatures[i].label), s_cheatFeatures[i].key,
                        s_cheatFeatures[i].mode ? L("Toggle", "تبديل") : L("Hold", "ضغط مستمر"));
            ImGui::SameLine();
            if (ImGui::SmallButton("X")) {
                s_cheatFeatures[i].key = 0;
                FeatureAction(L("Bind cleared", "تم مسح الزر"));
            }
            ImGui::PopID();
        }
    }
    for (int i = 0; i < (int)(sizeof(s_vehicleFeatures) / sizeof(Feature)); ++i) {
        if (s_vehicleFeatures[i].key > 0) {
            anyBind = true;
            ImGui::PushID(2000 + i);
            ImGui::Text("%s -> %d (%s)", FeatureTr(s_vehicleFeatures[i].label), s_vehicleFeatures[i].key,
                        s_vehicleFeatures[i].mode ? L("Toggle", "تبديل") : L("Hold", "ضغط مستمر"));
            ImGui::SameLine();
            if (ImGui::SmallButton("X")) {
                s_vehicleFeatures[i].key = 0;
                FeatureAction(L("Bind cleared", "تم مسح الزر"));
            }
            ImGui::PopID();
        }
    }
    if (!anyBind && s_binds.empty()) ImGui::TextDisabled("%s", L("No binds", "لا مفاتيح"));
    for (int i = 0; i < (int)s_binds.size(); ++i) {
        ImGui::Text("Bind: %s -> key %d", s_binds[i].action.c_str(), s_binds[i].key);
        ImGui::SameLine();
        if (ImGui::SmallButton("X")) {
            FeatureAction(L("Bind cleared", "تم مسح الزر"));
            s_binds.erase(s_binds.begin() + i);
            break;
        }
    }
    DrawColorSettings();
    ImGui::EndChild();
    ImGui::Columns(1);
}

/* Matches PollHotkeys at VA 0x10012250 in NRTH.dll */
static void PollHotkeys_10012250(void)
{
    if (s_capturingFeature || s_waitingForKey) {
        return;
    }
    auto pollFeatureArray = [](Feature *arr, int count) {
        for (int i = 0; i < count; ++i) {
            Feature &f = arr[i];
            if (f.key <= 0) continue;
            if (f.mode == 1) { /* Toggle */
                if (GetAsyncKeyState(f.key) & 1) {
                    f.on = !f.on;
                    NrthUI_SyncFeaturesToState();
                    TriggerFeatureImmediateAction(f);
                }
            } else { /* Hold */
                bool down = (GetAsyncKeyState(f.key) & 0x8000) != 0;
                if (f.on != down) {
                    f.on = down;
                    NrthUI_SyncFeaturesToState();
                }
            }
        }
    };
    pollFeatureArray(s_cheatFeatures, (int)(sizeof(s_cheatFeatures) / sizeof(Feature)));
    pollFeatureArray(s_vehicleFeatures, (int)(sizeof(s_vehicleFeatures) / sizeof(Feature)));
}

/* Watermark — DARKANARCHY | FPS | Server (matches VA 0x10012bc0) */
static void DrawWatermark_10012bc0(void)
{
    if (!g_cfg.watermark) {
        return;
    }
    ImGuiIO &io = ImGui::GetIO();
    float fps = io.Framerate > 0.0f ? io.Framerate : 60.0f;

    const char *statusAr = g_bArabic ? TrGet("", (s_status.find("connected") != std::string::npos)
                                                 ? "متصل بالسيرفر" : "غير متصل") : NULL;
    char wmBuf[320];
    if (g_bArabic) {
        snprintf(wmBuf, sizeof(wmBuf), "DARKANARCHY | FPS: %.0f | %s: %s", fps,
                 TrGet("", "السيرفر"), statusAr);
    } else {
        snprintf(wmBuf, sizeof(wmBuf), "DARKANARCHY | FPS: %.0f | Server: %s", fps, s_status.c_str());
    }

    ImVec2 textSz = ImGui::CalcTextSize(wmBuf);
    float winW = textSz.x + 34.0f;
    float posX = (io.DisplaySize.x > winW + 16.0f) ? (io.DisplaySize.x - winW - 14.0f) : 10.0f;
    ImGui::SetNextWindowPos(ImVec2(posX, 12.0f), ImGuiCond_Always);
    ImGui::SetNextWindowBgAlpha(0.80f);
    if (ImGui::Begin("##Watermark", nullptr,
                     ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_AlwaysAutoResize |
                     ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoFocusOnAppearing |
                     ImGuiWindowFlags_NoNav | ImGuiWindowFlags_NoMove)) {
        ImDrawList *dl = ImGui::GetWindowDrawList();
        ImVec2 p = ImGui::GetCursorScreenPos();
        float cy = p.y + ImGui::GetTextLineHeight() * 0.5f;
        DrawAnarchyLogo(dl, ImVec2(p.x + 10.0f, cy), 8.0f, 1.6f);
        ImGui::SetCursorPosX(p.x + 24.0f);
        ImGui::TextColored(kBloodHi, "DARKANARCHY");
        ImGui::SameLine();
        if (g_bArabic) {
            ImGui::TextUnformatted(strstr(wmBuf, "| ") ? strstr(wmBuf, "| ") : wmBuf);
        } else {
            ImGui::Text("|  FPS: %.0f  |  Server: %s", fps, s_status.c_str());
        }
    }
    ImGui::End();
}

/* Floating keybind list (matches VA 0x100130a0) */
static void DrawKeybindList_100130a0(void)
{
    if (!s_showKeybindWindow) {
        return;
    }
    ImGui::SetNextWindowPos(ImVec2(14.0f, 60.0f), ImGuiCond_FirstUseEver);
    ImGui::SetNextWindowSize(ImVec2(250.0f, 0.0f), ImGuiCond_Always);
    ImGui::SetNextWindowBgAlpha(0.85f);
    if (ImGui::Begin(L("Keybind's", "المفاتيح المخصصة##floating"), &s_showKeybindWindow,
                     ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_AlwaysAutoResize |
                     ImGuiWindowFlags_NoSavedSettings)) {
        bool any = false;
        auto listFeatureArray = [&](Feature *arr, int count) {
            for (int i = 0; i < count; ++i) {
                if (arr[i].key > 0) {
                    any = true;
                    ImGui::Text("%s [%s]", FeatureTr(arr[i].label),
                                arr[i].mode ? L("Toggle", "تبديل") : L("Hold", "ضغط مستمر"));
                    ImGui::SameLine(190.0f);
                    if (arr[i].on) {
                        ImGui::TextColored(kBloodHi, "ON");
                    } else {
                        ImGui::TextDisabled("OFF");
                    }
                }
            }
        };
        listFeatureArray(s_cheatFeatures, (int)(sizeof(s_cheatFeatures) / sizeof(Feature)));
        listFeatureArray(s_vehicleFeatures, (int)(sizeof(s_vehicleFeatures) / sizeof(Feature)));
        if (!any) {
            ImGui::TextDisabled("%s", L("No active binds", "لا مفاتيح مفعلة"));
        }
    }
    ImGui::End();
}

/* Toast notifications (matches VA 0x10016990) */
static void DrawNotifications_10016990(void)
{
    if (!g_cfg.notifications || s_notifications.empty()) {
        return;
    }
    ULONGLONG now = GetTickCount64();
    const ULONGLONG kDurationMs = 3500ULL;
    for (int i = (int)s_notifications.size() - 1; i >= 0; --i) {
        if (now - s_notifications[i].createdTick > kDurationMs) {
            s_notifications.erase(s_notifications.begin() + i);
        }
    }
    ImGuiIO &io = ImGui::GetIO();
    float baseY = (io.DisplaySize.y > 100.0f ? io.DisplaySize.y : 720.0f) - 76.0f;
    float baseX = (io.DisplaySize.x > 300.0f ? io.DisplaySize.x : 1280.0f) - 290.0f;
    for (int i = 0; i < (int)s_notifications.size(); ++i) {
        char winId[32];
        snprintf(winId, sizeof(winId), "##toast_%d", i);
        ImGui::SetNextWindowPos(ImVec2(baseX, baseY - i * 62.0f), ImGuiCond_Always);
        ImGui::SetNextWindowSize(ImVec2(276.0f, 54.0f), ImGuiCond_Always);
        ImGui::SetNextWindowBgAlpha(0.90f);
        if (ImGui::Begin(winId, nullptr,
                         ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoSavedSettings |
                         ImGuiWindowFlags_NoFocusOnAppearing | ImGuiWindowFlags_NoNav |
                         ImGuiWindowFlags_NoMove)) {
            ImDrawList *dl = ImGui::GetWindowDrawList();
            ImVec2 p = ImGui::GetCursorScreenPos();
            DrawAnarchyLogo(dl, ImVec2(p.x + 12.0f, p.y + 16.0f), 9.0f, 1.6f);
            ImGui::SetCursorPosX(p.x + 28.0f);
            ImGui::TextColored(kBloodHi, "DARKANARCHY");
            /* clip text to the toast width so long Arabic messages wrap safely */
            ImGui::PushTextWrapPos(p.x + 262.0f);
            ImGui::TextUnformatted(s_notifications[i].text.c_str());
            ImGui::PopTextWrapPos();
        }
        ImGui::End();
    }
}

void NrthUI_Build()
{
    ImGui::SetNextWindowSize(ImVec2(880, 570), ImGuiCond_FirstUseEver);
    if (!s_menuOpen) return;
    if (!ImGui::Begin("DARKANARCHY", &s_menuOpen, ImGuiWindowFlags_NoCollapse)) {
        ImGui::End();
        return;
    }

    /* ---------------- Header: logo + brand + byline + language toggle --- */
    ImDrawList *dl = ImGui::GetWindowDrawList();
    ImVec2 hp = ImGui::GetCursorScreenPos();
    float logoR = 22.0f;
    float headerH = logoR * 2.0f + 8.0f;
    ImVec2 headerMin = hp;
    ImVec2 headerMax = ImVec2(hp.x + ImGui::GetContentRegionAvail().x, hp.y + headerH);
    dl->AddRectFilled(headerMin, headerMax, IM_COL32(16, 14, 14, 200), 8.0f);
    dl->AddRect(headerMin, headerMax, IM_COL32(90, 20, 20, 160), 8.0f);

    DrawAnarchyLogo(dl, ImVec2(hp.x + 14.0f + logoR, hp.y + headerH * 0.5f), logoR, 2.4f);

    ImGui::SetCursorScreenPos(ImVec2(hp.x + 14.0f + logoR * 2.0f + 14.0f, hp.y + 8.0f));
    ImGui::PushStyleColor(ImGuiCol_Text, kBloodHi);
    ImGui::Text("D A R K A N A R C H Y");
    ImGui::PopStyleColor();
    ImGui::SetCursorScreenPos(ImVec2(hp.x + 14.0f + logoR * 2.0f + 14.0f, hp.y + 34.0f));
    ImGui::TextDisabled("by XRAOUF");

    /* Language toggle (right side of header) */
    float toggleW = 110.0f;
    ImGui::SetCursorScreenPos(ImVec2(headerMax.x - toggleW - 12.0f, hp.y + (headerH - 26.0f) * 0.5f));
    ImGui::PushStyleColor(ImGuiCol_Button, kBloodDim);
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, kBlood);
    ImGui::PushStyleColor(ImGuiCol_ButtonActive, kBloodHi);
    if (ImGui::Button(g_bArabic ? "English" : "العربية", ImVec2(toggleW, 26.0f))) {
        NrthUI_SetLanguageArabic(!g_bArabic);
    }
    ImGui::PopStyleColor(3);

    ImGui::SetCursorScreenPos(ImVec2(hp.x, hp.y + headerH + 8.0f));
    StatusLine();
    ImGui::Separator();
    /* ---------------- End header ---------------------------------------- */

    static const char *kTopEn[] = {"Scripts", "Dumper", "Cheat", "Vehicle", "Config"};
    static const char *kTopAr[] = {"سكربتات", "ملفات", "غش", "مركبات", "إعدادات"};
    float w = (ImGui::GetContentRegionAvail().x - 4 * 8.f) / 5.f;
    for (int i = 0; i < 5; ++i) {
        char hid[32];
        snprintf(hid, sizeof(hid), "nvx_top_%d", i); /* stable IDs across languages */
        if (TabButton(L(kTopEn[i], kTopAr[i]), hid, s_topTab == i, ImVec2(w, 36))) s_topTab = i;
        if (i < 4) ImGui::SameLine();
    }
    ImGui::Spacing();

    if (s_topTab == 0) {
        static const char *kSubEn[] = {"Editor", "Scripts", "Resources", "Events", "Events Table", "Packets"};
        static const char *kSubAr[] = {"المحرر", "سكربتات", "المودات", "الأحداث", "جدول الأحداث", "الباكيتات"};
        float sw = (ImGui::GetContentRegionAvail().x - 5 * 6.f) / 6.f;
        for (int i = 0; i < 6; ++i) {
            char hid[32];
            snprintf(hid, sizeof(hid), "nvx_ssub_%d", i);
            if (TabButton(L(kSubEn[i], kSubAr[i]), hid, s_scriptsSub == i, ImVec2(sw, 28))) s_scriptsSub = i;
            if (i < 5) ImGui::SameLine();
        }
        ImGui::BeginChild("##nvx_content", ImVec2(0, 0), true);
        switch (s_scriptsSub) {
            case 0: DrawEditor();       break;
            case 1: DrawScriptsList();  break;
            case 2: DrawResources();    break;
            case 3: DrawEvents();       break;
            case 4: DrawEventsTable();  break;
            case 5: DrawPackets();      break;
        }
        ImGui::EndChild();
    } else if (s_topTab == 1) {
        ImGui::BeginChild("##nvx_content", ImVec2(0, 0), true);
        DrawDumper();
        ImGui::EndChild();
    } else if (s_topTab == 2) {
        static const char *kCSubEn[] = {"Player", "Other", "Markers"};
        static const char *kCSubAr[] = {"اللاعب", "أخرى", "العلامات"};
        float sw = (ImGui::GetContentRegionAvail().x - 2 * 6.f) / 3.f;
        for (int i = 0; i < 3; ++i) {
            char hid[32];
            snprintf(hid, sizeof(hid), "nvx_csub_%d", i);
            if (TabButton(L(kCSubEn[i], kCSubAr[i]), hid, s_cheatSub == i, ImVec2(sw, 28))) s_cheatSub = i;
            if (i < 2) ImGui::SameLine();
        }
        ImGui::BeginChild("##nvx_content", ImVec2(0, 0), true);
        switch (s_cheatSub) {
            case 0: DrawPlayerTab();  break;
            case 1: DrawOtherTab();   break;
            case 2: DrawMarkersTab(); break;
        }
        ImGui::EndChild();
    } else if (s_topTab == 3) {
        ImGui::BeginChild("##nvx_content", ImVec2(0, 0), true);
        DrawVehicleTab();
        ImGui::EndChild();
    } else {
        ImGui::BeginChild("##nvx_content", ImVec2(0, 0), true);
        DrawConfigTab();
        ImGui::EndChild();
    }

    ImGui::End();
}

extern "C" void NrthUI_RenderFrame(bool menuOpen)
{
    ImFont *font = (ImFont *)(g_bArabic ? g_pFontAr : g_pFontEn);
    if (font) ImGui::PushFont(font);

    PollHotkeys_10012250();
    DrawWatermark_10012bc0();
    DrawKeybindList_100130a0();
    if (menuOpen) {
        s_menuOpen = true;
        NrthUI_Build();
    }
    DrawNotifications_10016990();

    if (font) ImGui::PopFont();
}

#else /* Headless / non-Win32 build for verification tests */

extern "C" void NrthUI_ApplyTheme(void) {}
extern "C" void NrthUI_Build(void) {}
extern "C" void NrthUI_RenderFrame(bool menuOpen) { (void)menuOpen; }
extern "C" void NrthUI_PushToastNotification(const char *msg) { (void)msg; }

#endif
