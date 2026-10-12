#pragma once
/**
 * ============================================================================
 * nrth_ui.h — DARKANARCHY (by XRAOUF) Overlay UI & MTA Packet / Feature Sync
 * ============================================================================
 * Bilingual UI (Arabic العربية + English) with embedded TrueType fonts:
 *   - English TTF : ChakraPetch-SemiBold.ttf
 *   - Arabic TTF  : IBMPlexSansArabic-SemiBold.ttf (with contextual shaper & BiDi)
 * ============================================================================
 */
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

typedef struct _NrthPacketDef {
    int         id;
    const char *name;
    bool        isReportChannel;
} NrthPacketDef;

#ifdef __cplusplus
extern "C" {
#endif

void NrthUI_ApplyTheme(void);
void NrthUI_Build(void);
void NrthUI_RenderFrame(bool menuOpen);

/* Bilingual & Arabic contextual shaping API */
void        NrthUI_SetLanguageArabic(bool isArabic);
bool        NrthUI_IsLanguageArabic(void);
const char *NrthUI_ShapeArabicText(const char *utf8In, char *outBuf, size_t outCap);
void        NrthUI_SetFonts(void *pEnglishFont, void *pArabicFont);

/* Arabic presentation-form shaper & simplified UAX#9 BiDi reorder
 * (exposed for verification tests; both are pure functions) */
size_t NrthShape_ArabicCodepoints(const uint32_t *in, size_t n, uint32_t *out, size_t outCap);
size_t NrthBidi_ReorderVisual(const uint32_t *in, size_t n, uint32_t *out, size_t outCap);

const NrthPacketDef *NrthUI_GetPacketCatalog(uint32_t *outCount);
void                 NrthUI_SyncFeaturesToState(void);
bool                 NrthUI_ExecuteLuaViaBridge(const char *code, size_t len, int vmMode);

/* ---- Live hook callbacks (0x100047b0, 0x100050a0, 0x100052b0, 0x1001da80) */
void     NrthUI_OnClientScriptLoaded(const char *chunkName, const char *code, size_t len);
bool     NrthUI_ShouldBlockServerEvent(const char *eventName);
void     NrthUI_OnResourceStarted(const char *resName);
bool     NrthUI_OnPacketSent(unsigned char packetId);
uint32_t NrthUI_GetMarkerCount(void);
bool     NrthUI_GetMarkerAt(uint32_t idx, float *outX, float *outY, float *outZ);
void     NrthUI_PushToastNotification(const char *msg);

#ifdef __cplusplus
}
#endif
