#pragma once
/**
 * ============================================================================
 * nrth_config.h — Configuration loader/writer matching original NRTH.dll
 * ============================================================================
 * Evidence:
 *   - Config path decrypted at VA 0x1001fcff (K=0x20): "C:\Overwack\loader_config.cfg"
 *   - Format tokens:
 *       " no_spoofer=%d" (VA 0x1001fdc5, K=0x20)
 *       " menu_key=%d"   (VA 0x1001fd7b, K=0x20, default 45 = VK_INSERT)
 *   - UI Config -> Save writes ".ovr" ("OVRCFG" header) + loader_config.cfg
 * ============================================================================
 */
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef NRTH_VK_INSERT
#define NRTH_VK_INSERT 45
#endif

typedef struct _NrthConfig {
    int  menuKey;       /* default 45 (VK_INSERT), parsed from " menu_key=%d"   */
    int  noSpoofer;     /* default 0, parsed from " no_spoofer=%d"              */
    bool watermark;     /* UI Watermark toggle                                  */
    bool notifications; /* UI Notifications toggle                              */
    char activePath[260];
} NrthConfig;

extern NrthConfig g_cfg;

/* Decrypts and returns "C:\Overwack\loader_config.cfg" (VA 0x1001fcff, K=0x20) */
const char *NrthConfig_GetPrimaryPath(void);

/* Decrypts and returns " menu_key=%d" (VA 0x1001fd7b, K=0x20) */
const char *NrthConfig_GetMenuKeyFmt(void);

/* Decrypts and returns " no_spoofer=%d" (VA 0x1001fdc5, K=0x20) */
const char *NrthConfig_GetNoSpooferFmt(void);

/* Loads config from `overridePath` if non-NULL, otherwise tries
 * "C:\Overwack\loader_config.cfg" then local "loader_config.cfg". */
bool NrthConfig_Load(const char *overridePath);

/* Saves config to `overridePath` if non-NULL, otherwise writes to
 * "C:\Overwack\loader_config.cfg" (creating C:\Overwack on Windows)
 * and mirrors to local "loader_config.cfg". */
bool NrthConfig_Save(const char *overridePath);

/* Parses raw text buffer containing " no_spoofer=%d" and/or " menu_key=%d" into *cfg */
bool NrthConfig_ParseBuffer(const char *buf, NrthConfig *cfg);

/* Formats *cfg into `outBuf` using the decrypted format tokens */
int NrthConfig_FormatBuffer(const NrthConfig *cfg, char *outBuf, uint32_t outCap);

/* Writes a named .ovr profile ("OVRCFG\n...") and updates loader_config.cfg */
bool NrthConfig_SaveOvr(const char *ovrPath, const char *overrideCfgPath);

#ifdef __cplusplus
}
#endif
