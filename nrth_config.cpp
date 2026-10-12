/**
 * ============================================================================
 * nrth_config.cpp — Configuration loader/writer matching original NRTH.dll
 * ============================================================================
 * Evidence:
 *   - VA 0x1001fcff: decrypts "C:\Overwack\loader_config.cfg" (K=0x20)
 *   - VA 0x1001fdc5: decrypts " no_spoofer=%d" (K=0x20)
 *   - VA 0x1001fd7b: decrypts " menu_key=%d" (K=0x20, default 45 = VK_INSERT)
 *   - VA 0x100eb018: "OVRCFG" header in .ovr profile files
 * ============================================================================
 */
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "nrth_config.h"
#include "nrth_codec.h"

NrthConfig g_cfg = {
    NRTH_VK_INSERT, /* menuKey = 45 (VK_INSERT) */
    0,              /* noSpoofer = 0            */
    true,           /* watermark                */
    true,           /* notifications            */
    "C:\\Overwack\\loader_config.cfg"
};

static char s_pathBuf[sizeof(kCt_LoaderCfgPath)]  = {0};
static bool s_pathGate                            = false;
static char s_menuKeyFmtBuf[sizeof(kCt_MenuKeyFmt)] = {0};
static bool s_menuKeyFmtGate                        = false;
static char s_noSpoofFmtBuf[sizeof(kCt_NoSpooferFmt)] = {0};
static bool s_noSpoofFmtGate                          = false;

extern "C" const char *NrthConfig_GetPrimaryPath(void)
{
    return NrthDecryptOnce(kCt_LoaderCfgPath, sizeof(kCt_LoaderCfgPath), 0x20,
                           s_pathBuf, &s_pathGate);
}

extern "C" const char *NrthConfig_GetMenuKeyFmt(void)
{
    return NrthDecryptOnce(kCt_MenuKeyFmt, sizeof(kCt_MenuKeyFmt), 0x20,
                           s_menuKeyFmtBuf, &s_menuKeyFmtGate);
}

extern "C" const char *NrthConfig_GetNoSpooferFmt(void)
{
    return NrthDecryptOnce(kCt_NoSpooferFmt, sizeof(kCt_NoSpooferFmt), 0x20,
                           s_noSpoofFmtBuf, &s_noSpoofFmtGate);
}

extern "C" bool NrthConfig_ParseBuffer(const char *buf, NrthConfig *cfg)
{
    if (!buf || !cfg) {
        return false;
    }
    const char *fmtSpoof = NrthConfig_GetNoSpooferFmt(); /* " no_spoofer=%d" */
    const char *fmtKey   = NrthConfig_GetMenuKeyFmt();   /* " menu_key=%d"   */
    bool matchedAny = false;

    const char *pSpoof = strstr(buf, "no_spoofer=");
    if (pSpoof) {
        int val = 0;
        if (pSpoof > buf && *(pSpoof - 1) == ' ') {
            if (sscanf(pSpoof - 1, fmtSpoof, &val) == 1) {
                cfg->noSpoofer = val;
                matchedAny = true;
            }
        } else if (sscanf(pSpoof, fmtSpoof + 1, &val) == 1) {
            cfg->noSpoofer = val;
            matchedAny = true;
        }
    }

    const char *pKey = strstr(buf, "menu_key=");
    if (pKey) {
        int val = 0;
        if (pKey > buf && *(pKey - 1) == ' ') {
            if (sscanf(pKey - 1, fmtKey, &val) == 1 && val > 0) {
                cfg->menuKey = val;
                matchedAny = true;
            }
        } else if (sscanf(pKey, fmtKey + 1, &val) == 1 && val > 0) {
            cfg->menuKey = val;
            matchedAny = true;
        }
    }

    if (cfg->menuKey <= 0) {
        cfg->menuKey = NRTH_VK_INSERT;
    }
    return matchedAny;
}

extern "C" int NrthConfig_FormatBuffer(const NrthConfig *cfg, char *outBuf, uint32_t outCap)
{
    if (!cfg || !outBuf || outCap < 32) {
        return -1;
    }
    const char *fmtSpoof = NrthConfig_GetNoSpooferFmt(); /* " no_spoofer=%d" */
    const char *fmtKey   = NrthConfig_GetMenuKeyFmt();   /* " menu_key=%d"   */
    int keyVal = (cfg->menuKey > 0) ? cfg->menuKey : NRTH_VK_INSERT;

    char line1[64] = {0};
    char line2[64] = {0};
    snprintf(line1, sizeof(line1), fmtSpoof, cfg->noSpoofer);
    snprintf(line2, sizeof(line2), fmtKey, keyVal);
    return snprintf(outBuf, outCap, "%s\n%s\n", line1, line2);
}

extern "C" bool NrthConfig_Load(const char *overridePath)
{
    const char *primary = NrthConfig_GetPrimaryPath();
    const char *candidates[3] = {
        overridePath,
        primary,
        "loader_config.cfg"
    };

    for (int i = 0; i < 3; ++i) {
        const char *path = candidates[i];
        if (!path || !path[0]) {
            continue;
        }
        FILE *fp = fopen(path, "rb");
        if (!fp) {
            continue;
        }
        char buf[1024] = {0};
        size_t n = fread(buf, 1, sizeof(buf) - 1, fp);
        fclose(fp);
        buf[n] = '\0';
        strncpy(g_cfg.activePath, path, sizeof(g_cfg.activePath) - 1);
        g_cfg.activePath[sizeof(g_cfg.activePath) - 1] = '\0';
        NrthConfig_ParseBuffer(buf, &g_cfg);
        return true;
    }

    if (g_cfg.menuKey <= 0) {
        g_cfg.menuKey = NRTH_VK_INSERT;
    }
    return false;
}

extern "C" bool NrthConfig_Save(const char *overridePath)
{
    char content[256] = {0};
    if (NrthConfig_FormatBuffer(&g_cfg, content, sizeof(content)) < 0) {
        return false;
    }

    bool wroteAny = false;
    if (overridePath && overridePath[0]) {
        FILE *fp = fopen(overridePath, "wb");
        if (fp) {
            fwrite(content, 1, strlen(content), fp);
            fclose(fp);
            strncpy(g_cfg.activePath, overridePath, sizeof(g_cfg.activePath) - 1);
            g_cfg.activePath[sizeof(g_cfg.activePath) - 1] = '\0';
            return true;
        }
        return false;
    }

#ifdef _WIN32
    CreateDirectoryA("C:\\Overwack", NULL);
#endif
    const char *primary = NrthConfig_GetPrimaryPath();
    FILE *fpPrimary = fopen(primary, "wb");
    if (fpPrimary) {
        fwrite(content, 1, strlen(content), fpPrimary);
        fclose(fpPrimary);
        strncpy(g_cfg.activePath, primary, sizeof(g_cfg.activePath) - 1);
        g_cfg.activePath[sizeof(g_cfg.activePath) - 1] = '\0';
        wroteAny = true;
    }

    FILE *fpLocal = fopen("loader_config.cfg", "wb");
    if (fpLocal) {
        fwrite(content, 1, strlen(content), fpLocal);
        fclose(fpLocal);
        if (!wroteAny) {
            strncpy(g_cfg.activePath, "loader_config.cfg", sizeof(g_cfg.activePath) - 1);
            g_cfg.activePath[sizeof(g_cfg.activePath) - 1] = '\0';
        }
        wroteAny = true;
    }

    return wroteAny;
}

extern "C" bool NrthConfig_SaveOvr(const char *ovrPath, const char *overrideCfgPath)
{
    if (!ovrPath || !ovrPath[0]) {
        return false;
    }
    char cfgLines[256] = {0};
    NrthConfig_FormatBuffer(&g_cfg, cfgLines, sizeof(cfgLines));

    FILE *fp = fopen(ovrPath, "wb");
    if (!fp) {
        return false;
    }
    fputs("OVRCFG\n", fp);
    fputs(cfgLines, fp);
    fclose(fp);

    NrthConfig_Save(overrideCfgPath);
    return true;
}
