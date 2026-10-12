/**
 * ============================================================================
 * nrth_audit.cpp — NORTH/NVX **defensive audit** module (result class R2)
 * ============================================================================
 * Implements detection logic derived from the real mechanism of NRTH.dll
 * (mta_blue_team_case/mechanism_overview_ar.md §3.1, §3.2, §4):
 *   * the sample's positional-XOR string codec, so a defender can decode the
 *     obfuscated records of a new variant without re-doing the disassembly;
 *   * a byte-pattern matcher with '?' wildcards, matching the semantics of the
 *     sample's own resolver (VA 0x10002960), used here to locate the *targets*;
 *   * a prologue-state classifier that recognises the footprint the sample leaves
 *     when it detours a function (E9 / FF 25) or kills a check (C3 / C2 imm16).
 *
 * It contains NO injection, NO hook installation, NO memory writes, NO module
 * pinning, NO string obfuscation of payload, NO game-VM execution and NO feature
 * logic. It reads bytes and reports. See nrth_audit.h for the scope rationale.
 *
 * All buffer handling is bounds-checked against untrusted input: a truncated,
 * malformed or hostile PE must return an error, never read out of bounds.
 * ============================================================================
 */
#include "nrth_audit.h"
#include "nrth_audit_sigs.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#define NVXA_MAX_PAT   512     /* max pattern tokens (sample's longest: 120)      */
#define NVXA_MAX_HITS  64      /* hits kept per pattern per section               */
#define NVXA_HEAD_WIDE 8       /* bytes a near-detour may overwrite (5..8)        */

/* -------------------------------------------------------------------------- */
/* little-endian helpers                                                       */
/* -------------------------------------------------------------------------- */
static uint32_t nvxa_rd32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint16_t nvxa_rd16(const uint8_t *p)
{
    return (uint16_t)((uint32_t)p[0] | ((uint32_t)p[1] << 8));
}

static int nvxa_is_print(unsigned char c)
{
    return c >= 0x20 && c < 0x7f;
}

extern "C" const char *NrthAuditVersion(void)
{
    return "nrth_audit " NRTH_AUDIT_VERSION " (defensive audit: read-only, no hook/patch/inject)";
}

extern "C" uint32_t NrthSigCount(void)
{
    return NRTH_SIG_COUNT;
}

extern "C" const NrthSignature *NrthSigAt(uint32_t i)
{
    if (i < 1 || i > NRTH_SIG_COUNT) {
        return NULL;
    }
    return &g_NrthSigTable[i - 1];
}

extern "C" const char *NrthPrologueStateName(uint32_t state)
{
    switch (state) {
    case NRTH_PRO_PRISTINE:      return "PRISTINE (pattern matches byte-for-byte)";
    case NRTH_PRO_DETOUR_JMP32:  return "DETOUR_JMP32 (E9 rel32 - near detour)";
    case NRTH_PRO_DETOUR_FARJMP: return "DETOUR_FARJMP (FF 25 [addr] - absolute detour)";
    case NRTH_PRO_DETOUR_PUSHRET: return "DETOUR_PUSHRET (68 imm32 + C3)";
    case NRTH_PRO_KILL_RET:      return "KILL_RET (C3 - function returns immediately)";
    case NRTH_PRO_KILL_RETN:     return "KILL_RETN (C2 imm16 - no-op with stack cleanup)";
    case NRTH_PRO_STUB_IMM:      return "STUB_IMM (C7 05 [g],imm32 - global forced to constant)";
    case NRTH_PRO_PAD:           return "PAD (90/CC run - body relocated)";
    case NRTH_PRO_JMP_INDIRECT:  return "JMP_INDIRECT (FF /4 or FF /6 - jump through reg/mem)";
    default:                     return "UNKNOWN (normal prologue, no patch signature)";
    }
}

/* -------------------------------------------------------------------------- */
/* codec:  out[p] = in[p] ^ ((p - key) & 0xFF)                                 */
/* Verified against the sample's decryptors 0x100078d0 (scalar, key 0x2D) and  */
/* 0x1000bc00 (SSE, key 0x20); the transform is symmetric so it also encodes.  */
/* -------------------------------------------------------------------------- */
extern "C" int32_t NrthXorTransform(const uint8_t *in, uint32_t len, uint32_t key,
                                   uint8_t *out, uint32_t outCap)
{
    if (!in || !out || len == 0 || len > outCap) {
        return NVXA_E_INVALID;
    }
    for (uint32_t p = 0; p < len; ++p) {
        out[p] = (uint8_t)(in[p] ^ (uint8_t)(p - key));
    }
    return (int32_t)len;
}

extern "C" int32_t NrthXorCrack(const uint8_t *in, uint32_t len, char *text,
                               uint32_t textCap, uint32_t *outKey)
{
    if (!in || len == 0 || !text || textCap < 2) {
        return NVXA_E_INVALID;
    }
    int32_t bestLen = 0;
    uint32_t bestKey = 0;
    uint8_t local[NVXA_MAX_PAT];
    uint32_t n = len > NVXA_MAX_PAT ? NVXA_MAX_PAT : len;

    for (uint32_t key = 0; key < 256; ++key) {
        for (uint32_t p = 0; p < n; ++p) {
            local[p] = (uint8_t)(in[p] ^ (uint8_t)(p - key));
        }
        uint32_t run = 0;
        while (run < n && nvxa_is_print(local[run])) {
            ++run;
        }
        if (run < 4) {
            continue;
        }
        int32_t score = (int32_t)run + ((key == 0x2Du || key == 0x20u) ? 2 : 0);
        if (score > bestLen) {
            bestLen = (int32_t)run;
            bestKey = key;
        }
    }
    if (bestLen <= 0) {
        text[0] = '\0';
        return 0;
    }
    uint32_t outLen = (uint32_t)bestLen;
    if (outLen > textCap - 1) {
        outLen = textCap - 1;
    }
    for (uint32_t p = 0; p < outLen; ++p) {
        text[p] = (char)(in[p] ^ (uint8_t)(p - bestKey));
    }
    text[outLen] = '\0';
    if (outKey) {
        *outKey = bestKey;
    }
    return (int32_t)outLen;
}

extern "C" int32_t NrthXorDecodeRecordAt(const NrthPeView *pe, uint32_t va, uint32_t len,
                                        char *text, uint32_t textCap, uint32_t *outKey)
{
    if (!pe || !text) {
        return NVXA_E_INVALID;
    }
    if (va < pe->imageBase) {
        return NVXA_E_INVALID;
    }
    const uint8_t *p = NrthPeRvaToPtr(pe, va - pe->imageBase, len);
    if (!p) {
        return NVXA_E_TRUNCATED;
    }
    return NrthXorCrack(p, len, text, textCap, outKey);
}

/* -------------------------------------------------------------------------- */
/* pattern engine — same surface syntax the sample uses ("55 8B ? A3 ...")     */
/* -------------------------------------------------------------------------- */
static int nvxa_hex(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

extern "C" int32_t NrthPatCompile(const char *text, uint8_t *bytes, uint8_t *mask,
                                 uint32_t cap, uint32_t *outLen)
{
    if (!text || !bytes || !mask || !outLen) {
        return NVXA_E_INVALID;
    }
    uint32_t n = 0;
    const char *p = text;
    while (*p) {
        while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') {
            ++p;
        }
        if (!*p) {
            break;
        }
        if (n >= cap) {
            return NVXA_E_INVALID;
        }
        if (p[0] == '?' || p[0] == '*' || p[0] == '.') {   /* wildcard token: "?", "??" */
            bytes[n] = 0;
            mask[n] = 0;
            ++n;
            while (*p && *p != ' ' && *p != '\t') {
                ++p;
            }
            continue;
        }
        int hi = nvxa_hex((unsigned char)p[0]);
        int lo = (p[1] && nvxa_hex((unsigned char)p[1]) >= 0) ? nvxa_hex((unsigned char)p[1]) : -1;
        if (hi < 0) {
            return NVXA_E_INVALID;
        }
        uint32_t v = (uint32_t)hi;
        const char *q = p + 1;
        if (lo >= 0) {
            v = v * 16 + (uint32_t)lo;
            q = p + 2;
        }
        if (v > 0xffu) {
            return NVXA_E_INVALID;
        }
        bytes[n] = (uint8_t)v;
        mask[n] = 0xff;
        ++n;
        while (*q && *q != ' ' && *q != '\t') {
            ++q;                                        /* trailing junk ignored */
        }
        p = q;
    }
    *outLen = n;
    return (int32_t)n;
}

/* Scan for a compiled pattern; hits[] receives byte offsets. */
/* Wildcard scan. Fills hits[] with at most maxHits byte offsets and returns how many it
 * wrote; *total (optional) receives the full number of matches, which can be larger —
 * callers must never index hits[] beyond the returned count. */
static int32_t nvxa_scan_compiled(const uint8_t *buf, uint32_t len, const uint8_t *bytes,
                                 const uint8_t *mask, uint32_t plen, uint32_t *hits,
                                 uint32_t maxHits, uint32_t *total)
{
    if (!buf || !bytes || plen == 0 || plen > len) {
        return 0;
    }
    /* anchor on the first concrete byte */
    uint32_t anchor = 0;
    while (anchor < plen && mask[anchor] == 0) {
        ++anchor;
    }
    if (anchor >= plen) {            /* all wildcards: refuse (would match everywhere) */
        return NVXA_E_INVALID;
    }
    uint8_t ab = bytes[anchor];
    int32_t count = 0;
    for (uint32_t i = anchor; i + (plen - anchor) <= len; ++i) {
        if (buf[i] != ab) {
            continue;
        }
        uint32_t start = i - anchor;
        int ok = 1;
        for (uint32_t j = 0; j < plen; ++j) {
            if (mask[j] && buf[start + j] != bytes[j]) {
                ok = 0;
                break;
            }
        }
        if (!ok) {
            continue;
        }
        if (hits && (uint32_t)count < maxHits) {
            hits[count] = start;
        }
        ++count;
        i += plen - 1 - anchor;      /* non-overlapping matches */
    }
    if (total) {
        *total = count;
    }
    return (count > (int32_t)maxHits) ? (int32_t)maxHits : count;
}

extern "C" int32_t NrthPatScan(const uint8_t *buf, uint32_t len, const char *pattern,
                              uint32_t *hits, uint32_t maxHits)
{
    uint8_t bytes[NVXA_MAX_PAT], mask[NVXA_MAX_PAT];
    uint32_t plen = 0;
    int32_t r = NrthPatCompile(pattern, bytes, mask, NVXA_MAX_PAT, &plen);
    if (r < 0) {
        return r;
    }
    return nvxa_scan_compiled(buf, len, bytes, mask, plen, hits, maxHits, NULL);
}

/* Shared token rewriter behind NrthPatWidenHead / NrthPatPatchHead. With `replace == NULL`
 * the first `head` tokens become '?'; otherwise they are dropped and `replace` (a concrete
 * footprint such as "E9 ? ? ? ?") is written in front. Returns the output token count. */
static int32_t nvxa_pat_rewrite(const char *pattern, uint32_t head, const char *replace,
                                char *out, uint32_t outCap)
{
    if (!pattern || !out || outCap < 2) {
        return NVXA_E_INVALID;
    }
    uint32_t tok = 0;
    const char *p = pattern;
    if (replace) {                                  /* skip the tokens the footprint replaces */
        while (tok < head) {
            while (*p == ' ') {
                ++p;
            }
            if (!*p) {
                break;
            }
            while (*p && *p != ' ') {
                ++p;
            }
            ++tok;
        }
    }
    uint32_t o = 0, n = 0;
    if (replace && *replace) {
        int wrote = snprintf(out, outCap, "%s", replace);
        if (wrote < 0 || (uint32_t)wrote >= outCap) {
            return NVXA_E_TRUNCATED;
        }
        o = (uint32_t)wrote;
        for (const char *q = replace; *q; ++q) {
            if (*q == ' ') {
                ++n;
            }
        }
        ++n;
    }
    while (*p) {
        while (*p == ' ') {
            ++p;
        }
        if (!*p) {
            break;
        }
        const char *s = p;
        while (*p && *p != ' ') {
            ++p;
        }
        int wrote;
        if (!replace && tok < head) {
            wrote = snprintf(out + o, outCap - o, "%s?", o ? " " : "");
        } else {
            wrote = snprintf(out + o, outCap - o, "%s%.*s", o ? " " : "", (int)(p - s), s);
        }
        if (wrote < 0 || o + (uint32_t)wrote >= outCap) {
            return NVXA_E_TRUNCATED;
        }
        o += (uint32_t)wrote;
        ++n;
        ++tok;
    }
    if (n == 0) {
        return NVXA_E_INVALID;
    }
    out[o] = '\0';
    return (int32_t)n;
}

extern "C" int32_t NrthPatPatchHead(const char *pattern, uint32_t head, const char *footprint,
                                    char *out, uint32_t outCap)
{
    if (!footprint) {
        return NVXA_E_INVALID;
    }
    return nvxa_pat_rewrite(pattern, head, footprint, out, outCap);
}

extern "C" int32_t NrthPatWidenHead(const char *pattern, uint32_t head, char *out,
                                   uint32_t outCap)
{
    return nvxa_pat_rewrite(pattern, head, NULL, out, outCap);
}

/* -------------------------------------------------------------------------- */
/* prologue classification: recognises the shapes produced by the sample's      */
/* detour installation (MinHook) and by its one-byte "check kill" writes.       */
/* -------------------------------------------------------------------------- */
extern "C" int32_t NrthClassifyPrologue(const uint8_t *func, uint32_t avail, uint32_t *outDetail)
{
    if (outDetail) {
        *outDetail = 0;
    }
    if (!func || avail == 0) {
        return NVXA_E_INVALID;
    }
    uint8_t b0 = func[0];
    if (b0 == 0xC3) {
        return NRTH_PRO_KILL_RET;
    }
    if (b0 == 0xC2 && avail >= 3) {
        if (outDetail) {
            *outDetail = nvxa_rd16(func + 1);
        }
        return NRTH_PRO_KILL_RETN;
    }
    if (b0 == 0xE9 && avail >= 5) {
        if (outDetail) {
            *outDetail = nvxa_rd32(func + 1);      /* rel32, add to (rva+5) to resolve */
        }
        return NRTH_PRO_DETOUR_JMP32;
    }
    if (b0 == 0xFF && avail >= 6 && (func[1] == 0x25 || func[1] == 0x15)) {
        if (outDetail) {
            *outDetail = nvxa_rd32(func + 2);
        }
        return func[1] == 0x25 ? NRTH_PRO_DETOUR_FARJMP : NRTH_PRO_JMP_INDIRECT;
    }
    if (b0 == 0xFF && avail >= 2 && (func[1] == 0xE0 || func[1] == 0xE1 || func[1] == 0xE2 ||
                                     func[1] == 0xE3 || func[1] == 0xE6 || func[1] == 0xE7)) {
        return NRTH_PRO_JMP_INDIRECT;
    }
    if (b0 == 0x68 && avail >= 6 && func[5] == 0xC3) {
        if (outDetail) {
            *outDetail = nvxa_rd32(func + 1);
        }
        return NRTH_PRO_DETOUR_PUSHRET;
    }
    if (b0 == 0xC7 && avail >= 7 && (func[1] == 0x05 || func[1] == 0x0D)) {
        if (outDetail) {
            *outDetail = nvxa_rd32(func + 6);
        }
        return NRTH_PRO_STUB_IMM;
    }
    if (b0 == 0x90 || b0 == 0xCC) {
        uint32_t run = 0;
        while (run < avail && (func[run] == 0x90 || func[run] == 0xCC)) {
            ++run;
        }
        if (run >= 4) {
            return NRTH_PRO_PAD;
        }
    }
    return (int32_t)NRTH_PRO_UNKNOWN;   /* ordinary prologue: nothing patched */
}

/* -------------------------------------------------------------------------- */
/* PE view                                                                      */
/* -------------------------------------------------------------------------- */
extern "C" int32_t NrthPeMap(const uint8_t *img, uint32_t size, NrthPeView *out)
{
    if (!img || !out || size < 0x40) {
        return NVXA_E_INVALID;
    }
    memset(out, 0, sizeof(*out));
    out->img = img;
    out->size = size;

    if (nvxa_rd16(img) != 0x5A4D) {                     /* 'MZ' */
        return NVXA_E_FORMAT;
    }
    uint32_t peOff = nvxa_rd32(img + 0x3C);
    if (peOff + 24 >= size || nvxa_rd32(img + peOff) != 0x00004550) {   /* 'PE\0\0' */
        return NVXA_E_FORMAT;
    }
    const uint8_t *coh = img + peOff;
    out->machine = nvxa_rd16(coh + 4);
    uint32_t nSec = nvxa_rd16(coh + 6);
    out->timestamp = nvxa_rd32(coh + 8);
    /* Offsets relative to the 'PE\0\0' signature: Machine@4 NumberOfSections@6
       TimeDateStamp@8 PointerToSymbolTable@12 NumberOfSymbols@16
       SizeOfOptionalHeader@20 Characteristics@22, optional header@24. */
    uint32_t optSize = nvxa_rd16(coh + 20);
    out->characteristics = nvxa_rd16(coh + 22);
    uint32_t opt = peOff + 4 + 20;              /* after 'PE\0\0' + 20-byte file header */
    if (opt + 16 > size || nSec == 0 || nSec > NRTH_PE_MAX_SECTIONS || opt + optSize > size) {
        return NVXA_E_FORMAT;
    }
    uint16_t magic = nvxa_rd16(img + opt);
    if (magic != 0x10b && magic != 0x20b) {
        return NVXA_E_FORMAT;
    }
    out->entryRva = nvxa_rd32(img + opt + 16);
    out->imageBase = (magic == 0x10b) ? nvxa_rd32(img + opt + 28) : nvxa_rd32(img + opt + 24);
    out->nSections = (uint16_t)nSec;

    const uint8_t *sh = img + opt + optSize;
    if ((uint32_t)(sh - img) + nSec * 40 > size) {
        return NVXA_E_FORMAT;
    }
    for (uint32_t i = 0; i < nSec; ++i) {
        const uint8_t *e = sh + i * 40;
        NrthPeSection *s = &out->sec[i];
        memcpy(s->name, e, 8);
        s->name[8] = '\0';
        s->vsize = nvxa_rd32(e + 8);
        s->rva = nvxa_rd32(e + 12);
        s->rsize = nvxa_rd32(e + 16);
        s->raw = nvxa_rd32(e + 20);
        s->characteristics = nvxa_rd32(e + 36);
    }
    /* File image vs. already-mapped dump. A file image has every section that carries
     * data on disk (`rsize > 0`) stored inside the buffer at a sane raw offset. A dump
     * keeps the virtual layout instead, so we index by RVA. Sections with rsize == 0
     * (uninitialised .data, .pdata, resource overlays, ...) say nothing either way. */
    out->mapped = 0;
    for (uint32_t i = 0; i < nSec; ++i) {
        const NrthPeSection *s = &out->sec[i];
        if (s->rsize == 0) {
            continue;
        }
        if (s->raw < 0x40 || s->raw > size || s->rsize > size - s->raw) {
            out->mapped = 1;
            break;
        }
    }
    return NVXA_OK;
}

extern "C" const uint8_t *NrthPeSectionData(const NrthPeView *pe, uint32_t idx, uint32_t *outLen,
                                           uint32_t *outRva)
{
    if (!pe || idx >= pe->nSections || !outLen) {
        return NULL;
    }
    const NrthPeSection *s = &pe->sec[idx];
    const uint8_t *p;
    uint32_t len;
    if (pe->mapped) {
        if (s->rva >= pe->size) {
            return NULL;
        }
        p = pe->img + s->rva;
        len = pe->size - s->rva;
        if (s->vsize && s->vsize < len) {
            len = s->vsize;
        }
    } else {
        if (s->raw >= pe->size) {
            return NULL;
        }
        p = pe->img + s->raw;
        len = pe->size - s->raw;
        if (s->rsize && s->rsize < len) {
            len = s->rsize;
        }
        if (s->vsize && s->vsize < len) {
            len = s->vsize;
        }
    }
    *outLen = len;
    if (outRva) {
        *outRva = s->rva;
    }
    return p;
}

extern "C" const uint8_t *NrthPeRvaToPtr(const NrthPeView *pe, uint32_t rva, uint32_t want)
{
    if (!pe) {
        return NULL;
    }
    for (uint32_t i = 0; i < pe->nSections; ++i) {
        const NrthPeSection *s = &pe->sec[i];
        if (rva < s->rva) {
            continue;
        }
        uint32_t off = rva - s->rva;
        uint32_t base = pe->mapped ? s->rva : s->raw;
        if (off > s->vsize && off > s->rsize) {
            continue;
        }
        if (base > pe->size || off > pe->size - base || want > pe->size - base - off) {
            return NULL;
        }
        return pe->img + base + off;
    }
    return NULL;
}

extern "C" uint32_t NrthPeTextRva(const NrthPeView *pe)
{
    if (!pe) {
        return 0;
    }
    for (uint32_t i = 0; i < pe->nSections; ++i) {
        if (strcmp(pe->sec[i].name, ".text") == 0) {
            return pe->sec[i].rva;
        }
    }
    return pe->nSections ? pe->sec[0].rva : 0;
}

/* -------------------------------------------------------------------------- */
/* whole-module audit                                                           */
/* -------------------------------------------------------------------------- */
/* True when the compiled pattern matches at exactly this offset — used to decide whether a
 * widened ("patched") hit is really the pristine pattern, without relying on the capped
 * hit array. */
static int nvxa_match_at(const uint8_t *buf, uint32_t len, uint32_t off, const uint8_t *bytes,
                         const uint8_t *mask, uint32_t plen)
{
    if (!buf || plen == 0 || off + plen > len) {
        return 0;
    }
    for (uint32_t j = 0; j < plen; ++j) {
        if (mask[j] && buf[off + j] != bytes[j]) {
            return 0;
        }
    }
    return 1;
}

extern "C" int32_t NrthPrologueIsTamper(uint32_t state)
{
    switch (state) {
    case NRTH_PRO_DETOUR_JMP32:
    case NRTH_PRO_DETOUR_FARJMP:
    case NRTH_PRO_DETOUR_PUSHRET:
    case NRTH_PRO_KILL_RET:
    case NRTH_PRO_KILL_RETN:
    case NRTH_PRO_STUB_IMM:
    case NRTH_PRO_JMP_INDIRECT:
        return 1;
    default:
        return 0;
    }
}

static void nvxa_note(NrthSigFinding *f, uint32_t secRva, uint32_t off, int full,
                      uint32_t state, uint32_t detail)
{
    uint32_t rva = secRva + off;
    if (full) {
        if (f->fullHits == 0) {
            f->firstFullRva = rva;
            f->state = NRTH_PRO_PRISTINE;
        }
        ++f->fullHits;
        return;
    }
    ++f->patchedHits;
    if (f->firstPatchedRva == 0) {
        f->firstPatchedRva = rva;
        f->state = state;
        f->detail = detail;
    }
}

/* The four shapes this audit looks for when the complete pattern does not match. Each one
 * is what the sample itself writes (or what MinHook writes on its behalf): the leading
 * tokens of the target function are replaced by the footprint, the rest of the function is
 * untouched. Requiring the concrete footprint bytes instead of a wildcarded head is what
 * keeps the on-disk check free of coincidences. */
#define NVXA_N_FOOTPRINT 4
static const struct {
    const char *footprint;   /* tokens written over the function entry            */
    uint32_t head;           /* how many pattern tokens they replace              */
    uint32_t state;          /* NrthPrologueState to report                       */
} kNvxaFootprint[NVXA_N_FOOTPRINT] = {
    { "C3",             1, NRTH_PRO_KILL_RET },       /* the sample's 1-byte check kill */
    { "E9 ? ? ? ?",      5, NRTH_PRO_DETOUR_JMP32 },   /* MinHook near jump            */
    { "FF 25 ? ? ? ?",   6, NRTH_PRO_DETOUR_FARJMP }, /* absolute jump through memory  */
    { "68 ? ? ? ? C3",   5, NRTH_PRO_DETOUR_PUSHRET } /* push addr / ret trampoline      */
};

extern "C" int32_t NrthAuditImage(const uint8_t *img, uint32_t size, NrthSigFinding *findings,
                                 uint32_t maxFindings)
{
    NrthPeView pe;
    int32_t r = NrthPeMap(img, size, &pe);
    if (r != NVXA_OK) {
        return r;
    }
    if (findings && maxFindings < NRTH_SIG_COUNT) {
        return NVXA_E_INVALID;
    }
    if (findings) {
        memset(findings, 0, sizeof(NrthSigFinding) * NRTH_SIG_COUNT);
    }

    int32_t withHits = 0;
    for (uint32_t si = 0; si < NRTH_SIG_COUNT; ++si) {
        const NrthSignature *sg = &g_NrthSigTable[si];
        uint8_t bExact[NVXA_MAX_PAT], mExact[NVXA_MAX_PAT];
        uint32_t nExact = 0;
        uint8_t bF[NVXA_N_FOOTPRINT][NVXA_MAX_PAT], mF[NVXA_N_FOOTPRINT][NVXA_MAX_PAT];
        uint32_t nF[NVXA_N_FOOTPRINT];
        int okF[NVXA_N_FOOTPRINT];

        if (NrthPatCompile(sg->pattern, bExact, mExact, NVXA_MAX_PAT, &nExact) < 0) {
            return NVXA_E_FORMAT;
        }
        for (uint32_t fi = 0; fi < NVXA_N_FOOTPRINT; ++fi) {
            char pat[3 * NVXA_MAX_PAT];
            nF[fi] = 0;
            okF[fi] = 0;
            if (NrthPatPatchHead(sg->pattern, kNvxaFootprint[fi].head,
                                kNvxaFootprint[fi].footprint, pat, sizeof(pat)) < 0) {
                continue;
            }
            if (NrthPatCompile(pat, bF[fi], mF[fi], NVXA_MAX_PAT, &nF[fi]) >= 0 && nF[fi] > 0) {
                okF[fi] = 1;
            }
        }

        uint32_t hitsFull[NVXA_MAX_HITS], hitsF[NVXA_MAX_HITS];
        uint32_t total = 0;
        int sawText = 0, sawOther = 0;
        for (uint32_t sec = 0; sec < pe.nSections; ++sec) {
            uint32_t slen = 0, srva = 0;
            const uint8_t *sd = NrthPeSectionData(&pe, sec, &slen, &srva);
            if (!sd || slen < nExact) {
                continue;
            }
            const char *nm = pe.sec[sec].name;
            int isText = (nm[0] == '.' && nm[1] == 't' && nm[2] == 'e');
            uint32_t tFull = 0;
            int32_t hFull = nvxa_scan_compiled(sd, slen, bExact, mExact, nExact, hitsFull,
                                              NVXA_MAX_HITS, &tFull);
            for (int32_t i = 0; findings && i < hFull; ++i) {
                nvxa_note(&findings[si], srva, hitsFull[i], 1, NRTH_PRO_PRISTINE, 0);
            }
            if (findings && tFull > (uint32_t)hFull) {
                findings[si].fullHits += tFull - (uint32_t)hFull;  /* hits beyond the buffer */
            }
            total += tFull;
            if (tFull) {
                if (isText) { sawText = 1; } else { sawOther = 1; }
            }
            for (uint32_t fi = 0; fi < NVXA_N_FOOTPRINT; ++fi) {
                if (!okF[fi]) {
                    continue;
                }
                uint32_t tF = 0;
                int32_t hF = nvxa_scan_compiled(sd, slen, bF[fi], mF[fi], nF[fi], hitsF,
                                                 NVXA_MAX_HITS, &tF);
                for (int32_t i = 0; i < hF; ++i) {
                    uint32_t off = hitsF[i];
                    if (nvxa_match_at(sd, slen, off, bExact, mExact, nExact)) {
                        continue;                    /* the function entry is intact */
                    }
                    uint32_t detail = 0;
                    /* keep where the detour points so an analyst can follow it */
                    if (fi == 1) {                                  /* E9 rel32 */
                        if (off + 5 <= slen) {
                            int32_t rel = (int32_t)nvxa_rd32(sd + off + 1);
                            detail = (uint32_t)((int32_t)(srva + off + 5) + rel);
                        }
                    } else if (fi == 2 || fi == 3) {                /* FF 25 abs32 / 68 abs32 */
                        uint32_t d = (fi == 2) ? 2u : 1u;
                        if (off + d + 4 <= slen) {
                            uint32_t abs = nvxa_rd32(sd + off + d);
                            detail = (abs >= (uint32_t)pe.imageBase)
                                         ? (abs - (uint32_t)pe.imageBase)
                                         : abs;
                        }
                    }
                    if (findings) {
                        nvxa_note(&findings[si], srva, off, 0, kNvxaFootprint[fi].state, detail);
                    }
                }
                if (tF > (uint32_t)hF) {
                    total += tF - (uint32_t)hF;      /* footprint hits beyond the buffer */
                }
                total += (uint32_t)hF;
                if (hF > 0) {
                    if (isText) { sawText = 1; } else { sawOther = 1; }
                }
            }
        }
        if (findings && total && sawText && !sawOther) {
            findings[si].textSectionOnly = 1;
        }
        if (findings && (findings[si].fullHits || findings[si].patchedHits)) {
            findings[si].sigId = sg->id;
            ++withHits;
        }
    }
    return withHits;
}

/* ---- file I/O (read-only) ------------------------------------------------- */
#define NVXA_MAX_IMAGE (64u * 1024u * 1024u)

static uint8_t *nvxa_read_file(const char *path, uint32_t *outSize)
{
    FILE *f = fopen(path, "rb");
    if (!f) {
        return NULL;
    }
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return NULL;
    }
    long sz = ftell(f);
    if (sz <= 0 || (unsigned long)sz > NVXA_MAX_IMAGE) {
        fclose(f);
        return NULL;
    }
    rewind(f);
    uint8_t *buf = (uint8_t *)malloc((size_t)sz);
    if (!buf) {
        fclose(f);
        return NULL;
    }
    size_t got = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    if (got != (size_t)sz) {
        free(buf);
        return NULL;
    }
    *outSize = (uint32_t)sz;
    return buf;
}

extern "C" int32_t NrthAuditImageFile(const char *path, NrthSigFinding *findings,
                                      uint32_t maxFindings)
{
    uint32_t size = 0;
    uint8_t *buf = nvxa_read_file(path, &size);
    if (!buf) {
        return NVXA_E_IO;
    }
    int32_t r = NrthAuditImage(buf, size, findings, maxFindings);
    free(buf);
    return r;
}

/* -------------------------------------------------------------------------- */
/* hidden-signature discovery (variant triage)                                  */
/* Anchored sweep: only positions whose positional-XOR decode *starts* with a     */
/* compiler function prologue are considered, which pins the key in one step and    */
/* keeps random-byte noise out. Mirrors tools/nrth_sig_export.py (data-sweep pass).  */
/* -------------------------------------------------------------------------- */
static const char *const kPrologues[] = { "55 8B EC ", "53 8B DC " };
#define NVXA_N_PROLOGUE ((int)(sizeof(kPrologues) / sizeof(kPrologues[0])))

static int nvxa_sig_like(const char *s, uint32_t n)
{
    if (n < 12) {
        return 0;
    }
    for (uint32_t i = 0; i < n; ++i) {
        char c = s[i];
        int hexok = (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F');
        if (!hexok && c != '?' && c != ' ') {
            return 0;
        }
    }
    /* require at least one space-separated token pair */
    return strchr(s, ' ') != NULL;
}

extern "C" int32_t NrthFindHiddenSignatures(const uint8_t *img, uint32_t size, uint32_t minLen,
                                           char *textOut, uint32_t textCap, uint32_t *outVas,
                                           uint32_t maxVas)
{
    NrthPeView pe;
    int32_t r = NrthPeMap(img, size, &pe);
    if (r != NVXA_OK) {
        return r;
    }
    if (minLen < 12) {
        minLen = 12;
    }
    uint32_t wpos = 0, found = 0;
    if (textOut && textCap) {
        textOut[0] = '\0';
    }

    for (uint32_t si = 0; si < pe.nSections; ++si) {
        const char *nm = pe.sec[si].name;
        if (!(nm[0] == '.' && (nm[1] == 'd' || nm[1] == 'r' || nm[1] == 't'))) {
            continue;                    /* .data / .rdata / .text only */
        }
        uint32_t slen = 0, srva = 0;
        const uint8_t *sd = NrthPeSectionData(&pe, si, &slen, &srva);
        if (!sd || slen < 16) {
            continue;
        }
        for (uint32_t off = 0; off + 12 <= slen; off += 4) {
            for (int pi = 0; pi < NVXA_N_PROLOGUE; ++pi) {
                const char *pref = kPrologues[pi];
                uint32_t plen = (uint32_t)strlen(pref);
                uint32_t key = (uint32_t)(0x100 - (sd[off] ^ (uint8_t)pref[0])) & 0xFFu;
                int match = 1;
                for (uint32_t i = 0; i < plen; ++i) {
                    if ((char)(sd[off + i] ^ (uint8_t)(i - key)) != pref[i]) {
                        match = 0;
                        break;
                    }
                }
                if (!match) {
                    continue;
                }
                char line[NVXA_MAX_PAT * 3];
                uint32_t n = 0;
                for (uint32_t i = 0; i + off < slen && n + 1 < sizeof(line); ++i) {
                    char c = (char)(sd[off + i] ^ (uint8_t)(i - key));
                    if (c == '\0' || !nvxa_is_print((unsigned char)c)) {
                        break;
                    }
                    line[n++] = c;
                }
                line[n] = '\0';
                if (n < minLen || !nvxa_sig_like(line, n)) {
                    continue;
                }
                if (found < maxVas && outVas) {
                    outVas[found] = srva + off;
                }
                ++found;
                if (textOut) {
                    uint32_t need = n + 12;
                    if (wpos + need < textCap) {
                        wpos += (uint32_t)snprintf(textOut + wpos, textCap - wpos, "rva 0x%06x "
                                                                                   "key 0x%02X %s\n",
                                                   srva + off, key, line);
                    }
                }
                break;                   /* one prefix per position */
            }
        }
    }
    return (int32_t)found;
}

extern "C" int32_t NrthAuditDiff(const uint8_t *cleanImg, uint32_t cleanSize,
                               const uint8_t *susImg, uint32_t susSize,
                               NrthAuditDiffRow *rows, uint32_t maxRows)
{
    if (rows && maxRows < NRTH_SIG_COUNT) {
        return NVXA_E_INVALID;
    }
    NrthSigFinding clean[NRTH_SIG_COUNT], sus[NRTH_SIG_COUNT];
    int32_t rc = NrthAuditImage(cleanImg, cleanSize, clean, NRTH_SIG_COUNT);
    if (rc < 0) {
        return rc;
    }
    rc = NrthAuditImage(susImg, susSize, sus, NRTH_SIG_COUNT);
    if (rc < 0) {
        return rc;
    }
    int32_t alerted = 0;
    /* one memset per call: rows is caller memory, so zero it before filling */
    for (uint32_t i = 0; i < NRTH_SIG_COUNT; ++i) {
        NrthAuditDiffRow *d = rows ? &rows[i] : NULL;
        const int found = (clean[i].fullHits + clean[i].patchedHits) > 0;
        const int patched = sus[i].patchedHits > 0;
        if (!d) {
            continue;
        }
        d->sigId = sus[i].sigId ? sus[i].sigId : clean[i].sigId;
        d->cleanFull = clean[i].fullHits;
        d->cleanPatched = clean[i].patchedHits;
        d->susFull = sus[i].fullHits;
        d->susPatched = sus[i].patchedHits;
        d->susState = sus[i].state;
        d->susRva = sus[i].firstPatchedRva;
        d->susDetail = sus[i].detail;
        /* Alignment: within one build a signature locates one function, so the RVA is the key
         * that says "this row in the suspect image is the same function as this row in the
         * baseline". Without that requirement, any jump thunk that happens to match a pattern in
         * a different build is reported as a new detour - measured on NRTH.dll vs the
         * reconstruction, where signature #18 matched a thunk at 0x0d9f91. */
        const int sameFn = found && (sus[i].firstPatchedRva == clean[i].firstFullRva ||
                                    sus[i].firstPatchedRva == clean[i].firstPatchedRva);
        d->addedFootprint = (patched && sameFn && clean[i].patchedHits == 0) ? 1u : 0u;
        d->susUnlocated = (patched && !sameFn) ? 1u : 0u;
        d->targetLost = (found && (sus[i].fullHits + sus[i].patchedHits) == 0) ? 1u : 0u;
        if (d->addedFootprint) {
            ++alerted;
        }
    }
    return alerted;
}

extern "C" int32_t NrthAuditDiffFiles(const char *cleanPath, const char *susPath,
                                     NrthAuditDiffRow *rows, uint32_t maxRows)
{
    uint32_t asz = 0, bsz = 0;
    uint8_t *a = nvxa_read_file(cleanPath, &asz);
    uint8_t *b = a ? nvxa_read_file(susPath, &bsz) : NULL;
    int32_t r = (a && b) ? NrthAuditDiff(a, asz, b, bsz, rows, maxRows) : NVXA_E_IO;
    if (!b && rows && maxRows >= NRTH_SIG_COUNT) {
        memset(rows, 0, sizeof(NrthAuditDiffRow) * NRTH_SIG_COUNT);
    }
    free(a);
    free(b);
    return r;
}

/* -------------------------------------------------------------------------- */
/* self test — evidence vectors taken from the original sample                  */
/* -------------------------------------------------------------------------- */
#define NVXA_CHECK(cond, name)                                                       \
    do {                                                                            \
        if (!(cond)) {                                                              \
            ++failed;                                                               \
            if (report && pos + 96 < cap) {                                         \
                pos += (uint32_t)snprintf(report + pos, cap - pos, "  [FAIL] %s\n", name); \
            }                                                                       \
        } else if (report && pos + 96 < cap) {                                      \
            pos += (uint32_t)snprintf(report + pos, cap - pos, "  [ ok ] %s\n", name);   \
        }                                                                           \
    } while (0)

extern "C" int32_t NrthAuditSelfTest(char *report, uint32_t cap)
{
    uint32_t pos = 0;
    int32_t failed = 0;
    if (report && cap) {
        pos += (uint32_t)snprintf(report + pos, cap - pos, "nrth_audit self-test (%s)\n",
                                  NRTH_AUDIT_VERSION);
    }

    /* 1. codec: ciphertext recovered from NRTH.dll VA 0x10005c56 (inline dwords) */
    static const uint8_t ctClient[] = { 0xb0, 0xb8, 0xbc, 0xb3, 0xb9, 0xac, 0xf7, 0xbe, 0xb7, 0xb0 };
    char txt[64];
    uint32_t key = 0;
    int32_t n = NrthXorCrack(ctClient, sizeof(ctClient), txt, sizeof(txt), &key);
    NVXA_CHECK(n == 10 && strcmp(txt, "client.dll") == 0 && key == 0x2D,
               "codec: 'client.dll' record (key 0x2D)");

    /* 2. codec: 8-byte SSE variant, ciphertext at NRTH.dll VA 0x1002069c */
    static const uint8_t ctNetc[] = { 0x8e, 0x84, 0x96, 0x80, 0xca, 0x81, 0x8a, 0x8b };
    n = NrthXorCrack(ctNetc, sizeof(ctNetc), txt, sizeof(txt), &key);
    NVXA_CHECK(n == 8 && strcmp(txt, "netc.dll") == 0 && key == 0x20,
               "codec: 'netc.dll' record (key 0x20)");

    /* 3. codec: 12-byte record at NRTH.dll VA 0x100044df */
    static const uint8_t ctChunk[] = { 0x93, 0xb5, 0xa0, 0xa2, 0xb8, 0x87, 0xb0, 0xb4,
                                       0xb1, 0xb9, 0xbe, 0xaa };
    n = NrthXorCrack(ctChunk, sizeof(ctChunk), txt, sizeof(txt), &key);
    NVXA_CHECK(n == 12 && strcmp(txt, "@auto_inject") == 0,
               "codec: '@auto_inject' chunk name");

    /* 4. codec: first 16 bytes of the .rdata block behind hook signature #1
     *    (NRTH.dll VA 0x100f2060) -> "55 8B EC 8B 45 ?" */
    static const uint8_t ctSig1[] = { 0xe6, 0xe1, 0xf5, 0xee, 0x95, 0xf8, 0x9c, 0x99, 0xfb,
                                      0xe4, 0x9f, 0xfe, 0xeb, 0xd5, 0xc1, 0xdd };
    char pat[256];
    n = NrthXorCrack(ctSig1, sizeof(ctSig1), pat, sizeof(pat), &key);
    NVXA_CHECK(n == 16 && strcmp(pat, "55 8B EC 8B 45 ?") == 0,
               "codec: hook signature #1 head block");

    /* 4b. tamper predicate: only real footprints count */
    NVXA_CHECK(NrthPrologueIsTamper(NRTH_PRO_KILL_RET) == 1 &&
               NrthPrologueIsTamper(NRTH_PRO_DETOUR_JMP32) == 1 &&
               NrthPrologueIsTamper(NRTH_PRO_STUB_IMM) == 1 &&
               NrthPrologueIsTamper(NRTH_PRO_UNKNOWN) == 0 &&
               NrthPrologueIsTamper(NRTH_PRO_PRISTINE) == 0 &&
               NrthPrologueIsTamper(NRTH_PRO_PAD) == 0,
               "predicate: only detour/kill/stub states count as tampering");

    /* 5. transform is symmetric (encode == decode) */
    uint8_t a[16], b[16];
    memcpy(a, ctClient, sizeof(ctClient));
    NrthXorTransform(a, 10, 0x2D, b, sizeof(b));
    NrthXorTransform(b, 10, 0x2D, a, sizeof(a));
    NVXA_CHECK(memcmp(a, ctClient, 10) == 0, "codec: transform is symmetric");

    /* 6. pattern engine: wildcards + compile errors */
    uint8_t bytes[32], masks[32];
    uint32_t plen = 0;
    NVXA_CHECK(NrthPatCompile("55 8b ? A3 ?? C3", bytes, masks, 32, &plen) == 6 && plen == 6 &&
                   masks[2] == 0 && bytes[0] == 0x55,
               "pattern: wildcard, lower-case hex and ?? token");
    static const uint8_t hay[] = { 0x55, 0x8B, 0xEC, 0x8B, 0x45, 0x11, 0xA3, 0x00, 0x00, 0x00,
                                   0x00, 0x8B, 0x45, 0x22 };
    uint32_t hits[8];
    NVXA_CHECK(NrthPatScan(hay, sizeof(hay), "55 8B EC 8B 45 ? A3 ? ? ? ? 8B 45", hits, 8) == 1 &&
                   hits[0] == 0,
               "pattern: sample hook signature #1 matches its target prologue");
    NVXA_CHECK(NrthPatScan(hay, sizeof(hay), "AA BB CC", hits, 8) == 0,
               "pattern: absent pattern returns 0 hits");
    NVXA_CHECK(NrthPatWidenHead("55 8B EC 8B 45 ? A3", 1, pat, sizeof(pat)) == 7 &&
                   strncmp(pat, "? 8B EC 8B 45 ? A3", 18) == 0,
               "pattern: head widening (kill-switch variant) keeps the tail");
    NVXA_CHECK(NrthPatPatchHead("55 8B EC 8B 45 ? A3", 1, "C3", pat, sizeof(pat)) == 7 &&
                   strncmp(pat, "C3 8B EC 8B 45 ? A3", 19) == 0,
               "pattern: head substitution writes the footprint over the entry");
    NVXA_CHECK(NrthPatPatchHead("55 8B EC 8B 45 ? A3", 5, "E9 ? ? ? ?", pat, sizeof(pat)) == 7 &&
                   strncmp(pat, "E9 ? ? ? ? ? A3", 15) == 0,
               "pattern: 5-token substitution for a near detour");

    /* 7. prologue classifier — the shapes the sample leaves behind */
    static const uint8_t pRet[] = { 0xC3, 0x90, 0x90, 0x90 };
    static const uint8_t pRetn[] = { 0xC2, 0x10, 0x00 };
    static const uint8_t pE9[] = { 0xE9, 0xFB, 0x04, 0x00, 0x00, 0x8B };
    static const uint8_t pFar[] = { 0xFF, 0x25, 0x40, 0x20, 0x40, 0x00 };
    static const uint8_t pPad[] = { 0x90, 0x90, 0x90, 0x90, 0x90, 0x8B };
    uint32_t detail = 0;
    NVXA_CHECK(NrthClassifyPrologue(pRet, 4, &detail) == NRTH_PRO_KILL_RET,
               "footprint: C3 = check kill (the sample's 0x10011870 write)");
    NVXA_CHECK(NrthClassifyPrologue(pRetn, 3, &detail) == NRTH_PRO_KILL_RETN && detail == 0x10,
               "footprint: C2 imm16");
    NVXA_CHECK(NrthClassifyPrologue(pE9, 6, &detail) == NRTH_PRO_DETOUR_JMP32 && detail == 0x4FB,
               "footprint: E9 rel32 near detour");
    NVXA_CHECK(NrthClassifyPrologue(pFar, 6, &detail) == NRTH_PRO_DETOUR_FARJMP,
               "footprint: FF 25 absolute detour");
    NVXA_CHECK(NrthClassifyPrologue(pPad, 6, &detail) == NRTH_PRO_PAD, "footprint: nop padding");

    /* 8. catalogue integrity: every generated row compiles and is anchored on a prologue */
    int catOk = (NrthSigCount() > 0);
    for (uint32_t i = 1; i <= NrthSigCount() && catOk; ++i) {
        const NrthSignature *s = NrthSigAt(i);
        uint8_t bb[NVXA_MAX_PAT], mm[NVXA_MAX_PAT];
        uint32_t nn = 0;
        if (!s || s->id != i || !s->target || !s->role || !s->pattern || !s->evidence ||
            s->confidence != 2 ||
            NrthPatCompile(s->pattern, bb, mm, NVXA_MAX_PAT, &nn) < 0 ||
            (uint32_t)strlen(s->pattern) != s->pattern_len || nn == 0) {
            catOk = 0;
            break;
        }
        if (!(strncmp(s->pattern, "55 8B EC ", 9) == 0 ||
              strncmp(s->pattern, "53 8B DC ", 9) == 0)) {
            catOk = 0;
            break;
        }
    }
    NVXA_CHECK(catOk, "catalogue: generated signature rows are well formed");

    /* 9. robustness: garbage must never crash or read out of bounds */
    static const uint8_t junk[] = { 'M', 'Z', 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
    NrthPeView pv;
    NVXA_CHECK(NrthPeMap(junk, sizeof(junk), &pv) != NVXA_OK, "PE: malformed header rejected");
    NVXA_CHECK(NrthAuditImage(junk, sizeof(junk), NULL, 0) != NVXA_OK,
               "PE: malformed image rejected by audit");
    NVXA_CHECK(NrthXorCrack(junk, 0, txt, sizeof(txt), &key) == NVXA_E_INVALID,
               "codec: empty input rejected");

    if (report && pos + 64 < cap) {
        snprintf(report + pos, cap - pos, "result: %s\n", failed ? "FAILURES" : "all checks passed");
    }
    return failed;
}
