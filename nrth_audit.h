/**
 * ============================================================================
 * nrth_audit.h — PUBLIC CONTRACT of the NORTH/NVX **defensive audit** module
 * ============================================================================
 * Result class: R2 (newly authored defensive code) built on D2 evidence
 * (disassembly-derived findings) from the original sample. See
 * ../../mta_blue_team_case/report.md §2.1 for the scope decision behind this file.
 *
 * The module turns the sample's *own* mechanism primitives into detection logic:
 *
 *   mechanism in NRTH.dll                                this module
 *   --------------------------------------------------   --------------------------------
 *   §3.1 positional-XOR string codec (per-record key)    NrthXorTransform/NrthXorCrack
 *   §3.2 finds client.dll/netc.dll functions by code     NrthPatCompile/NrthPatScan —
 *        pattern with '?' wildcards (resolver 0x10002960)   same matcher semantics, used
 *                                                          to locate the *targets*
 *   §3.2 installs MinHook detours on them; §4 writes a   NrthClassifyPrologue — reports
 *        single 0xC3 (RET) byte over a netc.dll check    E9/FF25 detour + C3/C2 kill
 *   §2/§3 module pinning, injection, Lua-VM execution    NOT implemented (see below)
 *
 * WHAT THIS MODULE DELIBERATELY DOES **NOT** DO (blue-team scope decision):
 *   - it never opens another process, never injects, never hooks, never changes memory
 *     protection, never writes a byte outside its own caller-provided output buffers;
 *   - it cannot execute Lua in a game VM and contains no script payload, no feature
 *     logic, no overlay, no loader, no self-protection and no evasion;
 *   - it reads one *file* (a module copy, or a memory-dump the team already owns) and
 *     reports where the tool's hook targets are and whether a prologue looks patched.
 * Everything an attacker would need to weaponise this is deliberately absent, while
 * everything a defender needs (module-relative offsets + patch state) is present.
 *
 * Inputs are UNTRUSTED data: malformed/truncated PE input must fail safely.
 *
 * Version 1.2.0 (2026-10-11): NrthAuditDiff only alerts on a footprint that sits on the SAME located
 * function as the baseline (RVA agreement is the alignment key). Measured reason: diffing the
 * original NRTH.dll against our own reconstruction produced one DETOUR_JMP32 "added footprint",
 * which was a jump thunk of a different build, not a patch - see detection/audit_tool.md.
 * NrthAuditDiffRow gained susUnlocated, which counts exactly that case informationally.
 *
 * Version 1.1.0 (2026-10-10): added NrthPrologueIsTamper, NrthPatPatchHead and the A/B
 * comparison entry points (NrthAuditDiff / NrthAuditDiffFiles, ordinals 22-23). The patched-hit
 * rule was also tightened: a widened hit now counts only when the entry carries a concrete
 * footprint, which removed 5 false positives per 20 rows measured against NRTH.dll itself.
 * Builds as a Windows PE32 DLL (matching the sample's architecture) and also compiles
 * natively on Linux for unit testing — the logic is plain C++17 with no OS coupling.
 * ============================================================================
 */
#ifndef NRTH_AUDIT_H
#define NRTH_AUDIT_H

#include <stdint.h>

/* Linkage. Define NRTH_AUDIT_BUILD when compiling this module *into* NRTH_audit.dll, and
 * NRTH_AUDIT_STATIC when the sources are compiled straight into a consumer (the CLI does
 * that, so nrth_audit.exe has no import table dependency on the DLL). With neither define
 * the header declares the API as imported, which is what a third-party scanner tool should
 * do: LoadLibrary("NRTH_audit.dll") + GetProcAddress, or link against the import library. */
#ifdef _WIN32
#  if defined(NRTH_AUDIT_BUILD)
#    define NRTH_AUDIT_API __declspec(dllexport)
#  elif defined(NRTH_AUDIT_STATIC)
#    define NRTH_AUDIT_API
#  else
#    define NRTH_AUDIT_API __declspec(dllimport)
#  endif
#  define NRTH_AUDIT_C extern "C"
#else
#  define NRTH_AUDIT_API
#  define NRTH_AUDIT_C extern "C"
#endif

#define NRTH_AUDIT_VERSION "1.2.0"

/* ---- status codes -------------------------------------------------------- */
#define NVXA_OK             0
#define NVXA_E_INVALID     -1   /* bad argument / output buffer too small        */
#define NVXA_E_FORMAT      -2   /* not a PE image / no sections                  */
#define NVXA_E_TRUNCATED   -3   /* image shorter than its headers promise        */
#define NVXA_E_IO          -4   /* file could not be read                        */

/* ---- prologue states: the runtime footprint of the tool's patching -------- */
typedef enum _NrthPrologueState {
    NRTH_PRO_UNKNOWN = 0,
    NRTH_PRO_PRISTINE = 1,        /* matches the tool's own search pattern          */
    NRTH_PRO_DETOUR_JMP32 = 2,    /* E9 rel32        — MinHook-style near detour    */
    NRTH_PRO_DETOUR_FARJMP = 3,   /* FF 25 [addr]    — absolute/far detour          */
    NRTH_PRO_DETOUR_PUSHRET = 4,  /* 68 xx push+ret  — trampoline push form         */
    NRTH_PRO_KILL_RET = 5,        /* C3              — "return immediately" patch   */
    NRTH_PRO_KILL_RETN = 6,       /* C2 imm16        — cleaned-stack no-op patch     */
    NRTH_PRO_STUB_IMM = 7,        /* C7 05 [g],imm   — global forced to a constant   */
    NRTH_PRO_PAD = 8,             /* long 90/CC run  — body moved elsewhere          */
    NRTH_PRO_JMP_INDIRECT = 9     /* FF 25/FF E0 style jump through register/memory   */
} NrthPrologueState;

/* ---- verified signature catalogue (generated: see nrth_audit_sigs.h) ----- */
typedef struct _NrthSignature {
    uint32_t id;
    const char *pattern;      /* "55 8B EC 8B 45 ? A3 ? ? ? ? ..." ('?' = wildcard) */
    const char *target;       /* module the sample scans                       */
    const char *role;         /* what the sample does with the match           */
    uint32_t decryptor_va;    /* VA of the sample's string-decryptor call       */
    uint32_t pattern_len;     /* length of the recovered pattern text, in bytes */
    uint32_t xor_key;         /* effective key: plain[p]^(p-key)&0xFF           */
    uint32_t confidence;      /* 2 High / 1 Medium / 0 Low                     */
    const char *evidence;     /* VA(s) of the record construction site(s)      */
} NrthSignature;

/* ---- one result row per catalogue signature ------------------------------ */
typedef struct _NrthSigFinding {
    uint32_t sigId;
    uint32_t fullHits;        /* occurrences of the complete pattern            */
    uint32_t patchedHits;     /* occurrences where only the *tail* matches      */
    uint32_t firstFullRva;    /*   (prologue differs) — the hook/kill footprint  */
    uint32_t firstPatchedRva;
    uint32_t state;           /* NrthPrologueState at firstPatchedRva            */
    uint32_t detail;          /* state-specific: detour target RVA / stub value  */
    uint32_t textSectionOnly;  /* 1 when the finding lies in a section ".text"    */
} NrthSigFinding;

/* ---- minimal PE view ----------------------------------------------------- */
#define NRTH_PE_MAX_SECTIONS 96
typedef struct _NrthPeSection {
    char name[9];
    uint32_t rva, vsize, raw, rsize, characteristics;
} NrthPeSection;

typedef struct _NrthPeView {
    const uint8_t *img;
    uint32_t size;
    uint32_t imageBase;
    uint32_t entryRva;
    uint32_t timestamp;
    uint16_t machine;
    uint16_t nSections;
    uint32_t characteristics;
    int mapped;               /* 1 = image already loaded (VA offsets), 0 = file */
    NrthPeSection sec[NRTH_PE_MAX_SECTIONS];
} NrthPeView;

#ifdef __cplusplus
extern "C" {
#endif

/* --- version / catalogue -------------------------------------------------- */
NRTH_AUDIT_C NRTH_AUDIT_API const char *NrthAuditVersion(void);
NRTH_AUDIT_C NRTH_AUDIT_API uint32_t NrthSigCount(void);
NRTH_AUDIT_C NRTH_AUDIT_API const NrthSignature *NrthSigAt(uint32_t i);
NRTH_AUDIT_C NRTH_AUDIT_API const char *NrthPrologueStateName(uint32_t state);
/* 1 when the state is an active tamper footprint (detour jump, 0xC3/0xC2 kill, forced
 * constant, jump-through-memory), 0 for UNKNOWN/PRISTINE/PAD. NrthAuditImage counts a
 * widened hit as "patched" only when this predicate is true, so a coincidental tail match
 * on a perfectly normal function prologue never raises an alert. */
NRTH_AUDIT_C NRTH_AUDIT_API int32_t NrthPrologueIsTamper(uint32_t state);

/* --- codec (§3.1: positional XOR, symmetric) ------------------------------ */
/* out[p] = in[p] ^ ((p - key) & 0xFF). Returns bytes written, or NVXA_E_*.      */
NRTH_AUDIT_C NRTH_AUDIT_API int32_t NrthXorTransform(const uint8_t *in, uint32_t len,
                                                     uint32_t key, uint8_t *out,
                                                     uint32_t outCap);
/* Best printable decode over all 256 keys (family keys 0x2D/0x20 win ties).
 * NUL-terminates `text`. Returns the printable length, or 0 when nothing decodes. */
NRTH_AUDIT_C NRTH_AUDIT_API int32_t NrthXorCrack(const uint8_t *in, uint32_t len,
                                                  char *text, uint32_t textCap,
                                                  uint32_t *outKey);
/* Locate + decrypt one obfuscated record of a sample of this family at `va`.      */
NRTH_AUDIT_C NRTH_AUDIT_API int32_t NrthXorDecodeRecordAt(const NrthPeView *pe,
                                                          uint32_t va, uint32_t len,
                                                          char *text, uint32_t textCap,
                                                          uint32_t *outKey);

/* --- pattern engine (same matching semantics as the sample's resolver) --------- */
/* "55 8B ? A3" -> bytes/mask. Returns pattern length, or NVXA_E_*. */
NRTH_AUDIT_C NRTH_AUDIT_API int32_t NrthPatCompile(const char *text, uint8_t *bytes,
                                                   uint8_t *mask, uint32_t cap,
                                                   uint32_t *outLen);
/* Wildcard scan; returns the number of offsets written into hits[] (byte offsets in buf),
   capped at maxHits. Only ever index hits[] with the returned count. */
NRTH_AUDIT_C NRTH_AUDIT_API int32_t NrthPatScan(const uint8_t *buf, uint32_t len,
                                                const char *pattern, uint32_t *hits,
                                                uint32_t maxHits);
/* Widen a pattern: replace the first `head` tokens with wildcards, so a patched
 * prologue still anchors on the (unmodified) tail. Returns the new token count. */
NRTH_AUDIT_C NRTH_AUDIT_API int32_t NrthPatWidenHead(const char *pattern, uint32_t head,
                                                      char *out, uint32_t outCap);
/* Same, but instead of '?'-wildcarding the first `head` tokens it *substitutes* the
 * concrete footprint tokens (e.g. "C3", "E9 ? ? ? ?", "FF 25 ? ? ? ?", "68 ? ? ? ? C3").
 * That is how NrthAuditImage recognises a hooked/killed function without the false
 * positives a wildcarded head produces on unrelated code. */
NRTH_AUDIT_C NRTH_AUDIT_API int32_t NrthPatPatchHead(const char *pattern, uint32_t head,
                                                     const char *footprint, char *out,
                                                     uint32_t outCap);

/* --- patch footprint -------------------------------------------------------- */
/* func = bytes at a located target (file copy or owned dump).
 * outDetail = jump target RVA / stub value when derivable. */
NRTH_AUDIT_C NRTH_AUDIT_API int32_t NrthClassifyPrologue(const uint8_t *func, uint32_t avail,
                                                         uint32_t *outDetail);

/* --- PE view --------------------------------------------------------------- */
NRTH_AUDIT_C NRTH_AUDIT_API int32_t NrthPeMap(const uint8_t *img, uint32_t size,
                                              NrthPeView *out);
/* Section data for scanning, honouring file vs mapped layout. */
NRTH_AUDIT_C NRTH_AUDIT_API const uint8_t *NrthPeSectionData(const NrthPeView *pe,
                                                              uint32_t sectionIndex,
                                                              uint32_t *outLen,
                                                              uint32_t *outRva);
/* VA -> offset inside a mapped image (returns NULL when outside). */
NRTH_AUDIT_C NRTH_AUDIT_API const uint8_t *NrthPeRvaToPtr(const NrthPeView *pe, uint32_t rva,
                                                          uint32_t want);

/* --- whole-module audit ----------------------------------------------------- */
/* Audit every catalogue signature against an image buffer (file image or an owned,
 * already-read dump). Returns the number of signatures with any hit, or NVXA_E_*.
 * findings[] must hold NrthSigCount() entries (NULL is allowed = count only). */
NRTH_AUDIT_C NRTH_AUDIT_API int32_t NrthAuditImage(const uint8_t *img, uint32_t size,
                                                   NrthSigFinding *findings,
                                                   uint32_t maxFindings);
NRTH_AUDIT_C NRTH_AUDIT_API int32_t NrthAuditImageFile(const char *path,
                                                       NrthSigFinding *findings,
                                                       uint32_t maxFindings);
/* RVA (not VA) of the module's .text start, or 0 — helper for callers. */
NRTH_AUDIT_C NRTH_AUDIT_API uint32_t NrthPeTextRva(const NrthPeView *pe);

/* --- A/B comparison: known-good copy vs the copy actually loaded ------------ */
/* The strongest form of this check, because it removes every judgement call about
 * "is this prologue normal for this compiler": you give a clean `client.dll` (your
 * baseline, from the same MTA build) and the module as loaded in the suspect process,
 * and the diff says which located functions changed. Rows are per signature, in
 * catalogue order; `addedFootprint` is the number you alert on. */
typedef struct _NrthAuditDiffRow {
    uint32_t sigId;
    uint32_t cleanFull;        /* complete-pattern hits in the baseline image      */
    uint32_t cleanPatched;
    uint32_t susFull;          /* ... in the loaded/suspect image                  */
    uint32_t susPatched;
    uint32_t susState;         /* footprint at the suspect's first patched RVA     */
    uint32_t susRva;
    uint32_t susDetail;        /* detour target RVA, when the state carries one    */
    uint32_t addedFootprint;   /* 1 when the suspect patched the SAME function the baseline
                                * located at this RVA and the baseline had no footprint there.
                                * This is the only field to alert on. */
    uint32_t targetLost;       /* 1 when baseline found the pattern and suspect did not */
    uint32_t susUnlocated;     /* 1 when the suspect has a footprint at an RVA the baseline never
                                * located: a different build (or a pattern that matched unrelated
                                * code), reported so it can be seen but deliberately NOT an alert. */
} NrthAuditDiffRow;

/* Returns the number of rows with an added footprint (>=0) or NVXA_E_*. Both inputs
 * may be file images or dumps; they are only compared through the located-pattern
 * offsets, so differing ImageBases are fine. The located RVA is also what aligns the two
 * images: a footprint at an RVA the baseline never located is counted as `susUnlocated`,
 * not as tampering, so diffing two different builds yields no alert instead of a flood.
 * For a meaningful check the two files must still be the same build of the same module.
 * Multi-hit signatures are aligned on their FIRST located function only. */
NRTH_AUDIT_C NRTH_AUDIT_API int32_t NrthAuditDiff(const uint8_t *cleanImg, uint32_t cleanSize,
                                                 const uint8_t *susImg, uint32_t susSize,
                                                 NrthAuditDiffRow *rows, uint32_t maxRows);
NRTH_AUDIT_C NRTH_AUDIT_API int32_t NrthAuditDiffFiles(const char *cleanPath, const char *susPath,
                                                       NrthAuditDiffRow *rows, uint32_t maxRows);

/* --- hidden-signature discovery (variant triage) ---------------------------- */
/* Prologue-anchored sweep for obfuscated pattern strings held in a sample of this
 * family: for each aligned position, the key that makes the bytes read
 * "55 8B EC " / "53 8B DC " is tried, and a printable hex-pattern run >= minLen is
 * reported. textOut gets NUL-terminated strings, each <= 255 chars, separated by \n.
 * Returns the number of distinct candidates (0 is a valid answer, not an error). */
NRTH_AUDIT_C NRTH_AUDIT_API int32_t NrthFindHiddenSignatures(const uint8_t *img, uint32_t size,
                                                            uint32_t minLen,
                                                            char *textOut,
                                                            uint32_t textCap,
                                                            uint32_t *outVas,
                                                            uint32_t maxVas);

/* --- self test ------------------------------------------------------------- */
/* Runs the built-in evidence vectors (codec, pattern engine, classifier, catalogue
 * consistency). Writes a human-readable report; returns 0 when all checks pass,
 * otherwise the number of failed checks. */
NRTH_AUDIT_C NRTH_AUDIT_API int32_t NrthAuditSelfTest(char *report, uint32_t reportCap);

#ifdef __cplusplus
}
#endif

#endif /* NRTH_AUDIT_H */
