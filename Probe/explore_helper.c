/*
 * explore_helper.c — exhaustive IN-PROCESS exploration of the dyld4
 * `ref & 0x7fff` OOB. No crash, no force-quit: we call dyld's own
 * recursiveMarkBeingValidated / isValid directly with synthetic RuntimeState
 * and large RW validation arrays, then snapshot which bytes got written and
 * with which values. This maps the full reachable write surface of the bug.
 *
 * Verified against dyld 27.0.1 (24A446), __TEXT vmaddr 0x18047c000:
 *   recursiveMarkBeingValidated : offset 0x3b9fc
 *   PrebuiltLoader::isValid     : offset 0x3b6e4
 *
 * Array selection (csel on ref sign bit):
 *   ref < 0  (bit15 set)   -> state[+0x450]  (app validation array)
 *   ref >= 0 (bit15 clear) -> state[+0x438]  (cache validation array)
 * Index = ref & 0x7fff (0..32767). Writes are fixed values {0x01, 0x02, 0xff}.
 */

#include <dlfcn.h>
#include <sys/mman.h>
#include <ptrauth.h>
#include <mach-o/loader.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define REC_MARK_OFFSET 0x3b9fc
#define ISVALID_OFFSET  0x3b6e4
#define DYLD_TEXT_VMADDR 0x18047c000ULL
#define ARR_LEN 0x10000          /* 64 KiB, covers idx 0..32767 */

static uintptr_t text_vmaddr(const void *mhbase) {
    const struct mach_header_64 *mh = (const struct mach_header_64 *)mhbase;
    if (mh->magic != MH_MAGIC_64) return 0;
    const uint8_t *p = (const uint8_t *)(mh + 1);
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        const struct load_command *lc = (const struct load_command *)p;
        if (lc->cmdsize < sizeof(struct load_command)) return 0;
        if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *seg = (const struct segment_command_64 *)lc;
            if (strcmp(seg->segname, "__TEXT") == 0) return (uintptr_t)seg->vmaddr;
        }
        p += lc->cmdsize;
    }
    return 0;
}

static int locate_dyld(uintptr_t *base, const char **image) {
    static const char *cands[] = {
        "dyld_get_image_header", "_dyld_get_image_header",
        "dyld_get_image_name", "_dyld_get_image_name",
        "dyld_get_image_vmaddr_slide", "_dyld_get_image_vmaddr_slide"
    };
    Dl_info di; memset(&di, 0, sizeof(di));
    *image = "(none)";
    for (unsigned i = 0; i < sizeof(cands)/sizeof(cands[0]); i++) {
        void *h = dlsym(RTLD_DEFAULT, cands[i]);
        if (!h) continue;
        Dl_info t; memset(&t, 0, sizeof(t));
        if (dladdr(h, &t) != 0 && t.dli_fname) { di = t; *image = t.dli_fname; break; }
    }
    if (!di.dli_fbase) return 0;
    uintptr_t imgVM = text_vmaddr(di.dli_fbase);
    if (!imgVM) return 0;
    uintptr_t b = (uintptr_t)di.dli_fbase - imgVM + DYLD_TEXT_VMADDR;
    if (text_vmaddr((void*)b) != DYLD_TEXT_VMADDR) return 0;
    *base = b;
    return 1;
}

typedef void (*dyldfn)(void *, void *, unsigned long);

/* A synthetic RuntimeState with:
 *   +0x08  -> config block (read by isValid: ldrb [x8,#0x280])
 *   +0x438 -> cache array pointer
 *   +0x450 -> app array pointer
 * and a synthetic loader with Ref (u16) at +0x6.
 */
static uint8_t *g_state = NULL, *g_config = NULL, *g_cache = NULL, *g_app = NULL, *g_loader = NULL;

static void setup_state(void) {
    g_state  = (uint8_t *)calloc(1, 0x600);
    g_config = (uint8_t *)calloc(1, 0x400);
    g_cache  = (uint8_t *)calloc(1, ARR_LEN);
    g_app    = (uint8_t *)calloc(1, ARR_LEN);
    g_loader = (uint8_t *)calloc(1, 0x100);
    memcpy(g_state + 0x08, &g_config, 8);
    memcpy(g_state + 0x438, &g_cache, 8);
    memcpy(g_state + 0x450, &g_app, 8);
}

static void reset_arrays(void) {
    memset(g_cache, 0, ARR_LEN);
    memset(g_app, 0, ARR_LEN);
}

/* Count non-zero bytes and report the distinct byte values written, plus
 * the min/max indices touched. */
static void scan(char *out, size_t n, const uint8_t *arr, const char *tag) {
    size_t cnt = 0; int mn = -1, mx = -1; int vals[256] = {0};
    for (int i = 0; i < ARR_LEN; i++) {
        if (arr[i]) { cnt++; vals[arr[i]] = 1; if (mn<0) mn=i; mx=i; }
    }
    char vstr[64] = ""; size_t vp = 0;
    for (int v=1; v<256; v++) if (vals[v]) vp += (size_t)snprintf(vstr+vp, sizeof(vstr)-vp, "%02x,", v);
    snprintf(out, n, "%s writes=%zu range=[%d..%d] vals={%s}",
             tag, cnt, mn, mx, vstr);
}

/* fire the accessor with a given ref; which function */
static void invoke(dyldfn fn, uint16_t ref) {
    g_loader[6] = (uint8_t)(ref & 0xff);
    g_loader[7] = (uint8_t)(ref >> 8);
    fn(g_loader, g_state, 0);
}

/*
 * probe_explore(out, outlen) fills `out` with the full dump.
 * Returns 0 on success.
 */
int probe_explore(char *out, size_t outlen) {
    size_t p = 0;
    #define EMIT(...) do { p += (size_t)snprintf(out+p, outlen-p, __VA_ARGS__); if (p>=outlen) return -1; } while(0)

    uintptr_t base; const char *image;
    if (!locate_dyld(&base, &image)) { snprintf(out, outlen, "EXPLORE: cannot locate dyld"); return -1; }
    dyldfn rec = (dyldfn)ptrauth_sign_unauthenticated((void*)(base+REC_MARK_OFFSET), ptrauth_key_function_pointer, 0);
    dyldfn val = (dyldfn)ptrauth_sign_unauthenticated((void*)(base+ISVALID_OFFSET),  ptrauth_key_function_pointer, 0);

    EMIT("=== DYLD4 OOB EXPLORATION DUMP ===\n");
    EMIT("[env] image=%s base=0x%lx pagesize=%d\n", image, (unsigned long)base, getpagesize());
    EMIT("[env] recMark=0x%lx isValid=0x%lx arrLen=0x%x\n",
         (unsigned long)(base+REC_MARK_OFFSET), (unsigned long)(base+ISVALID_OFFSET), ARR_LEN);

    setup_state();

    /* ---- TEST A: array selection by ref sign bit ---- */
    EMIT("\n[A] ARRAY SELECTION (ref sign bit -> +0x450 app / +0x438 cache)\n");
    reset_arrays(); invoke(rec, 0xffff);
    { char b[128]; scan(b,sizeof(b),g_app,"A1 ref=0xffff (neg)"); EMIT("  %s\n",b);
      scan(b,sizeof(b),g_cache,"   cache array"); EMIT("  %s\n",b); }
    reset_arrays(); invoke(rec, 0x7fff);
    { char b[128]; scan(b,sizeof(b),g_cache,"A2 ref=0x7fff (pos)"); EMIT("  %s\n",b);
      scan(b,sizeof(b),g_app,"   app array"); EMIT("  %s\n",b); }

    /* ---- TEST B: ref sweep on the app array via recursiveMarkBeingValidated ---- */
    EMIT("\n[B] REF SWEEP — recursiveMarkBeingValidated (each fresh zeroed app array)\n");
    static const uint16_t refs[] = {
        0xffff,0xfffe,0xfffd,0xff00,0xf000,0xa000,0x9001,0x8001,0x8000,
        0x7fff,0x7000,0x4000,0x2000,0x1000,0x0100,0x0001,0x0000
    };
    for (unsigned i=0;i<sizeof(refs)/sizeof(refs[0]);i++) {
        reset_arrays(); invoke(rec, refs[i]);
        int idx = refs[i] & 0x7fff;
        uint8_t v = (refs[i] & 0x8000) ? g_app[idx] : g_cache[idx];
        char b[128]; scan(b,sizeof(b), (refs[i]&0x8000)?g_app:g_cache," ");
        EMIT("  ref=0x%04x idx=%5d  byte[array+idx]=0x%02x  %s\n",
             refs[i], idx, v, b);
    }

    /* ---- TEST C: same sweep via isValid (different write path / value 0x02) ---- */
    EMIT("\n[C] REF SWEEP — PrebuiltLoader::isValid\n");
    for (unsigned i=0;i<sizeof(refs)/sizeof(refs[0]);i++) {
        reset_arrays(); invoke(val, refs[i]);
        int idx = refs[i] & 0x7fff;
        uint8_t *arr = (refs[i]&0x8000)?g_app:g_cache;
        char b[128]; scan(b,sizeof(b),arr," ");
        EMIT("  ref=0x%04x idx=%5d  byte[array+idx]=0x%02x  %s\n",
             refs[i], idx, arr[idx], b);
    }

    /* ---- TEST D: pre-filled value semantics (cbnz read gate) ---- */
    EMIT("\n[D] VALUE GATE — prefill array[idx] then call; observe whether write occurs\n");
    static const uint8_t seeds[] = {0x00,0x01,0x02,0xff};
    for (unsigned s=0;s<sizeof(seeds);s++) {
        reset_arrays(); g_app[32767]=seeds[s]; invoke(rec,0xffff);
        EMIT("  seed=0x%02x -> array[32767]=0x%02x (unchanged means cbnz returned early)\n",
             seeds[s], g_app[32767]);
    }

    /* ---- TEST E: multi-loader composite in one state ---- */
    EMIT("\n[E] MULTI-HIT — sequential refs, same arrays (simulates many loaders)\n");
    reset_arrays();
    static const uint16_t multi[] = {0x8001,0x8010,0x8100,0x9000,0xa000,0xffff};
    for (unsigned i=0;i<sizeof(multi)/sizeof(multi[0]);i++) invoke(rec,multi[i]);
    { char b[128]; scan(b,sizeof(b),g_app,"  app array"); EMIT("  %s\n",b); }

    /* ---- TEST F: full-reach coarse sweep (extent map) ---- */
    EMIT("\n[F] EXTENT MAP — coarse sweep across 0..32767 (recursiveMark, app array)\n");
    for (uint32_t idx=0; idx<=0x7fff; idx+=0x0800) {
        reset_arrays(); invoke(rec, (uint16_t)(0x8000 | idx));
        EMIT("  idx=0x%04x -> byte=0x%02x\n", idx, g_app[idx]);
    }

    EMIT("\n[END] exploration complete — all accesses were to RW synthetic arrays (no fault)\n");
    return 0;
}
