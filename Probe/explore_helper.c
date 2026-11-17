/*
 * explore_helper.c — exhaustive IN-PROCESS exploration of the dyld4
 * `ref & 0x7fff` OOB. No crash, no force-quit.
 *
 * Calls dyld's own validation functions with synthetic RuntimeState + large
 * RW arrays, sweeps ref values, and writes results INCREMENTALLY to a file
 * (so a partial crash never loses earlier findings).
 *
 * 27.0.1 __TEXT base 0x18047c000:
 *   recursiveMarkBeingValidated : 0x3b9fc   (no extra state deps)
 *   PrebuiltLoader::isValid     : 0x3b6e4
 *     - ref<0  (bit15 set)   -> app array +0x450; only needs state[+8] config
 *     - ref>=0 (bit15 clear) -> cache path: reads state[+0x430] (cache PLS
 *       pointer). Our synthetic state has that = NULL -> isValid with a
 *       POSITIVE ref faults in .cold.1. Therefore the isValid sweep uses
 *       NEGATIVE refs only; the positive-ref/cache-array case is covered by
 *       recursiveMarkBeingValidated in Test A2, which has no such dependency.
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
#define ARR_LEN 0x10000

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

static uint8_t *g_state = NULL, *g_config = NULL, *g_cache = NULL, *g_app = NULL, *g_loader = NULL;
static uint8_t *g_fake_pls = NULL;

static void setup_state(void) {
    g_state  = (uint8_t *)calloc(1, 0x600);
    g_config = (uint8_t *)calloc(1, 0x1000);   /* state[+8] -> config; isValid reads [config+0x280] */
    g_cache  = (uint8_t *)calloc(1, ARR_LEN);
    g_app    = (uint8_t *)calloc(1, ARR_LEN);
    /* isValid's .cold.1 calls LoaderRef::loader which reads the PLS pointer
     * from loader+0x448 and then [pls+0xc] (count). Give the fake loader a
     * valid fake PLS there so it never dereferences NULL. */
    g_loader    = (uint8_t *)calloc(1, 0x600);
    g_fake_pls  = (uint8_t *)calloc(1, 0x1000);
    memcpy(g_loader + 0x448, &g_fake_pls, 8);
    g_fake_pls[0xc] = 0;   /* PLS count = 0 -> .cold.1 loop is skipped (cbz) */
    memcpy(g_state + 0x08, &g_config, 8);
    memcpy(g_state + 0x438, &g_cache, 8);
    memcpy(g_state + 0x450, &g_app, 8);
    memset(g_config, 0, 0x1000);
    /* isValid .cold.1 receives x0 = RuntimeState (not loader): it does
     * `ldr x21,[x0,#0x448]; ldr w8,[x21,#0xc]`. Point state+0x448 at our
     * fake PLS too, with a small count, so no NULL deref. */
    memcpy(g_state + 0x448, &g_fake_pls, 8);
    memcpy(g_state + 0x430, &g_fake_pls, 8);  /* belt-and-suspenders for cache path */
}
static void reset_arrays(void) { memset(g_cache, 0, ARR_LEN); memset(g_app, 0, ARR_LEN); }

static void scan(FILE *f, const uint8_t *arr, const char *tag) {
    size_t cnt = 0; int mn = -1, mx = -1; int vals[256] = {0};
    for (int i = 0; i < ARR_LEN; i++) {
        if (arr[i]) { cnt++; vals[arr[i]] = 1; if (mn<0) mn=i; mx=i; }
    }
    fprintf(f, "%s writes=%zu range=[%d..%d] vals=", tag, cnt, mn, mx);
    for (int v=1; v<256; v++) if (vals[v]) fprintf(f, "%02x,", v);
    fprintf(f, "\n");
}

static void invoke(dyldfn fn, uint16_t ref) {
    g_loader[6] = (uint8_t)(ref & 0xff);
    g_loader[7] = (uint8_t)(ref >> 8);
    fn(g_loader, g_state, 0);
}

/* probe_explore(path): writes the full dump to `path` incrementally. */
int probe_explore(const char *path) {
    FILE *f = fopen(path, "w");
    if (!f) return -1;

    uintptr_t base; const char *image;
    if (!locate_dyld(&base, &image)) {
        fprintf(f, "EXPLORE: cannot locate dyld\n"); fclose(f); return -1;
    }
    dyldfn rec = (dyldfn)ptrauth_sign_unauthenticated((void*)(base+REC_MARK_OFFSET), ptrauth_key_function_pointer, 0);
    dyldfn val = (dyldfn)ptrauth_sign_unauthenticated((void*)(base+ISVALID_OFFSET),  ptrauth_key_function_pointer, 0);

    fprintf(f, "=== DYLD4 OOB EXPLORATION DUMP ===\n");
    fprintf(f, "[env] image=%s base=0x%lx pagesize=%d\n", image, (unsigned long)base, getpagesize());
    fprintf(f, "[env] recMark=0x%lx isValid=0x%lx arrLen=0x%x\n",
            (unsigned long)(base+REC_MARK_OFFSET), (unsigned long)(base+ISVALID_OFFSET), ARR_LEN);
    fflush(f);

    setup_state();

    /* A: array selection via recursiveMark (safe for both signs) */
    fprintf(f, "\n[A] ARRAY SELECTION (ref sign bit -> +0x450 app / +0x438 cache)\n"); fflush(f);
    reset_arrays(); invoke(rec, 0xffff);
    scan(f, g_app,   "A1 ref=0xffff neg -> app array  ");
    scan(f, g_cache, "     ref=0xffff neg -> cache array"); fflush(f);
    reset_arrays(); invoke(rec, 0x7fff);
    scan(f, g_cache, "A2 ref=0x7fff pos -> cache array ");
    scan(f, g_app,   "     ref=0x7fff pos -> app array  "); fflush(f);

    /* B: ref sweep via recursiveMark (both signs, safe) */
    fprintf(f, "\n[B] REF SWEEP — recursiveMarkBeingValidated\n"); fflush(f);
    static const uint16_t refs[] = {
        0xffff,0xfffe,0xfffd,0xff00,0xf000,0xa000,0x9001,0x8001,0x8000,
        0x7fff,0x7000,0x4000,0x2000,0x1000,0x0100,0x0001,0x0000
    };
    for (unsigned i=0;i<sizeof(refs)/sizeof(refs[0]);i++) {
        reset_arrays(); invoke(rec, refs[i]);
        int idx = refs[i] & 0x7fff;
        uint8_t *arr = (refs[i]&0x8000)?g_app:g_cache;
        fprintf(f, "  ref=0x%04x idx=%5d array=%s byte=0x%02x\n",
                refs[i], idx, (refs[i]&0x8000)?"app":"cache", arr[idx]);
        fflush(f);
    }

    /* C: ref sweep via isValid — negative refs only. (Positive refs push
     * isValid into the cache-PLS path which needs a real PLS object graph;
     * the cache-array case is already covered by recursiveMark in Test A2.) */
    fprintf(f, "\n[C] REF SWEEP — PrebuiltLoader::isValid (app path, negative refs)\n"); fflush(f);
    static const uint16_t negrefs[] = {
        0xffff,0xfffe,0xfffd,0xff00,0xf000,0xa000,0x9001,0x8001,0x8000
    };
    for (unsigned i=0;i<sizeof(negrefs)/sizeof(negrefs[0]);i++) {
        reset_arrays(); invoke(val, negrefs[i]);
        int idx = negrefs[i] & 0x7fff;
        fprintf(f, "  ref=0x%04x idx=%5d byte=0x%02x writes=%s\n",
                negrefs[i], idx, g_app[idx], g_app[idx]?"yes":"no");
        fflush(f);
    }

    /* D: cbnz read gate */
    fprintf(f, "\n[D] VALUE GATE — prefill array[idx] then call recursiveMark\n"); fflush(f);
    static const uint8_t seeds[] = {0x00,0x01,0x02,0xff};
    for (unsigned s=0;s<sizeof(seeds);s++) {
        reset_arrays(); g_app[32767]=seeds[s]; invoke(rec,0xffff);
        fprintf(f, "  seed=0x%02x -> array[32767]=0x%02x\n", seeds[s], g_app[32767]);
        fflush(f);
    }

    /* E: multi-loader composite */
    fprintf(f, "\n[E] MULTI-HIT — sequential refs, same arrays\n"); fflush(f);
    reset_arrays();
    static const uint16_t multi[] = {0x8001,0x8010,0x8100,0x9000,0xa000,0xffff};
    for (unsigned i=0;i<sizeof(multi)/sizeof(multi[0]);i++) invoke(rec,multi[i]);
    scan(f, g_app, "  app array"); fflush(f);

    /* F: coarse extent map */
    fprintf(f, "\n[F] EXTENT MAP — coarse sweep across 0..32767 (recursiveMark, app array)\n"); fflush(f);
    for (uint32_t idx=0; idx<=0x7fff; idx+=0x0800) {
        reset_arrays(); invoke(rec, (uint16_t)(0x8000 | idx));
        fprintf(f, "  idx=0x%04x -> byte=0x%02x\n", idx, g_app[idx]);
        fflush(f);
    }

    fprintf(f, "\n[END] exploration complete — all accesses to RW synthetic arrays\n");
    fclose(f);
    return 0;
}
