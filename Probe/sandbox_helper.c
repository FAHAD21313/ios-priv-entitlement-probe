/*
 * sandbox_helper.c — device-side REACHABILITY probe (non-destructive).
 * Tests which privileged IOKit user clients and Mach services a free-signed
 * sandboxed app can reach. Opens handles / looks up ports only; does NOT send
 * malformed data or crash anything. Results written incrementally to a file.
 */
#include <mach/mach.h>
#include <mach/mach_error.h>
#include <mach/bootstrap.h>
#include <IOKit/IOKitLib.h>
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* iOS SDK does not declare bootstrap_look_up; declare it ourselves. */
extern kern_return_t bootstrap_look_up(mach_port_t bp, const char *service_name, mach_port_t *sp);

/* mach_lookup via bootstrap (safe: just look up, do not send) */
static mach_port_t lookup(const char *name) {
    mach_port_t p = MACH_PORT_NULL;
    kern_return_t kr = bootstrap_look_up(bootstrap_port, (char*)name, &p);
    if (kr != KERN_SUCCESS) return MACH_PORT_NULL;
    return p;
}

int probe_sandbox(const char *path) {
    FILE *f = fopen(path, "w");
    if (!f) return -1;

    fprintf(f, "=== SANDBOX REACHABILITY PROBE ===\n"); fflush(f);

    /* ---- IOKit user client openability ---- */
    fprintf(f, "\n[IOKIT] IOServiceOpen by class name (kr==0 means reachable)\n"); fflush(f);
    static const char *classes[] = {
        "IOSurfaceRootUserClient",
        "IOSurfaceAcceleratorClient",
        "IOSurfaceAcceleratorParavirtClient",
        "AppleAVE2UserClient",
        "AppleAVEUserClient",
        "AppleH16ANEInterface",
        "AppleNeuralEngineUserClient",
        "IOHIDLibUserClient",
        "IOHIDFastPathUserClient",
        "IOMobileFramebufferUserClient",
        "IOGraphicsAccelerator2",
        "AGXDeviceUserClient",
        "AppleMPEG2CodecDevice",
        "AppleAVDUserClient"
    };
    for (unsigned i = 0; i < sizeof(classes)/sizeof(classes[0]); i++) {
        io_service_t svc = IOServiceGetMatchingService(IOMainPort(bootstrap_port, 0),
                              IOServiceMatching(classes[i]));
        if (svc == IO_OBJECT_NULL) {
            fprintf(f, "  %-38s service=NOT-FOUND\n", classes[i]);
        } else {
            io_connect_t conn = IO_OBJECT_NULL;
            kern_return_t kr = IOServiceOpen(svc, mach_task_self(), 0, &conn);
            fprintf(f, "  %-38s service=FOUND open_kr=0x%x %s conn=%s\n",
                    classes[i], kr,
                    kr == KERN_SUCCESS ? "OPENED" : "DENIED",
                    conn != IO_OBJECT_NULL ? "yes" : "no");
            if (conn != IO_OBJECT_NULL) IOServiceClose(conn);
            IOObjectRelease(svc);
        }
        fflush(f);
    }

    /* ---- Mach service lookup ---- */
    fprintf(f, "\n[MACH] bootstrap_look_up (non-null means reachable)\n"); fflush(f);
    static const char *services[] = {
        "com.apple.quicklook.ThumbnailsAgent",
        "com.apple.quicklook.QLThumbnailGenerator",
        "com.apple.MobileQuickLook",
        "com.apple.CoreGraphics.CGPDFService",
        "com.apple.mobileassetd",
        "com.apple.pasteboard",
        "com.apple.analyticsd",
        "com.apple.fileprovider",
        "com.apple.dt.previewsd",
        "com.apple.BlastDoor.ThumbnailsBlastDoorService",
        "com.apple.knowledge-agent",
        "com.apple.trustd",
        "com.apple.securityd",
        "com.apple.amfid"
    };
    for (unsigned i = 0; i < sizeof(services)/sizeof(services[0]); i++) {
        mach_port_t p = lookup(services[i]);
        fprintf(f, "  %-48s %s\n", services[i],
                p != MACH_PORT_NULL ? "REACHABLE" : "not-found/denied");
        if (p != MACH_PORT_NULL) mach_port_deallocate(mach_task_self(), p);
        fflush(f);
    }

    fprintf(f, "\n[END] reachability probe complete\n");
    fclose(f);
    return 0;
}
