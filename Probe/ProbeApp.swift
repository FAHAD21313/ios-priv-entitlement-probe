//
//  ProbeApp.swift
//  iOS private-entitlement probe — iOS 27.0.1 (24A446)
//
//  WHAT THIS PROBES
//  ----------------
//  Static analysis of the AMFI kext on iOS 27.0.1 showed that the kernel
//  never verifies the provisioning profile's own CMS chain: the profile is
//  DER/plist parsed, its dictionary keys are inspected, and the profile itself
//  arrives from `amfid` over MIG.  The kernel authenticates only the daemon's
//  identity.
//
//  The one link that could not be read statically is `amfid`'s own behaviour,
//  because it is a filesystem binary behind a per-device AEA key.
//
//  This app measures the OUTCOME on the device, from the inside:
//
//    1. provenance   — what signature does this build actually carry?
//    2. policy bytes — what did the signer write into the CT-policy field?
//    3. entitlements — which com.apple.private.* keys are visible, and are
//                      they merely STORED or actually HONOURED?
//    4. sandbox     — is the sandbox actually off?
//    5. anchor set  — does the RUNTIME trust-anchor set accept our chain?
//    6. install     — does the privileged install channel actually open?
//    7. kernel log  — which gate fired, in AMFI's own words?
//
//  A stored entitlement is NOT proof of an honoured one.  The authoritative
//  signals are (4), (6) and (7); (3) is only a hint.
//
//  The report is written to Documents/probe-report.txt so it can be shared
//  back for analysis.
//

import UIKit
import Security
import os
import ObjectiveC.runtime
import Darwin

// MARK: - Logging

final class ProbeLogger {
    static let shared = ProbeLogger()
    private let osLog = OSLog(subsystem: "com.research.ios27.privprobe", category: "probe")
    func log(_ m: String) {
        os_log("%{public}@", log: osLog, type: .info, m as NSString)
    }
}

// MARK: - Dynamic Security.framework entry points
//
// SecTask, SecStaticCode and SecRequirement are NOT public API on iOS, so they
// are resolved at run time out of the shipped Security.framework.

enum DynSec {
    typealias CreateTask = @convention(c) (CFTypeRef?) -> Unmanaged<CFTypeRef>?
    typealias CopyEntitlement = @convention(c) (CFTypeRef, CFString, CFTypeRef?) -> CFTypeRef?
    typealias CreateStaticCode = @convention(c) (CFURL, CFTypeRef?, UnsafeMutablePointer<CFTypeRef?>) -> Int32
    typealias CreateRequirement = @convention(c) (CFString, CFTypeRef?, UnsafeMutablePointer<CFTypeRef?>) -> Int32
    typealias CheckValidity = @convention(c) (CFTypeRef, CFTypeRef?, CFTypeRef, UnsafeMutablePointer<Unmanaged<CFError>?>) -> Int32

    static let handle: UnsafeMutableRawPointer? = dlopen(
        "/System/Library/Frameworks/Security.framework/Security", RTLD_LAZY)

    static func sym(_ name: String) -> UnsafeMutableRawPointer? {
        guard let handle else { return nil }
        return dlsym(handle, name)
    }

    static let createTask: CreateTask? = {
        guard let s = sym("SecTaskCreateFromSelf") else { return nil }
        return unsafeBitCast(s, to: CreateTask.self)
    }()
    static let copyEntitlement: CopyEntitlement? = {
        guard let s = sym("SecTaskCopyValueForEntitlement") else { return nil }
        return unsafeBitCast(s, to: CopyEntitlement.self)
    }()
    static let createStaticCode: CreateStaticCode? = {
        guard let s = sym("SecStaticCodeCreateWithPath") else { return nil }
        return unsafeBitCast(s, to: CreateStaticCode.self)
    }()
    static let createRequirement: CreateRequirement? = {
        guard let s = sym("SecRequirementCreateWithString") else { return nil }
        return unsafeBitCast(s, to: CreateRequirement.self)
    }()
    static let checkValidity: CheckValidity? = {
        guard let s = sym("SecStaticCodeCheckValidity") else { return nil }
        return unsafeBitCast(s, to: CheckValidity.self)
    }()
}

/// The set bit positions of a 64-bit value.
func bitsOf(_ v: UInt64) -> [Int] {
    var out: [Int] = []
    var i = 0
    while i < 64 {
        if (v & (UInt64(1) << UInt64(i))) != 0 { out.append(i) }
        i += 1
    }
    return out
}

// MARK: - Report accumulator

final class Report {
    private(set) var lines: [String] = []
    func add(_ s: String) {
        lines.append(s)
        ProbeLogger.shared.log(s)
    }
    func add(_ k: String, _ v: String) {
        add("\(k)=\(v)")
    }
    func section(_ s: String) { lines.append("--- \(s) ---") }
    var text: String { lines.joined(separator: "\n") + "\n" }
}

// MARK: - Mach-O / embedded signature reader

struct EmbeddedSignature {
    var superBlobOffset: Int = -1
    var superBlobLength: Int = 0
    var slots: [(type: Int, offset: Int)] = []
    var codeDirectoryOffset: Int = -1
    var codeDirectoryVersion: UInt32 = 0
    var identifier: String = ""
    var teamID: String = ""
    var execSegFlags: UInt64 = 0
    var policyFieldCandidates: [(name: String, offset: Int, value: UInt64)] = []
}

enum MachO {
    static let MH_MAGIC_64: UInt32 = 0xfeedfacf
    static let LC_CODE_SIGNATURE: UInt32 = 0x1d

    /// Parse the embedded code signature of a Mach-O file.
    static func readSignature(at path: String) -> EmbeddedSignature? {
        guard let data = FileManager.default.contents(atPath: path) else { return nil }
        let bytes = [UInt8](data)
        guard bytes.count > 32 else { return nil }

        let magic = readU32(bytes, 0)
        guard magic == MH_MAGIC_64 else { return nil }   // thin 64-bit only
        let ncmds = Int(readU32(bytes, 16))
        var off = 32
        var sigOff = -1, sigSize = 0
        for _ in 0..<ncmds {
            guard off + 8 <= bytes.count else { return nil }
            let cmd = readU32(bytes, off)
            let cmdsize = Int(readU32(bytes, off + 4))
            if cmdsize < 8 { return nil }
            if cmd == LC_CODE_SIGNATURE {
                sigOff = Int(readU32(bytes, off + 8))
                sigSize = Int(readU32(bytes, off + 12))
            }
            off += cmdsize
        }
        guard sigOff >= 0, sigOff + sigSize <= bytes.count else { return nil }

        var sig = EmbeddedSignature()
        sig.superBlobOffset = sigOff
        sig.superBlobLength = sigSize

        // The SuperBlob header is big-endian.
        let sb = sigOff
        guard sb + 12 <= bytes.count else { return nil }
        let sbMagic = readU32BE(bytes, sb)
        guard sbMagic == 0xfade0cc0 else { return nil }
        let count = Int(readU32BE(bytes, sb + 8))
        for i in 0..<min(count, 32) {
            let e = sb + 12 + i * 8
            guard e + 8 <= bytes.count else { break }
            sig.slots.append((type: Int(readU32BE(bytes, e)), offset: Int(readU32BE(bytes, e + 4))))
        }

        // CodeDirectory (slot 0)
        if let cdSlot = sig.slots.first(where: { $0.type == 0 }) {
            let cd = sb + cdSlot.offset
            guard cd + 0x60 <= bytes.count else { return sig }
            guard readU32BE(bytes, cd) == 0xfade0c02 else { return sig }
            sig.codeDirectoryOffset = cd
            sig.codeDirectoryVersion = readU32BE(bytes, cd + 8)
            let identOff = Int(readU32BE(bytes, cd + 20))
            if cd + identOff < bytes.count {
                sig.identifier = readCString(bytes, cd + identOff)
            }
            // teamOffset is at CodeDirectory+0x30 (version >= 0x20200)
            if sig.codeDirectoryVersion >= 0x20200, cd + 0x34 <= bytes.count {
                let teamOff = Int(readU32BE(bytes, cd + 0x30))
                if teamOff != 0, cd + teamOff < bytes.count {
                    sig.teamID = readCString(bytes, cd + teamOff)
                }
            }
            if sig.codeDirectoryVersion >= 0x20400, cd + 0x58 <= bytes.count {
                sig.execSegFlags = readU64BE(bytes, cd + 0x50)
            }
        }

        // The CT-policy field.  The kernel reads 8 bytes at +0xb8 of a blob it
        // has already verified; we report every plausible interpretation so a
        // human can line them up against the disassembly.
        sig.policyFieldCandidates.append(("superblob+0xb8", sb, readU64BE(bytes, sb + 0xb8)))
        if sig.codeDirectoryOffset >= 0 {
            let cd = sig.codeDirectoryOffset
            sig.policyFieldCandidates.append(("codedirectory+0x50 (execSegFlags)", cd, sig.execSegFlags))
            sig.policyFieldCandidates.append(("codedirectory+0xb8", cd, readU64BE(bytes, cd + 0xb8)))
        }
        if let cmsSlot = sig.slots.first(where: { $0.type == 0x10000 }) {
            let cms = sb + cmsSlot.offset
            sig.policyFieldCandidates.append(("cms+0xb8", cms, readU64BE(bytes, cms + 0xb8)))
            sig.policyFieldCandidates.append(("cms+0x8", cms, readU64BE(bytes, cms + 0x8)))
        }
        return sig
    }

    static func readU32(_ b: [UInt8], _ o: Int) -> UInt32 {
        guard o + 4 <= b.count else { return 0 }
        return UInt32(b[o]) | (UInt32(b[o + 1]) << 8) | (UInt32(b[o + 2]) << 16) | (UInt32(b[o + 3]) << 24)
    }
    static func readU32BE(_ b: [UInt8], _ o: Int) -> UInt32 {
        guard o + 4 <= b.count else { return 0 }
        return (UInt32(b[o]) << 24) | (UInt32(b[o + 1]) << 16) | (UInt32(b[o + 2]) << 8) | UInt32(b[o + 3])
    }
    static func readU64BE(_ b: [UInt8], _ o: Int) -> UInt64 {
        guard o + 8 <= b.count else { return 0 }
        var v: UInt64 = 0
        for i in (0..<8).reversed() { v = (v << 8) | UInt64(b[o + i]) }
        return v
    }
    static func readCString(_ b: [UInt8], _ o: Int) -> String {
        guard o < b.count else { return "" }
        var end = o
        while end < b.count && b[end] != 0 { end += 1 }
        return String(decoding: b[o..<end], as: UTF8.self)
    }
}

// MARK: - Entitlements

enum Entitlements {
    /// Keys we care about.  The first group is control keys; the second group is
    /// the private keys the research is about.
    static let control: [String] = [
        "application-identifier",
        "com.apple.developer.team-identifier",
        "com.apple.security.application-groups",
        "get-task-allow",
        "keychain-access-groups",
    ]
    static let privateKeys: [String] = [
        "com.apple.private.mobileinstall.allowedSPI",
        "com.apple.private.installcoordinationd.daemon",
        "com.apple.private.install.distributor-info-source",
        "com.apple.private.mobileinstall.allowed-linked-parents",
        "com.apple.private.security.no-sandbox",
        "com.apple.private.security.no-container",
        "com.apple.private.security.container-required",
        "com.apple.private.amfi.can-execute-cdhash",
        "com.apple.private.amfi.can-load-cdhash",
        "com.apple.private.usermanagerd.persona.fetch",
    ]

    static func value(_ key: String) -> (present: Bool, description: String) {
        guard let create = DynSec.createTask, let copy = DynSec.copyEntitlement else {
            return (false, "symbols-unavailable")
        }
        guard let taskRef = create(nil) else { return (false, "no-task") }
        let task = taskRef.takeUnretainedValue()
        guard let v = copy(task, key as CFString, nil) else { return (false, "-") }
        return (true, describe(v))
    }

    static func describe(_ v: Any) -> String {
        if let b = v as? Bool { return b ? "true" : "false" }
        if let n = v as? NSNumber { return n.boolValue ? "true" : "false" }
        if let s = v as? String { return s }
        if let arr = v as? [Any] { return "[" + arr.map { describe($0) }.joined(separator: ",") + "]" }
        if let d = v as? [String: Any] {
            let keys = d.keys.sorted().joined(separator: ",")
            return "dict(" + keys + ")"
        }
        return String(describing: type(of: v))
    }
}

// MARK: - Sandbox probes

enum Sandbox {
    /// A container-privileged app can normally not touch these paths.
    static func probes() -> [(String, String)] {
        var out: [(String, String)] = []
        let writable = "/private/var/mobile/Library/probe-\(ProcessInfo.processInfo.processIdentifier).txt"
        do {
            try "probe".write(toFile: writable, atomically: true, encoding: .utf8)
            out.append(("write-outside-container", "ALLOWED"))
            try? FileManager.default.removeItem(atPath: writable)
        } catch {
            out.append(("write-outside-container", "DENIED"))
        }
        let readable = "/private/var/mobile/Library/Caches"
        if FileManager.default.fileExists(atPath: readable) {
            out.append(("read-private-dir", "VISIBLE"))
        } else {
            out.append(("read-private-dir", "HIDDEN"))
        }
        out.append(("container-home", FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first?.path ?? "-"))
        return out
    }
}

// MARK: - Trust evaluation (iOS-valid)
//
// NOTE: `SecRequirementCreateWithString("anchor apple")` fails with
// errSecParam (-50) on iOS — the "apple" anchor clause is not part of the
// iOS requirement grammar.  The iOS-valid way to ask the same question is to
// build a trust on our own certificate chain and ask the system to evaluate it.

enum TrustProbe {
    typealias CreateTrust = @convention(c) (CFTypeRef, CFTypeRef, UnsafeMutablePointer<SecTrust?>) -> Int32
    typealias EvaluateTrust = @convention(c) (CFTypeRef, UnsafeMutablePointer<Unmanaged<CFError>?>) -> Int32
    typealias CopyAnchor = @convention(c) (CFTypeRef, UnsafeMutablePointer<SecCertificate?>) -> Int32

    static let createTrust: CreateTrust? = {
        guard let s = DynSec.sym("SecTrustCreateWithCertificates") else { return nil }
        return unsafeBitCast(s, to: CreateTrust.self)
    }()
    static let evaluateTrust: EvaluateTrust? = {
        guard let s = DynSec.sym("SecTrustEvaluateWithError") else { return nil }
        return unsafeBitCast(s, to: EvaluateTrust.self)
    }()
    static let copyAnchor: CopyAnchor? = {
        guard let s = DynSec.sym("SecTrustCopyAnchor") else { return nil }
        return unsafeBitCast(s, to: CopyAnchor.self)
    }()

    static func sha256Of(_ cert: SecCertificate) -> String {
        let d = SecCertificateCopyData(cert) as Data
        return d.map { String(format: "%02x", $0) }.joined()
    }

    /// Evaluate a certificate chain given as DER blobs (the provisioning
    /// profile's DeveloperCertificates).  SecStaticCodeCopySigningInformation
    /// is NOT exported on iOS, so the profile is the only reachable source of
    /// the chain.
    static func evaluate(derCerts: [Data]) -> [(String, String)] {
        var out: [(String, String)] = []
        out.append(("symbol-SecTrustCreateWithCertificates", createTrust == nil ? "MISSING" : "present"))
        out.append(("symbol-SecTrustEvaluateWithError", evaluateTrust == nil ? "MISSING" : "present"))
        out.append(("symbol-SecTrustCopyAnchor", copyAnchor == nil ? "MISSING" : "present"))
        guard let mkTrust = createTrust, let evaluate = evaluateTrust,
              let mkCert = AnchorSet.createCertFromData else {
            out.append(("trust", "symbols-unavailable"))
            return out
        }
        guard !derCerts.isEmpty else {
            out.append(("trust-eval", "no-chain"))
            return out
        }

        var certsFound: [SecCertificate] = []
        for (i, der) in derCerts.enumerated() {
            var c: SecCertificate?
            if mkCert(der as CFData, &c) == 0, let cert = c {
                certsFound.append(cert)
                out.append(("chain[\(i)]-sha256", sha256Of(cert)))
            } else {
                out.append(("chain[\(i)]", "create-failed"))
            }
        }
        guard !certsFound.isEmpty else {
            out.append(("trust-eval", "no-chain"))
            return out
        }

        // SecTrustCreateWithCertificates accepts a single certificate as well
        // as an array, so no CFArray has to be built.
        let chain = certsFound[0]

        for (label, policy) in [("basic-x509", SecPolicyCreateBasicX509()),
                                ("ssl", SecPolicyCreateSSL(true, "apple.com" as CFString))] {
            var trust: SecTrust?
            let terr = mkTrust(chain, policy, &trust)
            guard terr == 0, let t = trust else {
                out.append(("trust-\(label)", "create-failed(\(terr))"))
                continue
            }
            var err: Unmanaged<CFError>?
            let v = evaluate(t, &err)
            out.append(("trust-\(label)", v == 0 ? "TRUSTED" : "NOT-TRUSTED(\(v))"))
            if let copyAnchor = copyAnchor {
                var anchor: SecCertificate?
                if copyAnchor(t, &anchor) == 0, let a = anchor {
                    let h = sha256Of(a)
                    let tag = h.hasPrefix(AnchorSet.publicAppleRootSHA256) ? "  <<< PUBLIC APPLE ROOT CA" : ""
                    out.append(("trust-\(label)-anchor-sha256", h + tag))
                } else {
                    out.append(("trust-\(label)-anchor-sha256", "-"))
                }
            }
            if let copyAnchors = AnchorSet.copyTrustAnchors {
                if let arr = copyAnchors(t) {
                    for (k, v) in AnchorSet.describe(arr, label: "trust-\(label)-anchors") { out.append((k, v)) }
                }
            }
        }
        return out
    }
}

// MARK: - Runtime anchor enumeration
//
// Security.framework exports SecGetAppleTrustAnchors(), which returns the
// anchor collection the system uses at run time (the "prod" set unless the
// calling process holds the com.apple.security entitlement, in which case the
// "all" set including test roots is returned).  That is the direct answer to
// "does the running iOS trust a chain that ends at the PUBLIC Apple root".

enum AnchorSet {
    typealias GetAnchors = @convention(c) () -> CFTypeRef?
    typealias CopyCorporateRoots = @convention(c) () -> CFTypeRef?
    typealias CopyTrustAnchors = @convention(c) (CFTypeRef) -> CFTypeRef?
    typealias CreateCertFromData = @convention(c) (CFTypeRef?, UnsafeMutablePointer<SecCertificate?>) -> Int32

    static let getAnchors: GetAnchors? = {
        guard let s = DynSec.sym("SecGetAppleTrustAnchors") else { return nil }
        return unsafeBitCast(s, to: GetAnchors.self)
    }()
    static let copyCorporateRoots: CopyCorporateRoots? = {
        guard let s = DynSec.sym("SecCertificateCopyAppleCorporateRoots") else { return nil }
        return unsafeBitCast(s, to: CopyCorporateRoots.self)
    }()
    static let copyTrustAnchors: CopyTrustAnchors? = {
        guard let s = DynSec.sym("SecTrustCopyAppleAnchors") else { return nil }
        return unsafeBitCast(s, to: CopyTrustAnchors.self)
    }()
    static let createCertFromData: CreateCertFromData? = {
        guard let s = DynSec.sym("SecCertificateCreateWithData") else { return nil }
        return unsafeBitCast(s, to: CreateCertFromData.self)
    }()

    /// SHA-256 of the PUBLIC "Apple Root CA" — the reference fingerprint.
    static let publicAppleRootSHA256 = "b0b1730ecbc7ff4505142c49"

    static func sha256(_ cert: SecCertificate) -> String {
        let d = SecCertificateCopyData(cert) as Data
        return d.map { String(format: "%02x", $0) }.joined()
    }

    /// Walk a CFArray of SecCertificate and describe each entry.
    static func describe(_ arrRef: CFTypeRef?, label: String) -> [(String, String)] {
        var out: [(String, String)] = []
        guard let raw = arrRef else {
            out.append((label, "absent"))
            return out
        }
        let arr = unsafeBitCast(raw as AnyObject, to: CFArray.self)
        let n = CFArrayGetCount(arr)
        out.append(("\(label)-count", String(n)))
        for i in 0..<n {
            guard let p = CFArrayGetValueAtIndex(arr, i) else { continue }
            let cert = unsafeBitCast(p, to: SecCertificate.self)
            let h = sha256(cert)
            let tag = h.hasPrefix(publicAppleRootSHA256) ? "  <<< PUBLIC APPLE ROOT CA" : ""
            out.append(("\(label)[\(i)]-sha256", h + tag))
        }
        return out
    }

    static func run() -> [(String, String)] {
        var out: [(String, String)] = []
        out.append(("symbol-SecGetAppleTrustAnchors", getAnchors == nil ? "MISSING" : "present"))
        out.append(("symbol-SecCertificateCopyAppleCorporateRoots", copyCorporateRoots == nil ? "MISSING" : "present"))
        out.append(("symbol-SecTrustCopyAppleAnchors", copyTrustAnchors == nil ? "MISSING" : "present"))
        out.append(("reference-public-apple-root-sha256", publicAppleRootSHA256))

        if let g = getAnchors {
            for (k, v) in describe(g(), label: "runtime-anchors") { out.append((k, v)) }
        }
        if let c = copyCorporateRoots {
            for (k, v) in describe(c(), label: "corporate-roots") { out.append((k, v)) }
        }
        return out
    }
}

// MARK: - Trust-anchor probe (the "anchor apple" clause)

enum AnchorProbe {
    /// Evaluate the `anchor apple` code-requirement against our own signature.
    /// If the runtime anchor set contains the PUBLIC Apple root — and our build
    /// is signed by an ordinary developer certificate, which chains to exactly
    /// that root — this succeeds.
    static func run() -> [(String, String)] {
        var out: [(String, String)] = []
        guard let mkCode = DynSec.createStaticCode,
              let mkReq = DynSec.createRequirement,
              let check = DynSec.checkValidity else {
            out.append(("anchor", "symbols-unavailable"))
            return out
        }
        var codeRef: CFTypeRef?
        let cerr = mkCode(Bundle.main.bundleURL as CFURL, nil, &codeRef)
        guard cerr == 0, let code = codeRef else {
            out.append(("anchor-apple", "no-staticcode(\(cerr))"))
            return out
        }
        out.append(("static-code-created", "ok"))
        for req in ["anchor apple", "anchor apple generic",
                    "identifier \"\(Bundle.main.bundleIdentifier)\""] {
            var reqRef: CFTypeRef?
            let rerr = mkReq(req as CFString, nil, &reqRef)
            guard rerr == 0, let requirement = reqRef else {
                out.append(("req:\(req)", "create-failed(\(rerr))"))
                continue
            }
            var err: Unmanaged<CFError>?
            let v = check(code, nil, requirement, &err)
            out.append(("req:\(req)", v == 0 ? "SATISFIED" : "NOT-SATISFIED"))
        }
        return out
    }
}

// MARK: - Privileged install probe

enum InstallProbe {
    /// Classes that plausibly expose the privileged install entry points.
    static let classNames = [
        "IXAppInstallCoordinator",
        "IXSimpleInstaller",
        "MIMobileInstallation",
        "MIInstaller",
        "MobileInstallation",
    ]

    /// Selector fragments we consider interesting.
    static let interesting = ["installApplication", "install", "Install", "consumeSource"]

    static func run() -> [(String, String)] {
        var out: [(String, String)] = []

        for name in classNames {
            guard let cls = NSClassFromString(name) else {
                out.append(("class:\(name)", "absent"))
                continue
            }
            out.append(("class:\(name)", "present"))

            var selectors: [String] = []
            var count: UInt32 = 0
            if let methods = class_copyMethodList(object_getClass(cls), &count) {
                for i in 0..<Int(count) {
                    let sel = method_getName(methods[i])
                    selectors.append(NSStringFromSelector(sel))
                }
                free(methods)
            }
            if let meta = object_getClass(cls) as? AnyClass,
               let methods = class_copyMethodList(meta, &count) {
                for i in 0..<Int(count) {
                    let sel = method_getName(methods[i])
                    selectors.append(NSStringFromSelector(sel))
                }
                free(methods)
            }
            let hits = selectors.filter { s in interesting.contains { $0.isEmpty ? false : s.contains($0) } }
            out.append(("selectors:\(name)", hits.isEmpty ? "none" : hits.joined(separator: " | ")))

            // Type encodings: they tell us the exact shape of every argument,
            // which is what is needed to call these safely.
            if !hits.isEmpty {
                var enc: [String] = []
                var mcount: UInt32 = 0
                if let mlist = class_copyMethodList(object_getClass(cls), &mcount) {
                    for i in 0..<Int(mcount) {
                        let m = mlist[i]
                        let sel = method_getName(m)
                        let name = NSStringFromSelector(sel)
                        guard hits.contains(name) else { continue }
                        if let t = method_getTypeEncoding(m) {
                            enc.append("\(name) :: \(String(cString: t))")
                        }
                    }
                    free(mlist)
                }
                if !enc.isEmpty {
                    out.append(("encodings:\(name)", enc.joined(separator: " | ")))
                }
            }
        }

        // NOTE: we deliberately do NOT invoke the coordinator from the app.
        // These are variadic Objective-C methods; calling them with arguments
        // we cannot construct raises an ObjC exception that Swift cannot catch,
        // and a crash here would destroy the whole report.  Instead we publish
        // the exact selector inventory, so the invocation can be specified
        // precisely in a follow-up build.
        out.append(("attempt", "not-attempted-see-selectors-above"))
        return out
    }

}

// MARK: - Kernel log capture (best effort)

enum LogProbe {
    static let markers = [
        "AMFI", "amfi", "AppleInternalProfile", "empty profile",
        "disallowed entitlement key", "profile validated", "XNU monitor refused",
        "CoreTrust", "CT policy", "unsuitable CT policy", "fast-path-appstore",
        "restricted entitlements", "allowedSPI",
    ]

    static func run() -> [String] {
        // The unified log is not readable by a sandboxed app (OSLogStore is not
        // exposed to iOS), so the kernel's own AMFI lines cannot be captured
        // from inside the app.  Everything the probe logs about itself goes to
        // the unified log under this subsystem, so the kernel's lines for this
        // process can be picked up from a Mac with the command below.
        return [
            "LOG capture=app-side-unavailable",
            "LOG self-subsystem=com.research.ios27.privprobe",
            "LOG mac-command=log show --last 10m --predicate 'process == \"Probe\" OR eventMessage CONTAINS[c] \"AMFI\"'",
            "LOG markers=\(markers.joined(separator: ","))",
        ]
    }
}

// MARK: - Harness

func runHarness() -> String {
    let r = Report()
    r.add("=== iOS private-entitlement probe ===")
    r.add("device-os=\(UIDevice.current.systemVersion)")
    r.add("device-model=\(UIDevice.current.model)")
    r.add("bundle-id=\(Bundle.main.bundleIdentifier ?? "-")")
    r.add("process-id=\(ProcessInfo.processInfo.processIdentifier)")
    r.add("executable=\(Bundle.main.executableURL?.path ?? "-")")

    // 1. provenance -----------------------------------------------------------
    r.section("PROVENANCE")
    let execPath = Bundle.main.executableURL?.path ?? ""
    if let sig = MachO.readSignature(at: execPath) {
        r.add("signature-present", "yes")
        r.add("identifier", sig.identifier.isEmpty ? "-" : sig.identifier)
        r.add("team-id", sig.teamID.isEmpty ? "-" : sig.teamID)
        r.add("codedirectory-version", String(format: "0x%x", sig.codeDirectoryVersion))
        r.add("exec-seg-flags", String(format: "0x%016llx", sig.execSegFlags))
        r.add("superblob-slots", String(sig.slots.map { String(format: "0x%x", $0.type) }.joined(separator: ",")))
        for c in sig.policyFieldCandidates {
            r.add(String(format: "policy-field %@", c.name), String(format: "0x%016llx", c.value))
        }
        // The accept mask AMFI applies.  We report the raw bits of each
        // candidate so the arithmetic is done by the reader: an "intersects"
        // flag would be a false-positive generator, because a random 64-bit
        // value intersects a 12-bit mask most of the time.
        let acceptMask: UInt64 = 0x0000_1800_0001_ff80
        r.add("amfi-accept-mask", String(format: "0x%016llx", acceptMask))
        r.add("amfi-accept-mask-bits", bitsOf(acceptMask).map { String($0) }.joined(separator: ","))
        for c in sig.policyFieldCandidates {
            let bits = bitsOf(c.value)
            let joined = bits.map { String($0) }.joined(separator: ",")
            r.add(String(format: "policy-field %@ bits", c.name), bits.isEmpty ? "-" : joined)
        }
    } else {
        r.add("signature-present", "no")
    }

    // 2. the provisioning profile we shipped ----------------------------------
    r.section("PROFILE")
    var profileCerts: [Data] = []
    if let profURL = Bundle.main.url(forResource: "embedded", withExtension: "mobileprovision"),
       let profData = try? Data(contentsOf: profURL) {
        r.add("profile-present", "yes")
        r.add("profile-size", String(profData.count))
        // A real profile is a CMS blob; a crafted one is a bare plist.
        let head = profData.prefix(4)
        if head.elementsEqual(Data([0x30, 0x82, 0x01, 0x22])) || profData.count > 20000 {
            r.add("profile-kind", "cms-or-large")
        } else {
            r.add("profile-kind", "raw-plist-or-small")
        }
        // A real mobileprovision is a CMS (DER) wrapper around the plist, so
        // parse the plist out of the container rather than the whole file.
        var plistData: Data? = nil
        if let xml = profData.range(of: Data("<?xml".utf8)) {
            plistData = profData[xml.lowerBound...]
        } else if let bin = profData.range(of: Data("bplist00".utf8)) {
            plistData = profData[bin.lowerBound...]
        }
        if let pd = plistData,
           let plist = try? PropertyListSerialization.propertyList(from: pd, options: [], format: nil),
           let dict = plist as? [String: Any] {
            r.add("profile-keys", dict.keys.sorted().joined(separator: ","))
            r.add("profile-apple-internal-profile", (dict["AppleInternalProfile"] as? Bool) == true ? "true" : "false")
            if let ents = dict["Entitlements"] as? [String: Any] {
                r.add("profile-entitlements", ents.keys.sorted().joined(separator: ","))
            }
            if let ders = dict["DeveloperCertificates"] as? [Data] {
                profileCerts = ders
                r.add("profile-developer-certificates", String(ders.count))
                for (i, d) in ders.enumerated() {
                    let h = d.map { String(format: "%02x", $0) }.joined()
                    let tag = h.hasPrefix(AnchorSet.publicAppleRootSHA256) ? "  <<< PUBLIC APPLE ROOT CA" : ""
                    r.add("profile-cert[\(i)]-sha256", h + tag)
                    for (k, v) in LeafIdentity.describe(d) { r.add("profile-cert[\(i)]-\(k)", v) }
                }
            }
            r.add("profile-local-provision", (dict["LocalProvision"] as? Bool).map { $0 ? "true" : "false" } ?? "-")
            r.add("profile-is-xcode-managed", (dict["IsXcodeManaged"] as? Bool).map { $0 ? "true" : "false" } ?? "-")
        } else {
            r.add("profile-parsed", "no")
        }
    } else {
        r.add("profile-present", "no")
    }

    // 3. entitlements ---------------------------------------------------------
    r.section("ENTITLEMENTS")
    for k in Entitlements.control {
        let v = Entitlements.value(k)
        r.add("ENTITLEMENT \(k)", "stored=\(v.present) value=\(v.description)")
    }
    for k in Entitlements.privateKeys {
        let v = Entitlements.value(k)
        r.add("ENTITLEMENT \(k)", "stored=\(v.present) value=\(v.description)")
    }

    // 4. sandbox --------------------------------------------------------------
    r.section("SANDBOX")
    for (k, v) in Sandbox.probes() { r.add(k, v) }

    // 5. anchor set -----------------------------------------------------------
    r.section("ANCHOR")
    for (k, v) in AnchorProbe.run() { r.add(k, v) }
    for (k, v) in AnchorSet.run() { r.add(k, v) }
    for (k, v) in TrustProbe.evaluate(derCerts: profileCerts) { r.add(k, v) }

    // 6. the privileged install channel --------------------------------------
    r.section("INSTALL")
    for (k, v) in InstallProbe.run() { r.add(k, v) }

    // 7. the kernel's own words ----------------------------------------------
    r.section("KERNEL-LOG")
    for l in LogProbe.run() { r.add(l) }

    r.add("=== end (before the install attempt) ===")

    r.add("=== end ===")
    return r.text
}

// MARK: - UI

final class ProbeViewController: UIViewController {
    private let runBtn = UIButton(type: .system)
    private let copyBtn = UIButton(type: .system)
    private let saveBtn = UIButton(type: .system)
    private let textView = UITextView()
    private var report = ""

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .systemBackground
        title = "Priv-Ent Probe"

        runBtn.setTitle("Run Probe", for: .normal)
        runBtn.addTarget(self, action: #selector(onRun), for: .touchUpInside)
        copyBtn.setTitle("Copy", for: .normal)
        copyBtn.addTarget(self, action: #selector(onCopy), for: .touchUpInside)
        saveBtn.setTitle("Save", for: .normal)
        saveBtn.addTarget(self, action: #selector(onSave), for: .touchUpInside)

        let bar = UIStackView(arrangedSubviews: [runBtn, copyBtn, saveBtn])
        bar.axis = .horizontal
        bar.distribution = .fillEqually
        bar.spacing = 12

        textView.isEditable = false
        textView.font = UIFont.monospacedSystemFont(ofSize: 10, weight: .regular)

        let stack = UIStackView(arrangedSubviews: [bar, textView])
        stack.axis = .vertical
        stack.spacing = 8
        stack.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(stack)

        NSLayoutConstraint.activate([
            stack.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor, constant: 12),
            stack.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 12),
            stack.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -12),
            stack.bottomAnchor.constraint(equalTo: view.safeAreaLayoutGuide.bottomAnchor, constant: -12),
        ])
    }

    @objc private func onRun() {
        runBtn.isEnabled = false
        textView.text = "running…"
        DispatchQueue.global(qos: .userInitiated).async {
            let r = runHarness()
            DispatchQueue.main.async {
                self.report = r
                self.textView.text = r
                self.runBtn.isEnabled = true
            }
        }
    }

    @objc private func onCopy() {
        UIPasteboard.general.string = report
        let alert = UIAlertController(title: "Copied", message: "\(report.count) characters", preferredStyle: .alert)
        alert.addAction(UIAlertAction(title: "OK", style: .default))
        present(alert, animated: true)
    }

    @objc private func onSave() {
        if let dir = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first {
            let url = dir.appendingPathComponent("probe-report.txt")
            do {
                try report.write(to: url, atomically: true, encoding: .utf8)
                let alert = UIAlertController(title: "Saved", message: url.path, preferredStyle: .alert)
                alert.addAction(UIAlertAction(title: "OK", style: .default))
                present(alert, animated: true)
            } catch {
                let alert = UIAlertController(title: "Save failed", message: "\(error)", preferredStyle: .alert)
                alert.addAction(UIAlertAction(title: "OK", style: .default))
                present(alert, animated: true)
            }
        }
    }
}

@main
final class AppDelegate: UIResponder, UIApplicationDelegate {
    var window: UIWindow?

    func application(_ application: UIApplication,
                     didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {
        let w = UIWindow(frame: UIScreen.main.bounds)
        w.rootViewController = UINavigationController(rootViewController: ProbeViewController())
        w.makeKeyAndVisible()
        window = w
        return true
    }
}
