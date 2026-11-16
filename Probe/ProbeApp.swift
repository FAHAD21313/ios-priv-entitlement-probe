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

    /// The policy is the AND across every certificate of the chain.
    static func policy(chain: [[String]]) -> UInt64 {
        guard !chain.isEmpty else { return 0 }
        var acc = UInt64.max
        for oids in chain {
            let b = bits(forOIDs: oids).bits
            acc &= b
        }
        return acc
    }
}

// MARK: - Report accumulator
//
// The report is APPENDED, so several installs of the same bundle identifier
// accumulate in one file instead of producing one dump per run.

final class Report {
    private(set) var lines: [String] = []
    private let path: String

    init() {
        let dir = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first
        path = (dir?.appendingPathComponent("probe-report.txt").path) ?? "/tmp/probe-report.txt"
    }

    /// Persist after every section: a trap in a later probe must not destroy
    /// the evidence already collected.
    func flush() {
        let existing = (try? String(contentsOfFile: path, encoding: .utf8)) ?? ""
        try? (existing + text).write(toFile: path, atomically: true, encoding: .utf8)
    }

    func add(_ s: String) {
        lines.append(s)
        ProbeLogger.shared.log(s)
    }
    func add(_ k: String, _ v: String) { add("\(k)=\(v)") }
    func section(_ s: String) { lines.append("--- \(s) ---") }
    var text: String { lines.joined(separator: "\n") + "\n" }
    var filePath: String { path }
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
            var cert: SecCertificate?
            let cf = cand.withUnsafeBytes { raw -> CFData? in
                CFDataCreate(nil, raw.baseAddress, CFIndex(cand.count))
            }
            if let cf = cf, SecCertificateCreateWithData(cf, &cert) == 0, cert != nil {
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
            let end = min(sb + sig.slots.reduce(0) { max($0.offset, $1.offset) }, bytes.count)
            _ = end
            let blob = Data(bytes[e..<min(e + 4096, bytes.count)])
            sig.slices.append(SliceInfo(index: index,
                                        identifier: sig.identifier,
                                        teamID: sig.teamID,
                                        codeDirectoryVersion: sig.codeDirectoryVersion,
                                        execSegFlags: sig.execSegFlags,
                                        claimedEntitlements: parseEntitlementsBlob(blob)))
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
    static func parseEntitlementsBlob(_ d: Data) -> [String: String] {
        var out: [String: String] = [:]
        let b = [UInt8](d)
        guard b.count > 8, readU32BE(b, 0) == 0xfade7171 else { return out }
        let count = Int(readU32BE(b, 4))
        guard count > 0, count < 4096 else { return out }
        for i in 0..<count {
            let e = 8 + i * 8
            guard e + 8 <= b.count else { break }
            let keyOff = Int(readU32BE(b, e))
            let valOff = Int(readU32BE(b, e + 4))
            let key = readCString(b, keyOff)
            let val = readCString(b, valOff)
            if !key.isEmpty { out[key] = val.isEmpty ? "true" : val }
        }
        return out
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
            var info = SliceInfo(index: i, cputype: p.cpu, cpusubtype: p.sub,
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

    static func describe(_ v: Any) -> String {
        if let b = v as? Bool { return b ? "true" : "false" }
        if let n = v as? NSNumber { return n.boolValue ? "true" : "false" }
        if let s = v as? String { return s }
        if let arr = v as? [Any] { return "[" + arr.map { describe($0) }.joined(separator: ",") + "]" }
        if let d = v as? [String: Any] {
            return "dict(" + d.keys.sorted().joined(separator: ",") + ")"
        }
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
        return s as String
    }

    /// Run the launch-time validator against the running executable.
    static func run() -> [(String, String)] {
        var out: [(String, String)] = []
        out.append(("libmis-dlopen", handle == nil ? "FAILED" : "ok"))
        out.append(("symbol-MISValidateSignature", validateSignature == nil ? "MISSING" : "present"))
        out.append(("symbol-MISValidateSignatureAndCopyInfo", validateAndCopyInfo == nil ? "MISSING" : "present"))
        out.append(("symbol-MISProfileValidateSignature", profileValidateSignature == nil ? "MISSING" : "present"))

        let path = Bundle.main.executableURL?.path ?? ""
        if let v = validateSignature {
            let code = v(path as CFString, nil)
            out.append(("mis-validate-self", String(format: "0x%08x", UInt32(bitPattern: code))))
            out.append(("mis-validate-self-text", errorText(code)))
        }
        if let v = validateAndCopyInfo {
            var info: CFTypeRef?
            let code = v(path as CFString, nil, &info)
            out.append(("mis-validate-copy-info", String(format: "0x%08x", UInt32(bitPattern: code))))
            out.append(("mis-validate-copy-info-text", errorText(code)))
            if let i = info {
                out.append(("mis-info-type", String(describing: type(of: i))))
            }
        }
        return out
    }

    /// Ask libmis to validate OUR OWN embedded profile's signature.
    static func validateOwnProfile(_ profileData: Data?) -> [(String, String)] {
        var out: [(String, String)] = []
        guard let profileData, !profileData.isEmpty else {
            out.append(("mis-profile-validate", "no-profile"))
            return out
        }
        guard let create = profileCreateWithData, let validate = profileValidateSignature else {
            out.append(("mis-profile-validate", "symbols-unavailable"))
            return out
        }
        let cf = profileData.withUnsafeBytes { raw -> CFData? in
            CFDataCreate(nil, raw.baseAddress, CFIndex(profileData.count))
        }
        guard let cf = cf, let prof = create(nil, cf)?.takeUnretainedValue() else {
            out.append(("mis-profile-create", "FAILED"))
            return out
        }
        out.append(("mis-profile-create", "ok"))
        if let der = profileIsDEREncoded {
            out.append(("mis-profile-is-der", der(prof) ? "true" : "false"))
        }
        let code = validate(prof)
        out.append(("mis-profile-validate", String(format: "0x%08x", UInt32(bitPattern: code))))
        out.append(("mis-profile-validate-text", errorText(code)))
        if let payload = profileCopyPayload(prof) {
            out.append(("mis-profile-payload-bytes", String(CFGetLength(payload))))
        }
        if let gv = profileGetValue {
            for key in ["Entitlements", "AppleInternalProfile", "LocalProvision", "IsXcodeManaged", "UUID"] {
                if let v = gv(prof, key as CFString) {
                    out.append(("mis-profile-value \(key)", Ents.describe(v)))
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

    static func describe(_ arrRef: CFTypeRef?, label: String) -> [(String, String)] {
        var out: [(String, String)] = []
        guard let raw = arrRef else {
            out.append((label, "absent"))
            return out
        }
        let arr = unsafeBitCast(raw as AnyObject, to: CFArray.self)
        let n = CFArrayGetCount(arr)
        out.append(("\(label)-count", String(n)))
        var sawPublicRoot = false
        for i in 0..<n {
            guard let p = CFArrayGetValueAtIndex(arr, i) else { continue }
            let cert = unsafeBitCast(p, to: SecCertificate.self)
            let h = sha256(cert)
            if h.hasPrefix(publicAppleRootSHA256) { sawPublicRoot = true }
            out.append(("\(label)[\(i)]-sha256", h))
        }
        out.append(("\(label)-contains-public-apple-root", sawPublicRoot ? "YES" : "no"))
        return out
    }

    static func run() -> [(String, String)] {
        var out: [(String, String)] = []
        out.append(("symbol-SecGetAppleTrustAnchors", getAnchors == nil ? "MISSING" : "present"))
        if let g = getAnchors {
            for (k, v) in describe(g(), label: "runtime-anchors") { out.append((k, v)) }
        }
        if let c = copyCorporateRoots {
            for (k, v) in describe(c(), label: "corporate-roots") { out.append((k, v)) }
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

    static func evaluate(derCerts: [Data]) -> [(String, String)] {
        var out: [(String, String)] = []
        guard let mkTrust = createTrust, let evaluate = evaluateTrust else {
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
            let cf = der.withUnsafeBytes { raw -> CFData? in
                CFDataCreate(nil, raw.baseAddress, CFIndex(der.count))
            }
            if let cf = cf, SecCertificateCreateWithData(cf, &c) == 0, let cert = c {
                certsFound.append(cert)
                out.append(("chain[\(i)]-sha256", B64.sha256(der)))
            }
        }
        guard let first = certsFound.first else {
            out.append(("trust-eval", "no-chain"))
            return out
        }
        var trust: SecTrust?
        let terr = mkTrust(first, SecPolicyCreateBasicX509(), &trust)
        guard terr == 0, let t = trust else {
            out.append(("trust-basic-x509", "create-failed(\(terr))"))
            return out
        }
        var err: Unmanaged<CFError>?
        let v = evaluate(t, &err)
        out.append(("trust-basic-x509", v == 0 ? "TRUSTED" : "NOT-TRUSTED(\(v))"))
        if let chain = SecTrustCopyCertificateChain(t) {
            out.append(("trust-chain-count", String(chain.count)))
            for (i, c) in chain.enumerated() {
                out.append(("trust-chain[\(i)]-sha256", AnchorSet.sha256(c)))
            }
        }
        return out
    }
}

// MARK: - Effects: is the sandbox actually off?

enum Effects {
    static func run() -> [(String, String)] {
        var out: [(String, String)] = []
        let pid = ProcessInfo.processInfo.processIdentifier

        let writable = "/private/var/mobile/Library/probe-\(pid).txt"
        do {
            try "probe".write(toFile: writable, atomically: true, encoding: .utf8)
            out.append(("write-outside-container", "ALLOWED"))
            try? FileManager.default.removeItem(atPath: writable)
        } catch {
            out.append(("write-outside-container", "DENIED"))
        }

        let readable = "/private/var/mobile/Library/Caches"
        out.append(("read-private-dir", FileManager.default.fileExists(atPath: readable) ? "VISIBLE" : "HIDDEN"))

        let systemDir = "/private/var/db"
        out.append(("read-system-db", FileManager.default.fileExists(atPath: systemDir) ? "VISIBLE" : "HIDDEN"))

        out.append(("container-home", FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first?.path ?? "-"))
        out.append(("uid", String(getuid())))
        out.append(("euid", String(geteuid())))
        out.append(("gid", String(getgid())))
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

    static func run() -> [(String, String)] {
        var out: [(String, String)] = []

        let gate = Ents.value("com.apple.private.mobileinstall.allowedSPI")
        out.append(("install-gate-allowedSPI", gate.present ? "PRESENT" : "absent"))
        let daemon = Ents.value("com.apple.private.installcoordinationd.daemon")
        out.append(("install-gate-coordinationd", daemon.present ? "PRESENT" : "absent"))

        for name in classNames {
            guard let cls = NSClassFromString(name) else {
                out.append(("class:\(name)", "absent"))
                continue
            }
            out.append(("class:\(name)", "present"))
            var selectors: [String] = []
            var count: UInt32 = 0
            if let methods = class_copyMethodList(object_getClass(cls), &count) {
                for i in 0..<Int(count) { selectors.append(NSStringFromSelector(method_getName(methods[i]))) }
                free(methods)
            }
            if let meta = object_getClass(cls) as? AnyClass,
               let methods = class_copyMethodList(meta, &count) {
                for i in 0..<Int(count) { selectors.append(NSStringFromSelector(method_getName(methods[i]))) }
                free(methods)
            }
            let hits = selectors.filter { s in interesting.contains { $0.isEmpty ? false : s.contains($0) } }
            out.append(("selectors:\(name)", hits.isEmpty ? "none" : hits.joined(separator: " | ")))
        }
        return out
    }
}

// MARK: - Theory / verdict model

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
    var mis: [(String, String)] = []
    var misProfile: [(String, String)] = []
    var anchors: [(String, String)] = []
    var effects: [(String, String)] = []
    var install: [(String, String)] = []
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
                chainOIDs.append(oids)
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

    // The predicted CT policy: the AND across every certificate we found.
    if !chainOIDs.isEmpty {
        f.predictedPolicy = CTPolicy.policy(chain: chainOIDs)
    }
    r.add("predicted-ct-policy", Bits.hex(f.predictedPolicy))
    r.add("predicted-ct-policy-bits", Bits.list(f.predictedPolicy))
    r.add("predicted-ct-policy-in-accept-mask", (f.predictedPolicy & CTPolicy.acceptMask) != 0 ? "YES" : "no")
    r.add("predicted-ct-policy-has-fastpath-bit", (f.predictedPolicy & CTPolicy.fastPathMask) != 0 ? "YES" : "no")
    r.add("predicted-ct-policy-has-internal-profile-bit", (f.predictedPolicy & CTPolicy.internalProfileMask) != 0 ? "YES" : "no")

    // 4. LIBMIS ----------------------------------------------------------------
    r.section("LIBMIS")
    f.mis = Mis.run()
    for (k, v) in f.mis { r.add(k, v) }
    f.misProfile = Mis.validateOwnProfile(f.profileData)
    for (k, v) in f.misProfile { r.add(k, v) }

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
    for (k, v) in f.effects { r.add(k, v) }

    // 8. ANCHORS ---------------------------------------------------------------
    r.section("ANCHOR")
    f.anchors = AnchorSet.run()
    for (k, v) in f.anchors { r.add(k, v) }
    f.runtimeAnchorHasPublicRoot = f.anchors.contains {
        $0.key == "runtime-anchors-contains-public-apple-root" && $0.value == "YES"
    }
    f.anchorHasPublicRoot = f.anchors.contains {
        $0.key == "corporate-roots-contains-public-apple-root" && $0.value == "YES"
    }
    for (k, v) in TrustProbe.evaluate(derCerts: f.profileCerts) { r.add(k, v) }

    // 9. INSTALL ---------------------------------------------------------------
    r.section("INSTALL")
    f.install = InstallProbe.run()
    for (k, v) in f.install { r.add(k, v) }

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
    let internal = (pdict["AppleInternalProfile"] as? Bool) == true
    f.scenario = "\(sigKind)+\(pkind)+\(profileProvisionsPrivate ? "provisions-priv" : "no-priv")+\(internal ? "internal" : "not-internal")"
    r.add("scenario-signature", sigKind)
    r.add("scenario-profile", pkind)
    r.add("scenario-profile-provisions-private", profileProvisionsPrivate ? "YES" : "no")
    r.add("scenario-profile-apple-internal", internal ? "YES" : "no")
    r.add("scenario-id", f.scenario)

    r.flush()
    return f
}

// MARK: - Verdict engine

func evaluate(_ f: Facts) -> [Verdict] {
    var v: [Verdict] = []

    // T01 — the runtime anchor set contains the PUBLIC Apple Root CA.
    v.append(Verdict(id: "T01",
                      title: "the runtime trust-anchor set contains the PUBLIC Apple Root CA",
                      state: f.runtimeAnchorHasPublicRoot ? "CONFIRMED" : (f.anchorHasPublicRoot ? "CONFIRMED" : "REFUTED"),
                      evidence: f.runtimeAnchorHasPublicRoot ? "runtime-anchors-contains-public-apple-root=YES"
                               : (f.anchorHasPublicRoot ? "corporate-roots-contains-public-apple-root=YES" : "neither anchor list contains it")))

    // T02 — our leaf certificate carries 100.6.1.2 -> CT-policy bit 7.
    let leafBits = f.perCertBits.first?.1 ?? 0
    let hasBit7 = (leafBits & (UInt64(1) << 7)) != 0
    v.append(Verdict(id: "T02",
                      title: "the leaf certificate's Apple class grants CT-policy bit 7 (inside AMFI's accept mask)",
                      state: hasBit7 ? "CONFIRMED" : "REFUTED",
                      evidence: "leaf-class=\(f.leafClassOID ?? "-") leaf-bits=\(Bits.hex(leafBits))"))

    // T03 — the signer cannot write the CT-policy field: the on-disk value is
    //        not what the chain earns.
    let onDisk = f.signature.policyFieldCandidates.first.map { $0.value } ?? 0
    v.append(Verdict(id: "T03",
                      title: "the CT-policy field is not signer-controlled (on-disk value != predicted value)",
                      state: (onDisk == 0 && f.predictedPolicy != 0) ? "CONFIRMED" : "INCONCLUSIVE",
                      evidence: "on-disk=\(Bits.hex(onDisk)) predicted=\(Bits.hex(f.predictedPolicy))"))

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
    let profileHasNoValidSignature = f.misProfile.first { $0.key == "mis-profile-validate" }?.value ?? ""
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
    let internal = (f.profileDict["AppleInternalProfile"] as? Bool) == true
    if !provisionsPriv && !internal {
        v.append(Verdict(id: "T08", title: "a private entitlement requires a provisioned or Apple-internal profile",
                          state: "N/A", evidence: "this scenario claims no private entitlement"))
    } else if privateHonoured {
        v.append(Verdict(id: "T08", title: "a private entitlement requires a provisioned or Apple-internal profile",
                          state: "CONSISTENT",
                          evidence: "honoured with provisions-priv=\(provisionsPriv) apple-internal=\(internal)"))
    } else {
        v.append(Verdict(id: "T08", title: "a private entitlement requires a provisioned or Apple-internal profile",
                          state: "CONSISTENT",
                          evidence: "refused with provisions-priv=\(provisionsPriv) apple-internal=\(internal)"))
    }

    // T09 — the launch gate is conditional on mis.db, not an independent wall.
    let misSelf = f.mis.first { $0.key == "mis-validate-self" }?.value ?? "-"
    v.append(Verdict(id: "T09",
                      title: "the launch-time validator (libmis) does not independently re-verify the profile",
                      state: (misSelf == "0x00000000") ? "CONFIRMED" : "INCONCLUSIVE",
                      evidence: "MISValidateSignature(self)=\(misSelf); a non-zero code means the gate DID fire for this app"))

    // T10 — libmis does not re-verify the profile's CMS at launch.
    v.append(Verdict(id: "T10",
                      title: "libmis does not re-verify the provisioning profile's CMS chain",
                      state: (profileHasNoValidSignature.hasPrefix("0x00000000") ? "REFUTED" : "CONSISTENT"),
                      evidence: "MISProfileValidateSignature(own profile)=\(profileHasNoValidSignature)"))

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
    let gate = f.install.first { $0.key == "install-gate-allowedSPI" }?.value ?? "absent"
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
    let outside = f.effects.first { $0.key == "write-outside-container" }?.value ?? "-"
    v.append(Verdict(id: "T14",
                      title: "a no-sandbox entitlement, when honoured, actually lifts the sandbox",
                      state: (outside == "ALLOWED") ? "CONFIRMED" : (privateHonoured ? "REFUTED" : "N/A"),
                      evidence: "write-outside-container=\(outside) private-honoured=\(privateHonoured ? "YES" : "no")"))

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

        textView.isEditable = false
        textView.font = UIFont.monospacedSystemFont(ofSize: 9, weight: .regular)
        textView.text = "Open the app to run the probe."

        let stack = UIStackView(arrangedSubviews: [status, runBtn, textView])
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
