//
//  ProbeMinimal.swift
//  dyld4 OOB — exhaustive EXPLORATION probe (iOS 27.0.1 / 24A446)
//
//  ONE BUTTON. No crash, no force-quit, no auto-run.
//  Tapping the button:
//    1) dumps the app's own dyld closure completely (header + every loader);
//    2) calls dyld's own validation functions directly with synthetic
//       RuntimeState + large RW arrays (via explore_helper.c) and sweeps many
//       `ref & 0x7fff` values to map the OOB's full read/write capability;
//    3) writes one report to Documents/probe-report.txt and copies it.
//

import UIKit
import Foundation
import Darwin
import CryptoKit

// MARK: - helpers
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
    SHA256.hash(data: d).map { String(format: "%02x", $0) }.joined()
}

// MARK: - closure reader (read EVERYTHING from disk)
struct LoaderInfo {
    var index = 0
    var loaderOffset = 0
    var ref: UInt16 = 0
    var refOff = 0
    var idx = 0
    var inBounds = true
    var raw16 = ""
}

enum Closure {
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

    /// Full human-readable dump of one closure file.
    static func dump(_ path: String, into r: Rep) {
        r.add("closure-path=\(path)")
        guard let d = FileManager.default.contents(atPath: path) else {
            r.add("closure-readable=NO"); return
        }
        r.add("closure-size=\(d.count)")
        r.add("closure-sha256=\(sha256hex(d))")
        r.add("closure-boot-token=\(token(path))")
        guard d.count >= 0x14 else { r.add("closure-header=TOO-SHORT"); return }
        let magic = u32le(d, 0) ?? 0
        let version = u32le(d, 4) ?? 0
        let count = u32le(d, 0xc) ?? 0
        let off = u32le(d, 0x10) ?? 0
        r.add(String(format: "closure-magic=0x%08x %@", magic, magic == self.magic ? "OK" : "BAD"))
        r.add(String(format: "closure-version=0x%08x %@", version, version == self.version ? "OK" : "BAD"))
        r.add("closure-count=\(count)")
        r.add("closure-array-off=\(off)")

        // hex dump of header + first bytes of the loader array
        let dumpLen = min(d.count, 0x100)
        let head = d.subdata(in: 0..<dumpLen).map { String(format: "%02x", $0) }.joined()
        r.add("closure-hex-first-\(dumpLen)=\(head)")

        guard magic == self.magic, version == self.version else { r.add("closure-body=INVALID"); return }
        let base = Int(off)
        let n = Int(min(count, 0xffff))
        r.add("closure-loader-count-to-scan=\(n)")
        var offenders = 0
        for i in 0..<n {
            guard let lo = u32le(d, base + i * 4) else {
                r.add(String(format: "loader[%d]=OFFSET-OOB lo_off=%d", i, base + i*4)); break
            }
            let lp = base + Int(lo)
            guard let ref = u16le(d, lp + 6) else {
                r.add(String(format: "loader[%d]=REF-OOB lp=%d", i, lp)); continue
            }
            let idx = Int(ref & 0x7fff)
            let inB = idx < Int(count)
            if !inB { offenders += 1 }
            let raw = (lp >= 0 && lp + 16 <= d.count)
                ? d.subdata(in: lp..<(lp+16)).map { String(format: "%02x", $0) }.joined() : ""
            var li = LoaderInfo(index: i, loaderOffset: lp, ref: ref, refOff: lp + 6,
                                idx: idx, inBounds: inB, raw16: raw)
            r.add(String(format: "loader[%d] lp=%d ref=0x%04x idx=%d inBounds=%d raw=%@",
                         li.index, li.loaderOffset, li.ref, li.idx, li.inBounds ? 1 : 0, li.raw16))
        }
        r.add("closure-oob-offenders=\(offenders)")
        r.add("closure-verdict=\(offenders > 0 ? "OOB-CONFIRMED" : "NO-OOB")")
    }
}

// MARK: - the C exploration helper
@_silgen_name("probe_explore")
private func probe_explore(_ out: UnsafeMutablePointer<CChar>, _ outlen: Int) -> Int32

enum Explorer {
    static func run() -> String {
        let cap = 1 << 20 // 1 MiB
        let buf = UnsafeMutablePointer<CChar>.allocate(capacity: cap)
        defer { buf.deallocate() }
        buf.initialize(repeating: 0, count: cap)
        let rc = probe_explore(buf, cap)
        if rc != 0 { return "EXPLORE: helper returned \(rc)" }
        return String(cString: buf)
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
func runExploration() -> String {
    // Truncate previous report so this run's dump is self-contained.
    let u = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first!
        .appendingPathComponent("probe-report.txt")
    try? Data().write(to: u)

    let r = Rep()
    r.add("probe=dyld4-oob-EXPLORATION")
    r.add("device-os=\(UIDevice.current.systemVersion)")
    r.add("utc=\(ISO8601DateFormatter().string(from: Date()))")
    r.add("home=\(NSHomeDirectory())")
    let paths = Closure.paths()
    r.add("closure-count=\(paths.count)")
    r.section("CLOSURE DUMP")
    if paths.isEmpty {
        r.add("no .dyld4 closure found in \(Closure.dir())")
    } else {
        for p in paths { Closure.dump(p, into: r) }
    }
    r.section("DYLD OOB EXPLORATION")
    r.add(Explorer.run())
    r.add("=== END ===")
    return r.text
}

// MARK: - UI (ONE button)
final class VC: UIViewController {
    private let status = UILabel()
    private let runBtn = UIButton(type: .system)
    private let text = UITextView()

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .systemBackground
        title = "dyld4 OOB Explorer"

        status.text = "Tap once to dump the closure and explore the OOB."
        status.numberOfLines = 0
        status.font = .systemFont(ofSize: 13)

        runBtn.setTitle("Explore OOB", for: .normal)
        runBtn.titleLabel?.font = .boldSystemFont(ofSize: 18)
        runBtn.addTarget(self, action: #selector(explore), for: .touchUpInside)

        text.font = .monospacedSystemFont(ofSize: 10, weight: .regular)
        text.isEditable = false
        text.text = ""

        let stack = UIStackView(arrangedSubviews: [status, runBtn, text])
        stack.axis = .vertical; stack.spacing = 10
        stack.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(stack)
        NSLayoutConstraint.activate([
            stack.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor, constant: 16),
            stack.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 12),
            stack.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -12),
            stack.bottomAnchor.constraint(equalTo: view.bottomAnchor, constant: -12),
            runBtn.heightAnchor.constraint(equalToConstant: 44)
        ])
    }

    @objc private func explore() {
        runBtn.isEnabled = false
        status.text = "Dumping closure + exploring OOB…"
        DispatchQueue.global(qos: .userInitiated).async {
            let result = runExploration()
            DispatchQueue.main.async {
                self.text.text = result
                self.status.text = "Done — report saved to Documents/probe-report.txt"
                UIPasteboard.general.string = result
                self.runBtn.isEnabled = true
            }
        }
    }
}

class AppDelegate: UIResponder, UIApplicationDelegate {
    var window: UIWindow?
    func application(_ application: UIApplication,
                     didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {
        let w = UIWindow(frame: UIScreen.main.bounds)
        w.rootViewController = UINavigationController(rootViewController: VC())
        w.makeKeyAndVisible(); window = w
        return true
    }
}
