//
//  SandboxProbe.swift
//  Sandbox reachability probe — iOS 27.0.1, free-signed app, one button.
//  Non-destructive: opens IOKit handles, looks up Mach ports, generates a
//  thumbnail via public API, checks file access. Writes probe-report.txt.
//

import UIKit
import Foundation
import Darwin
import QuickLookThumbnailing

@_silgen_name("probe_sandbox")
private func probe_sandbox(_ path: UnsafePointer<CChar>) -> Int32

final class Rep {
    private var lines: [String] = []
    private let url = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first!
        .appendingPathComponent("probe-report.txt")
    func add(_ s: String) {
        lines.append(s)
        if let h = FileHandle(forWritingAtPath: url.path) {
            h.seekToEndOfFile(); h.write(Data((s + "\n").utf8)); try? h.close()
        } else { try? (s + "\n").write(to: url, atomically: true, encoding: .utf8) }
    }
    func section(_ s: String) { add("--- \(s) ---") }
    var text: String { lines.joined(separator: "\n") + "\n" }
}

func makeTinyPNG() -> URL? {
    // 1x1 transparent PNG
    let b64 = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8AAAwAB/wFfC+2AAAAAElFTkSuQmCC"
    guard let d = Data(base64Encoded: b64) else { return nil }
    let u = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first!
        .appendingPathComponent("tiny.png")
    try? d.write(to: u)
    return u
}

func runSandboxProbe() -> String {
    let u = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first!
        .appendingPathComponent("probe-report.txt")
    try? Data().write(to: u)
    let r = Rep()
    r.add("probe=sandbox-reachability")
    r.add("device-os=\(UIDevice.current.systemVersion)")
    r.add("utc=\(ISO8601DateFormatter().string(from: Date()))")
    r.add("home=\(NSHomeDirectory())")

    // C helper: IOKit + Mach
    r.section("REACHABILITY (C helper)")
    let dump = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first!
        .appendingPathComponent("sandbox-dump.txt")
    try? Data().write(to: dump)
    let rc = dump.path.withCString { probe_sandbox($0) }
    r.add((try? String(contentsOf: dump, encoding: .utf8)) ?? "helper failed rc=\(rc)")

    // QuickLook public API (proves out-of-process thumbnail path)
    r.section("QUICKLOOK PUBLIC API")
    if let img = makeTinyPNG() {
        let req = QLThumbnailGenerator.Request(fileAt: img, size: CGSize(width: 64, height: 64),
                                                scale: 1, representationTypes: .thumbnail)
        let sem = DispatchSemaphore(value: 0)
        var outcome = "pending"
        QLThumbnailGenerator.shared.generateBestRepresentation(for: req) { rep, err in
            if let _ = rep { outcome = "OK (thumbnail generated — out-of-process path exercised)" }
            else if let e = err { outcome = "error: \(e.localizedDescription)" }
            else { outcome = "unknown" }
            sem.signal()
        }
        if sem.wait(timeout: .now() + 10) == .timedOut { outcome = "timeout" }
        r.add("thumbnail-result=\(outcome)")
        // Deprecated saveBestRepresentation (the one agent says goes to agent)
        if let req2 = (try? QLThumbnailGenerator.Request(fileAt: img, size: CGSize(width: 64, height: 64),
                        scale: 1, representationTypes: .thumbnail)) {
            QLThumbnailGenerator.shared.saveBestRepresentation(for: req2) { err in
                r.add("saveBest-result=\(err == nil ? "OK" : "error: \(err!.localizedDescription)")")
            }
        }
    } else { r.add("thumbnail-result=no-test-image") }

    // File access to interesting paths
    r.section("FILE ACCESS")
    let paths = ["/tmp", "/var/tmp", NSHomeDirectory(),
                 "/System/Library/Caches/com.apple.dyld",
                 "/private/var/mobile/Library", "/var/mobile/Media"]
    for p in paths {
        let readable = FileManager.default.isReadableFile(atPath: p)
        let writable = FileManager.default.isWritableFile(atPath: p)
        r.add("\(p) read=\(readable) write=\(writable)")
    }
    r.add("=== END ===")
    return r.text
}

final class VC: UIViewController {
    private let status = UILabel()
    private let btn = UIButton(type: .system)
    private let text = UITextView()
    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .systemBackground
        title = "Sandbox Probe"
        status.text = "Tap once. Non-destructive reachability check."; status.numberOfLines = 0
        btn.setTitle("Probe Sandbox", for: .normal); btn.titleLabel?.font = .boldSystemFont(ofSize: 18)
        btn.addTarget(self, action: #selector(go), for: .touchUpInside)
        text.font = .monospacedSystemFont(ofSize: 10, weight: .regular); text.isEditable = false
        let st = UIStackView(arrangedSubviews: [status, btn, text]); st.axis = .vertical; st.spacing = 10
        st.translatesAutoresizingMaskIntoConstraints = false; view.addSubview(st)
        NSLayoutConstraint.activate([
            st.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor, constant: 16),
            st.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 12),
            st.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -12),
            st.bottomAnchor.constraint(equalTo: view.bottomAnchor, constant: -12),
            btn.heightAnchor.constraint(equalToConstant: 44)
        ])
    }
    @objc private func go() {
        btn.isEnabled = false; status.text = "Probing…"
        DispatchQueue.global(qos: .userInitiated).async {
            let res = runSandboxProbe()
            DispatchQueue.main.async {
                self.text.text = res; self.status.text = "Done — see probe-report.txt"
                UIPasteboard.general.string = res; self.btn.isEnabled = true
            }
        }
    }
}

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
