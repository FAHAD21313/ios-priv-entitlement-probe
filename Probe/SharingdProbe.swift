//
//  SharingdProbe.swift
//  PROTOTYPE (throwaway) — dynamic gate test for com.apple.sharingd.nsxpc.
//
//  Question this artifact answers: can a free-signed sandboxed app do anything
//  MORE than bootstrap_look_up() against sharingd's NSXPC listener?
//    (a) create an NSXPCConnection                -> CONNECT-ONLY subtest
//    (b) is the connection accepted by the daemon -> invalidation/interruption handlers
//    (c) can a well-formed message round-trip     -> one reply-block message per known protocol
//
//  Non-destructive by construction:
//   - no fuzzing, no malformed data, no raw mach_msg, no memory corruption;
//   - the single message uses a SELECTOR THE DAEMON DOES NOT IMPLEMENT
//     (sxpcProbePingWithReply:), so no real daemon functionality is invoked;
//     a reply/error proves the pipe works, an invalidation proves a gate.
//
//  Known protocol NAMES are from Sharing.framework strings (objc protocol
//  metadata): SFUnlockProtocol, SFAirDropNodeProtocol,
//  SFCompanionServiceManagerProtocol. We reuse only the names; the method is
//  ours and intentionally harmless.
//

import Foundation
import UIKit

// MARK: - Minimal well-formed protocols

/// Common reply shape shared by all three ObjC protocol names.
@objc
protocol SXPCProbeable: NSObjectProtocol {
    /// Deliberately not a real selector in sharingd. Reply is just a liveness signal.
    @objc(sxpcProbePingWithReply:)
    func sxpcProbePing(reply: @escaping (Bool, String?, Error?) -> Void)
}

@objc(SFUnlockProtocol)
protocol SFUnlockProbeProtocol: SXPCProbeable {}

@objc(SFAirDropNodeProtocol)
protocol SFAirDropNodeProbeProtocol: SXPCProbeable {}

@objc(SFCompanionServiceManagerProtocol)
protocol SFCompanionServiceManagerProbeProtocol: SXPCProbeable {}

// MARK: - Per-connection observer

private final class Watch {
    let label: String
    let rep: Rep
    private let t0 = Date()
    private let lock = NSLock()
    private let replySem = DispatchSemaphore(value: 0)
    private(set) var invalidated = false
    private(set) var interrupted = false
    private(set) var replied = false

    init(_ label: String, _ rep: Rep) { self.label = label; self.rep = rep }

    func log(_ s: String) {
        let dt = String(format: "%+.3f", Date().timeIntervalSince(t0))
        rep.add("[\(label) t=\(dt)s] \(s)")
    }
    func markInvalidated() { lock.lock(); invalidated = true; lock.unlock(); replySem.signal() }
    func markInterrupted() { lock.lock(); interrupted = true; lock.unlock() }
    func markReply()       { lock.lock(); replied = true;     lock.unlock(); replySem.signal() }
    func signal()          { replySem.signal() }

    var state: String {
        lock.lock(); defer { lock.unlock() }
        return "invalidated=\(invalidated) interrupted=\(interrupted) replied=\(replied)"
    }
    /// True if a reply/error/invalidation arrived before the timeout.
    func waitReply(_ seconds: Double) -> Bool {
        replySem.wait(timeout: .now() + seconds) == .success
    }
    /// Pure timed observation window (no event needed to end it).
    func observe(_ seconds: Double) {
        _ = DispatchSemaphore(value: 0).wait(timeout: .now() + seconds)
    }
}

// MARK: - Subtests

/// Connect with NO interface and NO message. Answers (a) and (b) in isolation:
/// if the daemon rejects at accept-time, invalidationHandler fires here.
private func runConnectOnly(rep: Rep, connections: inout [NSXPCConnection]) {
    let w = Watch("CONNECT-ONLY", rep)
    w.log("creating NSXPCConnection(machServiceName: com.apple.sharingd.nsxpc, options: [])")
    let c = NSXPCConnection(machServiceName: "com.apple.sharingd.nsxpc")
    c.invalidationHandler = { [weak w] in
        guard let w = w else { return }
        w.markInvalidated()
        w.log("invalidationHandler fired")
    }
    c.interruptionHandler = { [weak w] in
        guard let w = w else { return }
        w.markInterrupted()
        w.log("interruptionHandler fired")
    }
    connections.append(c)          // keep alive until the whole probe finishes
    c.resume()
    w.log("resume() called; observing 5s (no message sent)")
    w.observe(5)
    w.log("state: \(w.state)")
    if w.invalidated {
        w.log("VERDICT: connection INVALIDATED before any message -> daemon rejected at accept-time (or daemon unavailable). Sending is moot.")
    } else {
        w.log("VERDICT: connection stayed valid for 5s -> accept-time gate NOT observed. Continue to message subtests.")
    }
}

/// Connect, set interfaces, send ONE well-formed message with a harmless unknown selector.
private func runProtocolProbe(label: String, objcProto: Protocol,
                              rep: Rep,
                              connections: inout [NSXPCConnection]) {
    let w = Watch(label, rep)
    let iface = NSXPCInterface(with: objcProto)
    w.log("creating connection; remoteObjectInterface=exportedInterface=NSXPCInterface(\(label))")
    let c = NSXPCConnection(machServiceName: "com.apple.sharingd.nsxpc")
    c.remoteObjectInterface = iface
    c.exportedInterface = iface
    c.invalidationHandler = { [weak w] in
        guard let w = w else { return }
        w.markInvalidated()
        w.log("invalidationHandler fired")
    }
    c.interruptionHandler = { [weak w] in
        guard let w = w else { return }
        w.markInterrupted()
        w.log("interruptionHandler fired")
    }
    connections.append(c)
    c.resume()
    w.log("resume() called; observing 4s for accept/reject")
    w.observe(4)
    w.log("state before send: \(w.state)")

    guard !w.invalidated else {
        w.log("VERDICT: connection invalidated before send -> accept-time gate for this protocol name; no message attempted.")
        return
    }

    let proxy = c.remoteObjectProxyWithErrorHandler { [weak w] err in
        guard let w = w else { return }
        w.log("remoteObjectProxy error handler: \(err)")
        w.signal()
    } as? SXPCProbeable
    guard let proxy = proxy else {
        w.log("VERDICT: remoteObjectProxy cast to \(label) FAILED; no message sent.")
        return
    }
    w.log("proxy obtained; sending ONE message sxpcProbePingWithReply: (unknown selector, no daemon function invoked, no malformed data)")
    proxy.sxpcProbePing { [weak w] ok, msg, err in
        guard let w = w else { return }
        w.markReply()
        w.log("REPLY ok=\(ok) msg=\(String(describing: msg)) error=\(err.map { String(describing: $0) } ?? "nil")")
    }
    let arrived = w.waitReply(6)
    w.log("state after send: \(w.state); replyWithinTimeout=\(arrived)")
    if w.replied {
        w.log("VERDICT: message ROUND-TRIPPED (reply/error received) -> NSXPC data channel is OPEN for this protocol name.")
    } else if w.invalidated {
        w.log("VERDICT: connection INVALIDATED on send -> message-layer gate / daemon-side rejection.")
    } else {
        w.log("VERDICT: no reply in 6s -> message not serviced (gate, or one-way/no-reply handler). INCONCLUSIVE on data path.")
    }
}

// MARK: - Entry point (called by the second button in SandboxProbe.swift)

func runSharingdProbe() -> String {
    let rep = Rep()
    rep.section("SHARINGD NSXPC RUNTIME PROBE (prototype)")
    rep.add("probe=sharingd-nsxpc-runtime")
    rep.add("device-os=\(UIDevice.current.systemVersion)")
    rep.add("utc=\(ISO8601DateFormatter().string(from: Date()))")
    rep.add("service=com.apple.sharingd.nsxpc")
    rep.add("method=well-formed NSXPC only; unknown selector; no malformed data; no exploit")
    rep.add("interpretation: reply/error => data channel open; invalidation => daemon gate; timeout => inconclusive")

    var connections: [NSXPCConnection] = []
    runConnectOnly(rep: rep, connections: &connections)
    runProtocolProbe(label: "PROTO-SFUnlockProtocol",
                     objcProto: SFUnlockProbeProtocol.self, rep: rep, connections: &connections)
    runProtocolProbe(label: "PROTO-SFAirDropNodeProtocol",
                     objcProto: SFAirDropNodeProbeProtocol.self, rep: rep, connections: &connections)
    runProtocolProbe(label: "PROTO-SFCompanionServiceManagerProtocol",
                     objcProto: SFCompanionServiceManagerProbeProtocol.self, rep: rep, connections: &connections)

    for c in connections { c.invalidate() }
    connections.removeAll()
    rep.add("=== END SHARINGD NSXPC PROBE ===")
    return rep.text
}
