// vpnctl — tiny CLI to control profile-managed IKEv2 VPNs on macOS
// via NEVPNManager (NetworkExtension framework).
//
// Usage:
//   vpnctl list
//   vpnctl start  <displayName>
//   vpnctl stop   <displayName>
//   vpnctl status <displayName>
//
// Exit codes:
//   0 = success
//   1 = error (message on stderr)
//
// The entire flow is driven from a background queue while the main
// thread runs RunLoop.main so that NetworkExtension notifications
// and completion handlers are delivered correctly.

import Foundation
import NetworkExtension

func fatal(_ msg: String) -> Never {
    fputs("vpnctl: \(msg)\n", stderr)
    exit(1)
}

func statusString(_ s: NEVPNStatus) -> String {
    switch s {
    case .invalid:       return "Invalid"
    case .disconnected:  return "Disconnected"
    case .connecting:    return "Connecting"
    case .connected:     return "Connected"
    case .reasserting:   return "Reasserting"
    case .disconnecting: return "Disconnecting"
    @unknown default:    return "Unknown"
    }
}

guard CommandLine.arguments.count >= 2 else {
    fatal("usage: vpnctl {list|start|stop|status} [<vpn-display-name>]")
}

let action = CommandLine.arguments[1]

// "list" needs no display name; everything else does.
if action != "list" {
    guard CommandLine.arguments.count == 3 else {
        fatal("usage: vpnctl {start|stop|status} <vpn-display-name>")
    }
}

let targetName = CommandLine.arguments.count >= 3 ? CommandLine.arguments[2] : ""

// All work happens on a background queue; the main thread just pumps
// the run loop so that NE callbacks are delivered.
DispatchQueue.global(qos: .userInitiated).async {

    let sem = DispatchSemaphore(value: 0)

    // --- Collect all known VPN names (for list / diagnostics) ---
    var allNames: [String] = []

    // Tunnel provider managers (third-party VPN apps).
    NETunnelProviderManager.loadAllFromPreferences { managers, error in
        if error == nil, let managers = managers {
            for mgr in managers {
                allNames.append(mgr.localizedDescription ?? "(nil)")
            }
        }
        sem.signal()
    }
    sem.wait()

    // Shared built-in VPN manager (profile-installed IKEv2 etc.).
    NEVPNManager.shared().loadFromPreferences { error in
        if error == nil {
            let shared = NEVPNManager.shared()
            if let desc = shared.localizedDescription, !desc.isEmpty {
                allNames.append(desc)
            }
        }
        sem.signal()
    }
    sem.wait()

    // Handle "list" action early.
    if action == "list" {
        if allNames.isEmpty {
            print("No VPN configurations found.")
        } else {
            print("Available VPN configurations:")
            for name in allNames {
                print("  - \(name)")
            }
        }
        exit(0)
    }

    // --- Load VPN manager matching targetName ---
    var foundManager: NEVPNManager?

    // Try NETunnelProviderManager first.
    NETunnelProviderManager.loadAllFromPreferences { managers, error in
        if error == nil, let mgr = managers?.first(where: { $0.localizedDescription == targetName }) {
            foundManager = mgr
        }
        sem.signal()
    }
    sem.wait()

    // Fall back to the shared NEVPNManager (built-in IKEv2 from profiles).
    if foundManager == nil {
        NEVPNManager.shared().loadFromPreferences { error in
            if error == nil {
                let shared = NEVPNManager.shared()
                if shared.localizedDescription == targetName {
                    foundManager = shared
                }
            }
            sem.signal()
        }
        sem.wait()
    }

    guard let manager = foundManager else {
        var msg = "VPN '\(targetName)' not found via NEVPNManager."
        if allNames.isEmpty {
            msg += " No VPN configurations exist."
        } else {
            msg += " Available: \(allNames.joined(separator: ", "))"
        }
        fatal(msg)
    }

    // --- Execute action ---
    switch action {
    case "status":
        print(statusString(manager.connection.status))
        exit(0)

    case "start":
        // Track that we've seen at least one non-disconnected state
        // before treating disconnected as a failure.
        var sawConnecting = false

        // Observe status changes.
        let observer = NotificationCenter.default.addObserver(
            forName: .NEVPNStatusDidChange,
            object: manager.connection,
            queue: nil
        ) { _ in
            let s = manager.connection.status
            fputs("vpnctl: status -> \(statusString(s))\n", stderr)
            switch s {
            case .connecting, .reasserting:
                sawConnecting = true
            case .connected:
                print("Connected")
                exit(0)
            case .disconnected:
                if sawConnecting {
                    fatal("VPN failed (status: Disconnected)")
                }
                // Ignore initial disconnected state before connecting starts.
            case .invalid:
                fatal("VPN failed (status: Invalid)")
            default:
                break
            }
        }

        do {
            try manager.connection.startVPNTunnel()
        } catch {
            fatal("startVPNTunnel: \(error.localizedDescription)")
        }

        // Timeout after 20s.
        sleep(20)
        _ = observer  // prevent deallocation
        fatal("VPN connection timed out (status: \(statusString(manager.connection.status)))")

    case "stop":
        let observer = NotificationCenter.default.addObserver(
            forName: .NEVPNStatusDidChange,
            object: manager.connection,
            queue: nil
        ) { _ in
            if manager.connection.status == .disconnected {
                print("Disconnected")
                exit(0)
            }
        }

        if manager.connection.status == .disconnected {
            print("Disconnected")
            exit(0)
        }

        manager.connection.stopVPNTunnel()

        sleep(5)
        _ = observer
        print("Disconnected")
        exit(0)

    default:
        fatal("unknown action '\(action)' — use start, stop, or status")
    }
}

// Main thread: pump the run loop so NE delivers callbacks.
RunLoop.main.run()
