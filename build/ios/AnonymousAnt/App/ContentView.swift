import SwiftUI
import NetworkExtension

struct ContentView: View {
    @State private var isConnected = false
    @State private var isConnecting = false
    @State private var serverAddr = "127.0.0.1:8443"
    @State private var serverKey = ""
    @State private var selectedTransport = "tls"
    @State private var downloadSpeed = "0 MB"
    @State private var uploadSpeed = "0 MB"
    
    @State private var tunnelManager: NETunnelProviderManager?

    var body: some View {
        ZStack {
            Color(red: 13/255, green: 17/255, blue: 23/255)
                .ignoresSafeArea()

            VStack(spacing: 24) {
                // Header
                HStack {
                    Image(systemName: "ant.fill")
                        .font(.title2)
                        .foregroundColor(.green)
                    Text("AnonymousAnt")
                        .font(.headline)
                        .fontWeight(.bold)
                        .foregroundColor(.white)
                    Spacer()
                    Text(isConnected ? "PROTECTED" : "DISCONNECTED")
                        .font(.caption2)
                        .fontWeight(.bold)
                        .padding(.horizontal, 8)
                        .padding(.vertical, 4)
                        .background(isConnected ? Color.green.opacity(0.2) : Color.gray.opacity(0.2))
                        .foregroundColor(isConnected ? .green : .gray)
                        .cornerRadius(12)
                }
                .padding(.horizontal)

                Spacer()

                // Big Connect / Disconnect Action Button
                Button(action: toggleVPN) {
                    VStack(spacing: 8) {
                        Image(systemName: isConnected ? "power.circle.fill" : "power.circle")
                            .font(.system(size: 64))
                        Text(isConnected ? "DISCONNECT" : "CONNECT")
                            .font(.subheadline)
                            .fontWeight(.bold)
                    }
                    .foregroundColor(isConnected ? .green : .white)
                    .frame(width: 160, height: 160)
                    .background(Color(red: 22/255, green: 27/255, blue: 34/255))
                    .clipShape(Circle())
                    .overlay(
                        Circle().stroke(isConnected ? Color.green : Color.gray.opacity(0.3), lineWidth: 3)
                    )
                    .shadow(color: isConnected ? Color.green.opacity(0.4) : Color.black.opacity(0.4), radius: 16)
                }

                Spacer()

                // Configuration Section
                VStack(spacing: 12) {
                    VStack(alignment: .leading, spacing: 4) {
                        Text("SERVER URL OR ADDRESS")
                            .font(.caption2)
                            .foregroundColor(.gray)
                        TextField("ant://... or 127.0.0.1:8443", text: $serverAddr)
                            .textFieldStyle(RoundedBorderTextFieldStyle())
                            .autocapitalization(.none)
                            .disableAutocorrection(true)
                    }

                    VStack(alignment: .leading, spacing: 4) {
                        Text("SERVER PUBLIC KEY")
                            .font(.caption2)
                            .foregroundColor(.gray)
                        TextField("Curve25519 Key", text: $serverKey)
                            .textFieldStyle(RoundedBorderTextFieldStyle())
                            .autocapitalization(.none)
                    }

                    Picker("Transport", selection: $selectedTransport) {
                        Text("🛡️ Stealth TLS (Port 443)").tag("tls")
                        Text("🚀 Direct Fast UDP").tag("udp")
                        Text("🌐 CDN WebSocket").tag("ws")
                    }
                    .pickerStyle(SegmentedPickerStyle())
                }
                .padding()
                .background(Color(red: 22/255, green: 27/255, blue: 34/255))
                .cornerRadius(12)
                .padding(.horizontal)

                Text("Zero-Logging RAM Mode • 100% In-Memory")
                    .font(.caption2)
                    .foregroundColor(.gray)
                    .padding(.bottom, 8)
            }
        }
        .onAppear(perform: loadVPNPreferences)
    }

    private func loadVPNPreferences() {
        NETunnelProviderManager.loadAllFromPreferences { managers, error in
            if let manager = managers?.first {
                self.tunnelManager = manager
                self.isConnected = (manager.connection.status == .connected)
            }
        }
    }

    private func toggleVPN() {
        if isConnected {
            tunnelManager?.connection.stopVPNTunnel()
            isConnected = false
        } else {
            startVPN()
        }
    }

    private func startVPN() {
        let manager = tunnelManager ?? NETunnelProviderManager()
        let proto = NETunnelProviderProtocol()
        proto.providerBundleIdentifier = "com.anonymousant.ios.PacketTunnel"
        proto.serverAddress = serverAddr
        proto.providerConfiguration = [
            "server_addr": serverAddr,
            "server_key": serverKey,
            "transport": selectedTransport,
            "sni": "gateway.internal"
        ]

        manager.protocolConfiguration = proto
        manager.localizedDescription = "AnonymousAnt VPN"
        manager.isEnabled = true

        manager.saveToPreferences { error in
            guard error == nil else { return }
            manager.loadFromPreferences { _ in
                do {
                    try manager.connection.startVPNTunnel()
                    self.tunnelManager = manager
                    self.isConnected = true
                } catch {
                    print("Start tunnel failed: \(error)")
                }
            }
        }
    }
}
