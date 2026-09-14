# AnonymousAnt 🐜
> High-Throughput, Low-Memory, Zero-Logging VPN Designed to Tunnel From Anywhere, to Anywhere.

[![Go Version](https://img.shields.io/badge/go-1.24+-00ADD8?style=flat&logo=go)](https://golang.org)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Zero-Logging](https://img.shields.io/badge/zero--logging-100%25%20RAM-success)](#zero-logging--ephemeral-design)

AnonymousAnt is an ultra-resilient, cross-platform VPN engineered in pure Go. It establishes high-speed encrypted tunnels through hostile network environments (e.g. corporate firewalls, captive portals, school/hotel networks, and DPI surveillance) while preserving strict privacy, zero disk persistence, and a resident memory footprint below 20 MB.

---

## Key Features

* **Tunnel From Anywhere (Multi-Transport Chameleon Architecture)**:
  * 🚀 **Direct Fast Datagram (UDP)**: Noise Protocol over raw UDP sockets with 4MB buffer sizing for maximum throughput and wire-speed gaming/streaming.
  * 🛡️ **Stealth Shield (Chameleon TLS 1.3 on Port 443)**: Masquerades tunnel traffic as genuine HTTPS web browsing with configurable SNI.
  * 🌐 **CDN Chameleon (WebSocket over TLS)**: Tunnels packets through Cloudflare, CDNs, or corporate HTTP forward proxies.
  * 🎭 **Active Probing Defense**: If censors or scanners probe the VPN port with standard HTTP requests, the server responds with a genuine HTTP 200 OK decoy web page to defeat active probing.
  * 📦 **Anti-DPI Padding & Timing Jitter**: Dynamically pads packets to discrete block sizes to thwart statistical packet-size fingerprinting.

* **Zero-Logging & Ephemeral Security**:
  * **100% In-Memory**: No databases, no disk caches, no session history on disk.
  * **Memory Zeroing**: Automatic, compiler-safe memory wiping (`Zero` / `Zero32`) for Curve25519 private keys and symmetric AEAD session keys.
  * **Sanitized Logging**: All IPv4 and IPv6 addresses are redacted (`[REDACTED_IP]`) in logs.
  * **No Accounts / Instant Pairing**: One-line connection URLs (`ant://<public_key>@<server_host>:<port>?obfs=tls`).

* **High Performance & Low Memory**:
  * Zero allocations in steady-state packet loops via `sync.Pool` buffer recycling (`0 allocs/op`).
  * In-place ChaCha20-Poly1305 and AES-256-GCM AEAD encryption/decryption directly on preallocated MTU buffers.
  * Dynamic MSS Clamping to prevent packet fragmentation.

* **Clean Privilege Separation & Native User Interface**:
  * **Privileged Background Daemon** (`ant-daemon`): Safely executes with elevated permissions to manage TUN devices, routing tables, and the OS packet filter Kill Switch.
  * **Unprivileged Desktop UI** (`ant-ui`): Sleek modern desktop interface communicating with the daemon over local IPC (Unix domain socket / Windows named pipe).
  * **Cross-Platform Installations**:
    * **macOS**: Native `utun` driver, `pfctl` firewall kill switch, LaunchDaemon, and DMG packager.
    * **Windows**: Kernel-level **Wintun** NDIS driver integration and Windows Service installer.
    * **iOS**: Native Swift `NEPacketTunnelProvider` NetworkExtension powered by `gomobile bind` into an `AntTunnel.xcframework` with SwiftUI interface.

---

## Technical Evaluations

### 1. How Networks Block Tunnels & How AnonymousAnt Bypasses Them
| Blocking Technique | Why Standard VPNs Fail | How AnonymousAnt Evades |
| :--- | :--- | :--- |
| **UDP Throttling / Outright Drop** | WireGuard / OpenVPN UDP packets dropped by hotel/guest Wi-Fi. | Automatic fallback to **Port 443 TLS 1.3** or **WebSocket**. |
| **DPI Protocol Fingerprinting** | Initial handshake headers (WireGuard type `0x01`, OpenVPN opcodes) identified. | **Noise Protocol obfuscation** with variable-length random padding and pseudo-random magic bytes. |
| **SNI / Hostname Filtering** | DPI inspects plaintext Server Name Indication in TLS ClientHello. | **SNI Masquerading**: Emulates benign domain names or CDN fronting. |
| **Active Probing** | Firewall scanner connects to server on port 443 with probe HTTP requests. | **Chameleon Web Server**: AnonymousAnt serves a genuine static HTTPS website returning HTTP 200 OK. |

### 2. Security Evaluation: Is the User Truly Protected?
* **Hop-by-Hop vs. End-to-End**: Traffic within the tunnel is cryptographically shielded with forward secrecy (`Noise_IK_25519_ChaChaPoly_SHA256`). Once egressing the exit node, standard HTTPS/TLS traffic remains end-to-end encrypted. Unencrypted HTTP/DNS is protected up to the exit node.
* **Leak Protections**:
  * **DNS Leaks**: The client overrides host DNS to secure resolvers (`1.1.1.1` / DoH).
  * **IPv6 Leaks**: Host routing drops or blackholes unencapsulated IPv6 when IPv6 exit routing is inactive.
  * **Kill Switch**: macOS `pfctl` and Linux `iptables` drop all non-tunnel egress if the tunnel disconnects.

### 3. Bandwidth Trade-offs & Optimizations
* **Header Overhead**: Standard Ethernet MTU is 1500 bytes. Encapsulation adds ~72 bytes. AnonymousAnt sets TUN MTU to **1420 bytes** and applies **TCP MSS Clamping** to completely prevent IP fragmentation.
* **Avoiding TCP-over-TCP Meltdown**: Multiplexed datagrams avoid nested retransmission timer loops.

---

## Quickstart Guide

### Building Binaries
```bash
# Build all components
go build -o bin/antserver ./cmd/antserver
go build -o bin/antclient ./cmd/antclient
go build -o bin/ant-daemon ./cmd/ant-daemon
go build -o bin/ant-ui ./cmd/ant-ui
```

### Running the Server (Exit Node)
```bash
sudo ./bin/antserver -udp :51820 -tls :8443 -tun ant0
```
Output:
```
==================================================================
 Server Public Key:  m-XQ_4W5rXJ8y...
 Connection String:  ant://m-XQ_4W5rXJ8y...@<SERVER_HOST>:8443?obfs=tls
==================================================================
```

### Running with Desktop UI
1. Start the privileged daemon (in background or system service):
```bash
sudo ./bin/ant-daemon
```
2. Launch the desktop UI:
```bash
./bin/ant-ui
```
This automatically launches your browser to `http://127.0.0.1:47820` with the live control panel.

### Running the CLI Client (Headless)
```bash
# Connect using ant:// URL
sudo ./bin/antclient -url "ant://<KEY>@<SERVER_HOST>:8443?obfs=tls" -routes

# Or using explicit flags
sudo ./bin/antclient \
  -server <SERVER_HOST>:8443 \
  -key <SERVER_PUBLIC_KEY> \
  -transport tls \
  -routes \
  -killswitch
```

---

## 🇸🇬 Tunneling to Singapore (or Any Country)

To tunnel your traffic through Singapore (giving your device a genuine Singapore IP address):
1. **Deploy in Singapore** (1-command installer on any Ubuntu/Debian Singapore VPS e.g. DigitalOcean, AWS, Hetzner):
   ```bash
   curl -sSL https://raw.githubusercontent.com/chengyaolee/AnonymousAnt/main/deploy/singapore/setup.sh | sudo bash
   ```
2. **Copy the `ant://...` URL** printed in the terminal.
3. **Connect** from your device:
   * **Desktop UI**: Open `ant-ui`, paste the `ant://` URL, click **CONNECT**.
   * **CLI**: `sudo ./bin/antclient -url "ant://..." -routes`
   * **iOS**: Paste the `ant://` URL into the AnonymousAnt app and tap **CONNECT**.

See the full [Singapore Setup Guide](deploy/singapore/SINGAPORE_SETUP.md) for step-by-step screenshots and cloud provider walkthroughs.

---

## Native Platform Installations

### macOS
```bash
# Automated installer (registers LaunchDaemon)
sudo ./build/macos/install.sh

# Build DMG disk image
./build/macos/build_dmg.sh
```

### Windows
1. Build Windows binaries:
```bash
GOOS=windows GOARCH=amd64 go build -o bin/windows/ant-daemon.exe ./cmd/ant-daemon
GOOS=windows GOARCH=amd64 go build -o bin/windows/ant-ui.exe ./cmd/ant-ui
GOOS=windows GOARCH=amd64 go build -o bin/windows/antclient.exe ./cmd/antclient
```
2. Place `wintun.dll` in `build/windows/wintun/` and compile the installer using Inno Setup:
```cmd
iscc build\windows\installer.iss
```

### iOS
1. Build the Go mobile XCFramework:
```bash
./build/ios/build_xcframework.sh
```
2. Open `build/ios/AnonymousAnt/` in Xcode. The project integrates `PacketTunnelProvider.swift` (`NEPacketTunnelProvider`) with SwiftUI `ContentView.swift`.

---

## Architecture Overview

```
AnonymousAnt/
├── cmd/
│   ├── ant-daemon/             # Privileged background service (macOS / Linux)
│   ├── ant-ui/                 # Desktop GUI & embedded webview control panel
│   ├── antclient/              # Standalone CLI client
│   └── antserver/              # Server / Exit Node (dual UDP + Chameleon TLS 443)
├── pkg/
│   ├── buffer/                 # Zero-allocation sync.Pool memory allocator (0 allocs/op)
│   ├── crypto/                 # Curve25519 keys, Noise IK handshake, AEAD ciphers
│   ├── ipc/                    # Daemon <-> UI Unix socket IPC
│   ├── mobile/                 # Gomobile binding bridge for iOS NetworkExtension
│   ├── obfuscation/            # Packet padding & timing jitter against DPI
│   ├── protocol/               # 14-byte wire framing, replay window, sessions
│   ├── router/                 # OS route management & gateway preservation
│   ├── security/               # Memory zeroing, zero-logging, and firewall kill switch
│   ├── transport/              # Pluggable transports: UDP, TLS 1.3, WebSocket
│   └── tun/                    # OS TUN abstraction (macOS utun, Linux /dev/net/tun, Windows)
└── build/
    ├── ios/                    # gomobile build script, Swift NEPacketTunnelProvider, SwiftUI
    ├── macos/                  # LaunchDaemon plist, install script, DMG packager
    └── windows/                # Inno Setup script, Wintun integration
```

---

## License
MIT License.
