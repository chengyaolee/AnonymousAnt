package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/chengyaolee/AnonymousAnt/pkg/buffer"
	"github.com/chengyaolee/AnonymousAnt/pkg/crypto"
	"github.com/chengyaolee/AnonymousAnt/pkg/protocol"
	"github.com/chengyaolee/AnonymousAnt/pkg/router"
	"github.com/chengyaolee/AnonymousAnt/pkg/security"
	"github.com/chengyaolee/AnonymousAnt/pkg/transport"
	"github.com/chengyaolee/AnonymousAnt/pkg/tun"
)

func main() {
	serverAddr := flag.String("server", "127.0.0.1:8443", "Server host:port")
	serverKeyStr := flag.String("key", "", "Server Curve25519 public key (base64 or hex)")
	urlFlag := flag.String("url", "", "Full ant:// connection URL (e.g. ant://<pubkey>@<host>:8443?obfs=tls)")
	transMode := flag.String("transport", "tls", "Transport mode: 'tls' (chameleon port 443), 'udp', or 'ws'")
	sni := flag.String("sni", "gateway.internal", "SNI hostname for TLS masquerading")
	tunName := flag.String("tun", "ant1", "Local TUN device name")
	localIP := flag.String("ip", "10.8.0.2", "Local virtual IP")
	serverIP := flag.String("peer-ip", "10.8.0.1", "Remote virtual IP")
	enableRoutes := flag.Bool("routes", false, "Redirect default gateway through tunnel")
	enableKillSwitch := flag.Bool("killswitch", false, "Enable OS firewall kill switch")
	verbose := flag.Bool("v", false, "Verbose output")
	flag.Parse()

	if *verbose {
		security.SetLogLevel(security.LevelDebug)
	} else {
		security.SetLogLevel(security.LevelInfo)
	}

	rawURL := *urlFlag
	if rawURL == "" && len(flag.Args()) > 0 && strings.HasPrefix(flag.Arg(0), "ant://") {
		rawURL = flag.Arg(0)
	}
	if rawURL != "" {
		pk, h, tm, sn, err := ParseURL(rawURL)
		if err != nil {
			security.Error("Invalid ant:// URL: %v", err)
			os.Exit(1)
		}
		*serverKeyStr = pk
		*serverAddr = h
		if tm != "" {
			*transMode = tm
		}
		if sn != "" {
			*sni = sn
		}
	}

	if *serverKeyStr == "" {
		fmt.Println("Error: -key (server public key) or -url (ant://...) is required")
		flag.Usage()
		os.Exit(1)
	}

	serverPub, err := crypto.ParsePublicKey(*serverKeyStr)
	if err != nil {
		security.Error("Invalid server public key: %v", err)
		os.Exit(1)
	}

	clientPriv, _, err := crypto.GenerateKeyPair()
	if err != nil {
		security.Error("Failed to generate client ephemeral keys: %v", err)
		os.Exit(1)
	}
	defer clientPriv.Wipe()

	security.Info("Starting AnonymousAnt Client connecting to server...")

	// 1. Initialize Transport
	var tr transport.Transport
	switch *transMode {
	case "udp":
		tr, err = transport.NewUDPTransport(":0")
	case "tls":
		tr, err = transport.NewTLSClientTransport(*serverAddr, *sni)
	case "ws":
		wsURL := fmt.Sprintf("wss://%s/ws", *serverAddr)
		origin := fmt.Sprintf("https://%s", *sni)
		tr, err = transport.NewWSClientTransport(wsURL, origin, *sni)
	default:
		security.Error("Unknown transport: %s", *transMode)
		os.Exit(1)
	}
	if err != nil {
		security.Error("Failed to initialize transport: %v", err)
		os.Exit(1)
	}
	defer tr.Close()

	targetAddr, err := net.ResolveUDPAddr("udp", *serverAddr)
	if err != nil && *transMode == "udp" {
		security.Error("Failed to resolve server address: %v", err)
		os.Exit(1)
	}

	// 2. Perform Noise IK 1-RTT Handshake
	clientIndex := crypto.GenerateIndex()
	initiator, err := crypto.NewInitiatorHandshake(clientPriv, serverPub, clientIndex)
	if err != nil {
		security.Error("Handshake init failed: %v", err)
		os.Exit(1)
	}

	initMsg, err := initiator.CreateInitiation()
	if err != nil {
		security.Error("Failed to create handshake initiation: %v", err)
		os.Exit(1)
	}

	initBuf := buffer.Get()
	copy(initBuf.Data, initMsg)
	initBuf.Length = len(initMsg)
	if err := tr.Send(initBuf, targetAddr); err != nil {
		security.Error("Failed to send handshake: %v", err)
		os.Exit(1)
	}
	buffer.Put(initBuf)

	// Await handshake response
	respBuf := buffer.Get()
	_, err = tr.Receive(respBuf)
	if err != nil {
		security.Error("Failed to receive handshake response: %v", err)
		os.Exit(1)
	}

	sessionKeys, err := initiator.ConsumeResponse(respBuf.Bytes())
	buffer.Put(respBuf)
	if err != nil {
		security.Error("Handshake authentication failed: %v", err)
		os.Exit(1)
	}

	session, err := protocol.NewSession(sessionKeys, targetAddr, crypto.CipherChaCha20Poly1305)
	if err != nil {
		security.Error("Session setup failed: %v", err)
		os.Exit(1)
	}
	defer session.Wipe()

	security.Info("Handshake successful! Tunnel securely established.")

	// 3. Create TUN interface
	tunDev, err := tun.CreateTUN(*tunName, tun.DefaultMTU)
	if err != nil {
		security.Warn("Failed to create TUN interface (requires sudo): %v", err)
		security.Warn("Running in test mode without OS network device")
	} else {
		defer tunDev.Close()
		security.Info("TUN interface established: %s", tunDev.Name())
		_ = tun.ConfigureIP(tunDev.Name(), *localIP, *serverIP)
	}

	// 4. Configure OS routing and Kill Switch if requested
	var rtr router.Router
	var ks *security.KillSwitch
	if *enableRoutes && tunDev != nil {
		host, portStr, err := net.SplitHostPort(*serverAddr)
		if err != nil {
			host = *serverAddr
			portStr = "8443"
		}
		port, _ := strconv.Atoi(portStr)
		rtr = router.NewPlatformRouter()
		_ = rtr.SetupRoutes(tunDev.Name(), host, "")
		_ = rtr.SetupDNS([]string{"1.1.1.1", "1.0.0.1"})
		defer rtr.RestoreRoutes()
		defer rtr.RestoreDNS()

		if *enableKillSwitch {
			ks = security.NewKillSwitch(tunDev.Name(), host, port)
			_ = ks.Enable()
			defer ks.Disable()
		}
	}

	// 5. Packet Forwarding Loops
	stopCh := make(chan struct{})

	// Loop 1: TUN -> Network
	if tunDev != nil {
		go func() {
			for {
				buf := buffer.Get()
				if err := tunDev.ReadPacket(buf); err != nil {
					buffer.Put(buf)
					return
				}

				if err := session.EncryptPacket(buf, protocol.TypeData, 0); err != nil {
					buffer.Put(buf)
					continue
				}

				_ = tr.Send(buf, targetAddr)
				buffer.Put(buf)
			}
		}()
	}

	// Loop 2: Network -> TUN
	go func() {
		for {
			buf := buffer.Get()
			_, err := tr.Receive(buf)
			if err != nil {
				buffer.Put(buf)
				select {
				case <-stopCh:
					return
				default:
					continue
				}
			}

			h, err := protocol.StripHeader(buf)
			if err != nil {
				buffer.Put(buf)
				continue
			}

			if h.ReceiverIndex != session.LocalIndex {
				buffer.Put(buf)
				continue
			}

			if err := session.DecryptPacket(buf, h); err != nil {
				buffer.Put(buf)
				continue
			}

			if h.Type == protocol.TypeData && tunDev != nil {
				_ = tunDev.WritePacket(buf)
			}
			buffer.Put(buf)
		}
	}()

	// Heartbeat Keepalive loop
	go func() {
		ticker := time.NewTicker(protocol.KeepaliveInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				buf := buffer.Get()
				buf.Length = 0
				_ = session.EncryptPacket(buf, protocol.TypeKeepalive, 0)
				_ = tr.Send(buf, targetAddr)
				buffer.Put(buf)
			case <-stopCh:
				return
			}
		}
	}()

	// Wait for interrupt signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	<-sigCh

	close(stopCh)
	security.Info("Terminating AnonymousAnt Client. Restoring routes and clearing memory.")
}

// ParseURL parses an ant:// connection string.
func ParseURL(url string) (pubKey, host, transportMode, sni string, err error) {
	if !strings.HasPrefix(url, "ant://") {
		return "", "", "", "", fmt.Errorf("invalid URL scheme: must start with ant://")
	}
	trimmed := strings.TrimPrefix(url, "ant://")
	parts := strings.Split(trimmed, "@")
	if len(parts) != 2 {
		return "", "", "", "", fmt.Errorf("invalid URL format: expected ant://pubkey@host:port")
	}
	pubKey = parts[0]
	rest := parts[1]

	hostPart := rest
	transportMode = "tls"
	if idx := strings.Index(rest, "?"); idx != -1 {
		hostPart = rest[:idx]
		query := rest[idx+1:]
		for _, q := range strings.Split(query, "&") {
			kv := strings.Split(q, "=")
			if len(kv) == 2 {
				if kv[0] == "obfs" {
					transportMode = kv[1]
				} else if kv[0] == "sni" {
					sni = kv[1]
				}
			}
		}
	}
	host = hostPart
	return pubKey, host, transportMode, sni, nil
}
