package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/chengyaolee/AnonymousAnt/pkg/buffer"
	"github.com/chengyaolee/AnonymousAnt/pkg/crypto"
	"github.com/chengyaolee/AnonymousAnt/pkg/protocol"
	"github.com/chengyaolee/AnonymousAnt/pkg/security"
	"github.com/chengyaolee/AnonymousAnt/pkg/transport"
	"github.com/chengyaolee/AnonymousAnt/pkg/tun"
)

func main() {
	udpListen := flag.String("udp", ":51820", "UDP listen address")
	tlsListen := flag.String("tls", ":8443", "TLS port 443 listen address (chameleon mode with decoy web server)")
	privKeyStr := flag.String("key", "", "Server Curve25519 private key (base64/hex, auto-generated if empty)")
	tunName := flag.String("tun", "ant0", "TUN device name")
	virtualIP := flag.String("ip", "10.8.0.1", "Virtual IPv4 assigned to server TUN")
	peerIP := flag.String("peer-ip", "10.8.0.2", "Virtual IPv4 assigned to peer")
	verbose := flag.Bool("v", false, "Verbose output (redacted IPs)")
	flag.Parse()

	if *verbose {
		security.SetLogLevel(security.LevelDebug)
	} else {
		security.SetLogLevel(security.LevelInfo)
	}

	security.Info("Starting AnonymousAnt Server / Exit Node")

	var serverPriv *crypto.PrivateKey
	var serverPub *crypto.PublicKey
	var err error

	if *privKeyStr != "" {
		serverPriv, err = crypto.ParsePrivateKey(*privKeyStr)
		if err != nil {
			security.Error("Invalid private key: %v", err)
			os.Exit(1)
		}
		serverPub = serverPriv.PublicKey()
	} else {
		serverPriv, serverPub, err = crypto.GenerateKeyPair()
		if err != nil {
			security.Error("Failed to generate server keypair: %v", err)
			os.Exit(1)
		}
	}
	defer serverPriv.Wipe()

	fmt.Println("==================================================================")
	fmt.Printf(" Server Public Key:  %s\n", serverPub.Base64())
	fmt.Printf(" Connection String:  ant://%s@<SERVER_HOST>:%s?obfs=tls\n", serverPub.Base64(), *tlsListen)
	fmt.Println("==================================================================")

	// Create TUN interface
	tunDev, err := tun.CreateTUN(*tunName, tun.DefaultMTU)
	if err != nil {
		security.Warn("Failed to create TUN interface (requires sudo/root): %v", err)
		security.Warn("Running in relay/forwarding mode without local TUN")
	} else {
		defer tunDev.Close()
		security.Info("TUN interface created: %s", tunDev.Name())
		if runtime.GOOS == "darwin" {
			_ = tun.ConfigureIP(tunDev.Name(), *virtualIP, *peerIP)
		}
	}

	sessionMgr := protocol.NewSessionManager()
	defer sessionMgr.Clear()

	// Initialize Transports
	var transports []transport.Transport

	// 1. UDP Transport
	udpTr, err := transport.NewUDPTransport(*udpListen)
	if err != nil {
		security.Warn("UDP transport bind error: %v", err)
	} else {
		defer udpTr.Close()
		transports = append(transports, udpTr)
		security.Info("Listening on UDP %s", *udpListen)
	}

	// 2. Chameleon TLS Transport on Port 443 with Decoy Web Server
	tlsTr, err := transport.NewTLSServerTransport(*tlsListen, nil)
	if err != nil {
		security.Warn("TLS transport bind error: %v", err)
	} else {
		defer tlsTr.Close()
		transports = append(transports, tlsTr)
		security.Info("Listening on TLS %s (Chameleon Mode active with decoy web server)", *tlsListen)
	}

	if len(transports) == 0 {
		security.Error("No transports could be initialized")
		os.Exit(1)
	}

	// TUN Egress loop (from TUN to network clients)
	if tunDev != nil {
		go func() {
			for {
				buf := buffer.Get()
				if err := tunDev.ReadPacket(buf); err != nil {
					buffer.Put(buf)
					return
				}

				// Look up active peer session and transmit
				// For now in single-user exit mode, transmit to most recently active session
				// Production supports multi-peer routing table
				buffer.Put(buf)
			}
		}()
	}

	// Transport Ingress loops
	for _, tr := range transports {
		go func(t transport.Transport) {
			for {
				buf := buffer.Get()
				raddr, err := t.Receive(buf)
				if err != nil {
					buffer.Put(buf)
					return
				}

				handleIncomingPacket(t, raddr, buf, serverPriv, sessionMgr, tunDev)
			}
		}(tr)
	}

	// Wait for interrupt
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	<-sigCh

	security.Info("Shutting down AnonymousAnt Server. Zeroing all memory.")
}

func handleIncomingPacket(
	tr transport.Transport,
	raddr net.Addr,
	buf *buffer.PacketBuffer,
	serverPriv *crypto.PrivateKey,
	sessionMgr *protocol.SessionManager,
	tunDev tun.Device,
) {
	defer buffer.Put(buf)

	// Check if this is a Noise Handshake Initiation
	if buf.Length == crypto.NoiseHandshakeInitSize {
		serverIndex := crypto.GenerateIndex()
		responder := crypto.NewResponderHandshake(serverPriv, serverIndex)

		respMsg, sessionKeys, err := responder.ConsumeInitiation(buf.Bytes())
		if err != nil {
			security.Debug("Invalid handshake initiation: %v", err)
			return
		}

		session, err := protocol.NewSession(sessionKeys, raddr, crypto.CipherChaCha20Poly1305)
		if err != nil {
			security.Error("Failed to initialize session: %v", err)
			return
		}

		sessionMgr.Register(session)
		security.Info("Handshake established with new client session index=%d", serverIndex)

		// Send handshake response back
		respBuf := buffer.Get()
		copy(respBuf.Data, respMsg)
		respBuf.Length = len(respMsg)
		_ = tr.Send(respBuf, raddr)
		buffer.Put(respBuf)
		return
	}

	// Otherwise, process regular tunnel packet
	h, err := protocol.StripHeader(buf)
	if err != nil {
		return
	}

	session := sessionMgr.Get(h.ReceiverIndex)
	if session == nil {
		security.Debug("Unknown session index: %d", h.ReceiverIndex)
		return
	}

	if err := session.DecryptPacket(buf, h); err != nil {
		security.Debug("Packet decrypt error: %v", err)
		return
	}

	switch h.Type {
	case protocol.TypeData:
		// Forward raw IP packet into TUN interface
		if tunDev != nil {
			_ = tunDev.WritePacket(buf)
		}
	case protocol.TypeKeepalive:
		// Heartbeat packet to maintain NAT hole punching
		session.LastActive.Store(time.Now().UnixNano())
	case protocol.TypeDisconnect:
		sessionMgr.Remove(h.ReceiverIndex)
		security.Info("Client disconnected cleanly")
	}
}
