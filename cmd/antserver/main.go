package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"sync"
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
	enableNAT := flag.Bool("nat", true, "Automatically configure IPv4 forwarding and NAT masquerade for exit routing")
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

	tlsPort := strings.TrimPrefix(*tlsListen, ":")
	if _, p, err := net.SplitHostPort(*tlsListen); err == nil {
		tlsPort = p
	}

	fmt.Println("==================================================================")
	fmt.Printf(" Server Public Key:  %s\n", serverPub.Base64())
	fmt.Printf(" Connection String:  ant://%s@<SERVER_HOST>:%s?obfs=tls\n", serverPub.Base64(), tlsPort)
	fmt.Println("==================================================================")

	// Create TUN interface
	tunDev, err := tun.CreateTUN(*tunName, tun.DefaultMTU)
	if err != nil {
		security.Warn("Failed to create TUN interface (requires sudo/root): %v", err)
		security.Warn("Running in relay/forwarding mode without local TUN")
	} else {
		defer tunDev.Close()
		security.Info("TUN interface created: %s", tunDev.Name())
		_ = tun.ConfigureIP(tunDev.Name(), *virtualIP, *peerIP)

		if *enableNAT {
			cleanupNAT := setupServerNAT(tunDev.Name(), *virtualIP)
			defer cleanupNAT()
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

	peerTable := NewPeerTable()

	// TUN Egress loop (from TUN to network clients)
	if tunDev != nil {
		go func() {
			for {
				buf := buffer.Get()
				if err := tunDev.ReadPacket(buf); err != nil {
					buffer.Put(buf)
					return
				}

				var peer *ClientPeer
				if buf.Length >= 20 && buf.Bytes()[0]>>4 == 4 {
					dstIP := net.IP(buf.Bytes()[16:20]).String()
					peer = peerTable.Lookup(dstIP)
				} else {
					peer = peerTable.Lookup("")
				}

				if peer != nil && peer.Session != nil && peer.Transport != nil {
					if err := peer.Session.EncryptPacket(buf, protocol.TypeData, 0); err == nil {
						_ = peer.Transport.Send(buf, peer.RemoteAddr)
					}
				}
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

				handleIncomingPacket(t, raddr, buf, serverPriv, sessionMgr, peerTable, tunDev, *peerIP)
			}
		}(tr)
	}

	// Wait for interrupt
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	<-sigCh

	security.Info("Shutting down AnonymousAnt Server. Zeroing all memory.")
}

// ClientPeer tracks an active peer's virtual IP, session, and network address for return routing.
type ClientPeer struct {
	Session    *protocol.Session
	Transport  transport.Transport
	RemoteAddr net.Addr
	VirtualIP  string
	LastActive time.Time
}

// PeerTable maps virtual IP addresses (e.g. 10.8.0.2) to client sessions.
type PeerTable struct {
	mu         sync.RWMutex
	peersByIP  map[string]*ClientPeer
	lastActive *ClientPeer
}

func NewPeerTable() *PeerTable {
	return &PeerTable{
		peersByIP: make(map[string]*ClientPeer),
	}
}

func (pt *PeerTable) Register(ip string, session *protocol.Session, tr transport.Transport, raddr net.Addr) {
	pt.mu.Lock()
	defer pt.mu.Unlock()

	peer, exists := pt.peersByIP[ip]
	if !exists {
		peer = &ClientPeer{
			VirtualIP: ip,
		}
		pt.peersByIP[ip] = peer
	}
	peer.Session = session
	peer.Transport = tr
	peer.RemoteAddr = raddr
	peer.LastActive = time.Now()
	pt.lastActive = peer
}

func (pt *PeerTable) Lookup(ip string) *ClientPeer {
	pt.mu.RLock()
	defer pt.mu.RUnlock()

	if peer, ok := pt.peersByIP[ip]; ok {
		return peer
	}
	return pt.lastActive
}

func handleIncomingPacket(
	tr transport.Transport,
	raddr net.Addr,
	buf *buffer.PacketBuffer,
	serverPriv *crypto.PrivateKey,
	sessionMgr *protocol.SessionManager,
	peerTable *PeerTable,
	tunDev tun.Device,
	defaultPeerIP string,
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
		peerTable.Register(defaultPeerIP, session, tr, raddr)
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
		// Learn client IP address from packet source
		if buf.Length >= 20 && buf.Bytes()[0]>>4 == 4 {
			srcIP := net.IP(buf.Bytes()[12:16]).String()
			peerTable.Register(srcIP, session, tr, raddr)
		} else {
			peerTable.Register(defaultPeerIP, session, tr, raddr)
		}

		// Forward raw IP packet into TUN interface
		if tunDev != nil {
			_ = tunDev.WritePacket(buf)
		}
	case protocol.TypeKeepalive:
		// Heartbeat packet to maintain NAT hole punching
		session.LastActive.Store(time.Now().UnixNano())
		peerTable.Register(defaultPeerIP, session, tr, raddr)
	case protocol.TypeDisconnect:
		sessionMgr.Remove(h.ReceiverIndex)
		security.Info("Client disconnected cleanly")
	}
}

// setupServerNAT configures IP forwarding and NAT masquerade so the server acts as an exit node.
func setupServerNAT(tunName, virtualSubnet string) func() {
	if runtime.GOOS == "linux" {
		_ = exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1").Run()

		out, err := exec.Command("sh", "-c", "ip route show default | awk '{print $5}'").Output()
		wanIface := strings.TrimSpace(string(out))
		if err == nil && wanIface != "" {
			security.Info("Enabling NAT masquerade on WAN interface %s for subnet %s/24", wanIface, virtualSubnet)
			_ = exec.Command("iptables", "-t", "nat", "-A", "POSTROUTING", "-s", virtualSubnet+"/24", "-o", wanIface, "-j", "MASQUERADE").Run()
			_ = exec.Command("iptables", "-A", "FORWARD", "-i", tunName, "-j", "ACCEPT").Run()
			_ = exec.Command("iptables", "-A", "FORWARD", "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT").Run()

			return func() {
				_ = exec.Command("iptables", "-t", "nat", "-D", "POSTROUTING", "-s", virtualSubnet+"/24", "-o", wanIface, "-j", "MASQUERADE").Run()
				_ = exec.Command("iptables", "-D", "FORWARD", "-i", tunName, "-j", "ACCEPT").Run()
				_ = exec.Command("iptables", "-D", "FORWARD", "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT").Run()
			}
		}
	} else if runtime.GOOS == "darwin" {
		_ = exec.Command("sysctl", "-w", "net.inet.ip.forwarding=1").Run()
	}
	return func() {}
}
