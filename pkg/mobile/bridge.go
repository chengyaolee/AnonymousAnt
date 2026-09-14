package mobile

import (
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"sync/atomic"

	"github.com/chengyaolee/AnonymousAnt/pkg/buffer"
	"github.com/chengyaolee/AnonymousAnt/pkg/crypto"
	"github.com/chengyaolee/AnonymousAnt/pkg/protocol"
	"github.com/chengyaolee/AnonymousAnt/pkg/transport"
)

// PacketFlow is implemented by the iOS NEPacketTunnelProvider in Swift.
type PacketFlow interface {
	WritePacket(pkt []byte)
}

// TunnelEngine manages the Go tunnel lifecycle inside the iOS NetworkExtension process.
type TunnelEngine struct {
	mu         sync.Mutex
	running    bool
	flow       PacketFlow
	transport  transport.Transport
	session    *protocol.Session
	targetAddr net.Addr
	stopCh     chan struct{}

	bytesSent     atomic.Uint64
	bytesReceived atomic.Uint64
}

// Global instance for simple gomobile access
var globalEngine *TunnelEngine

// StartTunnel initializes the VPN tunnel from iOS NetworkExtension.
func StartTunnel(serverAddr, serverKey, transportMode, sni string, flow PacketFlow) error {
	if globalEngine != nil && globalEngine.running {
		return fmt.Errorf("tunnel already running")
	}

	serverPub, err := crypto.ParsePublicKey(serverKey)
	if err != nil {
		return fmt.Errorf("invalid server key: %w", err)
	}

	clientPriv, _, err := crypto.GenerateKeyPair()
	if err != nil {
		return fmt.Errorf("client key generation failed: %w", err)
	}
	defer clientPriv.Wipe()

	var tr transport.Transport
	switch transportMode {
	case "udp":
		tr, err = transport.NewUDPTransport(":0")
	case "tls", "":
		if sni == "" {
			sni = "gateway.internal"
		}
		tr, err = transport.NewTLSClientTransport(serverAddr, sni)
	case "ws":
		wsURL := fmt.Sprintf("wss://%s/ws", serverAddr)
		tr, err = transport.NewWSClientTransport(wsURL, "https://"+sni, sni)
	default:
		return fmt.Errorf("unsupported mobile transport: %s", transportMode)
	}

	if err != nil {
		return fmt.Errorf("transport initialization failed: %w", err)
	}

	targetAddr, _ := net.ResolveUDPAddr("udp", serverAddr)

	// Noise IK Handshake
	clientIndex := crypto.GenerateIndex()
	initiator, err := crypto.NewInitiatorHandshake(clientPriv, serverPub, clientIndex)
	if err != nil {
		tr.Close()
		return err
	}

	initMsg, err := initiator.CreateInitiation()
	if err != nil {
		tr.Close()
		return err
	}

	initBuf := buffer.Get()
	copy(initBuf.Data, initMsg)
	initBuf.Length = len(initMsg)
	_ = tr.Send(initBuf, targetAddr)
	buffer.Put(initBuf)

	respBuf := buffer.Get()
	_, err = tr.Receive(respBuf)
	if err != nil {
		buffer.Put(respBuf)
		tr.Close()
		return fmt.Errorf("handshake response timeout")
	}

	keys, err := initiator.ConsumeResponse(respBuf.Bytes())
	buffer.Put(respBuf)
	if err != nil {
		tr.Close()
		return fmt.Errorf("handshake authentication failed: %w", err)
	}

	session, err := protocol.NewSession(keys, targetAddr, crypto.CipherChaCha20Poly1305)
	if err != nil {
		tr.Close()
		return err
	}

	engine := &TunnelEngine{
		running:    true,
		flow:       flow,
		transport:  tr,
		session:    session,
		targetAddr: targetAddr,
		stopCh:     make(chan struct{}),
	}

	globalEngine = engine

	// Background network ingress loop (Network -> iOS NEPacketTunnelFlow)
	go engine.runNetworkIngress()

	return nil
}

// OnPacketFromDevice is called by Swift when an IP packet is read from iOS NEPacketTunnelFlow.
func OnPacketFromDevice(pkt []byte) {
	if globalEngine == nil || !globalEngine.running {
		return
	}

	buf := buffer.Get()
	copy(buf.Data, pkt)
	buf.Length = len(pkt)

	globalEngine.bytesSent.Add(uint64(len(pkt)))

	if err := globalEngine.session.EncryptPacket(buf, protocol.TypeData, 0); err != nil {
		buffer.Put(buf)
		return
	}

	_ = globalEngine.transport.Send(buf, globalEngine.targetAddr)
	buffer.Put(buf)
}

func (e *TunnelEngine) runNetworkIngress() {
	for {
		buf := buffer.Get()
		_, err := e.transport.Receive(buf)
		if err != nil {
			buffer.Put(buf)
			select {
			case <-e.stopCh:
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

		if h.ReceiverIndex != e.session.LocalIndex {
			buffer.Put(buf)
			continue
		}

		if err := e.session.DecryptPacket(buf, h); err != nil {
			buffer.Put(buf)
			continue
		}

		e.bytesReceived.Add(uint64(buf.Length))

		if h.Type == protocol.TypeData && e.flow != nil {
			// Deliver raw decrypted IP packet to iOS IP stack
			e.flow.WritePacket(buf.Bytes())
		}
		buffer.Put(buf)
	}
}

// StopTunnel cleanly terminates the mobile tunnel and zeroes keys.
func StopTunnel() {
	if globalEngine == nil {
		return
	}
	globalEngine.mu.Lock()
	defer globalEngine.mu.Unlock()

	if !globalEngine.running {
		return
	}

	close(globalEngine.stopCh)
	if globalEngine.transport != nil {
		_ = globalEngine.transport.Close()
	}
	if globalEngine.session != nil {
		globalEngine.session.Wipe()
	}
	globalEngine.running = false
	globalEngine = nil
}

// GetStats returns a JSON string with upload/download counts for the iOS UI.
func GetStats() string {
	if globalEngine == nil {
		return `{"running":false,"sent":0,"received":0}`
	}
	type stats struct {
		Running  bool   `json:"running"`
		Sent     uint64 `json:"sent"`
		Received uint64 `json:"received"`
	}
	st := stats{
		Running:  globalEngine.running,
		Sent:     globalEngine.bytesSent.Load(),
		Received: globalEngine.bytesReceived.Load(),
	}
	data, _ := json.Marshal(st)
	return string(data)
}
