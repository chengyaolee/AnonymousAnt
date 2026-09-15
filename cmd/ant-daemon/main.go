package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/chengyaolee/AnonymousAnt/pkg/buffer"
	"github.com/chengyaolee/AnonymousAnt/pkg/crypto"
	"github.com/chengyaolee/AnonymousAnt/pkg/ipc"
	"github.com/chengyaolee/AnonymousAnt/pkg/protocol"
	"github.com/chengyaolee/AnonymousAnt/pkg/router"
	"github.com/chengyaolee/AnonymousAnt/pkg/security"
	"github.com/chengyaolee/AnonymousAnt/pkg/transport"
	"github.com/chengyaolee/AnonymousAnt/pkg/tun"
)

type DaemonState struct {
	mu          sync.Mutex
	connected   bool
	params      ipc.ConnectParams
	tunDev      tun.Device
	transport   transport.Transport
	session     *protocol.Session
	router      router.Router
	killSwitch  *security.KillSwitch
	connectedAt time.Time
	stopCh      chan struct{}

	bytesSent       atomic.Uint64
	bytesReceived   atomic.Uint64
	packetsSent     atomic.Uint64
	packetsReceived atomic.Uint64
}

func (d *DaemonState) Handle(req ipc.Request) ipc.Response {
	switch req.Action {
	case ipc.ActionConnect:
		return d.handleConnect(req.Params)
	case ipc.ActionDisconnect:
		return d.handleDisconnect()
	case ipc.ActionGetStatus:
		return d.handleGetStatus()
	default:
		return ipc.Response{Success: false, Error: fmt.Sprintf("unknown action: %s", req.Action)}
	}
}

func sanitizeAddress(raw string) string {
	raw = strings.TrimSpace(raw)
	if strings.Contains(raw, "::") && !strings.HasPrefix(raw, "[") {
		raw = strings.ReplaceAll(raw, "::", ":")
	}
	if strings.HasSuffix(raw, ":") {
		return raw + "8443"
	}
	if !strings.Contains(raw, ":") {
		return net.JoinHostPort(raw, "8443")
	}
	return raw
}

func (d *DaemonState) handleConnect(params ipc.ConnectParams) ipc.Response {
	d.mu.Lock()
	defer d.mu.Unlock()

	params.ServerAddr = sanitizeAddress(params.ServerAddr)

	if d.connected {
		return ipc.Response{Success: false, Error: "already connected"}
	}

	serverPub, err := crypto.ParsePublicKey(params.ServerPubKey)
	if err != nil {
		return ipc.Response{Success: false, Error: fmt.Sprintf("invalid public key: %v", err)}
	}

	clientPriv, _, err := crypto.GenerateKeyPair()
	if err != nil {
		return ipc.Response{Success: false, Error: fmt.Sprintf("key generation failed: %v", err)}
	}
	defer clientPriv.Wipe()

	// Initialize transport
	var tr transport.Transport
	switch params.Transport {
	case "udp":
		tr, err = transport.NewUDPTransport(":0")
	case "tls", "":
		sni := params.SNI
		if sni == "" {
			sni = "gateway.internal"
		}
		tr, err = transport.NewTLSClientTransport(params.ServerAddr, sni)
	case "ws":
		wsURL := fmt.Sprintf("wss://%s/ws", params.ServerAddr)
		sni := params.SNI
		tr, err = transport.NewWSClientTransport(wsURL, "https://"+sni, sni)
	default:
		return ipc.Response{Success: false, Error: "unsupported transport"}
	}

	if err != nil {
		return ipc.Response{Success: false, Error: fmt.Sprintf("transport failed: %v", err)}
	}

	targetAddr, _ := net.ResolveUDPAddr("udp", params.ServerAddr)

	// Perform Handshake
	clientIndex := crypto.GenerateIndex()
	initiator, err := crypto.NewInitiatorHandshake(clientPriv, serverPub, clientIndex)
	if err != nil {
		tr.Close()
		return ipc.Response{Success: false, Error: err.Error()}
	}

	initMsg, err := initiator.CreateInitiation()
	if err != nil {
		tr.Close()
		return ipc.Response{Success: false, Error: err.Error()}
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
		return ipc.Response{Success: false, Error: "handshake receive failed"}
	}

	keys, err := initiator.ConsumeResponse(respBuf.Bytes())
	buffer.Put(respBuf)
	if err != nil {
		tr.Close()
		return ipc.Response{Success: false, Error: fmt.Sprintf("handshake auth failed: %v", err)}
	}

	session, err := protocol.NewSession(keys, targetAddr, crypto.CipherChaCha20Poly1305)
	if err != nil {
		tr.Close()
		return ipc.Response{Success: false, Error: err.Error()}
	}

	// Create TUN
	tunDev, err := tun.CreateTUN("ant0", tun.DefaultMTU)
	if err != nil {
		security.Warn("TUN creation warning: %v", err)
	} else {
		_ = tun.ConfigureIP(tunDev.Name(), "10.8.0.2", "10.8.0.1")
	}

	d.connected = true
	d.params = params
	d.transport = tr
	d.session = session
	d.tunDev = tunDev
	d.connectedAt = time.Now()
	d.stopCh = make(chan struct{})

	// Setup Routes and Kill Switch
	if tunDev != nil {
		host, portStr, err := net.SplitHostPort(params.ServerAddr)
		if err != nil {
			host = params.ServerAddr
			portStr = "8443"
		}
		port, _ := strconv.Atoi(portStr)
		d.router = router.NewPlatformRouter()
		_ = d.router.SetupRoutes(tunDev.Name(), host, "")
		_ = d.router.SetupDNS([]string{"1.1.1.1", "1.0.0.1"})

		if params.EnableKillSwitch {
			d.killSwitch = security.NewKillSwitch(tunDev.Name(), host, port)
			_ = d.killSwitch.Enable()
		}
	}

	// Start packet loops
	go d.runEgressLoop(targetAddr)
	go d.runIngressLoop()

	security.Info("Daemon connected successfully to %s", params.ServerAddr)
	return ipc.Response{Success: true}
}

func (d *DaemonState) runEgressLoop(targetAddr net.Addr) {
	if d.tunDev == nil {
		return
	}
	for {
		buf := buffer.Get()
		if err := d.tunDev.ReadPacket(buf); err != nil {
			buffer.Put(buf)
			return
		}

		d.bytesSent.Add(uint64(buf.Length))
		d.packetsSent.Add(1)

		if err := d.session.EncryptPacket(buf, protocol.TypeData, 0); err != nil {
			buffer.Put(buf)
			continue
		}

		_ = d.transport.Send(buf, targetAddr)
		buffer.Put(buf)
	}
}

func (d *DaemonState) runIngressLoop() {
	for {
		buf := buffer.Get()
		_, err := d.transport.Receive(buf)
		if err != nil {
			buffer.Put(buf)
			select {
			case <-d.stopCh:
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

		if h.ReceiverIndex != d.session.LocalIndex {
			buffer.Put(buf)
			continue
		}

		if err := d.session.DecryptPacket(buf, h); err != nil {
			buffer.Put(buf)
			continue
		}

		d.bytesReceived.Add(uint64(buf.Length))
		d.packetsReceived.Add(1)

		if h.Type == protocol.TypeData && d.tunDev != nil {
			_ = d.tunDev.WritePacket(buf)
		}
		buffer.Put(buf)
	}
}

func (d *DaemonState) handleDisconnect() ipc.Response {
	d.mu.Lock()
	defer d.mu.Unlock()

	if !d.connected {
		return ipc.Response{Success: true}
	}

	if d.stopCh != nil {
		close(d.stopCh)
	}
	if d.killSwitch != nil {
		_ = d.killSwitch.Disable()
	}
	if d.router != nil {
		_ = d.router.RestoreRoutes()
		_ = d.router.RestoreDNS()
	}
	if d.tunDev != nil {
		_ = d.tunDev.Close()
	}
	if d.transport != nil {
		_ = d.transport.Close()
	}
	if d.session != nil {
		d.session.Wipe()
	}

	d.connected = false
	security.Info("Daemon disconnected cleanly. Memory wiped.")
	return ipc.Response{Success: true}
}

func (d *DaemonState) handleGetStatus() ipc.Response {
	d.mu.Lock()
	defer d.mu.Unlock()

	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	memAllocMB := float64(m.Alloc) / 1024.0 / 1024.0

	var uptime int64
	if d.connected {
		uptime = int64(time.Since(d.connectedAt).Seconds())
	}

	ksActive := false
	if d.killSwitch != nil {
		ksActive = d.killSwitch.IsEnabled()
	}

	trans := "none"
	serverAddr := ""
	if d.connected {
		trans = d.params.Transport
		serverAddr = d.params.ServerAddr
	}

	return ipc.Response{
		Success: true,
		Status: &ipc.StatusResponse{
			Connected:        d.connected,
			Transport:        trans,
			ServerAddr:       serverAddr,
			BytesSent:        d.bytesSent.Load(),
			BytesReceived:    d.bytesReceived.Load(),
			PacketsSent:      d.packetsSent.Load(),
			PacketsReceived:  d.packetsReceived.Load(),
			UptimeSeconds:    uptime,
			MemoryAllocMB:    memAllocMB,
			KillSwitchActive: ksActive,
			VirtualIP:        "10.8.0.2",
		},
	}
}

func main() {
	sockPath := flag.String("sock", ipc.DefaultSocketPath, "Unix domain socket path for IPC")
	verbose := flag.Bool("v", false, "Verbose output")
	flag.Parse()

	if *verbose {
		security.SetLogLevel(security.LevelDebug)
	} else {
		security.SetLogLevel(security.LevelInfo)
	}

	security.Info("Starting AnonymousAnt Privileged Daemon")

	state := &DaemonState{}
	server, err := ipc.NewServer(*sockPath, state)
	if err != nil {
		security.Error("Failed to initialize IPC server: %v", err)
		os.Exit(1)
	}
	defer server.Close()

	security.Info("Daemon IPC listening on %s", *sockPath)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	<-sigCh

	security.Info("Daemon stopping...")
	state.handleDisconnect()
}
