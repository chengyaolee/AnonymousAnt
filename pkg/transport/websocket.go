package transport

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"

	"github.com/chengyaolee/AnonymousAnt/pkg/buffer"
	"golang.org/x/net/websocket"
)

// WSTransport allows tunneling through strict CDNs and corporate HTTP forward proxies.
type WSTransport struct {
	isServer   bool
	server     *http.Server
	clientConn *websocket.Conn
	listener   net.Listener

	mu          sync.RWMutex
	connections map[string]*websocket.Conn
	incoming    chan incomingPacket
	closed      chan struct{}
}

// NewWSServerTransport starts an HTTPS server providing a WebSocket endpoint at `path`.
func NewWSServerTransport(listenAddr, path string, cert *tls.Certificate) (*WSTransport, error) {
	if path == "" {
		path = "/ws"
	}

	var serverCert tls.Certificate
	if cert != nil {
		serverCert = *cert
	} else {
		var err error
		serverCert, err = GenerateSelfSignedCert()
		if err != nil {
			return nil, err
		}
	}

	t := &WSTransport{
		isServer:    true,
		connections: make(map[string]*websocket.Conn),
		incoming:    make(chan incomingPacket, 1024),
		closed:      make(chan struct{}),
	}

	mux := http.NewServeMux()
	mux.Handle(path, websocket.Handler(func(ws *websocket.Conn) {
		t.handleWSConn(ws)
	}))
	// Benign fallback for root
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(DecoyHTML))
	})

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		MinVersion:   tls.VersionTLS13,
	}

	ln, err := tls.Listen("tcp", listenAddr, tlsConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to listen on tls for ws: %w", err)
	}
	t.listener = ln

	t.server = &http.Server{
		Handler:   mux,
		TLSConfig: tlsConfig,
	}

	go func() {
		_ = t.server.Serve(ln)
	}()

	return t, nil
}

// NewWSClientTransport dials an external WebSocket endpoint over TLS.
func NewWSClientTransport(wsURL, origin, sni string) (*WSTransport, error) {
	cfg, err := websocket.NewConfig(wsURL, origin)
	if err != nil {
		return nil, err
	}
	cfg.TlsConfig = &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS13,
	}

	conn, err := websocket.DialConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to dial websocket: %w", err)
	}

	t := &WSTransport{
		isServer:   false,
		clientConn: conn,
		incoming:   make(chan incomingPacket, 1024),
		closed:     make(chan struct{}),
	}

	go t.clientReadLoop()
	return t, nil
}

func (t *WSTransport) handleWSConn(ws *websocket.Conn) {
	raddr := ws.Request().RemoteAddr
	ws.PayloadType = websocket.BinaryFrame

	t.mu.Lock()
	t.connections[raddr] = ws
	t.mu.Unlock()

	defer func() {
		t.mu.Lock()
		delete(t.connections, raddr)
		t.mu.Unlock()
		ws.Close()
	}()

	for {
		var data []byte
		if err := websocket.Message.Receive(ws, &data); err != nil {
			return
		}
		if len(data) == 0 {
			continue
		}

		select {
		case t.incoming <- incomingPacket{addr: ws.RemoteAddr(), data: data}:
		case <-t.closed:
			return
		}
	}
}

func (t *WSTransport) clientReadLoop() {
	t.clientConn.PayloadType = websocket.BinaryFrame
	for {
		var data []byte
		if err := websocket.Message.Receive(t.clientConn, &data); err != nil {
			return
		}
		if len(data) == 0 {
			continue
		}

		select {
		case t.incoming <- incomingPacket{addr: t.clientConn.RemoteAddr(), data: data}:
		case <-t.closed:
			return
		}
	}
}

// Send transmits the packet buffer as a binary WebSocket message.
func (t *WSTransport) Send(buf *buffer.PacketBuffer, target net.Addr) error {
	if !t.isServer {
		if t.clientConn == nil {
			return errors.New("ws client disconnected")
		}
		return websocket.Message.Send(t.clientConn, buf.Bytes())
	}

	t.mu.RLock()
	ws, exists := t.connections[target.String()]
	t.mu.RUnlock()

	if !exists {
		return fmt.Errorf("no active ws connection for %s", target.String())
	}

	return websocket.Message.Send(ws, buf.Bytes())
}

// Receive reads the next packet from the WebSocket channel.
func (t *WSTransport) Receive(buf *buffer.PacketBuffer) (net.Addr, error) {
	select {
	case pkt, ok := <-t.incoming:
		if !ok {
			return nil, errors.New("ws transport closed")
		}
		buf.Reset()
		copy(buf.Data, pkt.data)
		buf.Length = len(pkt.data)
		return pkt.addr, nil
	case <-t.closed:
		return nil, errors.New("ws transport closed")
	}
}

// LocalAddr returns the bound address.
func (t *WSTransport) LocalAddr() net.Addr {
	if t.isServer && t.listener != nil {
		return t.listener.Addr()
	}
	if t.clientConn != nil {
		return t.clientConn.LocalAddr()
	}
	return nil
}

// Close closes the WebSocket transport.
func (t *WSTransport) Close() error {
	select {
	case <-t.closed:
		return nil
	default:
		close(t.closed)
	}

	if t.isServer {
		t.mu.Lock()
		for _, c := range t.connections {
			_ = c.Close()
		}
		t.mu.Unlock()
		if t.server != nil {
			_ = t.server.Close()
		}
		if t.listener != nil {
			_ = t.listener.Close()
		}
		return nil
	}

	if t.clientConn != nil {
		return t.clientConn.Close()
	}
	return nil
}

// Mode returns ModeWebSocket.
func (t *WSTransport) Mode() Mode {
	return ModeWebSocket
}
