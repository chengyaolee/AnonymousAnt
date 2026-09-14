package transport

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"sync"
	"time"

	"github.com/chengyaolee/AnonymousAnt/pkg/buffer"
	"github.com/chengyaolee/AnonymousAnt/pkg/security"
)

const (
	TLSTunnelMagic = "\x16\x03\x01\xAA\xBB" // Tunnel initiation marker
	DecoyHTML      = "<!DOCTYPE html><html><head><title>System Status</title></head><body><h1>Relay Service</h1><p>Node operational.</p></body></html>\r\n"
)

// GenerateSelfSignedCert creates an in-memory ephemeral TLS 1.3 certificate.
func GenerateSelfSignedCert() (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			Organization: []string{"Cloud Edge Services"},
			CommonName:   "gateway.internal",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	return tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  priv,
	}, nil
}

// TLSTransport provides chameleon TLS 1.3 tunneling on Port 443 with decoy web fallback.
type TLSTransport struct {
	isServer   bool
	listener   net.Listener
	clientConn net.Conn

	// Server-side active client connections
	mu          sync.RWMutex
	connections map[string]net.Conn
	incoming    chan incomingPacket
	closed      chan struct{}
}

type incomingPacket struct {
	addr net.Addr
	data []byte
}

// NewTLSServerTransport starts a chameleon TLS listener on the given address.
func NewTLSServerTransport(listenAddr string, cert *tls.Certificate) (*TLSTransport, error) {
	var serverCert tls.Certificate
	if cert != nil {
		serverCert = *cert
	} else {
		var err error
		serverCert, err = GenerateSelfSignedCert()
		if err != nil {
			return nil, fmt.Errorf("failed to generate ephemeral tls cert: %w", err)
		}
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{"h2", "http/1.1", "ant/1"},
	}

	ln, err := tls.Listen("tcp", listenAddr, tlsConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to start tls listener: %w", err)
	}

	t := &TLSTransport{
		isServer:    true,
		listener:    ln,
		connections: make(map[string]net.Conn),
		incoming:    make(chan incomingPacket, 1024),
		closed:      make(chan struct{}),
	}

	go t.acceptLoop()
	return t, nil
}

// NewTLSClientTransport connects to a remote TLS 443 exit node using SNI masquerading.
func NewTLSClientTransport(serverAddr, sni string) (*TLSTransport, error) {
	if sni == "" {
		host, _, err := net.SplitHostPort(serverAddr)
		if err == nil {
			sni = host
		} else {
			sni = serverAddr
		}
	}

	tlsConfig := &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true, // Ephemeral self-signed node support
		MinVersion:         tls.VersionTLS13,
		NextProtos:         []string{"ant/1", "http/1.1"},
	}

	conn, err := tls.Dial("tcp", serverAddr, tlsConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to dial tls server: %w", err)
	}

	t := &TLSTransport{
		isServer:   false,
		clientConn: conn,
		incoming:   make(chan incomingPacket, 1024),
		closed:     make(chan struct{}),
	}

	go t.clientReadLoop()
	return t, nil
}

func (t *TLSTransport) acceptLoop() {
	for {
		conn, err := t.listener.Accept()
		if err != nil {
			select {
			case <-t.closed:
				return
			default:
				security.Warn("TLS accept error: %v", err)
				continue
			}
		}

		go t.handleServerConn(conn)
	}
}

func (t *TLSTransport) handleServerConn(conn net.Conn) {
	raddr := conn.RemoteAddr().String()

	// Sniff first packet or header to identify probe vs VPN tunnel
	var header [2]byte
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err := io.ReadFull(conn, header[:])
	_ = conn.SetReadDeadline(time.Time{})

	if err != nil {
		conn.Close()
		return
	}

	// Check if this looks like a plaintext HTTP probe (e.g., 'GE', 'PO', 'HE')
	if (header[0] == 'G' && header[1] == 'E') ||
		(header[0] == 'P' && header[1] == 'O') ||
		(header[0] == 'H' && header[1] == 'E') {
		// Respond with genuine HTTP 200 OK Decoy Web Page to defeat active probing!
		response := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
			len(DecoyHTML), DecoyHTML)
		_, _ = conn.Write([]byte(response))
		conn.Close()
		return
	}

	// Legitimate tunnel connection: register connection
	t.mu.Lock()
	t.connections[raddr] = conn
	t.mu.Unlock()

	defer func() {
		t.mu.Lock()
		delete(t.connections, raddr)
		t.mu.Unlock()
		conn.Close()
	}()

	// Read initial packet using length in header
	pktLen := binary.LittleEndian.Uint16(header[:])
	if pktLen > 0 && pktLen <= buffer.DefaultBufferSize {
		pktBuf := make([]byte, pktLen)
		if _, err := io.ReadFull(conn, pktBuf); err == nil {
			t.incoming <- incomingPacket{addr: conn.RemoteAddr(), data: pktBuf}
		}
	}

	// Read subsequent framed packets: [2 bytes length][payload]
	var lenBuf [2]byte
	for {
		if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
			return
		}
		length := binary.LittleEndian.Uint16(lenBuf[:])
		if length == 0 || length > buffer.DefaultBufferSize {
			return
		}
		data := make([]byte, length)
		if _, err := io.ReadFull(conn, data); err != nil {
			return
		}

		select {
		case t.incoming <- incomingPacket{addr: conn.RemoteAddr(), data: data}:
		case <-t.closed:
			return
		}
	}
}

func (t *TLSTransport) clientReadLoop() {
	var lenBuf [2]byte
	for {
		if _, err := io.ReadFull(t.clientConn, lenBuf[:]); err != nil {
			return
		}
		length := binary.LittleEndian.Uint16(lenBuf[:])
		if length == 0 || length > buffer.DefaultBufferSize {
			return
		}
		data := make([]byte, length)
		if _, err := io.ReadFull(t.clientConn, data); err != nil {
			return
		}

		select {
		case t.incoming <- incomingPacket{addr: t.clientConn.RemoteAddr(), data: data}:
		case <-t.closed:
			return
		}
	}
}

// Send transmits the packet buffer over TLS with a 2-byte frame length prefix.
func (t *TLSTransport) Send(buf *buffer.PacketBuffer, target net.Addr) error {
	var lenBuf [2]byte
	binary.LittleEndian.PutUint16(lenBuf[:], uint16(buf.Length))

	if !t.isServer {
		if t.clientConn == nil {
			return errors.New("tls client disconnected")
		}
		if _, err := t.clientConn.Write(lenBuf[:]); err != nil {
			return err
		}
		_, err := t.clientConn.Write(buf.Bytes())
		return err
	}

	// Server mode: lookup connection for target
	t.mu.RLock()
	conn, exists := t.connections[target.String()]
	t.mu.RUnlock()

	if !exists {
		return fmt.Errorf("no active tls connection for target %s", target.String())
	}

	if _, err := conn.Write(lenBuf[:]); err != nil {
		return err
	}
	_, err := conn.Write(buf.Bytes())
	return err
}

// Receive reads the next available packet frame from the transport.
func (t *TLSTransport) Receive(buf *buffer.PacketBuffer) (net.Addr, error) {
	select {
	case pkt, ok := <-t.incoming:
		if !ok {
			return nil, errors.New("tls transport closed")
		}
		buf.Reset()
		copy(buf.Data, pkt.data)
		buf.Length = len(pkt.data)
		return pkt.addr, nil
	case <-t.closed:
		return nil, errors.New("tls transport closed")
	}
}

// LocalAddr returns the local socket address.
func (t *TLSTransport) LocalAddr() net.Addr {
	if t.isServer {
		return t.listener.Addr()
	}
	if t.clientConn != nil {
		return t.clientConn.LocalAddr()
	}
	return nil
}

// Close terminates the TLS transport.
func (t *TLSTransport) Close() error {
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
		return t.listener.Close()
	}

	if t.clientConn != nil {
		return t.clientConn.Close()
	}
	return nil
}

// Mode returns ModeTLS.
func (t *TLSTransport) Mode() Mode {
	return ModeTLS
}
