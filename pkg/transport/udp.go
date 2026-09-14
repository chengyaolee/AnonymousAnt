package transport

import (
	"errors"
	"fmt"
	"net"

	"github.com/chengyaolee/AnonymousAnt/pkg/buffer"
)

const (
	// SocketBufferSize allocates 4MB buffer to prevent kernel drops under heavy bursts
	SocketBufferSize = 4 * 1024 * 1024
)

// UDPTransport provides datagram I/O directly over UDP sockets.
type UDPTransport struct {
	conn *net.UDPConn
}

// NewUDPTransport creates a UDP transport bound to the given address.
// If addr is empty or ":0", an ephemeral port is assigned.
func NewUDPTransport(listenAddr string) (*UDPTransport, error) {
	var laddr *net.UDPAddr
	var err error
	if listenAddr != "" {
		laddr, err = net.ResolveUDPAddr("udp", listenAddr)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve udp addr: %w", err)
		}
	}

	conn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		return nil, fmt.Errorf("failed to listen on udp: %w", err)
	}

	// Optimize socket buffers
	_ = conn.SetReadBuffer(SocketBufferSize)
	_ = conn.SetWriteBuffer(SocketBufferSize)

	return &UDPTransport{conn: conn}, nil
}

// Send sends the packet buffer to the specified remote address.
func (u *UDPTransport) Send(buf *buffer.PacketBuffer, target net.Addr) error {
	udpAddr, ok := target.(*net.UDPAddr)
	if !ok {
		var err error
		udpAddr, err = net.ResolveUDPAddr("udp", target.String())
		if err != nil {
			return err
		}
	}

	n, err := u.conn.WriteToUDP(buf.Bytes(), udpAddr)
	if err != nil {
		return err
	}
	if n != buf.Length {
		return errors.New("short udp write")
	}
	return nil
}

// Receive reads an incoming packet directly into the buffer with zero intermediate allocations.
func (u *UDPTransport) Receive(buf *buffer.PacketBuffer) (net.Addr, error) {
	buf.Reset()
	n, raddr, err := u.conn.ReadFromUDP(buf.Data)
	if err != nil {
		return nil, err
	}
	buf.Length = n
	return raddr, nil
}

// LocalAddr returns the local bound UDP address.
func (u *UDPTransport) LocalAddr() net.Addr {
	return u.conn.LocalAddr()
}

// Close closes the UDP socket.
func (u *UDPTransport) Close() error {
	return u.conn.Close()
}

// Mode returns ModeUDP.
func (u *UDPTransport) Mode() Mode {
	return ModeUDP
}
