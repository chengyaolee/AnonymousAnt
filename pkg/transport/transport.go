package transport

import (
	"net"

	"github.com/chengyaolee/AnonymousAnt/pkg/buffer"
)

// Mode represents the active transport protocol.
type Mode string

const (
	ModeUDP       Mode = "udp"
	ModeTLS       Mode = "tls"
	ModeWebSocket Mode = "ws"
)

// Transport is the universal interface implemented by all AnonymousAnt network transports.
type Transport interface {
	// Send transmits the packet buffer to the specified remote address.
	Send(buf *buffer.PacketBuffer, target net.Addr) error

	// Receive reads an incoming packet into the buffer and returns the remote address.
	Receive(buf *buffer.PacketBuffer) (net.Addr, error)

	// LocalAddr returns the local bound address.
	LocalAddr() net.Addr

	// Close cleanly terminates the transport listener or connection.
	Close() error

	// Mode returns the transport type identifier.
	Mode() Mode
}
