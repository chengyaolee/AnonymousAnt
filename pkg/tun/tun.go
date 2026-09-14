package tun

import (
	"errors"

	"github.com/chengyaolee/AnonymousAnt/pkg/buffer"
)

const (
	DefaultMTU = 1420
)

// Device represents an abstract operating system TUN interface.
type Device interface {
	// Name returns the OS interface name (e.g. utun3, tun0).
	Name() string

	// MTU returns the configured Maximum Transmission Unit.
	MTU() int

	// ReadPacket reads a raw IP packet from the TUN device into the buffer.
	ReadPacket(buf *buffer.PacketBuffer) error

	// WritePacket writes a raw IP packet from the buffer into the TUN device.
	WritePacket(buf *buffer.PacketBuffer) error

	// Close terminates the TUN device.
	Close() error
}

var ErrNotImplemented = errors.New("tun device not implemented for this platform")
