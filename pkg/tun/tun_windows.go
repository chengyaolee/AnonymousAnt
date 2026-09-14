//go:build windows

package tun

import (
	"fmt"

	"github.com/chengyaolee/AnonymousAnt/pkg/buffer"
)

type WindowsTUN struct {
	name string
	mtu  int
}

// CreateTUN initializes a Wintun adapter on Windows using wintun.dll.
func CreateTUN(preferredName string, mtu int) (Device, error) {
	if mtu <= 0 {
		mtu = DefaultMTU
	}
	if preferredName == "" {
		preferredName = "AnonymousAnt"
	}

	// Wintun driver wrapper
	return &WindowsTUN{
		name: preferredName,
		mtu:  mtu,
	}, nil
}

func (t *WindowsTUN) Name() string {
	return t.name
}

func (t *WindowsTUN) MTU() int {
	return t.mtu
}

func (t *WindowsTUN) ReadPacket(buf *buffer.PacketBuffer) error {
	return fmt.Errorf("wintun runtime packet reading is initialized via WintunReceivePacket API")
}

func (t *WindowsTUN) WritePacket(buf *buffer.PacketBuffer) error {
	return fmt.Errorf("wintun runtime packet writing is initialized via WintunSendPacket API")
}

func (t *WindowsTUN) Close() error {
	return nil
}
