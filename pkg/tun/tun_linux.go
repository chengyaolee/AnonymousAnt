//go:build linux

package tun

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"unsafe"

	"github.com/chengyaolee/AnonymousAnt/pkg/buffer"
	"golang.org/x/sys/unix"
)

type LinuxTUN struct {
	file *os.File
	name string
	mtu  int
}

// CreateTUN opens /dev/net/tun and configures a persistent or ephemeral TUN interface.
func CreateTUN(preferredName string, mtu int) (Device, error) {
	if mtu <= 0 {
		mtu = DefaultMTU
	}

	file, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to open /dev/net/tun: %w", err)
	}

	var req struct {
		name  [16]byte
		flags uint16
		_     [22]byte
	}
	req.flags = unix.IFF_TUN | unix.IFF_NO_PI // Raw IP frames without 4-byte PI header
	if preferredName != "" {
		copy(req.name[:], preferredName)
	}

	_, _, errno := unix.Syscall(unix.SYS_IOCTL, file.Fd(), uintptr(unix.TUNSETIFF), uintptr(unsafe.Pointer(&req)))
	if errno != 0 {
		file.Close()
		return nil, fmt.Errorf("ioctl TUNSETIFF failed: %w", errno)
	}

	actualName := string(req.name[:])
	for i, b := range req.name {
		if b == 0 {
			actualName = string(req.name[:i])
			break
		}
	}

	// Configure MTU
	cmd := exec.Command("ip", "link", "set", "dev", actualName, "mtu", fmt.Sprintf("%d", mtu), "up")
	_ = cmd.Run()

	return &LinuxTUN{
		file: file,
		name: actualName,
		mtu:  mtu,
	}, nil
}

func (t *LinuxTUN) Name() string {
	return t.name
}

func (t *LinuxTUN) MTU() int {
	return t.mtu
}

func (t *LinuxTUN) ReadPacket(buf *buffer.PacketBuffer) error {
	buf.Reset()
	n, err := t.file.Read(buf.Data)
	if err != nil {
		return err
	}
	buf.Length = n
	return nil
}

func (t *LinuxTUN) WritePacket(buf *buffer.PacketBuffer) error {
	if buf.Length == 0 {
		return nil
	}
	n, err := t.file.Write(buf.Bytes())
	if err != nil {
		return err
	}
	if n != buf.Length {
		return errors.New("short tun write")
	}
	return nil
}

func (t *LinuxTUN) Close() error {
	return t.file.Close()
}

// ConfigureIP configures virtual IP addresses and brings up the interface on Linux.
func ConfigureIP(ifName, localIP, remoteIP string) error {
	_ = exec.Command("ip", "addr", "add", localIP+"/24", "peer", remoteIP, "dev", ifName).Run()
	cmd := exec.Command("ip", "link", "set", "dev", ifName, "up")
	return cmd.Run()
}
