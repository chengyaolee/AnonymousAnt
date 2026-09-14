//go:build darwin

package tun

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os/exec"
	"unsafe"

	"github.com/chengyaolee/AnonymousAnt/pkg/buffer"
	"golang.org/x/sys/unix"
)

const (
	utunControlName  = "com.apple.net.utun_control"
	sysprotoControl  = 2 // SYSPROTO_CONTROL / AF_SYS_CONTROL
	utunOptIfname    = 2 // UTUN_OPT_IFNAME
)

type DarwinTUN struct {
	fd   int
	name string
	mtu  int
}

// CreateTUN allocates a native macOS utun device.
func CreateTUN(preferredName string, mtu int) (Device, error) {
	if mtu <= 0 {
		mtu = DefaultMTU
	}

	fd, err := unix.Socket(unix.AF_SYSTEM, unix.SOCK_DGRAM, unix.AF_SYS_CONTROL)
	if err != nil {
		return nil, fmt.Errorf("failed to open af_system socket: %w", err)
	}

	var ctlInfo struct {
		ctlID   uint32
		ctlName [96]byte
	}
	copy(ctlInfo.ctlName[:], utunControlName)

	if err := ioctl(fd, unix.CTLIOCGINFO, uintptr(unsafe.Pointer(&ctlInfo))); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("ioctl CTLIOCGINFO failed: %w", err)
	}

	sc := unix.SockaddrCtl{
		ID:   ctlInfo.ctlID,
		Unit: 0, // Auto-assign next free utunX
	}

	if err := unix.Connect(fd, &sc); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("connect to utun failed: %w", err)
	}

	var nameBuf [64]byte
	nameLen := uint32(len(nameBuf))
	if err := getsockopt(fd, sysprotoControl, utunOptIfname, uintptr(unsafe.Pointer(&nameBuf[0])), &nameLen); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("failed to get utun name: %w", err)
	}

	ifName := string(nameBuf[:nameLen-1])

	// Set MTU
	cmd := exec.Command("ifconfig", ifName, "mtu", fmt.Sprintf("%d", mtu))
	_ = cmd.Run()

	return &DarwinTUN{
		fd:   fd,
		name: ifName,
		mtu:  mtu,
	}, nil
}

func (t *DarwinTUN) Name() string {
	return t.name
}

func (t *DarwinTUN) MTU() int {
	return t.mtu
}

// ReadPacket reads raw packet from utun and strips the 4-byte Darwin family prefix.
func (t *DarwinTUN) ReadPacket(buf *buffer.PacketBuffer) error {
	buf.Reset()
	n, err := unix.Read(t.fd, buf.Data)
	if err != nil {
		return err
	}
	if n < 4 {
		return errors.New("read short packet on utun")
	}

	// First 4 bytes are AF_INET / AF_INET6 header in network byte order
	buf.Offset = 4
	buf.Length = n - 4
	return nil
}

// WritePacket writes packet to utun, prepending the 4-byte family prefix.
func (t *DarwinTUN) WritePacket(buf *buffer.PacketBuffer) error {
	if buf.Length == 0 {
		return nil
	}

	// Check IP version (IPv4 starts with 4 in upper nibble, IPv6 starts with 6)
	version := buf.Bytes()[0] >> 4
	var family uint32 = unix.AF_INET
	if version == 6 {
		family = unix.AF_INET6
	}

	// If we have 4 bytes headroom at offset, prepend in-place
	if buf.Offset >= 4 {
		buf.Offset -= 4
		buf.Length += 4
		binary.BigEndian.PutUint32(buf.Data[buf.Offset:buf.Offset+4], family)
		_, err := unix.Write(t.fd, buf.Bytes())
		return err
	}

	// Otherwise write using a small temporary slice or shifted buffer
	out := make([]byte, buf.Length+4)
	binary.BigEndian.PutUint32(out[0:4], family)
	copy(out[4:], buf.Bytes())
	_, err := unix.Write(t.fd, out)
	return err
}

func (t *DarwinTUN) Close() error {
	return unix.Close(t.fd)
}

func ioctl(fd int, req uint, arg uintptr) error {
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(req), arg)
	if errno != 0 {
		return errno
	}
	return nil
}

func getsockopt(fd int, level, opt int, val uintptr, vallen *uint32) error {
	_, _, errno := unix.Syscall6(unix.SYS_GETSOCKOPT, uintptr(fd), uintptr(level), uintptr(opt), val, uintptr(unsafe.Pointer(vallen)), 0)
	if errno != 0 {
		return errno
	}
	return nil
}

// ConfigureIP assigns local and remote IP addresses to the utun interface.
func ConfigureIP(ifName, localIP, remoteIP string) error {
	cmd := exec.Command("ifconfig", ifName, localIP, remoteIP, "up")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("ifconfig failed: %s: %w", string(out), err)
	}
	return nil
}
