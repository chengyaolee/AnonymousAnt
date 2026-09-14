package security

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
)

// KillSwitch manages OS-level packet filters to block all non-tunnel outbound traffic
// when the VPN drops, preventing data and IP leaks.
type KillSwitch struct {
	enabled       bool
	tunName       string
	serverIP      string
	serverPort    int
	anchorFile    string
}

// NewKillSwitch creates a KillSwitch instance.
func NewKillSwitch(tunName, serverIP string, serverPort int) *KillSwitch {
	return &KillSwitch{
		tunName:    tunName,
		serverIP:   serverIP,
		serverPort: serverPort,
	}
}

// Enable activates the firewall kill switch.
func (ks *KillSwitch) Enable() error {
	switch runtime.GOOS {
	case "darwin":
		return ks.enableDarwin()
	case "linux":
		return ks.enableLinux()
	default:
		return fmt.Errorf("killswitch not implemented for OS %s", runtime.GOOS)
	}
}

// Disable deactivates the firewall kill switch and flushes rules.
func (ks *KillSwitch) Disable() error {
	switch runtime.GOOS {
	case "darwin":
		return ks.disableDarwin()
	case "linux":
		return ks.disableLinux()
	default:
		return nil
	}
}

func (ks *KillSwitch) enableDarwin() error {
	rules := fmt.Sprintf(`
set block-policy drop
set skip on lo0
pass out quick on %s all
pass out quick proto udp to %s port %d
pass out quick proto tcp to %s port %d
block out all
`, ks.tunName, ks.serverIP, ks.serverPort, ks.serverIP, ks.serverPort)

	f, err := os.CreateTemp("", "ant-pf-*.conf")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())

	if _, err := f.WriteString(rules); err != nil {
		return err
	}
	f.Close()

	// Load into anchor
	cmd := exec.Command("pfctl", "-a", "com.anonymousant.killswitch", "-f", f.Name())
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("pfctl anchor load failed: %s: %w", string(out), err)
	}

	// Enable pf
	_ = exec.Command("pfctl", "-e").Run()
	ks.enabled = true
	Info("Kill switch enabled via pfctl (macOS)")
	return nil
}

func (ks *KillSwitch) disableDarwin() error {
	cmd := exec.Command("pfctl", "-a", "com.anonymousant.killswitch", "-F", "all")
	_ = cmd.Run()
	ks.enabled = false
	Info("Kill switch disabled (macOS)")
	return nil
}

func (ks *KillSwitch) enableLinux() error {
	// iptables fallback
	_ = exec.Command("iptables", "-I", "OUTPUT", "!", "-o", ks.tunName, "-d", ks.serverIP, "-j", "ACCEPT").Run()
	_ = exec.Command("iptables", "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT").Run()
	_ = exec.Command("iptables", "-A", "OUTPUT", "-o", ks.tunName, "-j", "ACCEPT").Run()
	_ = exec.Command("iptables", "-A", "OUTPUT", "-j", "DROP").Run()
	ks.enabled = true
	Info("Kill switch enabled via iptables (Linux)")
	return nil
}

func (ks *KillSwitch) disableLinux() error {
	_ = exec.Command("iptables", "-D", "OUTPUT", "-j", "DROP").Run()
	ks.enabled = false
	Info("Kill switch disabled (Linux)")
	return nil
}

// IsEnabled returns true if the kill switch is currently active.
func (ks *KillSwitch) IsEnabled() bool {
	return ks.enabled
}
