//go:build darwin

package router

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"os/exec"
	"strings"

	"github.com/chengyaolee/AnonymousAnt/pkg/security"
)

type DarwinRouter struct {
	tunName         string
	vpnServerIP     string
	physicalGateway string
	origDNSServers  []string
	primaryService  string
}

func NewPlatformRouter() Router {
	return &DarwinRouter{}
}

// GetDefaultGateway discovers the current physical default gateway IP and interface.
func GetDefaultGateway() (gateway string, iface string, err error) {
	cmd := exec.Command("route", "-n", "get", "default")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", "", fmt.Errorf("failed to get default gateway: %w", err)
	}

	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "gateway:") {
			gateway = strings.TrimSpace(strings.TrimPrefix(line, "gateway:"))
		} else if strings.HasPrefix(line, "interface:") {
			iface = strings.TrimSpace(strings.TrimPrefix(line, "interface:"))
		}
	}

	if gateway == "" {
		return "", "", fmt.Errorf("no default gateway found in route output")
	}
	return gateway, iface, nil
}

func (r *DarwinRouter) SetupRoutes(tunName, vpnServerIP, physicalGateway string) error {
	r.tunName = tunName

	host := vpnServerIP
	if h, _, err := net.SplitHostPort(vpnServerIP); err == nil {
		host = h
	}

	// Resolve hostname to IP if domain was provided
	var targetIP net.IP
	if ips, err := net.LookupIP(host); err == nil && len(ips) > 0 {
		for _, ip := range ips {
			if ip.To4() != nil {
				targetIP = ip.To4()
				break
			}
		}
	}
	if targetIP == nil {
		targetIP = net.ParseIP(host)
	}

	if targetIP != nil {
		r.vpnServerIP = targetIP.String()
	} else {
		r.vpnServerIP = host
	}

	if physicalGateway == "" {
		gw, _, err := GetDefaultGateway()
		if err != nil {
			return err
		}
		physicalGateway = gw
	}
	r.physicalGateway = physicalGateway

	// 1. Add host route to VPN Server via physical gateway so tunnel packets don't loop
	// Only needed if vpnServerIP is a real remote host (not loopback)
	if targetIP != nil && !targetIP.IsLoopback() {
		security.Info("Preserving physical route to VPN server %s via gateway %s", r.vpnServerIP, physicalGateway)
		cmd := exec.Command("route", "add", "-host", r.vpnServerIP, physicalGateway)
		_ = cmd.Run()

		// 2. Add two /1 subnets to cover 0.0.0.0/0 without overwriting the default gateway
		security.Info("Routing all internet traffic via interface %s", tunName)
		cmd1 := exec.Command("route", "add", "0.0.0.0/1", "-interface", tunName)
		if out, err := cmd1.CombinedOutput(); err != nil {
			return fmt.Errorf("failed to add 0.0.0.0/1 route: %s: %w", string(out), err)
		}

		cmd2 := exec.Command("route", "add", "128.0.0.0/1", "-interface", tunName)
		if out, err := cmd2.CombinedOutput(); err != nil {
			return fmt.Errorf("failed to add 128.0.0.0/1 route: %s: %w", string(out), err)
		}
	} else {
		// Loopback test mode: only route VPN subnet (10.8.0.0/24) to tun interface to prevent killing local internet
		security.Info("Loopback testing detected: routing only 10.8.0.0/24 to %s", tunName)
		_ = exec.Command("route", "add", "10.8.0.0/24", "-interface", tunName).Run()
	}

	return nil
}

func (r *DarwinRouter) RestoreRoutes() error {
	security.Info("Restoring original routing tables")
	if r.tunName != "" {
		_ = exec.Command("route", "delete", "0.0.0.0/1", "-interface", r.tunName).Run()
		_ = exec.Command("route", "delete", "128.0.0.0/1", "-interface", r.tunName).Run()
		_ = exec.Command("route", "delete", "10.8.0.0/24", "-interface", r.tunName).Run()
	}
	if r.vpnServerIP != "" && r.physicalGateway != "" {
		_ = exec.Command("route", "delete", "-host", r.vpnServerIP).Run()
	}
	return nil
}

func (r *DarwinRouter) SetupDNS(dnsServers []string) error {
	if len(dnsServers) == 0 {
		dnsServers = []string{"1.1.1.1", "1.0.0.1"}
	}
	// Discover primary network service
	out, err := exec.Command("networksetup", "-listallnetworkservices").CombinedOutput()
	if err != nil {
		return nil
	}
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		svc := strings.TrimSpace(line)
		if svc != "" && !strings.Contains(svc, "*") {
			r.primaryService = svc
			args := append([]string{"-setdnsservers", svc}, dnsServers...)
			_ = exec.Command("networksetup", args...).Run()
			break
		}
	}
	return nil
}

func (r *DarwinRouter) RestoreDNS() error {
	if r.primaryService != "" {
		_ = exec.Command("networksetup", "-setdnsservers", r.primaryService, "Empty").Run()
	}
	return nil
}
