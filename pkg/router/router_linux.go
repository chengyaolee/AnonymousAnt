//go:build linux

package router

import (
	"fmt"
	"net"
	"os/exec"

	"github.com/chengyaolee/AnonymousAnt/pkg/security"
)

type LinuxRouter struct {
	tunName         string
	vpnServerIP     string
	physicalGateway string
}

func NewPlatformRouter() Router {
	return &LinuxRouter{}
}

func (r *LinuxRouter) SetupRoutes(tunName, vpnServerIP, physicalGateway string) error {
	r.tunName = tunName
	r.vpnServerIP = vpnServerIP
	r.physicalGateway = physicalGateway

	ip := net.ParseIP(vpnServerIP)
	if ip != nil && !ip.IsLoopback() && physicalGateway != "" {
		_ = exec.Command("ip", "route", "add", vpnServerIP, "via", physicalGateway).Run()
	}

	_ = exec.Command("ip", "route", "add", "0.0.0.0/1", "dev", tunName).Run()
	_ = exec.Command("ip", "route", "add", "128.0.0.0/1", "dev", tunName).Run()
	return nil
}

func (r *LinuxRouter) RestoreRoutes() error {
	if r.tunName != "" {
		_ = exec.Command("ip", "route", "del", "0.0.0.0/1", "dev", r.tunName).Run()
		_ = exec.Command("ip", "route", "del", "128.0.0.0/1", "dev", r.tunName).Run()
	}
	if r.vpnServerIP != "" && r.physicalGateway != "" {
		_ = exec.Command("ip", "route", "del", r.vpnServerIP, "via", r.physicalGateway).Run()
	}
	return nil
}

func (r *LinuxRouter) SetupDNS(dnsServers []string) error {
	// Typically managed via resolvconf or systemd-resolved
	return nil
}

func (r *LinuxRouter) RestoreDNS() error {
	return nil
}
