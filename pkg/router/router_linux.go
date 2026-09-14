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

	host := vpnServerIP
	if h, _, err := net.SplitHostPort(vpnServerIP); err == nil {
		host = h
	}

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
	r.physicalGateway = physicalGateway

	if targetIP != nil && !targetIP.IsLoopback() {
		if physicalGateway != "" {
			_ = exec.Command("ip", "route", "add", r.vpnServerIP, "via", physicalGateway).Run()
		}
		_ = exec.Command("ip", "route", "add", "0.0.0.0/1", "dev", tunName).Run()
		_ = exec.Command("ip", "route", "add", "128.0.0.0/1", "dev", tunName).Run()
	} else {
		_ = exec.Command("ip", "route", "add", "10.8.0.0/24", "dev", tunName).Run()
	}
	return nil
}

func (r *LinuxRouter) RestoreRoutes() error {
	if r.tunName != "" {
		_ = exec.Command("ip", "route", "del", "0.0.0.0/1", "dev", r.tunName).Run()
		_ = exec.Command("ip", "route", "del", "128.0.0.0/1", "dev", r.tunName).Run()
		_ = exec.Command("ip", "route", "del", "10.8.0.0/24", "dev", r.tunName).Run()
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
