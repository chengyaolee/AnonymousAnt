//go:build windows

package router

import (
	"os/exec"
)

type WindowsRouter struct {
	tunName     string
	vpnServerIP string
}

func NewPlatformRouter() Router {
	return &WindowsRouter{}
}

func (r *WindowsRouter) SetupRoutes(tunName, vpnServerIP, physicalGateway string) error {
	r.tunName = tunName
	r.vpnServerIP = vpnServerIP

	// Windows route add commands
	_ = exec.Command("route", "add", "0.0.0.0", "mask", "128.0.0.0", "0.0.0.0", "if", tunName).Run()
	_ = exec.Command("route", "add", "128.0.0.0", "mask", "128.0.0.0", "0.0.0.0", "if", tunName).Run()
	return nil
}

func (r *WindowsRouter) RestoreRoutes() error {
	_ = exec.Command("route", "delete", "0.0.0.0", "mask", "128.0.0.0").Run()
	_ = exec.Command("route", "delete", "128.0.0.0", "mask", "128.0.0.0").Run()
	return nil
}

func (r *WindowsRouter) SetupDNS(dnsServers []string) error {
	return nil
}

func (r *WindowsRouter) RestoreDNS() error {
	return nil
}
