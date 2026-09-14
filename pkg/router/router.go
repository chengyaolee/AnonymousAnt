package router

import (
	"errors"
)

// Router manages OS-level routing tables and DNS configurations.
type Router interface {
	// SetupRoutes redirects default internet traffic to the VPN tunnel,
	// preserving the host gateway route to the VPN server to prevent routing loops.
	SetupRoutes(tunName, vpnServerIP, physicalGateway string) error

	// RestoreRoutes cleanly restores default routing back to the original physical gateway.
	RestoreRoutes() error

	// SetupDNS points the system resolver to the VPN DNS servers to prevent DNS leaks.
	SetupDNS(dnsServers []string) error

	// RestoreDNS restores the original DNS resolver settings.
	RestoreDNS() error
}

var ErrNotImplemented = errors.New("routing not implemented for this platform")
