package ipc

// Action represents an IPC command.
type Action string

const (
	ActionConnect       Action = "connect"
	ActionDisconnect    Action = "disconnect"
	ActionGetStatus     Action = "get_status"
	ActionSetKillSwitch Action = "set_killswitch"
)

// Request is sent from unprivileged UI/CLI to the privileged daemon.
type Request struct {
	Action Action        `json:"action"`
	Params ConnectParams `json:"params,omitempty"`
}

// ConnectParams contains connection settings.
type ConnectParams struct {
	ServerAddr       string `json:"server_addr"`
	ServerPubKey     string `json:"server_pub_key"`
	Transport        string `json:"transport"` // "udp", "tls", "ws"
	SNI              string `json:"sni,omitempty"`
	EnableKillSwitch bool   `json:"enable_kill_switch"`
	BlockPadding     bool   `json:"block_padding"`
	DecoyProbe       bool   `json:"decoy_probe"`
}

// Response is returned from daemon to the client.
type Response struct {
	Success bool            `json:"success"`
	Error   string          `json:"error,omitempty"`
	Status  *StatusResponse `json:"status,omitempty"`
}

// StatusResponse contains real-time operational telemetry.
type StatusResponse struct {
	Connected        bool    `json:"connected"`
	Transport        string  `json:"transport"`
	ServerAddr       string  `json:"server_addr"`
	BytesSent        uint64  `json:"bytes_sent"`
	BytesReceived    uint64  `json:"bytes_received"`
	PacketsSent      uint64  `json:"packets_sent"`
	PacketsReceived  uint64  `json:"packets_received"`
	UptimeSeconds    int64   `json:"uptime_seconds"`
	MemoryAllocMB    float64 `json:"memory_alloc_mb"`
	KillSwitchActive bool    `json:"kill_switch_active"`
	VirtualIP        string  `json:"virtual_ip"`
}
