package ipc

import (
	"encoding/json"
	"fmt"
	"net"
)

// Client sends requests to the running AnonymousAnt daemon.
type Client struct {
	path string
	conn net.Conn
	dec  *json.Decoder
	enc  *json.Encoder
}

// NewClient connects to the daemon's local IPC socket or loopback port.
func NewClient(socketPath string) (*Client, error) {
	if socketPath == "" {
		socketPath = DefaultSocketPath
	}

	network, addr := getNetworkAndAddr(socketPath)
	conn, err := net.Dial(network, addr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to AnonymousAnt daemon: %w", err)
	}

	return &Client{
		path: socketPath,
		conn: conn,
		dec:  json.NewDecoder(conn),
		enc:  json.NewEncoder(conn),
	}, nil
}

// Send sends a request and receives the response.
func (c *Client) Send(req Request) (Response, error) {
	if err := c.enc.Encode(req); err != nil {
		return Response{}, fmt.Errorf("failed to encode request: %w", err)
	}

	var resp Response
	if err := c.dec.Decode(&resp); err != nil {
		return Response{}, fmt.Errorf("failed to decode response: %w", err)
	}

	return resp, nil
}

// Connect sends a Connect command.
func (c *Client) Connect(params ConnectParams) (Response, error) {
	return c.Send(Request{
		Action: ActionConnect,
		Params: params,
	})
}

// Disconnect sends a Disconnect command.
func (c *Client) Disconnect() (Response, error) {
	return c.Send(Request{
		Action: ActionDisconnect,
	})
}

// GetStatus queries the daemon for current telemetry.
func (c *Client) GetStatus() (*StatusResponse, error) {
	resp, err := c.Send(Request{Action: ActionGetStatus})
	if err != nil {
		return nil, err
	}
	if !resp.Success {
		return nil, fmt.Errorf("daemon error: %s", resp.Error)
	}
	return resp.Status, nil
}

// Close closes the IPC connection.
func (c *Client) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}
