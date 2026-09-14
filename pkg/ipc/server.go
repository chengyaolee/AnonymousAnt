package ipc

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"

	"github.com/chengyaolee/AnonymousAnt/pkg/security"
)

var DefaultSocketPath = defaultSocket()

func defaultSocket() string {
	if runtime.GOOS == "windows" {
		return "127.0.0.1:47821"
	}
	return "/tmp/anonymousant.sock"
}

func getNetworkAndAddr(path string) (string, string) {
	if strings.Contains(path, ":") {
		return "tcp", path
	}
	return "unix", path
}

// Handler processes an incoming IPC request.
type Handler interface {
	Handle(req Request) Response
}

// Server listens for local IPC connections.
type Server struct {
	path     string
	listener net.Listener
	handler  Handler
	mu       sync.Mutex
	closed   chan struct{}
}

// NewServer creates and binds a local Unix domain socket or loopback TCP IPC listener.
func NewServer(socketPath string, handler Handler) (*Server, error) {
	if socketPath == "" {
		socketPath = DefaultSocketPath
	}

	network, addr := getNetworkAndAddr(socketPath)
	if network == "unix" {
		// Remove old socket file if present
		_ = os.Remove(addr)
	}

	ln, err := net.Listen(network, addr)
	if err != nil {
		return nil, err
	}

	if network == "unix" {
		// Set permissions so unprivileged users can communicate with the daemon
		_ = os.Chmod(addr, 0666)
	}

	s := &Server{
		path:     socketPath,
		listener: ln,
		handler:  handler,
		closed:   make(chan struct{}),
	}

	go s.acceptLoop()
	return s, nil
}

func (s *Server) acceptLoop() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.closed:
				return
			default:
				security.Warn("IPC accept error: %v", err)
				continue
			}
		}

		go s.handleClient(conn)
	}
}

func (s *Server) handleClient(conn net.Conn) {
	defer conn.Close()
	dec := json.NewDecoder(conn)
	enc := json.NewEncoder(conn)

	for {
		var req Request
		if err := dec.Decode(&req); err != nil {
			if errors.Is(err, io.EOF) {
				return
			}
			return
		}

		resp := s.handler.Handle(req)
		if err := enc.Encode(resp); err != nil {
			return
		}
	}
}

func (s *Server) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	select {
	case <-s.closed:
		return nil
	default:
		close(s.closed)
	}

	err := s.listener.Close()
	network, addr := getNetworkAndAddr(s.path)
	if network == "unix" {
		_ = os.Remove(addr)
	}
	return err
}
