package ipc

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"sync"

	"github.com/chengyaolee/AnonymousAnt/pkg/security"
)

const (
	DefaultSocketPath = "/tmp/anonymousant.sock"
)

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

// NewServer creates and binds a local Unix domain socket IPC listener.
func NewServer(socketPath string, handler Handler) (*Server, error) {
	if socketPath == "" {
		socketPath = DefaultSocketPath
	}

	// Remove old socket file if present
	_ = os.Remove(socketPath)

	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		return nil, err
	}

	// Set permissions so unprivileged users can communicate with the daemon
	_ = os.Chmod(socketPath, 0666)

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
	_ = os.Remove(s.path)
	return err
}
