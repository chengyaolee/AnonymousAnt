package ipc

import (
	"os"
	"path/filepath"
	"testing"
)

type echoHandler struct{}

func (h *echoHandler) Handle(req Request) Response {
	if req.Action == ActionGetStatus {
		return Response{
			Success: true,
			Status: &StatusResponse{
				Connected:     true,
				Transport:     "tls",
				MemoryAllocMB: 12.5,
			},
		}
	}
	return Response{Success: true}
}

func TestIPCCommunication(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "ant-ipc-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	sockPath := filepath.Join(tempDir, "test.sock")
	server, err := NewServer(sockPath, &echoHandler{})
	if err != nil {
		t.Fatalf("failed to start ipc server: %v", err)
	}
	defer server.Close()

	client, err := NewClient(sockPath)
	if err != nil {
		t.Fatalf("failed to connect ipc client: %v", err)
	}
	defer client.Close()

	status, err := client.GetStatus()
	if err != nil {
		t.Fatalf("failed to get status: %v", err)
	}

	if !status.Connected || status.Transport != "tls" || status.MemoryAllocMB != 12.5 {
		t.Fatalf("unexpected status returned: %+v", status)
	}
}

func TestIPCTCPCommunication(t *testing.T) {
	addr := "127.0.0.1:47829"
	server, err := NewServer(addr, &echoHandler{})
	if err != nil {
		t.Fatalf("failed to start tcp ipc server: %v", err)
	}
	defer server.Close()

	client, err := NewClient(addr)
	if err != nil {
		t.Fatalf("failed to connect tcp ipc client: %v", err)
	}
	defer client.Close()

	status, err := client.GetStatus()
	if err != nil {
		t.Fatalf("failed to get status over tcp: %v", err)
	}

	if !status.Connected || status.Transport != "tls" || status.MemoryAllocMB != 12.5 {
		t.Fatalf("unexpected status returned: %+v", status)
	}
}
