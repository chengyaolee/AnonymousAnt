package transport

import (
	"bytes"
	"crypto/tls"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/chengyaolee/AnonymousAnt/pkg/buffer"
)

func TestUDPTransportSendReceive(t *testing.T) {
	server, err := NewUDPTransport("127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start udp server: %v", err)
	}
	defer server.Close()

	client, err := NewUDPTransport("127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start udp client: %v", err)
	}
	defer client.Close()

	sendPayload := []byte("udp datagram test")
	buf := buffer.Get()
	copy(buf.Data, sendPayload)
	buf.Length = len(sendPayload)

	if err := client.Send(buf, server.LocalAddr()); err != nil {
		t.Fatalf("client send failed: %v", err)
	}
	buffer.Put(buf)

	recvBuf := buffer.Get()
	defer buffer.Put(recvBuf)

	raddr, err := server.Receive(recvBuf)
	if err != nil {
		t.Fatalf("server receive failed: %v", err)
	}

	if raddr == nil {
		t.Fatal("expected remote address, got nil")
	}

	if !bytes.Equal(recvBuf.Bytes(), sendPayload) {
		t.Fatalf("received data mismatch: got %s, want %s", recvBuf.Bytes(), sendPayload)
	}
}

func TestTLSTransportAndDecoyWebResponse(t *testing.T) {
	server, err := NewTLSServerTransport("127.0.0.1:0", nil)
	if err != nil {
		t.Fatalf("failed to start tls server: %v", err)
	}
	defer server.Close()

	serverAddr := server.LocalAddr().String()

	// 1. Test Active Probing Defense: Standard HTTP client probing the TLS port
	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		Timeout: 3 * time.Second,
	}

	resp, err := httpClient.Get("https://" + serverAddr + "/")
	if err != nil {
		t.Fatalf("http probe to tls server failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected decoy status 200 OK, got %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read decoy body: %v", err)
	}
	if !bytes.Contains(body, []byte("Relay Service")) {
		t.Fatalf("expected decoy body content, got: %s", string(body))
	}

	// 2. Test Legitimate Tunnel Framing over TLS
	client, err := NewTLSClientTransport(serverAddr, "gateway.internal")
	if err != nil {
		t.Fatalf("failed to connect tls client: %v", err)
	}
	defer client.Close()

	tunnelPayload := []byte("encrypted tunnel frame payload over tls")
	buf := buffer.Get()
	copy(buf.Data, tunnelPayload)
	buf.Length = len(tunnelPayload)

	if err := client.Send(buf, server.LocalAddr()); err != nil {
		t.Fatalf("tls client send failed: %v", err)
	}
	buffer.Put(buf)

	recvBuf := buffer.Get()
	defer buffer.Put(recvBuf)

	raddr, err := server.Receive(recvBuf)
	if err != nil {
		t.Fatalf("tls server receive failed: %v", err)
	}

	if raddr == nil {
		t.Fatal("expected remote address")
	}

	if !bytes.Equal(recvBuf.Bytes(), tunnelPayload) {
		t.Fatalf("received tunnel data mismatch: got %s, want %s", recvBuf.Bytes(), tunnelPayload)
	}
}
