package security

import (
	"bytes"
	"strings"
	"testing"
)

func TestZero(t *testing.T) {
	data := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	Zero(data)
	for i, v := range data {
		if v != 0 {
			t.Fatalf("expected byte at index %d to be 0, got %d", i, v)
		}
	}

	var key [32]byte
	for i := range key {
		key[i] = 0xAA
	}
	Zero32(&key)
	for i, v := range key {
		if v != 0 {
			t.Fatalf("expected key byte at index %d to be 0, got %d", i, v)
		}
	}
}

func TestZeroLogSanitization(t *testing.T) {
	var buf bytes.Buffer
	logger := NewZeroLogger(LevelDebug, &buf)

	logger.Info("Client connected from 192.168.1.55 to 10.0.0.1")
	output := buf.String()

	if strings.Contains(output, "192.168.1.55") || strings.Contains(output, "10.0.0.1") {
		t.Fatalf("logger leaked IP address: %s", output)
	}

	if !strings.Contains(output, "[REDACTED_IP]") {
		t.Fatalf("expected [REDACTED_IP] in output, got: %s", output)
	}
}
