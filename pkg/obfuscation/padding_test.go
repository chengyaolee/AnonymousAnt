package obfuscation

import (
	"bytes"
	"testing"

	"github.com/chengyaolee/AnonymousAnt/pkg/buffer"
)

func TestPadAndUnpadPacket(t *testing.T) {
	buf := buffer.Get()
	defer buffer.Put(buf)

	originalData := []byte("secret payload under DPI surveillance")
	copy(buf.Data, originalData)
	buf.Length = len(originalData)

	blockSize := 128
	if err := PadPacket(buf, blockSize); err != nil {
		t.Fatalf("padding failed: %v", err)
	}

	if buf.Length%blockSize != 0 {
		t.Fatalf("expected padded length to be multiple of %d, got %d", blockSize, buf.Length)
	}

	if err := UnpadPacket(buf); err != nil {
		t.Fatalf("unpadding failed: %v", err)
	}

	if buf.Length != len(originalData) {
		t.Fatalf("expected unpadded length %d, got %d", len(originalData), buf.Length)
	}

	if !bytes.Equal(buf.Bytes(), originalData) {
		t.Fatalf("unpadded data does not match original")
	}
}
