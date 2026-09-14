package buffer

import (
	"testing"
)

func TestPoolGetPut(t *testing.T) {
	buf := Get()
	if buf == nil {
		t.Fatal("expected buffer, got nil")
	}
	if len(buf.Data) != DefaultBufferSize {
		t.Fatalf("expected capacity %d, got %d", DefaultBufferSize, len(buf.Data))
	}

	testData := []byte("hello anonymous ant")
	copy(buf.Data, testData)
	buf.Length = len(testData)

	if string(buf.Bytes()) != "hello anonymous ant" {
		t.Fatalf("unexpected data: %s", string(buf.Bytes()))
	}

	Put(buf)
}

func BenchmarkPoolAllocations(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf := Get()
		buf.Length = 1420
		_ = buf.Bytes()
		Put(buf)
	}
}
