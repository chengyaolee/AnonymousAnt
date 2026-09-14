package buffer

import (
	"sync"
)

const (
	// DefaultBufferSize covers standard MTU (1500) + IP/UDP headers + Noise/AEAD overhead + padding.
	DefaultBufferSize = 2048

	// MaxPacketSize is the maximum theoretical IP datagram size.
	MaxPacketSize = 65535
)

// PacketBuffer represents a pooled byte buffer designed for zero-allocation packet handling.
type PacketBuffer struct {
	// Data is the underlying byte buffer.
	Data []byte
	// Length is the active valid length of data in the buffer.
	Length int
	// Offset is the starting position of valid data (useful for zero-copy header stripping/prepending).
	Offset int
}

// Bytes returns the valid slice of data.
func (b *PacketBuffer) Bytes() []byte {
	return b.Data[b.Offset : b.Offset+b.Length]
}

// Reset clears the offset and length without deallocating the underlying storage.
func (b *PacketBuffer) Reset() {
	b.Offset = 0
	b.Length = 0
}

// Pool manages pre-allocated PacketBuffer instances via sync.Pool.
type Pool struct {
	pool sync.Pool
	size int
}

// NewPool creates a buffer pool with buffers of capacity `bufferSize`.
func NewPool(bufferSize int) *Pool {
	if bufferSize <= 0 {
		bufferSize = DefaultBufferSize
	}
	p := &Pool{
		size: bufferSize,
	}
	p.pool.New = func() any {
		return &PacketBuffer{
			Data:   make([]byte, bufferSize),
			Length: 0,
			Offset: 0,
		}
	}
	return p
}

// GlobalPool is the default application-wide packet buffer pool.
var GlobalPool = NewPool(DefaultBufferSize)

// Get retrieves a buffer from the global pool.
func Get() *PacketBuffer {
	buf := GlobalPool.pool.Get().(*PacketBuffer)
	buf.Reset()
	return buf
}

// Put returns a buffer to the global pool.
func Put(buf *PacketBuffer) {
	if buf == nil {
		return
	}
	buf.Reset()
	GlobalPool.pool.Put(buf)
}

// Get retrieves a buffer from this specific pool.
func (p *Pool) Get() *PacketBuffer {
	buf := p.pool.Get().(*PacketBuffer)
	buf.Reset()
	return buf
}

// Put returns a buffer to this specific pool.
func (p *Pool) Put(buf *PacketBuffer) {
	if buf == nil {
		return
	}
	buf.Reset()
	p.pool.Put(buf)
}
