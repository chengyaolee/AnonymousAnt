package obfuscation

import (
	"crypto/rand"
	"errors"
	"math/big"
	"time"

	"github.com/chengyaolee/AnonymousAnt/pkg/buffer"
)

const (
	DefaultBlockSize = 128
	MaxBlockSize     = 512
)

// PadPacket appends pseudo-random bytes to `buf` in-place so its length becomes a multiple of `blockSize`.
// The final byte stores the number of padding bytes added.
func PadPacket(buf *buffer.PacketBuffer, blockSize int) error {
	if blockSize <= 0 {
		blockSize = DefaultBlockSize
	}
	if blockSize > MaxBlockSize {
		blockSize = MaxBlockSize
	}

	currentLen := buf.Length
	// We need at least 1 byte at the end for the padding length itself
	rem := (currentLen + 1) % blockSize
	var padLen int
	if rem != 0 {
		padLen = blockSize - rem
	}

	totalAdd := padLen + 1
	if buf.Offset+buf.Length+totalAdd > len(buf.Data) {
		return errors.New("buffer capacity exceeded for padding")
	}

	targetSlice := buf.Data[buf.Offset+buf.Length : buf.Offset+buf.Length+padLen]
	if padLen > 0 {
		if _, err := rand.Read(targetSlice); err != nil {
			return err
		}
	}

	// Final byte encodes the padLen
	buf.Data[buf.Offset+buf.Length+padLen] = byte(padLen)
	buf.Length += totalAdd
	return nil
}

// UnpadPacket reads the trailing padding length and removes the padding bytes in-place.
func UnpadPacket(buf *buffer.PacketBuffer) error {
	if buf.Length < 1 {
		return errors.New("buffer too short for unpadding")
	}

	padLen := int(buf.Data[buf.Offset+buf.Length-1])
	totalAdd := padLen + 1

	if totalAdd > buf.Length {
		return errors.New("invalid padding length metadata")
	}

	buf.Length -= totalAdd
	return nil
}

// ApplyJitter introduces an optional randomized microsecond/millisecond pause
// to defeat inter-arrival packet timing correlation attacks by DPI firewalls.
func ApplyJitter(minMs, maxMs int) {
	if maxMs <= minMs || minMs < 0 {
		return
	}
	diff := int64(maxMs - minMs)
	n, err := rand.Int(rand.Reader, big.NewInt(diff))
	if err != nil {
		return
	}
	sleepDuration := time.Duration(int64(minMs)+n.Int64()) * time.Millisecond
	time.Sleep(sleepDuration)
}
