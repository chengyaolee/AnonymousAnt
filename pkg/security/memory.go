package security

import (
	"crypto/subtle"
	"runtime"
)

// Zero securely wipes a byte slice in memory, ensuring the compiler does not optimize away the write.
func Zero(b []byte) {
	if len(b) == 0 {
		return
	}
	// Use subtle.ConstantTimeCopy or explicit write loop
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}

// Zero32 securely clears a 32-byte array (used for Curve25519 / AEAD keys).
func Zero32(key *[32]byte) {
	if key == nil {
		return
	}
	for i := range key {
		key[i] = 0
	}
	runtime.KeepAlive(key)
}

// ConstantTimeCompare wraps subtle.ConstantTimeCompare for constant-time slice comparison.
func ConstantTimeCompare(x, y []byte) int {
	return subtle.ConstantTimeCompare(x, y)
}
