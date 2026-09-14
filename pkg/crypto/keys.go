package crypto

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"github.com/chengyaolee/AnonymousAnt/pkg/security"
	"golang.org/x/crypto/curve25519"
)

const (
	KeySize = 32
)

// PrivateKey represents a 32-byte Curve25519 private key.
type PrivateKey [KeySize]byte

// PublicKey represents a 32-byte Curve25519 public key.
type PublicKey [KeySize]byte

// GenerateKeyPair generates a new random Curve25519 keypair.
func GenerateKeyPair() (*PrivateKey, *PublicKey, error) {
	var priv PrivateKey
	if _, err := io.ReadFull(rand.Reader, priv[:]); err != nil {
		return nil, nil, fmt.Errorf("failed to generate random bytes: %w", err)
	}

	// Clamp the private key according to Curve25519 specification
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64

	var pub PublicKey
	curve25519.ScalarBaseMult((*[32]byte)(&pub), (*[32]byte)(&priv))

	return &priv, &pub, nil
}

// PublicKey derives the public key from the private key.
func (k *PrivateKey) PublicKey() *PublicKey {
	var pub PublicKey
	curve25519.ScalarBaseMult((*[32]byte)(&pub), (*[32]byte)(k))
	return &pub
}

// SharedSecret calculates the X25519 Diffie-Hellman shared secret with a peer's public key.
func (k *PrivateKey) SharedSecret(peerPub *PublicKey) ([KeySize]byte, error) {
	var ss [KeySize]byte
	curve25519.ScalarMult(&ss, (*[32]byte)(k), (*[32]byte)(peerPub))

	// Check for all-zeros output which indicates an invalid small-order point
	var isZero byte
	for _, b := range ss {
		isZero |= b
	}
	if isZero == 0 {
		return ss, errors.New("invalid Curve25519 public key (contributory point)")
	}

	return ss, nil
}

// Wipe zeroes the private key in memory to prevent key leakage.
func (k *PrivateKey) Wipe() {
	security.Zero32((*[32]byte)(k))
}

// Base64 returns the base64-encoded string representation of the public key.
func (k *PublicKey) Base64() string {
	return base64.RawURLEncoding.EncodeToString(k[:])
}

// Hex returns the hexadecimal string representation of the public key.
func (k *PublicKey) Hex() string {
	return hex.EncodeToString(k[:])
}

// ParsePublicKey parses a base64 or hex string into a PublicKey.
func ParsePublicKey(s string) (*PublicKey, error) {
	var pub PublicKey
	data, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		// Fallback to hex
		data, err = hex.DecodeString(s)
		if err != nil {
			return nil, fmt.Errorf("invalid public key format: neither base64 nor hex: %w", err)
		}
	}
	if len(data) != KeySize {
		return nil, fmt.Errorf("invalid key length: got %d bytes, expected %d", len(data), KeySize)
	}
	copy(pub[:], data)
	return &pub, nil
}

// ParsePrivateKey parses a base64 or hex string into a PrivateKey.
func ParsePrivateKey(s string) (*PrivateKey, error) {
	var priv PrivateKey
	data, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		data, err = hex.DecodeString(s)
		if err != nil {
			return nil, fmt.Errorf("invalid private key format: %w", err)
		}
	}
	if len(data) != KeySize {
		return nil, fmt.Errorf("invalid key length: got %d bytes, expected %d", len(data), KeySize)
	}
	copy(priv[:], data)
	return &priv, nil
}
