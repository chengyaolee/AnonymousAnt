package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/chengyaolee/AnonymousAnt/pkg/buffer"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	TagSize   = 16
	NonceSize = 12
)

// CipherSuite represents the AEAD cipher in use.
type CipherSuite uint8

const (
	CipherChaCha20Poly1305 CipherSuite = 1
	CipherAESGCM           CipherSuite = 2
)

// AEADCipher wraps a standard cipher.AEAD with in-place zero-allocation buffer operations.
type AEADCipher struct {
	aead  cipher.AEAD
	suite CipherSuite
}

// NewAEADCipher initializes an AEAD cipher given a 32-byte key and cipher suite.
func NewAEADCipher(suite CipherSuite, key []byte) (*AEADCipher, error) {
	if len(key) != 32 {
		return nil, errors.New("aead key must be exactly 32 bytes")
	}

	var aead cipher.AEAD
	var err error

	switch suite {
	case CipherChaCha20Poly1305:
		aead, err = chacha20poly1305.New(key)
	case CipherAESGCM:
		block, errBlock := aes.NewCipher(key)
		if errBlock != nil {
			return nil, fmt.Errorf("aes block cipher creation failed: %w", errBlock)
		}
		aead, err = cipher.NewGCM(block)
	default:
		return nil, fmt.Errorf("unsupported cipher suite: %d", suite)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to create aead cipher: %w", err)
	}

	return &AEADCipher{
		aead:  aead,
		suite: suite,
	}, nil
}

// EncodeNonce builds a 12-byte nonce from an 8-byte counter and a 4-byte prefix/session identifier.
func EncodeNonce(counter uint64, nonceBuf *[NonceSize]byte) {
	binary.LittleEndian.PutUint32(nonceBuf[0:4], 0)
	binary.LittleEndian.PutUint64(nonceBuf[4:12], counter)
}

// EncryptInPlace encrypts the plaintext in `buf` using `counter` as the nonce.
// It appends the 16-byte authentication tag in-place without reallocation,
// updating buf.Length to include the tag.
func (c *AEADCipher) EncryptInPlace(buf *buffer.PacketBuffer, counter uint64, additionalData []byte) error {
	var nonce [NonceSize]byte
	EncodeNonce(counter, &nonce)

	// Ensure underlying array has space for additional TagSize
	requiredCap := buf.Offset + buf.Length + TagSize
	if cap(buf.Data) < requiredCap {
		return errors.New("buffer capacity insufficient for aead tag overhead")
	}

	// In-place Seal: dst slice starts at plaintext, capacity extends through tag
	plaintext := buf.Bytes()
	c.aead.Seal(plaintext[:0], nonce[:], plaintext, additionalData)
	buf.Length += TagSize
	return nil
}

// DecryptInPlace decrypts the ciphertext in `buf` in-place using `counter` as the nonce.
// It verifies the authentication tag and shrinks buf.Length by TagSize.
func (c *AEADCipher) DecryptInPlace(buf *buffer.PacketBuffer, counter uint64, additionalData []byte) error {
	if buf.Length < TagSize {
		return errors.New("ciphertext length shorter than authentication tag")
	}

	var nonce [NonceSize]byte
	EncodeNonce(counter, &nonce)

	ciphertext := buf.Bytes()
	_, err := c.aead.Open(ciphertext[:0], nonce[:], ciphertext, additionalData)
	if err != nil {
		return fmt.Errorf("aead authentication failed: %w", err)
	}

	buf.Length -= TagSize
	return nil
}
