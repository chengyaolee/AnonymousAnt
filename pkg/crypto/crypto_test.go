package crypto

import (
	"bytes"
	"testing"

	"github.com/chengyaolee/AnonymousAnt/pkg/buffer"
)

func TestKeyPairAndSharedSecret(t *testing.T) {
	privA, pubA, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate key A: %v", err)
	}
	defer privA.Wipe()

	privB, pubB, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate key B: %v", err)
	}
	defer privB.Wipe()

	ssA, err := privA.SharedSecret(pubB)
	if err != nil {
		t.Fatalf("DH A failed: %v", err)
	}

	ssB, err := privB.SharedSecret(pubA)
	if err != nil {
		t.Fatalf("DH B failed: %v", err)
	}

	if !bytes.Equal(ssA[:], ssB[:]) {
		t.Fatal("shared secrets do not match")
	}

	// Test string parsing
	b64 := pubA.Base64()
	parsedPub, err := ParsePublicKey(b64)
	if err != nil {
		t.Fatalf("parse base64 public key failed: %v", err)
	}
	if !bytes.Equal(pubA[:], parsedPub[:]) {
		t.Fatal("parsed public key does not match original")
	}
}

func TestAEADCipherInPlace(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	ciphers := []CipherSuite{CipherChaCha20Poly1305, CipherAESGCM}
	for _, suite := range ciphers {
		c, err := NewAEADCipher(suite, key)
		if err != nil {
			t.Fatalf("cipher creation failed for suite %d: %v", suite, err)
		}

		buf := buffer.Get()
		payload := []byte("confidential ip packet payload across tunnel")
		copy(buf.Data, payload)
		buf.Length = len(payload)

		ad := []byte("header-metadata")
		counter := uint64(42)

		// In-place encryption
		if err := c.EncryptInPlace(buf, counter, ad); err != nil {
			t.Fatalf("encryption failed: %v", err)
		}
		if buf.Length != len(payload)+TagSize {
			t.Fatalf("expected encrypted length %d, got %d", len(payload)+TagSize, buf.Length)
		}

		// In-place decryption
		if err := c.DecryptInPlace(buf, counter, ad); err != nil {
			t.Fatalf("decryption failed: %v", err)
		}
		if buf.Length != len(payload) {
			t.Fatalf("expected decrypted length %d, got %d", len(payload), buf.Length)
		}
		if !bytes.Equal(buf.Bytes(), payload) {
			t.Fatalf("decrypted payload does not match original")
		}

		buffer.Put(buf)
	}
}

func TestNoiseIKHandshake(t *testing.T) {
	serverPriv, serverPub, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed server key: %v", err)
	}
	defer serverPriv.Wipe()

	clientPriv, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed client key: %v", err)
	}
	defer clientPriv.Wipe()

	clientIndex := uint32(1001)
	serverIndex := uint32(2002)

	// 1. Initiator prepares initiation
	initiator, err := NewInitiatorHandshake(clientPriv, serverPub, clientIndex)
	if err != nil {
		t.Fatalf("failed to create initiator: %v", err)
	}

	initMsg, err := initiator.CreateInitiation()
	if err != nil {
		t.Fatalf("failed to create initiation message: %v", err)
	}
	if len(initMsg) != NoiseHandshakeInitSize {
		t.Fatalf("expected init msg size %d, got %d", NoiseHandshakeInitSize, len(initMsg))
	}

	// 2. Responder processes initiation and generates response
	responder := NewResponderHandshake(serverPriv, serverIndex)
	respMsg, serverSession, err := responder.ConsumeInitiation(initMsg)
	if err != nil {
		t.Fatalf("responder failed initiation: %v", err)
	}
	defer serverSession.Wipe()

	if len(respMsg) != NoiseHandshakeRespSize {
		t.Fatalf("expected resp msg size %d, got %d", NoiseHandshakeRespSize, len(respMsg))
	}

	// 3. Initiator processes response
	clientSession, err := initiator.ConsumeResponse(respMsg)
	if err != nil {
		t.Fatalf("initiator failed response: %v", err)
	}
	defer clientSession.Wipe()

	// Verify session keys align: client.SendKey == server.RecvKey and vice-versa
	if !bytes.Equal(clientSession.SendKey[:], serverSession.RecvKey[:]) {
		t.Fatal("client SendKey does not match server RecvKey")
	}
	if !bytes.Equal(clientSession.RecvKey[:], serverSession.SendKey[:]) {
		t.Fatal("client RecvKey does not match server SendKey")
	}

	if clientSession.PeerID != serverIndex || serverSession.PeerID != clientIndex {
		t.Fatalf("session indices mismatch: client peer=%d, server peer=%d",
			clientSession.PeerID, serverSession.PeerID)
	}
}

func BenchmarkAEADChaCha20Poly1305(b *testing.B) {
	key := make([]byte, 32)
	c, _ := NewAEADCipher(CipherChaCha20Poly1305, key)
	buf := buffer.Get()
	defer buffer.Put(buf)
	payload := make([]byte, 1420)
	copy(buf.Data, payload)
	buf.Length = len(payload)
	ad := []byte("test")

	b.SetBytes(1420)
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		buf.Length = 1420
		_ = c.EncryptInPlace(buf, uint64(i), ad)
		_ = c.DecryptInPlace(buf, uint64(i), ad)
	}
}
