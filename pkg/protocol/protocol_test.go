package protocol

import (
	"bytes"
	"net"
	"testing"

	"github.com/chengyaolee/AnonymousAnt/pkg/buffer"
	"github.com/chengyaolee/AnonymousAnt/pkg/crypto"
)

func TestHeaderEncodeDecode(t *testing.T) {
	orig := Header{
		Type:          TypeData,
		Flags:         FlagPadded,
		ReceiverIndex: 0x12345678,
		Counter:       0xAABBCCDDEEFF0011,
	}

	var buf [HeaderSize]byte
	EncodeHeader(orig, buf[:])

	decoded, err := DecodeHeader(buf[:])
	if err != nil {
		t.Fatalf("failed to decode header: %v", err)
	}

	if decoded != orig {
		t.Fatalf("decoded header %+v != original %+v", decoded, orig)
	}
}

func TestPrependAndStripHeader(t *testing.T) {
	buf := buffer.Get()
	defer buffer.Put(buf)

	payload := []byte("tun packet content")
	copy(buf.Data, payload)
	buf.Length = len(payload)

	h := Header{
		Type:          TypeData,
		Flags:         0,
		ReceiverIndex: 42,
		Counter:       100,
	}

	if err := PrependHeader(buf, h); err != nil {
		t.Fatalf("prepend failed: %v", err)
	}

	stripped, err := StripHeader(buf)
	if err != nil {
		t.Fatalf("strip failed: %v", err)
	}

	if stripped != h {
		t.Fatalf("stripped header mismatch: %+v vs %+v", stripped, h)
	}
	if !bytes.Equal(buf.Bytes(), payload) {
		t.Fatalf("payload mismatch after strip")
	}
}

func TestReplayWindow(t *testing.T) {
	rw := &ReplayWindow{}

	// Sequential
	if !rw.CheckAndSet(1) {
		t.Fatal("expected seq 1 to pass")
	}
	if !rw.CheckAndSet(2) {
		t.Fatal("expected seq 2 to pass")
	}

	// Replay seq 1
	if rw.CheckAndSet(1) {
		t.Fatal("expected replay of seq 1 to fail")
	}

	// Jump forward
	if !rw.CheckAndSet(50) {
		t.Fatal("expected seq 50 to pass")
	}

	// In-order within window
	if !rw.CheckAndSet(49) {
		t.Fatal("expected seq 49 to pass")
	}

	// Replay 49
	if rw.CheckAndSet(49) {
		t.Fatal("expected replay of seq 49 to fail")
	}

	// Far jump that expires old seqs
	if !rw.CheckAndSet(300) {
		t.Fatal("expected seq 300 to pass")
	}

	// Seq 50 is now too old (>128 diff)
	if rw.CheckAndSet(50) {
		t.Fatal("expected seq 50 to be rejected as too old")
	}
}

func TestSessionEncryptDecrypt(t *testing.T) {
	keys := &crypto.SessionKeys{
		SenderID: 10,
		PeerID:   20,
	}
	for i := range keys.SendKey {
		keys.SendKey[i] = byte(i)
		keys.RecvKey[i] = byte(i + 10)
	}

	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:9000")
	senderSession, err := NewSession(keys, addr, crypto.CipherChaCha20Poly1305)
	if err != nil {
		t.Fatalf("create sender session: %v", err)
	}

	// Reverse keys for receiver
	recvKeys := &crypto.SessionKeys{
		SenderID: 20,
		PeerID:   10,
		SendKey:  keys.RecvKey,
		RecvKey:  keys.SendKey,
	}
	receiverSession, err := NewSession(recvKeys, addr, crypto.CipherChaCha20Poly1305)
	if err != nil {
		t.Fatalf("create receiver session: %v", err)
	}

	// Packet
	buf := buffer.Get()
	defer buffer.Put(buf)
	rawPayload := []byte("ping icmp packet test across anonymousant")
	copy(buf.Data, rawPayload)
	buf.Length = len(rawPayload)

	// Encrypt
	if err := senderSession.EncryptPacket(buf, TypeData, 0); err != nil {
		t.Fatalf("encrypt packet: %v", err)
	}

	// Receiver strips header and decrypts
	header, err := StripHeader(buf)
	if err != nil {
		t.Fatalf("strip header: %v", err)
	}
	if header.ReceiverIndex != 20 {
		t.Fatalf("expected receiver index 20, got %d", header.ReceiverIndex)
	}

	if err := receiverSession.DecryptPacket(buf, header); err != nil {
		t.Fatalf("decrypt packet: %v", err)
	}

	if !bytes.Equal(buf.Bytes(), rawPayload) {
		t.Fatalf("decrypted payload != original")
	}
}
