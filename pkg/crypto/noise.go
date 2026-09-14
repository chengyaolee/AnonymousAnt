package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/chengyaolee/AnonymousAnt/pkg/security"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

const (
	NoiseHandshakeInitSize = 32 + 48 + (12 + 16) // Ephemeral (32) + Encrypted Static (48) + Encrypted Payload (28) = 108
	NoiseHandshakeRespSize = 32 + (4 + 16)       // Ephemeral (32) + Encrypted Payload (20) = 52
	NoiseProtocolName      = "Noise_IK_25519_ChaChaPoly_SHA256"
)

// SessionKeys holds the bidirectional symmetric keys derived from a completed handshake.
type SessionKeys struct {
	SendKey  [32]byte
	RecvKey  [32]byte
	SenderID uint32
	PeerID   uint32
}

// Wipe securely clears the derived session keys from memory.
func (sk *SessionKeys) Wipe() {
	security.Zero32(&sk.SendKey)
	security.Zero32(&sk.RecvKey)
}

// NoiseState tracks the cryptographic handshake state.
type NoiseState struct {
	chainingKey [32]byte
	hash        [32]byte
}

func newNoiseState() *NoiseState {
	ns := &NoiseState{}
	h := sha256.Sum256([]byte(NoiseProtocolName))
	ns.chainingKey = h
	ns.hash = h
	return ns
}

func (ns *NoiseState) mixKey(inputKeyMaterial []byte) [32]byte {
	kdf := hkdf.New(sha256.New, inputKeyMaterial, ns.chainingKey[:], nil)
	var nextCk [32]byte
	var tempKey [32]byte
	_, _ = io.ReadFull(kdf, nextCk[:])
	_, _ = io.ReadFull(kdf, tempKey[:])
	ns.chainingKey = nextCk
	return tempKey
}

func (ns *NoiseState) mixHash(data []byte) {
	h := sha256.New()
	h.Write(ns.hash[:])
	h.Write(data)
	copy(ns.hash[:], h.Sum(nil))
}

// InitiatorHandshake manages the client-side 1-RTT Noise IK handshake.
type InitiatorHandshake struct {
	staticPriv  *PrivateKey
	peerStatic  *PublicKey
	ephemPriv   *PrivateKey
	ephemPub    *PublicKey
	localIndex  uint32
	remoteIndex uint32
	noise       *NoiseState
}

// NewInitiatorHandshake creates a new handshake state machine for the initiator (client).
func NewInitiatorHandshake(localStatic *PrivateKey, peerStatic *PublicKey, localIndex uint32) (*InitiatorHandshake, error) {
	ephemPriv, ephemPub, err := GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("failed to generate ephemeral keypair: %w", err)
	}

	ns := newNoiseState()
	// Mix in responder's static public key known beforehand in IK pattern
	ns.mixHash(peerStatic[:])

	return &InitiatorHandshake{
		staticPriv: localStatic,
		peerStatic: peerStatic,
		ephemPriv:  ephemPriv,
		ephemPub:   ephemPub,
		localIndex: localIndex,
		noise:      ns,
	}, nil
}

// CreateInitiation produces the 96-byte initiation message to send to the responder.
func (ih *InitiatorHandshake) CreateInitiation() ([]byte, error) {
	out := make([]byte, NoiseHandshakeInitSize)

	// 1. Copy ephemeral public key
	copy(out[0:32], ih.ephemPub[:])
	ih.noise.mixHash(ih.ephemPub[:])

	// 2. es = DH(ephemPriv, peerStatic)
	es, err := ih.ephemPriv.SharedSecret(ih.peerStatic)
	if err != nil {
		return nil, err
	}
	key1 := ih.noise.mixKey(es[:])
	security.Zero32(&es)

	// 3. Encrypt local static public key
	aead1, err := chacha20poly1305.New(key1[:])
	if err != nil {
		return nil, err
	}
	var nonce1 [12]byte
	localPub := ih.staticPriv.PublicKey()
	aead1.Seal(out[32:32], nonce1[:], localPub[:], ih.noise.hash[:])
	ih.noise.mixHash(out[32:80]) // 32 byte static pub + 16 byte tag

	// 4. ss = DH(staticPriv, peerStatic)
	ss, err := ih.staticPriv.SharedSecret(ih.peerStatic)
	if err != nil {
		return nil, err
	}
	key2 := ih.noise.mixKey(ss[:])
	security.Zero32(&ss)

	// 5. Encrypt local timestamp + sender index as payload
	aead2, err := chacha20poly1305.New(key2[:])
	if err != nil {
		return nil, err
	}
	var payload [12]byte
	binary.LittleEndian.PutUint32(payload[0:4], ih.localIndex)
	binary.LittleEndian.PutUint64(payload[4:12], uint64(time.Now().UnixNano()))

	var nonce2 [12]byte
	aead2.Seal(out[80:80], nonce2[:], payload[:], ih.noise.hash[:])
	ih.noise.mixHash(out[80:108])

	return out, nil
}

// ConsumeResponse processes the 48-byte response message from the responder and outputs session keys.
func (ih *InitiatorHandshake) ConsumeResponse(resp []byte) (*SessionKeys, error) {
	if len(resp) < NoiseHandshakeRespSize {
		return nil, errors.New("response message too short")
	}

	var respEphemPub PublicKey
	copy(respEphemPub[:], resp[0:32])
	ih.noise.mixHash(respEphemPub[:])

	// ee = DH(ephemPriv, respEphemPub)
	ee, err := ih.ephemPriv.SharedSecret(&respEphemPub)
	if err != nil {
		return nil, err
	}
	_ = ih.noise.mixKey(ee[:])
	security.Zero32(&ee)

	// se = DH(staticPriv, respEphemPub)
	se, err := ih.staticPriv.SharedSecret(&respEphemPub)
	if err != nil {
		return nil, err
	}
	key := ih.noise.mixKey(se[:])
	security.Zero32(&se)

	// Decrypt payload containing remote index
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, err
	}
	var nonce [12]byte
	decryptedPayload, err := aead.Open(nil, nonce[:], resp[32:52], ih.noise.hash[:])
	if err != nil {
		return nil, fmt.Errorf("failed to authenticate response payload: %w", err)
	}
	ih.noise.mixHash(resp[32:52])

	if len(decryptedPayload) >= 4 {
		ih.remoteIndex = binary.LittleEndian.Uint32(decryptedPayload[0:4])
	}

	// Derive final transport keys
	kdf := hkdf.New(sha256.New, nil, ih.noise.chainingKey[:], []byte("AnonymousAnt-Split"))
	sk := &SessionKeys{
		SenderID: ih.localIndex,
		PeerID:   ih.remoteIndex,
	}
	_, _ = io.ReadFull(kdf, sk.SendKey[:])
	_, _ = io.ReadFull(kdf, sk.RecvKey[:])

	// Zero ephemeral private key
	ih.ephemPriv.Wipe()

	return sk, nil
}

// ResponderHandshake manages the server-side 1-RTT Noise IK handshake.
type ResponderHandshake struct {
	staticPriv  *PrivateKey
	localIndex  uint32
	remoteIndex uint32
	peerStatic  PublicKey
	noise       *NoiseState
}

// NewResponderHandshake creates a responder handshake state machine.
func NewResponderHandshake(localStatic *PrivateKey, localIndex uint32) *ResponderHandshake {
	ns := newNoiseState()
	localPub := localStatic.PublicKey()
	ns.mixHash(localPub[:])

	return &ResponderHandshake{
		staticPriv: localStatic,
		localIndex: localIndex,
		noise:      ns,
	}
}

// ConsumeInitiation processes an incoming 96-byte initiation and returns the responder's 48-byte reply & session keys.
func (rh *ResponderHandshake) ConsumeInitiation(initMsg []byte) ([]byte, *SessionKeys, error) {
	if len(initMsg) < NoiseHandshakeInitSize {
		return nil, nil, errors.New("initiation message too short")
	}

	var initEphemPub PublicKey
	copy(initEphemPub[:], initMsg[0:32])
	rh.noise.mixHash(initEphemPub[:])

	// 1. es = DH(staticPriv, initEphemPub)
	es, err := rh.staticPriv.SharedSecret(&initEphemPub)
	if err != nil {
		return nil, nil, err
	}
	key1 := rh.noise.mixKey(es[:])
	security.Zero32(&es)

	// 2. Decrypt peer static public key
	aead1, err := chacha20poly1305.New(key1[:])
	if err != nil {
		return nil, nil, err
	}
	var nonce1 [12]byte
	decryptedStatic, err := aead1.Open(nil, nonce1[:], initMsg[32:80], rh.noise.hash[:])
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decrypt initiator static key: %w", err)
	}
	copy(rh.peerStatic[:], decryptedStatic)
	rh.noise.mixHash(initMsg[32:80])

	// 3. ss = DH(staticPriv, peerStatic)
	ss, err := rh.staticPriv.SharedSecret(&rh.peerStatic)
	if err != nil {
		return nil, nil, err
	}
	key2 := rh.noise.mixKey(ss[:])
	security.Zero32(&ss)

	// 4. Decrypt payload (sender index + timestamp)
	aead2, err := chacha20poly1305.New(key2[:])
	if err != nil {
		return nil, nil, err
	}
	var nonce2 [12]byte
	decryptedPayload, err := aead2.Open(nil, nonce2[:], initMsg[80:108], rh.noise.hash[:])
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decrypt initiation payload: %w", err)
	}
	rh.noise.mixHash(initMsg[80:108])

	if len(decryptedPayload) >= 4 {
		rh.remoteIndex = binary.LittleEndian.Uint32(decryptedPayload[0:4])
	}

	// 5. Generate responder ephemeral keypair
	respEphemPriv, respEphemPub, err := GenerateKeyPair()
	if err != nil {
		return nil, nil, err
	}

	respMsg := make([]byte, NoiseHandshakeRespSize)
	copy(respMsg[0:32], respEphemPub[:])
	rh.noise.mixHash(respEphemPub[:])

	// 6. ee = DH(respEphemPriv, initEphemPub)
	ee, err := respEphemPriv.SharedSecret(&initEphemPub)
	if err != nil {
		return nil, nil, err
	}
	_ = rh.noise.mixKey(ee[:])
	security.Zero32(&ee)

	// 7. se = DH(respEphemPriv, peerStatic)
	se, err := respEphemPriv.SharedSecret(&rh.peerStatic)
	if err != nil {
		return nil, nil, err
	}
	key3 := rh.noise.mixKey(se[:])
	security.Zero32(&se)

	// 8. Encrypt response payload containing responder's index
	aead3, err := chacha20poly1305.New(key3[:])
	if err != nil {
		return nil, nil, err
	}
	var respPayload [4]byte
	binary.LittleEndian.PutUint32(respPayload[0:4], rh.localIndex)

	var nonce3 [12]byte
	aead3.Seal(respMsg[32:32], nonce3[:], respPayload[:], rh.noise.hash[:])
	rh.noise.mixHash(respMsg[32:52])

	// Derive final transport keys (note reverse direction from initiator!)
	kdf := hkdf.New(sha256.New, nil, rh.noise.chainingKey[:], []byte("AnonymousAnt-Split"))
	sk := &SessionKeys{
		SenderID: rh.localIndex,
		PeerID:   rh.remoteIndex,
	}
	_, _ = io.ReadFull(kdf, sk.RecvKey[:]) // Initiator SendKey = Responder RecvKey
	_, _ = io.ReadFull(kdf, sk.SendKey[:]) // Initiator RecvKey = Responder SendKey

	respEphemPriv.Wipe()

	return respMsg, sk, nil
}

// PeerStaticKey returns the authenticated public key of the remote peer.
func (rh *ResponderHandshake) PeerStaticKey() PublicKey {
	return rh.peerStatic
}

// GenerateIndex creates a random 32-bit session index.
func GenerateIndex() uint32 {
	var b [4]byte
	_, _ = rand.Read(b[:])
	idx := binary.LittleEndian.Uint32(b[:])
	if idx == 0 {
		idx = 1
	}
	return idx
}
