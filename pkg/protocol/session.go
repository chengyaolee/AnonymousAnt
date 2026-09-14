package protocol

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/chengyaolee/AnonymousAnt/pkg/buffer"
	"github.com/chengyaolee/AnonymousAnt/pkg/crypto"
	"github.com/chengyaolee/AnonymousAnt/pkg/security"
)

const (
	// WindowSize for anti-replay verification (128 packets)
	WindowSize = 128

	// RekeyTime specifies session lifetime before requiring rekeying
	RekeyTime = 2 * time.Hour

	// KeepaliveInterval specifies heartbeat frequency
	KeepaliveInterval = 15 * time.Second
)

// ReplayWindow implements a bitmap sliding window to thwart packet replay attacks over UDP.
type ReplayWindow struct {
	mu     sync.Mutex
	maxSeq uint64
	bitmap [2]uint64 // 128 bits
}

// CheckAndSet returns true if sequence number is valid and unplayed, false if replayed or too old.
func (rw *ReplayWindow) CheckAndSet(seq uint64) bool {
	rw.mu.Lock()
	defer rw.mu.Unlock()

	if seq > rw.maxSeq {
		diff := seq - rw.maxSeq
		if diff >= WindowSize {
			rw.bitmap[0] = 0
			rw.bitmap[1] = 0
		} else if diff >= 64 {
			rw.bitmap[1] = rw.bitmap[0] << (diff - 64)
			rw.bitmap[0] = 0
		} else {
			rw.bitmap[1] = (rw.bitmap[1] << diff) | (rw.bitmap[0] >> (64 - diff))
			rw.bitmap[0] <<= diff
		}
		rw.maxSeq = seq
		rw.bitmap[0] |= 1
		return true
	}

	diff := rw.maxSeq - seq
	if diff >= WindowSize {
		return false // Too old
	}

	word := diff / 64
	bit := diff % 64

	if (rw.bitmap[word] & (1 << bit)) != 0 {
		return false // Replayed packet
	}

	rw.bitmap[word] |= (1 << bit)
	return true
}

// Session tracks an active, ephemeral cryptographic tunnel session between peers.
type Session struct {
	LocalIndex  uint32
	RemoteIndex uint32

	SendCipher *crypto.AEADCipher
	RecvCipher *crypto.AEADCipher

	sendCounter atomic.Uint64
	replay      ReplayWindow

	RemoteAddr net.Addr
	LastActive atomic.Int64 // Unix timestamp nano
	CreatedAt  time.Time
}

// NewSession creates an active in-memory session from derived keys.
func NewSession(keys *crypto.SessionKeys, addr net.Addr, suite crypto.CipherSuite) (*Session, error) {
	sendCipher, err := crypto.NewAEADCipher(suite, keys.SendKey[:])
	if err != nil {
		return nil, err
	}
	recvCipher, err := crypto.NewAEADCipher(suite, keys.RecvKey[:])
	if err != nil {
		return nil, err
	}

	s := &Session{
		LocalIndex:  keys.SenderID,
		RemoteIndex: keys.PeerID,
		SendCipher:  sendCipher,
		RecvCipher:  recvCipher,
		RemoteAddr:  addr,
		CreatedAt:   time.Now(),
	}
	s.LastActive.Store(time.Now().UnixNano())
	return s, nil
}

// EncryptPacket encrypts a packet buffer in-place and prepends the protocol header.
func (s *Session) EncryptPacket(buf *buffer.PacketBuffer, msgType MessageType, flags uint8) error {
	counter := s.sendCounter.Add(1) - 1

	// In-place AEAD encryption
	var ad [HeaderSize]byte
	h := Header{
		Type:          msgType,
		Flags:         flags,
		ReceiverIndex: s.RemoteIndex,
		Counter:       counter,
	}
	EncodeHeader(h, ad[:])

	if err := s.SendCipher.EncryptInPlace(buf, counter, ad[:]); err != nil {
		return err
	}

	// Prepend header
	if err := PrependHeader(buf, h); err != nil {
		return err
	}

	s.LastActive.Store(time.Now().UnixNano())
	return nil
}

// DecryptPacket strips the header, validates replay protection, and decrypts the buffer in-place.
func (s *Session) DecryptPacket(buf *buffer.PacketBuffer, h Header) error {
	// Anti-replay check
	if !s.replay.CheckAndSet(h.Counter) {
		return errors.New("packet rejected by anti-replay window")
	}

	var ad [HeaderSize]byte
	EncodeHeader(h, ad[:])

	if err := s.RecvCipher.DecryptInPlace(buf, h.Counter, ad[:]); err != nil {
		return err
	}

	s.LastActive.Store(time.Now().UnixNano())
	return nil
}

// Wipe securely clears cryptographic session state from RAM.
func (s *Session) Wipe() {
	s.SendCipher = nil
	s.RecvCipher = nil
	s.replay.mu.Lock()
	s.replay.bitmap = [2]uint64{0, 0}
	s.replay.mu.Unlock()
}

// SessionManager manages all active in-memory sessions without any disk persistence.
type SessionManager struct {
	mu       sync.RWMutex
	sessions map[uint32]*Session
}

// NewSessionManager creates a new volatile session table.
func NewSessionManager() *SessionManager {
	return &SessionManager{
		sessions: make(map[uint32]*Session),
	}
}

// Register stores a session indexed by its local index.
func (sm *SessionManager) Register(s *Session) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.sessions[s.LocalIndex] = s
}

// Get finds a session by local index.
func (sm *SessionManager) Get(index uint32) *Session {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.sessions[index]
}

// Remove deletes and wipes a session from memory.
func (sm *SessionManager) Remove(index uint32) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	if s, exists := sm.sessions[index]; exists {
		s.Wipe()
		delete(sm.sessions, index)
		security.Debug("Session index wiped from memory")
	}
}

// Clear wipes all sessions (e.g. on shutdown).
func (sm *SessionManager) Clear() {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	for idx, s := range sm.sessions {
		s.Wipe()
		delete(sm.sessions, idx)
	}
}
