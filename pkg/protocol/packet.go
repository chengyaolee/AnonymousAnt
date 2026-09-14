package protocol

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/chengyaolee/AnonymousAnt/pkg/buffer"
)

// MessageType identifies the AnonymousAnt protocol message.
type MessageType uint8

const (
	TypeHandshakeInit MessageType = 1
	TypeHandshakeResp MessageType = 2
	TypeData          MessageType = 3
	TypeKeepalive     MessageType = 4
	TypeDisconnect    MessageType = 5
)

const (
	// HeaderSize: Type(1) + Flags(1) + ReceiverIndex(4) + Counter(8) = 14 bytes
	HeaderSize = 14

	// FlagPadded indicates that the payload includes random padding
	FlagPadded uint8 = 1 << 0
)

// Header represents the unpacked wire header of an AnonymousAnt packet.
type Header struct {
	Type          MessageType
	Flags         uint8
	ReceiverIndex uint32
	Counter       uint64
}

// EncodeHeader writes the header into a byte slice of at least HeaderSize bytes.
func EncodeHeader(h Header, dst []byte) {
	dst[0] = byte(h.Type)
	dst[1] = h.Flags
	binary.LittleEndian.PutUint32(dst[2:6], h.ReceiverIndex)
	binary.LittleEndian.PutUint64(dst[6:14], h.Counter)
}

// DecodeHeader extracts a Header from a byte slice.
func DecodeHeader(src []byte) (Header, error) {
	if len(src) < HeaderSize {
		return Header{}, errors.New("packet header truncated")
	}
	return Header{
		Type:          MessageType(src[0]),
		Flags:         src[1],
		ReceiverIndex: binary.LittleEndian.Uint32(src[2:6]),
		Counter:       binary.LittleEndian.Uint64(src[6:14]),
	}, nil
}

// PrependHeader writes the header into the front of a PacketBuffer in-place.
// If buf.Offset >= HeaderSize, it prepends without moving memory.
// Otherwise, it shifts data to the right.
func PrependHeader(buf *buffer.PacketBuffer, h Header) error {
	if buf.Offset >= HeaderSize {
		buf.Offset -= HeaderSize
		buf.Length += HeaderSize
		EncodeHeader(h, buf.Data[buf.Offset:buf.Offset+HeaderSize])
		return nil
	}

	// If offset is 0, verify total capacity
	if len(buf.Data) < buf.Length+HeaderSize {
		return fmt.Errorf("buffer capacity (%d) insufficient to prepend header (%d)",
			len(buf.Data), buf.Length+HeaderSize)
	}

	// Shift data to make room
	copy(buf.Data[HeaderSize:HeaderSize+buf.Length], buf.Bytes())
	buf.Offset = 0
	buf.Length += HeaderSize
	EncodeHeader(h, buf.Data[0:HeaderSize])
	return nil
}

// StripHeader advances the buffer's offset past the HeaderSize.
func StripHeader(buf *buffer.PacketBuffer) (Header, error) {
	if buf.Length < HeaderSize {
		return Header{}, errors.New("insufficient data for header")
	}
	h, err := DecodeHeader(buf.Bytes())
	if err != nil {
		return Header{}, err
	}
	buf.Offset += HeaderSize
	buf.Length -= HeaderSize
	return h, nil
}
