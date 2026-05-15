package easytier

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/bits"
)

const (
	Magic   uint32 = 0xd1e1a5e1
	Version uint32 = 1

	TCPTunnelHeaderSize   = 4
	PeerManagerHeaderSize = 16

	DefaultTCPPort = "11010"
	DefaultMTU     = 1380

	flagEncrypted    = 0b0000_0001
	flagLatencyFirst = 0b0000_0010
)

type PacketType uint8

const (
	PacketTypeInvalid         PacketType = 0
	PacketTypeData            PacketType = 1
	PacketTypeHandshake       PacketType = 2
	PacketTypePing            PacketType = 4
	PacketTypePong            PacketType = 5
	PacketTypeRPCReq          PacketType = 8
	PacketTypeRPCResp         PacketType = 9
	PacketTypeNoiseHandshake1 PacketType = 13
	PacketTypeNoiseHandshake2 PacketType = 14
	PacketTypeNoiseHandshake3 PacketType = 15
)

var (
	ErrUnsupportedSecureMode = errors.New("easytier secure-mode/noise handshake is not implemented")
	ErrInvalidPacket         = errors.New("invalid easytier packet")
)

type PeerManagerHeader struct {
	FromPeerID     uint32
	ToPeerID       uint32
	PacketType     PacketType
	Flags          uint8
	ForwardCounter uint8
	PayloadLength  uint32
}

func (h PeerManagerHeader) IsEncrypted() bool {
	return h.Flags&flagEncrypted != 0
}

func (h PeerManagerHeader) IsLatencyFirst() bool {
	return h.Flags&flagLatencyFirst != 0
}

func (h *PeerManagerHeader) SetEncrypted(encrypted bool) {
	if encrypted {
		h.Flags |= flagEncrypted
	} else {
		h.Flags &^= flagEncrypted
	}
}

func (h *PeerManagerHeader) SetLatencyFirst(latencyFirst bool) {
	if latencyFirst {
		h.Flags |= flagLatencyFirst
	} else {
		h.Flags &^= flagLatencyFirst
	}
}

type Packet struct {
	Header  PeerManagerHeader
	Payload []byte
}

func NewPacket(fromPeerID, toPeerID uint32, packetType PacketType, payload []byte) *Packet {
	return &Packet{
		Header: PeerManagerHeader{
			FromPeerID:     fromPeerID,
			ToPeerID:       toPeerID,
			PacketType:     packetType,
			ForwardCounter: 1,
			PayloadLength:  uint32(len(payload)),
		},
		Payload: append([]byte(nil), payload...),
	}
}

func ReadTCPPacket(r io.Reader, maxPacketSize int) (*Packet, error) {
	var lenBuf [TCPTunnelHeaderSize]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, err
	}
	bodyLen := binary.LittleEndian.Uint32(lenBuf[:])
	if bodyLen < PeerManagerHeaderSize {
		return nil, fmt.Errorf("%w: body too short", ErrInvalidPacket)
	}
	if maxPacketSize > 0 && bodyLen > uint32(maxPacketSize) {
		return nil, fmt.Errorf("%w: body too long", ErrInvalidPacket)
	}
	body := make([]byte, bodyLen)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	return ReadPacketBody(body, maxPacketSize)
}

func ReadPacketBody(body []byte, maxPacketSize int) (*Packet, error) {
	if len(body) < PeerManagerHeaderSize {
		return nil, fmt.Errorf("%w: body too short", ErrInvalidPacket)
	}
	if maxPacketSize > 0 && len(body) > maxPacketSize {
		return nil, fmt.Errorf("%w: body too long", ErrInvalidPacket)
	}
	packet := &Packet{
		Header: PeerManagerHeader{
			FromPeerID:     binary.LittleEndian.Uint32(body[0:4]),
			ToPeerID:       binary.LittleEndian.Uint32(body[4:8]),
			PacketType:     PacketType(body[8]),
			Flags:          body[9],
			ForwardCounter: body[10],
			PayloadLength:  binary.LittleEndian.Uint32(body[12:16]),
		},
		Payload: append([]byte(nil), body[PeerManagerHeaderSize:]...),
	}
	return packet, nil
}

func (p *Packet) MarshalTCP() []byte {
	body := p.MarshalBody()
	buf := make([]byte, TCPTunnelHeaderSize+len(body))
	binary.LittleEndian.PutUint32(buf[0:4], uint32(len(body)))
	copy(buf[4:], body)
	return buf
}

func (p *Packet) MarshalBody() []byte {
	bodyLen := PeerManagerHeaderSize + len(p.Payload)
	buf := make([]byte, bodyLen)
	binary.LittleEndian.PutUint32(buf[0:4], p.Header.FromPeerID)
	binary.LittleEndian.PutUint32(buf[4:8], p.Header.ToPeerID)
	buf[8] = byte(p.Header.PacketType)
	buf[9] = p.Header.Flags
	buf[10] = p.Header.ForwardCounter
	if p.Header.ForwardCounter == 0 {
		buf[10] = 1
	}
	binary.LittleEndian.PutUint32(buf[12:16], p.Header.PayloadLength)
	copy(buf[PeerManagerHeaderSize:], p.Payload)
	return buf
}

func (p *Packet) WriteTo(w io.Writer) error {
	_, err := w.Write(p.MarshalTCP())
	return err
}

func (p *Packet) EncryptAES128GCM(key [16]byte) error {
	if p.Header.IsEncrypted() {
		return nil
	}
	if p.Header.PayloadLength == 0 && len(p.Payload) > 0 {
		p.Header.PayloadLength = uint32(len(p.Payload))
	}

	block, err := aes.NewCipher(key[:])
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return err
	}
	sealed := gcm.Seal(nil, nonce, p.Payload, nil)
	tagStart := len(sealed) - gcm.Overhead()
	next := make([]byte, 0, len(p.Payload)+gcm.Overhead()+gcm.NonceSize())
	next = append(next, sealed[:tagStart]...)
	next = append(next, sealed[tagStart:]...)
	next = append(next, nonce...)
	p.Payload = next
	p.Header.SetEncrypted(true)
	return nil
}

func (p *Packet) DecryptAES128GCM(key [16]byte) error {
	if !p.Header.IsEncrypted() {
		return nil
	}
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	tailLen := gcm.Overhead() + gcm.NonceSize()
	if len(p.Payload) < tailLen {
		return fmt.Errorf("%w: encrypted payload too short", ErrInvalidPacket)
	}
	ciphertextLen := len(p.Payload) - tailLen
	tagStart := ciphertextLen
	nonceStart := ciphertextLen + gcm.Overhead()
	sealed := make([]byte, 0, ciphertextLen+gcm.Overhead())
	sealed = append(sealed, p.Payload[:ciphertextLen]...)
	sealed = append(sealed, p.Payload[tagStart:nonceStart]...)
	plain, err := gcm.Open(nil, p.Payload[nonceStart:], sealed, nil)
	if err != nil {
		return err
	}
	p.Payload = plain
	p.Header.PayloadLength = uint32(len(plain))
	p.Header.SetEncrypted(false)
	return nil
}

type HandshakeRequest struct {
	Magic               uint32
	MyPeerID            uint32
	Version             uint32
	Features            []string
	NetworkName         string
	NetworkSecretDigest []byte
}

func NewHandshakeRequest(myPeerID uint32, networkName string, digest [32]byte) HandshakeRequest {
	return HandshakeRequest{
		Magic:               Magic,
		MyPeerID:            myPeerID,
		Version:             Version,
		NetworkName:         networkName,
		NetworkSecretDigest: append([]byte(nil), digest[:]...),
	}
}

func (h HandshakeRequest) Marshal() []byte {
	var buf []byte
	buf = appendProtoVarint(buf, 1, uint64(h.Magic))
	buf = appendProtoVarint(buf, 2, uint64(h.MyPeerID))
	buf = appendProtoVarint(buf, 3, uint64(h.Version))
	for _, feature := range h.Features {
		buf = appendProtoBytes(buf, 4, []byte(feature))
	}
	buf = appendProtoBytes(buf, 5, []byte(h.NetworkName))
	buf = appendProtoBytes(buf, 6, h.NetworkSecretDigest)
	return buf
}

func ParseHandshakeRequest(payload []byte) (HandshakeRequest, error) {
	var req HandshakeRequest
	for len(payload) > 0 {
		key, n := consumeProtoVarint(payload)
		if n <= 0 {
			return req, fmt.Errorf("%w: malformed protobuf tag", ErrInvalidPacket)
		}
		payload = payload[n:]
		field := int(key >> 3)
		wireType := int(key & 0x7)

		switch wireType {
		case 0:
			value, n := consumeProtoVarint(payload)
			if n <= 0 {
				return req, fmt.Errorf("%w: malformed protobuf varint", ErrInvalidPacket)
			}
			payload = payload[n:]
			switch field {
			case 1:
				req.Magic = uint32(value)
			case 2:
				req.MyPeerID = uint32(value)
			case 3:
				req.Version = uint32(value)
			}
		case 2:
			length, n := consumeProtoVarint(payload)
			if n <= 0 || uint64(len(payload[n:])) < length {
				return req, fmt.Errorf("%w: malformed protobuf bytes", ErrInvalidPacket)
			}
			value := payload[n : n+int(length)]
			payload = payload[n+int(length):]
			switch field {
			case 4:
				req.Features = append(req.Features, string(value))
			case 5:
				req.NetworkName = string(value)
			case 6:
				req.NetworkSecretDigest = append(req.NetworkSecretDigest[:0], value...)
			}
		default:
			return req, fmt.Errorf("%w: unsupported protobuf wire type %d", ErrInvalidPacket, wireType)
		}
	}
	return req, nil
}

func appendProtoVarint(buf []byte, field int, value uint64) []byte {
	buf = binary.AppendUvarint(buf, uint64(field<<3))
	return binary.AppendUvarint(buf, value)
}

func appendProtoBytes(buf []byte, field int, value []byte) []byte {
	buf = binary.AppendUvarint(buf, uint64(field<<3|2))
	buf = binary.AppendUvarint(buf, uint64(len(value)))
	return append(buf, value...)
}

func consumeProtoVarint(buf []byte) (uint64, int) {
	value, n := binary.Uvarint(buf)
	return value, n
}

func NetworkSecretDigest(networkName, networkSecret string) [32]byte {
	var digest [32]byte
	h := newSipHash13()
	h.Write([]byte(networkName))
	h.Write([]byte(networkSecret))
	for i := 0; i < len(digest)/8; i++ {
		binary.BigEndian.PutUint64(digest[i*8:(i+1)*8], h.Sum64())
		h.Write(digest[:(i+1)*8])
	}
	return digest
}

func NetworkSecretKey128(networkSecret string) [16]byte {
	var key [16]byte
	h := newSipHash13()
	h.Write([]byte(networkSecret))
	binary.BigEndian.PutUint64(key[0:8], h.Sum64())
	h.Write(key[0:8])
	binary.BigEndian.PutUint64(key[8:16], h.Sum64())
	h.Write(key[0:16])
	return key
}

type sipHash13 struct {
	v0, v1, v2, v3 uint64
	tail           [8]byte
	ntail          int
	len            uint64
}

func newSipHash13() *sipHash13 {
	return &sipHash13{
		v0: 0x736f6d6570736575,
		v1: 0x646f72616e646f6d,
		v2: 0x6c7967656e657261,
		v3: 0x7465646279746573,
	}
}

func (h *sipHash13) Write(p []byte) {
	h.len += uint64(len(p))
	if h.ntail > 0 {
		n := copy(h.tail[h.ntail:], p)
		h.ntail += n
		p = p[n:]
		if h.ntail == 8 {
			h.writeBlock(binary.LittleEndian.Uint64(h.tail[:]))
			h.ntail = 0
		}
	}
	for len(p) >= 8 {
		h.writeBlock(binary.LittleEndian.Uint64(p[:8]))
		p = p[8:]
	}
	if len(p) > 0 {
		h.ntail = copy(h.tail[:], p)
		clear(h.tail[h.ntail:])
	}
}

func (h *sipHash13) Sum64() uint64 {
	copyH := *h
	var b uint64 = copyH.len << 56
	for i := 0; i < copyH.ntail; i++ {
		b |= uint64(copyH.tail[i]) << (8 * i)
	}
	copyH.writeBlock(b)
	copyH.v2 ^= 0xff
	copyH.round()
	copyH.round()
	copyH.round()
	return copyH.v0 ^ copyH.v1 ^ copyH.v2 ^ copyH.v3
}

func (h *sipHash13) writeBlock(m uint64) {
	h.v3 ^= m
	h.round()
	h.v0 ^= m
}

func (h *sipHash13) round() {
	h.v0 += h.v1
	h.v1 = bits.RotateLeft64(h.v1, 13)
	h.v1 ^= h.v0
	h.v0 = bits.RotateLeft64(h.v0, 32)
	h.v2 += h.v3
	h.v3 = bits.RotateLeft64(h.v3, 16)
	h.v3 ^= h.v2
	h.v0 += h.v3
	h.v3 = bits.RotateLeft64(h.v3, 21)
	h.v3 ^= h.v0
	h.v2 += h.v1
	h.v1 = bits.RotateLeft64(h.v1, 17)
	h.v1 ^= h.v2
	h.v2 = bits.RotateLeft64(h.v2, 32)
}

func ValidateHandshakeResponse(req HandshakeRequest, networkName string, digest [32]byte) error {
	if req.Magic != Magic {
		return fmt.Errorf("%w: unexpected magic 0x%x", ErrInvalidPacket, req.Magic)
	}
	if req.Version != Version {
		return fmt.Errorf("%w: unsupported version %d", ErrInvalidPacket, req.Version)
	}
	if req.NetworkName != networkName {
		return fmt.Errorf("easytier network name mismatch: got %q want %q", req.NetworkName, networkName)
	}
	if !bytes.Equal(req.NetworkSecretDigest, digest[:]) {
		return errors.New("easytier network secret digest mismatch")
	}
	return nil
}
