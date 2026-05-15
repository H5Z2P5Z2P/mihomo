package easytier

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

const (
	udpTunnelHeaderSize      = 8
	udpTunnelHandshakeSize   = 8
	udpTunnelPacketTypeSyn   = 1
	udpTunnelPacketTypeSack  = 2
	udpTunnelPacketTypeData  = 3
	udpTunnelMaxControlBytes = 65535
)

type peerTransport interface {
	ReadPacket(maxPacketSize int) (*Packet, error)
	WritePacket(packet *Packet) error
	SetDeadline(t time.Time) error
	Close() error
}

func newPeerTransport(ctx context.Context, endpoint peerEndpoint, conn net.Conn) (peerTransport, error) {
	switch endpoint.network {
	case "tcp":
		return &tcpPeerTransport{conn: conn}, nil
	case "udp":
		return newUDPPeerTransport(ctx, conn)
	default:
		return nil, fmt.Errorf("unsupported easytier peer scheme %q", endpoint.network)
	}
}

type tcpPeerTransport struct {
	conn net.Conn
}

func (t *tcpPeerTransport) ReadPacket(maxPacketSize int) (*Packet, error) {
	return ReadTCPPacket(t.conn, maxPacketSize)
}

func (t *tcpPeerTransport) WritePacket(packet *Packet) error {
	_, err := t.conn.Write(packet.MarshalTCP())
	return err
}

func (t *tcpPeerTransport) SetDeadline(deadline time.Time) error {
	return t.conn.SetDeadline(deadline)
}

func (t *tcpPeerTransport) Close() error {
	return t.conn.Close()
}

type udpPeerTransport struct {
	conn   net.Conn
	connID uint32
	buf    []byte
}

type udpTunnelPacket struct {
	connID  uint32
	msgType byte
	payload []byte
}

func newUDPPeerTransport(ctx context.Context, conn net.Conn) (*udpPeerTransport, error) {
	t := &udpPeerTransport{
		conn:   conn,
		connID: nonZeroRandomUint32(),
		buf:    make([]byte, udpTunnelHeaderSize+udpTunnelMaxControlBytes),
	}
	if err := t.handshake(ctx); err != nil {
		return nil, err
	}
	return t, nil
}

func (t *udpPeerTransport) handshake(ctx context.Context) error {
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(5 * time.Second)
	}
	_ = t.conn.SetDeadline(deadline)
	defer t.conn.SetDeadline(time.Time{})

	magic := randomUint64()
	if _, err := t.conn.Write(marshalUDPTunnelPacket(t.connID, udpTunnelPacketTypeSyn, uint16(udpTunnelHandshakeSize), uint64Payload(magic))); err != nil {
		return err
	}

	for {
		packet, err := t.readTunnelPacket(udpTunnelMaxControlBytes)
		if err != nil {
			return err
		}
		if packet.msgType != udpTunnelPacketTypeSack || packet.connID != t.connID {
			continue
		}
		if len(packet.payload) != udpTunnelHandshakeSize {
			return fmt.Errorf("%w: invalid udp sack payload size", ErrInvalidPacket)
		}
		if binary.LittleEndian.Uint64(packet.payload) != magic {
			return fmt.Errorf("%w: invalid udp sack magic", ErrInvalidPacket)
		}
		return nil
	}
}

func (t *udpPeerTransport) ReadPacket(maxPacketSize int) (*Packet, error) {
	for {
		packet, err := t.readTunnelPacket(maxPacketSize)
		if err != nil {
			return nil, err
		}
		if packet.msgType != udpTunnelPacketTypeData || packet.connID != t.connID {
			continue
		}
		return ReadPacketBody(packet.payload, maxPacketSize)
	}
}

func (t *udpPeerTransport) WritePacket(packet *Packet) error {
	body := packet.MarshalBody()
	if len(body) > udpTunnelMaxControlBytes {
		return fmt.Errorf("%w: body too long", ErrInvalidPacket)
	}
	_, err := t.conn.Write(marshalUDPTunnelPacket(t.connID, udpTunnelPacketTypeData, uint16(len(body)), body))
	return err
}

func (t *udpPeerTransport) SetDeadline(deadline time.Time) error {
	return t.conn.SetDeadline(deadline)
}

func (t *udpPeerTransport) Close() error {
	return t.conn.Close()
}

func (t *udpPeerTransport) readTunnelPacket(maxPayloadSize int) (udpTunnelPacket, error) {
	if maxPayloadSize <= 0 {
		maxPayloadSize = udpTunnelMaxControlBytes
	}
	if len(t.buf) < udpTunnelHeaderSize+maxPayloadSize {
		t.buf = make([]byte, udpTunnelHeaderSize+maxPayloadSize)
	}
	n, err := t.conn.Read(t.buf[:udpTunnelHeaderSize+maxPayloadSize])
	if err != nil {
		return udpTunnelPacket{}, err
	}
	return parseUDPTunnelPacket(t.buf[:n], maxPayloadSize)
}

func parseUDPTunnelPacket(buf []byte, maxPayloadSize int) (udpTunnelPacket, error) {
	if len(buf) < udpTunnelHeaderSize {
		return udpTunnelPacket{}, fmt.Errorf("%w: udp tunnel packet too short", ErrInvalidPacket)
	}
	payloadLen := int(binary.LittleEndian.Uint16(buf[6:8]))
	if payloadLen != len(buf)-udpTunnelHeaderSize {
		return udpTunnelPacket{}, fmt.Errorf("%w: udp tunnel payload size mismatch", ErrInvalidPacket)
	}
	if maxPayloadSize > 0 && payloadLen > maxPayloadSize {
		return udpTunnelPacket{}, fmt.Errorf("%w: udp tunnel payload too long", ErrInvalidPacket)
	}
	return udpTunnelPacket{
		connID:  binary.LittleEndian.Uint32(buf[0:4]),
		msgType: buf[4],
		payload: append([]byte(nil), buf[udpTunnelHeaderSize:]...),
	}, nil
}

func marshalUDPTunnelPacket(connID uint32, msgType byte, payloadLen uint16, payload []byte) []byte {
	buf := make([]byte, udpTunnelHeaderSize+len(payload))
	binary.LittleEndian.PutUint32(buf[0:4], connID)
	buf[4] = msgType
	binary.LittleEndian.PutUint16(buf[6:8], payloadLen)
	copy(buf[udpTunnelHeaderSize:], payload)
	return buf
}

func uint64Payload(value uint64) []byte {
	buf := make([]byte, udpTunnelHandshakeSize)
	binary.LittleEndian.PutUint64(buf, value)
	return buf
}

func nonZeroRandomUint32() uint32 {
	for {
		value := randomPeerID()
		if value != 0 {
			return value
		}
	}
}

func reconnectDelayForFailures(failures int, jitterSeed uint64) time.Duration {
	if failures <= 0 {
		return 0
	}
	delay := reconnectBaseInterval
	for attempt := 1; attempt < failures && delay < reconnectMaxInterval; attempt++ {
		delay *= 2
		if delay > reconnectMaxInterval {
			delay = reconnectMaxInterval
		}
	}
	if jitterMax := delay / 4; jitterMax > 0 {
		delay += time.Duration(jitterSeed % uint64(jitterMax+1))
	}
	return delay
}
