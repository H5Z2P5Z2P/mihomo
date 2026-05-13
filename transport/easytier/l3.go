package easytier

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"
)

const l3RequestTTL = 30 * time.Second

type packetWriter interface {
	WritePacket(packet []byte) error
}

type l3PingRequest struct {
	Identifier uint16
	Sequence   uint16
}

type L3PacketConn struct {
	client      *Client
	writer      packetWriter
	source      netip.Addr
	destination netip.Addr
	localSource netip.Addr

	mu       sync.Mutex
	closed   bool
	refs     []any
	requests map[l3PingRequest]time.Time
}

func (c *Client) ListenPacketL3(ctx context.Context, source, destination netip.Addr, writer packetWriter) (*L3PacketConn, error) {
	if !source.IsValid() || !destination.IsValid() {
		return nil, errors.New("invalid L3 source or destination")
	}
	if err := c.Start(ctx); err != nil {
		return nil, err
	}
	localSource, err := c.localL3Address(destination)
	if err != nil {
		return nil, err
	}
	conn := &L3PacketConn{
		client:      c,
		writer:      writer,
		source:      source,
		destination: destination,
		localSource: localSource,
		requests:    make(map[l3PingRequest]time.Time),
	}
	c.l3Mu.Lock()
	if c.l3Conns == nil {
		c.l3Conns = make(map[*L3PacketConn]struct{})
	}
	c.l3Conns[conn] = struct{}{}
	c.l3Mu.Unlock()
	return conn, nil
}

func (c *Client) handleL3Packet(packet []byte) bool {
	c.l3Mu.RLock()
	conns := make([]*L3PacketConn, 0, len(c.l3Conns))
	for conn := range c.l3Conns {
		conns = append(conns, conn)
	}
	c.l3Mu.RUnlock()

	for _, conn := range conns {
		if conn.handlePacket(packet) {
			return true
		}
	}
	return false
}

func (c *Client) closeL3Conns() {
	c.l3Mu.RLock()
	conns := make([]*L3PacketConn, 0, len(c.l3Conns))
	for conn := range c.l3Conns {
		conns = append(conns, conn)
	}
	c.l3Mu.RUnlock()
	for _, conn := range conns {
		_ = conn.Close()
	}
}

func (c *Client) localL3Address(destination netip.Addr) (netip.Addr, error) {
	if destination.Is4() {
		prefix, ok, err := c.ipv4Prefix()
		if err != nil || !ok {
			return netip.Addr{}, fmt.Errorf("easytier ipv4 is required for ICMP forwarding")
		}
		return prefix.Addr(), nil
	}
	if destination.Is6() && c.options.IPv6 != "" {
		prefix, err := parsePrefix(c.options.IPv6, 128)
		if err != nil {
			return netip.Addr{}, fmt.Errorf("parse easytier ipv6: %w", err)
		}
		return prefix.Addr(), nil
	}
	return netip.Addr{}, fmt.Errorf("easytier ipv6 is required for ICMP forwarding")
}

func (c *Client) sendRawPacket(payload []byte) error {
	packet := NewPacket(c.myPeerID, c.destinationPeerID(payload), PacketTypeData, payload)
	return c.sendPacket(packet)
}

func (c *L3PacketConn) WritePacket(packet []byte) error {
	packet, request, err := rewriteICMPRequestPacket(packet, c.localSource, c.destination)
	if err != nil {
		return err
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return errors.New("easytier L3 packet conn is closed")
	}
	c.pruneRequestsLocked(time.Now())
	c.requests[request] = time.Now()
	c.mu.Unlock()
	return c.client.sendRawPacket(packet)
}

func (c *L3PacketConn) handlePacket(packet []byte) bool {
	rewritten, request, ok := rewriteICMPReplyPacket(packet, c.destination, c.localSource, c.source)
	if !ok {
		return false
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return false
	}
	c.pruneRequestsLocked(time.Now())
	if _, exists := c.requests[request]; !exists {
		c.mu.Unlock()
		return false
	}
	delete(c.requests, request)
	c.mu.Unlock()
	_ = c.writer.WritePacket(rewritten)
	return true
}

func (c *L3PacketConn) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	c.refs = nil
	clear(c.requests)
	c.mu.Unlock()

	c.client.l3Mu.Lock()
	delete(c.client.l3Conns, c)
	c.client.l3Mu.Unlock()
	return nil
}

func (c *L3PacketConn) IsClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

func (c *L3PacketConn) AddRef(ref any) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return
	}
	c.refs = append(c.refs, ref)
}

func (c *L3PacketConn) pruneRequestsLocked(now time.Time) {
	for request, createdAt := range c.requests {
		if now.Sub(createdAt) > l3RequestTTL {
			delete(c.requests, request)
		}
	}
}

func rewriteICMPRequestPacket(packet []byte, source, destination netip.Addr) ([]byte, l3PingRequest, error) {
	packet = append([]byte(nil), packet...)
	version, err := ipVersion(packet)
	if err != nil {
		return nil, l3PingRequest{}, err
	}
	switch version {
	case 4:
		if !source.Is4() || !destination.Is4() {
			return nil, l3PingRequest{}, errors.New("IPv4 ICMP request requires IPv4 source and destination")
		}
		ihl := ipv4HeaderLength(packet)
		if len(packet) < ihl+8 || packet[9] != 1 || packet[ihl] != 8 || packet[ihl+1] != 0 {
			return nil, l3PingRequest{}, errors.New("only ICMPv4 echo requests are supported")
		}
		copy(packet[12:16], source.AsSlice())
		copy(packet[16:20], destination.AsSlice())
		setIPv4HeaderChecksum(packet[:ihl])
		return packet, l3PingRequest{
			Identifier: binary.BigEndian.Uint16(packet[ihl+4 : ihl+6]),
			Sequence:   binary.BigEndian.Uint16(packet[ihl+6 : ihl+8]),
		}, nil
	case 6:
		if !source.Is6() || !destination.Is6() {
			return nil, l3PingRequest{}, errors.New("IPv6 ICMP request requires IPv6 source and destination")
		}
		if len(packet) < 48 || packet[6] != 58 || packet[40] != 128 || packet[41] != 0 {
			return nil, l3PingRequest{}, errors.New("only ICMPv6 echo requests are supported")
		}
		copy(packet[8:24], source.AsSlice())
		copy(packet[24:40], destination.AsSlice())
		setICMPv6Checksum(packet)
		return packet, l3PingRequest{
			Identifier: binary.BigEndian.Uint16(packet[44:46]),
			Sequence:   binary.BigEndian.Uint16(packet[46:48]),
		}, nil
	default:
		return nil, l3PingRequest{}, errors.New("unsupported IP version")
	}
}

func rewriteICMPReplyPacket(packet []byte, source, destination, originalDestination netip.Addr) ([]byte, l3PingRequest, bool) {
	version, err := ipVersion(packet)
	if err != nil {
		return nil, l3PingRequest{}, false
	}
	packet = append([]byte(nil), packet...)
	switch version {
	case 4:
		ihl := ipv4HeaderLength(packet)
		if len(packet) < ihl+8 || packet[9] != 1 || packet[ihl] != 0 || packet[ihl+1] != 0 {
			return nil, l3PingRequest{}, false
		}
		packetSource := addrFromIPv4Bytes(packet[12:16])
		if packetSource != source {
			return nil, l3PingRequest{}, false
		}
		packetDestination := addrFromIPv4Bytes(packet[16:20])
		if packetDestination != destination {
			return nil, l3PingRequest{}, false
		}
		copy(packet[16:20], originalDestination.AsSlice())
		setIPv4HeaderChecksum(packet[:ihl])
		return packet, l3PingRequest{
			Identifier: binary.BigEndian.Uint16(packet[ihl+4 : ihl+6]),
			Sequence:   binary.BigEndian.Uint16(packet[ihl+6 : ihl+8]),
		}, true
	case 6:
		if len(packet) < 48 || packet[6] != 58 || packet[40] != 129 || packet[41] != 0 {
			return nil, l3PingRequest{}, false
		}
		packetSource := addrFromIPv6Bytes(packet[8:24])
		if packetSource != source {
			return nil, l3PingRequest{}, false
		}
		packetDestination := addrFromIPv6Bytes(packet[24:40])
		if packetDestination != destination {
			return nil, l3PingRequest{}, false
		}
		copy(packet[24:40], originalDestination.AsSlice())
		setICMPv6Checksum(packet)
		return packet, l3PingRequest{
			Identifier: binary.BigEndian.Uint16(packet[44:46]),
			Sequence:   binary.BigEndian.Uint16(packet[46:48]),
		}, true
	default:
		return nil, l3PingRequest{}, false
	}
}

func ipVersion(packet []byte) (int, error) {
	if len(packet) == 0 {
		return 0, errors.New("empty IP packet")
	}
	version := int(packet[0] >> 4)
	if version != 4 && version != 6 {
		return 0, errors.New("unsupported IP version")
	}
	return version, nil
}

func ipv4HeaderLength(packet []byte) int {
	return int(packet[0]&0x0f) * 4
}

func addrFromIPv4Bytes(b []byte) netip.Addr {
	var addr [4]byte
	copy(addr[:], b)
	return netip.AddrFrom4(addr)
}

func addrFromIPv6Bytes(b []byte) netip.Addr {
	var addr [16]byte
	copy(addr[:], b)
	return netip.AddrFrom16(addr)
}

func setIPv4HeaderChecksum(header []byte) {
	if len(header) < 20 {
		return
	}
	header[10] = 0
	header[11] = 0
	binary.BigEndian.PutUint16(header[10:12], checksum(header, 0))
}

func setICMPv6Checksum(packet []byte) {
	if len(packet) < 48 {
		return
	}
	payload := packet[40:]
	payload[2] = 0
	payload[3] = 0
	binary.BigEndian.PutUint16(payload[2:4], checksum(payload, ipv6PseudoHeaderSum(packet[8:24], packet[24:40], len(payload), 58)))
}

func ipv6PseudoHeaderSum(src, dst []byte, length int, nextHeader uint8) uint32 {
	var sum uint32
	sum = checksumSum(src, sum)
	sum = checksumSum(dst, sum)
	var lengthBuf [4]byte
	binary.BigEndian.PutUint32(lengthBuf[:], uint32(length))
	sum = checksumSum(lengthBuf[:], sum)
	return checksumSum([]byte{0, 0, 0, nextHeader}, sum)
}

func checksum(data []byte, initial uint32) uint16 {
	sum := checksumSum(data, initial)
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func checksumSum(data []byte, sum uint32) uint32 {
	for len(data) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(data[:2]))
		data = data[2:]
	}
	if len(data) == 1 {
		sum += uint32(data[0]) << 8
	}
	return sum
}
