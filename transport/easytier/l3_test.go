package easytier

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"
)

type packetWriterSpy struct {
	packets [][]byte
}

func (w *packetWriterSpy) WritePacket(packet []byte) error {
	w.packets = append(w.packets, append([]byte(nil), packet...))
	return nil
}

func TestRewriteICMPv4RequestPacketUsesEasyTierSource(t *testing.T) {
	packet := testICMPv4Packet(8, "28.0.0.1", "198.51.100.3", 0x1234, 0x0001)
	rewritten, request, err := rewriteICMPRequestPacket(packet, netip.MustParseAddr("198.51.100.11"), netip.MustParseAddr("198.51.100.3"))
	if err != nil {
		t.Fatal(err)
	}
	if request != (l3PingRequest{Identifier: 0x1234, Sequence: 0x0001}) {
		t.Fatalf("unexpected request: %#v", request)
	}
	if got := addrFromIPv4Bytes(rewritten[12:16]).String(); got != "198.51.100.11" {
		t.Fatalf("unexpected rewritten source: %s", got)
	}
	if got := addrFromIPv4Bytes(rewritten[16:20]).String(); got != "198.51.100.3" {
		t.Fatalf("unexpected rewritten destination: %s", got)
	}
}

func TestL3PacketConnHandlesMatchingICMPv4Reply(t *testing.T) {
	writer := &packetWriterSpy{}
	conn := &L3PacketConn{
		writer:      writer,
		source:      netip.MustParseAddr("28.0.0.1"),
		destination: netip.MustParseAddr("198.51.100.3"),
		localSource: netip.MustParseAddr("198.51.100.11"),
		requests: map[l3PingRequest]time.Time{
			{Identifier: 0x1234, Sequence: 0x0001}: time.Now(),
		},
	}
	packet := testICMPv4Packet(0, "198.51.100.3", "198.51.100.11", 0x1234, 0x0001)
	if !conn.handlePacket(packet) {
		t.Fatal("expected matching ICMPv4 reply to be consumed")
	}
	if len(writer.packets) != 1 {
		t.Fatalf("unexpected delivered packet count: %d", len(writer.packets))
	}
	if got := addrFromIPv4Bytes(writer.packets[0][16:20]).String(); got != "28.0.0.1" {
		t.Fatalf("unexpected restored destination: %s", got)
	}
	if len(conn.requests) != 0 {
		t.Fatalf("expected request map to be drained: %#v", conn.requests)
	}
}

func testICMPv4Packet(icmpType byte, source, destination string, identifier, sequence uint16) []byte {
	packet := make([]byte, 28)
	packet[0] = 0x45
	packet[8] = 64
	packet[9] = 1
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	copy(packet[12:16], netip.MustParseAddr(source).AsSlice())
	copy(packet[16:20], netip.MustParseAddr(destination).AsSlice())
	packet[20] = icmpType
	packet[21] = 0
	binary.BigEndian.PutUint16(packet[24:26], identifier)
	binary.BigEndian.PutUint16(packet[26:28], sequence)
	setIPv4HeaderChecksum(packet[:20])
	return packet
}
