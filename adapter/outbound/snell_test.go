package outbound

import (
	"bytes"
	"net"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/snell"
)

func TestNewSnellKeepsVersion5(t *testing.T) {
	proxy, err := NewSnell(SnellOption{
		Name:    "snell",
		Server:  "example.com",
		Port:    443,
		Psk:     "password",
		UDP:     true,
		Version: snell.Version5,
		Reuse:   true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if proxy.version != snell.Version5 {
		t.Fatalf("version = %d, want %d", proxy.version, snell.Version5)
	}
	if !proxy.reuse {
		t.Fatal("version 5 should support reuse")
	}
	if proxy.SupportUOT() {
		t.Fatal("version 5 UDP uses QUIC mode, not UDP-over-TCP")
	}
}

func TestSnellQUICPacketConnFirstPacketEnvelopeThenRaw(t *testing.T) {
	raw := &recordingPacketConn{localAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 10000}}
	serverAddr := &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 44046}
	metadata := &C.Metadata{NetWork: C.UDP, Host: "example.com", DstPort: 443}
	pc := newSnellQUICPacketConn(raw, serverAddr, []byte("password"), metadata, C.DualStack)
	targetAddr := &net.UDPAddr{IP: net.IPv4(9, 9, 9, 9), Port: 443}

	first := []byte("first quic packet")
	n, err := pc.WriteTo(first, targetAddr)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(first) {
		t.Fatalf("first write length = %d, want %d", n, len(first))
	}
	if len(raw.writes) != 1 {
		t.Fatalf("writes = %d, want 1", len(raw.writes))
	}
	if raw.writes[0].addr.String() != serverAddr.String() {
		t.Fatalf("first write addr = %s, want %s", raw.writes[0].addr, serverAddr)
	}
	if bytes.Equal(raw.writes[0].data, first) {
		t.Fatal("first packet should be encrypted envelope, got raw payload")
	}

	second := []byte("raw quic packet")
	n, err = pc.WriteTo(second, targetAddr)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(second) {
		t.Fatalf("second write length = %d, want %d", n, len(second))
	}
	if len(raw.writes) != 2 {
		t.Fatalf("writes = %d, want 2", len(raw.writes))
	}
	if !bytes.Equal(raw.writes[1].data, second) {
		t.Fatalf("second packet = %q, want raw %q", raw.writes[1].data, second)
	}
}

func TestSnellQUICPacketConnReadFromReturnsTarget(t *testing.T) {
	raw := &recordingPacketConn{localAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 10000}}
	serverAddr := &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 44046}
	targetAddr := &net.UDPAddr{IP: net.IPv4(9, 9, 9, 9), Port: 443}
	metadata := &C.Metadata{NetWork: C.UDP, DstIP: targetAddr.AddrPort().Addr(), DstPort: 443}
	pc := newSnellQUICPacketConn(raw, serverAddr, []byte("password"), metadata, C.DualStack)
	raw.reads = append(raw.reads, packetRead{data: []byte("response"), addr: serverAddr})

	buf := make([]byte, 64)
	n, addr, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(buf[:n]); got != "response" {
		t.Fatalf("response = %q", got)
	}
	if addr.String() != targetAddr.String() {
		t.Fatalf("read addr = %s, want %s", addr, targetAddr)
	}
}

type packetWrite struct {
	data []byte
	addr net.Addr
}

type packetRead struct {
	data []byte
	addr net.Addr
}

type recordingPacketConn struct {
	localAddr net.Addr
	writes    []packetWrite
	reads     []packetRead
}

func (c *recordingPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	if len(c.reads) == 0 {
		return 0, nil, net.ErrClosed
	}
	read := c.reads[0]
	c.reads = c.reads[1:]
	return copy(p, read.data), read.addr, nil
}

func (c *recordingPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	c.writes = append(c.writes, packetWrite{data: append([]byte(nil), p...), addr: addr})
	return len(p), nil
}

func (c *recordingPacketConn) Close() error { return nil }

func (c *recordingPacketConn) LocalAddr() net.Addr {
	if c.localAddr == nil {
		return &net.UDPAddr{}
	}
	return c.localAddr
}

func (c *recordingPacketConn) SetDeadline(time.Time) error      { return nil }
func (c *recordingPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (c *recordingPacketConn) SetWriteDeadline(time.Time) error { return nil }
