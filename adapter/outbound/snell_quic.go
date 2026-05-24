package outbound

import (
	"context"
	"errors"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/snell"
)

const snellQUICEnvelopeRetryInterval = 250 * time.Millisecond

type snellQUICPacketConn struct {
	net.PacketConn
	serverAddr *net.UDPAddr
	psk        []byte

	mux              sync.Mutex
	firstMu          sync.Mutex
	sent             atomic.Bool
	confirmed        atomic.Bool
	lastEnvelopeNano int64
	targetHost       string
	targetPort       uint16
	targetAddr       atomic.Value
	prefer           C.DNSPrefer
}

type snellQUICAddr struct {
	addr net.Addr
}

func newSnellQUICPacketConn(pc net.PacketConn, serverAddr *net.UDPAddr, psk []byte, metadata *C.Metadata, prefer C.DNSPrefer) *snellQUICPacketConn {
	qpc := &snellQUICPacketConn{
		PacketConn: pc,
		serverAddr: serverAddr,
		psk:        psk,
		targetHost: metadata.String(),
		targetPort: metadata.DstPort,
		prefer:     prefer,
	}
	if metadata.NetWork == C.UDP && metadata.DstIP.IsValid() {
		qpc.targetAddr.Store(snellQUICAddr{addr: metadata.UDPAddr()})
	}
	return qpc
}

func (c *snellQUICPacketConn) resolveUDP(ctx context.Context, metadata *C.Metadata) error {
	c.mux.Lock()
	if metadata.Host != "" {
		c.targetHost = metadata.Host
		c.targetPort = metadata.DstPort
	}
	c.mux.Unlock()

	if !metadata.Resolved() {
		ip, err := resolveIPWithResolver(ctx, metadata.Host, c.prefer, resolver.DefaultResolver)
		if err != nil {
			return err
		}
		metadata.DstIP = ip
	}

	c.mux.Lock()
	if metadata.NetWork == C.UDP && metadata.DstIP.IsValid() {
		c.targetAddr.Store(snellQUICAddr{addr: metadata.UDPAddr()})
	}
	c.mux.Unlock()
	return nil
}

func (c *snellQUICPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	if c.targetAddr.Load() == nil && addr != nil {
		c.targetAddr.Store(snellQUICAddr{addr: addr})
	}

	if c.confirmed.Load() {
		return c.PacketConn.WriteTo(b, c.serverAddr)
	}

	if !c.sent.Load() {
		c.firstMu.Lock()
		if !c.sent.Load() {
			if err := c.writeEnvelope(b, addr, time.Now()); err != nil {
				c.firstMu.Unlock()
				return 0, err
			}
			c.sent.Store(true)
			c.firstMu.Unlock()
			return len(b), nil
		}
		c.firstMu.Unlock()
	}

	now := time.Now()
	if c.shouldRetryEnvelope(now) {
		if err := c.writeEnvelope(b, addr, now); err != nil {
			return 0, err
		}
	}
	return c.PacketConn.WriteTo(b, c.serverAddr)
}

func (c *snellQUICPacketConn) shouldRetryEnvelope(now time.Time) bool {
	last := time.Unix(0, atomic.LoadInt64(&c.lastEnvelopeNano))
	return !last.IsZero() && now.Sub(last) >= snellQUICEnvelopeRetryInterval
}

func (c *snellQUICPacketConn) writeEnvelope(b []byte, addr net.Addr, now time.Time) error {
	host, port, err := c.target(addr)
	if err != nil {
		return err
	}
	envelope, err := snell.EncodeQUICEnvelope(c.psk, host, port, b)
	if err != nil {
		return err
	}
	if _, err = c.PacketConn.WriteTo(envelope, c.serverAddr); err != nil {
		return err
	}
	atomic.StoreInt64(&c.lastEnvelopeNano, now.UnixNano())
	return nil
}

func (c *snellQUICPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, _, err := c.PacketConn.ReadFrom(b)
	if err != nil {
		return n, nil, err
	}

	c.confirmed.Store(true)
	target, _ := c.targetAddr.Load().(snellQUICAddr)
	if target.addr == nil {
		target.addr = c.serverAddr
	}
	return n, target.addr, nil
}

func (c *snellQUICPacketConn) target(addr net.Addr) (string, uint16, error) {
	c.mux.Lock()
	defer c.mux.Unlock()

	if c.targetHost != "" && c.targetHost != "<nil>" && c.targetPort != 0 {
		return c.targetHost, c.targetPort, nil
	}
	if udpAddr, ok := addr.(*net.UDPAddr); ok && udpAddr != nil {
		return udpAddr.IP.String(), uint16(udpAddr.Port), nil
	}
	if addr == nil {
		return "", 0, errors.New("snell quic target invalid")
	}
	host, portString, err := net.SplitHostPort(addr.String())
	if err != nil {
		return "", 0, err
	}
	port, err := strconv.ParseUint(portString, 10, 16)
	if err != nil {
		return "", 0, err
	}
	return host, uint16(port), nil
}

func (c *snellQUICPacketConn) SetDeadline(t time.Time) error {
	return c.PacketConn.SetDeadline(t)
}

func (c *snellQUICPacketConn) SetReadDeadline(t time.Time) error {
	return c.PacketConn.SetReadDeadline(t)
}

func (c *snellQUICPacketConn) SetWriteDeadline(t time.Time) error {
	return c.PacketConn.SetWriteDeadline(t)
}
