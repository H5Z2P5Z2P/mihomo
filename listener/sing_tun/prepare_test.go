package sing_tun

import (
	"context"
	"net"
	"net/netip"
	"testing"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/inbound"
	"github.com/metacubex/mihomo/adapter/outbound"
	C "github.com/metacubex/mihomo/constant"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/listener/sing"
	RC "github.com/metacubex/mihomo/rules/common"
	M "github.com/metacubex/sing/common/metadata"
)

type l3ProxyAdapterStub struct {
	*outbound.Base
	metadata *C.Metadata
	writer   C.L3PacketWriter
	conn     C.L3PacketConn
}

func (a *l3ProxyAdapterStub) ListenPacketContextL3(ctx context.Context, metadata *C.Metadata, writer C.L3PacketWriter) (C.L3PacketConn, error) {
	a.metadata = metadata.Clone()
	a.writer = writer
	return a.conn, nil
}

type l3PacketConnStub struct{}

func (l *l3PacketConnStub) WritePacket(packet []byte) error { return nil }
func (l *l3PacketConnStub) Close() error                    { return nil }
func (l *l3PacketConnStub) IsClosed() bool                  { return false }

type metadataResolverTunnelStub struct {
	proxy    C.Proxy
	rule     C.Rule
	metadata *C.Metadata
}

func (t *metadataResolverTunnelStub) HandleTCPConn(conn net.Conn, metadata *C.Metadata) {}
func (t *metadataResolverTunnelStub) HandleUDPPacket(packet C.UDPPacket, metadata *C.Metadata) {
}
func (t *metadataResolverTunnelStub) NatTable() C.NatTable { return nil }
func (t *metadataResolverTunnelStub) ResolveMetadata(metadata *C.Metadata) (C.Proxy, C.Rule, error) {
	t.metadata = metadata.Clone()
	return t.proxy, t.rule, nil
}

type routeContextStub struct{}

func (routeContextStub) WritePacket(packet []byte) error { return nil }

func TestPrepareProxyICMPConnectionUsesL3Proxy(t *testing.T) {
	adapterStub := &l3ProxyAdapterStub{
		Base: outbound.NewBase(outbound.BaseOption{
			Name: "et-example",
			Addr: "easytier",
			Type: C.EasyTier,
			UDP:  true,
		}),
		conn: &l3PacketConnStub{},
	}
	proxy := adapter.NewProxy(adapterStub)
	rule, err := RC.NewIPCIDR("198.51.100.0/24", "et-example", RC.WithIPCIDRNoResolve(true))
	if err != nil {
		t.Fatal(err)
	}
	tunnelStub := &metadataResolverTunnelStub{proxy: proxy, rule: rule}
	handler := &ListenerHandler{
		ListenerHandler: &sing.ListenerHandler{ListenerConfig: sing.ListenerConfig{
			Tunnel:    tunnelStub,
			Type:      C.TUN,
			Additions: []inbound.Addition{inbound.WithInName("DEFAULT-TUN")},
		}},
		ICMPRoutingMode: LC.ICMPRoutingModeProxy,
	}

	destination, matchedRule, proxyName, err, handled := handler.prepareProxyICMPConnection(
		M.SocksaddrFrom(netip.MustParseAddr("28.0.0.1"), 0),
		M.SocksaddrFrom(netip.MustParseAddr("198.51.100.3"), 0),
		routeContextStub{},
	)
	if err != nil {
		t.Fatal(err)
	}
	if !handled || destination == nil {
		t.Fatal("expected ICMP proxy routing to return a direct route destination")
	}
	if matchedRule == nil || proxyName != "et-example" {
		t.Fatalf("unexpected routing result: rule=%v proxy=%s", matchedRule, proxyName)
	}
	if tunnelStub.metadata == nil || tunnelStub.metadata.NetWork != C.ICMP {
		t.Fatalf("unexpected tunnel metadata: %#v", tunnelStub.metadata)
	}
	if adapterStub.metadata == nil || adapterStub.metadata.DstIP.String() != "198.51.100.3" {
		t.Fatalf("unexpected proxy metadata: %#v", adapterStub.metadata)
	}
	if adapterStub.writer == nil {
		t.Fatal("expected routeContext to be passed to L3 proxy adapter")
	}
}

func TestPrepareProxyICMPConnectionFallsBackDirectForNonL3Proxy(t *testing.T) {
	proxy := adapter.NewProxy(outbound.NewBase(outbound.BaseOption{
		Name: "vmess-a",
		Addr: "vmess.example.com",
		Type: C.Vmess,
		UDP:  true,
	}))
	rule := RC.NewMatch("🐟 Final")
	tunnelStub := &metadataResolverTunnelStub{proxy: proxy, rule: rule}
	handler := &ListenerHandler{
		ListenerHandler: &sing.ListenerHandler{ListenerConfig: sing.ListenerConfig{
			Tunnel: tunnelStub,
			Type:   C.TUN,
		}},
		ICMPRoutingMode: LC.ICMPRoutingModeProxy,
	}

	destination, matchedRule, proxyName, err, handled := handler.prepareProxyICMPConnection(
		M.SocksaddrFrom(netip.MustParseAddr("28.0.0.1"), 0),
		M.SocksaddrFrom(netip.MustParseAddr("1.1.1.1"), 0),
		routeContextStub{},
	)
	if err != nil {
		t.Fatal(err)
	}
	if handled {
		t.Fatal("expected non-L3 proxy to fall back to direct ICMP forwarding")
	}
	if destination != nil || matchedRule != nil || proxyName != "" {
		t.Fatalf("unexpected fallback result: destination=%v rule=%v proxy=%q", destination, matchedRule, proxyName)
	}
}

func TestPrepareProxyICMPConnectionUsesNonEasyTierL3ProxyInProxyMode(t *testing.T) {
	adapterStub := &l3ProxyAdapterStub{
		Base: outbound.NewBase(outbound.BaseOption{
			Name: "ts-main",
			Addr: "tailscale",
			Type: C.Tailscale,
			UDP:  true,
		}),
		conn: &l3PacketConnStub{},
	}
	proxy := adapter.NewProxy(adapterStub)
	rule := RC.NewMatch("ts-main")
	tunnelStub := &metadataResolverTunnelStub{proxy: proxy, rule: rule}
	handler := &ListenerHandler{
		ListenerHandler: &sing.ListenerHandler{ListenerConfig: sing.ListenerConfig{
			Tunnel: tunnelStub,
			Type:   C.TUN,
		}},
		ICMPRoutingMode: LC.ICMPRoutingModeProxy,
	}

	destination, matchedRule, proxyName, err, handled := handler.prepareProxyICMPConnection(
		M.SocksaddrFrom(netip.MustParseAddr("28.0.0.1"), 0),
		M.SocksaddrFrom(netip.MustParseAddr("100.64.0.10"), 0),
		routeContextStub{},
	)
	if err != nil {
		t.Fatal(err)
	}
	if !handled || destination == nil {
		t.Fatal("expected proxy mode to use non-EasyTier L3 proxy")
	}
	if matchedRule == nil || proxyName != "ts-main" {
		t.Fatalf("unexpected routing result: rule=%v proxy=%s", matchedRule, proxyName)
	}
}

func TestPrepareProxyICMPConnectionFallsBackDirectForNonEasyTierL3ProxyInEasyTierMode(t *testing.T) {
	adapterStub := &l3ProxyAdapterStub{
		Base: outbound.NewBase(outbound.BaseOption{
			Name: "ts-main",
			Addr: "tailscale",
			Type: C.Tailscale,
			UDP:  true,
		}),
		conn: &l3PacketConnStub{},
	}
	proxy := adapter.NewProxy(adapterStub)
	rule := RC.NewMatch("ts-main")
	tunnelStub := &metadataResolverTunnelStub{proxy: proxy, rule: rule}
	handler := &ListenerHandler{
		ListenerHandler: &sing.ListenerHandler{ListenerConfig: sing.ListenerConfig{
			Tunnel: tunnelStub,
			Type:   C.TUN,
		}},
		ICMPRoutingMode: LC.ICMPRoutingModeEasyTier,
	}

	destination, matchedRule, proxyName, err, handled := handler.prepareProxyICMPConnection(
		M.SocksaddrFrom(netip.MustParseAddr("28.0.0.1"), 0),
		M.SocksaddrFrom(netip.MustParseAddr("100.64.0.10"), 0),
		routeContextStub{},
	)
	if err != nil {
		t.Fatal(err)
	}
	if handled {
		t.Fatal("expected easytier mode to bypass non-EasyTier L3 proxies")
	}
	if destination != nil || matchedRule != nil || proxyName != "" {
		t.Fatalf("unexpected fallback result: destination=%v rule=%v proxy=%q", destination, matchedRule, proxyName)
	}
}
