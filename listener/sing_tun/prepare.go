package sing_tun

import (
	"context"
	"net/netip"
	"time"

	"github.com/metacubex/mihomo/adapter/inbound"
	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/log"

	tun "github.com/metacubex/sing-tun"
	"github.com/metacubex/sing-tun/ping"
	"github.com/metacubex/sing/common/buf"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
)

func (h *ListenerHandler) PrepareConnection(network string, source M.Socksaddr, destination M.Socksaddr, routeContext tun.DirectRouteContext, timeout time.Duration) (tun.DirectRouteDestination, error) {
	switch network {
	case N.NetworkICMP: // our fork only send those type to PrepareConnection now
		if h.DisableICMPForwarding || h.skipPingForwardingByAddr(destination.Addr) { // skip if ICMP handling is disabled or other condition
			log.Infoln("[ICMP] %s %s --> %s using fake ping echo", network, source, destination)
			return nil, nil
		}
		if h.icmpRoutingMode() != LC.ICMPRoutingModeDirect {
			if directRouteDestination, rule, proxyName, err, handled := h.prepareProxyICMPConnection(source, destination, routeContext); handled {
				if err != nil {
					return nil, err
				}
				logICMPProxyRoute(network, source, destination, rule, proxyName)
				return directRouteDestination, nil
			}
		}
		log.Infoln("[ICMP] %s %s --> %s using DIRECT", network, source, destination)
		directRouteDestination, err := ping.ConnectDestination(context.TODO(), log.SingLogger, dialer.ICMPControl(destination.Addr), destination.Addr, routeContext, timeout)
		if err != nil {
			log.Warnln("[ICMP] failed to connect to %s", destination)
			return nil, err
		}
		log.Debugln("[ICMP] success connect to %s", destination)
		return directRouteDestination, nil
	}
	return nil, nil
}

type l3DirectRouteDestination struct {
	conn C.L3PacketConn
}

func (d *l3DirectRouteDestination) WritePacket(packet *buf.Buffer) error {
	defer packet.Release()
	return d.conn.WritePacket(append([]byte(nil), packet.Bytes()...))
}

func (d *l3DirectRouteDestination) Close() error {
	return d.conn.Close()
}

func (d *l3DirectRouteDestination) IsClosed() bool {
	return d.conn.IsClosed()
}

func (h *ListenerHandler) prepareProxyICMPConnection(source M.Socksaddr, destination M.Socksaddr, routeContext tun.DirectRouteContext) (tun.DirectRouteDestination, C.Rule, string, error, bool) {
	resolver, ok := any(h.Tunnel).(C.MetadataResolver)
	if !ok {
		return nil, nil, "", nil, false
	}

	metadata := &C.Metadata{NetWork: C.ICMP, Type: h.Type}
	inbound.ApplyAdditions(metadata, inbound.WithDstAddr(destination), inbound.WithSrcAddr(source))
	inbound.ApplyAdditions(metadata, h.Additions...)

	proxy, rule, err := resolver.ResolveMetadata(metadata)
	if err != nil {
		return nil, rule, "", err, true
	}
	leaf := unwrapProxy(proxy, metadata)
	switch leaf.Type() {
	case C.Direct:
		return nil, nil, "", nil, false
	case C.RejectDrop:
		return nil, rule, proxy.Name(), tun.ErrDrop, true
	case C.Reject:
		return nil, rule, proxy.Name(), tun.ErrReset, true
	}
	if !h.shouldUseICMPL3Proxy(leaf) {
		return nil, nil, "", nil, false
	}

	l3Proxy, ok := leaf.Adapter().(C.L3ProxyAdapter)
	if !ok {
		log.Warnln("[ICMP] matched proxy %s for %s, but selected leaf %s does not support L3, fallback to DIRECT", proxy.Name(), destination, leaf.Name())
		return nil, nil, "", nil, false
	}
	l3Conn, err := l3Proxy.ListenPacketContextL3(context.TODO(), metadata.Pure(), routeContext)
	if err != nil {
		return nil, rule, proxy.Name(), err, true
	}
	return &l3DirectRouteDestination{conn: l3Conn}, rule, proxy.Name(), nil, true
}

func (h *ListenerHandler) icmpRoutingMode() LC.ICMPRoutingMode {
	if mode, err := LC.ParseICMPRoutingMode(h.ICMPRoutingMode); err == nil {
		return mode
	}
	return LC.ICMPRoutingModeProxy
}

func (h *ListenerHandler) shouldUseICMPL3Proxy(leaf C.Proxy) bool {
	switch h.icmpRoutingMode() {
	case LC.ICMPRoutingModeDirect:
		return false
	case LC.ICMPRoutingModeEasyTier:
		return leaf.Type() == C.EasyTier
	default:
		return true
	}
}

func unwrapProxy(proxy C.Proxy, metadata *C.Metadata) C.Proxy {
	leaf := proxy
	for {
		next := leaf.Unwrap(metadata, true)
		if next == nil {
			return leaf
		}
		leaf = next
	}
}

func logICMPProxyRoute(network string, source M.Socksaddr, destination M.Socksaddr, rule C.Rule, proxyName string) {
	if rule != nil {
		if rule.Payload() != "" {
			log.Infoln("[ICMP] %s %s --> %s match %s(%s) using %s", network, source, destination, rule.RuleType().String(), rule.Payload(), proxyName)
		} else {
			log.Infoln("[ICMP] %s %s --> %s match %s using %s", network, source, destination, rule.RuleType().String(), proxyName)
		}
		return
	}
	log.Infoln("[ICMP] %s %s --> %s using %s", network, source, destination, proxyName)
}

func (h *ListenerHandler) skipPingForwardingByAddr(addr netip.Addr) bool {
	for _, prefix := range h.Inet4Address { // skip in interface ipv4 range
		if prefix.Contains(addr) {
			return true
		}
	}
	for _, prefix := range h.Inet6Address { // skip in interface ipv6 range
		if prefix.Contains(addr) {
			return true
		}
	}
	if resolver.IsFakeIP(addr) { // skip in fakeIp pool
		return true
	}
	return false
}
