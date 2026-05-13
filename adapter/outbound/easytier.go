package outbound

import (
	"context"
	"fmt"
	"strings"

	"github.com/metacubex/mihomo/component/loopback"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	et "github.com/metacubex/mihomo/transport/easytier"
	M "github.com/metacubex/sing/common/metadata"
)

type EasyTier struct {
	*Base
	option   EasyTierOption
	client   *et.Client
	loopBack *loopback.Detector
}

type EasyTierOption struct {
	BasicOption
	Name string `proxy:"name"`

	Peer              string   `proxy:"peer,omitempty"`
	Peers             []string `proxy:"peers,omitempty"`
	IPv4              string   `proxy:"ipv4,omitempty"`
	IPv6              string   `proxy:"ipv6,omitempty"`
	NetworkName       string   `proxy:"network-name,omitempty"`
	NetworkSecret     string   `proxy:"network-secret,omitempty"`
	MTU               int      `proxy:"mtu,omitempty"`
	UDP               bool     `proxy:"udp,omitempty"`
	NoListener        bool     `proxy:"no-listener,omitempty"`
	DisableEncryption bool     `proxy:"disable-encryption,omitempty"`
	ManualRoutes      []string `proxy:"manual-routes,omitempty"`
}

func NewEasyTier(option EasyTierOption) (*EasyTier, error) {
	addr := "easytier"
	peers := option.peerList()
	if len(peers) > 0 {
		addr = peers[0]
	}

	outbound := &EasyTier{
		Base: NewBase(BaseOption{
			Name:         option.Name,
			Addr:         addr,
			Type:         C.EasyTier,
			UDP:          true,
			TFO:          option.TFO,
			MPTCP:        option.MPTCP,
			Interface:    option.Interface,
			RoutingMark:  option.RoutingMark,
			Prefer:       option.IPVersion,
			ProviderName: option.ProviderName,
		}),
		option:   option,
		loopBack: loopback.NewDetector(),
	}
	outbound.dialer = option.NewDialer(outbound.DialOptions())
	outbound.client = et.NewClient(et.Options{
		Peers:             peers,
		IPv4:              option.IPv4,
		IPv6:              option.IPv6,
		NetworkName:       option.NetworkName,
		NetworkSecret:     option.NetworkSecret,
		MTU:               option.MTU,
		DisableEncryption: option.DisableEncryption,
		ManualRoutes:      option.ManualRoutes,
	}, outbound.dialer)
	return outbound, nil
}

func (e *EasyTier) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	if err := e.loopBack.CheckConn(metadata); err != nil {
		return nil, err
	}
	if err := e.resolve(ctx, metadata); err != nil {
		return nil, err
	}

	addr := M.SocksaddrFrom(metadata.DstIP, metadata.DstPort).Unwrap()
	c, err := e.client.DialContext(ctx, "tcp", addr.String())
	if err != nil {
		return nil, err
	}
	return e.loopBack.NewConn(NewConn(c, e)), nil
}

func (e *EasyTier) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (C.PacketConn, error) {
	if err := e.loopBack.CheckPacketConn(metadata); err != nil {
		return nil, err
	}
	if err := e.resolve(ctx, metadata); err != nil {
		return nil, err
	}

	addr := M.SocksaddrFrom(metadata.DstIP, metadata.DstPort).Unwrap()
	pc, err := e.client.ListenPacket(ctx, addr)
	if err != nil {
		return nil, err
	}
	return e.loopBack.NewPacketConn(newPacketConn(pc, e)), nil
}

func (e *EasyTier) ListenPacketContextL3(ctx context.Context, metadata *C.Metadata, writer C.L3PacketWriter) (C.L3PacketConn, error) {
	if err := e.resolve(ctx, metadata); err != nil {
		return nil, err
	}
	if !metadata.SrcIP.IsValid() {
		return nil, fmt.Errorf("missing easytier source ip for L3 packet")
	}
	return e.client.ListenPacketL3(ctx, metadata.SrcIP, metadata.DstIP, writer)
}

func (e *EasyTier) ResolveUDP(ctx context.Context, metadata *C.Metadata) error {
	return e.resolve(ctx, metadata)
}

func (e *EasyTier) IsL3Protocol(metadata *C.Metadata) bool {
	return true
}

func (e *EasyTier) Close() error {
	if e.client != nil {
		return e.client.Close()
	}
	return nil
}

func (e *EasyTier) resolve(ctx context.Context, metadata *C.Metadata) error {
	if metadata.Resolved() {
		return nil
	}
	if metadata.Host == "" {
		return fmt.Errorf("missing easytier destination ip")
	}
	ip, err := resolver.ResolveIPWithResolver(ctx, metadata.Host, resolver.DefaultResolver)
	if err != nil {
		return fmt.Errorf("can't resolve ip: %w", err)
	}
	metadata.DstIP = ip
	return nil
}

func (o EasyTierOption) peerList() []string {
	peers := make([]string, 0, len(o.Peers)+1)
	if peer := strings.TrimSpace(o.Peer); peer != "" {
		peers = append(peers, peer)
	}
	for _, peer := range o.Peers {
		if peer = strings.TrimSpace(peer); peer != "" {
			peers = append(peers, peer)
		}
	}
	return peers
}
