package outbound

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/loopback"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
)

const (
	defaultEasyTierBinary      = "easytier-core"
	defaultEasyTierStartWaitMS = 1500
)

type EasyTier struct {
	*Base
	option   EasyTierOption
	dialer   C.Dialer
	loopBack *loopback.Detector

	startMu sync.Mutex
	cmd     *exec.Cmd
	waitCh  chan error
	started bool
}

type EasyTierOption struct {
	BasicOption
	Name string `proxy:"name"`

	Binary        string   `proxy:"binary,omitempty"`
	Peer          string   `proxy:"peer,omitempty"`
	Peers         []string `proxy:"peers,omitempty"`
	IPv4          string   `proxy:"ipv4,omitempty"`
	IPv6          string   `proxy:"ipv6,omitempty"`
	NetworkName   string   `proxy:"network-name,omitempty"`
	NetworkSecret string   `proxy:"network-secret,omitempty"`
	NoListener    bool     `proxy:"no-listener,omitempty"`
	ManualRoutes  []string `proxy:"manual-routes,omitempty"`
	ExtraArgs     []string `proxy:"extra-args,omitempty"`
	AutoStart     *bool    `proxy:"auto-start,omitempty"`
	StartWaitMS   int      `proxy:"start-wait-ms,omitempty"`
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
	return outbound, nil
}

func (e *EasyTier) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	if err := e.loopBack.CheckConn(metadata); err != nil {
		return nil, err
	}
	if err := e.ensureStarted(ctx); err != nil {
		return nil, err
	}

	opts := e.DialOptions()
	opts = append(opts, dialer.WithResolver(resolver.DirectHostResolver))
	c, err := dialer.DialContext(ctx, "tcp", metadata.RemoteAddress(), opts...)
	if err != nil {
		return nil, err
	}
	return e.loopBack.NewConn(NewConn(c, e)), nil
}

func (e *EasyTier) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (C.PacketConn, error) {
	if err := e.loopBack.CheckPacketConn(metadata); err != nil {
		return nil, err
	}
	if err := e.ensureStarted(ctx); err != nil {
		return nil, err
	}
	if err := e.ResolveUDP(ctx, metadata); err != nil {
		return nil, err
	}
	pc, err := e.dialer.ListenPacket(ctx, "udp", "", metadata.AddrPort())
	if err != nil {
		return nil, err
	}
	return e.loopBack.NewPacketConn(newPacketConn(pc, e)), nil
}

func (e *EasyTier) ResolveUDP(ctx context.Context, metadata *C.Metadata) error {
	if (!metadata.Resolved() || resolver.DirectHostResolver != resolver.DefaultResolver) && metadata.Host != "" {
		ip, err := resolver.ResolveIPWithResolver(ctx, metadata.Host, resolver.DirectHostResolver)
		if err != nil {
			return fmt.Errorf("can't resolve ip: %w", err)
		}
		metadata.DstIP = ip
	}
	return nil
}

func (e *EasyTier) IsL3Protocol(metadata *C.Metadata) bool {
	return true
}

func (e *EasyTier) Close() error {
	e.startMu.Lock()
	defer e.startMu.Unlock()

	if e.cmd == nil || e.cmd.Process == nil {
		return nil
	}
	if !e.started {
		return nil
	}

	log.Infoln("[EasyTier](%s) stopping process pid=%d", e.Name(), e.cmd.Process.Pid)
	_ = e.cmd.Process.Kill()
	select {
	case <-e.waitCh:
	case <-time.After(3 * time.Second):
	}
	e.started = false
	return nil
}

func (e *EasyTier) ensureStarted(ctx context.Context) error {
	if !e.option.autoStart() {
		return nil
	}

	e.startMu.Lock()
	defer e.startMu.Unlock()

	if e.started {
		select {
		case err := <-e.waitCh:
			e.started = false
			return fmt.Errorf("easytier process exited: %w", err)
		default:
			return nil
		}
	}

	binary := e.option.binary()
	args := e.option.commandArgs()
	cmd := exec.Command(binary, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start easytier process: %w", err)
	}

	e.cmd = cmd
	e.waitCh = make(chan error, 1)
	e.started = true
	go func() {
		e.waitCh <- cmd.Wait()
	}()

	log.Infoln("[EasyTier](%s) started pid=%d args=%s", e.Name(), cmd.Process.Pid, easyTierArgsForLog(args))
	if wait := e.option.startWait(); wait > 0 {
		select {
		case err := <-e.waitCh:
			e.started = false
			return fmt.Errorf("easytier process exited during startup: %w", err)
		case <-time.After(wait):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

func (o EasyTierOption) binary() string {
	if binary := strings.TrimSpace(o.Binary); binary != "" {
		return binary
	}
	return defaultEasyTierBinary
}

func (o EasyTierOption) autoStart() bool {
	return o.AutoStart == nil || *o.AutoStart
}

func (o EasyTierOption) startWait() time.Duration {
	if o.StartWaitMS < 0 {
		return 0
	}
	if o.StartWaitMS > 0 {
		return time.Duration(o.StartWaitMS) * time.Millisecond
	}
	return defaultEasyTierStartWaitMS * time.Millisecond
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

func (o EasyTierOption) commandArgs() []string {
	args := make([]string, 0, 16+len(o.Peers)*2+len(o.ManualRoutes)*2+len(o.ExtraArgs))
	for _, peer := range o.peerList() {
		args = append(args, "-p", peer)
	}
	if o.IPv4 != "" {
		args = append(args, "--ipv4", o.IPv4)
	}
	if o.IPv6 != "" {
		args = append(args, "--ipv6", o.IPv6)
	}
	if o.NetworkName != "" {
		args = append(args, "--network-name", o.NetworkName)
	}
	if o.NetworkSecret != "" {
		args = append(args, "--network-secret", o.NetworkSecret)
	}
	if o.NoListener {
		args = append(args, "--no-listener")
	}
	for _, route := range o.ManualRoutes {
		if route = strings.TrimSpace(route); route != "" {
			args = append(args, "--manual-routes", route)
		}
	}
	args = append(args, o.ExtraArgs...)
	return args
}

func easyTierArgsForLog(args []string) string {
	masked := append([]string(nil), args...)
	for i, arg := range masked {
		if arg == "--network-secret" && i+1 < len(masked) {
			masked[i+1] = "<redacted>"
			continue
		}
		if strings.HasPrefix(arg, "--network-secret=") {
			masked[i] = "--network-secret=<redacted>"
		}
	}
	return strings.Join(masked, " ")
}
