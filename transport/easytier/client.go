package easytier

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/log"

	stackdevice "github.com/metacubex/sing-wireguard"
	M "github.com/metacubex/sing/common/metadata"
)

const (
	reconnectPollInterval   = time.Second
	reconnectBaseInterval   = time.Second
	reconnectMaxInterval    = 30 * time.Second
	routeSyncInterval       = 30 * time.Second
	routeStaleAfter         = 90 * time.Second
	observedRouteStaleAfter = 10 * time.Minute
	sessionPingInterval     = 10 * time.Second
	sessionPingTimeout      = 45 * time.Second
	waitForSessionInterval  = 200 * time.Millisecond
)

var ErrNoActivePeerSessions = errors.New("easytier has no active peer sessions")

type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

type Options struct {
	Peers             []string
	IPv4              string
	IPv6              string
	Hostname          string
	NetworkName       string
	NetworkSecret     string
	MTU               int
	LatencyFirst      bool
	DisableEncryption bool
	// ManualRoutes is accepted for config parity with EasyTier, but mihomo rules
	// decide which traffic enters this outbound.
	ManualRoutes []string
}

type peerEndpoint struct {
	network string
	address string
}

type peerSession struct {
	peerID    uint32
	endpoint  peerEndpoint
	transport peerTransport
	writeMu   sync.Mutex
	pingMu    sync.Mutex
	pings     map[uint64]time.Time
	latency   time.Duration
	latencyAt time.Time
}

type relayRouteSnapshot struct {
	updatedAt time.Time
	peers     map[uint32]routePeerInfo
}

type routeConnSnapshot struct {
	updatedAt        time.Time
	connectedPeerIDs map[uint32]struct{}
	version          uint32
}

type routePath struct {
	nextHopPeerID uint32
	hops          int
	cost          int
}

type routePathItem struct {
	peerID uint32
	hops   int
	cost   int
}

type routeTableView struct {
	nextHopByPeer map[uint32]routePath
	ipv4PeerByIP  map[netip.Addr]uint32
	ipv6PeerByIP  map[netip.Addr]uint32
	proxyEntries  []routeProxyEntry
}

type routeProxyEntry struct {
	prefix  netip.Prefix
	peerID  uint32
	version uint32
	path    routePath
}

type observedRoute struct {
	peerID uint32
	seenAt time.Time
}

type DebugSnapshot struct {
	MyPeerID       uint32
	Hostname       string
	Sessions       []DebugSession
	RoutePeers     []DebugRoutePeer
	RouteConns     []DebugRouteConn
	ObservedRoutes []DebugObservedRoute
	RouteTable     DebugRouteTableView
}

type DebugSession struct {
	PeerID     uint32
	Network    string
	Address    string
	Latency    time.Duration
	HasLatency bool
}

type DebugRoutePeer struct {
	PeerID        uint32
	IPv4          netip.Addr
	IPv6          netip.Addr
	NetworkLength int
	ProxyCIDRs    []netip.Prefix
	Hostname      string
	Version       uint32
	RelayPeerID   uint32
	Observed      bool
	ObservedAt    time.Time
}

type DebugRouteConn struct {
	PeerID           uint32
	Version          uint32
	ConnectedPeerIDs []uint32
}

type DebugObservedRoute struct {
	IP     netip.Addr
	PeerID uint32
	SeenAt time.Time
}

type DebugRouteTableView struct {
	NextHops     []DebugNextHop
	IPv4Mappings []DebugIPMapping
	IPv6Mappings []DebugIPMapping
	ProxyRoutes  []DebugProxyRoute
}

type DebugNextHop struct {
	PeerID        uint32
	NextHopPeerID uint32
	Hops          int
	Cost          int
}

type DebugIPMapping struct {
	IP     netip.Addr
	PeerID uint32
}

type DebugProxyRoute struct {
	Prefix        netip.Prefix
	PeerID        uint32
	NextHopPeerID uint32
	Hops          int
	Cost          int
	Version       uint32
}

type reconnectState struct {
	failures    int
	nextAttempt time.Time
}

type Client struct {
	options Options
	dialer  Dialer

	startMu sync.Mutex
	started bool

	myPeerID       uint32
	routeSessionID uint64
	peerRouteID    uint64
	instanceID     [4]uint32
	digest         [32]byte
	key128         [16]byte
	peerMu         sync.RWMutex
	peerEndpoints  []peerEndpoint

	device  stackdevice.Device
	cancel  context.CancelFunc
	done    chan struct{}
	closeMu sync.Mutex
	closeFn *sync.Once
	err     error

	sessionsMu        sync.RWMutex
	sessions          map[uint32]*peerSession
	connVersion       uint32
	reconnectMu       sync.Mutex
	reconnect         map[string]reconnectState
	routeMu           sync.RWMutex
	routes            map[uint32]relayRouteSnapshot
	routePeers        map[uint32]routePeerInfo
	rawRoutePeerInfos map[uint32][]byte
	routeConns        map[uint32]routeConnSnapshot
	observedRoutes    map[netip.Addr]observedRoute
	l3Mu              sync.RWMutex
	l3Conns           map[*L3PacketConn]struct{}
}

func NewClient(options Options, dialer Dialer) *Client {
	if dialer == nil {
		dialer = &net.Dialer{}
	}
	options.Hostname = defaultHostname(options.Hostname)
	return &Client{options: options, dialer: dialer}
}

func (c *Client) UpdatePeers(peers []string) error {
	peerEndpoints, err := parsePeerEndpoints(peers)
	if err != nil {
		return err
	}

	c.startMu.Lock()
	c.options.Peers = peerStringsFromEndpoints(peerEndpoints)
	c.setPeerEndpoints(peerEndpoints)
	started := c.started
	c.startMu.Unlock()

	c.pruneReconnectStates(peerEndpoints)
	if !started {
		return nil
	}
	c.removeUnconfiguredSessions(peerEndpoints)
	return nil
}

func (c *Client) DebugSnapshot() DebugSnapshot {
	snapshot := DebugSnapshot{MyPeerID: c.myPeerID, Hostname: c.options.Hostname}
	for _, session := range c.activeSessions() {
		latency, ok := session.currentLatency(time.Now())
		snapshot.Sessions = append(snapshot.Sessions, DebugSession{
			PeerID:     session.peerID,
			Network:    session.endpoint.network,
			Address:    session.endpoint.address,
			Latency:    latency,
			HasLatency: ok,
		})
	}
	activePeerIDs := c.activeSessionPeerIDs()
	c.routeMu.RLock()
	view := c.buildRouteTableViewLocked(activePeerIDs)
	for peerID, info := range c.routePeers {
		debugPeer := DebugRoutePeer{
			PeerID:        peerID,
			IPv4:          info.IPv4,
			IPv6:          info.IPv6,
			NetworkLength: info.NetworkLength,
			ProxyCIDRs:    append([]netip.Prefix(nil), info.ProxyCIDRs...),
			Hostname:      info.Hostname,
			Version:       info.Version,
		}
		for relayPeerID, relaySnapshot := range c.routes {
			if _, ok := relaySnapshot.peers[peerID]; ok {
				debugPeer.RelayPeerID = relayPeerID
				break
			}
		}
		for addr, observed := range c.observedRoutes {
			if observed.peerID == peerID {
				debugPeer.Observed = true
				debugPeer.ObservedAt = observed.seenAt
				if !debugPeer.IPv4.IsValid() && addr.Is4() {
					debugPeer.IPv4 = addr
				}
				if !debugPeer.IPv6.IsValid() && addr.Is6() {
					debugPeer.IPv6 = addr
				}
			}
		}
		snapshot.RoutePeers = append(snapshot.RoutePeers, debugPeer)
	}
	for peerID, conn := range c.routeConns {
		connectedPeerIDs := make([]uint32, 0, len(conn.connectedPeerIDs))
		for connectedPeerID := range conn.connectedPeerIDs {
			connectedPeerIDs = append(connectedPeerIDs, connectedPeerID)
		}
		sort.Slice(connectedPeerIDs, func(i, j int) bool { return connectedPeerIDs[i] < connectedPeerIDs[j] })
		snapshot.RouteConns = append(snapshot.RouteConns, DebugRouteConn{
			PeerID:           peerID,
			Version:          conn.version,
			ConnectedPeerIDs: connectedPeerIDs,
		})
	}
	for addr, observed := range c.observedRoutes {
		snapshot.ObservedRoutes = append(snapshot.ObservedRoutes, DebugObservedRoute{
			IP:     addr,
			PeerID: observed.peerID,
			SeenAt: observed.seenAt,
		})
	}
	for peerID, path := range view.nextHopByPeer {
		snapshot.RouteTable.NextHops = append(snapshot.RouteTable.NextHops, DebugNextHop{
			PeerID:        peerID,
			NextHopPeerID: path.nextHopPeerID,
			Hops:          path.hops,
			Cost:          path.cost,
		})
	}
	for addr, peerID := range view.ipv4PeerByIP {
		snapshot.RouteTable.IPv4Mappings = append(snapshot.RouteTable.IPv4Mappings, DebugIPMapping{IP: addr, PeerID: peerID})
	}
	for addr, peerID := range view.ipv6PeerByIP {
		snapshot.RouteTable.IPv6Mappings = append(snapshot.RouteTable.IPv6Mappings, DebugIPMapping{IP: addr, PeerID: peerID})
	}
	for _, proxy := range view.proxyEntries {
		snapshot.RouteTable.ProxyRoutes = append(snapshot.RouteTable.ProxyRoutes, DebugProxyRoute{
			Prefix:        proxy.prefix,
			PeerID:        proxy.peerID,
			NextHopPeerID: proxy.path.nextHopPeerID,
			Hops:          proxy.path.hops,
			Cost:          proxy.path.cost,
			Version:       proxy.version,
		})
	}
	c.routeMu.RUnlock()
	sort.Slice(snapshot.RoutePeers, func(i, j int) bool { return snapshot.RoutePeers[i].PeerID < snapshot.RoutePeers[j].PeerID })
	sort.Slice(snapshot.RouteConns, func(i, j int) bool { return snapshot.RouteConns[i].PeerID < snapshot.RouteConns[j].PeerID })
	sort.Slice(snapshot.ObservedRoutes, func(i, j int) bool { return snapshot.ObservedRoutes[i].IP.Compare(snapshot.ObservedRoutes[j].IP) < 0 })
	sort.Slice(snapshot.RouteTable.NextHops, func(i, j int) bool {
		return snapshot.RouteTable.NextHops[i].PeerID < snapshot.RouteTable.NextHops[j].PeerID
	})
	sort.Slice(snapshot.RouteTable.IPv4Mappings, func(i, j int) bool {
		return snapshot.RouteTable.IPv4Mappings[i].IP.Compare(snapshot.RouteTable.IPv4Mappings[j].IP) < 0
	})
	sort.Slice(snapshot.RouteTable.IPv6Mappings, func(i, j int) bool {
		return snapshot.RouteTable.IPv6Mappings[i].IP.Compare(snapshot.RouteTable.IPv6Mappings[j].IP) < 0
	})
	sort.Slice(snapshot.RouteTable.ProxyRoutes, func(i, j int) bool {
		if snapshot.RouteTable.ProxyRoutes[i].Prefix.Bits() != snapshot.RouteTable.ProxyRoutes[j].Prefix.Bits() {
			return snapshot.RouteTable.ProxyRoutes[i].Prefix.Bits() > snapshot.RouteTable.ProxyRoutes[j].Prefix.Bits()
		}
		if snapshot.RouteTable.ProxyRoutes[i].PeerID != snapshot.RouteTable.ProxyRoutes[j].PeerID {
			return snapshot.RouteTable.ProxyRoutes[i].PeerID < snapshot.RouteTable.ProxyRoutes[j].PeerID
		}
		return snapshot.RouteTable.ProxyRoutes[i].Prefix.String() < snapshot.RouteTable.ProxyRoutes[j].Prefix.String()
	})
	return snapshot
}

func (c *Client) Start(ctx context.Context) error {
	c.startMu.Lock()
	defer c.startMu.Unlock()

	if c.started {
		return c.err
	}
	if c.err != nil {
		return c.err
	}

	peerEndpoints, err := parsePeerEndpoints(c.options.Peers)
	if err != nil {
		return err
	}
	localPrefixes, err := c.localPrefixes()
	if err != nil {
		return err
	}

	mtu := c.options.MTU
	if mtu == 0 {
		mtu = DefaultMTU
	}
	device, err := stackdevice.NewStackDevice(localPrefixes, uint32(mtu))
	if err != nil {
		return err
	}
	if err = device.Start(); err != nil {
		_ = device.Close()
		return err
	}

	c.myPeerID = randomPeerID()
	c.routeSessionID = randomUint64()
	c.peerRouteID = randomUint64()
	c.instanceID = randomInstanceID()
	c.digest = NetworkSecretDigest(c.networkName(), c.options.NetworkSecret)
	c.key128 = NetworkSecretKey128(c.options.NetworkSecret)
	log.Infoln("[EasyTier] start peer=%d hostname=%s network=%s latency-first=%t peers=%d", c.myPeerID, c.options.Hostname, c.networkName(), c.options.LatencyFirst, len(peerEndpoints))
	c.setPeerEndpoints(peerEndpoints)
	c.device = device
	c.done = make(chan struct{})
	c.closeFn = &sync.Once{}
	c.sessions = make(map[uint32]*peerSession, len(peerEndpoints))
	c.reconnect = make(map[string]reconnectState, len(peerEndpoints))

	runCtx, cancel := context.WithCancel(context.Background())
	c.cancel = cancel

	sessions := make([]*peerSession, 0, len(peerEndpoints))
	dialErrors := make([]error, 0, len(peerEndpoints))
	for _, endpoint := range peerEndpoints {
		session, err := c.connectPeer(ctx, endpoint)
		if err != nil {
			dialErrors = append(dialErrors, fmt.Errorf("%s://%s: %w", endpoint.network, endpoint.address, err))
			continue
		}
		if session != nil {
			sessions = append(sessions, session)
		}
	}
	if len(sessions) == 0 {
		cancel()
		c.cancel = nil
		c.sessions = nil
		c.closeFn = nil
		c.done = nil
		c.device = nil
		_ = device.Close()
		if len(dialErrors) == 0 {
			return errors.New("easytier failed to connect to any peer")
		}
		return fmt.Errorf("easytier failed to connect to any peer: %w", errors.Join(dialErrors...))
	}

	c.started = true
	for _, session := range sessions {
		go c.readLoop(runCtx, session)
	}
	go c.reconnectLoop(runCtx)
	go c.writeLoop(runCtx)
	go c.routeLoop(runCtx)
	return nil
}

func (c *Client) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if err := c.Start(ctx); err != nil {
		return nil, err
	}
	destination := M.ParseSocksaddr(address)
	return c.device.DialContext(ctx, network, destination)
}

func (c *Client) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if err := c.Start(ctx); err != nil {
		return nil, err
	}
	return c.device.ListenPacket(ctx, destination)
}

func (c *Client) Close() error {
	c.closeWithError(nil)
	return nil
}

func (c *Client) connectPeer(ctx context.Context, endpoint peerEndpoint) (*peerSession, error) {
	conn, err := c.dialer.DialContext(ctx, endpoint.network, endpoint.address)
	if err != nil {
		return nil, err
	}
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		_ = tcpConn.SetNoDelay(true)
	}
	transport, err := newPeerTransport(ctx, endpoint, conn)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}

	remotePeerID, err := c.doHandshake(ctx, transport)
	if err != nil {
		_ = transport.Close()
		return nil, err
	}
	if !c.isPeerEndpointConfigured(endpoint) {
		_ = transport.Close()
		return nil, nil
	}

	session := &peerSession{peerID: remotePeerID, endpoint: endpoint, transport: transport}
	if !c.addSession(session) {
		_ = transport.Close()
		return nil, nil
	}
	c.clearReconnectState(endpoint)
	log.Infoln("[EasyTier] session connected peer=%d via=%s://%s", remotePeerID, endpoint.network, endpoint.address)
	if err := c.sendRouteSyncToSession(session); err != nil {
		c.removeSession(session)
		return nil, err
	}
	return session, nil
}

func (c *Client) doHandshake(ctx context.Context, transport peerTransport) (uint32, error) {
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(5 * time.Second)
	}
	_ = transport.SetDeadline(deadline)
	defer transport.SetDeadline(time.Time{})

	req := NewHandshakeRequest(c.myPeerID, c.networkName(), c.digest)
	packet := NewPacket(c.myPeerID, 0, PacketTypeHandshake, req.Marshal())
	if err := transport.WritePacket(packet); err != nil {
		return 0, err
	}

	for {
		packet, err := transport.ReadPacket(64 * 1024)
		if err != nil {
			return 0, err
		}
		switch packet.Header.PacketType {
		case PacketTypeHandshake:
			rsp, err := ParseHandshakeRequest(packet.Payload)
			if err != nil {
				return 0, err
			}
			if err = ValidateHandshakeResponse(rsp, c.networkName(), c.digest); err != nil {
				return 0, err
			}
			if rsp.MyPeerID == c.myPeerID {
				return 0, errors.New("easytier peer id conflict")
			}
			return rsp.MyPeerID, nil
		case PacketTypeNoiseHandshake1, PacketTypeNoiseHandshake2, PacketTypeNoiseHandshake3:
			return 0, ErrUnsupportedSecureMode
		}
	}
}

func (c *Client) readLoop(ctx context.Context, session *peerSession) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		packet, err := session.transport.ReadPacket(64 * 1024)
		if err != nil {
			c.handleSessionError(session, err)
			return
		}
		if err = c.handlePeerPacket(session, packet); err != nil {
			c.handleSessionError(session, err)
			return
		}
	}
}

func (c *Client) handlePeerPacket(session *peerSession, packet *Packet) error {
	if packet.Header.IsEncrypted() {
		if err := packet.DecryptAES128GCM(c.key128); err != nil {
			return err
		}
	}

	switch packet.Header.PacketType {
	case PacketTypePing:
		packet.Header.PacketType = PacketTypePong
		return c.sendPacketToSession(session, packet)
	case PacketTypePong:
		session.observePong(packet.Payload, time.Now())
		return nil
	case PacketTypeRPCReq:
		rpcReq, err := parseRPCPacket(packet.Payload)
		if err != nil {
			return err
		}
		if !isRouteSyncRequest(rpcReq, c.networkName()) {
			return nil
		}
		syncInfo, err := parseRouteSyncRPCRequest(rpcReq)
		if err != nil {
			return err
		}
		if rawInfos, rawErr := rawRoutePeerInfoPayloads(rpcReq); rawErr == nil {
			for i := range syncInfo.PeerInfos {
				if i < len(rawInfos) {
					syncInfo.PeerInfos[i].Raw = rawInfos[i]
				}
			}
		}
		log.Debugln("[EasyTier] route sync received relay=%d peers=%d conns=%d", session.peerID, len(syncInfo.PeerInfos), len(syncInfo.ConnInfos))
		c.updateRouteState(session.peerID, syncInfo)
		return c.sendPacketToSession(session, buildRouteSyncResponsePacket(rpcReq, c.myPeerID, packet.Header.FromPeerID, c.routeSessionID))
	case PacketTypeRPCResp:
		return nil
	case PacketTypeNoiseHandshake1, PacketTypeNoiseHandshake2, PacketTypeNoiseHandshake3:
		return ErrUnsupportedSecureMode
	case PacketTypeData:
		if packet.Header.ToPeerID != c.myPeerID {
			return nil
		}
		c.observeDataRoute(packet)
		if c.handleL3Packet(packet.Payload) {
			return nil
		}
		_, err := c.device.Write([][]byte{packet.Payload}, 0)
		return err
	default:
		return nil
	}
}

func (c *Client) writeLoop(ctx context.Context) {
	mtu, err := c.device.MTU()
	if err != nil || mtu <= 0 {
		mtu = DefaultMTU
	}
	buf := make([]byte, mtu+128)
	sizes := []int{0}
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		count, err := c.device.Read([][]byte{buf}, sizes, 0)
		if err != nil {
			c.closeWithError(err)
			return
		}
		if count == 0 || sizes[0] == 0 {
			continue
		}
		payload := append([]byte(nil), buf[:sizes[0]]...)
		packet := NewPacket(c.myPeerID, c.destinationPeerID(payload), PacketTypeData, payload)
		if err = c.sendPacketWithRetry(ctx, packet); err != nil {
			if ctx.Err() != nil {
				return
			}
			c.closeWithError(err)
			return
		}
	}
}

func (c *Client) routeLoop(ctx context.Context) {
	routeTicker := time.NewTicker(routeSyncInterval)
	defer routeTicker.Stop()
	pingTicker := time.NewTicker(sessionPingInterval)
	defer pingTicker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-pingTicker.C:
			c.pingSessions()
		case <-routeTicker.C:
			c.pruneStaleRoutes(time.Now())
			if err := c.sendRouteSync(); err != nil && !errors.Is(err, ErrNoActivePeerSessions) {
				continue
			}
		}
	}
}

func (c *Client) reconnectLoop(ctx context.Context) {
	for {
		if err := c.reconnectMissingPeers(ctx); err != nil && ctx.Err() != nil {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(reconnectPollInterval):
		}
	}
}

func (c *Client) reconnectMissingPeers(ctx context.Context) error {
	now := time.Now()
	for _, endpoint := range c.missingPeerEndpoints(now) {
		session, err := c.connectPeer(ctx, endpoint)
		if err != nil {
			c.recordReconnectFailure(endpoint, now)
			if ctx.Err() != nil {
				return ctx.Err()
			}
			continue
		}
		if session != nil {
			go c.readLoop(ctx, session)
		}
	}
	return nil
}

func (c *Client) sendRouteSync() error {
	sessions := c.activeSessions()
	if len(sessions) == 0 {
		return ErrNoActivePeerSessions
	}
	var firstErr error
	sent := false
	for _, session := range sessions {
		if err := c.sendRouteSyncToSession(session); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			c.handleSessionError(session, err)
			continue
		}
		sent = true
	}
	if sent {
		return nil
	}
	if firstErr != nil {
		return firstErr
	}
	return ErrNoActivePeerSessions
}

func (c *Client) sendRouteSyncToSession(session *peerSession) error {
	config, ok, err := c.routeRPCConfig(session.peerID)
	if err != nil || !ok {
		return err
	}
	packet, err := buildRouteSyncRequestPacket(config)
	if err != nil {
		return err
	}
	log.Debugln("[EasyTier] route sync send remote=%d hostname=%s route-peers=%d route-conns=%d", session.peerID, config.Hostname, len(config.PeerInfos), len(config.ConnInfos))
	return c.sendPacketToSession(session, packet)
}

func (c *Client) routeRPCConfig(remotePeerID uint32) (routeRPCConfig, bool, error) {
	ipv4, ok, err := c.ipv4Prefix()
	if err != nil || !ok {
		return routeRPCConfig{}, ok, err
	}
	return routeRPCConfig{
		MyPeerID:     c.myPeerID,
		RemotePeerID: remotePeerID,
		NetworkName:  c.networkName(),
		IPv4:         ipv4,
		Hostname:     c.options.Hostname,
		SessionID:    c.routeSessionID,
		PeerRouteID:  c.peerRouteID,
		InstanceID:   c.instanceID,
		PeerInfos:    c.routePeerInfoSnapshot(remotePeerID),
		ConnInfos:    c.routeConnInfoSnapshot(remotePeerID),
		Transaction:  int64(randomUint64() & (1<<63 - 1)),
	}, true, nil
}

func defaultHostname(hostname string) string {
	if hostname = strings.TrimSpace(hostname); hostname != "" {
		return hostname
	}
	if host, err := os.Hostname(); err == nil {
		if host = strings.TrimSpace(host); host != "" {
			return host
		}
	}
	return "mihomo"
}

func (c *Client) updateRoutes(relayPeerID uint32, peerInfos []routePeerInfo) {
	c.routeMu.Lock()
	defer c.routeMu.Unlock()
	if c.routes == nil {
		c.routes = make(map[uint32]relayRouteSnapshot)
	}
	if c.routePeers == nil {
		c.routePeers = make(map[uint32]routePeerInfo)
	}
	if c.rawRoutePeerInfos == nil {
		c.rawRoutePeerInfos = make(map[uint32][]byte)
	}
	snapshot := c.routes[relayPeerID]
	if snapshot.peers == nil {
		snapshot.peers = make(map[uint32]routePeerInfo, len(peerInfos))
	}
	snapshot.updatedAt = time.Now()
	for _, info := range peerInfos {
		if info.PeerID == 0 || info.PeerID == c.myPeerID {
			continue
		}
		info.RelayPeerID = relayPeerID
		stored := c.updateRoutePeerInfoLocked(info)
		stored.RelayPeerID = relayPeerID
		snapshot.peers[info.PeerID] = stored
	}
	c.routes[relayPeerID] = snapshot
	c.updateRouteConnInfosLocked(relayPeerID, peerInfos, nil)
}

func (c *Client) updateRouteState(relayPeerID uint32, syncInfo syncRouteInfo) {
	c.routeMu.Lock()
	if c.routes == nil {
		c.routes = make(map[uint32]relayRouteSnapshot)
	}
	if c.routePeers == nil {
		c.routePeers = make(map[uint32]routePeerInfo)
	}
	if c.rawRoutePeerInfos == nil {
		c.rawRoutePeerInfos = make(map[uint32][]byte)
	}
	if c.routeConns == nil {
		c.routeConns = make(map[uint32]routeConnSnapshot)
	}
	if c.observedRoutes == nil {
		c.observedRoutes = make(map[netip.Addr]observedRoute)
	}
	snapshot := c.routes[relayPeerID]
	if snapshot.peers == nil {
		snapshot.peers = make(map[uint32]routePeerInfo, len(syncInfo.PeerInfos))
	}
	snapshot.updatedAt = time.Now()
	for _, info := range syncInfo.PeerInfos {
		if info.PeerID == 0 || info.PeerID == c.myPeerID {
			continue
		}
		info.RelayPeerID = relayPeerID
		stored := c.updateRoutePeerInfoLocked(info)
		stored.RelayPeerID = relayPeerID
		snapshot.peers[info.PeerID] = stored
	}
	c.routes[relayPeerID] = snapshot
	c.updateRouteConnInfosLocked(relayPeerID, syncInfo.PeerInfos, syncInfo.ConnInfos)
	routePeers := len(c.routePeers)
	routeConns := len(c.routeConns)
	c.routeMu.Unlock()
	view := c.currentRouteTableView()
	nextHops := len(view.nextHopByPeer)
	ipv4Mappings := len(view.ipv4PeerByIP)
	ipv6Mappings := len(view.ipv6PeerByIP)
	proxyRoutes := len(view.proxyEntries)
	log.Debugln("[EasyTier] route table updated relay=%d route-peers=%d route-conns=%d next-hops=%d ipv4=%d ipv6=%d proxy-routes=%d", relayPeerID, routePeers, routeConns, nextHops, ipv4Mappings, ipv6Mappings, proxyRoutes)
}

func (c *Client) updateRoutePeerInfoLocked(info routePeerInfo) routePeerInfo {
	info = cloneRoutePeerInfo(info)
	if len(info.Raw) == 0 {
		if raw := c.rawRoutePeerInfos[info.PeerID]; len(raw) > 0 {
			info.Raw = append([]byte(nil), raw...)
		}
	}
	if current, ok := c.routePeers[info.PeerID]; ok {
		switch {
		case info.Version == 0 && current.Version > 0:
			return cloneRoutePeerInfo(current)
		case info.Version < current.Version:
			return cloneRoutePeerInfo(current)
		case info.Version == current.Version:
			info = mergeRoutePeerInfo(current, info)
		}
	}
	c.routePeers[info.PeerID] = cloneRoutePeerInfo(info)
	if len(info.Raw) > 0 {
		c.rawRoutePeerInfos[info.PeerID] = append([]byte(nil), info.Raw...)
	}
	log.Debugln("[EasyTier] route peer updated peer=%d hostname=%s ipv4=%s ipv6=%s proxy-cidrs=%d version=%d relay=%d", info.PeerID, info.Hostname, routeAddrForLog(info.IPv4), routeAddrForLog(info.IPv6), len(info.ProxyCIDRs), info.Version, info.RelayPeerID)
	return info
}

func (c *Client) updateRouteConnInfosLocked(relayPeerID uint32, peerInfos []routePeerInfo, connInfos []routeConnInfo) {
	if c.routeConns == nil {
		c.routeConns = make(map[uint32]routeConnSnapshot)
	}
	now := time.Now()
	if len(connInfos) == 0 {
		connected := make(map[uint32]struct{}, len(peerInfos)+1)
		version := uint32(1)
		if current, ok := c.routeConns[relayPeerID]; ok {
			version = current.version
			for peerID := range current.connectedPeerIDs {
				connected[peerID] = struct{}{}
			}
		}
		for _, info := range peerInfos {
			if info.PeerID != 0 && info.PeerID != c.myPeerID {
				connected[info.PeerID] = struct{}{}
			}
		}
		c.routeConns[relayPeerID] = routeConnSnapshot{updatedAt: now, connectedPeerIDs: connected, version: version}
		return
	}
	for _, info := range connInfos {
		if info.PeerID == 0 || info.PeerID == c.myPeerID {
			continue
		}
		current, ok := c.routeConns[info.PeerID]
		if ok && info.Version != 0 && info.Version < current.version {
			continue
		}
		connected := make(map[uint32]struct{}, len(info.ConnectedPeerIDs))
		for _, connectedPeerID := range info.ConnectedPeerIDs {
			if connectedPeerID != 0 && connectedPeerID != info.PeerID {
				connected[connectedPeerID] = struct{}{}
			}
		}
		version := info.Version
		if version == 0 && ok {
			version = current.version
		}
		c.routeConns[info.PeerID] = routeConnSnapshot{updatedAt: now, connectedPeerIDs: connected, version: version}
	}
}

func (c *Client) destinationPeerID(payload []byte) uint32 {
	addr, ok := ipPacketDestination(payload)
	if !ok {
		peerID := c.defaultPeerID(netip.Addr{})
		log.Debugln("[EasyTier] smart route selected peer=%d reason=fallback-no-ip latency-first=%t", peerID, c.options.LatencyFirst)
		return peerID
	}
	if peerID, reason, ok := c.lookupRoutePeer(addr); ok {
		log.Debugln("[EasyTier] smart route selected dst=%s peer=%d reason=%s latency-first=%t", addr, peerID, reason, c.options.LatencyFirst)
		return peerID
	}
	peerID := c.defaultPeerID(addr)
	log.Debugln("[EasyTier] smart route selected dst=%s peer=%d reason=fallback latency-first=%t", addr, peerID, c.options.LatencyFirst)
	return peerID
}

func (c *Client) lookupRoutePeer(addr netip.Addr) (uint32, string, bool) {
	view := c.currentRouteTableView()
	if addr.Is4() {
		if peerID, ok := view.ipv4PeerByIP[addr]; ok {
			return peerID, "ipv4", true
		}
	} else if addr.Is6() {
		if peerID, ok := view.ipv6PeerByIP[addr]; ok {
			return peerID, "ipv6", true
		}
	}
	for _, entry := range view.proxyEntries {
		if entry.prefix.Contains(addr) {
			return entry.peerID, "proxy-cidr:" + entry.prefix.String(), true
		}
	}
	return 0, "", false
}

func (c *Client) routePeerReachableLocked(peerID uint32, activePeerIDs []uint32) bool {
	_, ok := c.bestRoutePathLocked(peerID, activePeerIDs)
	return ok
}

func (c *Client) routePathExistsLocked(fromPeerID, toPeerID uint32) bool {
	_, ok := c.routePathFromNextHopLocked(fromPeerID, toPeerID)
	return ok
}

func (c *Client) bestRoutePathLocked(toPeerID uint32, activePeerIDs []uint32) (routePath, bool) {
	var best routePath
	for _, activePeerID := range activePeerIDs {
		path, ok := c.routePathFromNextHopLocked(activePeerID, toPeerID)
		if !ok {
			continue
		}
		if best.nextHopPeerID == 0 || c.routePathLess(path, best) {
			best = path
		}
	}
	if best.nextHopPeerID == 0 {
		return routePath{}, false
	}
	return best, true
}

func (c *Client) routePathLess(a, b routePath) bool {
	if c.options.LatencyFirst {
		aLatency, aOK := c.sessionLatencyByPeerID(a.nextHopPeerID)
		bLatency, bOK := c.sessionLatencyByPeerID(b.nextHopPeerID)
		if aOK != bOK {
			return aOK
		}
		if aOK && aLatency != bLatency {
			return aLatency < bLatency
		}
	}
	if a.hops != b.hops {
		return a.hops < b.hops
	}
	if a.cost != b.cost {
		return a.cost < b.cost
	}
	return a.nextHopPeerID < b.nextHopPeerID
}

func (c *Client) routeProxyEntryLess(a, b routeProxyEntry) bool {
	if a.prefix.Bits() != b.prefix.Bits() {
		return a.prefix.Bits() > b.prefix.Bits()
	}
	if a.version != b.version {
		return a.version > b.version
	}
	if c.routePathLess(a.path, b.path) {
		return true
	}
	if c.routePathLess(b.path, a.path) {
		return false
	}
	return a.peerID < b.peerID
}

func (c *Client) routePathFromNextHopLocked(fromPeerID, toPeerID uint32) (routePath, bool) {
	if fromPeerID == 0 || toPeerID == 0 {
		return routePath{}, false
	}
	if fromPeerID == toPeerID {
		return routePath{nextHopPeerID: fromPeerID, hops: 1}, true
	}
	bestByPeer := map[uint32]routePathItem{fromPeerID: {peerID: fromPeerID, hops: 1}}
	queue := []routePathItem{{peerID: fromPeerID, hops: 1}}
	var best routePath
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		if best.nextHopPeerID != 0 && cur.hops >= best.hops {
			continue
		}
		conn, ok := c.routeConns[cur.peerID]
		if !ok {
			continue
		}
		for nextPeerID := range conn.connectedPeerIDs {
			next := routePathItem{peerID: nextPeerID, hops: cur.hops + 1, cost: cur.cost + c.routeEdgeCostLocked(cur.peerID, nextPeerID)}
			if nextPeerID == toPeerID {
				candidate := routePath{nextHopPeerID: fromPeerID, hops: next.hops, cost: next.cost}
				if best.nextHopPeerID == 0 || c.routePathLess(candidate, best) {
					best = candidate
				}
				continue
			}
			if best.nextHopPeerID != 0 && next.hops >= best.hops {
				continue
			}
			if current, ok := bestByPeer[nextPeerID]; ok && !routeQueueItemLess(next, current) {
				continue
			}
			bestByPeer[nextPeerID] = next
			queue = append(queue, next)
		}
	}
	if best.nextHopPeerID == 0 {
		return routePath{}, false
	}
	return best, true
}

func routeQueueItemLess(a, b routePathItem) bool {
	if a.hops != b.hops {
		return a.hops < b.hops
	}
	if a.cost != b.cost {
		return a.cost < b.cost
	}
	return a.peerID < b.peerID
}

func (c *Client) routeEdgeCostLocked(fromPeerID, toPeerID uint32) int {
	cost := 1
	if info, ok := c.routePeers[toPeerID]; ok && info.Cost > 0 {
		cost = int(info.Cost)
	}
	if info, ok := c.routePeers[fromPeerID]; ok && info.FeatureFlags.AvoidRelayData {
		cost += 1_000_000
	}
	return cost
}

func (c *Client) currentRouteTableView() routeTableView {
	activePeerIDs := c.activeSessionPeerIDs()
	if len(activePeerIDs) == 0 {
		return routeTableView{}
	}
	c.routeMu.RLock()
	defer c.routeMu.RUnlock()
	return c.buildRouteTableViewLocked(activePeerIDs)
}

func (c *Client) buildRouteTableViewLocked(activePeerIDs []uint32) routeTableView {
	view := routeTableView{
		nextHopByPeer: make(map[uint32]routePath),
		ipv4PeerByIP:  make(map[netip.Addr]uint32),
		ipv6PeerByIP:  make(map[netip.Addr]uint32),
		proxyEntries:  make([]routeProxyEntry, 0, len(c.routePeers)),
	}
	peerIDs := make(map[uint32]struct{}, len(c.routePeers)+len(c.observedRoutes))
	for peerID := range c.routePeers {
		peerIDs[peerID] = struct{}{}
	}
	for _, observed := range c.observedRoutes {
		if !observed.seenAt.IsZero() {
			peerIDs[observed.peerID] = struct{}{}
		}
	}
	for peerID := range peerIDs {
		path, ok := c.bestRoutePathLocked(peerID, activePeerIDs)
		if !ok {
			continue
		}
		view.nextHopByPeer[peerID] = path
	}
	for peerID, info := range c.routePeers {
		path, ok := view.nextHopByPeer[peerID]
		if !ok {
			continue
		}
		if info.IPv4.IsValid() {
			if currentPeerID, ok := view.ipv4PeerByIP[info.IPv4]; !ok || c.routePeerCandidateBetterLocked(peerID, info.Version, path, currentPeerID, view.nextHopByPeer) {
				view.ipv4PeerByIP[info.IPv4] = peerID
			}
		}
		if info.IPv6.IsValid() {
			if currentPeerID, ok := view.ipv6PeerByIP[info.IPv6]; !ok || c.routePeerCandidateBetterLocked(peerID, info.Version, path, currentPeerID, view.nextHopByPeer) {
				view.ipv6PeerByIP[info.IPv6] = peerID
			}
		}
		for _, prefix := range info.ProxyCIDRs {
			view.proxyEntries = append(view.proxyEntries, routeProxyEntry{
				prefix:  prefix,
				peerID:  peerID,
				version: info.Version,
				path:    path,
			})
		}
	}
	now := time.Now()
	for addr, observed := range c.observedRoutes {
		if now.Sub(observed.seenAt) > observedRouteStaleAfter {
			continue
		}
		if _, ok := view.nextHopByPeer[observed.peerID]; !ok {
			continue
		}
		if addr.Is4() {
			if _, exists := view.ipv4PeerByIP[addr]; !exists {
				view.ipv4PeerByIP[addr] = observed.peerID
			}
		} else if addr.Is6() {
			if _, exists := view.ipv6PeerByIP[addr]; !exists {
				view.ipv6PeerByIP[addr] = observed.peerID
			}
		}
	}
	sort.Slice(view.proxyEntries, func(i, j int) bool {
		return c.routeProxyEntryLess(view.proxyEntries[i], view.proxyEntries[j])
	})
	return view
}

func (c *Client) routePeerCandidateBetterLocked(candidatePeerID uint32, candidateVersion uint32, candidatePath routePath, currentPeerID uint32, nextHopByPeer map[uint32]routePath) bool {
	currentInfo, ok := c.routePeers[currentPeerID]
	if !ok {
		return true
	}
	if candidateVersion > currentInfo.Version {
		return true
	}
	if candidatePeerID == currentPeerID {
		return false
	}
	currentPath, ok := nextHopByPeer[currentPeerID]
	if !ok {
		return true
	}
	return c.routePathLess(candidatePath, currentPath)
}

func (c *Client) observeDataRoute(packet *Packet) {
	if packet == nil || packet.Header.FromPeerID == 0 || packet.Header.FromPeerID == c.myPeerID {
		return
	}
	addr, ok := ipPacketSource(packet.Payload)
	if !ok || !addr.IsValid() {
		return
	}
	c.routeMu.Lock()
	defer c.routeMu.Unlock()
	if c.observedRoutes == nil {
		c.observedRoutes = make(map[netip.Addr]observedRoute)
	}
	c.observedRoutes[addr] = observedRoute{peerID: packet.Header.FromPeerID, seenAt: time.Now()}
	log.Debugln("[EasyTier] smart route observed src=%s peer=%d", addr, packet.Header.FromPeerID)
}

func ipPacketDestination(packet []byte) (netip.Addr, bool) {
	if len(packet) == 0 {
		return netip.Addr{}, false
	}
	switch packet[0] >> 4 {
	case 4:
		if len(packet) < 20 {
			return netip.Addr{}, false
		}
		var addr [4]byte
		copy(addr[:], packet[16:20])
		return netip.AddrFrom4(addr), true
	case 6:
		if len(packet) < 40 {
			return netip.Addr{}, false
		}
		var addr [16]byte
		copy(addr[:], packet[24:40])
		return netip.AddrFrom16(addr), true
	default:
		return netip.Addr{}, false
	}
}

func ipPacketSource(packet []byte) (netip.Addr, bool) {
	if len(packet) == 0 {
		return netip.Addr{}, false
	}
	switch packet[0] >> 4 {
	case 4:
		if len(packet) < 20 {
			return netip.Addr{}, false
		}
		var addr [4]byte
		copy(addr[:], packet[12:16])
		return netip.AddrFrom4(addr), true
	case 6:
		if len(packet) < 40 {
			return netip.Addr{}, false
		}
		var addr [16]byte
		copy(addr[:], packet[8:24])
		return netip.AddrFrom16(addr), true
	default:
		return netip.Addr{}, false
	}
}

func (c *Client) sendPacket(packet *Packet) error {
	if packet.Header.PacketType != PacketTypeData {
		session, err := c.selectSessionForPacket(packet)
		if err != nil {
			return err
		}
		return c.sendPacketToSession(session, packet)
	}

	tried := make(map[uint32]struct{})
	for {
		session, err := c.selectDataSession(packet, tried)
		if err != nil {
			return err
		}
		if err = c.sendPacketToSession(session, packet); err == nil {
			return nil
		}
		tried[session.peerID] = struct{}{}
		c.handleSessionError(session, err)
	}
}

func (c *Client) sendPacketWithRetry(ctx context.Context, packet *Packet) error {
	for {
		if packet.Header.PacketType == PacketTypeData && !packet.Header.IsEncrypted() {
			packet.Header.ToPeerID = c.destinationPeerID(packet.Payload)
		}
		err := c.sendPacket(packet)
		if err == nil {
			return nil
		}
		if !errors.Is(err, ErrNoActivePeerSessions) {
			return err
		}
		if err = c.waitForActiveSession(ctx); err != nil {
			return err
		}
	}
}

func (c *Client) sendPacketToSession(session *peerSession, packet *Packet) error {
	if err := c.preparePacket(packet); err != nil {
		return err
	}
	return c.writePacketToSession(session, packet)
}

func (c *Client) preparePacket(packet *Packet) error {
	if packet.Header.PacketType == PacketTypeData {
		packet.Header.SetLatencyFirst(c.options.LatencyFirst)
	}
	if !c.options.DisableEncryption && shouldEncrypt(packet.Header.PacketType) {
		if err := packet.EncryptAES128GCM(c.key128); err != nil {
			return err
		}
	}
	return nil
}

func (c *Client) writePacket(packet *Packet) error {
	session, err := c.selectSessionForPacket(packet)
	if err != nil {
		return err
	}
	return c.sendPacketToSession(session, packet)
}

func (c *Client) writePacketToSession(session *peerSession, packet *Packet) error {
	session.writeMu.Lock()
	defer session.writeMu.Unlock()
	return session.transport.WritePacket(packet)
}

func (c *Client) selectSessionForPacket(packet *Packet) (*peerSession, error) {
	if packet.Header.PacketType == PacketTypeData {
		return c.selectDataSession(packet, nil)
	}
	if packet.Header.ToPeerID != 0 {
		if session := c.sessionForPeer(packet.Header.ToPeerID); session != nil {
			return session, nil
		}
	}
	sessions := c.activeSessions()
	if len(sessions) == 0 {
		return nil, ErrNoActivePeerSessions
	}
	return sessions[0], nil
}

func (c *Client) selectDataSession(packet *Packet, exclude map[uint32]struct{}) (*peerSession, error) {
	if packet.Header.ToPeerID != 0 {
		if session := c.sessionForPeer(packet.Header.ToPeerID); session != nil && !isExcludedPeer(exclude, session.peerID) {
			log.Debugln("[EasyTier] smart route next-hop destination-peer=%d session=%d reason=direct-session latency-first=%t", packet.Header.ToPeerID, session.peerID, c.options.LatencyFirst)
			return session, nil
		}
		if relayPeerID, ok := c.routeRelayPeerID(packet.Header.ToPeerID); ok {
			if session := c.sessionForPeer(relayPeerID); session != nil && !isExcludedPeer(exclude, session.peerID) {
				log.Debugln("[EasyTier] smart route next-hop destination-peer=%d session=%d reason=relay latency-first=%t", packet.Header.ToPeerID, session.peerID, c.options.LatencyFirst)
				return session, nil
			}
		}
	}

	sessions := c.activeSessions()
	if len(sessions) == 0 {
		return nil, ErrNoActivePeerSessions
	}
	sessions = filterSessions(sessions, exclude)
	if len(sessions) == 0 {
		return nil, ErrNoActivePeerSessions
	}
	if addr, ok := ipPacketDestination(packet.Payload); ok && addr.IsValid() {
		if c.options.LatencyFirst && hasMeasuredLatency(sessions) {
			session := lowestLatencySession(sessions)
			if session == nil {
				return nil, ErrNoActivePeerSessions
			}
			log.Debugln("[EasyTier] smart route next-hop dst=%s session=%d reason=latency-first latency=%s", addr, session.peerID, sessionLatencyForLog(session))
			return session, nil
		}
		session := sessions[hashAddr(addr)%len(sessions)]
		if session == nil {
			return nil, ErrNoActivePeerSessions
		}
		log.Debugln("[EasyTier] smart route next-hop dst=%s session=%d reason=hash latency-first=%t", addr, session.peerID, c.options.LatencyFirst)
		return session, nil
	}
	session := lowestLatencySession(sessions)
	if session == nil {
		return nil, ErrNoActivePeerSessions
	}
	log.Debugln("[EasyTier] smart route next-hop session=%d reason=lowest-latency-no-ip latency=%s latency-first=%t", session.peerID, sessionLatencyForLog(session), c.options.LatencyFirst)
	return session, nil
}

func (c *Client) routeRelayPeerID(peerID uint32) (uint32, bool) {
	view := c.currentRouteTableView()
	path, ok := view.nextHopByPeer[peerID]
	if !ok {
		return 0, false
	}
	if c.sessionForPeer(path.nextHopPeerID) == nil {
		return 0, false
	}
	log.Debugln("[EasyTier] smart route relay target=%d next-hop=%d hops=%d cost=%d latency-first=%t", peerID, path.nextHopPeerID, path.hops, path.cost, c.options.LatencyFirst)
	return path.nextHopPeerID, true
}

func (c *Client) defaultPeerID(addr netip.Addr) uint32 {
	sessions := c.activeSessions()
	if len(sessions) == 0 {
		return 0
	}
	if c.options.LatencyFirst {
		session := lowestLatencySession(sessions)
		if session == nil {
			return 0
		}
		if addr.IsValid() {
			log.Debugln("[EasyTier] smart route fallback dst=%s peer=%d reason=latency-first latency=%s", addr, session.peerID, sessionLatencyForLog(session))
		} else {
			log.Debugln("[EasyTier] smart route fallback peer=%d reason=latency-first latency=%s", session.peerID, sessionLatencyForLog(session))
		}
		return session.peerID
	}
	if addr.IsValid() {
		session := sessions[hashAddr(addr)%len(sessions)]
		if session == nil {
			return 0
		}
		log.Debugln("[EasyTier] smart route fallback dst=%s peer=%d reason=hash", addr, session.peerID)
		return session.peerID
	}
	session := lowestLatencySession(sessions)
	if session == nil {
		return 0
	}
	log.Debugln("[EasyTier] smart route fallback peer=%d reason=lowest-latency-no-ip latency=%s", session.peerID, sessionLatencyForLog(session))
	return session.peerID
}

func (c *Client) addSession(session *peerSession) bool {
	c.sessionsMu.Lock()
	defer c.sessionsMu.Unlock()
	if c.sessions == nil {
		c.sessions = make(map[uint32]*peerSession)
	}
	if _, exists := c.sessions[session.peerID]; exists {
		return false
	}
	c.sessions[session.peerID] = session
	c.connVersion++
	return true
}

func (c *Client) removeSession(session *peerSession) int {
	c.sessionsMu.Lock()
	remaining := len(c.sessions)
	if current, ok := c.sessions[session.peerID]; ok && current == session {
		delete(c.sessions, session.peerID)
		c.connVersion++
		remaining = len(c.sessions)
	}
	c.sessionsMu.Unlock()
	c.pruneRoutesByRelayPeerID(session.peerID)
	c.resetReconnectState(session.endpoint)
	_ = session.transport.Close()
	log.Infoln("[EasyTier] session disconnected peer=%d remaining=%d", session.peerID, remaining)
	return remaining
}

func (c *Client) handleSessionError(session *peerSession, err error) {
	if session == nil {
		c.closeWithError(err)
		return
	}
	_ = c.removeSession(session)
}

func (c *Client) sessionForPeer(peerID uint32) *peerSession {
	c.sessionsMu.RLock()
	defer c.sessionsMu.RUnlock()
	return c.sessions[peerID]
}

func (c *Client) activeSessions() []*peerSession {
	c.sessionsMu.RLock()
	defer c.sessionsMu.RUnlock()
	sessions := make([]*peerSession, 0, len(c.sessions))
	for _, session := range c.sessions {
		sessions = append(sessions, session)
	}
	sort.Slice(sessions, func(i, j int) bool {
		return sessions[i].peerID < sessions[j].peerID
	})
	return sessions
}

func (c *Client) activeSessionPeerIDs() []uint32 {
	c.sessionsMu.RLock()
	defer c.sessionsMu.RUnlock()
	peerIDs := make([]uint32, 0, len(c.sessions))
	for peerID := range c.sessions {
		peerIDs = append(peerIDs, peerID)
	}
	sort.Slice(peerIDs, func(i, j int) bool {
		return peerIDs[i] < peerIDs[j]
	})
	return peerIDs
}

func (c *Client) sessionsForPeers(peerIDs []uint32) []*peerSession {
	c.sessionsMu.RLock()
	defer c.sessionsMu.RUnlock()
	sessions := make([]*peerSession, 0, len(peerIDs))
	for _, peerID := range peerIDs {
		if session := c.sessions[peerID]; session != nil {
			sessions = append(sessions, session)
		}
	}
	return sessions
}

func (c *Client) pingSessions() {
	now := time.Now()
	sessions := c.activeSessions()
	for _, session := range sessions {
		if session.needsPing(now) {
			_ = c.sendPacketToSession(session, NewPacket(c.myPeerID, session.peerID, PacketTypePing, session.startPing(now)))
		}
		session.prunePings(now)
	}
	if len(sessions) > 0 {
		c.pruneStaleRoutes(now)
	}
}

func (c *Client) pruneStaleRoutes(now time.Time) {
	c.routeMu.Lock()
	defer c.routeMu.Unlock()
	for relayPeerID, snapshot := range c.routes {
		if now.Sub(snapshot.updatedAt) > routeStaleAfter {
			delete(c.routes, relayPeerID)
		}
	}
	for peerID, snapshot := range c.routeConns {
		if now.Sub(snapshot.updatedAt) > routeStaleAfter {
			delete(c.routeConns, peerID)
		}
	}
	for addr, observed := range c.observedRoutes {
		if now.Sub(observed.seenAt) > observedRouteStaleAfter {
			delete(c.observedRoutes, addr)
		}
	}
}

func (c *Client) routePeerInfoSnapshot(remotePeerID uint32) []routePeerInfo {
	c.routeMu.RLock()
	defer c.routeMu.RUnlock()
	infos := make([]routePeerInfo, 0, len(c.routePeers))
	for peerID, info := range c.routePeers {
		if peerID == 0 || peerID == c.myPeerID || peerID == remotePeerID || info.Version == 0 {
			continue
		}
		info = cloneRoutePeerInfo(info)
		if len(info.Raw) == 0 {
			if raw := c.rawRoutePeerInfos[peerID]; len(raw) > 0 {
				info.Raw = append([]byte(nil), raw...)
			}
		}
		infos = append(infos, info)
	}
	sort.Slice(infos, func(i, j int) bool {
		return infos[i].PeerID < infos[j].PeerID
	})
	return infos
}

func (c *Client) routeConnInfoSnapshot(remotePeerID uint32) []routeConnInfo {
	c.sessionsMu.RLock()
	connected := make([]uint32, 0, len(c.sessions))
	connVersion := c.connVersion
	if connVersion == 0 {
		connVersion = 1
	}
	for peerID := range c.sessions {
		if peerID != 0 {
			connected = append(connected, peerID)
		}
	}
	c.sessionsMu.RUnlock()
	sort.Slice(connected, func(i, j int) bool { return connected[i] < connected[j] })
	infos := []routeConnInfo{{
		PeerID:           c.myPeerID,
		ConnectedPeerIDs: connected,
		Version:          connVersion,
	}}

	c.routeMu.RLock()
	defer c.routeMu.RUnlock()
	for peerID, conn := range c.routeConns {
		if peerID == 0 || peerID == c.myPeerID || peerID == remotePeerID || conn.version == 0 {
			continue
		}
		if !c.routePeerReachableLocked(peerID, connected) {
			continue
		}
		connectedPeerIDs := make([]uint32, 0, len(conn.connectedPeerIDs))
		for connectedPeerID := range conn.connectedPeerIDs {
			connectedPeerIDs = append(connectedPeerIDs, connectedPeerID)
		}
		sort.Slice(connectedPeerIDs, func(i, j int) bool { return connectedPeerIDs[i] < connectedPeerIDs[j] })
		infos = append(infos, routeConnInfo{
			PeerID:           peerID,
			ConnectedPeerIDs: connectedPeerIDs,
			Version:          conn.version,
		})
	}
	sort.Slice(infos, func(i, j int) bool {
		return infos[i].PeerID < infos[j].PeerID
	})
	return infos
}

func (c *Client) missingPeerEndpoints(now time.Time) []peerEndpoint {
	peerEndpoints := c.currentPeerEndpoints()
	c.sessionsMu.RLock()
	active := make(map[string]struct{}, len(c.sessions))
	for _, session := range c.sessions {
		active[peerEndpointKey(session.endpoint)] = struct{}{}
	}
	c.sessionsMu.RUnlock()

	missing := make([]peerEndpoint, 0, len(peerEndpoints))
	for _, endpoint := range peerEndpoints {
		if _, ok := active[peerEndpointKey(endpoint)]; ok {
			continue
		}
		if !c.shouldAttemptReconnect(endpoint, now) {
			continue
		}
		missing = append(missing, endpoint)
	}
	return missing
}

func (c *Client) shouldAttemptReconnect(endpoint peerEndpoint, now time.Time) bool {
	c.reconnectMu.Lock()
	defer c.reconnectMu.Unlock()
	state, ok := c.reconnect[peerEndpointKey(endpoint)]
	return !ok || !now.Before(state.nextAttempt)
}

func (c *Client) recordReconnectFailure(endpoint peerEndpoint, now time.Time) {
	c.reconnectMu.Lock()
	defer c.reconnectMu.Unlock()
	key := peerEndpointKey(endpoint)
	state := c.reconnect[key]
	state.failures++
	state.nextAttempt = now.Add(reconnectDelayForFailures(state.failures, randomUint64()))
	c.reconnect[key] = state
}

func (c *Client) clearReconnectState(endpoint peerEndpoint) {
	c.reconnectMu.Lock()
	defer c.reconnectMu.Unlock()
	delete(c.reconnect, peerEndpointKey(endpoint))
}

func (c *Client) resetReconnectState(endpoint peerEndpoint) {
	c.reconnectMu.Lock()
	defer c.reconnectMu.Unlock()
	delete(c.reconnect, peerEndpointKey(endpoint))
}

func (c *Client) waitForActiveSession(ctx context.Context) error {
	for {
		if len(c.activeSessions()) > 0 {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(waitForSessionInterval):
		}
	}
}

func (c *Client) pruneRoutesByRelayPeerID(peerID uint32) {
	c.routeMu.Lock()
	defer c.routeMu.Unlock()
	if len(c.routes) == 0 {
		return
	}
	delete(c.routes, peerID)
}

func (c *Client) drainSessions() []*peerSession {
	c.sessionsMu.Lock()
	defer c.sessionsMu.Unlock()
	sessions := make([]*peerSession, 0, len(c.sessions))
	for _, session := range c.sessions {
		sessions = append(sessions, session)
	}
	c.sessions = nil
	return sessions
}

func (c *Client) closeWithError(err error) {
	c.closeMu.Lock()
	closeFn := c.closeFn
	c.closeMu.Unlock()
	if closeFn == nil {
		return
	}

	closeFn.Do(func() {
		c.startMu.Lock()
		c.started = false
		c.startMu.Unlock()

		c.closeMu.Lock()
		if err != nil && c.err == nil {
			c.err = err
		}
		c.closeMu.Unlock()
		if c.cancel != nil {
			c.cancel()
		}
		for _, session := range c.drainSessions() {
			_ = session.transport.Close()
		}
		c.setPeerEndpoints(nil)
		c.reconnectMu.Lock()
		c.reconnect = nil
		c.reconnectMu.Unlock()
		c.routeMu.Lock()
		c.routes = nil
		c.routePeers = nil
		c.rawRoutePeerInfos = nil
		c.routeConns = nil
		c.observedRoutes = nil
		c.routeMu.Unlock()
		if c.device != nil {
			_ = c.device.Close()
		}
		c.closeL3Conns()
		if c.done != nil {
			close(c.done)
		}
	})
}

func (c *Client) networkName() string {
	if strings.TrimSpace(c.options.NetworkName) == "" {
		return "default"
	}
	return c.options.NetworkName
}

func routeAddrForLog(addr netip.Addr) string {
	if !addr.IsValid() {
		return "-"
	}
	return addr.String()
}

func sessionLatencyForLog(session *peerSession) string {
	if session == nil {
		return "unknown"
	}
	latency, ok := session.currentLatency(time.Now())
	if !ok {
		return "unknown"
	}
	return latency.String()
}

func (c *Client) localPrefixes() ([]netip.Prefix, error) {
	var prefixes []netip.Prefix
	if c.options.IPv4 != "" {
		prefix, err := parsePrefix(c.options.IPv4, 24)
		if err != nil {
			return nil, fmt.Errorf("parse easytier ipv4: %w", err)
		}
		prefixes = append(prefixes, prefix)
	}
	if c.options.IPv6 != "" {
		prefix, err := parsePrefix(c.options.IPv6, 128)
		if err != nil {
			return nil, fmt.Errorf("parse easytier ipv6: %w", err)
		}
		prefixes = append(prefixes, prefix)
	}
	if len(prefixes) == 0 {
		return nil, errors.New("easytier requires ipv4 or ipv6")
	}
	return prefixes, nil
}

func (c *Client) setPeerEndpoints(peerEndpoints []peerEndpoint) {
	c.peerMu.Lock()
	defer c.peerMu.Unlock()
	if len(peerEndpoints) == 0 {
		c.peerEndpoints = nil
		return
	}
	c.peerEndpoints = append(c.peerEndpoints[:0], peerEndpoints...)
}

func (c *Client) currentPeerEndpoints() []peerEndpoint {
	c.peerMu.RLock()
	defer c.peerMu.RUnlock()
	return append([]peerEndpoint(nil), c.peerEndpoints...)
}

func (c *Client) isPeerEndpointConfigured(endpoint peerEndpoint) bool {
	key := peerEndpointKey(endpoint)
	c.peerMu.RLock()
	defer c.peerMu.RUnlock()
	for _, configured := range c.peerEndpoints {
		if peerEndpointKey(configured) == key {
			return true
		}
	}
	return false
}

func (c *Client) removeUnconfiguredSessions(peerEndpoints []peerEndpoint) {
	allowed := make(map[string]struct{}, len(peerEndpoints))
	for _, endpoint := range peerEndpoints {
		allowed[peerEndpointKey(endpoint)] = struct{}{}
	}
	for _, session := range c.activeSessions() {
		if _, ok := allowed[peerEndpointKey(session.endpoint)]; ok {
			continue
		}
		c.removeSession(session)
	}
}

func (c *Client) pruneReconnectStates(peerEndpoints []peerEndpoint) {
	allowed := make(map[string]struct{}, len(peerEndpoints))
	for _, endpoint := range peerEndpoints {
		allowed[peerEndpointKey(endpoint)] = struct{}{}
	}
	c.reconnectMu.Lock()
	defer c.reconnectMu.Unlock()
	for key := range c.reconnect {
		if _, ok := allowed[key]; ok {
			continue
		}
		delete(c.reconnect, key)
	}
}

func (c *Client) ipv4Prefix() (netip.Prefix, bool, error) {
	if c.options.IPv4 == "" {
		return netip.Prefix{}, false, nil
	}
	prefix, err := parsePrefix(c.options.IPv4, 24)
	if err != nil {
		return netip.Prefix{}, false, err
	}
	return prefix, true, nil
}

func parsePrefix(value string, bits int) (netip.Prefix, error) {
	if !strings.Contains(value, "/") {
		value = fmt.Sprintf("%s/%d", value, bits)
	}
	return netip.ParsePrefix(value)
}

func parsePeerEndpoints(peers []string) ([]peerEndpoint, error) {
	endpoints := make([]peerEndpoint, 0, len(peers))
	for _, peer := range peers {
		peer = strings.TrimSpace(peer)
		if peer == "" {
			continue
		}
		network, address, err := parsePeerAddress(peer)
		if err != nil {
			return nil, err
		}
		endpoints = append(endpoints, peerEndpoint{network: network, address: address})
	}
	if len(endpoints) == 0 {
		return nil, errors.New("easytier requires at least one peer")
	}
	return endpoints, nil
}

func parsePeerAddress(peer string) (string, string, error) {
	if !strings.Contains(peer, "://") {
		peer = "tcp://" + peer
	}
	u, err := url.Parse(peer)
	if err != nil {
		return "", "", err
	}
	if u.Scheme != "tcp" && u.Scheme != "udp" {
		return "", "", fmt.Errorf("unsupported easytier peer scheme %q", u.Scheme)
	}
	host := u.Hostname()
	if host == "" {
		return "", "", fmt.Errorf("invalid easytier peer %q", peer)
	}
	port := u.Port()
	if port == "" {
		port = DefaultTCPPort
	}
	return u.Scheme, net.JoinHostPort(host, port), nil
}

func peerEndpointKey(endpoint peerEndpoint) string {
	return endpoint.network + "://" + endpoint.address
}

func peerStringsFromEndpoints(endpoints []peerEndpoint) []string {
	peers := make([]string, 0, len(endpoints))
	for _, endpoint := range endpoints {
		peers = append(peers, peerEndpointKey(endpoint))
	}
	return peers
}

func isExcludedPeer(exclude map[uint32]struct{}, peerID uint32) bool {
	if len(exclude) == 0 {
		return false
	}
	_, ok := exclude[peerID]
	return ok
}

func filterSessions(sessions []*peerSession, exclude map[uint32]struct{}) []*peerSession {
	if len(exclude) == 0 {
		return sessions
	}
	filtered := make([]*peerSession, 0, len(sessions))
	for _, session := range sessions {
		if isExcludedPeer(exclude, session.peerID) {
			continue
		}
		filtered = append(filtered, session)
	}
	return filtered
}

func mergeRoutePeerInfo(current, next routePeerInfo) routePeerInfo {
	if !next.IPv4.IsValid() {
		next.IPv4 = current.IPv4
	}
	if !next.IPv6.IsValid() {
		next.IPv6 = current.IPv6
	}
	if next.NetworkLength == 0 {
		next.NetworkLength = current.NetworkLength
	}
	if len(next.ProxyCIDRs) == 0 {
		next.ProxyCIDRs = append([]netip.Prefix(nil), current.ProxyCIDRs...)
	}
	if next.Hostname == "" {
		next.Hostname = current.Hostname
	}
	if next.UDPNATType == 0 {
		next.UDPNATType = current.UDPNATType
	}
	if next.TCPNATType == 0 {
		next.TCPNATType = current.TCPNATType
	}
	if !hasPeerFeatureFlags(next.FeatureFlags) {
		next.FeatureFlags = current.FeatureFlags
	}
	if next.PeerRouteID == 0 {
		next.PeerRouteID = current.PeerRouteID
	}
	if next.Version == 0 && current.Version > 0 {
		next.Version = current.Version
	}
	if len(next.Raw) == 0 {
		next.Raw = append([]byte(nil), current.Raw...)
	}
	return next
}

func cloneRoutePeerInfo(info routePeerInfo) routePeerInfo {
	if len(info.ProxyCIDRs) > 0 {
		info.ProxyCIDRs = append([]netip.Prefix(nil), info.ProxyCIDRs...)
	}
	if len(info.Raw) > 0 {
		info.Raw = append([]byte(nil), info.Raw...)
	}
	return info
}

func lowestLatencySession(sessions []*peerSession) *peerSession {
	if len(sessions) == 0 {
		return nil
	}
	best := sessions[0]
	for _, session := range sessions[1:] {
		if sessionLatencyRank(session) < sessionLatencyRank(best) {
			best = session
		}
	}
	return best
}

func hasMeasuredLatency(sessions []*peerSession) bool {
	now := time.Now()
	for _, session := range sessions {
		if _, ok := session.currentLatency(now); ok {
			return true
		}
	}
	return false
}

func sessionLatencyRank(session *peerSession) time.Duration {
	if session == nil {
		return time.Duration(1<<63 - 1)
	}
	latency, ok := session.currentLatency(time.Now())
	if !ok {
		return time.Duration(1<<63 - 1)
	}
	return latency
}

func (c *Client) sessionLatencyByPeerID(peerID uint32) (time.Duration, bool) {
	session := c.sessionForPeer(peerID)
	if session == nil {
		return 0, false
	}
	return session.currentLatency(time.Now())
}

func hashAddr(addr netip.Addr) int {
	b := addr.AsSlice()
	var h uint32 = 2166136261
	for _, v := range b {
		h ^= uint32(v)
		h *= 16777619
	}
	return int(h)
}

func randomPeerID() uint32 {
	var b [4]byte
	for {
		if _, err := rand.Read(b[:]); err != nil {
			return uint32(time.Now().UnixNano())
		}
		id := binary.LittleEndian.Uint32(b[:])
		if id != 0 {
			return id
		}
	}
}

func randomUint64() uint64 {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return uint64(time.Now().UnixNano())
	}
	return binary.LittleEndian.Uint64(b[:])
}

func randomInstanceID() [4]uint32 {
	var ret [4]uint32
	for i := range ret {
		ret[i] = uint32(randomUint64())
	}
	return ret
}

func shouldEncrypt(packetType PacketType) bool {
	switch packetType {
	case PacketTypeData, PacketTypeRPCReq, PacketTypeRPCResp:
		return true
	default:
		return false
	}
}

func (s *peerSession) startPing(now time.Time) []byte {
	s.pingMu.Lock()
	defer s.pingMu.Unlock()
	if s.pings == nil {
		s.pings = make(map[uint64]time.Time)
	}
	token := randomUint64()
	s.pings[token] = now
	payload := make([]byte, 8)
	binary.LittleEndian.PutUint64(payload, token)
	return payload
}

func (s *peerSession) observePong(payload []byte, now time.Time) {
	if len(payload) != 8 {
		return
	}
	token := binary.LittleEndian.Uint64(payload)
	s.pingMu.Lock()
	defer s.pingMu.Unlock()
	startedAt, ok := s.pings[token]
	if !ok {
		return
	}
	delete(s.pings, token)
	s.latency = now.Sub(startedAt)
	s.latencyAt = now
	log.Debugln("[EasyTier] session latency peer=%d rtt=%s", s.peerID, s.latency)
}

func (s *peerSession) prunePings(now time.Time) {
	s.pingMu.Lock()
	defer s.pingMu.Unlock()
	for token, startedAt := range s.pings {
		if now.Sub(startedAt) > sessionPingTimeout {
			delete(s.pings, token)
		}
	}
}

func (s *peerSession) needsPing(now time.Time) bool {
	s.pingMu.Lock()
	defer s.pingMu.Unlock()
	if len(s.pings) > 0 {
		return false
	}
	return s.latencyAt.IsZero() || now.Sub(s.latencyAt) >= sessionPingInterval
}

func (s *peerSession) currentLatency(now time.Time) (time.Duration, bool) {
	s.pingMu.Lock()
	defer s.pingMu.Unlock()
	if s.latencyAt.IsZero() || now.Sub(s.latencyAt) > sessionPingTimeout {
		return 0, false
	}
	return s.latency, true
}
