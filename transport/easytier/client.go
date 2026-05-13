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
	"strings"
	"sync"
	"time"

	stackdevice "github.com/metacubex/sing-wireguard"
	M "github.com/metacubex/sing/common/metadata"
)

type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

type Options struct {
	Peers             []string
	IPv4              string
	IPv6              string
	NetworkName       string
	NetworkSecret     string
	MTU               int
	DisableEncryption bool
	// ManualRoutes is accepted for config parity with EasyTier, but mihomo rules
	// decide which traffic enters this outbound.
	ManualRoutes []string
}

type Client struct {
	options Options
	dialer  Dialer

	startMu sync.Mutex
	started bool

	myPeerID       uint32
	remotePeerID   uint32
	routeSessionID uint64
	peerRouteID    uint64
	instanceID     [4]uint32
	digest         [32]byte
	key128         [16]byte

	conn    net.Conn
	device  stackdevice.Device
	cancel  context.CancelFunc
	done    chan struct{}
	closeMu sync.Mutex
	closeFn *sync.Once
	err     error

	writeMu sync.Mutex
	routeMu sync.RWMutex
	routes  map[uint32]routePeerInfo
	l3Mu    sync.RWMutex
	l3Conns map[*L3PacketConn]struct{}
}

func NewClient(options Options, dialer Dialer) *Client {
	if dialer == nil {
		dialer = &net.Dialer{}
	}
	return &Client{options: options, dialer: dialer}
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

	peerNetwork, peerAddress, err := firstPeerAddress(c.options.Peers)
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

	conn, err := c.dialer.DialContext(ctx, peerNetwork, peerAddress)
	if err != nil {
		_ = device.Close()
		return err
	}
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		_ = tcpConn.SetNoDelay(true)
	}

	c.myPeerID = randomPeerID()
	c.routeSessionID = randomUint64()
	c.peerRouteID = randomUint64()
	c.instanceID = randomInstanceID()
	c.digest = NetworkSecretDigest(c.networkName(), c.options.NetworkSecret)
	c.key128 = NetworkSecretKey128(c.options.NetworkSecret)
	c.conn = conn
	c.device = device
	c.done = make(chan struct{})
	c.closeFn = &sync.Once{}

	if err = c.doHandshake(ctx); err != nil {
		_ = conn.Close()
		_ = device.Close()
		return err
	}
	if err = c.sendRouteSync(); err != nil {
		_ = conn.Close()
		_ = device.Close()
		return err
	}

	runCtx, cancel := context.WithCancel(context.Background())
	c.cancel = cancel
	c.started = true
	go c.readLoop(runCtx)
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

func (c *Client) doHandshake(ctx context.Context) error {
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(5 * time.Second)
	}
	_ = c.conn.SetDeadline(deadline)
	defer c.conn.SetDeadline(time.Time{})

	req := NewHandshakeRequest(c.myPeerID, c.networkName(), c.digest)
	packet := NewPacket(c.myPeerID, 0, PacketTypeHandshake, req.Marshal())
	if err := c.writePacket(packet); err != nil {
		return err
	}

	for {
		packet, err := ReadTCPPacket(c.conn, 64*1024)
		if err != nil {
			return err
		}
		switch packet.Header.PacketType {
		case PacketTypeHandshake:
			rsp, err := ParseHandshakeRequest(packet.Payload)
			if err != nil {
				return err
			}
			if err = ValidateHandshakeResponse(rsp, c.networkName(), c.digest); err != nil {
				return err
			}
			if rsp.MyPeerID == c.myPeerID {
				return errors.New("easytier peer id conflict")
			}
			c.remotePeerID = rsp.MyPeerID
			return nil
		case PacketTypeNoiseHandshake1, PacketTypeNoiseHandshake2, PacketTypeNoiseHandshake3:
			return ErrUnsupportedSecureMode
		}
	}
}

func (c *Client) readLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		packet, err := ReadTCPPacket(c.conn, 64*1024)
		if err != nil {
			c.closeWithError(err)
			return
		}
		if err = c.handlePeerPacket(packet); err != nil {
			c.closeWithError(err)
			return
		}
	}
}

func (c *Client) handlePeerPacket(packet *Packet) error {
	if packet.Header.IsEncrypted() {
		if err := packet.DecryptAES128GCM(c.key128); err != nil {
			return err
		}
	}

	switch packet.Header.PacketType {
	case PacketTypePing:
		packet.Header.PacketType = PacketTypePong
		return c.writePacket(packet)
	case PacketTypePong:
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
		c.updateRoutes(syncInfo.PeerInfos)
		return c.sendPacket(buildRouteSyncResponsePacket(rpcReq, c.myPeerID, packet.Header.FromPeerID, c.routeSessionID))
	case PacketTypeRPCResp:
		return nil
	case PacketTypeNoiseHandshake1, PacketTypeNoiseHandshake2, PacketTypeNoiseHandshake3:
		return ErrUnsupportedSecureMode
	case PacketTypeData:
		if packet.Header.ToPeerID != c.myPeerID {
			return nil
		}
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
		if err = c.sendPacket(packet); err != nil {
			c.closeWithError(err)
			return
		}
	}
}

func (c *Client) routeLoop(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := c.sendRouteSync(); err != nil {
				c.closeWithError(err)
				return
			}
		}
	}
}

func (c *Client) sendRouteSync() error {
	config, ok, err := c.routeRPCConfig()
	if err != nil || !ok {
		return err
	}
	packet, err := buildRouteSyncRequestPacket(config)
	if err != nil {
		return err
	}
	return c.sendPacket(packet)
}

func (c *Client) routeRPCConfig() (routeRPCConfig, bool, error) {
	ipv4, ok, err := c.ipv4Prefix()
	if err != nil || !ok {
		return routeRPCConfig{}, ok, err
	}
	return routeRPCConfig{
		MyPeerID:     c.myPeerID,
		RemotePeerID: c.remotePeerID,
		NetworkName:  c.networkName(),
		IPv4:         ipv4,
		Hostname:     "mihomo",
		SessionID:    c.routeSessionID,
		PeerRouteID:  c.peerRouteID,
		InstanceID:   c.instanceID,
		Transaction:  int64(randomUint64() & (1<<63 - 1)),
	}, true, nil
}

func (c *Client) updateRoutes(peerInfos []routePeerInfo) {
	if len(peerInfos) == 0 {
		return
	}
	c.routeMu.Lock()
	defer c.routeMu.Unlock()
	if c.routes == nil {
		c.routes = make(map[uint32]routePeerInfo, len(peerInfos))
	}
	for _, info := range peerInfos {
		if info.PeerID == 0 {
			continue
		}
		c.routes[info.PeerID] = info
	}
}

func (c *Client) destinationPeerID(payload []byte) uint32 {
	addr, ok := ipPacketDestination(payload)
	if !ok {
		return c.remotePeerID
	}
	if peerID, ok := c.lookupRoutePeer(addr); ok {
		return peerID
	}
	return c.remotePeerID
}

func (c *Client) lookupRoutePeer(addr netip.Addr) (uint32, bool) {
	c.routeMu.RLock()
	defer c.routeMu.RUnlock()

	var bestPeerID uint32
	bestBits := -1
	for peerID, info := range c.routes {
		if peerID == c.myPeerID {
			continue
		}
		if addr.Is4() && info.IPv4.IsValid() && addr == info.IPv4 {
			return peerID, true
		}
		for _, prefix := range info.ProxyCIDRs {
			if prefix.Contains(addr) && prefix.Bits() > bestBits {
				bestPeerID = peerID
				bestBits = prefix.Bits()
			}
		}
	}
	if bestPeerID != 0 {
		return bestPeerID, true
	}
	return 0, false
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

func (c *Client) sendPacket(packet *Packet) error {
	if !c.options.DisableEncryption && shouldEncrypt(packet.Header.PacketType) {
		if err := packet.EncryptAES128GCM(c.key128); err != nil {
			return err
		}
	}
	return c.writePacket(packet)
}

func (c *Client) writePacket(packet *Packet) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return packet.WriteTo(c.conn)
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
		if c.conn != nil {
			_ = c.conn.Close()
		}
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

func firstPeerAddress(peers []string) (string, string, error) {
	for _, peer := range peers {
		peer = strings.TrimSpace(peer)
		if peer == "" {
			continue
		}
		return parsePeerAddress(peer)
	}
	return "", "", errors.New("easytier requires at least one peer")
}

func parsePeerAddress(peer string) (string, string, error) {
	if !strings.Contains(peer, "://") {
		peer = "tcp://" + peer
	}
	u, err := url.Parse(peer)
	if err != nil {
		return "", "", err
	}
	if u.Scheme != "tcp" {
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
	return "tcp", net.JoinHostPort(host, port), nil
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
