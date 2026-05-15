package easytier

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestNetworkSecretDigestMatchesEasyTierRust(t *testing.T) {
	digest := NetworkSecretDigest("example-net", "example-network-secret")
	want := "099397bbff4ffcbd1e5ea7e41dace0652390ef015b6fffecf0803e2fabd75a3d"
	if got := hex.EncodeToString(digest[:]); got != want {
		t.Fatalf("unexpected digest: got %s want %s", got, want)
	}

	key := NetworkSecretKey128("example-network-secret")
	wantKey := "c1bad39a44245f02340d6d012c1b327f"
	if got := hex.EncodeToString(key[:]); got != wantKey {
		t.Fatalf("unexpected key: got %s want %s", got, wantKey)
	}
}

func TestHandshakeRequestRoundTrip(t *testing.T) {
	digest := NetworkSecretDigest("example-net", "secret")
	want := NewHandshakeRequest(12345, "example-net", digest)
	want.Features = []string{"a", "b"}

	got, err := ParseHandshakeRequest(want.Marshal())
	if err != nil {
		t.Fatal(err)
	}
	if got.Magic != Magic || got.MyPeerID != want.MyPeerID || got.Version != Version || got.NetworkName != want.NetworkName {
		t.Fatalf("unexpected handshake: %#v", got)
	}
	if !bytes.Equal(got.NetworkSecretDigest, digest[:]) {
		t.Fatalf("unexpected digest: %x", got.NetworkSecretDigest)
	}
	if len(got.Features) != 2 || got.Features[0] != "a" || got.Features[1] != "b" {
		t.Fatalf("unexpected features: %#v", got.Features)
	}
}

func TestTCPPacketRoundTrip(t *testing.T) {
	packet := NewPacket(1, 2, PacketTypeData, []byte("payload"))
	packet.Header.SetLatencyFirst(true)
	encoded := packet.MarshalTCP()
	decoded, err := ReadTCPPacket(bytes.NewReader(encoded), 1024)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Header.FromPeerID != 1 || decoded.Header.ToPeerID != 2 || decoded.Header.PacketType != PacketTypeData {
		t.Fatalf("unexpected header: %#v", decoded.Header)
	}
	if !decoded.Header.IsLatencyFirst() {
		t.Fatal("packet should keep latency-first flag")
	}
	if !bytes.Equal(decoded.Payload, []byte("payload")) {
		t.Fatalf("unexpected payload: %q", decoded.Payload)
	}
}

func TestPacketBodyRoundTrip(t *testing.T) {
	packet := NewPacket(7, 8, PacketTypePing, []byte("payload"))
	decoded, err := ReadPacketBody(packet.MarshalBody(), 1024)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Header.FromPeerID != 7 || decoded.Header.ToPeerID != 8 || decoded.Header.PacketType != PacketTypePing {
		t.Fatalf("unexpected header: %#v", decoded.Header)
	}
	if !bytes.Equal(decoded.Payload, []byte("payload")) {
		t.Fatalf("unexpected payload: %q", decoded.Payload)
	}
}

func TestClientSendPacketSetsLatencyFirstForData(t *testing.T) {
	client := NewClient(Options{LatencyFirst: true, DisableEncryption: true}, nil)
	client.sessions = map[uint32]*peerSession{2: newDiscardSession(2)}
	packet := NewPacket(1, 2, PacketTypeData, []byte("payload"))
	if err := client.sendPacket(packet); err != nil {
		t.Fatal(err)
	}
	if !packet.Header.IsLatencyFirst() {
		t.Fatal("expected client to mark data packets as latency-first")
	}

	control := NewPacket(1, 2, PacketTypePing, nil)
	if err := client.sendPacket(control); err != nil {
		t.Fatal(err)
	}
	if control.Header.IsLatencyFirst() {
		t.Fatal("non-data packets should not carry latency-first")
	}
}

type discardConn struct{}

func (discardConn) Read([]byte) (int, error)         { return 0, nil }
func (discardConn) Write(b []byte) (int, error)      { return len(b), nil }
func (discardConn) Close() error                     { return nil }
func (discardConn) LocalAddr() net.Addr              { return nil }
func (discardConn) RemoteAddr() net.Addr             { return nil }
func (discardConn) SetDeadline(time.Time) error      { return nil }
func (discardConn) SetReadDeadline(time.Time) error  { return nil }
func (discardConn) SetWriteDeadline(time.Time) error { return nil }

func newDiscardSession(peerID uint32) *peerSession {
	return &peerSession{peerID: peerID, transport: &tcpPeerTransport{conn: discardConn{}}}
}

func newDiscardSessionWithEndpoint(peerID uint32, endpoint peerEndpoint) *peerSession {
	return &peerSession{peerID: peerID, endpoint: endpoint, transport: &tcpPeerTransport{conn: discardConn{}}}
}

func latencySession(peerID uint32, latency time.Duration) *peerSession {
	return &peerSession{
		peerID:    peerID,
		transport: &tcpPeerTransport{conn: discardConn{}},
		latency:   latency,
		latencyAt: time.Now(),
	}
}

func TestAESGCMEncryptDecrypt(t *testing.T) {
	key := NetworkSecretKey128("secret")
	packet := NewPacket(1, 2, PacketTypeData, []byte("payload"))
	if err := packet.EncryptAES128GCM(key); err != nil {
		t.Fatal(err)
	}
	if !packet.Header.IsEncrypted() {
		t.Fatal("packet should be marked encrypted")
	}
	if bytes.Equal(packet.Payload, []byte("payload")) {
		t.Fatal("payload should be encrypted")
	}
	if err := packet.DecryptAES128GCM(key); err != nil {
		t.Fatal(err)
	}
	if packet.Header.IsEncrypted() {
		t.Fatal("packet should be marked decrypted")
	}
	if !bytes.Equal(packet.Payload, []byte("payload")) {
		t.Fatalf("unexpected payload: %q", packet.Payload)
	}
}

func TestParsePeerAddressDefaultsToTCPPort(t *testing.T) {
	network, address, err := parsePeerAddress("peer.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if network != "tcp" || address != "peer.example.com:11010" {
		t.Fatalf("unexpected address: %s %s", network, address)
	}
}

func TestParsePeerAddressAcceptsUDP(t *testing.T) {
	network, address, err := parsePeerAddress("udp://peer.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if network != "udp" || address != "peer.example.com:11010" {
		t.Fatalf("unexpected address: %s %s", network, address)
	}
}

func TestIPv4PrefixDefaultsToEasyTier24(t *testing.T) {
	client := NewClient(Options{IPv4: "198.51.100.11"}, nil)
	prefix, ok, err := client.ipv4Prefix()
	if err != nil {
		t.Fatal(err)
	}
	if !ok || prefix.String() != "198.51.100.11/24" {
		t.Fatalf("unexpected prefix: %s", prefix)
	}
}

func TestRouteSyncRPCPacketRoundTrip(t *testing.T) {
	packet, err := buildRouteSyncRequestPacket(routeRPCConfig{
		MyPeerID:     11,
		RemotePeerID: 22,
		NetworkName:  "example-net",
		IPv4:         netip.MustParsePrefix("198.51.100.11/24"),
		Hostname:     "mihomo",
		SessionID:    33,
		PeerRouteID:  44,
		InstanceID:   [4]uint32{1, 2, 3, 4},
		ProxyCIDRs:   []string{"203.0.113.1/32"},
		Transaction:  55,
	})
	if err != nil {
		t.Fatal(err)
	}
	if packet.Header.PacketType != PacketTypeRPCReq {
		t.Fatalf("unexpected packet type: %d", packet.Header.PacketType)
	}
	rpcReq, err := parseRPCPacket(packet.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if !isRouteSyncRequest(rpcReq, "example-net") {
		t.Fatalf("unexpected rpc request: %#v", rpcReq)
	}
	if rpcReq.FromPeer != 11 || rpcReq.ToPeer != 22 || rpcReq.TransactionID != 55 {
		t.Fatalf("unexpected rpc ids: %#v", rpcReq)
	}
	syncInfo, err := parseRouteSyncRPCRequest(rpcReq)
	if err != nil {
		t.Fatal(err)
	}
	rawInfos, err := rawRoutePeerInfoPayloads(rpcReq)
	if err != nil {
		t.Fatal(err)
	}
	if len(rawInfos) != 1 {
		t.Fatalf("unexpected raw route info count: %d", len(rawInfos))
	}
	if syncInfo.MyPeerID != 11 || len(syncInfo.PeerInfos) != 1 {
		t.Fatalf("unexpected sync route info: %#v", syncInfo)
	}
	peerInfo := syncInfo.PeerInfos[0]
	peerInfo.Raw = rawInfos[0]
	if peerInfo.PeerID != 11 || peerInfo.IPv4.String() != "198.51.100.11" || peerInfo.NetworkLength != 24 {
		t.Fatalf("unexpected peer info: %#v", peerInfo)
	}
	if len(peerInfo.ProxyCIDRs) != 1 || peerInfo.ProxyCIDRs[0].String() != "203.0.113.1/32" {
		t.Fatalf("unexpected proxy cidrs: %#v", peerInfo.ProxyCIDRs)
	}
	if peerInfo.Hostname != "mihomo" {
		t.Fatalf("unexpected hostname: %q", peerInfo.Hostname)
	}
	if len(peerInfo.Raw) == 0 {
		t.Fatal("expected raw route peer info payload")
	}
}

func TestParseRoutePeerInfoParsesExtendedFields(t *testing.T) {
	featureFlags := appendProtoVarint(nil, 1, 1)
	featureFlags = appendProtoVarint(featureFlags, 8, 1)
	ipv6Addr := appendProtoVarint(nil, 1, 0x20010db8)
	ipv6Addr = appendProtoVarint(ipv6Addr, 2, 0)
	ipv6Addr = appendProtoVarint(ipv6Addr, 3, 0)
	ipv6Addr = appendProtoVarint(ipv6Addr, 4, 1)
	ipv6Inet := appendProtoBytes(nil, 1, ipv6Addr)
	payload := appendProtoVarint(nil, 1, 77)
	payload = appendProtoBytes(payload, 6, []byte("node-a"))
	payload = appendProtoVarint(payload, 7, 5)
	payload = appendProtoVarint(payload, 9, 9)
	payload = appendProtoBytes(payload, 11, featureFlags)
	payload = appendProtoVarint(payload, 12, 12345)
	payload = appendProtoBytes(payload, 15, ipv6Inet)
	payload = appendProtoVarint(payload, 17, 6)

	info, err := parseRoutePeerInfo(payload)
	if err != nil {
		t.Fatal(err)
	}
	if info.Hostname != "node-a" || info.UDPNATType != 5 || info.TCPNATType != 6 {
		t.Fatalf("unexpected extended fields: %#v", info)
	}
	if !info.FeatureFlags.IsPublicServer || !info.FeatureFlags.IsCredentialPeer {
		t.Fatalf("unexpected feature flags: %#v", info.FeatureFlags)
	}
	if info.PeerRouteID != 12345 {
		t.Fatalf("unexpected peer route id: %d", info.PeerRouteID)
	}
	if got := info.IPv6.String(); got != "2001:db8::1" {
		t.Fatalf("unexpected ipv6: %s", got)
	}
}

func TestParseRouteConnPeerList(t *testing.T) {
	peerIDVersion := appendProtoVarint(nil, 1, 7)
	peerIDVersion = appendProtoVarint(peerIDVersion, 2, 3)
	connPeerInfo := appendProtoBytes(nil, 1, peerIDVersion)
	connPeerInfo = appendProtoVarint(connPeerInfo, 2, 8)
	connPeerInfo = appendProtoVarint(connPeerInfo, 2, 9)
	connPeerList := appendProtoBytes(nil, 1, connPeerInfo)

	infos, err := parseRouteConnPeerList(connPeerList)
	if err != nil {
		t.Fatal(err)
	}
	if len(infos) != 1 || infos[0].PeerID != 7 || infos[0].Version != 3 {
		t.Fatalf("unexpected conn peer list: %#v", infos)
	}
	if !reflect.DeepEqual(infos[0].ConnectedPeerIDs, []uint32{8, 9}) {
		t.Fatalf("unexpected connected peers: %#v", infos[0].ConnectedPeerIDs)
	}
}

func TestParseRouteConnBitmap(t *testing.T) {
	peerA := appendProtoVarint(nil, 1, 7)
	peerA = appendProtoVarint(peerA, 2, 3)
	peerB := appendProtoVarint(nil, 1, 8)
	peerB = appendProtoVarint(peerB, 2, 4)
	peerC := appendProtoVarint(nil, 1, 9)
	peerC = appendProtoVarint(peerC, 2, 5)
	payload := appendProtoBytes(nil, 1, peerA)
	payload = appendProtoBytes(payload, 1, peerB)
	payload = appendProtoBytes(payload, 1, peerC)
	// Row 0 contains bit 1, so peer 7 connects to peer 8.
	// Row 1 contains bit 2, so peer 8 connects to peer 9.
	payload = appendProtoBytes(payload, 2, []byte{0b00100010, 0})

	infos, err := parseRouteConnBitmap(payload)
	if err != nil {
		t.Fatal(err)
	}
	if len(infos) != 3 {
		t.Fatalf("unexpected bitmap info count: %d", len(infos))
	}
	if !reflect.DeepEqual(infos[0].ConnectedPeerIDs, []uint32{8}) {
		t.Fatalf("unexpected peer 7 connections: %#v", infos[0])
	}
	if !reflect.DeepEqual(infos[1].ConnectedPeerIDs, []uint32{9}) {
		t.Fatalf("unexpected peer 8 connections: %#v", infos[1])
	}
}

func TestBuildRouteSyncIncludesStoredRawPeerInfos(t *testing.T) {
	rawPeerInfo := appendProtoVarint(nil, 1, 77)
	rawPeerInfo = appendProtoVarint(rawPeerInfo, 9, 12)
	rawPeerInfo = append(rawPeerInfo, 0xfa, 0x01, 0x03, 0xaa, 0xbb, 0xcc)
	packet, err := buildRouteSyncRequestPacket(routeRPCConfig{
		MyPeerID:     11,
		RemotePeerID: 22,
		NetworkName:  "example-net",
		IPv4:         netip.MustParsePrefix("198.51.100.11/24"),
		SessionID:    33,
		PeerRouteID:  44,
		InstanceID:   [4]uint32{1, 2, 3, 4},
		PeerInfos: []routePeerInfo{{
			PeerID:  77,
			Version: 12,
			Raw:     rawPeerInfo,
		}},
		Transaction: 55,
	})
	if err != nil {
		t.Fatal(err)
	}
	rpcReq, err := parseRPCPacket(packet.Payload)
	if err != nil {
		t.Fatal(err)
	}
	rawInfos, err := rawRoutePeerInfoPayloads(rpcReq)
	if err != nil {
		t.Fatal(err)
	}
	if len(rawInfos) != 2 {
		t.Fatalf("unexpected raw route info count: %d", len(rawInfos))
	}
	if !bytes.Equal(rawInfos[1], rawPeerInfo) {
		t.Fatalf("stored raw route info was not preserved: got %x want %x", rawInfos[1], rawPeerInfo)
	}
}

func TestManualRoutesAreNotAdvertisedAsProxyCIDRs(t *testing.T) {
	client := NewClient(Options{
		IPv4:         "198.51.100.11",
		NetworkName:  "example-net",
		ManualRoutes: []string{"203.0.113.1/32"},
	}, nil)
	client.myPeerID = 11
	client.routeSessionID = 33
	client.peerRouteID = 44
	client.instanceID = [4]uint32{1, 2, 3, 4}

	config, ok, err := client.routeRPCConfig(22)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected route rpc config")
	}
	if len(config.ProxyCIDRs) != 0 {
		t.Fatalf("manual-routes must not be advertised as proxy_cidrs: %#v", config.ProxyCIDRs)
	}
}

func TestRouteRPCConfigUsesConfiguredHostname(t *testing.T) {
	client := NewClient(Options{IPv4: "198.51.100.11", Hostname: "configured-host"}, nil)
	client.myPeerID = 11
	client.routeSessionID = 33
	client.peerRouteID = 44
	client.instanceID = [4]uint32{1, 2, 3, 4}

	config, ok, err := client.routeRPCConfig(22)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected route rpc config")
	}
	if config.Hostname != "configured-host" {
		t.Fatalf("unexpected configured hostname: %s", config.Hostname)
	}
	packet, err := buildRouteSyncRequestPacket(config)
	if err != nil {
		t.Fatal(err)
	}
	rpcReq, err := parseRPCPacket(packet.Payload)
	if err != nil {
		t.Fatal(err)
	}
	syncInfo, err := parseRouteSyncRPCRequest(rpcReq)
	if err != nil {
		t.Fatal(err)
	}
	if len(syncInfo.PeerInfos) != 1 || syncInfo.PeerInfos[0].Hostname != "configured-host" {
		t.Fatalf("route sync did not include configured hostname: %#v", syncInfo.PeerInfos)
	}
}

func TestNewClientDefaultsHostnameFromOS(t *testing.T) {
	client := NewClient(Options{}, nil)
	want, _ := os.Hostname()
	want = strings.TrimSpace(want)
	if want == "" {
		want = "mihomo"
	}
	if client.options.Hostname != want {
		t.Fatalf("unexpected default hostname: got %q want %q", client.options.Hostname, want)
	}
}

func TestDestinationPeerUsesRouteTable(t *testing.T) {
	client := NewClient(Options{}, nil)
	client.myPeerID = 1
	client.sessions = map[uint32]*peerSession{2: &peerSession{peerID: 2}}
	client.updateRoutes(2, []routePeerInfo{
		{
			PeerID:     3,
			ProxyCIDRs: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")},
		},
		{
			PeerID:     4,
			ProxyCIDRs: []netip.Prefix{netip.MustParsePrefix("203.0.113.1/32")},
		},
		{
			PeerID: 5,
			IPv4:   netip.MustParseAddr("198.51.100.12"),
		},
	})

	if got := client.destinationPeerID(testIPv4Packet("10.0.0.2", "203.0.113.1")); got != 4 {
		t.Fatalf("unexpected proxy destination peer: got %d want 4", got)
	}
	if got := client.destinationPeerID(testIPv4Packet("10.0.0.2", "203.0.113.2")); got != 3 {
		t.Fatalf("unexpected cidr destination peer: got %d want 3", got)
	}
	if got := client.destinationPeerID(testIPv4Packet("10.0.0.2", "198.51.100.12")); got != 5 {
		t.Fatalf("unexpected virtual ip destination peer: got %d want 5", got)
	}
	if got := client.destinationPeerID(testIPv4Packet("10.0.0.2", "192.0.2.1")); got != 2 {
		t.Fatalf("unexpected fallback destination peer: got %d want 2", got)
	}
}

func TestUpdateRoutesMergesIncrementalRelayUpdates(t *testing.T) {
	client := NewClient(Options{}, nil)
	client.myPeerID = 1
	client.sessions = map[uint32]*peerSession{2: &peerSession{peerID: 2}}
	client.updateRoutes(2, []routePeerInfo{{PeerID: 7, IPv4: netip.MustParseAddr("198.51.100.7"), Version: 1}})
	client.updateRoutes(2, []routePeerInfo{{PeerID: 8, IPv4: netip.MustParseAddr("198.51.100.8"), Version: 2}})

	if got := client.destinationPeerID(testIPv4Packet("10.0.0.2", "198.51.100.7")); got != 7 {
		t.Fatalf("unexpected incremental route destination peer for first entry: got %d want 7", got)
	}
	if got := client.destinationPeerID(testIPv4Packet("10.0.0.2", "198.51.100.8")); got != 8 {
		t.Fatalf("unexpected incremental route destination peer for second entry: got %d want 8", got)
	}
}

func TestUpdateRoutesKeepsIPv4WhenPlaceholderVersionZeroArrives(t *testing.T) {
	client := NewClient(Options{}, nil)
	client.myPeerID = 1
	client.sessions = map[uint32]*peerSession{2: &peerSession{peerID: 2}}
	client.updateRoutes(2, []routePeerInfo{{PeerID: 7, IPv4: netip.MustParseAddr("192.88.99.2"), NetworkLength: 24, Version: 3}})
	client.updateRoutes(2, []routePeerInfo{{PeerID: 7, Version: 0}})

	if got := client.destinationPeerID(testIPv4Packet("10.0.0.2", "192.88.99.2")); got != 7 {
		t.Fatalf("unexpected destination peer after placeholder update: got %d want 7", got)
	}
}

func TestUpdateRoutesIgnoresOlderPeerInfoVersion(t *testing.T) {
	client := NewClient(Options{}, nil)
	client.myPeerID = 1
	client.sessions = map[uint32]*peerSession{2: &peerSession{peerID: 2}}
	client.updateRoutes(2, []routePeerInfo{{PeerID: 7, IPv4: netip.MustParseAddr("192.88.99.7"), Version: 3}})
	client.updateRoutes(2, []routePeerInfo{{PeerID: 7, IPv4: netip.MustParseAddr("192.88.99.8"), Version: 2}})

	if got := client.destinationPeerID(testIPv4Packet("10.0.0.2", "192.88.99.7")); got != 7 {
		t.Fatalf("unexpected destination peer after older update: got %d want 7", got)
	}
	if got := client.destinationPeerID(testIPv4Packet("10.0.0.2", "192.88.99.8")); got == 7 {
		t.Fatal("older peer info version should not replace current ipv4")
	}
}

func TestSelectDataSessionPrefersRelayPeer(t *testing.T) {
	client := NewClient(Options{}, nil)
	client.myPeerID = 1
	client.sessions = map[uint32]*peerSession{
		2: &peerSession{peerID: 2},
		4: &peerSession{peerID: 4},
	}
	client.updateRoutes(4, []routePeerInfo{{PeerID: 7}})

	session, err := client.selectDataSession(NewPacket(1, 7, PacketTypeData, []byte("payload")), nil)
	if err != nil {
		t.Fatal(err)
	}
	if session.peerID != 4 {
		t.Fatalf("unexpected relay session: got %d want 4", session.peerID)
	}
}

func TestSelectDataSessionUsesConnGraphForMultiHopRelay(t *testing.T) {
	client := NewClient(Options{}, nil)
	client.myPeerID = 1
	client.sessions = map[uint32]*peerSession{2: &peerSession{peerID: 2}}
	client.updateRouteState(2, syncRouteInfo{
		PeerInfos: []routePeerInfo{{PeerID: 7, IPv4: netip.MustParseAddr("198.51.100.7"), Version: 1}},
		ConnInfos: []routeConnInfo{
			{PeerID: 2, ConnectedPeerIDs: []uint32{6}, Version: 1},
			{PeerID: 6, ConnectedPeerIDs: []uint32{7}, Version: 1},
		},
	})

	if got := client.destinationPeerID(testIPv4Packet("10.0.0.2", "198.51.100.7")); got != 7 {
		t.Fatalf("unexpected multi-hop destination peer: got %d want 7", got)
	}
	session, err := client.selectDataSession(NewPacket(1, 7, PacketTypeData, []byte("payload")), nil)
	if err != nil {
		t.Fatal(err)
	}
	if session.peerID != 2 {
		t.Fatalf("unexpected next hop session: got %d want 2", session.peerID)
	}
}

func TestConnGraphPreventsUnreachablePeerSelection(t *testing.T) {
	client := NewClient(Options{}, nil)
	client.myPeerID = 1
	client.sessions = map[uint32]*peerSession{2: &peerSession{peerID: 2}}
	client.updateRouteState(2, syncRouteInfo{
		PeerInfos: []routePeerInfo{{PeerID: 7, IPv4: netip.MustParseAddr("198.51.100.7"), Version: 1}},
		ConnInfos: []routeConnInfo{{PeerID: 2, ConnectedPeerIDs: []uint32{6}, Version: 1}},
	})

	if got := client.destinationPeerID(testIPv4Packet("10.0.0.2", "198.51.100.7")); got == 7 {
		t.Fatal("unreachable peer should not be selected from peer info alone")
	}
}

func TestObserveDataRouteLearnsSourceIPMapping(t *testing.T) {
	client := NewClient(Options{}, nil)
	client.myPeerID = 1
	client.sessions = map[uint32]*peerSession{2: &peerSession{peerID: 2}}
	client.updateRouteState(2, syncRouteInfo{
		PeerInfos: []routePeerInfo{{PeerID: 7, Version: 1}},
		ConnInfos: []routeConnInfo{{PeerID: 2, ConnectedPeerIDs: []uint32{7}, Version: 1}},
	})
	packet := NewPacket(7, 1, PacketTypeData, testIPv4Packet("192.88.99.2", "192.88.99.11"))
	client.observeDataRoute(packet)
	if got := client.destinationPeerID(testIPv4Packet("192.88.99.11", "192.88.99.2")); got != 7 {
		t.Fatalf("unexpected learned destination peer: got %d want 7", got)
	}
}

func TestObservedRouteExpiresWhenStale(t *testing.T) {
	client := NewClient(Options{}, nil)
	client.myPeerID = 1
	client.sessions = map[uint32]*peerSession{2: &peerSession{peerID: 2}}
	client.routeConns = map[uint32]routeConnSnapshot{
		2: {connectedPeerIDs: map[uint32]struct{}{7: {}}, version: 1, updatedAt: time.Now()},
	}
	client.observedRoutes = map[netip.Addr]observedRoute{
		netip.MustParseAddr("192.88.99.2"): {peerID: 7, seenAt: time.Now().Add(-observedRouteStaleAfter - time.Second)},
	}
	client.pruneStaleRoutes(time.Now())
	if got := client.destinationPeerID(testIPv4Packet("192.88.99.11", "192.88.99.2")); got == 7 {
		t.Fatal("stale observed route should not be used")
	}
}

func TestRouteRelayPeerIDPrefersLowerLatencyRelay(t *testing.T) {
	client := NewClient(Options{LatencyFirst: true}, nil)
	client.myPeerID = 1
	client.sessions = map[uint32]*peerSession{
		2: latencySession(2, 40*time.Millisecond),
		4: latencySession(4, 10*time.Millisecond),
	}
	client.updateRoutes(2, []routePeerInfo{{PeerID: 7}})
	client.updateRoutes(4, []routePeerInfo{{PeerID: 7}})

	relayPeerID, ok := client.routeRelayPeerID(7)
	if !ok {
		t.Fatal("expected relay peer id")
	}
	if relayPeerID != 4 {
		t.Fatalf("unexpected relay peer selection: got %d want 4", relayPeerID)
	}
}

func TestRouteRelayPeerIDPrefersFewerHopsByDefault(t *testing.T) {
	client := NewClient(Options{}, nil)
	client.myPeerID = 1
	client.sessions = map[uint32]*peerSession{
		2: latencySession(2, 40*time.Millisecond),
		4: latencySession(4, 10*time.Millisecond),
	}
	client.updateRouteState(2, syncRouteInfo{
		PeerInfos: []routePeerInfo{{PeerID: 7, Version: 1}},
		ConnInfos: []routeConnInfo{
			{PeerID: 2, ConnectedPeerIDs: []uint32{7}, Version: 1},
			{PeerID: 4, ConnectedPeerIDs: []uint32{6}, Version: 1},
			{PeerID: 6, ConnectedPeerIDs: []uint32{7}, Version: 1},
		},
	})

	relayPeerID, ok := client.routeRelayPeerID(7)
	if !ok {
		t.Fatal("expected relay peer id")
	}
	if relayPeerID != 2 {
		t.Fatalf("unexpected least-hop relay selection: got %d want 2", relayPeerID)
	}
}

func TestRouteRelayPeerIDLatencyFirstPrefersLowerRTT(t *testing.T) {
	client := NewClient(Options{LatencyFirst: true}, nil)
	client.myPeerID = 1
	client.sessions = map[uint32]*peerSession{
		2: latencySession(2, 40*time.Millisecond),
		4: latencySession(4, 10*time.Millisecond),
	}
	client.updateRouteState(2, syncRouteInfo{
		PeerInfos: []routePeerInfo{{PeerID: 7, Version: 1}},
		ConnInfos: []routeConnInfo{
			{PeerID: 2, ConnectedPeerIDs: []uint32{7}, Version: 1},
			{PeerID: 4, ConnectedPeerIDs: []uint32{7}, Version: 1},
		},
	})

	relayPeerID, ok := client.routeRelayPeerID(7)
	if !ok {
		t.Fatal("expected relay peer id")
	}
	if relayPeerID != 4 {
		t.Fatalf("unexpected latency-first relay selection: got %d want 4", relayPeerID)
	}
}

func TestSendPacketWithRetryWaitsForRecoveredSession(t *testing.T) {
	client := NewClient(Options{DisableEncryption: true}, nil)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	go func() {
		time.Sleep(50 * time.Millisecond)
		client.addSession(newDiscardSession(2))
	}()

	packet := NewPacket(1, 2, PacketTypeData, []byte("payload"))
	if err := client.sendPacketWithRetry(ctx, packet); err != nil {
		t.Fatal(err)
	}
}

func TestRemoveSessionPrunesRelayRoutes(t *testing.T) {
	client := NewClient(Options{}, nil)
	client.myPeerID = 1
	client.sessions = map[uint32]*peerSession{
		2: newDiscardSession(2),
		4: newDiscardSession(4),
	}
	client.updateRoutes(4, []routePeerInfo{{PeerID: 5, IPv4: netip.MustParseAddr("198.51.100.12")}})

	if got := client.destinationPeerID(testIPv4Packet("10.0.0.2", "198.51.100.12")); got != 5 {
		t.Fatalf("unexpected route destination peer before prune: got %d want 5", got)
	}
	if remaining := client.removeSession(client.sessions[4]); remaining != 1 {
		t.Fatalf("unexpected remaining session count: got %d want 1", remaining)
	}
	if got := client.destinationPeerID(testIPv4Packet("10.0.0.2", "198.51.100.12")); got != 2 {
		t.Fatalf("unexpected fallback destination peer after prune: got %d want 2", got)
	}
}

func TestParsePeerEndpointsAcceptsMultiplePeers(t *testing.T) {
	endpoints, err := parsePeerEndpoints([]string{"peer-a.example.com", "udp://peer-b.example.com:22020"})
	if err != nil {
		t.Fatal(err)
	}
	if len(endpoints) != 2 {
		t.Fatalf("unexpected endpoint count: %d", len(endpoints))
	}
	if endpoints[0].network != "tcp" || endpoints[1].network != "udp" {
		t.Fatalf("unexpected endpoint networks: %#v", endpoints)
	}
	if endpoints[0].address != "peer-a.example.com:11010" || endpoints[1].address != "peer-b.example.com:22020" {
		t.Fatalf("unexpected endpoints: %#v", endpoints)
	}
}

func TestUpdatePeersReplacesConfiguredEndpoints(t *testing.T) {
	client := NewClient(Options{Peers: []string{"tcp://one.example:11010"}}, nil)
	client.started = true
	client.setPeerEndpoints([]peerEndpoint{{network: "tcp", address: "one.example:11010"}})
	client.sessions = map[uint32]*peerSession{
		2: newDiscardSessionWithEndpoint(2, peerEndpoint{network: "tcp", address: "one.example:11010"}),
		3: newDiscardSessionWithEndpoint(3, peerEndpoint{network: "tcp", address: "stale.example:11010"}),
	}
	client.reconnect = map[string]reconnectState{
		peerEndpointKey(peerEndpoint{network: "tcp", address: "one.example:11010"}):   {failures: 1},
		peerEndpointKey(peerEndpoint{network: "tcp", address: "stale.example:11010"}): {failures: 2},
	}

	if err := client.UpdatePeers([]string{"udp://two.example:22020"}); err != nil {
		t.Fatal(err)
	}

	endpoints := client.currentPeerEndpoints()
	if len(endpoints) != 1 || endpoints[0].network != "udp" || endpoints[0].address != "two.example:22020" {
		t.Fatalf("unexpected updated peers: %#v", endpoints)
	}
	if len(client.activeSessions()) != 0 {
		t.Fatalf("expected stale sessions to be removed: %#v", client.activeSessions())
	}
	if _, ok := client.reconnect[peerEndpointKey(peerEndpoint{network: "tcp", address: "stale.example:11010"})]; ok {
		t.Fatal("expected stale reconnect state to be pruned")
	}
	missing := client.missingPeerEndpoints(time.Now())
	if len(missing) != 1 || missing[0].network != "udp" || missing[0].address != "two.example:22020" {
		t.Fatalf("unexpected missing peers after update: %#v", missing)
	}
	if !reflect.DeepEqual(client.options.Peers, []string{"udp://two.example:22020"}) {
		t.Fatalf("unexpected stored peer strings: %#v", client.options.Peers)
	}
}

func TestUpdatePeersBeforeStartOnlyRefreshesConfig(t *testing.T) {
	client := NewClient(Options{Peers: []string{"tcp://one.example:11010"}}, nil)
	if err := client.UpdatePeers([]string{"tcp://two.example:11010", "udp://three.example:11010"}); err != nil {
		t.Fatal(err)
	}
	endpoints := client.currentPeerEndpoints()
	if len(endpoints) != 2 {
		t.Fatalf("unexpected endpoint count: %#v", endpoints)
	}
	if endpoints[0].address != "two.example:11010" || endpoints[1].address != "three.example:11010" {
		t.Fatalf("unexpected endpoints: %#v", endpoints)
	}
	if len(client.activeSessions()) != 0 {
		t.Fatalf("unexpected sessions before start: %#v", client.activeSessions())
	}
}

func TestReconnectDelayForFailuresBacksOff(t *testing.T) {
	if got := reconnectDelayForFailures(1, 0); got != time.Second {
		t.Fatalf("unexpected first reconnect delay: %s", got)
	}
	if got := reconnectDelayForFailures(2, 0); got != 2*time.Second {
		t.Fatalf("unexpected second reconnect delay: %s", got)
	}
	if got := reconnectDelayForFailures(6, 0); got != 30*time.Second {
		t.Fatalf("unexpected capped reconnect delay: %s", got)
	}
	jittered := reconnectDelayForFailures(1, 1)
	if jittered <= time.Second || jittered > time.Second+time.Second/4 {
		t.Fatalf("unexpected jittered reconnect delay: %s", jittered)
	}
}

func TestUDPPeerTransportRoundTrip(t *testing.T) {
	server, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	serverDone := make(chan error, 1)
	go func() {
		buf := make([]byte, udpTunnelHeaderSize+udpTunnelMaxControlBytes)

		n, addr, err := server.ReadFrom(buf)
		if err != nil {
			serverDone <- err
			return
		}
		syn, err := parseUDPTunnelPacket(buf[:n], udpTunnelMaxControlBytes)
		if err != nil {
			serverDone <- err
			return
		}
		if syn.msgType != udpTunnelPacketTypeSyn {
			serverDone <- errUnexpectedUDPType(syn.msgType, udpTunnelPacketTypeSyn)
			return
		}
		if _, err = server.WriteTo(marshalUDPTunnelPacket(syn.connID, udpTunnelPacketTypeSack, uint16(len(syn.payload)), syn.payload), addr); err != nil {
			serverDone <- err
			return
		}

		n, addr, err = server.ReadFrom(buf)
		if err != nil {
			serverDone <- err
			return
		}
		data, err := parseUDPTunnelPacket(buf[:n], udpTunnelMaxControlBytes)
		if err != nil {
			serverDone <- err
			return
		}
		if data.msgType != udpTunnelPacketTypeData {
			serverDone <- errUnexpectedUDPType(data.msgType, udpTunnelPacketTypeData)
			return
		}
		packet, err := ReadPacketBody(data.payload, 1024)
		if err != nil {
			serverDone <- err
			return
		}
		if packet.Header.FromPeerID != 1 || packet.Header.ToPeerID != 2 || !bytes.Equal(packet.Payload, []byte("payload")) {
			serverDone <- errUnexpectedUDPPacket(packet)
			return
		}
		_, err = server.WriteTo(marshalUDPTunnelPacket(data.connID, udpTunnelPacketTypeData, uint16(len(data.payload)), data.payload), addr)
		serverDone <- err
	}()

	conn, err := net.Dial("udp", server.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	transport, err := newUDPPeerTransport(context.Background(), conn)
	if err != nil {
		t.Fatal(err)
	}
	packet := NewPacket(1, 2, PacketTypeData, []byte("payload"))
	if err := transport.WritePacket(packet); err != nil {
		t.Fatal(err)
	}
	decoded, err := transport.ReadPacket(1024)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Header.FromPeerID != 1 || decoded.Header.ToPeerID != 2 || !bytes.Equal(decoded.Payload, []byte("payload")) {
		t.Fatalf("unexpected udp packet: %#v %q", decoded.Header, decoded.Payload)
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
}

func errUnexpectedUDPType(got, want byte) error {
	return fmt.Errorf("unexpected udp tunnel packet type: got %d want %d", got, want)
}

func errUnexpectedUDPPacket(packet *Packet) error {
	return fmt.Errorf("unexpected udp packet: %#v %q", packet.Header, packet.Payload)
}

func testIPv4Packet(src, dst string) []byte {
	packet := make([]byte, 20)
	packet[0] = 0x45
	copy(packet[12:16], netip.MustParseAddr(src).AsSlice())
	copy(packet[16:20], netip.MustParseAddr(dst).AsSlice())
	return packet
}
