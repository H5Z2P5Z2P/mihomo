package easytier

import (
	"bytes"
	"encoding/hex"
	"net/netip"
	"testing"
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
	encoded := packet.MarshalTCP()
	decoded, err := ReadTCPPacket(bytes.NewReader(encoded), 1024)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Header.FromPeerID != 1 || decoded.Header.ToPeerID != 2 || decoded.Header.PacketType != PacketTypeData {
		t.Fatalf("unexpected header: %#v", decoded.Header)
	}
	if !bytes.Equal(decoded.Payload, []byte("payload")) {
		t.Fatalf("unexpected payload: %q", decoded.Payload)
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
	if syncInfo.MyPeerID != 11 || len(syncInfo.PeerInfos) != 1 {
		t.Fatalf("unexpected sync route info: %#v", syncInfo)
	}
	peerInfo := syncInfo.PeerInfos[0]
	if peerInfo.PeerID != 11 || peerInfo.IPv4.String() != "198.51.100.11" || peerInfo.NetworkLength != 24 {
		t.Fatalf("unexpected peer info: %#v", peerInfo)
	}
	if len(peerInfo.ProxyCIDRs) != 1 || peerInfo.ProxyCIDRs[0].String() != "203.0.113.1/32" {
		t.Fatalf("unexpected proxy cidrs: %#v", peerInfo.ProxyCIDRs)
	}
}

func TestManualRoutesAreNotAdvertisedAsProxyCIDRs(t *testing.T) {
	client := NewClient(Options{
		IPv4:         "198.51.100.11",
		NetworkName:  "example-net",
		ManualRoutes: []string{"203.0.113.1/32"},
	}, nil)
	client.myPeerID = 11
	client.remotePeerID = 22
	client.routeSessionID = 33
	client.peerRouteID = 44
	client.instanceID = [4]uint32{1, 2, 3, 4}

	config, ok, err := client.routeRPCConfig()
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

func TestDestinationPeerUsesRouteTable(t *testing.T) {
	client := NewClient(Options{}, nil)
	client.myPeerID = 1
	client.remotePeerID = 2
	client.updateRoutes([]routePeerInfo{
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

func testIPv4Packet(src, dst string) []byte {
	packet := make([]byte, 20)
	packet[0] = 0x45
	copy(packet[12:16], netip.MustParseAddr(src).AsSlice())
	copy(packet[16:20], netip.MustParseAddr(dst).AsSlice())
	return packet
}
