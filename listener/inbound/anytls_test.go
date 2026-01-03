package inbound_test

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter/outbound"
	N "github.com/metacubex/mihomo/common/net"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener/inbound"
	"github.com/stretchr/testify/assert"
)

// User provided keys
const (
	testPrivateKey = "2Hfl7xC6Rr7JhURi81GdWiEGRsu1bYvwRyIV4_Zh2mA"
	testPublicKey  = "_N9DjqSgv_RF-2vPQ5znlLlLWRI3UH2qL1m1uZV1Sho"
	testShortID    = "12345678"
	testDest       = "itunes.apple.com"
)

func TestInboundAnyTLS_Reality(t *testing.T) {
	// Using variables from common_test.go
	inboundOptions := inbound.AnyTLSOption{
		BaseOption: inbound.BaseOption{
			NameStr: "anytls_reality_in",
			Listen:  "127.0.0.1",
			Port:    "0",
		},
		Users: map[string]string{
			"test": "password",
		},
		RealityConfig: inbound.RealityConfig{
			Dest:        net.JoinHostPort(testDest, "443"),
			PrivateKey:  testPrivateKey,
			ShortID:     []string{testShortID},
			ServerNames: []string{testDest},
		},
	}

	in, err := inbound.NewAnyTLS(&inboundOptions)
	if !assert.NoError(t, err) {
		return
	}
	defer in.Close()

	tunnel := NewHttpTestTunnel()
	defer tunnel.Close()

	err = in.Listen(tunnel)
	if !assert.NoError(t, err) {
		return
	}

	addrPort, err := netip.ParseAddrPort(in.Address())
	if !assert.NoError(t, err) {
		return
	}

	outboundOptions := outbound.AnyTLSOption{
		Name:              "anytls_reality_out",
		Server:            addrPort.Addr().String(),
		Port:              int(addrPort.Port()),
		Password:          "password",
		SNI:               testDest,
		ClientFingerprint: "chrome",
		RealityOpts: outbound.RealityOptions{
			PublicKey: testPublicKey,
			ShortID:   testShortID,
		},
	}

	out, err := outbound.NewAnyTLS(outboundOptions)
	if !assert.NoError(t, err) {
		return
	}

	tunnel.DoTest(t, out)
}

func TestInboundAnyTLS_Reality_RealWebsite(t *testing.T) {
	// Setup a Tunnel that actually dials out
	realTunnel := &TestTunnel{
		HandleTCPConnFn: func(conn net.Conn, metadata *C.Metadata) {
			// Dial the actual destination
			remoteAddr := metadata.RemoteAddress()
			remote, err := net.DialTimeout("tcp", remoteAddr, 5*time.Second)
			if err != nil {
				conn.Close()
				return
			}
			N.Relay(conn, remote)
		},
		HandleUDPPacketFn: func(packet C.UDPPacket, metadata *C.Metadata) {
			// No UDP support in this test
		},
		NatTableFn: func() C.NatTable { return nil },
		CloseFn:    func() error { return nil },
	}

	inboundOptions := inbound.AnyTLSOption{
		BaseOption: inbound.BaseOption{
			NameStr: "anytls_reality_real_in",
			Listen:  "127.0.0.1",
			Port:    "0",
		},
		Users: map[string]string{
			"test": "password",
		},
		RealityConfig: inbound.RealityConfig{
			Dest:        net.JoinHostPort(testDest, "443"),
			PrivateKey:  testPrivateKey,
			ShortID:     []string{testShortID},
			ServerNames: []string{testDest},
		},
	}

	in, err := inbound.NewAnyTLS(&inboundOptions)
	if !assert.NoError(t, err) {
		return
	}
	defer in.Close()

	err = in.Listen(realTunnel)
	if !assert.NoError(t, err) {
		return
	}

	addrPort, err := netip.ParseAddrPort(in.Address())
	if !assert.NoError(t, err) {
		return
	}

	outboundOptions := outbound.AnyTLSOption{
		Name:              "anytls_reality_real_out",
		Server:            addrPort.Addr().String(),
		Port:              int(addrPort.Port()),
		Password:          "password",
		SNI:               testDest,
		ClientFingerprint: "chrome",
		RealityOpts: outbound.RealityOptions{
			PublicKey: testPublicKey,
			ShortID:   testShortID,
		},
	}

	out, err := outbound.NewAnyTLS(outboundOptions)
	if !assert.NoError(t, err) {
		return
	}

	// Make a real HTTP request

	targetURL := "http://www.google.com" // Simple HTTP request
	// Note: HTTPS might work too but requires client to trust Google's cert, which default client does.

	client := http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				// We ignore addr here because we want to route through the proxy?
				// No, DialContext receives the target addr. We need to tell the proxy to dial THIS addr.
				// The proxy.DialContext takes metadata with DstIP/Port.

				host, portStr, _ := net.SplitHostPort(addr)
				port, _ := net.LookupPort("tcp", portStr)

				// We need IP of www.google.com for metadata since AnyTLS client expects IP in metadata?
				// outbound.DialContext -> client.CreateProxy -> expects SOCKS addr.
				// metadata.String() returns Host if IP is not set?
				// Let's create metadata with Host.

				metadata := &C.Metadata{
					NetWork: C.TCP,
					Host:    host,
					DstPort: uint16(port),
					Type:    C.HTTP, // Just a hint
				}

				return out.DialContext(ctx, metadata)
			},
		},
		Timeout: 5 * time.Second,
	}

	resp, err := client.Get(targetURL)
	if !assert.NoError(t, err) {
		return
	}
	defer resp.Body.Close()

	t.Logf("Got response status: %s", resp.Status)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}
