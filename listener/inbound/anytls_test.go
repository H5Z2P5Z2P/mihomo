package inbound_test

import (
	"net"
	"net/netip"
	"testing"

	"github.com/metacubex/mihomo/adapter/outbound"
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
	outboundOptions.DialerForAPI = tunnel.NewDialer()

	out, err := outbound.NewAnyTLS(outboundOptions)
	if !assert.NoError(t, err) {
		return
	}

	tunnel.DoTest(t, out)
}
