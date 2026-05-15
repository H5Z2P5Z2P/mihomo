package adapter

import (
	"encoding/json"
	"testing"

	C "github.com/metacubex/mihomo/constant"
)

func TestParseTailscaleProxy(t *testing.T) {
	proxy, err := ParseProxy(map[string]any{
		"name":        "ts-main",
		"type":        "tailscale",
		"auth-key":    "tskey-auth-test",
		"hostname":    "ts-main",
		"control-url": "https://controlplane.tailscale.com",
		"ephemeral":   false,
		"state-dir":   "tailstate/ts-main",
		"exit-node":   "exit-gateway.example.ts.net",
	})
	if err != nil {
		t.Fatal(err)
	}
	if proxy.Name() != "ts-main" {
		t.Fatalf("unexpected proxy name: %s", proxy.Name())
	}
	if proxy.Type() != C.Tailscale {
		t.Fatalf("unexpected proxy type: %s", proxy.Type())
	}
	if !proxy.SupportUDP() {
		t.Fatal("tailscale proxy should advertise UDP support")
	}
}

func TestParseEasyTierProxy(t *testing.T) {
	proxy, err := ParseProxy(map[string]any{
		"name":               "et-main",
		"type":               "easytier",
		"peer":               "tcp://peer.example.com:11010",
		"ipv4":               "198.51.100.11",
		"hostname":           "et-main-host",
		"network-name":       "example-net",
		"network-secret":     "example-network-secret",
		"latency-first":      true,
		"no-listener":        true,
		"manual-routes":      []string{"203.0.113.1/32"},
		"disable-encryption": false,
	})
	if err != nil {
		t.Fatal(err)
	}
	if proxy.Name() != "et-main" {
		t.Fatalf("unexpected proxy name: %s", proxy.Name())
	}
	if proxy.Type() != C.EasyTier {
		t.Fatalf("unexpected proxy type: %s", proxy.Type())
	}
	if !proxy.SupportUDP() {
		t.Fatal("easytier proxy should advertise UDP support")
	}
	if _, ok := proxy.Adapter().(C.L3ProxyAdapter); !ok {
		t.Fatal("easytier proxy should support L3 packet forwarding")
	}
	body, err := proxy.Adapter().MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	var payload struct {
		Option struct {
			Hostname string `json:"hostname"`
		} `json:"option"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Option.Hostname != "et-main-host" {
		t.Fatalf("unexpected parsed hostname: %s", payload.Option.Hostname)
	}
}
