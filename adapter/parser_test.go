package adapter

import (
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
	autoStart := false
	proxy, err := ParseProxy(map[string]any{
		"name":           "et-main",
		"type":           "easytier",
		"binary":         "/usr/local/bin/easytier-core",
		"peer":           "tcp://op.uily.de:23980",
		"ipv4":           "192.88.99.3",
		"network-name":   "boom",
		"network-secret": "luncheon-splendid-tinsmith-reformat-engraving-spending",
		"no-listener":    true,
		"manual-routes":  []string{"192.168.50.1/32"},
		"auto-start":     autoStart,
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
}
